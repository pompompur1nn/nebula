use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type Runtime = State;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKEN_BRIDGE_ASSET_REGISTRY_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-confidential-token-bridge-asset-registry-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_TOKEN_BRIDGE_ASSET_REGISTRY_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const DEVNET_HEIGHT: u64 = 1_824_000;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_ATTESTATION_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-bridge-asset-registry-v1";
pub const CONFIDENTIAL_PROOF_SUITE: &str =
    "RingCT-amount-conservation+membership-nullifier+bridge-denomination-v1";
pub const BRIDGE_MANIFEST_SUITE: &str = "private-l2-pq-bridge-mint-burn-manifest-v1";
pub const COMPLIANCE_ATTESTATION_SUITE: &str =
    "private-l2-confidential-token-compliance-attestation-v1";
pub const DENOMINATION_MAP_SUITE: &str = "cross-chain-denomination-map-root-v1";
pub const COVENANT_HOOK_SUITE: &str = "token-covenant-hook-commitment-root-v1";
pub const RESERVE_ATTESTATION_SUITE: &str = "bridge-reserve-attestation-root-v1";
pub const PRIVACY_FENCE_SUITE: &str = "bridge-asset-nullifier-fence-root-v1";
pub const LOW_FEE_SPONSORSHIP_SUITE: &str = "low-fee-confidential-bridge-sponsorship-root-v1";
pub const SLASHING_EVIDENCE_SUITE: &str = "bridge-asset-registry-slashing-evidence-root-v1";
pub const DEVNET_L2_NETWORK: &str = "nebula-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_REGISTRY_ID: &str =
    "private-l2-pq-confidential-token-bridge-asset-registry-devnet";
pub const DEVNET_REPLAY_DOMAIN: &str =
    "nebula-private-l2-pq-confidential-token-bridge-asset-registry-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_BATCH_PRIVACY_SET_SIZE: u64 = 524_288;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_LISTING_TTL_BLOCKS: u64 = 86_400;
pub const DEFAULT_MANIFEST_TTL_BLOCKS: u64 = 144;
pub const DEFAULT_ATTESTATION_TTL_BLOCKS: u64 = 7_200;
pub const DEFAULT_DENOMINATION_TTL_BLOCKS: u64 = 172_800;
pub const DEFAULT_FEE_SCHEDULE_TTL_BLOCKS: u64 = 28_800;
pub const DEFAULT_PROOF_REQUIREMENT_TTL_BLOCKS: u64 = 43_200;
pub const DEFAULT_HOOK_TTL_BLOCKS: u64 = 28_800;
pub const DEFAULT_RESERVE_TTL_BLOCKS: u64 = 720;
pub const DEFAULT_FENCE_TTL_BLOCKS: u64 = 288;
pub const DEFAULT_SPONSOR_TTL_BLOCKS: u64 = 96;
pub const DEFAULT_SLASH_CHALLENGE_TTL_BLOCKS: u64 = 2_880;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 18;
pub const DEFAULT_MAX_SPONSOR_FEE_BPS: u64 = 8;
pub const DEFAULT_TARGET_REBATE_BPS: u64 = 6;
pub const DEFAULT_RESERVE_SAFETY_BPS: u64 = 10_250;
pub const DEFAULT_SLASH_BPS: u64 = 1_500;
pub const DEFAULT_MAX_ASSET_LISTINGS: usize = 1_048_576;
pub const DEFAULT_MAX_MANIFESTS: usize = 4_194_304;
pub const DEFAULT_MAX_ATTESTATIONS: usize = 4_194_304;
pub const DEFAULT_MAX_DENOMINATION_MAPS: usize = 524_288;
pub const DEFAULT_MAX_FEE_POLICIES: usize = 524_288;
pub const DEFAULT_MAX_PROOF_REQUIREMENTS: usize = 524_288;
pub const DEFAULT_MAX_COVENANT_HOOKS: usize = 1_048_576;
pub const DEFAULT_MAX_RESERVE_ATTESTATIONS: usize = 2_097_152;
pub const DEFAULT_MAX_PRIVACY_FENCES: usize = 8_388_608;
pub const DEFAULT_MAX_SPONSORSHIPS: usize = 2_097_152;
pub const DEFAULT_MAX_SLASHING_EVIDENCE: usize = 1_048_576;
pub const DEFAULT_MAX_EVENTS: usize = 16_777_216;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ChainKind {
    NebulaL2,
    MoneroMainnet,
    MoneroDevnet,
    Bitcoin,
    Ethereum,
    Solana,
    Cosmos,
    Celestia,
    Arbitrum,
    Optimism,
    Polygon,
}

impl ChainKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NebulaL2 => "nebula_l2",
            Self::MoneroMainnet => "monero_mainnet",
            Self::MoneroDevnet => "monero_devnet",
            Self::Bitcoin => "bitcoin",
            Self::Ethereum => "ethereum",
            Self::Solana => "solana",
            Self::Cosmos => "cosmos",
            Self::Celestia => "celestia",
            Self::Arbitrum => "arbitrum",
            Self::Optimism => "optimism",
            Self::Polygon => "polygon",
        }
    }

    pub fn finality_score(self) -> u64 {
        match self {
            Self::NebulaL2 => 9_900,
            Self::MoneroMainnet => 9_700,
            Self::MoneroDevnet => 9_600,
            Self::Bitcoin => 9_500,
            Self::Ethereum => 9_250,
            Self::Celestia => 8_950,
            Self::Arbitrum => 8_850,
            Self::Optimism => 8_750,
            Self::Cosmos => 8_650,
            Self::Solana => 8_450,
            Self::Polygon => 8_300,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AssetKind {
    WrappedMonero,
    ConfidentialFungibleToken,
    PrivateStableAsset,
    TokenizedVaultShare,
    TokenizedRwaReceipt,
    ConfidentialLpReceipt,
    SyntheticBridgeClaim,
    GovernanceNote,
    SettlementCoupon,
    RebateCredit,
}

impl AssetKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WrappedMonero => "wrapped_monero",
            Self::ConfidentialFungibleToken => "confidential_fungible_token",
            Self::PrivateStableAsset => "private_stable_asset",
            Self::TokenizedVaultShare => "tokenized_vault_share",
            Self::TokenizedRwaReceipt => "tokenized_rwa_receipt",
            Self::ConfidentialLpReceipt => "confidential_lp_receipt",
            Self::SyntheticBridgeClaim => "synthetic_bridge_claim",
            Self::GovernanceNote => "governance_note",
            Self::SettlementCoupon => "settlement_coupon",
            Self::RebateCredit => "rebate_credit",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ListingStatus {
    Draft,
    Proposed,
    Attested,
    Active,
    Paused,
    Frozen,
    Retiring,
    Retired,
    Slashed,
}

impl ListingStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Proposed => "proposed",
            Self::Attested => "attested",
            Self::Active => "active",
            Self::Paused => "paused",
            Self::Frozen => "frozen",
            Self::Retiring => "retiring",
            Self::Retired => "retired",
            Self::Slashed => "slashed",
        }
    }

    pub fn accepts_bridge_activity(self) -> bool {
        matches!(self, Self::Attested | Self::Active)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BridgeAction {
    ShieldedMint,
    ShieldedBurn,
    ReserveRebalance,
    EmergencyExit,
    DenominationMigration,
    CovenantHookExecution,
    FeeSponsorSettlement,
}

impl BridgeAction {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ShieldedMint => "shielded_mint",
            Self::ShieldedBurn => "shielded_burn",
            Self::ReserveRebalance => "reserve_rebalance",
            Self::EmergencyExit => "emergency_exit",
            Self::DenominationMigration => "denomination_migration",
            Self::CovenantHookExecution => "covenant_hook_execution",
            Self::FeeSponsorSettlement => "fee_sponsor_settlement",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ManifestStatus {
    Draft,
    PrivacyChecked,
    ComplianceAttested,
    ReserveLocked,
    ProofReady,
    Submitted,
    Finalized,
    Expired,
    Rejected,
    Disputed,
}

impl ManifestStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::PrivacyChecked => "privacy_checked",
            Self::ComplianceAttested => "compliance_attested",
            Self::ReserveLocked => "reserve_locked",
            Self::ProofReady => "proof_ready",
            Self::Submitted => "submitted",
            Self::Finalized => "finalized",
            Self::Expired => "expired",
            Self::Rejected => "rejected",
            Self::Disputed => "disputed",
        }
    }

    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Draft
                | Self::PrivacyChecked
                | Self::ComplianceAttested
                | Self::ReserveLocked
                | Self::ProofReady
                | Self::Submitted
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ComplianceKind {
    SanctionsNonMembership,
    JurisdictionRule,
    TravelRuleEnvelope,
    IssuerEligibility,
    ReserveCoverage,
    BridgeMintBurn,
    ContractAllowance,
    ViewKeyDisclosure,
}

impl ComplianceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SanctionsNonMembership => "sanctions_non_membership",
            Self::JurisdictionRule => "jurisdiction_rule",
            Self::TravelRuleEnvelope => "travel_rule_envelope",
            Self::IssuerEligibility => "issuer_eligibility",
            Self::ReserveCoverage => "reserve_coverage",
            Self::BridgeMintBurn => "bridge_mint_burn",
            Self::ContractAllowance => "contract_allowance",
            Self::ViewKeyDisclosure => "view_key_disclosure",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
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

    pub fn permits_manifest(self) -> bool {
        matches!(self, Self::Allowed | Self::AllowedWithDisclosure)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DenominationKind {
    AtomicUnits,
    Piconero,
    TokenDecimals,
    VaultShares,
    ReceiptUnits,
    SyntheticIndexUnits,
}

impl DenominationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AtomicUnits => "atomic_units",
            Self::Piconero => "piconero",
            Self::TokenDecimals => "token_decimals",
            Self::VaultShares => "vault_shares",
            Self::ReceiptUnits => "receipt_units",
            Self::SyntheticIndexUnits => "synthetic_index_units",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FeeLane {
    SponsoredLowFee,
    RetailPrivate,
    DefiBatch,
    BridgeFast,
    ReserveRebalance,
    Emergency,
}

impl FeeLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SponsoredLowFee => "sponsored_low_fee",
            Self::RetailPrivate => "retail_private",
            Self::DefiBatch => "defi_batch",
            Self::BridgeFast => "bridge_fast",
            Self::ReserveRebalance => "reserve_rebalance",
            Self::Emergency => "emergency",
        }
    }

    pub fn base_fee_bps(self, config: &Config) -> u64 {
        match self {
            Self::SponsoredLowFee => config.max_sponsor_fee_bps,
            Self::RetailPrivate => config.max_user_fee_bps.saturating_mul(2) / 3,
            Self::DefiBatch => config.max_user_fee_bps / 2,
            Self::BridgeFast => config.max_user_fee_bps,
            Self::ReserveRebalance => config.max_user_fee_bps / 3,
            Self::Emergency => config.max_user_fee_bps,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofRequirementKind {
    AmountConservation,
    AssetMembership,
    DenominationConversion,
    NullifierFreshness,
    ReserveCoverage,
    ComplianceVerdict,
    CovenantHookAuthorization,
    SponsorBudget,
}

impl ProofRequirementKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AmountConservation => "amount_conservation",
            Self::AssetMembership => "asset_membership",
            Self::DenominationConversion => "denomination_conversion",
            Self::NullifierFreshness => "nullifier_freshness",
            Self::ReserveCoverage => "reserve_coverage",
            Self::ComplianceVerdict => "compliance_verdict",
            Self::CovenantHookAuthorization => "covenant_hook_authorization",
            Self::SponsorBudget => "sponsor_budget",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofSystem {
    RingCt,
    BulletproofPlus,
    Halo2,
    Plonky3,
    Risc0,
    Sp1,
    RecursiveAggregate,
    PqSignatureBundle,
}

impl ProofSystem {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RingCt => "ring_ct",
            Self::BulletproofPlus => "bulletproof_plus",
            Self::Halo2 => "halo2",
            Self::Plonky3 => "plonky3",
            Self::Risc0 => "risc0",
            Self::Sp1 => "sp1",
            Self::RecursiveAggregate => "recursive_aggregate",
            Self::PqSignatureBundle => "pq_signature_bundle",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HookKind {
    BeforeMint,
    AfterMint,
    BeforeBurn,
    AfterBurn,
    BeforeTransfer,
    ReserveCheck,
    ComplianceCheck,
    SponsorSettlement,
}

impl HookKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BeforeMint => "before_mint",
            Self::AfterMint => "after_mint",
            Self::BeforeBurn => "before_burn",
            Self::AfterBurn => "after_burn",
            Self::BeforeTransfer => "before_transfer",
            Self::ReserveCheck => "reserve_check",
            Self::ComplianceCheck => "compliance_check",
            Self::SponsorSettlement => "sponsor_settlement",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HookStatus {
    Proposed,
    Active,
    Paused,
    Superseded,
    Retired,
}

impl HookStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::Active => "active",
            Self::Paused => "paused",
            Self::Superseded => "superseded",
            Self::Retired => "retired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReserveStatus {
    Submitted,
    Active,
    UnderCollateralized,
    Expired,
    Disputed,
    Slashed,
}

impl ReserveStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Active => "active",
            Self::UnderCollateralized => "under_collateralized",
            Self::Expired => "expired",
            Self::Disputed => "disputed",
            Self::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FenceKind {
    InputNullifier,
    OutputCommitment,
    ComplianceNullifier,
    BridgeReplay,
    ViewTagFence,
    SponsorClaim,
    ReserveWitness,
    SlashingChallenge,
}

impl FenceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InputNullifier => "input_nullifier",
            Self::OutputCommitment => "output_commitment",
            Self::ComplianceNullifier => "compliance_nullifier",
            Self::BridgeReplay => "bridge_replay",
            Self::ViewTagFence => "view_tag_fence",
            Self::SponsorClaim => "sponsor_claim",
            Self::ReserveWitness => "reserve_witness",
            Self::SlashingChallenge => "slashing_challenge",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorshipStatus {
    Offered,
    Reserved,
    Spent,
    Rebated,
    Expired,
    Slashed,
}

impl SponsorshipStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Offered => "offered",
            Self::Reserved => "reserved",
            Self::Spent => "spent",
            Self::Rebated => "rebated",
            Self::Expired => "expired",
            Self::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SlashingReason {
    InvalidReserve,
    DoubleManifest,
    DuplicateNullifier,
    FalseComplianceAttestation,
    InvalidDenominationMap,
    HookMisexecution,
    SponsorFraud,
    WithheldDisclosure,
}

impl SlashingReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidReserve => "invalid_reserve",
            Self::DoubleManifest => "double_manifest",
            Self::DuplicateNullifier => "duplicate_nullifier",
            Self::FalseComplianceAttestation => "false_compliance_attestation",
            Self::InvalidDenominationMap => "invalid_denomination_map",
            Self::HookMisexecution => "hook_misexecution",
            Self::SponsorFraud => "sponsor_fraud",
            Self::WithheldDisclosure => "withheld_disclosure",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceStatus {
    Submitted,
    Accepted,
    Rejected,
    Challenged,
    Slashed,
}

impl EvidenceStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
            Self::Challenged => "challenged",
            Self::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationKind {
    ListAsset,
    PublishManifest,
    AttestCompliance,
    MapDenomination,
    ScheduleFeePolicy,
    AddProofRequirement,
    RegisterHook,
    AttestReserve,
    OpenFence,
    SponsorFee,
    SubmitSlashingEvidence,
}

impl OperationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ListAsset => "list_asset",
            Self::PublishManifest => "publish_manifest",
            Self::AttestCompliance => "attest_compliance",
            Self::MapDenomination => "map_denomination",
            Self::ScheduleFeePolicy => "schedule_fee_policy",
            Self::AddProofRequirement => "add_proof_requirement",
            Self::RegisterHook => "register_hook",
            Self::AttestReserve => "attest_reserve",
            Self::OpenFence => "open_fence",
            Self::SponsorFee => "sponsor_fee",
            Self::SubmitSlashingEvidence => "submit_slashing_evidence",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub registry_id: String,
    pub l2_network: String,
    pub monero_network: String,
    pub replay_domain: String,
    pub fee_asset_id: String,
    pub hash_suite: String,
    pub pq_attestation_suite: String,
    pub confidential_proof_suite: String,
    pub bridge_manifest_suite: String,
    pub compliance_attestation_suite: String,
    pub denomination_map_suite: String,
    pub covenant_hook_suite: String,
    pub reserve_attestation_suite: String,
    pub privacy_fence_suite: String,
    pub low_fee_sponsorship_suite: String,
    pub slashing_evidence_suite: String,
    pub min_privacy_set_size: u64,
    pub batch_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub listing_ttl_blocks: u64,
    pub manifest_ttl_blocks: u64,
    pub attestation_ttl_blocks: u64,
    pub denomination_ttl_blocks: u64,
    pub fee_schedule_ttl_blocks: u64,
    pub proof_requirement_ttl_blocks: u64,
    pub hook_ttl_blocks: u64,
    pub reserve_ttl_blocks: u64,
    pub fence_ttl_blocks: u64,
    pub sponsor_ttl_blocks: u64,
    pub slash_challenge_ttl_blocks: u64,
    pub max_user_fee_bps: u64,
    pub max_sponsor_fee_bps: u64,
    pub target_rebate_bps: u64,
    pub reserve_safety_bps: u64,
    pub slash_bps: u64,
    pub max_asset_listings: usize,
    pub max_manifests: usize,
    pub max_attestations: usize,
    pub max_denomination_maps: usize,
    pub max_fee_policies: usize,
    pub max_proof_requirements: usize,
    pub max_covenant_hooks: usize,
    pub max_reserve_attestations: usize,
    pub max_privacy_fences: usize,
    pub max_sponsorships: usize,
    pub max_slashing_evidence: usize,
    pub max_events: usize,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            registry_id: DEVNET_REGISTRY_ID.to_string(),
            l2_network: DEVNET_L2_NETWORK.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            replay_domain: DEVNET_REPLAY_DOMAIN.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            hash_suite: HASH_SUITE.to_string(),
            pq_attestation_suite: PQ_ATTESTATION_SUITE.to_string(),
            confidential_proof_suite: CONFIDENTIAL_PROOF_SUITE.to_string(),
            bridge_manifest_suite: BRIDGE_MANIFEST_SUITE.to_string(),
            compliance_attestation_suite: COMPLIANCE_ATTESTATION_SUITE.to_string(),
            denomination_map_suite: DENOMINATION_MAP_SUITE.to_string(),
            covenant_hook_suite: COVENANT_HOOK_SUITE.to_string(),
            reserve_attestation_suite: RESERVE_ATTESTATION_SUITE.to_string(),
            privacy_fence_suite: PRIVACY_FENCE_SUITE.to_string(),
            low_fee_sponsorship_suite: LOW_FEE_SPONSORSHIP_SUITE.to_string(),
            slashing_evidence_suite: SLASHING_EVIDENCE_SUITE.to_string(),
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            batch_privacy_set_size: DEFAULT_BATCH_PRIVACY_SET_SIZE,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            listing_ttl_blocks: DEFAULT_LISTING_TTL_BLOCKS,
            manifest_ttl_blocks: DEFAULT_MANIFEST_TTL_BLOCKS,
            attestation_ttl_blocks: DEFAULT_ATTESTATION_TTL_BLOCKS,
            denomination_ttl_blocks: DEFAULT_DENOMINATION_TTL_BLOCKS,
            fee_schedule_ttl_blocks: DEFAULT_FEE_SCHEDULE_TTL_BLOCKS,
            proof_requirement_ttl_blocks: DEFAULT_PROOF_REQUIREMENT_TTL_BLOCKS,
            hook_ttl_blocks: DEFAULT_HOOK_TTL_BLOCKS,
            reserve_ttl_blocks: DEFAULT_RESERVE_TTL_BLOCKS,
            fence_ttl_blocks: DEFAULT_FENCE_TTL_BLOCKS,
            sponsor_ttl_blocks: DEFAULT_SPONSOR_TTL_BLOCKS,
            slash_challenge_ttl_blocks: DEFAULT_SLASH_CHALLENGE_TTL_BLOCKS,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            max_sponsor_fee_bps: DEFAULT_MAX_SPONSOR_FEE_BPS,
            target_rebate_bps: DEFAULT_TARGET_REBATE_BPS,
            reserve_safety_bps: DEFAULT_RESERVE_SAFETY_BPS,
            slash_bps: DEFAULT_SLASH_BPS,
            max_asset_listings: DEFAULT_MAX_ASSET_LISTINGS,
            max_manifests: DEFAULT_MAX_MANIFESTS,
            max_attestations: DEFAULT_MAX_ATTESTATIONS,
            max_denomination_maps: DEFAULT_MAX_DENOMINATION_MAPS,
            max_fee_policies: DEFAULT_MAX_FEE_POLICIES,
            max_proof_requirements: DEFAULT_MAX_PROOF_REQUIREMENTS,
            max_covenant_hooks: DEFAULT_MAX_COVENANT_HOOKS,
            max_reserve_attestations: DEFAULT_MAX_RESERVE_ATTESTATIONS,
            max_privacy_fences: DEFAULT_MAX_PRIVACY_FENCES,
            max_sponsorships: DEFAULT_MAX_SPONSORSHIPS,
            max_slashing_evidence: DEFAULT_MAX_SLASHING_EVIDENCE,
            max_events: DEFAULT_MAX_EVENTS,
        }
    }

    pub fn record(&self) -> Value {
        json!(self)
    }

    pub fn validate(&self) -> Result<()> {
        ensure_eq("config chain id", &self.chain_id, CHAIN_ID)?;
        ensure_eq("config protocol", &self.protocol_version, PROTOCOL_VERSION)?;
        ensure_bps("max user fee", self.max_user_fee_bps)?;
        ensure_bps("max sponsor fee", self.max_sponsor_fee_bps)?;
        ensure_bps("target rebate", self.target_rebate_bps)?;
        ensure(
            self.reserve_safety_bps >= MAX_BPS,
            "reserve safety below par",
        )?;
        ensure_nonzero("min privacy set size", self.min_privacy_set_size)?;
        ensure_nonzero("batch privacy set size", self.batch_privacy_set_size)?;
        ensure(
            self.min_pq_security_bits >= DEFAULT_MIN_PQ_SECURITY_BITS,
            "PQ security bits below runtime floor",
        )?;
        ensure_nonempty("registry id", &self.registry_id)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub asset_listing_count: u64,
    pub manifest_count: u64,
    pub compliance_attestation_count: u64,
    pub denomination_map_count: u64,
    pub fee_policy_count: u64,
    pub proof_requirement_count: u64,
    pub covenant_hook_count: u64,
    pub reserve_attestation_count: u64,
    pub privacy_fence_count: u64,
    pub consumed_nullifier_count: u64,
    pub sponsorship_count: u64,
    pub slashing_evidence_count: u64,
    pub event_count: u64,
}

impl Counters {
    pub fn zero() -> Self {
        Self {
            asset_listing_count: 0,
            manifest_count: 0,
            compliance_attestation_count: 0,
            denomination_map_count: 0,
            fee_policy_count: 0,
            proof_requirement_count: 0,
            covenant_hook_count: 0,
            reserve_attestation_count: 0,
            privacy_fence_count: 0,
            consumed_nullifier_count: 0,
            sponsorship_count: 0,
            slashing_evidence_count: 0,
            event_count: 0,
        }
    }

    pub fn record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub counters_root: String,
    pub asset_listings_root: String,
    pub manifests_root: String,
    pub compliance_attestations_root: String,
    pub denomination_maps_root: String,
    pub fee_policies_root: String,
    pub proof_requirements_root: String,
    pub covenant_hooks_root: String,
    pub reserve_attestations_root: String,
    pub privacy_fences_root: String,
    pub consumed_nullifiers_root: String,
    pub sponsorships_root: String,
    pub slashing_evidence_root: String,
    pub events_root: String,
    pub asset_to_manifests_index_root: String,
    pub asset_to_attestations_index_root: String,
    pub asset_to_reserves_index_root: String,
    pub chain_to_denominations_index_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn empty() -> Self {
        let empty = root_from_record("PQL2-BRIDGE-ASSET-REGISTRY-EMPTY", &json!({}));
        Self {
            config_root: empty.clone(),
            counters_root: empty.clone(),
            asset_listings_root: empty.clone(),
            manifests_root: empty.clone(),
            compliance_attestations_root: empty.clone(),
            denomination_maps_root: empty.clone(),
            fee_policies_root: empty.clone(),
            proof_requirements_root: empty.clone(),
            covenant_hooks_root: empty.clone(),
            reserve_attestations_root: empty.clone(),
            privacy_fences_root: empty.clone(),
            consumed_nullifiers_root: empty.clone(),
            sponsorships_root: empty.clone(),
            slashing_evidence_root: empty.clone(),
            events_root: empty.clone(),
            asset_to_manifests_index_root: empty.clone(),
            asset_to_attestations_index_root: empty.clone(),
            asset_to_reserves_index_root: empty.clone(),
            chain_to_denominations_index_root: empty.clone(),
            state_root: empty,
        }
    }

    pub fn record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ShieldedAssetListing {
    pub asset_id: String,
    pub symbol_commitment: String,
    pub metadata_commitment: String,
    pub issuer_commitment: String,
    pub asset_kind: AssetKind,
    pub status: ListingStatus,
    pub native_chain: ChainKind,
    pub native_chain_asset_commitment: String,
    pub decimals: u8,
    pub supply_cap_commitment: String,
    pub circulating_supply_root: String,
    pub authority_root: String,
    pub privacy_policy_root: String,
    pub compliance_policy_root: String,
    pub denomination_root: String,
    pub bridge_adapter_root: String,
    pub covenant_hook_root: String,
    pub reserve_policy_root: String,
    pub pq_attestation_root: String,
    pub registered_at_height: u64,
    pub updated_at_height: u64,
    pub expires_at_height: u64,
    pub nonce: String,
}

impl ShieldedAssetListing {
    pub fn record(&self) -> Value {
        json!({
            "asset_id": self.asset_id,
            "symbol_commitment": self.symbol_commitment,
            "metadata_commitment": self.metadata_commitment,
            "issuer_commitment": self.issuer_commitment,
            "asset_kind": self.asset_kind.as_str(),
            "status": self.status.as_str(),
            "native_chain": self.native_chain.as_str(),
            "native_chain_asset_commitment": self.native_chain_asset_commitment,
            "decimals": self.decimals,
            "supply_cap_commitment": self.supply_cap_commitment,
            "circulating_supply_root": self.circulating_supply_root,
            "authority_root": self.authority_root,
            "privacy_policy_root": self.privacy_policy_root,
            "compliance_policy_root": self.compliance_policy_root,
            "denomination_root": self.denomination_root,
            "bridge_adapter_root": self.bridge_adapter_root,
            "covenant_hook_root": self.covenant_hook_root,
            "reserve_policy_root": self.reserve_policy_root,
            "pq_attestation_root": self.pq_attestation_root,
            "registered_at_height": self.registered_at_height,
            "updated_at_height": self.updated_at_height,
            "expires_at_height": self.expires_at_height,
            "nonce": self.nonce,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BridgeMintBurnManifest {
    pub manifest_id: String,
    pub asset_id: String,
    pub action: BridgeAction,
    pub status: ManifestStatus,
    pub source_chain: ChainKind,
    pub destination_chain: ChainKind,
    pub source_asset_commitment: String,
    pub destination_asset_commitment: String,
    pub amount_commitment_root: String,
    pub denomination_map_id: String,
    pub input_nullifier_root: String,
    pub output_commitment_root: String,
    pub reserve_attestation_id: String,
    pub compliance_attestation_id: String,
    pub proof_requirement_root: String,
    pub covenant_hook_root: String,
    pub fee_policy_id: String,
    pub sponsorship_id: String,
    pub encrypted_recipient_root: String,
    pub bridge_adapter_transcript_root: String,
    pub pq_signature_root: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub finalized_at_height: u64,
    pub nonce: String,
}

impl BridgeMintBurnManifest {
    pub fn record(&self) -> Value {
        json!({
            "manifest_id": self.manifest_id,
            "asset_id": self.asset_id,
            "action": self.action.as_str(),
            "status": self.status.as_str(),
            "source_chain": self.source_chain.as_str(),
            "destination_chain": self.destination_chain.as_str(),
            "source_asset_commitment": self.source_asset_commitment,
            "destination_asset_commitment": self.destination_asset_commitment,
            "amount_commitment_root": self.amount_commitment_root,
            "denomination_map_id": self.denomination_map_id,
            "input_nullifier_root": self.input_nullifier_root,
            "output_commitment_root": self.output_commitment_root,
            "reserve_attestation_id": self.reserve_attestation_id,
            "compliance_attestation_id": self.compliance_attestation_id,
            "proof_requirement_root": self.proof_requirement_root,
            "covenant_hook_root": self.covenant_hook_root,
            "fee_policy_id": self.fee_policy_id,
            "sponsorship_id": self.sponsorship_id,
            "encrypted_recipient_root": self.encrypted_recipient_root,
            "bridge_adapter_transcript_root": self.bridge_adapter_transcript_root,
            "pq_signature_root": self.pq_signature_root,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "finalized_at_height": self.finalized_at_height,
            "nonce": self.nonce,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivateComplianceAttestation {
    pub attestation_id: String,
    pub asset_id: String,
    pub manifest_id: String,
    pub attester_commitment: String,
    pub kind: ComplianceKind,
    pub verdict: ComplianceVerdict,
    pub policy_root: String,
    pub disclosure_root: String,
    pub jurisdiction_root: String,
    pub watchlist_nonmembership_root: String,
    pub proof_transcript_root: String,
    pub pq_signature_root: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub issued_at_height: u64,
    pub expires_at_height: u64,
    pub nonce: String,
}

impl PrivateComplianceAttestation {
    pub fn record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "asset_id": self.asset_id,
            "manifest_id": self.manifest_id,
            "attester_commitment": self.attester_commitment,
            "kind": self.kind.as_str(),
            "verdict": self.verdict.as_str(),
            "policy_root": self.policy_root,
            "disclosure_root": self.disclosure_root,
            "jurisdiction_root": self.jurisdiction_root,
            "watchlist_nonmembership_root": self.watchlist_nonmembership_root,
            "proof_transcript_root": self.proof_transcript_root,
            "pq_signature_root": self.pq_signature_root,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "issued_at_height": self.issued_at_height,
            "expires_at_height": self.expires_at_height,
            "nonce": self.nonce,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CrossChainDenominationMap {
    pub map_id: String,
    pub asset_id: String,
    pub source_chain: ChainKind,
    pub destination_chain: ChainKind,
    pub source_denomination: DenominationKind,
    pub destination_denomination: DenominationKind,
    pub source_decimals: u8,
    pub destination_decimals: u8,
    pub conversion_rate_commitment: String,
    pub rounding_policy_root: String,
    pub dust_limit_commitment: String,
    pub oracle_attestation_root: String,
    pub status: ListingStatus,
    pub activated_at_height: u64,
    pub expires_at_height: u64,
    pub nonce: String,
}

impl CrossChainDenominationMap {
    pub fn record(&self) -> Value {
        json!({
            "map_id": self.map_id,
            "asset_id": self.asset_id,
            "source_chain": self.source_chain.as_str(),
            "destination_chain": self.destination_chain.as_str(),
            "source_denomination": self.source_denomination.as_str(),
            "destination_denomination": self.destination_denomination.as_str(),
            "source_decimals": self.source_decimals,
            "destination_decimals": self.destination_decimals,
            "conversion_rate_commitment": self.conversion_rate_commitment,
            "rounding_policy_root": self.rounding_policy_root,
            "dust_limit_commitment": self.dust_limit_commitment,
            "oracle_attestation_root": self.oracle_attestation_root,
            "status": self.status.as_str(),
            "activated_at_height": self.activated_at_height,
            "expires_at_height": self.expires_at_height,
            "nonce": self.nonce,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FeePolicySchedule {
    pub fee_policy_id: String,
    pub asset_id: String,
    pub lane: FeeLane,
    pub fee_asset_id: String,
    pub base_fee_bps: u64,
    pub max_user_fee_bps: u64,
    pub max_sponsor_fee_bps: u64,
    pub target_rebate_bps: u64,
    pub volatility_band_root: String,
    pub congestion_curve_root: String,
    pub sponsor_priority_root: String,
    pub privacy_budget_root: String,
    pub effective_at_height: u64,
    pub expires_at_height: u64,
    pub nonce: String,
}

impl FeePolicySchedule {
    pub fn record(&self) -> Value {
        json!({
            "fee_policy_id": self.fee_policy_id,
            "asset_id": self.asset_id,
            "lane": self.lane.as_str(),
            "fee_asset_id": self.fee_asset_id,
            "base_fee_bps": self.base_fee_bps,
            "max_user_fee_bps": self.max_user_fee_bps,
            "max_sponsor_fee_bps": self.max_sponsor_fee_bps,
            "target_rebate_bps": self.target_rebate_bps,
            "volatility_band_root": self.volatility_band_root,
            "congestion_curve_root": self.congestion_curve_root,
            "sponsor_priority_root": self.sponsor_priority_root,
            "privacy_budget_root": self.privacy_budget_root,
            "effective_at_height": self.effective_at_height,
            "expires_at_height": self.expires_at_height,
            "nonce": self.nonce,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProofRequirement {
    pub requirement_id: String,
    pub asset_id: String,
    pub action: BridgeAction,
    pub kind: ProofRequirementKind,
    pub proof_system: ProofSystem,
    pub verifier_key_root: String,
    pub public_input_schema_root: String,
    pub witness_hint_root: String,
    pub recursion_policy_root: String,
    pub min_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub required: bool,
    pub effective_at_height: u64,
    pub expires_at_height: u64,
    pub nonce: String,
}

impl ProofRequirement {
    pub fn record(&self) -> Value {
        json!({
            "requirement_id": self.requirement_id,
            "asset_id": self.asset_id,
            "action": self.action.as_str(),
            "kind": self.kind.as_str(),
            "proof_system": self.proof_system.as_str(),
            "verifier_key_root": self.verifier_key_root,
            "public_input_schema_root": self.public_input_schema_root,
            "witness_hint_root": self.witness_hint_root,
            "recursion_policy_root": self.recursion_policy_root,
            "min_privacy_set_size": self.min_privacy_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
            "required": self.required,
            "effective_at_height": self.effective_at_height,
            "expires_at_height": self.expires_at_height,
            "nonce": self.nonce,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TokenCovenantHook {
    pub hook_id: String,
    pub asset_id: String,
    pub hook_kind: HookKind,
    pub status: HookStatus,
    pub contract_commitment: String,
    pub entrypoint_commitment: String,
    pub authorization_root: String,
    pub call_policy_root: String,
    pub gas_policy_root: String,
    pub rollback_policy_root: String,
    pub pq_signature_root: String,
    pub registered_at_height: u64,
    pub expires_at_height: u64,
    pub nonce: String,
}

impl TokenCovenantHook {
    pub fn record(&self) -> Value {
        json!({
            "hook_id": self.hook_id,
            "asset_id": self.asset_id,
            "hook_kind": self.hook_kind.as_str(),
            "status": self.status.as_str(),
            "contract_commitment": self.contract_commitment,
            "entrypoint_commitment": self.entrypoint_commitment,
            "authorization_root": self.authorization_root,
            "call_policy_root": self.call_policy_root,
            "gas_policy_root": self.gas_policy_root,
            "rollback_policy_root": self.rollback_policy_root,
            "pq_signature_root": self.pq_signature_root,
            "registered_at_height": self.registered_at_height,
            "expires_at_height": self.expires_at_height,
            "nonce": self.nonce,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReserveAttestation {
    pub reserve_attestation_id: String,
    pub asset_id: String,
    pub reserve_chain: ChainKind,
    pub custodian_commitment: String,
    pub reserve_commitment_root: String,
    pub liability_commitment_root: String,
    pub coverage_bps: u64,
    pub reserve_safety_bps: u64,
    pub oracle_transcript_root: String,
    pub auditor_committee_root: String,
    pub pq_signature_root: String,
    pub status: ReserveStatus,
    pub attested_at_height: u64,
    pub expires_at_height: u64,
    pub nonce: String,
}

impl ReserveAttestation {
    pub fn record(&self) -> Value {
        json!({
            "reserve_attestation_id": self.reserve_attestation_id,
            "asset_id": self.asset_id,
            "reserve_chain": self.reserve_chain.as_str(),
            "custodian_commitment": self.custodian_commitment,
            "reserve_commitment_root": self.reserve_commitment_root,
            "liability_commitment_root": self.liability_commitment_root,
            "coverage_bps": self.coverage_bps,
            "reserve_safety_bps": self.reserve_safety_bps,
            "oracle_transcript_root": self.oracle_transcript_root,
            "auditor_committee_root": self.auditor_committee_root,
            "pq_signature_root": self.pq_signature_root,
            "status": self.status.as_str(),
            "attested_at_height": self.attested_at_height,
            "expires_at_height": self.expires_at_height,
            "nonce": self.nonce,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivacyNullifierFence {
    pub fence_id: String,
    pub asset_id: String,
    pub subject_id: String,
    pub fence_kind: FenceKind,
    pub nullifier_root: String,
    pub commitment_root: String,
    pub replay_domain: String,
    pub view_tag_root: String,
    pub consumed: bool,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub nonce: String,
}

impl PrivacyNullifierFence {
    pub fn record(&self) -> Value {
        json!({
            "fence_id": self.fence_id,
            "asset_id": self.asset_id,
            "subject_id": self.subject_id,
            "fence_kind": self.fence_kind.as_str(),
            "nullifier_root": self.nullifier_root,
            "commitment_root": self.commitment_root,
            "replay_domain": self.replay_domain,
            "view_tag_root": self.view_tag_root,
            "consumed": self.consumed,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "nonce": self.nonce,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LowFeeSponsorship {
    pub sponsorship_id: String,
    pub sponsor_commitment: String,
    pub asset_id: String,
    pub manifest_id: String,
    pub fee_policy_id: String,
    pub fee_asset_id: String,
    pub max_fee_units: u128,
    pub reserved_fee_units: u128,
    pub spent_fee_units: u128,
    pub rebate_bps: u64,
    pub privacy_budget_root: String,
    pub claim_nullifier_root: String,
    pub status: SponsorshipStatus,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub nonce: String,
}

impl LowFeeSponsorship {
    pub fn record(&self) -> Value {
        json!({
            "sponsorship_id": self.sponsorship_id,
            "sponsor_commitment": self.sponsor_commitment,
            "asset_id": self.asset_id,
            "manifest_id": self.manifest_id,
            "fee_policy_id": self.fee_policy_id,
            "fee_asset_id": self.fee_asset_id,
            "max_fee_units": self.max_fee_units,
            "reserved_fee_units": self.reserved_fee_units,
            "spent_fee_units": self.spent_fee_units,
            "rebate_bps": self.rebate_bps,
            "privacy_budget_root": self.privacy_budget_root,
            "claim_nullifier_root": self.claim_nullifier_root,
            "status": self.status.as_str(),
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "nonce": self.nonce,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SlashingEvidence {
    pub evidence_id: String,
    pub accused_commitment: String,
    pub asset_id: String,
    pub manifest_id: String,
    pub reason: SlashingReason,
    pub status: EvidenceStatus,
    pub evidence_root: String,
    pub conflicting_record_root: String,
    pub challenger_commitment: String,
    pub slash_amount_commitment: String,
    pub slash_bps: u64,
    pub evidence_nullifier_root: String,
    pub pq_signature_root: String,
    pub submitted_at_height: u64,
    pub challenge_expires_at_height: u64,
    pub nonce: String,
}

impl SlashingEvidence {
    pub fn record(&self) -> Value {
        json!({
            "evidence_id": self.evidence_id,
            "accused_commitment": self.accused_commitment,
            "asset_id": self.asset_id,
            "manifest_id": self.manifest_id,
            "reason": self.reason.as_str(),
            "status": self.status.as_str(),
            "evidence_root": self.evidence_root,
            "conflicting_record_root": self.conflicting_record_root,
            "challenger_commitment": self.challenger_commitment,
            "slash_amount_commitment": self.slash_amount_commitment,
            "slash_bps": self.slash_bps,
            "evidence_nullifier_root": self.evidence_nullifier_root,
            "pq_signature_root": self.pq_signature_root,
            "submitted_at_height": self.submitted_at_height,
            "challenge_expires_at_height": self.challenge_expires_at_height,
            "nonce": self.nonce,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RuntimeEvent {
    pub event_id: String,
    pub operation: OperationKind,
    pub object_id: String,
    pub asset_id: String,
    pub root: String,
    pub height: u64,
    pub ordinal: u64,
}

impl RuntimeEvent {
    pub fn record(&self) -> Value {
        json!({
            "event_id": self.event_id,
            "operation": self.operation.as_str(),
            "object_id": self.object_id,
            "asset_id": self.asset_id,
            "root": self.root,
            "height": self.height,
            "ordinal": self.ordinal,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ListAssetRequest {
    pub symbol_commitment: String,
    pub metadata_commitment: String,
    pub issuer_commitment: String,
    pub asset_kind: AssetKind,
    pub native_chain: ChainKind,
    pub native_chain_asset_commitment: String,
    pub decimals: u8,
    pub supply_cap_commitment: String,
    pub circulating_supply_root: String,
    pub authority_root: String,
    pub privacy_policy_root: String,
    pub compliance_policy_root: String,
    pub denomination_root: String,
    pub bridge_adapter_root: String,
    pub covenant_hook_root: String,
    pub reserve_policy_root: String,
    pub pq_attestation_root: String,
    pub nonce: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublishManifestRequest {
    pub asset_id: String,
    pub action: BridgeAction,
    pub source_chain: ChainKind,
    pub destination_chain: ChainKind,
    pub source_asset_commitment: String,
    pub destination_asset_commitment: String,
    pub amount_commitment_root: String,
    pub denomination_map_id: String,
    pub input_nullifier_root: String,
    pub output_commitment_root: String,
    pub reserve_attestation_id: String,
    pub compliance_attestation_id: String,
    pub proof_requirement_root: String,
    pub covenant_hook_root: String,
    pub fee_policy_id: String,
    pub sponsorship_id: String,
    pub encrypted_recipient_root: String,
    pub bridge_adapter_transcript_root: String,
    pub pq_signature_root: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub nonce: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AttestComplianceRequest {
    pub asset_id: String,
    pub manifest_id: String,
    pub attester_commitment: String,
    pub kind: ComplianceKind,
    pub verdict: ComplianceVerdict,
    pub policy_root: String,
    pub disclosure_root: String,
    pub jurisdiction_root: String,
    pub watchlist_nonmembership_root: String,
    pub proof_transcript_root: String,
    pub pq_signature_root: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub nonce: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MapDenominationRequest {
    pub asset_id: String,
    pub source_chain: ChainKind,
    pub destination_chain: ChainKind,
    pub source_denomination: DenominationKind,
    pub destination_denomination: DenominationKind,
    pub source_decimals: u8,
    pub destination_decimals: u8,
    pub conversion_rate_commitment: String,
    pub rounding_policy_root: String,
    pub dust_limit_commitment: String,
    pub oracle_attestation_root: String,
    pub nonce: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ScheduleFeePolicyRequest {
    pub asset_id: String,
    pub lane: FeeLane,
    pub fee_asset_id: String,
    pub base_fee_bps: u64,
    pub max_user_fee_bps: u64,
    pub max_sponsor_fee_bps: u64,
    pub target_rebate_bps: u64,
    pub volatility_band_root: String,
    pub congestion_curve_root: String,
    pub sponsor_priority_root: String,
    pub privacy_budget_root: String,
    pub nonce: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AddProofRequirementRequest {
    pub asset_id: String,
    pub action: BridgeAction,
    pub kind: ProofRequirementKind,
    pub proof_system: ProofSystem,
    pub verifier_key_root: String,
    pub public_input_schema_root: String,
    pub witness_hint_root: String,
    pub recursion_policy_root: String,
    pub min_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub required: bool,
    pub nonce: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RegisterHookRequest {
    pub asset_id: String,
    pub hook_kind: HookKind,
    pub contract_commitment: String,
    pub entrypoint_commitment: String,
    pub authorization_root: String,
    pub call_policy_root: String,
    pub gas_policy_root: String,
    pub rollback_policy_root: String,
    pub pq_signature_root: String,
    pub nonce: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AttestReserveRequest {
    pub asset_id: String,
    pub reserve_chain: ChainKind,
    pub custodian_commitment: String,
    pub reserve_commitment_root: String,
    pub liability_commitment_root: String,
    pub coverage_bps: u64,
    pub oracle_transcript_root: String,
    pub auditor_committee_root: String,
    pub pq_signature_root: String,
    pub nonce: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OpenFenceRequest {
    pub asset_id: String,
    pub subject_id: String,
    pub fence_kind: FenceKind,
    pub nullifier_root: String,
    pub commitment_root: String,
    pub view_tag_root: String,
    pub consumed: bool,
    pub nonce: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SponsorFeeRequest {
    pub sponsor_commitment: String,
    pub asset_id: String,
    pub manifest_id: String,
    pub fee_policy_id: String,
    pub fee_asset_id: String,
    pub max_fee_units: u128,
    pub reserved_fee_units: u128,
    pub privacy_budget_root: String,
    pub claim_nullifier_root: String,
    pub nonce: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SubmitSlashingEvidenceRequest {
    pub accused_commitment: String,
    pub asset_id: String,
    pub manifest_id: String,
    pub reason: SlashingReason,
    pub evidence_root: String,
    pub conflicting_record_root: String,
    pub challenger_commitment: String,
    pub slash_amount_commitment: String,
    pub evidence_nullifier_root: String,
    pub pq_signature_root: String,
    pub nonce: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublicRecord {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub registry_id: String,
    pub height: u64,
    pub roots: Roots,
    pub counters: Counters,
}

impl PublicRecord {
    pub fn record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub height: u64,
    pub counters: Counters,
    pub roots: Roots,
    pub asset_listings: BTreeMap<String, ShieldedAssetListing>,
    pub manifests: BTreeMap<String, BridgeMintBurnManifest>,
    pub compliance_attestations: BTreeMap<String, PrivateComplianceAttestation>,
    pub denomination_maps: BTreeMap<String, CrossChainDenominationMap>,
    pub fee_policies: BTreeMap<String, FeePolicySchedule>,
    pub proof_requirements: BTreeMap<String, ProofRequirement>,
    pub covenant_hooks: BTreeMap<String, TokenCovenantHook>,
    pub reserve_attestations: BTreeMap<String, ReserveAttestation>,
    pub privacy_fences: BTreeMap<String, PrivacyNullifierFence>,
    pub consumed_nullifiers: BTreeSet<String>,
    pub sponsorships: BTreeMap<String, LowFeeSponsorship>,
    pub slashing_evidence: BTreeMap<String, SlashingEvidence>,
    pub events: BTreeMap<String, RuntimeEvent>,
    pub asset_to_manifests: BTreeMap<String, BTreeSet<String>>,
    pub asset_to_attestations: BTreeMap<String, BTreeSet<String>>,
    pub asset_to_reserves: BTreeMap<String, BTreeSet<String>>,
    pub chain_to_denominations: BTreeMap<String, BTreeSet<String>>,
}

impl State {
    pub fn new(config: Config, height: u64) -> Result<Self> {
        config.validate()?;
        let mut state = Self {
            config,
            height,
            counters: Counters::zero(),
            roots: Roots::empty(),
            asset_listings: BTreeMap::new(),
            manifests: BTreeMap::new(),
            compliance_attestations: BTreeMap::new(),
            denomination_maps: BTreeMap::new(),
            fee_policies: BTreeMap::new(),
            proof_requirements: BTreeMap::new(),
            covenant_hooks: BTreeMap::new(),
            reserve_attestations: BTreeMap::new(),
            privacy_fences: BTreeMap::new(),
            consumed_nullifiers: BTreeSet::new(),
            sponsorships: BTreeMap::new(),
            slashing_evidence: BTreeMap::new(),
            events: BTreeMap::new(),
            asset_to_manifests: BTreeMap::new(),
            asset_to_attestations: BTreeMap::new(),
            asset_to_reserves: BTreeMap::new(),
            chain_to_denominations: BTreeMap::new(),
        };
        state.refresh_roots();
        Ok(state)
    }

    pub fn devnet() -> Result<Self> {
        let mut state = Self::new(Config::devnet(), DEVNET_HEIGHT)?;
        let asset = state.list_asset(devnet_asset_request(
            "wrapped-xmr",
            AssetKind::WrappedMonero,
            1,
        ))?;
        let denom = state.map_denomination(devnet_denomination_request(&asset.asset_id, 2))?;
        let fee = state.schedule_fee_policy(devnet_fee_policy_request(&asset.asset_id, 3))?;
        let proof =
            state.add_proof_requirement(devnet_proof_requirement_request(&asset.asset_id, 4))?;
        let hook = state.register_hook(devnet_hook_request(&asset.asset_id, 5))?;
        let reserve = state.attest_reserve(devnet_reserve_request(&asset.asset_id, 6))?;
        let compliance =
            state.attest_compliance(devnet_compliance_request(&asset.asset_id, "", 7))?;
        let sponsor = state.sponsor_fee(devnet_sponsorship_request(
            &asset.asset_id,
            "",
            &fee.fee_policy_id,
            8,
        ))?;
        let manifest = state.publish_manifest(devnet_manifest_request(
            &asset.asset_id,
            &denom.map_id,
            &reserve.reserve_attestation_id,
            &compliance.attestation_id,
            &proof.requirement_id,
            &hook.hook_id,
            &fee.fee_policy_id,
            &sponsor.sponsorship_id,
            9,
        ))?;
        state.open_fence(devnet_fence_request(
            &asset.asset_id,
            &manifest.manifest_id,
            FenceKind::BridgeReplay,
            true,
            10,
        ))?;
        state.submit_slashing_evidence(devnet_slashing_request(
            &asset.asset_id,
            &manifest.manifest_id,
            11,
        ))?;

        let stable = state.list_asset(devnet_asset_request(
            "private-usd",
            AssetKind::PrivateStableAsset,
            12,
        ))?;
        let stable_denom =
            state.map_denomination(devnet_denomination_request(&stable.asset_id, 13))?;
        let stable_fee =
            state.schedule_fee_policy(devnet_fee_policy_request(&stable.asset_id, 14))?;
        let stable_proof =
            state.add_proof_requirement(devnet_proof_requirement_request(&stable.asset_id, 15))?;
        let stable_reserve = state.attest_reserve(devnet_reserve_request(&stable.asset_id, 16))?;
        let stable_compliance =
            state.attest_compliance(devnet_compliance_request(&stable.asset_id, "", 17))?;
        let stable_sponsor = state.sponsor_fee(devnet_sponsorship_request(
            &stable.asset_id,
            "",
            &stable_fee.fee_policy_id,
            18,
        ))?;
        state.publish_manifest(devnet_manifest_request(
            &stable.asset_id,
            &stable_denom.map_id,
            &stable_reserve.reserve_attestation_id,
            &stable_compliance.attestation_id,
            &stable_proof.requirement_id,
            "",
            &stable_fee.fee_policy_id,
            &stable_sponsor.sponsorship_id,
            19,
        ))?;
        state.refresh_roots();
        Ok(state)
    }

    pub fn public_record(&self) -> PublicRecord {
        PublicRecord {
            chain_id: self.config.chain_id.clone(),
            protocol_version: self.config.protocol_version.clone(),
            schema_version: self.config.schema_version,
            registry_id: self.config.registry_id.clone(),
            height: self.height,
            roots: self.roots.clone(),
            counters: self.counters.clone(),
        }
    }

    pub fn state_root(&self) -> String {
        state_root_from_public_record(&self.public_record())
    }

    pub fn refresh_roots(&mut self) {
        let config_root =
            root_from_record("PQL2-BRIDGE-ASSET-REGISTRY-CONFIG", &self.config.record());
        let counters_root = root_from_record(
            "PQL2-BRIDGE-ASSET-REGISTRY-COUNTERS",
            &self.counters.record(),
        );
        let asset_listings_root = record_root(
            "PQL2-BRIDGE-ASSET-REGISTRY-ASSET-LISTINGS",
            self.asset_listings.values(),
        );
        let manifests_root = record_root(
            "PQL2-BRIDGE-ASSET-REGISTRY-MANIFESTS",
            self.manifests.values(),
        );
        let compliance_attestations_root = record_root(
            "PQL2-BRIDGE-ASSET-REGISTRY-COMPLIANCE-ATTESTATIONS",
            self.compliance_attestations.values(),
        );
        let denomination_maps_root = record_root(
            "PQL2-BRIDGE-ASSET-REGISTRY-DENOMINATION-MAPS",
            self.denomination_maps.values(),
        );
        let fee_policies_root = record_root(
            "PQL2-BRIDGE-ASSET-REGISTRY-FEE-POLICIES",
            self.fee_policies.values(),
        );
        let proof_requirements_root = record_root(
            "PQL2-BRIDGE-ASSET-REGISTRY-PROOF-REQUIREMENTS",
            self.proof_requirements.values(),
        );
        let covenant_hooks_root = record_root(
            "PQL2-BRIDGE-ASSET-REGISTRY-COVENANT-HOOKS",
            self.covenant_hooks.values(),
        );
        let reserve_attestations_root = record_root(
            "PQL2-BRIDGE-ASSET-REGISTRY-RESERVE-ATTESTATIONS",
            self.reserve_attestations.values(),
        );
        let privacy_fences_root = record_root(
            "PQL2-BRIDGE-ASSET-REGISTRY-PRIVACY-FENCES",
            self.privacy_fences.values(),
        );
        let consumed_nullifiers_root = set_root(
            "PQL2-BRIDGE-ASSET-REGISTRY-CONSUMED-NULLIFIERS",
            &self.consumed_nullifiers,
        );
        let sponsorships_root = record_root(
            "PQL2-BRIDGE-ASSET-REGISTRY-SPONSORSHIPS",
            self.sponsorships.values(),
        );
        let slashing_evidence_root = record_root(
            "PQL2-BRIDGE-ASSET-REGISTRY-SLASHING-EVIDENCE",
            self.slashing_evidence.values(),
        );
        let events_root = record_root("PQL2-BRIDGE-ASSET-REGISTRY-EVENTS", self.events.values());
        let asset_to_manifests_index_root = index_root(
            "PQL2-BRIDGE-ASSET-REGISTRY-ASSET-MANIFEST-INDEX",
            &self.asset_to_manifests,
        );
        let asset_to_attestations_index_root = index_root(
            "PQL2-BRIDGE-ASSET-REGISTRY-ASSET-ATTESTATION-INDEX",
            &self.asset_to_attestations,
        );
        let asset_to_reserves_index_root = index_root(
            "PQL2-BRIDGE-ASSET-REGISTRY-ASSET-RESERVE-INDEX",
            &self.asset_to_reserves,
        );
        let chain_to_denominations_index_root = index_root(
            "PQL2-BRIDGE-ASSET-REGISTRY-CHAIN-DENOMINATION-INDEX",
            &self.chain_to_denominations,
        );
        let state_root = root_from_record(
            "PQL2-BRIDGE-ASSET-REGISTRY-STATE-ROOT",
            &json!({
                "chain_id": CHAIN_ID,
                "protocol_version": PROTOCOL_VERSION,
                "height": self.height,
                "config_root": config_root,
                "counters_root": counters_root,
                "asset_listings_root": asset_listings_root,
                "manifests_root": manifests_root,
                "compliance_attestations_root": compliance_attestations_root,
                "denomination_maps_root": denomination_maps_root,
                "fee_policies_root": fee_policies_root,
                "proof_requirements_root": proof_requirements_root,
                "covenant_hooks_root": covenant_hooks_root,
                "reserve_attestations_root": reserve_attestations_root,
                "privacy_fences_root": privacy_fences_root,
                "consumed_nullifiers_root": consumed_nullifiers_root,
                "sponsorships_root": sponsorships_root,
                "slashing_evidence_root": slashing_evidence_root,
                "events_root": events_root,
                "asset_to_manifests_index_root": asset_to_manifests_index_root,
                "asset_to_attestations_index_root": asset_to_attestations_index_root,
                "asset_to_reserves_index_root": asset_to_reserves_index_root,
                "chain_to_denominations_index_root": chain_to_denominations_index_root,
            }),
        );
        self.roots = Roots {
            config_root,
            counters_root,
            asset_listings_root,
            manifests_root,
            compliance_attestations_root,
            denomination_maps_root,
            fee_policies_root,
            proof_requirements_root,
            covenant_hooks_root,
            reserve_attestations_root,
            privacy_fences_root,
            consumed_nullifiers_root,
            sponsorships_root,
            slashing_evidence_root,
            events_root,
            asset_to_manifests_index_root,
            asset_to_attestations_index_root,
            asset_to_reserves_index_root,
            chain_to_denominations_index_root,
            state_root,
        };
    }

    pub fn list_asset(&mut self, request: ListAssetRequest) -> Result<ShieldedAssetListing> {
        ensure_capacity(
            "asset listings",
            self.asset_listings.len(),
            self.config.max_asset_listings,
        )?;
        validate_required_list_asset(&request)?;
        let next = self.counters.asset_listing_count.saturating_add(1);
        let asset_id = asset_listing_id(&request, next);
        ensure_absent(&self.asset_listings, "asset listing", &asset_id)?;
        let listing = ShieldedAssetListing {
            asset_id: asset_id.clone(),
            symbol_commitment: request.symbol_commitment,
            metadata_commitment: request.metadata_commitment,
            issuer_commitment: request.issuer_commitment,
            asset_kind: request.asset_kind,
            status: ListingStatus::Active,
            native_chain: request.native_chain,
            native_chain_asset_commitment: request.native_chain_asset_commitment,
            decimals: request.decimals,
            supply_cap_commitment: request.supply_cap_commitment,
            circulating_supply_root: request.circulating_supply_root,
            authority_root: request.authority_root,
            privacy_policy_root: request.privacy_policy_root,
            compliance_policy_root: request.compliance_policy_root,
            denomination_root: request.denomination_root,
            bridge_adapter_root: request.bridge_adapter_root,
            covenant_hook_root: request.covenant_hook_root,
            reserve_policy_root: request.reserve_policy_root,
            pq_attestation_root: request.pq_attestation_root,
            registered_at_height: self.height,
            updated_at_height: self.height,
            expires_at_height: self.height + self.config.listing_ttl_blocks,
            nonce: request.nonce,
        };
        self.asset_listings
            .insert(asset_id.clone(), listing.clone());
        self.counters.asset_listing_count = next;
        self.push_event(
            OperationKind::ListAsset,
            &asset_id,
            &asset_id,
            &listing.record(),
        )?;
        self.refresh_roots();
        Ok(listing)
    }

    pub fn publish_manifest(
        &mut self,
        request: PublishManifestRequest,
    ) -> Result<BridgeMintBurnManifest> {
        ensure_capacity("manifests", self.manifests.len(), self.config.max_manifests)?;
        validate_required_manifest(&request)?;
        validate_privacy_and_pq(
            request.privacy_set_size,
            request.pq_security_bits,
            &self.config,
        )?;
        self.require_active_asset(&request.asset_id)?;
        if !request.reserve_attestation_id.is_empty() {
            self.require_reserve(&request.reserve_attestation_id)?;
        }
        if !request.compliance_attestation_id.is_empty() {
            self.require_compliance(&request.compliance_attestation_id)?;
        }
        if !request.fee_policy_id.is_empty() {
            self.require_fee_policy(&request.fee_policy_id)?;
        }
        self.insert_consumed_nullifier(&request.input_nullifier_root)?;
        let next = self.counters.manifest_count.saturating_add(1);
        let manifest_id = bridge_manifest_id(&request, next);
        let manifest = BridgeMintBurnManifest {
            manifest_id: manifest_id.clone(),
            asset_id: request.asset_id.clone(),
            action: request.action,
            status: ManifestStatus::Submitted,
            source_chain: request.source_chain,
            destination_chain: request.destination_chain,
            source_asset_commitment: request.source_asset_commitment,
            destination_asset_commitment: request.destination_asset_commitment,
            amount_commitment_root: request.amount_commitment_root,
            denomination_map_id: request.denomination_map_id,
            input_nullifier_root: request.input_nullifier_root,
            output_commitment_root: request.output_commitment_root,
            reserve_attestation_id: request.reserve_attestation_id,
            compliance_attestation_id: request.compliance_attestation_id,
            proof_requirement_root: request.proof_requirement_root,
            covenant_hook_root: request.covenant_hook_root,
            fee_policy_id: request.fee_policy_id,
            sponsorship_id: request.sponsorship_id,
            encrypted_recipient_root: request.encrypted_recipient_root,
            bridge_adapter_transcript_root: request.bridge_adapter_transcript_root,
            pq_signature_root: request.pq_signature_root,
            privacy_set_size: request.privacy_set_size,
            pq_security_bits: request.pq_security_bits,
            opened_at_height: self.height,
            expires_at_height: self.height + self.config.manifest_ttl_blocks,
            finalized_at_height: 0,
            nonce: request.nonce,
        };
        self.manifests.insert(manifest_id.clone(), manifest.clone());
        self.asset_to_manifests
            .entry(request.asset_id.clone())
            .or_default()
            .insert(manifest_id.clone());
        self.counters.manifest_count = next;
        self.push_event(
            OperationKind::PublishManifest,
            &manifest_id,
            &request.asset_id,
            &manifest.record(),
        )?;
        self.refresh_roots();
        Ok(manifest)
    }

    pub fn attest_compliance(
        &mut self,
        request: AttestComplianceRequest,
    ) -> Result<PrivateComplianceAttestation> {
        ensure_capacity(
            "compliance attestations",
            self.compliance_attestations.len(),
            self.config.max_attestations,
        )?;
        validate_required_compliance(&request)?;
        validate_privacy_and_pq(
            request.privacy_set_size,
            request.pq_security_bits,
            &self.config,
        )?;
        self.require_active_asset(&request.asset_id)?;
        ensure(
            request.verdict.permits_manifest(),
            "compliance verdict does not permit bridge manifest",
        )?;
        let next = self.counters.compliance_attestation_count.saturating_add(1);
        let attestation_id = compliance_attestation_id(&request, next);
        let attestation = PrivateComplianceAttestation {
            attestation_id: attestation_id.clone(),
            asset_id: request.asset_id.clone(),
            manifest_id: request.manifest_id,
            attester_commitment: request.attester_commitment,
            kind: request.kind,
            verdict: request.verdict,
            policy_root: request.policy_root,
            disclosure_root: request.disclosure_root,
            jurisdiction_root: request.jurisdiction_root,
            watchlist_nonmembership_root: request.watchlist_nonmembership_root,
            proof_transcript_root: request.proof_transcript_root,
            pq_signature_root: request.pq_signature_root,
            privacy_set_size: request.privacy_set_size,
            pq_security_bits: request.pq_security_bits,
            issued_at_height: self.height,
            expires_at_height: self.height + self.config.attestation_ttl_blocks,
            nonce: request.nonce,
        };
        self.compliance_attestations
            .insert(attestation_id.clone(), attestation.clone());
        self.asset_to_attestations
            .entry(request.asset_id.clone())
            .or_default()
            .insert(attestation_id.clone());
        self.counters.compliance_attestation_count = next;
        self.push_event(
            OperationKind::AttestCompliance,
            &attestation_id,
            &request.asset_id,
            &attestation.record(),
        )?;
        self.refresh_roots();
        Ok(attestation)
    }

    pub fn map_denomination(
        &mut self,
        request: MapDenominationRequest,
    ) -> Result<CrossChainDenominationMap> {
        ensure_capacity(
            "denomination maps",
            self.denomination_maps.len(),
            self.config.max_denomination_maps,
        )?;
        validate_required_denomination(&request)?;
        self.require_active_asset(&request.asset_id)?;
        let next = self.counters.denomination_map_count.saturating_add(1);
        let map_id = denomination_map_id(&request, next);
        let record = CrossChainDenominationMap {
            map_id: map_id.clone(),
            asset_id: request.asset_id.clone(),
            source_chain: request.source_chain,
            destination_chain: request.destination_chain,
            source_denomination: request.source_denomination,
            destination_denomination: request.destination_denomination,
            source_decimals: request.source_decimals,
            destination_decimals: request.destination_decimals,
            conversion_rate_commitment: request.conversion_rate_commitment,
            rounding_policy_root: request.rounding_policy_root,
            dust_limit_commitment: request.dust_limit_commitment,
            oracle_attestation_root: request.oracle_attestation_root,
            status: ListingStatus::Active,
            activated_at_height: self.height,
            expires_at_height: self.height + self.config.denomination_ttl_blocks,
            nonce: request.nonce,
        };
        self.denomination_maps
            .insert(map_id.clone(), record.clone());
        let index_key = format!(
            "{}:{}",
            request.source_chain.as_str(),
            request.destination_chain.as_str()
        );
        self.chain_to_denominations
            .entry(index_key)
            .or_default()
            .insert(map_id.clone());
        self.counters.denomination_map_count = next;
        self.push_event(
            OperationKind::MapDenomination,
            &map_id,
            &request.asset_id,
            &record.record(),
        )?;
        self.refresh_roots();
        Ok(record)
    }

    pub fn schedule_fee_policy(
        &mut self,
        request: ScheduleFeePolicyRequest,
    ) -> Result<FeePolicySchedule> {
        ensure_capacity(
            "fee policies",
            self.fee_policies.len(),
            self.config.max_fee_policies,
        )?;
        validate_required_fee_policy(&request)?;
        validate_bps("base fee", request.base_fee_bps)?;
        validate_bps("max user fee", request.max_user_fee_bps)?;
        validate_bps("max sponsor fee", request.max_sponsor_fee_bps)?;
        validate_bps("target rebate", request.target_rebate_bps)?;
        self.require_active_asset(&request.asset_id)?;
        let next = self.counters.fee_policy_count.saturating_add(1);
        let fee_policy_id = fee_policy_id(&request, next);
        let record = FeePolicySchedule {
            fee_policy_id: fee_policy_id.clone(),
            asset_id: request.asset_id.clone(),
            lane: request.lane,
            fee_asset_id: request.fee_asset_id,
            base_fee_bps: request.base_fee_bps,
            max_user_fee_bps: request.max_user_fee_bps,
            max_sponsor_fee_bps: request.max_sponsor_fee_bps,
            target_rebate_bps: request.target_rebate_bps,
            volatility_band_root: request.volatility_band_root,
            congestion_curve_root: request.congestion_curve_root,
            sponsor_priority_root: request.sponsor_priority_root,
            privacy_budget_root: request.privacy_budget_root,
            effective_at_height: self.height,
            expires_at_height: self.height + self.config.fee_schedule_ttl_blocks,
            nonce: request.nonce,
        };
        self.fee_policies
            .insert(fee_policy_id.clone(), record.clone());
        self.counters.fee_policy_count = next;
        self.push_event(
            OperationKind::ScheduleFeePolicy,
            &fee_policy_id,
            &request.asset_id,
            &record.record(),
        )?;
        self.refresh_roots();
        Ok(record)
    }

    pub fn add_proof_requirement(
        &mut self,
        request: AddProofRequirementRequest,
    ) -> Result<ProofRequirement> {
        ensure_capacity(
            "proof requirements",
            self.proof_requirements.len(),
            self.config.max_proof_requirements,
        )?;
        validate_required_proof_requirement(&request)?;
        ensure(
            request.min_privacy_set_size >= self.config.min_privacy_set_size,
            "proof requirement privacy set below config floor",
        )?;
        ensure(
            request.min_pq_security_bits >= self.config.min_pq_security_bits,
            "proof requirement PQ bits below config floor",
        )?;
        self.require_active_asset(&request.asset_id)?;
        let next = self.counters.proof_requirement_count.saturating_add(1);
        let requirement_id = proof_requirement_id(&request, next);
        let record = ProofRequirement {
            requirement_id: requirement_id.clone(),
            asset_id: request.asset_id.clone(),
            action: request.action,
            kind: request.kind,
            proof_system: request.proof_system,
            verifier_key_root: request.verifier_key_root,
            public_input_schema_root: request.public_input_schema_root,
            witness_hint_root: request.witness_hint_root,
            recursion_policy_root: request.recursion_policy_root,
            min_privacy_set_size: request.min_privacy_set_size,
            min_pq_security_bits: request.min_pq_security_bits,
            required: request.required,
            effective_at_height: self.height,
            expires_at_height: self.height + self.config.proof_requirement_ttl_blocks,
            nonce: request.nonce,
        };
        self.proof_requirements
            .insert(requirement_id.clone(), record.clone());
        self.counters.proof_requirement_count = next;
        self.push_event(
            OperationKind::AddProofRequirement,
            &requirement_id,
            &request.asset_id,
            &record.record(),
        )?;
        self.refresh_roots();
        Ok(record)
    }

    pub fn register_hook(&mut self, request: RegisterHookRequest) -> Result<TokenCovenantHook> {
        ensure_capacity(
            "covenant hooks",
            self.covenant_hooks.len(),
            self.config.max_covenant_hooks,
        )?;
        validate_required_hook(&request)?;
        self.require_active_asset(&request.asset_id)?;
        let next = self.counters.covenant_hook_count.saturating_add(1);
        let hook_id = covenant_hook_id(&request, next);
        let record = TokenCovenantHook {
            hook_id: hook_id.clone(),
            asset_id: request.asset_id.clone(),
            hook_kind: request.hook_kind,
            status: HookStatus::Active,
            contract_commitment: request.contract_commitment,
            entrypoint_commitment: request.entrypoint_commitment,
            authorization_root: request.authorization_root,
            call_policy_root: request.call_policy_root,
            gas_policy_root: request.gas_policy_root,
            rollback_policy_root: request.rollback_policy_root,
            pq_signature_root: request.pq_signature_root,
            registered_at_height: self.height,
            expires_at_height: self.height + self.config.hook_ttl_blocks,
            nonce: request.nonce,
        };
        self.covenant_hooks.insert(hook_id.clone(), record.clone());
        self.counters.covenant_hook_count = next;
        self.push_event(
            OperationKind::RegisterHook,
            &hook_id,
            &request.asset_id,
            &record.record(),
        )?;
        self.refresh_roots();
        Ok(record)
    }

    pub fn attest_reserve(&mut self, request: AttestReserveRequest) -> Result<ReserveAttestation> {
        ensure_capacity(
            "reserve attestations",
            self.reserve_attestations.len(),
            self.config.max_reserve_attestations,
        )?;
        validate_required_reserve(&request)?;
        ensure(
            request.coverage_bps >= self.config.reserve_safety_bps,
            "reserve coverage below safety threshold",
        )?;
        self.require_active_asset(&request.asset_id)?;
        let next = self.counters.reserve_attestation_count.saturating_add(1);
        let reserve_attestation_id = reserve_attestation_id(&request, next);
        let record = ReserveAttestation {
            reserve_attestation_id: reserve_attestation_id.clone(),
            asset_id: request.asset_id.clone(),
            reserve_chain: request.reserve_chain,
            custodian_commitment: request.custodian_commitment,
            reserve_commitment_root: request.reserve_commitment_root,
            liability_commitment_root: request.liability_commitment_root,
            coverage_bps: request.coverage_bps,
            reserve_safety_bps: self.config.reserve_safety_bps,
            oracle_transcript_root: request.oracle_transcript_root,
            auditor_committee_root: request.auditor_committee_root,
            pq_signature_root: request.pq_signature_root,
            status: ReserveStatus::Active,
            attested_at_height: self.height,
            expires_at_height: self.height + self.config.reserve_ttl_blocks,
            nonce: request.nonce,
        };
        self.reserve_attestations
            .insert(reserve_attestation_id.clone(), record.clone());
        self.asset_to_reserves
            .entry(request.asset_id.clone())
            .or_default()
            .insert(reserve_attestation_id.clone());
        self.counters.reserve_attestation_count = next;
        self.push_event(
            OperationKind::AttestReserve,
            &reserve_attestation_id,
            &request.asset_id,
            &record.record(),
        )?;
        self.refresh_roots();
        Ok(record)
    }

    pub fn open_fence(&mut self, request: OpenFenceRequest) -> Result<PrivacyNullifierFence> {
        ensure_capacity(
            "privacy fences",
            self.privacy_fences.len(),
            self.config.max_privacy_fences,
        )?;
        validate_required_fence(&request)?;
        self.require_active_asset(&request.asset_id)?;
        if request.consumed {
            self.insert_consumed_nullifier(&request.nullifier_root)?;
        }
        let next = self.counters.privacy_fence_count.saturating_add(1);
        let fence_id = privacy_fence_id(&request, next);
        let record = PrivacyNullifierFence {
            fence_id: fence_id.clone(),
            asset_id: request.asset_id.clone(),
            subject_id: request.subject_id,
            fence_kind: request.fence_kind,
            nullifier_root: request.nullifier_root,
            commitment_root: request.commitment_root,
            replay_domain: self.config.replay_domain.clone(),
            view_tag_root: request.view_tag_root,
            consumed: request.consumed,
            opened_at_height: self.height,
            expires_at_height: self.height + self.config.fence_ttl_blocks,
            nonce: request.nonce,
        };
        self.privacy_fences.insert(fence_id.clone(), record.clone());
        self.counters.privacy_fence_count = next;
        self.push_event(
            OperationKind::OpenFence,
            &fence_id,
            &request.asset_id,
            &record.record(),
        )?;
        self.refresh_roots();
        Ok(record)
    }

    pub fn sponsor_fee(&mut self, request: SponsorFeeRequest) -> Result<LowFeeSponsorship> {
        ensure_capacity(
            "sponsorships",
            self.sponsorships.len(),
            self.config.max_sponsorships,
        )?;
        validate_required_sponsorship(&request)?;
        ensure(
            request.reserved_fee_units <= request.max_fee_units,
            "reserved fee exceeds max fee units",
        )?;
        self.require_active_asset(&request.asset_id)?;
        if !request.fee_policy_id.is_empty() {
            self.require_fee_policy(&request.fee_policy_id)?;
        }
        let next = self.counters.sponsorship_count.saturating_add(1);
        let sponsorship_id = sponsorship_id(&request, next);
        let record = LowFeeSponsorship {
            sponsorship_id: sponsorship_id.clone(),
            sponsor_commitment: request.sponsor_commitment,
            asset_id: request.asset_id.clone(),
            manifest_id: request.manifest_id,
            fee_policy_id: request.fee_policy_id,
            fee_asset_id: request.fee_asset_id,
            max_fee_units: request.max_fee_units,
            reserved_fee_units: request.reserved_fee_units,
            spent_fee_units: 0,
            rebate_bps: self.config.target_rebate_bps,
            privacy_budget_root: request.privacy_budget_root,
            claim_nullifier_root: request.claim_nullifier_root,
            status: SponsorshipStatus::Reserved,
            opened_at_height: self.height,
            expires_at_height: self.height + self.config.sponsor_ttl_blocks,
            nonce: request.nonce,
        };
        self.sponsorships
            .insert(sponsorship_id.clone(), record.clone());
        self.counters.sponsorship_count = next;
        self.push_event(
            OperationKind::SponsorFee,
            &sponsorship_id,
            &request.asset_id,
            &record.record(),
        )?;
        self.refresh_roots();
        Ok(record)
    }

    pub fn submit_slashing_evidence(
        &mut self,
        request: SubmitSlashingEvidenceRequest,
    ) -> Result<SlashingEvidence> {
        ensure_capacity(
            "slashing evidence",
            self.slashing_evidence.len(),
            self.config.max_slashing_evidence,
        )?;
        validate_required_slashing(&request)?;
        validate_bps("slash bps", self.config.slash_bps)?;
        self.require_active_asset(&request.asset_id)?;
        self.insert_consumed_nullifier(&request.evidence_nullifier_root)?;
        let next = self.counters.slashing_evidence_count.saturating_add(1);
        let evidence_id = slashing_evidence_id(&request, next);
        let record = SlashingEvidence {
            evidence_id: evidence_id.clone(),
            accused_commitment: request.accused_commitment,
            asset_id: request.asset_id.clone(),
            manifest_id: request.manifest_id,
            reason: request.reason,
            status: EvidenceStatus::Submitted,
            evidence_root: request.evidence_root,
            conflicting_record_root: request.conflicting_record_root,
            challenger_commitment: request.challenger_commitment,
            slash_amount_commitment: request.slash_amount_commitment,
            slash_bps: self.config.slash_bps,
            evidence_nullifier_root: request.evidence_nullifier_root,
            pq_signature_root: request.pq_signature_root,
            submitted_at_height: self.height,
            challenge_expires_at_height: self.height + self.config.slash_challenge_ttl_blocks,
            nonce: request.nonce,
        };
        self.slashing_evidence
            .insert(evidence_id.clone(), record.clone());
        self.counters.slashing_evidence_count = next;
        self.push_event(
            OperationKind::SubmitSlashingEvidence,
            &evidence_id,
            &request.asset_id,
            &record.record(),
        )?;
        self.refresh_roots();
        Ok(record)
    }

    fn require_active_asset(&self, asset_id: &str) -> Result<&ShieldedAssetListing> {
        let asset = self
            .asset_listings
            .get(asset_id)
            .ok_or_else(|| "bridge asset listing not found".to_string())?;
        ensure(
            asset.status.accepts_bridge_activity(),
            "bridge asset listing is not active",
        )?;
        Ok(asset)
    }

    fn require_reserve(&self, reserve_attestation_id: &str) -> Result<&ReserveAttestation> {
        self.reserve_attestations
            .get(reserve_attestation_id)
            .ok_or_else(|| "reserve attestation not found".to_string())
    }

    fn require_compliance(&self, attestation_id: &str) -> Result<&PrivateComplianceAttestation> {
        self.compliance_attestations
            .get(attestation_id)
            .ok_or_else(|| "compliance attestation not found".to_string())
    }

    fn require_fee_policy(&self, fee_policy_id: &str) -> Result<&FeePolicySchedule> {
        self.fee_policies
            .get(fee_policy_id)
            .ok_or_else(|| "fee policy not found".to_string())
    }

    fn insert_consumed_nullifier(&mut self, nullifier_root: &str) -> Result<()> {
        ensure_nonempty("nullifier root", nullifier_root)?;
        if !self.consumed_nullifiers.insert(nullifier_root.to_string()) {
            return Err("privacy nullifier already consumed".to_string());
        }
        self.counters.consumed_nullifier_count =
            self.counters.consumed_nullifier_count.saturating_add(1);
        Ok(())
    }

    fn push_event(
        &mut self,
        operation: OperationKind,
        object_id: &str,
        asset_id: &str,
        record: &Value,
    ) -> Result<()> {
        ensure_capacity("events", self.events.len(), self.config.max_events)?;
        let ordinal = self.counters.event_count.saturating_add(1);
        let root = root_from_record("PQL2-BRIDGE-ASSET-REGISTRY-EVENT-OBJECT-ROOT", record);
        let event_id = event_id(operation, object_id, self.height, ordinal);
        let event = RuntimeEvent {
            event_id: event_id.clone(),
            operation,
            object_id: object_id.to_string(),
            asset_id: asset_id.to_string(),
            root,
            height: self.height,
            ordinal,
        };
        self.events.insert(event_id, event);
        self.counters.event_count = ordinal;
        Ok(())
    }
}

pub fn devnet() -> Result<State> {
    State::devnet()
}

pub fn private_l2_pq_confidential_token_bridge_asset_registry_state_root(state: &State) -> String {
    state.state_root()
}

pub fn devnet_state_root() -> Result<String> {
    Ok(State::devnet()?.state_root())
}

pub fn devnet_public_record() -> Result<PublicRecord> {
    Ok(State::devnet()?.public_record())
}

pub fn state_root_from_public_record(record: &PublicRecord) -> String {
    root_from_record(
        "PQL2-BRIDGE-ASSET-REGISTRY-PUBLIC-RECORD-ROOT",
        &record.record(),
    )
}

pub fn asset_listing_id(request: &ListAssetRequest, counter: u64) -> String {
    root_from_record(
        "PQL2-BRIDGE-ASSET-REGISTRY-ASSET-ID",
        &json!({
            "counter": counter,
            "issuer_commitment": request.issuer_commitment,
            "asset_kind": request.asset_kind.as_str(),
            "native_chain": request.native_chain.as_str(),
            "native_chain_asset_commitment": request.native_chain_asset_commitment,
            "symbol_commitment": request.symbol_commitment,
            "metadata_commitment": request.metadata_commitment,
            "nonce": request.nonce,
        }),
    )
}

pub fn bridge_manifest_id(request: &PublishManifestRequest, counter: u64) -> String {
    root_from_record(
        "PQL2-BRIDGE-ASSET-REGISTRY-MANIFEST-ID",
        &json!({
            "counter": counter,
            "asset_id": request.asset_id,
            "action": request.action.as_str(),
            "source_chain": request.source_chain.as_str(),
            "destination_chain": request.destination_chain.as_str(),
            "input_nullifier_root": request.input_nullifier_root,
            "output_commitment_root": request.output_commitment_root,
            "amount_commitment_root": request.amount_commitment_root,
            "nonce": request.nonce,
        }),
    )
}

pub fn compliance_attestation_id(request: &AttestComplianceRequest, counter: u64) -> String {
    root_from_record(
        "PQL2-BRIDGE-ASSET-REGISTRY-COMPLIANCE-ATTESTATION-ID",
        &json!({
            "counter": counter,
            "asset_id": request.asset_id,
            "manifest_id": request.manifest_id,
            "attester_commitment": request.attester_commitment,
            "kind": request.kind.as_str(),
            "verdict": request.verdict.as_str(),
            "proof_transcript_root": request.proof_transcript_root,
            "nonce": request.nonce,
        }),
    )
}

pub fn denomination_map_id(request: &MapDenominationRequest, counter: u64) -> String {
    root_from_record(
        "PQL2-BRIDGE-ASSET-REGISTRY-DENOMINATION-MAP-ID",
        &json!({
            "counter": counter,
            "asset_id": request.asset_id,
            "source_chain": request.source_chain.as_str(),
            "destination_chain": request.destination_chain.as_str(),
            "source_denomination": request.source_denomination.as_str(),
            "destination_denomination": request.destination_denomination.as_str(),
            "conversion_rate_commitment": request.conversion_rate_commitment,
            "nonce": request.nonce,
        }),
    )
}

pub fn fee_policy_id(request: &ScheduleFeePolicyRequest, counter: u64) -> String {
    root_from_record(
        "PQL2-BRIDGE-ASSET-REGISTRY-FEE-POLICY-ID",
        &json!({
            "counter": counter,
            "asset_id": request.asset_id,
            "lane": request.lane.as_str(),
            "fee_asset_id": request.fee_asset_id,
            "base_fee_bps": request.base_fee_bps,
            "max_user_fee_bps": request.max_user_fee_bps,
            "max_sponsor_fee_bps": request.max_sponsor_fee_bps,
            "target_rebate_bps": request.target_rebate_bps,
            "nonce": request.nonce,
        }),
    )
}

pub fn proof_requirement_id(request: &AddProofRequirementRequest, counter: u64) -> String {
    root_from_record(
        "PQL2-BRIDGE-ASSET-REGISTRY-PROOF-REQUIREMENT-ID",
        &json!({
            "counter": counter,
            "asset_id": request.asset_id,
            "action": request.action.as_str(),
            "kind": request.kind.as_str(),
            "proof_system": request.proof_system.as_str(),
            "verifier_key_root": request.verifier_key_root,
            "nonce": request.nonce,
        }),
    )
}

pub fn covenant_hook_id(request: &RegisterHookRequest, counter: u64) -> String {
    root_from_record(
        "PQL2-BRIDGE-ASSET-REGISTRY-COVENANT-HOOK-ID",
        &json!({
            "counter": counter,
            "asset_id": request.asset_id,
            "hook_kind": request.hook_kind.as_str(),
            "contract_commitment": request.contract_commitment,
            "entrypoint_commitment": request.entrypoint_commitment,
            "nonce": request.nonce,
        }),
    )
}

pub fn reserve_attestation_id(request: &AttestReserveRequest, counter: u64) -> String {
    root_from_record(
        "PQL2-BRIDGE-ASSET-REGISTRY-RESERVE-ATTESTATION-ID",
        &json!({
            "counter": counter,
            "asset_id": request.asset_id,
            "reserve_chain": request.reserve_chain.as_str(),
            "custodian_commitment": request.custodian_commitment,
            "reserve_commitment_root": request.reserve_commitment_root,
            "liability_commitment_root": request.liability_commitment_root,
            "coverage_bps": request.coverage_bps,
            "nonce": request.nonce,
        }),
    )
}

pub fn privacy_fence_id(request: &OpenFenceRequest, counter: u64) -> String {
    root_from_record(
        "PQL2-BRIDGE-ASSET-REGISTRY-PRIVACY-FENCE-ID",
        &json!({
            "counter": counter,
            "asset_id": request.asset_id,
            "subject_id": request.subject_id,
            "fence_kind": request.fence_kind.as_str(),
            "nullifier_root": request.nullifier_root,
            "commitment_root": request.commitment_root,
            "nonce": request.nonce,
        }),
    )
}

pub fn sponsorship_id(request: &SponsorFeeRequest, counter: u64) -> String {
    root_from_record(
        "PQL2-BRIDGE-ASSET-REGISTRY-SPONSORSHIP-ID",
        &json!({
            "counter": counter,
            "sponsor_commitment": request.sponsor_commitment,
            "asset_id": request.asset_id,
            "manifest_id": request.manifest_id,
            "fee_policy_id": request.fee_policy_id,
            "claim_nullifier_root": request.claim_nullifier_root,
            "nonce": request.nonce,
        }),
    )
}

pub fn slashing_evidence_id(request: &SubmitSlashingEvidenceRequest, counter: u64) -> String {
    root_from_record(
        "PQL2-BRIDGE-ASSET-REGISTRY-SLASHING-EVIDENCE-ID",
        &json!({
            "counter": counter,
            "accused_commitment": request.accused_commitment,
            "asset_id": request.asset_id,
            "manifest_id": request.manifest_id,
            "reason": request.reason.as_str(),
            "evidence_root": request.evidence_root,
            "evidence_nullifier_root": request.evidence_nullifier_root,
            "nonce": request.nonce,
        }),
    )
}

pub fn event_id(operation: OperationKind, object_id: &str, height: u64, ordinal: u64) -> String {
    domain_hash(
        "PQL2-BRIDGE-ASSET-REGISTRY-EVENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(operation.as_str()),
            HashPart::Str(object_id),
            HashPart::U64(height),
            HashPart::U64(ordinal),
        ],
        32,
    )
}

pub fn root_from_record(domain: &str, record: &Value) -> String {
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

pub fn payload_root(domain: &str, payload: &Value) -> String {
    root_from_record(
        &format!("PQL2-BRIDGE-ASSET-REGISTRY-PAYLOAD-{domain}"),
        payload,
    )
}

pub fn deterministic_commitment(domain: &str, label: &str, nonce: u64) -> String {
    domain_hash(
        &format!("PQL2-BRIDGE-ASSET-REGISTRY-COMMITMENT-{domain}"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
            HashPart::U64(nonce),
        ],
        32,
    )
}

pub fn deterministic_root(domain: &str, label: &str, nonce: u64) -> String {
    root_from_record(
        &format!("PQL2-BRIDGE-ASSET-REGISTRY-ROOT-{domain}"),
        &json!({
            "label": label,
            "nonce": nonce,
        }),
    )
}

fn validate_required_list_asset(request: &ListAssetRequest) -> Result<()> {
    ensure_nonempty("symbol commitment", &request.symbol_commitment)?;
    ensure_nonempty("metadata commitment", &request.metadata_commitment)?;
    ensure_nonempty("issuer commitment", &request.issuer_commitment)?;
    ensure_nonempty(
        "native chain asset commitment",
        &request.native_chain_asset_commitment,
    )?;
    ensure_nonempty("supply cap commitment", &request.supply_cap_commitment)?;
    ensure_nonempty("circulating supply root", &request.circulating_supply_root)?;
    ensure_nonempty("authority root", &request.authority_root)?;
    ensure_nonempty("privacy policy root", &request.privacy_policy_root)?;
    ensure_nonempty("compliance policy root", &request.compliance_policy_root)?;
    ensure_nonempty("denomination root", &request.denomination_root)?;
    ensure_nonempty("bridge adapter root", &request.bridge_adapter_root)?;
    ensure_nonempty("reserve policy root", &request.reserve_policy_root)?;
    ensure_nonempty("PQ attestation root", &request.pq_attestation_root)?;
    ensure(request.decimals <= 30, "asset decimals too large")
}

fn validate_required_manifest(request: &PublishManifestRequest) -> Result<()> {
    ensure_nonempty("asset id", &request.asset_id)?;
    ensure_nonempty("source asset commitment", &request.source_asset_commitment)?;
    ensure_nonempty(
        "destination asset commitment",
        &request.destination_asset_commitment,
    )?;
    ensure_nonempty("amount commitment root", &request.amount_commitment_root)?;
    ensure_nonempty("denomination map id", &request.denomination_map_id)?;
    ensure_nonempty("input nullifier root", &request.input_nullifier_root)?;
    ensure_nonempty("output commitment root", &request.output_commitment_root)?;
    ensure_nonempty("proof requirement root", &request.proof_requirement_root)?;
    ensure_nonempty(
        "encrypted recipient root",
        &request.encrypted_recipient_root,
    )?;
    ensure_nonempty(
        "bridge adapter transcript root",
        &request.bridge_adapter_transcript_root,
    )?;
    ensure_nonempty("PQ signature root", &request.pq_signature_root)
}

fn validate_required_compliance(request: &AttestComplianceRequest) -> Result<()> {
    ensure_nonempty("asset id", &request.asset_id)?;
    ensure_nonempty("attester commitment", &request.attester_commitment)?;
    ensure_nonempty("policy root", &request.policy_root)?;
    ensure_nonempty("disclosure root", &request.disclosure_root)?;
    ensure_nonempty("jurisdiction root", &request.jurisdiction_root)?;
    ensure_nonempty(
        "watchlist nonmembership root",
        &request.watchlist_nonmembership_root,
    )?;
    ensure_nonempty("proof transcript root", &request.proof_transcript_root)?;
    ensure_nonempty("PQ signature root", &request.pq_signature_root)
}

fn validate_required_denomination(request: &MapDenominationRequest) -> Result<()> {
    ensure_nonempty("asset id", &request.asset_id)?;
    ensure_nonempty(
        "conversion rate commitment",
        &request.conversion_rate_commitment,
    )?;
    ensure_nonempty("rounding policy root", &request.rounding_policy_root)?;
    ensure_nonempty("dust limit commitment", &request.dust_limit_commitment)?;
    ensure_nonempty("oracle attestation root", &request.oracle_attestation_root)
}

fn validate_required_fee_policy(request: &ScheduleFeePolicyRequest) -> Result<()> {
    ensure_nonempty("asset id", &request.asset_id)?;
    ensure_nonempty("fee asset id", &request.fee_asset_id)?;
    ensure_nonempty("volatility band root", &request.volatility_band_root)?;
    ensure_nonempty("congestion curve root", &request.congestion_curve_root)?;
    ensure_nonempty("sponsor priority root", &request.sponsor_priority_root)?;
    ensure_nonempty("privacy budget root", &request.privacy_budget_root)
}

fn validate_required_proof_requirement(request: &AddProofRequirementRequest) -> Result<()> {
    ensure_nonempty("asset id", &request.asset_id)?;
    ensure_nonempty("verifier key root", &request.verifier_key_root)?;
    ensure_nonempty(
        "public input schema root",
        &request.public_input_schema_root,
    )?;
    ensure_nonempty("witness hint root", &request.witness_hint_root)?;
    ensure_nonempty("recursion policy root", &request.recursion_policy_root)
}

fn validate_required_hook(request: &RegisterHookRequest) -> Result<()> {
    ensure_nonempty("asset id", &request.asset_id)?;
    ensure_nonempty("contract commitment", &request.contract_commitment)?;
    ensure_nonempty("entrypoint commitment", &request.entrypoint_commitment)?;
    ensure_nonempty("authorization root", &request.authorization_root)?;
    ensure_nonempty("call policy root", &request.call_policy_root)?;
    ensure_nonempty("gas policy root", &request.gas_policy_root)?;
    ensure_nonempty("rollback policy root", &request.rollback_policy_root)?;
    ensure_nonempty("PQ signature root", &request.pq_signature_root)
}

fn validate_required_reserve(request: &AttestReserveRequest) -> Result<()> {
    ensure_nonempty("asset id", &request.asset_id)?;
    ensure_nonempty("custodian commitment", &request.custodian_commitment)?;
    ensure_nonempty("reserve commitment root", &request.reserve_commitment_root)?;
    ensure_nonempty(
        "liability commitment root",
        &request.liability_commitment_root,
    )?;
    ensure_nonempty("oracle transcript root", &request.oracle_transcript_root)?;
    ensure_nonempty("auditor committee root", &request.auditor_committee_root)?;
    ensure_nonempty("PQ signature root", &request.pq_signature_root)
}

fn validate_required_fence(request: &OpenFenceRequest) -> Result<()> {
    ensure_nonempty("asset id", &request.asset_id)?;
    ensure_nonempty("subject id", &request.subject_id)?;
    ensure_nonempty("nullifier root", &request.nullifier_root)?;
    ensure_nonempty("commitment root", &request.commitment_root)?;
    ensure_nonempty("view tag root", &request.view_tag_root)
}

fn validate_required_sponsorship(request: &SponsorFeeRequest) -> Result<()> {
    ensure_nonempty("sponsor commitment", &request.sponsor_commitment)?;
    ensure_nonempty("asset id", &request.asset_id)?;
    ensure_nonempty("fee asset id", &request.fee_asset_id)?;
    ensure_nonempty("privacy budget root", &request.privacy_budget_root)?;
    ensure_nonempty("claim nullifier root", &request.claim_nullifier_root)
}

fn validate_required_slashing(request: &SubmitSlashingEvidenceRequest) -> Result<()> {
    ensure_nonempty("accused commitment", &request.accused_commitment)?;
    ensure_nonempty("asset id", &request.asset_id)?;
    ensure_nonempty("evidence root", &request.evidence_root)?;
    ensure_nonempty("conflicting record root", &request.conflicting_record_root)?;
    ensure_nonempty("challenger commitment", &request.challenger_commitment)?;
    ensure_nonempty("slash amount commitment", &request.slash_amount_commitment)?;
    ensure_nonempty("evidence nullifier root", &request.evidence_nullifier_root)?;
    ensure_nonempty("PQ signature root", &request.pq_signature_root)
}

fn validate_privacy_and_pq(
    privacy_set_size: u64,
    pq_security_bits: u16,
    config: &Config,
) -> Result<()> {
    ensure(
        privacy_set_size >= config.min_privacy_set_size,
        "privacy set below runtime minimum",
    )?;
    ensure(
        pq_security_bits >= config.min_pq_security_bits,
        "PQ security bits below runtime minimum",
    )
}

fn validate_bps(field: &str, value: u64) -> Result<()> {
    ensure(value <= MAX_BPS, &format!("{field} exceeds max bps"))
}

fn ensure(condition: bool, message: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(message.to_string())
    }
}

fn ensure_eq(field: &str, actual: &str, expected: &str) -> Result<()> {
    if actual == expected {
        Ok(())
    } else {
        Err(format!(
            "{field} mismatch: expected {expected}, got {actual}"
        ))
    }
}

fn ensure_bps(field: &str, value: u64) -> Result<()> {
    ensure(value <= MAX_BPS, &format!("{field} exceeds {MAX_BPS} bps"))
}

fn ensure_nonzero(field: &str, value: u64) -> Result<()> {
    ensure(value > 0, &format!("{field} must be nonzero"))
}

fn ensure_nonempty(field: &str, value: &str) -> Result<()> {
    ensure(
        !value.trim().is_empty(),
        &format!("{field} must be nonempty"),
    )
}

fn ensure_capacity(field: &str, current: usize, max: usize) -> Result<()> {
    ensure(current < max, &format!("{field} capacity exhausted"))
}

fn ensure_absent<T>(map: &BTreeMap<String, T>, field: &str, id: &str) -> Result<()> {
    ensure(
        !map.contains_key(id),
        &format!("{field} already exists: {id}"),
    )
}

trait RuntimeRecord {
    fn record(&self) -> Value;
}

impl RuntimeRecord for ShieldedAssetListing {
    fn record(&self) -> Value {
        ShieldedAssetListing::record(self)
    }
}

impl RuntimeRecord for BridgeMintBurnManifest {
    fn record(&self) -> Value {
        BridgeMintBurnManifest::record(self)
    }
}

impl RuntimeRecord for PrivateComplianceAttestation {
    fn record(&self) -> Value {
        PrivateComplianceAttestation::record(self)
    }
}

impl RuntimeRecord for CrossChainDenominationMap {
    fn record(&self) -> Value {
        CrossChainDenominationMap::record(self)
    }
}

impl RuntimeRecord for FeePolicySchedule {
    fn record(&self) -> Value {
        FeePolicySchedule::record(self)
    }
}

impl RuntimeRecord for ProofRequirement {
    fn record(&self) -> Value {
        ProofRequirement::record(self)
    }
}

impl RuntimeRecord for TokenCovenantHook {
    fn record(&self) -> Value {
        TokenCovenantHook::record(self)
    }
}

impl RuntimeRecord for ReserveAttestation {
    fn record(&self) -> Value {
        ReserveAttestation::record(self)
    }
}

impl RuntimeRecord for PrivacyNullifierFence {
    fn record(&self) -> Value {
        PrivacyNullifierFence::record(self)
    }
}

impl RuntimeRecord for LowFeeSponsorship {
    fn record(&self) -> Value {
        LowFeeSponsorship::record(self)
    }
}

impl RuntimeRecord for SlashingEvidence {
    fn record(&self) -> Value {
        SlashingEvidence::record(self)
    }
}

impl RuntimeRecord for RuntimeEvent {
    fn record(&self) -> Value {
        RuntimeEvent::record(self)
    }
}

fn record_root<'a, T, I>(domain: &str, records: I) -> String
where
    T: RuntimeRecord + 'a,
    I: IntoIterator<Item = &'a T>,
{
    let leaves = records
        .into_iter()
        .map(RuntimeRecord::record)
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn set_root(domain: &str, values: &BTreeSet<String>) -> String {
    let leaves = values
        .iter()
        .map(|value| json!({ "chain_id": CHAIN_ID, "value": value }))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn index_root(domain: &str, index: &BTreeMap<String, BTreeSet<String>>) -> String {
    let leaves = index
        .iter()
        .map(|(key, values)| {
            json!({
                "key": key,
                "values": values.iter().cloned().collect::<Vec<_>>(),
            })
        })
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn devnet_asset_request(label: &str, asset_kind: AssetKind, nonce: u64) -> ListAssetRequest {
    ListAssetRequest {
        symbol_commitment: deterministic_commitment("symbol", label, nonce),
        metadata_commitment: deterministic_commitment("metadata", label, nonce),
        issuer_commitment: deterministic_commitment("issuer", label, nonce),
        asset_kind,
        native_chain: ChainKind::MoneroDevnet,
        native_chain_asset_commitment: deterministic_commitment("native-asset", label, nonce),
        decimals: 12,
        supply_cap_commitment: deterministic_commitment("supply-cap", label, nonce),
        circulating_supply_root: deterministic_root("circulating-supply", label, nonce),
        authority_root: deterministic_root("authority", label, nonce),
        privacy_policy_root: deterministic_root("privacy-policy", label, nonce),
        compliance_policy_root: deterministic_root("compliance-policy", label, nonce),
        denomination_root: deterministic_root("denomination", label, nonce),
        bridge_adapter_root: deterministic_root("bridge-adapter", label, nonce),
        covenant_hook_root: deterministic_root("covenant-hook", label, nonce),
        reserve_policy_root: deterministic_root("reserve-policy", label, nonce),
        pq_attestation_root: deterministic_root("pq-attestation", label, nonce),
        nonce: nonce.to_string(),
    }
}

fn devnet_denomination_request(asset_id: &str, nonce: u64) -> MapDenominationRequest {
    MapDenominationRequest {
        asset_id: asset_id.to_string(),
        source_chain: ChainKind::MoneroDevnet,
        destination_chain: ChainKind::NebulaL2,
        source_denomination: DenominationKind::Piconero,
        destination_denomination: DenominationKind::TokenDecimals,
        source_decimals: 12,
        destination_decimals: 12,
        conversion_rate_commitment: deterministic_commitment("conversion-rate", asset_id, nonce),
        rounding_policy_root: deterministic_root("rounding-policy", asset_id, nonce),
        dust_limit_commitment: deterministic_commitment("dust-limit", asset_id, nonce),
        oracle_attestation_root: deterministic_root("denomination-oracle", asset_id, nonce),
        nonce: nonce.to_string(),
    }
}

fn devnet_fee_policy_request(asset_id: &str, nonce: u64) -> ScheduleFeePolicyRequest {
    let config = Config::devnet();
    ScheduleFeePolicyRequest {
        asset_id: asset_id.to_string(),
        lane: FeeLane::SponsoredLowFee,
        fee_asset_id: config.fee_asset_id,
        base_fee_bps: FeeLane::SponsoredLowFee.base_fee_bps(&config),
        max_user_fee_bps: config.max_user_fee_bps,
        max_sponsor_fee_bps: config.max_sponsor_fee_bps,
        target_rebate_bps: config.target_rebate_bps,
        volatility_band_root: deterministic_root("fee-volatility", asset_id, nonce),
        congestion_curve_root: deterministic_root("fee-congestion", asset_id, nonce),
        sponsor_priority_root: deterministic_root("fee-sponsor-priority", asset_id, nonce),
        privacy_budget_root: deterministic_root("fee-privacy-budget", asset_id, nonce),
        nonce: nonce.to_string(),
    }
}

fn devnet_proof_requirement_request(asset_id: &str, nonce: u64) -> AddProofRequirementRequest {
    AddProofRequirementRequest {
        asset_id: asset_id.to_string(),
        action: BridgeAction::ShieldedMint,
        kind: ProofRequirementKind::AmountConservation,
        proof_system: ProofSystem::RecursiveAggregate,
        verifier_key_root: deterministic_root("verifier-key", asset_id, nonce),
        public_input_schema_root: deterministic_root("public-input-schema", asset_id, nonce),
        witness_hint_root: deterministic_root("witness-hint", asset_id, nonce),
        recursion_policy_root: deterministic_root("recursion-policy", asset_id, nonce),
        min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
        min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        required: true,
        nonce: nonce.to_string(),
    }
}

fn devnet_hook_request(asset_id: &str, nonce: u64) -> RegisterHookRequest {
    RegisterHookRequest {
        asset_id: asset_id.to_string(),
        hook_kind: HookKind::ReserveCheck,
        contract_commitment: deterministic_commitment("hook-contract", asset_id, nonce),
        entrypoint_commitment: deterministic_commitment("hook-entrypoint", asset_id, nonce),
        authorization_root: deterministic_root("hook-authorization", asset_id, nonce),
        call_policy_root: deterministic_root("hook-call-policy", asset_id, nonce),
        gas_policy_root: deterministic_root("hook-gas-policy", asset_id, nonce),
        rollback_policy_root: deterministic_root("hook-rollback-policy", asset_id, nonce),
        pq_signature_root: deterministic_root("hook-pq-signature", asset_id, nonce),
        nonce: nonce.to_string(),
    }
}

fn devnet_reserve_request(asset_id: &str, nonce: u64) -> AttestReserveRequest {
    AttestReserveRequest {
        asset_id: asset_id.to_string(),
        reserve_chain: ChainKind::MoneroDevnet,
        custodian_commitment: deterministic_commitment("reserve-custodian", asset_id, nonce),
        reserve_commitment_root: deterministic_root("reserve-commitment", asset_id, nonce),
        liability_commitment_root: deterministic_root("reserve-liability", asset_id, nonce),
        coverage_bps: DEFAULT_RESERVE_SAFETY_BPS,
        oracle_transcript_root: deterministic_root("reserve-oracle", asset_id, nonce),
        auditor_committee_root: deterministic_root("reserve-auditors", asset_id, nonce),
        pq_signature_root: deterministic_root("reserve-pq-signature", asset_id, nonce),
        nonce: nonce.to_string(),
    }
}

fn devnet_compliance_request(
    asset_id: &str,
    manifest_id: &str,
    nonce: u64,
) -> AttestComplianceRequest {
    AttestComplianceRequest {
        asset_id: asset_id.to_string(),
        manifest_id: manifest_id.to_string(),
        attester_commitment: deterministic_commitment("compliance-attester", asset_id, nonce),
        kind: ComplianceKind::BridgeMintBurn,
        verdict: ComplianceVerdict::Allowed,
        policy_root: deterministic_root("compliance-policy", asset_id, nonce),
        disclosure_root: deterministic_root("compliance-disclosure", asset_id, nonce),
        jurisdiction_root: deterministic_root("compliance-jurisdiction", asset_id, nonce),
        watchlist_nonmembership_root: deterministic_root(
            "watchlist-nonmembership",
            asset_id,
            nonce,
        ),
        proof_transcript_root: deterministic_root("compliance-proof", asset_id, nonce),
        pq_signature_root: deterministic_root("compliance-pq-signature", asset_id, nonce),
        privacy_set_size: DEFAULT_BATCH_PRIVACY_SET_SIZE,
        pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        nonce: nonce.to_string(),
    }
}

fn devnet_sponsorship_request(
    asset_id: &str,
    manifest_id: &str,
    fee_policy_id: &str,
    nonce: u64,
) -> SponsorFeeRequest {
    SponsorFeeRequest {
        sponsor_commitment: deterministic_commitment("fee-sponsor", asset_id, nonce),
        asset_id: asset_id.to_string(),
        manifest_id: manifest_id.to_string(),
        fee_policy_id: fee_policy_id.to_string(),
        fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
        max_fee_units: 1_000_000,
        reserved_fee_units: 125_000,
        privacy_budget_root: deterministic_root("sponsor-privacy-budget", asset_id, nonce),
        claim_nullifier_root: deterministic_root("sponsor-claim-nullifier", asset_id, nonce),
        nonce: nonce.to_string(),
    }
}

fn devnet_manifest_request(
    asset_id: &str,
    denomination_map_id: &str,
    reserve_attestation_id: &str,
    compliance_attestation_id: &str,
    proof_requirement_id: &str,
    hook_id: &str,
    fee_policy_id: &str,
    sponsorship_id: &str,
    nonce: u64,
) -> PublishManifestRequest {
    PublishManifestRequest {
        asset_id: asset_id.to_string(),
        action: BridgeAction::ShieldedMint,
        source_chain: ChainKind::MoneroDevnet,
        destination_chain: ChainKind::NebulaL2,
        source_asset_commitment: deterministic_commitment("manifest-source-asset", asset_id, nonce),
        destination_asset_commitment: deterministic_commitment(
            "manifest-destination-asset",
            asset_id,
            nonce,
        ),
        amount_commitment_root: deterministic_root("manifest-amount", asset_id, nonce),
        denomination_map_id: denomination_map_id.to_string(),
        input_nullifier_root: deterministic_root("manifest-input-nullifier", asset_id, nonce),
        output_commitment_root: deterministic_root("manifest-output-commitment", asset_id, nonce),
        reserve_attestation_id: reserve_attestation_id.to_string(),
        compliance_attestation_id: compliance_attestation_id.to_string(),
        proof_requirement_root: deterministic_root(
            "manifest-proof-requirement",
            proof_requirement_id,
            nonce,
        ),
        covenant_hook_root: deterministic_root("manifest-covenant-hook", hook_id, nonce),
        fee_policy_id: fee_policy_id.to_string(),
        sponsorship_id: sponsorship_id.to_string(),
        encrypted_recipient_root: deterministic_root("manifest-recipient", asset_id, nonce),
        bridge_adapter_transcript_root: deterministic_root("manifest-adapter", asset_id, nonce),
        pq_signature_root: deterministic_root("manifest-pq-signature", asset_id, nonce),
        privacy_set_size: DEFAULT_BATCH_PRIVACY_SET_SIZE,
        pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        nonce: nonce.to_string(),
    }
}

fn devnet_fence_request(
    asset_id: &str,
    subject_id: &str,
    fence_kind: FenceKind,
    consumed: bool,
    nonce: u64,
) -> OpenFenceRequest {
    OpenFenceRequest {
        asset_id: asset_id.to_string(),
        subject_id: subject_id.to_string(),
        fence_kind,
        nullifier_root: deterministic_root("fence-nullifier", subject_id, nonce),
        commitment_root: deterministic_root("fence-commitment", subject_id, nonce),
        view_tag_root: deterministic_root("fence-view-tag", subject_id, nonce),
        consumed,
        nonce: nonce.to_string(),
    }
}

fn devnet_slashing_request(
    asset_id: &str,
    manifest_id: &str,
    nonce: u64,
) -> SubmitSlashingEvidenceRequest {
    SubmitSlashingEvidenceRequest {
        accused_commitment: deterministic_commitment("slash-accused", manifest_id, nonce),
        asset_id: asset_id.to_string(),
        manifest_id: manifest_id.to_string(),
        reason: SlashingReason::InvalidReserve,
        evidence_root: deterministic_root("slash-evidence", manifest_id, nonce),
        conflicting_record_root: deterministic_root("slash-conflict", manifest_id, nonce),
        challenger_commitment: deterministic_commitment("slash-challenger", manifest_id, nonce),
        slash_amount_commitment: deterministic_commitment("slash-amount", manifest_id, nonce),
        evidence_nullifier_root: deterministic_root("slash-nullifier", manifest_id, nonce),
        pq_signature_root: deterministic_root("slash-pq-signature", manifest_id, nonce),
        nonce: nonce.to_string(),
    }
}
