use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type Runtime = State;

pub const PROTOCOL_VERSION: &str =
    "nebula-private-l2-confidential-token-airdrop-claim-netting-runtime-v1";
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const ELIGIBILITY_ROOT_SUITE: &str =
    "shielded-airdrop-eligibility-root-with-private-amount-buckets-v1";
pub const CLAIM_NOTE_SUITE: &str = "monero-l2-private-airdrop-claim-note-commitment-v1";
pub const CLAIM_NETTING_PROOF_SUITE: &str =
    "zk-confidential-airdrop-claim-netting-and-batched-mint-proof-v1";
pub const PQ_ATTESTATION_SUITE: &str =
    "ml-dsa-87+slh-dsa-shake-256f-anti-sybil-airdrop-attestation-v1";
pub const SPONSOR_FEE_SUITE: &str = "sponsor-funded-low-fee-airdrop-claim-v1";
pub const SETTLEMENT_RECEIPT_SUITE: &str = "confidential-airdrop-netted-mint-settlement-receipt-v1";
pub const REBATE_SUITE: &str = "privacy-preserving-airdrop-fee-rebate-v1";
pub const PRIVACY_FENCE_SUITE: &str =
    "airdrop-claim-nullifier-root-and-note-commitment-privacy-fence-v1";
pub const DEFAULT_L2_NETWORK: &str = "nebula-devnet";
pub const DEFAULT_MONERO_NETWORK: &str = "monero-devnet";
pub const DEFAULT_AIRDROP_ASSET_ID: &str = "claimd-devnet";
pub const DEFAULT_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEVNET_HEIGHT: u64 = 1_338_400;
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_EPOCH_BLOCKS: u64 = 720;
pub const DEFAULT_CLAIM_TTL_BLOCKS: u64 = 1_440;
pub const DEFAULT_BATCH_TTL_BLOCKS: u64 = 24;
pub const DEFAULT_ATTESTATION_TTL_BLOCKS: u64 = 2_880;
pub const DEFAULT_SPONSOR_RESERVATION_TTL_BLOCKS: u64 = 36;
pub const DEFAULT_SETTLEMENT_WINDOW_BLOCKS: u64 = 12;
pub const DEFAULT_MIN_PRIVACY_SET: u64 = 65_536;
pub const DEFAULT_TARGET_PRIVACY_SET: u64 = 262_144;
pub const DEFAULT_MIN_BATCH_CLAIMS: u64 = 8;
pub const DEFAULT_MAX_BATCH_CLAIMS: usize = 16_384;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 12;
pub const DEFAULT_TARGET_USER_FEE_BPS: u64 = 3;
pub const DEFAULT_SPONSOR_COVER_BPS: u64 = 9_700;
pub const DEFAULT_REBATE_BPS: u64 = 8;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const MAX_AIRDROPS: usize = 262_144;
pub const MAX_ELIGIBILITY_ROOTS: usize = 524_288;
pub const MAX_CLAIM_NOTES: usize = 4_194_304;
pub const MAX_CLAIM_BATCHES: usize = 1_048_576;
pub const MAX_PQ_ATTESTATIONS: usize = 4_194_304;
pub const MAX_SPONSOR_RESERVATIONS: usize = 2_097_152;
pub const MAX_SETTLEMENT_RECEIPTS: usize = 2_097_152;
pub const MAX_REBATES: usize = 2_097_152;
pub const MAX_PRIVACY_FENCES: usize = 8_388_608;
pub const MAX_NULLIFIERS: usize = 16_777_216;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AirdropKind {
    CommunityRetroactive,
    LiquidityBootstrapping,
    DefiUsageReward,
    BridgeMigration,
    GovernanceGenesis,
    BuilderGrant,
    WalletRecovery,
    MerchantAdoption,
    PrivacyMining,
    EmergencyRelief,
}

impl AirdropKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CommunityRetroactive => "community_retroactive",
            Self::LiquidityBootstrapping => "liquidity_bootstrapping",
            Self::DefiUsageReward => "defi_usage_reward",
            Self::BridgeMigration => "bridge_migration",
            Self::GovernanceGenesis => "governance_genesis",
            Self::BuilderGrant => "builder_grant",
            Self::WalletRecovery => "wallet_recovery",
            Self::MerchantAdoption => "merchant_adoption",
            Self::PrivacyMining => "privacy_mining",
            Self::EmergencyRelief => "emergency_relief",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AirdropStatus {
    Draft,
    RootCommitted,
    Claiming,
    Paused,
    NettingOnly,
    Settled,
    Closed,
}

impl AirdropStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::RootCommitted => "root_committed",
            Self::Claiming => "claiming",
            Self::Paused => "paused",
            Self::NettingOnly => "netting_only",
            Self::Settled => "settled",
            Self::Closed => "closed",
        }
    }

    pub fn accepts_claims(self) -> bool {
        matches!(self, Self::RootCommitted | Self::Claiming)
    }

    pub fn accepts_batches(self) -> bool {
        matches!(
            self,
            Self::Claiming | Self::NettingOnly | Self::RootCommitted
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EligibilityRootKind {
    WalletActivity,
    BridgeSnapshot,
    DefiLiquidity,
    GovernanceParticipation,
    MerchantVolume,
    BuilderGrant,
    RebateCarry,
    SybilAppeal,
}

impl EligibilityRootKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WalletActivity => "wallet_activity",
            Self::BridgeSnapshot => "bridge_snapshot",
            Self::DefiLiquidity => "defi_liquidity",
            Self::GovernanceParticipation => "governance_participation",
            Self::MerchantVolume => "merchant_volume",
            Self::BuilderGrant => "builder_grant",
            Self::RebateCarry => "rebate_carry",
            Self::SybilAppeal => "sybil_appeal",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EligibilityRootStatus {
    Proposed,
    Attested,
    Active,
    Superseded,
    Frozen,
    Rejected,
}

impl EligibilityRootStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::Attested => "attested",
            Self::Active => "active",
            Self::Superseded => "superseded",
            Self::Frozen => "frozen",
            Self::Rejected => "rejected",
        }
    }

    pub fn usable(self) -> bool {
        matches!(self, Self::Attested | Self::Active)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimNoteKind {
    StandardClaim,
    DefiBoostedClaim,
    LiquidityProviderClaim,
    BridgeMigrationClaim,
    GovernanceClaim,
    SponsorRebateClaim,
    AppealGrantedClaim,
}

impl ClaimNoteKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::StandardClaim => "standard_claim",
            Self::DefiBoostedClaim => "defi_boosted_claim",
            Self::LiquidityProviderClaim => "liquidity_provider_claim",
            Self::BridgeMigrationClaim => "bridge_migration_claim",
            Self::GovernanceClaim => "governance_claim",
            Self::SponsorRebateClaim => "sponsor_rebate_claim",
            Self::AppealGrantedClaim => "appeal_granted_claim",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimNoteStatus {
    Submitted,
    Attested,
    Fenced,
    Queued,
    Netted,
    Minted,
    Rejected,
    Expired,
}

impl ClaimNoteStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Attested => "attested",
            Self::Fenced => "fenced",
            Self::Queued => "queued",
            Self::Netted => "netted",
            Self::Minted => "minted",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }

    pub fn batchable(self) -> bool {
        matches!(
            self,
            Self::Submitted | Self::Attested | Self::Fenced | Self::Queued
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchLane {
    SponsorFunded,
    RetailLowFee,
    DefiLiquidity,
    BridgeMigration,
    Governance,
    Appeal,
    Emergency,
}

impl BatchLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SponsorFunded => "sponsor_funded",
            Self::RetailLowFee => "retail_low_fee",
            Self::DefiLiquidity => "defi_liquidity",
            Self::BridgeMigration => "bridge_migration",
            Self::Governance => "governance",
            Self::Appeal => "appeal",
            Self::Emergency => "emergency",
        }
    }

    pub fn fee_bps(self, config: &Config) -> u64 {
        match self {
            Self::SponsorFunded => config.target_user_fee_bps.saturating_sub(2),
            Self::RetailLowFee => config.target_user_fee_bps,
            Self::DefiLiquidity | Self::BridgeMigration => {
                config.target_user_fee_bps.saturating_add(2)
            }
            Self::Governance | Self::Appeal => config.target_user_fee_bps.saturating_add(1),
            Self::Emergency => config.max_user_fee_bps,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchStatus {
    Proposed,
    PrivacyFenced,
    Attested,
    SponsorReserved,
    Netted,
    SettlementReady,
    Settled,
    Rejected,
    Expired,
}

impl BatchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::PrivacyFenced => "privacy_fenced",
            Self::Attested => "attested",
            Self::SponsorReserved => "sponsor_reserved",
            Self::Netted => "netted",
            Self::SettlementReady => "settlement_ready",
            Self::Settled => "settled",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }

    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Proposed
                | Self::PrivacyFenced
                | Self::Attested
                | Self::SponsorReserved
                | Self::Netted
                | Self::SettlementReady
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PqAttestationKind {
    AntiSybil,
    HumanUniqueness,
    DeviceBound,
    SocialGraph,
    BridgeHistory,
    DefiUsage,
    AppealReview,
    SponsorPolicy,
}

impl PqAttestationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AntiSybil => "anti_sybil",
            Self::HumanUniqueness => "human_uniqueness",
            Self::DeviceBound => "device_bound",
            Self::SocialGraph => "social_graph",
            Self::BridgeHistory => "bridge_history",
            Self::DefiUsage => "defi_usage",
            Self::AppealReview => "appeal_review",
            Self::SponsorPolicy => "sponsor_policy",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationVerdict {
    Allow,
    AllowWithLimit,
    RequireReview,
    Deny,
    Revoke,
}

impl AttestationVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::AllowWithLimit => "allow_with_limit",
            Self::RequireReview => "require_review",
            Self::Deny => "deny",
            Self::Revoke => "revoke",
        }
    }

    pub fn permits_claim(self) -> bool {
        matches!(self, Self::Allow | Self::AllowWithLimit)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorPolicy {
    None,
    FeeOnly,
    FeeAndProof,
    FullClaimLane,
    EmergencySubsidy,
}

impl SponsorPolicy {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::FeeOnly => "fee_only",
            Self::FeeAndProof => "fee_and_proof",
            Self::FullClaimLane => "full_claim_lane",
            Self::EmergencySubsidy => "emergency_subsidy",
        }
    }

    pub fn sponsored(self) -> bool {
        !matches!(self, Self::None)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReservationStatus {
    Reserved,
    Attached,
    Consumed,
    Released,
    Expired,
}

impl ReservationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Attached => "attached",
            Self::Consumed => "consumed",
            Self::Released => "released",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptKind {
    NettedMint,
    SponsorPaidMint,
    DefiUtilityMint,
    BridgeMigrationMint,
    RebateMint,
    FinalCloseout,
}

impl ReceiptKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NettedMint => "netted_mint",
            Self::SponsorPaidMint => "sponsor_paid_mint",
            Self::DefiUtilityMint => "defi_utility_mint",
            Self::BridgeMigrationMint => "bridge_migration_mint",
            Self::RebateMint => "rebate_mint",
            Self::FinalCloseout => "final_closeout",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RebateReason {
    SponsorRefund,
    OverpaidFee,
    BatchCompression,
    DefiUtility,
    PrivacySetBonus,
    AppealGranted,
    LateSettlement,
}

impl RebateReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SponsorRefund => "sponsor_refund",
            Self::OverpaidFee => "overpaid_fee",
            Self::BatchCompression => "batch_compression",
            Self::DefiUtility => "defi_utility",
            Self::PrivacySetBonus => "privacy_set_bonus",
            Self::AppealGranted => "appeal_granted",
            Self::LateSettlement => "late_settlement",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FenceKind {
    EligibilityNullifier,
    ClaimNullifier,
    NoteCommitment,
    PqCredentialTag,
    SponsorVoucher,
    SettlementReceipt,
    RebateCommitment,
}

impl FenceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::EligibilityNullifier => "eligibility_nullifier",
            Self::ClaimNullifier => "claim_nullifier",
            Self::NoteCommitment => "note_commitment",
            Self::PqCredentialTag => "pq_credential_tag",
            Self::SponsorVoucher => "sponsor_voucher",
            Self::SettlementReceipt => "settlement_receipt",
            Self::RebateCommitment => "rebate_commitment",
        }
    }

    pub fn spends_nullifier(self) -> bool {
        matches!(self, Self::EligibilityNullifier | Self::ClaimNullifier)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub protocol_version: String,
    pub schema_version: u64,
    pub chain_id: String,
    pub l2_network: String,
    pub monero_network: String,
    pub airdrop_asset_id: String,
    pub fee_asset_id: String,
    pub hash_suite: String,
    pub eligibility_root_suite: String,
    pub claim_note_suite: String,
    pub claim_netting_proof_suite: String,
    pub pq_attestation_suite: String,
    pub sponsor_fee_suite: String,
    pub settlement_receipt_suite: String,
    pub rebate_suite: String,
    pub privacy_fence_suite: String,
    pub epoch_blocks: u64,
    pub claim_ttl_blocks: u64,
    pub batch_ttl_blocks: u64,
    pub attestation_ttl_blocks: u64,
    pub sponsor_reservation_ttl_blocks: u64,
    pub settlement_window_blocks: u64,
    pub min_privacy_set: u64,
    pub target_privacy_set: u64,
    pub min_batch_claims: u64,
    pub max_batch_claims: usize,
    pub max_user_fee_bps: u64,
    pub target_user_fee_bps: u64,
    pub sponsor_cover_bps: u64,
    pub rebate_bps: u64,
    pub min_pq_security_bits: u16,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            chain_id: CHAIN_ID.to_string(),
            l2_network: DEFAULT_L2_NETWORK.to_string(),
            monero_network: DEFAULT_MONERO_NETWORK.to_string(),
            airdrop_asset_id: DEFAULT_AIRDROP_ASSET_ID.to_string(),
            fee_asset_id: DEFAULT_FEE_ASSET_ID.to_string(),
            hash_suite: HASH_SUITE.to_string(),
            eligibility_root_suite: ELIGIBILITY_ROOT_SUITE.to_string(),
            claim_note_suite: CLAIM_NOTE_SUITE.to_string(),
            claim_netting_proof_suite: CLAIM_NETTING_PROOF_SUITE.to_string(),
            pq_attestation_suite: PQ_ATTESTATION_SUITE.to_string(),
            sponsor_fee_suite: SPONSOR_FEE_SUITE.to_string(),
            settlement_receipt_suite: SETTLEMENT_RECEIPT_SUITE.to_string(),
            rebate_suite: REBATE_SUITE.to_string(),
            privacy_fence_suite: PRIVACY_FENCE_SUITE.to_string(),
            epoch_blocks: DEFAULT_EPOCH_BLOCKS,
            claim_ttl_blocks: DEFAULT_CLAIM_TTL_BLOCKS,
            batch_ttl_blocks: DEFAULT_BATCH_TTL_BLOCKS,
            attestation_ttl_blocks: DEFAULT_ATTESTATION_TTL_BLOCKS,
            sponsor_reservation_ttl_blocks: DEFAULT_SPONSOR_RESERVATION_TTL_BLOCKS,
            settlement_window_blocks: DEFAULT_SETTLEMENT_WINDOW_BLOCKS,
            min_privacy_set: DEFAULT_MIN_PRIVACY_SET,
            target_privacy_set: DEFAULT_TARGET_PRIVACY_SET,
            min_batch_claims: DEFAULT_MIN_BATCH_CLAIMS,
            max_batch_claims: DEFAULT_MAX_BATCH_CLAIMS,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            target_user_fee_bps: DEFAULT_TARGET_USER_FEE_BPS,
            sponsor_cover_bps: DEFAULT_SPONSOR_COVER_BPS,
            rebate_bps: DEFAULT_REBATE_BPS,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn validate(&self) -> Result<()> {
        ensure_nonempty("protocol_version", &self.protocol_version)?;
        ensure_nonempty("chain_id", &self.chain_id)?;
        ensure_nonempty("l2_network", &self.l2_network)?;
        ensure_nonempty("monero_network", &self.monero_network)?;
        ensure_nonempty("airdrop_asset_id", &self.airdrop_asset_id)?;
        ensure_nonempty("fee_asset_id", &self.fee_asset_id)?;
        ensure_bps("max_user_fee_bps", self.max_user_fee_bps)?;
        ensure_bps("target_user_fee_bps", self.target_user_fee_bps)?;
        ensure_bps("sponsor_cover_bps", self.sponsor_cover_bps)?;
        ensure_bps("rebate_bps", self.rebate_bps)?;
        if self.target_user_fee_bps > self.max_user_fee_bps {
            return Err("target_user_fee_bps must be <= max_user_fee_bps".to_string());
        }
        if self.min_privacy_set == 0 || self.target_privacy_set < self.min_privacy_set {
            return Err("target_privacy_set must be >= min_privacy_set".to_string());
        }
        if self.min_batch_claims == 0 || self.max_batch_claims < self.min_batch_claims as usize {
            return Err("max_batch_claims must be >= min_batch_claims".to_string());
        }
        if self.min_pq_security_bits < 192 {
            return Err("min_pq_security_bits below policy floor".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "chain_id": self.chain_id,
            "l2_network": self.l2_network,
            "monero_network": self.monero_network,
            "airdrop_asset_id": self.airdrop_asset_id,
            "fee_asset_id": self.fee_asset_id,
            "hash_suite": self.hash_suite,
            "eligibility_root_suite": self.eligibility_root_suite,
            "claim_note_suite": self.claim_note_suite,
            "claim_netting_proof_suite": self.claim_netting_proof_suite,
            "pq_attestation_suite": self.pq_attestation_suite,
            "sponsor_fee_suite": self.sponsor_fee_suite,
            "settlement_receipt_suite": self.settlement_receipt_suite,
            "rebate_suite": self.rebate_suite,
            "privacy_fence_suite": self.privacy_fence_suite,
            "epoch_blocks": self.epoch_blocks,
            "claim_ttl_blocks": self.claim_ttl_blocks,
            "batch_ttl_blocks": self.batch_ttl_blocks,
            "attestation_ttl_blocks": self.attestation_ttl_blocks,
            "sponsor_reservation_ttl_blocks": self.sponsor_reservation_ttl_blocks,
            "settlement_window_blocks": self.settlement_window_blocks,
            "min_privacy_set": self.min_privacy_set,
            "target_privacy_set": self.target_privacy_set,
            "min_batch_claims": self.min_batch_claims,
            "max_batch_claims": self.max_batch_claims,
            "max_user_fee_bps": self.max_user_fee_bps,
            "target_user_fee_bps": self.target_user_fee_bps,
            "sponsor_cover_bps": self.sponsor_cover_bps,
            "rebate_bps": self.rebate_bps,
            "min_pq_security_bits": self.min_pq_security_bits,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AirdropRequest {
    pub issuer_id: String,
    pub airdrop_symbol: String,
    pub airdrop_kind: AirdropKind,
    pub token_asset_id: String,
    pub sponsor_policy: SponsorPolicy,
    pub supply_cap_commitment: String,
    pub treasury_commitment: String,
    pub policy_root: String,
    pub metadata_root: String,
    pub claim_start_height: u64,
    pub claim_end_height: u64,
    pub decimals: u8,
    pub defi_utility_enabled: bool,
    pub low_fee_enabled: bool,
}

impl AirdropRequest {
    pub fn validate(&self) -> Result<()> {
        ensure_nonempty("issuer_id", &self.issuer_id)?;
        ensure_nonempty("airdrop_symbol", &self.airdrop_symbol)?;
        ensure_nonempty("token_asset_id", &self.token_asset_id)?;
        ensure_hash_like("supply_cap_commitment", &self.supply_cap_commitment)?;
        ensure_hash_like("treasury_commitment", &self.treasury_commitment)?;
        ensure_hash_like("policy_root", &self.policy_root)?;
        ensure_hash_like("metadata_root", &self.metadata_root)?;
        if self.claim_end_height <= self.claim_start_height {
            return Err("claim_end_height must exceed claim_start_height".to_string());
        }
        if self.decimals > 18 {
            return Err("decimals must be <= 18".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "issuer_id": self.issuer_id,
            "airdrop_symbol": self.airdrop_symbol,
            "airdrop_kind": self.airdrop_kind.as_str(),
            "token_asset_id": self.token_asset_id,
            "sponsor_policy": self.sponsor_policy.as_str(),
            "supply_cap_commitment": self.supply_cap_commitment,
            "treasury_commitment": self.treasury_commitment,
            "policy_root": self.policy_root,
            "metadata_root": self.metadata_root,
            "claim_start_height": self.claim_start_height,
            "claim_end_height": self.claim_end_height,
            "decimals": self.decimals,
            "defi_utility_enabled": self.defi_utility_enabled,
            "low_fee_enabled": self.low_fee_enabled,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AirdropRecord {
    pub airdrop_id: String,
    pub request: AirdropRequest,
    pub status: AirdropStatus,
    pub created_height: u64,
    pub updated_height: u64,
}

impl AirdropRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "airdrop_id": self.airdrop_id,
            "request": self.request.public_record(),
            "status": self.status.as_str(),
            "created_height": self.created_height,
            "updated_height": self.updated_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct EligibilityRootRequest {
    pub airdrop_id: String,
    pub root_kind: EligibilityRootKind,
    pub epoch: u64,
    pub eligibility_root: String,
    pub amount_bucket_root: String,
    pub region_fence_root: String,
    pub sybil_score_root: String,
    pub snapshot_root: String,
    pub min_privacy_set: u64,
    pub total_eligible_commitment: String,
    pub attester_id: String,
}

impl EligibilityRootRequest {
    pub fn validate(&self, config: &Config) -> Result<()> {
        ensure_nonempty("airdrop_id", &self.airdrop_id)?;
        ensure_hash_like("eligibility_root", &self.eligibility_root)?;
        ensure_hash_like("amount_bucket_root", &self.amount_bucket_root)?;
        ensure_hash_like("region_fence_root", &self.region_fence_root)?;
        ensure_hash_like("sybil_score_root", &self.sybil_score_root)?;
        ensure_hash_like("snapshot_root", &self.snapshot_root)?;
        ensure_hash_like("total_eligible_commitment", &self.total_eligible_commitment)?;
        ensure_nonempty("attester_id", &self.attester_id)?;
        if self.min_privacy_set < config.min_privacy_set {
            return Err("eligibility root privacy set below config floor".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "airdrop_id": self.airdrop_id,
            "root_kind": self.root_kind.as_str(),
            "epoch": self.epoch,
            "eligibility_root": self.eligibility_root,
            "amount_bucket_root": self.amount_bucket_root,
            "region_fence_root": self.region_fence_root,
            "sybil_score_root": self.sybil_score_root,
            "snapshot_root": self.snapshot_root,
            "min_privacy_set": self.min_privacy_set,
            "total_eligible_commitment": self.total_eligible_commitment,
            "attester_id": self.attester_id,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct EligibilityRootRecord {
    pub eligibility_root_id: String,
    pub request: EligibilityRootRequest,
    pub status: EligibilityRootStatus,
    pub created_height: u64,
    pub updated_height: u64,
}

impl EligibilityRootRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "eligibility_root_id": self.eligibility_root_id,
            "request": self.request.public_record(),
            "status": self.status.as_str(),
            "created_height": self.created_height,
            "updated_height": self.updated_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ClaimNoteRequest {
    pub airdrop_id: String,
    pub eligibility_root_id: String,
    pub note_kind: ClaimNoteKind,
    pub claimant_note_commitment: String,
    pub eligibility_nullifier: String,
    pub claim_nullifier: String,
    pub encrypted_amount_commitment: String,
    pub recipient_stealth_address_commitment: String,
    pub membership_proof_commitment: String,
    pub pq_credential_tag: String,
    pub claim_salt: String,
    pub requested_fee_bps: u64,
    pub privacy_set_size: u64,
}

impl ClaimNoteRequest {
    pub fn validate(&self, config: &Config) -> Result<()> {
        ensure_nonempty("airdrop_id", &self.airdrop_id)?;
        ensure_nonempty("eligibility_root_id", &self.eligibility_root_id)?;
        ensure_hash_like("claimant_note_commitment", &self.claimant_note_commitment)?;
        ensure_hash_like("eligibility_nullifier", &self.eligibility_nullifier)?;
        ensure_hash_like("claim_nullifier", &self.claim_nullifier)?;
        ensure_hash_like(
            "encrypted_amount_commitment",
            &self.encrypted_amount_commitment,
        )?;
        ensure_hash_like(
            "recipient_stealth_address_commitment",
            &self.recipient_stealth_address_commitment,
        )?;
        ensure_hash_like(
            "membership_proof_commitment",
            &self.membership_proof_commitment,
        )?;
        ensure_hash_like("pq_credential_tag", &self.pq_credential_tag)?;
        ensure_nonempty("claim_salt", &self.claim_salt)?;
        ensure_bps("requested_fee_bps", self.requested_fee_bps)?;
        if self.requested_fee_bps > config.max_user_fee_bps {
            return Err("requested_fee_bps exceeds config maximum".to_string());
        }
        if self.privacy_set_size < config.min_privacy_set {
            return Err("claim privacy_set_size below config floor".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "airdrop_id": self.airdrop_id,
            "eligibility_root_id": self.eligibility_root_id,
            "note_kind": self.note_kind.as_str(),
            "claimant_note_commitment": self.claimant_note_commitment,
            "eligibility_nullifier": self.eligibility_nullifier,
            "claim_nullifier": self.claim_nullifier,
            "encrypted_amount_commitment": self.encrypted_amount_commitment,
            "recipient_stealth_address_commitment": self.recipient_stealth_address_commitment,
            "membership_proof_commitment": self.membership_proof_commitment,
            "pq_credential_tag": self.pq_credential_tag,
            "claim_salt": self.claim_salt,
            "requested_fee_bps": self.requested_fee_bps,
            "privacy_set_size": self.privacy_set_size,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ClaimNoteRecord {
    pub claim_note_id: String,
    pub request: ClaimNoteRequest,
    pub status: ClaimNoteStatus,
    pub fee_amount: u128,
    pub expires_height: u64,
    pub created_height: u64,
    pub updated_height: u64,
}

impl ClaimNoteRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "claim_note_id": self.claim_note_id,
            "request": self.request.public_record(),
            "status": self.status.as_str(),
            "fee_amount": self.fee_amount,
            "expires_height": self.expires_height,
            "created_height": self.created_height,
            "updated_height": self.updated_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ClaimBatchRequest {
    pub airdrop_id: String,
    pub lane: BatchLane,
    pub batch_salt: String,
    pub claim_note_ids: Vec<String>,
    pub output_note_commitments: Vec<String>,
    pub net_mint_amount_commitment: String,
    pub gross_claim_amount_commitment: String,
    pub fee_commitment: String,
    pub proof_commitment: String,
    pub sponsor_hint: Option<String>,
    pub requested_fee_bps: u64,
    pub privacy_set_size: u64,
}

impl ClaimBatchRequest {
    pub fn validate(&self, config: &Config) -> Result<()> {
        ensure_nonempty("airdrop_id", &self.airdrop_id)?;
        ensure_nonempty("batch_salt", &self.batch_salt)?;
        if self.claim_note_ids.len() < config.min_batch_claims as usize {
            return Err("claim batch below min_batch_claims".to_string());
        }
        if self.claim_note_ids.len() > config.max_batch_claims {
            return Err("claim batch exceeds max_batch_claims".to_string());
        }
        if self.output_note_commitments.len() != self.claim_note_ids.len() {
            return Err("output_note_commitments must match claim_note_ids length".to_string());
        }
        ensure_unique("claim_note_ids", &self.claim_note_ids)?;
        ensure_unique("output_note_commitments", &self.output_note_commitments)?;
        for claim_note_id in &self.claim_note_ids {
            ensure_hash_like("claim_note_id", claim_note_id)?;
        }
        for output in &self.output_note_commitments {
            ensure_hash_like("output_note_commitment", output)?;
        }
        ensure_hash_like(
            "net_mint_amount_commitment",
            &self.net_mint_amount_commitment,
        )?;
        ensure_hash_like(
            "gross_claim_amount_commitment",
            &self.gross_claim_amount_commitment,
        )?;
        ensure_hash_like("fee_commitment", &self.fee_commitment)?;
        ensure_hash_like("proof_commitment", &self.proof_commitment)?;
        ensure_bps("requested_fee_bps", self.requested_fee_bps)?;
        if self.requested_fee_bps > self.lane.fee_bps(config) {
            return Err("requested_fee_bps exceeds lane limit".to_string());
        }
        if self.privacy_set_size < config.min_privacy_set {
            return Err("batch privacy_set_size below config floor".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "airdrop_id": self.airdrop_id,
            "lane": self.lane.as_str(),
            "batch_salt": self.batch_salt,
            "claim_note_ids": self.claim_note_ids,
            "output_note_commitments": self.output_note_commitments,
            "net_mint_amount_commitment": self.net_mint_amount_commitment,
            "gross_claim_amount_commitment": self.gross_claim_amount_commitment,
            "fee_commitment": self.fee_commitment,
            "proof_commitment": self.proof_commitment,
            "sponsor_hint": self.sponsor_hint,
            "requested_fee_bps": self.requested_fee_bps,
            "privacy_set_size": self.privacy_set_size,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ClaimBatchRecord {
    pub claim_batch_id: String,
    pub request: ClaimBatchRequest,
    pub status: BatchStatus,
    pub claim_count: u64,
    pub estimated_fee_amount: u128,
    pub expires_height: u64,
    pub created_height: u64,
    pub updated_height: u64,
}

impl ClaimBatchRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "claim_batch_id": self.claim_batch_id,
            "request": self.request.public_record(),
            "status": self.status.as_str(),
            "claim_count": self.claim_count,
            "estimated_fee_amount": self.estimated_fee_amount,
            "expires_height": self.expires_height,
            "created_height": self.created_height,
            "updated_height": self.updated_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PqAttestationRequest {
    pub airdrop_id: String,
    pub claim_note_id: Option<String>,
    pub claim_batch_id: Option<String>,
    pub attestation_kind: PqAttestationKind,
    pub verdict: AttestationVerdict,
    pub attester_id: String,
    pub credential_root: String,
    pub anti_sybil_root: String,
    pub selective_disclosure_root: String,
    pub min_security_bits: u16,
    pub expires_height: u64,
}

impl PqAttestationRequest {
    pub fn validate(&self, config: &Config) -> Result<()> {
        ensure_nonempty("airdrop_id", &self.airdrop_id)?;
        if self.claim_note_id.is_none() && self.claim_batch_id.is_none() {
            return Err("attestation must target a claim note or batch".to_string());
        }
        ensure_nonempty("attester_id", &self.attester_id)?;
        ensure_hash_like("credential_root", &self.credential_root)?;
        ensure_hash_like("anti_sybil_root", &self.anti_sybil_root)?;
        ensure_hash_like("selective_disclosure_root", &self.selective_disclosure_root)?;
        if self.min_security_bits < config.min_pq_security_bits {
            return Err("PQ attestation below configured security bits".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "airdrop_id": self.airdrop_id,
            "claim_note_id": self.claim_note_id,
            "claim_batch_id": self.claim_batch_id,
            "attestation_kind": self.attestation_kind.as_str(),
            "verdict": self.verdict.as_str(),
            "attester_id": self.attester_id,
            "credential_root": self.credential_root,
            "anti_sybil_root": self.anti_sybil_root,
            "selective_disclosure_root": self.selective_disclosure_root,
            "min_security_bits": self.min_security_bits,
            "expires_height": self.expires_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PqAttestationRecord {
    pub pq_attestation_id: String,
    pub request: PqAttestationRequest,
    pub created_height: u64,
}

impl PqAttestationRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "pq_attestation_id": self.pq_attestation_id,
            "request": self.request.public_record(),
            "created_height": self.created_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SponsorReservationRequest {
    pub sponsor_id: String,
    pub airdrop_id: String,
    pub claim_batch_id: String,
    pub policy: SponsorPolicy,
    pub max_fee_amount: u128,
    pub reserved_fee_commitment: String,
    pub voucher_commitment: String,
    pub cover_bps: u64,
    pub expires_height: u64,
}

impl SponsorReservationRequest {
    pub fn validate(&self, config: &Config) -> Result<()> {
        ensure_nonempty("sponsor_id", &self.sponsor_id)?;
        ensure_nonempty("airdrop_id", &self.airdrop_id)?;
        ensure_nonempty("claim_batch_id", &self.claim_batch_id)?;
        if !self.policy.sponsored() {
            return Err("sponsor reservation requires sponsored policy".to_string());
        }
        ensure_hash_like("reserved_fee_commitment", &self.reserved_fee_commitment)?;
        ensure_hash_like("voucher_commitment", &self.voucher_commitment)?;
        ensure_bps("cover_bps", self.cover_bps)?;
        if self.cover_bps < config.sponsor_cover_bps {
            return Err("cover_bps below configured sponsor cover".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "sponsor_id": self.sponsor_id,
            "airdrop_id": self.airdrop_id,
            "claim_batch_id": self.claim_batch_id,
            "policy": self.policy.as_str(),
            "max_fee_amount": self.max_fee_amount,
            "reserved_fee_commitment": self.reserved_fee_commitment,
            "voucher_commitment": self.voucher_commitment,
            "cover_bps": self.cover_bps,
            "expires_height": self.expires_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SponsorReservationRecord {
    pub reservation_id: String,
    pub request: SponsorReservationRequest,
    pub status: ReservationStatus,
    pub created_height: u64,
    pub updated_height: u64,
}

impl SponsorReservationRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "reservation_id": self.reservation_id,
            "request": self.request.public_record(),
            "status": self.status.as_str(),
            "created_height": self.created_height,
            "updated_height": self.updated_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SettlementReceiptRequest {
    pub airdrop_id: String,
    pub claim_batch_id: String,
    pub receipt_kind: ReceiptKind,
    pub settlement_root: String,
    pub minted_note_root: String,
    pub spent_nullifier_root: String,
    pub fee_paid_amount: u128,
    pub sponsor_paid_amount: u128,
    pub settled_height: u64,
}

impl SettlementReceiptRequest {
    pub fn validate(&self) -> Result<()> {
        ensure_nonempty("airdrop_id", &self.airdrop_id)?;
        ensure_nonempty("claim_batch_id", &self.claim_batch_id)?;
        ensure_hash_like("settlement_root", &self.settlement_root)?;
        ensure_hash_like("minted_note_root", &self.minted_note_root)?;
        ensure_hash_like("spent_nullifier_root", &self.spent_nullifier_root)?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "airdrop_id": self.airdrop_id,
            "claim_batch_id": self.claim_batch_id,
            "receipt_kind": self.receipt_kind.as_str(),
            "settlement_root": self.settlement_root,
            "minted_note_root": self.minted_note_root,
            "spent_nullifier_root": self.spent_nullifier_root,
            "fee_paid_amount": self.fee_paid_amount,
            "sponsor_paid_amount": self.sponsor_paid_amount,
            "settled_height": self.settled_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SettlementReceiptRecord {
    pub receipt_id: String,
    pub request: SettlementReceiptRequest,
    pub created_height: u64,
}

impl SettlementReceiptRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "request": self.request.public_record(),
            "created_height": self.created_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RebateRequest {
    pub airdrop_id: String,
    pub claim_batch_id: String,
    pub recipient_commitment: String,
    pub rebate_note_commitment: String,
    pub rebate_reason: RebateReason,
    pub rebate_amount: u128,
    pub fee_asset_id: String,
}

impl RebateRequest {
    pub fn validate(&self) -> Result<()> {
        ensure_nonempty("airdrop_id", &self.airdrop_id)?;
        ensure_nonempty("claim_batch_id", &self.claim_batch_id)?;
        ensure_hash_like("recipient_commitment", &self.recipient_commitment)?;
        ensure_hash_like("rebate_note_commitment", &self.rebate_note_commitment)?;
        ensure_nonempty("fee_asset_id", &self.fee_asset_id)?;
        if self.rebate_amount == 0 {
            return Err("rebate_amount must be nonzero".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "airdrop_id": self.airdrop_id,
            "claim_batch_id": self.claim_batch_id,
            "recipient_commitment": self.recipient_commitment,
            "rebate_note_commitment": self.rebate_note_commitment,
            "rebate_reason": self.rebate_reason.as_str(),
            "rebate_amount": self.rebate_amount,
            "fee_asset_id": self.fee_asset_id,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RebateRecord {
    pub rebate_id: String,
    pub request: RebateRequest,
    pub created_height: u64,
}

impl RebateRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "rebate_id": self.rebate_id,
            "request": self.request.public_record(),
            "created_height": self.created_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PrivacyFenceRequest {
    pub airdrop_id: String,
    pub claim_note_id: Option<String>,
    pub claim_batch_id: Option<String>,
    pub fence_kind: FenceKind,
    pub fence_commitment: String,
    pub privacy_set_root: String,
    pub effective_height: u64,
}

impl PrivacyFenceRequest {
    pub fn validate(&self) -> Result<()> {
        ensure_nonempty("airdrop_id", &self.airdrop_id)?;
        if self.claim_note_id.is_none() && self.claim_batch_id.is_none() {
            return Err("privacy fence must target a claim note or batch".to_string());
        }
        ensure_hash_like("fence_commitment", &self.fence_commitment)?;
        ensure_hash_like("privacy_set_root", &self.privacy_set_root)?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "airdrop_id": self.airdrop_id,
            "claim_note_id": self.claim_note_id,
            "claim_batch_id": self.claim_batch_id,
            "fence_kind": self.fence_kind.as_str(),
            "fence_commitment": self.fence_commitment,
            "privacy_set_root": self.privacy_set_root,
            "effective_height": self.effective_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PrivacyFenceRecord {
    pub fence_id: String,
    pub request: PrivacyFenceRequest,
    pub created_height: u64,
}

impl PrivacyFenceRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "fence_id": self.fence_id,
            "request": self.request.public_record(),
            "created_height": self.created_height,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Counters {
    pub airdrops: u64,
    pub eligibility_roots: u64,
    pub claim_notes: u64,
    pub claim_batches: u64,
    pub pq_attestations: u64,
    pub sponsor_reservations: u64,
    pub settlement_receipts: u64,
    pub rebates: u64,
    pub privacy_fences: u64,
    pub nullifiers: u64,
    pub public_records: u64,
    pub submitted_claims: u64,
    pub minted_claims: u64,
    pub sponsor_reserved_amount: u128,
    pub sponsor_paid_amount: u128,
    pub fee_paid_amount: u128,
    pub rebated_amount: u128,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "airdrops": self.airdrops,
            "eligibility_roots": self.eligibility_roots,
            "claim_notes": self.claim_notes,
            "claim_batches": self.claim_batches,
            "pq_attestations": self.pq_attestations,
            "sponsor_reservations": self.sponsor_reservations,
            "settlement_receipts": self.settlement_receipts,
            "rebates": self.rebates,
            "privacy_fences": self.privacy_fences,
            "nullifiers": self.nullifiers,
            "public_records": self.public_records,
            "submitted_claims": self.submitted_claims,
            "minted_claims": self.minted_claims,
            "sponsor_reserved_amount": self.sponsor_reserved_amount,
            "sponsor_paid_amount": self.sponsor_paid_amount,
            "fee_paid_amount": self.fee_paid_amount,
            "rebated_amount": self.rebated_amount,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Roots {
    pub airdrop_root: String,
    pub eligibility_root_root: String,
    pub claim_note_root: String,
    pub claim_batch_root: String,
    pub pq_attestation_root: String,
    pub sponsor_reservation_root: String,
    pub settlement_receipt_root: String,
    pub rebate_root: String,
    pub privacy_fence_root: String,
    pub nullifier_root: String,
    pub public_record_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "airdrop_root": self.airdrop_root,
            "eligibility_root_root": self.eligibility_root_root,
            "claim_note_root": self.claim_note_root,
            "claim_batch_root": self.claim_batch_root,
            "pq_attestation_root": self.pq_attestation_root,
            "sponsor_reservation_root": self.sponsor_reservation_root,
            "settlement_receipt_root": self.settlement_receipt_root,
            "rebate_root": self.rebate_root,
            "privacy_fence_root": self.privacy_fence_root,
            "nullifier_root": self.nullifier_root,
            "public_record_root": self.public_record_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PublicRuntimeRecord {
    pub record_id: String,
    pub record_kind: String,
    pub subject_id: String,
    pub height: u64,
    pub payload: Value,
}

impl PublicRuntimeRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "record_id": self.record_id,
            "record_kind": self.record_kind,
            "subject_id": self.subject_id,
            "height": self.height,
            "payload": self.payload,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub height: u64,
    pub airdrops: BTreeMap<String, AirdropRecord>,
    pub eligibility_roots: BTreeMap<String, EligibilityRootRecord>,
    pub claim_notes: BTreeMap<String, ClaimNoteRecord>,
    pub claim_batches: BTreeMap<String, ClaimBatchRecord>,
    pub pq_attestations: BTreeMap<String, PqAttestationRecord>,
    pub sponsor_reservations: BTreeMap<String, SponsorReservationRecord>,
    pub settlement_receipts: BTreeMap<String, SettlementReceiptRecord>,
    pub rebates: BTreeMap<String, RebateRecord>,
    pub privacy_fences: BTreeMap<String, PrivacyFenceRecord>,
    pub nullifiers: BTreeSet<String>,
    pub public_records: BTreeMap<String, PublicRuntimeRecord>,
}

impl State {
    pub fn new(config: Config, height: u64) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            config,
            height,
            airdrops: BTreeMap::new(),
            eligibility_roots: BTreeMap::new(),
            claim_notes: BTreeMap::new(),
            claim_batches: BTreeMap::new(),
            pq_attestations: BTreeMap::new(),
            sponsor_reservations: BTreeMap::new(),
            settlement_receipts: BTreeMap::new(),
            rebates: BTreeMap::new(),
            privacy_fences: BTreeMap::new(),
            nullifiers: BTreeSet::new(),
            public_records: BTreeMap::new(),
        })
    }

    pub fn devnet() -> Result<Self> {
        let mut state = Self::new(Config::devnet(), DEVNET_HEIGHT)?;
        let airdrop_id = state.register_airdrop(
            AirdropRequest {
                issuer_id: "issuer:devnet-community-foundation".to_string(),
                airdrop_symbol: "CLAIMD".to_string(),
                airdrop_kind: AirdropKind::CommunityRetroactive,
                token_asset_id: DEFAULT_AIRDROP_ASSET_ID.to_string(),
                sponsor_policy: SponsorPolicy::FullClaimLane,
                supply_cap_commitment: sample_hash("supply-cap"),
                treasury_commitment: sample_hash("treasury"),
                policy_root: sample_hash("policy"),
                metadata_root: sample_hash("metadata"),
                claim_start_height: DEVNET_HEIGHT,
                claim_end_height: DEVNET_HEIGHT + DEFAULT_EPOCH_BLOCKS * 8,
                decimals: 6,
                defi_utility_enabled: true,
                low_fee_enabled: true,
            },
            AirdropStatus::Claiming,
        )?;
        let root_id = state.commit_eligibility_root(
            EligibilityRootRequest {
                airdrop_id: airdrop_id.clone(),
                root_kind: EligibilityRootKind::WalletActivity,
                epoch: 1,
                eligibility_root: sample_hash("eligibility"),
                amount_bucket_root: sample_hash("amount-bucket"),
                region_fence_root: sample_hash("region-fence"),
                sybil_score_root: sample_hash("sybil-score"),
                snapshot_root: sample_hash("snapshot"),
                min_privacy_set: DEFAULT_TARGET_PRIVACY_SET,
                total_eligible_commitment: sample_hash("total-eligible"),
                attester_id: "attester:devnet-pq-anti-sybil-council".to_string(),
            },
            EligibilityRootStatus::Active,
        )?;
        let mut claim_ids = Vec::new();
        for index in 0..DEFAULT_MIN_BATCH_CLAIMS {
            let claim_id = state.submit_claim_note(ClaimNoteRequest {
                airdrop_id: airdrop_id.clone(),
                eligibility_root_id: root_id.clone(),
                note_kind: ClaimNoteKind::StandardClaim,
                claimant_note_commitment: sample_hash(&format!("claim-note-{index}")),
                eligibility_nullifier: sample_hash(&format!("eligibility-nullifier-{index}")),
                claim_nullifier: sample_hash(&format!("claim-nullifier-{index}")),
                encrypted_amount_commitment: sample_hash(&format!("amount-{index}")),
                recipient_stealth_address_commitment: sample_hash(&format!("stealth-{index}")),
                membership_proof_commitment: sample_hash(&format!("membership-{index}")),
                pq_credential_tag: sample_hash(&format!("pq-tag-{index}")),
                claim_salt: format!("devnet-claim-salt-{index}"),
                requested_fee_bps: DEFAULT_TARGET_USER_FEE_BPS,
                privacy_set_size: DEFAULT_TARGET_PRIVACY_SET,
            })?;
            state.record_pq_attestation(PqAttestationRequest {
                airdrop_id: airdrop_id.clone(),
                claim_note_id: Some(claim_id.clone()),
                claim_batch_id: None,
                attestation_kind: PqAttestationKind::AntiSybil,
                verdict: AttestationVerdict::Allow,
                attester_id: "attester:devnet-pq-anti-sybil-council".to_string(),
                credential_root: sample_hash(&format!("credential-{index}")),
                anti_sybil_root: sample_hash(&format!("anti-sybil-{index}")),
                selective_disclosure_root: sample_hash(&format!("disclosure-{index}")),
                min_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
                expires_height: state.height + DEFAULT_ATTESTATION_TTL_BLOCKS,
            })?;
            state.install_privacy_fence(PrivacyFenceRequest {
                airdrop_id: airdrop_id.clone(),
                claim_note_id: Some(claim_id.clone()),
                claim_batch_id: None,
                fence_kind: FenceKind::ClaimNullifier,
                fence_commitment: sample_hash(&format!("claim-nullifier-{index}")),
                privacy_set_root: sample_hash("claim-privacy-set"),
                effective_height: state.height,
            })?;
            claim_ids.push(claim_id);
        }
        let batch_id = state.propose_claim_batch(ClaimBatchRequest {
            airdrop_id: airdrop_id.clone(),
            lane: BatchLane::SponsorFunded,
            batch_salt: "devnet-airdrop-batch-0001".to_string(),
            output_note_commitments: (0..DEFAULT_MIN_BATCH_CLAIMS)
                .map(|index| sample_hash(&format!("output-note-{index}")))
                .collect(),
            claim_note_ids: claim_ids,
            net_mint_amount_commitment: sample_hash("net-mint"),
            gross_claim_amount_commitment: sample_hash("gross-claim"),
            fee_commitment: sample_hash("fee"),
            proof_commitment: sample_hash("netting-proof"),
            sponsor_hint: Some("sponsor:devnet-low-fee-airdrop-desk".to_string()),
            requested_fee_bps: 1,
            privacy_set_size: DEFAULT_TARGET_PRIVACY_SET,
        })?;
        state.reserve_sponsor_fee(SponsorReservationRequest {
            sponsor_id: "sponsor:devnet-low-fee-airdrop-desk".to_string(),
            airdrop_id: airdrop_id.clone(),
            claim_batch_id: batch_id.clone(),
            policy: SponsorPolicy::FullClaimLane,
            max_fee_amount: 50_000,
            reserved_fee_commitment: sample_hash("reserved-fee"),
            voucher_commitment: sample_hash("voucher"),
            cover_bps: DEFAULT_SPONSOR_COVER_BPS,
            expires_height: state.height + DEFAULT_SPONSOR_RESERVATION_TTL_BLOCKS,
        })?;
        state.settle_claim_batch(SettlementReceiptRequest {
            airdrop_id: airdrop_id.clone(),
            claim_batch_id: batch_id.clone(),
            receipt_kind: ReceiptKind::SponsorPaidMint,
            settlement_root: sample_hash("settlement"),
            minted_note_root: sample_hash("minted-notes"),
            spent_nullifier_root: sample_hash("spent-nullifiers"),
            fee_paid_amount: 8,
            sponsor_paid_amount: 7,
            settled_height: state.height + 1,
        })?;
        state.record_rebate(RebateRequest {
            airdrop_id,
            claim_batch_id: batch_id,
            recipient_commitment: sample_hash("rebate-recipient"),
            rebate_note_commitment: sample_hash("rebate-note"),
            rebate_reason: RebateReason::BatchCompression,
            rebate_amount: 3,
            fee_asset_id: DEFAULT_FEE_ASSET_ID.to_string(),
        })?;
        Ok(state)
    }

    pub fn register_airdrop(
        &mut self,
        request: AirdropRequest,
        status: AirdropStatus,
    ) -> Result<String> {
        request.validate()?;
        ensure_capacity("airdrops", self.airdrops.len(), MAX_AIRDROPS)?;
        let airdrop_id = airdrop_id(&request);
        if self.airdrops.contains_key(&airdrop_id) {
            return Err(format!("airdrop already exists: {airdrop_id}"));
        }
        let record = AirdropRecord {
            airdrop_id: airdrop_id.clone(),
            request,
            status,
            created_height: self.height,
            updated_height: self.height,
        };
        self.publish("airdrop", &airdrop_id, record.public_record())?;
        self.airdrops.insert(airdrop_id.clone(), record);
        Ok(airdrop_id)
    }

    pub fn commit_eligibility_root(
        &mut self,
        request: EligibilityRootRequest,
        status: EligibilityRootStatus,
    ) -> Result<String> {
        request.validate(&self.config)?;
        ensure_capacity(
            "eligibility_roots",
            self.eligibility_roots.len(),
            MAX_ELIGIBILITY_ROOTS,
        )?;
        let airdrop = self
            .airdrops
            .get_mut(&request.airdrop_id)
            .ok_or_else(|| format!("unknown airdrop_id: {}", request.airdrop_id))?;
        let root_id = eligibility_root_id(&request);
        if self.eligibility_roots.contains_key(&root_id) {
            return Err(format!("eligibility root already exists: {root_id}"));
        }
        if airdrop.status == AirdropStatus::Draft && status.usable() {
            airdrop.status = AirdropStatus::RootCommitted;
            airdrop.updated_height = self.height;
        }
        let record = EligibilityRootRecord {
            eligibility_root_id: root_id.clone(),
            request,
            status,
            created_height: self.height,
            updated_height: self.height,
        };
        self.publish("eligibility_root", &root_id, record.public_record())?;
        self.eligibility_roots.insert(root_id.clone(), record);
        Ok(root_id)
    }

    pub fn submit_claim_note(&mut self, request: ClaimNoteRequest) -> Result<String> {
        request.validate(&self.config)?;
        ensure_capacity("claim_notes", self.claim_notes.len(), MAX_CLAIM_NOTES)?;
        let airdrop = self
            .airdrops
            .get(&request.airdrop_id)
            .ok_or_else(|| format!("unknown airdrop_id: {}", request.airdrop_id))?;
        if !airdrop.status.accepts_claims() {
            return Err("airdrop does not accept claims".to_string());
        }
        if self.height < airdrop.request.claim_start_height
            || self.height > airdrop.request.claim_end_height
        {
            return Err("claim outside configured airdrop window".to_string());
        }
        let root = self
            .eligibility_roots
            .get(&request.eligibility_root_id)
            .ok_or_else(|| {
                format!(
                    "unknown eligibility_root_id: {}",
                    request.eligibility_root_id
                )
            })?;
        if root.request.airdrop_id != request.airdrop_id {
            return Err("eligibility root does not belong to airdrop".to_string());
        }
        if !root.status.usable() {
            return Err("eligibility root is not usable".to_string());
        }
        for nullifier in [&request.eligibility_nullifier, &request.claim_nullifier] {
            if self.nullifiers.contains(nullifier) {
                return Err(format!("nullifier already spent or fenced: {nullifier}"));
            }
        }
        let claim_note_id = claim_note_id(&request);
        if self.claim_notes.contains_key(&claim_note_id) {
            return Err(format!("claim note already exists: {claim_note_id}"));
        }
        let fee_amount = claim_fee_amount(&request, &self.config);
        let record = ClaimNoteRecord {
            claim_note_id: claim_note_id.clone(),
            request,
            status: ClaimNoteStatus::Submitted,
            fee_amount,
            expires_height: self.height + self.config.claim_ttl_blocks,
            created_height: self.height,
            updated_height: self.height,
        };
        self.publish("claim_note", &claim_note_id, record.public_record())?;
        self.claim_notes.insert(claim_note_id.clone(), record);
        Ok(claim_note_id)
    }

    pub fn record_pq_attestation(&mut self, request: PqAttestationRequest) -> Result<String> {
        request.validate(&self.config)?;
        ensure_capacity(
            "pq_attestations",
            self.pq_attestations.len(),
            MAX_PQ_ATTESTATIONS,
        )?;
        let attestation_id = pq_attestation_id(&request);
        if self.pq_attestations.contains_key(&attestation_id) {
            return Err(format!("PQ attestation already exists: {attestation_id}"));
        }
        if let Some(claim_note_id) = &request.claim_note_id {
            let claim = self
                .claim_notes
                .get_mut(claim_note_id)
                .ok_or_else(|| format!("unknown claim_note_id: {claim_note_id}"))?;
            if claim.request.airdrop_id != request.airdrop_id {
                return Err("PQ attestation airdrop mismatch for claim note".to_string());
            }
            claim.status = if request.verdict.permits_claim() {
                ClaimNoteStatus::Attested
            } else {
                ClaimNoteStatus::Rejected
            };
            claim.updated_height = self.height;
        }
        if let Some(batch_id) = &request.claim_batch_id {
            let batch = self
                .claim_batches
                .get_mut(batch_id)
                .ok_or_else(|| format!("unknown claim_batch_id: {batch_id}"))?;
            if batch.request.airdrop_id != request.airdrop_id {
                return Err("PQ attestation airdrop mismatch for claim batch".to_string());
            }
            batch.status = if request.verdict.permits_claim() {
                BatchStatus::Attested
            } else {
                BatchStatus::Rejected
            };
            batch.updated_height = self.height;
        }
        let record = PqAttestationRecord {
            pq_attestation_id: attestation_id.clone(),
            request,
            created_height: self.height,
        };
        self.publish("pq_attestation", &attestation_id, record.public_record())?;
        self.pq_attestations.insert(attestation_id.clone(), record);
        Ok(attestation_id)
    }

    pub fn install_privacy_fence(&mut self, request: PrivacyFenceRequest) -> Result<String> {
        request.validate()?;
        ensure_capacity(
            "privacy_fences",
            self.privacy_fences.len(),
            MAX_PRIVACY_FENCES,
        )?;
        let fence_id = privacy_fence_id(&request);
        if self.privacy_fences.contains_key(&fence_id) {
            return Err(format!("privacy fence already exists: {fence_id}"));
        }
        if request.fence_kind.spends_nullifier() {
            ensure_capacity("nullifiers", self.nullifiers.len(), MAX_NULLIFIERS)?;
            if self.nullifiers.contains(&request.fence_commitment) {
                return Err("privacy fence nullifier already installed".to_string());
            }
            self.nullifiers.insert(request.fence_commitment.clone());
        }
        if let Some(claim_note_id) = &request.claim_note_id {
            let claim = self
                .claim_notes
                .get_mut(claim_note_id)
                .ok_or_else(|| format!("unknown claim_note_id: {claim_note_id}"))?;
            if claim.request.airdrop_id != request.airdrop_id {
                return Err("privacy fence airdrop mismatch for claim note".to_string());
            }
            if request.fence_kind == FenceKind::ClaimNullifier
                && claim.request.claim_nullifier != request.fence_commitment
            {
                return Err("claim nullifier fence does not match claim note".to_string());
            }
            if claim.status.batchable() {
                claim.status = ClaimNoteStatus::Fenced;
                claim.updated_height = self.height;
            }
        }
        if let Some(batch_id) = &request.claim_batch_id {
            let batch = self
                .claim_batches
                .get_mut(batch_id)
                .ok_or_else(|| format!("unknown claim_batch_id: {batch_id}"))?;
            if batch.request.airdrop_id != request.airdrop_id {
                return Err("privacy fence airdrop mismatch for claim batch".to_string());
            }
            if batch.status == BatchStatus::Proposed {
                batch.status = BatchStatus::PrivacyFenced;
                batch.updated_height = self.height;
            }
        }
        let record = PrivacyFenceRecord {
            fence_id: fence_id.clone(),
            request,
            created_height: self.height,
        };
        self.publish("privacy_fence", &fence_id, record.public_record())?;
        self.privacy_fences.insert(fence_id.clone(), record);
        Ok(fence_id)
    }

    pub fn propose_claim_batch(&mut self, request: ClaimBatchRequest) -> Result<String> {
        request.validate(&self.config)?;
        ensure_capacity("claim_batches", self.claim_batches.len(), MAX_CLAIM_BATCHES)?;
        let airdrop = self
            .airdrops
            .get(&request.airdrop_id)
            .ok_or_else(|| format!("unknown airdrop_id: {}", request.airdrop_id))?;
        if !airdrop.status.accepts_batches() {
            return Err("airdrop does not accept claim batches".to_string());
        }
        let mut estimated_fee_amount = 0_u128;
        for claim_id in &request.claim_note_ids {
            let claim = self
                .claim_notes
                .get(claim_id)
                .ok_or_else(|| format!("unknown claim_note_id: {claim_id}"))?;
            if claim.request.airdrop_id != request.airdrop_id {
                return Err("claim note airdrop mismatch in batch".to_string());
            }
            if !claim.status.batchable() {
                return Err(format!("claim note is not batchable: {claim_id}"));
            }
            estimated_fee_amount = estimated_fee_amount.saturating_add(claim.fee_amount);
        }
        let batch_id = claim_batch_id(&request);
        if self.claim_batches.contains_key(&batch_id) {
            return Err(format!("claim batch already exists: {batch_id}"));
        }
        for claim_id in &request.claim_note_ids {
            if let Some(claim) = self.claim_notes.get_mut(claim_id) {
                claim.status = ClaimNoteStatus::Queued;
                claim.updated_height = self.height;
            }
        }
        let record = ClaimBatchRecord {
            claim_batch_id: batch_id.clone(),
            claim_count: request.claim_note_ids.len() as u64,
            estimated_fee_amount,
            expires_height: self.height + self.config.batch_ttl_blocks,
            request,
            status: BatchStatus::Proposed,
            created_height: self.height,
            updated_height: self.height,
        };
        self.publish("claim_batch", &batch_id, record.public_record())?;
        self.claim_batches.insert(batch_id.clone(), record);
        Ok(batch_id)
    }

    pub fn reserve_sponsor_fee(&mut self, request: SponsorReservationRequest) -> Result<String> {
        request.validate(&self.config)?;
        ensure_capacity(
            "sponsor_reservations",
            self.sponsor_reservations.len(),
            MAX_SPONSOR_RESERVATIONS,
        )?;
        let batch = self
            .claim_batches
            .get_mut(&request.claim_batch_id)
            .ok_or_else(|| format!("unknown claim_batch_id: {}", request.claim_batch_id))?;
        if batch.request.airdrop_id != request.airdrop_id {
            return Err("sponsor reservation airdrop mismatch".to_string());
        }
        if request.max_fee_amount < batch.estimated_fee_amount {
            return Err("max_fee_amount below batch estimated fee".to_string());
        }
        let reservation_id = sponsor_reservation_id(&request);
        if self.sponsor_reservations.contains_key(&reservation_id) {
            return Err(format!(
                "sponsor reservation already exists: {reservation_id}"
            ));
        }
        batch.status = BatchStatus::SponsorReserved;
        batch.updated_height = self.height;
        let record = SponsorReservationRecord {
            reservation_id: reservation_id.clone(),
            request,
            status: ReservationStatus::Attached,
            created_height: self.height,
            updated_height: self.height,
        };
        self.publish(
            "sponsor_reservation",
            &reservation_id,
            record.public_record(),
        )?;
        self.sponsor_reservations
            .insert(reservation_id.clone(), record);
        Ok(reservation_id)
    }

    pub fn mark_batch_netted(&mut self, claim_batch_id: &str) -> Result<()> {
        let batch = self
            .claim_batches
            .get_mut(claim_batch_id)
            .ok_or_else(|| format!("unknown claim_batch_id: {claim_batch_id}"))?;
        if !batch.status.live() {
            return Err("claim batch is not live".to_string());
        }
        batch.status = BatchStatus::Netted;
        batch.updated_height = self.height;
        for claim_id in &batch.request.claim_note_ids {
            if let Some(claim) = self.claim_notes.get_mut(claim_id) {
                claim.status = ClaimNoteStatus::Netted;
                claim.updated_height = self.height;
            }
        }
        let payload = batch.public_record();
        self.publish("claim_batch_netted", claim_batch_id, payload)
    }

    pub fn settle_claim_batch(&mut self, request: SettlementReceiptRequest) -> Result<String> {
        request.validate()?;
        ensure_capacity(
            "settlement_receipts",
            self.settlement_receipts.len(),
            MAX_SETTLEMENT_RECEIPTS,
        )?;
        let batch = self
            .claim_batches
            .get_mut(&request.claim_batch_id)
            .ok_or_else(|| format!("unknown claim_batch_id: {}", request.claim_batch_id))?;
        if batch.request.airdrop_id != request.airdrop_id {
            return Err("settlement receipt airdrop mismatch".to_string());
        }
        if !batch.status.live() {
            return Err("claim batch is not live for settlement".to_string());
        }
        let receipt_id = settlement_receipt_id(&request);
        if self.settlement_receipts.contains_key(&receipt_id) {
            return Err(format!("settlement receipt already exists: {receipt_id}"));
        }
        batch.status = BatchStatus::Settled;
        batch.updated_height = request.settled_height;
        self.height = self.height.max(request.settled_height);
        for claim_id in &batch.request.claim_note_ids {
            if let Some(claim) = self.claim_notes.get_mut(claim_id) {
                claim.status = ClaimNoteStatus::Minted;
                claim.updated_height = self.height;
            }
        }
        for reservation in self.sponsor_reservations.values_mut() {
            if reservation.request.claim_batch_id == request.claim_batch_id {
                reservation.status = ReservationStatus::Consumed;
                reservation.updated_height = self.height;
            }
        }
        let record = SettlementReceiptRecord {
            receipt_id: receipt_id.clone(),
            request,
            created_height: self.height,
        };
        self.publish("settlement_receipt", &receipt_id, record.public_record())?;
        self.settlement_receipts.insert(receipt_id.clone(), record);
        Ok(receipt_id)
    }

    pub fn record_rebate(&mut self, request: RebateRequest) -> Result<String> {
        request.validate()?;
        ensure_capacity("rebates", self.rebates.len(), MAX_REBATES)?;
        let batch = self
            .claim_batches
            .get(&request.claim_batch_id)
            .ok_or_else(|| format!("unknown claim_batch_id: {}", request.claim_batch_id))?;
        if batch.request.airdrop_id != request.airdrop_id {
            return Err("rebate airdrop mismatch".to_string());
        }
        let rebate_id = rebate_id(&request);
        if self.rebates.contains_key(&rebate_id) {
            return Err(format!("rebate already exists: {rebate_id}"));
        }
        let record = RebateRecord {
            rebate_id: rebate_id.clone(),
            request,
            created_height: self.height,
        };
        self.publish("rebate", &rebate_id, record.public_record())?;
        self.rebates.insert(rebate_id.clone(), record);
        Ok(rebate_id)
    }

    pub fn counters(&self) -> Counters {
        let mut counters = Counters {
            airdrops: self.airdrops.len() as u64,
            eligibility_roots: self.eligibility_roots.len() as u64,
            claim_notes: self.claim_notes.len() as u64,
            claim_batches: self.claim_batches.len() as u64,
            pq_attestations: self.pq_attestations.len() as u64,
            sponsor_reservations: self.sponsor_reservations.len() as u64,
            settlement_receipts: self.settlement_receipts.len() as u64,
            rebates: self.rebates.len() as u64,
            privacy_fences: self.privacy_fences.len() as u64,
            nullifiers: self.nullifiers.len() as u64,
            public_records: self.public_records.len() as u64,
            submitted_claims: self.claim_notes.len() as u64,
            ..Counters::default()
        };
        for claim in self.claim_notes.values() {
            if claim.status == ClaimNoteStatus::Minted {
                counters.minted_claims = counters.minted_claims.saturating_add(1);
            }
        }
        for reservation in self.sponsor_reservations.values() {
            counters.sponsor_reserved_amount = counters
                .sponsor_reserved_amount
                .saturating_add(reservation.request.max_fee_amount);
        }
        for receipt in self.settlement_receipts.values() {
            counters.fee_paid_amount = counters
                .fee_paid_amount
                .saturating_add(receipt.request.fee_paid_amount);
            counters.sponsor_paid_amount = counters
                .sponsor_paid_amount
                .saturating_add(receipt.request.sponsor_paid_amount);
        }
        for rebate in self.rebates.values() {
            counters.rebated_amount = counters
                .rebated_amount
                .saturating_add(rebate.request.rebate_amount);
        }
        counters
    }

    pub fn roots(&self) -> Roots {
        Roots {
            airdrop_root: map_root(
                "private_l2_confidential_airdrop_claim:airdrops",
                &self.airdrops,
                AirdropRecord::public_record,
            ),
            eligibility_root_root: map_root(
                "private_l2_confidential_airdrop_claim:eligibility_roots",
                &self.eligibility_roots,
                EligibilityRootRecord::public_record,
            ),
            claim_note_root: map_root(
                "private_l2_confidential_airdrop_claim:claim_notes",
                &self.claim_notes,
                ClaimNoteRecord::public_record,
            ),
            claim_batch_root: map_root(
                "private_l2_confidential_airdrop_claim:claim_batches",
                &self.claim_batches,
                ClaimBatchRecord::public_record,
            ),
            pq_attestation_root: map_root(
                "private_l2_confidential_airdrop_claim:pq_attestations",
                &self.pq_attestations,
                PqAttestationRecord::public_record,
            ),
            sponsor_reservation_root: map_root(
                "private_l2_confidential_airdrop_claim:sponsor_reservations",
                &self.sponsor_reservations,
                SponsorReservationRecord::public_record,
            ),
            settlement_receipt_root: map_root(
                "private_l2_confidential_airdrop_claim:settlement_receipts",
                &self.settlement_receipts,
                SettlementReceiptRecord::public_record,
            ),
            rebate_root: map_root(
                "private_l2_confidential_airdrop_claim:rebates",
                &self.rebates,
                RebateRecord::public_record,
            ),
            privacy_fence_root: map_root(
                "private_l2_confidential_airdrop_claim:privacy_fences",
                &self.privacy_fences,
                PrivacyFenceRecord::public_record,
            ),
            nullifier_root: set_root(
                "private_l2_confidential_airdrop_claim:nullifiers",
                &self.nullifiers,
            ),
            public_record_root: map_root(
                "private_l2_confidential_airdrop_claim:public_records",
                &self.public_records,
                PublicRuntimeRecord::public_record,
            ),
        }
    }

    pub fn public_record_without_state_root(&self) -> Value {
        json!({
            "kind": "private_l2_confidential_token_airdrop_claim_netting_state",
            "protocol_version": self.config.protocol_version,
            "schema_version": self.config.schema_version,
            "chain_id": self.config.chain_id,
            "height": self.height,
            "config": self.config.public_record(),
            "counters": self.counters().public_record(),
            "roots": self.roots().public_record(),
        })
    }

    pub fn public_record(&self) -> Value {
        let record = self.public_record_without_state_root();
        let state_root = state_root_from_record(&record);
        json!({
            "state_root": state_root,
            "record": record,
        })
    }

    pub fn state_root(&self) -> String {
        state_root_from_record(&self.public_record_without_state_root())
    }

    fn publish(&mut self, record_kind: &str, subject_id: &str, payload: Value) -> Result<()> {
        let record_id = public_record_id(record_kind, subject_id, self.height, &payload);
        if self.public_records.contains_key(&record_id) {
            return Err(format!("public record already exists: {record_id}"));
        }
        let record = PublicRuntimeRecord {
            record_id: record_id.clone(),
            record_kind: record_kind.to_string(),
            subject_id: subject_id.to_string(),
            height: self.height,
            payload,
        };
        self.public_records.insert(record_id, record);
        Ok(())
    }
}

pub fn private_l2_confidential_token_airdrop_claim_netting_runtime_devnet() -> Result<State> {
    State::devnet()
}

pub fn private_l2_confidential_token_airdrop_claim_netting_runtime_public_record(
    state: &State,
) -> Value {
    state.public_record()
}

pub fn private_l2_confidential_token_airdrop_claim_netting_runtime_state_root(
    state: &State,
) -> String {
    state.state_root()
}

pub fn airdrop_id(request: &AirdropRequest) -> String {
    domain_hash(
        "private_l2_confidential_airdrop_claim:airdrop_id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(request.issuer_id.as_str()),
            HashPart::Str(request.airdrop_symbol.as_str()),
            HashPart::Str(request.airdrop_kind.as_str()),
            HashPart::Str(request.token_asset_id.as_str()),
            HashPart::Str(request.policy_root.as_str()),
        ],
        32,
    )
}

pub fn eligibility_root_id(request: &EligibilityRootRequest) -> String {
    domain_hash(
        "private_l2_confidential_airdrop_claim:eligibility_root_id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(request.airdrop_id.as_str()),
            HashPart::Str(request.root_kind.as_str()),
            HashPart::U64(request.epoch),
            HashPart::Str(request.eligibility_root.as_str()),
            HashPart::Str(request.amount_bucket_root.as_str()),
        ],
        32,
    )
}

pub fn claim_note_id(request: &ClaimNoteRequest) -> String {
    let record = request.public_record();
    domain_hash(
        "private_l2_confidential_airdrop_claim:claim_note_id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(request.airdrop_id.as_str()),
            HashPart::Str(request.eligibility_root_id.as_str()),
            HashPart::Str(request.note_kind.as_str()),
            HashPart::Str(request.claim_nullifier.as_str()),
            HashPart::Str(request.claim_salt.as_str()),
            HashPart::Json(&record),
        ],
        32,
    )
}

pub fn claim_batch_id(request: &ClaimBatchRequest) -> String {
    let record = request.public_record();
    domain_hash(
        "private_l2_confidential_airdrop_claim:claim_batch_id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(request.airdrop_id.as_str()),
            HashPart::Str(request.lane.as_str()),
            HashPart::Str(request.batch_salt.as_str()),
            HashPart::Json(&record),
        ],
        32,
    )
}

pub fn pq_attestation_id(request: &PqAttestationRequest) -> String {
    domain_hash(
        "private_l2_confidential_airdrop_claim:pq_attestation_id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(request.airdrop_id.as_str()),
            HashPart::Str(request.attestation_kind.as_str()),
            HashPart::Str(request.verdict.as_str()),
            HashPart::Str(request.attester_id.as_str()),
            HashPart::Str(request.credential_root.as_str()),
        ],
        32,
    )
}

pub fn sponsor_reservation_id(request: &SponsorReservationRequest) -> String {
    domain_hash(
        "private_l2_confidential_airdrop_claim:sponsor_reservation_id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(request.sponsor_id.as_str()),
            HashPart::Str(request.airdrop_id.as_str()),
            HashPart::Str(request.claim_batch_id.as_str()),
            HashPart::Str(request.voucher_commitment.as_str()),
        ],
        32,
    )
}

pub fn settlement_receipt_id(request: &SettlementReceiptRequest) -> String {
    domain_hash(
        "private_l2_confidential_airdrop_claim:settlement_receipt_id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(request.airdrop_id.as_str()),
            HashPart::Str(request.claim_batch_id.as_str()),
            HashPart::Str(request.receipt_kind.as_str()),
            HashPart::Str(request.settlement_root.as_str()),
            HashPart::U64(request.settled_height),
        ],
        32,
    )
}

pub fn rebate_id(request: &RebateRequest) -> String {
    domain_hash(
        "private_l2_confidential_airdrop_claim:rebate_id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(request.airdrop_id.as_str()),
            HashPart::Str(request.claim_batch_id.as_str()),
            HashPart::Str(request.recipient_commitment.as_str()),
            HashPart::Str(request.rebate_note_commitment.as_str()),
            HashPart::Str(request.rebate_reason.as_str()),
        ],
        32,
    )
}

pub fn privacy_fence_id(request: &PrivacyFenceRequest) -> String {
    domain_hash(
        "private_l2_confidential_airdrop_claim:privacy_fence_id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(request.airdrop_id.as_str()),
            HashPart::Str(request.fence_kind.as_str()),
            HashPart::Str(request.fence_commitment.as_str()),
            HashPart::U64(request.effective_height),
        ],
        32,
    )
}

pub fn state_root_from_record(record: &Value) -> String {
    domain_hash(
        "private_l2_confidential_airdrop_claim:state_root",
        &[HashPart::Str(CHAIN_ID), HashPart::Json(record)],
        32,
    )
}

pub fn public_record_id(
    record_kind: &str,
    subject_id: &str,
    height: u64,
    payload: &Value,
) -> String {
    domain_hash(
        "private_l2_confidential_airdrop_claim:public_record_id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(record_kind),
            HashPart::Str(subject_id),
            HashPart::U64(height),
            HashPart::Json(payload),
        ],
        32,
    )
}

fn claim_fee_amount(request: &ClaimNoteRequest, config: &Config) -> u128 {
    let effective_bps = request.requested_fee_bps.min(config.target_user_fee_bps);
    let privacy_discount = if request.privacy_set_size >= config.target_privacy_set {
        1
    } else {
        0
    };
    effective_bps.saturating_sub(privacy_discount) as u128
}

fn map_root<T, F>(domain: &str, map: &BTreeMap<String, T>, public_record: F) -> String
where
    F: Fn(&T) -> Value,
{
    let leaves = map
        .iter()
        .map(|(key, value)| {
            json!({
                "key": key,
                "value": public_record(value),
            })
        })
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn set_root(domain: &str, set: &BTreeSet<String>) -> String {
    let leaves = set.iter().map(|value| json!(value)).collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn ensure_nonempty(field: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        Err(format!("{field} must be nonempty"))
    } else {
        Ok(())
    }
}

fn ensure_hash_like(field: &str, value: &str) -> Result<()> {
    ensure_nonempty(field, value)?;
    if value.len() < 16 {
        return Err(format!("{field} must be at least 16 characters"));
    }
    Ok(())
}

fn ensure_bps(field: &str, value: u64) -> Result<()> {
    if value > MAX_BPS {
        Err(format!("{field} must be <= {MAX_BPS}"))
    } else {
        Ok(())
    }
}

fn ensure_capacity(field: &str, current_len: usize, max_len: usize) -> Result<()> {
    if current_len >= max_len {
        Err(format!("{field} capacity exceeded"))
    } else {
        Ok(())
    }
}

fn ensure_unique(field: &str, values: &[String]) -> Result<()> {
    let mut seen = BTreeSet::new();
    for value in values {
        if !seen.insert(value) {
            return Err(format!("{field} contains duplicate value: {value}"));
        }
    }
    Ok(())
}

fn sample_hash(label: &str) -> String {
    domain_hash(
        "private_l2_confidential_airdrop_claim:devnet_sample",
        &[HashPart::Str(CHAIN_ID), HashPart::Str(label)],
        32,
    )
}
