use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateLowFeeTokenLaunchAuctionResult<T> = Result<T, String>;

pub const PRIVATE_LOW_FEE_TOKEN_LAUNCH_AUCTION_PROTOCOL_VERSION: &str =
    "nebula-private-low-fee-token-launch-auction-v1";
pub const PRIVATE_LOW_FEE_TOKEN_LAUNCH_AUCTION_SCHEMA_VERSION: &str =
    "private-low-fee-token-launch-auction-state-v1";
pub const PRIVATE_LOW_FEE_TOKEN_LAUNCH_AUCTION_DEVNET_LABEL: &str =
    "devnet-private-low-fee-token-launch-auction";
pub const PRIVATE_LOW_FEE_TOKEN_LAUNCH_AUCTION_HASH_SUITE: &str = "SHAKE256-domain-separated";
pub const PRIVATE_LOW_FEE_TOKEN_LAUNCH_AUCTION_COMMITMENT_SCHEME: &str =
    "shake256-domain-separated-private-sale-commitment-v1";
pub const PRIVATE_LOW_FEE_TOKEN_LAUNCH_AUCTION_SEALED_BID_SCHEME: &str =
    "threshold-encrypted-sealed-bid-commit-reveal-v1";
pub const PRIVATE_LOW_FEE_TOKEN_LAUNCH_AUCTION_ALLOCATION_PROOF_SYSTEM: &str =
    "devnet-mock-zk-private-allocation-clearing-proof-v1";
pub const PRIVATE_LOW_FEE_TOKEN_LAUNCH_AUCTION_PQ_CREDENTIAL_SUITE: &str =
    "ML-DSA-87+SLH-DSA-SHAKE-256f-anti-sybil-credential";
pub const PRIVATE_LOW_FEE_TOKEN_LAUNCH_AUCTION_PQ_KEM_SUITE: &str = "ML-KEM-1024";
pub const PRIVATE_LOW_FEE_TOKEN_LAUNCH_AUCTION_LOW_FEE_LANE: &str =
    "private-low-fee-token-launch-auction";
pub const PRIVATE_LOW_FEE_TOKEN_LAUNCH_AUCTION_FEE_ASSET_ID: &str = "piconero";
pub const PRIVATE_LOW_FEE_TOKEN_LAUNCH_AUCTION_COLLATERAL_ASSET_ID: &str = "wxmr-devnet";
pub const PRIVATE_LOW_FEE_TOKEN_LAUNCH_AUCTION_DEFAULT_HEIGHT: u64 = 4_096;
pub const PRIVATE_LOW_FEE_TOKEN_LAUNCH_AUCTION_DEFAULT_ROUND_BLOCKS: u64 = 720;
pub const PRIVATE_LOW_FEE_TOKEN_LAUNCH_AUCTION_DEFAULT_COMMIT_BLOCKS: u64 = 240;
pub const PRIVATE_LOW_FEE_TOKEN_LAUNCH_AUCTION_DEFAULT_REVEAL_BLOCKS: u64 = 120;
pub const PRIVATE_LOW_FEE_TOKEN_LAUNCH_AUCTION_DEFAULT_SETTLEMENT_BLOCKS: u64 = 180;
pub const PRIVATE_LOW_FEE_TOKEN_LAUNCH_AUCTION_DEFAULT_REFUND_BLOCKS: u64 = 360;
pub const PRIVATE_LOW_FEE_TOKEN_LAUNCH_AUCTION_DEFAULT_CREDENTIAL_TTL_BLOCKS: u64 = 7_200;
pub const PRIVATE_LOW_FEE_TOKEN_LAUNCH_AUCTION_DEFAULT_RECEIPT_TTL_BLOCKS: u64 = 1_440;
pub const PRIVATE_LOW_FEE_TOKEN_LAUNCH_AUCTION_DEFAULT_MIN_ANONYMITY_SET: u64 = 512;
pub const PRIVATE_LOW_FEE_TOKEN_LAUNCH_AUCTION_DEFAULT_PRIVACY_SET_SIZE: u64 = 2_048;
pub const PRIVATE_LOW_FEE_TOKEN_LAUNCH_AUCTION_DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 192;
pub const PRIVATE_LOW_FEE_TOKEN_LAUNCH_AUCTION_DEFAULT_MIN_BID_UNITS: u64 = 100;
pub const PRIVATE_LOW_FEE_TOKEN_LAUNCH_AUCTION_DEFAULT_MAX_BID_UNITS: u64 = 25_000;
pub const PRIVATE_LOW_FEE_TOKEN_LAUNCH_AUCTION_DEFAULT_MAX_FEE_UNITS: u64 = 18;
pub const PRIVATE_LOW_FEE_TOKEN_LAUNCH_AUCTION_DEFAULT_SPONSOR_BUDGET_UNITS: u64 = 250_000;
pub const PRIVATE_LOW_FEE_TOKEN_LAUNCH_AUCTION_DEFAULT_MAX_SYBIL_SCORE_BPS: u64 = 2_000;
pub const PRIVATE_LOW_FEE_TOKEN_LAUNCH_AUCTION_DEFAULT_MAX_DISCOUNT_BPS: u64 = 9_500;
pub const PRIVATE_LOW_FEE_TOKEN_LAUNCH_AUCTION_MAX_BPS: u64 = 10_000;
pub const PRIVATE_LOW_FEE_TOKEN_LAUNCH_AUCTION_MAX_LAUNCHES: usize = 16_384;
pub const PRIVATE_LOW_FEE_TOKEN_LAUNCH_AUCTION_MAX_ROUNDS: usize = 65_536;
pub const PRIVATE_LOW_FEE_TOKEN_LAUNCH_AUCTION_MAX_COMMITMENTS: usize = 262_144;
pub const PRIVATE_LOW_FEE_TOKEN_LAUNCH_AUCTION_MAX_CREDENTIALS: usize = 262_144;
pub const PRIVATE_LOW_FEE_TOKEN_LAUNCH_AUCTION_MAX_BIDS: usize = 262_144;
pub const PRIVATE_LOW_FEE_TOKEN_LAUNCH_AUCTION_MAX_RECEIPTS: usize = 262_144;
pub const PRIVATE_LOW_FEE_TOKEN_LAUNCH_AUCTION_MAX_PROOFS: usize = 65_536;
pub const PRIVATE_LOW_FEE_TOKEN_LAUNCH_AUCTION_MAX_ROUTES: usize = 16_384;
pub const PRIVATE_LOW_FEE_TOKEN_LAUNCH_AUCTION_MAX_REFUNDS: usize = 262_144;
pub const PRIVATE_LOW_FEE_TOKEN_LAUNCH_AUCTION_MAX_NULLIFIERS: usize = 524_288;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LaunchStatus {
    Draft,
    Scheduled,
    CredentialGateOpen,
    Live,
    Sealed,
    Allocating,
    LiquidityBootstrapping,
    Settled,
    Cancelled,
    Failed,
}

impl LaunchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Scheduled => "scheduled",
            Self::CredentialGateOpen => "credential_gate_open",
            Self::Live => "live",
            Self::Sealed => "sealed",
            Self::Allocating => "allocating",
            Self::LiquidityBootstrapping => "liquidity_bootstrapping",
            Self::Settled => "settled",
            Self::Cancelled => "cancelled",
            Self::Failed => "failed",
        }
    }

    pub fn accepts_rounds(self) -> bool {
        matches!(
            self,
            Self::Draft | Self::Scheduled | Self::CredentialGateOpen
        )
    }

    pub fn accepts_bids(self) -> bool {
        matches!(self, Self::CredentialGateOpen | Self::Live)
    }

    pub fn terminal(self) -> bool {
        matches!(self, Self::Settled | Self::Cancelled | Self::Failed)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SaleRoundKind {
    Founder,
    Strategic,
    PrivateSale,
    Community,
    LiquidityBootstrap,
    DeveloperGrant,
    Airdrop,
    ContractBound,
}

impl SaleRoundKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Founder => "founder",
            Self::Strategic => "strategic",
            Self::PrivateSale => "private_sale",
            Self::Community => "community",
            Self::LiquidityBootstrap => "liquidity_bootstrap",
            Self::DeveloperGrant => "developer_grant",
            Self::Airdrop => "airdrop",
            Self::ContractBound => "contract_bound",
        }
    }

    pub fn credential_required(self) -> bool {
        matches!(
            self,
            Self::PrivateSale | Self::Community | Self::Airdrop | Self::ContractBound
        )
    }

    pub fn can_bootstrap_liquidity(self) -> bool {
        matches!(self, Self::LiquidityBootstrap | Self::Community)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RoundStatus {
    Planned,
    CredentialGated,
    CommitOpen,
    RevealOpen,
    Sealed,
    Allocated,
    Settled,
    Cancelled,
    Expired,
}

impl RoundStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Planned => "planned",
            Self::CredentialGated => "credential_gated",
            Self::CommitOpen => "commit_open",
            Self::RevealOpen => "reveal_open",
            Self::Sealed => "sealed",
            Self::Allocated => "allocated",
            Self::Settled => "settled",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
        }
    }

    pub fn accepts_commitments(self) -> bool {
        matches!(self, Self::CredentialGated | Self::CommitOpen)
    }

    pub fn accepts_reveals(self) -> bool {
        matches!(self, Self::RevealOpen)
    }

    pub fn terminal(self) -> bool {
        matches!(self, Self::Settled | Self::Cancelled | Self::Expired)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialKind {
    HumanUniqueness,
    KycLight,
    KycFull,
    AccreditedInvestor,
    JurisdictionEligibility,
    SanctionsClear,
    ProtocolReputation,
    LiquidityProvider,
    ContractDeveloper,
    GovernanceDelegate,
    CustomPredicate,
}

impl CredentialKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::HumanUniqueness => "human_uniqueness",
            Self::KycLight => "kyc_light",
            Self::KycFull => "kyc_full",
            Self::AccreditedInvestor => "accredited_investor",
            Self::JurisdictionEligibility => "jurisdiction_eligibility",
            Self::SanctionsClear => "sanctions_clear",
            Self::ProtocolReputation => "protocol_reputation",
            Self::LiquidityProvider => "liquidity_provider",
            Self::ContractDeveloper => "contract_developer",
            Self::GovernanceDelegate => "governance_delegate",
            Self::CustomPredicate => "custom_predicate",
        }
    }

    pub fn default_weight(self) -> u64 {
        match self {
            Self::KycFull | Self::AccreditedInvestor | Self::SanctionsClear => 4,
            Self::KycLight | Self::JurisdictionEligibility => 3,
            Self::HumanUniqueness | Self::ProtocolReputation | Self::LiquidityProvider => 2,
            Self::ContractDeveloper | Self::GovernanceDelegate | Self::CustomPredicate => 1,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialStatus {
    Committed,
    Attested,
    Active,
    Frozen,
    Revoked,
    Expired,
}

impl CredentialStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Committed => "committed",
            Self::Attested => "attested",
            Self::Active => "active",
            Self::Frozen => "frozen",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
        }
    }

    pub fn usable(self) -> bool {
        matches!(self, Self::Attested | Self::Active)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BidStatus {
    Committed,
    Revealed,
    Qualified,
    Accepted,
    PartiallyFilled,
    Rejected,
    Settled,
    Refunded,
    Slashed,
    Expired,
}

impl BidStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Committed => "committed",
            Self::Revealed => "revealed",
            Self::Qualified => "qualified",
            Self::Accepted => "accepted",
            Self::PartiallyFilled => "partially_filled",
            Self::Rejected => "rejected",
            Self::Settled => "settled",
            Self::Refunded => "refunded",
            Self::Slashed => "slashed",
            Self::Expired => "expired",
        }
    }

    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Committed
                | Self::Revealed
                | Self::Qualified
                | Self::Accepted
                | Self::PartiallyFilled
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FeeCreditStatus {
    Reserved,
    Sponsored,
    Consumed,
    Refunded,
    Expired,
}

impl FeeCreditStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Sponsored => "sponsored",
            Self::Consumed => "consumed",
            Self::Refunded => "refunded",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VestingStatus {
    Pending,
    Active,
    CliffLocked,
    Streaming,
    Matured,
    Cancelled,
}

impl VestingStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Active => "active",
            Self::CliffLocked => "cliff_locked",
            Self::Streaming => "streaming",
            Self::Matured => "matured",
            Self::Cancelled => "cancelled",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofStatus {
    Queued,
    Proving,
    Verified,
    Rejected,
    Expired,
}

impl ProofStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Proving => "proving",
            Self::Verified => "verified",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }

    pub fn accepted(self) -> bool {
        matches!(self, Self::Verified)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LiquidityRouteStatus {
    Planned,
    Funded,
    Bootstrapping,
    Live,
    Settled,
    Cancelled,
}

impl LiquidityRouteStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Planned => "planned",
            Self::Funded => "funded",
            Self::Bootstrapping => "bootstrapping",
            Self::Live => "live",
            Self::Settled => "settled",
            Self::Cancelled => "cancelled",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RefundStatus {
    Claimable,
    Claimed,
    Donated,
    Expired,
    Disputed,
}

impl RefundStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Claimable => "claimable",
            Self::Claimed => "claimed",
            Self::Donated => "donated",
            Self::Expired => "expired",
            Self::Disputed => "disputed",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub round_blocks: u64,
    pub commit_blocks: u64,
    pub reveal_blocks: u64,
    pub settlement_blocks: u64,
    pub refund_blocks: u64,
    pub credential_ttl_blocks: u64,
    pub receipt_ttl_blocks: u64,
    pub min_anonymity_set: u64,
    pub privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub min_bid_units: u64,
    pub max_bid_units: u64,
    pub max_fee_units: u64,
    pub sponsor_budget_units: u64,
    pub max_sybil_score_bps: u64,
    pub max_discount_bps: u64,
    pub low_fee_lane: String,
    pub fee_asset_id: String,
    pub collateral_asset_id: String,
    pub hash_suite: String,
    pub commitment_scheme: String,
    pub sealed_bid_scheme: String,
    pub allocation_proof_system: String,
    pub pq_credential_suite: String,
    pub pq_kem_suite: String,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            round_blocks: PRIVATE_LOW_FEE_TOKEN_LAUNCH_AUCTION_DEFAULT_ROUND_BLOCKS,
            commit_blocks: PRIVATE_LOW_FEE_TOKEN_LAUNCH_AUCTION_DEFAULT_COMMIT_BLOCKS,
            reveal_blocks: PRIVATE_LOW_FEE_TOKEN_LAUNCH_AUCTION_DEFAULT_REVEAL_BLOCKS,
            settlement_blocks: PRIVATE_LOW_FEE_TOKEN_LAUNCH_AUCTION_DEFAULT_SETTLEMENT_BLOCKS,
            refund_blocks: PRIVATE_LOW_FEE_TOKEN_LAUNCH_AUCTION_DEFAULT_REFUND_BLOCKS,
            credential_ttl_blocks:
                PRIVATE_LOW_FEE_TOKEN_LAUNCH_AUCTION_DEFAULT_CREDENTIAL_TTL_BLOCKS,
            receipt_ttl_blocks: PRIVATE_LOW_FEE_TOKEN_LAUNCH_AUCTION_DEFAULT_RECEIPT_TTL_BLOCKS,
            min_anonymity_set: PRIVATE_LOW_FEE_TOKEN_LAUNCH_AUCTION_DEFAULT_MIN_ANONYMITY_SET,
            privacy_set_size: PRIVATE_LOW_FEE_TOKEN_LAUNCH_AUCTION_DEFAULT_PRIVACY_SET_SIZE,
            min_pq_security_bits: PRIVATE_LOW_FEE_TOKEN_LAUNCH_AUCTION_DEFAULT_MIN_PQ_SECURITY_BITS,
            min_bid_units: PRIVATE_LOW_FEE_TOKEN_LAUNCH_AUCTION_DEFAULT_MIN_BID_UNITS,
            max_bid_units: PRIVATE_LOW_FEE_TOKEN_LAUNCH_AUCTION_DEFAULT_MAX_BID_UNITS,
            max_fee_units: PRIVATE_LOW_FEE_TOKEN_LAUNCH_AUCTION_DEFAULT_MAX_FEE_UNITS,
            sponsor_budget_units: PRIVATE_LOW_FEE_TOKEN_LAUNCH_AUCTION_DEFAULT_SPONSOR_BUDGET_UNITS,
            max_sybil_score_bps: PRIVATE_LOW_FEE_TOKEN_LAUNCH_AUCTION_DEFAULT_MAX_SYBIL_SCORE_BPS,
            max_discount_bps: PRIVATE_LOW_FEE_TOKEN_LAUNCH_AUCTION_DEFAULT_MAX_DISCOUNT_BPS,
            low_fee_lane: PRIVATE_LOW_FEE_TOKEN_LAUNCH_AUCTION_LOW_FEE_LANE.to_string(),
            fee_asset_id: PRIVATE_LOW_FEE_TOKEN_LAUNCH_AUCTION_FEE_ASSET_ID.to_string(),
            collateral_asset_id: PRIVATE_LOW_FEE_TOKEN_LAUNCH_AUCTION_COLLATERAL_ASSET_ID
                .to_string(),
            hash_suite: PRIVATE_LOW_FEE_TOKEN_LAUNCH_AUCTION_HASH_SUITE.to_string(),
            commitment_scheme: PRIVATE_LOW_FEE_TOKEN_LAUNCH_AUCTION_COMMITMENT_SCHEME.to_string(),
            sealed_bid_scheme: PRIVATE_LOW_FEE_TOKEN_LAUNCH_AUCTION_SEALED_BID_SCHEME.to_string(),
            allocation_proof_system: PRIVATE_LOW_FEE_TOKEN_LAUNCH_AUCTION_ALLOCATION_PROOF_SYSTEM
                .to_string(),
            pq_credential_suite: PRIVATE_LOW_FEE_TOKEN_LAUNCH_AUCTION_PQ_CREDENTIAL_SUITE
                .to_string(),
            pq_kem_suite: PRIVATE_LOW_FEE_TOKEN_LAUNCH_AUCTION_PQ_KEM_SUITE.to_string(),
        }
    }

    pub fn validate(&self) -> PrivateLowFeeTokenLaunchAuctionResult<()> {
        if self.round_blocks == 0
            || self.commit_blocks == 0
            || self.reveal_blocks == 0
            || self.settlement_blocks == 0
            || self.refund_blocks == 0
            || self.credential_ttl_blocks == 0
            || self.receipt_ttl_blocks == 0
        {
            return Err("private launch auction windows must be positive".to_string());
        }
        if self.commit_blocks + self.reveal_blocks + self.settlement_blocks > self.round_blocks {
            return Err("private launch auction phase windows exceed round blocks".to_string());
        }
        if self.min_anonymity_set == 0 || self.privacy_set_size < self.min_anonymity_set {
            return Err("private launch auction anonymity set is invalid".to_string());
        }
        if self.min_bid_units == 0 || self.max_bid_units < self.min_bid_units {
            return Err("private launch auction bid bounds are invalid".to_string());
        }
        if self.max_sybil_score_bps > PRIVATE_LOW_FEE_TOKEN_LAUNCH_AUCTION_MAX_BPS
            || self.max_discount_bps > PRIVATE_LOW_FEE_TOKEN_LAUNCH_AUCTION_MAX_BPS
        {
            return Err("private launch auction bps config exceeds max".to_string());
        }
        ensure_non_empty(&self.low_fee_lane, "low_fee_lane")?;
        ensure_non_empty(&self.fee_asset_id, "fee_asset_id")?;
        ensure_non_empty(&self.collateral_asset_id, "collateral_asset_id")?;
        ensure_non_empty(&self.hash_suite, "hash_suite")?;
        ensure_non_empty(&self.commitment_scheme, "commitment_scheme")?;
        ensure_non_empty(&self.sealed_bid_scheme, "sealed_bid_scheme")?;
        ensure_non_empty(&self.allocation_proof_system, "allocation_proof_system")?;
        ensure_non_empty(&self.pq_credential_suite, "pq_credential_suite")?;
        ensure_non_empty(&self.pq_kem_suite, "pq_kem_suite")?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "round_blocks": self.round_blocks,
            "commit_blocks": self.commit_blocks,
            "reveal_blocks": self.reveal_blocks,
            "settlement_blocks": self.settlement_blocks,
            "refund_blocks": self.refund_blocks,
            "credential_ttl_blocks": self.credential_ttl_blocks,
            "receipt_ttl_blocks": self.receipt_ttl_blocks,
            "min_anonymity_set": self.min_anonymity_set,
            "privacy_set_size": self.privacy_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
            "min_bid_units": self.min_bid_units,
            "max_bid_units": self.max_bid_units,
            "max_fee_units": self.max_fee_units,
            "sponsor_budget_units": self.sponsor_budget_units,
            "max_sybil_score_bps": self.max_sybil_score_bps,
            "max_discount_bps": self.max_discount_bps,
            "low_fee_lane": self.low_fee_lane,
            "fee_asset_id": self.fee_asset_id,
            "collateral_asset_id": self.collateral_asset_id,
            "hash_suite": self.hash_suite,
            "commitment_scheme": self.commitment_scheme,
            "sealed_bid_scheme": self.sealed_bid_scheme,
            "allocation_proof_system": self.allocation_proof_system,
            "pq_credential_suite": self.pq_credential_suite,
            "pq_kem_suite": self.pq_kem_suite,
        })
    }

    pub fn root(&self) -> String {
        payload_root(
            "PRIVATE-LOW-FEE-TOKEN-LAUNCH-AUCTION-CONFIG",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Launch {
    pub launch_id: String,
    pub issuer_commitment: String,
    pub token_commitment: String,
    pub treasury_commitment: String,
    pub status: LaunchStatus,
    pub sale_round_ids: BTreeSet<String>,
    pub liquidity_route_ids: BTreeSet<String>,
    pub auditor_set_id: String,
    pub min_raise_units: u64,
    pub hard_cap_units: u64,
    pub token_supply_commitment: String,
    pub metadata_root: String,
    pub created_height: u64,
    pub updated_height: u64,
}

impl Launch {
    pub fn validate(&self) -> PrivateLowFeeTokenLaunchAuctionResult<()> {
        ensure_non_empty(&self.launch_id, "launch_id")?;
        ensure_non_empty(&self.issuer_commitment, "issuer_commitment")?;
        ensure_non_empty(&self.token_commitment, "token_commitment")?;
        ensure_non_empty(&self.treasury_commitment, "treasury_commitment")?;
        ensure_non_empty(&self.auditor_set_id, "auditor_set_id")?;
        ensure_non_empty(&self.token_supply_commitment, "token_supply_commitment")?;
        ensure_non_empty(&self.metadata_root, "metadata_root")?;
        if self.hard_cap_units == 0 || self.min_raise_units > self.hard_cap_units {
            return Err(format!("launch {} has invalid cap bounds", self.launch_id));
        }
        if self.updated_height < self.created_height {
            return Err(format!("launch {} updated before creation", self.launch_id));
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "launch_id": self.launch_id,
            "issuer_commitment": self.issuer_commitment,
            "token_commitment": self.token_commitment,
            "treasury_commitment": self.treasury_commitment,
            "status": self.status.as_str(),
            "sale_round_ids": string_set_record(&self.sale_round_ids),
            "liquidity_route_ids": string_set_record(&self.liquidity_route_ids),
            "auditor_set_id": self.auditor_set_id,
            "min_raise_units": self.min_raise_units,
            "hard_cap_units": self.hard_cap_units,
            "token_supply_commitment": self.token_supply_commitment,
            "metadata_root": self.metadata_root,
            "created_height": self.created_height,
            "updated_height": self.updated_height,
        })
    }

    pub fn root(&self) -> String {
        payload_root(
            "PRIVATE-LOW-FEE-TOKEN-LAUNCH-AUCTION-LAUNCH",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SaleRound {
    pub round_id: String,
    pub launch_id: String,
    pub kind: SaleRoundKind,
    pub status: RoundStatus,
    pub start_height: u64,
    pub commit_end_height: u64,
    pub reveal_end_height: u64,
    pub settle_height: u64,
    pub price_commitment: String,
    pub allocation_cap_units: u64,
    pub min_bid_units: u64,
    pub max_bid_units: u64,
    pub required_credential_kinds: BTreeSet<CredentialKind>,
    pub accepted_jurisdiction_root: String,
    pub privacy_set_root: String,
    pub round_salt_commitment: String,
}

impl SaleRound {
    pub fn validate(&self, config: &Config) -> PrivateLowFeeTokenLaunchAuctionResult<()> {
        ensure_non_empty(&self.round_id, "round_id")?;
        ensure_non_empty(&self.launch_id, "launch_id")?;
        ensure_non_empty(&self.price_commitment, "price_commitment")?;
        ensure_non_empty(
            &self.accepted_jurisdiction_root,
            "accepted_jurisdiction_root",
        )?;
        ensure_non_empty(&self.privacy_set_root, "privacy_set_root")?;
        ensure_non_empty(&self.round_salt_commitment, "round_salt_commitment")?;
        if self.commit_end_height <= self.start_height
            || self.reveal_end_height <= self.commit_end_height
            || self.settle_height <= self.reveal_end_height
        {
            return Err(format!("round {} has invalid phase heights", self.round_id));
        }
        if self.allocation_cap_units == 0 {
            return Err(format!("round {} cap must be positive", self.round_id));
        }
        if self.min_bid_units < config.min_bid_units
            || self.max_bid_units > config.max_bid_units
            || self.max_bid_units < self.min_bid_units
        {
            return Err(format!("round {} bid bounds are invalid", self.round_id));
        }
        if self.kind.credential_required() && self.required_credential_kinds.is_empty() {
            return Err(format!(
                "round {} is missing credential gates",
                self.round_id
            ));
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        let kinds = self
            .required_credential_kinds
            .iter()
            .map(|kind| json!(kind.as_str()))
            .collect::<Vec<_>>();
        json!({
            "round_id": self.round_id,
            "launch_id": self.launch_id,
            "kind": self.kind.as_str(),
            "status": self.status.as_str(),
            "start_height": self.start_height,
            "commit_end_height": self.commit_end_height,
            "reveal_end_height": self.reveal_end_height,
            "settle_height": self.settle_height,
            "price_commitment": self.price_commitment,
            "allocation_cap_units": self.allocation_cap_units,
            "min_bid_units": self.min_bid_units,
            "max_bid_units": self.max_bid_units,
            "required_credential_kinds": kinds,
            "accepted_jurisdiction_root": self.accepted_jurisdiction_root,
            "privacy_set_root": self.privacy_set_root,
            "round_salt_commitment": self.round_salt_commitment,
        })
    }

    pub fn root(&self) -> String {
        payload_root(
            "PRIVATE-LOW-FEE-TOKEN-LAUNCH-AUCTION-ROUND",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateCommitment {
    pub commitment_id: String,
    pub round_id: String,
    pub bidder_commitment: String,
    pub credential_id: String,
    pub amount_commitment: String,
    pub quote_asset_commitment: String,
    pub nullifier_commitment: String,
    pub encrypted_payload_root: String,
    pub fee_credit_id: String,
    pub first_seen_height: u64,
}

impl PrivateCommitment {
    pub fn validate(&self) -> PrivateLowFeeTokenLaunchAuctionResult<()> {
        ensure_non_empty(&self.commitment_id, "commitment_id")?;
        ensure_non_empty(&self.round_id, "round_id")?;
        ensure_non_empty(&self.bidder_commitment, "bidder_commitment")?;
        ensure_non_empty(&self.credential_id, "credential_id")?;
        ensure_non_empty(&self.amount_commitment, "amount_commitment")?;
        ensure_non_empty(&self.quote_asset_commitment, "quote_asset_commitment")?;
        ensure_non_empty(&self.nullifier_commitment, "nullifier_commitment")?;
        ensure_non_empty(&self.encrypted_payload_root, "encrypted_payload_root")?;
        ensure_non_empty(&self.fee_credit_id, "fee_credit_id")?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "commitment_id": self.commitment_id,
            "round_id": self.round_id,
            "bidder_commitment": self.bidder_commitment,
            "credential_id": self.credential_id,
            "amount_commitment": self.amount_commitment,
            "quote_asset_commitment": self.quote_asset_commitment,
            "nullifier_commitment": self.nullifier_commitment,
            "encrypted_payload_root": self.encrypted_payload_root,
            "fee_credit_id": self.fee_credit_id,
            "first_seen_height": self.first_seen_height,
        })
    }

    pub fn root(&self) -> String {
        payload_root(
            "PRIVATE-LOW-FEE-TOKEN-LAUNCH-AUCTION-COMMITMENT",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeeCredit {
    pub fee_credit_id: String,
    pub sponsor_commitment: String,
    pub beneficiary_commitment: String,
    pub round_id: String,
    pub status: FeeCreditStatus,
    pub max_fee_units: u64,
    pub discount_bps: u64,
    pub reserved_units: u64,
    pub consumed_units: u64,
    pub expires_height: u64,
    pub credit_note_root: String,
}

impl FeeCredit {
    pub fn validate(&self, config: &Config) -> PrivateLowFeeTokenLaunchAuctionResult<()> {
        ensure_non_empty(&self.fee_credit_id, "fee_credit_id")?;
        ensure_non_empty(&self.sponsor_commitment, "sponsor_commitment")?;
        ensure_non_empty(&self.beneficiary_commitment, "beneficiary_commitment")?;
        ensure_non_empty(&self.round_id, "round_id")?;
        ensure_non_empty(&self.credit_note_root, "credit_note_root")?;
        if self.max_fee_units == 0 || self.max_fee_units > config.max_fee_units {
            return Err(format!(
                "fee credit {} exceeds max fee units",
                self.fee_credit_id
            ));
        }
        if self.discount_bps > config.max_discount_bps {
            return Err(format!(
                "fee credit {} exceeds max discount bps",
                self.fee_credit_id
            ));
        }
        if self.consumed_units > self.reserved_units {
            return Err(format!(
                "fee credit {} consumed more than reserved",
                self.fee_credit_id
            ));
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "fee_credit_id": self.fee_credit_id,
            "sponsor_commitment": self.sponsor_commitment,
            "beneficiary_commitment": self.beneficiary_commitment,
            "round_id": self.round_id,
            "status": self.status.as_str(),
            "max_fee_units": self.max_fee_units,
            "discount_bps": self.discount_bps,
            "reserved_units": self.reserved_units,
            "consumed_units": self.consumed_units,
            "expires_height": self.expires_height,
            "credit_note_root": self.credit_note_root,
        })
    }

    pub fn root(&self) -> String {
        payload_root(
            "PRIVATE-LOW-FEE-TOKEN-LAUNCH-AUCTION-FEE-CREDIT",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AntiSybilCredential {
    pub credential_id: String,
    pub issuer_id: String,
    pub holder_commitment: String,
    pub kind: CredentialKind,
    pub status: CredentialStatus,
    pub weight: u64,
    pub sybil_score_bps: u64,
    pub anonymity_set_size: u64,
    pub issued_height: u64,
    pub expires_height: u64,
    pub pq_signature_root: String,
    pub revocation_nullifier: String,
}

impl AntiSybilCredential {
    pub fn validate(&self, config: &Config) -> PrivateLowFeeTokenLaunchAuctionResult<()> {
        ensure_non_empty(&self.credential_id, "credential_id")?;
        ensure_non_empty(&self.issuer_id, "issuer_id")?;
        ensure_non_empty(&self.holder_commitment, "holder_commitment")?;
        ensure_non_empty(&self.pq_signature_root, "pq_signature_root")?;
        ensure_non_empty(&self.revocation_nullifier, "revocation_nullifier")?;
        if self.weight == 0 {
            return Err(format!("credential {} has zero weight", self.credential_id));
        }
        if self.sybil_score_bps > config.max_sybil_score_bps {
            return Err(format!(
                "credential {} exceeds sybil score policy",
                self.credential_id
            ));
        }
        if self.anonymity_set_size < config.min_anonymity_set {
            return Err(format!(
                "credential {} anonymity set below policy",
                self.credential_id
            ));
        }
        if self.expires_height <= self.issued_height {
            return Err(format!(
                "credential {} expiry is invalid",
                self.credential_id
            ));
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "credential_id": self.credential_id,
            "issuer_id": self.issuer_id,
            "holder_commitment": self.holder_commitment,
            "kind": self.kind.as_str(),
            "status": self.status.as_str(),
            "weight": self.weight,
            "sybil_score_bps": self.sybil_score_bps,
            "anonymity_set_size": self.anonymity_set_size,
            "issued_height": self.issued_height,
            "expires_height": self.expires_height,
            "pq_signature_root": self.pq_signature_root,
            "revocation_nullifier": self.revocation_nullifier,
        })
    }

    pub fn root(&self) -> String {
        payload_root(
            "PRIVATE-LOW-FEE-TOKEN-LAUNCH-AUCTION-CREDENTIAL",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedBid {
    pub bid_id: String,
    pub round_id: String,
    pub commitment_id: String,
    pub credential_id: String,
    pub status: BidStatus,
    pub bid_commitment: String,
    pub encrypted_bid_root: String,
    pub reveal_proof_root: String,
    pub quote_amount_commitment: String,
    pub max_price_commitment: String,
    pub nullifier_commitment: String,
    pub created_height: u64,
    pub revealed_height: Option<u64>,
}

impl SealedBid {
    pub fn validate(&self) -> PrivateLowFeeTokenLaunchAuctionResult<()> {
        ensure_non_empty(&self.bid_id, "bid_id")?;
        ensure_non_empty(&self.round_id, "round_id")?;
        ensure_non_empty(&self.commitment_id, "commitment_id")?;
        ensure_non_empty(&self.credential_id, "credential_id")?;
        ensure_non_empty(&self.bid_commitment, "bid_commitment")?;
        ensure_non_empty(&self.encrypted_bid_root, "encrypted_bid_root")?;
        ensure_non_empty(&self.reveal_proof_root, "reveal_proof_root")?;
        ensure_non_empty(&self.quote_amount_commitment, "quote_amount_commitment")?;
        ensure_non_empty(&self.max_price_commitment, "max_price_commitment")?;
        ensure_non_empty(&self.nullifier_commitment, "nullifier_commitment")?;
        if let Some(revealed_height) = self.revealed_height {
            if revealed_height < self.created_height {
                return Err(format!("bid {} revealed before creation", self.bid_id));
            }
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "bid_id": self.bid_id,
            "round_id": self.round_id,
            "commitment_id": self.commitment_id,
            "credential_id": self.credential_id,
            "status": self.status.as_str(),
            "bid_commitment": self.bid_commitment,
            "encrypted_bid_root": self.encrypted_bid_root,
            "reveal_proof_root": self.reveal_proof_root,
            "quote_amount_commitment": self.quote_amount_commitment,
            "max_price_commitment": self.max_price_commitment,
            "nullifier_commitment": self.nullifier_commitment,
            "created_height": self.created_height,
            "revealed_height": self.revealed_height,
        })
    }

    pub fn root(&self) -> String {
        payload_root(
            "PRIVATE-LOW-FEE-TOKEN-LAUNCH-AUCTION-BID",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VestingReceipt {
    pub receipt_id: String,
    pub launch_id: String,
    pub round_id: String,
    pub bid_id: String,
    pub beneficiary_commitment: String,
    pub status: VestingStatus,
    pub allocation_commitment: String,
    pub vesting_schedule_root: String,
    pub cliff_height: u64,
    pub start_height: u64,
    pub end_height: u64,
    pub receipt_proof_root: String,
    pub created_height: u64,
}

impl VestingReceipt {
    pub fn validate(&self) -> PrivateLowFeeTokenLaunchAuctionResult<()> {
        ensure_non_empty(&self.receipt_id, "receipt_id")?;
        ensure_non_empty(&self.launch_id, "launch_id")?;
        ensure_non_empty(&self.round_id, "round_id")?;
        ensure_non_empty(&self.bid_id, "bid_id")?;
        ensure_non_empty(&self.beneficiary_commitment, "beneficiary_commitment")?;
        ensure_non_empty(&self.allocation_commitment, "allocation_commitment")?;
        ensure_non_empty(&self.vesting_schedule_root, "vesting_schedule_root")?;
        ensure_non_empty(&self.receipt_proof_root, "receipt_proof_root")?;
        if self.start_height > self.cliff_height || self.cliff_height > self.end_height {
            return Err(format!(
                "receipt {} has invalid vesting heights",
                self.receipt_id
            ));
        }
        if self.created_height > self.start_height {
            return Err(format!(
                "receipt {} starts before creation",
                self.receipt_id
            ));
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "launch_id": self.launch_id,
            "round_id": self.round_id,
            "bid_id": self.bid_id,
            "beneficiary_commitment": self.beneficiary_commitment,
            "status": self.status.as_str(),
            "allocation_commitment": self.allocation_commitment,
            "vesting_schedule_root": self.vesting_schedule_root,
            "cliff_height": self.cliff_height,
            "start_height": self.start_height,
            "end_height": self.end_height,
            "receipt_proof_root": self.receipt_proof_root,
            "created_height": self.created_height,
        })
    }

    pub fn root(&self) -> String {
        payload_root(
            "PRIVATE-LOW-FEE-TOKEN-LAUNCH-AUCTION-VESTING-RECEIPT",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZkAllocationProof {
    pub proof_id: String,
    pub round_id: String,
    pub launch_id: String,
    pub proof_status: ProofStatus,
    pub allocation_root_before: String,
    pub allocation_root_after: String,
    pub winning_bid_root: String,
    pub refund_root: String,
    pub constraint_system_root: String,
    pub public_inputs_root: String,
    pub verifier_key_root: String,
    pub generated_height: u64,
    pub verified_height: Option<u64>,
}

impl ZkAllocationProof {
    pub fn validate(&self) -> PrivateLowFeeTokenLaunchAuctionResult<()> {
        ensure_non_empty(&self.proof_id, "proof_id")?;
        ensure_non_empty(&self.round_id, "round_id")?;
        ensure_non_empty(&self.launch_id, "launch_id")?;
        ensure_non_empty(&self.allocation_root_before, "allocation_root_before")?;
        ensure_non_empty(&self.allocation_root_after, "allocation_root_after")?;
        ensure_non_empty(&self.winning_bid_root, "winning_bid_root")?;
        ensure_non_empty(&self.refund_root, "refund_root")?;
        ensure_non_empty(&self.constraint_system_root, "constraint_system_root")?;
        ensure_non_empty(&self.public_inputs_root, "public_inputs_root")?;
        ensure_non_empty(&self.verifier_key_root, "verifier_key_root")?;
        if let Some(verified_height) = self.verified_height {
            if verified_height < self.generated_height {
                return Err(format!(
                    "proof {} verified before generation",
                    self.proof_id
                ));
            }
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "proof_id": self.proof_id,
            "round_id": self.round_id,
            "launch_id": self.launch_id,
            "proof_status": self.proof_status.as_str(),
            "allocation_root_before": self.allocation_root_before,
            "allocation_root_after": self.allocation_root_after,
            "winning_bid_root": self.winning_bid_root,
            "refund_root": self.refund_root,
            "constraint_system_root": self.constraint_system_root,
            "public_inputs_root": self.public_inputs_root,
            "verifier_key_root": self.verifier_key_root,
            "generated_height": self.generated_height,
            "verified_height": self.verified_height,
        })
    }

    pub fn root(&self) -> String {
        payload_root(
            "PRIVATE-LOW-FEE-TOKEN-LAUNCH-AUCTION-ALLOCATION-PROOF",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiquidityBootstrapRoute {
    pub route_id: String,
    pub launch_id: String,
    pub round_id: String,
    pub status: LiquidityRouteStatus,
    pub pool_commitment: String,
    pub base_asset_commitment: String,
    pub quote_asset_commitment: String,
    pub initial_price_commitment: String,
    pub inventory_commitment: String,
    pub route_policy_root: String,
    pub solver_commitments: BTreeSet<String>,
    pub start_height: u64,
    pub end_height: u64,
}

impl LiquidityBootstrapRoute {
    pub fn validate(&self) -> PrivateLowFeeTokenLaunchAuctionResult<()> {
        ensure_non_empty(&self.route_id, "route_id")?;
        ensure_non_empty(&self.launch_id, "launch_id")?;
        ensure_non_empty(&self.round_id, "round_id")?;
        ensure_non_empty(&self.pool_commitment, "pool_commitment")?;
        ensure_non_empty(&self.base_asset_commitment, "base_asset_commitment")?;
        ensure_non_empty(&self.quote_asset_commitment, "quote_asset_commitment")?;
        ensure_non_empty(&self.initial_price_commitment, "initial_price_commitment")?;
        ensure_non_empty(&self.inventory_commitment, "inventory_commitment")?;
        ensure_non_empty(&self.route_policy_root, "route_policy_root")?;
        if self.solver_commitments.is_empty() {
            return Err(format!("route {} has no solvers", self.route_id));
        }
        if self.end_height <= self.start_height {
            return Err(format!("route {} has invalid height window", self.route_id));
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "route_id": self.route_id,
            "launch_id": self.launch_id,
            "round_id": self.round_id,
            "status": self.status.as_str(),
            "pool_commitment": self.pool_commitment,
            "base_asset_commitment": self.base_asset_commitment,
            "quote_asset_commitment": self.quote_asset_commitment,
            "initial_price_commitment": self.initial_price_commitment,
            "inventory_commitment": self.inventory_commitment,
            "route_policy_root": self.route_policy_root,
            "solver_commitments": string_set_record(&self.solver_commitments),
            "start_height": self.start_height,
            "end_height": self.end_height,
        })
    }

    pub fn root(&self) -> String {
        payload_root(
            "PRIVATE-LOW-FEE-TOKEN-LAUNCH-AUCTION-LIQUIDITY-ROUTE",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RefundClaim {
    pub refund_id: String,
    pub round_id: String,
    pub bid_id: String,
    pub claimant_commitment: String,
    pub status: RefundStatus,
    pub refund_amount_commitment: String,
    pub fee_refund_commitment: String,
    pub refund_nullifier: String,
    pub claim_proof_root: String,
    pub claimable_height: u64,
    pub claimed_height: Option<u64>,
}

impl RefundClaim {
    pub fn validate(&self) -> PrivateLowFeeTokenLaunchAuctionResult<()> {
        ensure_non_empty(&self.refund_id, "refund_id")?;
        ensure_non_empty(&self.round_id, "round_id")?;
        ensure_non_empty(&self.bid_id, "bid_id")?;
        ensure_non_empty(&self.claimant_commitment, "claimant_commitment")?;
        ensure_non_empty(&self.refund_amount_commitment, "refund_amount_commitment")?;
        ensure_non_empty(&self.fee_refund_commitment, "fee_refund_commitment")?;
        ensure_non_empty(&self.refund_nullifier, "refund_nullifier")?;
        ensure_non_empty(&self.claim_proof_root, "claim_proof_root")?;
        if let Some(claimed_height) = self.claimed_height {
            if claimed_height < self.claimable_height {
                return Err(format!(
                    "refund {} claimed before claimable",
                    self.refund_id
                ));
            }
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "refund_id": self.refund_id,
            "round_id": self.round_id,
            "bid_id": self.bid_id,
            "claimant_commitment": self.claimant_commitment,
            "status": self.status.as_str(),
            "refund_amount_commitment": self.refund_amount_commitment,
            "fee_refund_commitment": self.fee_refund_commitment,
            "refund_nullifier": self.refund_nullifier,
            "claim_proof_root": self.claim_proof_root,
            "claimable_height": self.claimable_height,
            "claimed_height": self.claimed_height,
        })
    }

    pub fn root(&self) -> String {
        payload_root(
            "PRIVATE-LOW-FEE-TOKEN-LAUNCH-AUCTION-REFUND",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NullifierEntry {
    pub nullifier: String,
    pub source_id: String,
    pub source_kind: String,
    pub first_seen_height: u64,
}

impl NullifierEntry {
    pub fn validate(&self) -> PrivateLowFeeTokenLaunchAuctionResult<()> {
        ensure_non_empty(&self.nullifier, "nullifier")?;
        ensure_non_empty(&self.source_id, "source_id")?;
        ensure_non_empty(&self.source_kind, "source_kind")?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "nullifier": self.nullifier,
            "source_id": self.source_id,
            "source_kind": self.source_kind,
            "first_seen_height": self.first_seen_height,
        })
    }

    pub fn root(&self) -> String {
        payload_root(
            "PRIVATE-LOW-FEE-TOKEN-LAUNCH-AUCTION-NULLIFIER",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roots {
    pub config_root: String,
    pub launch_root: String,
    pub round_root: String,
    pub commitment_root: String,
    pub fee_credit_root: String,
    pub credential_root: String,
    pub bid_root: String,
    pub vesting_receipt_root: String,
    pub allocation_proof_root: String,
    pub liquidity_route_root: String,
    pub refund_claim_root: String,
    pub nullifier_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "launch_root": self.launch_root,
            "round_root": self.round_root,
            "commitment_root": self.commitment_root,
            "fee_credit_root": self.fee_credit_root,
            "credential_root": self.credential_root,
            "bid_root": self.bid_root,
            "vesting_receipt_root": self.vesting_receipt_root,
            "allocation_proof_root": self.allocation_proof_root,
            "liquidity_route_root": self.liquidity_route_root,
            "refund_claim_root": self.refund_claim_root,
            "nullifier_root": self.nullifier_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    pub launches: u64,
    pub rounds: u64,
    pub private_commitments: u64,
    pub fee_credits: u64,
    pub anti_sybil_credentials: u64,
    pub sealed_bids: u64,
    pub vesting_receipts: u64,
    pub allocation_proofs: u64,
    pub liquidity_routes: u64,
    pub refund_claims: u64,
    pub nullifiers: u64,
    pub live_rounds: u64,
    pub live_bids: u64,
    pub claimable_refunds: u64,
    pub verified_allocation_proofs: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "launches": self.launches,
            "rounds": self.rounds,
            "private_commitments": self.private_commitments,
            "fee_credits": self.fee_credits,
            "anti_sybil_credentials": self.anti_sybil_credentials,
            "sealed_bids": self.sealed_bids,
            "vesting_receipts": self.vesting_receipts,
            "allocation_proofs": self.allocation_proofs,
            "liquidity_routes": self.liquidity_routes,
            "refund_claims": self.refund_claims,
            "nullifiers": self.nullifiers,
            "live_rounds": self.live_rounds,
            "live_bids": self.live_bids,
            "claimable_refunds": self.claimable_refunds,
            "verified_allocation_proofs": self.verified_allocation_proofs,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub height: u64,
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: String,
    pub label: String,
    pub config: Config,
    pub launches: BTreeMap<String, Launch>,
    pub rounds: BTreeMap<String, SaleRound>,
    pub private_commitments: BTreeMap<String, PrivateCommitment>,
    pub fee_credits: BTreeMap<String, FeeCredit>,
    pub anti_sybil_credentials: BTreeMap<String, AntiSybilCredential>,
    pub sealed_bids: BTreeMap<String, SealedBid>,
    pub vesting_receipts: BTreeMap<String, VestingReceipt>,
    pub allocation_proofs: BTreeMap<String, ZkAllocationProof>,
    pub liquidity_routes: BTreeMap<String, LiquidityBootstrapRoute>,
    pub refund_claims: BTreeMap<String, RefundClaim>,
    pub nullifiers: BTreeMap<String, NullifierEntry>,
}

impl State {
    pub fn devnet() -> PrivateLowFeeTokenLaunchAuctionResult<Self> {
        let config = Config::devnet();
        let height = PRIVATE_LOW_FEE_TOKEN_LAUNCH_AUCTION_DEFAULT_HEIGHT;
        let mut sale_round_ids = BTreeSet::new();
        let mut route_ids = BTreeSet::new();

        let launch_one = launch_fixture(
            "aurora-privacy-index",
            LaunchStatus::Live,
            height - 600,
            height - 12,
            5_000_000,
            50_000_000,
        );
        let launch_two = launch_fixture(
            "monero-settlement-mesh",
            LaunchStatus::LiquidityBootstrapping,
            height - 1_800,
            height - 6,
            8_000_000,
            80_000_000,
        );

        let round_one = round_fixture(
            &launch_one.launch_id,
            "community",
            SaleRoundKind::Community,
            RoundStatus::CommitOpen,
            height - 48,
            &config,
        );
        let round_two = round_fixture(
            &launch_two.launch_id,
            "liquidity-bootstrap",
            SaleRoundKind::LiquidityBootstrap,
            RoundStatus::Allocated,
            height - 640,
            &config,
        );

        sale_round_ids.insert(round_one.round_id.clone());
        let launch_one = Launch {
            sale_round_ids: sale_round_ids.clone(),
            ..launch_one
        };
        sale_round_ids.clear();
        sale_round_ids.insert(round_two.round_id.clone());

        let route_one = route_fixture(
            &launch_two.launch_id,
            &round_two.round_id,
            "dex-route-a",
            height - 40,
        );
        route_ids.insert(route_one.route_id.clone());
        let launch_two = Launch {
            sale_round_ids: sale_round_ids.clone(),
            liquidity_route_ids: route_ids.clone(),
            ..launch_two
        };

        let credential_one = credential_fixture(
            "devnet-human-001",
            CredentialKind::HumanUniqueness,
            height - 500,
        );
        let credential_two = credential_fixture(
            "devnet-lp-042",
            CredentialKind::LiquidityProvider,
            height - 900,
        );

        let credit_one = fee_credit_fixture(
            &round_one.round_id,
            "launch-sponsor-a",
            "bidder-a",
            height + 300,
        );
        let credit_two = fee_credit_fixture(
            &round_two.round_id,
            "launch-sponsor-b",
            "bidder-b",
            height + 100,
        );

        let commitment_one = commitment_fixture(
            &round_one.round_id,
            &credential_one.credential_id,
            &credit_one.fee_credit_id,
            "alpha",
            height - 20,
        );
        let commitment_two = commitment_fixture(
            &round_two.round_id,
            &credential_two.credential_id,
            &credit_two.fee_credit_id,
            "beta",
            height - 560,
        );

        let bid_one = bid_fixture(
            &round_one.round_id,
            &commitment_one.commitment_id,
            &credential_one.credential_id,
            BidStatus::Committed,
            "alpha",
            height - 18,
            None,
        );
        let bid_two = bid_fixture(
            &round_two.round_id,
            &commitment_two.commitment_id,
            &credential_two.credential_id,
            BidStatus::Accepted,
            "beta",
            height - 540,
            Some(height - 460),
        );

        let receipt_one = receipt_fixture(
            &launch_two.launch_id,
            &round_two.round_id,
            &bid_two.bid_id,
            "beta",
            height - 12,
        );
        let proof_one = proof_fixture(
            &launch_two.launch_id,
            &round_two.round_id,
            "allocation-proof-beta",
            ProofStatus::Verified,
            height - 24,
            Some(height - 20),
        );
        let refund_one = refund_fixture(
            &round_two.round_id,
            &bid_two.bid_id,
            "beta-refund",
            height - 10,
        );

        let nullifier_one = nullifier_fixture(
            &commitment_one.nullifier_commitment,
            &commitment_one.commitment_id,
            "private_commitment",
            height - 20,
        );
        let nullifier_two = nullifier_fixture(
            &bid_two.nullifier_commitment,
            &bid_two.bid_id,
            "sealed_bid",
            height - 540,
        );

        let mut launches = BTreeMap::new();
        launches.insert(launch_one.launch_id.clone(), launch_one);
        launches.insert(launch_two.launch_id.clone(), launch_two);

        let mut rounds = BTreeMap::new();
        rounds.insert(round_one.round_id.clone(), round_one);
        rounds.insert(round_two.round_id.clone(), round_two);

        let mut private_commitments = BTreeMap::new();
        private_commitments.insert(commitment_one.commitment_id.clone(), commitment_one);
        private_commitments.insert(commitment_two.commitment_id.clone(), commitment_two);

        let mut fee_credits = BTreeMap::new();
        fee_credits.insert(credit_one.fee_credit_id.clone(), credit_one);
        fee_credits.insert(credit_two.fee_credit_id.clone(), credit_two);

        let mut anti_sybil_credentials = BTreeMap::new();
        anti_sybil_credentials.insert(credential_one.credential_id.clone(), credential_one);
        anti_sybil_credentials.insert(credential_two.credential_id.clone(), credential_two);

        let mut sealed_bids = BTreeMap::new();
        sealed_bids.insert(bid_one.bid_id.clone(), bid_one);
        sealed_bids.insert(bid_two.bid_id.clone(), bid_two);

        let mut vesting_receipts = BTreeMap::new();
        vesting_receipts.insert(receipt_one.receipt_id.clone(), receipt_one);

        let mut allocation_proofs = BTreeMap::new();
        allocation_proofs.insert(proof_one.proof_id.clone(), proof_one);

        let mut liquidity_routes = BTreeMap::new();
        liquidity_routes.insert(route_one.route_id.clone(), route_one);

        let mut refund_claims = BTreeMap::new();
        refund_claims.insert(refund_one.refund_id.clone(), refund_one);

        let mut nullifiers = BTreeMap::new();
        nullifiers.insert(nullifier_one.nullifier.clone(), nullifier_one);
        nullifiers.insert(nullifier_two.nullifier.clone(), nullifier_two);

        let state = Self {
            height,
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PRIVATE_LOW_FEE_TOKEN_LAUNCH_AUCTION_PROTOCOL_VERSION.to_string(),
            schema_version: PRIVATE_LOW_FEE_TOKEN_LAUNCH_AUCTION_SCHEMA_VERSION.to_string(),
            label: PRIVATE_LOW_FEE_TOKEN_LAUNCH_AUCTION_DEVNET_LABEL.to_string(),
            config,
            launches,
            rounds,
            private_commitments,
            fee_credits,
            anti_sybil_credentials,
            sealed_bids,
            vesting_receipts,
            allocation_proofs,
            liquidity_routes,
            refund_claims,
            nullifiers,
        };
        state.validate()?;
        Ok(state)
    }

    pub fn validate(&self) -> PrivateLowFeeTokenLaunchAuctionResult<()> {
        ensure_non_empty(&self.chain_id, "chain_id")?;
        ensure_non_empty(&self.protocol_version, "protocol_version")?;
        ensure_non_empty(&self.schema_version, "schema_version")?;
        ensure_non_empty(&self.label, "label")?;
        if self.protocol_version != PRIVATE_LOW_FEE_TOKEN_LAUNCH_AUCTION_PROTOCOL_VERSION {
            return Err("private launch auction protocol version mismatch".to_string());
        }
        self.config.validate()?;
        ensure_len(
            self.launches.len(),
            PRIVATE_LOW_FEE_TOKEN_LAUNCH_AUCTION_MAX_LAUNCHES,
            "launches",
        )?;
        ensure_len(
            self.rounds.len(),
            PRIVATE_LOW_FEE_TOKEN_LAUNCH_AUCTION_MAX_ROUNDS,
            "rounds",
        )?;
        ensure_len(
            self.private_commitments.len(),
            PRIVATE_LOW_FEE_TOKEN_LAUNCH_AUCTION_MAX_COMMITMENTS,
            "private_commitments",
        )?;
        ensure_len(
            self.fee_credits.len(),
            PRIVATE_LOW_FEE_TOKEN_LAUNCH_AUCTION_MAX_COMMITMENTS,
            "fee_credits",
        )?;
        ensure_len(
            self.anti_sybil_credentials.len(),
            PRIVATE_LOW_FEE_TOKEN_LAUNCH_AUCTION_MAX_CREDENTIALS,
            "anti_sybil_credentials",
        )?;
        ensure_len(
            self.sealed_bids.len(),
            PRIVATE_LOW_FEE_TOKEN_LAUNCH_AUCTION_MAX_BIDS,
            "sealed_bids",
        )?;
        ensure_len(
            self.vesting_receipts.len(),
            PRIVATE_LOW_FEE_TOKEN_LAUNCH_AUCTION_MAX_RECEIPTS,
            "vesting_receipts",
        )?;
        ensure_len(
            self.allocation_proofs.len(),
            PRIVATE_LOW_FEE_TOKEN_LAUNCH_AUCTION_MAX_PROOFS,
            "allocation_proofs",
        )?;
        ensure_len(
            self.liquidity_routes.len(),
            PRIVATE_LOW_FEE_TOKEN_LAUNCH_AUCTION_MAX_ROUTES,
            "liquidity_routes",
        )?;
        ensure_len(
            self.refund_claims.len(),
            PRIVATE_LOW_FEE_TOKEN_LAUNCH_AUCTION_MAX_REFUNDS,
            "refund_claims",
        )?;
        ensure_len(
            self.nullifiers.len(),
            PRIVATE_LOW_FEE_TOKEN_LAUNCH_AUCTION_MAX_NULLIFIERS,
            "nullifiers",
        )?;

        for (id, launch) in &self.launches {
            if id != &launch.launch_id {
                return Err(format!("launch map key mismatch for {id}"));
            }
            launch.validate()?;
            for round_id in &launch.sale_round_ids {
                let round = self
                    .rounds
                    .get(round_id)
                    .ok_or_else(|| format!("launch {id} references missing round {round_id}"))?;
                if round.launch_id != launch.launch_id {
                    return Err(format!("round {round_id} belongs to wrong launch"));
                }
            }
            for route_id in &launch.liquidity_route_ids {
                let route = self
                    .liquidity_routes
                    .get(route_id)
                    .ok_or_else(|| format!("launch {id} references missing route {route_id}"))?;
                if route.launch_id != launch.launch_id {
                    return Err(format!("route {route_id} belongs to wrong launch"));
                }
            }
        }

        for (id, round) in &self.rounds {
            if id != &round.round_id {
                return Err(format!("round map key mismatch for {id}"));
            }
            round.validate(&self.config)?;
            if !self.launches.contains_key(&round.launch_id) {
                return Err(format!(
                    "round {id} references missing launch {}",
                    round.launch_id
                ));
            }
        }

        for (id, credential) in &self.anti_sybil_credentials {
            if id != &credential.credential_id {
                return Err(format!("credential map key mismatch for {id}"));
            }
            credential.validate(&self.config)?;
        }

        let mut seen_nullifiers = BTreeSet::new();
        for (id, commitment) in &self.private_commitments {
            if id != &commitment.commitment_id {
                return Err(format!("commitment map key mismatch for {id}"));
            }
            commitment.validate()?;
            if !self.rounds.contains_key(&commitment.round_id) {
                return Err(format!(
                    "commitment {id} references missing round {}",
                    commitment.round_id
                ));
            }
            if !self
                .anti_sybil_credentials
                .contains_key(&commitment.credential_id)
            {
                return Err(format!(
                    "commitment {id} references missing credential {}",
                    commitment.credential_id
                ));
            }
            if !self.fee_credits.contains_key(&commitment.fee_credit_id) {
                return Err(format!(
                    "commitment {id} references missing fee credit {}",
                    commitment.fee_credit_id
                ));
            }
            if !seen_nullifiers.insert(commitment.nullifier_commitment.clone()) {
                return Err(format!("duplicate commitment nullifier for {id}"));
            }
        }

        for (id, fee_credit) in &self.fee_credits {
            if id != &fee_credit.fee_credit_id {
                return Err(format!("fee credit map key mismatch for {id}"));
            }
            fee_credit.validate(&self.config)?;
            if !self.rounds.contains_key(&fee_credit.round_id) {
                return Err(format!(
                    "fee credit {id} references missing round {}",
                    fee_credit.round_id
                ));
            }
        }

        for (id, bid) in &self.sealed_bids {
            if id != &bid.bid_id {
                return Err(format!("bid map key mismatch for {id}"));
            }
            bid.validate()?;
            if !self.rounds.contains_key(&bid.round_id) {
                return Err(format!(
                    "bid {id} references missing round {}",
                    bid.round_id
                ));
            }
            if !self.private_commitments.contains_key(&bid.commitment_id) {
                return Err(format!(
                    "bid {id} references missing commitment {}",
                    bid.commitment_id
                ));
            }
            if !self.anti_sybil_credentials.contains_key(&bid.credential_id) {
                return Err(format!(
                    "bid {id} references missing credential {}",
                    bid.credential_id
                ));
            }
            if !seen_nullifiers.insert(bid.nullifier_commitment.clone()) {
                return Err(format!("duplicate bid nullifier for {id}"));
            }
        }

        for (id, receipt) in &self.vesting_receipts {
            if id != &receipt.receipt_id {
                return Err(format!("receipt map key mismatch for {id}"));
            }
            receipt.validate()?;
            if !self.launches.contains_key(&receipt.launch_id) {
                return Err(format!(
                    "receipt {id} references missing launch {}",
                    receipt.launch_id
                ));
            }
            if !self.rounds.contains_key(&receipt.round_id) {
                return Err(format!(
                    "receipt {id} references missing round {}",
                    receipt.round_id
                ));
            }
            if !self.sealed_bids.contains_key(&receipt.bid_id) {
                return Err(format!(
                    "receipt {id} references missing bid {}",
                    receipt.bid_id
                ));
            }
        }

        for (id, proof) in &self.allocation_proofs {
            if id != &proof.proof_id {
                return Err(format!("proof map key mismatch for {id}"));
            }
            proof.validate()?;
            if !self.launches.contains_key(&proof.launch_id) {
                return Err(format!(
                    "proof {id} references missing launch {}",
                    proof.launch_id
                ));
            }
            if !self.rounds.contains_key(&proof.round_id) {
                return Err(format!(
                    "proof {id} references missing round {}",
                    proof.round_id
                ));
            }
        }

        for (id, route) in &self.liquidity_routes {
            if id != &route.route_id {
                return Err(format!("route map key mismatch for {id}"));
            }
            route.validate()?;
            if !self.launches.contains_key(&route.launch_id) {
                return Err(format!(
                    "route {id} references missing launch {}",
                    route.launch_id
                ));
            }
            if !self.rounds.contains_key(&route.round_id) {
                return Err(format!(
                    "route {id} references missing round {}",
                    route.round_id
                ));
            }
        }

        for (id, refund) in &self.refund_claims {
            if id != &refund.refund_id {
                return Err(format!("refund map key mismatch for {id}"));
            }
            refund.validate()?;
            if !self.rounds.contains_key(&refund.round_id) {
                return Err(format!(
                    "refund {id} references missing round {}",
                    refund.round_id
                ));
            }
            if !self.sealed_bids.contains_key(&refund.bid_id) {
                return Err(format!(
                    "refund {id} references missing bid {}",
                    refund.bid_id
                ));
            }
            if !seen_nullifiers.insert(refund.refund_nullifier.clone()) {
                return Err(format!("duplicate refund nullifier for {id}"));
            }
        }

        for (id, nullifier) in &self.nullifiers {
            if id != &nullifier.nullifier {
                return Err(format!("nullifier map key mismatch for {id}"));
            }
            nullifier.validate()?;
        }
        Ok(())
    }

    pub fn set_height(&mut self, height: u64) -> PrivateLowFeeTokenLaunchAuctionResult<()> {
        self.height = height;
        self.validate()
    }

    pub fn update_height(&mut self, delta: u64) -> PrivateLowFeeTokenLaunchAuctionResult<()> {
        self.height = self
            .height
            .checked_add(delta)
            .ok_or_else(|| "private launch auction height overflow".to_string())?;
        self.validate()
    }

    pub fn roots(&self) -> Roots {
        let config_root = self.config.root();
        let launch_root = map_root(
            "PRIVATE-LOW-FEE-TOKEN-LAUNCH-AUCTION-LAUNCH-ROOT",
            &self.launches,
            Launch::root,
        );
        let round_root = map_root(
            "PRIVATE-LOW-FEE-TOKEN-LAUNCH-AUCTION-ROUND-ROOT",
            &self.rounds,
            SaleRound::root,
        );
        let commitment_root = map_root(
            "PRIVATE-LOW-FEE-TOKEN-LAUNCH-AUCTION-COMMITMENT-ROOT",
            &self.private_commitments,
            PrivateCommitment::root,
        );
        let fee_credit_root = map_root(
            "PRIVATE-LOW-FEE-TOKEN-LAUNCH-AUCTION-FEE-CREDIT-ROOT",
            &self.fee_credits,
            FeeCredit::root,
        );
        let credential_root = map_root(
            "PRIVATE-LOW-FEE-TOKEN-LAUNCH-AUCTION-CREDENTIAL-ROOT",
            &self.anti_sybil_credentials,
            AntiSybilCredential::root,
        );
        let bid_root = map_root(
            "PRIVATE-LOW-FEE-TOKEN-LAUNCH-AUCTION-BID-ROOT",
            &self.sealed_bids,
            SealedBid::root,
        );
        let vesting_receipt_root = map_root(
            "PRIVATE-LOW-FEE-TOKEN-LAUNCH-AUCTION-VESTING-RECEIPT-ROOT",
            &self.vesting_receipts,
            VestingReceipt::root,
        );
        let allocation_proof_root = map_root(
            "PRIVATE-LOW-FEE-TOKEN-LAUNCH-AUCTION-ALLOCATION-PROOF-ROOT",
            &self.allocation_proofs,
            ZkAllocationProof::root,
        );
        let liquidity_route_root = map_root(
            "PRIVATE-LOW-FEE-TOKEN-LAUNCH-AUCTION-LIQUIDITY-ROUTE-ROOT",
            &self.liquidity_routes,
            LiquidityBootstrapRoute::root,
        );
        let refund_claim_root = map_root(
            "PRIVATE-LOW-FEE-TOKEN-LAUNCH-AUCTION-REFUND-ROOT",
            &self.refund_claims,
            RefundClaim::root,
        );
        let nullifier_root = map_root(
            "PRIVATE-LOW-FEE-TOKEN-LAUNCH-AUCTION-NULLIFIER-ROOT",
            &self.nullifiers,
            NullifierEntry::root,
        );
        let state_root = domain_hash(
            "PRIVATE-LOW-FEE-TOKEN-LAUNCH-AUCTION-STATE-ROOT",
            &[
                HashPart::Str(&config_root),
                HashPart::Str(&launch_root),
                HashPart::Str(&round_root),
                HashPart::Str(&commitment_root),
                HashPart::Str(&fee_credit_root),
                HashPart::Str(&credential_root),
                HashPart::Str(&bid_root),
                HashPart::Str(&vesting_receipt_root),
                HashPart::Str(&allocation_proof_root),
                HashPart::Str(&liquidity_route_root),
                HashPart::Str(&refund_claim_root),
                HashPart::Str(&nullifier_root),
                HashPart::Int(self.height as i128),
            ],
            32,
        );
        Roots {
            config_root,
            launch_root,
            round_root,
            commitment_root,
            fee_credit_root,
            credential_root,
            bid_root,
            vesting_receipt_root,
            allocation_proof_root,
            liquidity_route_root,
            refund_claim_root,
            nullifier_root,
            state_root,
        }
    }

    pub fn counters(&self) -> Counters {
        Counters {
            launches: self.launches.len() as u64,
            rounds: self.rounds.len() as u64,
            private_commitments: self.private_commitments.len() as u64,
            fee_credits: self.fee_credits.len() as u64,
            anti_sybil_credentials: self.anti_sybil_credentials.len() as u64,
            sealed_bids: self.sealed_bids.len() as u64,
            vesting_receipts: self.vesting_receipts.len() as u64,
            allocation_proofs: self.allocation_proofs.len() as u64,
            liquidity_routes: self.liquidity_routes.len() as u64,
            refund_claims: self.refund_claims.len() as u64,
            nullifiers: self.nullifiers.len() as u64,
            live_rounds: self
                .rounds
                .values()
                .filter(|round| !round.status.terminal())
                .count() as u64,
            live_bids: self
                .sealed_bids
                .values()
                .filter(|bid| bid.status.live())
                .count() as u64,
            claimable_refunds: self
                .refund_claims
                .values()
                .filter(|refund| refund.status == RefundStatus::Claimable)
                .count() as u64,
            verified_allocation_proofs: self
                .allocation_proofs
                .values()
                .filter(|proof| proof.proof_status.accepted())
                .count() as u64,
        }
    }

    pub fn state_root(&self) -> String {
        self.roots().state_root
    }

    pub fn public_record(&self) -> Value {
        json!({
            "height": self.height,
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "label": self.label,
            "config": self.config.public_record(),
            "launches": map_records(&self.launches, Launch::public_record),
            "rounds": map_records(&self.rounds, SaleRound::public_record),
            "private_commitments": map_records(&self.private_commitments, PrivateCommitment::public_record),
            "fee_credits": map_records(&self.fee_credits, FeeCredit::public_record),
            "anti_sybil_credentials": map_records(&self.anti_sybil_credentials, AntiSybilCredential::public_record),
            "sealed_bids": map_records(&self.sealed_bids, SealedBid::public_record),
            "vesting_receipts": map_records(&self.vesting_receipts, VestingReceipt::public_record),
            "allocation_proofs": map_records(&self.allocation_proofs, ZkAllocationProof::public_record),
            "liquidity_routes": map_records(&self.liquidity_routes, LiquidityBootstrapRoute::public_record),
            "refund_claims": map_records(&self.refund_claims, RefundClaim::public_record),
            "nullifiers": map_records(&self.nullifiers, NullifierEntry::public_record),
            "roots": self.roots().public_record(),
            "counters": self.counters().public_record(),
        })
    }
}

pub fn root_from_record(record: &Value) -> String {
    domain_hash(
        "PRIVATE-LOW-FEE-TOKEN-LAUNCH-AUCTION-ROOT-FROM-RECORD",
        &[HashPart::Json(record)],
        32,
    )
}

pub fn devnet() -> PrivateLowFeeTokenLaunchAuctionResult<State> {
    State::devnet()
}

pub fn launch_id(label: &str, issuer_commitment: &str, token_commitment: &str) -> String {
    domain_hash(
        "PRIVATE-LOW-FEE-TOKEN-LAUNCH-AUCTION-LAUNCH-ID",
        &[
            HashPart::Str(label),
            HashPart::Str(issuer_commitment),
            HashPart::Str(token_commitment),
        ],
        24,
    )
}

pub fn sale_round_id(
    launch_id: &str,
    label: &str,
    kind: SaleRoundKind,
    start_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-LOW-FEE-TOKEN-LAUNCH-AUCTION-ROUND-ID",
        &[
            HashPart::Str(launch_id),
            HashPart::Str(label),
            HashPart::Str(kind.as_str()),
            HashPart::Int(start_height as i128),
        ],
        24,
    )
}

pub fn private_commitment_id(
    round_id: &str,
    bidder_commitment: &str,
    nullifier_commitment: &str,
) -> String {
    domain_hash(
        "PRIVATE-LOW-FEE-TOKEN-LAUNCH-AUCTION-COMMITMENT-ID",
        &[
            HashPart::Str(round_id),
            HashPart::Str(bidder_commitment),
            HashPart::Str(nullifier_commitment),
        ],
        24,
    )
}

pub fn anti_sybil_credential_id(
    issuer_id: &str,
    holder_commitment: &str,
    kind: CredentialKind,
    revocation_nullifier: &str,
) -> String {
    domain_hash(
        "PRIVATE-LOW-FEE-TOKEN-LAUNCH-AUCTION-CREDENTIAL-ID",
        &[
            HashPart::Str(issuer_id),
            HashPart::Str(holder_commitment),
            HashPart::Str(kind.as_str()),
            HashPart::Str(revocation_nullifier),
        ],
        24,
    )
}

pub fn fee_credit_id(
    round_id: &str,
    sponsor_commitment: &str,
    beneficiary_commitment: &str,
    credit_note_root: &str,
) -> String {
    domain_hash(
        "PRIVATE-LOW-FEE-TOKEN-LAUNCH-AUCTION-FEE-CREDIT-ID",
        &[
            HashPart::Str(round_id),
            HashPart::Str(sponsor_commitment),
            HashPart::Str(beneficiary_commitment),
            HashPart::Str(credit_note_root),
        ],
        24,
    )
}

pub fn sealed_bid_id(round_id: &str, commitment_id: &str, bid_commitment: &str) -> String {
    domain_hash(
        "PRIVATE-LOW-FEE-TOKEN-LAUNCH-AUCTION-SEALED-BID-ID",
        &[
            HashPart::Str(round_id),
            HashPart::Str(commitment_id),
            HashPart::Str(bid_commitment),
        ],
        24,
    )
}

pub fn vesting_receipt_id(launch_id: &str, round_id: &str, bid_id: &str) -> String {
    domain_hash(
        "PRIVATE-LOW-FEE-TOKEN-LAUNCH-AUCTION-VESTING-RECEIPT-ID",
        &[
            HashPart::Str(launch_id),
            HashPart::Str(round_id),
            HashPart::Str(bid_id),
        ],
        24,
    )
}

pub fn allocation_proof_id(
    round_id: &str,
    allocation_root_after: &str,
    public_inputs_root: &str,
) -> String {
    domain_hash(
        "PRIVATE-LOW-FEE-TOKEN-LAUNCH-AUCTION-ALLOCATION-PROOF-ID",
        &[
            HashPart::Str(round_id),
            HashPart::Str(allocation_root_after),
            HashPart::Str(public_inputs_root),
        ],
        24,
    )
}

pub fn liquidity_route_id(launch_id: &str, round_id: &str, pool_commitment: &str) -> String {
    domain_hash(
        "PRIVATE-LOW-FEE-TOKEN-LAUNCH-AUCTION-LIQUIDITY-ROUTE-ID",
        &[
            HashPart::Str(launch_id),
            HashPart::Str(round_id),
            HashPart::Str(pool_commitment),
        ],
        24,
    )
}

pub fn refund_claim_id(round_id: &str, bid_id: &str, refund_nullifier: &str) -> String {
    domain_hash(
        "PRIVATE-LOW-FEE-TOKEN-LAUNCH-AUCTION-REFUND-ID",
        &[
            HashPart::Str(round_id),
            HashPart::Str(bid_id),
            HashPart::Str(refund_nullifier),
        ],
        24,
    )
}

fn launch_fixture(
    label: &str,
    status: LaunchStatus,
    created_height: u64,
    updated_height: u64,
    min_raise_units: u64,
    hard_cap_units: u64,
) -> Launch {
    let issuer_commitment = string_root("PRIVATE-LOW-FEE-TOKEN-LAUNCH-AUCTION-ISSUER", label);
    let token_commitment = string_root("PRIVATE-LOW-FEE-TOKEN-LAUNCH-AUCTION-TOKEN", label);
    let launch_id = launch_id(label, &issuer_commitment, &token_commitment);
    Launch {
        launch_id,
        issuer_commitment,
        token_commitment,
        treasury_commitment: string_root("PRIVATE-LOW-FEE-TOKEN-LAUNCH-AUCTION-TREASURY", label),
        status,
        sale_round_ids: BTreeSet::new(),
        liquidity_route_ids: BTreeSet::new(),
        auditor_set_id: format!("auditor-set-{label}"),
        min_raise_units,
        hard_cap_units,
        token_supply_commitment: string_root("PRIVATE-LOW-FEE-TOKEN-LAUNCH-AUCTION-SUPPLY", label),
        metadata_root: payload_root(
            "PRIVATE-LOW-FEE-TOKEN-LAUNCH-AUCTION-METADATA",
            &json!({ "label": label, "devnet": true }),
        ),
        created_height,
        updated_height,
    }
}

fn round_fixture(
    launch_id: &str,
    label: &str,
    kind: SaleRoundKind,
    status: RoundStatus,
    start_height: u64,
    config: &Config,
) -> SaleRound {
    let round_id = sale_round_id(launch_id, label, kind, start_height);
    let mut required_credential_kinds = BTreeSet::new();
    if kind.credential_required() {
        required_credential_kinds.insert(CredentialKind::HumanUniqueness);
        required_credential_kinds.insert(CredentialKind::SanctionsClear);
    }
    if kind == SaleRoundKind::LiquidityBootstrap {
        required_credential_kinds.insert(CredentialKind::LiquidityProvider);
    }
    SaleRound {
        round_id,
        launch_id: launch_id.to_string(),
        kind,
        status,
        start_height,
        commit_end_height: start_height + config.commit_blocks,
        reveal_end_height: start_height + config.commit_blocks + config.reveal_blocks,
        settle_height: start_height
            + config.commit_blocks
            + config.reveal_blocks
            + config.settlement_blocks,
        price_commitment: string_root("PRIVATE-LOW-FEE-TOKEN-LAUNCH-AUCTION-PRICE", label),
        allocation_cap_units: 10_000_000,
        min_bid_units: config.min_bid_units,
        max_bid_units: config.max_bid_units,
        required_credential_kinds,
        accepted_jurisdiction_root: string_root(
            "PRIVATE-LOW-FEE-TOKEN-LAUNCH-AUCTION-JURISDICTIONS",
            label,
        ),
        privacy_set_root: string_root("PRIVATE-LOW-FEE-TOKEN-LAUNCH-AUCTION-PRIVACY-SET", label),
        round_salt_commitment: string_root(
            "PRIVATE-LOW-FEE-TOKEN-LAUNCH-AUCTION-ROUND-SALT",
            label,
        ),
    }
}

fn credential_fixture(
    label: &str,
    kind: CredentialKind,
    issued_height: u64,
) -> AntiSybilCredential {
    let holder_commitment = string_root("PRIVATE-LOW-FEE-TOKEN-LAUNCH-AUCTION-HOLDER", label);
    let revocation_nullifier =
        string_root("PRIVATE-LOW-FEE-TOKEN-LAUNCH-AUCTION-REVOCATION", label);
    let credential_id = anti_sybil_credential_id(
        "nebula-devnet-anti-sybil-issuer",
        &holder_commitment,
        kind,
        &revocation_nullifier,
    );
    AntiSybilCredential {
        credential_id,
        issuer_id: "nebula-devnet-anti-sybil-issuer".to_string(),
        holder_commitment,
        kind,
        status: CredentialStatus::Active,
        weight: kind.default_weight(),
        sybil_score_bps: 750,
        anonymity_set_size: PRIVATE_LOW_FEE_TOKEN_LAUNCH_AUCTION_DEFAULT_PRIVACY_SET_SIZE,
        issued_height,
        expires_height: issued_height
            + PRIVATE_LOW_FEE_TOKEN_LAUNCH_AUCTION_DEFAULT_CREDENTIAL_TTL_BLOCKS,
        pq_signature_root: string_root("PRIVATE-LOW-FEE-TOKEN-LAUNCH-AUCTION-PQ-SIGNATURE", label),
        revocation_nullifier,
    }
}

fn fee_credit_fixture(
    round_id: &str,
    sponsor_label: &str,
    beneficiary_label: &str,
    expires_height: u64,
) -> FeeCredit {
    let sponsor_commitment = string_root(
        "PRIVATE-LOW-FEE-TOKEN-LAUNCH-AUCTION-SPONSOR",
        sponsor_label,
    );
    let beneficiary_commitment = string_root(
        "PRIVATE-LOW-FEE-TOKEN-LAUNCH-AUCTION-BENEFICIARY",
        beneficiary_label,
    );
    let credit_note_root = payload_root(
        "PRIVATE-LOW-FEE-TOKEN-LAUNCH-AUCTION-CREDIT-NOTE",
        &json!({ "round_id": round_id, "sponsor": sponsor_label, "beneficiary": beneficiary_label }),
    );
    FeeCredit {
        fee_credit_id: fee_credit_id(
            round_id,
            &sponsor_commitment,
            &beneficiary_commitment,
            &credit_note_root,
        ),
        sponsor_commitment,
        beneficiary_commitment,
        round_id: round_id.to_string(),
        status: FeeCreditStatus::Sponsored,
        max_fee_units: 12,
        discount_bps: 8_000,
        reserved_units: 12,
        consumed_units: 4,
        expires_height,
        credit_note_root,
    }
}

fn commitment_fixture(
    round_id: &str,
    credential_id: &str,
    fee_credit_id: &str,
    label: &str,
    first_seen_height: u64,
) -> PrivateCommitment {
    let bidder_commitment = string_root("PRIVATE-LOW-FEE-TOKEN-LAUNCH-AUCTION-BIDDER", label);
    let nullifier_commitment = string_root(
        "PRIVATE-LOW-FEE-TOKEN-LAUNCH-AUCTION-COMMITMENT-NULLIFIER",
        label,
    );
    PrivateCommitment {
        commitment_id: private_commitment_id(round_id, &bidder_commitment, &nullifier_commitment),
        round_id: round_id.to_string(),
        bidder_commitment,
        credential_id: credential_id.to_string(),
        amount_commitment: string_root("PRIVATE-LOW-FEE-TOKEN-LAUNCH-AUCTION-AMOUNT", label),
        quote_asset_commitment: string_root("PRIVATE-LOW-FEE-TOKEN-LAUNCH-AUCTION-QUOTE", label),
        nullifier_commitment,
        encrypted_payload_root: string_root(
            "PRIVATE-LOW-FEE-TOKEN-LAUNCH-AUCTION-ENCRYPTED-PAYLOAD",
            label,
        ),
        fee_credit_id: fee_credit_id.to_string(),
        first_seen_height,
    }
}

fn bid_fixture(
    round_id: &str,
    commitment_id: &str,
    credential_id: &str,
    status: BidStatus,
    label: &str,
    created_height: u64,
    revealed_height: Option<u64>,
) -> SealedBid {
    let bid_commitment = string_root("PRIVATE-LOW-FEE-TOKEN-LAUNCH-AUCTION-BID-COMMITMENT", label);
    SealedBid {
        bid_id: sealed_bid_id(round_id, commitment_id, &bid_commitment),
        round_id: round_id.to_string(),
        commitment_id: commitment_id.to_string(),
        credential_id: credential_id.to_string(),
        status,
        bid_commitment,
        encrypted_bid_root: string_root(
            "PRIVATE-LOW-FEE-TOKEN-LAUNCH-AUCTION-ENCRYPTED-BID",
            label,
        ),
        reveal_proof_root: string_root("PRIVATE-LOW-FEE-TOKEN-LAUNCH-AUCTION-REVEAL-PROOF", label),
        quote_amount_commitment: string_root(
            "PRIVATE-LOW-FEE-TOKEN-LAUNCH-AUCTION-QUOTE-AMOUNT",
            label,
        ),
        max_price_commitment: string_root("PRIVATE-LOW-FEE-TOKEN-LAUNCH-AUCTION-MAX-PRICE", label),
        nullifier_commitment: string_root(
            "PRIVATE-LOW-FEE-TOKEN-LAUNCH-AUCTION-BID-NULLIFIER",
            label,
        ),
        created_height,
        revealed_height,
    }
}

fn receipt_fixture(
    launch_id: &str,
    round_id: &str,
    bid_id: &str,
    label: &str,
    created_height: u64,
) -> VestingReceipt {
    VestingReceipt {
        receipt_id: vesting_receipt_id(launch_id, round_id, bid_id),
        launch_id: launch_id.to_string(),
        round_id: round_id.to_string(),
        bid_id: bid_id.to_string(),
        beneficiary_commitment: string_root(
            "PRIVATE-LOW-FEE-TOKEN-LAUNCH-AUCTION-RECEIPT-BENEFICIARY",
            label,
        ),
        status: VestingStatus::CliffLocked,
        allocation_commitment: string_root(
            "PRIVATE-LOW-FEE-TOKEN-LAUNCH-AUCTION-ALLOCATION",
            label,
        ),
        vesting_schedule_root: string_root(
            "PRIVATE-LOW-FEE-TOKEN-LAUNCH-AUCTION-VESTING-SCHEDULE",
            label,
        ),
        cliff_height: created_height + 720,
        start_height: created_height,
        end_height: created_height + 8_640,
        receipt_proof_root: string_root(
            "PRIVATE-LOW-FEE-TOKEN-LAUNCH-AUCTION-RECEIPT-PROOF",
            label,
        ),
        created_height,
    }
}

fn proof_fixture(
    launch_id: &str,
    round_id: &str,
    label: &str,
    proof_status: ProofStatus,
    generated_height: u64,
    verified_height: Option<u64>,
) -> ZkAllocationProof {
    let allocation_root_after = string_root(
        "PRIVATE-LOW-FEE-TOKEN-LAUNCH-AUCTION-ALLOCATION-AFTER",
        label,
    );
    let public_inputs_root =
        string_root("PRIVATE-LOW-FEE-TOKEN-LAUNCH-AUCTION-PUBLIC-INPUTS", label);
    ZkAllocationProof {
        proof_id: allocation_proof_id(round_id, &allocation_root_after, &public_inputs_root),
        round_id: round_id.to_string(),
        launch_id: launch_id.to_string(),
        proof_status,
        allocation_root_before: string_root(
            "PRIVATE-LOW-FEE-TOKEN-LAUNCH-AUCTION-ALLOCATION-BEFORE",
            label,
        ),
        allocation_root_after,
        winning_bid_root: string_root("PRIVATE-LOW-FEE-TOKEN-LAUNCH-AUCTION-WINNING-BIDS", label),
        refund_root: string_root(
            "PRIVATE-LOW-FEE-TOKEN-LAUNCH-AUCTION-REFUND-ROOT-FIXTURE",
            label,
        ),
        constraint_system_root: string_root(
            "PRIVATE-LOW-FEE-TOKEN-LAUNCH-AUCTION-CONSTRAINT-SYSTEM",
            label,
        ),
        public_inputs_root,
        verifier_key_root: string_root("PRIVATE-LOW-FEE-TOKEN-LAUNCH-AUCTION-VERIFIER-KEY", label),
        generated_height,
        verified_height,
    }
}

fn route_fixture(
    launch_id: &str,
    round_id: &str,
    label: &str,
    start_height: u64,
) -> LiquidityBootstrapRoute {
    let pool_commitment = string_root("PRIVATE-LOW-FEE-TOKEN-LAUNCH-AUCTION-POOL", label);
    let mut solver_commitments = BTreeSet::new();
    solver_commitments.insert(string_root(
        "PRIVATE-LOW-FEE-TOKEN-LAUNCH-AUCTION-SOLVER",
        "solver-a",
    ));
    solver_commitments.insert(string_root(
        "PRIVATE-LOW-FEE-TOKEN-LAUNCH-AUCTION-SOLVER",
        "solver-b",
    ));
    LiquidityBootstrapRoute {
        route_id: liquidity_route_id(launch_id, round_id, &pool_commitment),
        launch_id: launch_id.to_string(),
        round_id: round_id.to_string(),
        status: LiquidityRouteStatus::Bootstrapping,
        pool_commitment,
        base_asset_commitment: string_root(
            "PRIVATE-LOW-FEE-TOKEN-LAUNCH-AUCTION-BASE-ASSET",
            label,
        ),
        quote_asset_commitment: string_root("PRIVATE-LOW-FEE-TOKEN-LAUNCH-AUCTION-LP-QUOTE", label),
        initial_price_commitment: string_root(
            "PRIVATE-LOW-FEE-TOKEN-LAUNCH-AUCTION-INITIAL-PRICE",
            label,
        ),
        inventory_commitment: string_root("PRIVATE-LOW-FEE-TOKEN-LAUNCH-AUCTION-INVENTORY", label),
        route_policy_root: string_root("PRIVATE-LOW-FEE-TOKEN-LAUNCH-AUCTION-ROUTE-POLICY", label),
        solver_commitments,
        start_height,
        end_height: start_height + 720,
    }
}

fn refund_fixture(round_id: &str, bid_id: &str, label: &str, claimable_height: u64) -> RefundClaim {
    let refund_nullifier = string_root(
        "PRIVATE-LOW-FEE-TOKEN-LAUNCH-AUCTION-REFUND-NULLIFIER",
        label,
    );
    RefundClaim {
        refund_id: refund_claim_id(round_id, bid_id, &refund_nullifier),
        round_id: round_id.to_string(),
        bid_id: bid_id.to_string(),
        claimant_commitment: string_root("PRIVATE-LOW-FEE-TOKEN-LAUNCH-AUCTION-CLAIMANT", label),
        status: RefundStatus::Claimable,
        refund_amount_commitment: string_root(
            "PRIVATE-LOW-FEE-TOKEN-LAUNCH-AUCTION-REFUND-AMOUNT",
            label,
        ),
        fee_refund_commitment: string_root(
            "PRIVATE-LOW-FEE-TOKEN-LAUNCH-AUCTION-FEE-REFUND",
            label,
        ),
        refund_nullifier,
        claim_proof_root: string_root("PRIVATE-LOW-FEE-TOKEN-LAUNCH-AUCTION-CLAIM-PROOF", label),
        claimable_height,
        claimed_height: None,
    }
}

fn nullifier_fixture(
    nullifier: &str,
    source_id: &str,
    source_kind: &str,
    first_seen_height: u64,
) -> NullifierEntry {
    NullifierEntry {
        nullifier: nullifier.to_string(),
        source_id: source_id.to_string(),
        source_kind: source_kind.to_string(),
        first_seen_height,
    }
}

fn map_root<T, F>(domain: &str, map: &BTreeMap<String, T>, root_fn: F) -> String
where
    F: Fn(&T) -> String,
{
    let leaves = map
        .iter()
        .map(|(id, value)| json!({ "id": id, "root": root_fn(value) }))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn map_records<T, F>(map: &BTreeMap<String, T>, record_fn: F) -> Vec<Value>
where
    F: Fn(&T) -> Value,
{
    map.values().map(record_fn).collect::<Vec<_>>()
}

fn string_set_record(values: &BTreeSet<String>) -> Vec<Value> {
    values.iter().map(|value| json!(value)).collect::<Vec<_>>()
}

fn string_root(domain: &str, value: &str) -> String {
    domain_hash(domain, &[HashPart::Str(value)], 32)
}

fn payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(domain, &[HashPart::Json(payload)], 32)
}

fn ensure_len(actual: usize, max: usize, label: &str) -> PrivateLowFeeTokenLaunchAuctionResult<()> {
    if actual > max {
        Err(format!("private launch auction {label} exceeds max"))
    } else {
        Ok(())
    }
}

fn ensure_non_empty(value: &str, label: &str) -> PrivateLowFeeTokenLaunchAuctionResult<()> {
    if value.is_empty() {
        Err(format!("{label} cannot be empty"))
    } else {
        Ok(())
    }
}
