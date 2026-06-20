use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2ConfidentialTokenBasketIndexVaultRuntimeResult<T> =
    std::result::Result<T, String>;
pub type Result<T> = PrivateL2ConfidentialTokenBasketIndexVaultRuntimeResult<T>;
pub type Runtime = State;

pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_BASKET_INDEX_VAULT_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-confidential-token-basket-index-vault-runtime-v1";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_BASKET_INDEX_VAULT_RUNTIME_SCHEMA_VERSION: u64 = 1;
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_BASKET_INDEX_VAULT_RUNTIME_HASH_SUITE: &str =
    "SHAKE256-domain-separated-canonical-json";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_BASKET_INDEX_VAULT_RUNTIME_PQ_AUTH_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256s-token-basket-index-vault-v1";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_BASKET_INDEX_VAULT_RUNTIME_BASKET_DEFINITION_SCHEME: &str =
    "monero-private-l2-sealed-token-basket-definition-root-v1";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_BASKET_INDEX_VAULT_RUNTIME_DEPOSIT_NOTE_SCHEME: &str =
    "monero-private-l2-encrypted-token-basket-deposit-note-root-v1";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_BASKET_INDEX_VAULT_RUNTIME_REDEEM_NOTE_SCHEME: &str =
    "monero-private-l2-encrypted-token-basket-redeem-note-root-v1";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_BASKET_INDEX_VAULT_RUNTIME_REBALANCE_BATCH_SCHEME: &str =
    "monero-private-l2-confidential-token-index-rebalance-batch-root-v1";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_BASKET_INDEX_VAULT_RUNTIME_NAV_ATTESTATION_SCHEME: &str =
    "monero-private-l2-private-nav-oracle-attestation-root-v1";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_BASKET_INDEX_VAULT_RUNTIME_SPONSOR_REBATE_SCHEME: &str =
    "monero-private-l2-token-index-vault-sponsor-rebate-root-v1";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_BASKET_INDEX_VAULT_RUNTIME_LOW_FEE_SETTLEMENT_SCHEME: &str =
    "roots-only-low-fee-token-basket-index-settlement-root-v1";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_BASKET_INDEX_VAULT_RUNTIME_PRIVACY_FENCE_SCHEME: &str =
    "monero-private-l2-token-index-vault-nullifier-fence-root-v1";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_BASKET_INDEX_VAULT_RUNTIME_PUBLIC_RECORD_SCHEME: &str =
    "roots-only-confidential-token-basket-index-vault-public-record-v1";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_BASKET_INDEX_VAULT_RUNTIME_DEVNET_HEIGHT: u64 = 1_384_000;
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_BASKET_INDEX_VAULT_RUNTIME_DEFAULT_MONERO_NETWORK: &str =
    "monero-devnet";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_BASKET_INDEX_VAULT_RUNTIME_DEFAULT_L2_NETWORK: &str =
    "nebula-devnet";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_BASKET_INDEX_VAULT_RUNTIME_DEFAULT_LOW_FEE_LANE: &str =
    "devnet-private-l2-token-index-vault-low-fee";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_BASKET_INDEX_VAULT_RUNTIME_DEFAULT_FEE_ASSET_ID: &str =
    "asset:piconero";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_BASKET_INDEX_VAULT_RUNTIME_DEFAULT_SHARE_ASSET_ID: &str =
    "asset:private-index-share";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_BASKET_INDEX_VAULT_RUNTIME_MAX_BPS: u64 = 10_000;
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_BASKET_INDEX_VAULT_RUNTIME_DEFAULT_MIN_PRIVACY_SET_SIZE:
    u64 = 16_384;
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_BASKET_INDEX_VAULT_RUNTIME_DEFAULT_BATCH_PRIVACY_SET_SIZE: u64 = 262_144;
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_BASKET_INDEX_VAULT_RUNTIME_DEFAULT_MAX_USER_FEE_BPS: u64 =
    14;
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_BASKET_INDEX_VAULT_RUNTIME_DEFAULT_TARGET_USER_FEE_BPS:
    u64 = 5;
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_BASKET_INDEX_VAULT_RUNTIME_DEFAULT_SPONSOR_REBATE_BPS: u64 =
    7;
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_BASKET_INDEX_VAULT_RUNTIME_DEFAULT_MANAGER_FEE_BPS: u64 =
    18;
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_BASKET_INDEX_VAULT_RUNTIME_DEFAULT_MAX_TRACKING_ERROR_BPS: u64 = 75;
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_BASKET_INDEX_VAULT_RUNTIME_DEFAULT_MAX_COMPONENTS: usize =
    128;
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_BASKET_INDEX_VAULT_RUNTIME_DEFAULT_MAX_BASKETS: usize =
    262_144;
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_BASKET_INDEX_VAULT_RUNTIME_DEFAULT_MAX_NOTES: usize =
    4_194_304;
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_BASKET_INDEX_VAULT_RUNTIME_DEFAULT_MAX_REBALANCE_BATCHES:
    usize = 1_048_576;
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_BASKET_INDEX_VAULT_RUNTIME_DEFAULT_MAX_NAV_ATTESTATIONS:
    usize = 2_097_152;
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_BASKET_INDEX_VAULT_RUNTIME_DEFAULT_MAX_SPONSOR_REBATES:
    usize = 2_097_152;
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_BASKET_INDEX_VAULT_RUNTIME_DEFAULT_MAX_SETTLEMENTS: usize =
    2_097_152;
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_BASKET_INDEX_VAULT_RUNTIME_DEFAULT_MAX_PRIVACY_FENCES:
    usize = 8_388_608;
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_BASKET_INDEX_VAULT_RUNTIME_DEFAULT_NOTE_TTL_BLOCKS: u64 =
    96;
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_BASKET_INDEX_VAULT_RUNTIME_DEFAULT_REBALANCE_TTL_BLOCKS:
    u64 = 32;
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_BASKET_INDEX_VAULT_RUNTIME_DEFAULT_ATTESTATION_TTL_BLOCKS: u64 = 720;
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_BASKET_INDEX_VAULT_RUNTIME_DEFAULT_SETTLEMENT_TTL_BLOCKS:
    u64 = 18;
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_BASKET_INDEX_VAULT_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS:
    u16 = 256;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BasketKind {
    MarketCapIndex,
    EqualWeightIndex,
    VolatilityTarget,
    YieldWeighted,
    SyntheticSector,
    StableBasket,
    CustomVault,
}
impl BasketKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MarketCapIndex => "market_cap_index",
            Self::EqualWeightIndex => "equal_weight_index",
            Self::VolatilityTarget => "volatility_target",
            Self::YieldWeighted => "yield_weighted",
            Self::SyntheticSector => "synthetic_sector",
            Self::StableBasket => "stable_basket",
            Self::CustomVault => "custom_vault",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BasketStatus {
    Draft,
    Sealed,
    Active,
    DepositOnly,
    RedeemOnly,
    RebalanceOnly,
    Paused,
    Retired,
}
impl BasketStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Sealed => "sealed",
            Self::Active => "active",
            Self::DepositOnly => "deposit_only",
            Self::RedeemOnly => "redeem_only",
            Self::RebalanceOnly => "rebalance_only",
            Self::Paused => "paused",
            Self::Retired => "retired",
        }
    }
    pub fn accepts_deposits(self) -> bool {
        matches!(self, Self::Active | Self::DepositOnly)
    }
    pub fn accepts_redeems(self) -> bool {
        matches!(self, Self::Active | Self::RedeemOnly)
    }
    pub fn accepts_rebalances(self) -> bool {
        matches!(self, Self::Active | Self::RebalanceOnly)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NoteKind {
    Deposit,
    Redeem,
    MigrationIn,
    MigrationOut,
    FeeSweep,
    RebateClaim,
}
impl NoteKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Deposit => "deposit",
            Self::Redeem => "redeem",
            Self::MigrationIn => "migration_in",
            Self::MigrationOut => "migration_out",
            Self::FeeSweep => "fee_sweep",
            Self::RebateClaim => "rebate_claim",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NoteStatus {
    Submitted,
    PrivacyFenced,
    NavQuoted,
    Accepted,
    Batched,
    Settled,
    Redeemed,
    Expired,
    Rejected,
}
impl NoteStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::PrivacyFenced => "privacy_fenced",
            Self::NavQuoted => "nav_quoted",
            Self::Accepted => "accepted",
            Self::Batched => "batched",
            Self::Settled => "settled",
            Self::Redeemed => "redeemed",
            Self::Expired => "expired",
            Self::Rejected => "rejected",
        }
    }
    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Submitted
                | Self::PrivacyFenced
                | Self::NavQuoted
                | Self::Accepted
                | Self::Batched
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RebalanceIntent {
    TargetWeights,
    CashDragSweep,
    OracleCorrection,
    FeeHarvest,
    EmergencyDeRisk,
    ComponentMigration,
}
impl RebalanceIntent {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::TargetWeights => "target_weights",
            Self::CashDragSweep => "cash_drag_sweep",
            Self::OracleCorrection => "oracle_correction",
            Self::FeeHarvest => "fee_harvest",
            Self::EmergencyDeRisk => "emergency_de_risk",
            Self::ComponentMigration => "component_migration",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RebalanceStatus {
    Proposed,
    PrivacyFenced,
    NavAttested,
    Sponsored,
    Queued,
    Executed,
    Settled,
    Rejected,
    Expired,
}
impl RebalanceStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::PrivacyFenced => "privacy_fenced",
            Self::NavAttested => "nav_attested",
            Self::Sponsored => "sponsored",
            Self::Queued => "queued",
            Self::Executed => "executed",
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
                | Self::NavAttested
                | Self::Sponsored
                | Self::Queued
                | Self::Executed
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NavVerdict {
    Pending,
    Fresh,
    Stale,
    Disputed,
    CircuitBreaker,
    Rejected,
}
impl NavVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Fresh => "fresh",
            Self::Stale => "stale",
            Self::Disputed => "disputed",
            Self::CircuitBreaker => "circuit_breaker",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorRebateStatus {
    Reserved,
    Earned,
    Claimed,
    Released,
    Expired,
}
impl SponsorRebateStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Earned => "earned",
            Self::Claimed => "claimed",
            Self::Released => "released",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementStatus {
    Queued,
    Aggregated,
    Published,
    Finalized,
    Disputed,
    Expired,
}
impl SettlementStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Aggregated => "aggregated",
            Self::Published => "published",
            Self::Finalized => "finalized",
            Self::Disputed => "disputed",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivacyFenceStatus {
    Open,
    Locked,
    Consumed,
    Released,
    Expired,
}
impl PrivacyFenceStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Locked => "locked",
            Self::Consumed => "consumed",
            Self::Released => "released",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VaultEventKind {
    BasketSealed,
    DepositQueued,
    RedeemQueued,
    NavAttested,
    RebalanceQueued,
    RebalanceSettled,
    SponsorRebateEarned,
    SettlementFinalized,
    FenceConsumed,
}
impl VaultEventKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BasketSealed => "basket_sealed",
            Self::DepositQueued => "deposit_queued",
            Self::RedeemQueued => "redeem_queued",
            Self::NavAttested => "nav_attested",
            Self::RebalanceQueued => "rebalance_queued",
            Self::RebalanceSettled => "rebalance_settled",
            Self::SponsorRebateEarned => "sponsor_rebate_earned",
            Self::SettlementFinalized => "settlement_finalized",
            Self::FenceConsumed => "fence_consumed",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub protocol_version: String,
    pub schema_version: u64,
    pub chain_id: String,
    pub hash_suite: String,
    pub pq_auth_suite: String,
    pub basket_definition_scheme: String,
    pub deposit_note_scheme: String,
    pub redeem_note_scheme: String,
    pub rebalance_batch_scheme: String,
    pub nav_attestation_scheme: String,
    pub sponsor_rebate_scheme: String,
    pub low_fee_settlement_scheme: String,
    pub privacy_fence_scheme: String,
    pub public_record_scheme: String,
    pub monero_network: String,
    pub l2_network: String,
    pub low_fee_lane: String,
    pub fee_asset_id: String,
    pub share_asset_id: String,
    pub min_privacy_set_size: u64,
    pub batch_privacy_set_size: u64,
    pub max_user_fee_bps: u64,
    pub target_user_fee_bps: u64,
    pub sponsor_rebate_bps: u64,
    pub manager_fee_bps: u64,
    pub max_tracking_error_bps: u64,
    pub max_components: usize,
    pub max_baskets: usize,
    pub max_notes: usize,
    pub max_rebalance_batches: usize,
    pub max_nav_attestations: usize,
    pub max_sponsor_rebates: usize,
    pub max_settlements: usize,
    pub max_privacy_fences: usize,
    pub note_ttl_blocks: u64,
    pub rebalance_ttl_blocks: u64,
    pub attestation_ttl_blocks: u64,
    pub settlement_ttl_blocks: u64,
    pub min_pq_security_bits: u16,
    pub require_private_nav_attestations: bool,
    pub require_privacy_fences: bool,
    pub require_low_fee_settlement: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BasketComponent {
    pub component_id: String,
    pub asset_id: String,
    pub sealed_symbol_commitment: String,
    pub target_weight_bps: u64,
    pub min_weight_bps: u64,
    pub max_weight_bps: u64,
    pub oracle_feed_commitment: String,
    pub risk_bucket: String,
    pub rebalance_enabled: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedBasketDefinition {
    pub basket_id: String,
    pub kind: BasketKind,
    pub status: BasketStatus,
    pub manager_commitment: String,
    pub share_asset_id: String,
    pub sealed_terms_ciphertext: String,
    pub component_root: String,
    pub components: Vec<BasketComponent>,
    pub fee_bps: u64,
    pub tracking_error_limit_bps: u64,
    pub created_height: u64,
    pub activation_height: u64,
    pub expiry_height: u64,
    pub definition_commitment: String,
    pub privacy_domain: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedVaultNote {
    pub note_id: String,
    pub basket_id: String,
    pub kind: NoteKind,
    pub status: NoteStatus,
    pub owner_view_key_commitment: String,
    pub encrypted_payload: String,
    pub amount_commitment: String,
    pub share_commitment: String,
    pub nav_quote_id: String,
    pub nullifier: String,
    pub fence_id: String,
    pub sponsor_id: String,
    pub submitted_height: u64,
    pub expires_height: u64,
    pub fee_bps: u64,
    pub metadata_root: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NavOracleAttestation {
    pub attestation_id: String,
    pub basket_id: String,
    pub verdict: NavVerdict,
    pub oracle_committee_root: String,
    pub price_vector_root: String,
    pub nav_commitment: String,
    pub confidence_bps: u64,
    pub tracking_error_bps: u64,
    pub valid_from_height: u64,
    pub valid_until_height: u64,
    pub signature_root: String,
    pub disclosure_policy_root: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RebalanceBatch {
    pub batch_id: String,
    pub basket_id: String,
    pub intent: RebalanceIntent,
    pub status: RebalanceStatus,
    pub input_note_root: String,
    pub output_note_root: String,
    pub target_component_root: String,
    pub nav_attestation_id: String,
    pub sponsor_rebate_id: String,
    pub privacy_fence_root: String,
    pub solver_commitment: String,
    pub created_height: u64,
    pub expires_height: u64,
    pub estimated_fee_bps: u64,
    pub tracking_error_after_bps: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SponsorRebate {
    pub rebate_id: String,
    pub sponsor_id: String,
    pub basket_id: String,
    pub status: SponsorRebateStatus,
    pub batch_id: String,
    pub note_root: String,
    pub rebate_commitment: String,
    pub budget_commitment: String,
    pub fee_discount_bps: u64,
    pub reserved_height: u64,
    pub expires_height: u64,
    pub claim_nullifier: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeSettlement {
    pub settlement_id: String,
    pub batch_id: String,
    pub basket_id: String,
    pub status: SettlementStatus,
    pub lane: String,
    pub settlement_root: String,
    pub public_delta_root: String,
    pub fee_commitment: String,
    pub rebate_root: String,
    pub posted_height: u64,
    pub finalized_height: u64,
    pub aggregator_commitment: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivacyFence {
    pub fence_id: String,
    pub basket_id: String,
    pub status: PrivacyFenceStatus,
    pub nullifier_root: String,
    pub membership_root: String,
    pub min_privacy_set_size: u64,
    pub opened_height: u64,
    pub expires_height: u64,
    pub consumed_by: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultEvent {
    pub event_id: String,
    pub kind: VaultEventKind,
    pub basket_id: String,
    pub subject_id: String,
    pub height: u64,
    pub record_root: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicRecord {
    pub protocol_version: String,
    pub schema_version: u64,
    pub chain_id: String,
    pub height: u64,
    pub basket_root: String,
    pub deposit_note_root: String,
    pub redeem_note_root: String,
    pub rebalance_batch_root: String,
    pub nav_attestation_root: String,
    pub sponsor_rebate_root: String,
    pub settlement_root: String,
    pub privacy_fence_root: String,
    pub event_root: String,
    pub state_root: String,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version: PRIVATE_L2_CONFIDENTIAL_TOKEN_BASKET_INDEX_VAULT_RUNTIME_PROTOCOL_VERSION.to_string(),
            schema_version: PRIVATE_L2_CONFIDENTIAL_TOKEN_BASKET_INDEX_VAULT_RUNTIME_SCHEMA_VERSION,
            chain_id: CHAIN_ID.to_string(),
            hash_suite: PRIVATE_L2_CONFIDENTIAL_TOKEN_BASKET_INDEX_VAULT_RUNTIME_HASH_SUITE.to_string(),
            pq_auth_suite: PRIVATE_L2_CONFIDENTIAL_TOKEN_BASKET_INDEX_VAULT_RUNTIME_PQ_AUTH_SUITE.to_string(),
            basket_definition_scheme: PRIVATE_L2_CONFIDENTIAL_TOKEN_BASKET_INDEX_VAULT_RUNTIME_BASKET_DEFINITION_SCHEME.to_string(),
            deposit_note_scheme: PRIVATE_L2_CONFIDENTIAL_TOKEN_BASKET_INDEX_VAULT_RUNTIME_DEPOSIT_NOTE_SCHEME.to_string(),
            redeem_note_scheme: PRIVATE_L2_CONFIDENTIAL_TOKEN_BASKET_INDEX_VAULT_RUNTIME_REDEEM_NOTE_SCHEME.to_string(),
            rebalance_batch_scheme: PRIVATE_L2_CONFIDENTIAL_TOKEN_BASKET_INDEX_VAULT_RUNTIME_REBALANCE_BATCH_SCHEME.to_string(),
            nav_attestation_scheme: PRIVATE_L2_CONFIDENTIAL_TOKEN_BASKET_INDEX_VAULT_RUNTIME_NAV_ATTESTATION_SCHEME.to_string(),
            sponsor_rebate_scheme: PRIVATE_L2_CONFIDENTIAL_TOKEN_BASKET_INDEX_VAULT_RUNTIME_SPONSOR_REBATE_SCHEME.to_string(),
            low_fee_settlement_scheme: PRIVATE_L2_CONFIDENTIAL_TOKEN_BASKET_INDEX_VAULT_RUNTIME_LOW_FEE_SETTLEMENT_SCHEME.to_string(),
            privacy_fence_scheme: PRIVATE_L2_CONFIDENTIAL_TOKEN_BASKET_INDEX_VAULT_RUNTIME_PRIVACY_FENCE_SCHEME.to_string(),
            public_record_scheme: PRIVATE_L2_CONFIDENTIAL_TOKEN_BASKET_INDEX_VAULT_RUNTIME_PUBLIC_RECORD_SCHEME.to_string(),
            monero_network: PRIVATE_L2_CONFIDENTIAL_TOKEN_BASKET_INDEX_VAULT_RUNTIME_DEFAULT_MONERO_NETWORK.to_string(),
            l2_network: PRIVATE_L2_CONFIDENTIAL_TOKEN_BASKET_INDEX_VAULT_RUNTIME_DEFAULT_L2_NETWORK.to_string(),
            low_fee_lane: PRIVATE_L2_CONFIDENTIAL_TOKEN_BASKET_INDEX_VAULT_RUNTIME_DEFAULT_LOW_FEE_LANE.to_string(),
            fee_asset_id: PRIVATE_L2_CONFIDENTIAL_TOKEN_BASKET_INDEX_VAULT_RUNTIME_DEFAULT_FEE_ASSET_ID.to_string(),
            share_asset_id: PRIVATE_L2_CONFIDENTIAL_TOKEN_BASKET_INDEX_VAULT_RUNTIME_DEFAULT_SHARE_ASSET_ID.to_string(),
            min_privacy_set_size: PRIVATE_L2_CONFIDENTIAL_TOKEN_BASKET_INDEX_VAULT_RUNTIME_DEFAULT_MIN_PRIVACY_SET_SIZE,
            batch_privacy_set_size: PRIVATE_L2_CONFIDENTIAL_TOKEN_BASKET_INDEX_VAULT_RUNTIME_DEFAULT_BATCH_PRIVACY_SET_SIZE,
            max_user_fee_bps: PRIVATE_L2_CONFIDENTIAL_TOKEN_BASKET_INDEX_VAULT_RUNTIME_DEFAULT_MAX_USER_FEE_BPS,
            target_user_fee_bps: PRIVATE_L2_CONFIDENTIAL_TOKEN_BASKET_INDEX_VAULT_RUNTIME_DEFAULT_TARGET_USER_FEE_BPS,
            sponsor_rebate_bps: PRIVATE_L2_CONFIDENTIAL_TOKEN_BASKET_INDEX_VAULT_RUNTIME_DEFAULT_SPONSOR_REBATE_BPS,
            manager_fee_bps: PRIVATE_L2_CONFIDENTIAL_TOKEN_BASKET_INDEX_VAULT_RUNTIME_DEFAULT_MANAGER_FEE_BPS,
            max_tracking_error_bps: PRIVATE_L2_CONFIDENTIAL_TOKEN_BASKET_INDEX_VAULT_RUNTIME_DEFAULT_MAX_TRACKING_ERROR_BPS,
            max_components: PRIVATE_L2_CONFIDENTIAL_TOKEN_BASKET_INDEX_VAULT_RUNTIME_DEFAULT_MAX_COMPONENTS,
            max_baskets: PRIVATE_L2_CONFIDENTIAL_TOKEN_BASKET_INDEX_VAULT_RUNTIME_DEFAULT_MAX_BASKETS,
            max_notes: PRIVATE_L2_CONFIDENTIAL_TOKEN_BASKET_INDEX_VAULT_RUNTIME_DEFAULT_MAX_NOTES,
            max_rebalance_batches: PRIVATE_L2_CONFIDENTIAL_TOKEN_BASKET_INDEX_VAULT_RUNTIME_DEFAULT_MAX_REBALANCE_BATCHES,
            max_nav_attestations: PRIVATE_L2_CONFIDENTIAL_TOKEN_BASKET_INDEX_VAULT_RUNTIME_DEFAULT_MAX_NAV_ATTESTATIONS,
            max_sponsor_rebates: PRIVATE_L2_CONFIDENTIAL_TOKEN_BASKET_INDEX_VAULT_RUNTIME_DEFAULT_MAX_SPONSOR_REBATES,
            max_settlements: PRIVATE_L2_CONFIDENTIAL_TOKEN_BASKET_INDEX_VAULT_RUNTIME_DEFAULT_MAX_SETTLEMENTS,
            max_privacy_fences: PRIVATE_L2_CONFIDENTIAL_TOKEN_BASKET_INDEX_VAULT_RUNTIME_DEFAULT_MAX_PRIVACY_FENCES,
            note_ttl_blocks: PRIVATE_L2_CONFIDENTIAL_TOKEN_BASKET_INDEX_VAULT_RUNTIME_DEFAULT_NOTE_TTL_BLOCKS,
            rebalance_ttl_blocks: PRIVATE_L2_CONFIDENTIAL_TOKEN_BASKET_INDEX_VAULT_RUNTIME_DEFAULT_REBALANCE_TTL_BLOCKS,
            attestation_ttl_blocks: PRIVATE_L2_CONFIDENTIAL_TOKEN_BASKET_INDEX_VAULT_RUNTIME_DEFAULT_ATTESTATION_TTL_BLOCKS,
            settlement_ttl_blocks: PRIVATE_L2_CONFIDENTIAL_TOKEN_BASKET_INDEX_VAULT_RUNTIME_DEFAULT_SETTLEMENT_TTL_BLOCKS,
            min_pq_security_bits: PRIVATE_L2_CONFIDENTIAL_TOKEN_BASKET_INDEX_VAULT_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS,
            require_private_nav_attestations: true,
            require_privacy_fences: true,
            require_low_fee_settlement: true,
        }
    }

    pub fn validate(&self) -> Result<()> {
        ensure_nonempty("protocol_version", &self.protocol_version)?;
        ensure_nonempty("chain_id", &self.chain_id)?;
        ensure_nonempty("low_fee_lane", &self.low_fee_lane)?;
        ensure_bps("max_user_fee_bps", self.max_user_fee_bps)?;
        ensure_bps("target_user_fee_bps", self.target_user_fee_bps)?;
        ensure_bps("sponsor_rebate_bps", self.sponsor_rebate_bps)?;
        ensure_bps("manager_fee_bps", self.manager_fee_bps)?;
        ensure_bps("max_tracking_error_bps", self.max_tracking_error_bps)?;
        if self.target_user_fee_bps > self.max_user_fee_bps {
            return Err("target_user_fee_bps exceeds max_user_fee_bps".to_string());
        }
        if self.max_components == 0 || self.max_baskets == 0 || self.max_notes == 0 {
            return Err("runtime limits must be non-zero".to_string());
        }
        if self.min_privacy_set_size == 0 || self.batch_privacy_set_size < self.min_privacy_set_size
        {
            return Err("privacy set sizes are inconsistent".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealBasketRequest {
    pub kind: BasketKind,
    pub manager_commitment: String,
    pub share_asset_id: String,
    pub sealed_terms_ciphertext: String,
    pub components: Vec<BasketComponent>,
    pub fee_bps: u64,
    pub tracking_error_limit_bps: u64,
    pub activation_height: u64,
    pub expiry_height: u64,
    pub privacy_domain: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubmitNoteRequest {
    pub basket_id: String,
    pub kind: NoteKind,
    pub owner_view_key_commitment: String,
    pub encrypted_payload: String,
    pub amount_commitment: String,
    pub share_commitment: String,
    pub nav_quote_id: String,
    pub nullifier: String,
    pub fence_id: String,
    pub sponsor_id: String,
    pub fee_bps: u64,
    pub metadata: Value,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NavAttestationRequest {
    pub basket_id: String,
    pub verdict: NavVerdict,
    pub oracle_committee_root: String,
    pub price_vector_root: String,
    pub nav_commitment: String,
    pub confidence_bps: u64,
    pub tracking_error_bps: u64,
    pub signature_root: String,
    pub disclosure_policy_root: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RebalanceBatchRequest {
    pub basket_id: String,
    pub intent: RebalanceIntent,
    pub input_note_root: String,
    pub output_note_root: String,
    pub target_components: Vec<BasketComponent>,
    pub nav_attestation_id: String,
    pub sponsor_rebate_id: String,
    pub privacy_fence_root: String,
    pub solver_commitment: String,
    pub estimated_fee_bps: u64,
    pub tracking_error_after_bps: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SponsorRebateRequest {
    pub sponsor_id: String,
    pub basket_id: String,
    pub batch_id: String,
    pub note_root: String,
    pub rebate_commitment: String,
    pub budget_commitment: String,
    pub fee_discount_bps: u64,
    pub claim_nullifier: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivacyFenceRequest {
    pub basket_id: String,
    pub nullifiers: Vec<String>,
    pub membership_root: String,
    pub min_privacy_set_size: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeSettlementRequest {
    pub batch_id: String,
    pub basket_id: String,
    pub lane: String,
    pub public_delta_root: String,
    pub fee_commitment: String,
    pub rebate_root: String,
    pub aggregator_commitment: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub height: u64,
    pub baskets: BTreeMap<String, SealedBasketDefinition>,
    pub deposit_notes: BTreeMap<String, EncryptedVaultNote>,
    pub redeem_notes: BTreeMap<String, EncryptedVaultNote>,
    pub rebalances: BTreeMap<String, RebalanceBatch>,
    pub nav_attestations: BTreeMap<String, NavOracleAttestation>,
    pub sponsor_rebates: BTreeMap<String, SponsorRebate>,
    pub settlements: BTreeMap<String, LowFeeSettlement>,
    pub privacy_fences: BTreeMap<String, PrivacyFence>,
    pub events: BTreeMap<String, VaultEvent>,
    pub spent_nullifiers: BTreeSet<String>,
}

impl Default for State {
    fn default() -> Self {
        Self::devnet()
    }
}
pub fn devnet() -> State {
    State::devnet()
}

impl State {
    pub fn new(config: Config, height: u64) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            config,
            height,
            baskets: BTreeMap::new(),
            deposit_notes: BTreeMap::new(),
            redeem_notes: BTreeMap::new(),
            rebalances: BTreeMap::new(),
            nav_attestations: BTreeMap::new(),
            sponsor_rebates: BTreeMap::new(),
            settlements: BTreeMap::new(),
            privacy_fences: BTreeMap::new(),
            events: BTreeMap::new(),
            spent_nullifiers: BTreeSet::new(),
        })
    }
    pub fn devnet() -> Self {
        Self::new(
            Config::devnet(),
            PRIVATE_L2_CONFIDENTIAL_TOKEN_BASKET_INDEX_VAULT_RUNTIME_DEVNET_HEIGHT,
        )
        .expect("devnet config")
    }
    pub fn advance_to(&mut self, height: u64) -> Result<()> {
        if height < self.height {
            return Err("height cannot move backwards".to_string());
        }
        self.height = height;
        Ok(())
    }
    pub fn seal_basket(&mut self, request: SealBasketRequest) -> Result<SealedBasketDefinition> {
        self.ensure_capacity("baskets", self.baskets.len(), self.config.max_baskets)?;
        self.validate_components(&request.components)?;
        ensure_nonempty("manager_commitment", &request.manager_commitment)?;
        ensure_nonempty("sealed_terms_ciphertext", &request.sealed_terms_ciphertext)?;
        ensure_bps("fee_bps", request.fee_bps)?;
        ensure_bps("tracking_error_limit_bps", request.tracking_error_limit_bps)?;
        if request.tracking_error_limit_bps > self.config.max_tracking_error_bps {
            return Err("tracking error limit exceeds config".to_string());
        }
        if request.activation_height < self.height {
            return Err("activation height is in the past".to_string());
        }
        if request.expiry_height <= request.activation_height {
            return Err("expiry height must follow activation".to_string());
        }
        let component_root = component_root(&request.components);
        let basket_id = basket_id(
            &request.manager_commitment,
            &component_root,
            self.height,
            self.baskets.len() as u64,
        );
        if self.baskets.contains_key(&basket_id) {
            return Err("basket id already exists".to_string());
        }
        let definition_commitment = deterministic_root(
            "basket_definition",
            &[
                HashPart::Str(&basket_id),
                HashPart::Str(&component_root),
                HashPart::Str(&request.sealed_terms_ciphertext),
                HashPart::U64(request.fee_bps),
            ],
        );
        let basket = SealedBasketDefinition {
            basket_id: basket_id.clone(),
            kind: request.kind,
            status: BasketStatus::Sealed,
            manager_commitment: request.manager_commitment,
            share_asset_id: if request.share_asset_id.is_empty() {
                self.config.share_asset_id.clone()
            } else {
                request.share_asset_id
            },
            sealed_terms_ciphertext: request.sealed_terms_ciphertext,
            component_root,
            components: request.components,
            fee_bps: request.fee_bps,
            tracking_error_limit_bps: request.tracking_error_limit_bps,
            created_height: self.height,
            activation_height: request.activation_height,
            expiry_height: request.expiry_height,
            definition_commitment,
            privacy_domain: request.privacy_domain,
        };
        self.baskets.insert(basket_id.clone(), basket.clone());
        self.record_event(
            VaultEventKind::BasketSealed,
            &basket_id,
            &basket_id,
            &record_root(&basket),
        );
        Ok(basket)
    }
    pub fn activate_basket(&mut self, basket_id: &str) -> Result<()> {
        let record_root = {
            let basket = self
                .baskets
                .get_mut(basket_id)
                .ok_or_else(|| "unknown basket".to_string())?;
            if self.height < basket.activation_height {
                return Err("basket activation height not reached".to_string());
            }
            if self.height >= basket.expiry_height {
                return Err("basket expired".to_string());
            }
            basket.status = BasketStatus::Active;
            record_root(basket)
        };
        self.record_event(
            VaultEventKind::BasketSealed,
            basket_id,
            basket_id,
            &record_root,
        );
        Ok(())
    }
    pub fn submit_note(&mut self, request: SubmitNoteRequest) -> Result<EncryptedVaultNote> {
        self.ensure_capacity(
            "notes",
            self.deposit_notes.len() + self.redeem_notes.len(),
            self.config.max_notes,
        )?;
        let basket = self
            .baskets
            .get(&request.basket_id)
            .ok_or_else(|| "unknown basket".to_string())?;
        match request.kind {
            NoteKind::Deposit
            | NoteKind::MigrationIn
            | NoteKind::FeeSweep
            | NoteKind::RebateClaim
                if !basket.status.accepts_deposits() =>
            {
                return Err("basket does not accept deposits".to_string())
            }
            NoteKind::Redeem | NoteKind::MigrationOut if !basket.status.accepts_redeems() => {
                return Err("basket does not accept redemptions".to_string())
            }
            _ => {}
        }
        ensure_nonempty(
            "owner_view_key_commitment",
            &request.owner_view_key_commitment,
        )?;
        ensure_nonempty("encrypted_payload", &request.encrypted_payload)?;
        ensure_nonempty("amount_commitment", &request.amount_commitment)?;
        ensure_nonempty("nullifier", &request.nullifier)?;
        ensure_bps("fee_bps", request.fee_bps)?;
        if request.fee_bps > self.config.max_user_fee_bps {
            return Err("note fee exceeds configured maximum".to_string());
        }
        if self.spent_nullifiers.contains(&request.nullifier) {
            return Err("nullifier already consumed".to_string());
        }
        let metadata_root = value_root("note_metadata", &request.metadata);
        let note_id = note_id(
            &request.basket_id,
            request.kind,
            &request.nullifier,
            self.height,
            self.deposit_notes.len() as u64 + self.redeem_notes.len() as u64,
        );
        let note = EncryptedVaultNote {
            note_id: note_id.clone(),
            basket_id: request.basket_id.clone(),
            kind: request.kind,
            status: NoteStatus::Submitted,
            owner_view_key_commitment: request.owner_view_key_commitment,
            encrypted_payload: request.encrypted_payload,
            amount_commitment: request.amount_commitment,
            share_commitment: request.share_commitment,
            nav_quote_id: request.nav_quote_id,
            nullifier: request.nullifier,
            fence_id: request.fence_id,
            sponsor_id: request.sponsor_id,
            submitted_height: self.height,
            expires_height: self.height.saturating_add(self.config.note_ttl_blocks),
            fee_bps: request.fee_bps,
            metadata_root,
        };
        if matches!(note.kind, NoteKind::Redeem | NoteKind::MigrationOut) {
            self.redeem_notes.insert(note_id.clone(), note.clone());
            self.record_event(
                VaultEventKind::RedeemQueued,
                &request.basket_id,
                &note_id,
                &record_root(&note),
            );
        } else {
            self.deposit_notes.insert(note_id.clone(), note.clone());
            self.record_event(
                VaultEventKind::DepositQueued,
                &request.basket_id,
                &note_id,
                &record_root(&note),
            );
        }
        Ok(note)
    }
    pub fn open_privacy_fence(&mut self, request: PrivacyFenceRequest) -> Result<PrivacyFence> {
        self.ensure_capacity(
            "privacy_fences",
            self.privacy_fences.len(),
            self.config.max_privacy_fences,
        )?;
        self.require_basket(&request.basket_id)?;
        if request.min_privacy_set_size < self.config.min_privacy_set_size {
            return Err("privacy fence below configured minimum".to_string());
        }
        if request.nullifiers.len() as u64 > request.min_privacy_set_size {
            return Err("fence reveals too many nullifiers for requested privacy set".to_string());
        }
        let mut seen = BTreeSet::new();
        for n in &request.nullifiers {
            ensure_nonempty("nullifier", n)?;
            if !seen.insert(n.clone()) {
                return Err("duplicate nullifier in fence".to_string());
            }
            if self.spent_nullifiers.contains(n) {
                return Err("nullifier already spent".to_string());
            }
        }
        let nullifier_values = request
            .nullifiers
            .iter()
            .map(|n| json!(n))
            .collect::<Vec<_>>();
        let nullifier_root = merkle_root(
            "token_basket_index_vault_privacy_fence_nullifiers",
            &nullifier_values,
        );
        let fence_id = privacy_fence_id(
            &request.basket_id,
            &nullifier_root,
            self.height,
            self.privacy_fences.len() as u64,
        );
        let fence = PrivacyFence {
            fence_id: fence_id.clone(),
            basket_id: request.basket_id.clone(),
            status: PrivacyFenceStatus::Open,
            nullifier_root,
            membership_root: request.membership_root,
            min_privacy_set_size: request.min_privacy_set_size,
            opened_height: self.height,
            expires_height: self.height.saturating_add(self.config.note_ttl_blocks),
            consumed_by: String::new(),
        };
        self.privacy_fences.insert(fence_id.clone(), fence.clone());
        Ok(fence)
    }
    pub fn attach_note_fence(&mut self, note_id: &str, fence_id: &str) -> Result<()> {
        let fence = self
            .privacy_fences
            .get(fence_id)
            .ok_or_else(|| "unknown privacy fence".to_string())?;
        if !matches!(
            fence.status,
            PrivacyFenceStatus::Open | PrivacyFenceStatus::Locked
        ) {
            return Err("privacy fence is not usable".to_string());
        }
        if self.height > fence.expires_height {
            return Err("privacy fence expired".to_string());
        }
        if let Some(note) = self.deposit_notes.get_mut(note_id) {
            note.fence_id = fence_id.to_string();
            note.status = NoteStatus::PrivacyFenced;
            return Ok(());
        }
        if let Some(note) = self.redeem_notes.get_mut(note_id) {
            note.fence_id = fence_id.to_string();
            note.status = NoteStatus::PrivacyFenced;
            return Ok(());
        }
        Err("unknown note".to_string())
    }
    pub fn attest_nav(&mut self, request: NavAttestationRequest) -> Result<NavOracleAttestation> {
        self.ensure_capacity(
            "nav_attestations",
            self.nav_attestations.len(),
            self.config.max_nav_attestations,
        )?;
        self.require_basket(&request.basket_id)?;
        ensure_nonempty("oracle_committee_root", &request.oracle_committee_root)?;
        ensure_nonempty("price_vector_root", &request.price_vector_root)?;
        ensure_nonempty("nav_commitment", &request.nav_commitment)?;
        ensure_nonempty("signature_root", &request.signature_root)?;
        ensure_bps("confidence_bps", request.confidence_bps)?;
        ensure_bps("tracking_error_bps", request.tracking_error_bps)?;
        if request.tracking_error_bps > self.config.max_tracking_error_bps
            && matches!(request.verdict, NavVerdict::Fresh)
        {
            return Err("fresh NAV attestation exceeds tracking error limit".to_string());
        }
        let attestation_id = nav_attestation_id(
            &request.basket_id,
            &request.price_vector_root,
            &request.nav_commitment,
            self.height,
            self.nav_attestations.len() as u64,
        );
        let attestation = NavOracleAttestation {
            attestation_id: attestation_id.clone(),
            basket_id: request.basket_id.clone(),
            verdict: request.verdict,
            oracle_committee_root: request.oracle_committee_root,
            price_vector_root: request.price_vector_root,
            nav_commitment: request.nav_commitment,
            confidence_bps: request.confidence_bps,
            tracking_error_bps: request.tracking_error_bps,
            valid_from_height: self.height,
            valid_until_height: self
                .height
                .saturating_add(self.config.attestation_ttl_blocks),
            signature_root: request.signature_root,
            disclosure_policy_root: request.disclosure_policy_root,
        };
        self.nav_attestations
            .insert(attestation_id.clone(), attestation.clone());
        self.record_event(
            VaultEventKind::NavAttested,
            &request.basket_id,
            &attestation_id,
            &record_root(&attestation),
        );
        Ok(attestation)
    }
    pub fn reserve_sponsor_rebate(
        &mut self,
        request: SponsorRebateRequest,
    ) -> Result<SponsorRebate> {
        self.ensure_capacity(
            "sponsor_rebates",
            self.sponsor_rebates.len(),
            self.config.max_sponsor_rebates,
        )?;
        self.require_basket(&request.basket_id)?;
        ensure_nonempty("sponsor_id", &request.sponsor_id)?;
        ensure_nonempty("rebate_commitment", &request.rebate_commitment)?;
        ensure_nonempty("budget_commitment", &request.budget_commitment)?;
        ensure_nonempty("claim_nullifier", &request.claim_nullifier)?;
        ensure_bps("fee_discount_bps", request.fee_discount_bps)?;
        if request.fee_discount_bps > self.config.max_user_fee_bps {
            return Err("rebate discount exceeds maximum user fee".to_string());
        }
        if self.spent_nullifiers.contains(&request.claim_nullifier) {
            return Err("rebate claim nullifier already spent".to_string());
        }
        let rebate_id = sponsor_rebate_id(
            &request.sponsor_id,
            &request.basket_id,
            &request.rebate_commitment,
            self.height,
            self.sponsor_rebates.len() as u64,
        );
        let rebate = SponsorRebate {
            rebate_id: rebate_id.clone(),
            sponsor_id: request.sponsor_id,
            basket_id: request.basket_id.clone(),
            status: SponsorRebateStatus::Reserved,
            batch_id: request.batch_id,
            note_root: request.note_root,
            rebate_commitment: request.rebate_commitment,
            budget_commitment: request.budget_commitment,
            fee_discount_bps: request.fee_discount_bps,
            reserved_height: self.height,
            expires_height: self
                .height
                .saturating_add(self.config.settlement_ttl_blocks),
            claim_nullifier: request.claim_nullifier,
        };
        self.sponsor_rebates
            .insert(rebate_id.clone(), rebate.clone());
        Ok(rebate)
    }
    pub fn propose_rebalance(&mut self, request: RebalanceBatchRequest) -> Result<RebalanceBatch> {
        self.ensure_capacity(
            "rebalances",
            self.rebalances.len(),
            self.config.max_rebalance_batches,
        )?;
        let basket = self
            .baskets
            .get(&request.basket_id)
            .ok_or_else(|| "unknown basket".to_string())?;
        if !basket.status.accepts_rebalances() {
            return Err("basket does not accept rebalances".to_string());
        }
        self.validate_components(&request.target_components)?;
        ensure_nonempty("input_note_root", &request.input_note_root)?;
        ensure_nonempty("output_note_root", &request.output_note_root)?;
        ensure_nonempty("solver_commitment", &request.solver_commitment)?;
        ensure_bps("estimated_fee_bps", request.estimated_fee_bps)?;
        ensure_bps("tracking_error_after_bps", request.tracking_error_after_bps)?;
        if request.estimated_fee_bps > self.config.max_user_fee_bps {
            return Err("rebalance fee exceeds configured maximum".to_string());
        }
        if request.tracking_error_after_bps > basket.tracking_error_limit_bps {
            return Err("rebalance tracking error exceeds basket limit".to_string());
        }
        if self.config.require_private_nav_attestations {
            self.require_fresh_nav(&request.nav_attestation_id, &request.basket_id)?;
        }
        let target_component_root = component_root(&request.target_components);
        let batch_id = rebalance_batch_id(
            &request.basket_id,
            &request.input_note_root,
            &request.output_note_root,
            &target_component_root,
            self.height,
            self.rebalances.len() as u64,
        );
        let batch = RebalanceBatch {
            batch_id: batch_id.clone(),
            basket_id: request.basket_id.clone(),
            intent: request.intent,
            status: RebalanceStatus::Proposed,
            input_note_root: request.input_note_root,
            output_note_root: request.output_note_root,
            target_component_root,
            nav_attestation_id: request.nav_attestation_id,
            sponsor_rebate_id: request.sponsor_rebate_id,
            privacy_fence_root: request.privacy_fence_root,
            solver_commitment: request.solver_commitment,
            created_height: self.height,
            expires_height: self.height.saturating_add(self.config.rebalance_ttl_blocks),
            estimated_fee_bps: request.estimated_fee_bps,
            tracking_error_after_bps: request.tracking_error_after_bps,
        };
        self.rebalances.insert(batch_id.clone(), batch.clone());
        self.record_event(
            VaultEventKind::RebalanceQueued,
            &request.basket_id,
            &batch_id,
            &record_root(&batch),
        );
        Ok(batch)
    }
    pub fn mark_rebalance_stage(&mut self, batch_id: &str, status: RebalanceStatus) -> Result<()> {
        let (basket_id, root) = {
            let batch = self
                .rebalances
                .get_mut(batch_id)
                .ok_or_else(|| "unknown rebalance batch".to_string())?;
            if self.height > batch.expires_height && status.live() {
                return Err("rebalance batch expired".to_string());
            }
            batch.status = status;
            (batch.basket_id.clone(), record_root(batch))
        };
        if matches!(status, RebalanceStatus::Settled) {
            self.record_event(
                VaultEventKind::RebalanceSettled,
                &basket_id,
                batch_id,
                &root,
            );
        }
        Ok(())
    }
    pub fn publish_low_fee_settlement(
        &mut self,
        request: LowFeeSettlementRequest,
    ) -> Result<LowFeeSettlement> {
        self.ensure_capacity(
            "settlements",
            self.settlements.len(),
            self.config.max_settlements,
        )?;
        self.require_basket(&request.basket_id)?;
        let batch = self
            .rebalances
            .get(&request.batch_id)
            .ok_or_else(|| "unknown rebalance batch".to_string())?;
        if batch.basket_id != request.basket_id {
            return Err("settlement basket mismatch".to_string());
        }
        ensure_nonempty("lane", &request.lane)?;
        ensure_nonempty("public_delta_root", &request.public_delta_root)?;
        ensure_nonempty("fee_commitment", &request.fee_commitment)?;
        ensure_nonempty("aggregator_commitment", &request.aggregator_commitment)?;
        if self.config.require_low_fee_settlement && request.lane != self.config.low_fee_lane {
            return Err("settlement must use configured low-fee lane".to_string());
        }
        let settlement_root = deterministic_root(
            "low_fee_settlement",
            &[
                HashPart::Str(&request.batch_id),
                HashPart::Str(&request.public_delta_root),
                HashPart::Str(&request.fee_commitment),
                HashPart::Str(&request.rebate_root),
            ],
        );
        let settlement_id = settlement_id(
            &request.batch_id,
            &settlement_root,
            self.height,
            self.settlements.len() as u64,
        );
        let settlement = LowFeeSettlement {
            settlement_id: settlement_id.clone(),
            batch_id: request.batch_id.clone(),
            basket_id: request.basket_id.clone(),
            status: SettlementStatus::Published,
            lane: request.lane,
            settlement_root,
            public_delta_root: request.public_delta_root,
            fee_commitment: request.fee_commitment,
            rebate_root: request.rebate_root,
            posted_height: self.height,
            finalized_height: 0,
            aggregator_commitment: request.aggregator_commitment,
        };
        self.settlements
            .insert(settlement_id.clone(), settlement.clone());
        self.record_event(
            VaultEventKind::SettlementFinalized,
            &request.basket_id,
            &settlement_id,
            &record_root(&settlement),
        );
        Ok(settlement)
    }
    pub fn finalize_settlement(&mut self, settlement_id: &str) -> Result<()> {
        let (basket_id, batch_id, root) = {
            let settlement = self
                .settlements
                .get_mut(settlement_id)
                .ok_or_else(|| "unknown settlement".to_string())?;
            if matches!(
                settlement.status,
                SettlementStatus::Disputed | SettlementStatus::Expired
            ) {
                return Err("settlement cannot be finalized".to_string());
            }
            settlement.status = SettlementStatus::Finalized;
            settlement.finalized_height = self.height;
            (
                settlement.basket_id.clone(),
                settlement.batch_id.clone(),
                record_root(settlement),
            )
        };
        if let Some(batch) = self.rebalances.get_mut(&batch_id) {
            batch.status = RebalanceStatus::Settled;
        }
        self.record_event(
            VaultEventKind::SettlementFinalized,
            &basket_id,
            settlement_id,
            &root,
        );
        Ok(())
    }
    pub fn consume_note_nullifier(&mut self, note_id: &str) -> Result<()> {
        let note = if let Some(note) = self.deposit_notes.get_mut(note_id) {
            note
        } else if let Some(note) = self.redeem_notes.get_mut(note_id) {
            note
        } else {
            return Err("unknown note".to_string());
        };
        if self.spent_nullifiers.contains(&note.nullifier) {
            return Err("nullifier already consumed".to_string());
        }
        note.status = NoteStatus::Settled;
        self.spent_nullifiers.insert(note.nullifier.clone());
        Ok(())
    }
    pub fn expire_height_sensitive_records(&mut self) {
        for note in self
            .deposit_notes
            .values_mut()
            .chain(self.redeem_notes.values_mut())
        {
            if note.status.live() && self.height > note.expires_height {
                note.status = NoteStatus::Expired;
            }
        }
        for batch in self.rebalances.values_mut() {
            if batch.status.live() && self.height > batch.expires_height {
                batch.status = RebalanceStatus::Expired;
            }
        }
        for rebate in self.sponsor_rebates.values_mut() {
            if matches!(
                rebate.status,
                SponsorRebateStatus::Reserved | SponsorRebateStatus::Earned
            ) && self.height > rebate.expires_height
            {
                rebate.status = SponsorRebateStatus::Expired;
            }
        }
        for fence in self.privacy_fences.values_mut() {
            if matches!(
                fence.status,
                PrivacyFenceStatus::Open | PrivacyFenceStatus::Locked
            ) && self.height > fence.expires_height
            {
                fence.status = PrivacyFenceStatus::Expired;
            }
        }
    }
    pub fn public_record(&self) -> PublicRecord {
        let basket_root = map_root("token_basket_index_vault_baskets", &self.baskets);
        let deposit_note_root = map_root(
            "token_basket_index_vault_deposit_notes",
            &self.deposit_notes,
        );
        let redeem_note_root =
            map_root("token_basket_index_vault_redeem_notes", &self.redeem_notes);
        let rebalance_batch_root =
            map_root("token_basket_index_vault_rebalances", &self.rebalances);
        let nav_attestation_root = map_root(
            "token_basket_index_vault_nav_attestations",
            &self.nav_attestations,
        );
        let sponsor_rebate_root = map_root(
            "token_basket_index_vault_sponsor_rebates",
            &self.sponsor_rebates,
        );
        let settlement_root = map_root("token_basket_index_vault_settlements", &self.settlements);
        let privacy_fence_root = map_root(
            "token_basket_index_vault_privacy_fences",
            &self.privacy_fences,
        );
        let event_root = map_root("token_basket_index_vault_events", &self.events);
        let state_root = deterministic_root(
            "state",
            &[
                HashPart::Str(&basket_root),
                HashPart::Str(&deposit_note_root),
                HashPart::Str(&redeem_note_root),
                HashPart::Str(&rebalance_batch_root),
                HashPart::Str(&nav_attestation_root),
                HashPart::Str(&sponsor_rebate_root),
                HashPart::Str(&settlement_root),
                HashPart::Str(&privacy_fence_root),
                HashPart::Str(&event_root),
                HashPart::U64(self.height),
            ],
        );
        PublicRecord {
            protocol_version: self.config.protocol_version.clone(),
            schema_version: self.config.schema_version,
            chain_id: self.config.chain_id.clone(),
            height: self.height,
            basket_root,
            deposit_note_root,
            redeem_note_root,
            rebalance_batch_root,
            nav_attestation_root,
            sponsor_rebate_root,
            settlement_root,
            privacy_fence_root,
            event_root,
            state_root,
        }
    }
    pub fn state_root(&self) -> String {
        self.public_record().state_root
    }
    fn require_basket(&self, basket_id: &str) -> Result<&SealedBasketDefinition> {
        self.baskets
            .get(basket_id)
            .ok_or_else(|| "unknown basket".to_string())
    }
    fn require_fresh_nav(
        &self,
        attestation_id: &str,
        basket_id: &str,
    ) -> Result<&NavOracleAttestation> {
        let attestation = self
            .nav_attestations
            .get(attestation_id)
            .ok_or_else(|| "unknown NAV attestation".to_string())?;
        if attestation.basket_id != basket_id {
            return Err("NAV attestation basket mismatch".to_string());
        }
        if !matches!(attestation.verdict, NavVerdict::Fresh) {
            return Err("NAV attestation is not fresh".to_string());
        }
        if self.height > attestation.valid_until_height {
            return Err("NAV attestation expired".to_string());
        }
        Ok(attestation)
    }
    fn ensure_capacity(&self, label: &str, len: usize, max: usize) -> Result<()> {
        if len >= max {
            Err(format!("{label} capacity exceeded"))
        } else {
            Ok(())
        }
    }
    fn validate_components(&self, components: &[BasketComponent]) -> Result<()> {
        validate_components(components, self.config.max_components)
    }
    fn record_event(
        &mut self,
        kind: VaultEventKind,
        basket_id: &str,
        subject_id: &str,
        root: &str,
    ) {
        let event_id = event_id(
            kind,
            basket_id,
            subject_id,
            self.height,
            self.events.len() as u64,
        );
        let event = VaultEvent {
            event_id: event_id.clone(),
            kind,
            basket_id: basket_id.to_string(),
            subject_id: subject_id.to_string(),
            height: self.height,
            record_root: root.to_string(),
        };
        self.events.insert(event_id, event);
    }
}

pub fn public_record(state: &State) -> PublicRecord {
    state.public_record()
}
pub fn state_root(state: &State) -> String {
    state.state_root()
}
pub fn deterministic_root(domain: &str, parts: &[HashPart<'_>]) -> String {
    domain_hash(&format!("token_basket_index_vault:{domain}"), parts, 32)
}
pub fn value_root(domain: &str, value: &Value) -> String {
    deterministic_root(domain, &[HashPart::Json(value)])
}
pub fn record_root<T: Serialize>(value: &T) -> String {
    let value = serde_json::to_value(value).expect("record serialization");
    value_root("record", &value)
}
pub fn map_root<T: Serialize>(domain: &str, values: &BTreeMap<String, T>) -> String {
    let leaves = values
        .iter()
        .map(|(key, value)| json!({ "key": key, "value_root": record_root(value) }))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}
pub fn component_root(components: &[BasketComponent]) -> String {
    let leaves = components.iter().map(|component| json!({ "component_id": component.component_id, "asset_id": component.asset_id, "target_weight_bps": component.target_weight_bps, "min_weight_bps": component.min_weight_bps, "max_weight_bps": component.max_weight_bps, "oracle_feed_commitment": component.oracle_feed_commitment, "risk_bucket": component.risk_bucket, "rebalance_enabled": component.rebalance_enabled })).collect::<Vec<_>>();
    merkle_root("token_basket_index_vault_components", &leaves)
}
pub fn basket_id(
    manager_commitment: &str,
    component_root: &str,
    height: u64,
    nonce: u64,
) -> String {
    deterministic_root(
        "basket_id",
        &[
            HashPart::Str(manager_commitment),
            HashPart::Str(component_root),
            HashPart::U64(height),
            HashPart::U64(nonce),
        ],
    )
}
pub fn note_id(
    basket_id: &str,
    kind: NoteKind,
    nullifier: &str,
    height: u64,
    nonce: u64,
) -> String {
    deterministic_root(
        "note_id",
        &[
            HashPart::Str(basket_id),
            HashPart::Str(kind.as_str()),
            HashPart::Str(nullifier),
            HashPart::U64(height),
            HashPart::U64(nonce),
        ],
    )
}
pub fn nav_attestation_id(
    basket_id: &str,
    price_vector_root: &str,
    nav_commitment: &str,
    height: u64,
    nonce: u64,
) -> String {
    deterministic_root(
        "nav_attestation_id",
        &[
            HashPart::Str(basket_id),
            HashPart::Str(price_vector_root),
            HashPart::Str(nav_commitment),
            HashPart::U64(height),
            HashPart::U64(nonce),
        ],
    )
}
pub fn rebalance_batch_id(
    basket_id: &str,
    input_note_root: &str,
    output_note_root: &str,
    target_component_root: &str,
    height: u64,
    nonce: u64,
) -> String {
    deterministic_root(
        "rebalance_batch_id",
        &[
            HashPart::Str(basket_id),
            HashPart::Str(input_note_root),
            HashPart::Str(output_note_root),
            HashPart::Str(target_component_root),
            HashPart::U64(height),
            HashPart::U64(nonce),
        ],
    )
}
pub fn sponsor_rebate_id(
    sponsor_id: &str,
    basket_id: &str,
    rebate_commitment: &str,
    height: u64,
    nonce: u64,
) -> String {
    deterministic_root(
        "sponsor_rebate_id",
        &[
            HashPart::Str(sponsor_id),
            HashPart::Str(basket_id),
            HashPart::Str(rebate_commitment),
            HashPart::U64(height),
            HashPart::U64(nonce),
        ],
    )
}
pub fn privacy_fence_id(basket_id: &str, nullifier_root: &str, height: u64, nonce: u64) -> String {
    deterministic_root(
        "privacy_fence_id",
        &[
            HashPart::Str(basket_id),
            HashPart::Str(nullifier_root),
            HashPart::U64(height),
            HashPart::U64(nonce),
        ],
    )
}
pub fn settlement_id(batch_id: &str, settlement_root: &str, height: u64, nonce: u64) -> String {
    deterministic_root(
        "settlement_id",
        &[
            HashPart::Str(batch_id),
            HashPart::Str(settlement_root),
            HashPart::U64(height),
            HashPart::U64(nonce),
        ],
    )
}
pub fn event_id(
    kind: VaultEventKind,
    basket_id: &str,
    subject_id: &str,
    height: u64,
    nonce: u64,
) -> String {
    deterministic_root(
        "event_id",
        &[
            HashPart::Str(kind.as_str()),
            HashPart::Str(basket_id),
            HashPart::Str(subject_id),
            HashPart::U64(height),
            HashPart::U64(nonce),
        ],
    )
}
pub fn ensure_nonempty(label: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        Err(format!("{label} must not be empty"))
    } else {
        Ok(())
    }
}
pub fn ensure_bps(label: &str, value: u64) -> Result<()> {
    if value > PRIVATE_L2_CONFIDENTIAL_TOKEN_BASKET_INDEX_VAULT_RUNTIME_MAX_BPS {
        Err(format!("{label} exceeds bps maximum"))
    } else {
        Ok(())
    }
}
pub fn validate_components(components: &[BasketComponent], max_components: usize) -> Result<()> {
    if components.is_empty() {
        return Err("basket must contain at least one component".to_string());
    }
    if components.len() > max_components {
        return Err("basket has too many components".to_string());
    }
    let mut ids = BTreeSet::new();
    let mut assets = BTreeSet::new();
    let mut total = 0_u64;
    for component in components {
        ensure_nonempty("component_id", &component.component_id)?;
        ensure_nonempty("asset_id", &component.asset_id)?;
        ensure_nonempty(
            "sealed_symbol_commitment",
            &component.sealed_symbol_commitment,
        )?;
        ensure_nonempty("oracle_feed_commitment", &component.oracle_feed_commitment)?;
        ensure_bps("target_weight_bps", component.target_weight_bps)?;
        ensure_bps("min_weight_bps", component.min_weight_bps)?;
        ensure_bps("max_weight_bps", component.max_weight_bps)?;
        if component.min_weight_bps > component.target_weight_bps
            || component.target_weight_bps > component.max_weight_bps
        {
            return Err("component target weight outside min/max bounds".to_string());
        }
        if !ids.insert(component.component_id.clone()) {
            return Err("duplicate component id".to_string());
        }
        if !assets.insert(component.asset_id.clone()) {
            return Err("duplicate component asset".to_string());
        }
        total = total.saturating_add(component.target_weight_bps);
    }
    if total != PRIVATE_L2_CONFIDENTIAL_TOKEN_BASKET_INDEX_VAULT_RUNTIME_MAX_BPS {
        return Err("component target weights must sum to 10000 bps".to_string());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn component(id: &str, asset: &str, weight: u64) -> BasketComponent {
        BasketComponent {
            component_id: id.to_string(),
            asset_id: asset.to_string(),
            sealed_symbol_commitment: format!("sealed:{id}"),
            target_weight_bps: weight,
            min_weight_bps: 0,
            max_weight_bps: PRIVATE_L2_CONFIDENTIAL_TOKEN_BASKET_INDEX_VAULT_RUNTIME_MAX_BPS,
            oracle_feed_commitment: format!("oracle:{asset}"),
            risk_bucket: "devnet".to_string(),
            rebalance_enabled: true,
        }
    }
    #[test]
    fn devnet_state_has_stable_public_record() {
        let state = State::devnet();
        assert_eq!(state.public_record().state_root, state.state_root());
    }
    #[test]
    fn basket_component_weights_must_sum() {
        assert!(validate_components(
            &[
                component("a", "asset:a", 5_000),
                component("b", "asset:b", 5_000)
            ],
            4
        )
        .is_ok());
    }
}
