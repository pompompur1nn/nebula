use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::hash::{domain_hash, merkle_root, HashPart};

pub type PrivateL2PqConfidentialTokenClearingHouseRuntimeResult<T> = std::result::Result<T, String>;
pub type Result<T> = PrivateL2PqConfidentialTokenClearingHouseRuntimeResult<T>;
pub type Runtime = State;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKEN_CLEARING_HOUSE_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-confidential-token-clearing-house-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_TOKEN_CLEARING_HOUSE_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const DEVNET_HEIGHT: u64 = 1_620_000;
pub const DEVNET_L2_NETWORK: &str = "nebula-private-l2-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEFAULT_FEE_ASSET_ID: &str = "piconero-devnet";
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_AUTH_SUITE: &str = "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-clearing-house-v1";
pub const CONFIDENTIAL_TOKEN_SUITE: &str =
    "RingCT-amount-conservation+note-nullifier+range-proof-v1";
pub const AMM_CLEARING_SUITE: &str = "sealed-private-amm-netting-invariant-v1";
pub const COVENANT_GUARD_SUITE: &str = "root-only-confidential-token-covenant-guard-v1";
pub const RECEIPT_SUITE: &str = "recursive-batch-settlement-receipt-v1";
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_BATCH_PRIVACY_SET_SIZE: u64 = 524_288;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 9;
pub const DEFAULT_MAX_AMM_FEE_BPS: u64 = 12;
pub const DEFAULT_TARGET_REBATE_BPS: u64 = 5;
pub const DEFAULT_SLASHING_PENALTY_BPS: u64 = 1_500;
pub const DEFAULT_AUTH_TTL_BLOCKS: u64 = 128;
pub const DEFAULT_BATCH_TTL_BLOCKS: u64 = 48;
pub const DEFAULT_RECEIPT_FINALITY_BLOCKS: u64 = 8;
pub const DEFAULT_MAX_BATCH_ITEMS: usize = 16_384;
pub const DEFAULT_MAX_TOKEN_CLASSES: usize = 1_048_576;
pub const DEFAULT_MAX_AUTH_ROOTS: usize = 8_388_608;
pub const DEFAULT_MAX_BATCHES: usize = 8_388_608;
pub const DEFAULT_MAX_NETTING_CYCLES: usize = 4_194_304;
pub const DEFAULT_MAX_AMM_CLEARINGS: usize = 4_194_304;
pub const DEFAULT_MAX_GUARD_RAILS: usize = 2_097_152;
pub const DEFAULT_MAX_RECEIPTS: usize = 8_388_608;
pub const DEFAULT_MAX_REBATES: usize = 8_388_608;
pub const DEFAULT_MAX_SLASHES: usize = 2_097_152;
pub const DEFAULT_MAX_NULLIFIERS: usize = 67_108_864;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenClassKind {
    WrappedMonero,
    ConfidentialAsset,
    StableAsset,
    GovernanceNote,
    VaultShare,
    LiquidityReceipt,
    SyntheticClaim,
    CreditNote,
    SettlementCoupon,
    AppSpecificToken,
}

impl TokenClassKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WrappedMonero => "wrapped_monero",
            Self::ConfidentialAsset => "confidential_asset",
            Self::StableAsset => "stable_asset",
            Self::GovernanceNote => "governance_note",
            Self::VaultShare => "vault_share",
            Self::LiquidityReceipt => "liquidity_receipt",
            Self::SyntheticClaim => "synthetic_claim",
            Self::CreditNote => "credit_note",
            Self::SettlementCoupon => "settlement_coupon",
            Self::AppSpecificToken => "app_specific_token",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenClassStatus {
    Registered,
    Active,
    Paused,
    Frozen,
    Retired,
    Slashed,
}

impl TokenClassStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Registered => "registered",
            Self::Active => "active",
            Self::Paused => "paused",
            Self::Frozen => "frozen",
            Self::Retired => "retired",
            Self::Slashed => "slashed",
        }
    }

    pub fn accepts_activity(self) -> bool {
        matches!(self, Self::Registered | Self::Active)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchKind {
    ShieldedMint,
    ShieldedBurn,
    MixedMintBurn,
    AtomicTransferNetting,
    AmmClearing,
    RebateSettlement,
}

impl BatchKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ShieldedMint => "shielded_mint",
            Self::ShieldedBurn => "shielded_burn",
            Self::MixedMintBurn => "mixed_mint_burn",
            Self::AtomicTransferNetting => "atomic_transfer_netting",
            Self::AmmClearing => "amm_clearing",
            Self::RebateSettlement => "rebate_settlement",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchStatus {
    Open,
    Authorized,
    Netted,
    Cleared,
    Settled,
    Expired,
    Disputed,
    Slashed,
}

impl BatchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Authorized => "authorized",
            Self::Netted => "netted",
            Self::Cleared => "cleared",
            Self::Settled => "settled",
            Self::Expired => "expired",
            Self::Disputed => "disputed",
            Self::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorizationScope {
    ClassRegistrar,
    MintAuthority,
    BurnAuthority,
    TransferSender,
    TransferRecipient,
    AmmOperator,
    CovenantGuardian,
    RebateSponsor,
    SettlementProver,
    Watchtower,
}

impl AuthorizationScope {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ClassRegistrar => "class_registrar",
            Self::MintAuthority => "mint_authority",
            Self::BurnAuthority => "burn_authority",
            Self::TransferSender => "transfer_sender",
            Self::TransferRecipient => "transfer_recipient",
            Self::AmmOperator => "amm_operator",
            Self::CovenantGuardian => "covenant_guardian",
            Self::RebateSponsor => "rebate_sponsor",
            Self::SettlementProver => "settlement_prover",
            Self::Watchtower => "watchtower",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GuardRailKind {
    MaxFeeBps,
    MaxBatchItems,
    MinPrivacySet,
    RequiredPqAuth,
    FrozenJurisdictionRoot,
    MintCapCommitment,
    BurnWindow,
    AmmSlippageBound,
    NullifierRateLimit,
    EmergencyPause,
}

impl GuardRailKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MaxFeeBps => "max_fee_bps",
            Self::MaxBatchItems => "max_batch_items",
            Self::MinPrivacySet => "min_privacy_set",
            Self::RequiredPqAuth => "required_pq_auth",
            Self::FrozenJurisdictionRoot => "frozen_jurisdiction_root",
            Self::MintCapCommitment => "mint_cap_commitment",
            Self::BurnWindow => "burn_window",
            Self::AmmSlippageBound => "amm_slippage_bound",
            Self::NullifierRateLimit => "nullifier_rate_limit",
            Self::EmergencyPause => "emergency_pause",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptStatus {
    PendingFinality,
    Final,
    ReorgGuarded,
    Challenged,
    Reversed,
}

impl ReceiptStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PendingFinality => "pending_finality",
            Self::Final => "final",
            Self::ReorgGuarded => "reorg_guarded",
            Self::Challenged => "challenged",
            Self::Reversed => "reversed",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SlashReason {
    InvalidPqAuthorization,
    ReusedNullifier,
    BrokenAmountConservation,
    CovenantViolation,
    AmmInvariantFailure,
    LateSettlement,
    FraudulentReceipt,
    DataWithheld,
}

impl SlashReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidPqAuthorization => "invalid_pq_authorization",
            Self::ReusedNullifier => "reused_nullifier",
            Self::BrokenAmountConservation => "broken_amount_conservation",
            Self::CovenantViolation => "covenant_violation",
            Self::AmmInvariantFailure => "amm_invariant_failure",
            Self::LateSettlement => "late_settlement",
            Self::FraudulentReceipt => "fraudulent_receipt",
            Self::DataWithheld => "data_withheld",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskSignalKind {
    PrivacySetBelowTarget,
    NullifierReuseAttempt,
    FeeAbovePolicy,
    PqAuthorizationNearExpiry,
    AmmPriceImpactSpike,
    SettlementLag,
    GuardRailTrip,
    SlashingCluster,
}

impl RiskSignalKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrivacySetBelowTarget => "privacy_set_below_target",
            Self::NullifierReuseAttempt => "nullifier_reuse_attempt",
            Self::FeeAbovePolicy => "fee_above_policy",
            Self::PqAuthorizationNearExpiry => "pq_authorization_near_expiry",
            Self::AmmPriceImpactSpike => "amm_price_impact_spike",
            Self::SettlementLag => "settlement_lag",
            Self::GuardRailTrip => "guard_rail_trip",
            Self::SlashingCluster => "slashing_cluster",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeLane {
    TokenRegistry,
    PqAuthorization,
    ShieldedMintBurn,
    TransferNetting,
    AmmClearing,
    CovenantGuard,
    FeeRebate,
    SettlementReceipt,
    PrivacyAccounting,
    Slashing,
}

impl RuntimeLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::TokenRegistry => "token_registry",
            Self::PqAuthorization => "pq_authorization",
            Self::ShieldedMintBurn => "shielded_mint_burn",
            Self::TransferNetting => "transfer_netting",
            Self::AmmClearing => "amm_clearing",
            Self::CovenantGuard => "covenant_guard",
            Self::FeeRebate => "fee_rebate",
            Self::SettlementReceipt => "settlement_receipt",
            Self::PrivacyAccounting => "privacy_accounting",
            Self::Slashing => "slashing",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RuntimeLaneSnapshot {
    pub lane: RuntimeLane,
    pub record_count: u64,
    pub capacity: u64,
    pub root: String,
    pub backlog_commitment: String,
    pub health_commitment: String,
}

impl RuntimeLaneSnapshot {
    pub fn public_record(&self) -> Value {
        json!({
            "lane": self.lane.as_str(),
            "record_count": self.record_count,
            "capacity": self.capacity,
            "root": self.root,
            "backlog_commitment": self.backlog_commitment,
            "health_commitment": self.health_commitment
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivacyBudgetCheckpoint {
    pub checkpoint_id: String,
    pub token_class_id: String,
    pub accounting_root: String,
    pub nullifier_root: String,
    pub privacy_set_size: u64,
    pub spent_count: u64,
    pub anonymity_floor: u64,
    pub checkpoint_height: u64,
}

impl PrivacyBudgetCheckpoint {
    pub fn public_record(&self) -> Value {
        json!({
            "checkpoint_id": self.checkpoint_id,
            "token_class_id": self.token_class_id,
            "accounting_root": self.accounting_root,
            "nullifier_root": self.nullifier_root,
            "privacy_set_size": self.privacy_set_size,
            "spent_count": self.spent_count,
            "anonymity_floor": self.anonymity_floor,
            "checkpoint_height": self.checkpoint_height
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskSignalRecord {
    pub signal_id: String,
    pub kind: RiskSignalKind,
    pub source_id: String,
    pub token_class_id: String,
    pub evidence_root: String,
    pub severity_commitment: String,
    pub mitigation_root: String,
    pub observed_height: u64,
}

impl RiskSignalRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "signal_id": self.signal_id,
            "kind": self.kind.as_str(),
            "source_id": self.source_id,
            "token_class_id": self.token_class_id,
            "evidence_root": self.evidence_root,
            "severity_commitment": self.severity_commitment,
            "mitigation_root": self.mitigation_root,
            "observed_height": self.observed_height
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ClearingHouseSnapshot {
    pub snapshot_id: String,
    pub height: u64,
    pub state_root: String,
    pub roots: Roots,
    pub counters: Counters,
    pub lane_snapshots: Vec<RuntimeLaneSnapshot>,
    pub privacy_checkpoint: PrivacyBudgetCheckpoint,
    pub risk_signals: Vec<RiskSignalRecord>,
}

impl ClearingHouseSnapshot {
    pub fn public_record(&self) -> Value {
        json!({
            "snapshot_id": self.snapshot_id,
            "height": self.height,
            "state_root": self.state_root,
            "roots": self.roots.public_record(),
            "counters": self.counters.public_record(),
            "lane_snapshots": self
                .lane_snapshots
                .iter()
                .map(RuntimeLaneSnapshot::public_record)
                .collect::<Vec<_>>(),
            "privacy_checkpoint": self.privacy_checkpoint.public_record(),
            "risk_signals": self
                .risk_signals
                .iter()
                .map(RiskSignalRecord::public_record)
                .collect::<Vec<_>>()
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub l2_network: String,
    pub monero_network: String,
    pub fee_asset_id: String,
    pub min_privacy_set_size: u64,
    pub batch_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub max_user_fee_bps: u64,
    pub max_amm_fee_bps: u64,
    pub target_rebate_bps: u64,
    pub slashing_penalty_bps: u64,
    pub auth_ttl_blocks: u64,
    pub batch_ttl_blocks: u64,
    pub receipt_finality_blocks: u64,
    pub max_batch_items: usize,
    pub max_token_classes: usize,
    pub max_auth_roots: usize,
    pub max_batches: usize,
    pub max_netting_cycles: usize,
    pub max_amm_clearings: usize,
    pub max_guard_rails: usize,
    pub max_receipts: usize,
    pub max_rebates: usize,
    pub max_slashes: usize,
    pub max_nullifiers: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            l2_network: DEVNET_L2_NETWORK.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            fee_asset_id: DEFAULT_FEE_ASSET_ID.to_string(),
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            batch_privacy_set_size: DEFAULT_BATCH_PRIVACY_SET_SIZE,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            max_amm_fee_bps: DEFAULT_MAX_AMM_FEE_BPS,
            target_rebate_bps: DEFAULT_TARGET_REBATE_BPS,
            slashing_penalty_bps: DEFAULT_SLASHING_PENALTY_BPS,
            auth_ttl_blocks: DEFAULT_AUTH_TTL_BLOCKS,
            batch_ttl_blocks: DEFAULT_BATCH_TTL_BLOCKS,
            receipt_finality_blocks: DEFAULT_RECEIPT_FINALITY_BLOCKS,
            max_batch_items: DEFAULT_MAX_BATCH_ITEMS,
            max_token_classes: DEFAULT_MAX_TOKEN_CLASSES,
            max_auth_roots: DEFAULT_MAX_AUTH_ROOTS,
            max_batches: DEFAULT_MAX_BATCHES,
            max_netting_cycles: DEFAULT_MAX_NETTING_CYCLES,
            max_amm_clearings: DEFAULT_MAX_AMM_CLEARINGS,
            max_guard_rails: DEFAULT_MAX_GUARD_RAILS,
            max_receipts: DEFAULT_MAX_RECEIPTS,
            max_rebates: DEFAULT_MAX_REBATES,
            max_slashes: DEFAULT_MAX_SLASHES,
            max_nullifiers: DEFAULT_MAX_NULLIFIERS,
        }
    }
}

impl Config {
    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "l2_network": self.l2_network,
            "monero_network": self.monero_network,
            "fee_asset_id": self.fee_asset_id,
            "min_privacy_set_size": self.min_privacy_set_size,
            "batch_privacy_set_size": self.batch_privacy_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
            "max_user_fee_bps": self.max_user_fee_bps,
            "max_amm_fee_bps": self.max_amm_fee_bps,
            "target_rebate_bps": self.target_rebate_bps,
            "slashing_penalty_bps": self.slashing_penalty_bps,
            "auth_ttl_blocks": self.auth_ttl_blocks,
            "batch_ttl_blocks": self.batch_ttl_blocks,
            "receipt_finality_blocks": self.receipt_finality_blocks,
            "max_batch_items": self.max_batch_items,
            "max_token_classes": self.max_token_classes,
            "max_auth_roots": self.max_auth_roots,
            "max_batches": self.max_batches,
            "max_netting_cycles": self.max_netting_cycles,
            "max_amm_clearings": self.max_amm_clearings,
            "max_guard_rails": self.max_guard_rails,
            "max_receipts": self.max_receipts,
            "max_rebates": self.max_rebates,
            "max_slashes": self.max_slashes,
            "max_nullifiers": self.max_nullifiers,
            "hash_suite": HASH_SUITE,
            "pq_auth_suite": PQ_AUTH_SUITE,
            "confidential_token_suite": CONFIDENTIAL_TOKEN_SUITE,
            "amm_clearing_suite": AMM_CLEARING_SUITE,
            "covenant_guard_suite": COVENANT_GUARD_SUITE,
            "receipt_suite": RECEIPT_SUITE
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub token_classes_registered: u64,
    pub auth_roots_registered: u64,
    pub shielded_batches_submitted: u64,
    pub netting_cycles_cleared: u64,
    pub amm_clearings_executed: u64,
    pub guard_rails_installed: u64,
    pub receipts_issued: u64,
    pub rebates_issued: u64,
    pub nullifiers_observed: u64,
    pub slash_events: u64,
    pub low_fee_savings_commitment: String,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "token_classes_registered": self.token_classes_registered,
            "auth_roots_registered": self.auth_roots_registered,
            "shielded_batches_submitted": self.shielded_batches_submitted,
            "netting_cycles_cleared": self.netting_cycles_cleared,
            "amm_clearings_executed": self.amm_clearings_executed,
            "guard_rails_installed": self.guard_rails_installed,
            "receipts_issued": self.receipts_issued,
            "rebates_issued": self.rebates_issued,
            "nullifiers_observed": self.nullifiers_observed,
            "slash_events": self.slash_events,
            "low_fee_savings_commitment": self.low_fee_savings_commitment
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub token_class_root: String,
    pub pq_authorization_root: String,
    pub shielded_batch_root: String,
    pub transfer_netting_root: String,
    pub amm_clearing_root: String,
    pub covenant_guard_root: String,
    pub settlement_receipt_root: String,
    pub fee_rebate_root: String,
    pub nullifier_root: String,
    pub slashing_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "token_class_root": self.token_class_root,
            "pq_authorization_root": self.pq_authorization_root,
            "shielded_batch_root": self.shielded_batch_root,
            "transfer_netting_root": self.transfer_netting_root,
            "amm_clearing_root": self.amm_clearing_root,
            "covenant_guard_root": self.covenant_guard_root,
            "settlement_receipt_root": self.settlement_receipt_root,
            "fee_rebate_root": self.fee_rebate_root,
            "nullifier_root": self.nullifier_root,
            "slashing_root": self.slashing_root
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ConfidentialTokenClassRecord {
    pub token_class_id: String,
    pub kind: TokenClassKind,
    pub status: TokenClassStatus,
    pub issuer_commitment: String,
    pub symbol_commitment: String,
    pub metadata_root: String,
    pub supply_commitment: String,
    pub covenant_root: String,
    pub pq_authority_root: String,
    pub fee_policy_root: String,
    pub created_height: u64,
    pub last_updated_height: u64,
}

impl ConfidentialTokenClassRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "token_class_id": self.token_class_id,
            "kind": self.kind.as_str(),
            "status": self.status.as_str(),
            "issuer_commitment": self.issuer_commitment,
            "symbol_commitment": self.symbol_commitment,
            "metadata_root": self.metadata_root,
            "supply_commitment": self.supply_commitment,
            "covenant_root": self.covenant_root,
            "pq_authority_root": self.pq_authority_root,
            "fee_policy_root": self.fee_policy_root,
            "created_height": self.created_height,
            "last_updated_height": self.last_updated_height
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RegisterTokenClassRequest {
    pub kind: TokenClassKind,
    pub issuer_commitment: String,
    pub symbol_commitment: String,
    pub metadata_root: String,
    pub supply_commitment: String,
    pub covenant_root: String,
    pub pq_authority_root: String,
    pub fee_policy_root: String,
    pub height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqAuthorizationRootRecord {
    pub authorization_id: String,
    pub token_class_id: String,
    pub scope: AuthorizationScope,
    pub subject_commitment: String,
    pub authorization_root: String,
    pub verifier_key_root: String,
    pub min_security_bits: u16,
    pub valid_from_height: u64,
    pub expires_at_height: u64,
    pub consumed: bool,
}

impl PqAuthorizationRootRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "authorization_id": self.authorization_id,
            "token_class_id": self.token_class_id,
            "scope": self.scope.as_str(),
            "subject_commitment": self.subject_commitment,
            "authorization_root": self.authorization_root,
            "verifier_key_root": self.verifier_key_root,
            "min_security_bits": self.min_security_bits,
            "valid_from_height": self.valid_from_height,
            "expires_at_height": self.expires_at_height,
            "consumed": self.consumed
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RegisterPqAuthorizationRequest {
    pub token_class_id: String,
    pub scope: AuthorizationScope,
    pub subject_commitment: String,
    pub authorization_root: String,
    pub verifier_key_root: String,
    pub min_security_bits: u16,
    pub valid_from_height: u64,
    pub expires_at_height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ShieldedBatchRecord {
    pub batch_id: String,
    pub token_class_id: String,
    pub kind: BatchKind,
    pub status: BatchStatus,
    pub input_note_root: String,
    pub output_note_root: String,
    pub amount_conservation_root: String,
    pub proof_root: String,
    pub pq_authorization_ids: Vec<String>,
    pub nullifiers: Vec<String>,
    pub item_count: usize,
    pub fee_commitment: String,
    pub privacy_set_size: u64,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
}

impl ShieldedBatchRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "token_class_id": self.token_class_id,
            "kind": self.kind.as_str(),
            "status": self.status.as_str(),
            "input_note_root": self.input_note_root,
            "output_note_root": self.output_note_root,
            "amount_conservation_root": self.amount_conservation_root,
            "proof_root": self.proof_root,
            "pq_authorization_ids": self.pq_authorization_ids,
            "nullifiers": self.nullifiers,
            "item_count": self.item_count,
            "fee_commitment": self.fee_commitment,
            "privacy_set_size": self.privacy_set_size,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SubmitShieldedBatchRequest {
    pub token_class_id: String,
    pub kind: BatchKind,
    pub input_note_root: String,
    pub output_note_root: String,
    pub amount_conservation_root: String,
    pub proof_root: String,
    pub pq_authorization_ids: Vec<String>,
    pub nullifiers: Vec<String>,
    pub item_count: usize,
    pub fee_commitment: String,
    pub privacy_set_size: u64,
    pub opened_at_height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TransferNettingCycleRecord {
    pub netting_id: String,
    pub token_class_id: String,
    pub participant_set_root: String,
    pub debit_root: String,
    pub credit_root: String,
    pub net_delta_commitment: String,
    pub conservation_proof_root: String,
    pub settled_batch_ids: Vec<String>,
    pub nullifier_root: String,
    pub fee_commitment: String,
    pub cleared_height: u64,
}

impl TransferNettingCycleRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "netting_id": self.netting_id,
            "token_class_id": self.token_class_id,
            "participant_set_root": self.participant_set_root,
            "debit_root": self.debit_root,
            "credit_root": self.credit_root,
            "net_delta_commitment": self.net_delta_commitment,
            "conservation_proof_root": self.conservation_proof_root,
            "settled_batch_ids": self.settled_batch_ids,
            "nullifier_root": self.nullifier_root,
            "fee_commitment": self.fee_commitment,
            "cleared_height": self.cleared_height
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AtomicTransferNettingRequest {
    pub token_class_id: String,
    pub participant_set_root: String,
    pub debit_root: String,
    pub credit_root: String,
    pub net_delta_commitment: String,
    pub conservation_proof_root: String,
    pub settled_batch_ids: Vec<String>,
    pub fee_commitment: String,
    pub cleared_height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivateAmmClearingRecord {
    pub clearing_id: String,
    pub pool_id: String,
    pub token_class_id_a: String,
    pub token_class_id_b: String,
    pub encrypted_order_root: String,
    pub reserve_commitment_before: String,
    pub reserve_commitment_after: String,
    pub invariant_proof_root: String,
    pub price_impact_commitment: String,
    pub fee_commitment: String,
    pub rebate_commitment: String,
    pub nullifier_root: String,
    pub batch_ids: Vec<String>,
    pub cleared_height: u64,
}

impl PrivateAmmClearingRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "clearing_id": self.clearing_id,
            "pool_id": self.pool_id,
            "token_class_id_a": self.token_class_id_a,
            "token_class_id_b": self.token_class_id_b,
            "encrypted_order_root": self.encrypted_order_root,
            "reserve_commitment_before": self.reserve_commitment_before,
            "reserve_commitment_after": self.reserve_commitment_after,
            "invariant_proof_root": self.invariant_proof_root,
            "price_impact_commitment": self.price_impact_commitment,
            "fee_commitment": self.fee_commitment,
            "rebate_commitment": self.rebate_commitment,
            "nullifier_root": self.nullifier_root,
            "batch_ids": self.batch_ids,
            "cleared_height": self.cleared_height
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivateAmmClearingRequest {
    pub pool_id: String,
    pub token_class_id_a: String,
    pub token_class_id_b: String,
    pub encrypted_order_root: String,
    pub reserve_commitment_before: String,
    pub reserve_commitment_after: String,
    pub invariant_proof_root: String,
    pub price_impact_commitment: String,
    pub fee_commitment: String,
    pub rebate_commitment: String,
    pub batch_ids: Vec<String>,
    pub cleared_height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CovenantGuardRailRecord {
    pub guard_id: String,
    pub token_class_id: String,
    pub kind: GuardRailKind,
    pub guard_root: String,
    pub threshold_commitment: String,
    pub enforcement_root: String,
    pub installed_by_commitment: String,
    pub active: bool,
    pub installed_height: u64,
}

impl CovenantGuardRailRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "guard_id": self.guard_id,
            "token_class_id": self.token_class_id,
            "kind": self.kind.as_str(),
            "guard_root": self.guard_root,
            "threshold_commitment": self.threshold_commitment,
            "enforcement_root": self.enforcement_root,
            "installed_by_commitment": self.installed_by_commitment,
            "active": self.active,
            "installed_height": self.installed_height
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct InstallCovenantGuardRailRequest {
    pub token_class_id: String,
    pub kind: GuardRailKind,
    pub guard_root: String,
    pub threshold_commitment: String,
    pub enforcement_root: String,
    pub installed_by_commitment: String,
    pub installed_height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FeeRebateRecord {
    pub rebate_id: String,
    pub recipient_commitment: String,
    pub token_class_id: String,
    pub source_id: String,
    pub fee_commitment: String,
    pub rebate_commitment: String,
    pub sponsor_commitment: String,
    pub proof_root: String,
    pub issued_height: u64,
}

impl FeeRebateRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "rebate_id": self.rebate_id,
            "recipient_commitment": self.recipient_commitment,
            "token_class_id": self.token_class_id,
            "source_id": self.source_id,
            "fee_commitment": self.fee_commitment,
            "rebate_commitment": self.rebate_commitment,
            "sponsor_commitment": self.sponsor_commitment,
            "proof_root": self.proof_root,
            "issued_height": self.issued_height
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct IssueFeeRebateRequest {
    pub recipient_commitment: String,
    pub token_class_id: String,
    pub source_id: String,
    pub fee_commitment: String,
    pub rebate_commitment: String,
    pub sponsor_commitment: String,
    pub proof_root: String,
    pub issued_height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SettlementReceiptRecord {
    pub receipt_id: String,
    pub batch_id: String,
    pub status: ReceiptStatus,
    pub pre_state_root: String,
    pub post_state_root: String,
    pub recursive_proof_root: String,
    pub monero_anchor_root: String,
    pub da_commitment_root: String,
    pub settled_height: u64,
    pub finality_height: u64,
}

impl SettlementReceiptRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "batch_id": self.batch_id,
            "status": self.status.as_str(),
            "pre_state_root": self.pre_state_root,
            "post_state_root": self.post_state_root,
            "recursive_proof_root": self.recursive_proof_root,
            "monero_anchor_root": self.monero_anchor_root,
            "da_commitment_root": self.da_commitment_root,
            "settled_height": self.settled_height,
            "finality_height": self.finality_height
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct IssueSettlementReceiptRequest {
    pub batch_id: String,
    pub pre_state_root: String,
    pub post_state_root: String,
    pub recursive_proof_root: String,
    pub monero_anchor_root: String,
    pub da_commitment_root: String,
    pub settled_height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivacyAccountingRecord {
    pub accounting_id: String,
    pub token_class_id: String,
    pub source_id: String,
    pub nullifier_root: String,
    pub new_nullifiers: Vec<String>,
    pub spent_count: u64,
    pub privacy_set_size: u64,
    pub entropy_commitment: String,
    pub recorded_height: u64,
}

impl PrivacyAccountingRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "accounting_id": self.accounting_id,
            "token_class_id": self.token_class_id,
            "source_id": self.source_id,
            "nullifier_root": self.nullifier_root,
            "new_nullifiers": self.new_nullifiers,
            "spent_count": self.spent_count,
            "privacy_set_size": self.privacy_set_size,
            "entropy_commitment": self.entropy_commitment,
            "recorded_height": self.recorded_height
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SlashingRecord {
    pub slash_id: String,
    pub offender_commitment: String,
    pub reason: SlashReason,
    pub source_id: String,
    pub evidence_root: String,
    pub penalty_commitment: String,
    pub beneficiary_commitment: String,
    pub applied_height: u64,
}

impl SlashingRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "slash_id": self.slash_id,
            "offender_commitment": self.offender_commitment,
            "reason": self.reason.as_str(),
            "source_id": self.source_id,
            "evidence_root": self.evidence_root,
            "penalty_commitment": self.penalty_commitment,
            "beneficiary_commitment": self.beneficiary_commitment,
            "applied_height": self.applied_height
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SlashRequest {
    pub offender_commitment: String,
    pub reason: SlashReason,
    pub source_id: String,
    pub evidence_root: String,
    pub penalty_commitment: String,
    pub beneficiary_commitment: String,
    pub applied_height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub token_classes: BTreeMap<String, ConfidentialTokenClassRecord>,
    pub pq_authorizations: BTreeMap<String, PqAuthorizationRootRecord>,
    pub shielded_batches: BTreeMap<String, ShieldedBatchRecord>,
    pub transfer_netting_cycles: BTreeMap<String, TransferNettingCycleRecord>,
    pub amm_clearings: BTreeMap<String, PrivateAmmClearingRecord>,
    pub covenant_guard_rails: BTreeMap<String, CovenantGuardRailRecord>,
    pub settlement_receipts: BTreeMap<String, SettlementReceiptRecord>,
    pub fee_rebates: BTreeMap<String, FeeRebateRecord>,
    pub privacy_accounting: BTreeMap<String, PrivacyAccountingRecord>,
    pub slashes: BTreeMap<String, SlashingRecord>,
    pub spent_nullifiers: BTreeSet<String>,
}

impl Default for State {
    fn default() -> Self {
        Self {
            config: Config::default(),
            counters: Counters::default(),
            token_classes: BTreeMap::new(),
            pq_authorizations: BTreeMap::new(),
            shielded_batches: BTreeMap::new(),
            transfer_netting_cycles: BTreeMap::new(),
            amm_clearings: BTreeMap::new(),
            covenant_guard_rails: BTreeMap::new(),
            settlement_receipts: BTreeMap::new(),
            fee_rebates: BTreeMap::new(),
            privacy_accounting: BTreeMap::new(),
            slashes: BTreeMap::new(),
            spent_nullifiers: BTreeSet::new(),
        }
    }
}

impl State {
    pub fn devnet() -> Self {
        let mut state = Self::default();
        let xmr = state
            .register_token_class(RegisterTokenClassRequest {
                kind: TokenClassKind::WrappedMonero,
                issuer_commitment: string_root("DEVNET-ISSUER", "monero-bridge-council"),
                symbol_commitment: string_root("DEVNET-SYMBOL", "pXMR"),
                metadata_root: string_root("DEVNET-METADATA", "private-wrapped-monero"),
                supply_commitment: string_root("DEVNET-SUPPLY", "confidential-supply-pxmr"),
                covenant_root: string_root("DEVNET-COVENANT", "low-fee-private-transfer"),
                pq_authority_root: string_root("DEVNET-PQ-AUTHORITY", "bridge-council-root"),
                fee_policy_root: string_root("DEVNET-FEE-POLICY", "max-9bps-rebate-5bps"),
                height: DEVNET_HEIGHT,
            })
            .expect("devnet token class");
        let stable = state
            .register_token_class(RegisterTokenClassRequest {
                kind: TokenClassKind::StableAsset,
                issuer_commitment: string_root("DEVNET-ISSUER", "stable-asset-council"),
                symbol_commitment: string_root("DEVNET-SYMBOL", "pUSD"),
                metadata_root: string_root("DEVNET-METADATA", "private-usd-note"),
                supply_commitment: string_root("DEVNET-SUPPLY", "confidential-supply-pusd"),
                covenant_root: string_root("DEVNET-COVENANT", "amm-and-netting-enabled"),
                pq_authority_root: string_root("DEVNET-PQ-AUTHORITY", "stable-council-root"),
                fee_policy_root: string_root("DEVNET-FEE-POLICY", "max-9bps-rebate-5bps"),
                height: DEVNET_HEIGHT + 1,
            })
            .expect("devnet stable class");
        let mint_auth = state
            .register_pq_authorization_root(RegisterPqAuthorizationRequest {
                token_class_id: xmr.token_class_id.clone(),
                scope: AuthorizationScope::MintAuthority,
                subject_commitment: string_root("DEVNET-SUBJECT", "mint-authority-alpha"),
                authorization_root: string_root("DEVNET-AUTH", "mint-root-alpha"),
                verifier_key_root: string_root("DEVNET-VK", PQ_AUTH_SUITE),
                min_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
                valid_from_height: DEVNET_HEIGHT,
                expires_at_height: DEVNET_HEIGHT + DEFAULT_AUTH_TTL_BLOCKS,
            })
            .expect("devnet auth");
        state
            .install_covenant_guard_rail(InstallCovenantGuardRailRequest {
                token_class_id: xmr.token_class_id.clone(),
                kind: GuardRailKind::MinPrivacySet,
                guard_root: string_root("DEVNET-GUARD", "privacy-set"),
                threshold_commitment: int_root("DEVNET-THRESHOLD", DEFAULT_MIN_PRIVACY_SET_SIZE),
                enforcement_root: string_root("DEVNET-ENFORCEMENT", "reject-small-batches"),
                installed_by_commitment: string_root("DEVNET-GUARDIAN", "guardian-alpha"),
                installed_height: DEVNET_HEIGHT + 2,
            })
            .expect("devnet guard");
        let mint_batch = state
            .submit_shielded_batch(SubmitShieldedBatchRequest {
                token_class_id: xmr.token_class_id.clone(),
                kind: BatchKind::ShieldedMint,
                input_note_root: string_root("DEVNET-NOTES-IN", "mint-empty"),
                output_note_root: string_root("DEVNET-NOTES-OUT", "mint-pxmr-notes"),
                amount_conservation_root: string_root("DEVNET-CONSERVATION", "mint-bridge-lock"),
                proof_root: string_root("DEVNET-PROOF", "mint-range-membership-proof"),
                pq_authorization_ids: vec![mint_auth.authorization_id.clone()],
                nullifiers: vec![string_root("DEVNET-NULLIFIER", "mint-alpha")],
                item_count: 64,
                fee_commitment: int_root("DEVNET-FEE", 3),
                privacy_set_size: DEFAULT_BATCH_PRIVACY_SET_SIZE,
                opened_at_height: DEVNET_HEIGHT + 3,
            })
            .expect("devnet batch");
        state
            .clear_atomic_transfer_netting(AtomicTransferNettingRequest {
                token_class_id: xmr.token_class_id.clone(),
                participant_set_root: string_root("DEVNET-PARTICIPANTS", "alice-bob-carol"),
                debit_root: string_root("DEVNET-DEBITS", "private-debits"),
                credit_root: string_root("DEVNET-CREDITS", "private-credits"),
                net_delta_commitment: string_root("DEVNET-NET-DELTA", "zero-sum"),
                conservation_proof_root: string_root("DEVNET-NETTING-PROOF", "conserved"),
                settled_batch_ids: vec![mint_batch.batch_id.clone()],
                fee_commitment: int_root("DEVNET-NETTING-FEE", 2),
                cleared_height: DEVNET_HEIGHT + 4,
            })
            .expect("devnet netting");
        state
            .clear_private_amm(PrivateAmmClearingRequest {
                pool_id: deterministic_id("DEVNET-POOL", &[HashPart::Str("pxmr-pusd")]),
                token_class_id_a: xmr.token_class_id.clone(),
                token_class_id_b: stable.token_class_id.clone(),
                encrypted_order_root: string_root("DEVNET-ORDERS", "sealed-amm-flow"),
                reserve_commitment_before: string_root("DEVNET-RESERVE-BEFORE", "sealed"),
                reserve_commitment_after: string_root("DEVNET-RESERVE-AFTER", "sealed"),
                invariant_proof_root: string_root("DEVNET-INVARIANT", "xyk-private-proof"),
                price_impact_commitment: int_root("DEVNET-PRICE-IMPACT", 4),
                fee_commitment: int_root("DEVNET-AMM-FEE", 4),
                rebate_commitment: int_root("DEVNET-AMM-REBATE", 2),
                batch_ids: vec![mint_batch.batch_id.clone()],
                cleared_height: DEVNET_HEIGHT + 5,
            })
            .expect("devnet amm");
        state
            .issue_settlement_receipt(IssueSettlementReceiptRequest {
                batch_id: mint_batch.batch_id,
                pre_state_root: string_root("DEVNET-PRE-STATE", "pre"),
                post_state_root: state.state_root(),
                recursive_proof_root: string_root("DEVNET-RECURSIVE-PROOF", "receipt-proof"),
                monero_anchor_root: string_root("DEVNET-MONERO-ANCHOR", "anchor"),
                da_commitment_root: string_root("DEVNET-DA", "available"),
                settled_height: DEVNET_HEIGHT + 6,
            })
            .expect("devnet receipt");
        state
    }

    pub fn roots(&self) -> Roots {
        Roots {
            token_class_root: records_root(
                "TOKEN-CLASS-ROOT",
                self.token_classes
                    .values()
                    .map(ConfidentialTokenClassRecord::public_record)
                    .collect(),
            ),
            pq_authorization_root: records_root(
                "PQ-AUTHORIZATION-ROOT",
                self.pq_authorizations
                    .values()
                    .map(PqAuthorizationRootRecord::public_record)
                    .collect(),
            ),
            shielded_batch_root: records_root(
                "SHIELDED-BATCH-ROOT",
                self.shielded_batches
                    .values()
                    .map(ShieldedBatchRecord::public_record)
                    .collect(),
            ),
            transfer_netting_root: records_root(
                "TRANSFER-NETTING-ROOT",
                self.transfer_netting_cycles
                    .values()
                    .map(TransferNettingCycleRecord::public_record)
                    .collect(),
            ),
            amm_clearing_root: records_root(
                "AMM-CLEARING-ROOT",
                self.amm_clearings
                    .values()
                    .map(PrivateAmmClearingRecord::public_record)
                    .collect(),
            ),
            covenant_guard_root: records_root(
                "COVENANT-GUARD-ROOT",
                self.covenant_guard_rails
                    .values()
                    .map(CovenantGuardRailRecord::public_record)
                    .collect(),
            ),
            settlement_receipt_root: records_root(
                "SETTLEMENT-RECEIPT-ROOT",
                self.settlement_receipts
                    .values()
                    .map(SettlementReceiptRecord::public_record)
                    .collect(),
            ),
            fee_rebate_root: records_root(
                "FEE-REBATE-ROOT",
                self.fee_rebates
                    .values()
                    .map(FeeRebateRecord::public_record)
                    .collect(),
            ),
            nullifier_root: records_root(
                "NULLIFIER-ACCOUNTING-ROOT",
                self.privacy_accounting
                    .values()
                    .map(PrivacyAccountingRecord::public_record)
                    .collect(),
            ),
            slashing_root: records_root(
                "SLASHING-ROOT",
                self.slashes
                    .values()
                    .map(SlashingRecord::public_record)
                    .collect(),
            ),
        }
    }

    pub fn state_root(&self) -> String {
        state_root_from_record(&self.public_record_without_root())
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_root();
        if let Some(map) = record.as_object_mut() {
            map.insert("state_root".to_string(), Value::String(self.state_root()));
        }
        record
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": self.roots().public_record(),
            "spent_nullifier_count": self.spent_nullifiers.len()
        })
    }

    pub fn register_token_class(
        &mut self,
        request: RegisterTokenClassRequest,
    ) -> Result<ConfidentialTokenClassRecord> {
        self.ensure_capacity(
            self.token_classes.len(),
            self.config.max_token_classes,
            "token classes",
        )?;
        ensure_nonempty(&request.issuer_commitment, "issuer commitment")?;
        ensure_nonempty(&request.symbol_commitment, "symbol commitment")?;
        ensure_nonempty(&request.metadata_root, "metadata root")?;
        ensure_nonempty(&request.covenant_root, "covenant root")?;
        ensure_nonempty(&request.pq_authority_root, "pq authority root")?;
        let token_class_id = deterministic_id(
            "TOKEN-CLASS-ID",
            &[
                HashPart::Str(request.kind.as_str()),
                HashPart::Str(&request.issuer_commitment),
                HashPart::Str(&request.symbol_commitment),
                HashPart::Str(&request.metadata_root),
            ],
        );
        if self.token_classes.contains_key(&token_class_id) {
            return Err(format!("token class already registered: {token_class_id}"));
        }
        let record = ConfidentialTokenClassRecord {
            token_class_id: token_class_id.clone(),
            kind: request.kind,
            status: TokenClassStatus::Registered,
            issuer_commitment: request.issuer_commitment,
            symbol_commitment: request.symbol_commitment,
            metadata_root: request.metadata_root,
            supply_commitment: request.supply_commitment,
            covenant_root: request.covenant_root,
            pq_authority_root: request.pq_authority_root,
            fee_policy_root: request.fee_policy_root,
            created_height: request.height,
            last_updated_height: request.height,
        };
        self.token_classes.insert(token_class_id, record.clone());
        self.counters.token_classes_registered += 1;
        Ok(record)
    }

    pub fn activate_token_class(&mut self, token_class_id: &str, height: u64) -> Result<()> {
        let class = self
            .token_classes
            .get_mut(token_class_id)
            .ok_or_else(|| format!("unknown token class: {token_class_id}"))?;
        if matches!(
            class.status,
            TokenClassStatus::Frozen | TokenClassStatus::Slashed
        ) {
            return Err("frozen or slashed token class cannot be activated".to_string());
        }
        class.status = TokenClassStatus::Active;
        class.last_updated_height = height;
        Ok(())
    }

    pub fn pause_token_class(&mut self, token_class_id: &str, height: u64) -> Result<()> {
        let class = self
            .token_classes
            .get_mut(token_class_id)
            .ok_or_else(|| format!("unknown token class: {token_class_id}"))?;
        class.status = TokenClassStatus::Paused;
        class.last_updated_height = height;
        Ok(())
    }

    pub fn register_pq_authorization_root(
        &mut self,
        request: RegisterPqAuthorizationRequest,
    ) -> Result<PqAuthorizationRootRecord> {
        self.ensure_capacity(
            self.pq_authorizations.len(),
            self.config.max_auth_roots,
            "pq authorizations",
        )?;
        self.ensure_active_class(&request.token_class_id)?;
        ensure_nonempty(&request.authorization_root, "authorization root")?;
        ensure_nonempty(&request.verifier_key_root, "verifier key root")?;
        if request.min_security_bits < self.config.min_pq_security_bits {
            return Err("pq authorization security bits below runtime minimum".to_string());
        }
        if request.expires_at_height <= request.valid_from_height {
            return Err("authorization expiry must be after valid_from height".to_string());
        }
        let authorization_id = deterministic_id(
            "PQ-AUTHORIZATION-ID",
            &[
                HashPart::Str(&request.token_class_id),
                HashPart::Str(request.scope.as_str()),
                HashPart::Str(&request.subject_commitment),
                HashPart::Str(&request.authorization_root),
                HashPart::U64(request.valid_from_height),
            ],
        );
        if self.pq_authorizations.contains_key(&authorization_id) {
            return Err(format!(
                "authorization already registered: {authorization_id}"
            ));
        }
        let record = PqAuthorizationRootRecord {
            authorization_id: authorization_id.clone(),
            token_class_id: request.token_class_id,
            scope: request.scope,
            subject_commitment: request.subject_commitment,
            authorization_root: request.authorization_root,
            verifier_key_root: request.verifier_key_root,
            min_security_bits: request.min_security_bits,
            valid_from_height: request.valid_from_height,
            expires_at_height: request.expires_at_height,
            consumed: false,
        };
        self.pq_authorizations
            .insert(authorization_id, record.clone());
        self.counters.auth_roots_registered += 1;
        Ok(record)
    }

    pub fn submit_shielded_batch(
        &mut self,
        request: SubmitShieldedBatchRequest,
    ) -> Result<ShieldedBatchRecord> {
        self.ensure_capacity(
            self.shielded_batches.len(),
            self.config.max_batches,
            "shielded batches",
        )?;
        self.ensure_active_class(&request.token_class_id)?;
        if request.item_count == 0 || request.item_count > self.config.max_batch_items {
            return Err("batch item count outside configured bounds".to_string());
        }
        if request.privacy_set_size < self.config.min_privacy_set_size {
            return Err("privacy set too small for shielded batch".to_string());
        }
        if request.nullifiers.len() > request.item_count {
            return Err("nullifier count exceeds batch item count".to_string());
        }
        self.ensure_new_nullifiers(&request.nullifiers)?;
        for authorization_id in &request.pq_authorization_ids {
            self.ensure_authorization(
                authorization_id,
                &request.token_class_id,
                request.opened_at_height,
            )?;
        }
        let nullifier_root = records_root(
            "BATCH-NULLIFIER-ROOT",
            request
                .nullifiers
                .iter()
                .map(|nullifier| json!({ "nullifier": nullifier }))
                .collect(),
        );
        let batch_id = deterministic_id(
            "SHIELDED-BATCH-ID",
            &[
                HashPart::Str(&request.token_class_id),
                HashPart::Str(request.kind.as_str()),
                HashPart::Str(&request.input_note_root),
                HashPart::Str(&request.output_note_root),
                HashPart::Str(&nullifier_root),
                HashPart::U64(request.opened_at_height),
            ],
        );
        if self.shielded_batches.contains_key(&batch_id) {
            return Err(format!("shielded batch already submitted: {batch_id}"));
        }
        for nullifier in &request.nullifiers {
            self.spent_nullifiers.insert(nullifier.clone());
        }
        let record = ShieldedBatchRecord {
            batch_id: batch_id.clone(),
            token_class_id: request.token_class_id,
            kind: request.kind,
            status: BatchStatus::Authorized,
            input_note_root: request.input_note_root,
            output_note_root: request.output_note_root,
            amount_conservation_root: request.amount_conservation_root,
            proof_root: request.proof_root,
            pq_authorization_ids: request.pq_authorization_ids,
            nullifiers: request.nullifiers.clone(),
            item_count: request.item_count,
            fee_commitment: request.fee_commitment,
            privacy_set_size: request.privacy_set_size,
            opened_at_height: request.opened_at_height,
            expires_at_height: request.opened_at_height + self.config.batch_ttl_blocks,
        };
        self.record_privacy_accounting(
            &record.token_class_id,
            &batch_id,
            request.nullifiers,
            request.privacy_set_size,
            request.opened_at_height,
        )?;
        self.shielded_batches.insert(batch_id, record.clone());
        self.counters.shielded_batches_submitted += 1;
        Ok(record)
    }

    pub fn clear_atomic_transfer_netting(
        &mut self,
        request: AtomicTransferNettingRequest,
    ) -> Result<TransferNettingCycleRecord> {
        self.ensure_capacity(
            self.transfer_netting_cycles.len(),
            self.config.max_netting_cycles,
            "transfer netting cycles",
        )?;
        self.ensure_active_class(&request.token_class_id)?;
        if request.settled_batch_ids.is_empty() {
            return Err("netting cycle requires at least one batch".to_string());
        }
        for batch_id in &request.settled_batch_ids {
            self.ensure_batch_for_class(batch_id, &request.token_class_id)?;
        }
        let nullifier_root = records_root(
            "NETTING-BATCH-ROOT",
            request
                .settled_batch_ids
                .iter()
                .map(|batch_id| json!({ "batch_id": batch_id }))
                .collect(),
        );
        let netting_id = deterministic_id(
            "ATOMIC-TRANSFER-NETTING-ID",
            &[
                HashPart::Str(&request.token_class_id),
                HashPart::Str(&request.participant_set_root),
                HashPart::Str(&request.debit_root),
                HashPart::Str(&request.credit_root),
                HashPart::U64(request.cleared_height),
            ],
        );
        let record = TransferNettingCycleRecord {
            netting_id: netting_id.clone(),
            token_class_id: request.token_class_id,
            participant_set_root: request.participant_set_root,
            debit_root: request.debit_root,
            credit_root: request.credit_root,
            net_delta_commitment: request.net_delta_commitment,
            conservation_proof_root: request.conservation_proof_root,
            settled_batch_ids: request.settled_batch_ids.clone(),
            nullifier_root,
            fee_commitment: request.fee_commitment,
            cleared_height: request.cleared_height,
        };
        for batch_id in &request.settled_batch_ids {
            if let Some(batch) = self.shielded_batches.get_mut(batch_id) {
                batch.status = BatchStatus::Netted;
            }
        }
        self.transfer_netting_cycles
            .insert(netting_id, record.clone());
        self.counters.netting_cycles_cleared += 1;
        Ok(record)
    }

    pub fn clear_private_amm(
        &mut self,
        request: PrivateAmmClearingRequest,
    ) -> Result<PrivateAmmClearingRecord> {
        self.ensure_capacity(
            self.amm_clearings.len(),
            self.config.max_amm_clearings,
            "amm clearings",
        )?;
        self.ensure_active_class(&request.token_class_id_a)?;
        self.ensure_active_class(&request.token_class_id_b)?;
        if request.token_class_id_a == request.token_class_id_b {
            return Err("amm clearing requires two distinct token classes".to_string());
        }
        for batch_id in &request.batch_ids {
            if !self.shielded_batches.contains_key(batch_id) {
                return Err(format!("unknown amm batch: {batch_id}"));
            }
        }
        let nullifier_root = records_root(
            "AMM-BATCH-ROOT",
            request
                .batch_ids
                .iter()
                .map(|batch_id| json!({ "batch_id": batch_id }))
                .collect(),
        );
        let clearing_id = deterministic_id(
            "PRIVATE-AMM-CLEARING-ID",
            &[
                HashPart::Str(&request.pool_id),
                HashPart::Str(&request.token_class_id_a),
                HashPart::Str(&request.token_class_id_b),
                HashPart::Str(&request.encrypted_order_root),
                HashPart::U64(request.cleared_height),
            ],
        );
        let record = PrivateAmmClearingRecord {
            clearing_id: clearing_id.clone(),
            pool_id: request.pool_id,
            token_class_id_a: request.token_class_id_a,
            token_class_id_b: request.token_class_id_b,
            encrypted_order_root: request.encrypted_order_root,
            reserve_commitment_before: request.reserve_commitment_before,
            reserve_commitment_after: request.reserve_commitment_after,
            invariant_proof_root: request.invariant_proof_root,
            price_impact_commitment: request.price_impact_commitment,
            fee_commitment: request.fee_commitment,
            rebate_commitment: request.rebate_commitment,
            nullifier_root,
            batch_ids: request.batch_ids.clone(),
            cleared_height: request.cleared_height,
        };
        for batch_id in &request.batch_ids {
            if let Some(batch) = self.shielded_batches.get_mut(batch_id) {
                batch.status = BatchStatus::Cleared;
            }
        }
        self.amm_clearings.insert(clearing_id, record.clone());
        self.counters.amm_clearings_executed += 1;
        Ok(record)
    }

    pub fn install_covenant_guard_rail(
        &mut self,
        request: InstallCovenantGuardRailRequest,
    ) -> Result<CovenantGuardRailRecord> {
        self.ensure_capacity(
            self.covenant_guard_rails.len(),
            self.config.max_guard_rails,
            "covenant guard rails",
        )?;
        self.ensure_active_class(&request.token_class_id)?;
        let guard_id = deterministic_id(
            "COVENANT-GUARD-ID",
            &[
                HashPart::Str(&request.token_class_id),
                HashPart::Str(request.kind.as_str()),
                HashPart::Str(&request.guard_root),
                HashPart::U64(request.installed_height),
            ],
        );
        let record = CovenantGuardRailRecord {
            guard_id: guard_id.clone(),
            token_class_id: request.token_class_id,
            kind: request.kind,
            guard_root: request.guard_root,
            threshold_commitment: request.threshold_commitment,
            enforcement_root: request.enforcement_root,
            installed_by_commitment: request.installed_by_commitment,
            active: true,
            installed_height: request.installed_height,
        };
        self.covenant_guard_rails.insert(guard_id, record.clone());
        self.counters.guard_rails_installed += 1;
        Ok(record)
    }

    pub fn issue_fee_rebate(&mut self, request: IssueFeeRebateRequest) -> Result<FeeRebateRecord> {
        self.ensure_capacity(
            self.fee_rebates.len(),
            self.config.max_rebates,
            "fee rebates",
        )?;
        self.ensure_active_class(&request.token_class_id)?;
        let rebate_id = deterministic_id(
            "FEE-REBATE-ID",
            &[
                HashPart::Str(&request.recipient_commitment),
                HashPart::Str(&request.token_class_id),
                HashPart::Str(&request.source_id),
                HashPart::Str(&request.rebate_commitment),
                HashPart::U64(request.issued_height),
            ],
        );
        let record = FeeRebateRecord {
            rebate_id: rebate_id.clone(),
            recipient_commitment: request.recipient_commitment,
            token_class_id: request.token_class_id,
            source_id: request.source_id,
            fee_commitment: request.fee_commitment,
            rebate_commitment: request.rebate_commitment,
            sponsor_commitment: request.sponsor_commitment,
            proof_root: request.proof_root,
            issued_height: request.issued_height,
        };
        self.fee_rebates.insert(rebate_id, record.clone());
        self.counters.rebates_issued += 1;
        Ok(record)
    }

    pub fn issue_settlement_receipt(
        &mut self,
        request: IssueSettlementReceiptRequest,
    ) -> Result<SettlementReceiptRecord> {
        self.ensure_capacity(
            self.settlement_receipts.len(),
            self.config.max_receipts,
            "settlement receipts",
        )?;
        if !self.shielded_batches.contains_key(&request.batch_id) {
            return Err(format!("unknown receipt batch: {}", request.batch_id));
        }
        let receipt_id = deterministic_id(
            "SETTLEMENT-RECEIPT-ID",
            &[
                HashPart::Str(&request.batch_id),
                HashPart::Str(&request.pre_state_root),
                HashPart::Str(&request.post_state_root),
                HashPart::Str(&request.recursive_proof_root),
                HashPart::U64(request.settled_height),
            ],
        );
        let record = SettlementReceiptRecord {
            receipt_id: receipt_id.clone(),
            batch_id: request.batch_id.clone(),
            status: ReceiptStatus::PendingFinality,
            pre_state_root: request.pre_state_root,
            post_state_root: request.post_state_root,
            recursive_proof_root: request.recursive_proof_root,
            monero_anchor_root: request.monero_anchor_root,
            da_commitment_root: request.da_commitment_root,
            settled_height: request.settled_height,
            finality_height: request.settled_height + self.config.receipt_finality_blocks,
        };
        if let Some(batch) = self.shielded_batches.get_mut(&request.batch_id) {
            batch.status = BatchStatus::Settled;
        }
        self.settlement_receipts.insert(receipt_id, record.clone());
        self.counters.receipts_issued += 1;
        Ok(record)
    }

    pub fn finalize_receipt(&mut self, receipt_id: &str, height: u64) -> Result<()> {
        let receipt = self
            .settlement_receipts
            .get_mut(receipt_id)
            .ok_or_else(|| format!("unknown receipt: {receipt_id}"))?;
        if height < receipt.finality_height {
            receipt.status = ReceiptStatus::ReorgGuarded;
            return Ok(());
        }
        receipt.status = ReceiptStatus::Final;
        Ok(())
    }

    pub fn slash(&mut self, request: SlashRequest) -> Result<SlashingRecord> {
        self.ensure_capacity(self.slashes.len(), self.config.max_slashes, "slashes")?;
        let slash_id = deterministic_id(
            "SLASH-ID",
            &[
                HashPart::Str(&request.offender_commitment),
                HashPart::Str(request.reason.as_str()),
                HashPart::Str(&request.source_id),
                HashPart::Str(&request.evidence_root),
                HashPart::U64(request.applied_height),
            ],
        );
        let record = SlashingRecord {
            slash_id: slash_id.clone(),
            offender_commitment: request.offender_commitment,
            reason: request.reason,
            source_id: request.source_id.clone(),
            evidence_root: request.evidence_root,
            penalty_commitment: request.penalty_commitment,
            beneficiary_commitment: request.beneficiary_commitment,
            applied_height: request.applied_height,
        };
        if let Some(batch) = self.shielded_batches.get_mut(&request.source_id) {
            batch.status = BatchStatus::Slashed;
        }
        self.slashes.insert(slash_id, record.clone());
        self.counters.slash_events += 1;
        Ok(record)
    }

    fn record_privacy_accounting(
        &mut self,
        token_class_id: &str,
        source_id: &str,
        nullifiers: Vec<String>,
        privacy_set_size: u64,
        height: u64,
    ) -> Result<PrivacyAccountingRecord> {
        self.ensure_capacity(
            self.privacy_accounting.len(),
            self.config.max_nullifiers,
            "privacy accounting records",
        )?;
        let nullifier_root = records_root(
            "PRIVACY-NULLIFIER-ROOT",
            nullifiers
                .iter()
                .map(|nullifier| json!({ "nullifier": nullifier }))
                .collect(),
        );
        let accounting_id = deterministic_id(
            "PRIVACY-ACCOUNTING-ID",
            &[
                HashPart::Str(token_class_id),
                HashPart::Str(source_id),
                HashPart::Str(&nullifier_root),
                HashPart::U64(height),
            ],
        );
        let record = PrivacyAccountingRecord {
            accounting_id: accounting_id.clone(),
            token_class_id: token_class_id.to_string(),
            source_id: source_id.to_string(),
            nullifier_root,
            spent_count: nullifiers.len() as u64,
            new_nullifiers: nullifiers,
            privacy_set_size,
            entropy_commitment: int_root("PRIVACY-ENTROPY", privacy_set_size),
            recorded_height: height,
        };
        self.privacy_accounting
            .insert(accounting_id, record.clone());
        self.counters.nullifiers_observed += record.spent_count;
        Ok(record)
    }

    fn ensure_capacity(&self, current: usize, max: usize, label: &str) -> Result<()> {
        if current >= max {
            return Err(format!("{label} capacity exceeded"));
        }
        Ok(())
    }

    fn ensure_active_class(&self, token_class_id: &str) -> Result<()> {
        let class = self
            .token_classes
            .get(token_class_id)
            .ok_or_else(|| format!("unknown token class: {token_class_id}"))?;
        if !class.status.accepts_activity() {
            return Err(format!(
                "token class does not accept activity: {token_class_id}"
            ));
        }
        Ok(())
    }

    fn ensure_authorization(
        &self,
        authorization_id: &str,
        token_class_id: &str,
        height: u64,
    ) -> Result<()> {
        let authorization = self
            .pq_authorizations
            .get(authorization_id)
            .ok_or_else(|| format!("unknown pq authorization: {authorization_id}"))?;
        if authorization.token_class_id != token_class_id {
            return Err("authorization token class mismatch".to_string());
        }
        if authorization.consumed {
            return Err("authorization already consumed".to_string());
        }
        if height < authorization.valid_from_height || height > authorization.expires_at_height {
            return Err("authorization outside validity window".to_string());
        }
        if authorization.min_security_bits < self.config.min_pq_security_bits {
            return Err("authorization below pq security floor".to_string());
        }
        Ok(())
    }

    fn ensure_batch_for_class(&self, batch_id: &str, token_class_id: &str) -> Result<()> {
        let batch = self
            .shielded_batches
            .get(batch_id)
            .ok_or_else(|| format!("unknown shielded batch: {batch_id}"))?;
        if batch.token_class_id != token_class_id {
            return Err("batch token class mismatch".to_string());
        }
        if matches!(
            batch.status,
            BatchStatus::Expired | BatchStatus::Disputed | BatchStatus::Slashed
        ) {
            return Err("batch cannot be netted in current status".to_string());
        }
        Ok(())
    }

    fn ensure_new_nullifiers(&self, nullifiers: &[String]) -> Result<()> {
        let mut seen = BTreeSet::new();
        for nullifier in nullifiers {
            ensure_nonempty(nullifier, "nullifier")?;
            if !seen.insert(nullifier) {
                return Err("duplicate nullifier in request".to_string());
            }
            if self.spent_nullifiers.contains(nullifier) {
                return Err(format!("nullifier already spent: {nullifier}"));
            }
        }
        Ok(())
    }
}

pub fn deterministic_id(domain: &str, parts: &[HashPart<'_>]) -> String {
    domain_hash(
        &format!("PRIVATE-L2-PQ-CONFIDENTIAL-TOKEN-CLEARING-HOUSE:{domain}"),
        parts,
        32,
    )
}

pub fn public_record_root(domain: &str, record: &Value) -> String {
    deterministic_id(domain, &[HashPart::Json(record)])
}

pub fn state_root_from_record(record: &Value) -> String {
    public_record_root("STATE-ROOT", record)
}

pub fn string_root(domain: &str, value: &str) -> String {
    deterministic_id(domain, &[HashPart::Str(value)])
}

pub fn int_root(domain: &str, value: u64) -> String {
    deterministic_id(domain, &[HashPart::U64(value)])
}

pub fn records_root(domain: &str, records: Vec<Value>) -> String {
    merkle_root(
        &format!("PRIVATE-L2-PQ-CONFIDENTIAL-TOKEN-CLEARING-HOUSE:{domain}"),
        &records,
    )
}

fn ensure_nonempty(value: &str, label: &str) -> Result<()> {
    if value.trim().is_empty() {
        return Err(format!("{label} must not be empty"));
    }
    Ok(())
}
