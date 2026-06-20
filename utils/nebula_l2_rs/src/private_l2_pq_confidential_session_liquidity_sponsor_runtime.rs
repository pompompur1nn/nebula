use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2PqConfidentialSessionLiquiditySponsorRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_SESSION_LIQUIDITY_SPONSOR_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-confidential-session-liquidity-sponsor-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_SESSION_LIQUIDITY_SPONSOR_RUNTIME_PROTOCOL_VERSION;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_SESSION_LIQUIDITY_SPONSOR_RUNTIME_SCHEMA_VERSION: u64 = 1;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_SESSION_LIQUIDITY_SPONSOR_RUNTIME_DEVNET_HEIGHT: u64 =
    1_276_000;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_SESSION_LIQUIDITY_SPONSOR_RUNTIME_DEVNET_L2_NETWORK: &str =
    "nebula-devnet";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_SESSION_LIQUIDITY_SPONSOR_RUNTIME_DEVNET_MONERO_NETWORK: &str =
    "monero-devnet";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_SESSION_LIQUIDITY_SPONSOR_RUNTIME_DEFAULT_FEE_ASSET_ID: &str =
    "piconero-devnet";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_SESSION_LIQUIDITY_SPONSOR_RUNTIME_HASH_SUITE: &str =
    "SHAKE256-domain-separated-canonical-json";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_SESSION_LIQUIDITY_SPONSOR_RUNTIME_PQ_AUTH_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-confidential-session-liquidity-sponsor-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_SESSION_LIQUIDITY_SPONSOR_RUNTIME_POOL_SCHEME: &str =
    "sealed-confidential-session-sponsor-pool-root-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_SESSION_LIQUIDITY_SPONSOR_RUNTIME_COMMITMENT_SCHEME: &str =
    "sealed-liquidity-sponsorship-commitment-root-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_SESSION_LIQUIDITY_SPONSOR_RUNTIME_PROOF_SCHEME: &str =
    "pq-user-session-sponsor-proof-root-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_SESSION_LIQUIDITY_SPONSOR_RUNTIME_RESERVATION_SCHEME: &str =
    "private-session-liquidity-reservation-root-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_SESSION_LIQUIDITY_SPONSOR_RUNTIME_BATCH_SCHEME: &str =
    "sponsored-confidential-session-settlement-batch-root-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_SESSION_LIQUIDITY_SPONSOR_RUNTIME_REBATE_SCHEME: &str =
    "low-fee-confidential-session-rebate-root-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_SESSION_LIQUIDITY_SPONSOR_RUNTIME_PRIVACY_SET_SCHEME: &str =
    "session-liquidity-sponsor-privacy-set-accounting-root-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_SESSION_LIQUIDITY_SPONSOR_RUNTIME_SLASHING_SCHEME: &str =
    "invalid-session-sponsor-proof-slashing-root-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_SESSION_LIQUIDITY_SPONSOR_RUNTIME_DEFAULT_MAX_POOLS: usize =
    1_048_576;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_SESSION_LIQUIDITY_SPONSOR_RUNTIME_DEFAULT_MAX_COMMITMENTS:
    usize = 8_388_608;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_SESSION_LIQUIDITY_SPONSOR_RUNTIME_DEFAULT_MAX_PROOFS: usize =
    8_388_608;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_SESSION_LIQUIDITY_SPONSOR_RUNTIME_DEFAULT_MAX_RESERVATIONS:
    usize = 8_388_608;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_SESSION_LIQUIDITY_SPONSOR_RUNTIME_DEFAULT_MAX_BATCHES: usize =
    1_048_576;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_SESSION_LIQUIDITY_SPONSOR_RUNTIME_DEFAULT_MAX_REBATES: usize =
    4_194_304;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_SESSION_LIQUIDITY_SPONSOR_RUNTIME_DEFAULT_MAX_PRIVACY_EPOCHS:
    usize = 524_288;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_SESSION_LIQUIDITY_SPONSOR_RUNTIME_DEFAULT_MAX_SLASHES: usize =
    1_048_576;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_SESSION_LIQUIDITY_SPONSOR_RUNTIME_DEFAULT_MAX_BATCH_ITEMS:
    usize = 16_384;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_SESSION_LIQUIDITY_SPONSOR_RUNTIME_DEFAULT_COMMITMENT_TTL_BLOCKS:
    u64 = 96;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_SESSION_LIQUIDITY_SPONSOR_RUNTIME_DEFAULT_PROOF_TTL_BLOCKS:
    u64 = 128;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_SESSION_LIQUIDITY_SPONSOR_RUNTIME_DEFAULT_RESERVATION_TTL_BLOCKS:
    u64 = 32;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_SESSION_LIQUIDITY_SPONSOR_RUNTIME_DEFAULT_BATCH_TTL_BLOCKS:
    u64 = 48;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_SESSION_LIQUIDITY_SPONSOR_RUNTIME_DEFAULT_MIN_PRIVACY_SET_SIZE:
    u64 = 65_536;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_SESSION_LIQUIDITY_SPONSOR_RUNTIME_DEFAULT_BATCH_PRIVACY_SET_SIZE:
    u64 = 262_144;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_SESSION_LIQUIDITY_SPONSOR_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS:
    u16 = 256;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_SESSION_LIQUIDITY_SPONSOR_RUNTIME_DEFAULT_MAX_USER_FEE_BPS:
    u64 = 8;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_SESSION_LIQUIDITY_SPONSOR_RUNTIME_DEFAULT_MAX_SPONSOR_FEE_BPS:
    u64 = 6;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_SESSION_LIQUIDITY_SPONSOR_RUNTIME_DEFAULT_TARGET_REBATE_BPS:
    u64 = 4;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_SESSION_LIQUIDITY_SPONSOR_RUNTIME_DEFAULT_SLASHING_PENALTY_BPS:
    u64 = 1_500;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_SESSION_LIQUIDITY_SPONSOR_RUNTIME_MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorPoolKind {
    UniversalSession,
    ContractCall,
    DefiSwap,
    Lending,
    Perpetuals,
    ConfidentialToken,
    StableAsset,
    BridgeExit,
    EmergencyEscape,
}

impl SponsorPoolKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::UniversalSession => "universal_session",
            Self::ContractCall => "contract_call",
            Self::DefiSwap => "defi_swap",
            Self::Lending => "lending",
            Self::Perpetuals => "perpetuals",
            Self::ConfidentialToken => "confidential_token",
            Self::StableAsset => "stable_asset",
            Self::BridgeExit => "bridge_exit",
            Self::EmergencyEscape => "emergency_escape",
        }
    }

    pub fn defi(self) -> bool {
        matches!(
            self,
            Self::DefiSwap | Self::Lending | Self::Perpetuals | Self::StableAsset
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PoolStatus {
    Registered,
    Active,
    Paused,
    Draining,
    Exhausted,
    Slashed,
    Closed,
}

impl PoolStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Registered => "registered",
            Self::Active => "active",
            Self::Paused => "paused",
            Self::Draining => "draining",
            Self::Exhausted => "exhausted",
            Self::Slashed => "slashed",
            Self::Closed => "closed",
        }
    }

    pub fn accepts_commitments(self) -> bool {
        matches!(self, Self::Registered | Self::Active)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionLane {
    PrivateContractCall,
    ConfidentialSwap,
    ConfidentialLending,
    ConfidentialPerps,
    ConfidentialTokenTransfer,
    PrivateStablecoinPayment,
    MoneroExit,
    ProofPublication,
    WalletRecovery,
}

impl SessionLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrivateContractCall => "private_contract_call",
            Self::ConfidentialSwap => "confidential_swap",
            Self::ConfidentialLending => "confidential_lending",
            Self::ConfidentialPerps => "confidential_perps",
            Self::ConfidentialTokenTransfer => "confidential_token_transfer",
            Self::PrivateStablecoinPayment => "private_stablecoin_payment",
            Self::MoneroExit => "monero_exit",
            Self::ProofPublication => "proof_publication",
            Self::WalletRecovery => "wallet_recovery",
        }
    }

    pub fn high_priority(self) -> bool {
        matches!(
            self,
            Self::ConfidentialSwap
                | Self::ConfidentialPerps
                | Self::PrivateContractCall
                | Self::WalletRecovery
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CommitmentStatus {
    Posted,
    ProofAttached,
    Reserved,
    Batched,
    Settled,
    Rebated,
    Expired,
    Rejected,
    Slashed,
}

impl CommitmentStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Posted => "posted",
            Self::ProofAttached => "proof_attached",
            Self::Reserved => "reserved",
            Self::Batched => "batched",
            Self::Settled => "settled",
            Self::Rebated => "rebated",
            Self::Expired => "expired",
            Self::Rejected => "rejected",
            Self::Slashed => "slashed",
        }
    }

    pub fn reservable(self) -> bool {
        matches!(self, Self::Posted | Self::ProofAttached)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofKind {
    PqUserSession,
    PqDelegatedSession,
    PqPaymasterPolicy,
    LiquidityAllowance,
    ConfidentialSpendLimit,
    ReplayFence,
    SponsorEligibility,
    BatchSettlement,
}

impl ProofKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PqUserSession => "pq_user_session",
            Self::PqDelegatedSession => "pq_delegated_session",
            Self::PqPaymasterPolicy => "pq_paymaster_policy",
            Self::LiquidityAllowance => "liquidity_allowance",
            Self::ConfidentialSpendLimit => "confidential_spend_limit",
            Self::ReplayFence => "replay_fence",
            Self::SponsorEligibility => "sponsor_eligibility",
            Self::BatchSettlement => "batch_settlement",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofStatus {
    Submitted,
    Verified,
    Linked,
    Consumed,
    Rejected,
    Expired,
    Slashed,
}

impl ProofStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Verified => "verified",
            Self::Linked => "linked",
            Self::Consumed => "consumed",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
            Self::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReservationStatus {
    Reserved,
    Executing,
    Batched,
    Settled,
    Rebated,
    Expired,
    Slashed,
}

impl ReservationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Executing => "executing",
            Self::Batched => "batched",
            Self::Settled => "settled",
            Self::Rebated => "rebated",
            Self::Expired => "expired",
            Self::Slashed => "slashed",
        }
    }

    pub fn can_settle(self) -> bool {
        matches!(self, Self::Reserved | Self::Executing | Self::Batched)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchStatus {
    Open,
    SettlementReady,
    Settled,
    Rebated,
    Disputed,
    Expired,
    Slashed,
}

impl BatchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::SettlementReady => "settlement_ready",
            Self::Settled => "settled",
            Self::Rebated => "rebated",
            Self::Disputed => "disputed",
            Self::Expired => "expired",
            Self::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RebateStatus {
    Issued,
    Claimed,
    Netted,
    Expired,
    Slashed,
}

impl RebateStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Issued => "issued",
            Self::Claimed => "claimed",
            Self::Netted => "netted",
            Self::Expired => "expired",
            Self::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivacySetKind {
    SessionCommitment,
    SponsorPool,
    PqProof,
    Reservation,
    SettlementBatch,
    Rebate,
    Slashing,
}

impl PrivacySetKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SessionCommitment => "session_commitment",
            Self::SponsorPool => "sponsor_pool",
            Self::PqProof => "pq_proof",
            Self::Reservation => "reservation",
            Self::SettlementBatch => "settlement_batch",
            Self::Rebate => "rebate",
            Self::Slashing => "slashing",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SlashKind {
    InvalidPqProof,
    DoubleReservedNullifier,
    UnderfundedSponsorship,
    ExpiredCommitmentUsed,
    InvalidSettlementWitness,
    PrivacySetUnderflow,
    FeePolicyViolation,
}

impl SlashKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidPqProof => "invalid_pq_proof",
            Self::DoubleReservedNullifier => "double_reserved_nullifier",
            Self::UnderfundedSponsorship => "underfunded_sponsorship",
            Self::ExpiredCommitmentUsed => "expired_commitment_used",
            Self::InvalidSettlementWitness => "invalid_settlement_witness",
            Self::PrivacySetUnderflow => "privacy_set_underflow",
            Self::FeePolicyViolation => "fee_policy_violation",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub l2_network: String,
    pub monero_network: String,
    pub fee_asset_id: String,
    pub max_pools: usize,
    pub max_commitments: usize,
    pub max_proofs: usize,
    pub max_reservations: usize,
    pub max_batches: usize,
    pub max_rebates: usize,
    pub max_privacy_epochs: usize,
    pub max_slashes: usize,
    pub max_batch_items: usize,
    pub commitment_ttl_blocks: u64,
    pub proof_ttl_blocks: u64,
    pub reservation_ttl_blocks: u64,
    pub batch_ttl_blocks: u64,
    pub min_privacy_set_size: u64,
    pub batch_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub max_user_fee_bps: u64,
    pub max_sponsor_fee_bps: u64,
    pub target_rebate_bps: u64,
    pub slashing_penalty_bps: u64,
    pub require_pq_proof: bool,
    pub require_replay_fence: bool,
    pub require_confidential_amounts: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            l2_network:
                PRIVATE_L2_PQ_CONFIDENTIAL_SESSION_LIQUIDITY_SPONSOR_RUNTIME_DEVNET_L2_NETWORK
                    .to_string(),
            monero_network:
                PRIVATE_L2_PQ_CONFIDENTIAL_SESSION_LIQUIDITY_SPONSOR_RUNTIME_DEVNET_MONERO_NETWORK
                    .to_string(),
            fee_asset_id:
                PRIVATE_L2_PQ_CONFIDENTIAL_SESSION_LIQUIDITY_SPONSOR_RUNTIME_DEFAULT_FEE_ASSET_ID
                    .to_string(),
            max_pools: PRIVATE_L2_PQ_CONFIDENTIAL_SESSION_LIQUIDITY_SPONSOR_RUNTIME_DEFAULT_MAX_POOLS,
            max_commitments:
                PRIVATE_L2_PQ_CONFIDENTIAL_SESSION_LIQUIDITY_SPONSOR_RUNTIME_DEFAULT_MAX_COMMITMENTS,
            max_proofs:
                PRIVATE_L2_PQ_CONFIDENTIAL_SESSION_LIQUIDITY_SPONSOR_RUNTIME_DEFAULT_MAX_PROOFS,
            max_reservations:
                PRIVATE_L2_PQ_CONFIDENTIAL_SESSION_LIQUIDITY_SPONSOR_RUNTIME_DEFAULT_MAX_RESERVATIONS,
            max_batches:
                PRIVATE_L2_PQ_CONFIDENTIAL_SESSION_LIQUIDITY_SPONSOR_RUNTIME_DEFAULT_MAX_BATCHES,
            max_rebates:
                PRIVATE_L2_PQ_CONFIDENTIAL_SESSION_LIQUIDITY_SPONSOR_RUNTIME_DEFAULT_MAX_REBATES,
            max_privacy_epochs:
                PRIVATE_L2_PQ_CONFIDENTIAL_SESSION_LIQUIDITY_SPONSOR_RUNTIME_DEFAULT_MAX_PRIVACY_EPOCHS,
            max_slashes:
                PRIVATE_L2_PQ_CONFIDENTIAL_SESSION_LIQUIDITY_SPONSOR_RUNTIME_DEFAULT_MAX_SLASHES,
            max_batch_items:
                PRIVATE_L2_PQ_CONFIDENTIAL_SESSION_LIQUIDITY_SPONSOR_RUNTIME_DEFAULT_MAX_BATCH_ITEMS,
            commitment_ttl_blocks:
                PRIVATE_L2_PQ_CONFIDENTIAL_SESSION_LIQUIDITY_SPONSOR_RUNTIME_DEFAULT_COMMITMENT_TTL_BLOCKS,
            proof_ttl_blocks:
                PRIVATE_L2_PQ_CONFIDENTIAL_SESSION_LIQUIDITY_SPONSOR_RUNTIME_DEFAULT_PROOF_TTL_BLOCKS,
            reservation_ttl_blocks:
                PRIVATE_L2_PQ_CONFIDENTIAL_SESSION_LIQUIDITY_SPONSOR_RUNTIME_DEFAULT_RESERVATION_TTL_BLOCKS,
            batch_ttl_blocks:
                PRIVATE_L2_PQ_CONFIDENTIAL_SESSION_LIQUIDITY_SPONSOR_RUNTIME_DEFAULT_BATCH_TTL_BLOCKS,
            min_privacy_set_size:
                PRIVATE_L2_PQ_CONFIDENTIAL_SESSION_LIQUIDITY_SPONSOR_RUNTIME_DEFAULT_MIN_PRIVACY_SET_SIZE,
            batch_privacy_set_size:
                PRIVATE_L2_PQ_CONFIDENTIAL_SESSION_LIQUIDITY_SPONSOR_RUNTIME_DEFAULT_BATCH_PRIVACY_SET_SIZE,
            min_pq_security_bits:
                PRIVATE_L2_PQ_CONFIDENTIAL_SESSION_LIQUIDITY_SPONSOR_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS,
            max_user_fee_bps:
                PRIVATE_L2_PQ_CONFIDENTIAL_SESSION_LIQUIDITY_SPONSOR_RUNTIME_DEFAULT_MAX_USER_FEE_BPS,
            max_sponsor_fee_bps:
                PRIVATE_L2_PQ_CONFIDENTIAL_SESSION_LIQUIDITY_SPONSOR_RUNTIME_DEFAULT_MAX_SPONSOR_FEE_BPS,
            target_rebate_bps:
                PRIVATE_L2_PQ_CONFIDENTIAL_SESSION_LIQUIDITY_SPONSOR_RUNTIME_DEFAULT_TARGET_REBATE_BPS,
            slashing_penalty_bps:
                PRIVATE_L2_PQ_CONFIDENTIAL_SESSION_LIQUIDITY_SPONSOR_RUNTIME_DEFAULT_SLASHING_PENALTY_BPS,
            require_pq_proof: true,
            require_replay_fence: true,
            require_confidential_amounts: true,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "l2_network": self.l2_network,
            "monero_network": self.monero_network,
            "fee_asset_id": self.fee_asset_id,
            "max_pools": self.max_pools,
            "max_commitments": self.max_commitments,
            "max_proofs": self.max_proofs,
            "max_reservations": self.max_reservations,
            "max_batches": self.max_batches,
            "max_rebates": self.max_rebates,
            "max_privacy_epochs": self.max_privacy_epochs,
            "max_slashes": self.max_slashes,
            "max_batch_items": self.max_batch_items,
            "commitment_ttl_blocks": self.commitment_ttl_blocks,
            "proof_ttl_blocks": self.proof_ttl_blocks,
            "reservation_ttl_blocks": self.reservation_ttl_blocks,
            "batch_ttl_blocks": self.batch_ttl_blocks,
            "min_privacy_set_size": self.min_privacy_set_size,
            "batch_privacy_set_size": self.batch_privacy_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
            "max_user_fee_bps": self.max_user_fee_bps,
            "max_sponsor_fee_bps": self.max_sponsor_fee_bps,
            "target_rebate_bps": self.target_rebate_bps,
            "slashing_penalty_bps": self.slashing_penalty_bps,
            "require_pq_proof": self.require_pq_proof,
            "require_replay_fence": self.require_replay_fence,
            "require_confidential_amounts": self.require_confidential_amounts,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub pools_registered: u64,
    pub commitments_posted: u64,
    pub pq_proofs_attached: u64,
    pub reservations_made: u64,
    pub batches_settled: u64,
    pub rebates_issued: u64,
    pub privacy_epochs_accounted: u64,
    pub invalid_proofs_slashed: u64,
    pub sponsored_notional_micro_units: u64,
    pub reserved_liquidity_micro_units: u64,
    pub settled_liquidity_micro_units: u64,
    pub rebated_fee_micro_units: u64,
    pub slashed_bond_micro_units: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "pools_registered": self.pools_registered,
            "commitments_posted": self.commitments_posted,
            "pq_proofs_attached": self.pq_proofs_attached,
            "reservations_made": self.reservations_made,
            "batches_settled": self.batches_settled,
            "rebates_issued": self.rebates_issued,
            "privacy_epochs_accounted": self.privacy_epochs_accounted,
            "invalid_proofs_slashed": self.invalid_proofs_slashed,
            "sponsored_notional_micro_units": self.sponsored_notional_micro_units,
            "reserved_liquidity_micro_units": self.reserved_liquidity_micro_units,
            "settled_liquidity_micro_units": self.settled_liquidity_micro_units,
            "rebated_fee_micro_units": self.rebated_fee_micro_units,
            "slashed_bond_micro_units": self.slashed_bond_micro_units,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub pool_root: String,
    pub commitment_root: String,
    pub proof_root: String,
    pub reservation_root: String,
    pub batch_root: String,
    pub rebate_root: String,
    pub privacy_set_root: String,
    pub nullifier_root: String,
    pub slashing_root: String,
    pub config_root: String,
    pub counters_root: String,
    pub public_record_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "pool_root": self.pool_root,
            "commitment_root": self.commitment_root,
            "proof_root": self.proof_root,
            "reservation_root": self.reservation_root,
            "batch_root": self.batch_root,
            "rebate_root": self.rebate_root,
            "privacy_set_root": self.privacy_set_root,
            "nullifier_root": self.nullifier_root,
            "slashing_root": self.slashing_root,
            "config_root": self.config_root,
            "counters_root": self.counters_root,
            "public_record_root": self.public_record_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RegisterSponsorPoolRequest {
    pub kind: SponsorPoolKind,
    pub sponsor_commitment: String,
    pub operator_commitment: String,
    pub asset_root: String,
    pub liquidity_note_root: String,
    pub fee_policy_root: String,
    pub eligibility_root: String,
    pub risk_policy_root: String,
    pub total_liquidity_micro_units: u64,
    pub sponsor_bond_micro_units: u64,
    pub max_sponsor_fee_bps: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub opened_at_height: u64,
    pub nonce: u64,
}

impl RegisterSponsorPoolRequest {
    pub fn validate(&self, config: &Config) -> Result<()> {
        ensure_non_empty("sponsor commitment", &self.sponsor_commitment)?;
        ensure_non_empty("operator commitment", &self.operator_commitment)?;
        ensure_root("asset root", &self.asset_root)?;
        ensure_root("liquidity note root", &self.liquidity_note_root)?;
        ensure_root("fee policy root", &self.fee_policy_root)?;
        ensure_root("eligibility root", &self.eligibility_root)?;
        ensure_root("risk policy root", &self.risk_policy_root)?;
        ensure_bps("max sponsor fee bps", self.max_sponsor_fee_bps)?;
        if self.max_sponsor_fee_bps > config.max_sponsor_fee_bps {
            return Err("sponsor pool fee exceeds configured maximum".to_string());
        }
        ensure_min_privacy(config, self.privacy_set_size, false)?;
        ensure_pq(config, self.pq_security_bits)?;
        if self.total_liquidity_micro_units == 0 {
            return Err("sponsor pool liquidity must be non-zero".to_string());
        }
        if self.sponsor_bond_micro_units == 0 {
            return Err("sponsor bond must be non-zero".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": self.kind.as_str(),
            "sponsor_commitment": self.sponsor_commitment,
            "operator_commitment": self.operator_commitment,
            "asset_root": self.asset_root,
            "liquidity_note_root": self.liquidity_note_root,
            "fee_policy_root": self.fee_policy_root,
            "eligibility_root": self.eligibility_root,
            "risk_policy_root": self.risk_policy_root,
            "total_liquidity_micro_units": self.total_liquidity_micro_units,
            "sponsor_bond_micro_units": self.sponsor_bond_micro_units,
            "max_sponsor_fee_bps": self.max_sponsor_fee_bps,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "opened_at_height": self.opened_at_height,
            "nonce": self.nonce,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SponsorPoolRecord {
    pub pool_id: String,
    pub status: PoolStatus,
    pub kind: SponsorPoolKind,
    pub sponsor_commitment: String,
    pub operator_commitment: String,
    pub asset_root: String,
    pub liquidity_note_root: String,
    pub fee_policy_root: String,
    pub eligibility_root: String,
    pub risk_policy_root: String,
    pub total_liquidity_micro_units: u64,
    pub available_liquidity_micro_units: u64,
    pub reserved_liquidity_micro_units: u64,
    pub settled_liquidity_micro_units: u64,
    pub fees_earned_micro_units: u64,
    pub rebates_paid_micro_units: u64,
    pub sponsor_bond_micro_units: u64,
    pub slashed_micro_units: u64,
    pub max_sponsor_fee_bps: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub opened_at_height: u64,
    pub last_activity_height: u64,
    pub nonce: u64,
}

impl SponsorPoolRecord {
    pub fn from_request(pool_id: String, request: RegisterSponsorPoolRequest) -> Self {
        Self {
            pool_id,
            status: PoolStatus::Registered,
            kind: request.kind,
            sponsor_commitment: request.sponsor_commitment,
            operator_commitment: request.operator_commitment,
            asset_root: request.asset_root,
            liquidity_note_root: request.liquidity_note_root,
            fee_policy_root: request.fee_policy_root,
            eligibility_root: request.eligibility_root,
            risk_policy_root: request.risk_policy_root,
            total_liquidity_micro_units: request.total_liquidity_micro_units,
            available_liquidity_micro_units: request.total_liquidity_micro_units,
            reserved_liquidity_micro_units: 0,
            settled_liquidity_micro_units: 0,
            fees_earned_micro_units: 0,
            rebates_paid_micro_units: 0,
            sponsor_bond_micro_units: request.sponsor_bond_micro_units,
            slashed_micro_units: 0,
            max_sponsor_fee_bps: request.max_sponsor_fee_bps,
            privacy_set_size: request.privacy_set_size,
            pq_security_bits: request.pq_security_bits,
            opened_at_height: request.opened_at_height,
            last_activity_height: request.opened_at_height,
            nonce: request.nonce,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "pool_id": self.pool_id,
            "status": self.status.as_str(),
            "kind": self.kind.as_str(),
            "sponsor_commitment": self.sponsor_commitment,
            "operator_commitment": self.operator_commitment,
            "asset_root": self.asset_root,
            "liquidity_note_root": self.liquidity_note_root,
            "fee_policy_root": self.fee_policy_root,
            "eligibility_root": self.eligibility_root,
            "risk_policy_root": self.risk_policy_root,
            "total_liquidity_micro_units": self.total_liquidity_micro_units,
            "available_liquidity_micro_units": self.available_liquidity_micro_units,
            "reserved_liquidity_micro_units": self.reserved_liquidity_micro_units,
            "settled_liquidity_micro_units": self.settled_liquidity_micro_units,
            "fees_earned_micro_units": self.fees_earned_micro_units,
            "rebates_paid_micro_units": self.rebates_paid_micro_units,
            "sponsor_bond_micro_units": self.sponsor_bond_micro_units,
            "slashed_micro_units": self.slashed_micro_units,
            "max_sponsor_fee_bps": self.max_sponsor_fee_bps,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "opened_at_height": self.opened_at_height,
            "last_activity_height": self.last_activity_height,
            "nonce": self.nonce,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PostSealedLiquiditySponsorshipCommitmentRequest {
    pub pool_id: String,
    pub lane: SessionLane,
    pub user_commitment: String,
    pub session_commitment: String,
    pub contract_commitment: String,
    pub call_policy_root: String,
    pub sealed_amount_root: String,
    pub fee_limit_root: String,
    pub privacy_hint_root: String,
    pub session_nullifier: String,
    pub max_user_fee_bps: u64,
    pub requested_liquidity_micro_units: u64,
    pub privacy_set_size: u64,
    pub posted_at_height: u64,
    pub expires_at_height: u64,
    pub nonce: u64,
}

impl PostSealedLiquiditySponsorshipCommitmentRequest {
    pub fn validate(&self, config: &Config) -> Result<()> {
        ensure_non_empty("pool id", &self.pool_id)?;
        ensure_non_empty("user commitment", &self.user_commitment)?;
        ensure_non_empty("session commitment", &self.session_commitment)?;
        ensure_non_empty("contract commitment", &self.contract_commitment)?;
        ensure_root("call policy root", &self.call_policy_root)?;
        ensure_root("sealed amount root", &self.sealed_amount_root)?;
        ensure_root("fee limit root", &self.fee_limit_root)?;
        ensure_root("privacy hint root", &self.privacy_hint_root)?;
        ensure_non_empty("session nullifier", &self.session_nullifier)?;
        ensure_bps("max user fee bps", self.max_user_fee_bps)?;
        if self.max_user_fee_bps > config.max_user_fee_bps {
            return Err("session user fee exceeds configured maximum".to_string());
        }
        if self.requested_liquidity_micro_units == 0 {
            return Err("requested liquidity must be non-zero".to_string());
        }
        ensure_min_privacy(config, self.privacy_set_size, false)?;
        ensure_expiry(
            "commitment",
            self.posted_at_height,
            self.expires_at_height,
            config.commitment_ttl_blocks,
        )?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "pool_id": self.pool_id,
            "lane": self.lane.as_str(),
            "user_commitment": self.user_commitment,
            "session_commitment": self.session_commitment,
            "contract_commitment": self.contract_commitment,
            "call_policy_root": self.call_policy_root,
            "sealed_amount_root": self.sealed_amount_root,
            "fee_limit_root": self.fee_limit_root,
            "privacy_hint_root": self.privacy_hint_root,
            "session_nullifier": self.session_nullifier,
            "max_user_fee_bps": self.max_user_fee_bps,
            "requested_liquidity_micro_units": self.requested_liquidity_micro_units,
            "privacy_set_size": self.privacy_set_size,
            "posted_at_height": self.posted_at_height,
            "expires_at_height": self.expires_at_height,
            "nonce": self.nonce,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SponsorshipCommitmentRecord {
    pub commitment_id: String,
    pub status: CommitmentStatus,
    pub pool_id: String,
    pub lane: SessionLane,
    pub user_commitment: String,
    pub session_commitment: String,
    pub contract_commitment: String,
    pub call_policy_root: String,
    pub sealed_amount_root: String,
    pub fee_limit_root: String,
    pub privacy_hint_root: String,
    pub session_nullifier: String,
    pub proof_ids: Vec<String>,
    pub reservation_id: String,
    pub batch_id: String,
    pub rebate_id: String,
    pub max_user_fee_bps: u64,
    pub requested_liquidity_micro_units: u64,
    pub reserved_liquidity_micro_units: u64,
    pub settled_liquidity_micro_units: u64,
    pub charged_fee_micro_units: u64,
    pub privacy_set_size: u64,
    pub posted_at_height: u64,
    pub expires_at_height: u64,
    pub settled_at_height: u64,
    pub nonce: u64,
}

impl SponsorshipCommitmentRecord {
    pub fn from_request(
        commitment_id: String,
        request: PostSealedLiquiditySponsorshipCommitmentRequest,
    ) -> Self {
        Self {
            commitment_id,
            status: CommitmentStatus::Posted,
            pool_id: request.pool_id,
            lane: request.lane,
            user_commitment: request.user_commitment,
            session_commitment: request.session_commitment,
            contract_commitment: request.contract_commitment,
            call_policy_root: request.call_policy_root,
            sealed_amount_root: request.sealed_amount_root,
            fee_limit_root: request.fee_limit_root,
            privacy_hint_root: request.privacy_hint_root,
            session_nullifier: request.session_nullifier,
            proof_ids: Vec::new(),
            reservation_id: String::new(),
            batch_id: String::new(),
            rebate_id: String::new(),
            max_user_fee_bps: request.max_user_fee_bps,
            requested_liquidity_micro_units: request.requested_liquidity_micro_units,
            reserved_liquidity_micro_units: 0,
            settled_liquidity_micro_units: 0,
            charged_fee_micro_units: 0,
            privacy_set_size: request.privacy_set_size,
            posted_at_height: request.posted_at_height,
            expires_at_height: request.expires_at_height,
            settled_at_height: 0,
            nonce: request.nonce,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "commitment_id": self.commitment_id,
            "status": self.status.as_str(),
            "pool_id": self.pool_id,
            "lane": self.lane.as_str(),
            "user_commitment": self.user_commitment,
            "session_commitment": self.session_commitment,
            "contract_commitment": self.contract_commitment,
            "call_policy_root": self.call_policy_root,
            "sealed_amount_root": self.sealed_amount_root,
            "fee_limit_root": self.fee_limit_root,
            "privacy_hint_root": self.privacy_hint_root,
            "session_nullifier": self.session_nullifier,
            "proof_ids": self.proof_ids,
            "reservation_id": self.reservation_id,
            "batch_id": self.batch_id,
            "rebate_id": self.rebate_id,
            "max_user_fee_bps": self.max_user_fee_bps,
            "requested_liquidity_micro_units": self.requested_liquidity_micro_units,
            "reserved_liquidity_micro_units": self.reserved_liquidity_micro_units,
            "settled_liquidity_micro_units": self.settled_liquidity_micro_units,
            "charged_fee_micro_units": self.charged_fee_micro_units,
            "privacy_set_size": self.privacy_set_size,
            "posted_at_height": self.posted_at_height,
            "expires_at_height": self.expires_at_height,
            "settled_at_height": self.settled_at_height,
            "nonce": self.nonce,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AttachPqUserSessionProofRequest {
    pub kind: ProofKind,
    pub commitment_id: String,
    pub signer_commitment: String,
    pub pq_public_key_root: String,
    pub session_proof_root: String,
    pub liquidity_authorization_root: String,
    pub replay_fence_root: String,
    pub policy_witness_root: String,
    pub proof_nullifier: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub attached_at_height: u64,
    pub expires_at_height: u64,
    pub nonce: u64,
}

impl AttachPqUserSessionProofRequest {
    pub fn validate(&self, config: &Config) -> Result<()> {
        ensure_non_empty("commitment id", &self.commitment_id)?;
        ensure_non_empty("signer commitment", &self.signer_commitment)?;
        ensure_root("pq public key root", &self.pq_public_key_root)?;
        ensure_root("session proof root", &self.session_proof_root)?;
        ensure_root(
            "liquidity authorization root",
            &self.liquidity_authorization_root,
        )?;
        ensure_root("replay fence root", &self.replay_fence_root)?;
        ensure_root("policy witness root", &self.policy_witness_root)?;
        ensure_non_empty("proof nullifier", &self.proof_nullifier)?;
        ensure_min_privacy(config, self.privacy_set_size, false)?;
        ensure_pq(config, self.pq_security_bits)?;
        ensure_expiry(
            "proof",
            self.attached_at_height,
            self.expires_at_height,
            config.proof_ttl_blocks,
        )?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": self.kind.as_str(),
            "commitment_id": self.commitment_id,
            "signer_commitment": self.signer_commitment,
            "pq_public_key_root": self.pq_public_key_root,
            "session_proof_root": self.session_proof_root,
            "liquidity_authorization_root": self.liquidity_authorization_root,
            "replay_fence_root": self.replay_fence_root,
            "policy_witness_root": self.policy_witness_root,
            "proof_nullifier": self.proof_nullifier,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "attached_at_height": self.attached_at_height,
            "expires_at_height": self.expires_at_height,
            "nonce": self.nonce,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqUserSessionProofRecord {
    pub proof_id: String,
    pub status: ProofStatus,
    pub kind: ProofKind,
    pub commitment_id: String,
    pub signer_commitment: String,
    pub pq_public_key_root: String,
    pub session_proof_root: String,
    pub liquidity_authorization_root: String,
    pub replay_fence_root: String,
    pub policy_witness_root: String,
    pub proof_nullifier: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub attached_at_height: u64,
    pub expires_at_height: u64,
    pub consumed_at_height: u64,
    pub nonce: u64,
}

impl PqUserSessionProofRecord {
    pub fn from_request(proof_id: String, request: AttachPqUserSessionProofRequest) -> Self {
        Self {
            proof_id,
            status: ProofStatus::Submitted,
            kind: request.kind,
            commitment_id: request.commitment_id,
            signer_commitment: request.signer_commitment,
            pq_public_key_root: request.pq_public_key_root,
            session_proof_root: request.session_proof_root,
            liquidity_authorization_root: request.liquidity_authorization_root,
            replay_fence_root: request.replay_fence_root,
            policy_witness_root: request.policy_witness_root,
            proof_nullifier: request.proof_nullifier,
            privacy_set_size: request.privacy_set_size,
            pq_security_bits: request.pq_security_bits,
            attached_at_height: request.attached_at_height,
            expires_at_height: request.expires_at_height,
            consumed_at_height: 0,
            nonce: request.nonce,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "proof_id": self.proof_id,
            "status": self.status.as_str(),
            "kind": self.kind.as_str(),
            "commitment_id": self.commitment_id,
            "signer_commitment": self.signer_commitment,
            "pq_public_key_root": self.pq_public_key_root,
            "session_proof_root": self.session_proof_root,
            "liquidity_authorization_root": self.liquidity_authorization_root,
            "replay_fence_root": self.replay_fence_root,
            "policy_witness_root": self.policy_witness_root,
            "proof_nullifier": self.proof_nullifier,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "attached_at_height": self.attached_at_height,
            "expires_at_height": self.expires_at_height,
            "consumed_at_height": self.consumed_at_height,
            "nonce": self.nonce,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReserveSessionLiquidityRequest {
    pub commitment_id: String,
    pub proof_id: String,
    pub pool_id: String,
    pub reservation_note_root: String,
    pub encrypted_route_root: String,
    pub liquidity_receipt_root: String,
    pub reserved_liquidity_micro_units: u64,
    pub sponsor_fee_bps: u64,
    pub privacy_set_size: u64,
    pub reserved_at_height: u64,
    pub expires_at_height: u64,
    pub nonce: u64,
}

impl ReserveSessionLiquidityRequest {
    pub fn validate(&self, config: &Config) -> Result<()> {
        ensure_non_empty("commitment id", &self.commitment_id)?;
        ensure_non_empty("proof id", &self.proof_id)?;
        ensure_non_empty("pool id", &self.pool_id)?;
        ensure_root("reservation note root", &self.reservation_note_root)?;
        ensure_root("encrypted route root", &self.encrypted_route_root)?;
        ensure_root("liquidity receipt root", &self.liquidity_receipt_root)?;
        if self.reserved_liquidity_micro_units == 0 {
            return Err("reserved liquidity must be non-zero".to_string());
        }
        ensure_bps("sponsor fee bps", self.sponsor_fee_bps)?;
        if self.sponsor_fee_bps > config.max_sponsor_fee_bps {
            return Err("reservation sponsor fee exceeds configured maximum".to_string());
        }
        ensure_min_privacy(config, self.privacy_set_size, false)?;
        ensure_expiry(
            "reservation",
            self.reserved_at_height,
            self.expires_at_height,
            config.reservation_ttl_blocks,
        )?;
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SessionLiquidityReservationRecord {
    pub reservation_id: String,
    pub status: ReservationStatus,
    pub commitment_id: String,
    pub proof_id: String,
    pub pool_id: String,
    pub reservation_note_root: String,
    pub encrypted_route_root: String,
    pub liquidity_receipt_root: String,
    pub reserved_liquidity_micro_units: u64,
    pub settled_liquidity_micro_units: u64,
    pub sponsor_fee_bps: u64,
    pub sponsor_fee_micro_units: u64,
    pub privacy_set_size: u64,
    pub reserved_at_height: u64,
    pub expires_at_height: u64,
    pub settled_at_height: u64,
    pub nonce: u64,
}

impl SessionLiquidityReservationRecord {
    pub fn from_request(reservation_id: String, request: ReserveSessionLiquidityRequest) -> Self {
        Self {
            reservation_id,
            status: ReservationStatus::Reserved,
            commitment_id: request.commitment_id,
            proof_id: request.proof_id,
            pool_id: request.pool_id,
            reservation_note_root: request.reservation_note_root,
            encrypted_route_root: request.encrypted_route_root,
            liquidity_receipt_root: request.liquidity_receipt_root,
            reserved_liquidity_micro_units: request.reserved_liquidity_micro_units,
            settled_liquidity_micro_units: 0,
            sponsor_fee_bps: request.sponsor_fee_bps,
            sponsor_fee_micro_units: 0,
            privacy_set_size: request.privacy_set_size,
            reserved_at_height: request.reserved_at_height,
            expires_at_height: request.expires_at_height,
            settled_at_height: 0,
            nonce: request.nonce,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "reservation_id": self.reservation_id,
            "status": self.status.as_str(),
            "commitment_id": self.commitment_id,
            "proof_id": self.proof_id,
            "pool_id": self.pool_id,
            "reservation_note_root": self.reservation_note_root,
            "encrypted_route_root": self.encrypted_route_root,
            "liquidity_receipt_root": self.liquidity_receipt_root,
            "reserved_liquidity_micro_units": self.reserved_liquidity_micro_units,
            "settled_liquidity_micro_units": self.settled_liquidity_micro_units,
            "sponsor_fee_bps": self.sponsor_fee_bps,
            "sponsor_fee_micro_units": self.sponsor_fee_micro_units,
            "privacy_set_size": self.privacy_set_size,
            "reserved_at_height": self.reserved_at_height,
            "expires_at_height": self.expires_at_height,
            "settled_at_height": self.settled_at_height,
            "nonce": self.nonce,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BatchSponsoredSessionSettlementRequest {
    pub sponsor_operator_commitment: String,
    pub settlement_root: String,
    pub execution_witness_root: String,
    pub output_note_root: String,
    pub fee_note_root: String,
    pub reservation_ids: Vec<String>,
    pub pool_ids: Vec<String>,
    pub settled_liquidity_micro_units: u64,
    pub sponsor_fee_micro_units: u64,
    pub privacy_set_size: u64,
    pub settled_at_height: u64,
    pub expires_at_height: u64,
    pub nonce: u64,
}

impl BatchSponsoredSessionSettlementRequest {
    pub fn validate(&self, config: &Config) -> Result<()> {
        ensure_non_empty(
            "sponsor operator commitment",
            &self.sponsor_operator_commitment,
        )?;
        ensure_root("settlement root", &self.settlement_root)?;
        ensure_root("execution witness root", &self.execution_witness_root)?;
        ensure_root("output note root", &self.output_note_root)?;
        ensure_root("fee note root", &self.fee_note_root)?;
        if self.reservation_ids.is_empty() {
            return Err("batch must include reservations".to_string());
        }
        if self.reservation_ids.len() > config.max_batch_items {
            return Err("batch exceeds max batch items".to_string());
        }
        if self.settled_liquidity_micro_units == 0 {
            return Err("batch settled liquidity must be non-zero".to_string());
        }
        ensure_min_privacy(config, self.privacy_set_size, true)?;
        ensure_expiry(
            "batch",
            self.settled_at_height,
            self.expires_at_height,
            config.batch_ttl_blocks,
        )?;
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SponsoredSessionSettlementBatchRecord {
    pub batch_id: String,
    pub status: BatchStatus,
    pub sponsor_operator_commitment: String,
    pub settlement_root: String,
    pub execution_witness_root: String,
    pub output_note_root: String,
    pub fee_note_root: String,
    pub reservation_ids: Vec<String>,
    pub pool_ids: Vec<String>,
    pub settled_liquidity_micro_units: u64,
    pub sponsor_fee_micro_units: u64,
    pub rebate_ids: Vec<String>,
    pub privacy_set_size: u64,
    pub settled_at_height: u64,
    pub expires_at_height: u64,
    pub nonce: u64,
}

impl SponsoredSessionSettlementBatchRecord {
    pub fn from_request(batch_id: String, request: BatchSponsoredSessionSettlementRequest) -> Self {
        Self {
            batch_id,
            status: BatchStatus::SettlementReady,
            sponsor_operator_commitment: request.sponsor_operator_commitment,
            settlement_root: request.settlement_root,
            execution_witness_root: request.execution_witness_root,
            output_note_root: request.output_note_root,
            fee_note_root: request.fee_note_root,
            reservation_ids: request.reservation_ids,
            pool_ids: request.pool_ids,
            settled_liquidity_micro_units: request.settled_liquidity_micro_units,
            sponsor_fee_micro_units: request.sponsor_fee_micro_units,
            rebate_ids: Vec::new(),
            privacy_set_size: request.privacy_set_size,
            settled_at_height: request.settled_at_height,
            expires_at_height: request.expires_at_height,
            nonce: request.nonce,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "status": self.status.as_str(),
            "sponsor_operator_commitment": self.sponsor_operator_commitment,
            "settlement_root": self.settlement_root,
            "execution_witness_root": self.execution_witness_root,
            "output_note_root": self.output_note_root,
            "fee_note_root": self.fee_note_root,
            "reservation_ids": self.reservation_ids,
            "pool_ids": self.pool_ids,
            "settled_liquidity_micro_units": self.settled_liquidity_micro_units,
            "sponsor_fee_micro_units": self.sponsor_fee_micro_units,
            "rebate_ids": self.rebate_ids,
            "privacy_set_size": self.privacy_set_size,
            "settled_at_height": self.settled_at_height,
            "expires_at_height": self.expires_at_height,
            "nonce": self.nonce,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct IssueLowFeeRebateRequest {
    pub batch_id: String,
    pub commitment_id: String,
    pub reservation_id: String,
    pub claimant_commitment: String,
    pub rebate_note_root: String,
    pub fee_receipt_root: String,
    pub rebate_micro_units: u64,
    pub target_fee_bps: u64,
    pub privacy_set_size: u64,
    pub issued_at_height: u64,
    pub nonce: u64,
}

impl IssueLowFeeRebateRequest {
    pub fn validate(&self, config: &Config) -> Result<()> {
        ensure_non_empty("batch id", &self.batch_id)?;
        ensure_non_empty("commitment id", &self.commitment_id)?;
        ensure_non_empty("reservation id", &self.reservation_id)?;
        ensure_non_empty("claimant commitment", &self.claimant_commitment)?;
        ensure_root("rebate note root", &self.rebate_note_root)?;
        ensure_root("fee receipt root", &self.fee_receipt_root)?;
        ensure_bps("target fee bps", self.target_fee_bps)?;
        if self.target_fee_bps > config.target_rebate_bps {
            return Err("rebate target exceeds configured low-fee target".to_string());
        }
        ensure_min_privacy(config, self.privacy_set_size, false)?;
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LowFeeRebateRecord {
    pub rebate_id: String,
    pub status: RebateStatus,
    pub batch_id: String,
    pub commitment_id: String,
    pub reservation_id: String,
    pub claimant_commitment: String,
    pub rebate_note_root: String,
    pub fee_receipt_root: String,
    pub rebate_micro_units: u64,
    pub target_fee_bps: u64,
    pub privacy_set_size: u64,
    pub issued_at_height: u64,
    pub nonce: u64,
}

impl LowFeeRebateRecord {
    pub fn from_request(rebate_id: String, request: IssueLowFeeRebateRequest) -> Self {
        Self {
            rebate_id,
            status: RebateStatus::Issued,
            batch_id: request.batch_id,
            commitment_id: request.commitment_id,
            reservation_id: request.reservation_id,
            claimant_commitment: request.claimant_commitment,
            rebate_note_root: request.rebate_note_root,
            fee_receipt_root: request.fee_receipt_root,
            rebate_micro_units: request.rebate_micro_units,
            target_fee_bps: request.target_fee_bps,
            privacy_set_size: request.privacy_set_size,
            issued_at_height: request.issued_at_height,
            nonce: request.nonce,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "rebate_id": self.rebate_id,
            "status": self.status.as_str(),
            "batch_id": self.batch_id,
            "commitment_id": self.commitment_id,
            "reservation_id": self.reservation_id,
            "claimant_commitment": self.claimant_commitment,
            "rebate_note_root": self.rebate_note_root,
            "fee_receipt_root": self.fee_receipt_root,
            "rebate_micro_units": self.rebate_micro_units,
            "target_fee_bps": self.target_fee_bps,
            "privacy_set_size": self.privacy_set_size,
            "issued_at_height": self.issued_at_height,
            "nonce": self.nonce,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AccountPrivacySetRequest {
    pub kind: PrivacySetKind,
    pub epoch: u64,
    pub aggregate_root: String,
    pub member_root: String,
    pub nullifier_root: String,
    pub observed_members: u64,
    pub minimum_required_members: u64,
    pub accounted_at_height: u64,
    pub nonce: u64,
}

impl AccountPrivacySetRequest {
    pub fn validate(&self, config: &Config) -> Result<()> {
        ensure_root("aggregate root", &self.aggregate_root)?;
        ensure_root("member root", &self.member_root)?;
        ensure_root("nullifier root", &self.nullifier_root)?;
        if self.observed_members < self.minimum_required_members {
            return Err("privacy set observed members below request minimum".to_string());
        }
        if self.minimum_required_members < config.min_privacy_set_size {
            return Err("privacy set request below configured minimum".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivacySetAccountingRecord {
    pub privacy_epoch_id: String,
    pub kind: PrivacySetKind,
    pub epoch: u64,
    pub aggregate_root: String,
    pub member_root: String,
    pub nullifier_root: String,
    pub observed_members: u64,
    pub minimum_required_members: u64,
    pub accounted_at_height: u64,
    pub nonce: u64,
}

impl PrivacySetAccountingRecord {
    pub fn from_request(privacy_epoch_id: String, request: AccountPrivacySetRequest) -> Self {
        Self {
            privacy_epoch_id,
            kind: request.kind,
            epoch: request.epoch,
            aggregate_root: request.aggregate_root,
            member_root: request.member_root,
            nullifier_root: request.nullifier_root,
            observed_members: request.observed_members,
            minimum_required_members: request.minimum_required_members,
            accounted_at_height: request.accounted_at_height,
            nonce: request.nonce,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "privacy_epoch_id": self.privacy_epoch_id,
            "kind": self.kind.as_str(),
            "epoch": self.epoch,
            "aggregate_root": self.aggregate_root,
            "member_root": self.member_root,
            "nullifier_root": self.nullifier_root,
            "observed_members": self.observed_members,
            "minimum_required_members": self.minimum_required_members,
            "accounted_at_height": self.accounted_at_height,
            "nonce": self.nonce,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SlashInvalidSponsorProofRequest {
    pub kind: SlashKind,
    pub pool_id: String,
    pub commitment_id: String,
    pub proof_id: String,
    pub accused_sponsor_commitment: String,
    pub challenger_commitment: String,
    pub evidence_root: String,
    pub invalidity_witness_root: String,
    pub slash_bps: u64,
    pub slashed_at_height: u64,
    pub nonce: u64,
}

impl SlashInvalidSponsorProofRequest {
    pub fn validate(&self, config: &Config) -> Result<()> {
        ensure_non_empty("pool id", &self.pool_id)?;
        ensure_non_empty("commitment id", &self.commitment_id)?;
        ensure_non_empty("proof id", &self.proof_id)?;
        ensure_non_empty(
            "accused sponsor commitment",
            &self.accused_sponsor_commitment,
        )?;
        ensure_non_empty("challenger commitment", &self.challenger_commitment)?;
        ensure_root("evidence root", &self.evidence_root)?;
        ensure_root("invalidity witness root", &self.invalidity_witness_root)?;
        ensure_bps("slash bps", self.slash_bps)?;
        if self.slash_bps > config.slashing_penalty_bps {
            return Err("slash bps exceeds configured penalty".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SponsorProofSlashingRecord {
    pub slash_id: String,
    pub kind: SlashKind,
    pub pool_id: String,
    pub commitment_id: String,
    pub proof_id: String,
    pub accused_sponsor_commitment: String,
    pub challenger_commitment: String,
    pub evidence_root: String,
    pub invalidity_witness_root: String,
    pub slash_bps: u64,
    pub slashed_micro_units: u64,
    pub slashed_at_height: u64,
    pub nonce: u64,
}

impl SponsorProofSlashingRecord {
    pub fn from_request(
        slash_id: String,
        slashed_micro_units: u64,
        request: SlashInvalidSponsorProofRequest,
    ) -> Self {
        Self {
            slash_id,
            kind: request.kind,
            pool_id: request.pool_id,
            commitment_id: request.commitment_id,
            proof_id: request.proof_id,
            accused_sponsor_commitment: request.accused_sponsor_commitment,
            challenger_commitment: request.challenger_commitment,
            evidence_root: request.evidence_root,
            invalidity_witness_root: request.invalidity_witness_root,
            slash_bps: request.slash_bps,
            slashed_micro_units,
            slashed_at_height: request.slashed_at_height,
            nonce: request.nonce,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "slash_id": self.slash_id,
            "kind": self.kind.as_str(),
            "pool_id": self.pool_id,
            "commitment_id": self.commitment_id,
            "proof_id": self.proof_id,
            "accused_sponsor_commitment": self.accused_sponsor_commitment,
            "challenger_commitment": self.challenger_commitment,
            "evidence_root": self.evidence_root,
            "invalidity_witness_root": self.invalidity_witness_root,
            "slash_bps": self.slash_bps,
            "slashed_micro_units": self.slashed_micro_units,
            "slashed_at_height": self.slashed_at_height,
            "nonce": self.nonce,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub chain_id: String,
    pub height: u64,
    pub config: Config,
    pub counters: Counters,
    pub sponsor_pools: BTreeMap<String, SponsorPoolRecord>,
    pub commitments: BTreeMap<String, SponsorshipCommitmentRecord>,
    pub proofs: BTreeMap<String, PqUserSessionProofRecord>,
    pub reservations: BTreeMap<String, SessionLiquidityReservationRecord>,
    pub settlement_batches: BTreeMap<String, SponsoredSessionSettlementBatchRecord>,
    pub rebates: BTreeMap<String, LowFeeRebateRecord>,
    pub privacy_sets: BTreeMap<String, PrivacySetAccountingRecord>,
    pub slashes: BTreeMap<String, SponsorProofSlashingRecord>,
    pub used_session_nullifiers: BTreeSet<String>,
    pub used_proof_nullifiers: BTreeSet<String>,
}

impl State {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            height: PRIVATE_L2_PQ_CONFIDENTIAL_SESSION_LIQUIDITY_SPONSOR_RUNTIME_DEVNET_HEIGHT,
            config: Config::devnet(),
            counters: Counters::default(),
            sponsor_pools: BTreeMap::new(),
            commitments: BTreeMap::new(),
            proofs: BTreeMap::new(),
            reservations: BTreeMap::new(),
            settlement_batches: BTreeMap::new(),
            rebates: BTreeMap::new(),
            privacy_sets: BTreeMap::new(),
            slashes: BTreeMap::new(),
            used_session_nullifiers: BTreeSet::new(),
            used_proof_nullifiers: BTreeSet::new(),
        }
    }

    pub fn roots(&self) -> Roots {
        let pool_root = map_root(
            "PRIVATE-L2-PQ-CONFIDENTIAL-SESSION-LIQUIDITY-SPONSOR-POOL-ROOT",
            &self.sponsor_pools,
            SponsorPoolRecord::public_record,
        );
        let commitment_root = map_root(
            "PRIVATE-L2-PQ-CONFIDENTIAL-SESSION-LIQUIDITY-SPONSOR-COMMITMENT-ROOT",
            &self.commitments,
            SponsorshipCommitmentRecord::public_record,
        );
        let proof_root = map_root(
            "PRIVATE-L2-PQ-CONFIDENTIAL-SESSION-LIQUIDITY-SPONSOR-PROOF-ROOT",
            &self.proofs,
            PqUserSessionProofRecord::public_record,
        );
        let reservation_root = map_root(
            "PRIVATE-L2-PQ-CONFIDENTIAL-SESSION-LIQUIDITY-SPONSOR-RESERVATION-ROOT",
            &self.reservations,
            SessionLiquidityReservationRecord::public_record,
        );
        let batch_root = map_root(
            "PRIVATE-L2-PQ-CONFIDENTIAL-SESSION-LIQUIDITY-SPONSOR-BATCH-ROOT",
            &self.settlement_batches,
            SponsoredSessionSettlementBatchRecord::public_record,
        );
        let rebate_root = map_root(
            "PRIVATE-L2-PQ-CONFIDENTIAL-SESSION-LIQUIDITY-SPONSOR-REBATE-ROOT",
            &self.rebates,
            LowFeeRebateRecord::public_record,
        );
        let privacy_set_root = map_root(
            "PRIVATE-L2-PQ-CONFIDENTIAL-SESSION-LIQUIDITY-SPONSOR-PRIVACY-SET-ROOT",
            &self.privacy_sets,
            PrivacySetAccountingRecord::public_record,
        );
        let nullifier_root = public_record_root(
            "PRIVATE-L2-PQ-CONFIDENTIAL-SESSION-LIQUIDITY-SPONSOR-NULLIFIER-ROOT",
            &[
                json!({"session": set_root("SESSION-NULLIFIERS", &self.used_session_nullifiers)}),
                json!({"proof": set_root("PROOF-NULLIFIERS", &self.used_proof_nullifiers)}),
            ],
        );
        let slashing_root = map_root(
            "PRIVATE-L2-PQ-CONFIDENTIAL-SESSION-LIQUIDITY-SPONSOR-SLASHING-ROOT",
            &self.slashes,
            SponsorProofSlashingRecord::public_record,
        );
        let config_root = root_from_record(
            "PRIVATE-L2-PQ-CONFIDENTIAL-SESSION-LIQUIDITY-SPONSOR-CONFIG-ROOT",
            &self.config.public_record(),
        );
        let counters_root = root_from_record(
            "PRIVATE-L2-PQ-CONFIDENTIAL-SESSION-LIQUIDITY-SPONSOR-COUNTERS-ROOT",
            &self.counters.public_record(),
        );
        let public_record_root_value = public_record_root(
            "PRIVATE-L2-PQ-CONFIDENTIAL-SESSION-LIQUIDITY-SPONSOR-PUBLIC-RECORD-ROOT",
            &[
                Value::String(pool_root.clone()),
                Value::String(commitment_root.clone()),
                Value::String(proof_root.clone()),
                Value::String(reservation_root.clone()),
                Value::String(batch_root.clone()),
                Value::String(rebate_root.clone()),
                Value::String(privacy_set_root.clone()),
                Value::String(nullifier_root.clone()),
                Value::String(slashing_root.clone()),
                Value::String(config_root.clone()),
                Value::String(counters_root.clone()),
            ],
        );
        let state_root = state_root_from_record(&json!({
            "chain_id": self.chain_id,
            "height": self.height,
            "protocol_version": PROTOCOL_VERSION,
            "public_record_root": public_record_root_value,
        }));
        Roots {
            pool_root,
            commitment_root,
            proof_root,
            reservation_root,
            batch_root,
            rebate_root,
            privacy_set_root,
            nullifier_root,
            slashing_root,
            config_root,
            counters_root,
            public_record_root: public_record_root_value,
            state_root,
        }
    }

    pub fn state_root(&self) -> String {
        self.roots().state_root
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": PRIVATE_L2_PQ_CONFIDENTIAL_SESSION_LIQUIDITY_SPONSOR_RUNTIME_SCHEMA_VERSION,
            "hash_suite": PRIVATE_L2_PQ_CONFIDENTIAL_SESSION_LIQUIDITY_SPONSOR_RUNTIME_HASH_SUITE,
            "pq_auth_suite": PRIVATE_L2_PQ_CONFIDENTIAL_SESSION_LIQUIDITY_SPONSOR_RUNTIME_PQ_AUTH_SUITE,
            "chain_id": self.chain_id,
            "height": self.height,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": self.roots().public_record(),
        })
    }

    pub fn register_confidential_session_sponsor_pool(
        &mut self,
        request: RegisterSponsorPoolRequest,
    ) -> Result<String> {
        ensure_capacity(
            "sponsor pools",
            self.sponsor_pools.len(),
            self.config.max_pools,
        )?;
        request.validate(&self.config)?;
        let pool_id = sponsor_pool_id(
            request.kind,
            &request.sponsor_commitment,
            &request.asset_root,
            request.nonce,
        );
        if self.sponsor_pools.contains_key(&pool_id) {
            return Err("sponsor pool already exists".to_string());
        }
        self.counters.pools_registered = self.counters.pools_registered.saturating_add(1);
        self.sponsor_pools.insert(
            pool_id.clone(),
            SponsorPoolRecord::from_request(pool_id.clone(), request),
        );
        Ok(pool_id)
    }

    pub fn post_sealed_liquidity_sponsorship_commitment(
        &mut self,
        request: PostSealedLiquiditySponsorshipCommitmentRequest,
    ) -> Result<String> {
        ensure_capacity(
            "commitments",
            self.commitments.len(),
            self.config.max_commitments,
        )?;
        request.validate(&self.config)?;
        let pool = self
            .sponsor_pools
            .get(&request.pool_id)
            .ok_or_else(|| "sponsor pool not found".to_string())?;
        if !pool.status.accepts_commitments() {
            return Err("sponsor pool is not accepting commitments".to_string());
        }
        if self
            .used_session_nullifiers
            .contains(&request.session_nullifier)
        {
            return Err("session nullifier already used".to_string());
        }
        let commitment_id = sponsorship_commitment_id(
            request.lane,
            &request.pool_id,
            &request.session_commitment,
            &request.session_nullifier,
            request.nonce,
        );
        if self.commitments.contains_key(&commitment_id) {
            return Err("sponsorship commitment already exists".to_string());
        }
        self.used_session_nullifiers
            .insert(request.session_nullifier.clone());
        self.counters.commitments_posted = self.counters.commitments_posted.saturating_add(1);
        self.counters.sponsored_notional_micro_units = self
            .counters
            .sponsored_notional_micro_units
            .saturating_add(request.requested_liquidity_micro_units);
        self.commitments.insert(
            commitment_id.clone(),
            SponsorshipCommitmentRecord::from_request(commitment_id.clone(), request),
        );
        Ok(commitment_id)
    }

    pub fn attach_pq_user_session_proof(
        &mut self,
        request: AttachPqUserSessionProofRequest,
    ) -> Result<String> {
        ensure_capacity("proofs", self.proofs.len(), self.config.max_proofs)?;
        request.validate(&self.config)?;
        if self
            .used_proof_nullifiers
            .contains(&request.proof_nullifier)
        {
            return Err("proof nullifier already used".to_string());
        }
        let commitment = self
            .commitments
            .get_mut(&request.commitment_id)
            .ok_or_else(|| "commitment not found".to_string())?;
        if !commitment.status.reservable() {
            return Err("commitment cannot accept proof".to_string());
        }
        let proof_id = pq_session_proof_id(
            request.kind,
            &request.commitment_id,
            &request.session_proof_root,
            request.nonce,
        );
        if self.proofs.contains_key(&proof_id) {
            return Err("pq session proof already exists".to_string());
        }
        commitment.status = CommitmentStatus::ProofAttached;
        commitment.proof_ids.push(proof_id.clone());
        self.used_proof_nullifiers
            .insert(request.proof_nullifier.clone());
        self.counters.pq_proofs_attached = self.counters.pq_proofs_attached.saturating_add(1);
        self.proofs.insert(
            proof_id.clone(),
            PqUserSessionProofRecord::from_request(proof_id.clone(), request),
        );
        Ok(proof_id)
    }

    pub fn reserve_session_liquidity(
        &mut self,
        request: ReserveSessionLiquidityRequest,
    ) -> Result<String> {
        ensure_capacity(
            "reservations",
            self.reservations.len(),
            self.config.max_reservations,
        )?;
        request.validate(&self.config)?;
        let pool = self
            .sponsor_pools
            .get_mut(&request.pool_id)
            .ok_or_else(|| "sponsor pool not found".to_string())?;
        if pool.available_liquidity_micro_units < request.reserved_liquidity_micro_units {
            return Err("insufficient pool liquidity".to_string());
        }
        let commitment = self
            .commitments
            .get_mut(&request.commitment_id)
            .ok_or_else(|| "commitment not found".to_string())?;
        if commitment.pool_id != request.pool_id {
            return Err("commitment pool mismatch".to_string());
        }
        if !commitment.status.reservable() {
            return Err("commitment is not reservable".to_string());
        }
        let proof = self
            .proofs
            .get_mut(&request.proof_id)
            .ok_or_else(|| "pq proof not found".to_string())?;
        if proof.commitment_id != request.commitment_id {
            return Err("proof commitment mismatch".to_string());
        }
        let reservation_id = reservation_id(
            &request.commitment_id,
            &request.proof_id,
            &request.reservation_note_root,
            request.nonce,
        );
        if self.reservations.contains_key(&reservation_id) {
            return Err("reservation already exists".to_string());
        }
        pool.available_liquidity_micro_units = pool
            .available_liquidity_micro_units
            .saturating_sub(request.reserved_liquidity_micro_units);
        pool.reserved_liquidity_micro_units = pool
            .reserved_liquidity_micro_units
            .saturating_add(request.reserved_liquidity_micro_units);
        pool.last_activity_height = request.reserved_at_height;
        commitment.status = CommitmentStatus::Reserved;
        commitment.reservation_id = reservation_id.clone();
        commitment.reserved_liquidity_micro_units = request.reserved_liquidity_micro_units;
        proof.status = ProofStatus::Linked;
        self.counters.reservations_made = self.counters.reservations_made.saturating_add(1);
        self.counters.reserved_liquidity_micro_units = self
            .counters
            .reserved_liquidity_micro_units
            .saturating_add(request.reserved_liquidity_micro_units);
        self.reservations.insert(
            reservation_id.clone(),
            SessionLiquidityReservationRecord::from_request(reservation_id.clone(), request),
        );
        Ok(reservation_id)
    }

    pub fn batch_sponsored_session_settlements(
        &mut self,
        request: BatchSponsoredSessionSettlementRequest,
    ) -> Result<String> {
        ensure_capacity(
            "settlement batches",
            self.settlement_batches.len(),
            self.config.max_batches,
        )?;
        request.validate(&self.config)?;
        let batch_id = settlement_batch_id(
            &request.sponsor_operator_commitment,
            &request.settlement_root,
            request.settled_at_height,
            request.nonce,
        );
        if self.settlement_batches.contains_key(&batch_id) {
            return Err("settlement batch already exists".to_string());
        }
        for reservation_id in &request.reservation_ids {
            let reservation = self
                .reservations
                .get_mut(reservation_id)
                .ok_or_else(|| format!("reservation not found: {reservation_id}"))?;
            if !reservation.status.can_settle() {
                return Err(format!("reservation cannot settle: {reservation_id}"));
            }
            reservation.status = ReservationStatus::Settled;
            reservation.settled_liquidity_micro_units = reservation.reserved_liquidity_micro_units;
            reservation.sponsor_fee_micro_units = fee_amount(
                reservation.reserved_liquidity_micro_units,
                reservation.sponsor_fee_bps,
            );
            reservation.settled_at_height = request.settled_at_height;
            if let Some(commitment) = self.commitments.get_mut(&reservation.commitment_id) {
                commitment.status = CommitmentStatus::Settled;
                commitment.batch_id = batch_id.clone();
                commitment.settled_liquidity_micro_units =
                    reservation.reserved_liquidity_micro_units;
                commitment.charged_fee_micro_units = reservation.sponsor_fee_micro_units;
                commitment.settled_at_height = request.settled_at_height;
            }
            if let Some(pool) = self.sponsor_pools.get_mut(&reservation.pool_id) {
                pool.reserved_liquidity_micro_units = pool
                    .reserved_liquidity_micro_units
                    .saturating_sub(reservation.reserved_liquidity_micro_units);
                pool.settled_liquidity_micro_units = pool
                    .settled_liquidity_micro_units
                    .saturating_add(reservation.reserved_liquidity_micro_units);
                pool.fees_earned_micro_units = pool
                    .fees_earned_micro_units
                    .saturating_add(reservation.sponsor_fee_micro_units);
                pool.last_activity_height = request.settled_at_height;
            }
        }
        self.counters.batches_settled = self.counters.batches_settled.saturating_add(1);
        self.counters.settled_liquidity_micro_units = self
            .counters
            .settled_liquidity_micro_units
            .saturating_add(request.settled_liquidity_micro_units);
        self.settlement_batches.insert(
            batch_id.clone(),
            SponsoredSessionSettlementBatchRecord::from_request(batch_id.clone(), request),
        );
        Ok(batch_id)
    }

    pub fn issue_low_fee_rebate(&mut self, request: IssueLowFeeRebateRequest) -> Result<String> {
        ensure_capacity("rebates", self.rebates.len(), self.config.max_rebates)?;
        request.validate(&self.config)?;
        if !self.settlement_batches.contains_key(&request.batch_id) {
            return Err("settlement batch not found".to_string());
        }
        let rebate_id = rebate_id(
            &request.commitment_id,
            &request.reservation_id,
            &request.rebate_note_root,
            request.nonce,
        );
        if self.rebates.contains_key(&rebate_id) {
            return Err("rebate already exists".to_string());
        }
        if let Some(commitment) = self.commitments.get_mut(&request.commitment_id) {
            commitment.status = CommitmentStatus::Rebated;
            commitment.rebate_id = rebate_id.clone();
        }
        if let Some(reservation) = self.reservations.get_mut(&request.reservation_id) {
            reservation.status = ReservationStatus::Rebated;
        }
        if let Some(batch) = self.settlement_batches.get_mut(&request.batch_id) {
            batch.status = BatchStatus::Rebated;
            batch.rebate_ids.push(rebate_id.clone());
        }
        self.counters.rebates_issued = self.counters.rebates_issued.saturating_add(1);
        self.counters.rebated_fee_micro_units = self
            .counters
            .rebated_fee_micro_units
            .saturating_add(request.rebate_micro_units);
        self.rebates.insert(
            rebate_id.clone(),
            LowFeeRebateRecord::from_request(rebate_id.clone(), request),
        );
        Ok(rebate_id)
    }

    pub fn account_privacy_set(&mut self, request: AccountPrivacySetRequest) -> Result<String> {
        ensure_capacity(
            "privacy epochs",
            self.privacy_sets.len(),
            self.config.max_privacy_epochs,
        )?;
        request.validate(&self.config)?;
        let privacy_epoch_id = privacy_epoch_id(
            request.kind,
            request.epoch,
            &request.aggregate_root,
            request.nonce,
        );
        if self.privacy_sets.contains_key(&privacy_epoch_id) {
            return Err("privacy epoch already accounted".to_string());
        }
        self.counters.privacy_epochs_accounted =
            self.counters.privacy_epochs_accounted.saturating_add(1);
        self.privacy_sets.insert(
            privacy_epoch_id.clone(),
            PrivacySetAccountingRecord::from_request(privacy_epoch_id.clone(), request),
        );
        Ok(privacy_epoch_id)
    }

    pub fn slash_invalid_sponsor_proof(
        &mut self,
        request: SlashInvalidSponsorProofRequest,
    ) -> Result<String> {
        ensure_capacity("slashes", self.slashes.len(), self.config.max_slashes)?;
        request.validate(&self.config)?;
        let pool = self
            .sponsor_pools
            .get_mut(&request.pool_id)
            .ok_or_else(|| "sponsor pool not found".to_string())?;
        let slashed_micro_units = fee_amount(pool.sponsor_bond_micro_units, request.slash_bps);
        let slash_id = slash_id(
            request.kind,
            &request.accused_sponsor_commitment,
            &request.evidence_root,
            request.nonce,
        );
        if self.slashes.contains_key(&slash_id) {
            return Err("slash already exists".to_string());
        }
        pool.status = PoolStatus::Slashed;
        pool.slashed_micro_units = pool.slashed_micro_units.saturating_add(slashed_micro_units);
        pool.sponsor_bond_micro_units = pool
            .sponsor_bond_micro_units
            .saturating_sub(slashed_micro_units);
        if let Some(commitment) = self.commitments.get_mut(&request.commitment_id) {
            commitment.status = CommitmentStatus::Slashed;
        }
        if let Some(proof) = self.proofs.get_mut(&request.proof_id) {
            proof.status = ProofStatus::Slashed;
        }
        self.counters.invalid_proofs_slashed =
            self.counters.invalid_proofs_slashed.saturating_add(1);
        self.counters.slashed_bond_micro_units = self
            .counters
            .slashed_bond_micro_units
            .saturating_add(slashed_micro_units);
        self.slashes.insert(
            slash_id.clone(),
            SponsorProofSlashingRecord::from_request(
                slash_id.clone(),
                slashed_micro_units,
                request,
            ),
        );
        Ok(slash_id)
    }
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn private_l2_pq_confidential_session_liquidity_sponsor_runtime_state_root() -> String {
    State::devnet().state_root()
}

pub fn sponsor_pool_id(
    kind: SponsorPoolKind,
    sponsor_commitment: &str,
    asset_root: &str,
    nonce: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-SESSION-LIQUIDITY-SPONSOR-POOL-ID",
        &[
            HashPart::Str(kind.as_str()),
            HashPart::Str(sponsor_commitment),
            HashPart::Str(asset_root),
            HashPart::U64(nonce),
        ],
        32,
    )
}

pub fn sponsorship_commitment_id(
    lane: SessionLane,
    pool_id: &str,
    session_commitment: &str,
    session_nullifier: &str,
    nonce: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-SESSION-LIQUIDITY-SPONSOR-COMMITMENT-ID",
        &[
            HashPart::Str(lane.as_str()),
            HashPart::Str(pool_id),
            HashPart::Str(session_commitment),
            HashPart::Str(session_nullifier),
            HashPart::U64(nonce),
        ],
        32,
    )
}

pub fn pq_session_proof_id(
    kind: ProofKind,
    commitment_id: &str,
    proof_root: &str,
    nonce: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-SESSION-LIQUIDITY-SPONSOR-PQ-PROOF-ID",
        &[
            HashPart::Str(kind.as_str()),
            HashPart::Str(commitment_id),
            HashPart::Str(proof_root),
            HashPart::U64(nonce),
        ],
        32,
    )
}

pub fn reservation_id(
    commitment_id: &str,
    proof_id: &str,
    reservation_note_root: &str,
    nonce: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-SESSION-LIQUIDITY-SPONSOR-RESERVATION-ID",
        &[
            HashPart::Str(commitment_id),
            HashPart::Str(proof_id),
            HashPart::Str(reservation_note_root),
            HashPart::U64(nonce),
        ],
        32,
    )
}

pub fn settlement_batch_id(
    sponsor_operator_commitment: &str,
    settlement_root: &str,
    settled_at_height: u64,
    nonce: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-SESSION-LIQUIDITY-SPONSOR-BATCH-ID",
        &[
            HashPart::Str(sponsor_operator_commitment),
            HashPart::Str(settlement_root),
            HashPart::U64(settled_at_height),
            HashPart::U64(nonce),
        ],
        32,
    )
}

pub fn rebate_id(
    commitment_id: &str,
    reservation_id: &str,
    rebate_note_root: &str,
    nonce: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-SESSION-LIQUIDITY-SPONSOR-REBATE-ID",
        &[
            HashPart::Str(commitment_id),
            HashPart::Str(reservation_id),
            HashPart::Str(rebate_note_root),
            HashPart::U64(nonce),
        ],
        32,
    )
}

pub fn privacy_epoch_id(
    kind: PrivacySetKind,
    epoch: u64,
    aggregate_root: &str,
    nonce: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-SESSION-LIQUIDITY-SPONSOR-PRIVACY-EPOCH-ID",
        &[
            HashPart::Str(kind.as_str()),
            HashPart::U64(epoch),
            HashPart::Str(aggregate_root),
            HashPart::U64(nonce),
        ],
        32,
    )
}

pub fn slash_id(
    kind: SlashKind,
    accused_sponsor_commitment: &str,
    evidence_root: &str,
    nonce: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-SESSION-LIQUIDITY-SPONSOR-SLASH-ID",
        &[
            HashPart::Str(kind.as_str()),
            HashPart::Str(accused_sponsor_commitment),
            HashPart::Str(evidence_root),
            HashPart::U64(nonce),
        ],
        32,
    )
}

pub fn deterministic_root(label: &str, subject: &str, nonce: &str) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-SESSION-LIQUIDITY-SPONSOR-DETERMINISTIC-ROOT",
        &[
            HashPart::Str(label),
            HashPart::Str(subject),
            HashPart::Str(nonce),
        ],
        32,
    )
}

pub fn payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(domain, &[HashPart::Json(payload)], 32)
}

pub fn root_from_record(domain: &str, record: &Value) -> String {
    payload_root(domain, record)
}

pub fn public_record_root(domain: &str, records: &[Value]) -> String {
    merkle_root(domain, records)
}

pub fn state_root_from_record(record: &Value) -> String {
    root_from_record(
        "PRIVATE-L2-PQ-CONFIDENTIAL-SESSION-LIQUIDITY-SPONSOR-STATE-ROOT",
        record,
    )
}

pub fn root_from_values(domain: &str, values: &[&str]) -> String {
    let leaves = values
        .iter()
        .map(|value| Value::String((*value).to_string()))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn public_records_from_map<T, F>(map: &BTreeMap<String, T>, public_record: F) -> Vec<Value>
where
    F: Fn(&T) -> Value,
{
    map.values().map(public_record).collect()
}

fn map_root<T, F>(domain: &str, map: &BTreeMap<String, T>, public_record: F) -> String
where
    F: Fn(&T) -> Value,
{
    let records = public_records_from_map(map, public_record);
    public_record_root(domain, &records)
}

fn set_root(domain: &str, set: &BTreeSet<String>) -> String {
    let records = set
        .iter()
        .map(|item| Value::String(item.clone()))
        .collect::<Vec<_>>();
    public_record_root(domain, &records)
}

fn ensure_non_empty(name: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        return Err(format!("{name} must be non-empty"));
    }
    Ok(())
}

fn ensure_root(name: &str, value: &str) -> Result<()> {
    ensure_non_empty(name, value)?;
    if value.len() < 16 {
        return Err(format!("{name} must be hash-like"));
    }
    Ok(())
}

fn ensure_bps(name: &str, value: u64) -> Result<()> {
    if value > PRIVATE_L2_PQ_CONFIDENTIAL_SESSION_LIQUIDITY_SPONSOR_RUNTIME_MAX_BPS {
        return Err(format!("{name} exceeds max bps"));
    }
    Ok(())
}

fn ensure_capacity(name: &str, current: usize, max: usize) -> Result<()> {
    if current >= max {
        return Err(format!("{name} capacity exhausted"));
    }
    Ok(())
}

fn ensure_min_privacy(config: &Config, observed: u64, batch: bool) -> Result<()> {
    let required = if batch {
        config.batch_privacy_set_size
    } else {
        config.min_privacy_set_size
    };
    if observed < required {
        return Err("privacy set below configured threshold".to_string());
    }
    Ok(())
}

fn ensure_pq(config: &Config, pq_security_bits: u16) -> Result<()> {
    if pq_security_bits < config.min_pq_security_bits {
        return Err("post-quantum security bits below configured minimum".to_string());
    }
    Ok(())
}

fn ensure_expiry(name: &str, opened_at: u64, expires_at: u64, ttl: u64) -> Result<()> {
    if expires_at <= opened_at {
        return Err(format!("{name} expiry must be after open height"));
    }
    if expires_at.saturating_sub(opened_at) > ttl {
        return Err(format!("{name} expiry exceeds configured ttl"));
    }
    Ok(())
}

fn fee_amount(amount_micro_units: u64, fee_bps: u64) -> u64 {
    amount_micro_units.saturating_mul(fee_bps)
        / PRIVATE_L2_PQ_CONFIDENTIAL_SESSION_LIQUIDITY_SPONSOR_RUNTIME_MAX_BPS
}
