use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2ConfidentialStableSwapRuntimeResult<T> = Result<T, String>;

pub const PRIVATE_L2_CONFIDENTIAL_STABLE_SWAP_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-confidential-stable-swap-runtime-v1";
pub const PRIVATE_L2_CONFIDENTIAL_STABLE_SWAP_RUNTIME_SCHEMA_VERSION: u64 = 1;
pub const PRIVATE_L2_CONFIDENTIAL_STABLE_SWAP_RUNTIME_HASH_SUITE: &str =
    "SHAKE256-domain-separated-canonical-json";
pub const PRIVATE_L2_CONFIDENTIAL_STABLE_SWAP_RUNTIME_PQ_AUTH_SCHEME: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256s-stable-swap-v1";
pub const PRIVATE_L2_CONFIDENTIAL_STABLE_SWAP_RUNTIME_POOL_SCHEME: &str =
    "monero-private-l2-confidential-stable-swap-pool-root-v1";
pub const PRIVATE_L2_CONFIDENTIAL_STABLE_SWAP_RUNTIME_SWAP_NOTE_SCHEME: &str =
    "monero-private-l2-confidential-stable-swap-note-root-v1";
pub const PRIVATE_L2_CONFIDENTIAL_STABLE_SWAP_RUNTIME_LIQUIDITY_NOTE_SCHEME: &str =
    "monero-private-l2-confidential-stable-swap-liquidity-root-v1";
pub const PRIVATE_L2_CONFIDENTIAL_STABLE_SWAP_RUNTIME_SPONSOR_SCHEME: &str =
    "roots-only-low-fee-stable-swap-sponsor-reservation-v1";
pub const PRIVATE_L2_CONFIDENTIAL_STABLE_SWAP_RUNTIME_RISK_SCHEME: &str =
    "monero-private-l2-confidential-stable-swap-pq-risk-root-v1";
pub const PRIVATE_L2_CONFIDENTIAL_STABLE_SWAP_RUNTIME_BATCH_SCHEME: &str =
    "monero-private-l2-confidential-stable-swap-batch-root-v1";
pub const PRIVATE_L2_CONFIDENTIAL_STABLE_SWAP_RUNTIME_RECEIPT_SCHEME: &str =
    "roots-only-confidential-stable-swap-receipt-v1";
pub const PRIVATE_L2_CONFIDENTIAL_STABLE_SWAP_RUNTIME_DEVNET_HEIGHT: u64 = 214_000;
pub const PRIVATE_L2_CONFIDENTIAL_STABLE_SWAP_RUNTIME_DEFAULT_MONERO_NETWORK: &str =
    "monero-devnet";
pub const PRIVATE_L2_CONFIDENTIAL_STABLE_SWAP_RUNTIME_DEFAULT_L2_NETWORK: &str = "nebula-devnet";
pub const PRIVATE_L2_CONFIDENTIAL_STABLE_SWAP_RUNTIME_DEFAULT_LOW_FEE_LANE: &str =
    "devnet-private-l2-stable-swap-low-fee";
pub const PRIVATE_L2_CONFIDENTIAL_STABLE_SWAP_RUNTIME_DEFAULT_MAX_POOLS: usize = 65_536;
pub const PRIVATE_L2_CONFIDENTIAL_STABLE_SWAP_RUNTIME_DEFAULT_MAX_PENDING_SWAP_NOTES: usize =
    1_048_576;
pub const PRIVATE_L2_CONFIDENTIAL_STABLE_SWAP_RUNTIME_DEFAULT_MAX_LIQUIDITY_NOTES: usize = 524_288;
pub const PRIVATE_L2_CONFIDENTIAL_STABLE_SWAP_RUNTIME_DEFAULT_MAX_SPONSOR_RESERVATIONS: usize =
    524_288;
pub const PRIVATE_L2_CONFIDENTIAL_STABLE_SWAP_RUNTIME_DEFAULT_MAX_PQ_ATTESTATIONS: usize = 524_288;
pub const PRIVATE_L2_CONFIDENTIAL_STABLE_SWAP_RUNTIME_DEFAULT_MAX_BATCH_ITEMS: usize = 8_192;
pub const PRIVATE_L2_CONFIDENTIAL_STABLE_SWAP_RUNTIME_DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 4_096;
pub const PRIVATE_L2_CONFIDENTIAL_STABLE_SWAP_RUNTIME_DEFAULT_BATCH_PRIVACY_SET_SIZE: u64 = 32_768;
pub const PRIVATE_L2_CONFIDENTIAL_STABLE_SWAP_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const PRIVATE_L2_CONFIDENTIAL_STABLE_SWAP_RUNTIME_DEFAULT_MAX_USER_FEE_BPS: u64 = 16;
pub const PRIVATE_L2_CONFIDENTIAL_STABLE_SWAP_RUNTIME_DEFAULT_PROTOCOL_FEE_BPS: u64 = 3;
pub const PRIVATE_L2_CONFIDENTIAL_STABLE_SWAP_RUNTIME_DEFAULT_MAX_AMPLIFICATION_BPS: u64 = 50_000;
pub const PRIVATE_L2_CONFIDENTIAL_STABLE_SWAP_RUNTIME_DEFAULT_SETTLEMENT_TTL_BLOCKS: u64 = 18;
pub const PRIVATE_L2_CONFIDENTIAL_STABLE_SWAP_RUNTIME_MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StableSwapPoolKind {
    TwoAssetStable,
    MultiAssetStable,
    StableToMonero,
    WrappedStableBasket,
    DefiSettlementRail,
}

impl StableSwapPoolKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::TwoAssetStable => "two_asset_stable",
            Self::MultiAssetStable => "multi_asset_stable",
            Self::StableToMonero => "stable_to_monero",
            Self::WrappedStableBasket => "wrapped_stable_basket",
            Self::DefiSettlementRail => "defi_settlement_rail",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PoolStatus {
    Open,
    Paused,
    RebalanceOnly,
    Settling,
    Closed,
}

impl PoolStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Paused => "paused",
            Self::RebalanceOnly => "rebalance_only",
            Self::Settling => "settling",
            Self::Closed => "closed",
        }
    }

    pub fn accepts_swaps(self) -> bool {
        matches!(self, Self::Open)
    }

    pub fn accepts_liquidity(self) -> bool {
        matches!(self, Self::Open | Self::RebalanceOnly)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwapNoteStatus {
    Pending,
    RiskAttested,
    Sponsored,
    Batched,
    Settled,
    Rejected,
    Expired,
}

impl SwapNoteStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::RiskAttested => "risk_attested",
            Self::Sponsored => "sponsored",
            Self::Batched => "batched",
            Self::Settled => "settled",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }

    pub fn batchable(self) -> bool {
        matches!(self, Self::RiskAttested | Self::Sponsored)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LiquidityAction {
    Add,
    Remove,
    Rebalance,
    FeeSkim,
}

impl LiquidityAction {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Add => "add",
            Self::Remove => "remove",
            Self::Rebalance => "rebalance",
            Self::FeeSkim => "fee_skim",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LiquidityNoteStatus {
    Pending,
    Sponsored,
    Batched,
    Settled,
    Rejected,
    Expired,
}

impl LiquidityNoteStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Sponsored => "sponsored",
            Self::Batched => "batched",
            Self::Settled => "settled",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }

    pub fn batchable(self) -> bool {
        matches!(self, Self::Pending | Self::Sponsored)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorReservationStatus {
    Reserved,
    Applied,
    Exhausted,
    Expired,
}

impl SponsorReservationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Applied => "applied",
            Self::Exhausted => "exhausted",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqRiskVerdict {
    Safe,
    Watch,
    RotateKeys,
    Reject,
}

impl PqRiskVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Safe => "safe",
            Self::Watch => "watch",
            Self::RotateKeys => "rotate_keys",
            Self::Reject => "reject",
        }
    }

    pub fn allows_settlement(self) -> bool {
        matches!(self, Self::Safe | Self::Watch)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchStatus {
    Open,
    SettlementReady,
    Settled,
    Disputed,
    Expired,
}

impl BatchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::SettlementReady => "settlement_ready",
            Self::Settled => "settled",
            Self::Disputed => "disputed",
            Self::Expired => "expired",
        }
    }

    pub fn can_settle(self) -> bool {
        matches!(self, Self::SettlementReady)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptKind {
    PoolOpened,
    SwapNoteAccepted,
    LiquidityNoteAccepted,
    SponsorReserved,
    PqRiskAttested,
    BatchSettled,
}

impl ReceiptKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PoolOpened => "pool_opened",
            Self::SwapNoteAccepted => "swap_note_accepted",
            Self::LiquidityNoteAccepted => "liquidity_note_accepted",
            Self::SponsorReserved => "sponsor_reserved",
            Self::PqRiskAttested => "pq_risk_attested",
            Self::BatchSettled => "batch_settled",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub protocol_version: String,
    pub schema_version: u64,
    pub chain_id: String,
    pub monero_network: String,
    pub l2_network: String,
    pub low_fee_lane_id: String,
    pub hash_suite: String,
    pub pq_authorization_scheme: String,
    pub pool_scheme: String,
    pub swap_note_scheme: String,
    pub liquidity_note_scheme: String,
    pub sponsor_scheme: String,
    pub risk_scheme: String,
    pub batch_scheme: String,
    pub receipt_scheme: String,
    pub max_pools: usize,
    pub max_pending_swap_notes: usize,
    pub max_liquidity_notes: usize,
    pub max_sponsor_reservations: usize,
    pub max_pq_attestations: usize,
    pub max_batch_items: usize,
    pub min_privacy_set_size: u64,
    pub min_batch_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub max_user_fee_bps: u64,
    pub protocol_fee_bps: u64,
    pub max_amplification_bps: u64,
    pub settlement_ttl_blocks: u64,
    pub require_low_fee_sponsor: bool,
    pub require_pq_attestation: bool,
    pub require_defi_hook_root: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version: PRIVATE_L2_CONFIDENTIAL_STABLE_SWAP_RUNTIME_PROTOCOL_VERSION
                .to_string(),
            schema_version: PRIVATE_L2_CONFIDENTIAL_STABLE_SWAP_RUNTIME_SCHEMA_VERSION,
            chain_id: CHAIN_ID.to_string(),
            monero_network: PRIVATE_L2_CONFIDENTIAL_STABLE_SWAP_RUNTIME_DEFAULT_MONERO_NETWORK
                .to_string(),
            l2_network: PRIVATE_L2_CONFIDENTIAL_STABLE_SWAP_RUNTIME_DEFAULT_L2_NETWORK.to_string(),
            low_fee_lane_id: PRIVATE_L2_CONFIDENTIAL_STABLE_SWAP_RUNTIME_DEFAULT_LOW_FEE_LANE
                .to_string(),
            hash_suite: PRIVATE_L2_CONFIDENTIAL_STABLE_SWAP_RUNTIME_HASH_SUITE.to_string(),
            pq_authorization_scheme: PRIVATE_L2_CONFIDENTIAL_STABLE_SWAP_RUNTIME_PQ_AUTH_SCHEME
                .to_string(),
            pool_scheme: PRIVATE_L2_CONFIDENTIAL_STABLE_SWAP_RUNTIME_POOL_SCHEME.to_string(),
            swap_note_scheme: PRIVATE_L2_CONFIDENTIAL_STABLE_SWAP_RUNTIME_SWAP_NOTE_SCHEME
                .to_string(),
            liquidity_note_scheme:
                PRIVATE_L2_CONFIDENTIAL_STABLE_SWAP_RUNTIME_LIQUIDITY_NOTE_SCHEME.to_string(),
            sponsor_scheme: PRIVATE_L2_CONFIDENTIAL_STABLE_SWAP_RUNTIME_SPONSOR_SCHEME.to_string(),
            risk_scheme: PRIVATE_L2_CONFIDENTIAL_STABLE_SWAP_RUNTIME_RISK_SCHEME.to_string(),
            batch_scheme: PRIVATE_L2_CONFIDENTIAL_STABLE_SWAP_RUNTIME_BATCH_SCHEME.to_string(),
            receipt_scheme: PRIVATE_L2_CONFIDENTIAL_STABLE_SWAP_RUNTIME_RECEIPT_SCHEME.to_string(),
            max_pools: PRIVATE_L2_CONFIDENTIAL_STABLE_SWAP_RUNTIME_DEFAULT_MAX_POOLS,
            max_pending_swap_notes:
                PRIVATE_L2_CONFIDENTIAL_STABLE_SWAP_RUNTIME_DEFAULT_MAX_PENDING_SWAP_NOTES,
            max_liquidity_notes:
                PRIVATE_L2_CONFIDENTIAL_STABLE_SWAP_RUNTIME_DEFAULT_MAX_LIQUIDITY_NOTES,
            max_sponsor_reservations:
                PRIVATE_L2_CONFIDENTIAL_STABLE_SWAP_RUNTIME_DEFAULT_MAX_SPONSOR_RESERVATIONS,
            max_pq_attestations:
                PRIVATE_L2_CONFIDENTIAL_STABLE_SWAP_RUNTIME_DEFAULT_MAX_PQ_ATTESTATIONS,
            max_batch_items: PRIVATE_L2_CONFIDENTIAL_STABLE_SWAP_RUNTIME_DEFAULT_MAX_BATCH_ITEMS,
            min_privacy_set_size:
                PRIVATE_L2_CONFIDENTIAL_STABLE_SWAP_RUNTIME_DEFAULT_MIN_PRIVACY_SET_SIZE,
            min_batch_privacy_set_size:
                PRIVATE_L2_CONFIDENTIAL_STABLE_SWAP_RUNTIME_DEFAULT_BATCH_PRIVACY_SET_SIZE,
            min_pq_security_bits:
                PRIVATE_L2_CONFIDENTIAL_STABLE_SWAP_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS,
            max_user_fee_bps: PRIVATE_L2_CONFIDENTIAL_STABLE_SWAP_RUNTIME_DEFAULT_MAX_USER_FEE_BPS,
            protocol_fee_bps: PRIVATE_L2_CONFIDENTIAL_STABLE_SWAP_RUNTIME_DEFAULT_PROTOCOL_FEE_BPS,
            max_amplification_bps:
                PRIVATE_L2_CONFIDENTIAL_STABLE_SWAP_RUNTIME_DEFAULT_MAX_AMPLIFICATION_BPS,
            settlement_ttl_blocks:
                PRIVATE_L2_CONFIDENTIAL_STABLE_SWAP_RUNTIME_DEFAULT_SETTLEMENT_TTL_BLOCKS,
            require_low_fee_sponsor: true,
            require_pq_attestation: true,
            require_defi_hook_root: true,
        }
    }

    pub fn validate(&self) -> PrivateL2ConfidentialStableSwapRuntimeResult<()> {
        if self.max_pools == 0 || self.max_pending_swap_notes == 0 || self.max_batch_items == 0 {
            return Err("confidential stable swap capacities must be positive".to_string());
        }
        if self.max_batch_items > self.max_pending_swap_notes {
            return Err("confidential stable swap batch size exceeds pending capacity".to_string());
        }
        if self.min_batch_privacy_set_size < self.min_privacy_set_size {
            return Err("confidential stable swap batch privacy set is below minimum".to_string());
        }
        if self.min_pq_security_bits < 128 {
            return Err("confidential stable swap PQ security floor is too low".to_string());
        }
        if self.protocol_fee_bps > self.max_user_fee_bps
            || self.max_user_fee_bps > PRIVATE_L2_CONFIDENTIAL_STABLE_SWAP_RUNTIME_MAX_BPS
        {
            return Err("confidential stable swap fee policy is invalid".to_string());
        }
        if self.max_amplification_bps == 0 {
            return Err("confidential stable swap amplification cap must be positive".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "chain_id": self.chain_id,
            "monero_network": self.monero_network,
            "l2_network": self.l2_network,
            "low_fee_lane_id": self.low_fee_lane_id,
            "hash_suite": self.hash_suite,
            "pq_authorization_scheme": self.pq_authorization_scheme,
            "pool_scheme": self.pool_scheme,
            "swap_note_scheme": self.swap_note_scheme,
            "liquidity_note_scheme": self.liquidity_note_scheme,
            "sponsor_scheme": self.sponsor_scheme,
            "risk_scheme": self.risk_scheme,
            "batch_scheme": self.batch_scheme,
            "receipt_scheme": self.receipt_scheme,
            "max_pools": self.max_pools,
            "max_pending_swap_notes": self.max_pending_swap_notes,
            "max_liquidity_notes": self.max_liquidity_notes,
            "max_sponsor_reservations": self.max_sponsor_reservations,
            "max_pq_attestations": self.max_pq_attestations,
            "max_batch_items": self.max_batch_items,
            "min_privacy_set_size": self.min_privacy_set_size,
            "min_batch_privacy_set_size": self.min_batch_privacy_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
            "max_user_fee_bps": self.max_user_fee_bps,
            "protocol_fee_bps": self.protocol_fee_bps,
            "max_amplification_bps": self.max_amplification_bps,
            "settlement_ttl_blocks": self.settlement_ttl_blocks,
            "require_low_fee_sponsor": self.require_low_fee_sponsor,
            "require_pq_attestation": self.require_pq_attestation,
            "require_defi_hook_root": self.require_defi_hook_root,
        })
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    pub pool_counter: u64,
    pub swap_note_counter: u64,
    pub liquidity_note_counter: u64,
    pub sponsor_reservation_counter: u64,
    pub pq_attestation_counter: u64,
    pub batch_counter: u64,
    pub receipt_counter: u64,
    pub rejected_counter: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "pool_counter": self.pool_counter,
            "swap_note_counter": self.swap_note_counter,
            "liquidity_note_counter": self.liquidity_note_counter,
            "sponsor_reservation_counter": self.sponsor_reservation_counter,
            "pq_attestation_counter": self.pq_attestation_counter,
            "batch_counter": self.batch_counter,
            "receipt_counter": self.receipt_counter,
            "rejected_counter": self.rejected_counter,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpenPoolRequest {
    pub pool_kind: StableSwapPoolKind,
    pub pool_owner_commitment: String,
    pub asset_ids: Vec<String>,
    pub asset_registry_root: String,
    pub initial_reserve_commitment_root: String,
    pub invariant_commitment_root: String,
    pub amplification_bps: u64,
    pub max_user_fee_bps: u64,
    pub oracle_bound_root: String,
    pub defi_hook_root: String,
    pub pq_authorization_root: String,
    pub min_privacy_set_size: u64,
}

impl OpenPoolRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "pool_kind": self.pool_kind.as_str(),
            "pool_owner_commitment": self.pool_owner_commitment,
            "asset_ids": self.asset_ids,
            "asset_registry_root": self.asset_registry_root,
            "initial_reserve_commitment_root": self.initial_reserve_commitment_root,
            "invariant_commitment_root": self.invariant_commitment_root,
            "amplification_bps": self.amplification_bps,
            "max_user_fee_bps": self.max_user_fee_bps,
            "oracle_bound_root": self.oracle_bound_root,
            "defi_hook_root": self.defi_hook_root,
            "pq_authorization_root": self.pq_authorization_root,
            "min_privacy_set_size": self.min_privacy_set_size,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwapNoteRequest {
    pub pool_id: String,
    pub trader_commitment: String,
    pub input_asset_id: String,
    pub output_asset_id: String,
    pub input_note_root: String,
    pub output_note_commitment_root: String,
    pub nullifier: String,
    pub slippage_bound_root: String,
    pub fee_commitment_root: String,
    pub user_max_fee_bps: u64,
    pub low_fee_sponsor_id: Option<String>,
    pub pq_authorization_root: String,
    pub defi_call_hook_root: String,
    pub expires_at_height: u64,
}

impl SwapNoteRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "pool_id": self.pool_id,
            "trader_commitment": self.trader_commitment,
            "input_asset_id": self.input_asset_id,
            "output_asset_id": self.output_asset_id,
            "input_note_root": self.input_note_root,
            "output_note_commitment_root": self.output_note_commitment_root,
            "nullifier": self.nullifier,
            "slippage_bound_root": self.slippage_bound_root,
            "fee_commitment_root": self.fee_commitment_root,
            "user_max_fee_bps": self.user_max_fee_bps,
            "low_fee_sponsor_id": self.low_fee_sponsor_id,
            "pq_authorization_root": self.pq_authorization_root,
            "defi_call_hook_root": self.defi_call_hook_root,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiquidityNoteRequest {
    pub pool_id: String,
    pub action: LiquidityAction,
    pub provider_commitment: String,
    pub asset_commitment_root: String,
    pub lp_note_commitment_root: String,
    pub nullifier: String,
    pub fee_commitment_root: String,
    pub low_fee_sponsor_id: Option<String>,
    pub pq_authorization_root: String,
    pub defi_hook_root: String,
    pub expires_at_height: u64,
}

impl LiquidityNoteRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "pool_id": self.pool_id,
            "action": self.action.as_str(),
            "provider_commitment": self.provider_commitment,
            "asset_commitment_root": self.asset_commitment_root,
            "lp_note_commitment_root": self.lp_note_commitment_root,
            "nullifier": self.nullifier,
            "fee_commitment_root": self.fee_commitment_root,
            "low_fee_sponsor_id": self.low_fee_sponsor_id,
            "pq_authorization_root": self.pq_authorization_root,
            "defi_hook_root": self.defi_hook_root,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SponsorReservationRequest {
    pub sponsor_commitment: String,
    pub lane_id: String,
    pub fee_budget_commitment_root: String,
    pub max_fee_bps: u64,
    pub max_notes: u64,
    pub eligible_pool_root: String,
    pub refund_note_root: String,
    pub pq_authorization_root: String,
    pub expires_at_height: u64,
}

impl SponsorReservationRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "sponsor_commitment": self.sponsor_commitment,
            "lane_id": self.lane_id,
            "fee_budget_commitment_root": self.fee_budget_commitment_root,
            "max_fee_bps": self.max_fee_bps,
            "max_notes": self.max_notes,
            "eligible_pool_root": self.eligible_pool_root,
            "refund_note_root": self.refund_note_root,
            "pq_authorization_root": self.pq_authorization_root,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqRiskAttestationRequest {
    pub subject_id: String,
    pub subject_root: String,
    pub attestor_commitment: String,
    pub verdict: PqRiskVerdict,
    pub pq_security_bits: u16,
    pub key_rotation_root: String,
    pub transcript_root: String,
    pub expires_at_height: u64,
}

impl PqRiskAttestationRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "subject_id": self.subject_id,
            "subject_root": self.subject_root,
            "attestor_commitment": self.attestor_commitment,
            "verdict": self.verdict.as_str(),
            "pq_security_bits": self.pq_security_bits,
            "key_rotation_root": self.key_rotation_root,
            "transcript_root": self.transcript_root,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchSettlementRequest {
    pub pool_id: String,
    pub swap_note_ids: Vec<String>,
    pub liquidity_note_ids: Vec<String>,
    pub builder_commitment: String,
    pub settlement_tx_root: String,
    pub reserve_delta_root: String,
    pub fee_distribution_root: String,
    pub recursive_proof_root: String,
    pub batch_privacy_set_size: u64,
    pub pq_aggregate_attestation_root: String,
}

impl BatchSettlementRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "pool_id": self.pool_id,
            "swap_note_ids": self.swap_note_ids,
            "liquidity_note_ids": self.liquidity_note_ids,
            "builder_commitment": self.builder_commitment,
            "settlement_tx_root": self.settlement_tx_root,
            "reserve_delta_root": self.reserve_delta_root,
            "fee_distribution_root": self.fee_distribution_root,
            "recursive_proof_root": self.recursive_proof_root,
            "batch_privacy_set_size": self.batch_privacy_set_size,
            "pq_aggregate_attestation_root": self.pq_aggregate_attestation_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PoolRecord {
    pub pool_id: String,
    pub request: OpenPoolRequest,
    pub status: PoolStatus,
    pub opened_at_height: u64,
    pub pool_commitment_root: String,
}

impl PoolRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "pool_id": self.pool_id,
            "request": self.request.public_record(),
            "status": self.status.as_str(),
            "opened_at_height": self.opened_at_height,
            "pool_commitment_root": self.pool_commitment_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwapNoteRecord {
    pub note_id: String,
    pub request: SwapNoteRequest,
    pub status: SwapNoteStatus,
    pub submitted_at_height: u64,
    pub accepted_root: String,
}

impl SwapNoteRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "note_id": self.note_id,
            "request": self.request.public_record(),
            "status": self.status.as_str(),
            "submitted_at_height": self.submitted_at_height,
            "accepted_root": self.accepted_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiquidityNoteRecord {
    pub note_id: String,
    pub request: LiquidityNoteRequest,
    pub status: LiquidityNoteStatus,
    pub submitted_at_height: u64,
    pub accepted_root: String,
}

impl LiquidityNoteRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "note_id": self.note_id,
            "request": self.request.public_record(),
            "status": self.status.as_str(),
            "submitted_at_height": self.submitted_at_height,
            "accepted_root": self.accepted_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SponsorReservationRecord {
    pub reservation_id: String,
    pub request: SponsorReservationRequest,
    pub status: SponsorReservationStatus,
    pub reserved_at_height: u64,
    pub used_notes: u64,
    pub reservation_root: String,
}

impl SponsorReservationRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "reservation_id": self.reservation_id,
            "request": self.request.public_record(),
            "status": self.status.as_str(),
            "reserved_at_height": self.reserved_at_height,
            "used_notes": self.used_notes,
            "reservation_root": self.reservation_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqRiskAttestationRecord {
    pub attestation_id: String,
    pub request: PqRiskAttestationRequest,
    pub attested_at_height: u64,
    pub attestation_root: String,
}

impl PqRiskAttestationRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "request": self.request.public_record(),
            "attested_at_height": self.attested_at_height,
            "attestation_root": self.attestation_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchRecord {
    pub batch_id: String,
    pub request: BatchSettlementRequest,
    pub status: BatchStatus,
    pub opened_at_height: u64,
    pub settled_at_height: Option<u64>,
    pub batch_root: String,
}

impl BatchRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "request": self.request.public_record(),
            "status": self.status.as_str(),
            "opened_at_height": self.opened_at_height,
            "settled_at_height": self.settled_at_height,
            "batch_root": self.batch_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceiptRecord {
    pub receipt_id: String,
    pub receipt_kind: ReceiptKind,
    pub subject_id: String,
    pub subject_root: String,
    pub state_root: String,
    pub emitted_at_height: u64,
}

impl ReceiptRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "receipt_kind": self.receipt_kind.as_str(),
            "subject_id": self.subject_id,
            "subject_root": self.subject_root,
            "state_root": self.state_root,
            "emitted_at_height": self.emitted_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roots {
    pub pool_root: String,
    pub swap_note_root: String,
    pub liquidity_note_root: String,
    pub sponsor_reservation_root: String,
    pub pq_attestation_root: String,
    pub batch_root: String,
    pub receipt_root: String,
    pub nullifier_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "pool_root": self.pool_root,
            "swap_note_root": self.swap_note_root,
            "liquidity_note_root": self.liquidity_note_root,
            "sponsor_reservation_root": self.sponsor_reservation_root,
            "pq_attestation_root": self.pq_attestation_root,
            "batch_root": self.batch_root,
            "receipt_root": self.receipt_root,
            "nullifier_root": self.nullifier_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub current_height: u64,
    pub pools: BTreeMap<String, PoolRecord>,
    pub swap_notes: BTreeMap<String, SwapNoteRecord>,
    pub liquidity_notes: BTreeMap<String, LiquidityNoteRecord>,
    pub sponsor_reservations: BTreeMap<String, SponsorReservationRecord>,
    pub pq_attestations: BTreeMap<String, PqRiskAttestationRecord>,
    pub batches: BTreeMap<String, BatchRecord>,
    pub receipts: BTreeMap<String, ReceiptRecord>,
    pub consumed_nullifiers: BTreeSet<String>,
}

impl State {
    pub fn devnet() -> PrivateL2ConfidentialStableSwapRuntimeResult<Self> {
        Self::new(
            Config::devnet(),
            PRIVATE_L2_CONFIDENTIAL_STABLE_SWAP_RUNTIME_DEVNET_HEIGHT,
        )
    }

    pub fn new(
        config: Config,
        current_height: u64,
    ) -> PrivateL2ConfidentialStableSwapRuntimeResult<Self> {
        config.validate()?;
        Ok(Self {
            config,
            counters: Counters::default(),
            current_height,
            pools: BTreeMap::new(),
            swap_notes: BTreeMap::new(),
            liquidity_notes: BTreeMap::new(),
            sponsor_reservations: BTreeMap::new(),
            pq_attestations: BTreeMap::new(),
            batches: BTreeMap::new(),
            receipts: BTreeMap::new(),
            consumed_nullifiers: BTreeSet::new(),
        })
    }

    pub fn open_confidential_stable_swap_pool(
        &mut self,
        request: OpenPoolRequest,
    ) -> PrivateL2ConfidentialStableSwapRuntimeResult<PoolRecord> {
        if self.pools.len() >= self.config.max_pools {
            return Err("confidential stable swap pool capacity reached".to_string());
        }
        if request.asset_ids.len() < 2 {
            return Err("confidential stable swap pools require at least two assets".to_string());
        }
        if request.max_user_fee_bps > self.config.max_user_fee_bps {
            return Err("confidential stable swap pool fee exceeds devnet cap".to_string());
        }
        if request.amplification_bps > self.config.max_amplification_bps {
            return Err("confidential stable swap amplification exceeds devnet cap".to_string());
        }
        if request.min_privacy_set_size < self.config.min_privacy_set_size {
            return Err("confidential stable swap pool privacy set is below minimum".to_string());
        }
        if self.config.require_defi_hook_root && request.defi_hook_root.is_empty() {
            return Err("confidential stable swap pool requires a DeFi hook root".to_string());
        }
        self.counters.pool_counter += 1;
        let pool_id = stable_swap_id("pool", self.counters.pool_counter, &request.public_record());
        let pool_commitment_root = stable_swap_record_root("POOL", &request.public_record());
        let record = PoolRecord {
            pool_id: pool_id.clone(),
            request,
            status: PoolStatus::Open,
            opened_at_height: self.current_height,
            pool_commitment_root,
        };
        self.pools.insert(pool_id, record.clone());
        self.emit_receipt(
            ReceiptKind::PoolOpened,
            record.pool_id.clone(),
            record.pool_commitment_root.clone(),
        )?;
        Ok(record)
    }

    pub fn submit_shielded_swap_note(
        &mut self,
        request: SwapNoteRequest,
    ) -> PrivateL2ConfidentialStableSwapRuntimeResult<SwapNoteRecord> {
        if self.swap_notes.len() >= self.config.max_pending_swap_notes {
            return Err("confidential stable swap pending note capacity reached".to_string());
        }
        let pool = self.require_pool(&request.pool_id)?;
        if !pool.status.accepts_swaps() {
            return Err("confidential stable swap pool does not accept swaps".to_string());
        }
        if request.input_asset_id == request.output_asset_id {
            return Err("confidential stable swap note requires distinct assets".to_string());
        }
        if request.user_max_fee_bps > self.config.max_user_fee_bps {
            return Err("confidential stable swap note fee exceeds devnet cap".to_string());
        }
        if request.expires_at_height <= self.current_height {
            return Err("confidential stable swap note is already expired".to_string());
        }
        if self.consumed_nullifiers.contains(&request.nullifier) {
            return Err("confidential stable swap nullifier already consumed".to_string());
        }
        let mut status = SwapNoteStatus::Pending;
        if let Some(reservation_id) = request.low_fee_sponsor_id.as_ref() {
            self.apply_sponsor_reservation(reservation_id)?;
            status = SwapNoteStatus::Sponsored;
        } else if self.config.require_low_fee_sponsor {
            return Err("confidential stable swap note requires a low-fee sponsor".to_string());
        }
        self.counters.swap_note_counter += 1;
        let note_id = stable_swap_id(
            "swap-note",
            self.counters.swap_note_counter,
            &request.public_record(),
        );
        let accepted_root = stable_swap_record_root("SWAP-NOTE", &request.public_record());
        let nullifier = request.nullifier.clone();
        let record = SwapNoteRecord {
            note_id: note_id.clone(),
            request,
            status,
            submitted_at_height: self.current_height,
            accepted_root,
        };
        self.consumed_nullifiers.insert(nullifier);
        self.swap_notes.insert(note_id, record.clone());
        self.emit_receipt(
            ReceiptKind::SwapNoteAccepted,
            record.note_id.clone(),
            record.accepted_root.clone(),
        )?;
        Ok(record)
    }

    pub fn submit_liquidity_note(
        &mut self,
        request: LiquidityNoteRequest,
    ) -> PrivateL2ConfidentialStableSwapRuntimeResult<LiquidityNoteRecord> {
        if self.liquidity_notes.len() >= self.config.max_liquidity_notes {
            return Err("confidential stable swap liquidity note capacity reached".to_string());
        }
        let pool = self.require_pool(&request.pool_id)?;
        if !pool.status.accepts_liquidity() {
            return Err("confidential stable swap pool does not accept liquidity".to_string());
        }
        if request.expires_at_height <= self.current_height {
            return Err("confidential stable swap liquidity note is already expired".to_string());
        }
        if self.consumed_nullifiers.contains(&request.nullifier) {
            return Err(
                "confidential stable swap liquidity nullifier already consumed".to_string(),
            );
        }
        let mut status = LiquidityNoteStatus::Pending;
        if let Some(reservation_id) = request.low_fee_sponsor_id.as_ref() {
            self.apply_sponsor_reservation(reservation_id)?;
            status = LiquidityNoteStatus::Sponsored;
        } else if self.config.require_low_fee_sponsor {
            return Err(
                "confidential stable swap liquidity note requires a low-fee sponsor".to_string(),
            );
        }
        self.counters.liquidity_note_counter += 1;
        let note_id = stable_swap_id(
            "liquidity-note",
            self.counters.liquidity_note_counter,
            &request.public_record(),
        );
        let accepted_root = stable_swap_record_root("LIQUIDITY-NOTE", &request.public_record());
        let nullifier = request.nullifier.clone();
        let record = LiquidityNoteRecord {
            note_id: note_id.clone(),
            request,
            status,
            submitted_at_height: self.current_height,
            accepted_root,
        };
        self.consumed_nullifiers.insert(nullifier);
        self.liquidity_notes.insert(note_id, record.clone());
        self.emit_receipt(
            ReceiptKind::LiquidityNoteAccepted,
            record.note_id.clone(),
            record.accepted_root.clone(),
        )?;
        Ok(record)
    }

    pub fn reserve_low_fee_sponsor(
        &mut self,
        request: SponsorReservationRequest,
    ) -> PrivateL2ConfidentialStableSwapRuntimeResult<SponsorReservationRecord> {
        if self.sponsor_reservations.len() >= self.config.max_sponsor_reservations {
            return Err(
                "confidential stable swap sponsor reservation capacity reached".to_string(),
            );
        }
        if request.lane_id != self.config.low_fee_lane_id {
            return Err("confidential stable swap sponsor lane mismatch".to_string());
        }
        if request.max_fee_bps > self.config.max_user_fee_bps || request.max_notes == 0 {
            return Err("confidential stable swap sponsor fee policy is invalid".to_string());
        }
        if request.expires_at_height <= self.current_height {
            return Err(
                "confidential stable swap sponsor reservation is already expired".to_string(),
            );
        }
        self.counters.sponsor_reservation_counter += 1;
        let reservation_id = stable_swap_id(
            "sponsor",
            self.counters.sponsor_reservation_counter,
            &request.public_record(),
        );
        let reservation_root = stable_swap_record_root("SPONSOR", &request.public_record());
        let record = SponsorReservationRecord {
            reservation_id: reservation_id.clone(),
            request,
            status: SponsorReservationStatus::Reserved,
            reserved_at_height: self.current_height,
            used_notes: 0,
            reservation_root,
        };
        self.sponsor_reservations
            .insert(reservation_id, record.clone());
        self.emit_receipt(
            ReceiptKind::SponsorReserved,
            record.reservation_id.clone(),
            record.reservation_root.clone(),
        )?;
        Ok(record)
    }

    pub fn attest_pq_risk(
        &mut self,
        request: PqRiskAttestationRequest,
    ) -> PrivateL2ConfidentialStableSwapRuntimeResult<PqRiskAttestationRecord> {
        if self.pq_attestations.len() >= self.config.max_pq_attestations {
            return Err("confidential stable swap PQ attestation capacity reached".to_string());
        }
        if request.pq_security_bits < self.config.min_pq_security_bits {
            return Err(
                "confidential stable swap PQ attestation is below security floor".to_string(),
            );
        }
        if request.expires_at_height <= self.current_height {
            return Err("confidential stable swap PQ attestation is already expired".to_string());
        }
        if !request.verdict.allows_settlement() {
            self.counters.rejected_counter += 1;
        }
        self.counters.pq_attestation_counter += 1;
        let attestation_id = stable_swap_id(
            "pq-risk",
            self.counters.pq_attestation_counter,
            &request.public_record(),
        );
        let attestation_root = stable_swap_record_root("PQ-RISK", &request.public_record());
        let subject_id = request.subject_id.clone();
        let record = PqRiskAttestationRecord {
            attestation_id: attestation_id.clone(),
            request,
            attested_at_height: self.current_height,
            attestation_root,
        };
        self.mark_subject_attested(&subject_id, record.request.verdict)?;
        self.pq_attestations.insert(attestation_id, record.clone());
        self.emit_receipt(
            ReceiptKind::PqRiskAttested,
            record.attestation_id.clone(),
            record.attestation_root.clone(),
        )?;
        Ok(record)
    }

    pub fn settle_batch(
        &mut self,
        request: BatchSettlementRequest,
    ) -> PrivateL2ConfidentialStableSwapRuntimeResult<BatchRecord> {
        self.require_pool(&request.pool_id)?;
        let item_count = request.swap_note_ids.len() + request.liquidity_note_ids.len();
        if item_count == 0 {
            return Err("confidential stable swap batch must include notes".to_string());
        }
        if item_count > self.config.max_batch_items {
            return Err("confidential stable swap batch exceeds item cap".to_string());
        }
        if request.batch_privacy_set_size < self.config.min_batch_privacy_set_size {
            return Err("confidential stable swap batch privacy set is below minimum".to_string());
        }
        for note_id in &request.swap_note_ids {
            let note = self
                .swap_notes
                .get(note_id)
                .ok_or_else(|| format!("unknown confidential stable swap note {note_id}"))?;
            if note.request.pool_id != request.pool_id || !note.status.batchable() {
                return Err("confidential stable swap note is not batchable".to_string());
            }
        }
        for note_id in &request.liquidity_note_ids {
            let note = self.liquidity_notes.get(note_id).ok_or_else(|| {
                format!("unknown confidential stable swap liquidity note {note_id}")
            })?;
            if note.request.pool_id != request.pool_id || !note.status.batchable() {
                return Err("confidential stable swap liquidity note is not batchable".to_string());
            }
        }
        self.counters.batch_counter += 1;
        let batch_id = stable_swap_id(
            "batch",
            self.counters.batch_counter,
            &request.public_record(),
        );
        let batch_root = stable_swap_record_root("BATCH", &request.public_record());
        for note_id in &request.swap_note_ids {
            if let Some(note) = self.swap_notes.get_mut(note_id) {
                note.status = SwapNoteStatus::Settled;
            }
        }
        for note_id in &request.liquidity_note_ids {
            if let Some(note) = self.liquidity_notes.get_mut(note_id) {
                note.status = LiquidityNoteStatus::Settled;
            }
        }
        let record = BatchRecord {
            batch_id: batch_id.clone(),
            request,
            status: BatchStatus::Settled,
            opened_at_height: self.current_height,
            settled_at_height: Some(self.current_height),
            batch_root,
        };
        self.batches.insert(batch_id, record.clone());
        self.emit_receipt(
            ReceiptKind::BatchSettled,
            record.batch_id.clone(),
            record.batch_root.clone(),
        )?;
        Ok(record)
    }

    pub fn receipts(&self) -> Vec<ReceiptRecord> {
        self.receipts.values().cloned().collect()
    }

    pub fn roots(&self) -> Roots {
        let pool_root = merkle_root(
            "PRIVATE-L2-CONFIDENTIAL-STABLE-SWAP-POOLS",
            &self
                .pools
                .values()
                .map(PoolRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let swap_note_root = merkle_root(
            "PRIVATE-L2-CONFIDENTIAL-STABLE-SWAP-NOTES",
            &self
                .swap_notes
                .values()
                .map(SwapNoteRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let liquidity_note_root = merkle_root(
            "PRIVATE-L2-CONFIDENTIAL-STABLE-SWAP-LIQUIDITY",
            &self
                .liquidity_notes
                .values()
                .map(LiquidityNoteRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let sponsor_reservation_root = merkle_root(
            "PRIVATE-L2-CONFIDENTIAL-STABLE-SWAP-SPONSORS",
            &self
                .sponsor_reservations
                .values()
                .map(SponsorReservationRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let pq_attestation_root = merkle_root(
            "PRIVATE-L2-CONFIDENTIAL-STABLE-SWAP-PQ-ATTESTATIONS",
            &self
                .pq_attestations
                .values()
                .map(PqRiskAttestationRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let batch_root = merkle_root(
            "PRIVATE-L2-CONFIDENTIAL-STABLE-SWAP-BATCHES",
            &self
                .batches
                .values()
                .map(BatchRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let receipt_root = merkle_root(
            "PRIVATE-L2-CONFIDENTIAL-STABLE-SWAP-RECEIPTS",
            &self
                .receipts
                .values()
                .map(ReceiptRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let nullifier_root = merkle_root(
            "PRIVATE-L2-CONFIDENTIAL-STABLE-SWAP-NULLIFIERS",
            &self
                .consumed_nullifiers
                .iter()
                .map(|nullifier| json!(nullifier))
                .collect::<Vec<_>>(),
        );
        let state_payload = json!({
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "current_height": self.current_height,
            "pool_root": pool_root,
            "swap_note_root": swap_note_root,
            "liquidity_note_root": liquidity_note_root,
            "sponsor_reservation_root": sponsor_reservation_root,
            "pq_attestation_root": pq_attestation_root,
            "batch_root": batch_root,
            "receipt_root": receipt_root,
            "nullifier_root": nullifier_root,
        });
        let state_root = stable_swap_record_root("STATE", &state_payload);
        Roots {
            pool_root,
            swap_note_root,
            liquidity_note_root,
            sponsor_reservation_root,
            pq_attestation_root,
            batch_root,
            receipt_root,
            nullifier_root,
            state_root,
        }
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        json!({
            "protocol_version": self.config.protocol_version,
            "schema_version": self.config.schema_version,
            "chain_id": self.config.chain_id,
            "current_height": self.current_height,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": roots.public_record(),
        })
    }

    pub fn state_root(&self) -> String {
        self.roots().state_root
    }

    fn require_pool(
        &self,
        pool_id: &str,
    ) -> PrivateL2ConfidentialStableSwapRuntimeResult<&PoolRecord> {
        self.pools
            .get(pool_id)
            .ok_or_else(|| format!("unknown confidential stable swap pool {pool_id}"))
    }

    fn apply_sponsor_reservation(
        &mut self,
        reservation_id: &str,
    ) -> PrivateL2ConfidentialStableSwapRuntimeResult<()> {
        let reservation = self
            .sponsor_reservations
            .get_mut(reservation_id)
            .ok_or_else(|| {
                format!("unknown confidential stable swap sponsor reservation {reservation_id}")
            })?;
        if reservation.status != SponsorReservationStatus::Reserved
            && reservation.status != SponsorReservationStatus::Applied
        {
            return Err("confidential stable swap sponsor reservation is not usable".to_string());
        }
        if reservation.request.expires_at_height <= self.current_height {
            reservation.status = SponsorReservationStatus::Expired;
            return Err("confidential stable swap sponsor reservation expired".to_string());
        }
        if reservation.used_notes >= reservation.request.max_notes {
            reservation.status = SponsorReservationStatus::Exhausted;
            return Err("confidential stable swap sponsor reservation exhausted".to_string());
        }
        reservation.used_notes += 1;
        reservation.status = if reservation.used_notes >= reservation.request.max_notes {
            SponsorReservationStatus::Exhausted
        } else {
            SponsorReservationStatus::Applied
        };
        Ok(())
    }

    fn mark_subject_attested(
        &mut self,
        subject_id: &str,
        verdict: PqRiskVerdict,
    ) -> PrivateL2ConfidentialStableSwapRuntimeResult<()> {
        if let Some(note) = self.swap_notes.get_mut(subject_id) {
            note.status = if verdict.allows_settlement() {
                SwapNoteStatus::RiskAttested
            } else {
                SwapNoteStatus::Rejected
            };
            return Ok(());
        }
        if self.pools.contains_key(subject_id) || self.liquidity_notes.contains_key(subject_id) {
            return Ok(());
        }
        Err(format!(
            "unknown confidential stable swap PQ subject {subject_id}"
        ))
    }

    fn emit_receipt(
        &mut self,
        receipt_kind: ReceiptKind,
        subject_id: String,
        subject_root: String,
    ) -> PrivateL2ConfidentialStableSwapRuntimeResult<ReceiptRecord> {
        self.counters.receipt_counter += 1;
        let seed = json!({
            "receipt_kind": receipt_kind.as_str(),
            "subject_id": subject_id,
            "subject_root": subject_root,
            "counter": self.counters.receipt_counter,
        });
        let receipt_id = stable_swap_id("receipt", self.counters.receipt_counter, &seed);
        let receipt = ReceiptRecord {
            receipt_id: receipt_id.clone(),
            receipt_kind,
            subject_id,
            subject_root,
            state_root: self.roots().state_root,
            emitted_at_height: self.current_height,
        };
        self.receipts.insert(receipt_id, receipt.clone());
        Ok(receipt)
    }
}

pub type Runtime = State;

fn stable_swap_id(prefix: &str, counter: u64, payload: &Value) -> String {
    let digest = domain_hash(
        "PRIVATE-L2-CONFIDENTIAL-STABLE-SWAP-ID",
        &[
            HashPart::Str(PRIVATE_L2_CONFIDENTIAL_STABLE_SWAP_RUNTIME_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(prefix),
            HashPart::Int(counter as i128),
            HashPart::Json(payload),
        ],
        16,
    );
    format!("{prefix}-{counter}-{digest}")
}

fn stable_swap_record_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        &format!(
            "{}:{}:{}",
            PRIVATE_L2_CONFIDENTIAL_STABLE_SWAP_RUNTIME_PROTOCOL_VERSION, CHAIN_ID, domain
        ),
        &[HashPart::Json(payload)],
        32,
    )
}
