use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type MoneroL2PqPrivateExitLiquidityVaultRuntimeResult<T> = Result<T, String>;
pub type Runtime = State;

pub const MONERO_L2_PQ_PRIVATE_EXIT_LIQUIDITY_VAULT_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-private-exit-liquidity-vault-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_PRIVATE_EXIT_LIQUIDITY_VAULT_RUNTIME_PROTOCOL_VERSION;
pub const MONERO_L2_PQ_PRIVATE_EXIT_LIQUIDITY_VAULT_RUNTIME_SCHEMA_VERSION: u64 = 1;
pub const MONERO_L2_PQ_PRIVATE_EXIT_LIQUIDITY_VAULT_RUNTIME_DEVNET_HEIGHT: u64 = 684_000;
pub const MONERO_L2_PQ_PRIVATE_EXIT_LIQUIDITY_VAULT_RUNTIME_DEVNET_MONERO_NETWORK: &str =
    "monero-devnet";
pub const MONERO_L2_PQ_PRIVATE_EXIT_LIQUIDITY_VAULT_RUNTIME_DEVNET_L2_NETWORK: &str =
    "nebula-devnet";
pub const MONERO_L2_PQ_PRIVATE_EXIT_LIQUIDITY_VAULT_RUNTIME_DEVNET_ASSET_ID: &str = "wxmr-devnet";
pub const MONERO_L2_PQ_PRIVATE_EXIT_LIQUIDITY_VAULT_RUNTIME_DEVNET_FEE_ASSET_ID: &str =
    "piconero-devnet";
pub const MONERO_L2_PQ_PRIVATE_EXIT_LIQUIDITY_VAULT_RUNTIME_DEVNET_STABLE_ASSET_ID: &str =
    "dusd-devnet";
pub const MONERO_L2_PQ_PRIVATE_EXIT_LIQUIDITY_VAULT_RUNTIME_HASH_SUITE: &str =
    "SHAKE256-domain-separated-canonical-json";
pub const MONERO_L2_PQ_PRIVATE_EXIT_LIQUIDITY_VAULT_RUNTIME_VAULT_SCHEME: &str =
    "ml-dsa-87+slh-dsa-shake-192f-private-exit-liquidity-vault-root-v1";
pub const MONERO_L2_PQ_PRIVATE_EXIT_LIQUIDITY_VAULT_RUNTIME_LP_SCHEME: &str =
    "poseidon-compatible-roots-only-private-lp-commitment-root-v1";
pub const MONERO_L2_PQ_PRIVATE_EXIT_LIQUIDITY_VAULT_RUNTIME_RESERVE_ATTESTATION_SCHEME: &str =
    "ml-dsa-87+slh-dsa-shake-192f-pq-monero-reserve-attestation-root-v1";
pub const MONERO_L2_PQ_PRIVATE_EXIT_LIQUIDITY_VAULT_RUNTIME_QUOTE_SCHEME: &str =
    "ml-kem-1024-sealed-private-exit-liquidity-quote-root-v1";
pub const MONERO_L2_PQ_PRIVATE_EXIT_LIQUIDITY_VAULT_RUNTIME_SPONSOR_SCHEME: &str =
    "roots-only-fee-sponsor-private-exit-reservation-root-v1";
pub const MONERO_L2_PQ_PRIVATE_EXIT_LIQUIDITY_VAULT_RUNTIME_BATCH_SCHEME: &str =
    "zk-pq-monero-private-exit-batch-settlement-root-v1";
pub const MONERO_L2_PQ_PRIVATE_EXIT_LIQUIDITY_VAULT_RUNTIME_RECEIPT_SCHEME: &str =
    "monero-private-exit-receipt-rebate-root-v1";
pub const MONERO_L2_PQ_PRIVATE_EXIT_LIQUIDITY_VAULT_RUNTIME_NULLIFIER_SCHEME: &str =
    "monero-l2-pq-private-exit-liquidity-vault-nullifier-root-v1";
pub const MONERO_L2_PQ_PRIVATE_EXIT_LIQUIDITY_VAULT_RUNTIME_REPLAY_DOMAIN: &str =
    "monero-l2-pq-private-exit-liquidity-vault-devnet";
pub const MONERO_L2_PQ_PRIVATE_EXIT_LIQUIDITY_VAULT_RUNTIME_MAX_BPS: u64 = 10_000;
pub const MONERO_L2_PQ_PRIVATE_EXIT_LIQUIDITY_VAULT_RUNTIME_DEFAULT_QUOTE_TTL_BLOCKS: u64 = 16;
pub const MONERO_L2_PQ_PRIVATE_EXIT_LIQUIDITY_VAULT_RUNTIME_DEFAULT_SPONSOR_TTL_BLOCKS: u64 = 20;
pub const MONERO_L2_PQ_PRIVATE_EXIT_LIQUIDITY_VAULT_RUNTIME_DEFAULT_BATCH_TTL_BLOCKS: u64 = 32;
pub const MONERO_L2_PQ_PRIVATE_EXIT_LIQUIDITY_VAULT_RUNTIME_DEFAULT_RECEIPT_FINALITY_BLOCKS: u64 =
    6;
pub const MONERO_L2_PQ_PRIVATE_EXIT_LIQUIDITY_VAULT_RUNTIME_DEFAULT_REBATE_TTL_BLOCKS: u64 = 144;
pub const MONERO_L2_PQ_PRIVATE_EXIT_LIQUIDITY_VAULT_RUNTIME_DEFAULT_MIN_PRIVACY_SET_SIZE: u64 =
    65_536;
pub const MONERO_L2_PQ_PRIVATE_EXIT_LIQUIDITY_VAULT_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 192;
pub const MONERO_L2_PQ_PRIVATE_EXIT_LIQUIDITY_VAULT_RUNTIME_DEFAULT_TARGET_PQ_SECURITY_BITS: u16 =
    256;
pub const MONERO_L2_PQ_PRIVATE_EXIT_LIQUIDITY_VAULT_RUNTIME_DEFAULT_MIN_RESERVE_COVERAGE_BPS: u64 =
    10_500;
pub const MONERO_L2_PQ_PRIVATE_EXIT_LIQUIDITY_VAULT_RUNTIME_DEFAULT_TARGET_RESERVE_COVERAGE_BPS:
    u64 = 12_500;
pub const MONERO_L2_PQ_PRIVATE_EXIT_LIQUIDITY_VAULT_RUNTIME_DEFAULT_LOW_FEE_BPS: u64 = 4;
pub const MONERO_L2_PQ_PRIVATE_EXIT_LIQUIDITY_VAULT_RUNTIME_DEFAULT_MAX_USER_FEE_BPS: u64 = 22;
pub const MONERO_L2_PQ_PRIVATE_EXIT_LIQUIDITY_VAULT_RUNTIME_DEFAULT_LP_FEE_BPS: u64 = 12;
pub const MONERO_L2_PQ_PRIVATE_EXIT_LIQUIDITY_VAULT_RUNTIME_DEFAULT_REBATE_BPS: u64 = 8;
pub const MONERO_L2_PQ_PRIVATE_EXIT_LIQUIDITY_VAULT_RUNTIME_DEFAULT_SPONSOR_COVER_BPS: u64 = 8_800;
pub const MONERO_L2_PQ_PRIVATE_EXIT_LIQUIDITY_VAULT_RUNTIME_DEFAULT_MAX_BATCH_ITEMS: usize = 768;
pub const MONERO_L2_PQ_PRIVATE_EXIT_LIQUIDITY_VAULT_RUNTIME_MAX_VAULTS: usize = 262_144;
pub const MONERO_L2_PQ_PRIVATE_EXIT_LIQUIDITY_VAULT_RUNTIME_MAX_LP_COMMITMENTS: usize = 524_288;
pub const MONERO_L2_PQ_PRIVATE_EXIT_LIQUIDITY_VAULT_RUNTIME_MAX_ATTESTATIONS: usize = 1_048_576;
pub const MONERO_L2_PQ_PRIVATE_EXIT_LIQUIDITY_VAULT_RUNTIME_MAX_QUOTES: usize = 1_048_576;
pub const MONERO_L2_PQ_PRIVATE_EXIT_LIQUIDITY_VAULT_RUNTIME_MAX_SPONSOR_RESERVATIONS: usize =
    1_048_576;
pub const MONERO_L2_PQ_PRIVATE_EXIT_LIQUIDITY_VAULT_RUNTIME_MAX_BATCHES: usize = 262_144;
pub const MONERO_L2_PQ_PRIVATE_EXIT_LIQUIDITY_VAULT_RUNTIME_MAX_RECEIPTS: usize = 1_048_576;
pub const MONERO_L2_PQ_PRIVATE_EXIT_LIQUIDITY_VAULT_RUNTIME_MAX_REBATES: usize = 1_048_576;
pub const MONERO_L2_PQ_PRIVATE_EXIT_LIQUIDITY_VAULT_RUNTIME_MAX_FENCES: usize = 2_097_152;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExitLane {
    SponsoredLowFee,
    Standard,
    Fast,
    Defi,
    Rebalance,
    Emergency,
}

impl ExitLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SponsoredLowFee => "sponsored_low_fee",
            Self::Standard => "standard",
            Self::Fast => "fast",
            Self::Defi => "defi",
            Self::Rebalance => "rebalance",
            Self::Emergency => "emergency",
        }
    }

    pub fn fee_bps(self, config: &Config) -> u64 {
        match self {
            Self::SponsoredLowFee => config.low_fee_bps,
            Self::Rebalance => config.max_user_fee_bps / 2,
            Self::Defi => config.max_user_fee_bps.saturating_mul(3) / 4,
            Self::Standard => config.max_user_fee_bps.saturating_mul(2) / 3,
            Self::Fast | Self::Emergency => config.max_user_fee_bps,
        }
    }

    pub fn priority_weight(self) -> u64 {
        match self {
            Self::Emergency => 1_000,
            Self::Fast => 930,
            Self::SponsoredLowFee => 890,
            Self::Defi => 800,
            Self::Rebalance => 740,
            Self::Standard => 640,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VaultStatus {
    Active,
    Degraded,
    Paused,
    Draining,
    Slashed,
}

impl VaultStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Degraded => "degraded",
            Self::Paused => "paused",
            Self::Draining => "draining",
            Self::Slashed => "slashed",
        }
    }

    pub fn usable(self) -> bool {
        matches!(self, Self::Active | Self::Degraded)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CommitmentStatus {
    Pending,
    Active,
    Locked,
    Rebalancing,
    Redeemed,
    Slashed,
}

impl CommitmentStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Active => "active",
            Self::Locked => "locked",
            Self::Rebalancing => "rebalancing",
            Self::Redeemed => "redeemed",
            Self::Slashed => "slashed",
        }
    }

    pub fn liquid(self) -> bool {
        matches!(self, Self::Active | Self::Rebalancing)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuoteStatus {
    Open,
    Reserved,
    Batched,
    Settling,
    Settled,
    Expired,
    Cancelled,
    Slashed,
}

impl QuoteStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Reserved => "reserved",
            Self::Batched => "batched",
            Self::Settling => "settling",
            Self::Settled => "settled",
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
            Self::Slashed => "slashed",
        }
    }

    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Open | Self::Reserved | Self::Batched | Self::Settling
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReservationStatus {
    Reserved,
    BoundToQuote,
    Batched,
    ReceiptIssued,
    Settled,
    Released,
    Expired,
}

impl ReservationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::BoundToQuote => "bound_to_quote",
            Self::Batched => "batched",
            Self::ReceiptIssued => "receipt_issued",
            Self::Settled => "settled",
            Self::Released => "released",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchStatus {
    Open,
    Sealed,
    ReserveAttested,
    Sponsored,
    Submitted,
    Settled,
    Disputed,
    Expired,
}

impl BatchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Sealed => "sealed",
            Self::ReserveAttested => "reserve_attested",
            Self::Sponsored => "sponsored",
            Self::Submitted => "submitted",
            Self::Settled => "settled",
            Self::Disputed => "disputed",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptStatus {
    Pending,
    Final,
    RebateClaimed,
    Disputed,
}

impl ReceiptStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Final => "final",
            Self::RebateClaimed => "rebate_claimed",
            Self::Disputed => "disputed",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FenceKind {
    ExitNullifier,
    QuoteNullifier,
    ReservationNullifier,
    BatchReplay,
    ReceiptReplay,
    RebateNullifier,
}

impl FenceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ExitNullifier => "exit_nullifier",
            Self::QuoteNullifier => "quote_nullifier",
            Self::ReservationNullifier => "reservation_nullifier",
            Self::BatchReplay => "batch_replay",
            Self::ReceiptReplay => "receipt_replay",
            Self::RebateNullifier => "rebate_nullifier",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    pub chain_id: String,
    pub monero_network: String,
    pub l2_network: String,
    pub asset_id: String,
    pub fee_asset_id: String,
    pub stable_asset_id: String,
    pub hash_suite: String,
    pub vault_scheme: String,
    pub lp_scheme: String,
    pub reserve_attestation_scheme: String,
    pub quote_scheme: String,
    pub sponsor_scheme: String,
    pub batch_scheme: String,
    pub receipt_scheme: String,
    pub nullifier_scheme: String,
    pub replay_domain: String,
    pub quote_ttl_blocks: u64,
    pub sponsor_ttl_blocks: u64,
    pub batch_ttl_blocks: u64,
    pub receipt_finality_blocks: u64,
    pub rebate_ttl_blocks: u64,
    pub min_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub target_pq_security_bits: u16,
    pub min_reserve_coverage_bps: u64,
    pub target_reserve_coverage_bps: u64,
    pub low_fee_bps: u64,
    pub max_user_fee_bps: u64,
    pub lp_fee_bps: u64,
    pub rebate_bps: u64,
    pub sponsor_cover_bps: u64,
    pub max_batch_items: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            monero_network:
                MONERO_L2_PQ_PRIVATE_EXIT_LIQUIDITY_VAULT_RUNTIME_DEVNET_MONERO_NETWORK
                    .to_string(),
            l2_network: MONERO_L2_PQ_PRIVATE_EXIT_LIQUIDITY_VAULT_RUNTIME_DEVNET_L2_NETWORK
                .to_string(),
            asset_id: MONERO_L2_PQ_PRIVATE_EXIT_LIQUIDITY_VAULT_RUNTIME_DEVNET_ASSET_ID
                .to_string(),
            fee_asset_id: MONERO_L2_PQ_PRIVATE_EXIT_LIQUIDITY_VAULT_RUNTIME_DEVNET_FEE_ASSET_ID
                .to_string(),
            stable_asset_id:
                MONERO_L2_PQ_PRIVATE_EXIT_LIQUIDITY_VAULT_RUNTIME_DEVNET_STABLE_ASSET_ID
                    .to_string(),
            hash_suite: MONERO_L2_PQ_PRIVATE_EXIT_LIQUIDITY_VAULT_RUNTIME_HASH_SUITE.to_string(),
            vault_scheme: MONERO_L2_PQ_PRIVATE_EXIT_LIQUIDITY_VAULT_RUNTIME_VAULT_SCHEME
                .to_string(),
            lp_scheme: MONERO_L2_PQ_PRIVATE_EXIT_LIQUIDITY_VAULT_RUNTIME_LP_SCHEME.to_string(),
            reserve_attestation_scheme:
                MONERO_L2_PQ_PRIVATE_EXIT_LIQUIDITY_VAULT_RUNTIME_RESERVE_ATTESTATION_SCHEME
                    .to_string(),
            quote_scheme: MONERO_L2_PQ_PRIVATE_EXIT_LIQUIDITY_VAULT_RUNTIME_QUOTE_SCHEME
                .to_string(),
            sponsor_scheme: MONERO_L2_PQ_PRIVATE_EXIT_LIQUIDITY_VAULT_RUNTIME_SPONSOR_SCHEME
                .to_string(),
            batch_scheme: MONERO_L2_PQ_PRIVATE_EXIT_LIQUIDITY_VAULT_RUNTIME_BATCH_SCHEME
                .to_string(),
            receipt_scheme: MONERO_L2_PQ_PRIVATE_EXIT_LIQUIDITY_VAULT_RUNTIME_RECEIPT_SCHEME
                .to_string(),
            nullifier_scheme: MONERO_L2_PQ_PRIVATE_EXIT_LIQUIDITY_VAULT_RUNTIME_NULLIFIER_SCHEME
                .to_string(),
            replay_domain: MONERO_L2_PQ_PRIVATE_EXIT_LIQUIDITY_VAULT_RUNTIME_REPLAY_DOMAIN
                .to_string(),
            quote_ttl_blocks:
                MONERO_L2_PQ_PRIVATE_EXIT_LIQUIDITY_VAULT_RUNTIME_DEFAULT_QUOTE_TTL_BLOCKS,
            sponsor_ttl_blocks:
                MONERO_L2_PQ_PRIVATE_EXIT_LIQUIDITY_VAULT_RUNTIME_DEFAULT_SPONSOR_TTL_BLOCKS,
            batch_ttl_blocks:
                MONERO_L2_PQ_PRIVATE_EXIT_LIQUIDITY_VAULT_RUNTIME_DEFAULT_BATCH_TTL_BLOCKS,
            receipt_finality_blocks:
                MONERO_L2_PQ_PRIVATE_EXIT_LIQUIDITY_VAULT_RUNTIME_DEFAULT_RECEIPT_FINALITY_BLOCKS,
            rebate_ttl_blocks:
                MONERO_L2_PQ_PRIVATE_EXIT_LIQUIDITY_VAULT_RUNTIME_DEFAULT_REBATE_TTL_BLOCKS,
            min_privacy_set_size:
                MONERO_L2_PQ_PRIVATE_EXIT_LIQUIDITY_VAULT_RUNTIME_DEFAULT_MIN_PRIVACY_SET_SIZE,
            min_pq_security_bits:
                MONERO_L2_PQ_PRIVATE_EXIT_LIQUIDITY_VAULT_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS,
            target_pq_security_bits:
                MONERO_L2_PQ_PRIVATE_EXIT_LIQUIDITY_VAULT_RUNTIME_DEFAULT_TARGET_PQ_SECURITY_BITS,
            min_reserve_coverage_bps:
                MONERO_L2_PQ_PRIVATE_EXIT_LIQUIDITY_VAULT_RUNTIME_DEFAULT_MIN_RESERVE_COVERAGE_BPS,
            target_reserve_coverage_bps:
                MONERO_L2_PQ_PRIVATE_EXIT_LIQUIDITY_VAULT_RUNTIME_DEFAULT_TARGET_RESERVE_COVERAGE_BPS,
            low_fee_bps: MONERO_L2_PQ_PRIVATE_EXIT_LIQUIDITY_VAULT_RUNTIME_DEFAULT_LOW_FEE_BPS,
            max_user_fee_bps:
                MONERO_L2_PQ_PRIVATE_EXIT_LIQUIDITY_VAULT_RUNTIME_DEFAULT_MAX_USER_FEE_BPS,
            lp_fee_bps: MONERO_L2_PQ_PRIVATE_EXIT_LIQUIDITY_VAULT_RUNTIME_DEFAULT_LP_FEE_BPS,
            rebate_bps: MONERO_L2_PQ_PRIVATE_EXIT_LIQUIDITY_VAULT_RUNTIME_DEFAULT_REBATE_BPS,
            sponsor_cover_bps:
                MONERO_L2_PQ_PRIVATE_EXIT_LIQUIDITY_VAULT_RUNTIME_DEFAULT_SPONSOR_COVER_BPS,
            max_batch_items:
                MONERO_L2_PQ_PRIVATE_EXIT_LIQUIDITY_VAULT_RUNTIME_DEFAULT_MAX_BATCH_ITEMS,
        }
    }
}

impl Config {
    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "monero_network": self.monero_network,
            "l2_network": self.l2_network,
            "asset_id": self.asset_id,
            "fee_asset_id": self.fee_asset_id,
            "stable_asset_id": self.stable_asset_id,
            "hash_suite": self.hash_suite,
            "vault_scheme": self.vault_scheme,
            "lp_scheme": self.lp_scheme,
            "reserve_attestation_scheme": self.reserve_attestation_scheme,
            "quote_scheme": self.quote_scheme,
            "sponsor_scheme": self.sponsor_scheme,
            "batch_scheme": self.batch_scheme,
            "receipt_scheme": self.receipt_scheme,
            "nullifier_scheme": self.nullifier_scheme,
            "replay_domain": self.replay_domain,
            "quote_ttl_blocks": self.quote_ttl_blocks,
            "sponsor_ttl_blocks": self.sponsor_ttl_blocks,
            "batch_ttl_blocks": self.batch_ttl_blocks,
            "receipt_finality_blocks": self.receipt_finality_blocks,
            "rebate_ttl_blocks": self.rebate_ttl_blocks,
            "min_privacy_set_size": self.min_privacy_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
            "target_pq_security_bits": self.target_pq_security_bits,
            "min_reserve_coverage_bps": self.min_reserve_coverage_bps,
            "target_reserve_coverage_bps": self.target_reserve_coverage_bps,
            "low_fee_bps": self.low_fee_bps,
            "max_user_fee_bps": self.max_user_fee_bps,
            "lp_fee_bps": self.lp_fee_bps,
            "rebate_bps": self.rebate_bps,
            "sponsor_cover_bps": self.sponsor_cover_bps,
            "max_batch_items": self.max_batch_items,
        })
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Counters {
    pub vaults: u64,
    pub lp_commitments: u64,
    pub reserve_attestations: u64,
    pub encrypted_quotes: u64,
    pub sponsor_reservations: u64,
    pub batch_settlements: u64,
    pub receipts: u64,
    pub rebates: u64,
    pub fences: u64,
    pub events: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "vaults": self.vaults,
            "lp_commitments": self.lp_commitments,
            "reserve_attestations": self.reserve_attestations,
            "encrypted_quotes": self.encrypted_quotes,
            "sponsor_reservations": self.sponsor_reservations,
            "batch_settlements": self.batch_settlements,
            "receipts": self.receipts,
            "rebates": self.rebates,
            "fences": self.fences,
            "events": self.events,
        })
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Roots {
    pub config_root: String,
    pub vault_root: String,
    pub lp_commitment_root: String,
    pub reserve_attestation_root: String,
    pub encrypted_quote_root: String,
    pub sponsor_reservation_root: String,
    pub batch_settlement_root: String,
    pub receipt_root: String,
    pub rebate_root: String,
    pub nullifier_fence_root: String,
    pub public_event_root: String,
    pub counters_root: String,
    pub public_record_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "vault_root": self.vault_root,
            "lp_commitment_root": self.lp_commitment_root,
            "reserve_attestation_root": self.reserve_attestation_root,
            "encrypted_quote_root": self.encrypted_quote_root,
            "sponsor_reservation_root": self.sponsor_reservation_root,
            "batch_settlement_root": self.batch_settlement_root,
            "receipt_root": self.receipt_root,
            "rebate_root": self.rebate_root,
            "nullifier_fence_root": self.nullifier_fence_root,
            "public_event_root": self.public_event_root,
            "counters_root": self.counters_root,
            "public_record_root": self.public_record_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrivateExitLiquidityVault {
    pub vault_id: String,
    pub operator_commitment: String,
    pub lane: ExitLane,
    pub status: VaultStatus,
    pub spend_public_key_root: String,
    pub view_public_key_root: String,
    pub pq_verification_key_root: String,
    pub monero_reserve_address_commitment: String,
    pub reserve_commitment_root: String,
    pub available_liquidity_commitment: String,
    pub max_exit_commitment: String,
    pub fee_policy_root: String,
    pub defi_route_root: String,
    pub privacy_set_size: u64,
    pub reserve_coverage_bps: u64,
    pub pq_security_bits: u16,
    pub created_height: u64,
    pub updated_height: u64,
}

impl PrivateExitLiquidityVault {
    pub fn public_record(&self) -> Value {
        json!({
            "vault_id": self.vault_id,
            "operator_commitment": self.operator_commitment,
            "lane": self.lane.as_str(),
            "status": self.status.as_str(),
            "spend_public_key_root": self.spend_public_key_root,
            "view_public_key_root": self.view_public_key_root,
            "pq_verification_key_root": self.pq_verification_key_root,
            "monero_reserve_address_commitment": self.monero_reserve_address_commitment,
            "reserve_commitment_root": self.reserve_commitment_root,
            "available_liquidity_commitment": self.available_liquidity_commitment,
            "max_exit_commitment": self.max_exit_commitment,
            "fee_policy_root": self.fee_policy_root,
            "defi_route_root": self.defi_route_root,
            "privacy_set_size": self.privacy_set_size,
            "reserve_coverage_bps": self.reserve_coverage_bps,
            "pq_security_bits": self.pq_security_bits,
            "created_height": self.created_height,
            "updated_height": self.updated_height,
        })
    }

    pub fn root(&self) -> String {
        root_from_record(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-VAULT",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LpCommitment {
    pub lp_commitment_id: String,
    pub vault_id: String,
    pub provider_commitment: String,
    pub contribution_commitment: String,
    pub share_commitment: String,
    pub reward_key_commitment: String,
    pub withdrawal_nullifier_root: String,
    pub lock_until_height: u64,
    pub status: CommitmentStatus,
    pub created_height: u64,
}

impl LpCommitment {
    pub fn public_record(&self) -> Value {
        json!({
            "lp_commitment_id": self.lp_commitment_id,
            "vault_id": self.vault_id,
            "provider_commitment": self.provider_commitment,
            "contribution_commitment": self.contribution_commitment,
            "share_commitment": self.share_commitment,
            "reward_key_commitment": self.reward_key_commitment,
            "withdrawal_nullifier_root": self.withdrawal_nullifier_root,
            "lock_until_height": self.lock_until_height,
            "status": self.status.as_str(),
            "created_height": self.created_height,
        })
    }

    pub fn root(&self) -> String {
        root_from_record(
            "MONERO-L2-PQ-PRIVATE-EXIT-LP-COMMITMENT",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PqReserveAttestation {
    pub attestation_id: String,
    pub vault_id: String,
    pub reserve_epoch: u64,
    pub monero_height: u64,
    pub l2_height: u64,
    pub reserve_commitment_root: String,
    pub reserve_output_root: String,
    pub encrypted_sample_root: String,
    pub coverage_bps: u64,
    pub watcher_set_root: String,
    pub pq_signature_root: String,
    pub status: String,
}

impl PqReserveAttestation {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "vault_id": self.vault_id,
            "reserve_epoch": self.reserve_epoch,
            "monero_height": self.monero_height,
            "l2_height": self.l2_height,
            "reserve_commitment_root": self.reserve_commitment_root,
            "reserve_output_root": self.reserve_output_root,
            "encrypted_sample_root": self.encrypted_sample_root,
            "coverage_bps": self.coverage_bps,
            "watcher_set_root": self.watcher_set_root,
            "pq_signature_root": self.pq_signature_root,
            "status": self.status,
        })
    }

    pub fn root(&self) -> String {
        root_from_record(
            "MONERO-L2-PQ-PRIVATE-EXIT-RESERVE-ATTESTATION",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncryptedExitQuote {
    pub quote_id: String,
    pub vault_id: String,
    pub lane: ExitLane,
    pub exit_note_commitment: String,
    pub exit_nullifier: String,
    pub recipient_view_commitment: String,
    pub amount_commitment: String,
    pub max_fee_commitment: String,
    pub encrypted_quote_blob_root: String,
    pub quote_ciphertext_root: String,
    pub pq_ephemeral_key_root: String,
    pub route_commitment_root: String,
    pub fee_bps: u64,
    pub priority_weight: u64,
    pub privacy_set_size: u64,
    pub requested_height: u64,
    pub expires_height: u64,
    pub status: QuoteStatus,
}

impl EncryptedExitQuote {
    pub fn public_record(&self) -> Value {
        json!({
            "quote_id": self.quote_id,
            "vault_id": self.vault_id,
            "lane": self.lane.as_str(),
            "exit_note_commitment": self.exit_note_commitment,
            "exit_nullifier": self.exit_nullifier,
            "recipient_view_commitment": self.recipient_view_commitment,
            "amount_commitment": self.amount_commitment,
            "max_fee_commitment": self.max_fee_commitment,
            "encrypted_quote_blob_root": self.encrypted_quote_blob_root,
            "quote_ciphertext_root": self.quote_ciphertext_root,
            "pq_ephemeral_key_root": self.pq_ephemeral_key_root,
            "route_commitment_root": self.route_commitment_root,
            "fee_bps": self.fee_bps,
            "priority_weight": self.priority_weight,
            "privacy_set_size": self.privacy_set_size,
            "requested_height": self.requested_height,
            "expires_height": self.expires_height,
            "status": self.status.as_str(),
        })
    }

    pub fn root(&self) -> String {
        root_from_record(
            "MONERO-L2-PQ-PRIVATE-EXIT-ENCRYPTED-QUOTE",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FeeSponsorReservation {
    pub reservation_id: String,
    pub sponsor_commitment: String,
    pub quote_id: String,
    pub vault_id: String,
    pub credential_nullifier: String,
    pub fee_budget_commitment: String,
    pub covered_fee_bps: u64,
    pub sponsor_policy_root: String,
    pub rebate_address_commitment: String,
    pub created_height: u64,
    pub expires_height: u64,
    pub status: ReservationStatus,
}

impl FeeSponsorReservation {
    pub fn public_record(&self) -> Value {
        json!({
            "reservation_id": self.reservation_id,
            "sponsor_commitment": self.sponsor_commitment,
            "quote_id": self.quote_id,
            "vault_id": self.vault_id,
            "credential_nullifier": self.credential_nullifier,
            "fee_budget_commitment": self.fee_budget_commitment,
            "covered_fee_bps": self.covered_fee_bps,
            "sponsor_policy_root": self.sponsor_policy_root,
            "rebate_address_commitment": self.rebate_address_commitment,
            "created_height": self.created_height,
            "expires_height": self.expires_height,
            "status": self.status.as_str(),
        })
    }

    pub fn root(&self) -> String {
        root_from_record(
            "MONERO-L2-PQ-PRIVATE-EXIT-FEE-SPONSOR-RESERVATION",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BatchSettlement {
    pub batch_id: String,
    pub vault_id: String,
    pub lane: ExitLane,
    pub quote_root: String,
    pub reservation_root: String,
    pub nullifier_root: String,
    pub payout_commitment_root: String,
    pub monero_tx_commitment: String,
    pub settlement_proof_root: String,
    pub reserve_attestation_root: String,
    pub fee_distribution_root: String,
    pub item_count: u64,
    pub sealed_height: u64,
    pub submitted_height: u64,
    pub status: BatchStatus,
}

impl BatchSettlement {
    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "vault_id": self.vault_id,
            "lane": self.lane.as_str(),
            "quote_root": self.quote_root,
            "reservation_root": self.reservation_root,
            "nullifier_root": self.nullifier_root,
            "payout_commitment_root": self.payout_commitment_root,
            "monero_tx_commitment": self.monero_tx_commitment,
            "settlement_proof_root": self.settlement_proof_root,
            "reserve_attestation_root": self.reserve_attestation_root,
            "fee_distribution_root": self.fee_distribution_root,
            "item_count": self.item_count,
            "sealed_height": self.sealed_height,
            "submitted_height": self.submitted_height,
            "status": self.status.as_str(),
        })
    }

    pub fn root(&self) -> String {
        root_from_record(
            "MONERO-L2-PQ-PRIVATE-EXIT-BATCH-SETTLEMENT",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExitReceipt {
    pub receipt_id: String,
    pub quote_id: String,
    pub batch_id: String,
    pub vault_id: String,
    pub exit_nullifier: String,
    pub payout_commitment: String,
    pub monero_tx_commitment: String,
    pub settlement_receipt_root: String,
    pub fee_paid_commitment: String,
    pub rebate_commitment: String,
    pub finality_height: u64,
    pub status: ReceiptStatus,
}

impl ExitReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "quote_id": self.quote_id,
            "batch_id": self.batch_id,
            "vault_id": self.vault_id,
            "exit_nullifier": self.exit_nullifier,
            "payout_commitment": self.payout_commitment,
            "monero_tx_commitment": self.monero_tx_commitment,
            "settlement_receipt_root": self.settlement_receipt_root,
            "fee_paid_commitment": self.fee_paid_commitment,
            "rebate_commitment": self.rebate_commitment,
            "finality_height": self.finality_height,
            "status": self.status.as_str(),
        })
    }

    pub fn root(&self) -> String {
        root_from_record("MONERO-L2-PQ-PRIVATE-EXIT-RECEIPT", &self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExitRebate {
    pub rebate_id: String,
    pub receipt_id: String,
    pub sponsor_reservation_id: String,
    pub rebate_nullifier: String,
    pub recipient_commitment: String,
    pub rebate_commitment: String,
    pub sponsor_commitment: String,
    pub claim_window_start: u64,
    pub claim_window_end: u64,
    pub claimed: bool,
}

impl ExitRebate {
    pub fn public_record(&self) -> Value {
        json!({
            "rebate_id": self.rebate_id,
            "receipt_id": self.receipt_id,
            "sponsor_reservation_id": self.sponsor_reservation_id,
            "rebate_nullifier": self.rebate_nullifier,
            "recipient_commitment": self.recipient_commitment,
            "rebate_commitment": self.rebate_commitment,
            "sponsor_commitment": self.sponsor_commitment,
            "claim_window_start": self.claim_window_start,
            "claim_window_end": self.claim_window_end,
            "claimed": self.claimed,
        })
    }

    pub fn root(&self) -> String {
        root_from_record("MONERO-L2-PQ-PRIVATE-EXIT-REBATE", &self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrivacyNullifierFence {
    pub fence_id: String,
    pub kind: FenceKind,
    pub subject_id: String,
    pub nullifier: String,
    pub fence_root: String,
    pub height: u64,
}

impl PrivacyNullifierFence {
    pub fn public_record(&self) -> Value {
        json!({
            "fence_id": self.fence_id,
            "kind": self.kind.as_str(),
            "subject_id": self.subject_id,
            "nullifier": self.nullifier,
            "fence_root": self.fence_root,
            "height": self.height,
        })
    }

    pub fn root(&self) -> String {
        root_from_record(
            "MONERO-L2-PQ-PRIVATE-EXIT-NULLIFIER-FENCE",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub vaults: BTreeMap<String, PrivateExitLiquidityVault>,
    pub lp_commitments: BTreeMap<String, LpCommitment>,
    pub reserve_attestations: BTreeMap<String, PqReserveAttestation>,
    pub encrypted_quotes: BTreeMap<String, EncryptedExitQuote>,
    pub sponsor_reservations: BTreeMap<String, FeeSponsorReservation>,
    pub batch_settlements: BTreeMap<String, BatchSettlement>,
    pub receipts: BTreeMap<String, ExitReceipt>,
    pub rebates: BTreeMap<String, ExitRebate>,
    pub nullifier_fences: BTreeMap<String, PrivacyNullifierFence>,
    pub used_nullifiers: BTreeSet<String>,
    pub public_events: Vec<Value>,
}

impl Default for State {
    fn default() -> Self {
        let mut state = Self {
            config: Config::default(),
            counters: Counters::default(),
            roots: Roots::default(),
            vaults: BTreeMap::new(),
            lp_commitments: BTreeMap::new(),
            reserve_attestations: BTreeMap::new(),
            encrypted_quotes: BTreeMap::new(),
            sponsor_reservations: BTreeMap::new(),
            batch_settlements: BTreeMap::new(),
            receipts: BTreeMap::new(),
            rebates: BTreeMap::new(),
            nullifier_fences: BTreeMap::new(),
            used_nullifiers: BTreeSet::new(),
            public_events: Vec::new(),
        };
        state.refresh_roots();
        state
    }
}

impl State {
    pub fn devnet() -> Self {
        let mut state = Self::default();
        let base_height = MONERO_L2_PQ_PRIVATE_EXIT_LIQUIDITY_VAULT_RUNTIME_DEVNET_HEIGHT;
        let vault_a = state.devnet_vault("alpha", ExitLane::SponsoredLowFee, base_height);
        let vault_b = state.devnet_vault("bravo", ExitLane::Defi, base_height + 1);

        state.insert_vault(vault_a.clone());
        state.insert_vault(vault_b.clone());
        state.insert_lp_commitment(state.devnet_lp(
            "alpha-lp-0",
            &vault_a.vault_id,
            base_height + 2,
        ));
        state.insert_lp_commitment(state.devnet_lp(
            "alpha-lp-1",
            &vault_a.vault_id,
            base_height + 3,
        ));
        state.insert_lp_commitment(state.devnet_lp(
            "bravo-lp-0",
            &vault_b.vault_id,
            base_height + 4,
        ));

        let attestation_a =
            state.devnet_attestation("alpha-attestation-0", &vault_a, 0, base_height + 5);
        let attestation_b =
            state.devnet_attestation("bravo-attestation-0", &vault_b, 0, base_height + 6);
        state.insert_reserve_attestation(attestation_a.clone());
        state.insert_reserve_attestation(attestation_b.clone());

        let quote_a = state.devnet_quote(
            "alpha-quote-0",
            &vault_a,
            ExitLane::SponsoredLowFee,
            base_height + 7,
        );
        let quote_b =
            state.devnet_quote("bravo-quote-0", &vault_b, ExitLane::Defi, base_height + 8);
        state.insert_encrypted_quote(quote_a.clone());
        state.insert_encrypted_quote(quote_b.clone());

        let sponsor_a = state.devnet_sponsor_reservation(
            "alpha-sponsor-0",
            &vault_a,
            &quote_a,
            base_height + 9,
        );
        state.insert_sponsor_reservation(sponsor_a.clone());

        let batch_a = state.devnet_batch(
            "alpha-batch-0",
            &vault_a,
            &quote_a,
            &sponsor_a,
            &attestation_a,
            base_height + 12,
        );
        state.insert_batch_settlement(batch_a.clone());

        let receipt_a = state.devnet_receipt(
            "alpha-receipt-0",
            &vault_a,
            &quote_a,
            &batch_a,
            base_height + 18,
        );
        state.insert_receipt(receipt_a.clone());
        state.insert_rebate(state.devnet_rebate(
            "alpha-rebate-0",
            &receipt_a,
            &sponsor_a,
            base_height + 19,
        ));

        state.insert_fence(state.devnet_fence(
            FenceKind::ExitNullifier,
            &quote_a.quote_id,
            &quote_a.exit_nullifier,
            base_height + 7,
        ));
        state.insert_fence(state.devnet_fence(
            FenceKind::ReservationNullifier,
            &sponsor_a.reservation_id,
            &sponsor_a.credential_nullifier,
            base_height + 9,
        ));

        state.push_event(
            "devnet_private_exit_vault_ready",
            json!({
                "vault_count": state.vaults.len(),
                "quote_count": state.encrypted_quotes.len(),
                "batch_count": state.batch_settlements.len(),
            }),
            base_height + 20,
        );
        state.refresh_roots();
        state
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": MONERO_L2_PQ_PRIVATE_EXIT_LIQUIDITY_VAULT_RUNTIME_SCHEMA_VERSION,
            "chain_id": CHAIN_ID,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": self.roots_without_self_reference().public_record(),
        })
    }

    pub fn state_root(&self) -> String {
        state_root_from_record(&self.public_record())
    }

    pub fn refresh_roots(&mut self) {
        let config_record = self.config.public_record();
        let counter_record = self.counters.public_record();
        let vault_records = values_from_map(&self.vaults, PrivateExitLiquidityVault::public_record);
        let lp_records = values_from_map(&self.lp_commitments, LpCommitment::public_record);
        let attestation_records = values_from_map(
            &self.reserve_attestations,
            PqReserveAttestation::public_record,
        );
        let quote_records =
            values_from_map(&self.encrypted_quotes, EncryptedExitQuote::public_record);
        let sponsor_records = values_from_map(
            &self.sponsor_reservations,
            FeeSponsorReservation::public_record,
        );
        let batch_records =
            values_from_map(&self.batch_settlements, BatchSettlement::public_record);
        let receipt_records = values_from_map(&self.receipts, ExitReceipt::public_record);
        let rebate_records = values_from_map(&self.rebates, ExitRebate::public_record);
        let fence_records =
            values_from_map(&self.nullifier_fences, PrivacyNullifierFence::public_record);

        self.roots.config_root = payload_root("MONERO-L2-PQ-PRIVATE-EXIT-CONFIG", &config_record);
        self.roots.counters_root =
            payload_root("MONERO-L2-PQ-PRIVATE-EXIT-COUNTERS", &counter_record);
        self.roots.vault_root = merkle_root("MONERO-L2-PQ-PRIVATE-EXIT-VAULTS", &vault_records);
        self.roots.lp_commitment_root =
            merkle_root("MONERO-L2-PQ-PRIVATE-EXIT-LP-COMMITMENTS", &lp_records);
        self.roots.reserve_attestation_root = merkle_root(
            "MONERO-L2-PQ-PRIVATE-EXIT-RESERVE-ATTESTATIONS",
            &attestation_records,
        );
        self.roots.encrypted_quote_root =
            merkle_root("MONERO-L2-PQ-PRIVATE-EXIT-ENCRYPTED-QUOTES", &quote_records);
        self.roots.sponsor_reservation_root = merkle_root(
            "MONERO-L2-PQ-PRIVATE-EXIT-SPONSOR-RESERVATIONS",
            &sponsor_records,
        );
        self.roots.batch_settlement_root = merkle_root(
            "MONERO-L2-PQ-PRIVATE-EXIT-BATCH-SETTLEMENTS",
            &batch_records,
        );
        self.roots.receipt_root =
            merkle_root("MONERO-L2-PQ-PRIVATE-EXIT-RECEIPTS", &receipt_records);
        self.roots.rebate_root = merkle_root("MONERO-L2-PQ-PRIVATE-EXIT-REBATES", &rebate_records);
        self.roots.nullifier_fence_root =
            merkle_root("MONERO-L2-PQ-PRIVATE-EXIT-NULLIFIER-FENCES", &fence_records);
        self.roots.public_event_root = merkle_root(
            "MONERO-L2-PQ-PRIVATE-EXIT-PUBLIC-EVENTS",
            &self.public_events,
        );
        self.roots.public_record_root = public_record_root(&self.public_record_without_roots());
        self.roots.state_root = state_root_from_record(&self.public_record_without_state_root());
    }

    pub fn insert_vault(&mut self, vault: PrivateExitLiquidityVault) {
        self.counters.vaults = self.counters.vaults.max(self.vaults.len() as u64 + 1);
        self.vaults.insert(vault.vault_id.clone(), vault);
        self.refresh_roots();
    }

    pub fn insert_lp_commitment(&mut self, commitment: LpCommitment) {
        self.counters.lp_commitments = self
            .counters
            .lp_commitments
            .max(self.lp_commitments.len() as u64 + 1);
        self.lp_commitments
            .insert(commitment.lp_commitment_id.clone(), commitment);
        self.refresh_roots();
    }

    pub fn insert_reserve_attestation(&mut self, attestation: PqReserveAttestation) {
        self.counters.reserve_attestations = self
            .counters
            .reserve_attestations
            .max(self.reserve_attestations.len() as u64 + 1);
        self.reserve_attestations
            .insert(attestation.attestation_id.clone(), attestation);
        self.refresh_roots();
    }

    pub fn insert_encrypted_quote(&mut self, quote: EncryptedExitQuote) {
        self.counters.encrypted_quotes = self
            .counters
            .encrypted_quotes
            .max(self.encrypted_quotes.len() as u64 + 1);
        self.used_nullifiers.insert(quote.exit_nullifier.clone());
        self.encrypted_quotes.insert(quote.quote_id.clone(), quote);
        self.refresh_roots();
    }

    pub fn insert_sponsor_reservation(&mut self, reservation: FeeSponsorReservation) {
        self.counters.sponsor_reservations = self
            .counters
            .sponsor_reservations
            .max(self.sponsor_reservations.len() as u64 + 1);
        self.used_nullifiers
            .insert(reservation.credential_nullifier.clone());
        self.sponsor_reservations
            .insert(reservation.reservation_id.clone(), reservation);
        self.refresh_roots();
    }

    pub fn insert_batch_settlement(&mut self, batch: BatchSettlement) {
        self.counters.batch_settlements = self
            .counters
            .batch_settlements
            .max(self.batch_settlements.len() as u64 + 1);
        self.batch_settlements.insert(batch.batch_id.clone(), batch);
        self.refresh_roots();
    }

    pub fn insert_receipt(&mut self, receipt: ExitReceipt) {
        self.counters.receipts = self.counters.receipts.max(self.receipts.len() as u64 + 1);
        self.receipts.insert(receipt.receipt_id.clone(), receipt);
        self.refresh_roots();
    }

    pub fn insert_rebate(&mut self, rebate: ExitRebate) {
        self.counters.rebates = self.counters.rebates.max(self.rebates.len() as u64 + 1);
        self.used_nullifiers.insert(rebate.rebate_nullifier.clone());
        self.rebates.insert(rebate.rebate_id.clone(), rebate);
        self.refresh_roots();
    }

    pub fn insert_fence(&mut self, fence: PrivacyNullifierFence) {
        self.counters.fences = self
            .counters
            .fences
            .max(self.nullifier_fences.len() as u64 + 1);
        self.used_nullifiers.insert(fence.nullifier.clone());
        self.nullifier_fences.insert(fence.fence_id.clone(), fence);
        self.refresh_roots();
    }

    pub fn push_event(&mut self, event_type: &str, payload: Value, height: u64) {
        let event_id = event_id(event_type, height, self.counters.events + 1, &payload);
        self.public_events.push(json!({
            "event_id": event_id,
            "event_type": event_type,
            "height": height,
            "payload": payload,
        }));
        self.counters.events += 1;
        self.refresh_roots();
    }

    pub fn validate_config(&self) -> MoneroL2PqPrivateExitLiquidityVaultRuntimeResult<()> {
        if self.config.chain_id != CHAIN_ID {
            return Err("config chain_id does not match crate CHAIN_ID".to_string());
        }
        if self.config.min_pq_security_bits
            < MONERO_L2_PQ_PRIVATE_EXIT_LIQUIDITY_VAULT_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS
        {
            return Err("min pq security bits below runtime floor".to_string());
        }
        if self.config.low_fee_bps > self.config.max_user_fee_bps {
            return Err("low fee bps exceeds max user fee bps".to_string());
        }
        if self.config.lp_fee_bps > self.config.max_user_fee_bps {
            return Err("lp fee bps exceeds max user fee bps".to_string());
        }
        if self.config.rebate_bps > MONERO_L2_PQ_PRIVATE_EXIT_LIQUIDITY_VAULT_RUNTIME_MAX_BPS {
            return Err("rebate bps exceeds max bps".to_string());
        }
        Ok(())
    }

    pub fn validate_private_exit_fences(
        &self,
    ) -> MoneroL2PqPrivateExitLiquidityVaultRuntimeResult<()> {
        let mut seen = BTreeSet::new();
        for quote in self.encrypted_quotes.values() {
            if !seen.insert(quote.exit_nullifier.clone()) {
                return Err(format!(
                    "duplicate exit nullifier for quote {}",
                    quote.quote_id
                ));
            }
            if quote.privacy_set_size < self.config.min_privacy_set_size {
                return Err(format!(
                    "quote {} privacy set below minimum",
                    quote.quote_id
                ));
            }
        }
        for reservation in self.sponsor_reservations.values() {
            if !seen.insert(reservation.credential_nullifier.clone()) {
                return Err(format!(
                    "duplicate sponsor credential nullifier for reservation {}",
                    reservation.reservation_id
                ));
            }
        }
        for rebate in self.rebates.values() {
            if !seen.insert(rebate.rebate_nullifier.clone()) {
                return Err(format!(
                    "duplicate rebate nullifier for rebate {}",
                    rebate.rebate_id
                ));
            }
        }
        Ok(())
    }

    pub fn validate_reserve_coverage(
        &self,
    ) -> MoneroL2PqPrivateExitLiquidityVaultRuntimeResult<()> {
        for vault in self.vaults.values() {
            if vault.status.usable()
                && vault.reserve_coverage_bps < self.config.min_reserve_coverage_bps
            {
                return Err(format!(
                    "vault {} reserve coverage below minimum",
                    vault.vault_id
                ));
            }
            if vault.pq_security_bits < self.config.min_pq_security_bits {
                return Err(format!(
                    "vault {} pq security below minimum",
                    vault.vault_id
                ));
            }
        }
        for attestation in self.reserve_attestations.values() {
            if attestation.coverage_bps < self.config.min_reserve_coverage_bps {
                return Err(format!(
                    "attestation {} reserve coverage below minimum",
                    attestation.attestation_id
                ));
            }
        }
        Ok(())
    }

    pub fn live_quote_ids(&self) -> Vec<String> {
        self.encrypted_quotes
            .values()
            .filter(|quote| quote.status.live())
            .map(|quote| quote.quote_id.clone())
            .collect()
    }

    pub fn vault_liquidity_score(&self, vault_id: &str) -> u64 {
        let Some(vault) = self.vaults.get(vault_id) else {
            return 0;
        };
        let lp_count = self
            .lp_commitments
            .values()
            .filter(|commitment| commitment.vault_id == vault_id && commitment.status.liquid())
            .count() as u64;
        vault
            .reserve_coverage_bps
            .saturating_add(vault.privacy_set_size / 1024)
            .saturating_add(lp_count.saturating_mul(100))
            .saturating_add(vault.lane.priority_weight())
    }

    pub fn vault_records(&self) -> Vec<Value> {
        values_from_map(&self.vaults, PrivateExitLiquidityVault::public_record)
    }

    pub fn lp_commitment_records(&self) -> Vec<Value> {
        values_from_map(&self.lp_commitments, LpCommitment::public_record)
    }

    pub fn reserve_attestation_records(&self) -> Vec<Value> {
        values_from_map(
            &self.reserve_attestations,
            PqReserveAttestation::public_record,
        )
    }

    pub fn encrypted_quote_records(&self) -> Vec<Value> {
        values_from_map(&self.encrypted_quotes, EncryptedExitQuote::public_record)
    }

    pub fn sponsor_reservation_records(&self) -> Vec<Value> {
        values_from_map(
            &self.sponsor_reservations,
            FeeSponsorReservation::public_record,
        )
    }

    pub fn batch_settlement_records(&self) -> Vec<Value> {
        values_from_map(&self.batch_settlements, BatchSettlement::public_record)
    }

    pub fn receipt_records(&self) -> Vec<Value> {
        values_from_map(&self.receipts, ExitReceipt::public_record)
    }

    pub fn rebate_records(&self) -> Vec<Value> {
        values_from_map(&self.rebates, ExitRebate::public_record)
    }

    pub fn nullifier_fence_records(&self) -> Vec<Value> {
        values_from_map(&self.nullifier_fences, PrivacyNullifierFence::public_record)
    }

    pub fn vault_ids_by_status(&self, status: VaultStatus) -> Vec<String> {
        self.vaults
            .values()
            .filter(|vault| vault.status == status)
            .map(|vault| vault.vault_id.clone())
            .collect()
    }

    pub fn quote_ids_by_status(&self, status: QuoteStatus) -> Vec<String> {
        self.encrypted_quotes
            .values()
            .filter(|quote| quote.status == status)
            .map(|quote| quote.quote_id.clone())
            .collect()
    }

    pub fn reservation_ids_by_status(&self, status: ReservationStatus) -> Vec<String> {
        self.sponsor_reservations
            .values()
            .filter(|reservation| reservation.status == status)
            .map(|reservation| reservation.reservation_id.clone())
            .collect()
    }

    pub fn batch_ids_by_status(&self, status: BatchStatus) -> Vec<String> {
        self.batch_settlements
            .values()
            .filter(|batch| batch.status == status)
            .map(|batch| batch.batch_id.clone())
            .collect()
    }

    pub fn receipt_ids_by_status(&self, status: ReceiptStatus) -> Vec<String> {
        self.receipts
            .values()
            .filter(|receipt| receipt.status == status)
            .map(|receipt| receipt.receipt_id.clone())
            .collect()
    }

    pub fn quotes_for_vault(&self, vault_id: &str) -> Vec<EncryptedExitQuote> {
        self.encrypted_quotes
            .values()
            .filter(|quote| quote.vault_id == vault_id)
            .cloned()
            .collect()
    }

    pub fn reservations_for_quote(&self, quote_id: &str) -> Vec<FeeSponsorReservation> {
        self.sponsor_reservations
            .values()
            .filter(|reservation| reservation.quote_id == quote_id)
            .cloned()
            .collect()
    }

    pub fn receipts_for_batch(&self, batch_id: &str) -> Vec<ExitReceipt> {
        self.receipts
            .values()
            .filter(|receipt| receipt.batch_id == batch_id)
            .cloned()
            .collect()
    }

    pub fn rebates_for_receipt(&self, receipt_id: &str) -> Vec<ExitRebate> {
        self.rebates
            .values()
            .filter(|rebate| rebate.receipt_id == receipt_id)
            .cloned()
            .collect()
    }

    pub fn privacy_summary_record(&self) -> Value {
        let live_quotes = self
            .encrypted_quotes
            .values()
            .filter(|quote| quote.status.live())
            .count();
        let min_quote_privacy_set = self
            .encrypted_quotes
            .values()
            .map(|quote| quote.privacy_set_size)
            .min()
            .unwrap_or_default();
        json!({
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "nullifier_scheme": self.config.nullifier_scheme,
            "replay_domain": self.config.replay_domain,
            "used_nullifier_count": self.used_nullifiers.len(),
            "fence_count": self.nullifier_fences.len(),
            "live_quote_count": live_quotes,
            "min_quote_privacy_set": min_quote_privacy_set,
            "required_min_privacy_set": self.config.min_privacy_set_size,
            "nullifier_fence_root": self.roots.nullifier_fence_root,
        })
    }

    pub fn liquidity_summary_record(&self) -> Value {
        let active_vaults = self
            .vaults
            .values()
            .filter(|vault| vault.status.usable())
            .count();
        let active_lp_commitments = self
            .lp_commitments
            .values()
            .filter(|commitment| commitment.status.liquid())
            .count();
        let best_vault = self
            .vaults
            .keys()
            .max_by_key(|vault_id| self.vault_liquidity_score(vault_id))
            .cloned()
            .unwrap_or_default();
        json!({
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "asset_id": self.config.asset_id,
            "stable_asset_id": self.config.stable_asset_id,
            "active_vault_count": active_vaults,
            "active_lp_commitment_count": active_lp_commitments,
            "best_vault_id": best_vault,
            "target_reserve_coverage_bps": self.config.target_reserve_coverage_bps,
            "vault_root": self.roots.vault_root,
            "lp_commitment_root": self.roots.lp_commitment_root,
        })
    }

    pub fn fee_summary_record(&self) -> Value {
        let sponsored_quote_count = self
            .encrypted_quotes
            .values()
            .filter(|quote| quote.lane == ExitLane::SponsoredLowFee)
            .count();
        json!({
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "fee_asset_id": self.config.fee_asset_id,
            "low_fee_bps": self.config.low_fee_bps,
            "max_user_fee_bps": self.config.max_user_fee_bps,
            "lp_fee_bps": self.config.lp_fee_bps,
            "rebate_bps": self.config.rebate_bps,
            "sponsor_cover_bps": self.config.sponsor_cover_bps,
            "sponsored_quote_count": sponsored_quote_count,
            "sponsor_reservation_root": self.roots.sponsor_reservation_root,
            "rebate_root": self.roots.rebate_root,
        })
    }

    pub fn pq_summary_record(&self) -> Value {
        let min_vault_security = self
            .vaults
            .values()
            .map(|vault| vault.pq_security_bits)
            .min()
            .unwrap_or(self.config.target_pq_security_bits);
        let min_attested_coverage = self
            .reserve_attestations
            .values()
            .map(|attestation| attestation.coverage_bps)
            .min()
            .unwrap_or_default();
        json!({
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "reserve_attestation_scheme": self.config.reserve_attestation_scheme,
            "quote_scheme": self.config.quote_scheme,
            "min_pq_security_bits": self.config.min_pq_security_bits,
            "target_pq_security_bits": self.config.target_pq_security_bits,
            "observed_min_vault_security_bits": min_vault_security,
            "observed_min_attested_coverage_bps": min_attested_coverage,
            "reserve_attestation_root": self.roots.reserve_attestation_root,
            "encrypted_quote_root": self.roots.encrypted_quote_root,
        })
    }

    pub fn settlement_summary_record(&self) -> Value {
        let settled_batches = self
            .batch_settlements
            .values()
            .filter(|batch| batch.status == BatchStatus::Settled)
            .count();
        let final_receipts = self
            .receipts
            .values()
            .filter(|receipt| receipt.status == ReceiptStatus::Final)
            .count();
        json!({
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "batch_scheme": self.config.batch_scheme,
            "receipt_scheme": self.config.receipt_scheme,
            "batch_ttl_blocks": self.config.batch_ttl_blocks,
            "receipt_finality_blocks": self.config.receipt_finality_blocks,
            "settled_batch_count": settled_batches,
            "final_receipt_count": final_receipts,
            "batch_settlement_root": self.roots.batch_settlement_root,
            "receipt_root": self.roots.receipt_root,
        })
    }

    pub fn runtime_summary_record(&self) -> Value {
        json!({
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "privacy": self.privacy_summary_record(),
            "liquidity": self.liquidity_summary_record(),
            "fees": self.fee_summary_record(),
            "post_quantum": self.pq_summary_record(),
            "settlement": self.settlement_summary_record(),
            "state_root": self.roots.state_root,
        })
    }

    pub fn runtime_summary_root(&self) -> String {
        payload_root(
            "MONERO-L2-PQ-PRIVATE-EXIT-RUNTIME-SUMMARY",
            &self.runtime_summary_record(),
        )
    }

    pub fn validate_runtime(&self) -> MoneroL2PqPrivateExitLiquidityVaultRuntimeResult<()> {
        self.validate_config()?;
        self.validate_private_exit_fences()?;
        self.validate_reserve_coverage()?;
        if self.vaults.len() > MONERO_L2_PQ_PRIVATE_EXIT_LIQUIDITY_VAULT_RUNTIME_MAX_VAULTS {
            return Err("vault count exceeds runtime limit".to_string());
        }
        if self.lp_commitments.len()
            > MONERO_L2_PQ_PRIVATE_EXIT_LIQUIDITY_VAULT_RUNTIME_MAX_LP_COMMITMENTS
        {
            return Err("lp commitment count exceeds runtime limit".to_string());
        }
        if self.reserve_attestations.len()
            > MONERO_L2_PQ_PRIVATE_EXIT_LIQUIDITY_VAULT_RUNTIME_MAX_ATTESTATIONS
        {
            return Err("reserve attestation count exceeds runtime limit".to_string());
        }
        if self.encrypted_quotes.len()
            > MONERO_L2_PQ_PRIVATE_EXIT_LIQUIDITY_VAULT_RUNTIME_MAX_QUOTES
        {
            return Err("encrypted quote count exceeds runtime limit".to_string());
        }
        if self.sponsor_reservations.len()
            > MONERO_L2_PQ_PRIVATE_EXIT_LIQUIDITY_VAULT_RUNTIME_MAX_SPONSOR_RESERVATIONS
        {
            return Err("sponsor reservation count exceeds runtime limit".to_string());
        }
        if self.batch_settlements.len()
            > MONERO_L2_PQ_PRIVATE_EXIT_LIQUIDITY_VAULT_RUNTIME_MAX_BATCHES
        {
            return Err("batch settlement count exceeds runtime limit".to_string());
        }
        if self.receipts.len() > MONERO_L2_PQ_PRIVATE_EXIT_LIQUIDITY_VAULT_RUNTIME_MAX_RECEIPTS {
            return Err("receipt count exceeds runtime limit".to_string());
        }
        if self.rebates.len() > MONERO_L2_PQ_PRIVATE_EXIT_LIQUIDITY_VAULT_RUNTIME_MAX_REBATES {
            return Err("rebate count exceeds runtime limit".to_string());
        }
        if self.nullifier_fences.len()
            > MONERO_L2_PQ_PRIVATE_EXIT_LIQUIDITY_VAULT_RUNTIME_MAX_FENCES
        {
            return Err("nullifier fence count exceeds runtime limit".to_string());
        }
        Ok(())
    }

    fn roots_without_self_reference(&self) -> Roots {
        let mut roots = self.roots.clone();
        roots.public_record_root.clear();
        roots.state_root.clear();
        roots
    }

    fn public_record_without_roots(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": MONERO_L2_PQ_PRIVATE_EXIT_LIQUIDITY_VAULT_RUNTIME_SCHEMA_VERSION,
            "chain_id": CHAIN_ID,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
        })
    }

    fn public_record_without_state_root(&self) -> Value {
        let mut roots = self.roots.clone();
        roots.state_root.clear();
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": MONERO_L2_PQ_PRIVATE_EXIT_LIQUIDITY_VAULT_RUNTIME_SCHEMA_VERSION,
            "chain_id": CHAIN_ID,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": roots.public_record(),
        })
    }

    fn devnet_vault(&self, label: &str, lane: ExitLane, height: u64) -> PrivateExitLiquidityVault {
        let operator_commitment = commitment("DEVNET-VAULT-OPERATOR", label);
        let reserve_commitment_root = root_for_label("DEVNET-VAULT-RESERVE", label);
        let vault_id = vault_id(
            label,
            lane,
            &operator_commitment,
            &reserve_commitment_root,
            height,
        );
        PrivateExitLiquidityVault {
            vault_id,
            operator_commitment,
            lane,
            status: VaultStatus::Active,
            spend_public_key_root: root_for_label("DEVNET-MONERO-SPEND-KEY", label),
            view_public_key_root: root_for_label("DEVNET-MONERO-VIEW-KEY", label),
            pq_verification_key_root: root_for_label("DEVNET-PQ-VERIFYING-KEY", label),
            monero_reserve_address_commitment: commitment("DEVNET-MONERO-RESERVE-ADDRESS", label),
            reserve_commitment_root,
            available_liquidity_commitment: commitment("DEVNET-AVAILABLE-LIQUIDITY", label),
            max_exit_commitment: commitment("DEVNET-MAX-EXIT", label),
            fee_policy_root: root_for_label("DEVNET-FEE-POLICY", lane.as_str()),
            defi_route_root: root_for_label("DEVNET-DEFI-ROUTE", label),
            privacy_set_size: self.config.min_privacy_set_size.saturating_mul(2),
            reserve_coverage_bps: self.config.target_reserve_coverage_bps,
            pq_security_bits: self.config.target_pq_security_bits,
            created_height: height,
            updated_height: height,
        }
    }

    fn devnet_lp(&self, label: &str, vault_id: &str, height: u64) -> LpCommitment {
        let provider_commitment = commitment("DEVNET-LP-PROVIDER", label);
        let contribution_commitment = commitment("DEVNET-LP-CONTRIBUTION", label);
        let share_commitment = commitment("DEVNET-LP-SHARE", label);
        let reward_key_commitment = commitment("DEVNET-LP-REWARD-KEY", label);
        LpCommitment {
            lp_commitment_id: lp_commitment_id(
                vault_id,
                &provider_commitment,
                &share_commitment,
                height,
            ),
            vault_id: vault_id.to_string(),
            provider_commitment,
            contribution_commitment,
            share_commitment,
            reward_key_commitment,
            withdrawal_nullifier_root: root_for_label("DEVNET-LP-WITHDRAWAL-NULLIFIER", label),
            lock_until_height: height + 720,
            status: CommitmentStatus::Active,
            created_height: height,
        }
    }

    fn devnet_attestation(
        &self,
        label: &str,
        vault: &PrivateExitLiquidityVault,
        epoch: u64,
        height: u64,
    ) -> PqReserveAttestation {
        PqReserveAttestation {
            attestation_id: reserve_attestation_id(
                &vault.vault_id,
                epoch,
                &vault.reserve_commitment_root,
                height,
            ),
            vault_id: vault.vault_id.clone(),
            reserve_epoch: epoch,
            monero_height: height.saturating_sub(100),
            l2_height: height,
            reserve_commitment_root: vault.reserve_commitment_root.clone(),
            reserve_output_root: root_for_label("DEVNET-RESERVE-OUTPUT", label),
            encrypted_sample_root: root_for_label("DEVNET-ENCRYPTED-RESERVE-SAMPLE", label),
            coverage_bps: self.config.target_reserve_coverage_bps,
            watcher_set_root: root_for_label("DEVNET-RESERVE-WATCHER-SET", label),
            pq_signature_root: root_for_label("DEVNET-RESERVE-PQ-SIGNATURE", label),
            status: "quorum_attested".to_string(),
        }
    }

    fn devnet_quote(
        &self,
        label: &str,
        vault: &PrivateExitLiquidityVault,
        lane: ExitLane,
        height: u64,
    ) -> EncryptedExitQuote {
        let exit_note_commitment = commitment("DEVNET-EXIT-NOTE", label);
        let exit_nullifier = nullifier("DEVNET-EXIT-NULLIFIER", label);
        let amount_commitment = commitment("DEVNET-EXIT-AMOUNT", label);
        let max_fee_commitment = commitment("DEVNET-EXIT-MAX-FEE", label);
        EncryptedExitQuote {
            quote_id: encrypted_quote_id(
                &vault.vault_id,
                &exit_nullifier,
                &amount_commitment,
                height,
            ),
            vault_id: vault.vault_id.clone(),
            lane,
            exit_note_commitment,
            exit_nullifier,
            recipient_view_commitment: commitment("DEVNET-RECIPIENT-VIEW", label),
            amount_commitment,
            max_fee_commitment,
            encrypted_quote_blob_root: root_for_label("DEVNET-ENCRYPTED-QUOTE-BLOB", label),
            quote_ciphertext_root: root_for_label("DEVNET-QUOTE-CIPHERTEXT", label),
            pq_ephemeral_key_root: root_for_label("DEVNET-PQ-EPHEMERAL-KEY", label),
            route_commitment_root: root_for_label("DEVNET-QUOTE-ROUTE", label),
            fee_bps: lane.fee_bps(&self.config),
            priority_weight: lane.priority_weight(),
            privacy_set_size: self.config.min_privacy_set_size.saturating_mul(2),
            requested_height: height,
            expires_height: height + self.config.quote_ttl_blocks,
            status: QuoteStatus::Reserved,
        }
    }

    fn devnet_sponsor_reservation(
        &self,
        label: &str,
        vault: &PrivateExitLiquidityVault,
        quote: &EncryptedExitQuote,
        height: u64,
    ) -> FeeSponsorReservation {
        let sponsor_commitment = commitment("DEVNET-SPONSOR", label);
        let credential_nullifier = nullifier("DEVNET-SPONSOR-CREDENTIAL", label);
        FeeSponsorReservation {
            reservation_id: sponsor_reservation_id(
                &sponsor_commitment,
                &quote.quote_id,
                &credential_nullifier,
                height,
            ),
            sponsor_commitment,
            quote_id: quote.quote_id.clone(),
            vault_id: vault.vault_id.clone(),
            credential_nullifier,
            fee_budget_commitment: commitment("DEVNET-SPONSOR-FEE-BUDGET", label),
            covered_fee_bps: self.config.sponsor_cover_bps,
            sponsor_policy_root: root_for_label("DEVNET-SPONSOR-POLICY", label),
            rebate_address_commitment: commitment("DEVNET-SPONSOR-REBATE-ADDRESS", label),
            created_height: height,
            expires_height: height + self.config.sponsor_ttl_blocks,
            status: ReservationStatus::BoundToQuote,
        }
    }

    fn devnet_batch(
        &self,
        label: &str,
        vault: &PrivateExitLiquidityVault,
        quote: &EncryptedExitQuote,
        reservation: &FeeSponsorReservation,
        attestation: &PqReserveAttestation,
        height: u64,
    ) -> BatchSettlement {
        let quote_records = vec![quote.public_record()];
        let reservation_records = vec![reservation.public_record()];
        let nullifier_records = vec![json!({
            "quote_id": quote.quote_id,
            "exit_nullifier": quote.exit_nullifier,
        })];
        let quote_root = merkle_root("DEVNET-PRIVATE-EXIT-BATCH-QUOTE", &quote_records);
        let reservation_root = merkle_root(
            "DEVNET-PRIVATE-EXIT-BATCH-RESERVATION",
            &reservation_records,
        );
        let nullifier_root = merkle_root("DEVNET-PRIVATE-EXIT-BATCH-NULLIFIER", &nullifier_records);
        BatchSettlement {
            batch_id: batch_settlement_id(&vault.vault_id, &quote_root, &nullifier_root, height),
            vault_id: vault.vault_id.clone(),
            lane: quote.lane,
            quote_root,
            reservation_root,
            nullifier_root,
            payout_commitment_root: root_for_label("DEVNET-BATCH-PAYOUT", label),
            monero_tx_commitment: commitment("DEVNET-BATCH-MONERO-TX", label),
            settlement_proof_root: root_for_label("DEVNET-BATCH-SETTLEMENT-PROOF", label),
            reserve_attestation_root: attestation.root(),
            fee_distribution_root: root_for_label("DEVNET-BATCH-FEE-DISTRIBUTION", label),
            item_count: 1,
            sealed_height: height,
            submitted_height: height + 1,
            status: BatchStatus::Settled,
        }
    }

    fn devnet_receipt(
        &self,
        label: &str,
        vault: &PrivateExitLiquidityVault,
        quote: &EncryptedExitQuote,
        batch: &BatchSettlement,
        height: u64,
    ) -> ExitReceipt {
        ExitReceipt {
            receipt_id: receipt_id(
                &quote.quote_id,
                &batch.batch_id,
                &quote.exit_nullifier,
                height,
            ),
            quote_id: quote.quote_id.clone(),
            batch_id: batch.batch_id.clone(),
            vault_id: vault.vault_id.clone(),
            exit_nullifier: quote.exit_nullifier.clone(),
            payout_commitment: commitment("DEVNET-RECEIPT-PAYOUT", label),
            monero_tx_commitment: batch.monero_tx_commitment.clone(),
            settlement_receipt_root: root_for_label("DEVNET-SETTLEMENT-RECEIPT", label),
            fee_paid_commitment: commitment("DEVNET-RECEIPT-FEE-PAID", label),
            rebate_commitment: commitment("DEVNET-RECEIPT-REBATE", label),
            finality_height: height + self.config.receipt_finality_blocks,
            status: ReceiptStatus::Final,
        }
    }

    fn devnet_rebate(
        &self,
        label: &str,
        receipt: &ExitReceipt,
        reservation: &FeeSponsorReservation,
        height: u64,
    ) -> ExitRebate {
        let rebate_nullifier = nullifier("DEVNET-REBATE-NULLIFIER", label);
        ExitRebate {
            rebate_id: rebate_id(
                &receipt.receipt_id,
                &reservation.reservation_id,
                &rebate_nullifier,
            ),
            receipt_id: receipt.receipt_id.clone(),
            sponsor_reservation_id: reservation.reservation_id.clone(),
            rebate_nullifier,
            recipient_commitment: commitment("DEVNET-REBATE-RECIPIENT", label),
            rebate_commitment: receipt.rebate_commitment.clone(),
            sponsor_commitment: reservation.sponsor_commitment.clone(),
            claim_window_start: height,
            claim_window_end: height + self.config.rebate_ttl_blocks,
            claimed: false,
        }
    }

    fn devnet_fence(
        &self,
        kind: FenceKind,
        subject_id: &str,
        nullifier_value: &str,
        height: u64,
    ) -> PrivacyNullifierFence {
        let fence_root = nullifier_fence_root(kind, subject_id, nullifier_value);
        PrivacyNullifierFence {
            fence_id: fence_id(kind, subject_id, nullifier_value, height),
            kind,
            subject_id: subject_id.to_string(),
            nullifier: nullifier_value.to_string(),
            fence_root,
            height,
        }
    }
}

pub fn payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(domain, &[HashPart::Json(payload)], 32)
}

pub fn root_from_record(domain: &str, record: &Value) -> String {
    domain_hash(
        domain,
        &[HashPart::Str(CHAIN_ID), HashPart::Json(record)],
        32,
    )
}

pub fn public_record_root(record: &Value) -> String {
    domain_hash(
        "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-VAULT-PUBLIC-RECORD",
        &[HashPart::Json(record)],
        32,
    )
}

pub fn state_root_from_record(record: &Value) -> String {
    domain_hash(
        "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-VAULT-STATE-ROOT",
        &[HashPart::Json(record)],
        32,
    )
}

pub fn vault_id(
    label: &str,
    lane: ExitLane,
    operator_commitment: &str,
    reserve_commitment_root: &str,
    created_height: u64,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-VAULT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
            HashPart::Str(lane.as_str()),
            HashPart::Str(operator_commitment),
            HashPart::Str(reserve_commitment_root),
            HashPart::Int(created_height as i128),
        ],
        32,
    )
}

pub fn lp_commitment_id(
    vault_id: &str,
    provider_commitment: &str,
    share_commitment: &str,
    created_height: u64,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-PRIVATE-EXIT-LP-COMMITMENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(vault_id),
            HashPart::Str(provider_commitment),
            HashPart::Str(share_commitment),
            HashPart::Int(created_height as i128),
        ],
        32,
    )
}

pub fn reserve_attestation_id(
    vault_id: &str,
    reserve_epoch: u64,
    reserve_commitment_root: &str,
    l2_height: u64,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-PRIVATE-EXIT-RESERVE-ATTESTATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(vault_id),
            HashPart::Int(reserve_epoch as i128),
            HashPart::Str(reserve_commitment_root),
            HashPart::Int(l2_height as i128),
        ],
        32,
    )
}

pub fn encrypted_quote_id(
    vault_id: &str,
    exit_nullifier: &str,
    amount_commitment: &str,
    requested_height: u64,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-PRIVATE-EXIT-ENCRYPTED-QUOTE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(vault_id),
            HashPart::Str(exit_nullifier),
            HashPart::Str(amount_commitment),
            HashPart::Int(requested_height as i128),
        ],
        32,
    )
}

pub fn sponsor_reservation_id(
    sponsor_commitment: &str,
    quote_id: &str,
    credential_nullifier: &str,
    created_height: u64,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-PRIVATE-EXIT-SPONSOR-RESERVATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(sponsor_commitment),
            HashPart::Str(quote_id),
            HashPart::Str(credential_nullifier),
            HashPart::Int(created_height as i128),
        ],
        32,
    )
}

pub fn batch_settlement_id(
    vault_id: &str,
    quote_root: &str,
    nullifier_root: &str,
    sealed_height: u64,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-PRIVATE-EXIT-BATCH-SETTLEMENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(vault_id),
            HashPart::Str(quote_root),
            HashPart::Str(nullifier_root),
            HashPart::Int(sealed_height as i128),
        ],
        32,
    )
}

pub fn receipt_id(
    quote_id: &str,
    batch_id: &str,
    exit_nullifier: &str,
    finality_height: u64,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-PRIVATE-EXIT-RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(quote_id),
            HashPart::Str(batch_id),
            HashPart::Str(exit_nullifier),
            HashPart::Int(finality_height as i128),
        ],
        32,
    )
}

pub fn rebate_id(receipt_id: &str, reservation_id: &str, rebate_nullifier: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-PRIVATE-EXIT-REBATE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(receipt_id),
            HashPart::Str(reservation_id),
            HashPart::Str(rebate_nullifier),
        ],
        32,
    )
}

pub fn fence_id(kind: FenceKind, subject_id: &str, nullifier_value: &str, height: u64) -> String {
    domain_hash(
        "MONERO-L2-PQ-PRIVATE-EXIT-NULLIFIER-FENCE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(kind.as_str()),
            HashPart::Str(subject_id),
            HashPart::Str(nullifier_value),
            HashPart::Int(height as i128),
        ],
        32,
    )
}

pub fn event_id(event_type: &str, height: u64, sequence: u64, payload: &Value) -> String {
    domain_hash(
        "MONERO-L2-PQ-PRIVATE-EXIT-EVENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(event_type),
            HashPart::Int(height as i128),
            HashPart::Int(sequence as i128),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub fn commitment(domain: &str, label: &str) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}

pub fn nullifier(domain: &str, label: &str) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(MONERO_L2_PQ_PRIVATE_EXIT_LIQUIDITY_VAULT_RUNTIME_REPLAY_DOMAIN),
            HashPart::Str(label),
        ],
        32,
    )
}

pub fn root_for_label(domain: &str, label: &str) -> String {
    let record = json!({
        "chain_id": CHAIN_ID,
        "protocol_version": PROTOCOL_VERSION,
        "label": label,
    });
    payload_root(domain, &record)
}

pub fn nullifier_fence_root(kind: FenceKind, subject_id: &str, nullifier_value: &str) -> String {
    let record = json!({
        "chain_id": CHAIN_ID,
        "protocol_version": PROTOCOL_VERSION,
        "kind": kind.as_str(),
        "subject_id": subject_id,
        "nullifier": nullifier_value,
    });
    payload_root("MONERO-L2-PQ-PRIVATE-EXIT-NULLIFIER-FENCE-ROOT", &record)
}

fn values_from_map<T, F>(map: &BTreeMap<String, T>, f: F) -> Vec<Value>
where
    F: Fn(&T) -> Value,
{
    map.values().map(f).collect()
}
