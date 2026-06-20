use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type MoneroL2PqFastBridgeLiquidityRuntimeResult<T> = Result<T, String>;

pub const MONERO_L2_PQ_FAST_BRIDGE_LIQUIDITY_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-fast-bridge-liquidity-runtime-v1";
pub const PROTOCOL_VERSION: &str = MONERO_L2_PQ_FAST_BRIDGE_LIQUIDITY_RUNTIME_PROTOCOL_VERSION;
pub const MONERO_L2_PQ_FAST_BRIDGE_LIQUIDITY_RUNTIME_SCHEMA_VERSION: u64 = 1;
pub const MONERO_L2_PQ_FAST_BRIDGE_LIQUIDITY_RUNTIME_DEVNET_HEIGHT: u64 = 286_000;
pub const MONERO_L2_PQ_FAST_BRIDGE_LIQUIDITY_RUNTIME_DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const MONERO_L2_PQ_FAST_BRIDGE_LIQUIDITY_RUNTIME_DEVNET_L2_NETWORK: &str = "nebula-devnet";
pub const MONERO_L2_PQ_FAST_BRIDGE_LIQUIDITY_RUNTIME_DEVNET_ASSET_ID: &str = "wxmr-devnet";
pub const MONERO_L2_PQ_FAST_BRIDGE_LIQUIDITY_RUNTIME_DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const MONERO_L2_PQ_FAST_BRIDGE_LIQUIDITY_RUNTIME_HASH_SUITE: &str =
    "SHAKE256-domain-separated-canonical-json";
pub const MONERO_L2_PQ_FAST_BRIDGE_LIQUIDITY_RUNTIME_VAULT_SCHEME: &str =
    "ml-dsa-87-fast-bridge-liquidity-vault-root-v1";
pub const MONERO_L2_PQ_FAST_BRIDGE_LIQUIDITY_RUNTIME_QUOTE_SCHEME: &str =
    "ml-kem-1024+ml-dsa-87-fast-bridge-liquidity-quote-root-v1";
pub const MONERO_L2_PQ_FAST_BRIDGE_LIQUIDITY_RUNTIME_RESERVATION_SCHEME: &str =
    "roots-only-private-exit-entry-liquidity-reservation-root-v1";
pub const MONERO_L2_PQ_FAST_BRIDGE_LIQUIDITY_RUNTIME_RECEIPT_SCHEME: &str =
    "fast-finality-private-bridge-receipt-root-v1";
pub const MONERO_L2_PQ_FAST_BRIDGE_LIQUIDITY_RUNTIME_RESERVE_PROOF_SCHEME: &str =
    "roots-only-monero-l2-fast-bridge-reserve-proof-v1";
pub const MONERO_L2_PQ_FAST_BRIDGE_LIQUIDITY_RUNTIME_SPONSOR_SCHEME: &str =
    "sponsored-low-fee-private-bridge-liquidity-root-v1";
pub const MONERO_L2_PQ_FAST_BRIDGE_LIQUIDITY_RUNTIME_NULLIFIER_SCHEME: &str =
    "monero-l2-pq-fast-bridge-liquidity-nullifier-root-v1";
pub const MONERO_L2_PQ_FAST_BRIDGE_LIQUIDITY_RUNTIME_REPLAY_DOMAIN: &str =
    "monero-l2-pq-fast-bridge-liquidity-devnet";
pub const MONERO_L2_PQ_FAST_BRIDGE_LIQUIDITY_RUNTIME_MAX_BPS: u64 = 10_000;
pub const MONERO_L2_PQ_FAST_BRIDGE_LIQUIDITY_RUNTIME_DEFAULT_QUOTE_TTL_BLOCKS: u64 = 24;
pub const MONERO_L2_PQ_FAST_BRIDGE_LIQUIDITY_RUNTIME_DEFAULT_RESERVATION_TTL_BLOCKS: u64 = 36;
pub const MONERO_L2_PQ_FAST_BRIDGE_LIQUIDITY_RUNTIME_DEFAULT_RECEIPT_FINALITY_BLOCKS: u64 = 4;
pub const MONERO_L2_PQ_FAST_BRIDGE_LIQUIDITY_RUNTIME_DEFAULT_SETTLEMENT_TTL_BLOCKS: u64 = 144;
pub const MONERO_L2_PQ_FAST_BRIDGE_LIQUIDITY_RUNTIME_DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 8_192;
pub const MONERO_L2_PQ_FAST_BRIDGE_LIQUIDITY_RUNTIME_DEFAULT_MIN_RESERVE_PROOF_BPS: u64 = 10_500;
pub const MONERO_L2_PQ_FAST_BRIDGE_LIQUIDITY_RUNTIME_DEFAULT_TARGET_RESERVE_PROOF_BPS: u64 = 12_000;
pub const MONERO_L2_PQ_FAST_BRIDGE_LIQUIDITY_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 192;
pub const MONERO_L2_PQ_FAST_BRIDGE_LIQUIDITY_RUNTIME_DEFAULT_TARGET_PQ_SECURITY_BITS: u16 = 256;
pub const MONERO_L2_PQ_FAST_BRIDGE_LIQUIDITY_RUNTIME_DEFAULT_MAX_USER_FEE_BPS: u64 = 38;
pub const MONERO_L2_PQ_FAST_BRIDGE_LIQUIDITY_RUNTIME_DEFAULT_LOW_FEE_BPS: u64 = 7;
pub const MONERO_L2_PQ_FAST_BRIDGE_LIQUIDITY_RUNTIME_DEFAULT_SPONSOR_COVER_BPS: u64 = 8_500;
pub const MONERO_L2_PQ_FAST_BRIDGE_LIQUIDITY_RUNTIME_DEFAULT_SLASH_BPS: u64 = 500;
pub const MONERO_L2_PQ_FAST_BRIDGE_LIQUIDITY_RUNTIME_MAX_VAULTS: usize = 131_072;
pub const MONERO_L2_PQ_FAST_BRIDGE_LIQUIDITY_RUNTIME_MAX_QUOTES: usize = 262_144;
pub const MONERO_L2_PQ_FAST_BRIDGE_LIQUIDITY_RUNTIME_MAX_RESERVATIONS: usize = 262_144;
pub const MONERO_L2_PQ_FAST_BRIDGE_LIQUIDITY_RUNTIME_MAX_RECEIPTS: usize = 262_144;
pub const MONERO_L2_PQ_FAST_BRIDGE_LIQUIDITY_RUNTIME_MAX_SETTLEMENTS: usize = 262_144;
pub const MONERO_L2_PQ_FAST_BRIDGE_LIQUIDITY_RUNTIME_MAX_SLASHES: usize = 65_536;
pub const MONERO_L2_PQ_FAST_BRIDGE_LIQUIDITY_RUNTIME_MAX_PUBLIC_RECORDS: usize = 524_288;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BridgeDirection {
    PrivateEntry,
    PrivateExit,
    Bidirectional,
}

impl BridgeDirection {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrivateEntry => "private_entry",
            Self::PrivateExit => "private_exit",
            Self::Bidirectional => "bidirectional",
        }
    }

    pub fn supports_entry(self) -> bool {
        matches!(self, Self::PrivateEntry | Self::Bidirectional)
    }

    pub fn supports_exit(self) -> bool {
        matches!(self, Self::PrivateExit | Self::Bidirectional)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LiquidityClass {
    SponsoredLowFee,
    Standard,
    Fast,
    Defi,
    Emergency,
}

impl LiquidityClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SponsoredLowFee => "sponsored_low_fee",
            Self::Standard => "standard",
            Self::Fast => "fast",
            Self::Defi => "defi",
            Self::Emergency => "emergency",
        }
    }

    pub fn fee_bps(self, config: &Config) -> u64 {
        match self {
            Self::SponsoredLowFee => config.low_fee_bps,
            Self::Emergency | Self::Fast => config.max_user_fee_bps,
            Self::Defi => config.max_user_fee_bps.saturating_mul(3) / 4,
            Self::Standard => config.max_user_fee_bps.saturating_mul(2) / 3,
        }
    }

    pub fn priority_weight(self) -> u64 {
        match self {
            Self::Emergency => 1_000,
            Self::Fast => 900,
            Self::SponsoredLowFee => 860,
            Self::Defi => 720,
            Self::Standard => 500,
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
pub enum QuoteStatus {
    Open,
    Reserved,
    Settling,
    Settled,
    Expired,
    Slashed,
    Cancelled,
}

impl QuoteStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Reserved => "reserved",
            Self::Settling => "settling",
            Self::Settled => "settled",
            Self::Expired => "expired",
            Self::Slashed => "slashed",
            Self::Cancelled => "cancelled",
        }
    }

    pub fn live(self) -> bool {
        matches!(self, Self::Open | Self::Reserved | Self::Settling)
    }

    pub fn terminal(self) -> bool {
        matches!(
            self,
            Self::Settled | Self::Expired | Self::Slashed | Self::Cancelled
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReservationStatus {
    Reserved,
    ReceiptIssued,
    Settling,
    Settled,
    Released,
    Expired,
    Slashed,
}

impl ReservationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::ReceiptIssued => "receipt_issued",
            Self::Settling => "settling",
            Self::Settled => "settled",
            Self::Released => "released",
            Self::Expired => "expired",
            Self::Slashed => "slashed",
        }
    }

    pub fn live(self) -> bool {
        matches!(self, Self::Reserved | Self::ReceiptIssued | Self::Settling)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptStatus {
    Published,
    Finalized,
    Settled,
    Failed,
    Disputed,
}

impl ReceiptStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Published => "published",
            Self::Finalized => "finalized",
            Self::Settled => "settled",
            Self::Failed => "failed",
            Self::Disputed => "disputed",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementStatus {
    Submitted,
    Accepted,
    Finalized,
    Failed,
}

impl SettlementStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Accepted => "accepted",
            Self::Finalized => "finalized",
            Self::Failed => "failed",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SlashReason {
    StaleQuote,
    ReserveProofShortfall,
    ReceiptTimeout,
    DoubleReservation,
    InvalidPqAttestation,
}

impl SlashReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::StaleQuote => "stale_quote",
            Self::ReserveProofShortfall => "reserve_proof_shortfall",
            Self::ReceiptTimeout => "receipt_timeout",
            Self::DoubleReservation => "double_reservation",
            Self::InvalidPqAttestation => "invalid_pq_attestation",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub monero_network: String,
    pub l2_network: String,
    pub asset_id: String,
    pub fee_asset_id: String,
    pub hash_suite: String,
    pub vault_scheme: String,
    pub quote_scheme: String,
    pub reservation_scheme: String,
    pub receipt_scheme: String,
    pub reserve_proof_scheme: String,
    pub sponsor_scheme: String,
    pub nullifier_scheme: String,
    pub replay_domain: String,
    pub genesis_height: u64,
    pub quote_ttl_blocks: u64,
    pub reservation_ttl_blocks: u64,
    pub receipt_finality_blocks: u64,
    pub settlement_ttl_blocks: u64,
    pub min_privacy_set_size: u64,
    pub min_reserve_proof_bps: u64,
    pub target_reserve_proof_bps: u64,
    pub min_pq_security_bits: u16,
    pub target_pq_security_bits: u16,
    pub max_user_fee_bps: u64,
    pub low_fee_bps: u64,
    pub sponsor_cover_bps: u64,
    pub slash_bps: u64,
    pub max_vaults: usize,
    pub max_quotes: usize,
    pub max_reservations: usize,
    pub max_receipts: usize,
    pub max_settlements: usize,
    pub max_slashes: usize,
    pub max_public_records: usize,
    pub roots_only: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self::devnet()
    }
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: MONERO_L2_PQ_FAST_BRIDGE_LIQUIDITY_RUNTIME_SCHEMA_VERSION,
            monero_network: MONERO_L2_PQ_FAST_BRIDGE_LIQUIDITY_RUNTIME_DEVNET_MONERO_NETWORK
                .to_string(),
            l2_network: MONERO_L2_PQ_FAST_BRIDGE_LIQUIDITY_RUNTIME_DEVNET_L2_NETWORK.to_string(),
            asset_id: MONERO_L2_PQ_FAST_BRIDGE_LIQUIDITY_RUNTIME_DEVNET_ASSET_ID.to_string(),
            fee_asset_id: MONERO_L2_PQ_FAST_BRIDGE_LIQUIDITY_RUNTIME_DEVNET_FEE_ASSET_ID
                .to_string(),
            hash_suite: MONERO_L2_PQ_FAST_BRIDGE_LIQUIDITY_RUNTIME_HASH_SUITE.to_string(),
            vault_scheme: MONERO_L2_PQ_FAST_BRIDGE_LIQUIDITY_RUNTIME_VAULT_SCHEME.to_string(),
            quote_scheme: MONERO_L2_PQ_FAST_BRIDGE_LIQUIDITY_RUNTIME_QUOTE_SCHEME.to_string(),
            reservation_scheme: MONERO_L2_PQ_FAST_BRIDGE_LIQUIDITY_RUNTIME_RESERVATION_SCHEME
                .to_string(),
            receipt_scheme: MONERO_L2_PQ_FAST_BRIDGE_LIQUIDITY_RUNTIME_RECEIPT_SCHEME.to_string(),
            reserve_proof_scheme: MONERO_L2_PQ_FAST_BRIDGE_LIQUIDITY_RUNTIME_RESERVE_PROOF_SCHEME
                .to_string(),
            sponsor_scheme: MONERO_L2_PQ_FAST_BRIDGE_LIQUIDITY_RUNTIME_SPONSOR_SCHEME.to_string(),
            nullifier_scheme: MONERO_L2_PQ_FAST_BRIDGE_LIQUIDITY_RUNTIME_NULLIFIER_SCHEME
                .to_string(),
            replay_domain: MONERO_L2_PQ_FAST_BRIDGE_LIQUIDITY_RUNTIME_REPLAY_DOMAIN.to_string(),
            genesis_height: MONERO_L2_PQ_FAST_BRIDGE_LIQUIDITY_RUNTIME_DEVNET_HEIGHT,
            quote_ttl_blocks: MONERO_L2_PQ_FAST_BRIDGE_LIQUIDITY_RUNTIME_DEFAULT_QUOTE_TTL_BLOCKS,
            reservation_ttl_blocks:
                MONERO_L2_PQ_FAST_BRIDGE_LIQUIDITY_RUNTIME_DEFAULT_RESERVATION_TTL_BLOCKS,
            receipt_finality_blocks:
                MONERO_L2_PQ_FAST_BRIDGE_LIQUIDITY_RUNTIME_DEFAULT_RECEIPT_FINALITY_BLOCKS,
            settlement_ttl_blocks:
                MONERO_L2_PQ_FAST_BRIDGE_LIQUIDITY_RUNTIME_DEFAULT_SETTLEMENT_TTL_BLOCKS,
            min_privacy_set_size:
                MONERO_L2_PQ_FAST_BRIDGE_LIQUIDITY_RUNTIME_DEFAULT_MIN_PRIVACY_SET_SIZE,
            min_reserve_proof_bps:
                MONERO_L2_PQ_FAST_BRIDGE_LIQUIDITY_RUNTIME_DEFAULT_MIN_RESERVE_PROOF_BPS,
            target_reserve_proof_bps:
                MONERO_L2_PQ_FAST_BRIDGE_LIQUIDITY_RUNTIME_DEFAULT_TARGET_RESERVE_PROOF_BPS,
            min_pq_security_bits:
                MONERO_L2_PQ_FAST_BRIDGE_LIQUIDITY_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS,
            target_pq_security_bits:
                MONERO_L2_PQ_FAST_BRIDGE_LIQUIDITY_RUNTIME_DEFAULT_TARGET_PQ_SECURITY_BITS,
            max_user_fee_bps: MONERO_L2_PQ_FAST_BRIDGE_LIQUIDITY_RUNTIME_DEFAULT_MAX_USER_FEE_BPS,
            low_fee_bps: MONERO_L2_PQ_FAST_BRIDGE_LIQUIDITY_RUNTIME_DEFAULT_LOW_FEE_BPS,
            sponsor_cover_bps: MONERO_L2_PQ_FAST_BRIDGE_LIQUIDITY_RUNTIME_DEFAULT_SPONSOR_COVER_BPS,
            slash_bps: MONERO_L2_PQ_FAST_BRIDGE_LIQUIDITY_RUNTIME_DEFAULT_SLASH_BPS,
            max_vaults: MONERO_L2_PQ_FAST_BRIDGE_LIQUIDITY_RUNTIME_MAX_VAULTS,
            max_quotes: MONERO_L2_PQ_FAST_BRIDGE_LIQUIDITY_RUNTIME_MAX_QUOTES,
            max_reservations: MONERO_L2_PQ_FAST_BRIDGE_LIQUIDITY_RUNTIME_MAX_RESERVATIONS,
            max_receipts: MONERO_L2_PQ_FAST_BRIDGE_LIQUIDITY_RUNTIME_MAX_RECEIPTS,
            max_settlements: MONERO_L2_PQ_FAST_BRIDGE_LIQUIDITY_RUNTIME_MAX_SETTLEMENTS,
            max_slashes: MONERO_L2_PQ_FAST_BRIDGE_LIQUIDITY_RUNTIME_MAX_SLASHES,
            max_public_records: MONERO_L2_PQ_FAST_BRIDGE_LIQUIDITY_RUNTIME_MAX_PUBLIC_RECORDS,
            roots_only: true,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_l2_pq_fast_bridge_liquidity_runtime_config",
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "monero_network": self.monero_network,
            "l2_network": self.l2_network,
            "asset_id": self.asset_id,
            "fee_asset_id": self.fee_asset_id,
            "hash_suite": self.hash_suite,
            "vault_scheme": self.vault_scheme,
            "quote_scheme": self.quote_scheme,
            "reservation_scheme": self.reservation_scheme,
            "receipt_scheme": self.receipt_scheme,
            "reserve_proof_scheme": self.reserve_proof_scheme,
            "sponsor_scheme": self.sponsor_scheme,
            "nullifier_scheme": self.nullifier_scheme,
            "replay_domain": self.replay_domain,
            "genesis_height": self.genesis_height,
            "quote_ttl_blocks": self.quote_ttl_blocks,
            "reservation_ttl_blocks": self.reservation_ttl_blocks,
            "receipt_finality_blocks": self.receipt_finality_blocks,
            "settlement_ttl_blocks": self.settlement_ttl_blocks,
            "min_privacy_set_size": self.min_privacy_set_size,
            "min_reserve_proof_bps": self.min_reserve_proof_bps,
            "target_reserve_proof_bps": self.target_reserve_proof_bps,
            "min_pq_security_bits": self.min_pq_security_bits,
            "target_pq_security_bits": self.target_pq_security_bits,
            "max_user_fee_bps": self.max_user_fee_bps,
            "low_fee_bps": self.low_fee_bps,
            "sponsor_cover_bps": self.sponsor_cover_bps,
            "slash_bps": self.slash_bps,
            "max_vaults": self.max_vaults,
            "max_quotes": self.max_quotes,
            "max_reservations": self.max_reservations,
            "max_receipts": self.max_receipts,
            "max_settlements": self.max_settlements,
            "max_slashes": self.max_slashes,
            "max_public_records": self.max_public_records,
            "roots_only": self.roots_only,
        })
    }

    pub fn state_root(&self) -> String {
        payload_root(
            "MONERO-L2-PQ-FAST-BRIDGE-LIQUIDITY-CONFIG",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> MoneroL2PqFastBridgeLiquidityRuntimeResult<()> {
        require(!self.chain_id.is_empty(), "config chain id is empty")?;
        require(self.chain_id == CHAIN_ID, "config chain id mismatch")?;
        require(
            self.protocol_version == PROTOCOL_VERSION,
            "config protocol version mismatch",
        )?;
        require(self.schema_version > 0, "config schema version is zero")?;
        require(
            !self.monero_network.is_empty(),
            "config monero network is empty",
        )?;
        require(!self.l2_network.is_empty(), "config l2 network is empty")?;
        require(!self.asset_id.is_empty(), "config asset id is empty")?;
        require(
            !self.fee_asset_id.is_empty(),
            "config fee asset id is empty",
        )?;
        require(self.quote_ttl_blocks > 0, "quote ttl is zero")?;
        require(self.reservation_ttl_blocks > 0, "reservation ttl is zero")?;
        require(
            self.receipt_finality_blocks > 0,
            "receipt finality block count is zero",
        )?;
        require(self.settlement_ttl_blocks > 0, "settlement ttl is zero")?;
        require(
            self.min_privacy_set_size > 0,
            "minimum privacy set size is zero",
        )?;
        require(
            self.min_reserve_proof_bps >= MONERO_L2_PQ_FAST_BRIDGE_LIQUIDITY_RUNTIME_MAX_BPS,
            "reserve proof floor is below full coverage",
        )?;
        require(
            self.target_reserve_proof_bps >= self.min_reserve_proof_bps,
            "reserve proof target below floor",
        )?;
        require(
            self.min_pq_security_bits <= self.target_pq_security_bits,
            "minimum pq security above target",
        )?;
        require(
            self.max_user_fee_bps <= MONERO_L2_PQ_FAST_BRIDGE_LIQUIDITY_RUNTIME_MAX_BPS,
            "max user fee bps exceeds limit",
        )?;
        require(
            self.low_fee_bps <= self.max_user_fee_bps,
            "low fee bps exceeds max user fee bps",
        )?;
        require(
            self.sponsor_cover_bps <= MONERO_L2_PQ_FAST_BRIDGE_LIQUIDITY_RUNTIME_MAX_BPS,
            "sponsor cover bps exceeds limit",
        )?;
        require(
            self.slash_bps <= MONERO_L2_PQ_FAST_BRIDGE_LIQUIDITY_RUNTIME_MAX_BPS,
            "slash bps exceeds limit",
        )?;
        require(self.max_vaults > 0, "max vaults is zero")?;
        require(self.max_quotes > 0, "max quotes is zero")?;
        require(self.max_reservations > 0, "max reservations is zero")?;
        require(self.max_receipts > 0, "max receipts is zero")?;
        require(self.max_settlements > 0, "max settlements is zero")?;
        require(self.max_public_records > 0, "max public records is zero")?;
        require(self.roots_only, "runtime must use roots-only privacy")?;
        Ok(())
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    pub registered_vaults: u64,
    pub open_quotes: u64,
    pub reserved_quotes: u64,
    pub settled_quotes: u64,
    pub stale_quotes_slashed: u64,
    pub private_exit_reservations: u64,
    pub private_entry_reservations: u64,
    pub fast_receipts_issued: u64,
    pub receipts_finalized: u64,
    pub bridge_settlements: u64,
    pub sponsored_fee_piconero: u64,
    pub user_fee_piconero: u64,
    pub slashed_collateral_piconero: u64,
    pub reserved_liquidity_piconero: u64,
    pub settled_liquidity_piconero: u64,
    pub public_records: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_l2_pq_fast_bridge_liquidity_runtime_counters",
            "registered_vaults": self.registered_vaults,
            "open_quotes": self.open_quotes,
            "reserved_quotes": self.reserved_quotes,
            "settled_quotes": self.settled_quotes,
            "stale_quotes_slashed": self.stale_quotes_slashed,
            "private_exit_reservations": self.private_exit_reservations,
            "private_entry_reservations": self.private_entry_reservations,
            "fast_receipts_issued": self.fast_receipts_issued,
            "receipts_finalized": self.receipts_finalized,
            "bridge_settlements": self.bridge_settlements,
            "sponsored_fee_piconero": self.sponsored_fee_piconero,
            "user_fee_piconero": self.user_fee_piconero,
            "slashed_collateral_piconero": self.slashed_collateral_piconero,
            "reserved_liquidity_piconero": self.reserved_liquidity_piconero,
            "settled_liquidity_piconero": self.settled_liquidity_piconero,
            "public_records": self.public_records,
        })
    }

    pub fn state_root(&self) -> String {
        payload_root(
            "MONERO-L2-PQ-FAST-BRIDGE-LIQUIDITY-COUNTERS",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisterLiquidityVaultRequest {
    pub operator_commitment: String,
    pub vault_commitment_root: String,
    pub reserve_proof_root: String,
    pub pq_public_key_commitment: String,
    pub monero_subaddress_root: String,
    pub direction: BridgeDirection,
    pub capacity_piconero: u64,
    pub reserve_proof_bps: u64,
    pub min_pq_security_bits: u16,
    pub sponsor_budget_piconero: u64,
    pub collateral_piconero: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BridgeLiquidityQuoteRequest {
    pub vault_id: String,
    pub requester_commitment: String,
    pub direction: BridgeDirection,
    pub liquidity_class: LiquidityClass,
    pub amount_piconero: u64,
    pub max_fee_piconero: u64,
    pub private_route_root: String,
    pub reserve_proof_root: String,
    pub fee_sponsor_root: String,
    pub pq_quote_attestation_root: String,
    pub privacy_set_size: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateExitLiquidityReservationRequest {
    pub quote_id: String,
    pub user_commitment: String,
    pub direction: BridgeDirection,
    pub amount_piconero: u64,
    pub private_input_nullifier_root: String,
    pub private_output_commitment_root: String,
    pub stealth_payout_commitment_root: String,
    pub reserve_witness_root: String,
    pub replay_nullifier: String,
    pub privacy_set_size: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FastBridgeReceiptRequest {
    pub reservation_id: String,
    pub sequencer_commitment: String,
    pub fast_finality_committee_root: String,
    pub l2_inclusion_root: String,
    pub monero_payout_commitment_root: String,
    pub reserve_proof_root: String,
    pub pq_receipt_attestation_root: String,
    pub receipt_height: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BridgeLiquiditySettlementRequest {
    pub receipt_id: String,
    pub settlement_height: u64,
    pub monero_txid_commitment: String,
    pub output_proof_root: String,
    pub key_image_guard_root: String,
    pub reserve_release_root: String,
    pub settled_amount_piconero: u64,
    pub fee_paid_piconero: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StaleQuoteSlashRequest {
    pub quote_id: String,
    pub watcher_commitment: String,
    pub evidence_root: String,
    pub reason: SlashReason,
    pub observed_height: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiquidityVaultRecord {
    pub vault_id: String,
    pub operator_commitment: String,
    pub vault_commitment_root: String,
    pub reserve_proof_root: String,
    pub pq_public_key_commitment: String,
    pub monero_subaddress_root: String,
    pub direction: BridgeDirection,
    pub capacity_piconero: u64,
    pub available_piconero: u64,
    pub reserved_piconero: u64,
    pub settled_piconero: u64,
    pub reserve_proof_bps: u64,
    pub min_pq_security_bits: u16,
    pub sponsor_budget_piconero: u64,
    pub sponsor_spent_piconero: u64,
    pub collateral_piconero: u64,
    pub slashed_piconero: u64,
    pub status: VaultStatus,
    pub registered_at_height: u64,
    pub last_update_height: u64,
}

impl LiquidityVaultRecord {
    pub fn new(request: &RegisterLiquidityVaultRequest, height: u64) -> Self {
        let mut record = Self {
            vault_id: String::new(),
            operator_commitment: request.operator_commitment.clone(),
            vault_commitment_root: request.vault_commitment_root.clone(),
            reserve_proof_root: request.reserve_proof_root.clone(),
            pq_public_key_commitment: request.pq_public_key_commitment.clone(),
            monero_subaddress_root: request.monero_subaddress_root.clone(),
            direction: request.direction,
            capacity_piconero: request.capacity_piconero,
            available_piconero: request.capacity_piconero,
            reserved_piconero: 0,
            settled_piconero: 0,
            reserve_proof_bps: request.reserve_proof_bps,
            min_pq_security_bits: request.min_pq_security_bits,
            sponsor_budget_piconero: request.sponsor_budget_piconero,
            sponsor_spent_piconero: 0,
            collateral_piconero: request.collateral_piconero,
            slashed_piconero: 0,
            status: VaultStatus::Active,
            registered_at_height: height,
            last_update_height: height,
        };
        record.vault_id = id_from_record("VAULT-ID", &record.public_record_without_id());
        record
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_id();
        set_json_field(&mut record, "vault_id", json!(self.vault_id));
        record
    }

    fn public_record_without_id(&self) -> Value {
        json!({
            "kind": "monero_l2_pq_fast_bridge_liquidity_vault",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "operator_commitment": self.operator_commitment,
            "vault_commitment_root": self.vault_commitment_root,
            "reserve_proof_root": self.reserve_proof_root,
            "pq_public_key_commitment": self.pq_public_key_commitment,
            "monero_subaddress_root": self.monero_subaddress_root,
            "direction": self.direction.as_str(),
            "capacity_piconero": self.capacity_piconero,
            "available_piconero": self.available_piconero,
            "reserved_piconero": self.reserved_piconero,
            "settled_piconero": self.settled_piconero,
            "reserve_proof_bps": self.reserve_proof_bps,
            "min_pq_security_bits": self.min_pq_security_bits,
            "sponsor_budget_piconero": self.sponsor_budget_piconero,
            "sponsor_spent_piconero": self.sponsor_spent_piconero,
            "collateral_piconero": self.collateral_piconero,
            "slashed_piconero": self.slashed_piconero,
            "status": self.status.as_str(),
            "registered_at_height": self.registered_at_height,
            "last_update_height": self.last_update_height,
        })
    }

    pub fn state_root(&self) -> String {
        payload_root(
            "MONERO-L2-PQ-FAST-BRIDGE-LIQUIDITY-VAULT",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BridgeLiquidityQuoteRecord {
    pub quote_id: String,
    pub vault_id: String,
    pub requester_commitment: String,
    pub direction: BridgeDirection,
    pub liquidity_class: LiquidityClass,
    pub amount_piconero: u64,
    pub fee_piconero: u64,
    pub sponsor_fee_piconero: u64,
    pub user_fee_piconero: u64,
    pub max_fee_piconero: u64,
    pub private_route_root: String,
    pub reserve_proof_root: String,
    pub fee_sponsor_root: String,
    pub pq_quote_attestation_root: String,
    pub privacy_set_size: u64,
    pub issued_at_height: u64,
    pub valid_until_height: u64,
    pub reserved_amount_piconero: u64,
    pub status: QuoteStatus,
}

impl BridgeLiquidityQuoteRecord {
    pub fn new(request: &BridgeLiquidityQuoteRequest, config: &Config, height: u64) -> Self {
        let fee_piconero = fee_for_amount(
            request.amount_piconero,
            request.liquidity_class.fee_bps(config),
        );
        let sponsor_fee_piconero = if request.liquidity_class == LiquidityClass::SponsoredLowFee {
            fee_piconero.saturating_mul(config.sponsor_cover_bps)
                / MONERO_L2_PQ_FAST_BRIDGE_LIQUIDITY_RUNTIME_MAX_BPS
        } else {
            0
        };
        let user_fee_piconero = fee_piconero.saturating_sub(sponsor_fee_piconero);
        let mut record = Self {
            quote_id: String::new(),
            vault_id: request.vault_id.clone(),
            requester_commitment: request.requester_commitment.clone(),
            direction: request.direction,
            liquidity_class: request.liquidity_class,
            amount_piconero: request.amount_piconero,
            fee_piconero,
            sponsor_fee_piconero,
            user_fee_piconero,
            max_fee_piconero: request.max_fee_piconero,
            private_route_root: request.private_route_root.clone(),
            reserve_proof_root: request.reserve_proof_root.clone(),
            fee_sponsor_root: request.fee_sponsor_root.clone(),
            pq_quote_attestation_root: request.pq_quote_attestation_root.clone(),
            privacy_set_size: request.privacy_set_size,
            issued_at_height: height,
            valid_until_height: height.saturating_add(config.quote_ttl_blocks),
            reserved_amount_piconero: 0,
            status: QuoteStatus::Open,
        };
        record.quote_id = id_from_record("QUOTE-ID", &record.public_record_without_id());
        record
    }

    pub fn remaining_amount_piconero(&self) -> u64 {
        self.amount_piconero
            .saturating_sub(self.reserved_amount_piconero)
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_id();
        set_json_field(&mut record, "quote_id", json!(self.quote_id));
        record
    }

    fn public_record_without_id(&self) -> Value {
        json!({
            "kind": "monero_l2_pq_fast_bridge_liquidity_quote",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "vault_id": self.vault_id,
            "requester_commitment": self.requester_commitment,
            "direction": self.direction.as_str(),
            "liquidity_class": self.liquidity_class.as_str(),
            "amount_piconero": self.amount_piconero,
            "fee_piconero": self.fee_piconero,
            "sponsor_fee_piconero": self.sponsor_fee_piconero,
            "user_fee_piconero": self.user_fee_piconero,
            "max_fee_piconero": self.max_fee_piconero,
            "private_route_root": self.private_route_root,
            "reserve_proof_root": self.reserve_proof_root,
            "fee_sponsor_root": self.fee_sponsor_root,
            "pq_quote_attestation_root": self.pq_quote_attestation_root,
            "privacy_set_size": self.privacy_set_size,
            "issued_at_height": self.issued_at_height,
            "valid_until_height": self.valid_until_height,
            "reserved_amount_piconero": self.reserved_amount_piconero,
            "status": self.status.as_str(),
        })
    }

    pub fn state_root(&self) -> String {
        payload_root(
            "MONERO-L2-PQ-FAST-BRIDGE-LIQUIDITY-QUOTE",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateLiquidityReservationRecord {
    pub reservation_id: String,
    pub quote_id: String,
    pub vault_id: String,
    pub user_commitment: String,
    pub direction: BridgeDirection,
    pub amount_piconero: u64,
    pub fee_piconero: u64,
    pub sponsor_fee_piconero: u64,
    pub user_fee_piconero: u64,
    pub private_input_nullifier_root: String,
    pub private_output_commitment_root: String,
    pub stealth_payout_commitment_root: String,
    pub reserve_witness_root: String,
    pub replay_nullifier: String,
    pub privacy_set_size: u64,
    pub reserved_at_height: u64,
    pub expires_at_height: u64,
    pub status: ReservationStatus,
}

impl PrivateLiquidityReservationRecord {
    pub fn new(
        request: &PrivateExitLiquidityReservationRequest,
        quote: &BridgeLiquidityQuoteRecord,
        config: &Config,
        height: u64,
    ) -> Self {
        let fee_piconero = fee_for_amount(
            request.amount_piconero,
            quote.liquidity_class.fee_bps(config),
        );
        let sponsor_fee_piconero = if quote.liquidity_class == LiquidityClass::SponsoredLowFee {
            fee_piconero.saturating_mul(config.sponsor_cover_bps)
                / MONERO_L2_PQ_FAST_BRIDGE_LIQUIDITY_RUNTIME_MAX_BPS
        } else {
            0
        };
        let user_fee_piconero = fee_piconero.saturating_sub(sponsor_fee_piconero);
        let mut record = Self {
            reservation_id: String::new(),
            quote_id: request.quote_id.clone(),
            vault_id: quote.vault_id.clone(),
            user_commitment: request.user_commitment.clone(),
            direction: request.direction,
            amount_piconero: request.amount_piconero,
            fee_piconero,
            sponsor_fee_piconero,
            user_fee_piconero,
            private_input_nullifier_root: request.private_input_nullifier_root.clone(),
            private_output_commitment_root: request.private_output_commitment_root.clone(),
            stealth_payout_commitment_root: request.stealth_payout_commitment_root.clone(),
            reserve_witness_root: request.reserve_witness_root.clone(),
            replay_nullifier: request.replay_nullifier.clone(),
            privacy_set_size: request.privacy_set_size,
            reserved_at_height: height,
            expires_at_height: height.saturating_add(config.reservation_ttl_blocks),
            status: ReservationStatus::Reserved,
        };
        record.reservation_id =
            id_from_record("RESERVATION-ID", &record.public_record_without_id());
        record
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_id();
        set_json_field(&mut record, "reservation_id", json!(self.reservation_id));
        record
    }

    fn public_record_without_id(&self) -> Value {
        json!({
            "kind": "monero_l2_pq_fast_bridge_private_liquidity_reservation",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "quote_id": self.quote_id,
            "vault_id": self.vault_id,
            "user_commitment": self.user_commitment,
            "direction": self.direction.as_str(),
            "amount_piconero": self.amount_piconero,
            "fee_piconero": self.fee_piconero,
            "sponsor_fee_piconero": self.sponsor_fee_piconero,
            "user_fee_piconero": self.user_fee_piconero,
            "private_input_nullifier_root": self.private_input_nullifier_root,
            "private_output_commitment_root": self.private_output_commitment_root,
            "stealth_payout_commitment_root": self.stealth_payout_commitment_root,
            "reserve_witness_root": self.reserve_witness_root,
            "replay_nullifier": self.replay_nullifier,
            "privacy_set_size": self.privacy_set_size,
            "reserved_at_height": self.reserved_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn state_root(&self) -> String {
        payload_root(
            "MONERO-L2-PQ-FAST-BRIDGE-LIQUIDITY-RESERVATION",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FastBridgeReceiptRecord {
    pub receipt_id: String,
    pub reservation_id: String,
    pub quote_id: String,
    pub vault_id: String,
    pub sequencer_commitment: String,
    pub fast_finality_committee_root: String,
    pub l2_inclusion_root: String,
    pub monero_payout_commitment_root: String,
    pub reserve_proof_root: String,
    pub pq_receipt_attestation_root: String,
    pub receipt_height: u64,
    pub final_after_height: u64,
    pub amount_piconero: u64,
    pub fee_piconero: u64,
    pub status: ReceiptStatus,
}

impl FastBridgeReceiptRecord {
    pub fn new(
        request: &FastBridgeReceiptRequest,
        reservation: &PrivateLiquidityReservationRecord,
        config: &Config,
    ) -> Self {
        let mut record = Self {
            receipt_id: String::new(),
            reservation_id: request.reservation_id.clone(),
            quote_id: reservation.quote_id.clone(),
            vault_id: reservation.vault_id.clone(),
            sequencer_commitment: request.sequencer_commitment.clone(),
            fast_finality_committee_root: request.fast_finality_committee_root.clone(),
            l2_inclusion_root: request.l2_inclusion_root.clone(),
            monero_payout_commitment_root: request.monero_payout_commitment_root.clone(),
            reserve_proof_root: request.reserve_proof_root.clone(),
            pq_receipt_attestation_root: request.pq_receipt_attestation_root.clone(),
            receipt_height: request.receipt_height,
            final_after_height: request
                .receipt_height
                .saturating_add(config.receipt_finality_blocks),
            amount_piconero: reservation.amount_piconero,
            fee_piconero: reservation.fee_piconero,
            status: ReceiptStatus::Published,
        };
        record.receipt_id = id_from_record("RECEIPT-ID", &record.public_record_without_id());
        record
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_id();
        set_json_field(&mut record, "receipt_id", json!(self.receipt_id));
        record
    }

    fn public_record_without_id(&self) -> Value {
        json!({
            "kind": "monero_l2_pq_fast_bridge_finality_receipt",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "reservation_id": self.reservation_id,
            "quote_id": self.quote_id,
            "vault_id": self.vault_id,
            "sequencer_commitment": self.sequencer_commitment,
            "fast_finality_committee_root": self.fast_finality_committee_root,
            "l2_inclusion_root": self.l2_inclusion_root,
            "monero_payout_commitment_root": self.monero_payout_commitment_root,
            "reserve_proof_root": self.reserve_proof_root,
            "pq_receipt_attestation_root": self.pq_receipt_attestation_root,
            "receipt_height": self.receipt_height,
            "final_after_height": self.final_after_height,
            "amount_piconero": self.amount_piconero,
            "fee_piconero": self.fee_piconero,
            "status": self.status.as_str(),
        })
    }

    pub fn state_root(&self) -> String {
        payload_root(
            "MONERO-L2-PQ-FAST-BRIDGE-LIQUIDITY-RECEIPT",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BridgeLiquiditySettlementRecord {
    pub settlement_id: String,
    pub receipt_id: String,
    pub reservation_id: String,
    pub quote_id: String,
    pub vault_id: String,
    pub settlement_height: u64,
    pub monero_txid_commitment: String,
    pub output_proof_root: String,
    pub key_image_guard_root: String,
    pub reserve_release_root: String,
    pub settled_amount_piconero: u64,
    pub fee_paid_piconero: u64,
    pub status: SettlementStatus,
}

impl BridgeLiquiditySettlementRecord {
    pub fn new(
        request: &BridgeLiquiditySettlementRequest,
        receipt: &FastBridgeReceiptRecord,
    ) -> Self {
        let mut record = Self {
            settlement_id: String::new(),
            receipt_id: request.receipt_id.clone(),
            reservation_id: receipt.reservation_id.clone(),
            quote_id: receipt.quote_id.clone(),
            vault_id: receipt.vault_id.clone(),
            settlement_height: request.settlement_height,
            monero_txid_commitment: request.monero_txid_commitment.clone(),
            output_proof_root: request.output_proof_root.clone(),
            key_image_guard_root: request.key_image_guard_root.clone(),
            reserve_release_root: request.reserve_release_root.clone(),
            settled_amount_piconero: request.settled_amount_piconero,
            fee_paid_piconero: request.fee_paid_piconero,
            status: SettlementStatus::Finalized,
        };
        record.settlement_id = id_from_record("SETTLEMENT-ID", &record.public_record_without_id());
        record
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_id();
        set_json_field(&mut record, "settlement_id", json!(self.settlement_id));
        record
    }

    fn public_record_without_id(&self) -> Value {
        json!({
            "kind": "monero_l2_pq_fast_bridge_liquidity_settlement",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "receipt_id": self.receipt_id,
            "reservation_id": self.reservation_id,
            "quote_id": self.quote_id,
            "vault_id": self.vault_id,
            "settlement_height": self.settlement_height,
            "monero_txid_commitment": self.monero_txid_commitment,
            "output_proof_root": self.output_proof_root,
            "key_image_guard_root": self.key_image_guard_root,
            "reserve_release_root": self.reserve_release_root,
            "settled_amount_piconero": self.settled_amount_piconero,
            "fee_paid_piconero": self.fee_paid_piconero,
            "status": self.status.as_str(),
        })
    }

    pub fn state_root(&self) -> String {
        payload_root(
            "MONERO-L2-PQ-FAST-BRIDGE-LIQUIDITY-SETTLEMENT",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReserveProofRecord {
    pub proof_id: String,
    pub vault_id: String,
    pub subject_id: String,
    pub reserve_proof_root: String,
    pub covered_amount_piconero: u64,
    pub coverage_bps: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub observed_height: u64,
}

impl ReserveProofRecord {
    pub fn new(
        vault_id: &str,
        subject_id: &str,
        reserve_proof_root: &str,
        covered_amount_piconero: u64,
        coverage_bps: u64,
        privacy_set_size: u64,
        pq_security_bits: u16,
        observed_height: u64,
    ) -> Self {
        let mut record = Self {
            proof_id: String::new(),
            vault_id: vault_id.to_string(),
            subject_id: subject_id.to_string(),
            reserve_proof_root: reserve_proof_root.to_string(),
            covered_amount_piconero,
            coverage_bps,
            privacy_set_size,
            pq_security_bits,
            observed_height,
        };
        record.proof_id = id_from_record("RESERVE-PROOF-ID", &record.public_record_without_id());
        record
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_id();
        set_json_field(&mut record, "proof_id", json!(self.proof_id));
        record
    }

    fn public_record_without_id(&self) -> Value {
        json!({
            "kind": "monero_l2_pq_fast_bridge_reserve_proof",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "vault_id": self.vault_id,
            "subject_id": self.subject_id,
            "reserve_proof_root": self.reserve_proof_root,
            "covered_amount_piconero": self.covered_amount_piconero,
            "coverage_bps": self.coverage_bps,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "observed_height": self.observed_height,
        })
    }

    pub fn state_root(&self) -> String {
        payload_root(
            "MONERO-L2-PQ-FAST-BRIDGE-RESERVE-PROOF",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuoteSlashRecord {
    pub slash_id: String,
    pub quote_id: String,
    pub vault_id: String,
    pub watcher_commitment: String,
    pub evidence_root: String,
    pub reason: SlashReason,
    pub observed_height: u64,
    pub slashed_piconero: u64,
}

impl QuoteSlashRecord {
    pub fn new(
        request: &StaleQuoteSlashRequest,
        quote: &BridgeLiquidityQuoteRecord,
        config: &Config,
    ) -> Self {
        let slashed_piconero = fee_for_amount(quote.amount_piconero, config.slash_bps);
        let mut record = Self {
            slash_id: String::new(),
            quote_id: request.quote_id.clone(),
            vault_id: quote.vault_id.clone(),
            watcher_commitment: request.watcher_commitment.clone(),
            evidence_root: request.evidence_root.clone(),
            reason: request.reason,
            observed_height: request.observed_height,
            slashed_piconero,
        };
        record.slash_id = id_from_record("SLASH-ID", &record.public_record_without_id());
        record
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_id();
        set_json_field(&mut record, "slash_id", json!(self.slash_id));
        record
    }

    fn public_record_without_id(&self) -> Value {
        json!({
            "kind": "monero_l2_pq_fast_bridge_quote_slash",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "quote_id": self.quote_id,
            "vault_id": self.vault_id,
            "watcher_commitment": self.watcher_commitment,
            "evidence_root": self.evidence_root,
            "reason": self.reason.as_str(),
            "observed_height": self.observed_height,
            "slashed_piconero": self.slashed_piconero,
        })
    }

    pub fn state_root(&self) -> String {
        payload_root(
            "MONERO-L2-PQ-FAST-BRIDGE-QUOTE-SLASH",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RootsOnlyPublicRecord {
    pub record_id: String,
    pub subject_kind: String,
    pub subject_id: String,
    pub subject_root: String,
    pub published_height: u64,
    pub disclosed_fields: Vec<String>,
    pub disclosed_record: Value,
}

impl RootsOnlyPublicRecord {
    pub fn new(
        subject_kind: &str,
        subject_id: &str,
        subject_record: &Value,
        disclosed_fields: &[&str],
        published_height: u64,
    ) -> Self {
        let disclosed_record = project_fields(subject_record, disclosed_fields);
        let subject_root = payload_root("MONERO-L2-PQ-FAST-BRIDGE-PUBLIC-SUBJECT", subject_record);
        let disclosed_fields = disclosed_fields
            .iter()
            .map(|field| field.to_string())
            .collect::<Vec<_>>();
        let mut record = Self {
            record_id: String::new(),
            subject_kind: subject_kind.to_string(),
            subject_id: subject_id.to_string(),
            subject_root,
            published_height,
            disclosed_fields,
            disclosed_record,
        };
        record.record_id = id_from_record("PUBLIC-RECORD-ID", &record.public_record_without_id());
        record
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_id();
        set_json_field(&mut record, "record_id", json!(self.record_id));
        record
    }

    fn public_record_without_id(&self) -> Value {
        json!({
            "kind": "monero_l2_pq_fast_bridge_roots_only_public_record",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "subject_kind": self.subject_kind,
            "subject_id": self.subject_id,
            "subject_root": self.subject_root,
            "published_height": self.published_height,
            "disclosed_fields": self.disclosed_fields,
            "disclosed_record": self.disclosed_record,
        })
    }

    pub fn state_root(&self) -> String {
        payload_root(
            "MONERO-L2-PQ-FAST-BRIDGE-ROOTS-ONLY-PUBLIC-RECORD",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roots {
    pub config_root: String,
    pub vault_root: String,
    pub quote_root: String,
    pub reservation_root: String,
    pub receipt_root: String,
    pub settlement_root: String,
    pub reserve_proof_root: String,
    pub slash_root: String,
    pub nullifier_root: String,
    pub public_record_root: String,
    pub counters_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_l2_pq_fast_bridge_liquidity_runtime_roots",
            "config_root": self.config_root,
            "vault_root": self.vault_root,
            "quote_root": self.quote_root,
            "reservation_root": self.reservation_root,
            "receipt_root": self.receipt_root,
            "settlement_root": self.settlement_root,
            "reserve_proof_root": self.reserve_proof_root,
            "slash_root": self.slash_root,
            "nullifier_root": self.nullifier_root,
            "public_record_root": self.public_record_root,
            "counters_root": self.counters_root,
        })
    }

    pub fn state_root(&self) -> String {
        payload_root(
            "MONERO-L2-PQ-FAST-BRIDGE-LIQUIDITY-ROOTS",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub height: u64,
    pub config: Config,
    pub counters: Counters,
    pub vaults: BTreeMap<String, LiquidityVaultRecord>,
    pub quotes: BTreeMap<String, BridgeLiquidityQuoteRecord>,
    pub reservations: BTreeMap<String, PrivateLiquidityReservationRecord>,
    pub receipts: BTreeMap<String, FastBridgeReceiptRecord>,
    pub settlements: BTreeMap<String, BridgeLiquiditySettlementRecord>,
    pub reserve_proofs: BTreeMap<String, ReserveProofRecord>,
    pub slashes: BTreeMap<String, QuoteSlashRecord>,
    pub used_nullifiers: BTreeSet<String>,
    pub public_records: BTreeMap<String, RootsOnlyPublicRecord>,
    pub paused: bool,
}

impl State {
    pub fn devnet() -> Self {
        let mut state = Self {
            height: MONERO_L2_PQ_FAST_BRIDGE_LIQUIDITY_RUNTIME_DEVNET_HEIGHT,
            config: Config::devnet(),
            counters: Counters::default(),
            vaults: BTreeMap::new(),
            quotes: BTreeMap::new(),
            reservations: BTreeMap::new(),
            receipts: BTreeMap::new(),
            settlements: BTreeMap::new(),
            reserve_proofs: BTreeMap::new(),
            slashes: BTreeMap::new(),
            used_nullifiers: BTreeSet::new(),
            public_records: BTreeMap::new(),
            paused: false,
        };

        let fast_vault = RegisterLiquidityVaultRequest {
            operator_commitment: "devnet-fast-bridge-operator-root".to_string(),
            vault_commitment_root: seed_root("devnet-fast-vault"),
            reserve_proof_root: seed_root("devnet-fast-vault-reserve-proof"),
            pq_public_key_commitment: seed_root("devnet-fast-vault-pq-key"),
            monero_subaddress_root: seed_root("devnet-fast-vault-subaddresses"),
            direction: BridgeDirection::Bidirectional,
            capacity_piconero: 12_500_000_000_000,
            reserve_proof_bps: state.config.target_reserve_proof_bps,
            min_pq_security_bits: state.config.target_pq_security_bits,
            sponsor_budget_piconero: 125_000_000_000,
            collateral_piconero: 1_250_000_000_000,
        };
        let low_fee_vault = RegisterLiquidityVaultRequest {
            operator_commitment: "devnet-sponsored-low-fee-operator-root".to_string(),
            vault_commitment_root: seed_root("devnet-sponsored-low-fee-vault"),
            reserve_proof_root: seed_root("devnet-sponsored-low-fee-reserve-proof"),
            pq_public_key_commitment: seed_root("devnet-sponsored-low-fee-pq-key"),
            monero_subaddress_root: seed_root("devnet-sponsored-low-fee-subaddresses"),
            direction: BridgeDirection::PrivateExit,
            capacity_piconero: 7_500_000_000_000,
            reserve_proof_bps: state.config.target_reserve_proof_bps,
            min_pq_security_bits: state.config.target_pq_security_bits,
            sponsor_budget_piconero: 250_000_000_000,
            collateral_piconero: 900_000_000_000,
        };

        let fast_vault_id = state
            .register_liquidity_vault(fast_vault)
            .expect("devnet fast vault registration");
        let low_fee_vault_id = state
            .register_liquidity_vault(low_fee_vault)
            .expect("devnet low fee vault registration");

        let fast_quote = BridgeLiquidityQuoteRequest {
            vault_id: fast_vault_id,
            requester_commitment: "devnet-fast-exit-requester-root".to_string(),
            direction: BridgeDirection::PrivateExit,
            liquidity_class: LiquidityClass::Fast,
            amount_piconero: 850_000_000_000,
            max_fee_piconero: 4_000_000_000,
            private_route_root: seed_root("devnet-fast-exit-private-route"),
            reserve_proof_root: seed_root("devnet-fast-exit-reserve-proof"),
            fee_sponsor_root: seed_root("devnet-fast-exit-fee-sponsor"),
            pq_quote_attestation_root: seed_root("devnet-fast-exit-pq-quote"),
            privacy_set_size: state.config.min_privacy_set_size,
        };
        let low_fee_quote = BridgeLiquidityQuoteRequest {
            vault_id: low_fee_vault_id,
            requester_commitment: "devnet-sponsored-exit-requester-root".to_string(),
            direction: BridgeDirection::PrivateExit,
            liquidity_class: LiquidityClass::SponsoredLowFee,
            amount_piconero: 425_000_000_000,
            max_fee_piconero: 500_000_000,
            private_route_root: seed_root("devnet-sponsored-exit-private-route"),
            reserve_proof_root: seed_root("devnet-sponsored-exit-reserve-proof"),
            fee_sponsor_root: seed_root("devnet-sponsored-exit-fee-sponsor"),
            pq_quote_attestation_root: seed_root("devnet-sponsored-exit-pq-quote"),
            privacy_set_size: state.config.min_privacy_set_size.saturating_mul(2),
        };
        let quote_id = state
            .submit_bridge_liquidity_quote(fast_quote)
            .expect("devnet fast quote");
        state
            .submit_bridge_liquidity_quote(low_fee_quote)
            .expect("devnet low fee quote");

        let reservation_id = state
            .reserve_private_exit_liquidity(PrivateExitLiquidityReservationRequest {
                quote_id,
                user_commitment: "devnet-fast-exit-user-root".to_string(),
                direction: BridgeDirection::PrivateExit,
                amount_piconero: 400_000_000_000,
                private_input_nullifier_root: seed_root("devnet-fast-exit-input-nullifier"),
                private_output_commitment_root: seed_root("devnet-fast-exit-output-commitment"),
                stealth_payout_commitment_root: seed_root("devnet-fast-exit-stealth-payout"),
                reserve_witness_root: seed_root("devnet-fast-exit-reserve-witness"),
                replay_nullifier: seed_root("devnet-fast-exit-replay-nullifier"),
                privacy_set_size: state.config.min_privacy_set_size,
            })
            .expect("devnet reservation");
        state
            .issue_fast_bridge_receipt(FastBridgeReceiptRequest {
                reservation_id,
                sequencer_commitment: "devnet-fast-finality-sequencer-root".to_string(),
                fast_finality_committee_root: seed_root("devnet-fast-finality-committee"),
                l2_inclusion_root: seed_root("devnet-l2-inclusion-root"),
                monero_payout_commitment_root: seed_root("devnet-monero-payout-root"),
                reserve_proof_root: seed_root("devnet-receipt-reserve-proof"),
                pq_receipt_attestation_root: seed_root("devnet-pq-receipt-attestation"),
                receipt_height: state.height,
            })
            .expect("devnet fast receipt");
        state.refresh_public_records();
        state
    }

    pub fn register_liquidity_vault(
        &mut self,
        request: RegisterLiquidityVaultRequest,
    ) -> MoneroL2PqFastBridgeLiquidityRuntimeResult<String> {
        self.ensure_active()?;
        self.config.validate()?;
        require(
            self.vaults.len() < self.config.max_vaults,
            "too many liquidity vaults",
        )?;
        require(
            !request.operator_commitment.is_empty(),
            "operator commitment empty",
        )?;
        require(
            !request.vault_commitment_root.is_empty(),
            "vault commitment root empty",
        )?;
        require(
            !request.reserve_proof_root.is_empty(),
            "reserve proof root empty",
        )?;
        require(
            !request.pq_public_key_commitment.is_empty(),
            "pq public key commitment empty",
        )?;
        require(
            !request.monero_subaddress_root.is_empty(),
            "monero subaddress root empty",
        )?;
        require(request.capacity_piconero > 0, "vault capacity is zero")?;
        require(
            request.reserve_proof_bps >= self.config.min_reserve_proof_bps,
            "vault reserve proof below floor",
        )?;
        require(
            request.min_pq_security_bits >= self.config.min_pq_security_bits,
            "vault pq security below floor",
        )?;

        let vault = LiquidityVaultRecord::new(&request, self.height);
        let vault_id = vault.vault_id.clone();
        insert_unique(&mut self.vaults, vault_id.clone(), vault, "vault")?;
        let proof = ReserveProofRecord::new(
            &vault_id,
            &vault_id,
            &request.reserve_proof_root,
            request.capacity_piconero,
            request.reserve_proof_bps,
            self.config.min_privacy_set_size,
            request.min_pq_security_bits,
            self.height,
        );
        insert_unique(
            &mut self.reserve_proofs,
            proof.proof_id.clone(),
            proof,
            "reserve proof",
        )?;
        self.refresh_counters();
        self.refresh_public_records();
        Ok(vault_id)
    }

    pub fn submit_bridge_liquidity_quote(
        &mut self,
        request: BridgeLiquidityQuoteRequest,
    ) -> MoneroL2PqFastBridgeLiquidityRuntimeResult<String> {
        self.ensure_active()?;
        require(
            self.quotes.len() < self.config.max_quotes,
            "too many liquidity quotes",
        )?;
        let vault = self
            .vaults
            .get(&request.vault_id)
            .ok_or_else(|| "vault not found".to_string())?;
        require(vault.status.usable(), "vault is not usable")?;
        require(
            direction_supported(vault.direction, request.direction),
            "vault does not support quote direction",
        )?;
        require(request.amount_piconero > 0, "quote amount is zero")?;
        require(
            request.amount_piconero <= vault.available_piconero,
            "quote exceeds available vault liquidity",
        )?;
        require(
            request.privacy_set_size >= self.config.min_privacy_set_size,
            "quote privacy set below floor",
        )?;
        require(
            !request.private_route_root.is_empty(),
            "private route root empty",
        )?;
        require(
            !request.reserve_proof_root.is_empty(),
            "reserve proof root empty",
        )?;
        require(
            !request.pq_quote_attestation_root.is_empty(),
            "pq quote attestation root empty",
        )?;
        let quote = BridgeLiquidityQuoteRecord::new(&request, &self.config, self.height);
        require(
            quote.fee_piconero <= quote.max_fee_piconero,
            "quote fee exceeds user cap",
        )?;
        if quote.liquidity_class == LiquidityClass::SponsoredLowFee {
            require(
                vault
                    .sponsor_budget_piconero
                    .saturating_sub(vault.sponsor_spent_piconero)
                    >= quote.sponsor_fee_piconero,
                "vault sponsor budget exhausted",
            )?;
        }
        let quote_id = quote.quote_id.clone();
        let proof = ReserveProofRecord::new(
            &quote.vault_id,
            &quote_id,
            &quote.reserve_proof_root,
            quote.amount_piconero,
            self.config.target_reserve_proof_bps,
            quote.privacy_set_size,
            self.config.target_pq_security_bits,
            self.height,
        );
        insert_unique(&mut self.quotes, quote_id.clone(), quote, "quote")?;
        insert_unique(
            &mut self.reserve_proofs,
            proof.proof_id.clone(),
            proof,
            "reserve proof",
        )?;
        self.refresh_counters();
        self.refresh_public_records();
        Ok(quote_id)
    }

    pub fn reserve_private_exit_liquidity(
        &mut self,
        request: PrivateExitLiquidityReservationRequest,
    ) -> MoneroL2PqFastBridgeLiquidityRuntimeResult<String> {
        self.ensure_active()?;
        require(
            self.reservations.len() < self.config.max_reservations,
            "too many liquidity reservations",
        )?;
        require(
            matches!(
                request.direction,
                BridgeDirection::PrivateExit | BridgeDirection::PrivateEntry
            ),
            "reservation direction must be private entry or exit",
        )?;
        let quote = self
            .quotes
            .get(&request.quote_id)
            .ok_or_else(|| "quote not found".to_string())?
            .clone();
        require(quote.status.live(), "quote is not live")?;
        require(self.height <= quote.valid_until_height, "quote expired")?;
        require(
            direction_supported(quote.direction, request.direction),
            "quote does not support reservation direction",
        )?;
        require(request.amount_piconero > 0, "reservation amount is zero")?;
        require(
            request.amount_piconero <= quote.remaining_amount_piconero(),
            "reservation exceeds quote remainder",
        )?;
        require(
            request.privacy_set_size >= self.config.min_privacy_set_size,
            "reservation privacy set below floor",
        )?;
        require(
            !request.private_input_nullifier_root.is_empty(),
            "private input nullifier root empty",
        )?;
        require(
            !request.private_output_commitment_root.is_empty(),
            "private output commitment root empty",
        )?;
        require(
            !request.reserve_witness_root.is_empty(),
            "reserve witness root empty",
        )?;
        require(
            !self.used_nullifiers.contains(&request.replay_nullifier),
            "replay nullifier already used",
        )?;

        let reservation =
            PrivateLiquidityReservationRecord::new(&request, &quote, &self.config, self.height);
        let reservation_id = reservation.reservation_id.clone();
        self.used_nullifiers
            .insert(request.replay_nullifier.clone());
        {
            let vault = self
                .vaults
                .get_mut(&quote.vault_id)
                .ok_or_else(|| "vault not found".to_string())?;
            require(
                vault.available_piconero >= reservation.amount_piconero,
                "vault available liquidity below reservation",
            )?;
            vault.available_piconero = vault
                .available_piconero
                .saturating_sub(reservation.amount_piconero);
            vault.reserved_piconero = vault
                .reserved_piconero
                .saturating_add(reservation.amount_piconero);
            vault.sponsor_spent_piconero = vault
                .sponsor_spent_piconero
                .saturating_add(reservation.sponsor_fee_piconero);
            vault.last_update_height = self.height;
        }
        {
            let quote = self
                .quotes
                .get_mut(&request.quote_id)
                .ok_or_else(|| "quote not found".to_string())?;
            quote.reserved_amount_piconero = quote
                .reserved_amount_piconero
                .saturating_add(reservation.amount_piconero);
            quote.status = QuoteStatus::Reserved;
        }
        let proof = ReserveProofRecord::new(
            &reservation.vault_id,
            &reservation_id,
            &reservation.reserve_witness_root,
            reservation.amount_piconero,
            self.config.target_reserve_proof_bps,
            reservation.privacy_set_size,
            self.config.target_pq_security_bits,
            self.height,
        );
        insert_unique(
            &mut self.reservations,
            reservation_id.clone(),
            reservation,
            "reservation",
        )?;
        insert_unique(
            &mut self.reserve_proofs,
            proof.proof_id.clone(),
            proof,
            "reserve proof",
        )?;
        self.refresh_counters();
        self.refresh_public_records();
        Ok(reservation_id)
    }

    pub fn reserve_private_entry_liquidity(
        &mut self,
        request: PrivateExitLiquidityReservationRequest,
    ) -> MoneroL2PqFastBridgeLiquidityRuntimeResult<String> {
        require(
            request.direction == BridgeDirection::PrivateEntry,
            "entry reservation requires private entry direction",
        )?;
        self.reserve_private_exit_liquidity(request)
    }

    pub fn issue_fast_bridge_receipt(
        &mut self,
        request: FastBridgeReceiptRequest,
    ) -> MoneroL2PqFastBridgeLiquidityRuntimeResult<String> {
        self.ensure_active()?;
        require(
            self.receipts.len() < self.config.max_receipts,
            "too many fast bridge receipts",
        )?;
        let reservation = self
            .reservations
            .get(&request.reservation_id)
            .ok_or_else(|| "reservation not found".to_string())?
            .clone();
        require(
            reservation.status == ReservationStatus::Reserved,
            "reservation is not reservable",
        )?;
        require(
            self.height <= reservation.expires_at_height,
            "reservation expired",
        )?;
        require(
            request.receipt_height >= reservation.reserved_at_height,
            "receipt before reservation",
        )?;
        require(
            !request.fast_finality_committee_root.is_empty(),
            "fast finality committee root empty",
        )?;
        require(
            !request.l2_inclusion_root.is_empty(),
            "l2 inclusion root empty",
        )?;
        require(
            !request.monero_payout_commitment_root.is_empty(),
            "monero payout commitment root empty",
        )?;
        require(
            !request.pq_receipt_attestation_root.is_empty(),
            "pq receipt attestation root empty",
        )?;
        let receipt = FastBridgeReceiptRecord::new(&request, &reservation, &self.config);
        let receipt_id = receipt.receipt_id.clone();
        if let Some(reservation) = self.reservations.get_mut(&request.reservation_id) {
            reservation.status = ReservationStatus::ReceiptIssued;
        }
        if let Some(quote) = self.quotes.get_mut(&reservation.quote_id) {
            quote.status = QuoteStatus::Settling;
        }
        insert_unique(&mut self.receipts, receipt_id.clone(), receipt, "receipt")?;
        self.refresh_counters();
        self.refresh_public_records();
        Ok(receipt_id)
    }

    pub fn settle_bridge_liquidity(
        &mut self,
        request: BridgeLiquiditySettlementRequest,
    ) -> MoneroL2PqFastBridgeLiquidityRuntimeResult<String> {
        self.ensure_active()?;
        require(
            self.settlements.len() < self.config.max_settlements,
            "too many bridge settlements",
        )?;
        let receipt = self
            .receipts
            .get(&request.receipt_id)
            .ok_or_else(|| "receipt not found".to_string())?
            .clone();
        require(
            matches!(
                receipt.status,
                ReceiptStatus::Published | ReceiptStatus::Finalized
            ),
            "receipt cannot settle",
        )?;
        require(
            request.settlement_height >= receipt.final_after_height,
            "settlement before fast finality",
        )?;
        require(
            request.settlement_height
                <= receipt
                    .final_after_height
                    .saturating_add(self.config.settlement_ttl_blocks),
            "settlement outside ttl",
        )?;
        require(
            request.settled_amount_piconero == receipt.amount_piconero,
            "settled amount mismatch",
        )?;
        require(
            request.fee_paid_piconero <= receipt.fee_piconero,
            "settlement fee exceeds receipt fee",
        )?;
        require(
            !request.monero_txid_commitment.is_empty(),
            "monero txid commitment empty",
        )?;
        require(
            !request.output_proof_root.is_empty(),
            "output proof root empty",
        )?;
        require(
            !request.key_image_guard_root.is_empty(),
            "key image guard root empty",
        )?;
        let settlement = BridgeLiquiditySettlementRecord::new(&request, &receipt);
        let settlement_id = settlement.settlement_id.clone();
        {
            let reservation = self
                .reservations
                .get_mut(&receipt.reservation_id)
                .ok_or_else(|| "reservation not found".to_string())?;
            require(reservation.status.live(), "reservation not live")?;
            reservation.status = ReservationStatus::Settled;
        }
        {
            let quote = self
                .quotes
                .get_mut(&receipt.quote_id)
                .ok_or_else(|| "quote not found".to_string())?;
            quote.status = QuoteStatus::Settled;
        }
        {
            let vault = self
                .vaults
                .get_mut(&receipt.vault_id)
                .ok_or_else(|| "vault not found".to_string())?;
            vault.reserved_piconero = vault
                .reserved_piconero
                .saturating_sub(receipt.amount_piconero);
            vault.settled_piconero = vault
                .settled_piconero
                .saturating_add(receipt.amount_piconero);
            vault.last_update_height = request.settlement_height;
        }
        if let Some(receipt) = self.receipts.get_mut(&request.receipt_id) {
            receipt.status = ReceiptStatus::Settled;
        }
        insert_unique(
            &mut self.settlements,
            settlement_id.clone(),
            settlement,
            "settlement",
        )?;
        self.height = self.height.max(request.settlement_height);
        self.refresh_counters();
        self.refresh_public_records();
        Ok(settlement_id)
    }

    pub fn slash_stale_quote(
        &mut self,
        request: StaleQuoteSlashRequest,
    ) -> MoneroL2PqFastBridgeLiquidityRuntimeResult<String> {
        self.ensure_active()?;
        require(
            self.slashes.len() < self.config.max_slashes,
            "too many quote slashes",
        )?;
        require(
            request.reason == SlashReason::StaleQuote
                || request.reason == SlashReason::ReserveProofShortfall
                || request.reason == SlashReason::InvalidPqAttestation,
            "slash reason not valid for stale quote flow",
        )?;
        let quote = self
            .quotes
            .get(&request.quote_id)
            .ok_or_else(|| "quote not found".to_string())?
            .clone();
        require(quote.status.live(), "quote is not slashable")?;
        require(
            request.observed_height > quote.valid_until_height,
            "quote is not stale",
        )?;
        require(
            !request.watcher_commitment.is_empty(),
            "watcher commitment empty",
        )?;
        require(!request.evidence_root.is_empty(), "evidence root empty")?;
        let slash = QuoteSlashRecord::new(&request, &quote, &self.config);
        let slash_id = slash.slash_id.clone();
        {
            let quote = self
                .quotes
                .get_mut(&request.quote_id)
                .ok_or_else(|| "quote not found".to_string())?;
            quote.status = QuoteStatus::Slashed;
        }
        {
            let vault = self
                .vaults
                .get_mut(&quote.vault_id)
                .ok_or_else(|| "vault not found".to_string())?;
            let applied_slash = slash.slashed_piconero.min(vault.collateral_piconero);
            vault.collateral_piconero = vault.collateral_piconero.saturating_sub(applied_slash);
            vault.slashed_piconero = vault.slashed_piconero.saturating_add(applied_slash);
            vault.status = if vault.collateral_piconero == 0 {
                VaultStatus::Slashed
            } else {
                VaultStatus::Degraded
            };
            vault.last_update_height = request.observed_height;
        }
        insert_unique(&mut self.slashes, slash_id.clone(), slash, "slash")?;
        self.height = self.height.max(request.observed_height);
        self.refresh_counters();
        self.refresh_public_records();
        Ok(slash_id)
    }

    pub fn roots(&self) -> Roots {
        Roots {
            config_root: self.config.state_root(),
            vault_root: map_root(
                "MONERO-L2-PQ-FAST-BRIDGE-LIQUIDITY-VAULT-MAP",
                &self.vaults,
                LiquidityVaultRecord::public_record,
            ),
            quote_root: map_root(
                "MONERO-L2-PQ-FAST-BRIDGE-LIQUIDITY-QUOTE-MAP",
                &self.quotes,
                BridgeLiquidityQuoteRecord::public_record,
            ),
            reservation_root: map_root(
                "MONERO-L2-PQ-FAST-BRIDGE-LIQUIDITY-RESERVATION-MAP",
                &self.reservations,
                PrivateLiquidityReservationRecord::public_record,
            ),
            receipt_root: map_root(
                "MONERO-L2-PQ-FAST-BRIDGE-LIQUIDITY-RECEIPT-MAP",
                &self.receipts,
                FastBridgeReceiptRecord::public_record,
            ),
            settlement_root: map_root(
                "MONERO-L2-PQ-FAST-BRIDGE-LIQUIDITY-SETTLEMENT-MAP",
                &self.settlements,
                BridgeLiquiditySettlementRecord::public_record,
            ),
            reserve_proof_root: map_root(
                "MONERO-L2-PQ-FAST-BRIDGE-LIQUIDITY-RESERVE-PROOF-MAP",
                &self.reserve_proofs,
                ReserveProofRecord::public_record,
            ),
            slash_root: map_root(
                "MONERO-L2-PQ-FAST-BRIDGE-LIQUIDITY-SLASH-MAP",
                &self.slashes,
                QuoteSlashRecord::public_record,
            ),
            nullifier_root: set_root(
                "MONERO-L2-PQ-FAST-BRIDGE-LIQUIDITY-NULLIFIER-SET",
                &self.used_nullifiers,
            ),
            public_record_root: map_root(
                "MONERO-L2-PQ-FAST-BRIDGE-LIQUIDITY-PUBLIC-RECORD-MAP",
                &self.public_records,
                RootsOnlyPublicRecord::public_record,
            ),
            counters_root: self.counters.state_root(),
        }
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        set_json_field(&mut record, "state_root", json!(self.state_root()));
        record
    }

    pub fn public_record_without_state_root(&self) -> Value {
        let roots = self.roots();
        json!({
            "kind": "monero_l2_pq_fast_bridge_liquidity_runtime_state",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "height": self.height,
            "paused": self.paused,
            "config": self.config.public_record(),
            "roots": roots.public_record(),
            "roots_root": roots.state_root(),
            "counters": self.counters.public_record(),
            "privacy": "roots_only",
        })
    }

    pub fn state_root(&self) -> String {
        monero_l2_pq_fast_bridge_liquidity_runtime_state_root_from_record(
            &self.public_record_without_state_root(),
        )
    }

    pub fn validate(&self) -> MoneroL2PqFastBridgeLiquidityRuntimeResult<()> {
        self.config.validate()?;
        require(
            self.vaults.len() <= self.config.max_vaults,
            "too many vaults",
        )?;
        require(
            self.quotes.len() <= self.config.max_quotes,
            "too many quotes",
        )?;
        require(
            self.reservations.len() <= self.config.max_reservations,
            "too many reservations",
        )?;
        require(
            self.receipts.len() <= self.config.max_receipts,
            "too many receipts",
        )?;
        require(
            self.settlements.len() <= self.config.max_settlements,
            "too many settlements",
        )?;
        require(
            self.slashes.len() <= self.config.max_slashes,
            "too many slashes",
        )?;
        require(
            self.public_records.len() <= self.config.max_public_records,
            "too many public records",
        )?;
        for (vault_id, vault) in &self.vaults {
            require(vault_id == &vault.vault_id, "vault map key mismatch")?;
            require(
                vault
                    .available_piconero
                    .saturating_add(vault.reserved_piconero)
                    .saturating_add(vault.settled_piconero)
                    <= vault.capacity_piconero,
                "vault accounting exceeds capacity",
            )?;
            require(
                vault.reserve_proof_bps >= self.config.min_reserve_proof_bps,
                "vault reserve proof below floor",
            )?;
            require(
                vault.min_pq_security_bits >= self.config.min_pq_security_bits,
                "vault pq security below floor",
            )?;
        }
        for (quote_id, quote) in &self.quotes {
            require(quote_id == &quote.quote_id, "quote map key mismatch")?;
            require(
                self.vaults.contains_key(&quote.vault_id),
                "quote vault missing",
            )?;
            require(
                quote.reserved_amount_piconero <= quote.amount_piconero,
                "quote over-reserved",
            )?;
            require(
                quote.fee_piconero <= quote.max_fee_piconero,
                "quote fee exceeds cap",
            )?;
        }
        for (reservation_id, reservation) in &self.reservations {
            require(
                reservation_id == &reservation.reservation_id,
                "reservation map key mismatch",
            )?;
            require(
                self.quotes.contains_key(&reservation.quote_id),
                "reservation quote missing",
            )?;
            require(
                self.vaults.contains_key(&reservation.vault_id),
                "reservation vault missing",
            )?;
        }
        for (receipt_id, receipt) in &self.receipts {
            require(
                receipt_id == &receipt.receipt_id,
                "receipt map key mismatch",
            )?;
            require(
                self.reservations.contains_key(&receipt.reservation_id),
                "receipt reservation missing",
            )?;
        }
        for (settlement_id, settlement) in &self.settlements {
            require(
                settlement_id == &settlement.settlement_id,
                "settlement map key mismatch",
            )?;
            require(
                self.receipts.contains_key(&settlement.receipt_id),
                "settlement receipt missing",
            )?;
        }
        Ok(())
    }

    fn ensure_active(&self) -> MoneroL2PqFastBridgeLiquidityRuntimeResult<()> {
        require(!self.paused, "runtime is paused")
    }

    fn refresh_counters(&mut self) {
        let registered_vaults = self.vaults.len() as u64;
        let open_quotes = self
            .quotes
            .values()
            .filter(|quote| quote.status == QuoteStatus::Open)
            .count() as u64;
        let reserved_quotes = self
            .quotes
            .values()
            .filter(|quote| {
                quote.status == QuoteStatus::Reserved || quote.status == QuoteStatus::Settling
            })
            .count() as u64;
        let settled_quotes = self
            .quotes
            .values()
            .filter(|quote| quote.status == QuoteStatus::Settled)
            .count() as u64;
        let stale_quotes_slashed = self.slashes.len() as u64;
        let private_exit_reservations = self
            .reservations
            .values()
            .filter(|reservation| reservation.direction == BridgeDirection::PrivateExit)
            .count() as u64;
        let private_entry_reservations = self
            .reservations
            .values()
            .filter(|reservation| reservation.direction == BridgeDirection::PrivateEntry)
            .count() as u64;
        let fast_receipts_issued = self.receipts.len() as u64;
        let receipts_finalized = self
            .receipts
            .values()
            .filter(|receipt| {
                matches!(
                    receipt.status,
                    ReceiptStatus::Finalized | ReceiptStatus::Settled
                )
            })
            .count() as u64;
        let bridge_settlements = self.settlements.len() as u64;
        let sponsored_fee_piconero = self
            .reservations
            .values()
            .map(|reservation| reservation.sponsor_fee_piconero)
            .sum();
        let user_fee_piconero = self
            .reservations
            .values()
            .map(|reservation| reservation.user_fee_piconero)
            .sum();
        let slashed_collateral_piconero = self
            .vaults
            .values()
            .map(|vault| vault.slashed_piconero)
            .sum();
        let reserved_liquidity_piconero = self
            .vaults
            .values()
            .map(|vault| vault.reserved_piconero)
            .sum();
        let settled_liquidity_piconero = self
            .vaults
            .values()
            .map(|vault| vault.settled_piconero)
            .sum();
        self.counters = Counters {
            registered_vaults,
            open_quotes,
            reserved_quotes,
            settled_quotes,
            stale_quotes_slashed,
            private_exit_reservations,
            private_entry_reservations,
            fast_receipts_issued,
            receipts_finalized,
            bridge_settlements,
            sponsored_fee_piconero,
            user_fee_piconero,
            slashed_collateral_piconero,
            reserved_liquidity_piconero,
            settled_liquidity_piconero,
            public_records: self.public_records.len() as u64,
        };
    }

    fn refresh_public_records(&mut self) {
        let mut records = Vec::new();
        records.push((
            "config".to_string(),
            "config".to_string(),
            self.config.public_record(),
            vec!["protocol_version", "asset_id", "roots_only"],
        ));
        for vault in self.vaults.values() {
            records.push((
                "liquidity_vault".to_string(),
                vault.vault_id.clone(),
                vault.public_record(),
                vec![
                    "direction",
                    "reserve_proof_bps",
                    "status",
                    "available_piconero",
                ],
            ));
        }
        for quote in self.quotes.values() {
            records.push((
                "liquidity_quote".to_string(),
                quote.quote_id.clone(),
                quote.public_record(),
                vec![
                    "vault_id",
                    "direction",
                    "liquidity_class",
                    "amount_piconero",
                    "valid_until_height",
                    "status",
                ],
            ));
        }
        for reservation in self.reservations.values() {
            records.push((
                "private_liquidity_reservation".to_string(),
                reservation.reservation_id.clone(),
                reservation.public_record(),
                vec![
                    "quote_id",
                    "direction",
                    "amount_piconero",
                    "expires_at_height",
                    "status",
                ],
            ));
        }
        for receipt in self.receipts.values() {
            records.push((
                "fast_bridge_receipt".to_string(),
                receipt.receipt_id.clone(),
                receipt.public_record(),
                vec![
                    "reservation_id",
                    "final_after_height",
                    "amount_piconero",
                    "status",
                ],
            ));
        }
        for settlement in self.settlements.values() {
            records.push((
                "bridge_liquidity_settlement".to_string(),
                settlement.settlement_id.clone(),
                settlement.public_record(),
                vec![
                    "receipt_id",
                    "settlement_height",
                    "settled_amount_piconero",
                    "status",
                ],
            ));
        }
        for proof in self.reserve_proofs.values() {
            records.push((
                "reserve_proof".to_string(),
                proof.proof_id.clone(),
                proof.public_record(),
                vec![
                    "vault_id",
                    "coverage_bps",
                    "privacy_set_size",
                    "pq_security_bits",
                ],
            ));
        }
        for slash in self.slashes.values() {
            records.push((
                "quote_slash".to_string(),
                slash.slash_id.clone(),
                slash.public_record(),
                vec!["quote_id", "reason", "observed_height", "slashed_piconero"],
            ));
        }

        self.public_records.clear();
        for (subject_kind, subject_id, subject_record, disclosed_fields) in records {
            self.insert_public_record(
                &subject_kind,
                &subject_id,
                &subject_record,
                &disclosed_fields,
            );
        }
        self.counters.public_records = self.public_records.len() as u64;
    }

    fn insert_public_record(
        &mut self,
        subject_kind: &str,
        subject_id: &str,
        subject_record: &Value,
        disclosed_fields: &[&str],
    ) {
        if self.public_records.len() >= self.config.max_public_records {
            return;
        }
        let record = RootsOnlyPublicRecord::new(
            subject_kind,
            subject_id,
            subject_record,
            disclosed_fields,
            self.height,
        );
        self.public_records.insert(record.record_id.clone(), record);
    }
}

pub fn monero_l2_pq_fast_bridge_liquidity_runtime_devnet() -> State {
    State::devnet()
}

pub fn monero_l2_pq_fast_bridge_liquidity_runtime_state_root(state: &State) -> String {
    state.state_root()
}

pub fn monero_l2_pq_fast_bridge_liquidity_runtime_state_root_from_record(record: &Value) -> String {
    payload_root("MONERO-L2-PQ-FAST-BRIDGE-LIQUIDITY-STATE", record)
}

pub fn liquidity_vault_id(request: &RegisterLiquidityVaultRequest, height: u64) -> String {
    let record = LiquidityVaultRecord::new(request, height);
    record.vault_id
}

pub fn bridge_liquidity_quote_id(
    request: &BridgeLiquidityQuoteRequest,
    config: &Config,
    height: u64,
) -> String {
    let record = BridgeLiquidityQuoteRecord::new(request, config, height);
    record.quote_id
}

pub fn private_liquidity_reservation_id(
    request: &PrivateExitLiquidityReservationRequest,
    quote: &BridgeLiquidityQuoteRecord,
    config: &Config,
    height: u64,
) -> String {
    let record = PrivateLiquidityReservationRecord::new(request, quote, config, height);
    record.reservation_id
}

pub fn fast_bridge_receipt_id(
    request: &FastBridgeReceiptRequest,
    reservation: &PrivateLiquidityReservationRecord,
    config: &Config,
) -> String {
    let record = FastBridgeReceiptRecord::new(request, reservation, config);
    record.receipt_id
}

pub fn bridge_liquidity_settlement_id(
    request: &BridgeLiquiditySettlementRequest,
    receipt: &FastBridgeReceiptRecord,
) -> String {
    let record = BridgeLiquiditySettlementRecord::new(request, receipt);
    record.settlement_id
}

pub fn quote_slash_id(
    request: &StaleQuoteSlashRequest,
    quote: &BridgeLiquidityQuoteRecord,
    config: &Config,
) -> String {
    let record = QuoteSlashRecord::new(request, quote, config);
    record.slash_id
}

fn direction_supported(offered: BridgeDirection, requested: BridgeDirection) -> bool {
    match requested {
        BridgeDirection::PrivateEntry => offered.supports_entry(),
        BridgeDirection::PrivateExit => offered.supports_exit(),
        BridgeDirection::Bidirectional => offered == BridgeDirection::Bidirectional,
    }
}

fn require(condition: bool, message: &str) -> MoneroL2PqFastBridgeLiquidityRuntimeResult<()> {
    if condition {
        Ok(())
    } else {
        Err(message.to_string())
    }
}

fn insert_unique<T>(
    map: &mut BTreeMap<String, T>,
    key: String,
    value: T,
    label: &str,
) -> MoneroL2PqFastBridgeLiquidityRuntimeResult<()> {
    require(!key.is_empty(), &format!("{label} key is empty"))?;
    require(!map.contains_key(&key), &format!("{label} already exists"))?;
    map.insert(key, value);
    Ok(())
}

fn fee_for_amount(amount: u64, fee_bps: u64) -> u64 {
    amount.saturating_mul(fee_bps) / MONERO_L2_PQ_FAST_BRIDGE_LIQUIDITY_RUNTIME_MAX_BPS
}

fn payload_root(domain: &str, record: &Value) -> String {
    domain_hash(
        &format!("MONERO-L2-PQ-FAST-BRIDGE-LIQUIDITY:{domain}"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Json(record),
        ],
        32,
    )
}

fn id_from_record(domain: &str, record: &Value) -> String {
    domain_hash(
        &format!("MONERO-L2-PQ-FAST-BRIDGE-LIQUIDITY:{domain}"),
        &[HashPart::Str(CHAIN_ID), HashPart::Json(record)],
        20,
    )
}

fn seed_root(label: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-FAST-BRIDGE-LIQUIDITY:DEVNET-SEED",
        &[HashPart::Str(CHAIN_ID), HashPart::Str(label)],
        32,
    )
}

fn map_root<T, F>(domain: &str, map: &BTreeMap<String, T>, public_record: F) -> String
where
    F: Fn(&T) -> Value,
{
    let leaves = map
        .iter()
        .map(|(key, value)| json!({ "key": key, "record": public_record(value) }))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn set_root(domain: &str, set: &BTreeSet<String>) -> String {
    let leaves = set
        .iter()
        .map(|value| Value::String(value.clone()))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn project_fields(record: &Value, fields: &[&str]) -> Value {
    let mut projected = serde_json::Map::new();
    if let Some(object) = record.as_object() {
        for field in fields {
            if let Some(value) = object.get(*field) {
                projected.insert((*field).to_string(), value.clone());
            }
        }
    }
    Value::Object(projected)
}

fn set_json_field(record: &mut Value, key: &str, value: Value) {
    record
        .as_object_mut()
        .expect("public record is a JSON object")
        .insert(key.to_string(), value);
}
