use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqPrivateDecoyLiquidityRoutingRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_PRIVATE_DECOY_LIQUIDITY_ROUTING_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-private-decoy-liquidity-routing-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_PRIVATE_DECOY_LIQUIDITY_ROUTING_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const DEVNET_L2_NETWORK: &str = "nebula-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_ASSET_ID: &str = "wxmr-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_AUTH_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-decoy-liquidity-routing-v1";
pub const DECOY_ROUTE_SCHEME: &str = "monero-l2-pq-private-decoy-route-commitment-root-v1";
pub const LIQUIDITY_HINT_SCHEME: &str = "ml-kem-sealed-private-liquidity-hint-root-v1";
pub const RESERVE_MIRROR_SCHEME: &str = "pq-private-reserve-mirror-root-v1";
pub const RELAY_RESERVATION_SCHEME: &str = "private-relay-decoy-liquidity-reservation-root-v1";
pub const ROUTE_LOCK_SCHEME: &str = "reorg-safe-decoy-route-lock-root-v1";
pub const COVER_RECEIPT_SCHEME: &str = "fast-withdrawal-decoy-cover-receipt-root-v1";
pub const WATCHER_ATTESTATION_SCHEME: &str = "pq-private-decoy-routing-watcher-attestation-root-v1";
pub const PRIVACY_ACCOUNTING_SCHEME: &str = "private-decoy-routing-privacy-accounting-root-v1";
pub const SLASHING_SCHEME: &str = "private-decoy-liquidity-routing-slashing-root-v1";
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 262_144;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_LOW_FEE_BPS: u64 = 4;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 16;
pub const DEFAULT_REBATE_BPS: u64 = 6;
pub const DEFAULT_MIN_RESERVE_COVER_BPS: u64 = 10_500;
pub const DEFAULT_TARGET_RESERVE_COVER_BPS: u64 = 13_000;
pub const DEFAULT_ROUTE_TTL_BLOCKS: u64 = 32;
pub const DEFAULT_HINT_TTL_BLOCKS: u64 = 12;
pub const DEFAULT_RESERVATION_TTL_BLOCKS: u64 = 18;
pub const DEFAULT_LOCK_TTL_BLOCKS: u64 = 16;
pub const DEFAULT_RECEIPT_FINALITY_BLOCKS: u64 = 8;
pub const DEFAULT_MAX_ROUTES: usize = 2_097_152;
pub const DEFAULT_MAX_HINTS: usize = 4_194_304;
pub const DEFAULT_MAX_MIRRORS: usize = 1_048_576;
pub const DEFAULT_MAX_RESERVATIONS: usize = 2_097_152;
pub const DEFAULT_MAX_LOCKS: usize = 2_097_152;
pub const DEFAULT_MAX_RECEIPTS: usize = 2_097_152;
pub const DEFAULT_MAX_ATTESTATIONS: usize = 4_194_304;
pub const DEFAULT_MAX_PRIVACY_RECORDS: usize = 4_194_304;
pub const DEFAULT_MAX_SLASHES: usize = 1_048_576;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DecoyRouteKind {
    DepositShield,
    FastWithdrawal,
    LiquidityRebalance,
    MerchantPayment,
    AtomicSwap,
    ReserveAudit,
    EmergencyExit,
}

impl DecoyRouteKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DepositShield => "deposit_shield",
            Self::FastWithdrawal => "fast_withdrawal",
            Self::LiquidityRebalance => "liquidity_rebalance",
            Self::MerchantPayment => "merchant_payment",
            Self::AtomicSwap => "atomic_swap",
            Self::ReserveAudit => "reserve_audit",
            Self::EmergencyExit => "emergency_exit",
        }
    }

    pub fn priority_weight(self) -> u64 {
        match self {
            Self::EmergencyExit => 1_000,
            Self::FastWithdrawal => 930,
            Self::AtomicSwap => 860,
            Self::LiquidityRebalance => 800,
            Self::MerchantPayment => 730,
            Self::DepositShield => 680,
            Self::ReserveAudit => 540,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteStatus {
    Committed,
    Hinted,
    Reserved,
    Locked,
    Covered,
    Settled,
    Cancelled,
    Challenged,
    Expired,
}

impl RouteStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Committed => "committed",
            Self::Hinted => "hinted",
            Self::Reserved => "reserved",
            Self::Locked => "locked",
            Self::Covered => "covered",
            Self::Settled => "settled",
            Self::Cancelled => "cancelled",
            Self::Challenged => "challenged",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReservationStatus {
    Reserved,
    Consumed,
    Released,
    Slashed,
    Expired,
}

impl ReservationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Consumed => "consumed",
            Self::Released => "released",
            Self::Slashed => "slashed",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LockStatus {
    Active,
    Settled,
    Reorged,
    Released,
    Challenged,
}

impl LockStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Settled => "settled",
            Self::Reorged => "reorged",
            Self::Released => "released",
            Self::Challenged => "challenged",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptStatus {
    Published,
    Finalized,
    Reorged,
    Challenged,
}

impl ReceiptStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Published => "published",
            Self::Finalized => "finalized",
            Self::Reorged => "reorged",
            Self::Challenged => "challenged",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationKind {
    ReserveMirror,
    RelayObserved,
    ReorgSafe,
    RouteSettled,
    LiquidityAvailable,
    PrivacyBudget,
}

impl AttestationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ReserveMirror => "reserve_mirror",
            Self::RelayObserved => "relay_observed",
            Self::ReorgSafe => "reorg_safe",
            Self::RouteSettled => "route_settled",
            Self::LiquidityAvailable => "liquidity_available",
            Self::PrivacyBudget => "privacy_budget",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SlashKind {
    FalseReserve,
    DecoyLeak,
    RelayWithheld,
    ReorgUnsafeLock,
    DoubleReservation,
    FeeOvercharge,
}

impl SlashKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FalseReserve => "false_reserve",
            Self::DecoyLeak => "decoy_leak",
            Self::RelayWithheld => "relay_withheld",
            Self::ReorgUnsafeLock => "reorg_unsafe_lock",
            Self::DoubleReservation => "double_reservation",
            Self::FeeOvercharge => "fee_overcharge",
        }
    }

    pub fn severity_score(self) -> u64 {
        match self {
            Self::FalseReserve | Self::DecoyLeak | Self::DoubleReservation => 10_000,
            Self::ReorgUnsafeLock => 8_500,
            Self::RelayWithheld => 6_000,
            Self::FeeOvercharge => 3_500,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub l2_network: String,
    pub monero_network: String,
    pub asset_id: String,
    pub fee_asset_id: String,
    pub min_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub low_fee_bps: u64,
    pub max_user_fee_bps: u64,
    pub rebate_bps: u64,
    pub min_reserve_cover_bps: u64,
    pub target_reserve_cover_bps: u64,
    pub route_ttl_blocks: u64,
    pub hint_ttl_blocks: u64,
    pub reservation_ttl_blocks: u64,
    pub lock_ttl_blocks: u64,
    pub receipt_finality_blocks: u64,
    pub max_routes: usize,
    pub max_hints: usize,
    pub max_mirrors: usize,
    pub max_reservations: usize,
    pub max_locks: usize,
    pub max_receipts: usize,
    pub max_attestations: usize,
    pub max_privacy_records: usize,
    pub max_slashes: usize,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            l2_network: DEVNET_L2_NETWORK.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            asset_id: DEVNET_ASSET_ID.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            low_fee_bps: DEFAULT_LOW_FEE_BPS,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            rebate_bps: DEFAULT_REBATE_BPS,
            min_reserve_cover_bps: DEFAULT_MIN_RESERVE_COVER_BPS,
            target_reserve_cover_bps: DEFAULT_TARGET_RESERVE_COVER_BPS,
            route_ttl_blocks: DEFAULT_ROUTE_TTL_BLOCKS,
            hint_ttl_blocks: DEFAULT_HINT_TTL_BLOCKS,
            reservation_ttl_blocks: DEFAULT_RESERVATION_TTL_BLOCKS,
            lock_ttl_blocks: DEFAULT_LOCK_TTL_BLOCKS,
            receipt_finality_blocks: DEFAULT_RECEIPT_FINALITY_BLOCKS,
            max_routes: DEFAULT_MAX_ROUTES,
            max_hints: DEFAULT_MAX_HINTS,
            max_mirrors: DEFAULT_MAX_MIRRORS,
            max_reservations: DEFAULT_MAX_RESERVATIONS,
            max_locks: DEFAULT_MAX_LOCKS,
            max_receipts: DEFAULT_MAX_RECEIPTS,
            max_attestations: DEFAULT_MAX_ATTESTATIONS,
            max_privacy_records: DEFAULT_MAX_PRIVACY_RECORDS,
            max_slashes: DEFAULT_MAX_SLASHES,
        }
    }

    pub fn validate(&self) -> Result<()> {
        ensure_nonempty("chain_id", &self.chain_id)?;
        ensure_nonempty("l2_network", &self.l2_network)?;
        ensure_nonempty("monero_network", &self.monero_network)?;
        ensure_nonempty("asset_id", &self.asset_id)?;
        ensure_nonempty("fee_asset_id", &self.fee_asset_id)?;
        if self.min_privacy_set_size < 65_536 {
            return Err("min_privacy_set_size below Monero decoy routing floor".to_string());
        }
        if self.min_pq_security_bits < 192 {
            return Err("min_pq_security_bits below runtime PQ floor".to_string());
        }
        if self.low_fee_bps > self.max_user_fee_bps {
            return Err("low_fee_bps cannot exceed max_user_fee_bps".to_string());
        }
        if self.rebate_bps > self.max_user_fee_bps {
            return Err("rebate_bps cannot exceed max_user_fee_bps".to_string());
        }
        if self.min_reserve_cover_bps > self.target_reserve_cover_bps {
            return Err("min reserve cover cannot exceed target reserve cover".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_l2_pq_private_decoy_liquidity_routing_config",
            "chain_id": self.chain_id,
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "l2_network": self.l2_network,
            "monero_network": self.monero_network,
            "asset_id": self.asset_id,
            "fee_asset_id": self.fee_asset_id,
            "hash_suite": HASH_SUITE,
            "pq_auth_suite": PQ_AUTH_SUITE,
            "min_privacy_set_size": self.min_privacy_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
            "low_fee_bps": self.low_fee_bps,
            "max_user_fee_bps": self.max_user_fee_bps,
            "rebate_bps": self.rebate_bps,
            "min_reserve_cover_bps": self.min_reserve_cover_bps,
            "target_reserve_cover_bps": self.target_reserve_cover_bps,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Counters {
    pub next_route: u64,
    pub next_hint: u64,
    pub next_mirror: u64,
    pub next_reservation: u64,
    pub next_lock: u64,
    pub next_receipt: u64,
    pub next_attestation: u64,
    pub next_privacy_record: u64,
    pub next_slash: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_l2_pq_private_decoy_liquidity_routing_counters",
            "route_count": self.next_route,
            "hint_count": self.next_hint,
            "mirror_count": self.next_mirror,
            "reservation_count": self.next_reservation,
            "lock_count": self.next_lock,
            "receipt_count": self.next_receipt,
            "attestation_count": self.next_attestation,
            "privacy_record_count": self.next_privacy_record,
            "slash_count": self.next_slash,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub counters_root: String,
    pub route_root: String,
    pub hint_root: String,
    pub mirror_root: String,
    pub reservation_root: String,
    pub lock_root: String,
    pub receipt_root: String,
    pub attestation_root: String,
    pub privacy_record_root: String,
    pub slash_root: String,
    pub spent_nullifier_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_l2_pq_private_decoy_liquidity_routing_roots",
            "config_root": self.config_root,
            "counters_root": self.counters_root,
            "route_root": self.route_root,
            "hint_root": self.hint_root,
            "mirror_root": self.mirror_root,
            "reservation_root": self.reservation_root,
            "lock_root": self.lock_root,
            "receipt_root": self.receipt_root,
            "attestation_root": self.attestation_root,
            "privacy_record_root": self.privacy_record_root,
            "slash_root": self.slash_root,
            "spent_nullifier_root": self.spent_nullifier_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DecoyRouteCommitmentRequest {
    pub owner_commitment: String,
    pub route_kind: DecoyRouteKind,
    pub decoy_set_root: String,
    pub encrypted_path_root: String,
    pub route_amount_commitment: String,
    pub route_nullifier: String,
    pub privacy_set_size: u64,
    pub max_fee_micro_units: u64,
    pub opened_height: u64,
    pub metadata_root: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DecoyRouteCommitment {
    pub route_id: String,
    pub owner_commitment: String,
    pub route_kind: DecoyRouteKind,
    pub decoy_set_root: String,
    pub encrypted_path_root: String,
    pub route_amount_commitment: String,
    pub route_nullifier: String,
    pub privacy_set_size: u64,
    pub max_fee_micro_units: u64,
    pub opened_height: u64,
    pub expires_height: u64,
    pub priority_score: u64,
    pub status: RouteStatus,
    pub metadata_root: String,
}

impl DecoyRouteCommitment {
    pub fn from_request(config: &Config, request: DecoyRouteCommitmentRequest) -> Result<Self> {
        ensure_nonempty("owner_commitment", &request.owner_commitment)?;
        ensure_nonempty("decoy_set_root", &request.decoy_set_root)?;
        ensure_nonempty("encrypted_path_root", &request.encrypted_path_root)?;
        ensure_nonempty("route_amount_commitment", &request.route_amount_commitment)?;
        ensure_nonempty("route_nullifier", &request.route_nullifier)?;
        if request.privacy_set_size < config.min_privacy_set_size {
            return Err("route privacy set below configured minimum".to_string());
        }
        let route_id = decoy_route_id(&request);
        Ok(Self {
            route_id,
            owner_commitment: request.owner_commitment,
            route_kind: request.route_kind,
            decoy_set_root: request.decoy_set_root,
            encrypted_path_root: request.encrypted_path_root,
            route_amount_commitment: request.route_amount_commitment,
            route_nullifier: request.route_nullifier,
            privacy_set_size: request.privacy_set_size,
            max_fee_micro_units: request.max_fee_micro_units,
            opened_height: request.opened_height,
            expires_height: request
                .opened_height
                .saturating_add(config.route_ttl_blocks),
            priority_score: route_priority_score(
                request.route_kind,
                request.privacy_set_size,
                request.max_fee_micro_units,
            ),
            status: RouteStatus::Committed,
            metadata_root: request.metadata_root,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_l2_pq_private_decoy_route_commitment",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "route_id": self.route_id,
            "owner_commitment": self.owner_commitment,
            "route_kind": self.route_kind.as_str(),
            "decoy_set_root": self.decoy_set_root,
            "encrypted_path_root": self.encrypted_path_root,
            "route_amount_commitment": self.route_amount_commitment,
            "route_nullifier": self.route_nullifier,
            "privacy_set_size": self.privacy_set_size,
            "max_fee_micro_units": self.max_fee_micro_units,
            "opened_height": self.opened_height,
            "expires_height": self.expires_height,
            "priority_score": self.priority_score,
            "status": self.status.as_str(),
            "scheme": DECOY_ROUTE_SCHEME,
            "metadata_root": self.metadata_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LiquidityHintRequest {
    pub route_id: String,
    pub provider_id: String,
    pub encrypted_hint_root: String,
    pub reserve_hint_root: String,
    pub fee_quote_micro_units: u64,
    pub hint_height: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LiquidityHint {
    pub hint_id: String,
    pub route_id: String,
    pub provider_id: String,
    pub encrypted_hint_root: String,
    pub reserve_hint_root: String,
    pub fee_quote_micro_units: u64,
    pub hint_height: u64,
    pub expires_height: u64,
}

impl LiquidityHint {
    pub fn from_request(config: &Config, request: LiquidityHintRequest) -> Result<Self> {
        ensure_nonempty("route_id", &request.route_id)?;
        ensure_nonempty("provider_id", &request.provider_id)?;
        ensure_nonempty("encrypted_hint_root", &request.encrypted_hint_root)?;
        ensure_nonempty("reserve_hint_root", &request.reserve_hint_root)?;
        let hint_id = liquidity_hint_id(&request);
        Ok(Self {
            hint_id,
            route_id: request.route_id,
            provider_id: request.provider_id,
            encrypted_hint_root: request.encrypted_hint_root,
            reserve_hint_root: request.reserve_hint_root,
            fee_quote_micro_units: request.fee_quote_micro_units,
            hint_height: request.hint_height,
            expires_height: request.hint_height.saturating_add(config.hint_ttl_blocks),
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_l2_pq_private_liquidity_hint",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "hint_id": self.hint_id,
            "route_id": self.route_id,
            "provider_id": self.provider_id,
            "encrypted_hint_root": self.encrypted_hint_root,
            "reserve_hint_root": self.reserve_hint_root,
            "fee_quote_micro_units": self.fee_quote_micro_units,
            "hint_height": self.hint_height,
            "expires_height": self.expires_height,
            "scheme": LIQUIDITY_HINT_SCHEME,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ReserveMirrorRequest {
    pub provider_id: String,
    pub reserve_commitment: String,
    pub covered_route_root: String,
    pub reserve_cover_bps: u64,
    pub pq_attestation_root: String,
    pub observed_height: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ReserveMirror {
    pub mirror_id: String,
    pub provider_id: String,
    pub reserve_commitment: String,
    pub covered_route_root: String,
    pub reserve_cover_bps: u64,
    pub pq_attestation_root: String,
    pub observed_height: u64,
}

impl ReserveMirror {
    pub fn from_request(config: &Config, request: ReserveMirrorRequest) -> Result<Self> {
        ensure_nonempty("provider_id", &request.provider_id)?;
        ensure_nonempty("reserve_commitment", &request.reserve_commitment)?;
        ensure_nonempty("covered_route_root", &request.covered_route_root)?;
        ensure_nonempty("pq_attestation_root", &request.pq_attestation_root)?;
        if request.reserve_cover_bps < config.min_reserve_cover_bps {
            return Err("reserve cover is below configured minimum".to_string());
        }
        let mirror_id = reserve_mirror_id(&request);
        Ok(Self {
            mirror_id,
            provider_id: request.provider_id,
            reserve_commitment: request.reserve_commitment,
            covered_route_root: request.covered_route_root,
            reserve_cover_bps: request.reserve_cover_bps,
            pq_attestation_root: request.pq_attestation_root,
            observed_height: request.observed_height,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_l2_pq_private_reserve_mirror",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "mirror_id": self.mirror_id,
            "provider_id": self.provider_id,
            "reserve_commitment": self.reserve_commitment,
            "covered_route_root": self.covered_route_root,
            "reserve_cover_bps": self.reserve_cover_bps,
            "pq_attestation_root": self.pq_attestation_root,
            "observed_height": self.observed_height,
            "scheme": RESERVE_MIRROR_SCHEME,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RelayReservationRequest {
    pub route_id: String,
    pub provider_id: String,
    pub mirror_id: String,
    pub reservation_commitment: String,
    pub relay_fee_micro_units: u64,
    pub reservation_height: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RelayReservation {
    pub reservation_id: String,
    pub route_id: String,
    pub provider_id: String,
    pub mirror_id: String,
    pub reservation_commitment: String,
    pub relay_fee_micro_units: u64,
    pub reservation_height: u64,
    pub expires_height: u64,
    pub status: ReservationStatus,
}

impl RelayReservation {
    pub fn from_request(config: &Config, request: RelayReservationRequest) -> Result<Self> {
        ensure_nonempty("route_id", &request.route_id)?;
        ensure_nonempty("provider_id", &request.provider_id)?;
        ensure_nonempty("mirror_id", &request.mirror_id)?;
        ensure_nonempty("reservation_commitment", &request.reservation_commitment)?;
        let reservation_id = relay_reservation_id(&request);
        Ok(Self {
            reservation_id,
            route_id: request.route_id,
            provider_id: request.provider_id,
            mirror_id: request.mirror_id,
            reservation_commitment: request.reservation_commitment,
            relay_fee_micro_units: request.relay_fee_micro_units,
            reservation_height: request.reservation_height,
            expires_height: request
                .reservation_height
                .saturating_add(config.reservation_ttl_blocks),
            status: ReservationStatus::Reserved,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_l2_pq_private_decoy_relay_reservation",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "reservation_id": self.reservation_id,
            "route_id": self.route_id,
            "provider_id": self.provider_id,
            "mirror_id": self.mirror_id,
            "reservation_commitment": self.reservation_commitment,
            "relay_fee_micro_units": self.relay_fee_micro_units,
            "reservation_height": self.reservation_height,
            "expires_height": self.expires_height,
            "status": self.status.as_str(),
            "scheme": RELAY_RESERVATION_SCHEME,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RouteLockRequest {
    pub route_id: String,
    pub reservation_id: String,
    pub monero_anchor_root: String,
    pub l2_state_root: String,
    pub reorg_guard_root: String,
    pub locked_height: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RouteLock {
    pub lock_id: String,
    pub route_id: String,
    pub reservation_id: String,
    pub monero_anchor_root: String,
    pub l2_state_root: String,
    pub reorg_guard_root: String,
    pub locked_height: u64,
    pub expires_height: u64,
    pub status: LockStatus,
}

impl RouteLock {
    pub fn from_request(config: &Config, request: RouteLockRequest) -> Result<Self> {
        ensure_nonempty("route_id", &request.route_id)?;
        ensure_nonempty("reservation_id", &request.reservation_id)?;
        ensure_nonempty("monero_anchor_root", &request.monero_anchor_root)?;
        ensure_nonempty("l2_state_root", &request.l2_state_root)?;
        ensure_nonempty("reorg_guard_root", &request.reorg_guard_root)?;
        let lock_id = route_lock_id(&request);
        Ok(Self {
            lock_id,
            route_id: request.route_id,
            reservation_id: request.reservation_id,
            monero_anchor_root: request.monero_anchor_root,
            l2_state_root: request.l2_state_root,
            reorg_guard_root: request.reorg_guard_root,
            locked_height: request.locked_height,
            expires_height: request.locked_height.saturating_add(config.lock_ttl_blocks),
            status: LockStatus::Active,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_l2_pq_private_decoy_route_lock",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "lock_id": self.lock_id,
            "route_id": self.route_id,
            "reservation_id": self.reservation_id,
            "monero_anchor_root": self.monero_anchor_root,
            "l2_state_root": self.l2_state_root,
            "reorg_guard_root": self.reorg_guard_root,
            "locked_height": self.locked_height,
            "expires_height": self.expires_height,
            "status": self.status.as_str(),
            "scheme": ROUTE_LOCK_SCHEME,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CoverReceiptRequest {
    pub route_id: String,
    pub lock_id: String,
    pub provider_id: String,
    pub cover_commitment: String,
    pub fee_paid_micro_units: u64,
    pub rebate_nullifier: String,
    pub settled_height: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CoverReceipt {
    pub receipt_id: String,
    pub route_id: String,
    pub lock_id: String,
    pub provider_id: String,
    pub cover_commitment: String,
    pub fee_paid_micro_units: u64,
    pub rebate_micro_units: u64,
    pub rebate_nullifier: String,
    pub settled_height: u64,
    pub finality_height: u64,
    pub status: ReceiptStatus,
}

impl CoverReceipt {
    pub fn from_request(config: &Config, request: CoverReceiptRequest) -> Result<Self> {
        ensure_nonempty("route_id", &request.route_id)?;
        ensure_nonempty("lock_id", &request.lock_id)?;
        ensure_nonempty("provider_id", &request.provider_id)?;
        ensure_nonempty("cover_commitment", &request.cover_commitment)?;
        ensure_nonempty("rebate_nullifier", &request.rebate_nullifier)?;
        let rebate_micro_units = request
            .fee_paid_micro_units
            .saturating_mul(config.rebate_bps)
            / MAX_BPS;
        let receipt_id = cover_receipt_id(&request, rebate_micro_units);
        Ok(Self {
            receipt_id,
            route_id: request.route_id,
            lock_id: request.lock_id,
            provider_id: request.provider_id,
            cover_commitment: request.cover_commitment,
            fee_paid_micro_units: request.fee_paid_micro_units,
            rebate_micro_units,
            rebate_nullifier: request.rebate_nullifier,
            settled_height: request.settled_height,
            finality_height: request
                .settled_height
                .saturating_add(config.receipt_finality_blocks),
            status: ReceiptStatus::Published,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_l2_pq_private_decoy_cover_receipt",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "receipt_id": self.receipt_id,
            "route_id": self.route_id,
            "lock_id": self.lock_id,
            "provider_id": self.provider_id,
            "cover_commitment": self.cover_commitment,
            "fee_paid_micro_units": self.fee_paid_micro_units,
            "rebate_micro_units": self.rebate_micro_units,
            "rebate_nullifier": self.rebate_nullifier,
            "settled_height": self.settled_height,
            "finality_height": self.finality_height,
            "status": self.status.as_str(),
            "scheme": COVER_RECEIPT_SCHEME,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WatcherAttestationRequest {
    pub subject_id: String,
    pub watcher_id: String,
    pub kind: AttestationKind,
    pub attestation_root: String,
    pub pq_signature_root: String,
    pub observed_height: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WatcherAttestation {
    pub attestation_id: String,
    pub subject_id: String,
    pub watcher_id: String,
    pub kind: AttestationKind,
    pub attestation_root: String,
    pub pq_signature_root: String,
    pub observed_height: u64,
}

impl WatcherAttestation {
    pub fn from_request(request: WatcherAttestationRequest) -> Result<Self> {
        ensure_nonempty("subject_id", &request.subject_id)?;
        ensure_nonempty("watcher_id", &request.watcher_id)?;
        ensure_nonempty("attestation_root", &request.attestation_root)?;
        ensure_nonempty("pq_signature_root", &request.pq_signature_root)?;
        let attestation_id = watcher_attestation_id(&request);
        Ok(Self {
            attestation_id,
            subject_id: request.subject_id,
            watcher_id: request.watcher_id,
            kind: request.kind,
            attestation_root: request.attestation_root,
            pq_signature_root: request.pq_signature_root,
            observed_height: request.observed_height,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_l2_pq_private_decoy_watcher_attestation",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "attestation_id": self.attestation_id,
            "subject_id": self.subject_id,
            "watcher_id": self.watcher_id,
            "attestation_kind": self.kind.as_str(),
            "attestation_root": self.attestation_root,
            "pq_signature_root": self.pq_signature_root,
            "observed_height": self.observed_height,
            "scheme": WATCHER_ATTESTATION_SCHEME,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PrivacyAccountingRequest {
    pub subject_id: String,
    pub owner_commitment: String,
    pub nullifier: String,
    pub privacy_set_size: u64,
    pub decoy_budget_root: String,
    pub height: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PrivacyAccounting {
    pub privacy_record_id: String,
    pub subject_id: String,
    pub owner_commitment: String,
    pub nullifier: String,
    pub privacy_set_size: u64,
    pub decoy_budget_root: String,
    pub height: u64,
}

impl PrivacyAccounting {
    pub fn from_request(config: &Config, request: PrivacyAccountingRequest) -> Result<Self> {
        ensure_nonempty("subject_id", &request.subject_id)?;
        ensure_nonempty("owner_commitment", &request.owner_commitment)?;
        ensure_nonempty("nullifier", &request.nullifier)?;
        ensure_nonempty("decoy_budget_root", &request.decoy_budget_root)?;
        if request.privacy_set_size < config.min_privacy_set_size {
            return Err("privacy accounting set below configured minimum".to_string());
        }
        let privacy_record_id = privacy_record_id(&request);
        Ok(Self {
            privacy_record_id,
            subject_id: request.subject_id,
            owner_commitment: request.owner_commitment,
            nullifier: request.nullifier,
            privacy_set_size: request.privacy_set_size,
            decoy_budget_root: request.decoy_budget_root,
            height: request.height,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_l2_pq_private_decoy_privacy_accounting",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "privacy_record_id": self.privacy_record_id,
            "subject_id": self.subject_id,
            "owner_commitment": self.owner_commitment,
            "nullifier": self.nullifier,
            "privacy_set_size": self.privacy_set_size,
            "decoy_budget_root": self.decoy_budget_root,
            "height": self.height,
            "scheme": PRIVACY_ACCOUNTING_SCHEME,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SlashingEvidenceRequest {
    pub subject_id: String,
    pub offender_id: String,
    pub kind: SlashKind,
    pub evidence_root: String,
    pub witness_root: String,
    pub bond_micro_units: u64,
    pub height: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SlashingEvidence {
    pub slash_id: String,
    pub subject_id: String,
    pub offender_id: String,
    pub kind: SlashKind,
    pub evidence_root: String,
    pub witness_root: String,
    pub bond_micro_units: u64,
    pub severity_score: u64,
    pub height: u64,
    pub executed: bool,
}

impl SlashingEvidence {
    pub fn from_request(request: SlashingEvidenceRequest) -> Result<Self> {
        ensure_nonempty("subject_id", &request.subject_id)?;
        ensure_nonempty("offender_id", &request.offender_id)?;
        ensure_nonempty("evidence_root", &request.evidence_root)?;
        ensure_nonempty("witness_root", &request.witness_root)?;
        let slash_id = slashing_evidence_id(&request);
        Ok(Self {
            slash_id,
            subject_id: request.subject_id,
            offender_id: request.offender_id,
            kind: request.kind,
            evidence_root: request.evidence_root,
            witness_root: request.witness_root,
            bond_micro_units: request.bond_micro_units,
            severity_score: request.kind.severity_score(),
            height: request.height,
            executed: false,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_l2_pq_private_decoy_slashing_evidence",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "slash_id": self.slash_id,
            "subject_id": self.subject_id,
            "offender_id": self.offender_id,
            "slash_kind": self.kind.as_str(),
            "evidence_root": self.evidence_root,
            "witness_root": self.witness_root,
            "bond_micro_units": self.bond_micro_units,
            "severity_score": self.severity_score,
            "height": self.height,
            "executed": self.executed,
            "scheme": SLASHING_SCHEME,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub routes: BTreeMap<String, DecoyRouteCommitment>,
    pub hints: BTreeMap<String, LiquidityHint>,
    pub mirrors: BTreeMap<String, ReserveMirror>,
    pub reservations: BTreeMap<String, RelayReservation>,
    pub locks: BTreeMap<String, RouteLock>,
    pub receipts: BTreeMap<String, CoverReceipt>,
    pub attestations: BTreeMap<String, WatcherAttestation>,
    pub privacy_records: BTreeMap<String, PrivacyAccounting>,
    pub slashing_evidence: BTreeMap<String, SlashingEvidence>,
    spent_nullifiers: BTreeSet<String>,
}

impl State {
    pub fn devnet() -> Self {
        let mut state = Self {
            config: Config::devnet(),
            counters: Counters::default(),
            roots: Roots::default(),
            routes: BTreeMap::new(),
            hints: BTreeMap::new(),
            mirrors: BTreeMap::new(),
            reservations: BTreeMap::new(),
            locks: BTreeMap::new(),
            receipts: BTreeMap::new(),
            attestations: BTreeMap::new(),
            privacy_records: BTreeMap::new(),
            slashing_evidence: BTreeMap::new(),
            spent_nullifiers: BTreeSet::new(),
        };
        state.recompute_roots();
        state
    }

    pub fn with_config(config: Config) -> Result<Self> {
        config.validate()?;
        let mut state = Self {
            config,
            ..Self::devnet()
        };
        state.recompute_roots();
        Ok(state)
    }

    pub fn commit_route(
        &mut self,
        request: DecoyRouteCommitmentRequest,
    ) -> Result<DecoyRouteCommitment> {
        ensure_capacity("routes", self.routes.len(), self.config.max_routes)?;
        if self.spent_nullifiers.contains(&request.route_nullifier) {
            return Err("route nullifier already spent".to_string());
        }
        let route = DecoyRouteCommitment::from_request(&self.config, request)?;
        ensure_absent("route", &self.routes, &route.route_id)?;
        self.spent_nullifiers.insert(route.route_nullifier.clone());
        self.counters.next_route = self.counters.next_route.saturating_add(1);
        self.routes.insert(route.route_id.clone(), route.clone());
        self.recompute_roots();
        Ok(route)
    }

    pub fn post_hint(&mut self, request: LiquidityHintRequest) -> Result<LiquidityHint> {
        ensure_capacity("hints", self.hints.len(), self.config.max_hints)?;
        let hint = LiquidityHint::from_request(&self.config, request)?;
        let route = self
            .routes
            .get_mut(&hint.route_id)
            .ok_or_else(|| format!("unknown route_id {}", hint.route_id))?;
        ensure_absent("hint", &self.hints, &hint.hint_id)?;
        route.status = RouteStatus::Hinted;
        self.counters.next_hint = self.counters.next_hint.saturating_add(1);
        self.hints.insert(hint.hint_id.clone(), hint.clone());
        self.recompute_roots();
        Ok(hint)
    }

    pub fn mirror_reserve(&mut self, request: ReserveMirrorRequest) -> Result<ReserveMirror> {
        ensure_capacity("mirrors", self.mirrors.len(), self.config.max_mirrors)?;
        let mirror = ReserveMirror::from_request(&self.config, request)?;
        ensure_absent("reserve_mirror", &self.mirrors, &mirror.mirror_id)?;
        self.counters.next_mirror = self.counters.next_mirror.saturating_add(1);
        self.mirrors
            .insert(mirror.mirror_id.clone(), mirror.clone());
        self.recompute_roots();
        Ok(mirror)
    }

    pub fn reserve_relay(&mut self, request: RelayReservationRequest) -> Result<RelayReservation> {
        ensure_capacity(
            "reservations",
            self.reservations.len(),
            self.config.max_reservations,
        )?;
        let reservation = RelayReservation::from_request(&self.config, request)?;
        ensure_known("route", &self.routes, &reservation.route_id)?;
        ensure_known("reserve_mirror", &self.mirrors, &reservation.mirror_id)?;
        ensure_absent(
            "relay_reservation",
            &self.reservations,
            &reservation.reservation_id,
        )?;
        if let Some(route) = self.routes.get_mut(&reservation.route_id) {
            route.status = RouteStatus::Reserved;
        }
        self.counters.next_reservation = self.counters.next_reservation.saturating_add(1);
        self.reservations
            .insert(reservation.reservation_id.clone(), reservation.clone());
        self.recompute_roots();
        Ok(reservation)
    }

    pub fn lock_route(&mut self, request: RouteLockRequest) -> Result<RouteLock> {
        ensure_capacity("locks", self.locks.len(), self.config.max_locks)?;
        let lock = RouteLock::from_request(&self.config, request)?;
        ensure_known("route", &self.routes, &lock.route_id)?;
        let reservation = self
            .reservations
            .get_mut(&lock.reservation_id)
            .ok_or_else(|| format!("unknown reservation_id {}", lock.reservation_id))?;
        reservation.status = ReservationStatus::Consumed;
        if let Some(route) = self.routes.get_mut(&lock.route_id) {
            route.status = RouteStatus::Locked;
        }
        ensure_absent("route_lock", &self.locks, &lock.lock_id)?;
        self.counters.next_lock = self.counters.next_lock.saturating_add(1);
        self.locks.insert(lock.lock_id.clone(), lock.clone());
        self.recompute_roots();
        Ok(lock)
    }

    pub fn publish_cover_receipt(&mut self, request: CoverReceiptRequest) -> Result<CoverReceipt> {
        ensure_capacity("receipts", self.receipts.len(), self.config.max_receipts)?;
        if self.spent_nullifiers.contains(&request.rebate_nullifier) {
            return Err("rebate nullifier already spent".to_string());
        }
        let receipt = CoverReceipt::from_request(&self.config, request)?;
        ensure_known("route", &self.routes, &receipt.route_id)?;
        let lock = self
            .locks
            .get_mut(&receipt.lock_id)
            .ok_or_else(|| format!("unknown lock_id {}", receipt.lock_id))?;
        lock.status = LockStatus::Settled;
        if let Some(route) = self.routes.get_mut(&receipt.route_id) {
            route.status = RouteStatus::Covered;
        }
        ensure_absent("cover_receipt", &self.receipts, &receipt.receipt_id)?;
        self.spent_nullifiers
            .insert(receipt.rebate_nullifier.clone());
        self.counters.next_receipt = self.counters.next_receipt.saturating_add(1);
        self.receipts
            .insert(receipt.receipt_id.clone(), receipt.clone());
        self.recompute_roots();
        Ok(receipt)
    }

    pub fn attest(&mut self, request: WatcherAttestationRequest) -> Result<WatcherAttestation> {
        ensure_capacity(
            "attestations",
            self.attestations.len(),
            self.config.max_attestations,
        )?;
        let attestation = WatcherAttestation::from_request(request)?;
        ensure_absent(
            "watcher_attestation",
            &self.attestations,
            &attestation.attestation_id,
        )?;
        self.counters.next_attestation = self.counters.next_attestation.saturating_add(1);
        self.attestations
            .insert(attestation.attestation_id.clone(), attestation.clone());
        self.recompute_roots();
        Ok(attestation)
    }

    pub fn account_privacy(
        &mut self,
        request: PrivacyAccountingRequest,
    ) -> Result<PrivacyAccounting> {
        ensure_capacity(
            "privacy_records",
            self.privacy_records.len(),
            self.config.max_privacy_records,
        )?;
        if self.spent_nullifiers.contains(&request.nullifier) {
            return Err("privacy accounting nullifier already spent".to_string());
        }
        let privacy = PrivacyAccounting::from_request(&self.config, request)?;
        ensure_absent(
            "privacy_record",
            &self.privacy_records,
            &privacy.privacy_record_id,
        )?;
        self.spent_nullifiers.insert(privacy.nullifier.clone());
        self.counters.next_privacy_record = self.counters.next_privacy_record.saturating_add(1);
        self.privacy_records
            .insert(privacy.privacy_record_id.clone(), privacy.clone());
        self.recompute_roots();
        Ok(privacy)
    }

    pub fn file_slashing(&mut self, request: SlashingEvidenceRequest) -> Result<SlashingEvidence> {
        ensure_capacity(
            "slashing_evidence",
            self.slashing_evidence.len(),
            self.config.max_slashes,
        )?;
        let slash = SlashingEvidence::from_request(request)?;
        ensure_absent(
            "slashing_evidence",
            &self.slashing_evidence,
            &slash.slash_id,
        )?;
        if let Some(route) = self.routes.get_mut(&slash.subject_id) {
            route.status = RouteStatus::Challenged;
        }
        if let Some(lock) = self.locks.get_mut(&slash.subject_id) {
            lock.status = LockStatus::Challenged;
        }
        if let Some(receipt) = self.receipts.get_mut(&slash.subject_id) {
            receipt.status = ReceiptStatus::Challenged;
        }
        self.counters.next_slash = self.counters.next_slash.saturating_add(1);
        self.slashing_evidence
            .insert(slash.slash_id.clone(), slash.clone());
        self.recompute_roots();
        Ok(slash)
    }

    pub fn finalize_receipt(&mut self, receipt_id: &str) -> Result<()> {
        let receipt = self
            .receipts
            .get_mut(receipt_id)
            .ok_or_else(|| format!("unknown receipt_id {}", receipt_id))?;
        receipt.status = ReceiptStatus::Finalized;
        if let Some(route) = self.routes.get_mut(&receipt.route_id) {
            route.status = RouteStatus::Settled;
        }
        self.recompute_roots();
        Ok(())
    }

    pub fn recompute_roots(&mut self) {
        self.roots = Roots {
            config_root: record_root(
                "DECOY-LIQUIDITY-ROUTING-CONFIG",
                &self.config.public_record(),
            ),
            counters_root: record_root(
                "DECOY-LIQUIDITY-ROUTING-COUNTERS",
                &self.counters.public_record(),
            ),
            route_root: map_root("DECOY-LIQUIDITY-ROUTING-ROUTES", &self.routes),
            hint_root: map_root("DECOY-LIQUIDITY-ROUTING-HINTS", &self.hints),
            mirror_root: map_root("DECOY-LIQUIDITY-ROUTING-MIRRORS", &self.mirrors),
            reservation_root: map_root("DECOY-LIQUIDITY-ROUTING-RESERVATIONS", &self.reservations),
            lock_root: map_root("DECOY-LIQUIDITY-ROUTING-LOCKS", &self.locks),
            receipt_root: map_root("DECOY-LIQUIDITY-ROUTING-RECEIPTS", &self.receipts),
            attestation_root: map_root("DECOY-LIQUIDITY-ROUTING-ATTESTATIONS", &self.attestations),
            privacy_record_root: map_root("DECOY-LIQUIDITY-ROUTING-PRIVACY", &self.privacy_records),
            slash_root: map_root("DECOY-LIQUIDITY-ROUTING-SLASHES", &self.slashing_evidence),
            spent_nullifier_root: set_root(
                "DECOY-LIQUIDITY-ROUTING-SPENT-NULLIFIERS",
                &self.spent_nullifiers,
            ),
        };
    }

    pub fn public_record_without_state_root(&self) -> Value {
        json!({
            "kind": "monero_l2_pq_private_decoy_liquidity_routing_runtime",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
            "route_count": self.routes.len(),
            "hint_count": self.hints.len(),
            "mirror_count": self.mirrors.len(),
            "reservation_count": self.reservations.len(),
            "lock_count": self.locks.len(),
            "receipt_count": self.receipts.len(),
            "attestation_count": self.attestations.len(),
            "privacy_record_count": self.privacy_records.len(),
            "slash_count": self.slashing_evidence.len(),
            "spent_nullifier_count": self.spent_nullifiers.len(),
        })
    }

    pub fn state_root(&self) -> String {
        state_root_from_record(&self.public_record_without_state_root())
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        if let Some(object) = record.as_object_mut() {
            object.insert("state_root".to_string(), Value::String(self.state_root()));
        }
        record
    }
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn monero_l2_pq_private_decoy_liquidity_routing_runtime_state_root(state: &State) -> String {
    state.state_root()
}

pub fn monero_l2_pq_private_decoy_liquidity_routing_runtime_public_record(state: &State) -> Value {
    state.public_record()
}

pub fn decoy_route_id(request: &DecoyRouteCommitmentRequest) -> String {
    domain_hash(
        "DECOY-LIQUIDITY-ROUTING-ROUTE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.owner_commitment),
            HashPart::Str(request.route_kind.as_str()),
            HashPart::Str(&request.decoy_set_root),
            HashPart::Str(&request.encrypted_path_root),
            HashPart::Str(&request.route_nullifier),
            HashPart::U64(request.opened_height),
        ],
        32,
    )
}

pub fn liquidity_hint_id(request: &LiquidityHintRequest) -> String {
    domain_hash(
        "DECOY-LIQUIDITY-ROUTING-HINT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.route_id),
            HashPart::Str(&request.provider_id),
            HashPart::Str(&request.encrypted_hint_root),
            HashPart::Str(&request.reserve_hint_root),
            HashPart::U64(request.fee_quote_micro_units),
            HashPart::U64(request.hint_height),
        ],
        32,
    )
}

pub fn reserve_mirror_id(request: &ReserveMirrorRequest) -> String {
    domain_hash(
        "DECOY-LIQUIDITY-ROUTING-RESERVE-MIRROR-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.provider_id),
            HashPart::Str(&request.reserve_commitment),
            HashPart::Str(&request.covered_route_root),
            HashPart::U64(request.reserve_cover_bps),
            HashPart::Str(&request.pq_attestation_root),
            HashPart::U64(request.observed_height),
        ],
        32,
    )
}

pub fn relay_reservation_id(request: &RelayReservationRequest) -> String {
    domain_hash(
        "DECOY-LIQUIDITY-ROUTING-RELAY-RESERVATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.route_id),
            HashPart::Str(&request.provider_id),
            HashPart::Str(&request.mirror_id),
            HashPart::Str(&request.reservation_commitment),
            HashPart::U64(request.relay_fee_micro_units),
            HashPart::U64(request.reservation_height),
        ],
        32,
    )
}

pub fn route_lock_id(request: &RouteLockRequest) -> String {
    domain_hash(
        "DECOY-LIQUIDITY-ROUTING-LOCK-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.route_id),
            HashPart::Str(&request.reservation_id),
            HashPart::Str(&request.monero_anchor_root),
            HashPart::Str(&request.l2_state_root),
            HashPart::Str(&request.reorg_guard_root),
            HashPart::U64(request.locked_height),
        ],
        32,
    )
}

pub fn cover_receipt_id(request: &CoverReceiptRequest, rebate_micro_units: u64) -> String {
    domain_hash(
        "DECOY-LIQUIDITY-ROUTING-COVER-RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.route_id),
            HashPart::Str(&request.lock_id),
            HashPart::Str(&request.provider_id),
            HashPart::Str(&request.cover_commitment),
            HashPart::Str(&request.rebate_nullifier),
            HashPart::U64(request.fee_paid_micro_units),
            HashPart::U64(rebate_micro_units),
            HashPart::U64(request.settled_height),
        ],
        32,
    )
}

pub fn watcher_attestation_id(request: &WatcherAttestationRequest) -> String {
    domain_hash(
        "DECOY-LIQUIDITY-ROUTING-WATCHER-ATTESTATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.subject_id),
            HashPart::Str(&request.watcher_id),
            HashPart::Str(request.kind.as_str()),
            HashPart::Str(&request.attestation_root),
            HashPart::Str(&request.pq_signature_root),
            HashPart::U64(request.observed_height),
        ],
        32,
    )
}

pub fn privacy_record_id(request: &PrivacyAccountingRequest) -> String {
    domain_hash(
        "DECOY-LIQUIDITY-ROUTING-PRIVACY-RECORD-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.subject_id),
            HashPart::Str(&request.owner_commitment),
            HashPart::Str(&request.nullifier),
            HashPart::Str(&request.decoy_budget_root),
            HashPart::U64(request.privacy_set_size),
            HashPart::U64(request.height),
        ],
        32,
    )
}

pub fn slashing_evidence_id(request: &SlashingEvidenceRequest) -> String {
    domain_hash(
        "DECOY-LIQUIDITY-ROUTING-SLASHING-EVIDENCE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.subject_id),
            HashPart::Str(&request.offender_id),
            HashPart::Str(request.kind.as_str()),
            HashPart::Str(&request.evidence_root),
            HashPart::Str(&request.witness_root),
            HashPart::U64(request.bond_micro_units),
            HashPart::U64(request.height),
        ],
        32,
    )
}

pub fn route_priority_score(
    route_kind: DecoyRouteKind,
    privacy_set_size: u64,
    max_fee_micro_units: u64,
) -> u64 {
    route_kind
        .priority_weight()
        .saturating_add(privacy_set_size.min(1_048_576) / 1_024)
        .saturating_add(max_fee_micro_units.min(10_000_000) / 10_000)
}

pub fn payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub fn record_root(domain: &str, record: &Value) -> String {
    payload_root(domain, record)
}

pub fn public_record_root(domain: &str, records: &[Value]) -> String {
    merkle_root(domain, records)
}

pub fn state_root_from_record(record: &Value) -> String {
    payload_root("DECOY-LIQUIDITY-ROUTING-STATE-ROOT", record)
}

pub fn map_root<T: Serialize>(domain: &str, map: &BTreeMap<String, T>) -> String {
    let leaves = map
        .iter()
        .map(|(key, value)| {
            json!({
                "key": key,
                "value": serde_json::to_value(value).unwrap_or_else(|_| json!({"serialization": "failed"})),
            })
        })
        .collect::<Vec<_>>();
    public_record_root(domain, &leaves)
}

pub fn set_root(domain: &str, set: &BTreeSet<String>) -> String {
    let leaves = set
        .iter()
        .map(|value| json!({ "value": value }))
        .collect::<Vec<_>>();
    public_record_root(domain, &leaves)
}

pub fn ensure_nonempty(field: &str, value: &str) -> Result<()> {
    if value.is_empty() {
        Err(format!("{field} cannot be empty"))
    } else {
        Ok(())
    }
}

pub fn ensure_capacity(label: &str, current: usize, max: usize) -> Result<()> {
    if current >= max {
        Err(format!("{label} capacity exhausted"))
    } else {
        Ok(())
    }
}

pub fn ensure_absent<T>(label: &str, map: &BTreeMap<String, T>, key: &str) -> Result<()> {
    if map.contains_key(key) {
        Err(format!("{label} {key} already exists"))
    } else {
        Ok(())
    }
}

pub fn ensure_known<T>(label: &str, map: &BTreeMap<String, T>, key: &str) -> Result<()> {
    if map.contains_key(key) {
        Ok(())
    } else {
        Err(format!("unknown {label} {key}"))
    }
}
