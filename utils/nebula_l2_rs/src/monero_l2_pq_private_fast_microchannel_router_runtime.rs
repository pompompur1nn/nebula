use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqPrivateFastMicrochannelRouterRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_PRIVATE_FAST_MICROCHANNEL_ROUTER_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-private-fast-microchannel-router-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_PRIVATE_FAST_MICROCHANNEL_ROUTER_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const DEVNET_L2_NETWORK: &str = "nebula-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_ASSET_ID: &str = "wxmr-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEVNET_ROUTER_ID: &str = "devnet-monero-l2-pq-private-fast-microchannel-router";
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_ENDPOINT_ATTESTATION_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-private-endpoint-v1";
pub const SEALED_CHANNEL_SCHEME: &str = "ml-kem-sealed-monero-l2-private-microchannel-open-v1";
pub const LIQUIDITY_RESERVATION_SCHEME: &str = "private-fast-liquidity-path-reservation-root-v1";
pub const PRIVATE_CLAIM_SCHEME: &str = "htlc-like-private-claim-lock-root-v1";
pub const FEE_SPONSOR_SCHEME: &str = "low-fee-private-microchannel-route-sponsor-root-v1";
pub const MICROBATCH_SETTLEMENT_SCHEME: &str = "batched-private-microchannel-settlement-root-v1";
pub const FAST_RECEIPT_SCHEME: &str = "fast-private-route-receipt-root-v1";
pub const REORG_ANCHOR_SCHEME: &str = "monero-reorg-safe-microchannel-anchor-root-v1";
pub const NULLIFIER_FENCE_SCHEME: &str = "private-microchannel-nullifier-fence-root-v1";
pub const WATCHTOWER_CHALLENGE_SCHEME: &str =
    "private-watchtower-stale-settlement-challenge-root-v1";
pub const SLASHING_EVIDENCE_SCHEME: &str = "private-microchannel-misrouting-slashing-root-v1";
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 131_072;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_CHANNEL_TTL_BLOCKS: u64 = 64;
pub const DEFAULT_ENDPOINT_ATTESTATION_TTL_BLOCKS: u64 = 96;
pub const DEFAULT_RESERVATION_TTL_BLOCKS: u64 = 12;
pub const DEFAULT_CLAIM_TTL_BLOCKS: u64 = 18;
pub const DEFAULT_SETTLEMENT_DELAY_BLOCKS: u64 = 4;
pub const DEFAULT_RECEIPT_FINALITY_BLOCKS: u64 = 6;
pub const DEFAULT_REORG_ANCHOR_DEPTH: u64 = 12;
pub const DEFAULT_MIN_WATCHTOWER_QUORUM: u16 = 3;
pub const DEFAULT_MIN_QUORUM_WEIGHT: u64 = 5;
pub const DEFAULT_LOW_FEE_BPS: u64 = 3;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 18;
pub const DEFAULT_SPONSOR_COVER_BPS: u64 = 8_000;
pub const DEFAULT_MAX_SLASH_BPS: u64 = 5_000;
pub const DEFAULT_MAX_CHANNELS: usize = 2_097_152;
pub const DEFAULT_MAX_ENDPOINT_ATTESTATIONS: usize = 4_194_304;
pub const DEFAULT_MAX_RESERVATIONS: usize = 4_194_304;
pub const DEFAULT_MAX_PRIVATE_CLAIMS: usize = 4_194_304;
pub const DEFAULT_MAX_SPONSORSHIPS: usize = 2_097_152;
pub const DEFAULT_MAX_SETTLEMENTS: usize = 1_048_576;
pub const DEFAULT_MAX_RECEIPTS: usize = 4_194_304;
pub const DEFAULT_MAX_REORG_ANCHORS: usize = 2_097_152;
pub const DEFAULT_MAX_NULLIFIER_FENCES: usize = 8_388_608;
pub const DEFAULT_MAX_CHALLENGES: usize = 1_048_576;
pub const DEFAULT_MAX_SLASHES: usize = 1_048_576;
pub const DEFAULT_MAX_EVENTS: usize = 8_388_608;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ChannelKind {
    MerchantPayment,
    AtomicSwap,
    FastWithdrawal,
    LiquidityRebalance,
    FeeSponsoredRoute,
    EmergencyExit,
}
impl ChannelKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MerchantPayment => "merchant_payment",
            Self::AtomicSwap => "atomic_swap",
            Self::FastWithdrawal => "fast_withdrawal",
            Self::LiquidityRebalance => "liquidity_rebalance",
            Self::FeeSponsoredRoute => "fee_sponsored_route",
            Self::EmergencyExit => "emergency_exit",
        }
    }
    pub fn priority_weight(self) -> u64 {
        match self {
            Self::EmergencyExit => 1_000,
            Self::FastWithdrawal => 940,
            Self::AtomicSwap => 880,
            Self::FeeSponsoredRoute => 820,
            Self::LiquidityRebalance => 760,
            Self::MerchantPayment => 700,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ChannelStatus {
    Sealed,
    EndpointAttested,
    Reserved,
    ClaimLocked,
    Settling,
    Settled,
    Challenged,
    Slashed,
    Expired,
    Closed,
}
impl ChannelStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sealed => "sealed",
            Self::EndpointAttested => "endpoint_attested",
            Self::Reserved => "reserved",
            Self::ClaimLocked => "claim_locked",
            Self::Settling => "settling",
            Self::Settled => "settled",
            Self::Challenged => "challenged",
            Self::Slashed => "slashed",
            Self::Expired => "expired",
            Self::Closed => "closed",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EndpointRole {
    Sender,
    Receiver,
    Relay,
    Sponsor,
    Watchtower,
}
impl EndpointRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sender => "sender",
            Self::Receiver => "receiver",
            Self::Relay => "relay",
            Self::Sponsor => "sponsor",
            Self::Watchtower => "watchtower",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationStatus {
    Posted,
    Active,
    Superseded,
    Revoked,
    Expired,
    Slashed,
}
impl AttestationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Posted => "posted",
            Self::Active => "active",
            Self::Superseded => "superseded",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
            Self::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReservationStatus {
    Reserved,
    PartiallyFilled,
    Consumed,
    Released,
    Expired,
    Challenged,
    Slashed,
}
impl ReservationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::PartiallyFilled => "partially_filled",
            Self::Consumed => "consumed",
            Self::Released => "released",
            Self::Expired => "expired",
            Self::Challenged => "challenged",
            Self::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimStatus {
    Locked,
    Revealed,
    Settled,
    Refunded,
    Expired,
    Challenged,
    Slashed,
}
impl ClaimStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Locked => "locked",
            Self::Revealed => "revealed",
            Self::Settled => "settled",
            Self::Refunded => "refunded",
            Self::Expired => "expired",
            Self::Challenged => "challenged",
            Self::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorshipStatus {
    Pledged,
    Applied,
    Refunded,
    Exhausted,
    Challenged,
    Slashed,
}
impl SponsorshipStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pledged => "pledged",
            Self::Applied => "applied",
            Self::Refunded => "refunded",
            Self::Exhausted => "exhausted",
            Self::Challenged => "challenged",
            Self::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementStatus {
    Proposed,
    WatchtowerObserved,
    Anchored,
    Receipted,
    Finalized,
    StaleChallenged,
    Reorged,
    Slashed,
}
impl SettlementStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::WatchtowerObserved => "watchtower_observed",
            Self::Anchored => "anchored",
            Self::Receipted => "receipted",
            Self::Finalized => "finalized",
            Self::StaleChallenged => "stale_challenged",
            Self::Reorged => "reorged",
            Self::Slashed => "slashed",
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
    Revoked,
}
impl ReceiptStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Published => "published",
            Self::Finalized => "finalized",
            Self::Reorged => "reorged",
            Self::Challenged => "challenged",
            Self::Revoked => "revoked",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeKind {
    StaleSettlement,
    ReorgUnsafeAnchor,
    DuplicateNullifier,
    WithheldPreimage,
    InvalidEndpoint,
    LiquidityShortfall,
}
impl ChallengeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::StaleSettlement => "stale_settlement",
            Self::ReorgUnsafeAnchor => "reorg_unsafe_anchor",
            Self::DuplicateNullifier => "duplicate_nullifier",
            Self::WithheldPreimage => "withheld_preimage",
            Self::InvalidEndpoint => "invalid_endpoint",
            Self::LiquidityShortfall => "liquidity_shortfall",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SlashKind {
    Misrouting,
    DoubleReservation,
    FalseEndpointAttestation,
    StaleSettlement,
    FeeOvercharge,
    NullifierFenceBreach,
    WatchtowerFraud,
}
impl SlashKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Misrouting => "misrouting",
            Self::DoubleReservation => "double_reservation",
            Self::FalseEndpointAttestation => "false_endpoint_attestation",
            Self::StaleSettlement => "stale_settlement",
            Self::FeeOvercharge => "fee_overcharge",
            Self::NullifierFenceBreach => "nullifier_fence_breach",
            Self::WatchtowerFraud => "watchtower_fraud",
        }
    }
}

impl ChannelStatus {
    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Sealed
                | Self::EndpointAttested
                | Self::Reserved
                | Self::ClaimLocked
                | Self::Settling
        )
    }
}
impl ReservationStatus {
    pub fn live(self) -> bool {
        matches!(self, Self::Reserved | Self::PartiallyFilled)
    }
}
impl ChallengeKind {
    pub fn severity_score(self) -> u64 {
        match self {
            Self::DuplicateNullifier | Self::InvalidEndpoint => 10_000,
            Self::ReorgUnsafeAnchor => 8_000,
            Self::WithheldPreimage => 7_000,
            Self::LiquidityShortfall => 6_000,
            Self::StaleSettlement => 5_000,
        }
    }
}
impl SlashKind {
    pub fn severity_score(self) -> u64 {
        match self {
            Self::FalseEndpointAttestation | Self::NullifierFenceBreach | Self::WatchtowerFraud => {
                10_000
            }
            Self::Misrouting | Self::DoubleReservation => 8_500,
            Self::StaleSettlement => 6_500,
            Self::FeeOvercharge => 3_000,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub l2_network: String,
    pub monero_network: String,
    pub asset_id: String,
    pub fee_asset_id: String,
    pub router_id: String,
    pub hash_suite: String,
    pub pq_endpoint_attestation_suite: String,
    pub sealed_channel_scheme: String,
    pub liquidity_reservation_scheme: String,
    pub private_claim_scheme: String,
    pub fee_sponsor_scheme: String,
    pub microbatch_settlement_scheme: String,
    pub fast_receipt_scheme: String,
    pub reorg_anchor_scheme: String,
    pub nullifier_fence_scheme: String,
    pub watchtower_challenge_scheme: String,
    pub slashing_evidence_scheme: String,
    pub min_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub channel_ttl_blocks: u64,
    pub endpoint_attestation_ttl_blocks: u64,
    pub reservation_ttl_blocks: u64,
    pub claim_ttl_blocks: u64,
    pub settlement_delay_blocks: u64,
    pub receipt_finality_blocks: u64,
    pub reorg_anchor_depth: u64,
    pub min_watchtower_quorum: u16,
    pub min_quorum_weight: u64,
    pub low_fee_bps: u64,
    pub max_user_fee_bps: u64,
    pub sponsor_cover_bps: u64,
    pub max_slash_bps: u64,
    pub max_channels: usize,
    pub max_endpoint_attestations: usize,
    pub max_reservations: usize,
    pub max_private_claims: usize,
    pub max_sponsorships: usize,
    pub max_settlements: usize,
    pub max_receipts: usize,
    pub max_reorg_anchors: usize,
    pub max_nullifier_fences: usize,
    pub max_challenges: usize,
    pub max_slashes: usize,
    pub max_events: usize,
}
impl Config {
    pub fn public_record(&self) -> Value {
        serde_json::to_value(self)
            .unwrap_or_else(|_| json!({"serialization":"failed","kind":"Config"}))
    }
    pub fn record_root(&self) -> String {
        payload_root("CONFIG", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub next_channel: u64,
    pub next_attestation: u64,
    pub next_reservation: u64,
    pub next_claim: u64,
    pub next_sponsorship: u64,
    pub next_settlement: u64,
    pub next_receipt: u64,
    pub next_reorg_anchor: u64,
    pub next_nullifier_fence: u64,
    pub next_challenge: u64,
    pub next_slash: u64,
    pub next_event: u64,
}
impl Counters {
    pub fn public_record(&self) -> Value {
        serde_json::to_value(self)
            .unwrap_or_else(|_| json!({"serialization":"failed","kind":"Counters"}))
    }
    pub fn record_root(&self) -> String {
        payload_root("COUNTERS", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub counters_root: String,
    pub channel_root: String,
    pub endpoint_attestation_root: String,
    pub reservation_root: String,
    pub private_claim_root: String,
    pub sponsorship_root: String,
    pub settlement_root: String,
    pub receipt_root: String,
    pub reorg_anchor_root: String,
    pub nullifier_fence_root: String,
    pub challenge_root: String,
    pub slash_root: String,
    pub spent_nullifier_root: String,
    pub event_root: String,
}
impl Roots {
    pub fn public_record(&self) -> Value {
        serde_json::to_value(self)
            .unwrap_or_else(|_| json!({"serialization":"failed","kind":"Roots"}))
    }
    pub fn record_root(&self) -> String {
        payload_root("ROOTS", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SealedChannelOpenRequest {
    pub owner_commitment: String,
    pub counterparty_commitment: String,
    pub channel_kind: ChannelKind,
    pub sealed_open_root: String,
    pub encrypted_endpoint_root: String,
    pub initial_liquidity_commitment: String,
    pub route_policy_root: String,
    pub monero_anchor_root: String,
    pub open_nullifier: String,
    pub privacy_set_size: u64,
    pub max_fee_micro_units: u64,
    pub opened_height: u64,
}
impl SealedChannelOpenRequest {
    pub fn public_record(&self) -> Value {
        serde_json::to_value(self)
            .unwrap_or_else(|_| json!({"serialization":"failed","kind":"SealedChannelOpenRequest"}))
    }
    pub fn record_root(&self) -> String {
        payload_root("SEALEDCHANNELOPENREQUEST", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SealedChannel {
    pub channel_id: String,
    pub owner_commitment: String,
    pub counterparty_commitment: String,
    pub channel_kind: ChannelKind,
    pub status: ChannelStatus,
    pub sealed_open_root: String,
    pub encrypted_endpoint_root: String,
    pub initial_liquidity_commitment: String,
    pub route_policy_root: String,
    pub monero_anchor_root: String,
    pub open_nullifier: String,
    pub privacy_set_size: u64,
    pub max_fee_micro_units: u64,
    pub opened_height: u64,
    pub expires_height: u64,
    pub reserved_liquidity_micro_units: u64,
    pub settled_liquidity_micro_units: u64,
}
impl SealedChannel {
    pub fn public_record(&self) -> Value {
        serde_json::to_value(self)
            .unwrap_or_else(|_| json!({"serialization":"failed","kind":"SealedChannel"}))
    }
    pub fn record_root(&self) -> String {
        payload_root("SEALEDCHANNEL", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EndpointAttestationRequest {
    pub channel_id: String,
    pub endpoint_commitment: String,
    pub endpoint_role: EndpointRole,
    pub pq_key_commitment: String,
    pub pq_attestation_root: String,
    pub view_tag_root: String,
    pub attestation_nullifier: String,
    pub privacy_set_size: u64,
    pub attested_height: u64,
}
impl EndpointAttestationRequest {
    pub fn public_record(&self) -> Value {
        serde_json::to_value(self).unwrap_or_else(
            |_| json!({"serialization":"failed","kind":"EndpointAttestationRequest"}),
        )
    }
    pub fn record_root(&self) -> String {
        payload_root("ENDPOINTATTESTATIONREQUEST", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EndpointAttestation {
    pub attestation_id: String,
    pub channel_id: String,
    pub endpoint_commitment: String,
    pub endpoint_role: EndpointRole,
    pub status: AttestationStatus,
    pub pq_key_commitment: String,
    pub pq_attestation_root: String,
    pub view_tag_root: String,
    pub attestation_nullifier: String,
    pub privacy_set_size: u64,
    pub attested_height: u64,
    pub expires_height: u64,
}
impl EndpointAttestation {
    pub fn public_record(&self) -> Value {
        serde_json::to_value(self)
            .unwrap_or_else(|_| json!({"serialization":"failed","kind":"EndpointAttestation"}))
    }
    pub fn record_root(&self) -> String {
        payload_root("ENDPOINTATTESTATION", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiquidityPathReservationRequest {
    pub channel_id: String,
    pub attestation_id: String,
    pub router_commitment: String,
    pub path_commitment_root: String,
    pub liquidity_hint_root: String,
    pub amount_micro_units: u64,
    pub fee_quote_micro_units: u64,
    pub reservation_nullifier: String,
    pub privacy_set_size: u64,
    pub reserved_height: u64,
}
impl LiquidityPathReservationRequest {
    pub fn public_record(&self) -> Value {
        serde_json::to_value(self).unwrap_or_else(
            |_| json!({"serialization":"failed","kind":"LiquidityPathReservationRequest"}),
        )
    }
    pub fn record_root(&self) -> String {
        payload_root("LIQUIDITYPATHRESERVATIONREQUEST", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiquidityPathReservation {
    pub reservation_id: String,
    pub channel_id: String,
    pub attestation_id: String,
    pub router_commitment: String,
    pub status: ReservationStatus,
    pub path_commitment_root: String,
    pub liquidity_hint_root: String,
    pub amount_micro_units: u64,
    pub fee_quote_micro_units: u64,
    pub reservation_nullifier: String,
    pub privacy_set_size: u64,
    pub reserved_height: u64,
    pub expires_height: u64,
    pub filled_micro_units: u64,
}
impl LiquidityPathReservation {
    pub fn public_record(&self) -> Value {
        serde_json::to_value(self)
            .unwrap_or_else(|_| json!({"serialization":"failed","kind":"LiquidityPathReservation"}))
    }
    pub fn record_root(&self) -> String {
        payload_root("LIQUIDITYPATHRESERVATION", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivateClaimLockRequest {
    pub channel_id: String,
    pub reservation_id: String,
    pub claim_commitment: String,
    pub encrypted_preimage_root: String,
    pub timeout_commitment: String,
    pub claim_nullifier: String,
    pub amount_micro_units: u64,
    pub fee_micro_units: u64,
    pub privacy_set_size: u64,
    pub locked_height: u64,
}
impl PrivateClaimLockRequest {
    pub fn public_record(&self) -> Value {
        serde_json::to_value(self)
            .unwrap_or_else(|_| json!({"serialization":"failed","kind":"PrivateClaimLockRequest"}))
    }
    pub fn record_root(&self) -> String {
        payload_root("PRIVATECLAIMLOCKREQUEST", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivateClaimLock {
    pub claim_id: String,
    pub channel_id: String,
    pub reservation_id: String,
    pub status: ClaimStatus,
    pub claim_commitment: String,
    pub encrypted_preimage_root: String,
    pub timeout_commitment: String,
    pub claim_nullifier: String,
    pub amount_micro_units: u64,
    pub fee_micro_units: u64,
    pub privacy_set_size: u64,
    pub locked_height: u64,
    pub expires_height: u64,
}
impl PrivateClaimLock {
    pub fn public_record(&self) -> Value {
        serde_json::to_value(self)
            .unwrap_or_else(|_| json!({"serialization":"failed","kind":"PrivateClaimLock"}))
    }
    pub fn record_root(&self) -> String {
        payload_root("PRIVATECLAIMLOCK", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FeeSponsorshipRequest {
    pub channel_id: String,
    pub reservation_id: String,
    pub sponsor_commitment: String,
    pub sponsor_budget_root: String,
    pub sponsor_nullifier: String,
    pub covered_fee_micro_units: u64,
    pub rebate_commitment: String,
    pub privacy_set_size: u64,
    pub sponsored_height: u64,
}
impl FeeSponsorshipRequest {
    pub fn public_record(&self) -> Value {
        serde_json::to_value(self)
            .unwrap_or_else(|_| json!({"serialization":"failed","kind":"FeeSponsorshipRequest"}))
    }
    pub fn record_root(&self) -> String {
        payload_root("FEESPONSORSHIPREQUEST", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FeeSponsorship {
    pub sponsorship_id: String,
    pub channel_id: String,
    pub reservation_id: String,
    pub status: SponsorshipStatus,
    pub sponsor_commitment: String,
    pub sponsor_budget_root: String,
    pub sponsor_nullifier: String,
    pub covered_fee_micro_units: u64,
    pub rebate_commitment: String,
    pub privacy_set_size: u64,
    pub sponsored_height: u64,
}
impl FeeSponsorship {
    pub fn public_record(&self) -> Value {
        serde_json::to_value(self)
            .unwrap_or_else(|_| json!({"serialization":"failed","kind":"FeeSponsorship"}))
    }
    pub fn record_root(&self) -> String {
        payload_root("FEESPONSORSHIP", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MicrobatchSettlementRequest {
    pub batch_commitment: String,
    pub settlement_root: String,
    pub channel_root: String,
    pub claim_root: String,
    pub reservation_root: String,
    pub watchtower_quorum_root: String,
    pub monero_anchor_root: String,
    pub l2_state_root: String,
    pub settlement_nullifier: String,
    pub channel_ids: Vec<String>,
    pub claim_ids: Vec<String>,
    pub gross_amount_micro_units: u64,
    pub fee_paid_micro_units: u64,
    pub watchtower_weight: u64,
    pub settled_height: u64,
}
impl MicrobatchSettlementRequest {
    pub fn public_record(&self) -> Value {
        serde_json::to_value(self).unwrap_or_else(
            |_| json!({"serialization":"failed","kind":"MicrobatchSettlementRequest"}),
        )
    }
    pub fn record_root(&self) -> String {
        payload_root("MICROBATCHSETTLEMENTREQUEST", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MicrobatchSettlement {
    pub settlement_id: String,
    pub status: SettlementStatus,
    pub batch_commitment: String,
    pub settlement_root: String,
    pub channel_root: String,
    pub claim_root: String,
    pub reservation_root: String,
    pub watchtower_quorum_root: String,
    pub monero_anchor_root: String,
    pub l2_state_root: String,
    pub settlement_nullifier: String,
    pub channel_ids: Vec<String>,
    pub claim_ids: Vec<String>,
    pub gross_amount_micro_units: u64,
    pub fee_paid_micro_units: u64,
    pub watchtower_weight: u64,
    pub settled_height: u64,
    pub finalizable_height: u64,
}
impl MicrobatchSettlement {
    pub fn public_record(&self) -> Value {
        serde_json::to_value(self)
            .unwrap_or_else(|_| json!({"serialization":"failed","kind":"MicrobatchSettlement"}))
    }
    pub fn record_root(&self) -> String {
        payload_root("MICROBATCHSETTLEMENT", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FastReceiptRequest {
    pub settlement_id: String,
    pub channel_id: String,
    pub receipt_commitment: String,
    pub receipt_root: String,
    pub recipient_commitment: String,
    pub receipt_nullifier: String,
    pub amount_micro_units: u64,
    pub fee_micro_units: u64,
    pub published_height: u64,
}
impl FastReceiptRequest {
    pub fn public_record(&self) -> Value {
        serde_json::to_value(self)
            .unwrap_or_else(|_| json!({"serialization":"failed","kind":"FastReceiptRequest"}))
    }
    pub fn record_root(&self) -> String {
        payload_root("FASTRECEIPTREQUEST", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FastReceipt {
    pub receipt_id: String,
    pub settlement_id: String,
    pub channel_id: String,
    pub status: ReceiptStatus,
    pub receipt_commitment: String,
    pub receipt_root: String,
    pub recipient_commitment: String,
    pub receipt_nullifier: String,
    pub amount_micro_units: u64,
    pub fee_micro_units: u64,
    pub published_height: u64,
    pub finality_height: u64,
}
impl FastReceipt {
    pub fn public_record(&self) -> Value {
        serde_json::to_value(self)
            .unwrap_or_else(|_| json!({"serialization":"failed","kind":"FastReceipt"}))
    }
    pub fn record_root(&self) -> String {
        payload_root("FASTRECEIPT", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReorgAnchorRequest {
    pub subject_id: String,
    pub monero_height: u64,
    pub monero_block_hash: String,
    pub anchor_root: String,
    pub l2_state_root: String,
    pub watchtower_quorum_root: String,
    pub anchor_nullifier: String,
    pub anchored_height: u64,
}
impl ReorgAnchorRequest {
    pub fn public_record(&self) -> Value {
        serde_json::to_value(self)
            .unwrap_or_else(|_| json!({"serialization":"failed","kind":"ReorgAnchorRequest"}))
    }
    pub fn record_root(&self) -> String {
        payload_root("REORGANCHORREQUEST", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReorgAnchor {
    pub anchor_id: String,
    pub subject_id: String,
    pub monero_height: u64,
    pub monero_block_hash: String,
    pub anchor_root: String,
    pub l2_state_root: String,
    pub watchtower_quorum_root: String,
    pub anchor_nullifier: String,
    pub anchored_height: u64,
}
impl ReorgAnchor {
    pub fn public_record(&self) -> Value {
        serde_json::to_value(self)
            .unwrap_or_else(|_| json!({"serialization":"failed","kind":"ReorgAnchor"}))
    }
    pub fn record_root(&self) -> String {
        payload_root("REORGANCHOR", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NullifierFenceRequest {
    pub subject_id: String,
    pub owner_commitment: String,
    pub fence_root: String,
    pub nullifier: String,
    pub fence_height: u64,
}
impl NullifierFenceRequest {
    pub fn public_record(&self) -> Value {
        serde_json::to_value(self)
            .unwrap_or_else(|_| json!({"serialization":"failed","kind":"NullifierFenceRequest"}))
    }
    pub fn record_root(&self) -> String {
        payload_root("NULLIFIERFENCEREQUEST", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NullifierFence {
    pub fence_id: String,
    pub subject_id: String,
    pub owner_commitment: String,
    pub fence_root: String,
    pub nullifier: String,
    pub fence_height: u64,
}
impl NullifierFence {
    pub fn public_record(&self) -> Value {
        serde_json::to_value(self)
            .unwrap_or_else(|_| json!({"serialization":"failed","kind":"NullifierFence"}))
    }
    pub fn record_root(&self) -> String {
        payload_root("NULLIFIERFENCE", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WatchtowerChallengeRequest {
    pub subject_id: String,
    pub watchtower_id: String,
    pub challenge_kind: ChallengeKind,
    pub evidence_root: String,
    pub stale_state_root: String,
    pub fresh_state_root: String,
    pub challenge_nullifier: String,
    pub watchtower_weight: u64,
    pub challenged_height: u64,
}
impl WatchtowerChallengeRequest {
    pub fn public_record(&self) -> Value {
        serde_json::to_value(self).unwrap_or_else(
            |_| json!({"serialization":"failed","kind":"WatchtowerChallengeRequest"}),
        )
    }
    pub fn record_root(&self) -> String {
        payload_root("WATCHTOWERCHALLENGEREQUEST", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WatchtowerChallenge {
    pub challenge_id: String,
    pub subject_id: String,
    pub watchtower_id: String,
    pub challenge_kind: ChallengeKind,
    pub evidence_root: String,
    pub stale_state_root: String,
    pub fresh_state_root: String,
    pub challenge_nullifier: String,
    pub watchtower_weight: u64,
    pub challenged_height: u64,
    pub accepted: bool,
}
impl WatchtowerChallenge {
    pub fn public_record(&self) -> Value {
        serde_json::to_value(self)
            .unwrap_or_else(|_| json!({"serialization":"failed","kind":"WatchtowerChallenge"}))
    }
    pub fn record_root(&self) -> String {
        payload_root("WATCHTOWERCHALLENGE", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SlashingEvidenceRequest {
    pub subject_id: String,
    pub offender_id: String,
    pub slash_kind: SlashKind,
    pub evidence_root: String,
    pub witness_root: String,
    pub bond_micro_units: u64,
    pub slash_bps: u64,
    pub evidence_nullifier: String,
    pub height: u64,
}
impl SlashingEvidenceRequest {
    pub fn public_record(&self) -> Value {
        serde_json::to_value(self)
            .unwrap_or_else(|_| json!({"serialization":"failed","kind":"SlashingEvidenceRequest"}))
    }
    pub fn record_root(&self) -> String {
        payload_root("SLASHINGEVIDENCEREQUEST", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SlashingEvidence {
    pub slash_id: String,
    pub subject_id: String,
    pub offender_id: String,
    pub slash_kind: SlashKind,
    pub evidence_root: String,
    pub witness_root: String,
    pub bond_micro_units: u64,
    pub slash_bps: u64,
    pub evidence_nullifier: String,
    pub height: u64,
    pub slash_amount_micro_units: u64,
}
impl SlashingEvidence {
    pub fn public_record(&self) -> Value {
        serde_json::to_value(self)
            .unwrap_or_else(|_| json!({"serialization":"failed","kind":"SlashingEvidence"}))
    }
    pub fn record_root(&self) -> String {
        payload_root("SLASHINGEVIDENCE", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RuntimeEvent {
    pub event_id: String,
    pub event_kind: String,
    pub subject_id: String,
    pub payload_root: String,
    pub height: u64,
}
impl RuntimeEvent {
    pub fn public_record(&self) -> Value {
        serde_json::to_value(self)
            .unwrap_or_else(|_| json!({"serialization":"failed","kind":"RuntimeEvent"}))
    }
    pub fn record_root(&self) -> String {
        payload_root("RUNTIMEEVENT", &self.public_record())
    }
}

impl Config {
    pub fn devnet() -> Self {
        Self::default()
    }
    pub fn validate(&self) -> Result<()> {
        ensure_nonempty("chain_id", &self.chain_id)?;
        ensure_nonempty("protocol_version", &self.protocol_version)?;
        ensure_nonempty("router_id", &self.router_id)?;
        if self.protocol_version != PROTOCOL_VERSION {
            return Err("protocol_version mismatch".to_string());
        }
        if self.min_privacy_set_size < 65_536 {
            return Err("min_privacy_set_size below private Monero routing floor".to_string());
        }
        if self.min_pq_security_bits < 192 {
            return Err("min_pq_security_bits below runtime floor".to_string());
        }
        if self.low_fee_bps > self.max_user_fee_bps {
            return Err("low_fee_bps cannot exceed max_user_fee_bps".to_string());
        }
        if self.sponsor_cover_bps > MAX_BPS || self.max_slash_bps > MAX_BPS {
            return Err("bps config exceeds MAX_BPS".to_string());
        }
        Ok(())
    }
}
impl Default for Config {
    fn default() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            l2_network: DEVNET_L2_NETWORK.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            asset_id: DEVNET_ASSET_ID.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            router_id: DEVNET_ROUTER_ID.to_string(),
            hash_suite: HASH_SUITE.to_string(),
            pq_endpoint_attestation_suite: PQ_ENDPOINT_ATTESTATION_SUITE.to_string(),
            sealed_channel_scheme: SEALED_CHANNEL_SCHEME.to_string(),
            liquidity_reservation_scheme: LIQUIDITY_RESERVATION_SCHEME.to_string(),
            private_claim_scheme: PRIVATE_CLAIM_SCHEME.to_string(),
            fee_sponsor_scheme: FEE_SPONSOR_SCHEME.to_string(),
            microbatch_settlement_scheme: MICROBATCH_SETTLEMENT_SCHEME.to_string(),
            fast_receipt_scheme: FAST_RECEIPT_SCHEME.to_string(),
            reorg_anchor_scheme: REORG_ANCHOR_SCHEME.to_string(),
            nullifier_fence_scheme: NULLIFIER_FENCE_SCHEME.to_string(),
            watchtower_challenge_scheme: WATCHTOWER_CHALLENGE_SCHEME.to_string(),
            slashing_evidence_scheme: SLASHING_EVIDENCE_SCHEME.to_string(),
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            channel_ttl_blocks: DEFAULT_CHANNEL_TTL_BLOCKS,
            endpoint_attestation_ttl_blocks: DEFAULT_ENDPOINT_ATTESTATION_TTL_BLOCKS,
            reservation_ttl_blocks: DEFAULT_RESERVATION_TTL_BLOCKS,
            claim_ttl_blocks: DEFAULT_CLAIM_TTL_BLOCKS,
            settlement_delay_blocks: DEFAULT_SETTLEMENT_DELAY_BLOCKS,
            receipt_finality_blocks: DEFAULT_RECEIPT_FINALITY_BLOCKS,
            reorg_anchor_depth: DEFAULT_REORG_ANCHOR_DEPTH,
            min_watchtower_quorum: DEFAULT_MIN_WATCHTOWER_QUORUM,
            min_quorum_weight: DEFAULT_MIN_QUORUM_WEIGHT,
            low_fee_bps: DEFAULT_LOW_FEE_BPS,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            sponsor_cover_bps: DEFAULT_SPONSOR_COVER_BPS,
            max_slash_bps: DEFAULT_MAX_SLASH_BPS,
            max_channels: DEFAULT_MAX_CHANNELS,
            max_endpoint_attestations: DEFAULT_MAX_ENDPOINT_ATTESTATIONS,
            max_reservations: DEFAULT_MAX_RESERVATIONS,
            max_private_claims: DEFAULT_MAX_PRIVATE_CLAIMS,
            max_sponsorships: DEFAULT_MAX_SPONSORSHIPS,
            max_settlements: DEFAULT_MAX_SETTLEMENTS,
            max_receipts: DEFAULT_MAX_RECEIPTS,
            max_reorg_anchors: DEFAULT_MAX_REORG_ANCHORS,
            max_nullifier_fences: DEFAULT_MAX_NULLIFIER_FENCES,
            max_challenges: DEFAULT_MAX_CHALLENGES,
            max_slashes: DEFAULT_MAX_SLASHES,
            max_events: DEFAULT_MAX_EVENTS,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub channels: BTreeMap<String, SealedChannel>,
    pub endpoint_attestations: BTreeMap<String, EndpointAttestation>,
    pub reservations: BTreeMap<String, LiquidityPathReservation>,
    pub private_claims: BTreeMap<String, PrivateClaimLock>,
    pub sponsorships: BTreeMap<String, FeeSponsorship>,
    pub settlements: BTreeMap<String, MicrobatchSettlement>,
    pub receipts: BTreeMap<String, FastReceipt>,
    pub reorg_anchors: BTreeMap<String, ReorgAnchor>,
    pub nullifier_fences: BTreeMap<String, NullifierFence>,
    pub challenges: BTreeMap<String, WatchtowerChallenge>,
    pub slashes: BTreeMap<String, SlashingEvidence>,
    pub spent_nullifiers: BTreeSet<String>,
    pub events: BTreeMap<String, RuntimeEvent>,
}

impl State {
    pub fn devnet() -> Self {
        let mut state = Self {
            config: Config::devnet(),
            counters: Counters {
                next_channel: 1,
                next_attestation: 1,
                next_reservation: 1,
                next_claim: 1,
                next_sponsorship: 1,
                next_settlement: 1,
                next_receipt: 1,
                next_reorg_anchor: 1,
                next_nullifier_fence: 1,
                next_challenge: 1,
                next_slash: 1,
                next_event: 1,
            },
            roots: Roots::public_empty(),
            channels: BTreeMap::new(),
            endpoint_attestations: BTreeMap::new(),
            reservations: BTreeMap::new(),
            private_claims: BTreeMap::new(),
            sponsorships: BTreeMap::new(),
            settlements: BTreeMap::new(),
            receipts: BTreeMap::new(),
            reorg_anchors: BTreeMap::new(),
            nullifier_fences: BTreeMap::new(),
            challenges: BTreeMap::new(),
            slashes: BTreeMap::new(),
            spent_nullifiers: BTreeSet::new(),
            events: BTreeMap::new(),
        };
        state.recompute_roots();
        state
    }
    pub fn with_config(config: Config) -> Result<Self> {
        config.validate()?;
        let mut state = Self::devnet();
        state.config = config;
        state.recompute_roots();
        Ok(state)
    }
    pub fn recompute_roots(&mut self) {
        self.roots = self.compute_roots();
    }
    pub fn compute_roots(&self) -> Roots {
        Roots {
            config_root: payload_root("CONFIG", &self.config.public_record()),
            counters_root: payload_root("COUNTERS", &self.counters.public_record()),
            channel_root: map_root("CHANNELS", &self.channels),
            endpoint_attestation_root: map_root(
                "ENDPOINT-ATTESTATIONS",
                &self.endpoint_attestations,
            ),
            reservation_root: map_root("RESERVATIONS", &self.reservations),
            private_claim_root: map_root("PRIVATE-CLAIMS", &self.private_claims),
            sponsorship_root: map_root("SPONSORSHIPS", &self.sponsorships),
            settlement_root: map_root("SETTLEMENTS", &self.settlements),
            receipt_root: map_root("RECEIPTS", &self.receipts),
            reorg_anchor_root: map_root("REORG-ANCHORS", &self.reorg_anchors),
            nullifier_fence_root: map_root("NULLIFIER-FENCES", &self.nullifier_fences),
            challenge_root: map_root("CHALLENGES", &self.challenges),
            slash_root: map_root("SLASHES", &self.slashes),
            spent_nullifier_root: set_root("SPENT-NULLIFIERS", &self.spent_nullifiers),
            event_root: map_root("EVENTS", &self.events),
        }
    }
    fn push_event(
        &mut self,
        event_kind: &str,
        subject_id: &str,
        payload_root_value: &str,
        height: u64,
    ) -> Result<String> {
        ensure_capacity("events", self.events.len(), self.config.max_events)?;
        let event_id = sequence_id(
            "event",
            self.counters.next_event,
            &[subject_id, payload_root_value],
        );
        self.counters.next_event = self.counters.next_event.saturating_add(1);
        self.events.insert(
            event_id.clone(),
            RuntimeEvent {
                event_id: event_id.clone(),
                event_kind: event_kind.to_string(),
                subject_id: subject_id.to_string(),
                payload_root: payload_root_value.to_string(),
                height,
            },
        );
        Ok(event_id)
    }
    pub fn open_sealed_channel(
        &mut self,
        request: SealedChannelOpenRequest,
    ) -> Result<SealedChannel> {
        self.config.validate()?;
        ensure_capacity("channels", self.channels.len(), self.config.max_channels)?;
        ensure_nonempty("sealed_open_root", &request.sealed_open_root)?;
        ensure_min(
            "privacy_set_size",
            request.privacy_set_size,
            self.config.min_privacy_set_size,
        )?;
        ensure_fresh_nullifier(&self.spent_nullifiers, &request.open_nullifier)?;
        let channel_id = sealed_channel_id(&request);
        ensure_absent("channel", &self.channels, &channel_id)?;
        let channel = SealedChannel {
            channel_id: channel_id.clone(),
            owner_commitment: request.owner_commitment,
            counterparty_commitment: request.counterparty_commitment,
            channel_kind: request.channel_kind,
            status: ChannelStatus::Sealed,
            sealed_open_root: request.sealed_open_root,
            encrypted_endpoint_root: request.encrypted_endpoint_root,
            initial_liquidity_commitment: request.initial_liquidity_commitment,
            route_policy_root: request.route_policy_root,
            monero_anchor_root: request.monero_anchor_root,
            open_nullifier: request.open_nullifier.clone(),
            privacy_set_size: request.privacy_set_size,
            max_fee_micro_units: request.max_fee_micro_units,
            opened_height: request.opened_height,
            expires_height: request
                .opened_height
                .saturating_add(self.config.channel_ttl_blocks),
            reserved_liquidity_micro_units: 0,
            settled_liquidity_micro_units: 0,
        };
        self.spent_nullifiers.insert(request.open_nullifier);
        self.counters.next_channel = self.counters.next_channel.saturating_add(1);
        self.push_event(
            "sealed_channel_opened",
            &channel_id,
            &channel.record_root(),
            channel.opened_height,
        )?;
        self.channels.insert(channel_id, channel.clone());
        self.recompute_roots();
        Ok(channel)
    }
    pub fn attest_endpoint(
        &mut self,
        request: EndpointAttestationRequest,
    ) -> Result<EndpointAttestation> {
        ensure_capacity(
            "endpoint_attestations",
            self.endpoint_attestations.len(),
            self.config.max_endpoint_attestations,
        )?;
        ensure_known("channel", &self.channels, &request.channel_id)?;
        ensure_min(
            "privacy_set_size",
            request.privacy_set_size,
            self.config.min_privacy_set_size,
        )?;
        ensure_fresh_nullifier(&self.spent_nullifiers, &request.attestation_nullifier)?;
        let attestation_id = endpoint_attestation_id(&request);
        ensure_absent(
            "endpoint_attestation",
            &self.endpoint_attestations,
            &attestation_id,
        )?;
        let attestation = EndpointAttestation {
            attestation_id: attestation_id.clone(),
            channel_id: request.channel_id.clone(),
            endpoint_commitment: request.endpoint_commitment,
            endpoint_role: request.endpoint_role,
            status: AttestationStatus::Active,
            pq_key_commitment: request.pq_key_commitment,
            pq_attestation_root: request.pq_attestation_root,
            view_tag_root: request.view_tag_root,
            attestation_nullifier: request.attestation_nullifier.clone(),
            privacy_set_size: request.privacy_set_size,
            attested_height: request.attested_height,
            expires_height: request
                .attested_height
                .saturating_add(self.config.endpoint_attestation_ttl_blocks),
        };
        if let Some(channel) = self.channels.get_mut(&request.channel_id) {
            if channel.status == ChannelStatus::Sealed {
                channel.status = ChannelStatus::EndpointAttested;
            }
        }
        self.spent_nullifiers.insert(request.attestation_nullifier);
        self.counters.next_attestation = self.counters.next_attestation.saturating_add(1);
        self.push_event(
            "endpoint_attested",
            &attestation_id,
            &attestation.record_root(),
            attestation.attested_height,
        )?;
        self.endpoint_attestations
            .insert(attestation_id, attestation.clone());
        self.recompute_roots();
        Ok(attestation)
    }
    pub fn reserve_route(
        &mut self,
        request: LiquidityPathReservationRequest,
    ) -> Result<LiquidityPathReservation> {
        ensure_capacity(
            "reservations",
            self.reservations.len(),
            self.config.max_reservations,
        )?;
        ensure_known("channel", &self.channels, &request.channel_id)?;
        ensure_known(
            "endpoint_attestation",
            &self.endpoint_attestations,
            &request.attestation_id,
        )?;
        ensure_min(
            "privacy_set_size",
            request.privacy_set_size,
            self.config.min_privacy_set_size,
        )?;
        ensure_fresh_nullifier(&self.spent_nullifiers, &request.reservation_nullifier)?;
        if request.amount_micro_units == 0 {
            return Err("amount_micro_units cannot be zero".to_string());
        }
        if request.fee_quote_micro_units > request.amount_micro_units {
            return Err("fee quote cannot exceed amount".to_string());
        }
        let reservation_id = liquidity_path_reservation_id(&request);
        ensure_absent("reservation", &self.reservations, &reservation_id)?;
        let reservation = LiquidityPathReservation {
            reservation_id: reservation_id.clone(),
            channel_id: request.channel_id.clone(),
            attestation_id: request.attestation_id,
            router_commitment: request.router_commitment,
            status: ReservationStatus::Reserved,
            path_commitment_root: request.path_commitment_root,
            liquidity_hint_root: request.liquidity_hint_root,
            amount_micro_units: request.amount_micro_units,
            fee_quote_micro_units: request.fee_quote_micro_units,
            reservation_nullifier: request.reservation_nullifier.clone(),
            privacy_set_size: request.privacy_set_size,
            reserved_height: request.reserved_height,
            expires_height: request
                .reserved_height
                .saturating_add(self.config.reservation_ttl_blocks),
            filled_micro_units: 0,
        };
        if let Some(channel) = self.channels.get_mut(&request.channel_id) {
            if !channel.status.live() {
                return Err("channel is not live".to_string());
            }
            channel.status = ChannelStatus::Reserved;
            channel.reserved_liquidity_micro_units = channel
                .reserved_liquidity_micro_units
                .saturating_add(request.amount_micro_units);
        }
        self.spent_nullifiers.insert(request.reservation_nullifier);
        self.counters.next_reservation = self.counters.next_reservation.saturating_add(1);
        self.push_event(
            "route_reserved",
            &reservation_id,
            &reservation.record_root(),
            reservation.reserved_height,
        )?;
        self.reservations
            .insert(reservation_id, reservation.clone());
        self.recompute_roots();
        Ok(reservation)
    }
    pub fn lock_private_claim(
        &mut self,
        request: PrivateClaimLockRequest,
    ) -> Result<PrivateClaimLock> {
        ensure_capacity(
            "private_claims",
            self.private_claims.len(),
            self.config.max_private_claims,
        )?;
        ensure_known("channel", &self.channels, &request.channel_id)?;
        ensure_known("reservation", &self.reservations, &request.reservation_id)?;
        ensure_min(
            "privacy_set_size",
            request.privacy_set_size,
            self.config.min_privacy_set_size,
        )?;
        ensure_fresh_nullifier(&self.spent_nullifiers, &request.claim_nullifier)?;
        if request.amount_micro_units == 0 {
            return Err("claim amount cannot be zero".to_string());
        }
        let reservation = self
            .reservations
            .get(&request.reservation_id)
            .ok_or_else(|| "reservation missing".to_string())?;
        if !reservation.status.live() {
            return Err("reservation is not live".to_string());
        }
        if request.amount_micro_units
            > reservation
                .amount_micro_units
                .saturating_sub(reservation.filled_micro_units)
        {
            return Err("claim exceeds remaining reservation".to_string());
        }
        let claim_id = private_claim_lock_id(&request);
        ensure_absent("private_claim", &self.private_claims, &claim_id)?;
        let claim = PrivateClaimLock {
            claim_id: claim_id.clone(),
            channel_id: request.channel_id.clone(),
            reservation_id: request.reservation_id.clone(),
            status: ClaimStatus::Locked,
            claim_commitment: request.claim_commitment,
            encrypted_preimage_root: request.encrypted_preimage_root,
            timeout_commitment: request.timeout_commitment,
            claim_nullifier: request.claim_nullifier.clone(),
            amount_micro_units: request.amount_micro_units,
            fee_micro_units: request.fee_micro_units,
            privacy_set_size: request.privacy_set_size,
            locked_height: request.locked_height,
            expires_height: request
                .locked_height
                .saturating_add(self.config.claim_ttl_blocks),
        };
        if let Some(r) = self.reservations.get_mut(&request.reservation_id) {
            r.filled_micro_units = r
                .filled_micro_units
                .saturating_add(request.amount_micro_units);
            r.status = if r.filled_micro_units >= r.amount_micro_units {
                ReservationStatus::Consumed
            } else {
                ReservationStatus::PartiallyFilled
            };
        }
        if let Some(channel) = self.channels.get_mut(&request.channel_id) {
            channel.status = ChannelStatus::ClaimLocked;
        }
        self.spent_nullifiers.insert(request.claim_nullifier);
        self.counters.next_claim = self.counters.next_claim.saturating_add(1);
        self.push_event(
            "private_claim_locked",
            &claim_id,
            &claim.record_root(),
            claim.locked_height,
        )?;
        self.private_claims.insert(claim_id, claim.clone());
        self.recompute_roots();
        Ok(claim)
    }
    pub fn sponsor_route(&mut self, request: FeeSponsorshipRequest) -> Result<FeeSponsorship> {
        ensure_capacity(
            "sponsorships",
            self.sponsorships.len(),
            self.config.max_sponsorships,
        )?;
        ensure_known("channel", &self.channels, &request.channel_id)?;
        ensure_known("reservation", &self.reservations, &request.reservation_id)?;
        ensure_min(
            "privacy_set_size",
            request.privacy_set_size,
            self.config.min_privacy_set_size,
        )?;
        ensure_fresh_nullifier(&self.spent_nullifiers, &request.sponsor_nullifier)?;
        if request.covered_fee_micro_units == 0 {
            return Err("covered_fee_micro_units cannot be zero".to_string());
        }
        let sponsorship_id = fee_sponsorship_id(&request);
        ensure_absent("sponsorship", &self.sponsorships, &sponsorship_id)?;
        let sponsorship = FeeSponsorship {
            sponsorship_id: sponsorship_id.clone(),
            channel_id: request.channel_id,
            reservation_id: request.reservation_id,
            status: SponsorshipStatus::Pledged,
            sponsor_commitment: request.sponsor_commitment,
            sponsor_budget_root: request.sponsor_budget_root,
            sponsor_nullifier: request.sponsor_nullifier.clone(),
            covered_fee_micro_units: request.covered_fee_micro_units,
            rebate_commitment: request.rebate_commitment,
            privacy_set_size: request.privacy_set_size,
            sponsored_height: request.sponsored_height,
        };
        self.spent_nullifiers.insert(request.sponsor_nullifier);
        self.counters.next_sponsorship = self.counters.next_sponsorship.saturating_add(1);
        self.push_event(
            "route_sponsored",
            &sponsorship_id,
            &sponsorship.record_root(),
            sponsorship.sponsored_height,
        )?;
        self.sponsorships
            .insert(sponsorship_id, sponsorship.clone());
        self.recompute_roots();
        Ok(sponsorship)
    }
    pub fn settle_microbatch(
        &mut self,
        request: MicrobatchSettlementRequest,
    ) -> Result<MicrobatchSettlement> {
        ensure_capacity(
            "settlements",
            self.settlements.len(),
            self.config.max_settlements,
        )?;
        ensure_fresh_nullifier(&self.spent_nullifiers, &request.settlement_nullifier)?;
        if request.channel_ids.is_empty() || request.claim_ids.is_empty() {
            return Err("microbatch requires channels and claims".to_string());
        }
        if request.watchtower_weight < self.config.min_quorum_weight {
            return Err("watchtower weight below quorum".to_string());
        }
        for channel_id in &request.channel_ids {
            ensure_known("channel", &self.channels, channel_id)?;
        }
        for claim_id in &request.claim_ids {
            ensure_known("private_claim", &self.private_claims, claim_id)?;
        }
        let settlement_id = microbatch_settlement_id(&request);
        ensure_absent("settlement", &self.settlements, &settlement_id)?;
        let settlement = MicrobatchSettlement {
            settlement_id: settlement_id.clone(),
            status: SettlementStatus::Proposed,
            batch_commitment: request.batch_commitment,
            settlement_root: request.settlement_root,
            channel_root: request.channel_root,
            claim_root: request.claim_root,
            reservation_root: request.reservation_root,
            watchtower_quorum_root: request.watchtower_quorum_root,
            monero_anchor_root: request.monero_anchor_root,
            l2_state_root: request.l2_state_root,
            settlement_nullifier: request.settlement_nullifier.clone(),
            channel_ids: request.channel_ids,
            claim_ids: request.claim_ids,
            gross_amount_micro_units: request.gross_amount_micro_units,
            fee_paid_micro_units: request.fee_paid_micro_units,
            watchtower_weight: request.watchtower_weight,
            settled_height: request.settled_height,
            finalizable_height: request
                .settled_height
                .saturating_add(self.config.settlement_delay_blocks),
        };
        for channel_id in &settlement.channel_ids {
            if let Some(channel) = self.channels.get_mut(channel_id) {
                channel.status = ChannelStatus::Settling;
                channel.settled_liquidity_micro_units =
                    channel.settled_liquidity_micro_units.saturating_add(
                        settlement.gross_amount_micro_units
                            / settlement.channel_ids.len().max(1) as u64,
                    );
            }
        }
        for claim_id in &settlement.claim_ids {
            if let Some(claim) = self.private_claims.get_mut(claim_id) {
                claim.status = ClaimStatus::Settled;
            }
        }
        self.spent_nullifiers.insert(request.settlement_nullifier);
        self.counters.next_settlement = self.counters.next_settlement.saturating_add(1);
        self.push_event(
            "microbatch_settlement_proposed",
            &settlement_id,
            &settlement.record_root(),
            settlement.settled_height,
        )?;
        self.settlements.insert(settlement_id, settlement.clone());
        self.recompute_roots();
        Ok(settlement)
    }
    pub fn publish_fast_receipt(&mut self, request: FastReceiptRequest) -> Result<FastReceipt> {
        ensure_capacity("receipts", self.receipts.len(), self.config.max_receipts)?;
        ensure_known("settlement", &self.settlements, &request.settlement_id)?;
        ensure_known("channel", &self.channels, &request.channel_id)?;
        ensure_fresh_nullifier(&self.spent_nullifiers, &request.receipt_nullifier)?;
        let receipt_id = fast_receipt_id(&request);
        ensure_absent("receipt", &self.receipts, &receipt_id)?;
        let receipt = FastReceipt {
            receipt_id: receipt_id.clone(),
            settlement_id: request.settlement_id.clone(),
            channel_id: request.channel_id.clone(),
            status: ReceiptStatus::Published,
            receipt_commitment: request.receipt_commitment,
            receipt_root: request.receipt_root,
            recipient_commitment: request.recipient_commitment,
            receipt_nullifier: request.receipt_nullifier.clone(),
            amount_micro_units: request.amount_micro_units,
            fee_micro_units: request.fee_micro_units,
            published_height: request.published_height,
            finality_height: request
                .published_height
                .saturating_add(self.config.receipt_finality_blocks),
        };
        if let Some(settlement) = self.settlements.get_mut(&request.settlement_id) {
            settlement.status = SettlementStatus::Receipted;
        }
        if let Some(channel) = self.channels.get_mut(&request.channel_id) {
            channel.status = ChannelStatus::Settled;
        }
        self.spent_nullifiers.insert(request.receipt_nullifier);
        self.counters.next_receipt = self.counters.next_receipt.saturating_add(1);
        self.push_event(
            "fast_receipt_published",
            &receipt_id,
            &receipt.record_root(),
            receipt.published_height,
        )?;
        self.receipts.insert(receipt_id, receipt.clone());
        self.recompute_roots();
        Ok(receipt)
    }
    pub fn anchor_reorg_guard(&mut self, request: ReorgAnchorRequest) -> Result<ReorgAnchor> {
        ensure_capacity(
            "reorg_anchors",
            self.reorg_anchors.len(),
            self.config.max_reorg_anchors,
        )?;
        ensure_fresh_nullifier(&self.spent_nullifiers, &request.anchor_nullifier)?;
        if request.anchored_height
            < request
                .monero_height
                .saturating_add(self.config.reorg_anchor_depth)
        {
            return Err("anchor height below configured reorg depth".to_string());
        }
        let anchor_id = reorg_anchor_id(&request);
        ensure_absent("reorg_anchor", &self.reorg_anchors, &anchor_id)?;
        let anchor = ReorgAnchor {
            anchor_id: anchor_id.clone(),
            subject_id: request.subject_id,
            monero_height: request.monero_height,
            monero_block_hash: request.monero_block_hash,
            anchor_root: request.anchor_root,
            l2_state_root: request.l2_state_root,
            watchtower_quorum_root: request.watchtower_quorum_root,
            anchor_nullifier: request.anchor_nullifier.clone(),
            anchored_height: request.anchored_height,
        };
        self.spent_nullifiers.insert(request.anchor_nullifier);
        self.counters.next_reorg_anchor = self.counters.next_reorg_anchor.saturating_add(1);
        self.push_event(
            "reorg_anchor_published",
            &anchor_id,
            &anchor.record_root(),
            anchor.anchored_height,
        )?;
        self.reorg_anchors.insert(anchor_id, anchor.clone());
        self.recompute_roots();
        Ok(anchor)
    }
    pub fn fence_nullifier(&mut self, request: NullifierFenceRequest) -> Result<NullifierFence> {
        ensure_capacity(
            "nullifier_fences",
            self.nullifier_fences.len(),
            self.config.max_nullifier_fences,
        )?;
        ensure_fresh_nullifier(&self.spent_nullifiers, &request.nullifier)?;
        let fence_id = nullifier_fence_id(&request);
        ensure_absent("nullifier_fence", &self.nullifier_fences, &fence_id)?;
        let fence = NullifierFence {
            fence_id: fence_id.clone(),
            subject_id: request.subject_id,
            owner_commitment: request.owner_commitment,
            fence_root: request.fence_root,
            nullifier: request.nullifier.clone(),
            fence_height: request.fence_height,
        };
        self.spent_nullifiers.insert(request.nullifier);
        self.counters.next_nullifier_fence = self.counters.next_nullifier_fence.saturating_add(1);
        self.push_event(
            "nullifier_fenced",
            &fence_id,
            &fence.record_root(),
            fence.fence_height,
        )?;
        self.nullifier_fences.insert(fence_id, fence.clone());
        self.recompute_roots();
        Ok(fence)
    }
    pub fn challenge_stale_settlement(
        &mut self,
        request: WatchtowerChallengeRequest,
    ) -> Result<WatchtowerChallenge> {
        ensure_capacity(
            "challenges",
            self.challenges.len(),
            self.config.max_challenges,
        )?;
        ensure_fresh_nullifier(&self.spent_nullifiers, &request.challenge_nullifier)?;
        if request.watchtower_weight < self.config.min_quorum_weight {
            return Err("challenge watchtower weight below quorum".to_string());
        }
        let challenge_id = watchtower_challenge_id(&request);
        ensure_absent("challenge", &self.challenges, &challenge_id)?;
        let accepted = request.challenge_kind.severity_score() >= 5_000;
        let challenge = WatchtowerChallenge {
            challenge_id: challenge_id.clone(),
            subject_id: request.subject_id.clone(),
            watchtower_id: request.watchtower_id,
            challenge_kind: request.challenge_kind,
            evidence_root: request.evidence_root,
            stale_state_root: request.stale_state_root,
            fresh_state_root: request.fresh_state_root,
            challenge_nullifier: request.challenge_nullifier.clone(),
            watchtower_weight: request.watchtower_weight,
            challenged_height: request.challenged_height,
            accepted,
        };
        if let Some(settlement) = self.settlements.get_mut(&request.subject_id) {
            settlement.status = SettlementStatus::StaleChallenged;
        }
        if let Some(channel) = self.channels.get_mut(&request.subject_id) {
            channel.status = ChannelStatus::Challenged;
        }
        self.spent_nullifiers.insert(request.challenge_nullifier);
        self.counters.next_challenge = self.counters.next_challenge.saturating_add(1);
        self.push_event(
            "watchtower_challenge",
            &challenge_id,
            &challenge.record_root(),
            challenge.challenged_height,
        )?;
        self.challenges.insert(challenge_id, challenge.clone());
        self.recompute_roots();
        Ok(challenge)
    }
    pub fn slash_misrouting(
        &mut self,
        request: SlashingEvidenceRequest,
    ) -> Result<SlashingEvidence> {
        ensure_capacity("slashes", self.slashes.len(), self.config.max_slashes)?;
        ensure_fresh_nullifier(&self.spent_nullifiers, &request.evidence_nullifier)?;
        if request.slash_bps > self.config.max_slash_bps {
            return Err("slash_bps exceeds configured maximum".to_string());
        }
        let slash_id = slashing_evidence_id(&request);
        ensure_absent("slash", &self.slashes, &slash_id)?;
        let severity_bps = request.slash_kind.severity_score().min(MAX_BPS);
        let slash_amount_micro_units = request
            .bond_micro_units
            .saturating_mul(request.slash_bps.min(severity_bps))
            / MAX_BPS;
        let slash = SlashingEvidence {
            slash_id: slash_id.clone(),
            subject_id: request.subject_id.clone(),
            offender_id: request.offender_id,
            slash_kind: request.slash_kind,
            evidence_root: request.evidence_root,
            witness_root: request.witness_root,
            bond_micro_units: request.bond_micro_units,
            slash_bps: request.slash_bps,
            evidence_nullifier: request.evidence_nullifier.clone(),
            height: request.height,
            slash_amount_micro_units,
        };
        if let Some(channel) = self.channels.get_mut(&request.subject_id) {
            channel.status = ChannelStatus::Slashed;
        }
        if let Some(reservation) = self.reservations.get_mut(&request.subject_id) {
            reservation.status = ReservationStatus::Slashed;
        }
        if let Some(settlement) = self.settlements.get_mut(&request.subject_id) {
            settlement.status = SettlementStatus::Slashed;
        }
        self.spent_nullifiers.insert(request.evidence_nullifier);
        self.counters.next_slash = self.counters.next_slash.saturating_add(1);
        self.push_event(
            "misrouting_slashed",
            &slash_id,
            &slash.record_root(),
            slash.height,
        )?;
        self.slashes.insert(slash_id, slash.clone());
        self.recompute_roots();
        Ok(slash)
    }
    pub fn finalize_receipt(&mut self, receipt_id: &str, height: u64) -> Result<()> {
        let receipt = self
            .receipts
            .get_mut(receipt_id)
            .ok_or_else(|| format!("unknown receipt {receipt_id}"))?;
        if height < receipt.finality_height {
            return Err("receipt finality height not reached".to_string());
        }
        receipt.status = ReceiptStatus::Finalized;
        if let Some(settlement) = self.settlements.get_mut(&receipt.settlement_id) {
            settlement.status = SettlementStatus::Finalized;
        }
        self.recompute_roots();
        Ok(())
    }
    pub fn expire_height(&mut self, height: u64) -> usize {
        let mut changed = 0usize;
        for channel in self.channels.values_mut() {
            if channel.status.live() && height >= channel.expires_height {
                channel.status = ChannelStatus::Expired;
                changed = changed.saturating_add(1);
            }
        }
        for attestation in self.endpoint_attestations.values_mut() {
            if matches!(
                attestation.status,
                AttestationStatus::Active | AttestationStatus::Posted
            ) && height >= attestation.expires_height
            {
                attestation.status = AttestationStatus::Expired;
                changed = changed.saturating_add(1);
            }
        }
        for reservation in self.reservations.values_mut() {
            if reservation.status.live() && height >= reservation.expires_height {
                reservation.status = ReservationStatus::Expired;
                changed = changed.saturating_add(1);
            }
        }
        for claim in self.private_claims.values_mut() {
            if claim.status == ClaimStatus::Locked && height >= claim.expires_height {
                claim.status = ClaimStatus::Expired;
                changed = changed.saturating_add(1);
            }
        }
        if changed > 0 {
            self.recompute_roots();
        }
        changed
    }
    pub fn public_record_without_state_root(&self) -> Value {
        json!({"kind":"monero_l2_pq_private_fast_microchannel_router_state","chain_id":CHAIN_ID,"protocol_version":PROTOCOL_VERSION,"schema_version":SCHEMA_VERSION,"config":self.config.public_record(),"counters":self.counters.public_record(),"roots":self.roots.public_record(),"counts":{"channels":self.channels.len(),"endpoint_attestations":self.endpoint_attestations.len(),"reservations":self.reservations.len(),"private_claims":self.private_claims.len(),"sponsorships":self.sponsorships.len(),"settlements":self.settlements.len(),"receipts":self.receipts.len(),"reorg_anchors":self.reorg_anchors.len(),"nullifier_fences":self.nullifier_fences.len(),"challenges":self.challenges.len(),"slashes":self.slashes.len(),"spent_nullifiers":self.spent_nullifiers.len(),"events":self.events.len()}})
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
impl Default for State {
    fn default() -> Self {
        Self::devnet()
    }
}

impl Roots {
    pub fn public_empty() -> Self {
        Self {
            config_root: String::new(),
            counters_root: String::new(),
            channel_root: String::new(),
            endpoint_attestation_root: String::new(),
            reservation_root: String::new(),
            private_claim_root: String::new(),
            sponsorship_root: String::new(),
            settlement_root: String::new(),
            receipt_root: String::new(),
            reorg_anchor_root: String::new(),
            nullifier_fence_root: String::new(),
            challenge_root: String::new(),
            slash_root: String::new(),
            spent_nullifier_root: String::new(),
            event_root: String::new(),
        }
    }
}
pub fn devnet() -> State {
    State::devnet()
}
pub fn monero_l2_pq_private_fast_microchannel_router_runtime_state_root(state: &State) -> String {
    state.state_root()
}
pub fn monero_l2_pq_private_fast_microchannel_router_runtime_public_record(state: &State) -> Value {
    state.public_record()
}
pub fn sealed_channel_id(request: &SealedChannelOpenRequest) -> String {
    domain_hash(
        "FAST-MICROCHANNEL-SEALED-CHANNEL-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.owner_commitment),
            HashPart::Str(&request.counterparty_commitment),
            HashPart::Str(request.channel_kind.as_str()),
            HashPart::Str(&request.sealed_open_root),
            HashPart::Str(&request.open_nullifier),
            HashPart::U64(request.opened_height),
        ],
        32,
    )
}
pub fn endpoint_attestation_id(request: &EndpointAttestationRequest) -> String {
    domain_hash(
        "FAST-MICROCHANNEL-ENDPOINT-ATTESTATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.channel_id),
            HashPart::Str(&request.endpoint_commitment),
            HashPart::Str(request.endpoint_role.as_str()),
            HashPart::Str(&request.pq_attestation_root),
            HashPart::Str(&request.attestation_nullifier),
            HashPart::U64(request.attested_height),
        ],
        32,
    )
}
pub fn liquidity_path_reservation_id(request: &LiquidityPathReservationRequest) -> String {
    domain_hash(
        "FAST-MICROCHANNEL-LIQUIDITY-RESERVATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.channel_id),
            HashPart::Str(&request.attestation_id),
            HashPart::Str(&request.router_commitment),
            HashPart::Str(&request.path_commitment_root),
            HashPart::Str(&request.reservation_nullifier),
            HashPart::U64(request.amount_micro_units),
            HashPart::U64(request.reserved_height),
        ],
        32,
    )
}
pub fn private_claim_lock_id(request: &PrivateClaimLockRequest) -> String {
    domain_hash(
        "FAST-MICROCHANNEL-PRIVATE-CLAIM-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.channel_id),
            HashPart::Str(&request.reservation_id),
            HashPart::Str(&request.claim_commitment),
            HashPart::Str(&request.encrypted_preimage_root),
            HashPart::Str(&request.claim_nullifier),
            HashPart::U64(request.amount_micro_units),
            HashPart::U64(request.locked_height),
        ],
        32,
    )
}
pub fn fee_sponsorship_id(request: &FeeSponsorshipRequest) -> String {
    domain_hash(
        "FAST-MICROCHANNEL-FEE-SPONSORSHIP-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.channel_id),
            HashPart::Str(&request.reservation_id),
            HashPart::Str(&request.sponsor_commitment),
            HashPart::Str(&request.sponsor_budget_root),
            HashPart::Str(&request.sponsor_nullifier),
            HashPart::U64(request.covered_fee_micro_units),
            HashPart::U64(request.sponsored_height),
        ],
        32,
    )
}
pub fn microbatch_settlement_id(request: &MicrobatchSettlementRequest) -> String {
    domain_hash(
        "FAST-MICROCHANNEL-MICROBATCH-SETTLEMENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.batch_commitment),
            HashPart::Str(&request.settlement_root),
            HashPart::Str(&request.channel_root),
            HashPart::Str(&request.claim_root),
            HashPart::Str(&request.settlement_nullifier),
            HashPart::U64(request.gross_amount_micro_units),
            HashPart::U64(request.settled_height),
        ],
        32,
    )
}
pub fn fast_receipt_id(request: &FastReceiptRequest) -> String {
    domain_hash(
        "FAST-MICROCHANNEL-RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.settlement_id),
            HashPart::Str(&request.channel_id),
            HashPart::Str(&request.receipt_commitment),
            HashPart::Str(&request.receipt_root),
            HashPart::Str(&request.receipt_nullifier),
            HashPart::U64(request.amount_micro_units),
            HashPart::U64(request.published_height),
        ],
        32,
    )
}
pub fn reorg_anchor_id(request: &ReorgAnchorRequest) -> String {
    domain_hash(
        "FAST-MICROCHANNEL-REORG-ANCHOR-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.subject_id),
            HashPart::U64(request.monero_height),
            HashPart::Str(&request.monero_block_hash),
            HashPart::Str(&request.anchor_root),
            HashPart::Str(&request.anchor_nullifier),
            HashPart::U64(request.anchored_height),
        ],
        32,
    )
}
pub fn nullifier_fence_id(request: &NullifierFenceRequest) -> String {
    domain_hash(
        "FAST-MICROCHANNEL-NULLIFIER-FENCE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.subject_id),
            HashPart::Str(&request.owner_commitment),
            HashPart::Str(&request.fence_root),
            HashPart::Str(&request.nullifier),
            HashPart::U64(request.fence_height),
        ],
        32,
    )
}
pub fn watchtower_challenge_id(request: &WatchtowerChallengeRequest) -> String {
    domain_hash(
        "FAST-MICROCHANNEL-WATCHTOWER-CHALLENGE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.subject_id),
            HashPart::Str(&request.watchtower_id),
            HashPart::Str(request.challenge_kind.as_str()),
            HashPart::Str(&request.evidence_root),
            HashPart::Str(&request.challenge_nullifier),
            HashPart::U64(request.watchtower_weight),
            HashPart::U64(request.challenged_height),
        ],
        32,
    )
}
pub fn slashing_evidence_id(request: &SlashingEvidenceRequest) -> String {
    domain_hash(
        "FAST-MICROCHANNEL-SLASHING-EVIDENCE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.subject_id),
            HashPart::Str(&request.offender_id),
            HashPart::Str(request.slash_kind.as_str()),
            HashPart::Str(&request.evidence_root),
            HashPart::Str(&request.evidence_nullifier),
            HashPart::U64(request.bond_micro_units),
            HashPart::U64(request.height),
        ],
        32,
    )
}
pub fn sequence_id(kind: &str, sequence: u64, parts: &[&str]) -> String {
    let mut hash_parts = vec![
        HashPart::Str(CHAIN_ID),
        HashPart::Str(PROTOCOL_VERSION),
        HashPart::Str(kind),
        HashPart::U64(sequence),
    ];
    for part in parts {
        hash_parts.push(HashPart::Str(part));
    }
    domain_hash("FAST-MICROCHANNEL-SEQUENCE-ID", &hash_parts, 32)
}
pub fn route_priority_score(
    kind: ChannelKind,
    privacy_set_size: u64,
    max_fee_micro_units: u64,
) -> u64 {
    kind.priority_weight()
        .saturating_add(privacy_set_size.min(1_048_576) / 1_024)
        .saturating_sub(max_fee_micro_units.min(1_000_000) / 10_000)
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
    payload_root("FAST-MICROCHANNEL-ROUTER-STATE-ROOT", record)
}
pub fn map_root<T: Serialize>(domain: &str, map: &BTreeMap<String, T>) -> String {
    let leaves = map.iter().map(|(key, value)| json!({"key":key,"value":serde_json::to_value(value).unwrap_or_else(|_| json!({"serialization":"failed"}))})).collect::<Vec<_>>();
    public_record_root(domain, &leaves)
}
pub fn set_root(domain: &str, set: &BTreeSet<String>) -> String {
    let leaves = set
        .iter()
        .map(|value| json!({"value":value}))
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
pub fn ensure_min(label: &str, value: u64, min: u64) -> Result<()> {
    if value < min {
        Err(format!("{label} below minimum {min}"))
    } else {
        Ok(())
    }
}
pub fn ensure_fresh_nullifier(spent: &BTreeSet<String>, nullifier: &str) -> Result<()> {
    ensure_nonempty("nullifier", nullifier)?;
    if spent.contains(nullifier) {
        Err("nullifier already spent or fenced".to_string())
    } else {
        Ok(())
    }
}
