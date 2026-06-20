use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2ConfidentialContractEventFilterMarketRuntimeResult<T> = Result<T, String>;
pub type Runtime = State;

pub const PRIVATE_L2_CONFIDENTIAL_CONTRACT_EVENT_FILTER_MARKET_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-confidential-contract-event-filter-market-runtime-v1";
pub const PRIVATE_L2_CONFIDENTIAL_CONTRACT_EVENT_FILTER_MARKET_RUNTIME_SCHEMA_VERSION: u64 = 1;
pub const PRIVATE_L2_CONFIDENTIAL_CONTRACT_EVENT_FILTER_MARKET_RUNTIME_HASH_SUITE: &str =
    "SHAKE256-domain-separated-canonical-json";
pub const PRIVATE_L2_CONFIDENTIAL_CONTRACT_EVENT_FILTER_MARKET_RUNTIME_FILTER_ENCRYPTION_SUITE:
    &str = "ML-KEM-1024+Poseidon2-transcript+AEAD-confidential-filter-listing-v1";
pub const PRIVATE_L2_CONFIDENTIAL_CONTRACT_EVENT_FILTER_MARKET_RUNTIME_SUBSCRIBER_KEY_SUITE: &str =
    "ML-KEM-1024+view-tag-subscription-envelope-v1";
pub const PRIVATE_L2_CONFIDENTIAL_CONTRACT_EVENT_FILTER_MARKET_RUNTIME_PQ_ATTESTATION_SUITE: &str =
    "ML-DSA-87+SLH-DSA-SHAKE-256f-indexer-attestation-v1";
pub const PRIVATE_L2_CONFIDENTIAL_CONTRACT_EVENT_FILTER_MARKET_RUNTIME_NULLIFIER_SUITE: &str =
    "monero-l2-nullifier-fence-v1";
pub const PRIVATE_L2_CONFIDENTIAL_CONTRACT_EVENT_FILTER_MARKET_RUNTIME_DEVNET_HEIGHT: u64 =
    1_248_000;
pub const PRIVATE_L2_CONFIDENTIAL_CONTRACT_EVENT_FILTER_MARKET_RUNTIME_MAX_BPS: u64 = 10_000;
pub const PRIVATE_L2_CONFIDENTIAL_CONTRACT_EVENT_FILTER_MARKET_RUNTIME_DEFAULT_MIN_PRIVACY_SET:
    u64 = 65_536;
pub const PRIVATE_L2_CONFIDENTIAL_CONTRACT_EVENT_FILTER_MARKET_RUNTIME_DEFAULT_BATCH_PRIVACY_SET:
    u64 = 524_288;
pub const PRIVATE_L2_CONFIDENTIAL_CONTRACT_EVENT_FILTER_MARKET_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS:
    u16 = 256;
pub const PRIVATE_L2_CONFIDENTIAL_CONTRACT_EVENT_FILTER_MARKET_RUNTIME_DEFAULT_LISTING_TTL_BLOCKS:
    u64 = 43_200;
pub const PRIVATE_L2_CONFIDENTIAL_CONTRACT_EVENT_FILTER_MARKET_RUNTIME_DEFAULT_RESERVATION_TTL_BLOCKS:
    u64 = 96;
pub const PRIVATE_L2_CONFIDENTIAL_CONTRACT_EVENT_FILTER_MARKET_RUNTIME_DEFAULT_TICKET_TTL_BLOCKS:
    u64 = 256;
pub const PRIVATE_L2_CONFIDENTIAL_CONTRACT_EVENT_FILTER_MARKET_RUNTIME_DEFAULT_RECEIPT_TTL_BLOCKS:
    u64 = 21_600;
pub const PRIVATE_L2_CONFIDENTIAL_CONTRACT_EVENT_FILTER_MARKET_RUNTIME_DEFAULT_MAX_LISTINGS: usize =
    16_777_216;
pub const PRIVATE_L2_CONFIDENTIAL_CONTRACT_EVENT_FILTER_MARKET_RUNTIME_DEFAULT_MAX_SUBSCRIBERS:
    usize = 8_388_608;
pub const PRIVATE_L2_CONFIDENTIAL_CONTRACT_EVENT_FILTER_MARKET_RUNTIME_DEFAULT_MAX_ATTESTATIONS:
    usize = 16_777_216;
pub const PRIVATE_L2_CONFIDENTIAL_CONTRACT_EVENT_FILTER_MARKET_RUNTIME_DEFAULT_MAX_LANES: usize =
    1_048_576;
pub const PRIVATE_L2_CONFIDENTIAL_CONTRACT_EVENT_FILTER_MARKET_RUNTIME_DEFAULT_MAX_TICKETS: usize =
    67_108_864;
pub const PRIVATE_L2_CONFIDENTIAL_CONTRACT_EVENT_FILTER_MARKET_RUNTIME_DEFAULT_MAX_RECEIPTS: usize =
    67_108_864;
pub const PRIVATE_L2_CONFIDENTIAL_CONTRACT_EVENT_FILTER_MARKET_RUNTIME_DEFAULT_MAX_REBATES: usize =
    8_388_608;
pub const PRIVATE_L2_CONFIDENTIAL_CONTRACT_EVENT_FILTER_MARKET_RUNTIME_DEFAULT_MAX_NULLIFIERS:
    usize = 134_217_728;
pub const PRIVATE_L2_CONFIDENTIAL_CONTRACT_EVENT_FILTER_MARKET_RUNTIME_DEFAULT_MAX_PUBLIC_HINTS:
    usize = 33_554_432;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FilterCategory {
    TokenTransfer,
    DexSwap,
    LendingPosition,
    PerpetualFunding,
    Liquidation,
    BridgeMessage,
    GovernanceVote,
    OracleUpdate,
    AccountAbstraction,
    NftRoyalty,
    RfqQuote,
    CustomContract,
}

impl FilterCategory {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::TokenTransfer => "token_transfer",
            Self::DexSwap => "dex_swap",
            Self::LendingPosition => "lending_position",
            Self::PerpetualFunding => "perpetual_funding",
            Self::Liquidation => "liquidation",
            Self::BridgeMessage => "bridge_message",
            Self::GovernanceVote => "governance_vote",
            Self::OracleUpdate => "oracle_update",
            Self::AccountAbstraction => "account_abstraction",
            Self::NftRoyalty => "nft_royalty",
            Self::RfqQuote => "rfq_quote",
            Self::CustomContract => "custom_contract",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PredicateKind {
    TopicSet,
    ContractSelector,
    EventSignature,
    StorageSlot,
    AmountBand,
    AddressShield,
    ReceiptField,
    CrossContractTrace,
    DefiIntent,
    Composite,
}

impl PredicateKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::TopicSet => "topic_set",
            Self::ContractSelector => "contract_selector",
            Self::EventSignature => "event_signature",
            Self::StorageSlot => "storage_slot",
            Self::AmountBand => "amount_band",
            Self::AddressShield => "address_shield",
            Self::ReceiptField => "receipt_field",
            Self::CrossContractTrace => "cross_contract_trace",
            Self::DefiIntent => "defi_intent",
            Self::Composite => "composite",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ListingStatus {
    Encrypted,
    Attested,
    Active,
    Reserved,
    Paused,
    SoldOut,
    Expired,
    Revoked,
}

impl ListingStatus {
    pub fn marketable(self) -> bool {
        matches!(self, Self::Attested | Self::Active | Self::Reserved)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Encrypted => "encrypted",
            Self::Attested => "attested",
            Self::Active => "active",
            Self::Reserved => "reserved",
            Self::Paused => "paused",
            Self::SoldOut => "sold_out",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SubscriberKind {
    Wallet,
    Relayer,
    Liquidator,
    MarketMaker,
    LendingBot,
    GovernanceAgent,
    BridgeWatcher,
    OracleKeeper,
    AnalyticsVault,
    ContractHook,
}

impl SubscriberKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Wallet => "wallet",
            Self::Relayer => "relayer",
            Self::Liquidator => "liquidator",
            Self::MarketMaker => "market_maker",
            Self::LendingBot => "lending_bot",
            Self::GovernanceAgent => "governance_agent",
            Self::BridgeWatcher => "bridge_watcher",
            Self::OracleKeeper => "oracle_keeper",
            Self::AnalyticsVault => "analytics_vault",
            Self::ContractHook => "contract_hook",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SubscriberStatus {
    Registered,
    Active,
    RateLimited,
    Suspended,
    Revoked,
    Expired,
}

impl SubscriberStatus {
    pub fn can_buy(self) -> bool {
        matches!(self, Self::Registered | Self::Active | Self::RateLimited)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Registered => "registered",
            Self::Active => "active",
            Self::RateLimited => "rate_limited",
            Self::Suspended => "suspended",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationKind {
    PqIndexerKey,
    FilterWellFormedness,
    EncryptedPredicateSoundness,
    MatchCircuit,
    FeeSchedule,
    Availability,
    NullifierFence,
    SettlementBatch,
}

impl AttestationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PqIndexerKey => "pq_indexer_key",
            Self::FilterWellFormedness => "filter_well_formedness",
            Self::EncryptedPredicateSoundness => "encrypted_predicate_soundness",
            Self::MatchCircuit => "match_circuit",
            Self::FeeSchedule => "fee_schedule",
            Self::Availability => "availability",
            Self::NullifierFence => "nullifier_fence",
            Self::SettlementBatch => "settlement_batch",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationStatus {
    Posted,
    QuorumMet,
    Used,
    Challenged,
    Rejected,
    Expired,
}

impl AttestationStatus {
    pub fn usable(self) -> bool {
        matches!(self, Self::Posted | Self::QuorumMet | Self::Used)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Posted => "posted",
            Self::QuorumMet => "quorum_met",
            Self::Used => "used",
            Self::Challenged => "challenged",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LaneKind {
    InstantBuy,
    TimedReservation,
    SponsoredReservation,
    BatchAuction,
    DefiKeeper,
    CrossContract,
    EmergencyLowFee,
}

impl LaneKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InstantBuy => "instant_buy",
            Self::TimedReservation => "timed_reservation",
            Self::SponsoredReservation => "sponsored_reservation",
            Self::BatchAuction => "batch_auction",
            Self::DefiKeeper => "defi_keeper",
            Self::CrossContract => "cross_contract",
            Self::EmergencyLowFee => "emergency_low_fee",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LaneStatus {
    Open,
    Throttled,
    Reserved,
    Settling,
    Closed,
    Paused,
}

impl LaneStatus {
    pub fn accepts_orders(self) -> bool {
        matches!(self, Self::Open | Self::Throttled | Self::Reserved)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Throttled => "throttled",
            Self::Reserved => "reserved",
            Self::Settling => "settling",
            Self::Closed => "closed",
            Self::Paused => "paused",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TicketStatus {
    Issued,
    Matched,
    Delivered,
    Settled,
    Replayed,
    Refunded,
    Expired,
}

impl TicketStatus {
    pub fn payable(self) -> bool {
        matches!(self, Self::Matched | Self::Delivered | Self::Settled)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Issued => "issued",
            Self::Matched => "matched",
            Self::Delivered => "delivered",
            Self::Settled => "settled",
            Self::Replayed => "replayed",
            Self::Refunded => "refunded",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptStatus {
    Pending,
    Posted,
    Final,
    Rebatable,
    Disputed,
    Reversed,
}

impl ReceiptStatus {
    pub fn finalizes(self) -> bool {
        matches!(self, Self::Final | Self::Rebatable)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Posted => "posted",
            Self::Final => "final",
            Self::Rebatable => "rebatable",
            Self::Disputed => "disputed",
            Self::Reversed => "reversed",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RebateStatus {
    Accrued,
    Claimable,
    Claimed,
    Donated,
    Slashed,
    Expired,
}

impl RebateStatus {
    pub fn claimable(self) -> bool {
        matches!(self, Self::Accrued | Self::Claimable)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Accrued => "accrued",
            Self::Claimable => "claimable",
            Self::Claimed => "claimed",
            Self::Donated => "donated",
            Self::Slashed => "slashed",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub protocol_version: String,
    pub schema_version: u64,
    pub chain_id: String,
    pub hash_suite: String,
    pub filter_encryption_suite: String,
    pub subscriber_key_suite: String,
    pub pq_attestation_suite: String,
    pub nullifier_suite: String,
    pub min_privacy_set: u64,
    pub batch_privacy_set: u64,
    pub min_pq_security_bits: u16,
    pub listing_ttl_blocks: u64,
    pub reservation_ttl_blocks: u64,
    pub ticket_ttl_blocks: u64,
    pub receipt_ttl_blocks: u64,
    pub max_listing_fee_bps: u64,
    pub max_indexer_fee_bps: u64,
    pub max_delivery_fee_bps: u64,
    pub max_sponsor_fee_bps: u64,
    pub target_rebate_bps: u64,
    pub max_listings: usize,
    pub max_subscribers: usize,
    pub max_attestations: usize,
    pub max_lanes: usize,
    pub max_tickets: usize,
    pub max_receipts: usize,
    pub max_rebates: usize,
    pub max_nullifiers: usize,
    pub max_public_hints: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            protocol_version:
                PRIVATE_L2_CONFIDENTIAL_CONTRACT_EVENT_FILTER_MARKET_RUNTIME_PROTOCOL_VERSION
                    .to_string(),
            schema_version:
                PRIVATE_L2_CONFIDENTIAL_CONTRACT_EVENT_FILTER_MARKET_RUNTIME_SCHEMA_VERSION,
            chain_id: CHAIN_ID.to_string(),
            hash_suite: PRIVATE_L2_CONFIDENTIAL_CONTRACT_EVENT_FILTER_MARKET_RUNTIME_HASH_SUITE
                .to_string(),
            filter_encryption_suite:
                PRIVATE_L2_CONFIDENTIAL_CONTRACT_EVENT_FILTER_MARKET_RUNTIME_FILTER_ENCRYPTION_SUITE
                    .to_string(),
            subscriber_key_suite:
                PRIVATE_L2_CONFIDENTIAL_CONTRACT_EVENT_FILTER_MARKET_RUNTIME_SUBSCRIBER_KEY_SUITE
                    .to_string(),
            pq_attestation_suite:
                PRIVATE_L2_CONFIDENTIAL_CONTRACT_EVENT_FILTER_MARKET_RUNTIME_PQ_ATTESTATION_SUITE
                    .to_string(),
            nullifier_suite:
                PRIVATE_L2_CONFIDENTIAL_CONTRACT_EVENT_FILTER_MARKET_RUNTIME_NULLIFIER_SUITE
                    .to_string(),
            min_privacy_set:
                PRIVATE_L2_CONFIDENTIAL_CONTRACT_EVENT_FILTER_MARKET_RUNTIME_DEFAULT_MIN_PRIVACY_SET,
            batch_privacy_set:
                PRIVATE_L2_CONFIDENTIAL_CONTRACT_EVENT_FILTER_MARKET_RUNTIME_DEFAULT_BATCH_PRIVACY_SET,
            min_pq_security_bits:
                PRIVATE_L2_CONFIDENTIAL_CONTRACT_EVENT_FILTER_MARKET_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS,
            listing_ttl_blocks:
                PRIVATE_L2_CONFIDENTIAL_CONTRACT_EVENT_FILTER_MARKET_RUNTIME_DEFAULT_LISTING_TTL_BLOCKS,
            reservation_ttl_blocks:
                PRIVATE_L2_CONFIDENTIAL_CONTRACT_EVENT_FILTER_MARKET_RUNTIME_DEFAULT_RESERVATION_TTL_BLOCKS,
            ticket_ttl_blocks:
                PRIVATE_L2_CONFIDENTIAL_CONTRACT_EVENT_FILTER_MARKET_RUNTIME_DEFAULT_TICKET_TTL_BLOCKS,
            receipt_ttl_blocks:
                PRIVATE_L2_CONFIDENTIAL_CONTRACT_EVENT_FILTER_MARKET_RUNTIME_DEFAULT_RECEIPT_TTL_BLOCKS,
            max_listing_fee_bps: 18,
            max_indexer_fee_bps: 9,
            max_delivery_fee_bps: 7,
            max_sponsor_fee_bps: 6,
            target_rebate_bps: 5,
            max_listings:
                PRIVATE_L2_CONFIDENTIAL_CONTRACT_EVENT_FILTER_MARKET_RUNTIME_DEFAULT_MAX_LISTINGS,
            max_subscribers:
                PRIVATE_L2_CONFIDENTIAL_CONTRACT_EVENT_FILTER_MARKET_RUNTIME_DEFAULT_MAX_SUBSCRIBERS,
            max_attestations:
                PRIVATE_L2_CONFIDENTIAL_CONTRACT_EVENT_FILTER_MARKET_RUNTIME_DEFAULT_MAX_ATTESTATIONS,
            max_lanes: PRIVATE_L2_CONFIDENTIAL_CONTRACT_EVENT_FILTER_MARKET_RUNTIME_DEFAULT_MAX_LANES,
            max_tickets:
                PRIVATE_L2_CONFIDENTIAL_CONTRACT_EVENT_FILTER_MARKET_RUNTIME_DEFAULT_MAX_TICKETS,
            max_receipts:
                PRIVATE_L2_CONFIDENTIAL_CONTRACT_EVENT_FILTER_MARKET_RUNTIME_DEFAULT_MAX_RECEIPTS,
            max_rebates:
                PRIVATE_L2_CONFIDENTIAL_CONTRACT_EVENT_FILTER_MARKET_RUNTIME_DEFAULT_MAX_REBATES,
            max_nullifiers:
                PRIVATE_L2_CONFIDENTIAL_CONTRACT_EVENT_FILTER_MARKET_RUNTIME_DEFAULT_MAX_NULLIFIERS,
            max_public_hints:
                PRIVATE_L2_CONFIDENTIAL_CONTRACT_EVENT_FILTER_MARKET_RUNTIME_DEFAULT_MAX_PUBLIC_HINTS,
        }
    }
}

impl Config {
    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "chain_id": self.chain_id,
            "hash_suite": self.hash_suite,
            "filter_encryption_suite": self.filter_encryption_suite,
            "subscriber_key_suite": self.subscriber_key_suite,
            "pq_attestation_suite": self.pq_attestation_suite,
            "nullifier_suite": self.nullifier_suite,
            "min_privacy_set": self.min_privacy_set,
            "batch_privacy_set": self.batch_privacy_set,
            "min_pq_security_bits": self.min_pq_security_bits,
            "listing_ttl_blocks": self.listing_ttl_blocks,
            "reservation_ttl_blocks": self.reservation_ttl_blocks,
            "ticket_ttl_blocks": self.ticket_ttl_blocks,
            "receipt_ttl_blocks": self.receipt_ttl_blocks,
            "max_listing_fee_bps": self.max_listing_fee_bps,
            "max_indexer_fee_bps": self.max_indexer_fee_bps,
            "max_delivery_fee_bps": self.max_delivery_fee_bps,
            "max_sponsor_fee_bps": self.max_sponsor_fee_bps,
            "target_rebate_bps": self.target_rebate_bps,
            "max_listings": self.max_listings,
            "max_subscribers": self.max_subscribers,
            "max_attestations": self.max_attestations,
            "max_lanes": self.max_lanes,
            "max_tickets": self.max_tickets,
            "max_receipts": self.max_receipts,
            "max_rebates": self.max_rebates,
            "max_nullifiers": self.max_nullifiers,
            "max_public_hints": self.max_public_hints,
        })
    }

    pub fn root(&self) -> String {
        root_from_record("FILTER-MARKET-CONFIG", &self.public_record())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub listings: u64,
    pub subscribers: u64,
    pub attestations: u64,
    pub purchase_lanes: u64,
    pub reservations: u64,
    pub tickets: u64,
    pub receipts: u64,
    pub rebates: u64,
    pub nullifiers: u64,
    pub public_hints: u64,
    pub total_fee_piconero: u128,
    pub total_rebate_piconero: u128,
    pub matched_event_count: u128,
    pub delivered_event_count: u128,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "listings": self.listings,
            "subscribers": self.subscribers,
            "attestations": self.attestations,
            "purchase_lanes": self.purchase_lanes,
            "reservations": self.reservations,
            "tickets": self.tickets,
            "receipts": self.receipts,
            "rebates": self.rebates,
            "nullifiers": self.nullifiers,
            "public_hints": self.public_hints,
            "total_fee_piconero": self.total_fee_piconero.to_string(),
            "total_rebate_piconero": self.total_rebate_piconero.to_string(),
            "matched_event_count": self.matched_event_count.to_string(),
            "delivered_event_count": self.delivered_event_count.to_string(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EncryptedFilterListing {
    pub listing_id: String,
    pub seller_commitment: String,
    pub category: FilterCategory,
    pub predicate_kind: PredicateKind,
    pub contract_commitment: String,
    pub event_namespace_root: String,
    pub encrypted_predicate_root: String,
    pub encrypted_filter_blob_root: String,
    pub public_hint_root: String,
    pub price_piconero: u128,
    pub max_matches: u64,
    pub filled_matches: u64,
    pub min_privacy_set: u64,
    pub pq_security_bits: u16,
    pub fee_bps: u64,
    pub status: ListingStatus,
    pub created_at_height: u64,
    pub expires_at_height: u64,
    pub metadata: Value,
}

impl EncryptedFilterListing {
    pub fn public_record(&self) -> Value {
        json!({
            "listing_id": self.listing_id,
            "seller_commitment": self.seller_commitment,
            "category": self.category.as_str(),
            "predicate_kind": self.predicate_kind.as_str(),
            "contract_commitment": self.contract_commitment,
            "event_namespace_root": self.event_namespace_root,
            "encrypted_predicate_root": self.encrypted_predicate_root,
            "encrypted_filter_blob_root": self.encrypted_filter_blob_root,
            "public_hint_root": self.public_hint_root,
            "price_piconero": self.price_piconero.to_string(),
            "max_matches": self.max_matches,
            "filled_matches": self.filled_matches,
            "min_privacy_set": self.min_privacy_set,
            "pq_security_bits": self.pq_security_bits,
            "fee_bps": self.fee_bps,
            "status": self.status.as_str(),
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
            "metadata": self.metadata,
        })
    }

    pub fn root(&self) -> String {
        root_from_record("FILTER-MARKET-LISTING", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivateSubscriber {
    pub subscriber_id: String,
    pub owner_commitment: String,
    pub subscriber_kind: SubscriberKind,
    pub viewing_key_commitment: String,
    pub pq_kem_public_key_root: String,
    pub delivery_address_commitment: String,
    pub spending_limit_root: String,
    pub privacy_budget_root: String,
    pub nullifier_scope_root: String,
    pub min_privacy_set: u64,
    pub pq_security_bits: u16,
    pub status: SubscriberStatus,
    pub registered_at_height: u64,
    pub expires_at_height: u64,
    pub metadata: Value,
}

impl PrivateSubscriber {
    pub fn public_record(&self) -> Value {
        json!({
            "subscriber_id": self.subscriber_id,
            "owner_commitment": self.owner_commitment,
            "subscriber_kind": self.subscriber_kind.as_str(),
            "viewing_key_commitment": self.viewing_key_commitment,
            "pq_kem_public_key_root": self.pq_kem_public_key_root,
            "delivery_address_commitment": self.delivery_address_commitment,
            "spending_limit_root": self.spending_limit_root,
            "privacy_budget_root": self.privacy_budget_root,
            "nullifier_scope_root": self.nullifier_scope_root,
            "min_privacy_set": self.min_privacy_set,
            "pq_security_bits": self.pq_security_bits,
            "status": self.status.as_str(),
            "registered_at_height": self.registered_at_height,
            "expires_at_height": self.expires_at_height,
            "metadata": self.metadata,
        })
    }

    pub fn root(&self) -> String {
        root_from_record("FILTER-MARKET-SUBSCRIBER", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqIndexerAttestation {
    pub attestation_id: String,
    pub indexer_commitment: String,
    pub attestation_kind: AttestationKind,
    pub subject_id: String,
    pub subject_root: String,
    pub circuit_root: String,
    pub transcript_root: String,
    pub pq_public_key_root: String,
    pub aggregate_signature_root: String,
    pub committee_root: String,
    pub quorum_weight: u64,
    pub pq_security_bits: u16,
    pub status: AttestationStatus,
    pub attested_at_height: u64,
    pub expires_at_height: u64,
    pub metadata: Value,
}

impl PqIndexerAttestation {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "indexer_commitment": self.indexer_commitment,
            "attestation_kind": self.attestation_kind.as_str(),
            "subject_id": self.subject_id,
            "subject_root": self.subject_root,
            "circuit_root": self.circuit_root,
            "transcript_root": self.transcript_root,
            "pq_public_key_root": self.pq_public_key_root,
            "aggregate_signature_root": self.aggregate_signature_root,
            "committee_root": self.committee_root,
            "quorum_weight": self.quorum_weight,
            "pq_security_bits": self.pq_security_bits,
            "status": self.status.as_str(),
            "attested_at_height": self.attested_at_height,
            "expires_at_height": self.expires_at_height,
            "metadata": self.metadata,
        })
    }

    pub fn root(&self) -> String {
        root_from_record("FILTER-MARKET-PQ-ATTESTATION", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PurchaseLane {
    pub lane_id: String,
    pub lane_kind: LaneKind,
    pub listing_id: String,
    pub seller_commitment: String,
    pub sponsor_commitment: String,
    pub reserve_root: String,
    pub fee_quote_root: String,
    pub batch_policy_root: String,
    pub privacy_floor: u64,
    pub capacity: u64,
    pub filled: u64,
    pub max_fee_bps: u64,
    pub status: LaneStatus,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub metadata: Value,
}

impl PurchaseLane {
    pub fn public_record(&self) -> Value {
        json!({
            "lane_id": self.lane_id,
            "lane_kind": self.lane_kind.as_str(),
            "listing_id": self.listing_id,
            "seller_commitment": self.seller_commitment,
            "sponsor_commitment": self.sponsor_commitment,
            "reserve_root": self.reserve_root,
            "fee_quote_root": self.fee_quote_root,
            "batch_policy_root": self.batch_policy_root,
            "privacy_floor": self.privacy_floor,
            "capacity": self.capacity,
            "filled": self.filled,
            "max_fee_bps": self.max_fee_bps,
            "status": self.status.as_str(),
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "metadata": self.metadata,
        })
    }

    pub fn root(&self) -> String {
        root_from_record("FILTER-MARKET-PURCHASE-LANE", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FilterReservation {
    pub reservation_id: String,
    pub lane_id: String,
    pub listing_id: String,
    pub subscriber_id: String,
    pub buyer_commitment: String,
    pub reservation_nullifier: String,
    pub encrypted_payment_note_root: String,
    pub amount_piconero: u128,
    pub fee_bps: u64,
    pub reserved_matches: u64,
    pub reserved_at_height: u64,
    pub expires_at_height: u64,
    pub metadata: Value,
}

impl FilterReservation {
    pub fn public_record(&self) -> Value {
        json!({
            "reservation_id": self.reservation_id,
            "lane_id": self.lane_id,
            "listing_id": self.listing_id,
            "subscriber_id": self.subscriber_id,
            "buyer_commitment": self.buyer_commitment,
            "reservation_nullifier": self.reservation_nullifier,
            "encrypted_payment_note_root": self.encrypted_payment_note_root,
            "amount_piconero": self.amount_piconero.to_string(),
            "fee_bps": self.fee_bps,
            "reserved_matches": self.reserved_matches,
            "reserved_at_height": self.reserved_at_height,
            "expires_at_height": self.expires_at_height,
            "metadata": self.metadata,
        })
    }

    pub fn root(&self) -> String {
        root_from_record("FILTER-MARKET-RESERVATION", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EventMatchingTicket {
    pub ticket_id: String,
    pub lane_id: String,
    pub listing_id: String,
    pub subscriber_id: String,
    pub reservation_id: String,
    pub event_commitment: String,
    pub match_proof_root: String,
    pub encrypted_delivery_root: String,
    pub reveal_hint_root: String,
    pub nullifier: String,
    pub fee_piconero: u128,
    pub match_score_microunits: u64,
    pub status: TicketStatus,
    pub matched_at_height: u64,
    pub expires_at_height: u64,
    pub metadata: Value,
}

impl EventMatchingTicket {
    pub fn public_record(&self) -> Value {
        json!({
            "ticket_id": self.ticket_id,
            "lane_id": self.lane_id,
            "listing_id": self.listing_id,
            "subscriber_id": self.subscriber_id,
            "reservation_id": self.reservation_id,
            "event_commitment": self.event_commitment,
            "match_proof_root": self.match_proof_root,
            "encrypted_delivery_root": self.encrypted_delivery_root,
            "reveal_hint_root": self.reveal_hint_root,
            "nullifier": self.nullifier,
            "fee_piconero": self.fee_piconero.to_string(),
            "match_score_microunits": self.match_score_microunits,
            "status": self.status.as_str(),
            "matched_at_height": self.matched_at_height,
            "expires_at_height": self.expires_at_height,
            "metadata": self.metadata,
        })
    }

    pub fn root(&self) -> String {
        root_from_record("FILTER-MARKET-TICKET", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SettlementReceipt {
    pub receipt_id: String,
    pub ticket_id: String,
    pub lane_id: String,
    pub listing_id: String,
    pub subscriber_id: String,
    pub seller_commitment: String,
    pub indexer_commitment: String,
    pub settlement_note_root: String,
    pub delivery_receipt_root: String,
    pub fee_split_root: String,
    pub state_transition_root: String,
    pub paid_piconero: u128,
    pub indexer_fee_piconero: u128,
    pub protocol_fee_piconero: u128,
    pub status: ReceiptStatus,
    pub settled_at_height: u64,
    pub metadata: Value,
}

impl SettlementReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "ticket_id": self.ticket_id,
            "lane_id": self.lane_id,
            "listing_id": self.listing_id,
            "subscriber_id": self.subscriber_id,
            "seller_commitment": self.seller_commitment,
            "indexer_commitment": self.indexer_commitment,
            "settlement_note_root": self.settlement_note_root,
            "delivery_receipt_root": self.delivery_receipt_root,
            "fee_split_root": self.fee_split_root,
            "state_transition_root": self.state_transition_root,
            "paid_piconero": self.paid_piconero.to_string(),
            "indexer_fee_piconero": self.indexer_fee_piconero.to_string(),
            "protocol_fee_piconero": self.protocol_fee_piconero.to_string(),
            "status": self.status.as_str(),
            "settled_at_height": self.settled_at_height,
            "metadata": self.metadata,
        })
    }

    pub fn root(&self) -> String {
        root_from_record("FILTER-MARKET-SETTLEMENT-RECEIPT", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RebateCredit {
    pub rebate_id: String,
    pub receipt_id: String,
    pub beneficiary_commitment: String,
    pub rebate_note_root: String,
    pub reason_root: String,
    pub amount_piconero: u128,
    pub status: RebateStatus,
    pub accrued_at_height: u64,
    pub expires_at_height: u64,
    pub metadata: Value,
}

impl RebateCredit {
    pub fn public_record(&self) -> Value {
        json!({
            "rebate_id": self.rebate_id,
            "receipt_id": self.receipt_id,
            "beneficiary_commitment": self.beneficiary_commitment,
            "rebate_note_root": self.rebate_note_root,
            "reason_root": self.reason_root,
            "amount_piconero": self.amount_piconero.to_string(),
            "status": self.status.as_str(),
            "accrued_at_height": self.accrued_at_height,
            "expires_at_height": self.expires_at_height,
            "metadata": self.metadata,
        })
    }

    pub fn root(&self) -> String {
        root_from_record("FILTER-MARKET-REBATE", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivacyFence {
    pub fence_id: String,
    pub scope: String,
    pub subject_id: String,
    pub nullifier: String,
    pub commitment_root: String,
    pub privacy_set_root: String,
    pub min_privacy_set: u64,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub metadata: Value,
}

impl PrivacyFence {
    pub fn public_record(&self) -> Value {
        json!({
            "fence_id": self.fence_id,
            "scope": self.scope,
            "subject_id": self.subject_id,
            "nullifier": self.nullifier,
            "commitment_root": self.commitment_root,
            "privacy_set_root": self.privacy_set_root,
            "min_privacy_set": self.min_privacy_set,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "metadata": self.metadata,
        })
    }

    pub fn root(&self) -> String {
        root_from_record("FILTER-MARKET-PRIVACY-FENCE", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublicHint {
    pub hint_id: String,
    pub subject_id: String,
    pub hint_kind: String,
    pub hint_root: String,
    pub fee_hint_microunits: u64,
    pub privacy_band: u64,
    pub posted_at_height: u64,
    pub metadata: Value,
}

impl PublicHint {
    pub fn public_record(&self) -> Value {
        json!({
            "hint_id": self.hint_id,
            "subject_id": self.subject_id,
            "hint_kind": self.hint_kind,
            "hint_root": self.hint_root,
            "fee_hint_microunits": self.fee_hint_microunits,
            "privacy_band": self.privacy_band,
            "posted_at_height": self.posted_at_height,
            "metadata": self.metadata,
        })
    }

    pub fn root(&self) -> String {
        root_from_record("FILTER-MARKET-PUBLIC-HINT", &self.public_record())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub counters_root: String,
    pub listing_root: String,
    pub subscriber_root: String,
    pub pq_attestation_root: String,
    pub purchase_lane_root: String,
    pub reservation_root: String,
    pub ticket_root: String,
    pub receipt_root: String,
    pub rebate_root: String,
    pub privacy_fence_root: String,
    pub nullifier_root: String,
    pub public_hint_root: String,
    pub public_record_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "counters_root": self.counters_root,
            "listing_root": self.listing_root,
            "subscriber_root": self.subscriber_root,
            "pq_attestation_root": self.pq_attestation_root,
            "purchase_lane_root": self.purchase_lane_root,
            "reservation_root": self.reservation_root,
            "ticket_root": self.ticket_root,
            "receipt_root": self.receipt_root,
            "rebate_root": self.rebate_root,
            "privacy_fence_root": self.privacy_fence_root,
            "nullifier_root": self.nullifier_root,
            "public_hint_root": self.public_hint_root,
            "public_record_root": self.public_record_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub height: u64,
    pub epoch: u64,
    pub counters: Counters,
    pub listings: BTreeMap<String, EncryptedFilterListing>,
    pub subscribers: BTreeMap<String, PrivateSubscriber>,
    pub attestations: BTreeMap<String, PqIndexerAttestation>,
    pub purchase_lanes: BTreeMap<String, PurchaseLane>,
    pub reservations: BTreeMap<String, FilterReservation>,
    pub tickets: BTreeMap<String, EventMatchingTicket>,
    pub receipts: BTreeMap<String, SettlementReceipt>,
    pub rebates: BTreeMap<String, RebateCredit>,
    pub privacy_fences: BTreeMap<String, PrivacyFence>,
    pub nullifiers: BTreeSet<String>,
    pub public_hints: BTreeMap<String, PublicHint>,
}

impl Default for State {
    fn default() -> Self {
        Self {
            config: Config::default(),
            height: 0,
            epoch: 0,
            counters: Counters::default(),
            listings: BTreeMap::new(),
            subscribers: BTreeMap::new(),
            attestations: BTreeMap::new(),
            purchase_lanes: BTreeMap::new(),
            reservations: BTreeMap::new(),
            tickets: BTreeMap::new(),
            receipts: BTreeMap::new(),
            rebates: BTreeMap::new(),
            privacy_fences: BTreeMap::new(),
            nullifiers: BTreeSet::new(),
            public_hints: BTreeMap::new(),
        }
    }
}

impl State {
    pub fn devnet() -> Self {
        let mut state = Self {
            height: PRIVATE_L2_CONFIDENTIAL_CONTRACT_EVENT_FILTER_MARKET_RUNTIME_DEVNET_HEIGHT,
            epoch: 77,
            ..Self::default()
        };
        let base_height = state.height;

        let amm_listing = sample_listing(
            "amm-swap-filter",
            FilterCategory::DexSwap,
            PredicateKind::Composite,
            "seller-alpha",
            "contract-amm-stableswap",
            base_height,
            3_500_000_000,
            64_000,
        );
        let lending_listing = sample_listing(
            "lending-liquidation-filter",
            FilterCategory::Liquidation,
            PredicateKind::CrossContractTrace,
            "seller-beta",
            "contract-lending-core",
            base_height + 3,
            4_200_000_000,
            24_000,
        );
        let bridge_listing = sample_listing(
            "bridge-message-filter",
            FilterCategory::BridgeMessage,
            PredicateKind::EventSignature,
            "seller-gamma",
            "contract-monero-bridge",
            base_height + 6,
            2_100_000_000,
            96_000,
        );

        let listings = [amm_listing, lending_listing, bridge_listing];
        for listing in listings {
            state.counters.listings += 1;
            state.listings.insert(listing.listing_id.clone(), listing);
        }

        let subscriber_one = sample_subscriber(
            "keeper-subscriber",
            SubscriberKind::Liquidator,
            "owner-keeper-alpha",
            base_height + 8,
        );
        let subscriber_two = sample_subscriber(
            "wallet-subscriber",
            SubscriberKind::Wallet,
            "owner-wallet-beta",
            base_height + 9,
        );
        let subscriber_three = sample_subscriber(
            "router-subscriber",
            SubscriberKind::ContractHook,
            "owner-router-gamma",
            base_height + 10,
        );
        let subscribers = [subscriber_one, subscriber_two, subscriber_three];
        for subscriber in subscribers {
            state.counters.subscribers += 1;
            state
                .subscribers
                .insert(subscriber.subscriber_id.clone(), subscriber);
        }

        let listing_ids = state.listings.keys().cloned().collect::<Vec<_>>();
        for (index, listing_id) in listing_ids.iter().enumerate() {
            let listing = state.listings.get(listing_id).expect("devnet listing");
            let attestation = sample_attestation(
                &format!("indexer-attestation-{index}"),
                AttestationKind::EncryptedPredicateSoundness,
                &listing.listing_id,
                &listing.root(),
                base_height + 12 + index as u64,
            );
            state.counters.attestations += 1;
            state
                .attestations
                .insert(attestation.attestation_id.clone(), attestation);
        }

        let lane_one = sample_lane(
            "amm-instant-lane",
            LaneKind::InstantBuy,
            "amm-swap-filter",
            "seller-alpha",
            base_height + 20,
            4_096,
        );
        let lane_two = sample_lane(
            "liquidation-keeper-lane",
            LaneKind::DefiKeeper,
            "lending-liquidation-filter",
            "seller-beta",
            base_height + 21,
            1_024,
        );
        let lane_three = sample_lane(
            "bridge-sponsored-lane",
            LaneKind::SponsoredReservation,
            "bridge-message-filter",
            "seller-gamma",
            base_height + 22,
            8_192,
        );
        let lanes = [lane_one, lane_two, lane_three];
        for lane in lanes {
            state.counters.purchase_lanes += 1;
            state.purchase_lanes.insert(lane.lane_id.clone(), lane);
        }

        let reservation_one = sample_reservation(
            "reservation-amm-keeper",
            "amm-instant-lane",
            "amm-swap-filter",
            "keeper-subscriber",
            "buyer-keeper-alpha",
            base_height + 26,
            3_500_000_000,
        );
        let reservation_two = sample_reservation(
            "reservation-liquidation-keeper",
            "liquidation-keeper-lane",
            "lending-liquidation-filter",
            "keeper-subscriber",
            "buyer-keeper-alpha",
            base_height + 27,
            4_200_000_000,
        );
        let reservation_three = sample_reservation(
            "reservation-bridge-wallet",
            "bridge-sponsored-lane",
            "bridge-message-filter",
            "wallet-subscriber",
            "buyer-wallet-beta",
            base_height + 28,
            2_100_000_000,
        );
        let reservations = [reservation_one, reservation_two, reservation_three];
        for reservation in reservations {
            state
                .nullifiers
                .insert(reservation.reservation_nullifier.clone());
            state.counters.nullifiers += 1;
            state.counters.reservations += 1;
            state
                .reservations
                .insert(reservation.reservation_id.clone(), reservation);
        }

        let ticket_one = sample_ticket(
            "ticket-amm-swap-0001",
            "amm-instant-lane",
            "amm-swap-filter",
            "keeper-subscriber",
            "reservation-amm-keeper",
            base_height + 32,
            35_000_000,
        );
        let ticket_two = sample_ticket(
            "ticket-liquidation-0001",
            "liquidation-keeper-lane",
            "lending-liquidation-filter",
            "keeper-subscriber",
            "reservation-liquidation-keeper",
            base_height + 33,
            42_000_000,
        );
        let ticket_three = sample_ticket(
            "ticket-bridge-message-0001",
            "bridge-sponsored-lane",
            "bridge-message-filter",
            "wallet-subscriber",
            "reservation-bridge-wallet",
            base_height + 34,
            21_000_000,
        );
        let tickets = [ticket_one, ticket_two, ticket_three];
        for ticket in tickets {
            state.nullifiers.insert(ticket.nullifier.clone());
            state.counters.nullifiers += 1;
            state.counters.tickets += 1;
            state.counters.matched_event_count += 1;
            state.tickets.insert(ticket.ticket_id.clone(), ticket);
        }

        let receipt_one = sample_receipt(
            "receipt-amm-swap-0001",
            "ticket-amm-swap-0001",
            "amm-instant-lane",
            "amm-swap-filter",
            "keeper-subscriber",
            "seller-alpha",
            base_height + 40,
            35_000_000,
        );
        let receipt_two = sample_receipt(
            "receipt-liquidation-0001",
            "ticket-liquidation-0001",
            "liquidation-keeper-lane",
            "lending-liquidation-filter",
            "keeper-subscriber",
            "seller-beta",
            base_height + 41,
            42_000_000,
        );
        let receipt_three = sample_receipt(
            "receipt-bridge-message-0001",
            "ticket-bridge-message-0001",
            "bridge-sponsored-lane",
            "bridge-message-filter",
            "wallet-subscriber",
            "seller-gamma",
            base_height + 42,
            21_000_000,
        );
        let receipts = [receipt_one, receipt_two, receipt_three];
        for receipt in receipts {
            state.counters.receipts += 1;
            state.counters.delivered_event_count += 1;
            state.counters.total_fee_piconero += receipt.paid_piconero;
            state.receipts.insert(receipt.receipt_id.clone(), receipt);
        }

        let rebate_one = sample_rebate(
            "rebate-amm-swap-0001",
            "receipt-amm-swap-0001",
            "buyer-keeper-alpha",
            base_height + 44,
            175_000,
        );
        let rebate_two = sample_rebate(
            "rebate-bridge-message-0001",
            "receipt-bridge-message-0001",
            "buyer-wallet-beta",
            base_height + 45,
            105_000,
        );
        let rebates = [rebate_one, rebate_two];
        for rebate in rebates {
            state.counters.rebates += 1;
            state.counters.total_rebate_piconero += rebate.amount_piconero;
            state.rebates.insert(rebate.rebate_id.clone(), rebate);
        }

        for (scope, subject_id, label, height) in [
            (
                "listing",
                "amm-swap-filter",
                "fence-listing-amm",
                base_height + 50,
            ),
            (
                "subscriber",
                "keeper-subscriber",
                "fence-subscriber-keeper",
                base_height + 51,
            ),
            (
                "ticket",
                "ticket-liquidation-0001",
                "fence-ticket-liquidation",
                base_height + 52,
            ),
        ] {
            let fence = sample_fence(label, scope, subject_id, height);
            state.nullifiers.insert(fence.nullifier.clone());
            state.counters.nullifiers += 1;
            state.privacy_fences.insert(fence.fence_id.clone(), fence);
        }

        for (label, subject_id, kind, height) in [
            (
                "hint-amm-fee",
                "amm-swap-filter",
                "fee_band",
                base_height + 55,
            ),
            (
                "hint-liquidation-latency",
                "lending-liquidation-filter",
                "latency_band",
                base_height + 56,
            ),
            (
                "hint-bridge-topic",
                "bridge-message-filter",
                "topic_family",
                base_height + 57,
            ),
        ] {
            let hint = sample_public_hint(label, subject_id, kind, height);
            state.counters.public_hints += 1;
            state.public_hints.insert(hint.hint_id.clone(), hint);
        }

        state
    }

    pub fn roots(&self) -> Roots {
        let config_root = self.config.root();
        let counters_record = self.counters.public_record();
        let counters_root = root_from_record("FILTER-MARKET-COUNTERS", &counters_record);
        let listing_root = map_root(
            "FILTER-MARKET-LISTINGS",
            self.listings
                .values()
                .map(EncryptedFilterListing::public_record)
                .collect(),
        );
        let subscriber_root = map_root(
            "FILTER-MARKET-SUBSCRIBERS",
            self.subscribers
                .values()
                .map(PrivateSubscriber::public_record)
                .collect(),
        );
        let pq_attestation_root = map_root(
            "FILTER-MARKET-PQ-ATTESTATIONS",
            self.attestations
                .values()
                .map(PqIndexerAttestation::public_record)
                .collect(),
        );
        let purchase_lane_root = map_root(
            "FILTER-MARKET-PURCHASE-LANES",
            self.purchase_lanes
                .values()
                .map(PurchaseLane::public_record)
                .collect(),
        );
        let reservation_root = map_root(
            "FILTER-MARKET-RESERVATIONS",
            self.reservations
                .values()
                .map(FilterReservation::public_record)
                .collect(),
        );
        let ticket_root = map_root(
            "FILTER-MARKET-TICKETS",
            self.tickets
                .values()
                .map(EventMatchingTicket::public_record)
                .collect(),
        );
        let receipt_root = map_root(
            "FILTER-MARKET-RECEIPTS",
            self.receipts
                .values()
                .map(SettlementReceipt::public_record)
                .collect(),
        );
        let rebate_root = map_root(
            "FILTER-MARKET-REBATES",
            self.rebates
                .values()
                .map(RebateCredit::public_record)
                .collect(),
        );
        let privacy_fence_root = map_root(
            "FILTER-MARKET-PRIVACY-FENCES",
            self.privacy_fences
                .values()
                .map(PrivacyFence::public_record)
                .collect(),
        );
        let nullifier_root = map_root(
            "FILTER-MARKET-NULLIFIERS",
            self.nullifiers.iter().map(|value| json!(value)).collect(),
        );
        let public_hint_root = map_root(
            "FILTER-MARKET-PUBLIC-HINTS",
            self.public_hints
                .values()
                .map(PublicHint::public_record)
                .collect(),
        );

        let root_record = json!({
            "protocol_version": self.config.protocol_version,
            "chain_id": CHAIN_ID,
            "height": self.height,
            "epoch": self.epoch,
            "config_root": config_root,
            "counters_root": counters_root,
            "listing_root": listing_root,
            "subscriber_root": subscriber_root,
            "pq_attestation_root": pq_attestation_root,
            "purchase_lane_root": purchase_lane_root,
            "reservation_root": reservation_root,
            "ticket_root": ticket_root,
            "receipt_root": receipt_root,
            "rebate_root": rebate_root,
            "privacy_fence_root": privacy_fence_root,
            "nullifier_root": nullifier_root,
            "public_hint_root": public_hint_root,
        });
        let public_record_root = public_record_root(&root_record);
        let state_root = state_root_from_record(&root_record);

        Roots {
            config_root,
            counters_root,
            listing_root,
            subscriber_root,
            pq_attestation_root,
            purchase_lane_root,
            reservation_root,
            ticket_root,
            receipt_root,
            rebate_root,
            privacy_fence_root,
            nullifier_root,
            public_hint_root,
            public_record_root,
            state_root,
        }
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        json!({
            "protocol_version": self.config.protocol_version,
            "schema_version": self.config.schema_version,
            "chain_id": CHAIN_ID,
            "height": self.height,
            "epoch": self.epoch,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": roots.public_record(),
            "listings": self.listings.values().map(EncryptedFilterListing::public_record).collect::<Vec<_>>(),
            "subscribers": self.subscribers.values().map(PrivateSubscriber::public_record).collect::<Vec<_>>(),
            "attestations": self.attestations.values().map(PqIndexerAttestation::public_record).collect::<Vec<_>>(),
            "purchase_lanes": self.purchase_lanes.values().map(PurchaseLane::public_record).collect::<Vec<_>>(),
            "reservations": self.reservations.values().map(FilterReservation::public_record).collect::<Vec<_>>(),
            "tickets": self.tickets.values().map(EventMatchingTicket::public_record).collect::<Vec<_>>(),
            "receipts": self.receipts.values().map(SettlementReceipt::public_record).collect::<Vec<_>>(),
            "rebates": self.rebates.values().map(RebateCredit::public_record).collect::<Vec<_>>(),
            "privacy_fences": self.privacy_fences.values().map(PrivacyFence::public_record).collect::<Vec<_>>(),
            "nullifiers": self.nullifiers.iter().cloned().collect::<Vec<_>>(),
            "public_hints": self.public_hints.values().map(PublicHint::public_record).collect::<Vec<_>>(),
        })
    }

    pub fn state_root(&self) -> String {
        state_root_from_record(&self.public_record())
    }

    pub fn active_listing_ids(&self) -> Vec<String> {
        self.listings
            .values()
            .filter(|listing| listing.status.marketable())
            .map(|listing| listing.listing_id.clone())
            .collect()
    }

    pub fn active_subscriber_ids(&self) -> Vec<String> {
        self.subscribers
            .values()
            .filter(|subscriber| subscriber.status.can_buy())
            .map(|subscriber| subscriber.subscriber_id.clone())
            .collect()
    }

    pub fn unpaid_ticket_ids(&self) -> Vec<String> {
        self.tickets
            .values()
            .filter(|ticket| ticket.status.payable())
            .map(|ticket| ticket.ticket_id.clone())
            .collect()
    }

    pub fn claimable_rebate_ids(&self) -> Vec<String> {
        self.rebates
            .values()
            .filter(|rebate| rebate.status.claimable())
            .map(|rebate| rebate.rebate_id.clone())
            .collect()
    }
}

pub fn payload_root(payload: &Value) -> String {
    domain_hash(
        "FILTER-MARKET-PAYLOAD-ROOT",
        &[HashPart::Str(CHAIN_ID), HashPart::Json(payload)],
        32,
    )
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
        "FILTER-MARKET-PUBLIC-RECORD-ROOT",
        &[HashPart::Str(CHAIN_ID), HashPart::Json(record)],
        32,
    )
}

pub fn state_root_from_record(record: &Value) -> String {
    domain_hash(
        "FILTER-MARKET-STATE-ROOT",
        &[HashPart::Str(CHAIN_ID), HashPart::Json(record)],
        32,
    )
}

pub fn listing_id(
    seller_commitment: &str,
    contract_commitment: &str,
    category: FilterCategory,
    nonce: u64,
) -> String {
    domain_hash(
        "FILTER-MARKET-LISTING-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(seller_commitment),
            HashPart::Str(contract_commitment),
            HashPart::Str(category.as_str()),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn subscriber_id(
    owner_commitment: &str,
    subscriber_kind: SubscriberKind,
    nonce: u64,
) -> String {
    domain_hash(
        "FILTER-MARKET-SUBSCRIBER-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(owner_commitment),
            HashPart::Str(subscriber_kind.as_str()),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn attestation_id(indexer_commitment: &str, subject_id: &str, subject_root: &str) -> String {
    domain_hash(
        "FILTER-MARKET-ATTESTATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(indexer_commitment),
            HashPart::Str(subject_id),
            HashPart::Str(subject_root),
        ],
        32,
    )
}

pub fn lane_id(listing_id: &str, lane_kind: LaneKind, opened_at_height: u64) -> String {
    domain_hash(
        "FILTER-MARKET-LANE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(listing_id),
            HashPart::Str(lane_kind.as_str()),
            HashPart::Int(opened_at_height as i128),
        ],
        32,
    )
}

pub fn reservation_id(
    lane_id: &str,
    listing_id: &str,
    subscriber_id: &str,
    reservation_nullifier: &str,
) -> String {
    domain_hash(
        "FILTER-MARKET-RESERVATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(lane_id),
            HashPart::Str(listing_id),
            HashPart::Str(subscriber_id),
            HashPart::Str(reservation_nullifier),
        ],
        32,
    )
}

pub fn ticket_id(
    listing_id: &str,
    subscriber_id: &str,
    event_commitment: &str,
    nullifier: &str,
) -> String {
    domain_hash(
        "FILTER-MARKET-TICKET-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(listing_id),
            HashPart::Str(subscriber_id),
            HashPart::Str(event_commitment),
            HashPart::Str(nullifier),
        ],
        32,
    )
}

pub fn receipt_id(ticket_id: &str, settlement_note_root: &str, settled_at_height: u64) -> String {
    domain_hash(
        "FILTER-MARKET-RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(ticket_id),
            HashPart::Str(settlement_note_root),
            HashPart::Int(settled_at_height as i128),
        ],
        32,
    )
}

pub fn rebate_id(receipt_id: &str, beneficiary_commitment: &str, rebate_note_root: &str) -> String {
    domain_hash(
        "FILTER-MARKET-REBATE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(receipt_id),
            HashPart::Str(beneficiary_commitment),
            HashPart::Str(rebate_note_root),
        ],
        32,
    )
}

pub fn nullifier(scope: &str, owner_commitment: &str, secret_root: &str) -> String {
    domain_hash(
        "FILTER-MARKET-NULLIFIER",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(scope),
            HashPart::Str(owner_commitment),
            HashPart::Str(secret_root),
        ],
        32,
    )
}

pub fn fence_id(scope: &str, subject_id: &str, nullifier: &str) -> String {
    domain_hash(
        "FILTER-MARKET-FENCE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(scope),
            HashPart::Str(subject_id),
            HashPart::Str(nullifier),
        ],
        32,
    )
}

pub fn public_hint_id(subject_id: &str, hint_kind: &str, hint_root: &str) -> String {
    domain_hash(
        "FILTER-MARKET-PUBLIC-HINT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(subject_id),
            HashPart::Str(hint_kind),
            HashPart::Str(hint_root),
        ],
        32,
    )
}

pub fn encrypted_payload_root(label: &str, envelope_root: &str, ciphertext_root: &str) -> String {
    domain_hash(
        "FILTER-MARKET-ENCRYPTED-PAYLOAD-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Str(envelope_root),
            HashPart::Str(ciphertext_root),
        ],
        32,
    )
}

pub fn event_commitment(
    contract_commitment: &str,
    topic_root: &str,
    event_payload_root: &str,
) -> String {
    domain_hash(
        "FILTER-MARKET-EVENT-COMMITMENT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(contract_commitment),
            HashPart::Str(topic_root),
            HashPart::Str(event_payload_root),
        ],
        32,
    )
}

fn map_root(domain: &str, leaves: Vec<Value>) -> String {
    merkle_root(domain, &leaves)
}

fn sample_listing(
    label: &str,
    category: FilterCategory,
    predicate_kind: PredicateKind,
    seller_label: &str,
    contract_label: &str,
    height: u64,
    price_piconero: u128,
    max_matches: u64,
) -> EncryptedFilterListing {
    let seller_commitment = label_hash("SELLER-COMMITMENT", seller_label);
    let contract_commitment = label_hash("CONTRACT-COMMITMENT", contract_label);
    let event_namespace_record = json!({
        "label": label,
        "category": category.as_str(),
        "contract": contract_label,
        "topics": ["anonymous_topic_root", "encrypted_selector_root"],
    });
    let event_namespace_root = payload_root(&event_namespace_record);
    let encrypted_predicate_root = encrypted_payload_root(
        label,
        &event_namespace_root,
        &label_hash("FILTER-CIPHERTEXT", label),
    );
    let encrypted_filter_blob_root = encrypted_payload_root(
        &format!("{label}-blob"),
        &encrypted_predicate_root,
        &label_hash("FILTER-BLOB", label),
    );
    let public_hint_root = payload_root(&json!({
        "fee_band": "low",
        "latency_class": "fast",
        "privacy_floor": PRIVATE_L2_CONFIDENTIAL_CONTRACT_EVENT_FILTER_MARKET_RUNTIME_DEFAULT_MIN_PRIVACY_SET,
    }));
    let listing_id = listing_id(&seller_commitment, &contract_commitment, category, height);
    EncryptedFilterListing {
        listing_id,
        seller_commitment,
        category,
        predicate_kind,
        contract_commitment,
        event_namespace_root,
        encrypted_predicate_root,
        encrypted_filter_blob_root,
        public_hint_root,
        price_piconero,
        max_matches,
        filled_matches: 0,
        min_privacy_set:
            PRIVATE_L2_CONFIDENTIAL_CONTRACT_EVENT_FILTER_MARKET_RUNTIME_DEFAULT_MIN_PRIVACY_SET,
        pq_security_bits:
            PRIVATE_L2_CONFIDENTIAL_CONTRACT_EVENT_FILTER_MARKET_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS,
        fee_bps: 8,
        status: ListingStatus::Active,
        created_at_height: height,
        expires_at_height: height
            + PRIVATE_L2_CONFIDENTIAL_CONTRACT_EVENT_FILTER_MARKET_RUNTIME_DEFAULT_LISTING_TTL_BLOCKS,
        metadata: json!({
            "label": label,
            "domain": "monero_l2_confidential_contract_events",
            "use_cases": ["keeper_execution", "private_wallet_alerts", "defi_automation"],
        }),
    }
}

fn sample_subscriber(
    label: &str,
    subscriber_kind: SubscriberKind,
    owner_label: &str,
    height: u64,
) -> PrivateSubscriber {
    let owner_commitment = label_hash("SUBSCRIBER-OWNER", owner_label);
    let viewing_key_commitment = label_hash("VIEWING-KEY", label);
    let pq_kem_public_key_root = label_hash("PQ-KEM-PUBLIC-KEY", label);
    let delivery_address_commitment = label_hash("DELIVERY-ADDRESS", label);
    let spending_limit_root = payload_root(&json!({
        "daily_limit_piconero": "250000000000",
        "max_fee_bps": 12,
        "sponsor_ok": true,
    }));
    let privacy_budget_root = payload_root(&json!({
        "privacy_epoch": 77,
        "min_decoy_set": PRIVATE_L2_CONFIDENTIAL_CONTRACT_EVENT_FILTER_MARKET_RUNTIME_DEFAULT_BATCH_PRIVACY_SET,
        "view_tag_rotation": "per_ticket",
    }));
    let nullifier_scope_root = payload_root(&json!({
        "scope": label,
        "chain_id": CHAIN_ID,
        "suite": PRIVATE_L2_CONFIDENTIAL_CONTRACT_EVENT_FILTER_MARKET_RUNTIME_NULLIFIER_SUITE,
    }));
    PrivateSubscriber {
        subscriber_id: subscriber_id(&owner_commitment, subscriber_kind, height),
        owner_commitment,
        subscriber_kind,
        viewing_key_commitment,
        pq_kem_public_key_root,
        delivery_address_commitment,
        spending_limit_root,
        privacy_budget_root,
        nullifier_scope_root,
        min_privacy_set:
            PRIVATE_L2_CONFIDENTIAL_CONTRACT_EVENT_FILTER_MARKET_RUNTIME_DEFAULT_MIN_PRIVACY_SET,
        pq_security_bits:
            PRIVATE_L2_CONFIDENTIAL_CONTRACT_EVENT_FILTER_MARKET_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS,
        status: SubscriberStatus::Active,
        registered_at_height: height,
        expires_at_height: height
            + PRIVATE_L2_CONFIDENTIAL_CONTRACT_EVENT_FILTER_MARKET_RUNTIME_DEFAULT_LISTING_TTL_BLOCKS,
        metadata: json!({
            "label": label,
            "private_subscriber": true,
            "delivery": "encrypted_view_tag_lane",
        }),
    }
}

fn sample_attestation(
    label: &str,
    attestation_kind: AttestationKind,
    subject_id: &str,
    subject_root: &str,
    height: u64,
) -> PqIndexerAttestation {
    let indexer_commitment = label_hash("INDEXER-COMMITMENT", label);
    let circuit_root = payload_root(&json!({
        "kind": attestation_kind.as_str(),
        "circuit": "confidential_filter_match_v1",
        "public_inputs": ["subject_root", "privacy_floor", "pq_security_bits"],
    }));
    let transcript_root = payload_root(&json!({
        "subject_id": subject_id,
        "subject_root": subject_root,
        "height": height,
    }));
    let pq_public_key_root = label_hash("INDEXER-PQ-PUBLIC-KEY", label);
    let aggregate_signature_root = label_hash("PQ-AGGREGATE-SIGNATURE", label);
    let committee_root = payload_root(&json!({
        "committee": ["indexer-a", "indexer-b", "indexer-c", "indexer-d", "indexer-e"],
        "threshold": 4,
    }));
    PqIndexerAttestation {
        attestation_id: attestation_id(&indexer_commitment, subject_id, subject_root),
        indexer_commitment,
        attestation_kind,
        subject_id: subject_id.to_string(),
        subject_root: subject_root.to_string(),
        circuit_root,
        transcript_root,
        pq_public_key_root,
        aggregate_signature_root,
        committee_root,
        quorum_weight: 5,
        pq_security_bits:
            PRIVATE_L2_CONFIDENTIAL_CONTRACT_EVENT_FILTER_MARKET_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS,
        status: AttestationStatus::QuorumMet,
        attested_at_height: height,
        expires_at_height: height
            + PRIVATE_L2_CONFIDENTIAL_CONTRACT_EVENT_FILTER_MARKET_RUNTIME_DEFAULT_RECEIPT_TTL_BLOCKS,
        metadata: json!({
            "label": label,
            "attestation_suite": PRIVATE_L2_CONFIDENTIAL_CONTRACT_EVENT_FILTER_MARKET_RUNTIME_PQ_ATTESTATION_SUITE,
        }),
    }
}

fn sample_lane(
    label: &str,
    lane_kind: LaneKind,
    listing_label: &str,
    seller_label: &str,
    height: u64,
    capacity: u64,
) -> PurchaseLane {
    let seller_commitment = label_hash("SELLER-COMMITMENT", seller_label);
    let sponsor_commitment = label_hash("LANE-SPONSOR", label);
    let listing_id = label_hash("DEVNET-LISTING-ALIAS", listing_label);
    let reserve_root = payload_root(&json!({
        "lane": label,
        "reserve": "encrypted_capacity_book",
        "capacity": capacity,
    }));
    let fee_quote_root = payload_root(&json!({
        "max_fee_bps": 9,
        "base_fee_piconero": "120000",
        "compressed_batch_discount_bps": 3500,
    }));
    let batch_policy_root = payload_root(&json!({
        "max_batch_matches": 1024,
        "low_fee_priority": true,
        "defi_callback": lane_kind == LaneKind::DefiKeeper,
    }));
    PurchaseLane {
        lane_id: lane_id(&listing_id, lane_kind, height),
        lane_kind,
        listing_id,
        seller_commitment,
        sponsor_commitment,
        reserve_root,
        fee_quote_root,
        batch_policy_root,
        privacy_floor:
            PRIVATE_L2_CONFIDENTIAL_CONTRACT_EVENT_FILTER_MARKET_RUNTIME_DEFAULT_MIN_PRIVACY_SET,
        capacity,
        filled: 0,
        max_fee_bps: 9,
        status: LaneStatus::Open,
        opened_at_height: height,
        expires_at_height: height
            + PRIVATE_L2_CONFIDENTIAL_CONTRACT_EVENT_FILTER_MARKET_RUNTIME_DEFAULT_LISTING_TTL_BLOCKS,
        metadata: json!({
            "label": label,
            "lane_market": "low_fee_confidential_event_filters",
        }),
    }
}

fn sample_reservation(
    label: &str,
    lane_label: &str,
    listing_label: &str,
    subscriber_label: &str,
    buyer_label: &str,
    height: u64,
    amount_piconero: u128,
) -> FilterReservation {
    let lane_id = label_hash("DEVNET-LANE-ALIAS", lane_label);
    let listing_id = label_hash("DEVNET-LISTING-ALIAS", listing_label);
    let subscriber_id = label_hash("DEVNET-SUBSCRIBER-ALIAS", subscriber_label);
    let buyer_commitment = label_hash("BUYER-COMMITMENT", buyer_label);
    let secret_root = label_hash("RESERVATION-SECRET", label);
    let reservation_nullifier = nullifier("reservation", &buyer_commitment, &secret_root);
    let encrypted_payment_note_root = encrypted_payload_root(
        label,
        &label_hash("PAYMENT-ENVELOPE", label),
        &label_hash("PAYMENT-CIPHERTEXT", label),
    );
    FilterReservation {
        reservation_id: reservation_id(&lane_id, &listing_id, &subscriber_id, &reservation_nullifier),
        lane_id,
        listing_id,
        subscriber_id,
        buyer_commitment,
        reservation_nullifier,
        encrypted_payment_note_root,
        amount_piconero,
        fee_bps: 8,
        reserved_matches: 256,
        reserved_at_height: height,
        expires_at_height: height
            + PRIVATE_L2_CONFIDENTIAL_CONTRACT_EVENT_FILTER_MARKET_RUNTIME_DEFAULT_RESERVATION_TTL_BLOCKS,
        metadata: json!({
            "label": label,
            "reservation_lane": lane_label,
            "privacy_fence": true,
        }),
    }
}

fn sample_ticket(
    label: &str,
    lane_label: &str,
    listing_label: &str,
    subscriber_label: &str,
    reservation_label: &str,
    height: u64,
    fee_piconero: u128,
) -> EventMatchingTicket {
    let lane_id = label_hash("DEVNET-LANE-ALIAS", lane_label);
    let listing_id = label_hash("DEVNET-LISTING-ALIAS", listing_label);
    let subscriber_id = label_hash("DEVNET-SUBSCRIBER-ALIAS", subscriber_label);
    let reservation_id = label_hash("DEVNET-RESERVATION-ALIAS", reservation_label);
    let topic_root = label_hash("EVENT-TOPIC-ROOT", label);
    let event_payload_root = payload_root(&json!({
        "label": label,
        "encrypted_event": true,
        "defi_callback": listing_label.contains("liquidation"),
    }));
    let event_commitment = event_commitment(&listing_id, &topic_root, &event_payload_root);
    let match_proof_root = payload_root(&json!({
        "circuit": "confidential_event_filter_match_v1",
        "event_commitment": event_commitment,
        "listing_alias": listing_label,
    }));
    let encrypted_delivery_root = encrypted_payload_root(
        label,
        &label_hash("DELIVERY-ENVELOPE", label),
        &label_hash("DELIVERY-CIPHERTEXT", label),
    );
    let reveal_hint_root = payload_root(&json!({
        "view_tag": label_hash("VIEW-TAG", label),
        "batch_bucket": "devnet-fast-lane",
    }));
    let secret_root = label_hash("TICKET-SECRET", label);
    let nullifier = nullifier("ticket", &subscriber_id, &secret_root);
    EventMatchingTicket {
        ticket_id: ticket_id(&listing_id, &subscriber_id, &event_commitment, &nullifier),
        lane_id,
        listing_id,
        subscriber_id,
        reservation_id,
        event_commitment,
        match_proof_root,
        encrypted_delivery_root,
        reveal_hint_root,
        nullifier,
        fee_piconero,
        match_score_microunits: 999_000,
        status: TicketStatus::Delivered,
        matched_at_height: height,
        expires_at_height: height
            + PRIVATE_L2_CONFIDENTIAL_CONTRACT_EVENT_FILTER_MARKET_RUNTIME_DEFAULT_TICKET_TTL_BLOCKS,
        metadata: json!({
            "label": label,
            "matching": "private_indexer_ticket",
            "low_fee_batchable": true,
        }),
    }
}

fn sample_receipt(
    label: &str,
    ticket_label: &str,
    lane_label: &str,
    listing_label: &str,
    subscriber_label: &str,
    seller_label: &str,
    height: u64,
    paid_piconero: u128,
) -> SettlementReceipt {
    let ticket_id = label_hash("DEVNET-TICKET-ALIAS", ticket_label);
    let lane_id = label_hash("DEVNET-LANE-ALIAS", lane_label);
    let listing_id = label_hash("DEVNET-LISTING-ALIAS", listing_label);
    let subscriber_id = label_hash("DEVNET-SUBSCRIBER-ALIAS", subscriber_label);
    let seller_commitment = label_hash("SELLER-COMMITMENT", seller_label);
    let indexer_commitment = label_hash("INDEXER-COMMITMENT", label);
    let settlement_note_root = encrypted_payload_root(
        label,
        &label_hash("SETTLEMENT-ENVELOPE", label),
        &label_hash("SETTLEMENT-CIPHERTEXT", label),
    );
    let delivery_receipt_root = payload_root(&json!({
        "ticket": ticket_label,
        "delivery": "encrypted",
        "subscriber": subscriber_label,
    }));
    let fee_split_root = payload_root(&json!({
        "seller_bps": 8500,
        "indexer_bps": 900,
        "protocol_bps": 600,
    }));
    let state_transition_root = payload_root(&json!({
        "listing": listing_label,
        "ticket": ticket_label,
        "settled_height": height,
    }));
    let indexer_fee_piconero = paid_piconero * 9 / 100;
    let protocol_fee_piconero = paid_piconero * 6 / 100;
    SettlementReceipt {
        receipt_id: receipt_id(&ticket_id, &settlement_note_root, height),
        ticket_id,
        lane_id,
        listing_id,
        subscriber_id,
        seller_commitment,
        indexer_commitment,
        settlement_note_root,
        delivery_receipt_root,
        fee_split_root,
        state_transition_root,
        paid_piconero,
        indexer_fee_piconero,
        protocol_fee_piconero,
        status: ReceiptStatus::Rebatable,
        settled_at_height: height,
        metadata: json!({
            "label": label,
            "settlement": "roots_only_confidential_fee_split",
        }),
    }
}

fn sample_rebate(
    label: &str,
    receipt_label: &str,
    beneficiary_label: &str,
    height: u64,
    amount_piconero: u128,
) -> RebateCredit {
    let receipt_id = label_hash("DEVNET-RECEIPT-ALIAS", receipt_label);
    let beneficiary_commitment = label_hash("REBATE-BENEFICIARY", beneficiary_label);
    let rebate_note_root = encrypted_payload_root(
        label,
        &label_hash("REBATE-ENVELOPE", label),
        &label_hash("REBATE-CIPHERTEXT", label),
    );
    let reason_root = payload_root(&json!({
        "reason": "batch_compression_discount",
        "low_fee_market": true,
    }));
    RebateCredit {
        rebate_id: rebate_id(&receipt_id, &beneficiary_commitment, &rebate_note_root),
        receipt_id,
        beneficiary_commitment,
        rebate_note_root,
        reason_root,
        amount_piconero,
        status: RebateStatus::Claimable,
        accrued_at_height: height,
        expires_at_height: height
            + PRIVATE_L2_CONFIDENTIAL_CONTRACT_EVENT_FILTER_MARKET_RUNTIME_DEFAULT_RECEIPT_TTL_BLOCKS,
        metadata: json!({
            "label": label,
            "rebate_source": "low_fee_private_batch",
        }),
    }
}

fn sample_fence(label: &str, scope: &str, subject_id: &str, height: u64) -> PrivacyFence {
    let commitment_root = label_hash("FENCE-COMMITMENT", label);
    let privacy_set_root = payload_root(&json!({
        "scope": scope,
        "subject_id": subject_id,
        "privacy_floor": PRIVATE_L2_CONFIDENTIAL_CONTRACT_EVENT_FILTER_MARKET_RUNTIME_DEFAULT_BATCH_PRIVACY_SET,
    }));
    let secret_root = label_hash("FENCE-SECRET", label);
    let nullifier = nullifier(scope, subject_id, &secret_root);
    PrivacyFence {
        fence_id: fence_id(scope, subject_id, &nullifier),
        scope: scope.to_string(),
        subject_id: subject_id.to_string(),
        nullifier,
        commitment_root,
        privacy_set_root,
        min_privacy_set:
            PRIVATE_L2_CONFIDENTIAL_CONTRACT_EVENT_FILTER_MARKET_RUNTIME_DEFAULT_BATCH_PRIVACY_SET,
        opened_at_height: height,
        expires_at_height: height
            + PRIVATE_L2_CONFIDENTIAL_CONTRACT_EVENT_FILTER_MARKET_RUNTIME_DEFAULT_RECEIPT_TTL_BLOCKS,
        metadata: json!({
            "label": label,
            "fence": "nullifier_and_privacy_set",
        }),
    }
}

fn sample_public_hint(label: &str, subject_id: &str, hint_kind: &str, height: u64) -> PublicHint {
    let hint_root = payload_root(&json!({
        "label": label,
        "subject_id": subject_id,
        "hint_kind": hint_kind,
        "coarse_only": true,
    }));
    PublicHint {
        hint_id: public_hint_id(subject_id, hint_kind, &hint_root),
        subject_id: subject_id.to_string(),
        hint_kind: hint_kind.to_string(),
        hint_root,
        fee_hint_microunits: 1_250,
        privacy_band:
            PRIVATE_L2_CONFIDENTIAL_CONTRACT_EVENT_FILTER_MARKET_RUNTIME_DEFAULT_MIN_PRIVACY_SET,
        posted_at_height: height,
        metadata: json!({
            "label": label,
            "public_record": "coarse_market_hint",
        }),
    }
}

fn label_hash(domain: &str, label: &str) -> String {
    domain_hash(domain, &[HashPart::Str(CHAIN_ID), HashPart::Str(label)], 32)
}
