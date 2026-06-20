use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2ConfidentialContractEventSubscriptionRuntimeResult<T> = Result<T, String>;

pub const PRIVATE_L2_CONFIDENTIAL_CONTRACT_EVENT_SUBSCRIPTION_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-confidential-contract-event-subscription-runtime-v1";
pub const PRIVATE_L2_CONFIDENTIAL_CONTRACT_EVENT_SUBSCRIPTION_RUNTIME_SCHEMA_VERSION: u64 = 1;
pub const PRIVATE_L2_CONFIDENTIAL_CONTRACT_EVENT_SUBSCRIPTION_RUNTIME_HASH_SUITE: &str =
    "SHAKE256-domain-separated-canonical-json";
pub const PRIVATE_L2_CONFIDENTIAL_CONTRACT_EVENT_SUBSCRIPTION_RUNTIME_PQ_AUTH_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-contract-event-subscription-v1";
pub const PRIVATE_L2_CONFIDENTIAL_CONTRACT_EVENT_SUBSCRIPTION_RUNTIME_EVENT_ENCRYPTION_SUITE: &str =
    "ML-KEM-1024+Poseidon2-transcript+AEAD-confidential-event-delivery-v1";
pub const PRIVATE_L2_CONFIDENTIAL_CONTRACT_EVENT_SUBSCRIPTION_RUNTIME_DEVNET_HEIGHT: u64 = 972_000;
pub const PRIVATE_L2_CONFIDENTIAL_CONTRACT_EVENT_SUBSCRIPTION_RUNTIME_MAX_BPS: u64 = 10_000;
pub const PRIVATE_L2_CONFIDENTIAL_CONTRACT_EVENT_SUBSCRIPTION_RUNTIME_DEFAULT_MAX_STREAMS: usize =
    2_097_152;
pub const PRIVATE_L2_CONFIDENTIAL_CONTRACT_EVENT_SUBSCRIPTION_RUNTIME_DEFAULT_MAX_FILTERS: usize =
    16_777_216;
pub const PRIVATE_L2_CONFIDENTIAL_CONTRACT_EVENT_SUBSCRIPTION_RUNTIME_DEFAULT_MAX_SUBSCRIBERS:
    usize = 8_388_608;
pub const PRIVATE_L2_CONFIDENTIAL_CONTRACT_EVENT_SUBSCRIPTION_RUNTIME_DEFAULT_MAX_ATTESTATIONS:
    usize = 16_777_216;
pub const PRIVATE_L2_CONFIDENTIAL_CONTRACT_EVENT_SUBSCRIPTION_RUNTIME_DEFAULT_MAX_EVENTS: usize =
    134_217_728;
pub const PRIVATE_L2_CONFIDENTIAL_CONTRACT_EVENT_SUBSCRIPTION_RUNTIME_DEFAULT_MAX_RESERVATIONS:
    usize = 8_388_608;
pub const PRIVATE_L2_CONFIDENTIAL_CONTRACT_EVENT_SUBSCRIPTION_RUNTIME_DEFAULT_MAX_BATCHES: usize =
    4_194_304;
pub const PRIVATE_L2_CONFIDENTIAL_CONTRACT_EVENT_SUBSCRIPTION_RUNTIME_DEFAULT_MAX_RECEIPTS: usize =
    134_217_728;
pub const PRIVATE_L2_CONFIDENTIAL_CONTRACT_EVENT_SUBSCRIPTION_RUNTIME_DEFAULT_MAX_REBATES: usize =
    8_388_608;
pub const PRIVATE_L2_CONFIDENTIAL_CONTRACT_EVENT_SUBSCRIPTION_RUNTIME_DEFAULT_MAX_NULLIFIERS:
    usize = 134_217_728;
pub const PRIVATE_L2_CONFIDENTIAL_CONTRACT_EVENT_SUBSCRIPTION_RUNTIME_DEFAULT_MAX_BATCH_EVENTS:
    usize = 8_192;
pub const PRIVATE_L2_CONFIDENTIAL_CONTRACT_EVENT_SUBSCRIPTION_RUNTIME_DEFAULT_MIN_PRIVACY_SET: u64 =
    32_768;
pub const PRIVATE_L2_CONFIDENTIAL_CONTRACT_EVENT_SUBSCRIPTION_RUNTIME_DEFAULT_BATCH_PRIVACY_SET:
    u64 = 524_288;
pub const PRIVATE_L2_CONFIDENTIAL_CONTRACT_EVENT_SUBSCRIPTION_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS:
    u16 = 256;
pub const PRIVATE_L2_CONFIDENTIAL_CONTRACT_EVENT_SUBSCRIPTION_RUNTIME_DEFAULT_MAX_INDEXER_FEE_BPS:
    u64 = 9;
pub const PRIVATE_L2_CONFIDENTIAL_CONTRACT_EVENT_SUBSCRIPTION_RUNTIME_DEFAULT_MAX_DELIVERY_FEE_BPS:
    u64 = 7;
pub const PRIVATE_L2_CONFIDENTIAL_CONTRACT_EVENT_SUBSCRIPTION_RUNTIME_DEFAULT_MAX_SPONSOR_FEE_BPS:
    u64 = 6;
pub const PRIVATE_L2_CONFIDENTIAL_CONTRACT_EVENT_SUBSCRIPTION_RUNTIME_DEFAULT_TARGET_REBATE_BPS:
    u64 = 5;
pub const PRIVATE_L2_CONFIDENTIAL_CONTRACT_EVENT_SUBSCRIPTION_RUNTIME_DEFAULT_STREAM_TTL_BLOCKS:
    u64 = 86_400;
pub const PRIVATE_L2_CONFIDENTIAL_CONTRACT_EVENT_SUBSCRIPTION_RUNTIME_DEFAULT_FILTER_TTL_BLOCKS:
    u64 = 21_600;
pub const PRIVATE_L2_CONFIDENTIAL_CONTRACT_EVENT_SUBSCRIPTION_RUNTIME_DEFAULT_RESERVATION_TTL_BLOCKS:
    u64 = 96;
pub const PRIVATE_L2_CONFIDENTIAL_CONTRACT_EVENT_SUBSCRIPTION_RUNTIME_DEFAULT_BATCH_TTL_BLOCKS:
    u64 = 48;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ContractEventStreamKind {
    TokenTransfer,
    DexSwap,
    LendingPosition,
    PerpetualFunding,
    BridgeMessage,
    GovernanceVote,
    OracleUpdate,
    AccountAbstraction,
    Custom,
}

impl ContractEventStreamKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::TokenTransfer => "token_transfer",
            Self::DexSwap => "dex_swap",
            Self::LendingPosition => "lending_position",
            Self::PerpetualFunding => "perpetual_funding",
            Self::BridgeMessage => "bridge_message",
            Self::GovernanceVote => "governance_vote",
            Self::OracleUpdate => "oracle_update",
            Self::AccountAbstraction => "account_abstraction",
            Self::Custom => "custom",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StreamStatus {
    Proposed,
    Active,
    Paused,
    Draining,
    Retired,
}

impl StreamStatus {
    pub fn accepts_events(self) -> bool {
        matches!(self, Self::Active | Self::Draining)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::Active => "active",
            Self::Paused => "paused",
            Self::Draining => "draining",
            Self::Retired => "retired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FilterKind {
    TopicSet,
    ContractSelector,
    EncryptedPredicate,
    AmountBand,
    AddressShield,
    StorageSlot,
    ReceiptField,
    Composite,
}

impl FilterKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::TopicSet => "topic_set",
            Self::ContractSelector => "contract_selector",
            Self::EncryptedPredicate => "encrypted_predicate",
            Self::AmountBand => "amount_band",
            Self::AddressShield => "address_shield",
            Self::StorageSlot => "storage_slot",
            Self::ReceiptField => "receipt_field",
            Self::Composite => "composite",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FilterStatus {
    Encrypted,
    Attested,
    Active,
    Paused,
    Expired,
    Revoked,
}

impl FilterStatus {
    pub fn is_active(self) -> bool {
        matches!(self, Self::Attested | Self::Active)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SubscriberKind {
    Wallet,
    Relayer,
    ContractAgent,
    Liquidator,
    MarketMaker,
    BridgeWatcher,
    GovernanceDelegate,
    AnalyticsVault,
}

impl SubscriberKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Wallet => "wallet",
            Self::Relayer => "relayer",
            Self::ContractAgent => "contract_agent",
            Self::Liquidator => "liquidator",
            Self::MarketMaker => "market_maker",
            Self::BridgeWatcher => "bridge_watcher",
            Self::GovernanceDelegate => "governance_delegate",
            Self::AnalyticsVault => "analytics_vault",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SubscriberStatus {
    Registered,
    Active,
    RateLimited,
    Paused,
    Revoked,
    Expired,
}

impl SubscriberStatus {
    pub fn can_receive(self) -> bool {
        matches!(self, Self::Registered | Self::Active | Self::RateLimited)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationKind {
    PqSubscriberKey,
    PqIndexerKey,
    FilterWellFormedness,
    ReplayFence,
    DeliveryKeyRotation,
    SponsorAuthorization,
    CrossDomainCursor,
    EmergencyRecovery,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationVerdict {
    Valid,
    ValidWithWarning,
    NeedsMoreWitnesses,
    Quarantined,
    Invalid,
    Revoked,
}

impl AttestationVerdict {
    pub fn contributes_to_quorum(self) -> bool {
        matches!(self, Self::Valid | Self::ValidWithWarning)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EventCommitmentStatus {
    Observed,
    Indexed,
    Matched,
    Batched,
    Delivered,
    Withheld,
    Disputed,
    Expired,
}

impl EventCommitmentStatus {
    pub fn is_deliverable(self) -> bool {
        matches!(self, Self::Indexed | Self::Matched | Self::Batched)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReservationStatus {
    Reserved,
    BoundToFilter,
    Consumed,
    RebateQueued,
    Released,
    Expired,
    Slashed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DeliveryBatchStatus {
    Open,
    Sealed,
    Posted,
    Delivered,
    PartiallyDelivered,
    Disputed,
    Expired,
}

impl DeliveryBatchStatus {
    pub fn anchors_state(self) -> bool {
        matches!(self, Self::Sealed | Self::Posted | Self::Delivered)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptKind {
    EventDelivery,
    FilterDebit,
    IndexerCredit,
    SponsorSettlement,
    RebateCredit,
    DisputeResolution,
    CursorAdvance,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RebateStatus {
    Pending,
    Claimable,
    Claimed,
    DonatedToBatch,
    Expired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NullifierFenceStatus {
    Open,
    Locked,
    Spent,
    Disputed,
    Released,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CursorKind {
    ContractHeight,
    ReceiptIndex,
    EventSequence,
    BridgeMessageIndex,
    OracleRound,
    GovernanceEpoch,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub schema_version: u64,
    pub devnet_height: u64,
    pub fee_asset_id: String,
    pub max_streams: usize,
    pub max_filters: usize,
    pub max_subscribers: usize,
    pub max_attestations: usize,
    pub max_events: usize,
    pub max_reservations: usize,
    pub max_batches: usize,
    pub max_receipts: usize,
    pub max_rebates: usize,
    pub max_nullifiers: usize,
    pub max_batch_events: usize,
    pub min_privacy_set_size: u64,
    pub batch_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub max_indexer_fee_bps: u64,
    pub max_delivery_fee_bps: u64,
    pub max_sponsor_fee_bps: u64,
    pub target_rebate_bps: u64,
    pub stream_ttl_blocks: u64,
    pub filter_ttl_blocks: u64,
    pub reservation_ttl_blocks: u64,
    pub batch_ttl_blocks: u64,
    pub hash_suite: String,
    pub pq_auth_suite: String,
    pub event_encryption_suite: String,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            schema_version: PRIVATE_L2_CONFIDENTIAL_CONTRACT_EVENT_SUBSCRIPTION_RUNTIME_SCHEMA_VERSION,
            devnet_height: PRIVATE_L2_CONFIDENTIAL_CONTRACT_EVENT_SUBSCRIPTION_RUNTIME_DEVNET_HEIGHT,
            fee_asset_id: "nebula-l2-confidential-fee-credit".to_string(),
            max_streams:
                PRIVATE_L2_CONFIDENTIAL_CONTRACT_EVENT_SUBSCRIPTION_RUNTIME_DEFAULT_MAX_STREAMS,
            max_filters:
                PRIVATE_L2_CONFIDENTIAL_CONTRACT_EVENT_SUBSCRIPTION_RUNTIME_DEFAULT_MAX_FILTERS,
            max_subscribers:
                PRIVATE_L2_CONFIDENTIAL_CONTRACT_EVENT_SUBSCRIPTION_RUNTIME_DEFAULT_MAX_SUBSCRIBERS,
            max_attestations:
                PRIVATE_L2_CONFIDENTIAL_CONTRACT_EVENT_SUBSCRIPTION_RUNTIME_DEFAULT_MAX_ATTESTATIONS,
            max_events:
                PRIVATE_L2_CONFIDENTIAL_CONTRACT_EVENT_SUBSCRIPTION_RUNTIME_DEFAULT_MAX_EVENTS,
            max_reservations:
                PRIVATE_L2_CONFIDENTIAL_CONTRACT_EVENT_SUBSCRIPTION_RUNTIME_DEFAULT_MAX_RESERVATIONS,
            max_batches:
                PRIVATE_L2_CONFIDENTIAL_CONTRACT_EVENT_SUBSCRIPTION_RUNTIME_DEFAULT_MAX_BATCHES,
            max_receipts:
                PRIVATE_L2_CONFIDENTIAL_CONTRACT_EVENT_SUBSCRIPTION_RUNTIME_DEFAULT_MAX_RECEIPTS,
            max_rebates:
                PRIVATE_L2_CONFIDENTIAL_CONTRACT_EVENT_SUBSCRIPTION_RUNTIME_DEFAULT_MAX_REBATES,
            max_nullifiers:
                PRIVATE_L2_CONFIDENTIAL_CONTRACT_EVENT_SUBSCRIPTION_RUNTIME_DEFAULT_MAX_NULLIFIERS,
            max_batch_events:
                PRIVATE_L2_CONFIDENTIAL_CONTRACT_EVENT_SUBSCRIPTION_RUNTIME_DEFAULT_MAX_BATCH_EVENTS,
            min_privacy_set_size:
                PRIVATE_L2_CONFIDENTIAL_CONTRACT_EVENT_SUBSCRIPTION_RUNTIME_DEFAULT_MIN_PRIVACY_SET,
            batch_privacy_set_size:
                PRIVATE_L2_CONFIDENTIAL_CONTRACT_EVENT_SUBSCRIPTION_RUNTIME_DEFAULT_BATCH_PRIVACY_SET,
            min_pq_security_bits:
                PRIVATE_L2_CONFIDENTIAL_CONTRACT_EVENT_SUBSCRIPTION_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS,
            max_indexer_fee_bps:
                PRIVATE_L2_CONFIDENTIAL_CONTRACT_EVENT_SUBSCRIPTION_RUNTIME_DEFAULT_MAX_INDEXER_FEE_BPS,
            max_delivery_fee_bps:
                PRIVATE_L2_CONFIDENTIAL_CONTRACT_EVENT_SUBSCRIPTION_RUNTIME_DEFAULT_MAX_DELIVERY_FEE_BPS,
            max_sponsor_fee_bps:
                PRIVATE_L2_CONFIDENTIAL_CONTRACT_EVENT_SUBSCRIPTION_RUNTIME_DEFAULT_MAX_SPONSOR_FEE_BPS,
            target_rebate_bps:
                PRIVATE_L2_CONFIDENTIAL_CONTRACT_EVENT_SUBSCRIPTION_RUNTIME_DEFAULT_TARGET_REBATE_BPS,
            stream_ttl_blocks:
                PRIVATE_L2_CONFIDENTIAL_CONTRACT_EVENT_SUBSCRIPTION_RUNTIME_DEFAULT_STREAM_TTL_BLOCKS,
            filter_ttl_blocks:
                PRIVATE_L2_CONFIDENTIAL_CONTRACT_EVENT_SUBSCRIPTION_RUNTIME_DEFAULT_FILTER_TTL_BLOCKS,
            reservation_ttl_blocks:
                PRIVATE_L2_CONFIDENTIAL_CONTRACT_EVENT_SUBSCRIPTION_RUNTIME_DEFAULT_RESERVATION_TTL_BLOCKS,
            batch_ttl_blocks:
                PRIVATE_L2_CONFIDENTIAL_CONTRACT_EVENT_SUBSCRIPTION_RUNTIME_DEFAULT_BATCH_TTL_BLOCKS,
            hash_suite:
                PRIVATE_L2_CONFIDENTIAL_CONTRACT_EVENT_SUBSCRIPTION_RUNTIME_HASH_SUITE.to_string(),
            pq_auth_suite:
                PRIVATE_L2_CONFIDENTIAL_CONTRACT_EVENT_SUBSCRIPTION_RUNTIME_PQ_AUTH_SUITE.to_string(),
            event_encryption_suite:
                PRIVATE_L2_CONFIDENTIAL_CONTRACT_EVENT_SUBSCRIPTION_RUNTIME_EVENT_ENCRYPTION_SUITE
                    .to_string(),
        }
    }

    pub fn policy_record(&self) -> Value {
        json!({
            "schema_version": self.schema_version,
            "devnet_height": self.devnet_height,
            "fee_asset_id": self.fee_asset_id,
            "limits": {
                "max_streams": self.max_streams,
                "max_filters": self.max_filters,
                "max_subscribers": self.max_subscribers,
                "max_attestations": self.max_attestations,
                "max_events": self.max_events,
                "max_reservations": self.max_reservations,
                "max_batches": self.max_batches,
                "max_receipts": self.max_receipts,
                "max_rebates": self.max_rebates,
                "max_nullifiers": self.max_nullifiers,
                "max_batch_events": self.max_batch_events,
            },
            "privacy": {
                "min_privacy_set_size": self.min_privacy_set_size,
                "batch_privacy_set_size": self.batch_privacy_set_size,
                "min_pq_security_bits": self.min_pq_security_bits,
            },
            "fees": {
                "max_indexer_fee_bps": self.max_indexer_fee_bps,
                "max_delivery_fee_bps": self.max_delivery_fee_bps,
                "max_sponsor_fee_bps": self.max_sponsor_fee_bps,
                "target_rebate_bps": self.target_rebate_bps,
            },
            "ttls": {
                "stream_ttl_blocks": self.stream_ttl_blocks,
                "filter_ttl_blocks": self.filter_ttl_blocks,
                "reservation_ttl_blocks": self.reservation_ttl_blocks,
                "batch_ttl_blocks": self.batch_ttl_blocks,
            },
            "suites": {
                "hash_suite": self.hash_suite,
                "pq_auth_suite": self.pq_auth_suite,
                "event_encryption_suite": self.event_encryption_suite,
            }
        })
    }

    pub fn policy_root(&self) -> String {
        payload_root("contract-event-subscription:config", &self.policy_record())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub stream_count: u64,
    pub filter_count: u64,
    pub subscriber_count: u64,
    pub attestation_count: u64,
    pub event_count: u64,
    pub reservation_count: u64,
    pub batch_count: u64,
    pub receipt_count: u64,
    pub rebate_count: u64,
    pub nullifier_count: u64,
    pub cursor_checkpoint_count: u64,
    pub quorum_round_count: u64,
    pub lane_metric_count: u64,
    pub total_reserved_fee: u128,
    pub total_delivered_fee: u128,
    pub total_rebate_amount: u128,
}

impl Counters {
    pub fn record(&self) -> Value {
        json!({
            "stream_count": self.stream_count,
            "filter_count": self.filter_count,
            "subscriber_count": self.subscriber_count,
            "attestation_count": self.attestation_count,
            "event_count": self.event_count,
            "reservation_count": self.reservation_count,
            "batch_count": self.batch_count,
            "receipt_count": self.receipt_count,
            "rebate_count": self.rebate_count,
            "nullifier_count": self.nullifier_count,
            "cursor_checkpoint_count": self.cursor_checkpoint_count,
            "quorum_round_count": self.quorum_round_count,
            "lane_metric_count": self.lane_metric_count,
            "total_reserved_fee": self.total_reserved_fee.to_string(),
            "total_delivered_fee": self.total_delivered_fee.to_string(),
            "total_rebate_amount": self.total_rebate_amount.to_string(),
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub stream_root: String,
    pub filter_root: String,
    pub subscriber_root: String,
    pub attestation_root: String,
    pub event_root: String,
    pub reservation_root: String,
    pub batch_root: String,
    pub receipt_root: String,
    pub rebate_root: String,
    pub nullifier_root: String,
    pub cursor_root: String,
    pub quorum_root: String,
    pub lane_metric_root: String,
    pub counter_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn without_state_root(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "stream_root": self.stream_root,
            "filter_root": self.filter_root,
            "subscriber_root": self.subscriber_root,
            "attestation_root": self.attestation_root,
            "event_root": self.event_root,
            "reservation_root": self.reservation_root,
            "batch_root": self.batch_root,
            "receipt_root": self.receipt_root,
            "rebate_root": self.rebate_root,
            "nullifier_root": self.nullifier_root,
            "cursor_root": self.cursor_root,
            "quorum_root": self.quorum_root,
            "lane_metric_root": self.lane_metric_root,
            "counter_root": self.counter_root,
        })
    }

    pub fn record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "stream_root": self.stream_root,
            "filter_root": self.filter_root,
            "subscriber_root": self.subscriber_root,
            "attestation_root": self.attestation_root,
            "event_root": self.event_root,
            "reservation_root": self.reservation_root,
            "batch_root": self.batch_root,
            "receipt_root": self.receipt_root,
            "rebate_root": self.rebate_root,
            "nullifier_root": self.nullifier_root,
            "cursor_root": self.cursor_root,
            "quorum_root": self.quorum_root,
            "lane_metric_root": self.lane_metric_root,
            "counter_root": self.counter_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ContractEventStream {
    pub stream_id: String,
    pub contract_address_commitment: String,
    pub deployment_domain: String,
    pub event_kind: ContractEventStreamKind,
    pub topic_commitment_root: String,
    pub decoder_commitment: String,
    pub indexer_committee_root: String,
    pub cursor_kind: CursorKind,
    pub status: StreamStatus,
    pub min_confirmations: u64,
    pub min_privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub created_at_height: u64,
    pub expires_at_height: u64,
    pub fee_bps: u64,
    pub metadata_commitment: String,
}

impl ContractEventStream {
    pub fn record(&self) -> Value {
        json!({
            "stream_id": self.stream_id,
            "contract_address_commitment": self.contract_address_commitment,
            "deployment_domain": self.deployment_domain,
            "event_kind": self.event_kind,
            "topic_commitment_root": self.topic_commitment_root,
            "decoder_commitment": self.decoder_commitment,
            "indexer_committee_root": self.indexer_committee_root,
            "cursor_kind": self.cursor_kind,
            "status": self.status,
            "min_confirmations": self.min_confirmations,
            "min_privacy_set_size": self.min_privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
            "fee_bps": self.fee_bps,
            "metadata_commitment": self.metadata_commitment,
        })
    }

    pub fn commitment(&self) -> String {
        root_from_record("contract-event-subscription:stream", &self.record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EventFilterCiphertext {
    pub filter_id: String,
    pub stream_id: String,
    pub subscriber_id: String,
    pub filter_kind: FilterKind,
    pub encrypted_filter_payload: String,
    pub filter_key_commitment: String,
    pub topic_mask_commitment: String,
    pub predicate_commitment: String,
    pub cursor_start_commitment: String,
    pub nullifier_domain: String,
    pub status: FilterStatus,
    pub max_events_per_batch: u64,
    pub max_delivery_fee_bps: u64,
    pub created_at_height: u64,
    pub expires_at_height: u64,
}

impl EventFilterCiphertext {
    pub fn record(&self) -> Value {
        json!({
            "filter_id": self.filter_id,
            "stream_id": self.stream_id,
            "subscriber_id": self.subscriber_id,
            "filter_kind": self.filter_kind,
            "encrypted_filter_payload": self.encrypted_filter_payload,
            "filter_key_commitment": self.filter_key_commitment,
            "topic_mask_commitment": self.topic_mask_commitment,
            "predicate_commitment": self.predicate_commitment,
            "cursor_start_commitment": self.cursor_start_commitment,
            "nullifier_domain": self.nullifier_domain,
            "status": self.status,
            "max_events_per_batch": self.max_events_per_batch,
            "max_delivery_fee_bps": self.max_delivery_fee_bps,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn commitment(&self) -> String {
        root_from_record("contract-event-subscription:filter", &self.record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SubscriberProfile {
    pub subscriber_id: String,
    pub subscriber_kind: SubscriberKind,
    pub pq_delivery_key_commitment: String,
    pub pq_signing_key_commitment: String,
    pub wallet_view_tag_commitment: String,
    pub settlement_address_commitment: String,
    pub rate_limit_commitment: String,
    pub status: SubscriberStatus,
    pub min_privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub created_at_height: u64,
    pub key_rotation_nonce: u64,
}

impl SubscriberProfile {
    pub fn record(&self) -> Value {
        json!({
            "subscriber_id": self.subscriber_id,
            "subscriber_kind": self.subscriber_kind,
            "pq_delivery_key_commitment": self.pq_delivery_key_commitment,
            "pq_signing_key_commitment": self.pq_signing_key_commitment,
            "wallet_view_tag_commitment": self.wallet_view_tag_commitment,
            "settlement_address_commitment": self.settlement_address_commitment,
            "rate_limit_commitment": self.rate_limit_commitment,
            "status": self.status,
            "min_privacy_set_size": self.min_privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "created_at_height": self.created_at_height,
            "key_rotation_nonce": self.key_rotation_nonce,
        })
    }

    pub fn commitment(&self) -> String {
        root_from_record("contract-event-subscription:subscriber", &self.record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SubscriberAttestation {
    pub attestation_id: String,
    pub subscriber_id: String,
    pub filter_id: String,
    pub kind: AttestationKind,
    pub verdict: AttestationVerdict,
    pub attester_commitment: String,
    pub attestation_root: String,
    pub transcript_root: String,
    pub pq_signature_commitment: String,
    pub observed_at_height: u64,
    pub expires_at_height: u64,
}

impl SubscriberAttestation {
    pub fn record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "subscriber_id": self.subscriber_id,
            "filter_id": self.filter_id,
            "kind": self.kind,
            "verdict": self.verdict,
            "attester_commitment": self.attester_commitment,
            "attestation_root": self.attestation_root,
            "transcript_root": self.transcript_root,
            "pq_signature_commitment": self.pq_signature_commitment,
            "observed_at_height": self.observed_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn commitment(&self) -> String {
        root_from_record("contract-event-subscription:attestation", &self.record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ContractEventCommitment {
    pub event_id: String,
    pub stream_id: String,
    pub event_sequence: u64,
    pub block_height: u64,
    pub receipt_index: u64,
    pub encrypted_event_payload: String,
    pub event_payload_commitment: String,
    pub topic_commitment_root: String,
    pub matched_filter_root: String,
    pub nullifier: String,
    pub witness_commitment: String,
    pub status: EventCommitmentStatus,
    pub privacy_set_size: u64,
    pub indexer_fee_bps: u64,
}

impl ContractEventCommitment {
    pub fn record(&self) -> Value {
        json!({
            "event_id": self.event_id,
            "stream_id": self.stream_id,
            "event_sequence": self.event_sequence,
            "block_height": self.block_height,
            "receipt_index": self.receipt_index,
            "encrypted_event_payload": self.encrypted_event_payload,
            "event_payload_commitment": self.event_payload_commitment,
            "topic_commitment_root": self.topic_commitment_root,
            "matched_filter_root": self.matched_filter_root,
            "nullifier": self.nullifier,
            "witness_commitment": self.witness_commitment,
            "status": self.status,
            "privacy_set_size": self.privacy_set_size,
            "indexer_fee_bps": self.indexer_fee_bps,
        })
    }

    pub fn commitment(&self) -> String {
        root_from_record("contract-event-subscription:event", &self.record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SponsorReservation {
    pub reservation_id: String,
    pub sponsor_commitment: String,
    pub subscriber_id: String,
    pub filter_id: String,
    pub max_fee_amount: u128,
    pub reserved_fee_amount: u128,
    pub consumed_fee_amount: u128,
    pub rebate_bps: u64,
    pub status: ReservationStatus,
    pub created_at_height: u64,
    pub expires_at_height: u64,
    pub sponsor_proof_root: String,
}

impl SponsorReservation {
    pub fn record(&self) -> Value {
        json!({
            "reservation_id": self.reservation_id,
            "sponsor_commitment": self.sponsor_commitment,
            "subscriber_id": self.subscriber_id,
            "filter_id": self.filter_id,
            "max_fee_amount": self.max_fee_amount.to_string(),
            "reserved_fee_amount": self.reserved_fee_amount.to_string(),
            "consumed_fee_amount": self.consumed_fee_amount.to_string(),
            "rebate_bps": self.rebate_bps,
            "status": self.status,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
            "sponsor_proof_root": self.sponsor_proof_root,
        })
    }

    pub fn commitment(&self) -> String {
        root_from_record("contract-event-subscription:reservation", &self.record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CursorCheckpoint {
    pub checkpoint_id: String,
    pub stream_id: String,
    pub cursor_kind: CursorKind,
    pub cursor_value_commitment: String,
    pub previous_checkpoint_root: String,
    pub checkpoint_witness_root: String,
    pub observed_at_height: u64,
    pub event_count: u64,
}

impl CursorCheckpoint {
    pub fn record(&self) -> Value {
        json!({
            "checkpoint_id": self.checkpoint_id,
            "stream_id": self.stream_id,
            "cursor_kind": self.cursor_kind,
            "cursor_value_commitment": self.cursor_value_commitment,
            "previous_checkpoint_root": self.previous_checkpoint_root,
            "checkpoint_witness_root": self.checkpoint_witness_root,
            "observed_at_height": self.observed_at_height,
            "event_count": self.event_count,
        })
    }

    pub fn commitment(&self) -> String {
        root_from_record(
            "contract-event-subscription:cursor-checkpoint",
            &self.record(),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DeliveryShard {
    pub shard_id: String,
    pub batch_id: String,
    pub filter_id: String,
    pub subscriber_id: String,
    pub event_root: String,
    pub encrypted_delivery_root: String,
    pub shard_index: u32,
    pub event_count: u64,
    pub delivery_fee_amount: u128,
    pub privacy_set_size: u64,
}

impl DeliveryShard {
    pub fn record(&self) -> Value {
        json!({
            "shard_id": self.shard_id,
            "batch_id": self.batch_id,
            "filter_id": self.filter_id,
            "subscriber_id": self.subscriber_id,
            "event_root": self.event_root,
            "encrypted_delivery_root": self.encrypted_delivery_root,
            "shard_index": self.shard_index,
            "event_count": self.event_count,
            "delivery_fee_amount": self.delivery_fee_amount.to_string(),
            "privacy_set_size": self.privacy_set_size,
        })
    }

    pub fn commitment(&self) -> String {
        root_from_record("contract-event-subscription:delivery-shard", &self.record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DeliveryBatch {
    pub batch_id: String,
    pub stream_id: String,
    pub shard_root: String,
    pub event_root: String,
    pub filter_root: String,
    pub cursor_start_root: String,
    pub cursor_end_root: String,
    pub indexer_quorum_root: String,
    pub status: DeliveryBatchStatus,
    pub opened_at_height: u64,
    pub sealed_at_height: u64,
    pub expires_at_height: u64,
    pub event_count: u64,
    pub max_fee_amount: u128,
    pub settlement_commitment: String,
}

impl DeliveryBatch {
    pub fn record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "stream_id": self.stream_id,
            "shard_root": self.shard_root,
            "event_root": self.event_root,
            "filter_root": self.filter_root,
            "cursor_start_root": self.cursor_start_root,
            "cursor_end_root": self.cursor_end_root,
            "indexer_quorum_root": self.indexer_quorum_root,
            "status": self.status,
            "opened_at_height": self.opened_at_height,
            "sealed_at_height": self.sealed_at_height,
            "expires_at_height": self.expires_at_height,
            "event_count": self.event_count,
            "max_fee_amount": self.max_fee_amount.to_string(),
            "settlement_commitment": self.settlement_commitment,
        })
    }

    pub fn commitment(&self) -> String {
        root_from_record("contract-event-subscription:delivery-batch", &self.record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DeliveryReceipt {
    pub receipt_id: String,
    pub batch_id: String,
    pub shard_id: String,
    pub subscriber_id: String,
    pub reservation_id: String,
    pub kind: ReceiptKind,
    pub delivered_event_root: String,
    pub delivery_proof_root: String,
    pub fee_amount: u128,
    pub rebate_amount: u128,
    pub settled_at_height: u64,
}

impl DeliveryReceipt {
    pub fn record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "batch_id": self.batch_id,
            "shard_id": self.shard_id,
            "subscriber_id": self.subscriber_id,
            "reservation_id": self.reservation_id,
            "kind": self.kind,
            "delivered_event_root": self.delivered_event_root,
            "delivery_proof_root": self.delivery_proof_root,
            "fee_amount": self.fee_amount.to_string(),
            "rebate_amount": self.rebate_amount.to_string(),
            "settled_at_height": self.settled_at_height,
        })
    }

    pub fn commitment(&self) -> String {
        root_from_record("contract-event-subscription:receipt", &self.record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FeeRebate {
    pub rebate_id: String,
    pub receipt_id: String,
    pub reservation_id: String,
    pub claimant_commitment: String,
    pub rebate_amount: u128,
    pub rebate_bps: u64,
    pub status: RebateStatus,
    pub claim_after_height: u64,
    pub expires_at_height: u64,
}

impl FeeRebate {
    pub fn record(&self) -> Value {
        json!({
            "rebate_id": self.rebate_id,
            "receipt_id": self.receipt_id,
            "reservation_id": self.reservation_id,
            "claimant_commitment": self.claimant_commitment,
            "rebate_amount": self.rebate_amount.to_string(),
            "rebate_bps": self.rebate_bps,
            "status": self.status,
            "claim_after_height": self.claim_after_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn commitment(&self) -> String {
        root_from_record("contract-event-subscription:rebate", &self.record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NullifierFence {
    pub nullifier: String,
    pub stream_id: String,
    pub filter_id: String,
    pub event_id: String,
    pub fence_root: String,
    pub status: NullifierFenceStatus,
    pub locked_at_height: u64,
    pub released_at_height: u64,
}

impl NullifierFence {
    pub fn record(&self) -> Value {
        json!({
            "nullifier": self.nullifier,
            "stream_id": self.stream_id,
            "filter_id": self.filter_id,
            "event_id": self.event_id,
            "fence_root": self.fence_root,
            "status": self.status,
            "locked_at_height": self.locked_at_height,
            "released_at_height": self.released_at_height,
        })
    }

    pub fn commitment(&self) -> String {
        root_from_record("contract-event-subscription:nullifier", &self.record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct IndexerQuorumRound {
    pub round_id: String,
    pub stream_id: String,
    pub batch_id: String,
    pub quorum_committee_root: String,
    pub signature_root: String,
    pub valid_attestation_count: u64,
    pub required_attestation_count: u64,
    pub pq_security_bits: u16,
    pub observed_at_height: u64,
}

impl IndexerQuorumRound {
    pub fn record(&self) -> Value {
        json!({
            "round_id": self.round_id,
            "stream_id": self.stream_id,
            "batch_id": self.batch_id,
            "quorum_committee_root": self.quorum_committee_root,
            "signature_root": self.signature_root,
            "valid_attestation_count": self.valid_attestation_count,
            "required_attestation_count": self.required_attestation_count,
            "pq_security_bits": self.pq_security_bits,
            "observed_at_height": self.observed_at_height,
        })
    }

    pub fn commitment(&self) -> String {
        root_from_record("contract-event-subscription:indexer-quorum", &self.record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DispatchLaneMetrics {
    pub lane_id: String,
    pub lane_label: String,
    pub pending_batch_count: u64,
    pub sealed_batch_count: u64,
    pub delivered_event_count: u64,
    pub median_delivery_blocks: u64,
    pub target_fee_bps: u64,
    pub congestion_hint: u64,
    pub last_updated_height: u64,
}

impl DispatchLaneMetrics {
    pub fn record(&self) -> Value {
        json!({
            "lane_id": self.lane_id,
            "lane_label": self.lane_label,
            "pending_batch_count": self.pending_batch_count,
            "sealed_batch_count": self.sealed_batch_count,
            "delivered_event_count": self.delivered_event_count,
            "median_delivery_blocks": self.median_delivery_blocks,
            "target_fee_bps": self.target_fee_bps,
            "congestion_hint": self.congestion_hint,
            "last_updated_height": self.last_updated_height,
        })
    }

    pub fn commitment(&self) -> String {
        root_from_record(
            "contract-event-subscription:dispatch-lane-metrics",
            &self.record(),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub streams: BTreeMap<String, ContractEventStream>,
    pub filters: BTreeMap<String, EventFilterCiphertext>,
    pub subscribers: BTreeMap<String, SubscriberProfile>,
    pub attestations: BTreeMap<String, SubscriberAttestation>,
    pub events: BTreeMap<String, ContractEventCommitment>,
    pub reservations: BTreeMap<String, SponsorReservation>,
    pub cursor_checkpoints: BTreeMap<String, CursorCheckpoint>,
    pub delivery_shards: BTreeMap<String, DeliveryShard>,
    pub delivery_batches: BTreeMap<String, DeliveryBatch>,
    pub receipts: BTreeMap<String, DeliveryReceipt>,
    pub rebates: BTreeMap<String, FeeRebate>,
    pub nullifier_fences: BTreeMap<String, NullifierFence>,
    pub quorum_rounds: BTreeMap<String, IndexerQuorumRound>,
    pub dispatch_lane_metrics: BTreeMap<String, DispatchLaneMetrics>,
    pub consumed_nullifiers: BTreeSet<String>,
}

impl State {
    pub fn new(config: Config) -> Self {
        let mut state = Self {
            config,
            counters: Counters::default(),
            roots: Roots::default(),
            streams: BTreeMap::new(),
            filters: BTreeMap::new(),
            subscribers: BTreeMap::new(),
            attestations: BTreeMap::new(),
            events: BTreeMap::new(),
            reservations: BTreeMap::new(),
            cursor_checkpoints: BTreeMap::new(),
            delivery_shards: BTreeMap::new(),
            delivery_batches: BTreeMap::new(),
            receipts: BTreeMap::new(),
            rebates: BTreeMap::new(),
            nullifier_fences: BTreeMap::new(),
            quorum_rounds: BTreeMap::new(),
            dispatch_lane_metrics: BTreeMap::new(),
            consumed_nullifiers: BTreeSet::new(),
        };
        state.recompute_counters();
        state.recompute_roots();
        state
    }

    pub fn devnet() -> Self {
        let mut state = Self::new(Config::devnet());
        let height = state.config.devnet_height;

        let dex_stream = ContractEventStream {
            stream_id: contract_event_stream_id(
                "secret-dex-v3",
                "swap-executed-topic-root",
                "devnet-stream-0",
            ),
            contract_address_commitment: payload_root(
                "contract-event-subscription:contract-address",
                &json!({"contract": "secret-dex-v3", "domain": "nebula-l2"}),
            ),
            deployment_domain: "nebula-l2-contracts".to_string(),
            event_kind: ContractEventStreamKind::DexSwap,
            topic_commitment_root: root_from_values(
                "contract-event-subscription:devnet:dex-topics",
                &["swap_executed", "pool_id", "encrypted_amounts"],
            ),
            decoder_commitment: payload_root(
                "contract-event-subscription:decoder",
                &json!({"decoder": "confidential-swap-v3", "fields": 8}),
            ),
            indexer_committee_root: root_from_values(
                "contract-event-subscription:indexer-committee",
                &["aurora-indexer", "cedar-indexer", "sable-indexer"],
            ),
            cursor_kind: CursorKind::EventSequence,
            status: StreamStatus::Active,
            min_confirmations: 2,
            min_privacy_set_size: state.config.min_privacy_set_size,
            pq_security_bits: state.config.min_pq_security_bits,
            created_at_height: height - 1_200,
            expires_at_height: height + state.config.stream_ttl_blocks,
            fee_bps: 4,
            metadata_commitment: payload_root(
                "contract-event-subscription:stream-metadata",
                &json!({"name": "confidential-dex-swaps", "sla_blocks": 3}),
            ),
        };

        let bridge_stream = ContractEventStream {
            stream_id: contract_event_stream_id(
                "monero-bridge-router",
                "bridge-message-topic-root",
                "devnet-stream-1",
            ),
            contract_address_commitment: payload_root(
                "contract-event-subscription:contract-address",
                &json!({"contract": "monero-bridge-router", "domain": "nebula-l2"}),
            ),
            deployment_domain: "nebula-l2-bridge".to_string(),
            event_kind: ContractEventStreamKind::BridgeMessage,
            topic_commitment_root: root_from_values(
                "contract-event-subscription:devnet:bridge-topics",
                &["xmr_lock", "reserve_attestation", "batch_release"],
            ),
            decoder_commitment: payload_root(
                "contract-event-subscription:decoder",
                &json!({"decoder": "private-bridge-batch-v1", "fields": 11}),
            ),
            indexer_committee_root: root_from_values(
                "contract-event-subscription:indexer-committee",
                &[
                    "aurora-indexer",
                    "cedar-indexer",
                    "sable-indexer",
                    "zenith-indexer",
                ],
            ),
            cursor_kind: CursorKind::BridgeMessageIndex,
            status: StreamStatus::Active,
            min_confirmations: 4,
            min_privacy_set_size: state.config.min_privacy_set_size * 2,
            pq_security_bits: state.config.min_pq_security_bits,
            created_at_height: height - 900,
            expires_at_height: height + state.config.stream_ttl_blocks,
            fee_bps: 5,
            metadata_commitment: payload_root(
                "contract-event-subscription:stream-metadata",
                &json!({"name": "monero-private-bridge-events", "sla_blocks": 4}),
            ),
        };

        state
            .register_stream(dex_stream.clone())
            .expect("devnet dex stream");
        state
            .register_stream(bridge_stream.clone())
            .expect("devnet bridge stream");

        let subscriber = SubscriberProfile {
            subscriber_id: subscriber_id("market-maker-vault-alpha", "devnet-subscriber-0"),
            subscriber_kind: SubscriberKind::MarketMaker,
            pq_delivery_key_commitment: payload_root(
                "contract-event-subscription:pq-delivery-key",
                &json!({"owner": "market-maker-vault-alpha", "suite": "ml-kem-1024"}),
            ),
            pq_signing_key_commitment: payload_root(
                "contract-event-subscription:pq-signing-key",
                &json!({"owner": "market-maker-vault-alpha", "suite": "ml-dsa-87"}),
            ),
            wallet_view_tag_commitment: payload_root(
                "contract-event-subscription:view-tag",
                &json!({"owner": "market-maker-vault-alpha", "tag": "mm-alpha-private"}),
            ),
            settlement_address_commitment: payload_root(
                "contract-event-subscription:settlement-address",
                &json!({"asset": "fee-credit", "account": "mm-alpha-settlement"}),
            ),
            rate_limit_commitment: payload_root(
                "contract-event-subscription:rate-limit",
                &json!({"events_per_batch": 2048, "batches_per_epoch": 64}),
            ),
            status: SubscriberStatus::Active,
            min_privacy_set_size: state.config.min_privacy_set_size,
            pq_security_bits: state.config.min_pq_security_bits,
            created_at_height: height - 800,
            key_rotation_nonce: 3,
        };

        state
            .register_subscriber(subscriber.clone())
            .expect("devnet subscriber");

        let filter = EventFilterCiphertext {
            filter_id: filter_id(
                &dex_stream.stream_id,
                &subscriber.subscriber_id,
                "swap-filter-alpha",
            ),
            stream_id: dex_stream.stream_id.clone(),
            subscriber_id: subscriber.subscriber_id.clone(),
            filter_kind: FilterKind::Composite,
            encrypted_filter_payload: payload_root(
                "contract-event-subscription:encrypted-filter-payload",
                &json!({"ciphertext": "devnet-mm-alpha-swap-filter", "version": 1}),
            ),
            filter_key_commitment: payload_root(
                "contract-event-subscription:filter-key",
                &json!({"key": "mm-alpha-filter-key", "rotation": 3}),
            ),
            topic_mask_commitment: root_from_values(
                "contract-event-subscription:topic-mask",
                &["pool_id", "price_tick", "liquidity_bucket"],
            ),
            predicate_commitment: payload_root(
                "contract-event-subscription:predicate",
                &json!({"min_notional": "5000000", "assets": ["pXMR", "pUSD"]}),
            ),
            cursor_start_commitment: cursor_value_commitment(&dex_stream.stream_id, height - 128),
            nullifier_domain: "mm-alpha-swap-filter-nullifiers".to_string(),
            status: FilterStatus::Active,
            max_events_per_batch: 2_048,
            max_delivery_fee_bps: 5,
            created_at_height: height - 760,
            expires_at_height: height + state.config.filter_ttl_blocks,
        };

        state
            .register_filter(filter.clone())
            .expect("devnet filter");

        let attestation = SubscriberAttestation {
            attestation_id: subscriber_attestation_id(
                &subscriber.subscriber_id,
                &filter.filter_id,
                "pq-key-valid",
            ),
            subscriber_id: subscriber.subscriber_id.clone(),
            filter_id: filter.filter_id.clone(),
            kind: AttestationKind::PqSubscriberKey,
            verdict: AttestationVerdict::Valid,
            attester_commitment: payload_root(
                "contract-event-subscription:attester",
                &json!({"committee": "devnet-indexer-quorum", "member": "aurora"}),
            ),
            attestation_root: payload_root(
                "contract-event-subscription:attestation-root",
                &json!({"statement": "subscriber-key-valid", "bits": 256}),
            ),
            transcript_root: payload_root(
                "contract-event-subscription:attestation-transcript",
                &json!({"round": "devnet-972000", "filter": filter.filter_id}),
            ),
            pq_signature_commitment: payload_root(
                "contract-event-subscription:pq-signature",
                &json!({"suite": "ml-dsa-87", "signature": "devnet-signature-0"}),
            ),
            observed_at_height: height - 740,
            expires_at_height: height + state.config.filter_ttl_blocks,
        };

        state
            .record_attestation(attestation)
            .expect("devnet attestation");

        let reservation = SponsorReservation {
            reservation_id: sponsor_reservation_id(
                &subscriber.subscriber_id,
                &filter.filter_id,
                "reservation-alpha",
            ),
            sponsor_commitment: payload_root(
                "contract-event-subscription:sponsor",
                &json!({"sponsor": "fee-vault-alpha", "policy": "low-fee-batch-sponsor"}),
            ),
            subscriber_id: subscriber.subscriber_id.clone(),
            filter_id: filter.filter_id.clone(),
            max_fee_amount: 5_000_000,
            reserved_fee_amount: 2_500_000,
            consumed_fee_amount: 128_000,
            rebate_bps: state.config.target_rebate_bps,
            status: ReservationStatus::RebateQueued,
            created_at_height: height - 640,
            expires_at_height: height + state.config.reservation_ttl_blocks,
            sponsor_proof_root: payload_root(
                "contract-event-subscription:sponsor-proof",
                &json!({"credit_root": "fee-vault-alpha-credit-root", "nonce": 42}),
            ),
        };

        state
            .reserve_sponsor_fee(reservation.clone())
            .expect("devnet reservation");

        let event_a = devnet_event(
            &dex_stream.stream_id,
            &filter.filter_id,
            9_001,
            height - 9,
            0,
            state.config.min_privacy_set_size,
        );
        let event_b = devnet_event(
            &dex_stream.stream_id,
            &filter.filter_id,
            9_002,
            height - 8,
            1,
            state.config.min_privacy_set_size,
        );

        state.record_event(event_a.clone()).expect("devnet event a");
        state.record_event(event_b.clone()).expect("devnet event b");

        let checkpoint_start = CursorCheckpoint {
            checkpoint_id: cursor_checkpoint_id(&dex_stream.stream_id, height - 128, "start"),
            stream_id: dex_stream.stream_id.clone(),
            cursor_kind: CursorKind::EventSequence,
            cursor_value_commitment: cursor_value_commitment(&dex_stream.stream_id, height - 128),
            previous_checkpoint_root: payload_root(
                "contract-event-subscription:previous-cursor",
                &json!({"stream_id": dex_stream.stream_id, "cursor": height - 256}),
            ),
            checkpoint_witness_root: payload_root(
                "contract-event-subscription:cursor-witness",
                &json!({"observed": height - 128, "events": 0}),
            ),
            observed_at_height: height - 128,
            event_count: 0,
        };
        let checkpoint_end = CursorCheckpoint {
            checkpoint_id: cursor_checkpoint_id(&event_b.stream_id, height - 8, "end"),
            stream_id: event_b.stream_id.clone(),
            cursor_kind: CursorKind::EventSequence,
            cursor_value_commitment: cursor_value_commitment(&event_b.stream_id, height - 8),
            previous_checkpoint_root: checkpoint_start.commitment(),
            checkpoint_witness_root: payload_root(
                "contract-event-subscription:cursor-witness",
                &json!({"observed": height - 8, "events": 2}),
            ),
            observed_at_height: height - 8,
            event_count: 2,
        };

        state
            .record_cursor_checkpoint(checkpoint_start.clone())
            .expect("devnet checkpoint start");
        state
            .record_cursor_checkpoint(checkpoint_end.clone())
            .expect("devnet checkpoint end");

        let event_root = public_record_root(
            "contract-event-subscription:devnet:batch-events",
            &[event_a.record(), event_b.record()],
        );
        let batch_id = delivery_batch_id(&dex_stream.stream_id, &event_root, height - 4);
        let shard = DeliveryShard {
            shard_id: delivery_shard_id(&batch_id, &filter.filter_id, 0),
            batch_id: batch_id.clone(),
            filter_id: filter.filter_id.clone(),
            subscriber_id: subscriber.subscriber_id.clone(),
            event_root: event_root.clone(),
            encrypted_delivery_root: payload_root(
                "contract-event-subscription:encrypted-delivery",
                &json!({"payloads": ["event-a", "event-b"], "recipient": subscriber.subscriber_id}),
            ),
            shard_index: 0,
            event_count: 2,
            delivery_fee_amount: 128_000,
            privacy_set_size: state.config.batch_privacy_set_size,
        };

        let batch = DeliveryBatch {
            batch_id: batch_id.clone(),
            stream_id: dex_stream.stream_id.clone(),
            shard_root: public_record_root(
                "contract-event-subscription:devnet:shards",
                &[shard.record()],
            ),
            event_root: event_root.clone(),
            filter_root: root_from_record("contract-event-subscription:filter", &filter.record()),
            cursor_start_root: checkpoint_start.commitment(),
            cursor_end_root: checkpoint_end.commitment(),
            indexer_quorum_root: payload_root(
                "contract-event-subscription:indexer-quorum-root",
                &json!({"signers": ["aurora", "cedar", "sable"], "threshold": 2}),
            ),
            status: DeliveryBatchStatus::Delivered,
            opened_at_height: height - 7,
            sealed_at_height: height - 4,
            expires_at_height: height + state.config.batch_ttl_blocks,
            event_count: 2,
            max_fee_amount: 160_000,
            settlement_commitment: payload_root(
                "contract-event-subscription:settlement",
                &json!({"reservation_id": reservation.reservation_id, "fee": "128000"}),
            ),
        };

        state
            .record_delivery_shard(shard.clone())
            .expect("devnet shard");
        state
            .record_delivery_batch(batch.clone())
            .expect("devnet batch");

        let quorum = IndexerQuorumRound {
            round_id: indexer_quorum_round_id(&dex_stream.stream_id, &batch.batch_id, "round-0"),
            stream_id: dex_stream.stream_id.clone(),
            batch_id: batch.batch_id.clone(),
            quorum_committee_root: batch.indexer_quorum_root.clone(),
            signature_root: payload_root(
                "contract-event-subscription:quorum-signatures",
                &json!({"ml_dsa_signatures": ["aurora", "cedar", "sable"], "round": 0}),
            ),
            valid_attestation_count: 3,
            required_attestation_count: 2,
            pq_security_bits: state.config.min_pq_security_bits,
            observed_at_height: height - 3,
        };

        state
            .record_indexer_quorum_round(quorum)
            .expect("devnet quorum");

        let receipt = DeliveryReceipt {
            receipt_id: delivery_receipt_id(&batch.batch_id, &shard.shard_id, "receipt-0"),
            batch_id: batch.batch_id.clone(),
            shard_id: shard.shard_id.clone(),
            subscriber_id: subscriber.subscriber_id.clone(),
            reservation_id: reservation.reservation_id.clone(),
            kind: ReceiptKind::EventDelivery,
            delivered_event_root: event_root.clone(),
            delivery_proof_root: payload_root(
                "contract-event-subscription:delivery-proof",
                &json!({"batch": batch.batch_id, "events": 2, "privacy_set": state.config.batch_privacy_set_size}),
            ),
            fee_amount: 128_000,
            rebate_amount: 64,
            settled_at_height: height - 2,
        };

        state
            .record_delivery_receipt(receipt.clone())
            .expect("devnet receipt");

        let rebate = FeeRebate {
            rebate_id: fee_rebate_id(&receipt.receipt_id, &reservation.reservation_id),
            receipt_id: receipt.receipt_id.clone(),
            reservation_id: reservation.reservation_id.clone(),
            claimant_commitment: subscriber.settlement_address_commitment.clone(),
            rebate_amount: receipt.rebate_amount,
            rebate_bps: state.config.target_rebate_bps,
            status: RebateStatus::Claimable,
            claim_after_height: height + 1,
            expires_at_height: height + 7_200,
        };

        state.record_rebate(rebate).expect("devnet rebate");

        state
            .record_dispatch_lane_metrics(DispatchLaneMetrics {
                lane_id: dispatch_lane_id("dex-events-fast-lane"),
                lane_label: "dex-events-fast-lane".to_string(),
                pending_batch_count: 2,
                sealed_batch_count: 81,
                delivered_event_count: 14_832,
                median_delivery_blocks: 3,
                target_fee_bps: 4,
                congestion_hint: 17,
                last_updated_height: height,
            })
            .expect("devnet lane metrics");

        state.recompute_counters();
        state.recompute_roots();
        state
    }

    pub fn register_stream(
        &mut self,
        stream: ContractEventStream,
    ) -> PrivateL2ConfidentialContractEventSubscriptionRuntimeResult<()> {
        if self.streams.len() >= self.config.max_streams {
            return Err("stream capacity exceeded".to_string());
        }
        if !stream.status.accepts_events() && stream.status != StreamStatus::Proposed {
            return Err("stream status is not registerable".to_string());
        }
        if stream.pq_security_bits < self.config.min_pq_security_bits {
            return Err("stream pq security below runtime floor".to_string());
        }
        if stream.fee_bps > self.config.max_indexer_fee_bps {
            return Err("stream indexer fee above runtime ceiling".to_string());
        }
        self.streams.insert(stream.stream_id.clone(), stream);
        self.recompute_counters();
        self.recompute_roots();
        Ok(())
    }

    pub fn register_subscriber(
        &mut self,
        subscriber: SubscriberProfile,
    ) -> PrivateL2ConfidentialContractEventSubscriptionRuntimeResult<()> {
        if self.subscribers.len() >= self.config.max_subscribers {
            return Err("subscriber capacity exceeded".to_string());
        }
        if !subscriber.status.can_receive() {
            return Err("subscriber cannot receive events".to_string());
        }
        if subscriber.pq_security_bits < self.config.min_pq_security_bits {
            return Err("subscriber pq security below runtime floor".to_string());
        }
        self.subscribers
            .insert(subscriber.subscriber_id.clone(), subscriber);
        self.recompute_counters();
        self.recompute_roots();
        Ok(())
    }

    pub fn register_filter(
        &mut self,
        filter: EventFilterCiphertext,
    ) -> PrivateL2ConfidentialContractEventSubscriptionRuntimeResult<()> {
        if self.filters.len() >= self.config.max_filters {
            return Err("filter capacity exceeded".to_string());
        }
        if !self.streams.contains_key(&filter.stream_id) {
            return Err("filter references unknown stream".to_string());
        }
        if !self.subscribers.contains_key(&filter.subscriber_id) {
            return Err("filter references unknown subscriber".to_string());
        }
        if !filter.status.is_active() && filter.status != FilterStatus::Encrypted {
            return Err("filter status is not registerable".to_string());
        }
        if filter.max_delivery_fee_bps > self.config.max_delivery_fee_bps {
            return Err("filter delivery fee above runtime ceiling".to_string());
        }
        self.filters.insert(filter.filter_id.clone(), filter);
        self.recompute_counters();
        self.recompute_roots();
        Ok(())
    }

    pub fn record_attestation(
        &mut self,
        attestation: SubscriberAttestation,
    ) -> PrivateL2ConfidentialContractEventSubscriptionRuntimeResult<()> {
        if self.attestations.len() >= self.config.max_attestations {
            return Err("attestation capacity exceeded".to_string());
        }
        if !self.subscribers.contains_key(&attestation.subscriber_id) {
            return Err("attestation references unknown subscriber".to_string());
        }
        if !self.filters.contains_key(&attestation.filter_id) {
            return Err("attestation references unknown filter".to_string());
        }
        if !attestation.verdict.contributes_to_quorum() {
            return Err("attestation verdict does not contribute to quorum".to_string());
        }
        self.attestations
            .insert(attestation.attestation_id.clone(), attestation);
        self.recompute_counters();
        self.recompute_roots();
        Ok(())
    }

    pub fn record_event(
        &mut self,
        event: ContractEventCommitment,
    ) -> PrivateL2ConfidentialContractEventSubscriptionRuntimeResult<()> {
        if self.events.len() >= self.config.max_events {
            return Err("event capacity exceeded".to_string());
        }
        if !self.streams.contains_key(&event.stream_id) {
            return Err("event references unknown stream".to_string());
        }
        if self.consumed_nullifiers.contains(&event.nullifier) {
            return Err("event nullifier already consumed".to_string());
        }
        if event.privacy_set_size < self.config.min_privacy_set_size {
            return Err("event privacy set below runtime floor".to_string());
        }
        if event.indexer_fee_bps > self.config.max_indexer_fee_bps {
            return Err("event indexer fee above runtime ceiling".to_string());
        }
        let fence = NullifierFence {
            nullifier: event.nullifier.clone(),
            stream_id: event.stream_id.clone(),
            filter_id: event.matched_filter_root.clone(),
            event_id: event.event_id.clone(),
            fence_root: replay_fence_leaf(&event.stream_id, &event.nullifier),
            status: NullifierFenceStatus::Locked,
            locked_at_height: event.block_height,
            released_at_height: 0,
        };
        self.consumed_nullifiers.insert(event.nullifier.clone());
        self.nullifier_fences.insert(fence.nullifier.clone(), fence);
        self.events.insert(event.event_id.clone(), event);
        self.recompute_counters();
        self.recompute_roots();
        Ok(())
    }

    pub fn reserve_sponsor_fee(
        &mut self,
        reservation: SponsorReservation,
    ) -> PrivateL2ConfidentialContractEventSubscriptionRuntimeResult<()> {
        if self.reservations.len() >= self.config.max_reservations {
            return Err("reservation capacity exceeded".to_string());
        }
        if !self.subscribers.contains_key(&reservation.subscriber_id) {
            return Err("reservation references unknown subscriber".to_string());
        }
        if !self.filters.contains_key(&reservation.filter_id) {
            return Err("reservation references unknown filter".to_string());
        }
        if reservation.rebate_bps > self.config.target_rebate_bps {
            return Err("reservation rebate above target rebate".to_string());
        }
        if reservation.reserved_fee_amount > reservation.max_fee_amount {
            return Err("reserved amount exceeds maximum fee".to_string());
        }
        self.reservations
            .insert(reservation.reservation_id.clone(), reservation);
        self.recompute_counters();
        self.recompute_roots();
        Ok(())
    }

    pub fn record_cursor_checkpoint(
        &mut self,
        checkpoint: CursorCheckpoint,
    ) -> PrivateL2ConfidentialContractEventSubscriptionRuntimeResult<()> {
        if !self.streams.contains_key(&checkpoint.stream_id) {
            return Err("cursor checkpoint references unknown stream".to_string());
        }
        self.cursor_checkpoints
            .insert(checkpoint.checkpoint_id.clone(), checkpoint);
        self.recompute_counters();
        self.recompute_roots();
        Ok(())
    }

    pub fn record_delivery_shard(
        &mut self,
        shard: DeliveryShard,
    ) -> PrivateL2ConfidentialContractEventSubscriptionRuntimeResult<()> {
        if !self.filters.contains_key(&shard.filter_id) {
            return Err("delivery shard references unknown filter".to_string());
        }
        if !self.subscribers.contains_key(&shard.subscriber_id) {
            return Err("delivery shard references unknown subscriber".to_string());
        }
        self.delivery_shards.insert(shard.shard_id.clone(), shard);
        self.recompute_counters();
        self.recompute_roots();
        Ok(())
    }

    pub fn record_delivery_batch(
        &mut self,
        batch: DeliveryBatch,
    ) -> PrivateL2ConfidentialContractEventSubscriptionRuntimeResult<()> {
        if self.delivery_batches.len() >= self.config.max_batches {
            return Err("delivery batch capacity exceeded".to_string());
        }
        if !self.streams.contains_key(&batch.stream_id) {
            return Err("delivery batch references unknown stream".to_string());
        }
        if batch.event_count as usize > self.config.max_batch_events {
            return Err("delivery batch event count exceeds max batch events".to_string());
        }
        if !batch.status.anchors_state() && batch.status != DeliveryBatchStatus::Open {
            return Err("delivery batch status is not recordable".to_string());
        }
        self.delivery_batches.insert(batch.batch_id.clone(), batch);
        self.recompute_counters();
        self.recompute_roots();
        Ok(())
    }

    pub fn record_delivery_receipt(
        &mut self,
        receipt: DeliveryReceipt,
    ) -> PrivateL2ConfidentialContractEventSubscriptionRuntimeResult<()> {
        if self.receipts.len() >= self.config.max_receipts {
            return Err("receipt capacity exceeded".to_string());
        }
        if !self.delivery_batches.contains_key(&receipt.batch_id) {
            return Err("receipt references unknown batch".to_string());
        }
        if !self.delivery_shards.contains_key(&receipt.shard_id) {
            return Err("receipt references unknown shard".to_string());
        }
        if !self.reservations.contains_key(&receipt.reservation_id) {
            return Err("receipt references unknown reservation".to_string());
        }
        self.receipts.insert(receipt.receipt_id.clone(), receipt);
        self.recompute_counters();
        self.recompute_roots();
        Ok(())
    }

    pub fn record_rebate(
        &mut self,
        rebate: FeeRebate,
    ) -> PrivateL2ConfidentialContractEventSubscriptionRuntimeResult<()> {
        if self.rebates.len() >= self.config.max_rebates {
            return Err("rebate capacity exceeded".to_string());
        }
        if !self.receipts.contains_key(&rebate.receipt_id) {
            return Err("rebate references unknown receipt".to_string());
        }
        if !self.reservations.contains_key(&rebate.reservation_id) {
            return Err("rebate references unknown reservation".to_string());
        }
        self.rebates.insert(rebate.rebate_id.clone(), rebate);
        self.recompute_counters();
        self.recompute_roots();
        Ok(())
    }

    pub fn record_indexer_quorum_round(
        &mut self,
        round: IndexerQuorumRound,
    ) -> PrivateL2ConfidentialContractEventSubscriptionRuntimeResult<()> {
        if !self.streams.contains_key(&round.stream_id) {
            return Err("quorum round references unknown stream".to_string());
        }
        if !self.delivery_batches.contains_key(&round.batch_id) {
            return Err("quorum round references unknown batch".to_string());
        }
        if round.valid_attestation_count < round.required_attestation_count {
            return Err("quorum round does not satisfy threshold".to_string());
        }
        if round.pq_security_bits < self.config.min_pq_security_bits {
            return Err("quorum round pq security below runtime floor".to_string());
        }
        self.quorum_rounds.insert(round.round_id.clone(), round);
        self.recompute_counters();
        self.recompute_roots();
        Ok(())
    }

    pub fn record_dispatch_lane_metrics(
        &mut self,
        metrics: DispatchLaneMetrics,
    ) -> PrivateL2ConfidentialContractEventSubscriptionRuntimeResult<()> {
        if metrics.target_fee_bps > self.config.max_delivery_fee_bps {
            return Err("dispatch lane target fee above runtime ceiling".to_string());
        }
        self.dispatch_lane_metrics
            .insert(metrics.lane_id.clone(), metrics);
        self.recompute_counters();
        self.recompute_roots();
        Ok(())
    }

    pub fn recompute_counters(&mut self) {
        self.counters.stream_count = self.streams.len() as u64;
        self.counters.filter_count = self.filters.len() as u64;
        self.counters.subscriber_count = self.subscribers.len() as u64;
        self.counters.attestation_count = self.attestations.len() as u64;
        self.counters.event_count = self.events.len() as u64;
        self.counters.reservation_count = self.reservations.len() as u64;
        self.counters.batch_count = self.delivery_batches.len() as u64;
        self.counters.receipt_count = self.receipts.len() as u64;
        self.counters.rebate_count = self.rebates.len() as u64;
        self.counters.nullifier_count = self.nullifier_fences.len() as u64;
        self.counters.cursor_checkpoint_count = self.cursor_checkpoints.len() as u64;
        self.counters.quorum_round_count = self.quorum_rounds.len() as u64;
        self.counters.lane_metric_count = self.dispatch_lane_metrics.len() as u64;
        self.counters.total_reserved_fee = self
            .reservations
            .values()
            .map(|reservation| reservation.reserved_fee_amount)
            .sum();
        self.counters.total_delivered_fee = self
            .receipts
            .values()
            .map(|receipt| receipt.fee_amount)
            .sum();
        self.counters.total_rebate_amount = self
            .rebates
            .values()
            .map(|rebate| rebate.rebate_amount)
            .sum();
    }

    pub fn recompute_roots(&mut self) {
        let roots = Roots {
            config_root: self.config.policy_root(),
            stream_root: public_record_root(
                "contract-event-subscription:streams",
                &map_records(&self.streams),
            ),
            filter_root: public_record_root(
                "contract-event-subscription:filters",
                &map_records(&self.filters),
            ),
            subscriber_root: public_record_root(
                "contract-event-subscription:subscribers",
                &map_records(&self.subscribers),
            ),
            attestation_root: public_record_root(
                "contract-event-subscription:attestations",
                &map_records(&self.attestations),
            ),
            event_root: public_record_root(
                "contract-event-subscription:events",
                &map_records(&self.events),
            ),
            reservation_root: public_record_root(
                "contract-event-subscription:reservations",
                &map_records(&self.reservations),
            ),
            batch_root: public_record_root(
                "contract-event-subscription:batches",
                &map_records(&self.delivery_batches),
            ),
            receipt_root: public_record_root(
                "contract-event-subscription:receipts",
                &map_records(&self.receipts),
            ),
            rebate_root: public_record_root(
                "contract-event-subscription:rebates",
                &map_records(&self.rebates),
            ),
            nullifier_root: public_record_root(
                "contract-event-subscription:nullifiers",
                &map_records(&self.nullifier_fences),
            ),
            cursor_root: public_record_root(
                "contract-event-subscription:cursors",
                &map_records(&self.cursor_checkpoints),
            ),
            quorum_root: public_record_root(
                "contract-event-subscription:quorums",
                &map_records(&self.quorum_rounds),
            ),
            lane_metric_root: public_record_root(
                "contract-event-subscription:lane-metrics",
                &map_records(&self.dispatch_lane_metrics),
            ),
            counter_root: payload_root(
                "contract-event-subscription:counters",
                &self.counters.record(),
            ),
            state_root: String::new(),
        };
        let mut roots = roots;
        roots.state_root = state_root_from_record(&self.public_record_without_roots_state(&roots));
        self.roots = roots;
    }

    pub fn roots(&self) -> Roots {
        self.roots.clone()
    }

    pub fn public_record_without_state_root(&self) -> Value {
        self.public_record_without_roots_state(&self.roots)
    }

    fn public_record_without_roots_state(&self, roots: &Roots) -> Value {
        json!({
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_L2_CONFIDENTIAL_CONTRACT_EVENT_SUBSCRIPTION_RUNTIME_PROTOCOL_VERSION,
            "schema_version": PRIVATE_L2_CONFIDENTIAL_CONTRACT_EVENT_SUBSCRIPTION_RUNTIME_SCHEMA_VERSION,
            "config": self.config.policy_record(),
            "counters": self.counters.record(),
            "roots": roots.without_state_root(),
            "streams": map_records(&self.streams),
            "filters": map_records(&self.filters),
            "subscribers": map_records(&self.subscribers),
            "attestations": map_records(&self.attestations),
            "events": map_records(&self.events),
            "reservations": map_records(&self.reservations),
            "cursor_checkpoints": map_records(&self.cursor_checkpoints),
            "delivery_shards": map_records(&self.delivery_shards),
            "delivery_batches": map_records(&self.delivery_batches),
            "receipts": map_records(&self.receipts),
            "rebates": map_records(&self.rebates),
            "nullifier_fences": map_records(&self.nullifier_fences),
            "quorum_rounds": map_records(&self.quorum_rounds),
            "dispatch_lane_metrics": map_records(&self.dispatch_lane_metrics),
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        if let Value::Object(map) = &mut record {
            map.insert("state_root".to_string(), Value::String(self.state_root()));
        }
        record
    }

    pub fn state_root(&self) -> String {
        state_root_from_record(&self.public_record_without_state_root())
    }

    pub fn stream_ids(&self) -> Vec<String> {
        self.streams.keys().cloned().collect()
    }

    pub fn filter_ids_for_subscriber(&self, subscriber_id: &str) -> Vec<String> {
        self.filters
            .values()
            .filter(|filter| filter.subscriber_id == subscriber_id)
            .map(|filter| filter.filter_id.clone())
            .collect()
    }

    pub fn pending_delivery_event_ids(&self) -> Vec<String> {
        self.events
            .values()
            .filter(|event| event.status.is_deliverable())
            .map(|event| event.event_id.clone())
            .collect()
    }

    pub fn claimable_rebate_ids(&self) -> Vec<String> {
        self.rebates
            .values()
            .filter(|rebate| rebate.status == RebateStatus::Claimable)
            .map(|rebate| rebate.rebate_id.clone())
            .collect()
    }
}

pub type Runtime = State;

pub fn devnet() -> State {
    State::devnet()
}

pub fn private_l2_confidential_contract_event_subscription_runtime_public_record() -> Value {
    State::devnet().public_record()
}

pub fn private_l2_confidential_contract_event_subscription_runtime_state_root() -> String {
    State::devnet().state_root()
}

pub fn contract_event_stream_id(
    contract_address_commitment: &str,
    topic_commitment_root: &str,
    salt: &str,
) -> String {
    domain_hash(
        "contract-event-subscription:stream-id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(contract_address_commitment),
            HashPart::Str(topic_commitment_root),
            HashPart::Str(salt),
        ],
        32,
    )
}

pub fn subscriber_id(owner_commitment: &str, salt: &str) -> String {
    domain_hash(
        "contract-event-subscription:subscriber-id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(owner_commitment),
            HashPart::Str(salt),
        ],
        32,
    )
}

pub fn filter_id(stream_id: &str, subscriber_id: &str, filter_nonce: &str) -> String {
    domain_hash(
        "contract-event-subscription:filter-id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(stream_id),
            HashPart::Str(subscriber_id),
            HashPart::Str(filter_nonce),
        ],
        32,
    )
}

pub fn subscriber_attestation_id(subscriber_id: &str, filter_id: &str, nonce: &str) -> String {
    domain_hash(
        "contract-event-subscription:attestation-id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(subscriber_id),
            HashPart::Str(filter_id),
            HashPart::Str(nonce),
        ],
        32,
    )
}

pub fn contract_event_id(stream_id: &str, event_sequence: u64, block_height: u64) -> String {
    domain_hash(
        "contract-event-subscription:event-id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(stream_id),
            HashPart::U64(event_sequence),
            HashPart::U64(block_height),
        ],
        32,
    )
}

pub fn sponsor_reservation_id(
    subscriber_id: &str,
    filter_id: &str,
    reservation_nonce: &str,
) -> String {
    domain_hash(
        "contract-event-subscription:sponsor-reservation-id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(subscriber_id),
            HashPart::Str(filter_id),
            HashPart::Str(reservation_nonce),
        ],
        32,
    )
}

pub fn cursor_checkpoint_id(stream_id: &str, observed_height: u64, nonce: &str) -> String {
    domain_hash(
        "contract-event-subscription:cursor-checkpoint-id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(stream_id),
            HashPart::U64(observed_height),
            HashPart::Str(nonce),
        ],
        32,
    )
}

pub fn delivery_batch_id(stream_id: &str, event_root: &str, sealed_height: u64) -> String {
    domain_hash(
        "contract-event-subscription:delivery-batch-id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(stream_id),
            HashPart::Str(event_root),
            HashPart::U64(sealed_height),
        ],
        32,
    )
}

pub fn delivery_shard_id(batch_id: &str, filter_id: &str, shard_index: u32) -> String {
    domain_hash(
        "contract-event-subscription:delivery-shard-id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(batch_id),
            HashPart::Str(filter_id),
            HashPart::U64(shard_index as u64),
        ],
        32,
    )
}

pub fn delivery_receipt_id(batch_id: &str, shard_id: &str, nonce: &str) -> String {
    domain_hash(
        "contract-event-subscription:delivery-receipt-id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(batch_id),
            HashPart::Str(shard_id),
            HashPart::Str(nonce),
        ],
        32,
    )
}

pub fn fee_rebate_id(receipt_id: &str, reservation_id: &str) -> String {
    domain_hash(
        "contract-event-subscription:fee-rebate-id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(receipt_id),
            HashPart::Str(reservation_id),
        ],
        32,
    )
}

pub fn indexer_quorum_round_id(stream_id: &str, batch_id: &str, nonce: &str) -> String {
    domain_hash(
        "contract-event-subscription:indexer-quorum-round-id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(stream_id),
            HashPart::Str(batch_id),
            HashPart::Str(nonce),
        ],
        32,
    )
}

pub fn dispatch_lane_id(label: &str) -> String {
    domain_hash(
        "contract-event-subscription:dispatch-lane-id",
        &[HashPart::Str(CHAIN_ID), HashPart::Str(label)],
        32,
    )
}

pub fn replay_fence_leaf(stream_id: &str, nullifier: &str) -> String {
    domain_hash(
        "contract-event-subscription:replay-fence-leaf",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(stream_id),
            HashPart::Str(nullifier),
        ],
        32,
    )
}

pub fn cursor_value_commitment(stream_id: &str, cursor_value: u64) -> String {
    domain_hash(
        "contract-event-subscription:cursor-value",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(stream_id),
            HashPart::U64(cursor_value),
        ],
        32,
    )
}

pub fn payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
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

pub fn public_record_root(domain: &str, records: &[Value]) -> String {
    merkle_root(domain, records)
}

pub fn state_root_from_record(record: &Value) -> String {
    root_from_record("contract-event-subscription:state-root", record)
}

pub fn root_from_values(domain: &str, values: &[&str]) -> String {
    let leaves = values
        .iter()
        .map(|value| json!({"value": value}))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn map_records<T: Serialize>(map: &BTreeMap<String, T>) -> Vec<Value> {
    map.values()
        .map(|value| serde_json::to_value(value).expect("serializable contract event state"))
        .collect()
}

fn devnet_event(
    stream_id: &str,
    filter_id: &str,
    event_sequence: u64,
    block_height: u64,
    receipt_index: u64,
    privacy_set_size: u64,
) -> ContractEventCommitment {
    let event_id = contract_event_id(stream_id, event_sequence, block_height);
    let payload = json!({
        "stream_id": stream_id,
        "event_sequence": event_sequence,
        "block_height": block_height,
        "receipt_index": receipt_index,
        "ciphertext": format!("devnet-encrypted-event-{event_sequence}"),
    });
    let matched_filter_root = payload_root(
        "contract-event-subscription:matched-filter",
        &json!({"filter_id": filter_id, "event_sequence": event_sequence}),
    );
    ContractEventCommitment {
        event_id: event_id.clone(),
        stream_id: stream_id.to_string(),
        event_sequence,
        block_height,
        receipt_index,
        encrypted_event_payload: payload_root(
            "contract-event-subscription:encrypted-event",
            &payload,
        ),
        event_payload_commitment: payload_root(
            "contract-event-subscription:event-payload",
            &payload,
        ),
        topic_commitment_root: payload_root(
            "contract-event-subscription:event-topics",
            &json!({"topics": ["swap_executed", "private_amount"], "sequence": event_sequence}),
        ),
        matched_filter_root,
        nullifier: domain_hash(
            "contract-event-subscription:event-nullifier",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&event_id),
                HashPart::Str(filter_id),
            ],
            32,
        ),
        witness_commitment: payload_root(
            "contract-event-subscription:event-witness",
            &json!({"filter_id": filter_id, "receipt_index": receipt_index}),
        ),
        status: EventCommitmentStatus::Delivered,
        privacy_set_size,
        indexer_fee_bps: 4,
    }
}
