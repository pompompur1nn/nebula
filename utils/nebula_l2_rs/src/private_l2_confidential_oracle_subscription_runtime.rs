use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2ConfidentialOracleSubscriptionRuntimeResult<T> = Result<T, String>;

pub const PRIVATE_L2_CONFIDENTIAL_ORACLE_SUBSCRIPTION_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-confidential-oracle-subscription-runtime-v1";
pub const PRIVATE_L2_CONFIDENTIAL_ORACLE_SUBSCRIPTION_RUNTIME_SCHEMA_VERSION: u64 = 1;
pub const PRIVATE_L2_CONFIDENTIAL_ORACLE_SUBSCRIPTION_RUNTIME_HASH_SUITE: &str =
    "SHAKE256-domain-separated-canonical-json";
pub const PRIVATE_L2_CONFIDENTIAL_ORACLE_SUBSCRIPTION_RUNTIME_PQ_AUTH_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-oracle-subscription-v1";
pub const PRIVATE_L2_CONFIDENTIAL_ORACLE_SUBSCRIPTION_RUNTIME_DEVNET_HEIGHT: u64 = 936_000;
pub const PRIVATE_L2_CONFIDENTIAL_ORACLE_SUBSCRIPTION_RUNTIME_MAX_BPS: u64 = 10_000;
pub const PRIVATE_L2_CONFIDENTIAL_ORACLE_SUBSCRIPTION_RUNTIME_DEFAULT_MAX_FEEDS: usize = 262_144;
pub const PRIVATE_L2_CONFIDENTIAL_ORACLE_SUBSCRIPTION_RUNTIME_DEFAULT_MAX_SUBSCRIPTIONS: usize =
    4_194_304;
pub const PRIVATE_L2_CONFIDENTIAL_ORACLE_SUBSCRIPTION_RUNTIME_DEFAULT_MAX_UPDATES: usize =
    8_388_608;
pub const PRIVATE_L2_CONFIDENTIAL_ORACLE_SUBSCRIPTION_RUNTIME_DEFAULT_MAX_ATTESTATIONS: usize =
    4_194_304;
pub const PRIVATE_L2_CONFIDENTIAL_ORACLE_SUBSCRIPTION_RUNTIME_DEFAULT_MAX_RESERVATIONS: usize =
    4_194_304;
pub const PRIVATE_L2_CONFIDENTIAL_ORACLE_SUBSCRIPTION_RUNTIME_DEFAULT_MAX_BATCHES: usize =
    1_048_576;
pub const PRIVATE_L2_CONFIDENTIAL_ORACLE_SUBSCRIPTION_RUNTIME_DEFAULT_MAX_RECEIPTS: usize =
    8_388_608;
pub const PRIVATE_L2_CONFIDENTIAL_ORACLE_SUBSCRIPTION_RUNTIME_DEFAULT_MAX_REBATES: usize =
    4_194_304;
pub const PRIVATE_L2_CONFIDENTIAL_ORACLE_SUBSCRIPTION_RUNTIME_DEFAULT_MAX_BATCH_ITEMS: usize =
    16_384;
pub const PRIVATE_L2_CONFIDENTIAL_ORACLE_SUBSCRIPTION_RUNTIME_DEFAULT_MIN_PRIVACY_SET_SIZE: u64 =
    16_384;
pub const PRIVATE_L2_CONFIDENTIAL_ORACLE_SUBSCRIPTION_RUNTIME_DEFAULT_BATCH_PRIVACY_SET_SIZE: u64 =
    262_144;
pub const PRIVATE_L2_CONFIDENTIAL_ORACLE_SUBSCRIPTION_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS: u16 =
    256;
pub const PRIVATE_L2_CONFIDENTIAL_ORACLE_SUBSCRIPTION_RUNTIME_DEFAULT_MAX_SUBSCRIBER_FEE_BPS: u64 =
    10;
pub const PRIVATE_L2_CONFIDENTIAL_ORACLE_SUBSCRIPTION_RUNTIME_DEFAULT_MAX_PUBLISHER_FEE_BPS: u64 =
    6;
pub const PRIVATE_L2_CONFIDENTIAL_ORACLE_SUBSCRIPTION_RUNTIME_DEFAULT_MAX_SPONSOR_FEE_BPS: u64 = 8;
pub const PRIVATE_L2_CONFIDENTIAL_ORACLE_SUBSCRIPTION_RUNTIME_DEFAULT_TARGET_REBATE_BPS: u64 = 5;
pub const PRIVATE_L2_CONFIDENTIAL_ORACLE_SUBSCRIPTION_RUNTIME_DEFAULT_SUBSCRIPTION_TTL_BLOCKS: u64 =
    7_200;
pub const PRIVATE_L2_CONFIDENTIAL_ORACLE_SUBSCRIPTION_RUNTIME_DEFAULT_RESERVATION_TTL_BLOCKS: u64 =
    72;
pub const PRIVATE_L2_CONFIDENTIAL_ORACLE_SUBSCRIPTION_RUNTIME_DEFAULT_BATCH_TTL_BLOCKS: u64 = 36;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OracleFeedKind {
    PriceIndex,
    VolatilitySurface,
    ReserveProof,
    LiquidationSignal,
    RfqReferencePrice,
    BridgeLiquidity,
    GovernanceMetric,
    Custom,
}

impl OracleFeedKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PriceIndex => "price_index",
            Self::VolatilitySurface => "volatility_surface",
            Self::ReserveProof => "reserve_proof",
            Self::LiquidationSignal => "liquidation_signal",
            Self::RfqReferencePrice => "rfq_reference_price",
            Self::BridgeLiquidity => "bridge_liquidity",
            Self::GovernanceMetric => "governance_metric",
            Self::Custom => "custom",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FeedStatus {
    Open,
    Paused,
    Draining,
    Retired,
}

impl FeedStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Paused => "paused",
            Self::Draining => "draining",
            Self::Retired => "retired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SubscriptionStatus {
    Active,
    Paused,
    Expired,
    Cancelled,
    Exhausted,
}

impl SubscriptionStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Paused => "paused",
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
            Self::Exhausted => "exhausted",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UpdateStatus {
    Published,
    Attested,
    Batched,
    Delivered,
    Disputed,
    Expired,
}

impl UpdateStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Published => "published",
            Self::Attested => "attested",
            Self::Batched => "batched",
            Self::Delivered => "delivered",
            Self::Disputed => "disputed",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationVerdict {
    Valid,
    Delayed,
    Quarantined,
    Invalid,
}

impl AttestationVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Valid => "valid",
            Self::Delayed => "delayed",
            Self::Quarantined => "quarantined",
            Self::Invalid => "invalid",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationStatus {
    Recorded,
    Applied,
    Superseded,
    Expired,
}

impl AttestationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Recorded => "recorded",
            Self::Applied => "applied",
            Self::Superseded => "superseded",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorReservationStatus {
    Reserved,
    Consumed,
    Released,
    Expired,
}

impl SponsorReservationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Consumed => "consumed",
            Self::Released => "released",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DeliveryBatchStatus {
    Open,
    Sealed,
    Delivered,
    Disputed,
    Expired,
}

impl DeliveryBatchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Sealed => "sealed",
            Self::Delivered => "delivered",
            Self::Disputed => "disputed",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptKind {
    UpdateDelivery,
    SubscriptionDebit,
    PublisherCredit,
    SponsorSettlement,
    DisputeResolution,
}

impl ReceiptKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::UpdateDelivery => "update_delivery",
            Self::SubscriptionDebit => "subscription_debit",
            Self::PublisherCredit => "publisher_credit",
            Self::SponsorSettlement => "sponsor_settlement",
            Self::DisputeResolution => "dispute_resolution",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub schema_version: u64,
    pub devnet_height: u64,
    pub fee_asset_id: String,
    pub max_feeds: usize,
    pub max_subscriptions: usize,
    pub max_updates: usize,
    pub max_attestations: usize,
    pub max_reservations: usize,
    pub max_batches: usize,
    pub max_receipts: usize,
    pub max_rebates: usize,
    pub max_batch_items: usize,
    pub min_privacy_set_size: u64,
    pub batch_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub max_subscriber_fee_bps: u64,
    pub max_publisher_fee_bps: u64,
    pub max_sponsor_fee_bps: u64,
    pub target_rebate_bps: u64,
    pub subscription_ttl_blocks: u64,
    pub reservation_ttl_blocks: u64,
    pub batch_ttl_blocks: u64,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            schema_version: PRIVATE_L2_CONFIDENTIAL_ORACLE_SUBSCRIPTION_RUNTIME_SCHEMA_VERSION,
            devnet_height: PRIVATE_L2_CONFIDENTIAL_ORACLE_SUBSCRIPTION_RUNTIME_DEVNET_HEIGHT,
            fee_asset_id: "piconero-devnet".to_string(),
            max_feeds: PRIVATE_L2_CONFIDENTIAL_ORACLE_SUBSCRIPTION_RUNTIME_DEFAULT_MAX_FEEDS,
            max_subscriptions:
                PRIVATE_L2_CONFIDENTIAL_ORACLE_SUBSCRIPTION_RUNTIME_DEFAULT_MAX_SUBSCRIPTIONS,
            max_updates: PRIVATE_L2_CONFIDENTIAL_ORACLE_SUBSCRIPTION_RUNTIME_DEFAULT_MAX_UPDATES,
            max_attestations:
                PRIVATE_L2_CONFIDENTIAL_ORACLE_SUBSCRIPTION_RUNTIME_DEFAULT_MAX_ATTESTATIONS,
            max_reservations:
                PRIVATE_L2_CONFIDENTIAL_ORACLE_SUBSCRIPTION_RUNTIME_DEFAULT_MAX_RESERVATIONS,
            max_batches: PRIVATE_L2_CONFIDENTIAL_ORACLE_SUBSCRIPTION_RUNTIME_DEFAULT_MAX_BATCHES,
            max_receipts: PRIVATE_L2_CONFIDENTIAL_ORACLE_SUBSCRIPTION_RUNTIME_DEFAULT_MAX_RECEIPTS,
            max_rebates: PRIVATE_L2_CONFIDENTIAL_ORACLE_SUBSCRIPTION_RUNTIME_DEFAULT_MAX_REBATES,
            max_batch_items:
                PRIVATE_L2_CONFIDENTIAL_ORACLE_SUBSCRIPTION_RUNTIME_DEFAULT_MAX_BATCH_ITEMS,
            min_privacy_set_size:
                PRIVATE_L2_CONFIDENTIAL_ORACLE_SUBSCRIPTION_RUNTIME_DEFAULT_MIN_PRIVACY_SET_SIZE,
            batch_privacy_set_size:
                PRIVATE_L2_CONFIDENTIAL_ORACLE_SUBSCRIPTION_RUNTIME_DEFAULT_BATCH_PRIVACY_SET_SIZE,
            min_pq_security_bits:
                PRIVATE_L2_CONFIDENTIAL_ORACLE_SUBSCRIPTION_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS,
            max_subscriber_fee_bps:
                PRIVATE_L2_CONFIDENTIAL_ORACLE_SUBSCRIPTION_RUNTIME_DEFAULT_MAX_SUBSCRIBER_FEE_BPS,
            max_publisher_fee_bps:
                PRIVATE_L2_CONFIDENTIAL_ORACLE_SUBSCRIPTION_RUNTIME_DEFAULT_MAX_PUBLISHER_FEE_BPS,
            max_sponsor_fee_bps:
                PRIVATE_L2_CONFIDENTIAL_ORACLE_SUBSCRIPTION_RUNTIME_DEFAULT_MAX_SPONSOR_FEE_BPS,
            target_rebate_bps:
                PRIVATE_L2_CONFIDENTIAL_ORACLE_SUBSCRIPTION_RUNTIME_DEFAULT_TARGET_REBATE_BPS,
            subscription_ttl_blocks:
                PRIVATE_L2_CONFIDENTIAL_ORACLE_SUBSCRIPTION_RUNTIME_DEFAULT_SUBSCRIPTION_TTL_BLOCKS,
            reservation_ttl_blocks:
                PRIVATE_L2_CONFIDENTIAL_ORACLE_SUBSCRIPTION_RUNTIME_DEFAULT_RESERVATION_TTL_BLOCKS,
            batch_ttl_blocks:
                PRIVATE_L2_CONFIDENTIAL_ORACLE_SUBSCRIPTION_RUNTIME_DEFAULT_BATCH_TTL_BLOCKS,
        }
    }

    pub fn validate(&self) -> PrivateL2ConfidentialOracleSubscriptionRuntimeResult<()> {
        require_non_empty("fee_asset_id", &self.fee_asset_id)?;
        require_positive_usize("max_feeds", self.max_feeds)?;
        require_positive_usize("max_subscriptions", self.max_subscriptions)?;
        require_positive_usize("max_updates", self.max_updates)?;
        require_positive_usize("max_attestations", self.max_attestations)?;
        require_positive_usize("max_reservations", self.max_reservations)?;
        require_positive_usize("max_batches", self.max_batches)?;
        require_positive_usize("max_receipts", self.max_receipts)?;
        require_positive_usize("max_rebates", self.max_rebates)?;
        require_positive_usize("max_batch_items", self.max_batch_items)?;
        require_min_u64("min_privacy_set_size", self.min_privacy_set_size, 128)?;
        require_min_u64(
            "batch_privacy_set_size",
            self.batch_privacy_set_size,
            self.min_privacy_set_size,
        )?;
        if self.min_pq_security_bits
            < PRIVATE_L2_CONFIDENTIAL_ORACLE_SUBSCRIPTION_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS
        {
            return Err("oracle subscription PQ security bits below floor".to_string());
        }
        require_bps("max_subscriber_fee_bps", self.max_subscriber_fee_bps)?;
        require_bps("max_publisher_fee_bps", self.max_publisher_fee_bps)?;
        require_bps("max_sponsor_fee_bps", self.max_sponsor_fee_bps)?;
        require_bps("target_rebate_bps", self.target_rebate_bps)?;
        require_positive_u64("subscription_ttl_blocks", self.subscription_ttl_blocks)?;
        require_positive_u64("reservation_ttl_blocks", self.reservation_ttl_blocks)?;
        require_positive_u64("batch_ttl_blocks", self.batch_ttl_blocks)?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "schema_version": self.schema_version,
            "devnet_height": self.devnet_height,
            "fee_asset_id": self.fee_asset_id,
            "max_feeds": self.max_feeds,
            "max_subscriptions": self.max_subscriptions,
            "max_updates": self.max_updates,
            "max_attestations": self.max_attestations,
            "max_reservations": self.max_reservations,
            "max_batches": self.max_batches,
            "max_receipts": self.max_receipts,
            "max_rebates": self.max_rebates,
            "max_batch_items": self.max_batch_items,
            "min_privacy_set_size": self.min_privacy_set_size,
            "batch_privacy_set_size": self.batch_privacy_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
            "max_subscriber_fee_bps": self.max_subscriber_fee_bps,
            "max_publisher_fee_bps": self.max_publisher_fee_bps,
            "max_sponsor_fee_bps": self.max_sponsor_fee_bps,
            "target_rebate_bps": self.target_rebate_bps,
            "subscription_ttl_blocks": self.subscription_ttl_blocks,
            "reservation_ttl_blocks": self.reservation_ttl_blocks,
            "batch_ttl_blocks": self.batch_ttl_blocks,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub feeds_registered: u64,
    pub subscriptions_opened: u64,
    pub updates_published: u64,
    pub attestations_recorded: u64,
    pub reservations_opened: u64,
    pub batches_built: u64,
    pub receipts_published: u64,
    pub rebates_published: u64,
    pub stale_records_expired: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "feeds_registered": self.feeds_registered,
            "subscriptions_opened": self.subscriptions_opened,
            "updates_published": self.updates_published,
            "attestations_recorded": self.attestations_recorded,
            "reservations_opened": self.reservations_opened,
            "batches_built": self.batches_built,
            "receipts_published": self.receipts_published,
            "rebates_published": self.rebates_published,
            "stale_records_expired": self.stale_records_expired,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RegisterOracleFeedRequest {
    pub feed_kind: OracleFeedKind,
    pub feed_label: String,
    pub publisher_commitment: String,
    pub feed_metadata_root: String,
    pub update_schema_root: String,
    pub access_policy_root: String,
    pub pq_publisher_auth_root: String,
    pub min_update_interval_blocks: u64,
    pub publisher_fee_bps: u64,
    pub privacy_set_size: u64,
    pub registered_at_height: u64,
}

impl RegisterOracleFeedRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "feed_kind": self.feed_kind.as_str(),
            "feed_label": self.feed_label,
            "publisher_commitment": self.publisher_commitment,
            "feed_metadata_root": self.feed_metadata_root,
            "update_schema_root": self.update_schema_root,
            "access_policy_root": self.access_policy_root,
            "pq_publisher_auth_root": self.pq_publisher_auth_root,
            "min_update_interval_blocks": self.min_update_interval_blocks,
            "publisher_fee_bps": self.publisher_fee_bps,
            "privacy_set_size": self.privacy_set_size,
            "registered_at_height": self.registered_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OpenOracleSubscriptionRequest {
    pub feed_id: String,
    pub subscriber_commitment: String,
    pub encrypted_delivery_key_root: String,
    pub callback_contract_root: String,
    pub subscription_nullifier: String,
    pub fee_deposit_commitment_root: String,
    pub pq_subscriber_auth_root: String,
    pub max_updates: u64,
    pub subscriber_fee_bps: u64,
    pub privacy_set_size: u64,
    pub expires_at_height: u64,
}

impl OpenOracleSubscriptionRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "feed_id": self.feed_id,
            "subscriber_commitment": self.subscriber_commitment,
            "encrypted_delivery_key_root": self.encrypted_delivery_key_root,
            "callback_contract_root": self.callback_contract_root,
            "subscription_nullifier": self.subscription_nullifier,
            "fee_deposit_commitment_root": self.fee_deposit_commitment_root,
            "pq_subscriber_auth_root": self.pq_subscriber_auth_root,
            "max_updates": self.max_updates,
            "subscriber_fee_bps": self.subscriber_fee_bps,
            "privacy_set_size": self.privacy_set_size,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublishOracleUpdateRequest {
    pub feed_id: String,
    pub publisher_commitment: String,
    pub encrypted_update_payload_root: String,
    pub update_value_commitment_root: String,
    pub update_nullifier: String,
    pub freshness_proof_root: String,
    pub pq_publisher_signature_root: String,
    pub published_at_height: u64,
    pub expires_at_height: u64,
}

impl PublishOracleUpdateRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "feed_id": self.feed_id,
            "publisher_commitment": self.publisher_commitment,
            "encrypted_update_payload_root": self.encrypted_update_payload_root,
            "update_value_commitment_root": self.update_value_commitment_root,
            "update_nullifier": self.update_nullifier,
            "freshness_proof_root": self.freshness_proof_root,
            "pq_publisher_signature_root": self.pq_publisher_signature_root,
            "published_at_height": self.published_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AttestOracleUpdateRequest {
    pub update_id: String,
    pub feed_id: String,
    pub attestor_commitment: String,
    pub verdict: AttestationVerdict,
    pub latency_ms: u64,
    pub confidence_bps: u64,
    pub pq_attestation_root: String,
    pub valid_until_height: u64,
}

impl AttestOracleUpdateRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "update_id": self.update_id,
            "feed_id": self.feed_id,
            "attestor_commitment": self.attestor_commitment,
            "verdict": self.verdict.as_str(),
            "latency_ms": self.latency_ms,
            "confidence_bps": self.confidence_bps,
            "pq_attestation_root": self.pq_attestation_root,
            "valid_until_height": self.valid_until_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReserveOracleSponsorRequest {
    pub subscription_id: String,
    pub feed_id: String,
    pub sponsor_commitment: String,
    pub sponsored_fee_asset_id: String,
    pub reserved_fee_commitment_root: String,
    pub sponsor_auth_root: String,
    pub max_sponsor_fee_bps: u64,
    pub expires_at_height: u64,
}

impl ReserveOracleSponsorRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "subscription_id": self.subscription_id,
            "feed_id": self.feed_id,
            "sponsor_commitment": self.sponsor_commitment,
            "sponsored_fee_asset_id": self.sponsored_fee_asset_id,
            "reserved_fee_commitment_root": self.reserved_fee_commitment_root,
            "sponsor_auth_root": self.sponsor_auth_root,
            "max_sponsor_fee_bps": self.max_sponsor_fee_bps,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BuildOracleDeliveryBatchRequest {
    pub feed_id: String,
    pub update_ids: Vec<String>,
    pub subscription_ids: Vec<String>,
    pub sponsor_reservation_ids: Vec<String>,
    pub delivery_operator_commitment: String,
    pub aggregate_delivery_root: String,
    pub aggregate_pq_authorization_root: String,
    pub aggregate_privacy_proof_root: String,
    pub aggregate_fee_root: String,
    pub batch_privacy_set_size: u64,
    pub expires_at_height: u64,
}

impl BuildOracleDeliveryBatchRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "feed_id": self.feed_id,
            "update_ids": self.update_ids,
            "subscription_ids": self.subscription_ids,
            "sponsor_reservation_ids": self.sponsor_reservation_ids,
            "delivery_operator_commitment": self.delivery_operator_commitment,
            "aggregate_delivery_root": self.aggregate_delivery_root,
            "aggregate_pq_authorization_root": self.aggregate_pq_authorization_root,
            "aggregate_privacy_proof_root": self.aggregate_privacy_proof_root,
            "aggregate_fee_root": self.aggregate_fee_root,
            "batch_privacy_set_size": self.batch_privacy_set_size,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublishOracleDeliveryReceiptRequest {
    pub batch_id: String,
    pub update_id: String,
    pub subscription_id: String,
    pub receipt_kind: ReceiptKind,
    pub delivery_receipt_root: String,
    pub fee_paid_commitment_root: String,
    pub pq_receipt_auth_root: String,
    pub published_at_height: u64,
}

impl PublishOracleDeliveryReceiptRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "update_id": self.update_id,
            "subscription_id": self.subscription_id,
            "receipt_kind": self.receipt_kind.as_str(),
            "delivery_receipt_root": self.delivery_receipt_root,
            "fee_paid_commitment_root": self.fee_paid_commitment_root,
            "pq_receipt_auth_root": self.pq_receipt_auth_root,
            "published_at_height": self.published_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublishOracleRebateRequest {
    pub receipt_id: String,
    pub beneficiary_commitment: String,
    pub rebate_asset_id: String,
    pub rebate_commitment_root: String,
    pub fee_credit_root: String,
    pub pq_rebate_auth_root: String,
    pub published_at_height: u64,
}

impl PublishOracleRebateRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "beneficiary_commitment": self.beneficiary_commitment,
            "rebate_asset_id": self.rebate_asset_id,
            "rebate_commitment_root": self.rebate_commitment_root,
            "fee_credit_root": self.fee_credit_root,
            "pq_rebate_auth_root": self.pq_rebate_auth_root,
            "published_at_height": self.published_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OracleFeedRecord {
    pub feed_id: String,
    pub request: RegisterOracleFeedRequest,
    pub status: FeedStatus,
    pub registered_sequence: u64,
    pub update_count: u64,
    pub subscription_count: u64,
}

impl OracleFeedRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "feed_id": self.feed_id,
            "request": self.request.public_record(),
            "status": self.status.as_str(),
            "registered_sequence": self.registered_sequence,
            "update_count": self.update_count,
            "subscription_count": self.subscription_count,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OracleSubscriptionRecord {
    pub subscription_id: String,
    pub request: OpenOracleSubscriptionRequest,
    pub status: SubscriptionStatus,
    pub opened_sequence: u64,
    pub delivered_updates: u64,
    pub sponsor_reservation_ids: Vec<String>,
}

impl OracleSubscriptionRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "subscription_id": self.subscription_id,
            "request": self.request.public_record(),
            "status": self.status.as_str(),
            "opened_sequence": self.opened_sequence,
            "delivered_updates": self.delivered_updates,
            "sponsor_reservation_ids": self.sponsor_reservation_ids,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OracleUpdateRecord {
    pub update_id: String,
    pub request: PublishOracleUpdateRequest,
    pub status: UpdateStatus,
    pub published_sequence: u64,
    pub attestation_ids: Vec<String>,
    pub batch_id: String,
}

impl OracleUpdateRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "update_id": self.update_id,
            "request": self.request.public_record(),
            "status": self.status.as_str(),
            "published_sequence": self.published_sequence,
            "attestation_ids": self.attestation_ids,
            "batch_id": self.batch_id,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OracleAttestationRecord {
    pub attestation_id: String,
    pub request: AttestOracleUpdateRequest,
    pub status: AttestationStatus,
    pub recorded_sequence: u64,
}

impl OracleAttestationRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "request": self.request.public_record(),
            "status": self.status.as_str(),
            "recorded_sequence": self.recorded_sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OracleSponsorReservationRecord {
    pub reservation_id: String,
    pub request: ReserveOracleSponsorRequest,
    pub status: SponsorReservationStatus,
    pub reserved_sequence: u64,
}

impl OracleSponsorReservationRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "reservation_id": self.reservation_id,
            "request": self.request.public_record(),
            "status": self.status.as_str(),
            "reserved_sequence": self.reserved_sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OracleDeliveryBatchRecord {
    pub batch_id: String,
    pub request: BuildOracleDeliveryBatchRequest,
    pub status: DeliveryBatchStatus,
    pub built_sequence: u64,
    pub update_root: String,
    pub subscription_root: String,
    pub reservation_root: String,
}

impl OracleDeliveryBatchRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "request": self.request.public_record(),
            "status": self.status.as_str(),
            "built_sequence": self.built_sequence,
            "update_root": self.update_root,
            "subscription_root": self.subscription_root,
            "reservation_root": self.reservation_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OracleDeliveryReceiptRecord {
    pub receipt_id: String,
    pub request: PublishOracleDeliveryReceiptRequest,
    pub published_sequence: u64,
}

impl OracleDeliveryReceiptRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "request": self.request.public_record(),
            "published_sequence": self.published_sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OracleRebateRecord {
    pub rebate_id: String,
    pub request: PublishOracleRebateRequest,
    pub published_sequence: u64,
}

impl OracleRebateRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "rebate_id": self.rebate_id,
            "request": self.request.public_record(),
            "published_sequence": self.published_sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub feed_root: String,
    pub subscription_root: String,
    pub update_root: String,
    pub attestation_root: String,
    pub reservation_root: String,
    pub batch_root: String,
    pub receipt_root: String,
    pub rebate_root: String,
    pub nullifier_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "feed_root": self.feed_root,
            "subscription_root": self.subscription_root,
            "update_root": self.update_root,
            "attestation_root": self.attestation_root,
            "reservation_root": self.reservation_root,
            "batch_root": self.batch_root,
            "receipt_root": self.receipt_root,
            "rebate_root": self.rebate_root,
            "nullifier_root": self.nullifier_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub current_height: u64,
    pub config: Config,
    pub counters: Counters,
    pub feeds: BTreeMap<String, OracleFeedRecord>,
    pub subscriptions: BTreeMap<String, OracleSubscriptionRecord>,
    pub updates: BTreeMap<String, OracleUpdateRecord>,
    pub attestations: BTreeMap<String, OracleAttestationRecord>,
    pub reservations: BTreeMap<String, OracleSponsorReservationRecord>,
    pub batches: BTreeMap<String, OracleDeliveryBatchRecord>,
    pub receipts: BTreeMap<String, OracleDeliveryReceiptRecord>,
    pub rebates: BTreeMap<String, OracleRebateRecord>,
    pub consumed_nullifiers: BTreeSet<String>,
}

impl State {
    pub fn devnet() -> PrivateL2ConfidentialOracleSubscriptionRuntimeResult<Self> {
        Self::new(Config::devnet())
    }

    pub fn new(config: Config) -> PrivateL2ConfidentialOracleSubscriptionRuntimeResult<Self> {
        config.validate()?;
        Ok(Self {
            current_height: config.devnet_height,
            config,
            counters: Counters::default(),
            feeds: BTreeMap::new(),
            subscriptions: BTreeMap::new(),
            updates: BTreeMap::new(),
            attestations: BTreeMap::new(),
            reservations: BTreeMap::new(),
            batches: BTreeMap::new(),
            receipts: BTreeMap::new(),
            rebates: BTreeMap::new(),
            consumed_nullifiers: BTreeSet::new(),
        })
    }

    pub fn register_feed(
        &mut self,
        request: RegisterOracleFeedRequest,
    ) -> PrivateL2ConfidentialOracleSubscriptionRuntimeResult<String> {
        require_capacity("feeds", self.feeds.len(), self.config.max_feeds)?;
        self.validate_feed_request(&request)?;
        let sequence = self.counters.feeds_registered.saturating_add(1);
        let feed_id = oracle_feed_id(&request, sequence);
        if self.feeds.contains_key(&feed_id) {
            return Err("oracle feed id collision".to_string());
        }
        self.feeds.insert(
            feed_id.clone(),
            OracleFeedRecord {
                feed_id: feed_id.clone(),
                request,
                status: FeedStatus::Open,
                registered_sequence: sequence,
                update_count: 0,
                subscription_count: 0,
            },
        );
        self.counters.feeds_registered = sequence;
        Ok(feed_id)
    }

    pub fn open_subscription(
        &mut self,
        request: OpenOracleSubscriptionRequest,
    ) -> PrivateL2ConfidentialOracleSubscriptionRuntimeResult<String> {
        require_capacity(
            "subscriptions",
            self.subscriptions.len(),
            self.config.max_subscriptions,
        )?;
        self.validate_subscription_request(&request)?;
        if !self
            .consumed_nullifiers
            .insert(request.subscription_nullifier.clone())
        {
            return Err("oracle subscription nullifier already consumed".to_string());
        }
        let sequence = self.counters.subscriptions_opened.saturating_add(1);
        let subscription_id = oracle_subscription_id(&request, sequence);
        if self.subscriptions.contains_key(&subscription_id) {
            return Err("oracle subscription id collision".to_string());
        }
        self.subscriptions.insert(
            subscription_id.clone(),
            OracleSubscriptionRecord {
                subscription_id: subscription_id.clone(),
                request: request.clone(),
                status: SubscriptionStatus::Active,
                opened_sequence: sequence,
                delivered_updates: 0,
                sponsor_reservation_ids: Vec::new(),
            },
        );
        if let Some(feed) = self.feeds.get_mut(&request.feed_id) {
            feed.subscription_count = feed.subscription_count.saturating_add(1);
        }
        self.counters.subscriptions_opened = sequence;
        Ok(subscription_id)
    }

    pub fn publish_update(
        &mut self,
        request: PublishOracleUpdateRequest,
    ) -> PrivateL2ConfidentialOracleSubscriptionRuntimeResult<String> {
        require_capacity("updates", self.updates.len(), self.config.max_updates)?;
        self.validate_update_request(&request)?;
        if !self
            .consumed_nullifiers
            .insert(request.update_nullifier.clone())
        {
            return Err("oracle update nullifier already consumed".to_string());
        }
        let sequence = self.counters.updates_published.saturating_add(1);
        let update_id = oracle_update_id(&request, sequence);
        if self.updates.contains_key(&update_id) {
            return Err("oracle update id collision".to_string());
        }
        self.updates.insert(
            update_id.clone(),
            OracleUpdateRecord {
                update_id: update_id.clone(),
                request: request.clone(),
                status: UpdateStatus::Published,
                published_sequence: sequence,
                attestation_ids: Vec::new(),
                batch_id: String::new(),
            },
        );
        if let Some(feed) = self.feeds.get_mut(&request.feed_id) {
            feed.update_count = feed.update_count.saturating_add(1);
        }
        self.counters.updates_published = sequence;
        Ok(update_id)
    }

    pub fn attest_update(
        &mut self,
        request: AttestOracleUpdateRequest,
    ) -> PrivateL2ConfidentialOracleSubscriptionRuntimeResult<String> {
        require_capacity(
            "attestations",
            self.attestations.len(),
            self.config.max_attestations,
        )?;
        self.validate_attestation_request(&request)?;
        let sequence = self.counters.attestations_recorded.saturating_add(1);
        let attestation_id = oracle_attestation_id(&request, sequence);
        self.attestations.insert(
            attestation_id.clone(),
            OracleAttestationRecord {
                attestation_id: attestation_id.clone(),
                request: request.clone(),
                status: AttestationStatus::Recorded,
                recorded_sequence: sequence,
            },
        );
        if let Some(update) = self.updates.get_mut(&request.update_id) {
            update.status = UpdateStatus::Attested;
            update.attestation_ids.push(attestation_id.clone());
        }
        self.counters.attestations_recorded = sequence;
        Ok(attestation_id)
    }

    pub fn reserve_sponsor(
        &mut self,
        request: ReserveOracleSponsorRequest,
    ) -> PrivateL2ConfidentialOracleSubscriptionRuntimeResult<String> {
        require_capacity(
            "reservations",
            self.reservations.len(),
            self.config.max_reservations,
        )?;
        self.validate_reservation_request(&request)?;
        let sequence = self.counters.reservations_opened.saturating_add(1);
        let reservation_id = oracle_sponsor_reservation_id(&request, sequence);
        self.reservations.insert(
            reservation_id.clone(),
            OracleSponsorReservationRecord {
                reservation_id: reservation_id.clone(),
                request: request.clone(),
                status: SponsorReservationStatus::Reserved,
                reserved_sequence: sequence,
            },
        );
        if let Some(subscription) = self.subscriptions.get_mut(&request.subscription_id) {
            subscription
                .sponsor_reservation_ids
                .push(reservation_id.clone());
        }
        self.counters.reservations_opened = sequence;
        Ok(reservation_id)
    }

    pub fn build_delivery_batch(
        &mut self,
        request: BuildOracleDeliveryBatchRequest,
    ) -> PrivateL2ConfidentialOracleSubscriptionRuntimeResult<String> {
        require_capacity("batches", self.batches.len(), self.config.max_batches)?;
        self.validate_batch_request(&request)?;
        let sequence = self.counters.batches_built.saturating_add(1);
        let batch_id = oracle_delivery_batch_id(&request, sequence);
        let update_root = id_list_root(
            "PRIVATE-L2-CONFIDENTIAL-ORACLE-BATCH-UPDATE-ROOT",
            request.update_ids.iter(),
        );
        let subscription_root = id_list_root(
            "PRIVATE-L2-CONFIDENTIAL-ORACLE-BATCH-SUBSCRIPTION-ROOT",
            request.subscription_ids.iter(),
        );
        let reservation_root = id_list_root(
            "PRIVATE-L2-CONFIDENTIAL-ORACLE-BATCH-RESERVATION-ROOT",
            request.sponsor_reservation_ids.iter(),
        );
        self.batches.insert(
            batch_id.clone(),
            OracleDeliveryBatchRecord {
                batch_id: batch_id.clone(),
                request: request.clone(),
                status: DeliveryBatchStatus::Sealed,
                built_sequence: sequence,
                update_root,
                subscription_root,
                reservation_root,
            },
        );
        for update_id in &request.update_ids {
            if let Some(update) = self.updates.get_mut(update_id) {
                update.status = UpdateStatus::Batched;
                update.batch_id = batch_id.clone();
            }
        }
        for reservation_id in &request.sponsor_reservation_ids {
            if let Some(reservation) = self.reservations.get_mut(reservation_id) {
                reservation.status = SponsorReservationStatus::Consumed;
            }
        }
        self.counters.batches_built = sequence;
        Ok(batch_id)
    }

    pub fn publish_receipt(
        &mut self,
        request: PublishOracleDeliveryReceiptRequest,
    ) -> PrivateL2ConfidentialOracleSubscriptionRuntimeResult<String> {
        require_capacity("receipts", self.receipts.len(), self.config.max_receipts)?;
        self.validate_receipt_request(&request)?;
        let sequence = self.counters.receipts_published.saturating_add(1);
        let receipt_id = oracle_delivery_receipt_id(&request, sequence);
        self.receipts.insert(
            receipt_id.clone(),
            OracleDeliveryReceiptRecord {
                receipt_id: receipt_id.clone(),
                request: request.clone(),
                published_sequence: sequence,
            },
        );
        if let Some(update) = self.updates.get_mut(&request.update_id) {
            update.status = UpdateStatus::Delivered;
        }
        if let Some(subscription) = self.subscriptions.get_mut(&request.subscription_id) {
            subscription.delivered_updates = subscription.delivered_updates.saturating_add(1);
            if subscription.delivered_updates >= subscription.request.max_updates {
                subscription.status = SubscriptionStatus::Exhausted;
            }
        }
        if let Some(batch) = self.batches.get_mut(&request.batch_id) {
            batch.status = DeliveryBatchStatus::Delivered;
        }
        self.counters.receipts_published = sequence;
        Ok(receipt_id)
    }

    pub fn publish_rebate(
        &mut self,
        request: PublishOracleRebateRequest,
    ) -> PrivateL2ConfidentialOracleSubscriptionRuntimeResult<String> {
        require_capacity("rebates", self.rebates.len(), self.config.max_rebates)?;
        self.validate_rebate_request(&request)?;
        let sequence = self.counters.rebates_published.saturating_add(1);
        let rebate_id = oracle_rebate_id(&request, sequence);
        self.rebates.insert(
            rebate_id.clone(),
            OracleRebateRecord {
                rebate_id: rebate_id.clone(),
                request,
                published_sequence: sequence,
            },
        );
        self.counters.rebates_published = sequence;
        Ok(rebate_id)
    }

    pub fn expire_stale(&mut self, height: u64) -> u64 {
        self.current_height = self.current_height.max(height);
        let mut expired = 0_u64;
        for subscription in self.subscriptions.values_mut() {
            if subscription.status == SubscriptionStatus::Active
                && subscription.request.expires_at_height <= height
            {
                subscription.status = SubscriptionStatus::Expired;
                expired = expired.saturating_add(1);
            }
        }
        for update in self.updates.values_mut() {
            if matches!(
                update.status,
                UpdateStatus::Published | UpdateStatus::Attested
            ) && update.request.expires_at_height <= height
            {
                update.status = UpdateStatus::Expired;
                expired = expired.saturating_add(1);
            }
        }
        for reservation in self.reservations.values_mut() {
            if reservation.status == SponsorReservationStatus::Reserved
                && reservation.request.expires_at_height <= height
            {
                reservation.status = SponsorReservationStatus::Expired;
                expired = expired.saturating_add(1);
            }
        }
        for batch in self.batches.values_mut() {
            if batch.status == DeliveryBatchStatus::Sealed
                && batch.request.expires_at_height <= height
            {
                batch.status = DeliveryBatchStatus::Expired;
                expired = expired.saturating_add(1);
            }
        }
        self.counters.stale_records_expired =
            self.counters.stale_records_expired.saturating_add(expired);
        expired
    }

    pub fn roots(&self) -> Roots {
        Roots {
            feed_root: record_root(
                "PRIVATE-L2-CONFIDENTIAL-ORACLE-FEED-ROOT",
                self.feeds.values().map(OracleFeedRecord::public_record),
            ),
            subscription_root: record_root(
                "PRIVATE-L2-CONFIDENTIAL-ORACLE-SUBSCRIPTION-ROOT",
                self.subscriptions
                    .values()
                    .map(OracleSubscriptionRecord::public_record),
            ),
            update_root: record_root(
                "PRIVATE-L2-CONFIDENTIAL-ORACLE-UPDATE-ROOT",
                self.updates.values().map(OracleUpdateRecord::public_record),
            ),
            attestation_root: record_root(
                "PRIVATE-L2-CONFIDENTIAL-ORACLE-ATTESTATION-ROOT",
                self.attestations
                    .values()
                    .map(OracleAttestationRecord::public_record),
            ),
            reservation_root: record_root(
                "PRIVATE-L2-CONFIDENTIAL-ORACLE-RESERVATION-ROOT",
                self.reservations
                    .values()
                    .map(OracleSponsorReservationRecord::public_record),
            ),
            batch_root: record_root(
                "PRIVATE-L2-CONFIDENTIAL-ORACLE-BATCH-ROOT",
                self.batches
                    .values()
                    .map(OracleDeliveryBatchRecord::public_record),
            ),
            receipt_root: record_root(
                "PRIVATE-L2-CONFIDENTIAL-ORACLE-RECEIPT-ROOT",
                self.receipts
                    .values()
                    .map(OracleDeliveryReceiptRecord::public_record),
            ),
            rebate_root: record_root(
                "PRIVATE-L2-CONFIDENTIAL-ORACLE-REBATE-ROOT",
                self.rebates.values().map(OracleRebateRecord::public_record),
            ),
            nullifier_root: id_list_root(
                "PRIVATE-L2-CONFIDENTIAL-ORACLE-NULLIFIER-ROOT",
                self.consumed_nullifiers.iter(),
            ),
        }
    }

    pub fn public_record_without_state_root(&self) -> Value {
        json!({
            "kind": "private_l2_confidential_oracle_subscription_runtime",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_L2_CONFIDENTIAL_ORACLE_SUBSCRIPTION_RUNTIME_PROTOCOL_VERSION,
            "hash_suite": PRIVATE_L2_CONFIDENTIAL_ORACLE_SUBSCRIPTION_RUNTIME_HASH_SUITE,
            "pq_auth_suite": PRIVATE_L2_CONFIDENTIAL_ORACLE_SUBSCRIPTION_RUNTIME_PQ_AUTH_SUITE,
            "current_height": self.current_height,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": self.roots().public_record(),
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        record
            .as_object_mut()
            .expect("oracle subscription public record is an object")
            .insert("state_root".to_string(), Value::String(self.state_root()));
        record
    }

    pub fn state_root(&self) -> String {
        state_root_from_record(&self.public_record_without_state_root())
    }

    fn validate_feed_request(
        &self,
        request: &RegisterOracleFeedRequest,
    ) -> PrivateL2ConfidentialOracleSubscriptionRuntimeResult<()> {
        require_non_empty("feed_label", &request.feed_label)?;
        require_non_empty("publisher_commitment", &request.publisher_commitment)?;
        require_non_empty("feed_metadata_root", &request.feed_metadata_root)?;
        require_non_empty("update_schema_root", &request.update_schema_root)?;
        require_non_empty("access_policy_root", &request.access_policy_root)?;
        require_non_empty("pq_publisher_auth_root", &request.pq_publisher_auth_root)?;
        require_positive_u64(
            "min_update_interval_blocks",
            request.min_update_interval_blocks,
        )?;
        if request.publisher_fee_bps > self.config.max_publisher_fee_bps {
            return Err("oracle feed publisher fee exceeds configured maximum".to_string());
        }
        require_min_u64(
            "privacy_set_size",
            request.privacy_set_size,
            self.config.min_privacy_set_size,
        )
    }

    fn validate_subscription_request(
        &self,
        request: &OpenOracleSubscriptionRequest,
    ) -> PrivateL2ConfidentialOracleSubscriptionRuntimeResult<()> {
        let feed = self
            .feeds
            .get(&request.feed_id)
            .ok_or_else(|| "oracle subscription feed not found".to_string())?;
        if feed.status != FeedStatus::Open {
            return Err("oracle feed is not open".to_string());
        }
        require_non_empty("subscriber_commitment", &request.subscriber_commitment)?;
        require_non_empty(
            "encrypted_delivery_key_root",
            &request.encrypted_delivery_key_root,
        )?;
        require_non_empty("callback_contract_root", &request.callback_contract_root)?;
        require_non_empty("subscription_nullifier", &request.subscription_nullifier)?;
        require_non_empty(
            "fee_deposit_commitment_root",
            &request.fee_deposit_commitment_root,
        )?;
        require_non_empty("pq_subscriber_auth_root", &request.pq_subscriber_auth_root)?;
        require_positive_u64("max_updates", request.max_updates)?;
        if request.subscriber_fee_bps > self.config.max_subscriber_fee_bps {
            return Err("oracle subscription fee exceeds configured maximum".to_string());
        }
        require_min_u64(
            "privacy_set_size",
            request.privacy_set_size,
            self.config.min_privacy_set_size,
        )?;
        if request.expires_at_height <= self.current_height {
            return Err("oracle subscription expiry must be in the future".to_string());
        }
        if request.expires_at_height - self.current_height > self.config.subscription_ttl_blocks {
            return Err("oracle subscription ttl exceeds configured maximum".to_string());
        }
        Ok(())
    }

    fn validate_update_request(
        &self,
        request: &PublishOracleUpdateRequest,
    ) -> PrivateL2ConfidentialOracleSubscriptionRuntimeResult<()> {
        let feed = self
            .feeds
            .get(&request.feed_id)
            .ok_or_else(|| "oracle update feed not found".to_string())?;
        if feed.status != FeedStatus::Open {
            return Err("oracle feed is not open for updates".to_string());
        }
        if feed.request.publisher_commitment != request.publisher_commitment {
            return Err("oracle update publisher mismatch".to_string());
        }
        require_non_empty(
            "encrypted_update_payload_root",
            &request.encrypted_update_payload_root,
        )?;
        require_non_empty(
            "update_value_commitment_root",
            &request.update_value_commitment_root,
        )?;
        require_non_empty("update_nullifier", &request.update_nullifier)?;
        require_non_empty("freshness_proof_root", &request.freshness_proof_root)?;
        require_non_empty(
            "pq_publisher_signature_root",
            &request.pq_publisher_signature_root,
        )?;
        if request.published_at_height < self.current_height {
            return Err("oracle update cannot be published in the past".to_string());
        }
        if request.expires_at_height <= request.published_at_height {
            return Err("oracle update expiry must be after publish height".to_string());
        }
        Ok(())
    }

    fn validate_attestation_request(
        &self,
        request: &AttestOracleUpdateRequest,
    ) -> PrivateL2ConfidentialOracleSubscriptionRuntimeResult<()> {
        let update = self
            .updates
            .get(&request.update_id)
            .ok_or_else(|| "oracle attestation update not found".to_string())?;
        if update.request.feed_id != request.feed_id {
            return Err("oracle attestation feed mismatch".to_string());
        }
        require_non_empty("attestor_commitment", &request.attestor_commitment)?;
        require_non_empty("pq_attestation_root", &request.pq_attestation_root)?;
        require_bps("confidence_bps", request.confidence_bps)?;
        if request.verdict == AttestationVerdict::Invalid {
            return Err("invalid oracle updates are not accepted into active state".to_string());
        }
        if request.valid_until_height <= self.current_height {
            return Err("oracle attestation expiry must be in the future".to_string());
        }
        Ok(())
    }

    fn validate_reservation_request(
        &self,
        request: &ReserveOracleSponsorRequest,
    ) -> PrivateL2ConfidentialOracleSubscriptionRuntimeResult<()> {
        let subscription = self
            .subscriptions
            .get(&request.subscription_id)
            .ok_or_else(|| "oracle sponsor subscription not found".to_string())?;
        if subscription.request.feed_id != request.feed_id {
            return Err("oracle sponsor feed mismatch".to_string());
        }
        if subscription.status != SubscriptionStatus::Active {
            return Err("oracle sponsor subscription is not active".to_string());
        }
        require_non_empty("sponsor_commitment", &request.sponsor_commitment)?;
        require_non_empty("sponsored_fee_asset_id", &request.sponsored_fee_asset_id)?;
        require_non_empty(
            "reserved_fee_commitment_root",
            &request.reserved_fee_commitment_root,
        )?;
        require_non_empty("sponsor_auth_root", &request.sponsor_auth_root)?;
        if request.max_sponsor_fee_bps > self.config.max_sponsor_fee_bps {
            return Err("oracle sponsor fee exceeds configured maximum".to_string());
        }
        if request.expires_at_height <= self.current_height {
            return Err("oracle sponsor reservation expiry must be in the future".to_string());
        }
        if request.expires_at_height - self.current_height > self.config.reservation_ttl_blocks {
            return Err("oracle sponsor ttl exceeds configured maximum".to_string());
        }
        Ok(())
    }

    fn validate_batch_request(
        &self,
        request: &BuildOracleDeliveryBatchRequest,
    ) -> PrivateL2ConfidentialOracleSubscriptionRuntimeResult<()> {
        require_non_empty("feed_id", &request.feed_id)?;
        require_unique("update_ids", &request.update_ids)?;
        require_unique("subscription_ids", &request.subscription_ids)?;
        require_unique("sponsor_reservation_ids", &request.sponsor_reservation_ids)?;
        if request.update_ids.is_empty() || request.subscription_ids.is_empty() {
            return Err("oracle delivery batch needs updates and subscriptions".to_string());
        }
        if request
            .update_ids
            .len()
            .saturating_mul(request.subscription_ids.len())
            > self.config.max_batch_items
        {
            return Err("oracle delivery batch exceeds item limit".to_string());
        }
        require_non_empty(
            "delivery_operator_commitment",
            &request.delivery_operator_commitment,
        )?;
        require_non_empty("aggregate_delivery_root", &request.aggregate_delivery_root)?;
        require_non_empty(
            "aggregate_pq_authorization_root",
            &request.aggregate_pq_authorization_root,
        )?;
        require_non_empty(
            "aggregate_privacy_proof_root",
            &request.aggregate_privacy_proof_root,
        )?;
        require_non_empty("aggregate_fee_root", &request.aggregate_fee_root)?;
        require_min_u64(
            "batch_privacy_set_size",
            request.batch_privacy_set_size,
            self.config.batch_privacy_set_size,
        )?;
        if request.expires_at_height <= self.current_height {
            return Err("oracle delivery batch expiry must be in the future".to_string());
        }
        if request.expires_at_height - self.current_height > self.config.batch_ttl_blocks {
            return Err("oracle delivery batch ttl exceeds configured maximum".to_string());
        }
        for update_id in &request.update_ids {
            let update = self
                .updates
                .get(update_id)
                .ok_or_else(|| format!("oracle update {update_id} not found"))?;
            if update.request.feed_id != request.feed_id {
                return Err(format!("oracle update {update_id} feed mismatch"));
            }
            if !matches!(
                update.status,
                UpdateStatus::Published | UpdateStatus::Attested
            ) {
                return Err(format!("oracle update {update_id} is not deliverable"));
            }
        }
        for subscription_id in &request.subscription_ids {
            let subscription = self
                .subscriptions
                .get(subscription_id)
                .ok_or_else(|| format!("oracle subscription {subscription_id} not found"))?;
            if subscription.request.feed_id != request.feed_id {
                return Err(format!(
                    "oracle subscription {subscription_id} feed mismatch"
                ));
            }
            if subscription.status != SubscriptionStatus::Active {
                return Err(format!(
                    "oracle subscription {subscription_id} is not active"
                ));
            }
        }
        Ok(())
    }

    fn validate_receipt_request(
        &self,
        request: &PublishOracleDeliveryReceiptRequest,
    ) -> PrivateL2ConfidentialOracleSubscriptionRuntimeResult<()> {
        let batch = self
            .batches
            .get(&request.batch_id)
            .ok_or_else(|| "oracle receipt batch not found".to_string())?;
        if !batch
            .request
            .update_ids
            .iter()
            .any(|id| id == &request.update_id)
        {
            return Err("oracle receipt update not in batch".to_string());
        }
        if !batch
            .request
            .subscription_ids
            .iter()
            .any(|id| id == &request.subscription_id)
        {
            return Err("oracle receipt subscription not in batch".to_string());
        }
        require_non_empty("delivery_receipt_root", &request.delivery_receipt_root)?;
        require_non_empty(
            "fee_paid_commitment_root",
            &request.fee_paid_commitment_root,
        )?;
        require_non_empty("pq_receipt_auth_root", &request.pq_receipt_auth_root)?;
        Ok(())
    }

    fn validate_rebate_request(
        &self,
        request: &PublishOracleRebateRequest,
    ) -> PrivateL2ConfidentialOracleSubscriptionRuntimeResult<()> {
        if !self.receipts.contains_key(&request.receipt_id) {
            return Err("oracle rebate receipt not found".to_string());
        }
        require_non_empty("beneficiary_commitment", &request.beneficiary_commitment)?;
        require_non_empty("rebate_asset_id", &request.rebate_asset_id)?;
        require_non_empty("rebate_commitment_root", &request.rebate_commitment_root)?;
        require_non_empty("fee_credit_root", &request.fee_credit_root)?;
        require_non_empty("pq_rebate_auth_root", &request.pq_rebate_auth_root)?;
        Ok(())
    }
}

pub type Runtime = State;

pub fn oracle_feed_id(request: &RegisterOracleFeedRequest, sequence: u64) -> String {
    payload_id(
        "PRIVATE-L2-CONFIDENTIAL-ORACLE-FEED-ID",
        &json!({ "sequence": sequence, "request": request.public_record() }),
    )
}

pub fn oracle_subscription_id(request: &OpenOracleSubscriptionRequest, sequence: u64) -> String {
    payload_id(
        "PRIVATE-L2-CONFIDENTIAL-ORACLE-SUBSCRIPTION-ID",
        &json!({ "sequence": sequence, "request": request.public_record() }),
    )
}

pub fn oracle_update_id(request: &PublishOracleUpdateRequest, sequence: u64) -> String {
    payload_id(
        "PRIVATE-L2-CONFIDENTIAL-ORACLE-UPDATE-ID",
        &json!({ "sequence": sequence, "request": request.public_record() }),
    )
}

pub fn oracle_attestation_id(request: &AttestOracleUpdateRequest, sequence: u64) -> String {
    payload_id(
        "PRIVATE-L2-CONFIDENTIAL-ORACLE-ATTESTATION-ID",
        &json!({ "sequence": sequence, "request": request.public_record() }),
    )
}

pub fn oracle_sponsor_reservation_id(
    request: &ReserveOracleSponsorRequest,
    sequence: u64,
) -> String {
    payload_id(
        "PRIVATE-L2-CONFIDENTIAL-ORACLE-SPONSOR-RESERVATION-ID",
        &json!({ "sequence": sequence, "request": request.public_record() }),
    )
}

pub fn oracle_delivery_batch_id(
    request: &BuildOracleDeliveryBatchRequest,
    sequence: u64,
) -> String {
    payload_id(
        "PRIVATE-L2-CONFIDENTIAL-ORACLE-DELIVERY-BATCH-ID",
        &json!({ "sequence": sequence, "request": request.public_record() }),
    )
}

pub fn oracle_delivery_receipt_id(
    request: &PublishOracleDeliveryReceiptRequest,
    sequence: u64,
) -> String {
    payload_id(
        "PRIVATE-L2-CONFIDENTIAL-ORACLE-DELIVERY-RECEIPT-ID",
        &json!({ "sequence": sequence, "request": request.public_record() }),
    )
}

pub fn oracle_rebate_id(request: &PublishOracleRebateRequest, sequence: u64) -> String {
    payload_id(
        "PRIVATE-L2-CONFIDENTIAL-ORACLE-REBATE-ID",
        &json!({ "sequence": sequence, "request": request.public_record() }),
    )
}

pub fn root_from_record(domain: &str, record: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PRIVATE_L2_CONFIDENTIAL_ORACLE_SUBSCRIPTION_RUNTIME_PROTOCOL_VERSION),
            HashPart::Json(record),
        ],
        32,
    )
}

pub fn payload_root(domain: &str, payload: &Value) -> String {
    root_from_record(domain, payload)
}

pub fn public_record_root(domain: &str, records: &[Value]) -> String {
    let leaves = records
        .iter()
        .enumerate()
        .map(|(index, record)| {
            Value::String(root_from_record(
                domain,
                &json!({ "index": index, "record": record }),
            ))
        })
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

pub fn state_root_from_record(record: &Value) -> String {
    root_from_record(
        "PRIVATE-L2-CONFIDENTIAL-ORACLE-SUBSCRIPTION-STATE-ROOT",
        record,
    )
}

fn payload_id(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PRIVATE_L2_CONFIDENTIAL_ORACLE_SUBSCRIPTION_RUNTIME_PROTOCOL_VERSION),
            HashPart::Json(payload),
        ],
        32,
    )
}

fn record_root<I>(domain: &str, records: I) -> String
where
    I: Iterator<Item = Value>,
{
    public_record_root(domain, &records.collect::<Vec<_>>())
}

fn id_list_root<'a, I>(domain: &str, ids: I) -> String
where
    I: Iterator<Item = &'a String>,
{
    let leaves = ids
        .enumerate()
        .map(|(index, id)| {
            Value::String(domain_hash(
                domain,
                &[HashPart::Int(index as i128), HashPart::Str(id)],
                32,
            ))
        })
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn require_non_empty(
    name: &str,
    value: &str,
) -> PrivateL2ConfidentialOracleSubscriptionRuntimeResult<()> {
    if value.trim().is_empty() {
        Err(format!("oracle subscription {name} must not be empty"))
    } else {
        Ok(())
    }
}

fn require_positive_usize(
    name: &str,
    value: usize,
) -> PrivateL2ConfidentialOracleSubscriptionRuntimeResult<()> {
    if value == 0 {
        Err(format!("oracle subscription {name} must be positive"))
    } else {
        Ok(())
    }
}

fn require_positive_u64(
    name: &str,
    value: u64,
) -> PrivateL2ConfidentialOracleSubscriptionRuntimeResult<()> {
    if value == 0 {
        Err(format!("oracle subscription {name} must be positive"))
    } else {
        Ok(())
    }
}

fn require_min_u64(
    name: &str,
    value: u64,
    min: u64,
) -> PrivateL2ConfidentialOracleSubscriptionRuntimeResult<()> {
    if value < min {
        Err(format!("oracle subscription {name} must be at least {min}"))
    } else {
        Ok(())
    }
}

fn require_bps(name: &str, value: u64) -> PrivateL2ConfidentialOracleSubscriptionRuntimeResult<()> {
    if value > PRIVATE_L2_CONFIDENTIAL_ORACLE_SUBSCRIPTION_RUNTIME_MAX_BPS {
        Err(format!(
            "oracle subscription {name} exceeds basis-point maximum"
        ))
    } else {
        Ok(())
    }
}

fn require_capacity(
    name: &str,
    current: usize,
    max: usize,
) -> PrivateL2ConfidentialOracleSubscriptionRuntimeResult<()> {
    if current >= max {
        Err(format!("oracle subscription {name} capacity exhausted"))
    } else {
        Ok(())
    }
}

fn require_unique(
    name: &str,
    values: &[String],
) -> PrivateL2ConfidentialOracleSubscriptionRuntimeResult<()> {
    let mut seen = BTreeSet::new();
    for value in values {
        require_non_empty(name, value)?;
        if !seen.insert(value) {
            return Err(format!(
                "oracle subscription {name} contains duplicate id {value}"
            ));
        }
    }
    Ok(())
}
