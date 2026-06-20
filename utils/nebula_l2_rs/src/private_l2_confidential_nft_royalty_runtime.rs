use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2ConfidentialNftRoyaltyRuntimeResult<T> = Result<T, String>;

pub const PRIVATE_L2_CONFIDENTIAL_NFT_ROYALTY_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-confidential-nft-royalty-runtime-v1";
pub const PRIVATE_L2_CONFIDENTIAL_NFT_ROYALTY_RUNTIME_SCHEMA_VERSION: u64 = 1;
pub const PRIVATE_L2_CONFIDENTIAL_NFT_ROYALTY_RUNTIME_HASH_SUITE: &str =
    "SHAKE256-domain-separated-canonical-json";
pub const PRIVATE_L2_CONFIDENTIAL_NFT_ROYALTY_RUNTIME_PQ_AUTH_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256s-nft-royalty-v1";
pub const PRIVATE_L2_CONFIDENTIAL_NFT_ROYALTY_RUNTIME_COLLECTION_SCHEME: &str =
    "private-l2-shielded-nft-collection-root-v1";
pub const PRIVATE_L2_CONFIDENTIAL_NFT_ROYALTY_RUNTIME_MINT_NOTE_SCHEME: &str =
    "private-l2-confidential-nft-mint-note-root-v1";
pub const PRIVATE_L2_CONFIDENTIAL_NFT_ROYALTY_RUNTIME_MARKET_NOTE_SCHEME: &str =
    "private-l2-confidential-nft-marketplace-note-root-v1";
pub const PRIVATE_L2_CONFIDENTIAL_NFT_ROYALTY_RUNTIME_ROYALTY_SPLIT_SCHEME: &str =
    "private-l2-confidential-nft-royalty-split-root-v1";
pub const PRIVATE_L2_CONFIDENTIAL_NFT_ROYALTY_RUNTIME_SPONSOR_SCHEME: &str =
    "roots-only-low-fee-nft-royalty-sponsor-reservation-v1";
pub const PRIVATE_L2_CONFIDENTIAL_NFT_ROYALTY_RUNTIME_BATCH_SCHEME: &str =
    "private-l2-confidential-nft-sealed-transfer-batch-root-v1";
pub const PRIVATE_L2_CONFIDENTIAL_NFT_ROYALTY_RUNTIME_SETTLEMENT_SCHEME: &str =
    "private-l2-confidential-nft-fast-settlement-receipt-v1";
pub const PRIVATE_L2_CONFIDENTIAL_NFT_ROYALTY_RUNTIME_REBATE_SCHEME: &str =
    "private-l2-confidential-nft-royalty-rebate-receipt-v1";
pub const PRIVATE_L2_CONFIDENTIAL_NFT_ROYALTY_RUNTIME_DEVNET_HEIGHT: u64 = 648_000;
pub const PRIVATE_L2_CONFIDENTIAL_NFT_ROYALTY_RUNTIME_DEFAULT_MONERO_NETWORK: &str =
    "monero-devnet";
pub const PRIVATE_L2_CONFIDENTIAL_NFT_ROYALTY_RUNTIME_DEFAULT_L2_NETWORK: &str = "nebula-devnet";
pub const PRIVATE_L2_CONFIDENTIAL_NFT_ROYALTY_RUNTIME_DEFAULT_FEE_ASSET_ID: &str =
    "piconero-devnet";
pub const PRIVATE_L2_CONFIDENTIAL_NFT_ROYALTY_RUNTIME_DEFAULT_SETTLEMENT_ASSET_ID: &str =
    "wxmr-devnet";
pub const PRIVATE_L2_CONFIDENTIAL_NFT_ROYALTY_RUNTIME_DEFAULT_LOW_FEE_LANE: &str =
    "private-l2-confidential-nft-royalty";
pub const PRIVATE_L2_CONFIDENTIAL_NFT_ROYALTY_RUNTIME_DEFAULT_MAX_COLLECTIONS: usize = 262_144;
pub const PRIVATE_L2_CONFIDENTIAL_NFT_ROYALTY_RUNTIME_DEFAULT_MAX_MINT_NOTES: usize = 8_388_608;
pub const PRIVATE_L2_CONFIDENTIAL_NFT_ROYALTY_RUNTIME_DEFAULT_MAX_MARKET_NOTES: usize = 8_388_608;
pub const PRIVATE_L2_CONFIDENTIAL_NFT_ROYALTY_RUNTIME_DEFAULT_MAX_ROYALTY_ATTESTATIONS: usize =
    2_097_152;
pub const PRIVATE_L2_CONFIDENTIAL_NFT_ROYALTY_RUNTIME_DEFAULT_MAX_SPONSOR_RESERVATIONS: usize =
    2_097_152;
pub const PRIVATE_L2_CONFIDENTIAL_NFT_ROYALTY_RUNTIME_DEFAULT_MAX_BATCHES: usize = 1_048_576;
pub const PRIVATE_L2_CONFIDENTIAL_NFT_ROYALTY_RUNTIME_DEFAULT_MAX_SETTLEMENT_RECEIPTS: usize =
    1_048_576;
pub const PRIVATE_L2_CONFIDENTIAL_NFT_ROYALTY_RUNTIME_DEFAULT_MAX_REBATE_RECEIPTS: usize =
    1_048_576;
pub const PRIVATE_L2_CONFIDENTIAL_NFT_ROYALTY_RUNTIME_DEFAULT_MAX_BATCH_ITEMS: usize = 16_384;
pub const PRIVATE_L2_CONFIDENTIAL_NFT_ROYALTY_RUNTIME_DEFAULT_MAX_ROYALTY_SPLITS: usize = 64;
pub const PRIVATE_L2_CONFIDENTIAL_NFT_ROYALTY_RUNTIME_DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 16_384;
pub const PRIVATE_L2_CONFIDENTIAL_NFT_ROYALTY_RUNTIME_DEFAULT_BATCH_PRIVACY_SET_SIZE: u64 = 262_144;
pub const PRIVATE_L2_CONFIDENTIAL_NFT_ROYALTY_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const PRIVATE_L2_CONFIDENTIAL_NFT_ROYALTY_RUNTIME_DEFAULT_MAX_USER_FEE_BPS: u64 = 12;
pub const PRIVATE_L2_CONFIDENTIAL_NFT_ROYALTY_RUNTIME_DEFAULT_MAX_SPONSOR_FEE_BPS: u64 = 8;
pub const PRIVATE_L2_CONFIDENTIAL_NFT_ROYALTY_RUNTIME_DEFAULT_MAX_ROYALTY_BPS: u64 = 2_000;
pub const PRIVATE_L2_CONFIDENTIAL_NFT_ROYALTY_RUNTIME_DEFAULT_MINT_NOTE_TTL_BLOCKS: u64 = 36;
pub const PRIVATE_L2_CONFIDENTIAL_NFT_ROYALTY_RUNTIME_DEFAULT_MARKET_NOTE_TTL_BLOCKS: u64 = 18;
pub const PRIVATE_L2_CONFIDENTIAL_NFT_ROYALTY_RUNTIME_DEFAULT_SPONSOR_TTL_BLOCKS: u64 = 72;
pub const PRIVATE_L2_CONFIDENTIAL_NFT_ROYALTY_RUNTIME_DEFAULT_BATCH_TTL_BLOCKS: u64 = 12;
pub const PRIVATE_L2_CONFIDENTIAL_NFT_ROYALTY_RUNTIME_MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CollectionKind {
    Art,
    Gaming,
    Music,
    Membership,
    RealWorldAsset,
    DomainName,
    DeFiPosition,
    ContractBound,
}

impl CollectionKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Art => "art",
            Self::Gaming => "gaming",
            Self::Music => "music",
            Self::Membership => "membership",
            Self::RealWorldAsset => "real_world_asset",
            Self::DomainName => "domain_name",
            Self::DeFiPosition => "defi_position",
            Self::ContractBound => "contract_bound",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CollectionStatus {
    Registered,
    MintOpen,
    MarketOpen,
    Paused,
    Frozen,
    Retired,
}

impl CollectionStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Registered => "registered",
            Self::MintOpen => "mint_open",
            Self::MarketOpen => "market_open",
            Self::Paused => "paused",
            Self::Frozen => "frozen",
            Self::Retired => "retired",
        }
    }

    pub fn accepts_mints(self) -> bool {
        matches!(self, Self::Registered | Self::MintOpen | Self::MarketOpen)
    }

    pub fn accepts_market_notes(self) -> bool {
        matches!(self, Self::MarketOpen)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MintNoteStatus {
    Pending,
    PqAuthorized,
    SponsorCovered,
    TransferQueued,
    Settled,
    Rejected,
    Expired,
}

impl MintNoteStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::PqAuthorized => "pq_authorized",
            Self::SponsorCovered => "sponsor_covered",
            Self::TransferQueued => "transfer_queued",
            Self::Settled => "settled",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }

    pub fn batchable(self) -> bool {
        matches!(
            self,
            Self::Pending | Self::PqAuthorized | Self::SponsorCovered
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MarketNoteKind {
    PrivateListing,
    PrivateBid,
    CollectionOffer,
    RoyaltySwap,
    CollateralizedListing,
    FractionalExit,
}

impl MarketNoteKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrivateListing => "private_listing",
            Self::PrivateBid => "private_bid",
            Self::CollectionOffer => "collection_offer",
            Self::RoyaltySwap => "royalty_swap",
            Self::CollateralizedListing => "collateralized_listing",
            Self::FractionalExit => "fractional_exit",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MarketNoteStatus {
    Pending,
    Matched,
    PqAuthorized,
    SponsorCovered,
    Batched,
    Settled,
    Cancelled,
    Rejected,
    Expired,
}

impl MarketNoteStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Matched => "matched",
            Self::PqAuthorized => "pq_authorized",
            Self::SponsorCovered => "sponsor_covered",
            Self::Batched => "batched",
            Self::Settled => "settled",
            Self::Cancelled => "cancelled",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }

    pub fn batchable(self) -> bool {
        matches!(
            self,
            Self::Matched | Self::PqAuthorized | Self::SponsorCovered
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RoyaltyAttestationKind {
    CreatorSplit,
    MarketplaceSplit,
    RebateEligibility,
    CollectionOverride,
    SecondarySaleProof,
    DeFiRoyaltyRoute,
}

impl RoyaltyAttestationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CreatorSplit => "creator_split",
            Self::MarketplaceSplit => "marketplace_split",
            Self::RebateEligibility => "rebate_eligibility",
            Self::CollectionOverride => "collection_override",
            Self::SecondarySaleProof => "secondary_sale_proof",
            Self::DeFiRoyaltyRoute => "defi_royalty_route",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationVerdict {
    Accepted,
    Watch,
    Quarantined,
    Rejected,
}

impl AttestationVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Watch => "watch",
            Self::Quarantined => "quarantined",
            Self::Rejected => "rejected",
        }
    }

    pub fn allows_settlement(self) -> bool {
        matches!(self, Self::Accepted | Self::Watch)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorReservationStatus {
    Reserved,
    Consumed,
    Released,
    Expired,
    Slashed,
}

impl SponsorReservationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Consumed => "consumed",
            Self::Released => "released",
            Self::Expired => "expired",
            Self::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransferBatchStatus {
    Open,
    SettlementReady,
    Settled,
    Rejected,
    Expired,
}

impl TransferBatchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::SettlementReady => "settlement_ready",
            Self::Settled => "settled",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }

    pub fn can_settle(self) -> bool {
        matches!(self, Self::SettlementReady)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptStatus {
    Published,
    Finalized,
    Reorged,
}

impl ReceiptStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Published => "published",
            Self::Finalized => "finalized",
            Self::Reorged => "reorged",
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
    pub fee_asset_id: String,
    pub settlement_asset_id: String,
    pub low_fee_lane: String,
    pub max_collections: usize,
    pub max_mint_notes: usize,
    pub max_market_notes: usize,
    pub max_royalty_attestations: usize,
    pub max_sponsor_reservations: usize,
    pub max_batches: usize,
    pub max_settlement_receipts: usize,
    pub max_rebate_receipts: usize,
    pub max_batch_items: usize,
    pub max_royalty_splits: usize,
    pub min_privacy_set_size: u64,
    pub batch_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub max_user_fee_bps: u64,
    pub max_sponsor_fee_bps: u64,
    pub max_royalty_bps: u64,
    pub mint_note_ttl_blocks: u64,
    pub market_note_ttl_blocks: u64,
    pub sponsor_ttl_blocks: u64,
    pub batch_ttl_blocks: u64,
    pub require_pq_authorization: bool,
    pub require_fee_sponsor: bool,
    pub require_royalty_attestation: bool,
    pub allow_rebate_receipts: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version: PRIVATE_L2_CONFIDENTIAL_NFT_ROYALTY_RUNTIME_PROTOCOL_VERSION
                .to_string(),
            schema_version: PRIVATE_L2_CONFIDENTIAL_NFT_ROYALTY_RUNTIME_SCHEMA_VERSION,
            chain_id: CHAIN_ID.to_string(),
            monero_network: PRIVATE_L2_CONFIDENTIAL_NFT_ROYALTY_RUNTIME_DEFAULT_MONERO_NETWORK
                .to_string(),
            l2_network: PRIVATE_L2_CONFIDENTIAL_NFT_ROYALTY_RUNTIME_DEFAULT_L2_NETWORK.to_string(),
            fee_asset_id: PRIVATE_L2_CONFIDENTIAL_NFT_ROYALTY_RUNTIME_DEFAULT_FEE_ASSET_ID
                .to_string(),
            settlement_asset_id:
                PRIVATE_L2_CONFIDENTIAL_NFT_ROYALTY_RUNTIME_DEFAULT_SETTLEMENT_ASSET_ID.to_string(),
            low_fee_lane: PRIVATE_L2_CONFIDENTIAL_NFT_ROYALTY_RUNTIME_DEFAULT_LOW_FEE_LANE
                .to_string(),
            max_collections: PRIVATE_L2_CONFIDENTIAL_NFT_ROYALTY_RUNTIME_DEFAULT_MAX_COLLECTIONS,
            max_mint_notes: PRIVATE_L2_CONFIDENTIAL_NFT_ROYALTY_RUNTIME_DEFAULT_MAX_MINT_NOTES,
            max_market_notes: PRIVATE_L2_CONFIDENTIAL_NFT_ROYALTY_RUNTIME_DEFAULT_MAX_MARKET_NOTES,
            max_royalty_attestations:
                PRIVATE_L2_CONFIDENTIAL_NFT_ROYALTY_RUNTIME_DEFAULT_MAX_ROYALTY_ATTESTATIONS,
            max_sponsor_reservations:
                PRIVATE_L2_CONFIDENTIAL_NFT_ROYALTY_RUNTIME_DEFAULT_MAX_SPONSOR_RESERVATIONS,
            max_batches: PRIVATE_L2_CONFIDENTIAL_NFT_ROYALTY_RUNTIME_DEFAULT_MAX_BATCHES,
            max_settlement_receipts:
                PRIVATE_L2_CONFIDENTIAL_NFT_ROYALTY_RUNTIME_DEFAULT_MAX_SETTLEMENT_RECEIPTS,
            max_rebate_receipts:
                PRIVATE_L2_CONFIDENTIAL_NFT_ROYALTY_RUNTIME_DEFAULT_MAX_REBATE_RECEIPTS,
            max_batch_items: PRIVATE_L2_CONFIDENTIAL_NFT_ROYALTY_RUNTIME_DEFAULT_MAX_BATCH_ITEMS,
            max_royalty_splits:
                PRIVATE_L2_CONFIDENTIAL_NFT_ROYALTY_RUNTIME_DEFAULT_MAX_ROYALTY_SPLITS,
            min_privacy_set_size:
                PRIVATE_L2_CONFIDENTIAL_NFT_ROYALTY_RUNTIME_DEFAULT_MIN_PRIVACY_SET_SIZE,
            batch_privacy_set_size:
                PRIVATE_L2_CONFIDENTIAL_NFT_ROYALTY_RUNTIME_DEFAULT_BATCH_PRIVACY_SET_SIZE,
            min_pq_security_bits:
                PRIVATE_L2_CONFIDENTIAL_NFT_ROYALTY_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS,
            max_user_fee_bps: PRIVATE_L2_CONFIDENTIAL_NFT_ROYALTY_RUNTIME_DEFAULT_MAX_USER_FEE_BPS,
            max_sponsor_fee_bps:
                PRIVATE_L2_CONFIDENTIAL_NFT_ROYALTY_RUNTIME_DEFAULT_MAX_SPONSOR_FEE_BPS,
            max_royalty_bps: PRIVATE_L2_CONFIDENTIAL_NFT_ROYALTY_RUNTIME_DEFAULT_MAX_ROYALTY_BPS,
            mint_note_ttl_blocks:
                PRIVATE_L2_CONFIDENTIAL_NFT_ROYALTY_RUNTIME_DEFAULT_MINT_NOTE_TTL_BLOCKS,
            market_note_ttl_blocks:
                PRIVATE_L2_CONFIDENTIAL_NFT_ROYALTY_RUNTIME_DEFAULT_MARKET_NOTE_TTL_BLOCKS,
            sponsor_ttl_blocks:
                PRIVATE_L2_CONFIDENTIAL_NFT_ROYALTY_RUNTIME_DEFAULT_SPONSOR_TTL_BLOCKS,
            batch_ttl_blocks: PRIVATE_L2_CONFIDENTIAL_NFT_ROYALTY_RUNTIME_DEFAULT_BATCH_TTL_BLOCKS,
            require_pq_authorization: true,
            require_fee_sponsor: true,
            require_royalty_attestation: true,
            allow_rebate_receipts: true,
        }
    }

    pub fn validate(&self) -> PrivateL2ConfidentialNftRoyaltyRuntimeResult<()> {
        require_non_empty("protocol version", &self.protocol_version)?;
        require_non_empty("chain id", &self.chain_id)?;
        require_non_empty("monero network", &self.monero_network)?;
        require_non_empty("l2 network", &self.l2_network)?;
        require_non_empty("fee asset id", &self.fee_asset_id)?;
        require_non_empty("settlement asset id", &self.settlement_asset_id)?;
        require_non_empty("low fee lane", &self.low_fee_lane)?;
        if self.schema_version == 0 {
            return Err("NFT royalty schema_version must be positive".to_string());
        }
        if self.max_collections == 0
            || self.max_mint_notes == 0
            || self.max_market_notes == 0
            || self.max_royalty_attestations == 0
            || self.max_sponsor_reservations == 0
            || self.max_batches == 0
            || self.max_settlement_receipts == 0
            || self.max_rebate_receipts == 0
        {
            return Err("NFT royalty runtime capacities must be positive".to_string());
        }
        if self.max_batch_items == 0 {
            return Err("NFT royalty batch item capacity must be positive".to_string());
        }
        if self.max_royalty_splits == 0 {
            return Err("NFT royalty split capacity must be positive".to_string());
        }
        if self.min_privacy_set_size == 0 {
            return Err("NFT royalty min_privacy_set_size must be positive".to_string());
        }
        if self.batch_privacy_set_size < self.min_privacy_set_size {
            return Err("NFT royalty batch privacy set is below minimum".to_string());
        }
        if self.min_pq_security_bits < 128 {
            return Err("NFT royalty PQ security floor is too low".to_string());
        }
        if self.max_user_fee_bps > PRIVATE_L2_CONFIDENTIAL_NFT_ROYALTY_RUNTIME_MAX_BPS
            || self.max_sponsor_fee_bps > PRIVATE_L2_CONFIDENTIAL_NFT_ROYALTY_RUNTIME_MAX_BPS
            || self.max_royalty_bps > PRIVATE_L2_CONFIDENTIAL_NFT_ROYALTY_RUNTIME_MAX_BPS
        {
            return Err("NFT royalty bps limits exceed max bps".to_string());
        }
        if self.max_sponsor_fee_bps > self.max_user_fee_bps {
            return Err("NFT royalty sponsor fee cannot exceed user fee ceiling".to_string());
        }
        if self.mint_note_ttl_blocks == 0
            || self.market_note_ttl_blocks == 0
            || self.sponsor_ttl_blocks == 0
            || self.batch_ttl_blocks == 0
        {
            return Err("NFT royalty TTL values must be positive".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_confidential_nft_royalty_config",
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "chain_id": self.chain_id,
            "monero_network": self.monero_network,
            "l2_network": self.l2_network,
            "fee_asset_id": self.fee_asset_id,
            "settlement_asset_id": self.settlement_asset_id,
            "low_fee_lane": self.low_fee_lane,
            "max_collections": self.max_collections,
            "max_mint_notes": self.max_mint_notes,
            "max_market_notes": self.max_market_notes,
            "max_royalty_attestations": self.max_royalty_attestations,
            "max_sponsor_reservations": self.max_sponsor_reservations,
            "max_batches": self.max_batches,
            "max_settlement_receipts": self.max_settlement_receipts,
            "max_rebate_receipts": self.max_rebate_receipts,
            "max_batch_items": self.max_batch_items,
            "max_royalty_splits": self.max_royalty_splits,
            "min_privacy_set_size": self.min_privacy_set_size,
            "batch_privacy_set_size": self.batch_privacy_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
            "max_user_fee_bps": self.max_user_fee_bps,
            "max_sponsor_fee_bps": self.max_sponsor_fee_bps,
            "max_royalty_bps": self.max_royalty_bps,
            "mint_note_ttl_blocks": self.mint_note_ttl_blocks,
            "market_note_ttl_blocks": self.market_note_ttl_blocks,
            "sponsor_ttl_blocks": self.sponsor_ttl_blocks,
            "batch_ttl_blocks": self.batch_ttl_blocks,
            "require_pq_authorization": self.require_pq_authorization,
            "require_fee_sponsor": self.require_fee_sponsor,
            "require_royalty_attestation": self.require_royalty_attestation,
            "allow_rebate_receipts": self.allow_rebate_receipts,
        })
    }

    pub fn state_root(&self) -> String {
        root_from_record(
            "PRIVATE-L2-CONFIDENTIAL-NFT-ROYALTY-CONFIG",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    pub collections_registered: u64,
    pub mint_notes_submitted: u64,
    pub market_notes_submitted: u64,
    pub royalty_attestations_recorded: u64,
    pub sponsor_reservations: u64,
    pub sealed_batches: u64,
    pub settlement_receipts: u64,
    pub rebate_receipts: u64,
    pub cancelled_notes: u64,
    pub rejected_notes: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_confidential_nft_royalty_counters",
            "collections_registered": self.collections_registered,
            "mint_notes_submitted": self.mint_notes_submitted,
            "market_notes_submitted": self.market_notes_submitted,
            "royalty_attestations_recorded": self.royalty_attestations_recorded,
            "sponsor_reservations": self.sponsor_reservations,
            "sealed_batches": self.sealed_batches,
            "settlement_receipts": self.settlement_receipts,
            "rebate_receipts": self.rebate_receipts,
            "cancelled_notes": self.cancelled_notes,
            "rejected_notes": self.rejected_notes,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisterShieldedCollectionRequest {
    pub collection_slug: String,
    pub collection_kind: CollectionKind,
    pub creator_commitment: String,
    pub metadata_commitment_root: String,
    pub supply_cap_commitment_root: String,
    pub default_royalty_bps: u64,
    pub royalty_policy_root: String,
    pub pq_creator_auth_root: String,
    pub compliance_root: String,
    pub opened_at_height: u64,
}

impl RegisterShieldedCollectionRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "collection_slug": self.collection_slug,
            "collection_kind": self.collection_kind.as_str(),
            "creator_commitment": self.creator_commitment,
            "metadata_commitment_root": self.metadata_commitment_root,
            "supply_cap_commitment_root": self.supply_cap_commitment_root,
            "default_royalty_bps": self.default_royalty_bps,
            "royalty_policy_root": self.royalty_policy_root,
            "pq_creator_auth_root": self.pq_creator_auth_root,
            "compliance_root": self.compliance_root,
            "opened_at_height": self.opened_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubmitConfidentialNftMintNoteRequest {
    pub collection_id: String,
    pub minter_commitment: String,
    pub token_commitment_root: String,
    pub encrypted_metadata_root: String,
    pub serial_nullifier_hash: String,
    pub owner_note_root: String,
    pub royalty_policy_root: String,
    pub mint_price_commitment_root: String,
    pub pq_authorization_root: String,
    pub privacy_set_size: u64,
    pub user_fee_bps: u64,
    pub submitted_at_height: u64,
}

impl SubmitConfidentialNftMintNoteRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "collection_id": self.collection_id,
            "minter_commitment": self.minter_commitment,
            "token_commitment_root": self.token_commitment_root,
            "encrypted_metadata_root": self.encrypted_metadata_root,
            "serial_nullifier_hash": self.serial_nullifier_hash,
            "owner_note_root": self.owner_note_root,
            "royalty_policy_root": self.royalty_policy_root,
            "mint_price_commitment_root": self.mint_price_commitment_root,
            "pq_authorization_root": self.pq_authorization_root,
            "privacy_set_size": self.privacy_set_size,
            "user_fee_bps": self.user_fee_bps,
            "submitted_at_height": self.submitted_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubmitPrivateMarketplaceNoteRequest {
    pub collection_id: String,
    pub kind: MarketNoteKind,
    pub maker_commitment: String,
    pub taker_commitment_root: String,
    pub nft_note_root: String,
    pub price_commitment_root: String,
    pub payment_asset_id: String,
    pub royalty_quote_root: String,
    pub matching_hint_root: String,
    pub pq_authorization_root: String,
    pub privacy_set_size: u64,
    pub user_fee_bps: u64,
    pub submitted_at_height: u64,
}

impl SubmitPrivateMarketplaceNoteRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "collection_id": self.collection_id,
            "kind": self.kind.as_str(),
            "maker_commitment": self.maker_commitment,
            "taker_commitment_root": self.taker_commitment_root,
            "nft_note_root": self.nft_note_root,
            "price_commitment_root": self.price_commitment_root,
            "payment_asset_id": self.payment_asset_id,
            "royalty_quote_root": self.royalty_quote_root,
            "matching_hint_root": self.matching_hint_root,
            "pq_authorization_root": self.pq_authorization_root,
            "privacy_set_size": self.privacy_set_size,
            "user_fee_bps": self.user_fee_bps,
            "submitted_at_height": self.submitted_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordRoyaltySplitAttestationRequest {
    pub collection_id: String,
    pub subject_note_id: String,
    pub kind: RoyaltyAttestationKind,
    pub attestor_commitment: String,
    pub payee_commitment_root: String,
    pub split_commitment_root: String,
    pub royalty_amount_commitment_root: String,
    pub selective_disclosure_root: String,
    pub proof_root: String,
    pub pq_attestation_root: String,
    pub verdict: AttestationVerdict,
    pub total_royalty_bps: u64,
    pub split_count: usize,
    pub attested_at_height: u64,
}

impl RecordRoyaltySplitAttestationRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "collection_id": self.collection_id,
            "subject_note_id": self.subject_note_id,
            "kind": self.kind.as_str(),
            "attestor_commitment": self.attestor_commitment,
            "payee_commitment_root": self.payee_commitment_root,
            "split_commitment_root": self.split_commitment_root,
            "royalty_amount_commitment_root": self.royalty_amount_commitment_root,
            "selective_disclosure_root": self.selective_disclosure_root,
            "proof_root": self.proof_root,
            "pq_attestation_root": self.pq_attestation_root,
            "verdict": self.verdict.as_str(),
            "total_royalty_bps": self.total_royalty_bps,
            "split_count": self.split_count,
            "attested_at_height": self.attested_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReserveLowFeeSponsorRequest {
    pub subject_note_id: String,
    pub sponsor_commitment: String,
    pub budget_root: String,
    pub fee_asset_id: String,
    pub reserved_fee_bps: u64,
    pub reservation_nonce_root: String,
    pub pq_sponsor_auth_root: String,
    pub reserved_at_height: u64,
}

impl ReserveLowFeeSponsorRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "subject_note_id": self.subject_note_id,
            "sponsor_commitment": self.sponsor_commitment,
            "budget_root": self.budget_root,
            "fee_asset_id": self.fee_asset_id,
            "reserved_fee_bps": self.reserved_fee_bps,
            "reservation_nonce_root": self.reservation_nonce_root,
            "pq_sponsor_auth_root": self.pq_sponsor_auth_root,
            "reserved_at_height": self.reserved_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BuildSealedTransferBatchRequest {
    pub operator_commitment: String,
    pub collection_ids: Vec<String>,
    pub mint_note_ids: Vec<String>,
    pub market_note_ids: Vec<String>,
    pub royalty_attestation_ids: Vec<String>,
    pub sponsor_reservation_ids: Vec<String>,
    pub sealed_input_root: String,
    pub sealed_output_root: String,
    pub transfer_proof_root: String,
    pub royalty_distribution_root: String,
    pub aggregate_nullifier_root: String,
    pub pq_batch_auth_root: String,
    pub batch_privacy_set_size: u64,
    pub max_fee_bps: u64,
    pub built_at_height: u64,
}

impl BuildSealedTransferBatchRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "operator_commitment": self.operator_commitment,
            "collection_ids": self.collection_ids,
            "mint_note_ids": self.mint_note_ids,
            "market_note_ids": self.market_note_ids,
            "royalty_attestation_ids": self.royalty_attestation_ids,
            "sponsor_reservation_ids": self.sponsor_reservation_ids,
            "sealed_input_root": self.sealed_input_root,
            "sealed_output_root": self.sealed_output_root,
            "transfer_proof_root": self.transfer_proof_root,
            "royalty_distribution_root": self.royalty_distribution_root,
            "aggregate_nullifier_root": self.aggregate_nullifier_root,
            "pq_batch_auth_root": self.pq_batch_auth_root,
            "batch_privacy_set_size": self.batch_privacy_set_size,
            "max_fee_bps": self.max_fee_bps,
            "built_at_height": self.built_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IssueSettlementReceiptRequest {
    pub batch_id: String,
    pub settlement_tx_root: String,
    pub settlement_proof_root: String,
    pub nft_state_root_before: String,
    pub nft_state_root_after: String,
    pub payment_state_root_after: String,
    pub royalty_state_root_after: String,
    pub nullifier_root_after: String,
    pub fee_receipt_root: String,
    pub pq_settlement_root: String,
    pub settled_fee_bps: u64,
    pub settled_at_height: u64,
}

impl IssueSettlementReceiptRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "settlement_tx_root": self.settlement_tx_root,
            "settlement_proof_root": self.settlement_proof_root,
            "nft_state_root_before": self.nft_state_root_before,
            "nft_state_root_after": self.nft_state_root_after,
            "payment_state_root_after": self.payment_state_root_after,
            "royalty_state_root_after": self.royalty_state_root_after,
            "nullifier_root_after": self.nullifier_root_after,
            "fee_receipt_root": self.fee_receipt_root,
            "pq_settlement_root": self.pq_settlement_root,
            "settled_fee_bps": self.settled_fee_bps,
            "settled_at_height": self.settled_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IssueRoyaltyRebateReceiptRequest {
    pub settlement_receipt_id: String,
    pub beneficiary_commitment: String,
    pub rebate_asset_id: String,
    pub rebate_amount_commitment_root: String,
    pub royalty_credit_root: String,
    pub eligibility_proof_root: String,
    pub sponsor_reservation_id: String,
    pub pq_rebate_auth_root: String,
    pub issued_at_height: u64,
}

impl IssueRoyaltyRebateReceiptRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "settlement_receipt_id": self.settlement_receipt_id,
            "beneficiary_commitment": self.beneficiary_commitment,
            "rebate_asset_id": self.rebate_asset_id,
            "rebate_amount_commitment_root": self.rebate_amount_commitment_root,
            "royalty_credit_root": self.royalty_credit_root,
            "eligibility_proof_root": self.eligibility_proof_root,
            "sponsor_reservation_id": self.sponsor_reservation_id,
            "pq_rebate_auth_root": self.pq_rebate_auth_root,
            "issued_at_height": self.issued_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShieldedCollectionRecord {
    pub collection_id: String,
    pub request: RegisterShieldedCollectionRequest,
    pub status: CollectionStatus,
    pub latest_collection_state_root: String,
    pub minted_note_ids: Vec<String>,
    pub market_note_ids: Vec<String>,
    pub royalty_attestation_ids: Vec<String>,
    pub settled_batch_ids: Vec<String>,
}

impl ShieldedCollectionRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_confidential_nft_collection",
            "collection_id": self.collection_id,
            "collection_slug": self.request.collection_slug,
            "collection_kind": self.request.collection_kind.as_str(),
            "creator_commitment": self.request.creator_commitment,
            "metadata_commitment_root": self.request.metadata_commitment_root,
            "supply_cap_commitment_root": self.request.supply_cap_commitment_root,
            "default_royalty_bps": self.request.default_royalty_bps,
            "royalty_policy_root": self.request.royalty_policy_root,
            "pq_creator_auth_root": self.request.pq_creator_auth_root,
            "compliance_root": self.request.compliance_root,
            "status": self.status.as_str(),
            "latest_collection_state_root": self.latest_collection_state_root,
            "minted_note_ids": self.minted_note_ids,
            "market_note_ids": self.market_note_ids,
            "royalty_attestation_ids": self.royalty_attestation_ids,
            "settled_batch_ids": self.settled_batch_ids,
            "opened_at_height": self.request.opened_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfidentialNftMintNoteRecord {
    pub mint_note_id: String,
    pub request: SubmitConfidentialNftMintNoteRequest,
    pub status: MintNoteStatus,
    pub expires_at_height: u64,
}

impl ConfidentialNftMintNoteRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_confidential_nft_mint_note",
            "mint_note_id": self.mint_note_id,
            "collection_id": self.request.collection_id,
            "minter_commitment": self.request.minter_commitment,
            "token_commitment_root": self.request.token_commitment_root,
            "encrypted_metadata_root": self.request.encrypted_metadata_root,
            "serial_nullifier_hash": self.request.serial_nullifier_hash,
            "owner_note_root": self.request.owner_note_root,
            "royalty_policy_root": self.request.royalty_policy_root,
            "mint_price_commitment_root": self.request.mint_price_commitment_root,
            "pq_authorization_root": self.request.pq_authorization_root,
            "privacy_set_size": self.request.privacy_set_size,
            "user_fee_bps": self.request.user_fee_bps,
            "status": self.status.as_str(),
            "submitted_at_height": self.request.submitted_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateMarketplaceNoteRecord {
    pub market_note_id: String,
    pub request: SubmitPrivateMarketplaceNoteRequest,
    pub status: MarketNoteStatus,
    pub matched_note_id: Option<String>,
    pub expires_at_height: u64,
}

impl PrivateMarketplaceNoteRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_confidential_nft_market_note",
            "market_note_id": self.market_note_id,
            "collection_id": self.request.collection_id,
            "market_note_kind": self.request.kind.as_str(),
            "maker_commitment": self.request.maker_commitment,
            "taker_commitment_root": self.request.taker_commitment_root,
            "nft_note_root": self.request.nft_note_root,
            "price_commitment_root": self.request.price_commitment_root,
            "payment_asset_id": self.request.payment_asset_id,
            "royalty_quote_root": self.request.royalty_quote_root,
            "matching_hint_root": self.request.matching_hint_root,
            "pq_authorization_root": self.request.pq_authorization_root,
            "privacy_set_size": self.request.privacy_set_size,
            "user_fee_bps": self.request.user_fee_bps,
            "status": self.status.as_str(),
            "matched_note_id": self.matched_note_id,
            "submitted_at_height": self.request.submitted_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoyaltySplitAttestationRecord {
    pub attestation_id: String,
    pub request: RecordRoyaltySplitAttestationRequest,
}

impl RoyaltySplitAttestationRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_confidential_nft_royalty_split_attestation",
            "attestation_id": self.attestation_id,
            "collection_id": self.request.collection_id,
            "subject_note_id": self.request.subject_note_id,
            "attestation_kind": self.request.kind.as_str(),
            "attestor_commitment": self.request.attestor_commitment,
            "payee_commitment_root": self.request.payee_commitment_root,
            "split_commitment_root": self.request.split_commitment_root,
            "royalty_amount_commitment_root": self.request.royalty_amount_commitment_root,
            "selective_disclosure_root": self.request.selective_disclosure_root,
            "proof_root": self.request.proof_root,
            "pq_attestation_root": self.request.pq_attestation_root,
            "verdict": self.request.verdict.as_str(),
            "total_royalty_bps": self.request.total_royalty_bps,
            "split_count": self.request.split_count,
            "attested_at_height": self.request.attested_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeSponsorReservationRecord {
    pub reservation_id: String,
    pub request: ReserveLowFeeSponsorRequest,
    pub status: SponsorReservationStatus,
    pub expires_at_height: u64,
}

impl LowFeeSponsorReservationRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_confidential_nft_low_fee_sponsor_reservation",
            "reservation_id": self.reservation_id,
            "subject_note_id": self.request.subject_note_id,
            "sponsor_commitment": self.request.sponsor_commitment,
            "budget_root": self.request.budget_root,
            "fee_asset_id": self.request.fee_asset_id,
            "reserved_fee_bps": self.request.reserved_fee_bps,
            "reservation_nonce_root": self.request.reservation_nonce_root,
            "pq_sponsor_auth_root": self.request.pq_sponsor_auth_root,
            "status": self.status.as_str(),
            "reserved_at_height": self.request.reserved_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedTransferBatchRecord {
    pub batch_id: String,
    pub request: BuildSealedTransferBatchRequest,
    pub status: TransferBatchStatus,
    pub expires_at_height: u64,
}

impl SealedTransferBatchRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_confidential_nft_sealed_transfer_batch",
            "batch_id": self.batch_id,
            "operator_commitment": self.request.operator_commitment,
            "collection_ids": self.request.collection_ids,
            "mint_note_ids": self.request.mint_note_ids,
            "market_note_ids": self.request.market_note_ids,
            "royalty_attestation_ids": self.request.royalty_attestation_ids,
            "sponsor_reservation_ids": self.request.sponsor_reservation_ids,
            "sealed_input_root": self.request.sealed_input_root,
            "sealed_output_root": self.request.sealed_output_root,
            "transfer_proof_root": self.request.transfer_proof_root,
            "royalty_distribution_root": self.request.royalty_distribution_root,
            "aggregate_nullifier_root": self.request.aggregate_nullifier_root,
            "pq_batch_auth_root": self.request.pq_batch_auth_root,
            "batch_privacy_set_size": self.request.batch_privacy_set_size,
            "max_fee_bps": self.request.max_fee_bps,
            "status": self.status.as_str(),
            "built_at_height": self.request.built_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementReceiptRecord {
    pub receipt_id: String,
    pub request: IssueSettlementReceiptRequest,
    pub settled_collection_ids: Vec<String>,
    pub settled_mint_note_ids: Vec<String>,
    pub settled_market_note_ids: Vec<String>,
    pub status: ReceiptStatus,
}

impl SettlementReceiptRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_confidential_nft_settlement_receipt",
            "receipt_id": self.receipt_id,
            "batch_id": self.request.batch_id,
            "settlement_tx_root": self.request.settlement_tx_root,
            "settlement_proof_root": self.request.settlement_proof_root,
            "nft_state_root_before": self.request.nft_state_root_before,
            "nft_state_root_after": self.request.nft_state_root_after,
            "payment_state_root_after": self.request.payment_state_root_after,
            "royalty_state_root_after": self.request.royalty_state_root_after,
            "nullifier_root_after": self.request.nullifier_root_after,
            "fee_receipt_root": self.request.fee_receipt_root,
            "pq_settlement_root": self.request.pq_settlement_root,
            "settled_fee_bps": self.request.settled_fee_bps,
            "settled_collection_ids": self.settled_collection_ids,
            "settled_mint_note_ids": self.settled_mint_note_ids,
            "settled_market_note_ids": self.settled_market_note_ids,
            "status": self.status.as_str(),
            "settled_at_height": self.request.settled_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoyaltyRebateReceiptRecord {
    pub rebate_receipt_id: String,
    pub request: IssueRoyaltyRebateReceiptRequest,
    pub status: ReceiptStatus,
}

impl RoyaltyRebateReceiptRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_confidential_nft_royalty_rebate_receipt",
            "rebate_receipt_id": self.rebate_receipt_id,
            "settlement_receipt_id": self.request.settlement_receipt_id,
            "beneficiary_commitment": self.request.beneficiary_commitment,
            "rebate_asset_id": self.request.rebate_asset_id,
            "rebate_amount_commitment_root": self.request.rebate_amount_commitment_root,
            "royalty_credit_root": self.request.royalty_credit_root,
            "eligibility_proof_root": self.request.eligibility_proof_root,
            "sponsor_reservation_id": self.request.sponsor_reservation_id,
            "pq_rebate_auth_root": self.request.pq_rebate_auth_root,
            "status": self.status.as_str(),
            "issued_at_height": self.request.issued_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roots {
    pub collection_root: String,
    pub mint_note_root: String,
    pub market_note_root: String,
    pub royalty_attestation_root: String,
    pub sponsor_reservation_root: String,
    pub batch_root: String,
    pub settlement_receipt_root: String,
    pub rebate_receipt_root: String,
    pub nullifier_root: String,
    pub public_record_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "collection_root": self.collection_root,
            "mint_note_root": self.mint_note_root,
            "market_note_root": self.market_note_root,
            "royalty_attestation_root": self.royalty_attestation_root,
            "sponsor_reservation_root": self.sponsor_reservation_root,
            "batch_root": self.batch_root,
            "settlement_receipt_root": self.settlement_receipt_root,
            "rebate_receipt_root": self.rebate_receipt_root,
            "nullifier_root": self.nullifier_root,
            "public_record_root": self.public_record_root,
        })
    }

    pub fn state_root(&self) -> String {
        root_from_record(
            "PRIVATE-L2-CONFIDENTIAL-NFT-ROYALTY-ROOTS",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub current_height: u64,
    pub collections: BTreeMap<String, ShieldedCollectionRecord>,
    pub mint_notes: BTreeMap<String, ConfidentialNftMintNoteRecord>,
    pub market_notes: BTreeMap<String, PrivateMarketplaceNoteRecord>,
    pub royalty_attestations: BTreeMap<String, RoyaltySplitAttestationRecord>,
    pub sponsor_reservations: BTreeMap<String, LowFeeSponsorReservationRecord>,
    pub batches: BTreeMap<String, SealedTransferBatchRecord>,
    pub settlement_receipts: BTreeMap<String, SettlementReceiptRecord>,
    pub rebate_receipts: BTreeMap<String, RoyaltyRebateReceiptRecord>,
    pub consumed_nullifiers: BTreeSet<String>,
    pub public_records: Vec<Value>,
}

impl State {
    pub fn devnet() -> PrivateL2ConfidentialNftRoyaltyRuntimeResult<Self> {
        Self::new(Config::devnet())
    }

    pub fn new(config: Config) -> PrivateL2ConfidentialNftRoyaltyRuntimeResult<Self> {
        config.validate()?;
        Ok(Self {
            config,
            counters: Counters::default(),
            current_height: PRIVATE_L2_CONFIDENTIAL_NFT_ROYALTY_RUNTIME_DEVNET_HEIGHT,
            collections: BTreeMap::new(),
            mint_notes: BTreeMap::new(),
            market_notes: BTreeMap::new(),
            royalty_attestations: BTreeMap::new(),
            sponsor_reservations: BTreeMap::new(),
            batches: BTreeMap::new(),
            settlement_receipts: BTreeMap::new(),
            rebate_receipts: BTreeMap::new(),
            consumed_nullifiers: BTreeSet::new(),
            public_records: Vec::new(),
        })
    }

    pub fn set_height(&mut self, height: u64) {
        self.current_height = height;
    }

    pub fn register_shielded_collection(
        &mut self,
        request: RegisterShieldedCollectionRequest,
    ) -> PrivateL2ConfidentialNftRoyaltyRuntimeResult<ShieldedCollectionRecord> {
        self.ensure_capacity(
            self.collections.len(),
            self.config.max_collections,
            "collections",
        )?;
        require_non_empty("collection slug", &request.collection_slug)?;
        require_non_empty("creator commitment", &request.creator_commitment)?;
        require_non_empty(
            "metadata commitment root",
            &request.metadata_commitment_root,
        )?;
        require_non_empty(
            "supply cap commitment root",
            &request.supply_cap_commitment_root,
        )?;
        require_non_empty("royalty policy root", &request.royalty_policy_root)?;
        require_non_empty("PQ creator auth root", &request.pq_creator_auth_root)?;
        require_non_empty("compliance root", &request.compliance_root)?;
        if request.default_royalty_bps > self.config.max_royalty_bps {
            return Err("NFT collection royalty exceeds configured ceiling".to_string());
        }
        if self
            .collections
            .values()
            .any(|collection| collection.request.collection_slug == request.collection_slug)
        {
            return Err("NFT collection slug is already registered".to_string());
        }
        let counter = self.counters.collections_registered + 1;
        let collection_id = shielded_collection_id(&request, counter);
        let latest_collection_state_root = root_from_record(
            "PRIVATE-L2-CONFIDENTIAL-NFT-COLLECTION-INITIAL-STATE",
            &json!({
                "collection_id": collection_id,
                "metadata_commitment_root": request.metadata_commitment_root,
                "supply_cap_commitment_root": request.supply_cap_commitment_root,
                "royalty_policy_root": request.royalty_policy_root,
                "opened_at_height": request.opened_at_height,
            }),
        );
        let record = ShieldedCollectionRecord {
            collection_id: collection_id.clone(),
            request,
            status: CollectionStatus::Registered,
            latest_collection_state_root,
            minted_note_ids: Vec::new(),
            market_note_ids: Vec::new(),
            royalty_attestation_ids: Vec::new(),
            settled_batch_ids: Vec::new(),
        };
        self.counters.collections_registered = counter;
        self.collections.insert(collection_id, record.clone());
        self.public_records.push(record.public_record());
        Ok(record)
    }

    pub fn submit_confidential_mint_note(
        &mut self,
        request: SubmitConfidentialNftMintNoteRequest,
    ) -> PrivateL2ConfidentialNftRoyaltyRuntimeResult<ConfidentialNftMintNoteRecord> {
        self.ensure_capacity(
            self.mint_notes.len(),
            self.config.max_mint_notes,
            "mint notes",
        )?;
        require_non_empty("collection id", &request.collection_id)?;
        require_non_empty("minter commitment", &request.minter_commitment)?;
        require_non_empty("token commitment root", &request.token_commitment_root)?;
        require_non_empty("encrypted metadata root", &request.encrypted_metadata_root)?;
        require_non_empty("serial nullifier hash", &request.serial_nullifier_hash)?;
        require_non_empty("owner note root", &request.owner_note_root)?;
        require_non_empty("royalty policy root", &request.royalty_policy_root)?;
        require_non_empty(
            "mint price commitment root",
            &request.mint_price_commitment_root,
        )?;
        require_non_empty("PQ authorization root", &request.pq_authorization_root)?;
        self.require_privacy_set(request.privacy_set_size)?;
        self.require_user_fee(request.user_fee_bps)?;
        if self
            .consumed_nullifiers
            .contains(&request.serial_nullifier_hash)
        {
            return Err("NFT mint serial nullifier has already been consumed".to_string());
        }
        let collection = self
            .collections
            .get_mut(&request.collection_id)
            .ok_or_else(|| "NFT collection is not registered".to_string())?;
        if !collection.status.accepts_mints() {
            return Err("NFT collection does not accept mint notes".to_string());
        }
        let counter = self.counters.mint_notes_submitted + 1;
        let mint_note_id = confidential_mint_note_id(&request, counter);
        let expires_at_height = request
            .submitted_at_height
            .saturating_add(self.config.mint_note_ttl_blocks);
        let record = ConfidentialNftMintNoteRecord {
            mint_note_id: mint_note_id.clone(),
            request,
            status: MintNoteStatus::PqAuthorized,
            expires_at_height,
        };
        collection.status = CollectionStatus::MintOpen;
        collection.minted_note_ids.push(mint_note_id.clone());
        self.counters.mint_notes_submitted = counter;
        self.consumed_nullifiers
            .insert(record.request.serial_nullifier_hash.clone());
        self.mint_notes.insert(mint_note_id, record.clone());
        self.public_records.push(record.public_record());
        Ok(record)
    }

    pub fn submit_private_marketplace_note(
        &mut self,
        request: SubmitPrivateMarketplaceNoteRequest,
    ) -> PrivateL2ConfidentialNftRoyaltyRuntimeResult<PrivateMarketplaceNoteRecord> {
        self.ensure_capacity(
            self.market_notes.len(),
            self.config.max_market_notes,
            "market notes",
        )?;
        require_non_empty("collection id", &request.collection_id)?;
        require_non_empty("maker commitment", &request.maker_commitment)?;
        require_non_empty("taker commitment root", &request.taker_commitment_root)?;
        require_non_empty("NFT note root", &request.nft_note_root)?;
        require_non_empty("price commitment root", &request.price_commitment_root)?;
        require_non_empty("payment asset id", &request.payment_asset_id)?;
        require_non_empty("royalty quote root", &request.royalty_quote_root)?;
        require_non_empty("matching hint root", &request.matching_hint_root)?;
        require_non_empty("PQ authorization root", &request.pq_authorization_root)?;
        self.require_privacy_set(request.privacy_set_size)?;
        self.require_user_fee(request.user_fee_bps)?;
        let collection = self
            .collections
            .get_mut(&request.collection_id)
            .ok_or_else(|| "NFT collection is not registered".to_string())?;
        if !collection.status.accepts_market_notes()
            && collection.status != CollectionStatus::MintOpen
        {
            return Err("NFT collection does not accept marketplace notes".to_string());
        }
        let counter = self.counters.market_notes_submitted + 1;
        let market_note_id = marketplace_note_id(&request, counter);
        let expires_at_height = request
            .submitted_at_height
            .saturating_add(self.config.market_note_ttl_blocks);
        let record = PrivateMarketplaceNoteRecord {
            market_note_id: market_note_id.clone(),
            request,
            status: MarketNoteStatus::PqAuthorized,
            matched_note_id: None,
            expires_at_height,
        };
        collection.status = CollectionStatus::MarketOpen;
        collection.market_note_ids.push(market_note_id.clone());
        self.counters.market_notes_submitted = counter;
        self.market_notes.insert(market_note_id, record.clone());
        self.public_records.push(record.public_record());
        Ok(record)
    }

    pub fn match_marketplace_notes(
        &mut self,
        left_market_note_id: &str,
        right_market_note_id: &str,
    ) -> PrivateL2ConfidentialNftRoyaltyRuntimeResult<()> {
        if left_market_note_id == right_market_note_id {
            return Err("NFT marketplace note cannot match itself".to_string());
        }
        if !self.market_notes.contains_key(left_market_note_id)
            || !self.market_notes.contains_key(right_market_note_id)
        {
            return Err("NFT marketplace match references unknown note".to_string());
        }
        {
            let left = self
                .market_notes
                .get_mut(left_market_note_id)
                .ok_or_else(|| "NFT marketplace left note missing".to_string())?;
            left.status = MarketNoteStatus::Matched;
            left.matched_note_id = Some(right_market_note_id.to_string());
        }
        let right = self
            .market_notes
            .get_mut(right_market_note_id)
            .ok_or_else(|| "NFT marketplace right note missing".to_string())?;
        right.status = MarketNoteStatus::Matched;
        right.matched_note_id = Some(left_market_note_id.to_string());
        Ok(())
    }

    pub fn record_royalty_split_attestation(
        &mut self,
        request: RecordRoyaltySplitAttestationRequest,
    ) -> PrivateL2ConfidentialNftRoyaltyRuntimeResult<RoyaltySplitAttestationRecord> {
        self.ensure_capacity(
            self.royalty_attestations.len(),
            self.config.max_royalty_attestations,
            "royalty attestations",
        )?;
        require_non_empty("collection id", &request.collection_id)?;
        require_non_empty("subject note id", &request.subject_note_id)?;
        require_non_empty("attestor commitment", &request.attestor_commitment)?;
        require_non_empty("payee commitment root", &request.payee_commitment_root)?;
        require_non_empty("split commitment root", &request.split_commitment_root)?;
        require_non_empty(
            "royalty amount commitment root",
            &request.royalty_amount_commitment_root,
        )?;
        require_non_empty(
            "selective disclosure root",
            &request.selective_disclosure_root,
        )?;
        require_non_empty("proof root", &request.proof_root)?;
        require_non_empty("PQ attestation root", &request.pq_attestation_root)?;
        if request.total_royalty_bps > self.config.max_royalty_bps {
            return Err("NFT royalty attestation exceeds royalty ceiling".to_string());
        }
        if request.split_count == 0 || request.split_count > self.config.max_royalty_splits {
            return Err("NFT royalty split count is outside configured bounds".to_string());
        }
        if !request.verdict.allows_settlement() {
            return Err("NFT royalty attestation verdict blocks settlement".to_string());
        }
        let collection = self
            .collections
            .get_mut(&request.collection_id)
            .ok_or_else(|| "NFT collection is not registered".to_string())?;
        if !self.mint_notes.contains_key(&request.subject_note_id)
            && !self.market_notes.contains_key(&request.subject_note_id)
        {
            return Err("NFT royalty attestation subject note is unknown".to_string());
        }
        let counter = self.counters.royalty_attestations_recorded + 1;
        let attestation_id = royalty_attestation_id(&request, counter);
        let record = RoyaltySplitAttestationRecord {
            attestation_id: attestation_id.clone(),
            request,
        };
        collection
            .royalty_attestation_ids
            .push(attestation_id.clone());
        self.counters.royalty_attestations_recorded = counter;
        self.royalty_attestations
            .insert(attestation_id, record.clone());
        self.public_records.push(record.public_record());
        Ok(record)
    }

    pub fn reserve_low_fee_sponsor(
        &mut self,
        request: ReserveLowFeeSponsorRequest,
    ) -> PrivateL2ConfidentialNftRoyaltyRuntimeResult<LowFeeSponsorReservationRecord> {
        self.ensure_capacity(
            self.sponsor_reservations.len(),
            self.config.max_sponsor_reservations,
            "sponsor reservations",
        )?;
        require_non_empty("subject note id", &request.subject_note_id)?;
        require_non_empty("sponsor commitment", &request.sponsor_commitment)?;
        require_non_empty("budget root", &request.budget_root)?;
        require_non_empty("fee asset id", &request.fee_asset_id)?;
        require_non_empty("reservation nonce root", &request.reservation_nonce_root)?;
        require_non_empty("PQ sponsor auth root", &request.pq_sponsor_auth_root)?;
        if request.fee_asset_id != self.config.fee_asset_id {
            return Err("NFT sponsor reservation uses unsupported fee asset".to_string());
        }
        if request.reserved_fee_bps > self.config.max_sponsor_fee_bps {
            return Err("NFT sponsor reservation exceeds sponsor fee ceiling".to_string());
        }
        if !self.mint_notes.contains_key(&request.subject_note_id)
            && !self.market_notes.contains_key(&request.subject_note_id)
        {
            return Err("NFT sponsor reservation subject note is unknown".to_string());
        }
        let counter = self.counters.sponsor_reservations + 1;
        let reservation_id = low_fee_sponsor_reservation_id(&request, counter);
        let expires_at_height = request
            .reserved_at_height
            .saturating_add(self.config.sponsor_ttl_blocks);
        let record = LowFeeSponsorReservationRecord {
            reservation_id: reservation_id.clone(),
            request,
            status: SponsorReservationStatus::Reserved,
            expires_at_height,
        };
        self.counters.sponsor_reservations = counter;
        self.sponsor_reservations
            .insert(reservation_id, record.clone());
        self.public_records.push(record.public_record());
        Ok(record)
    }

    pub fn build_sealed_transfer_batch(
        &mut self,
        request: BuildSealedTransferBatchRequest,
    ) -> PrivateL2ConfidentialNftRoyaltyRuntimeResult<SealedTransferBatchRecord> {
        self.ensure_capacity(
            self.batches.len(),
            self.config.max_batches,
            "sealed batches",
        )?;
        require_non_empty("operator commitment", &request.operator_commitment)?;
        require_non_empty("sealed input root", &request.sealed_input_root)?;
        require_non_empty("sealed output root", &request.sealed_output_root)?;
        require_non_empty("transfer proof root", &request.transfer_proof_root)?;
        require_non_empty(
            "royalty distribution root",
            &request.royalty_distribution_root,
        )?;
        require_non_empty(
            "aggregate nullifier root",
            &request.aggregate_nullifier_root,
        )?;
        require_non_empty("PQ batch auth root", &request.pq_batch_auth_root)?;
        if request.mint_note_ids.is_empty() && request.market_note_ids.is_empty() {
            return Err("NFT sealed transfer batch must include notes".to_string());
        }
        if request.mint_note_ids.len() + request.market_note_ids.len() > self.config.max_batch_items
        {
            return Err("NFT sealed transfer batch exceeds item capacity".to_string());
        }
        if request.batch_privacy_set_size < self.config.batch_privacy_set_size {
            return Err("NFT sealed transfer batch privacy set is too small".to_string());
        }
        if request.max_fee_bps > self.config.max_user_fee_bps {
            return Err("NFT sealed transfer batch exceeds user fee ceiling".to_string());
        }
        for collection_id in &request.collection_ids {
            if !self.collections.contains_key(collection_id) {
                return Err("NFT sealed transfer batch references unknown collection".to_string());
            }
        }
        for mint_note_id in &request.mint_note_ids {
            let note = self.mint_notes.get(mint_note_id).ok_or_else(|| {
                "NFT sealed transfer batch references unknown mint note".to_string()
            })?;
            if !note.status.batchable() {
                return Err("NFT mint note is not batchable".to_string());
            }
        }
        for market_note_id in &request.market_note_ids {
            let note = self.market_notes.get(market_note_id).ok_or_else(|| {
                "NFT sealed transfer batch references unknown marketplace note".to_string()
            })?;
            if !note.status.batchable() {
                return Err("NFT marketplace note is not batchable".to_string());
            }
        }
        if self.config.require_royalty_attestation && request.royalty_attestation_ids.is_empty() {
            return Err("NFT sealed transfer batch requires royalty attestations".to_string());
        }
        for attestation_id in &request.royalty_attestation_ids {
            if !self.royalty_attestations.contains_key(attestation_id) {
                return Err(
                    "NFT sealed transfer batch references unknown royalty attestation".to_string(),
                );
            }
        }
        if self.config.require_fee_sponsor && request.sponsor_reservation_ids.is_empty() {
            return Err("NFT sealed transfer batch requires sponsor reservations".to_string());
        }
        for reservation_id in &request.sponsor_reservation_ids {
            let reservation = self
                .sponsor_reservations
                .get(reservation_id)
                .ok_or_else(|| {
                    "NFT sealed transfer batch references unknown sponsor reservation".to_string()
                })?;
            if reservation.status != SponsorReservationStatus::Reserved {
                return Err("NFT sponsor reservation is not available".to_string());
            }
        }
        let counter = self.counters.sealed_batches + 1;
        let batch_id = sealed_transfer_batch_id(&request, counter);
        let expires_at_height = request
            .built_at_height
            .saturating_add(self.config.batch_ttl_blocks);
        let record = SealedTransferBatchRecord {
            batch_id: batch_id.clone(),
            request: request.clone(),
            status: TransferBatchStatus::SettlementReady,
            expires_at_height,
        };
        for mint_note_id in &request.mint_note_ids {
            if let Some(note) = self.mint_notes.get_mut(mint_note_id) {
                note.status = MintNoteStatus::TransferQueued;
            }
        }
        for market_note_id in &request.market_note_ids {
            if let Some(note) = self.market_notes.get_mut(market_note_id) {
                note.status = MarketNoteStatus::Batched;
            }
        }
        self.counters.sealed_batches = counter;
        self.batches.insert(batch_id, record.clone());
        self.public_records.push(record.public_record());
        Ok(record)
    }

    pub fn issue_settlement_receipt(
        &mut self,
        request: IssueSettlementReceiptRequest,
    ) -> PrivateL2ConfidentialNftRoyaltyRuntimeResult<SettlementReceiptRecord> {
        self.ensure_capacity(
            self.settlement_receipts.len(),
            self.config.max_settlement_receipts,
            "settlement receipts",
        )?;
        require_non_empty("batch id", &request.batch_id)?;
        require_non_empty("settlement tx root", &request.settlement_tx_root)?;
        require_non_empty("settlement proof root", &request.settlement_proof_root)?;
        require_non_empty("NFT state root before", &request.nft_state_root_before)?;
        require_non_empty("NFT state root after", &request.nft_state_root_after)?;
        require_non_empty(
            "payment state root after",
            &request.payment_state_root_after,
        )?;
        require_non_empty(
            "royalty state root after",
            &request.royalty_state_root_after,
        )?;
        require_non_empty("nullifier root after", &request.nullifier_root_after)?;
        require_non_empty("fee receipt root", &request.fee_receipt_root)?;
        require_non_empty("PQ settlement root", &request.pq_settlement_root)?;
        if request.settled_fee_bps > self.config.max_user_fee_bps {
            return Err("NFT settlement fee exceeds user fee ceiling".to_string());
        }
        let batch = self
            .batches
            .get_mut(&request.batch_id)
            .ok_or_else(|| "NFT settlement references unknown sealed batch".to_string())?;
        if !batch.status.can_settle() {
            return Err("NFT sealed transfer batch is not settlement ready".to_string());
        }
        let settled_collection_ids = batch.request.collection_ids.clone();
        let settled_mint_note_ids = batch.request.mint_note_ids.clone();
        let settled_market_note_ids = batch.request.market_note_ids.clone();
        for mint_note_id in &settled_mint_note_ids {
            if let Some(note) = self.mint_notes.get_mut(mint_note_id) {
                note.status = MintNoteStatus::Settled;
            }
        }
        for market_note_id in &settled_market_note_ids {
            if let Some(note) = self.market_notes.get_mut(market_note_id) {
                note.status = MarketNoteStatus::Settled;
            }
        }
        for reservation_id in &batch.request.sponsor_reservation_ids {
            if let Some(reservation) = self.sponsor_reservations.get_mut(reservation_id) {
                reservation.status = SponsorReservationStatus::Consumed;
            }
        }
        for collection_id in &settled_collection_ids {
            if let Some(collection) = self.collections.get_mut(collection_id) {
                collection.latest_collection_state_root = request.nft_state_root_after.clone();
                collection.settled_batch_ids.push(request.batch_id.clone());
            }
        }
        batch.status = TransferBatchStatus::Settled;
        let counter = self.counters.settlement_receipts + 1;
        let receipt_id = settlement_receipt_id(&request, counter);
        let record = SettlementReceiptRecord {
            receipt_id: receipt_id.clone(),
            request,
            settled_collection_ids,
            settled_mint_note_ids,
            settled_market_note_ids,
            status: ReceiptStatus::Published,
        };
        self.counters.settlement_receipts = counter;
        self.settlement_receipts.insert(receipt_id, record.clone());
        self.public_records.push(record.public_record());
        Ok(record)
    }

    pub fn issue_royalty_rebate_receipt(
        &mut self,
        request: IssueRoyaltyRebateReceiptRequest,
    ) -> PrivateL2ConfidentialNftRoyaltyRuntimeResult<RoyaltyRebateReceiptRecord> {
        if !self.config.allow_rebate_receipts {
            return Err("NFT royalty rebate receipts are disabled".to_string());
        }
        self.ensure_capacity(
            self.rebate_receipts.len(),
            self.config.max_rebate_receipts,
            "rebate receipts",
        )?;
        require_non_empty("settlement receipt id", &request.settlement_receipt_id)?;
        require_non_empty("beneficiary commitment", &request.beneficiary_commitment)?;
        require_non_empty("rebate asset id", &request.rebate_asset_id)?;
        require_non_empty(
            "rebate amount commitment root",
            &request.rebate_amount_commitment_root,
        )?;
        require_non_empty("royalty credit root", &request.royalty_credit_root)?;
        require_non_empty("eligibility proof root", &request.eligibility_proof_root)?;
        require_non_empty("sponsor reservation id", &request.sponsor_reservation_id)?;
        require_non_empty("PQ rebate auth root", &request.pq_rebate_auth_root)?;
        if !self
            .settlement_receipts
            .contains_key(&request.settlement_receipt_id)
        {
            return Err("NFT royalty rebate references unknown settlement receipt".to_string());
        }
        if !self
            .sponsor_reservations
            .contains_key(&request.sponsor_reservation_id)
        {
            return Err("NFT royalty rebate references unknown sponsor reservation".to_string());
        }
        let counter = self.counters.rebate_receipts + 1;
        let rebate_receipt_id = royalty_rebate_receipt_id(&request, counter);
        let record = RoyaltyRebateReceiptRecord {
            rebate_receipt_id: rebate_receipt_id.clone(),
            request,
            status: ReceiptStatus::Published,
        };
        self.counters.rebate_receipts = counter;
        self.rebate_receipts
            .insert(rebate_receipt_id, record.clone());
        self.public_records.push(record.public_record());
        Ok(record)
    }

    pub fn roots(&self) -> Roots {
        let collection_leaves = self
            .collections
            .values()
            .map(|record| record.public_record())
            .collect::<Vec<_>>();
        let mint_note_leaves = self
            .mint_notes
            .values()
            .map(|record| record.public_record())
            .collect::<Vec<_>>();
        let market_note_leaves = self
            .market_notes
            .values()
            .map(|record| record.public_record())
            .collect::<Vec<_>>();
        let royalty_attestation_leaves = self
            .royalty_attestations
            .values()
            .map(|record| record.public_record())
            .collect::<Vec<_>>();
        let sponsor_reservation_leaves = self
            .sponsor_reservations
            .values()
            .map(|record| record.public_record())
            .collect::<Vec<_>>();
        let batch_leaves = self
            .batches
            .values()
            .map(|record| record.public_record())
            .collect::<Vec<_>>();
        let settlement_receipt_leaves = self
            .settlement_receipts
            .values()
            .map(|record| record.public_record())
            .collect::<Vec<_>>();
        let rebate_receipt_leaves = self
            .rebate_receipts
            .values()
            .map(|record| record.public_record())
            .collect::<Vec<_>>();
        let nullifier_leaves = self
            .consumed_nullifiers
            .iter()
            .map(|nullifier| Value::String(nullifier.clone()))
            .collect::<Vec<_>>();
        Roots {
            collection_root: public_record_root(
                "PRIVATE-L2-CONFIDENTIAL-NFT-COLLECTION-ROOT",
                &collection_leaves,
            ),
            mint_note_root: public_record_root(
                "PRIVATE-L2-CONFIDENTIAL-NFT-MINT-NOTE-ROOT",
                &mint_note_leaves,
            ),
            market_note_root: public_record_root(
                "PRIVATE-L2-CONFIDENTIAL-NFT-MARKET-NOTE-ROOT",
                &market_note_leaves,
            ),
            royalty_attestation_root: public_record_root(
                "PRIVATE-L2-CONFIDENTIAL-NFT-ROYALTY-ATTESTATION-ROOT",
                &royalty_attestation_leaves,
            ),
            sponsor_reservation_root: public_record_root(
                "PRIVATE-L2-CONFIDENTIAL-NFT-SPONSOR-RESERVATION-ROOT",
                &sponsor_reservation_leaves,
            ),
            batch_root: public_record_root("PRIVATE-L2-CONFIDENTIAL-NFT-BATCH-ROOT", &batch_leaves),
            settlement_receipt_root: public_record_root(
                "PRIVATE-L2-CONFIDENTIAL-NFT-SETTLEMENT-RECEIPT-ROOT",
                &settlement_receipt_leaves,
            ),
            rebate_receipt_root: public_record_root(
                "PRIVATE-L2-CONFIDENTIAL-NFT-REBATE-RECEIPT-ROOT",
                &rebate_receipt_leaves,
            ),
            nullifier_root: merkle_root(
                "PRIVATE-L2-CONFIDENTIAL-NFT-CONSUMED-NULLIFIER-ROOT",
                &nullifier_leaves,
            ),
            public_record_root: merkle_root(
                "PRIVATE-L2-CONFIDENTIAL-NFT-PUBLIC-RECORD-ROOT",
                &self.public_records,
            ),
        }
    }

    pub fn public_record_without_state_root(&self) -> Value {
        let roots = self.roots();
        json!({
            "kind": "private_l2_confidential_nft_royalty_runtime",
            "protocol_version": PRIVATE_L2_CONFIDENTIAL_NFT_ROYALTY_RUNTIME_PROTOCOL_VERSION,
            "schema_version": PRIVATE_L2_CONFIDENTIAL_NFT_ROYALTY_RUNTIME_SCHEMA_VERSION,
            "hash_suite": PRIVATE_L2_CONFIDENTIAL_NFT_ROYALTY_RUNTIME_HASH_SUITE,
            "pq_auth_suite": PRIVATE_L2_CONFIDENTIAL_NFT_ROYALTY_RUNTIME_PQ_AUTH_SUITE,
            "collection_scheme": PRIVATE_L2_CONFIDENTIAL_NFT_ROYALTY_RUNTIME_COLLECTION_SCHEME,
            "mint_note_scheme": PRIVATE_L2_CONFIDENTIAL_NFT_ROYALTY_RUNTIME_MINT_NOTE_SCHEME,
            "market_note_scheme": PRIVATE_L2_CONFIDENTIAL_NFT_ROYALTY_RUNTIME_MARKET_NOTE_SCHEME,
            "royalty_split_scheme": PRIVATE_L2_CONFIDENTIAL_NFT_ROYALTY_RUNTIME_ROYALTY_SPLIT_SCHEME,
            "sponsor_scheme": PRIVATE_L2_CONFIDENTIAL_NFT_ROYALTY_RUNTIME_SPONSOR_SCHEME,
            "batch_scheme": PRIVATE_L2_CONFIDENTIAL_NFT_ROYALTY_RUNTIME_BATCH_SCHEME,
            "settlement_scheme": PRIVATE_L2_CONFIDENTIAL_NFT_ROYALTY_RUNTIME_SETTLEMENT_SCHEME,
            "rebate_scheme": PRIVATE_L2_CONFIDENTIAL_NFT_ROYALTY_RUNTIME_REBATE_SCHEME,
            "config": self.config.public_record(),
            "config_root": self.config.state_root(),
            "counters": self.counters.public_record(),
            "current_height": self.current_height,
            "roots": roots.public_record(),
            "roots_state_root": roots.state_root(),
            "collection_count": self.collections.len(),
            "mint_note_count": self.mint_notes.len(),
            "market_note_count": self.market_notes.len(),
            "royalty_attestation_count": self.royalty_attestations.len(),
            "sponsor_reservation_count": self.sponsor_reservations.len(),
            "batch_count": self.batches.len(),
            "settlement_receipt_count": self.settlement_receipts.len(),
            "rebate_receipt_count": self.rebate_receipts.len(),
            "consumed_nullifier_count": self.consumed_nullifiers.len(),
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        if let Some(object) = record.as_object_mut() {
            object.insert("state_root".to_string(), Value::String(self.state_root()));
        }
        record
    }

    pub fn state_root(&self) -> String {
        private_l2_confidential_nft_royalty_runtime_state_root_from_record(
            &self.public_record_without_state_root(),
        )
    }

    fn ensure_capacity(
        &self,
        current_len: usize,
        max_len: usize,
        label: &str,
    ) -> PrivateL2ConfidentialNftRoyaltyRuntimeResult<()> {
        if current_len >= max_len {
            return Err(format!("NFT royalty {label} capacity exhausted"));
        }
        Ok(())
    }

    fn require_privacy_set(
        &self,
        privacy_set_size: u64,
    ) -> PrivateL2ConfidentialNftRoyaltyRuntimeResult<()> {
        if privacy_set_size < self.config.min_privacy_set_size {
            return Err("NFT royalty privacy set is below configured minimum".to_string());
        }
        Ok(())
    }

    fn require_user_fee(&self, fee_bps: u64) -> PrivateL2ConfidentialNftRoyaltyRuntimeResult<()> {
        if fee_bps > self.config.max_user_fee_bps {
            return Err("NFT royalty user fee exceeds configured ceiling".to_string());
        }
        Ok(())
    }
}

pub fn shielded_collection_id(request: &RegisterShieldedCollectionRequest, counter: u64) -> String {
    root_from_record(
        "PRIVATE-L2-CONFIDENTIAL-NFT-COLLECTION-ID",
        &json!({
            "counter": counter,
            "collection_slug": request.collection_slug,
            "collection_kind": request.collection_kind.as_str(),
            "creator_commitment": request.creator_commitment,
            "metadata_commitment_root": request.metadata_commitment_root,
            "royalty_policy_root": request.royalty_policy_root,
            "opened_at_height": request.opened_at_height,
        }),
    )
}

pub fn confidential_mint_note_id(
    request: &SubmitConfidentialNftMintNoteRequest,
    counter: u64,
) -> String {
    root_from_record(
        "PRIVATE-L2-CONFIDENTIAL-NFT-MINT-NOTE-ID",
        &json!({
            "counter": counter,
            "collection_id": request.collection_id,
            "minter_commitment": request.minter_commitment,
            "token_commitment_root": request.token_commitment_root,
            "serial_nullifier_hash": request.serial_nullifier_hash,
            "owner_note_root": request.owner_note_root,
            "submitted_at_height": request.submitted_at_height,
        }),
    )
}

pub fn marketplace_note_id(request: &SubmitPrivateMarketplaceNoteRequest, counter: u64) -> String {
    root_from_record(
        "PRIVATE-L2-CONFIDENTIAL-NFT-MARKET-NOTE-ID",
        &json!({
            "counter": counter,
            "collection_id": request.collection_id,
            "kind": request.kind.as_str(),
            "maker_commitment": request.maker_commitment,
            "nft_note_root": request.nft_note_root,
            "price_commitment_root": request.price_commitment_root,
            "royalty_quote_root": request.royalty_quote_root,
            "submitted_at_height": request.submitted_at_height,
        }),
    )
}

pub fn royalty_attestation_id(
    request: &RecordRoyaltySplitAttestationRequest,
    counter: u64,
) -> String {
    root_from_record(
        "PRIVATE-L2-CONFIDENTIAL-NFT-ROYALTY-ATTESTATION-ID",
        &json!({
            "counter": counter,
            "collection_id": request.collection_id,
            "subject_note_id": request.subject_note_id,
            "kind": request.kind.as_str(),
            "attestor_commitment": request.attestor_commitment,
            "split_commitment_root": request.split_commitment_root,
            "proof_root": request.proof_root,
            "pq_attestation_root": request.pq_attestation_root,
            "attested_at_height": request.attested_at_height,
        }),
    )
}

pub fn low_fee_sponsor_reservation_id(
    request: &ReserveLowFeeSponsorRequest,
    counter: u64,
) -> String {
    root_from_record(
        "PRIVATE-L2-CONFIDENTIAL-NFT-SPONSOR-RESERVATION-ID",
        &json!({
            "counter": counter,
            "subject_note_id": request.subject_note_id,
            "sponsor_commitment": request.sponsor_commitment,
            "budget_root": request.budget_root,
            "fee_asset_id": request.fee_asset_id,
            "reservation_nonce_root": request.reservation_nonce_root,
            "reserved_at_height": request.reserved_at_height,
        }),
    )
}

pub fn sealed_transfer_batch_id(request: &BuildSealedTransferBatchRequest, counter: u64) -> String {
    root_from_record(
        "PRIVATE-L2-CONFIDENTIAL-NFT-SEALED-TRANSFER-BATCH-ID",
        &json!({
            "counter": counter,
            "operator_commitment": request.operator_commitment,
            "collection_ids": request.collection_ids,
            "mint_note_ids": request.mint_note_ids,
            "market_note_ids": request.market_note_ids,
            "royalty_attestation_ids": request.royalty_attestation_ids,
            "sponsor_reservation_ids": request.sponsor_reservation_ids,
            "sealed_input_root": request.sealed_input_root,
            "sealed_output_root": request.sealed_output_root,
            "transfer_proof_root": request.transfer_proof_root,
            "built_at_height": request.built_at_height,
        }),
    )
}

pub fn settlement_receipt_id(request: &IssueSettlementReceiptRequest, counter: u64) -> String {
    root_from_record(
        "PRIVATE-L2-CONFIDENTIAL-NFT-SETTLEMENT-RECEIPT-ID",
        &json!({
            "counter": counter,
            "batch_id": request.batch_id,
            "settlement_tx_root": request.settlement_tx_root,
            "settlement_proof_root": request.settlement_proof_root,
            "nft_state_root_before": request.nft_state_root_before,
            "nft_state_root_after": request.nft_state_root_after,
            "royalty_state_root_after": request.royalty_state_root_after,
            "settled_at_height": request.settled_at_height,
        }),
    )
}

pub fn royalty_rebate_receipt_id(
    request: &IssueRoyaltyRebateReceiptRequest,
    counter: u64,
) -> String {
    root_from_record(
        "PRIVATE-L2-CONFIDENTIAL-NFT-ROYALTY-REBATE-RECEIPT-ID",
        &json!({
            "counter": counter,
            "settlement_receipt_id": request.settlement_receipt_id,
            "beneficiary_commitment": request.beneficiary_commitment,
            "rebate_asset_id": request.rebate_asset_id,
            "rebate_amount_commitment_root": request.rebate_amount_commitment_root,
            "royalty_credit_root": request.royalty_credit_root,
            "issued_at_height": request.issued_at_height,
        }),
    )
}

pub fn private_l2_confidential_nft_royalty_runtime_state_root_from_record(
    record: &Value,
) -> String {
    root_from_record(
        "PRIVATE-L2-CONFIDENTIAL-NFT-ROYALTY-RUNTIME-STATE-ROOT",
        record,
    )
}

pub fn state_root_from_record(record: &Value) -> String {
    private_l2_confidential_nft_royalty_runtime_state_root_from_record(record)
}

pub fn root_from_record(domain: &str, record: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(PRIVATE_L2_CONFIDENTIAL_NFT_ROYALTY_RUNTIME_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Json(record),
        ],
        32,
    )
}

pub fn payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(PRIVATE_L2_CONFIDENTIAL_NFT_ROYALTY_RUNTIME_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub fn payload_id(domain: &str, parts: &[HashPart<'_>]) -> String {
    domain_hash(
        &format!(
            "{}:{}:{}",
            PRIVATE_L2_CONFIDENTIAL_NFT_ROYALTY_RUNTIME_PROTOCOL_VERSION, CHAIN_ID, domain
        ),
        parts,
        32,
    )
}

pub fn public_record_root(domain: &str, records: &[Value]) -> String {
    let leaves = records
        .iter()
        .map(|record| Value::String(payload_root(domain, record)))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn require_non_empty(label: &str, value: &str) -> PrivateL2ConfidentialNftRoyaltyRuntimeResult<()> {
    if value.trim().is_empty() {
        return Err(format!("NFT royalty {label} is required"));
    }
    Ok(())
}
