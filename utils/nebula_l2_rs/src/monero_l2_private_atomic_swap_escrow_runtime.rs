use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type MoneroL2PrivateAtomicSwapEscrowRuntimeResult<T> = Result<T, String>;

pub const MONERO_L2_PRIVATE_ATOMIC_SWAP_ESCROW_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-private-atomic-swap-escrow-runtime-v1";
pub const PROTOCOL_VERSION: &str = MONERO_L2_PRIVATE_ATOMIC_SWAP_ESCROW_RUNTIME_PROTOCOL_VERSION;
pub const MONERO_L2_PRIVATE_ATOMIC_SWAP_ESCROW_RUNTIME_SCHEMA_VERSION: u64 = 1;
pub const MONERO_L2_PRIVATE_ATOMIC_SWAP_ESCROW_RUNTIME_DEVNET_HEIGHT: u64 = 736_000;
pub const MONERO_L2_PRIVATE_ATOMIC_SWAP_ESCROW_RUNTIME_DEVNET_MONERO_NETWORK: &str =
    "monero-devnet";
pub const MONERO_L2_PRIVATE_ATOMIC_SWAP_ESCROW_RUNTIME_DEVNET_L2_NETWORK: &str = "nebula-devnet";
pub const MONERO_L2_PRIVATE_ATOMIC_SWAP_ESCROW_RUNTIME_DEVNET_BASE_ASSET_ID: &str = "wxmr-devnet";
pub const MONERO_L2_PRIVATE_ATOMIC_SWAP_ESCROW_RUNTIME_DEVNET_QUOTE_ASSET_ID: &str =
    "private-usd-devnet";
pub const MONERO_L2_PRIVATE_ATOMIC_SWAP_ESCROW_RUNTIME_DEVNET_FEE_ASSET_ID: &str =
    "piconero-devnet";
pub const MONERO_L2_PRIVATE_ATOMIC_SWAP_ESCROW_RUNTIME_HASH_SUITE: &str =
    "SHAKE256-domain-separated-canonical-json";
pub const MONERO_L2_PRIVATE_ATOMIC_SWAP_ESCROW_RUNTIME_SWAP_OFFER_SCHEME: &str =
    "private-monero-l2-atomic-swap-offer-root-v1";
pub const MONERO_L2_PRIVATE_ATOMIC_SWAP_ESCROW_RUNTIME_LOCK_NOTE_SCHEME: &str =
    "shielded-monero-l2-atomic-swap-lock-note-root-v1";
pub const MONERO_L2_PRIVATE_ATOMIC_SWAP_ESCROW_RUNTIME_PQ_ADAPTOR_SCHEME: &str =
    "ml-kem-1024+ml-dsa-87+slh-dsa-shake-256f-adaptor-attestation-v1";
pub const MONERO_L2_PRIVATE_ATOMIC_SWAP_ESCROW_RUNTIME_LOW_FEE_RESERVATION_SCHEME: &str =
    "low-fee-maker-taker-private-swap-reservation-root-v1";
pub const MONERO_L2_PRIVATE_ATOMIC_SWAP_ESCROW_RUNTIME_SETTLEMENT_BATCH_SCHEME: &str =
    "private-atomic-swap-settlement-batch-root-v1";
pub const MONERO_L2_PRIVATE_ATOMIC_SWAP_ESCROW_RUNTIME_DISPUTE_RECEIPT_SCHEME: &str =
    "private-atomic-swap-dispute-receipt-root-v1";
pub const MONERO_L2_PRIVATE_ATOMIC_SWAP_ESCROW_RUNTIME_MAX_BPS: u64 = 10_000;
pub const MONERO_L2_PRIVATE_ATOMIC_SWAP_ESCROW_RUNTIME_DEFAULT_MAX_OFFERS: usize = 262_144;
pub const MONERO_L2_PRIVATE_ATOMIC_SWAP_ESCROW_RUNTIME_DEFAULT_MAX_LOCK_NOTES: usize = 1_048_576;
pub const MONERO_L2_PRIVATE_ATOMIC_SWAP_ESCROW_RUNTIME_DEFAULT_MAX_ATTESTATIONS: usize = 1_048_576;
pub const MONERO_L2_PRIVATE_ATOMIC_SWAP_ESCROW_RUNTIME_DEFAULT_MAX_RESERVATIONS: usize = 1_048_576;
pub const MONERO_L2_PRIVATE_ATOMIC_SWAP_ESCROW_RUNTIME_DEFAULT_MAX_BATCHES: usize = 524_288;
pub const MONERO_L2_PRIVATE_ATOMIC_SWAP_ESCROW_RUNTIME_DEFAULT_MAX_DISPUTES: usize = 524_288;
pub const MONERO_L2_PRIVATE_ATOMIC_SWAP_ESCROW_RUNTIME_DEFAULT_MAX_PUBLIC_RECORDS: usize =
    4_194_304;
pub const MONERO_L2_PRIVATE_ATOMIC_SWAP_ESCROW_RUNTIME_DEFAULT_MIN_PRIVACY_SET_SIZE: usize = 8_192;
pub const MONERO_L2_PRIVATE_ATOMIC_SWAP_ESCROW_RUNTIME_DEFAULT_BATCH_PRIVACY_SET_SIZE: usize =
    16_384;
pub const MONERO_L2_PRIVATE_ATOMIC_SWAP_ESCROW_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 192;
pub const MONERO_L2_PRIVATE_ATOMIC_SWAP_ESCROW_RUNTIME_DEFAULT_TARGET_PQ_SECURITY_BITS: u16 = 256;
pub const MONERO_L2_PRIVATE_ATOMIC_SWAP_ESCROW_RUNTIME_DEFAULT_MAX_USER_FEE_BPS: u64 = 24;
pub const MONERO_L2_PRIVATE_ATOMIC_SWAP_ESCROW_RUNTIME_DEFAULT_LOW_FEE_BPS: u64 = 5;
pub const MONERO_L2_PRIVATE_ATOMIC_SWAP_ESCROW_RUNTIME_DEFAULT_REBATE_BPS: u64 = 12;
pub const MONERO_L2_PRIVATE_ATOMIC_SWAP_ESCROW_RUNTIME_DEFAULT_OFFER_TTL_BLOCKS: u64 = 72;
pub const MONERO_L2_PRIVATE_ATOMIC_SWAP_ESCROW_RUNTIME_DEFAULT_LOCK_NOTE_TTL_BLOCKS: u64 = 144;
pub const MONERO_L2_PRIVATE_ATOMIC_SWAP_ESCROW_RUNTIME_DEFAULT_RESERVATION_TTL_BLOCKS: u64 = 24;
pub const MONERO_L2_PRIVATE_ATOMIC_SWAP_ESCROW_RUNTIME_DEFAULT_DISPUTE_WINDOW_BLOCKS: u64 = 96;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SwapDirection {
    MoneroForL2Asset,
    L2AssetForMonero,
    Bidirectional,
}

impl SwapDirection {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MoneroForL2Asset => "monero_for_l2_asset",
            Self::L2AssetForMonero => "l2_asset_for_monero",
            Self::Bidirectional => "bidirectional",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SwapRole {
    Maker,
    Taker,
}

impl SwapRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Maker => "maker",
            Self::Taker => "taker",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SwapOfferStatus {
    Open,
    MakerLocked,
    TakerLocked,
    Matched,
    Batched,
    Settled,
    Disputed,
    Expired,
    Cancelled,
}

impl SwapOfferStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::MakerLocked => "maker_locked",
            Self::TakerLocked => "taker_locked",
            Self::Matched => "matched",
            Self::Batched => "batched",
            Self::Settled => "settled",
            Self::Disputed => "disputed",
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
        }
    }

    pub fn accepts_locks(self) -> bool {
        matches!(self, Self::Open | Self::MakerLocked | Self::TakerLocked)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LockNoteStatus {
    Submitted,
    Accepted,
    Matched,
    Batched,
    Settled,
    Refunded,
    Disputed,
    Expired,
    Rejected,
}

impl LockNoteStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Accepted => "accepted",
            Self::Matched => "matched",
            Self::Batched => "batched",
            Self::Settled => "settled",
            Self::Refunded => "refunded",
            Self::Disputed => "disputed",
            Self::Expired => "expired",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PqAdaptorAttestationStatus {
    Proposed,
    Verified,
    BoundToLocks,
    Revealed,
    Settled,
    Disputed,
    Expired,
    Rejected,
}

impl PqAdaptorAttestationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::Verified => "verified",
            Self::BoundToLocks => "bound_to_locks",
            Self::Revealed => "revealed",
            Self::Settled => "settled",
            Self::Disputed => "disputed",
            Self::Expired => "expired",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReservationStatus {
    Reserved,
    Consumed,
    RebateQueued,
    Refunded,
    Slashed,
    Expired,
}

impl ReservationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Consumed => "consumed",
            Self::RebateQueued => "rebate_queued",
            Self::Refunded => "refunded",
            Self::Slashed => "slashed",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementBatchStatus {
    Proposed,
    Sealed,
    Settled,
    PartiallySettled,
    Disputed,
    Cancelled,
}

impl SettlementBatchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::Sealed => "sealed",
            Self::Settled => "settled",
            Self::PartiallySettled => "partially_settled",
            Self::Disputed => "disputed",
            Self::Cancelled => "cancelled",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DisputeSubjectKind {
    SwapOffer,
    LockNote,
    PqAdaptorAttestation,
    LowFeeReservation,
    SettlementBatch,
}

impl DisputeSubjectKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SwapOffer => "swap_offer",
            Self::LockNote => "lock_note",
            Self::PqAdaptorAttestation => "pq_adaptor_attestation",
            Self::LowFeeReservation => "low_fee_reservation",
            Self::SettlementBatch => "settlement_batch",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DisputeKind {
    InvalidLock,
    InvalidAdaptorSecret,
    TimeoutMismatch,
    SettlementMismatch,
    DuplicateNullifier,
    FeeReservationDefault,
    PrivacyLeak,
}

impl DisputeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidLock => "invalid_lock",
            Self::InvalidAdaptorSecret => "invalid_adaptor_secret",
            Self::TimeoutMismatch => "timeout_mismatch",
            Self::SettlementMismatch => "settlement_mismatch",
            Self::DuplicateNullifier => "duplicate_nullifier",
            Self::FeeReservationDefault => "fee_reservation_default",
            Self::PrivacyLeak => "privacy_leak",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DisputeStatus {
    Open,
    EvidenceSubmitted,
    Sustained,
    Rejected,
    Expired,
}

impl DisputeStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::EvidenceSubmitted => "evidence_submitted",
            Self::Sustained => "sustained",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub monero_network: String,
    pub l2_network: String,
    pub base_asset_id: String,
    pub quote_asset_id: String,
    pub fee_asset_id: String,
    pub hash_suite: String,
    pub swap_offer_scheme: String,
    pub lock_note_scheme: String,
    pub pq_adaptor_scheme: String,
    pub low_fee_reservation_scheme: String,
    pub settlement_batch_scheme: String,
    pub dispute_receipt_scheme: String,
    pub genesis_height: u64,
    pub max_offers: usize,
    pub max_lock_notes: usize,
    pub max_adaptor_attestations: usize,
    pub max_low_fee_reservations: usize,
    pub max_settlement_batches: usize,
    pub max_dispute_receipts: usize,
    pub max_public_records: usize,
    pub min_privacy_set_size: usize,
    pub batch_privacy_set_size: usize,
    pub min_pq_security_bits: u16,
    pub target_pq_security_bits: u16,
    pub max_user_fee_bps: u64,
    pub low_fee_bps: u64,
    pub rebate_bps: u64,
    pub offer_ttl_blocks: u64,
    pub lock_note_ttl_blocks: u64,
    pub reservation_ttl_blocks: u64,
    pub dispute_window_blocks: u64,
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
            schema_version: MONERO_L2_PRIVATE_ATOMIC_SWAP_ESCROW_RUNTIME_SCHEMA_VERSION,
            monero_network: MONERO_L2_PRIVATE_ATOMIC_SWAP_ESCROW_RUNTIME_DEVNET_MONERO_NETWORK
                .to_string(),
            l2_network: MONERO_L2_PRIVATE_ATOMIC_SWAP_ESCROW_RUNTIME_DEVNET_L2_NETWORK.to_string(),
            base_asset_id: MONERO_L2_PRIVATE_ATOMIC_SWAP_ESCROW_RUNTIME_DEVNET_BASE_ASSET_ID
                .to_string(),
            quote_asset_id: MONERO_L2_PRIVATE_ATOMIC_SWAP_ESCROW_RUNTIME_DEVNET_QUOTE_ASSET_ID
                .to_string(),
            fee_asset_id: MONERO_L2_PRIVATE_ATOMIC_SWAP_ESCROW_RUNTIME_DEVNET_FEE_ASSET_ID
                .to_string(),
            hash_suite: MONERO_L2_PRIVATE_ATOMIC_SWAP_ESCROW_RUNTIME_HASH_SUITE.to_string(),
            swap_offer_scheme: MONERO_L2_PRIVATE_ATOMIC_SWAP_ESCROW_RUNTIME_SWAP_OFFER_SCHEME
                .to_string(),
            lock_note_scheme: MONERO_L2_PRIVATE_ATOMIC_SWAP_ESCROW_RUNTIME_LOCK_NOTE_SCHEME
                .to_string(),
            pq_adaptor_scheme: MONERO_L2_PRIVATE_ATOMIC_SWAP_ESCROW_RUNTIME_PQ_ADAPTOR_SCHEME
                .to_string(),
            low_fee_reservation_scheme:
                MONERO_L2_PRIVATE_ATOMIC_SWAP_ESCROW_RUNTIME_LOW_FEE_RESERVATION_SCHEME.to_string(),
            settlement_batch_scheme:
                MONERO_L2_PRIVATE_ATOMIC_SWAP_ESCROW_RUNTIME_SETTLEMENT_BATCH_SCHEME.to_string(),
            dispute_receipt_scheme:
                MONERO_L2_PRIVATE_ATOMIC_SWAP_ESCROW_RUNTIME_DISPUTE_RECEIPT_SCHEME.to_string(),
            genesis_height: MONERO_L2_PRIVATE_ATOMIC_SWAP_ESCROW_RUNTIME_DEVNET_HEIGHT,
            max_offers: MONERO_L2_PRIVATE_ATOMIC_SWAP_ESCROW_RUNTIME_DEFAULT_MAX_OFFERS,
            max_lock_notes: MONERO_L2_PRIVATE_ATOMIC_SWAP_ESCROW_RUNTIME_DEFAULT_MAX_LOCK_NOTES,
            max_adaptor_attestations:
                MONERO_L2_PRIVATE_ATOMIC_SWAP_ESCROW_RUNTIME_DEFAULT_MAX_ATTESTATIONS,
            max_low_fee_reservations:
                MONERO_L2_PRIVATE_ATOMIC_SWAP_ESCROW_RUNTIME_DEFAULT_MAX_RESERVATIONS,
            max_settlement_batches:
                MONERO_L2_PRIVATE_ATOMIC_SWAP_ESCROW_RUNTIME_DEFAULT_MAX_BATCHES,
            max_dispute_receipts: MONERO_L2_PRIVATE_ATOMIC_SWAP_ESCROW_RUNTIME_DEFAULT_MAX_DISPUTES,
            max_public_records:
                MONERO_L2_PRIVATE_ATOMIC_SWAP_ESCROW_RUNTIME_DEFAULT_MAX_PUBLIC_RECORDS,
            min_privacy_set_size:
                MONERO_L2_PRIVATE_ATOMIC_SWAP_ESCROW_RUNTIME_DEFAULT_MIN_PRIVACY_SET_SIZE,
            batch_privacy_set_size:
                MONERO_L2_PRIVATE_ATOMIC_SWAP_ESCROW_RUNTIME_DEFAULT_BATCH_PRIVACY_SET_SIZE,
            min_pq_security_bits:
                MONERO_L2_PRIVATE_ATOMIC_SWAP_ESCROW_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS,
            target_pq_security_bits:
                MONERO_L2_PRIVATE_ATOMIC_SWAP_ESCROW_RUNTIME_DEFAULT_TARGET_PQ_SECURITY_BITS,
            max_user_fee_bps: MONERO_L2_PRIVATE_ATOMIC_SWAP_ESCROW_RUNTIME_DEFAULT_MAX_USER_FEE_BPS,
            low_fee_bps: MONERO_L2_PRIVATE_ATOMIC_SWAP_ESCROW_RUNTIME_DEFAULT_LOW_FEE_BPS,
            rebate_bps: MONERO_L2_PRIVATE_ATOMIC_SWAP_ESCROW_RUNTIME_DEFAULT_REBATE_BPS,
            offer_ttl_blocks: MONERO_L2_PRIVATE_ATOMIC_SWAP_ESCROW_RUNTIME_DEFAULT_OFFER_TTL_BLOCKS,
            lock_note_ttl_blocks:
                MONERO_L2_PRIVATE_ATOMIC_SWAP_ESCROW_RUNTIME_DEFAULT_LOCK_NOTE_TTL_BLOCKS,
            reservation_ttl_blocks:
                MONERO_L2_PRIVATE_ATOMIC_SWAP_ESCROW_RUNTIME_DEFAULT_RESERVATION_TTL_BLOCKS,
            dispute_window_blocks:
                MONERO_L2_PRIVATE_ATOMIC_SWAP_ESCROW_RUNTIME_DEFAULT_DISPUTE_WINDOW_BLOCKS,
        }
    }

    pub fn validate(&self) -> MoneroL2PrivateAtomicSwapEscrowRuntimeResult<()> {
        require(self.chain_id == CHAIN_ID, "chain id mismatch")?;
        require(
            self.protocol_version == PROTOCOL_VERSION,
            "protocol version mismatch",
        )?;
        require(
            self.schema_version == MONERO_L2_PRIVATE_ATOMIC_SWAP_ESCROW_RUNTIME_SCHEMA_VERSION,
            "schema version mismatch",
        )?;
        require_non_empty("monero_network", &self.monero_network)?;
        require_non_empty("l2_network", &self.l2_network)?;
        require_non_empty("base_asset_id", &self.base_asset_id)?;
        require_non_empty("quote_asset_id", &self.quote_asset_id)?;
        require_non_empty("fee_asset_id", &self.fee_asset_id)?;
        require_positive_usize("max_offers", self.max_offers)?;
        require_positive_usize("max_lock_notes", self.max_lock_notes)?;
        require_positive_usize("max_adaptor_attestations", self.max_adaptor_attestations)?;
        require_positive_usize("max_low_fee_reservations", self.max_low_fee_reservations)?;
        require_positive_usize("max_settlement_batches", self.max_settlement_batches)?;
        require_positive_usize("max_dispute_receipts", self.max_dispute_receipts)?;
        require_positive_usize("max_public_records", self.max_public_records)?;
        require_positive_usize("min_privacy_set_size", self.min_privacy_set_size)?;
        if self.batch_privacy_set_size < self.min_privacy_set_size {
            return Err("batch_privacy_set_size below minimum privacy set".to_string());
        }
        require(
            self.min_pq_security_bits >= 192,
            "minimum pq security below policy",
        )?;
        require(
            self.target_pq_security_bits >= self.min_pq_security_bits,
            "target pq security below minimum",
        )?;
        require_bps("max_user_fee_bps", self.max_user_fee_bps)?;
        require_bps("low_fee_bps", self.low_fee_bps)?;
        require_bps("rebate_bps", self.rebate_bps)?;
        require(
            self.low_fee_bps <= self.max_user_fee_bps,
            "low fee bps exceeds user fee ceiling",
        )?;
        require(self.offer_ttl_blocks > 0, "offer ttl is zero")?;
        require(self.lock_note_ttl_blocks > 0, "lock note ttl is zero")?;
        require(self.reservation_ttl_blocks > 0, "reservation ttl is zero")?;
        require(self.dispute_window_blocks > 0, "dispute window is zero")?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub offer_counter: u64,
    pub lock_note_counter: u64,
    pub adaptor_attestation_counter: u64,
    pub low_fee_reservation_counter: u64,
    pub settlement_batch_counter: u64,
    pub dispute_receipt_counter: u64,
    pub settled_offers: u64,
    pub disputed_offers: u64,
    pub maker_reservations: u64,
    pub taker_reservations: u64,
    pub public_records: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub counters_root: String,
    pub swap_offer_root: String,
    pub shielded_lock_note_root: String,
    pub pq_adaptor_attestation_root: String,
    pub low_fee_reservation_root: String,
    pub private_settlement_batch_root: String,
    pub dispute_receipt_root: String,
    pub nullifier_root: String,
    pub public_record_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CreateSwapOfferRequest {
    pub maker_commitment: String,
    pub direction: SwapDirection,
    pub base_asset_id: String,
    pub quote_asset_id: String,
    pub amount_commitment_root: String,
    pub price_commitment_root: String,
    pub maker_terms_root: String,
    pub maker_refund_root: String,
    pub privacy_set_size: usize,
    pub max_fee_bps: u64,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub offer_nonce: String,
}

impl CreateSwapOfferRequest {
    pub fn validate(&self, config: &Config) -> MoneroL2PrivateAtomicSwapEscrowRuntimeResult<()> {
        require_non_empty("maker_commitment", &self.maker_commitment)?;
        require_non_empty("base_asset_id", &self.base_asset_id)?;
        require_non_empty("quote_asset_id", &self.quote_asset_id)?;
        require_root("amount_commitment_root", &self.amount_commitment_root)?;
        require_root("price_commitment_root", &self.price_commitment_root)?;
        require_root("maker_terms_root", &self.maker_terms_root)?;
        require_root("maker_refund_root", &self.maker_refund_root)?;
        require_non_empty("offer_nonce", &self.offer_nonce)?;
        require_min_privacy(config, self.privacy_set_size)?;
        require_bps("max_fee_bps", self.max_fee_bps)?;
        require(
            self.max_fee_bps <= config.max_user_fee_bps,
            "offer fee exceeds runtime ceiling",
        )?;
        require(
            self.expires_at_height > self.opened_at_height,
            "offer expiry must be after open height",
        )?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "maker_commitment": self.maker_commitment,
            "direction": self.direction.as_str(),
            "base_asset_id": self.base_asset_id,
            "quote_asset_id": self.quote_asset_id,
            "amount_commitment_root": self.amount_commitment_root,
            "price_commitment_root": self.price_commitment_root,
            "maker_terms_root": self.maker_terms_root,
            "maker_refund_root": self.maker_refund_root,
            "privacy_set_size": self.privacy_set_size,
            "max_fee_bps": self.max_fee_bps,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "offer_nonce": self.offer_nonce,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SubmitShieldedLockNoteRequest {
    pub offer_id: String,
    pub locker_role: SwapRole,
    pub owner_commitment: String,
    pub note_commitment_root: String,
    pub amount_commitment_root: String,
    pub nullifier_root: String,
    pub range_proof_root: String,
    pub encrypted_swap_state_root: String,
    pub timelock_commitment_root: String,
    pub pq_authorization_root: String,
    pub privacy_set_size: usize,
    pub submitted_at_height: u64,
    pub expires_at_height: u64,
    pub note_nonce: String,
}

impl SubmitShieldedLockNoteRequest {
    pub fn validate(&self, config: &Config) -> MoneroL2PrivateAtomicSwapEscrowRuntimeResult<()> {
        require_non_empty("offer_id", &self.offer_id)?;
        require_non_empty("owner_commitment", &self.owner_commitment)?;
        require_root("note_commitment_root", &self.note_commitment_root)?;
        require_root("amount_commitment_root", &self.amount_commitment_root)?;
        require_root("nullifier_root", &self.nullifier_root)?;
        require_root("range_proof_root", &self.range_proof_root)?;
        require_root("encrypted_swap_state_root", &self.encrypted_swap_state_root)?;
        require_root("timelock_commitment_root", &self.timelock_commitment_root)?;
        require_root("pq_authorization_root", &self.pq_authorization_root)?;
        require_non_empty("note_nonce", &self.note_nonce)?;
        require_min_privacy(config, self.privacy_set_size)?;
        require(
            self.expires_at_height > self.submitted_at_height,
            "lock note expiry must be after submission height",
        )?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "offer_id": self.offer_id,
            "locker_role": self.locker_role.as_str(),
            "owner_commitment": self.owner_commitment,
            "note_commitment_root": self.note_commitment_root,
            "amount_commitment_root": self.amount_commitment_root,
            "nullifier_root": self.nullifier_root,
            "range_proof_root": self.range_proof_root,
            "encrypted_swap_state_root": self.encrypted_swap_state_root,
            "timelock_commitment_root": self.timelock_commitment_root,
            "pq_authorization_root": self.pq_authorization_root,
            "privacy_set_size": self.privacy_set_size,
            "submitted_at_height": self.submitted_at_height,
            "expires_at_height": self.expires_at_height,
            "note_nonce": self.note_nonce,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AttestPqAdaptorRequest {
    pub offer_id: String,
    pub maker_note_id: Option<String>,
    pub taker_note_id: Option<String>,
    pub attester_commitment: String,
    pub adaptor_public_key_root: String,
    pub encrypted_adaptor_secret_root: String,
    pub pq_transcript_root: String,
    pub ml_dsa_signature_root: String,
    pub slh_dsa_signature_root: String,
    pub security_bits: u16,
    pub attested_at_height: u64,
    pub attestation_nonce: String,
}

impl AttestPqAdaptorRequest {
    pub fn validate(&self, config: &Config) -> MoneroL2PrivateAtomicSwapEscrowRuntimeResult<()> {
        require_non_empty("offer_id", &self.offer_id)?;
        require_non_empty("attester_commitment", &self.attester_commitment)?;
        require_root("adaptor_public_key_root", &self.adaptor_public_key_root)?;
        require_root(
            "encrypted_adaptor_secret_root",
            &self.encrypted_adaptor_secret_root,
        )?;
        require_root("pq_transcript_root", &self.pq_transcript_root)?;
        require_root("ml_dsa_signature_root", &self.ml_dsa_signature_root)?;
        require_root("slh_dsa_signature_root", &self.slh_dsa_signature_root)?;
        require_non_empty("attestation_nonce", &self.attestation_nonce)?;
        require(
            self.security_bits >= config.min_pq_security_bits,
            "pq adaptor security below runtime minimum",
        )?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReserveLowFeeSwapRequest {
    pub offer_id: String,
    pub reserver_role: SwapRole,
    pub sponsor_commitment: String,
    pub fee_asset_id: String,
    pub max_fee_bps: u64,
    pub reservation_budget_root: String,
    pub rebate_destination_root: String,
    pub pq_sponsor_authorization_root: String,
    pub reserved_at_height: u64,
    pub reserved_until_height: u64,
    pub reservation_nonce: String,
}

impl ReserveLowFeeSwapRequest {
    pub fn validate(&self, config: &Config) -> MoneroL2PrivateAtomicSwapEscrowRuntimeResult<()> {
        require_non_empty("offer_id", &self.offer_id)?;
        require_non_empty("sponsor_commitment", &self.sponsor_commitment)?;
        require_non_empty("fee_asset_id", &self.fee_asset_id)?;
        require_bps("max_fee_bps", self.max_fee_bps)?;
        require(
            self.max_fee_bps <= config.max_user_fee_bps,
            "reservation fee exceeds runtime ceiling",
        )?;
        require_root("reservation_budget_root", &self.reservation_budget_root)?;
        require_root("rebate_destination_root", &self.rebate_destination_root)?;
        require_root(
            "pq_sponsor_authorization_root",
            &self.pq_sponsor_authorization_root,
        )?;
        require_non_empty("reservation_nonce", &self.reservation_nonce)?;
        require(
            self.reserved_until_height > self.reserved_at_height,
            "reservation expiry must be after reservation height",
        )?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "offer_id": self.offer_id,
            "reserver_role": self.reserver_role.as_str(),
            "sponsor_commitment": self.sponsor_commitment,
            "fee_asset_id": self.fee_asset_id,
            "max_fee_bps": self.max_fee_bps,
            "reservation_budget_root": self.reservation_budget_root,
            "rebate_destination_root": self.rebate_destination_root,
            "pq_sponsor_authorization_root": self.pq_sponsor_authorization_root,
            "reserved_at_height": self.reserved_at_height,
            "reserved_until_height": self.reserved_until_height,
            "reservation_nonce": self.reservation_nonce,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BuildPrivateSettlementBatchRequest {
    pub coordinator_commitment: String,
    pub offer_ids: Vec<String>,
    pub lock_note_ids: Vec<String>,
    pub attestation_ids: Vec<String>,
    pub reservation_ids: Vec<String>,
    pub netted_swap_root: String,
    pub monero_settlement_root: String,
    pub l2_transition_root: String,
    pub fee_rebate_root: String,
    pub privacy_set_size: usize,
    pub settled_at_height: u64,
    pub batch_nonce: String,
}

impl BuildPrivateSettlementBatchRequest {
    pub fn validate(&self, config: &Config) -> MoneroL2PrivateAtomicSwapEscrowRuntimeResult<()> {
        require_non_empty("coordinator_commitment", &self.coordinator_commitment)?;
        require_non_empty_vec("offer_ids", &self.offer_ids)?;
        require_non_empty_vec("lock_note_ids", &self.lock_note_ids)?;
        require_unique("offer_ids", &self.offer_ids)?;
        require_unique("lock_note_ids", &self.lock_note_ids)?;
        require_unique("attestation_ids", &self.attestation_ids)?;
        require_unique("reservation_ids", &self.reservation_ids)?;
        require_root("netted_swap_root", &self.netted_swap_root)?;
        require_root("monero_settlement_root", &self.monero_settlement_root)?;
        require_root("l2_transition_root", &self.l2_transition_root)?;
        require_root("fee_rebate_root", &self.fee_rebate_root)?;
        require_non_empty("batch_nonce", &self.batch_nonce)?;
        if self.privacy_set_size < config.batch_privacy_set_size {
            return Err("settlement batch privacy set below runtime minimum".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FileDisputeReceiptRequest {
    pub subject_kind: DisputeSubjectKind,
    pub subject_id: String,
    pub challenger_commitment: String,
    pub kind: DisputeKind,
    pub evidence_root: String,
    pub requested_remedy_root: String,
    pub pq_signature_root: String,
    pub opened_at_height: u64,
    pub dispute_nonce: String,
}

impl FileDisputeReceiptRequest {
    pub fn validate(&self) -> MoneroL2PrivateAtomicSwapEscrowRuntimeResult<()> {
        require_non_empty("subject_id", &self.subject_id)?;
        require_non_empty("challenger_commitment", &self.challenger_commitment)?;
        require_root("evidence_root", &self.evidence_root)?;
        require_root("requested_remedy_root", &self.requested_remedy_root)?;
        require_root("pq_signature_root", &self.pq_signature_root)?;
        require_non_empty("dispute_nonce", &self.dispute_nonce)?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "subject_kind": self.subject_kind.as_str(),
            "subject_id": self.subject_id,
            "challenger_commitment": self.challenger_commitment,
            "kind": self.kind.as_str(),
            "evidence_root": self.evidence_root,
            "requested_remedy_root": self.requested_remedy_root,
            "pq_signature_root": self.pq_signature_root,
            "opened_at_height": self.opened_at_height,
            "dispute_nonce": self.dispute_nonce,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SwapOfferRecord {
    pub offer_id: String,
    pub sequence: u64,
    pub request: CreateSwapOfferRequest,
    pub status: SwapOfferStatus,
    pub offer_root: String,
}

impl SwapOfferRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "offer_id": self.offer_id,
            "sequence": self.sequence,
            "request": self.request.public_record(),
            "status": self.status.as_str(),
            "offer_root": self.offer_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ShieldedLockNoteRecord {
    pub lock_note_id: String,
    pub sequence: u64,
    pub request: SubmitShieldedLockNoteRequest,
    pub status: LockNoteStatus,
    pub lock_note_root: String,
}

impl ShieldedLockNoteRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "lock_note_id": self.lock_note_id,
            "sequence": self.sequence,
            "request": self.request.public_record(),
            "status": self.status.as_str(),
            "lock_note_root": self.lock_note_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqAdaptorAttestationRecord {
    pub attestation_id: String,
    pub sequence: u64,
    pub request: AttestPqAdaptorRequest,
    pub status: PqAdaptorAttestationStatus,
    pub attestation_root: String,
}

impl PqAdaptorAttestationRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "sequence": self.sequence,
            "request": self.request.public_record(),
            "status": self.status.as_str(),
            "attestation_root": self.attestation_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LowFeeSwapReservationRecord {
    pub reservation_id: String,
    pub sequence: u64,
    pub request: ReserveLowFeeSwapRequest,
    pub low_fee_bps: u64,
    pub rebate_bps: u64,
    pub status: ReservationStatus,
    pub reservation_root: String,
}

impl LowFeeSwapReservationRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "reservation_id": self.reservation_id,
            "sequence": self.sequence,
            "request": self.request.public_record(),
            "low_fee_bps": self.low_fee_bps,
            "rebate_bps": self.rebate_bps,
            "status": self.status.as_str(),
            "reservation_root": self.reservation_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivateSettlementBatchRecord {
    pub batch_id: String,
    pub sequence: u64,
    pub request: BuildPrivateSettlementBatchRequest,
    pub status: SettlementBatchStatus,
    pub batch_root: String,
    pub state_root_after: String,
}

impl PrivateSettlementBatchRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "sequence": self.sequence,
            "request": self.request.public_record(),
            "status": self.status.as_str(),
            "batch_root": self.batch_root,
            "state_root_after": self.state_root_after,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DisputeReceiptRecord {
    pub dispute_id: String,
    pub sequence: u64,
    pub request: FileDisputeReceiptRequest,
    pub status: DisputeStatus,
    pub dispute_root: String,
    pub expires_at_height: u64,
}

impl DisputeReceiptRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "dispute_id": self.dispute_id,
            "sequence": self.sequence,
            "request": self.request.public_record(),
            "status": self.status.as_str(),
            "dispute_root": self.dispute_root,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub swap_offers: BTreeMap<String, SwapOfferRecord>,
    pub shielded_lock_notes: BTreeMap<String, ShieldedLockNoteRecord>,
    pub pq_adaptor_attestations: BTreeMap<String, PqAdaptorAttestationRecord>,
    pub low_fee_reservations: BTreeMap<String, LowFeeSwapReservationRecord>,
    pub private_settlement_batches: BTreeMap<String, PrivateSettlementBatchRecord>,
    pub dispute_receipts: BTreeMap<String, DisputeReceiptRecord>,
    pub consumed_nullifiers: BTreeSet<String>,
    pub public_records: BTreeMap<String, Value>,
}

impl State {
    pub fn devnet() -> MoneroL2PrivateAtomicSwapEscrowRuntimeResult<Self> {
        Self::new(Config::devnet())
    }

    pub fn new(config: Config) -> MoneroL2PrivateAtomicSwapEscrowRuntimeResult<Self> {
        config.validate()?;
        let mut state = Self {
            config,
            counters: Counters::default(),
            swap_offers: BTreeMap::new(),
            shielded_lock_notes: BTreeMap::new(),
            pq_adaptor_attestations: BTreeMap::new(),
            low_fee_reservations: BTreeMap::new(),
            private_settlement_batches: BTreeMap::new(),
            dispute_receipts: BTreeMap::new(),
            consumed_nullifiers: BTreeSet::new(),
            public_records: BTreeMap::new(),
        };
        let config_record = state.config.public_record();
        state.record_public("config".to_string(), config_record)?;
        Ok(state)
    }

    pub fn create_swap_offer(
        &mut self,
        request: CreateSwapOfferRequest,
    ) -> MoneroL2PrivateAtomicSwapEscrowRuntimeResult<SwapOfferRecord> {
        request.validate(&self.config)?;
        ensure_capacity(
            self.swap_offers.len(),
            self.config.max_offers,
            "swap offers",
        )?;
        self.counters.offer_counter = self.counters.offer_counter.saturating_add(1);
        let sequence = self.counters.offer_counter;
        let offer_id = private_atomic_swap_offer_id(&request, sequence);
        require(
            !self.swap_offers.contains_key(&offer_id),
            "duplicate swap offer",
        )?;
        let offer_root = root_from_record(
            "MONERO-L2-PRIVATE-ATOMIC-SWAP-ESCROW-OFFER",
            &request.public_record(),
        );
        let record = SwapOfferRecord {
            offer_id: offer_id.clone(),
            sequence,
            request,
            status: SwapOfferStatus::Open,
            offer_root,
        };
        self.swap_offers.insert(offer_id.clone(), record.clone());
        self.record_public(format!("offer:{offer_id}"), record.public_record())?;
        Ok(record)
    }

    pub fn submit_shielded_lock_note(
        &mut self,
        request: SubmitShieldedLockNoteRequest,
    ) -> MoneroL2PrivateAtomicSwapEscrowRuntimeResult<ShieldedLockNoteRecord> {
        request.validate(&self.config)?;
        ensure_capacity(
            self.shielded_lock_notes.len(),
            self.config.max_lock_notes,
            "shielded lock notes",
        )?;
        {
            let offer = self.require_offer(&request.offer_id)?;
            require(
                offer.status.accepts_locks(),
                "swap offer does not accept locks",
            )?;
            require(
                request.expires_at_height
                    <= offer
                        .request
                        .expires_at_height
                        .saturating_add(self.config.lock_note_ttl_blocks),
                "lock note expiry exceeds swap window",
            )?;
        }
        require(
            !self.consumed_nullifiers.contains(&request.nullifier_root),
            "duplicate lock note nullifier",
        )?;
        self.counters.lock_note_counter = self.counters.lock_note_counter.saturating_add(1);
        let sequence = self.counters.lock_note_counter;
        let lock_note_id = shielded_atomic_swap_lock_note_id(&request, sequence);
        let lock_note_root = root_from_record(
            "MONERO-L2-PRIVATE-ATOMIC-SWAP-ESCROW-LOCK-NOTE",
            &request.public_record(),
        );
        let offer_id = request.offer_id.clone();
        let locker_role = request.locker_role;
        let record = ShieldedLockNoteRecord {
            lock_note_id: lock_note_id.clone(),
            sequence,
            request: request.clone(),
            status: LockNoteStatus::Accepted,
            lock_note_root,
        };
        self.consumed_nullifiers
            .insert(request.nullifier_root.clone());
        self.shielded_lock_notes
            .insert(lock_note_id.clone(), record.clone());
        let updated_offer_record = if let Some(offer) = self.swap_offers.get_mut(&offer_id) {
            offer.status = match locker_role {
                SwapRole::Maker => {
                    if offer.status == SwapOfferStatus::TakerLocked {
                        SwapOfferStatus::Matched
                    } else {
                        SwapOfferStatus::MakerLocked
                    }
                }
                SwapRole::Taker => {
                    if offer.status == SwapOfferStatus::MakerLocked {
                        SwapOfferStatus::Matched
                    } else {
                        SwapOfferStatus::TakerLocked
                    }
                }
            };
            Some(offer.public_record())
        } else {
            None
        };
        self.record_public(format!("lock_note:{lock_note_id}"), record.public_record())?;
        if let Some(offer_record) = updated_offer_record {
            self.record_public(format!("offer:{offer_id}"), offer_record)?;
        }
        Ok(record)
    }

    pub fn attest_pq_adaptor(
        &mut self,
        request: AttestPqAdaptorRequest,
    ) -> MoneroL2PrivateAtomicSwapEscrowRuntimeResult<PqAdaptorAttestationRecord> {
        request.validate(&self.config)?;
        ensure_capacity(
            self.pq_adaptor_attestations.len(),
            self.config.max_adaptor_attestations,
            "pq adaptor attestations",
        )?;
        self.require_offer(&request.offer_id)?;
        if let Some(note_id) = &request.maker_note_id {
            self.require_lock_note(note_id)?;
        }
        if let Some(note_id) = &request.taker_note_id {
            self.require_lock_note(note_id)?;
        }
        self.counters.adaptor_attestation_counter =
            self.counters.adaptor_attestation_counter.saturating_add(1);
        let sequence = self.counters.adaptor_attestation_counter;
        let attestation_id = pq_adaptor_attestation_id(&request, sequence);
        let attestation_root = root_from_record(
            "MONERO-L2-PRIVATE-ATOMIC-SWAP-ESCROW-PQ-ADAPTOR-ATTESTATION",
            &request.public_record(),
        );
        let status = if request.maker_note_id.is_some() && request.taker_note_id.is_some() {
            PqAdaptorAttestationStatus::BoundToLocks
        } else {
            PqAdaptorAttestationStatus::Verified
        };
        let record = PqAdaptorAttestationRecord {
            attestation_id: attestation_id.clone(),
            sequence,
            request,
            status,
            attestation_root,
        };
        self.pq_adaptor_attestations
            .insert(attestation_id.clone(), record.clone());
        self.record_public(
            format!("adaptor_attestation:{attestation_id}"),
            record.public_record(),
        )?;
        Ok(record)
    }

    pub fn reserve_low_fee_swap(
        &mut self,
        request: ReserveLowFeeSwapRequest,
    ) -> MoneroL2PrivateAtomicSwapEscrowRuntimeResult<LowFeeSwapReservationRecord> {
        request.validate(&self.config)?;
        ensure_capacity(
            self.low_fee_reservations.len(),
            self.config.max_low_fee_reservations,
            "low fee reservations",
        )?;
        self.require_offer(&request.offer_id)?;
        self.counters.low_fee_reservation_counter =
            self.counters.low_fee_reservation_counter.saturating_add(1);
        let sequence = self.counters.low_fee_reservation_counter;
        let reservation_id = low_fee_atomic_swap_reservation_id(&request, sequence);
        let reservation_root = root_from_record(
            "MONERO-L2-PRIVATE-ATOMIC-SWAP-ESCROW-LOW-FEE-RESERVATION",
            &request.public_record(),
        );
        match request.reserver_role {
            SwapRole::Maker => {
                self.counters.maker_reservations =
                    self.counters.maker_reservations.saturating_add(1)
            }
            SwapRole::Taker => {
                self.counters.taker_reservations =
                    self.counters.taker_reservations.saturating_add(1)
            }
        }
        let record = LowFeeSwapReservationRecord {
            reservation_id: reservation_id.clone(),
            sequence,
            request,
            low_fee_bps: self.config.low_fee_bps,
            rebate_bps: self.config.rebate_bps,
            status: ReservationStatus::Reserved,
            reservation_root,
        };
        self.low_fee_reservations
            .insert(reservation_id.clone(), record.clone());
        self.record_public(
            format!("low_fee_reservation:{reservation_id}"),
            record.public_record(),
        )?;
        Ok(record)
    }

    pub fn build_private_settlement_batch(
        &mut self,
        request: BuildPrivateSettlementBatchRequest,
    ) -> MoneroL2PrivateAtomicSwapEscrowRuntimeResult<PrivateSettlementBatchRecord> {
        request.validate(&self.config)?;
        ensure_capacity(
            self.private_settlement_batches.len(),
            self.config.max_settlement_batches,
            "private settlement batches",
        )?;
        for offer_id in &request.offer_ids {
            self.require_offer(offer_id)?;
        }
        for note_id in &request.lock_note_ids {
            self.require_lock_note(note_id)?;
        }
        for attestation_id in &request.attestation_ids {
            self.require_attestation(attestation_id)?;
        }
        for reservation_id in &request.reservation_ids {
            self.require_reservation(reservation_id)?;
        }
        self.counters.settlement_batch_counter =
            self.counters.settlement_batch_counter.saturating_add(1);
        let sequence = self.counters.settlement_batch_counter;
        let batch_id = private_atomic_swap_settlement_batch_id(&request, sequence);
        let batch_root = root_from_record(
            "MONERO-L2-PRIVATE-ATOMIC-SWAP-ESCROW-SETTLEMENT-BATCH",
            &request.public_record(),
        );
        for offer_id in &request.offer_ids {
            if let Some(offer) = self.swap_offers.get_mut(offer_id) {
                offer.status = SwapOfferStatus::Settled;
            }
            self.counters.settled_offers = self.counters.settled_offers.saturating_add(1);
        }
        for note_id in &request.lock_note_ids {
            if let Some(note) = self.shielded_lock_notes.get_mut(note_id) {
                note.status = LockNoteStatus::Settled;
            }
        }
        for attestation_id in &request.attestation_ids {
            if let Some(attestation) = self.pq_adaptor_attestations.get_mut(attestation_id) {
                attestation.status = PqAdaptorAttestationStatus::Settled;
            }
        }
        for reservation_id in &request.reservation_ids {
            if let Some(reservation) = self.low_fee_reservations.get_mut(reservation_id) {
                reservation.status = ReservationStatus::RebateQueued;
            }
        }
        let state_root_after = state_root_from_record(&json!({
            "previous_state_root": self.state_root(),
            "batch_root": batch_root,
            "sequence": sequence,
        }));
        let record = PrivateSettlementBatchRecord {
            batch_id: batch_id.clone(),
            sequence,
            request: request.clone(),
            status: SettlementBatchStatus::Settled,
            batch_root,
            state_root_after,
        };
        self.private_settlement_batches
            .insert(batch_id.clone(), record.clone());
        self.refresh_public_records_for_batch(&request)?;
        self.record_public(
            format!("private_settlement_batch:{batch_id}"),
            record.public_record(),
        )?;
        Ok(record)
    }

    pub fn file_dispute_receipt(
        &mut self,
        request: FileDisputeReceiptRequest,
    ) -> MoneroL2PrivateAtomicSwapEscrowRuntimeResult<DisputeReceiptRecord> {
        request.validate()?;
        ensure_capacity(
            self.dispute_receipts.len(),
            self.config.max_dispute_receipts,
            "dispute receipts",
        )?;
        self.require_subject(request.subject_kind, &request.subject_id)?;
        self.counters.dispute_receipt_counter =
            self.counters.dispute_receipt_counter.saturating_add(1);
        let sequence = self.counters.dispute_receipt_counter;
        let dispute_id = private_atomic_swap_dispute_receipt_id(&request, sequence);
        let dispute_root = root_from_record(
            "MONERO-L2-PRIVATE-ATOMIC-SWAP-ESCROW-DISPUTE-RECEIPT",
            &request.public_record(),
        );
        let subject_kind = request.subject_kind;
        let subject_id = request.subject_id.clone();
        self.mark_subject_disputed(subject_kind, &subject_id);
        let subject_public_record = self.subject_public_record(subject_kind, &subject_id);
        if subject_kind == DisputeSubjectKind::SwapOffer {
            self.counters.disputed_offers = self.counters.disputed_offers.saturating_add(1);
        }
        let record = DisputeReceiptRecord {
            dispute_id: dispute_id.clone(),
            sequence,
            expires_at_height: request
                .opened_at_height
                .saturating_add(self.config.dispute_window_blocks),
            request,
            status: DisputeStatus::Open,
            dispute_root,
        };
        self.dispute_receipts
            .insert(dispute_id.clone(), record.clone());
        if let Some(subject_public_record) = subject_public_record {
            self.record_public(
                subject_public_key(subject_kind, &subject_id),
                subject_public_record,
            )?;
        }
        self.record_public(format!("dispute:{dispute_id}"), record.public_record())?;
        Ok(record)
    }

    pub fn counters(&self) -> Counters {
        let mut counters = self.counters.clone();
        counters.public_records = self.public_records.len() as u64;
        counters
    }

    pub fn roots(&self) -> Roots {
        Roots {
            config_root: root_from_record(
                "MONERO-L2-PRIVATE-ATOMIC-SWAP-ESCROW-CONFIG",
                &self.config.public_record(),
            ),
            counters_root: root_from_record(
                "MONERO-L2-PRIVATE-ATOMIC-SWAP-ESCROW-COUNTERS",
                &self.counters().public_record(),
            ),
            swap_offer_root: map_root(
                "MONERO-L2-PRIVATE-ATOMIC-SWAP-ESCROW-OFFER-ROOT",
                &self.swap_offers,
                SwapOfferRecord::public_record,
            ),
            shielded_lock_note_root: map_root(
                "MONERO-L2-PRIVATE-ATOMIC-SWAP-ESCROW-LOCK-NOTE-ROOT",
                &self.shielded_lock_notes,
                ShieldedLockNoteRecord::public_record,
            ),
            pq_adaptor_attestation_root: map_root(
                "MONERO-L2-PRIVATE-ATOMIC-SWAP-ESCROW-PQ-ADAPTOR-ROOT",
                &self.pq_adaptor_attestations,
                PqAdaptorAttestationRecord::public_record,
            ),
            low_fee_reservation_root: map_root(
                "MONERO-L2-PRIVATE-ATOMIC-SWAP-ESCROW-LOW-FEE-ROOT",
                &self.low_fee_reservations,
                LowFeeSwapReservationRecord::public_record,
            ),
            private_settlement_batch_root: map_root(
                "MONERO-L2-PRIVATE-ATOMIC-SWAP-ESCROW-SETTLEMENT-BATCH-ROOT",
                &self.private_settlement_batches,
                PrivateSettlementBatchRecord::public_record,
            ),
            dispute_receipt_root: map_root(
                "MONERO-L2-PRIVATE-ATOMIC-SWAP-ESCROW-DISPUTE-ROOT",
                &self.dispute_receipts,
                DisputeReceiptRecord::public_record,
            ),
            nullifier_root: set_root(
                "MONERO-L2-PRIVATE-ATOMIC-SWAP-ESCROW-NULLIFIER-ROOT",
                &self.consumed_nullifiers,
            ),
            public_record_root: map_value_root(
                "MONERO-L2-PRIVATE-ATOMIC-SWAP-ESCROW-PUBLIC-RECORD-ROOT",
                &self.public_records,
            ),
        }
    }

    pub fn public_record_without_state_root(&self) -> Value {
        json!({
            "protocol_version": self.config.protocol_version,
            "schema_version": self.config.schema_version,
            "chain_id": self.config.chain_id,
            "config": self.config.public_record(),
            "counters": self.counters().public_record(),
            "roots": self.roots().public_record(),
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        set_json_field(&mut record, "state_root", json!(self.state_root()));
        record
    }

    pub fn state_root(&self) -> String {
        state_root_from_record(&self.public_record_without_state_root())
    }

    fn record_public(
        &mut self,
        key: String,
        record: Value,
    ) -> MoneroL2PrivateAtomicSwapEscrowRuntimeResult<()> {
        if !self.public_records.contains_key(&key) {
            ensure_capacity(
                self.public_records.len(),
                self.config.max_public_records,
                "public records",
            )?;
        }
        self.public_records.insert(key, record);
        self.counters.public_records = self.public_records.len() as u64;
        Ok(())
    }

    fn require_offer(
        &self,
        offer_id: &str,
    ) -> MoneroL2PrivateAtomicSwapEscrowRuntimeResult<&SwapOfferRecord> {
        self.swap_offers
            .get(offer_id)
            .ok_or_else(|| format!("unknown swap offer {offer_id}"))
    }

    fn require_lock_note(
        &self,
        lock_note_id: &str,
    ) -> MoneroL2PrivateAtomicSwapEscrowRuntimeResult<&ShieldedLockNoteRecord> {
        self.shielded_lock_notes
            .get(lock_note_id)
            .ok_or_else(|| format!("unknown shielded lock note {lock_note_id}"))
    }

    fn require_attestation(
        &self,
        attestation_id: &str,
    ) -> MoneroL2PrivateAtomicSwapEscrowRuntimeResult<&PqAdaptorAttestationRecord> {
        self.pq_adaptor_attestations
            .get(attestation_id)
            .ok_or_else(|| format!("unknown pq adaptor attestation {attestation_id}"))
    }

    fn require_reservation(
        &self,
        reservation_id: &str,
    ) -> MoneroL2PrivateAtomicSwapEscrowRuntimeResult<&LowFeeSwapReservationRecord> {
        self.low_fee_reservations
            .get(reservation_id)
            .ok_or_else(|| format!("unknown low fee reservation {reservation_id}"))
    }

    fn require_subject(
        &self,
        kind: DisputeSubjectKind,
        subject_id: &str,
    ) -> MoneroL2PrivateAtomicSwapEscrowRuntimeResult<()> {
        match kind {
            DisputeSubjectKind::SwapOffer => self.require_offer(subject_id).map(|_| ()),
            DisputeSubjectKind::LockNote => self.require_lock_note(subject_id).map(|_| ()),
            DisputeSubjectKind::PqAdaptorAttestation => {
                self.require_attestation(subject_id).map(|_| ())
            }
            DisputeSubjectKind::LowFeeReservation => {
                self.require_reservation(subject_id).map(|_| ())
            }
            DisputeSubjectKind::SettlementBatch => self
                .private_settlement_batches
                .get(subject_id)
                .ok_or_else(|| format!("unknown private settlement batch {subject_id}"))
                .map(|_| ()),
        }
    }

    fn mark_subject_disputed(&mut self, kind: DisputeSubjectKind, subject_id: &str) {
        match kind {
            DisputeSubjectKind::SwapOffer => {
                if let Some(record) = self.swap_offers.get_mut(subject_id) {
                    record.status = SwapOfferStatus::Disputed;
                }
            }
            DisputeSubjectKind::LockNote => {
                if let Some(record) = self.shielded_lock_notes.get_mut(subject_id) {
                    record.status = LockNoteStatus::Disputed;
                }
            }
            DisputeSubjectKind::PqAdaptorAttestation => {
                if let Some(record) = self.pq_adaptor_attestations.get_mut(subject_id) {
                    record.status = PqAdaptorAttestationStatus::Disputed;
                }
            }
            DisputeSubjectKind::LowFeeReservation => {
                if let Some(record) = self.low_fee_reservations.get_mut(subject_id) {
                    record.status = ReservationStatus::Slashed;
                }
            }
            DisputeSubjectKind::SettlementBatch => {
                if let Some(record) = self.private_settlement_batches.get_mut(subject_id) {
                    record.status = SettlementBatchStatus::Disputed;
                }
            }
        }
    }

    fn subject_public_record(&self, kind: DisputeSubjectKind, subject_id: &str) -> Option<Value> {
        match kind {
            DisputeSubjectKind::SwapOffer => self
                .swap_offers
                .get(subject_id)
                .map(SwapOfferRecord::public_record),
            DisputeSubjectKind::LockNote => self
                .shielded_lock_notes
                .get(subject_id)
                .map(ShieldedLockNoteRecord::public_record),
            DisputeSubjectKind::PqAdaptorAttestation => self
                .pq_adaptor_attestations
                .get(subject_id)
                .map(PqAdaptorAttestationRecord::public_record),
            DisputeSubjectKind::LowFeeReservation => self
                .low_fee_reservations
                .get(subject_id)
                .map(LowFeeSwapReservationRecord::public_record),
            DisputeSubjectKind::SettlementBatch => self
                .private_settlement_batches
                .get(subject_id)
                .map(PrivateSettlementBatchRecord::public_record),
        }
    }

    fn refresh_public_records_for_batch(
        &mut self,
        request: &BuildPrivateSettlementBatchRequest,
    ) -> MoneroL2PrivateAtomicSwapEscrowRuntimeResult<()> {
        for offer_id in &request.offer_ids {
            if let Some(record) = self
                .swap_offers
                .get(offer_id)
                .map(SwapOfferRecord::public_record)
            {
                self.record_public(format!("offer:{offer_id}"), record)?;
            }
        }
        for note_id in &request.lock_note_ids {
            if let Some(record) = self
                .shielded_lock_notes
                .get(note_id)
                .map(ShieldedLockNoteRecord::public_record)
            {
                self.record_public(format!("lock_note:{note_id}"), record)?;
            }
        }
        for attestation_id in &request.attestation_ids {
            if let Some(record) = self
                .pq_adaptor_attestations
                .get(attestation_id)
                .map(PqAdaptorAttestationRecord::public_record)
            {
                self.record_public(format!("adaptor_attestation:{attestation_id}"), record)?;
            }
        }
        for reservation_id in &request.reservation_ids {
            if let Some(record) = self
                .low_fee_reservations
                .get(reservation_id)
                .map(LowFeeSwapReservationRecord::public_record)
            {
                self.record_public(format!("low_fee_reservation:{reservation_id}"), record)?;
            }
        }
        Ok(())
    }
}

pub type Runtime = State;

pub fn devnet() -> MoneroL2PrivateAtomicSwapEscrowRuntimeResult<State> {
    State::devnet()
}

pub fn monero_l2_private_atomic_swap_escrow_runtime_devnet(
) -> MoneroL2PrivateAtomicSwapEscrowRuntimeResult<State> {
    State::devnet()
}

pub fn monero_l2_private_atomic_swap_escrow_runtime_state_root(state: &State) -> String {
    state.state_root()
}

pub fn monero_l2_private_atomic_swap_escrow_runtime_public_record(state: &State) -> Value {
    state.public_record()
}

pub fn private_atomic_swap_offer_id(request: &CreateSwapOfferRequest, sequence: u64) -> String {
    domain_hash(
        "MONERO-L2-PRIVATE-ATOMIC-SWAP-ESCROW-OFFER-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Int(sequence as i128),
            HashPart::Str(&request.maker_commitment),
            HashPart::Str(request.direction.as_str()),
            HashPart::Str(&request.base_asset_id),
            HashPart::Str(&request.quote_asset_id),
            HashPart::Str(&request.amount_commitment_root),
            HashPart::Str(&request.price_commitment_root),
            HashPart::Str(&request.offer_nonce),
        ],
        32,
    )
}

pub fn shielded_atomic_swap_lock_note_id(
    request: &SubmitShieldedLockNoteRequest,
    sequence: u64,
) -> String {
    domain_hash(
        "MONERO-L2-PRIVATE-ATOMIC-SWAP-ESCROW-LOCK-NOTE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Int(sequence as i128),
            HashPart::Str(&request.offer_id),
            HashPart::Str(request.locker_role.as_str()),
            HashPart::Str(&request.owner_commitment),
            HashPart::Str(&request.note_commitment_root),
            HashPart::Str(&request.nullifier_root),
            HashPart::Str(&request.note_nonce),
        ],
        32,
    )
}

pub fn pq_adaptor_attestation_id(request: &AttestPqAdaptorRequest, sequence: u64) -> String {
    domain_hash(
        "MONERO-L2-PRIVATE-ATOMIC-SWAP-ESCROW-PQ-ADAPTOR-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Int(sequence as i128),
            HashPart::Str(&request.offer_id),
            HashPart::Str(request.maker_note_id.as_deref().unwrap_or("")),
            HashPart::Str(request.taker_note_id.as_deref().unwrap_or("")),
            HashPart::Str(&request.attester_commitment),
            HashPart::Str(&request.adaptor_public_key_root),
            HashPart::Str(&request.pq_transcript_root),
            HashPart::Str(&request.attestation_nonce),
        ],
        32,
    )
}

pub fn low_fee_atomic_swap_reservation_id(
    request: &ReserveLowFeeSwapRequest,
    sequence: u64,
) -> String {
    domain_hash(
        "MONERO-L2-PRIVATE-ATOMIC-SWAP-ESCROW-LOW-FEE-RESERVATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Int(sequence as i128),
            HashPart::Str(&request.offer_id),
            HashPart::Str(request.reserver_role.as_str()),
            HashPart::Str(&request.sponsor_commitment),
            HashPart::Str(&request.fee_asset_id),
            HashPart::Str(&request.reservation_budget_root),
            HashPart::Str(&request.reservation_nonce),
        ],
        32,
    )
}

pub fn private_atomic_swap_settlement_batch_id(
    request: &BuildPrivateSettlementBatchRequest,
    sequence: u64,
) -> String {
    domain_hash(
        "MONERO-L2-PRIVATE-ATOMIC-SWAP-ESCROW-SETTLEMENT-BATCH-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Int(sequence as i128),
            HashPart::Str(&request.coordinator_commitment),
            HashPart::Str(&id_list_root("offers", &request.offer_ids)),
            HashPart::Str(&id_list_root("lock-notes", &request.lock_note_ids)),
            HashPart::Str(&request.netted_swap_root),
            HashPart::Str(&request.monero_settlement_root),
            HashPart::Str(&request.batch_nonce),
        ],
        32,
    )
}

pub fn private_atomic_swap_dispute_receipt_id(
    request: &FileDisputeReceiptRequest,
    sequence: u64,
) -> String {
    domain_hash(
        "MONERO-L2-PRIVATE-ATOMIC-SWAP-ESCROW-DISPUTE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Int(sequence as i128),
            HashPart::Str(request.subject_kind.as_str()),
            HashPart::Str(&request.subject_id),
            HashPart::Str(&request.challenger_commitment),
            HashPart::Str(request.kind.as_str()),
            HashPart::Str(&request.evidence_root),
            HashPart::Str(&request.dispute_nonce),
        ],
        32,
    )
}

pub fn public_record_root(domain: &str, records: &[Value]) -> String {
    merkle_root(domain, records)
}

pub fn state_root_from_record(record: &Value) -> String {
    root_from_record("MONERO-L2-PRIVATE-ATOMIC-SWAP-ESCROW-STATE", record)
}

pub fn root_from_record(domain: &str, record: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Json(record),
        ],
        32,
    )
}

pub fn payload_root(domain: &str, payload: &Value) -> String {
    root_from_record(domain, payload)
}

fn map_root<T, F>(domain: &str, map: &BTreeMap<String, T>, public_record: F) -> String
where
    F: Fn(&T) -> Value,
{
    let records = map
        .iter()
        .map(|(key, value)| json!({ "key": key, "record": public_record(value) }))
        .collect::<Vec<_>>();
    public_record_root(domain, &records)
}

fn map_value_root(domain: &str, map: &BTreeMap<String, Value>) -> String {
    let records = map
        .iter()
        .map(|(key, value)| json!({ "key": key, "record": value }))
        .collect::<Vec<_>>();
    public_record_root(domain, &records)
}

fn set_root(domain: &str, set: &BTreeSet<String>) -> String {
    let records = set.iter().map(|value| json!(value)).collect::<Vec<_>>();
    public_record_root(domain, &records)
}

fn id_list_root(domain: &str, ids: &[String]) -> String {
    let records = ids.iter().map(|id| json!({ "id": id })).collect::<Vec<_>>();
    public_record_root(
        &format!("MONERO-L2-PRIVATE-ATOMIC-SWAP-ESCROW-ID-LIST-{domain}"),
        &records,
    )
}

fn subject_public_key(kind: DisputeSubjectKind, subject_id: &str) -> String {
    let prefix = match kind {
        DisputeSubjectKind::SwapOffer => "offer",
        DisputeSubjectKind::LockNote => "lock_note",
        DisputeSubjectKind::PqAdaptorAttestation => "adaptor_attestation",
        DisputeSubjectKind::LowFeeReservation => "low_fee_reservation",
        DisputeSubjectKind::SettlementBatch => "private_settlement_batch",
    };
    format!("{prefix}:{subject_id}")
}

fn ensure_capacity(
    current: usize,
    max: usize,
    label: &str,
) -> MoneroL2PrivateAtomicSwapEscrowRuntimeResult<()> {
    require(current < max, &format!("{label} capacity exhausted"))
}

fn require_min_privacy(
    config: &Config,
    privacy_set_size: usize,
) -> MoneroL2PrivateAtomicSwapEscrowRuntimeResult<()> {
    require(
        privacy_set_size >= config.min_privacy_set_size,
        "privacy set below runtime minimum",
    )
}

fn require_non_empty_vec(
    field: &str,
    values: &[String],
) -> MoneroL2PrivateAtomicSwapEscrowRuntimeResult<()> {
    require(!values.is_empty(), &format!("{field} cannot be empty"))?;
    for value in values {
        require_non_empty(field, value)?;
    }
    Ok(())
}

fn require_unique(
    field: &str,
    values: &[String],
) -> MoneroL2PrivateAtomicSwapEscrowRuntimeResult<()> {
    let mut seen = BTreeSet::new();
    for value in values {
        require_non_empty(field, value)?;
        if !seen.insert(value) {
            return Err(format!("{field} contains duplicate value {value}"));
        }
    }
    Ok(())
}

fn require_root(field: &str, value: &str) -> MoneroL2PrivateAtomicSwapEscrowRuntimeResult<()> {
    require_non_empty(field, value)?;
    require(value.len() >= 16, &format!("{field} must look like a root"))
}

fn require_non_empty(field: &str, value: &str) -> MoneroL2PrivateAtomicSwapEscrowRuntimeResult<()> {
    require(
        !value.trim().is_empty(),
        &format!("{field} cannot be empty"),
    )
}

fn require_positive_usize(
    field: &str,
    value: usize,
) -> MoneroL2PrivateAtomicSwapEscrowRuntimeResult<()> {
    require(value > 0, &format!("{field} must be positive"))
}

fn require_bps(field: &str, value: u64) -> MoneroL2PrivateAtomicSwapEscrowRuntimeResult<()> {
    require(
        value <= MONERO_L2_PRIVATE_ATOMIC_SWAP_ESCROW_RUNTIME_MAX_BPS,
        &format!("{field} exceeds basis point maximum"),
    )
}

fn require(condition: bool, message: &str) -> MoneroL2PrivateAtomicSwapEscrowRuntimeResult<()> {
    if condition {
        Ok(())
    } else {
        Err(message.to_string())
    }
}

fn set_json_field(record: &mut Value, key: &str, value: Value) {
    if let Value::Object(fields) = record {
        fields.insert(key.to_string(), value);
    }
}
