use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type MoneroL2PrivateDepositNoteMintRuntimeResult<T> = Result<T, String>;

pub const MONERO_L2_PRIVATE_DEPOSIT_NOTE_MINT_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-private-deposit-note-mint-runtime-v1";
pub const PROTOCOL_VERSION: &str = MONERO_L2_PRIVATE_DEPOSIT_NOTE_MINT_RUNTIME_PROTOCOL_VERSION;
pub const MONERO_L2_PRIVATE_DEPOSIT_NOTE_MINT_RUNTIME_SCHEMA_VERSION: u64 = 1;
pub const MONERO_L2_PRIVATE_DEPOSIT_NOTE_MINT_RUNTIME_HASH_SUITE: &str =
    "SHAKE256-domain-separated-canonical-json";
pub const MONERO_L2_PRIVATE_DEPOSIT_NOTE_MINT_RUNTIME_PQ_AUTH_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-deposit-auth-v1";
pub const MONERO_L2_PRIVATE_DEPOSIT_NOTE_MINT_RUNTIME_NOTE_SCHEME: &str =
    "monero-l2-private-deposit-note-commitment-v1";
pub const MONERO_L2_PRIVATE_DEPOSIT_NOTE_MINT_RUNTIME_RESERVE_SCHEME: &str =
    "roots-only-monero-reserve-and-view-key-privacy-v1";
pub const MONERO_L2_PRIVATE_DEPOSIT_NOTE_MINT_RUNTIME_RECEIPT_SCHEME: &str =
    "fast-entry-private-deposit-receipt-root-v1";
pub const MONERO_L2_PRIVATE_DEPOSIT_NOTE_MINT_RUNTIME_SPONSOR_SCHEME: &str =
    "low-fee-sponsored-private-deposit-note-mint-v1";
pub const MONERO_L2_PRIVATE_DEPOSIT_NOTE_MINT_RUNTIME_NULLIFIER_SCHEME: &str =
    "monero-l2-private-deposit-nullifier-replay-fence-v1";
pub const MONERO_L2_PRIVATE_DEPOSIT_NOTE_MINT_RUNTIME_REPLAY_DOMAIN: &str =
    "monero-l2-private-deposit-note-mint-devnet";
pub const MONERO_L2_PRIVATE_DEPOSIT_NOTE_MINT_RUNTIME_DEVNET_HEIGHT: u64 = 312_000;
pub const MONERO_L2_PRIVATE_DEPOSIT_NOTE_MINT_RUNTIME_DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const MONERO_L2_PRIVATE_DEPOSIT_NOTE_MINT_RUNTIME_DEVNET_L2_NETWORK: &str = "nebula-devnet";
pub const MONERO_L2_PRIVATE_DEPOSIT_NOTE_MINT_RUNTIME_DEVNET_ASSET_ID: &str = "wxmr-devnet";
pub const MONERO_L2_PRIVATE_DEPOSIT_NOTE_MINT_RUNTIME_DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const MONERO_L2_PRIVATE_DEPOSIT_NOTE_MINT_RUNTIME_MAX_BPS: u64 = 10_000;
pub const MONERO_L2_PRIVATE_DEPOSIT_NOTE_MINT_RUNTIME_DEFAULT_WINDOW_TTL_BLOCKS: u64 = 720;
pub const MONERO_L2_PRIVATE_DEPOSIT_NOTE_MINT_RUNTIME_DEFAULT_FAST_RECEIPT_TTL_BLOCKS: u64 = 18;
pub const MONERO_L2_PRIVATE_DEPOSIT_NOTE_MINT_RUNTIME_DEFAULT_SETTLEMENT_TTL_BLOCKS: u64 = 144;
pub const MONERO_L2_PRIVATE_DEPOSIT_NOTE_MINT_RUNTIME_DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 16_384;
pub const MONERO_L2_PRIVATE_DEPOSIT_NOTE_MINT_RUNTIME_DEFAULT_BATCH_PRIVACY_SET_SIZE: u64 = 65_536;
pub const MONERO_L2_PRIVATE_DEPOSIT_NOTE_MINT_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const MONERO_L2_PRIVATE_DEPOSIT_NOTE_MINT_RUNTIME_DEFAULT_MIN_RESERVE_PROOF_BPS: u64 = 10_250;
pub const MONERO_L2_PRIVATE_DEPOSIT_NOTE_MINT_RUNTIME_DEFAULT_TARGET_RESERVE_PROOF_BPS: u64 =
    12_000;
pub const MONERO_L2_PRIVATE_DEPOSIT_NOTE_MINT_RUNTIME_DEFAULT_MAX_USER_FEE_BPS: u64 = 24;
pub const MONERO_L2_PRIVATE_DEPOSIT_NOTE_MINT_RUNTIME_DEFAULT_LOW_FEE_BPS: u64 = 4;
pub const MONERO_L2_PRIVATE_DEPOSIT_NOTE_MINT_RUNTIME_DEFAULT_SPONSOR_COVER_BPS: u64 = 9_000;
pub const MONERO_L2_PRIVATE_DEPOSIT_NOTE_MINT_RUNTIME_MAX_WINDOWS: usize = 131_072;
pub const MONERO_L2_PRIVATE_DEPOSIT_NOTE_MINT_RUNTIME_MAX_DEPOSITS: usize = 1_048_576;
pub const MONERO_L2_PRIVATE_DEPOSIT_NOTE_MINT_RUNTIME_MAX_ATTESTATIONS: usize = 1_048_576;
pub const MONERO_L2_PRIVATE_DEPOSIT_NOTE_MINT_RUNTIME_MAX_NOTES: usize = 1_048_576;
pub const MONERO_L2_PRIVATE_DEPOSIT_NOTE_MINT_RUNTIME_MAX_RECEIPTS: usize = 1_048_576;
pub const MONERO_L2_PRIVATE_DEPOSIT_NOTE_MINT_RUNTIME_MAX_BATCHES: usize = 262_144;
pub const MONERO_L2_PRIVATE_DEPOSIT_NOTE_MINT_RUNTIME_MAX_PUBLIC_RECORDS: usize = 2_097_152;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DepositWindowStatus {
    Open,
    Paused,
    Closing,
    Closed,
    Settled,
}

impl DepositWindowStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Paused => "paused",
            Self::Closing => "closing",
            Self::Closed => "closed",
            Self::Settled => "settled",
        }
    }

    pub fn accepts_deposits(self) -> bool {
        matches!(self, Self::Open | Self::Closing)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DepositPriority {
    SponsoredLowFee,
    Standard,
    FastEntry,
    DefiEntry,
    Emergency,
}

impl DepositPriority {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SponsoredLowFee => "sponsored_low_fee",
            Self::Standard => "standard",
            Self::FastEntry => "fast_entry",
            Self::DefiEntry => "defi_entry",
            Self::Emergency => "emergency",
        }
    }

    pub fn weight(self) -> u64 {
        match self {
            Self::Emergency => 10_000,
            Self::FastEntry => 9_300,
            Self::DefiEntry => 8_600,
            Self::SponsoredLowFee => 8_200,
            Self::Standard => 6_000,
        }
    }

    pub fn user_fee_bps(self, config: &Config) -> u64 {
        match self {
            Self::SponsoredLowFee => config.low_fee_bps,
            Self::Standard => config.max_user_fee_bps.saturating_mul(2) / 3,
            Self::FastEntry | Self::Emergency => config.max_user_fee_bps,
            Self::DefiEntry => config.max_user_fee_bps.saturating_mul(3) / 4,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorPolicy {
    None,
    LowFeeOnly,
    FullUserFee,
    EmergencySubsidy,
}

impl SponsorPolicy {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::LowFeeOnly => "low_fee_only",
            Self::FullUserFee => "full_user_fee",
            Self::EmergencySubsidy => "emergency_subsidy",
        }
    }

    pub fn sponsored(self) -> bool {
        !matches!(self, Self::None)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqAuthorizationStatus {
    Submitted,
    Accepted,
    Replayed,
    Revoked,
    Expired,
}

impl PqAuthorizationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Accepted => "accepted",
            Self::Replayed => "replayed",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
        }
    }

    pub fn usable(self) -> bool {
        matches!(self, Self::Submitted | Self::Accepted)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DepositRequestStatus {
    Submitted,
    ReserveAttested,
    NoteMinted,
    FastEntryReceipted,
    Batched,
    Settled,
    Rejected,
    Expired,
}

impl DepositRequestStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::ReserveAttested => "reserve_attested",
            Self::NoteMinted => "note_minted",
            Self::FastEntryReceipted => "fast_entry_receipted",
            Self::Batched => "batched",
            Self::Settled => "settled",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }

    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Submitted
                | Self::ReserveAttested
                | Self::NoteMinted
                | Self::FastEntryReceipted
                | Self::Batched
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReserveAttestationStatus {
    Pending,
    Accepted,
    Superseded,
    Challenged,
    Rejected,
}

impl ReserveAttestationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Accepted => "accepted",
            Self::Superseded => "superseded",
            Self::Challenged => "challenged",
            Self::Rejected => "rejected",
        }
    }

    pub fn acceptable(self) -> bool {
        matches!(self, Self::Pending | Self::Accepted)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DepositNoteStatus {
    Minted,
    FastEntryReceipted,
    Batched,
    Settled,
    Cancelled,
    Slashed,
}

impl DepositNoteStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Minted => "minted",
            Self::FastEntryReceipted => "fast_entry_receipted",
            Self::Batched => "batched",
            Self::Settled => "settled",
            Self::Cancelled => "cancelled",
            Self::Slashed => "slashed",
        }
    }

    pub fn settlement_eligible(self) -> bool {
        matches!(self, Self::Minted | Self::FastEntryReceipted)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FastEntryReceiptStatus {
    Issued,
    Accepted,
    Finalized,
    Expired,
    Replayed,
}

impl FastEntryReceiptStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Issued => "issued",
            Self::Accepted => "accepted",
            Self::Finalized => "finalized",
            Self::Expired => "expired",
            Self::Replayed => "replayed",
        }
    }

    pub fn live(self) -> bool {
        matches!(self, Self::Issued | Self::Accepted)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DepositBatchStatus {
    Open,
    Proved,
    Submitted,
    Settled,
    Rejected,
}

impl DepositBatchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Proved => "proved",
            Self::Submitted => "submitted",
            Self::Settled => "settled",
            Self::Rejected => "rejected",
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
    pub asset_id: String,
    pub fee_asset_id: String,
    pub hash_suite: String,
    pub pq_authorization_suite: String,
    pub note_scheme: String,
    pub reserve_scheme: String,
    pub receipt_scheme: String,
    pub sponsor_scheme: String,
    pub nullifier_scheme: String,
    pub replay_domain: String,
    pub window_ttl_blocks: u64,
    pub fast_receipt_ttl_blocks: u64,
    pub settlement_ttl_blocks: u64,
    pub min_privacy_set_size: u64,
    pub batch_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub min_reserve_proof_bps: u64,
    pub target_reserve_proof_bps: u64,
    pub max_user_fee_bps: u64,
    pub low_fee_bps: u64,
    pub sponsor_cover_bps: u64,
    pub max_windows: usize,
    pub max_deposits: usize,
    pub max_attestations: usize,
    pub max_notes: usize,
    pub max_receipts: usize,
    pub max_batches: usize,
    pub max_public_records: usize,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: MONERO_L2_PRIVATE_DEPOSIT_NOTE_MINT_RUNTIME_SCHEMA_VERSION,
            chain_id: CHAIN_ID.to_string(),
            monero_network: MONERO_L2_PRIVATE_DEPOSIT_NOTE_MINT_RUNTIME_DEVNET_MONERO_NETWORK
                .to_string(),
            l2_network: MONERO_L2_PRIVATE_DEPOSIT_NOTE_MINT_RUNTIME_DEVNET_L2_NETWORK.to_string(),
            asset_id: MONERO_L2_PRIVATE_DEPOSIT_NOTE_MINT_RUNTIME_DEVNET_ASSET_ID.to_string(),
            fee_asset_id: MONERO_L2_PRIVATE_DEPOSIT_NOTE_MINT_RUNTIME_DEVNET_FEE_ASSET_ID
                .to_string(),
            hash_suite: MONERO_L2_PRIVATE_DEPOSIT_NOTE_MINT_RUNTIME_HASH_SUITE.to_string(),
            pq_authorization_suite: MONERO_L2_PRIVATE_DEPOSIT_NOTE_MINT_RUNTIME_PQ_AUTH_SUITE
                .to_string(),
            note_scheme: MONERO_L2_PRIVATE_DEPOSIT_NOTE_MINT_RUNTIME_NOTE_SCHEME.to_string(),
            reserve_scheme: MONERO_L2_PRIVATE_DEPOSIT_NOTE_MINT_RUNTIME_RESERVE_SCHEME.to_string(),
            receipt_scheme: MONERO_L2_PRIVATE_DEPOSIT_NOTE_MINT_RUNTIME_RECEIPT_SCHEME.to_string(),
            sponsor_scheme: MONERO_L2_PRIVATE_DEPOSIT_NOTE_MINT_RUNTIME_SPONSOR_SCHEME.to_string(),
            nullifier_scheme: MONERO_L2_PRIVATE_DEPOSIT_NOTE_MINT_RUNTIME_NULLIFIER_SCHEME
                .to_string(),
            replay_domain: MONERO_L2_PRIVATE_DEPOSIT_NOTE_MINT_RUNTIME_REPLAY_DOMAIN.to_string(),
            window_ttl_blocks:
                MONERO_L2_PRIVATE_DEPOSIT_NOTE_MINT_RUNTIME_DEFAULT_WINDOW_TTL_BLOCKS,
            fast_receipt_ttl_blocks:
                MONERO_L2_PRIVATE_DEPOSIT_NOTE_MINT_RUNTIME_DEFAULT_FAST_RECEIPT_TTL_BLOCKS,
            settlement_ttl_blocks:
                MONERO_L2_PRIVATE_DEPOSIT_NOTE_MINT_RUNTIME_DEFAULT_SETTLEMENT_TTL_BLOCKS,
            min_privacy_set_size:
                MONERO_L2_PRIVATE_DEPOSIT_NOTE_MINT_RUNTIME_DEFAULT_MIN_PRIVACY_SET_SIZE,
            batch_privacy_set_size:
                MONERO_L2_PRIVATE_DEPOSIT_NOTE_MINT_RUNTIME_DEFAULT_BATCH_PRIVACY_SET_SIZE,
            min_pq_security_bits:
                MONERO_L2_PRIVATE_DEPOSIT_NOTE_MINT_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS,
            min_reserve_proof_bps:
                MONERO_L2_PRIVATE_DEPOSIT_NOTE_MINT_RUNTIME_DEFAULT_MIN_RESERVE_PROOF_BPS,
            target_reserve_proof_bps:
                MONERO_L2_PRIVATE_DEPOSIT_NOTE_MINT_RUNTIME_DEFAULT_TARGET_RESERVE_PROOF_BPS,
            max_user_fee_bps: MONERO_L2_PRIVATE_DEPOSIT_NOTE_MINT_RUNTIME_DEFAULT_MAX_USER_FEE_BPS,
            low_fee_bps: MONERO_L2_PRIVATE_DEPOSIT_NOTE_MINT_RUNTIME_DEFAULT_LOW_FEE_BPS,
            sponsor_cover_bps:
                MONERO_L2_PRIVATE_DEPOSIT_NOTE_MINT_RUNTIME_DEFAULT_SPONSOR_COVER_BPS,
            max_windows: MONERO_L2_PRIVATE_DEPOSIT_NOTE_MINT_RUNTIME_MAX_WINDOWS,
            max_deposits: MONERO_L2_PRIVATE_DEPOSIT_NOTE_MINT_RUNTIME_MAX_DEPOSITS,
            max_attestations: MONERO_L2_PRIVATE_DEPOSIT_NOTE_MINT_RUNTIME_MAX_ATTESTATIONS,
            max_notes: MONERO_L2_PRIVATE_DEPOSIT_NOTE_MINT_RUNTIME_MAX_NOTES,
            max_receipts: MONERO_L2_PRIVATE_DEPOSIT_NOTE_MINT_RUNTIME_MAX_RECEIPTS,
            max_batches: MONERO_L2_PRIVATE_DEPOSIT_NOTE_MINT_RUNTIME_MAX_BATCHES,
            max_public_records: MONERO_L2_PRIVATE_DEPOSIT_NOTE_MINT_RUNTIME_MAX_PUBLIC_RECORDS,
        }
    }

    pub fn validate(&self) -> MoneroL2PrivateDepositNoteMintRuntimeResult<()> {
        require(
            self.protocol_version == PROTOCOL_VERSION,
            "protocol version mismatch",
        )?;
        require(self.schema_version == 1, "schema version mismatch")?;
        require(self.chain_id == CHAIN_ID, "config chain id mismatch")?;
        required("monero_network", &self.monero_network)?;
        required("l2_network", &self.l2_network)?;
        required("asset_id", &self.asset_id)?;
        required("fee_asset_id", &self.fee_asset_id)?;
        require(
            self.min_pq_security_bits
                >= MONERO_L2_PRIVATE_DEPOSIT_NOTE_MINT_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS,
            "minimum PQ security bits too low",
        )?;
        require(
            self.min_reserve_proof_bps >= MONERO_L2_PRIVATE_DEPOSIT_NOTE_MINT_RUNTIME_MAX_BPS,
            "reserve proof must cover deposits",
        )?;
        require(
            self.target_reserve_proof_bps >= self.min_reserve_proof_bps,
            "target reserve proof below minimum",
        )?;
        require(
            self.max_user_fee_bps <= MONERO_L2_PRIVATE_DEPOSIT_NOTE_MINT_RUNTIME_MAX_BPS,
            "max user fee bps too high",
        )?;
        require(
            self.low_fee_bps <= self.max_user_fee_bps,
            "low fee bps exceeds max user fee bps",
        )?;
        require(
            self.sponsor_cover_bps <= MONERO_L2_PRIVATE_DEPOSIT_NOTE_MINT_RUNTIME_MAX_BPS,
            "sponsor cover bps too high",
        )?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "chain_id": self.chain_id,
            "monero_network": self.monero_network,
            "l2_network": self.l2_network,
            "asset_id": self.asset_id,
            "fee_asset_id": self.fee_asset_id,
            "hash_suite": self.hash_suite,
            "pq_authorization_suite": self.pq_authorization_suite,
            "note_scheme": self.note_scheme,
            "reserve_scheme": self.reserve_scheme,
            "receipt_scheme": self.receipt_scheme,
            "sponsor_scheme": self.sponsor_scheme,
            "nullifier_scheme": self.nullifier_scheme,
            "replay_domain": self.replay_domain,
            "window_ttl_blocks": self.window_ttl_blocks,
            "fast_receipt_ttl_blocks": self.fast_receipt_ttl_blocks,
            "settlement_ttl_blocks": self.settlement_ttl_blocks,
            "min_privacy_set_size": self.min_privacy_set_size,
            "batch_privacy_set_size": self.batch_privacy_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
            "min_reserve_proof_bps": self.min_reserve_proof_bps,
            "target_reserve_proof_bps": self.target_reserve_proof_bps,
            "max_user_fee_bps": self.max_user_fee_bps,
            "low_fee_bps": self.low_fee_bps,
            "sponsor_cover_bps": self.sponsor_cover_bps,
            "max_windows": self.max_windows,
            "max_deposits": self.max_deposits,
            "max_attestations": self.max_attestations,
            "max_notes": self.max_notes,
            "max_receipts": self.max_receipts,
            "max_batches": self.max_batches,
            "max_public_records": self.max_public_records,
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "MONERO-L2-PRIVATE-DEPOSIT-NOTE-MINT-CONFIG",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    pub windows_registered: u64,
    pub private_deposits_submitted: u64,
    pub pq_authorizations_accepted: u64,
    pub reserve_attestations_accepted: u64,
    pub l2_deposit_notes_minted: u64,
    pub fast_entry_receipts_issued: u64,
    pub deposit_note_batches_settled: u64,
    pub replay_fences_consumed: u64,
    pub nullifiers_consumed: u64,
    pub sponsored_notes_minted: u64,
    pub total_private_amount: u128,
    pub total_public_fee: u128,
    pub total_sponsor_fee: u128,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "windows_registered": self.windows_registered,
            "private_deposits_submitted": self.private_deposits_submitted,
            "pq_authorizations_accepted": self.pq_authorizations_accepted,
            "reserve_attestations_accepted": self.reserve_attestations_accepted,
            "l2_deposit_notes_minted": self.l2_deposit_notes_minted,
            "fast_entry_receipts_issued": self.fast_entry_receipts_issued,
            "deposit_note_batches_settled": self.deposit_note_batches_settled,
            "replay_fences_consumed": self.replay_fences_consumed,
            "nullifiers_consumed": self.nullifiers_consumed,
            "sponsored_notes_minted": self.sponsored_notes_minted,
            "total_private_amount": self.total_private_amount.to_string(),
            "total_public_fee": self.total_public_fee.to_string(),
            "total_sponsor_fee": self.total_sponsor_fee.to_string(),
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "MONERO-L2-PRIVATE-DEPOSIT-NOTE-MINT-COUNTERS",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roots {
    pub config_root: String,
    pub counters_root: String,
    pub window_root: String,
    pub open_window_root: String,
    pub deposit_root: String,
    pub live_deposit_root: String,
    pub pq_authorization_root: String,
    pub reserve_attestation_root: String,
    pub note_root: String,
    pub unsettled_note_root: String,
    pub receipt_root: String,
    pub batch_root: String,
    pub consumed_nullifier_root: String,
    pub replay_fence_root: String,
    pub reserve_privacy_root: String,
    pub view_key_privacy_root: String,
    pub sponsor_root: String,
    pub event_root: String,
}

impl Roots {
    pub fn empty(config: &Config, counters: &Counters) -> Self {
        Self {
            config_root: config.state_root(),
            counters_root: counters.state_root(),
            window_root: merkle_root("MONERO-L2-PRIVATE-DEPOSIT-NOTE-MINT-WINDOWS", &[]),
            open_window_root: merkle_root("MONERO-L2-PRIVATE-DEPOSIT-NOTE-MINT-OPEN-WINDOWS", &[]),
            deposit_root: merkle_root("MONERO-L2-PRIVATE-DEPOSIT-NOTE-MINT-DEPOSITS", &[]),
            live_deposit_root: merkle_root(
                "MONERO-L2-PRIVATE-DEPOSIT-NOTE-MINT-LIVE-DEPOSITS",
                &[],
            ),
            pq_authorization_root: merkle_root(
                "MONERO-L2-PRIVATE-DEPOSIT-NOTE-MINT-PQ-AUTHORIZATIONS",
                &[],
            ),
            reserve_attestation_root: merkle_root(
                "MONERO-L2-PRIVATE-DEPOSIT-NOTE-MINT-RESERVE-ATTESTATIONS",
                &[],
            ),
            note_root: merkle_root("MONERO-L2-PRIVATE-DEPOSIT-NOTE-MINT-NOTES", &[]),
            unsettled_note_root: merkle_root(
                "MONERO-L2-PRIVATE-DEPOSIT-NOTE-MINT-UNSETTLED-NOTES",
                &[],
            ),
            receipt_root: merkle_root("MONERO-L2-PRIVATE-DEPOSIT-NOTE-MINT-RECEIPTS", &[]),
            batch_root: merkle_root("MONERO-L2-PRIVATE-DEPOSIT-NOTE-MINT-BATCHES", &[]),
            consumed_nullifier_root: merkle_root(
                "MONERO-L2-PRIVATE-DEPOSIT-NOTE-MINT-CONSUMED-NULLIFIERS",
                &[],
            ),
            replay_fence_root: merkle_root(
                "MONERO-L2-PRIVATE-DEPOSIT-NOTE-MINT-REPLAY-FENCES",
                &[],
            ),
            reserve_privacy_root: merkle_root(
                "MONERO-L2-PRIVATE-DEPOSIT-NOTE-MINT-RESERVE-PRIVACY-ROOTS",
                &[],
            ),
            view_key_privacy_root: merkle_root(
                "MONERO-L2-PRIVATE-DEPOSIT-NOTE-MINT-VIEW-KEY-PRIVACY-ROOTS",
                &[],
            ),
            sponsor_root: merkle_root("MONERO-L2-PRIVATE-DEPOSIT-NOTE-MINT-SPONSORS", &[]),
            event_root: merkle_root("MONERO-L2-PRIVATE-DEPOSIT-NOTE-MINT-EVENTS", &[]),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "counters_root": self.counters_root,
            "window_root": self.window_root,
            "open_window_root": self.open_window_root,
            "deposit_root": self.deposit_root,
            "live_deposit_root": self.live_deposit_root,
            "pq_authorization_root": self.pq_authorization_root,
            "reserve_attestation_root": self.reserve_attestation_root,
            "note_root": self.note_root,
            "unsettled_note_root": self.unsettled_note_root,
            "receipt_root": self.receipt_root,
            "batch_root": self.batch_root,
            "consumed_nullifier_root": self.consumed_nullifier_root,
            "replay_fence_root": self.replay_fence_root,
            "reserve_privacy_root": self.reserve_privacy_root,
            "view_key_privacy_root": self.view_key_privacy_root,
            "sponsor_root": self.sponsor_root,
            "event_root": self.event_root,
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "MONERO-L2-PRIVATE-DEPOSIT-NOTE-MINT-ROOTS",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisterDepositWindowRequest {
    pub monero_window_id: String,
    pub coordinator_id: String,
    pub reserve_vault_commitment: String,
    pub reserve_privacy_root: String,
    pub view_key_privacy_root: String,
    pub pq_authorization_root: String,
    pub sponsor_pool_root: String,
    pub min_deposit_amount: u128,
    pub max_deposit_amount: u128,
    pub target_reserve_bps: u64,
    pub min_pq_security_bits: u16,
    pub opens_at_height: u64,
    pub closes_at_height: u64,
    pub low_fee_enabled: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubmitPrivateDepositRequest {
    pub window_id: String,
    pub monero_tx_commitment: String,
    pub monero_output_commitment: String,
    pub deposit_amount_commitment: String,
    pub encrypted_view_key_root: String,
    pub view_tag_root: String,
    pub reserve_hint_root: String,
    pub pq_authorization_root: String,
    pub pq_authorization_nullifier: String,
    pub deposit_nullifier: String,
    pub replay_fence: String,
    pub privacy_set_size: u64,
    pub amount: u128,
    pub priority: DepositPriority,
    pub sponsor_policy: SponsorPolicy,
    pub submitted_at_height: u64,
    pub pq_security_bits: u16,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestDepositReserveRequest {
    pub deposit_id: String,
    pub reserve_attestor_id: String,
    pub reserve_snapshot_root: String,
    pub reserve_liability_root: String,
    pub view_key_privacy_root: String,
    pub reserve_privacy_root: String,
    pub reserve_coverage_bps: u64,
    pub attested_amount: u128,
    pub attested_at_height: u64,
    pub pq_attestation_root: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MintL2DepositNoteRequest {
    pub deposit_id: String,
    pub minter_id: String,
    pub note_commitment: String,
    pub note_asset_id: String,
    pub note_owner_root: String,
    pub note_view_key_root: String,
    pub note_entropy_root: String,
    pub low_fee_sponsor_root: String,
    pub sponsor_receipt_root: String,
    pub mint_proof_root: String,
    pub user_fee_bps: u64,
    pub sponsor_fee_bps: u64,
    pub minted_at_height: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IssueFastEntryReceiptRequest {
    pub note_id: String,
    pub receipt_issuer_id: String,
    pub fast_entry_root: String,
    pub availability_root: String,
    pub preconfirmation_root: String,
    pub receipt_nullifier: String,
    pub replay_fence: String,
    pub fee_bps: u64,
    pub issued_at_height: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettleDepositNoteBatchRequest {
    pub batch_coordinator_id: String,
    pub note_ids: Vec<String>,
    pub receipt_ids: Vec<String>,
    pub settlement_root: String,
    pub recursive_proof_root: String,
    pub monero_anchor_root: String,
    pub reserve_snapshot_root: String,
    pub view_key_privacy_root: String,
    pub pq_aggregate_authorization_root: String,
    pub replay_fence: String,
    pub privacy_set_size: u64,
    pub settled_at_height: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DepositWindowRecord {
    pub window_id: String,
    pub monero_window_id: String,
    pub coordinator_id: String,
    pub reserve_vault_commitment: String,
    pub reserve_privacy_root: String,
    pub view_key_privacy_root: String,
    pub pq_authorization_root: String,
    pub sponsor_pool_root: String,
    pub min_deposit_amount: u128,
    pub max_deposit_amount: u128,
    pub target_reserve_bps: u64,
    pub min_pq_security_bits: u16,
    pub opens_at_height: u64,
    pub closes_at_height: u64,
    pub low_fee_enabled: bool,
    pub status: DepositWindowStatus,
}

impl DepositWindowRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "window_id": self.window_id,
            "monero_window_id": self.monero_window_id,
            "coordinator_id": self.coordinator_id,
            "reserve_vault_commitment": self.reserve_vault_commitment,
            "reserve_privacy_root": self.reserve_privacy_root,
            "view_key_privacy_root": self.view_key_privacy_root,
            "pq_authorization_root": self.pq_authorization_root,
            "sponsor_pool_root": self.sponsor_pool_root,
            "min_deposit_amount": self.min_deposit_amount.to_string(),
            "max_deposit_amount": self.max_deposit_amount.to_string(),
            "target_reserve_bps": self.target_reserve_bps,
            "min_pq_security_bits": self.min_pq_security_bits,
            "opens_at_height": self.opens_at_height,
            "closes_at_height": self.closes_at_height,
            "low_fee_enabled": self.low_fee_enabled,
            "status": self.status.as_str(),
        })
    }

    pub fn state_root(&self) -> String {
        record_hash(
            "MONERO-L2-PRIVATE-DEPOSIT-NOTE-MINT-WINDOW",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqDepositAuthorizationRecord {
    pub authorization_id: String,
    pub deposit_id: String,
    pub window_id: String,
    pub pq_authorization_root: String,
    pub pq_authorization_nullifier: String,
    pub replay_fence: String,
    pub pq_security_bits: u16,
    pub status: PqAuthorizationStatus,
}

impl PqDepositAuthorizationRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "authorization_id": self.authorization_id,
            "deposit_id": self.deposit_id,
            "window_id": self.window_id,
            "pq_authorization_root": self.pq_authorization_root,
            "pq_authorization_nullifier": self.pq_authorization_nullifier,
            "replay_fence": self.replay_fence,
            "pq_security_bits": self.pq_security_bits,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateDepositRecord {
    pub deposit_id: String,
    pub window_id: String,
    pub monero_tx_commitment: String,
    pub monero_output_commitment: String,
    pub deposit_amount_commitment: String,
    pub encrypted_view_key_root: String,
    pub view_tag_root: String,
    pub reserve_hint_root: String,
    pub pq_authorization_root: String,
    pub authorization_id: String,
    pub deposit_nullifier: String,
    pub replay_fence: String,
    pub privacy_set_size: u64,
    pub amount: u128,
    pub priority: DepositPriority,
    pub sponsor_policy: SponsorPolicy,
    pub submitted_at_height: u64,
    pub pq_security_bits: u16,
    pub status: DepositRequestStatus,
    pub reserve_attestation_id: Option<String>,
    pub note_id: Option<String>,
    pub receipt_id: Option<String>,
    pub batch_id: Option<String>,
}

impl PrivateDepositRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "deposit_id": self.deposit_id,
            "window_id": self.window_id,
            "monero_tx_commitment": self.monero_tx_commitment,
            "monero_output_commitment": self.monero_output_commitment,
            "deposit_amount_commitment": self.deposit_amount_commitment,
            "encrypted_view_key_root": self.encrypted_view_key_root,
            "view_tag_root": self.view_tag_root,
            "reserve_hint_root": self.reserve_hint_root,
            "pq_authorization_root": self.pq_authorization_root,
            "authorization_id": self.authorization_id,
            "deposit_nullifier": self.deposit_nullifier,
            "replay_fence": self.replay_fence,
            "privacy_set_size": self.privacy_set_size,
            "amount": self.amount.to_string(),
            "priority": self.priority.as_str(),
            "priority_weight": self.priority.weight(),
            "sponsor_policy": self.sponsor_policy.as_str(),
            "submitted_at_height": self.submitted_at_height,
            "pq_security_bits": self.pq_security_bits,
            "status": self.status.as_str(),
            "reserve_attestation_id": self.reserve_attestation_id,
            "note_id": self.note_id,
            "receipt_id": self.receipt_id,
            "batch_id": self.batch_id,
        })
    }

    pub fn state_root(&self) -> String {
        record_hash(
            "MONERO-L2-PRIVATE-DEPOSIT-NOTE-MINT-DEPOSIT",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReserveAttestationRecord {
    pub attestation_id: String,
    pub deposit_id: String,
    pub reserve_attestor_id: String,
    pub reserve_snapshot_root: String,
    pub reserve_liability_root: String,
    pub view_key_privacy_root: String,
    pub reserve_privacy_root: String,
    pub reserve_coverage_bps: u64,
    pub attested_amount: u128,
    pub attested_at_height: u64,
    pub pq_attestation_root: String,
    pub status: ReserveAttestationStatus,
}

impl ReserveAttestationRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "deposit_id": self.deposit_id,
            "reserve_attestor_id": self.reserve_attestor_id,
            "reserve_snapshot_root": self.reserve_snapshot_root,
            "reserve_liability_root": self.reserve_liability_root,
            "view_key_privacy_root": self.view_key_privacy_root,
            "reserve_privacy_root": self.reserve_privacy_root,
            "reserve_coverage_bps": self.reserve_coverage_bps,
            "attested_amount": self.attested_amount.to_string(),
            "attested_at_height": self.attested_at_height,
            "pq_attestation_root": self.pq_attestation_root,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct L2DepositNoteRecord {
    pub note_id: String,
    pub deposit_id: String,
    pub window_id: String,
    pub attestation_id: String,
    pub minter_id: String,
    pub note_commitment: String,
    pub note_asset_id: String,
    pub note_owner_root: String,
    pub note_view_key_root: String,
    pub note_entropy_root: String,
    pub low_fee_sponsor_root: String,
    pub sponsor_receipt_root: String,
    pub mint_proof_root: String,
    pub amount: u128,
    pub user_fee_bps: u64,
    pub sponsor_fee_bps: u64,
    pub minted_at_height: u64,
    pub status: DepositNoteStatus,
    pub receipt_id: Option<String>,
    pub batch_id: Option<String>,
}

impl L2DepositNoteRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "note_id": self.note_id,
            "deposit_id": self.deposit_id,
            "window_id": self.window_id,
            "attestation_id": self.attestation_id,
            "minter_id": self.minter_id,
            "note_commitment": self.note_commitment,
            "note_asset_id": self.note_asset_id,
            "note_owner_root": self.note_owner_root,
            "note_view_key_root": self.note_view_key_root,
            "note_entropy_root": self.note_entropy_root,
            "low_fee_sponsor_root": self.low_fee_sponsor_root,
            "sponsor_receipt_root": self.sponsor_receipt_root,
            "mint_proof_root": self.mint_proof_root,
            "amount": self.amount.to_string(),
            "user_fee_bps": self.user_fee_bps,
            "sponsor_fee_bps": self.sponsor_fee_bps,
            "minted_at_height": self.minted_at_height,
            "status": self.status.as_str(),
            "receipt_id": self.receipt_id,
            "batch_id": self.batch_id,
        })
    }

    pub fn state_root(&self) -> String {
        record_hash(
            "MONERO-L2-PRIVATE-DEPOSIT-NOTE-MINT-NOTE",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FastEntryReceiptRecord {
    pub receipt_id: String,
    pub note_id: String,
    pub deposit_id: String,
    pub receipt_issuer_id: String,
    pub fast_entry_root: String,
    pub availability_root: String,
    pub preconfirmation_root: String,
    pub receipt_nullifier: String,
    pub replay_fence: String,
    pub fee_bps: u64,
    pub issued_at_height: u64,
    pub expires_at_height: u64,
    pub status: FastEntryReceiptStatus,
}

impl FastEntryReceiptRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "note_id": self.note_id,
            "deposit_id": self.deposit_id,
            "receipt_issuer_id": self.receipt_issuer_id,
            "fast_entry_root": self.fast_entry_root,
            "availability_root": self.availability_root,
            "preconfirmation_root": self.preconfirmation_root,
            "receipt_nullifier": self.receipt_nullifier,
            "replay_fence": self.replay_fence,
            "fee_bps": self.fee_bps,
            "issued_at_height": self.issued_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DepositNoteBatchRecord {
    pub batch_id: String,
    pub batch_coordinator_id: String,
    pub note_ids: Vec<String>,
    pub receipt_ids: Vec<String>,
    pub settlement_root: String,
    pub recursive_proof_root: String,
    pub monero_anchor_root: String,
    pub reserve_snapshot_root: String,
    pub view_key_privacy_root: String,
    pub pq_aggregate_authorization_root: String,
    pub replay_fence: String,
    pub privacy_set_size: u64,
    pub total_amount: u128,
    pub settled_at_height: u64,
    pub status: DepositBatchStatus,
}

impl DepositNoteBatchRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "batch_coordinator_id": self.batch_coordinator_id,
            "note_ids": self.note_ids,
            "receipt_ids": self.receipt_ids,
            "settlement_root": self.settlement_root,
            "recursive_proof_root": self.recursive_proof_root,
            "monero_anchor_root": self.monero_anchor_root,
            "reserve_snapshot_root": self.reserve_snapshot_root,
            "view_key_privacy_root": self.view_key_privacy_root,
            "pq_aggregate_authorization_root": self.pq_aggregate_authorization_root,
            "replay_fence": self.replay_fence,
            "privacy_set_size": self.privacy_set_size,
            "total_amount": self.total_amount.to_string(),
            "settled_at_height": self.settled_at_height,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayFenceRecord {
    pub replay_fence: String,
    pub domain: String,
    pub consumed_by: String,
    pub consumed_at_height: u64,
}

impl ReplayFenceRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "replay_fence": self.replay_fence,
            "domain": self.domain,
            "consumed_by": self.consumed_by,
            "consumed_at_height": self.consumed_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub windows: BTreeMap<String, DepositWindowRecord>,
    pub deposits: BTreeMap<String, PrivateDepositRecord>,
    pub pq_authorizations: BTreeMap<String, PqDepositAuthorizationRecord>,
    pub reserve_attestations: BTreeMap<String, ReserveAttestationRecord>,
    pub notes: BTreeMap<String, L2DepositNoteRecord>,
    pub receipts: BTreeMap<String, FastEntryReceiptRecord>,
    pub batches: BTreeMap<String, DepositNoteBatchRecord>,
    pub consumed_nullifiers: BTreeSet<String>,
    pub replay_fences: BTreeMap<String, ReplayFenceRecord>,
    pub events: Vec<Value>,
}

impl State {
    pub fn devnet() -> Self {
        let config = Config::devnet();
        Self {
            config,
            counters: Counters::default(),
            windows: BTreeMap::new(),
            deposits: BTreeMap::new(),
            pq_authorizations: BTreeMap::new(),
            reserve_attestations: BTreeMap::new(),
            notes: BTreeMap::new(),
            receipts: BTreeMap::new(),
            batches: BTreeMap::new(),
            consumed_nullifiers: BTreeSet::new(),
            replay_fences: BTreeMap::new(),
            events: Vec::new(),
        }
    }

    pub fn with_config(config: Config) -> MoneroL2PrivateDepositNoteMintRuntimeResult<Self> {
        config.validate()?;
        Ok(Self {
            config,
            ..Self::devnet()
        })
    }

    pub fn register_deposit_window(
        &mut self,
        request: RegisterDepositWindowRequest,
    ) -> MoneroL2PrivateDepositNoteMintRuntimeResult<DepositWindowRecord> {
        self.config.validate()?;
        require(
            self.windows.len() < self.config.max_windows,
            "deposit window capacity reached",
        )?;
        required("monero_window_id", &request.monero_window_id)?;
        required("coordinator_id", &request.coordinator_id)?;
        required(
            "reserve_vault_commitment",
            &request.reserve_vault_commitment,
        )?;
        required("reserve_privacy_root", &request.reserve_privacy_root)?;
        required("view_key_privacy_root", &request.view_key_privacy_root)?;
        required("pq_authorization_root", &request.pq_authorization_root)?;
        require(
            request.min_deposit_amount > 0,
            "minimum deposit amount must be positive",
        )?;
        require(
            request.max_deposit_amount >= request.min_deposit_amount,
            "maximum deposit amount below minimum",
        )?;
        require(
            request.target_reserve_bps >= self.config.min_reserve_proof_bps,
            "target reserve below runtime minimum",
        )?;
        require(
            request.min_pq_security_bits >= self.config.min_pq_security_bits,
            "window PQ security below runtime minimum",
        )?;
        require(
            request.closes_at_height > request.opens_at_height,
            "window close height must exceed open height",
        )?;
        require(
            request.closes_at_height - request.opens_at_height <= self.config.window_ttl_blocks,
            "window ttl exceeds runtime limit",
        )?;

        let window_id = deposit_window_id(&request);
        require(
            !self.windows.contains_key(&window_id),
            "deposit window already registered",
        )?;
        require(
            self.windows
                .values()
                .all(|window| window.monero_window_id != request.monero_window_id),
            "monero window already registered",
        )?;

        let record = DepositWindowRecord {
            window_id: window_id.clone(),
            monero_window_id: request.monero_window_id,
            coordinator_id: request.coordinator_id,
            reserve_vault_commitment: request.reserve_vault_commitment,
            reserve_privacy_root: request.reserve_privacy_root,
            view_key_privacy_root: request.view_key_privacy_root,
            pq_authorization_root: request.pq_authorization_root,
            sponsor_pool_root: request.sponsor_pool_root,
            min_deposit_amount: request.min_deposit_amount,
            max_deposit_amount: request.max_deposit_amount,
            target_reserve_bps: request.target_reserve_bps,
            min_pq_security_bits: request.min_pq_security_bits,
            opens_at_height: request.opens_at_height,
            closes_at_height: request.closes_at_height,
            low_fee_enabled: request.low_fee_enabled,
            status: DepositWindowStatus::Open,
        };

        self.windows.insert(window_id.clone(), record.clone());
        self.counters.windows_registered += 1;
        self.push_event(
            "deposit_window_registered",
            &window_id,
            record.public_record(),
        );
        Ok(record)
    }

    pub fn submit_private_deposit(
        &mut self,
        request: SubmitPrivateDepositRequest,
    ) -> MoneroL2PrivateDepositNoteMintRuntimeResult<PrivateDepositRecord> {
        self.config.validate()?;
        require(
            self.deposits.len() < self.config.max_deposits,
            "private deposit capacity reached",
        )?;
        required("window_id", &request.window_id)?;
        required("monero_tx_commitment", &request.monero_tx_commitment)?;
        required(
            "monero_output_commitment",
            &request.monero_output_commitment,
        )?;
        required(
            "deposit_amount_commitment",
            &request.deposit_amount_commitment,
        )?;
        required("encrypted_view_key_root", &request.encrypted_view_key_root)?;
        required("view_tag_root", &request.view_tag_root)?;
        required("reserve_hint_root", &request.reserve_hint_root)?;
        required("pq_authorization_root", &request.pq_authorization_root)?;
        required(
            "pq_authorization_nullifier",
            &request.pq_authorization_nullifier,
        )?;
        required("deposit_nullifier", &request.deposit_nullifier)?;
        required("replay_fence", &request.replay_fence)?;
        require(
            request.privacy_set_size >= self.config.min_privacy_set_size,
            "deposit privacy set below runtime minimum",
        )?;
        require(request.amount > 0, "deposit amount must be positive")?;
        require(
            request.pq_security_bits >= self.config.min_pq_security_bits,
            "deposit PQ security below runtime minimum",
        )?;
        require(
            !self
                .consumed_nullifiers
                .contains(&request.pq_authorization_nullifier),
            "PQ authorization nullifier already consumed",
        )?;
        require(
            !self
                .consumed_nullifiers
                .contains(&request.deposit_nullifier),
            "deposit nullifier already consumed",
        )?;
        require(
            !self.replay_fences.contains_key(&request.replay_fence),
            "deposit replay fence already consumed",
        )?;

        let window = self
            .windows
            .get(&request.window_id)
            .ok_or_else(|| "deposit window not found".to_string())?;
        require(
            window.status.accepts_deposits(),
            "deposit window is not open",
        )?;
        require(
            request.submitted_at_height >= window.opens_at_height
                && request.submitted_at_height <= window.closes_at_height,
            "deposit submitted outside window",
        )?;
        require(
            request.amount >= window.min_deposit_amount
                && request.amount <= window.max_deposit_amount,
            "deposit amount outside window bounds",
        )?;
        require(
            request.pq_security_bits >= window.min_pq_security_bits,
            "deposit PQ security below window minimum",
        )?;
        if request.sponsor_policy.sponsored() {
            require(
                window.low_fee_enabled,
                "window does not allow sponsored low-fee deposits",
            )?;
            required("sponsor_pool_root", &window.sponsor_pool_root)?;
        }

        let deposit_id = private_deposit_id(&request);
        require(
            !self.deposits.contains_key(&deposit_id),
            "private deposit already submitted",
        )?;
        let authorization_id = pq_deposit_authorization_id(
            &deposit_id,
            &request.pq_authorization_root,
            &request.pq_authorization_nullifier,
        );

        let authorization = PqDepositAuthorizationRecord {
            authorization_id: authorization_id.clone(),
            deposit_id: deposit_id.clone(),
            window_id: request.window_id.clone(),
            pq_authorization_root: request.pq_authorization_root.clone(),
            pq_authorization_nullifier: request.pq_authorization_nullifier.clone(),
            replay_fence: request.replay_fence.clone(),
            pq_security_bits: request.pq_security_bits,
            status: PqAuthorizationStatus::Accepted,
        };

        let record = PrivateDepositRecord {
            deposit_id: deposit_id.clone(),
            window_id: request.window_id,
            monero_tx_commitment: request.monero_tx_commitment,
            monero_output_commitment: request.monero_output_commitment,
            deposit_amount_commitment: request.deposit_amount_commitment,
            encrypted_view_key_root: request.encrypted_view_key_root,
            view_tag_root: request.view_tag_root,
            reserve_hint_root: request.reserve_hint_root,
            pq_authorization_root: request.pq_authorization_root,
            authorization_id: authorization_id.clone(),
            deposit_nullifier: request.deposit_nullifier.clone(),
            replay_fence: request.replay_fence.clone(),
            privacy_set_size: request.privacy_set_size,
            amount: request.amount,
            priority: request.priority,
            sponsor_policy: request.sponsor_policy,
            submitted_at_height: request.submitted_at_height,
            pq_security_bits: request.pq_security_bits,
            status: DepositRequestStatus::Submitted,
            reserve_attestation_id: None,
            note_id: None,
            receipt_id: None,
            batch_id: None,
        };

        self.consumed_nullifiers
            .insert(request.pq_authorization_nullifier);
        self.consumed_nullifiers.insert(request.deposit_nullifier);
        self.replay_fences.insert(
            request.replay_fence.clone(),
            ReplayFenceRecord {
                replay_fence: request.replay_fence,
                domain: self.config.replay_domain.clone(),
                consumed_by: deposit_id.clone(),
                consumed_at_height: request.submitted_at_height,
            },
        );
        self.pq_authorizations
            .insert(authorization_id, authorization);
        self.deposits.insert(deposit_id.clone(), record.clone());
        self.counters.private_deposits_submitted += 1;
        self.counters.pq_authorizations_accepted += 1;
        self.counters.nullifiers_consumed += 2;
        self.counters.replay_fences_consumed += 1;
        self.counters.total_private_amount = self
            .counters
            .total_private_amount
            .saturating_add(request.amount);
        self.push_event(
            "private_deposit_submitted",
            &deposit_id,
            record.public_record(),
        );
        Ok(record)
    }

    pub fn attest_deposit_reserve(
        &mut self,
        request: AttestDepositReserveRequest,
    ) -> MoneroL2PrivateDepositNoteMintRuntimeResult<ReserveAttestationRecord> {
        self.config.validate()?;
        require(
            self.reserve_attestations.len() < self.config.max_attestations,
            "reserve attestation capacity reached",
        )?;
        required("deposit_id", &request.deposit_id)?;
        required("reserve_attestor_id", &request.reserve_attestor_id)?;
        required("reserve_snapshot_root", &request.reserve_snapshot_root)?;
        required("reserve_liability_root", &request.reserve_liability_root)?;
        required("view_key_privacy_root", &request.view_key_privacy_root)?;
        required("reserve_privacy_root", &request.reserve_privacy_root)?;
        required("pq_attestation_root", &request.pq_attestation_root)?;
        require(
            request.reserve_coverage_bps >= self.config.min_reserve_proof_bps,
            "reserve coverage below runtime minimum",
        )?;

        let deposit = self
            .deposits
            .get_mut(&request.deposit_id)
            .ok_or_else(|| "private deposit not found".to_string())?;
        require(
            deposit.status == DepositRequestStatus::Submitted,
            "deposit is not ready for reserve attestation",
        )?;
        require(
            request.attested_amount >= deposit.amount,
            "attested amount below private deposit amount",
        )?;
        require(
            deposit.reserve_attestation_id.is_none(),
            "deposit already has reserve attestation",
        )?;

        let attestation_id = reserve_attestation_id(&request);
        require(
            !self.reserve_attestations.contains_key(&attestation_id),
            "reserve attestation already accepted",
        )?;

        let record = ReserveAttestationRecord {
            attestation_id: attestation_id.clone(),
            deposit_id: request.deposit_id.clone(),
            reserve_attestor_id: request.reserve_attestor_id,
            reserve_snapshot_root: request.reserve_snapshot_root,
            reserve_liability_root: request.reserve_liability_root,
            view_key_privacy_root: request.view_key_privacy_root,
            reserve_privacy_root: request.reserve_privacy_root,
            reserve_coverage_bps: request.reserve_coverage_bps,
            attested_amount: request.attested_amount,
            attested_at_height: request.attested_at_height,
            pq_attestation_root: request.pq_attestation_root,
            status: ReserveAttestationStatus::Accepted,
        };

        deposit.status = DepositRequestStatus::ReserveAttested;
        deposit.reserve_attestation_id = Some(attestation_id.clone());
        self.reserve_attestations
            .insert(attestation_id.clone(), record.clone());
        self.counters.reserve_attestations_accepted += 1;
        self.push_event(
            "deposit_reserve_attested",
            &attestation_id,
            record.public_record(),
        );
        Ok(record)
    }

    pub fn mint_l2_deposit_note(
        &mut self,
        request: MintL2DepositNoteRequest,
    ) -> MoneroL2PrivateDepositNoteMintRuntimeResult<L2DepositNoteRecord> {
        self.config.validate()?;
        require(
            self.notes.len() < self.config.max_notes,
            "deposit note capacity reached",
        )?;
        required("deposit_id", &request.deposit_id)?;
        required("minter_id", &request.minter_id)?;
        required("note_commitment", &request.note_commitment)?;
        required("note_asset_id", &request.note_asset_id)?;
        required("note_owner_root", &request.note_owner_root)?;
        required("note_view_key_root", &request.note_view_key_root)?;
        required("note_entropy_root", &request.note_entropy_root)?;
        required("mint_proof_root", &request.mint_proof_root)?;
        require(
            request.note_asset_id == self.config.asset_id,
            "note asset id does not match runtime asset",
        )?;
        require(
            request.user_fee_bps <= self.config.max_user_fee_bps,
            "user fee exceeds runtime maximum",
        )?;
        require(
            request.sponsor_fee_bps <= MONERO_L2_PRIVATE_DEPOSIT_NOTE_MINT_RUNTIME_MAX_BPS,
            "sponsor fee bps too high",
        )?;

        let deposit = self
            .deposits
            .get_mut(&request.deposit_id)
            .ok_or_else(|| "private deposit not found".to_string())?;
        require(
            deposit.status == DepositRequestStatus::ReserveAttested,
            "deposit is not ready for note mint",
        )?;
        require(deposit.note_id.is_none(), "deposit note already minted")?;
        if deposit.sponsor_policy.sponsored() {
            required("low_fee_sponsor_root", &request.low_fee_sponsor_root)?;
            required("sponsor_receipt_root", &request.sponsor_receipt_root)?;
            require(
                request.user_fee_bps <= self.config.low_fee_bps,
                "sponsored deposit note must use low fee tier",
            )?;
            require(
                request.sponsor_fee_bps >= self.config.sponsor_cover_bps,
                "sponsor cover below runtime minimum",
            )?;
        } else {
            require(
                request.user_fee_bps <= deposit.priority.user_fee_bps(&self.config),
                "user fee exceeds deposit priority fee",
            )?;
        }

        let attestation_id = deposit
            .reserve_attestation_id
            .clone()
            .ok_or_else(|| "deposit missing reserve attestation".to_string())?;
        let note_id = l2_deposit_note_id(&request, &attestation_id);
        require(
            !self.notes.contains_key(&note_id),
            "deposit note already exists",
        )?;

        let record = L2DepositNoteRecord {
            note_id: note_id.clone(),
            deposit_id: request.deposit_id.clone(),
            window_id: deposit.window_id.clone(),
            attestation_id,
            minter_id: request.minter_id,
            note_commitment: request.note_commitment,
            note_asset_id: request.note_asset_id,
            note_owner_root: request.note_owner_root,
            note_view_key_root: request.note_view_key_root,
            note_entropy_root: request.note_entropy_root,
            low_fee_sponsor_root: request.low_fee_sponsor_root,
            sponsor_receipt_root: request.sponsor_receipt_root,
            mint_proof_root: request.mint_proof_root,
            amount: deposit.amount,
            user_fee_bps: request.user_fee_bps,
            sponsor_fee_bps: request.sponsor_fee_bps,
            minted_at_height: request.minted_at_height,
            status: DepositNoteStatus::Minted,
            receipt_id: None,
            batch_id: None,
        };

        deposit.status = DepositRequestStatus::NoteMinted;
        deposit.note_id = Some(note_id.clone());
        self.notes.insert(note_id.clone(), record.clone());
        self.counters.l2_deposit_notes_minted += 1;
        self.counters.total_public_fee = self
            .counters
            .total_public_fee
            .saturating_add(fee_amount(record.amount, request.user_fee_bps));
        if deposit.sponsor_policy.sponsored() {
            self.counters.sponsored_notes_minted += 1;
            self.counters.total_sponsor_fee = self
                .counters
                .total_sponsor_fee
                .saturating_add(fee_amount(record.amount, request.sponsor_fee_bps));
        }
        self.push_event("l2_deposit_note_minted", &note_id, record.public_record());
        Ok(record)
    }

    pub fn issue_fast_entry_receipt(
        &mut self,
        request: IssueFastEntryReceiptRequest,
    ) -> MoneroL2PrivateDepositNoteMintRuntimeResult<FastEntryReceiptRecord> {
        self.config.validate()?;
        require(
            self.receipts.len() < self.config.max_receipts,
            "fast entry receipt capacity reached",
        )?;
        required("note_id", &request.note_id)?;
        required("receipt_issuer_id", &request.receipt_issuer_id)?;
        required("fast_entry_root", &request.fast_entry_root)?;
        required("availability_root", &request.availability_root)?;
        required("preconfirmation_root", &request.preconfirmation_root)?;
        required("receipt_nullifier", &request.receipt_nullifier)?;
        required("replay_fence", &request.replay_fence)?;
        require(
            request.fee_bps <= self.config.max_user_fee_bps,
            "fast entry fee exceeds runtime maximum",
        )?;
        require(
            !self
                .consumed_nullifiers
                .contains(&request.receipt_nullifier),
            "receipt nullifier already consumed",
        )?;
        require(
            !self.replay_fences.contains_key(&request.replay_fence),
            "receipt replay fence already consumed",
        )?;

        let note = self
            .notes
            .get_mut(&request.note_id)
            .ok_or_else(|| "deposit note not found".to_string())?;
        require(
            note.status == DepositNoteStatus::Minted,
            "deposit note is not ready for fast entry receipt",
        )?;
        require(
            note.receipt_id.is_none(),
            "deposit note already has receipt",
        )?;
        let deposit = self
            .deposits
            .get_mut(&note.deposit_id)
            .ok_or_else(|| "private deposit missing for note".to_string())?;
        require(
            deposit.status == DepositRequestStatus::NoteMinted,
            "deposit is not ready for fast entry receipt",
        )?;

        let receipt_id = fast_entry_receipt_id(&request, &note.deposit_id);
        require(
            !self.receipts.contains_key(&receipt_id),
            "fast entry receipt already exists",
        )?;
        let record = FastEntryReceiptRecord {
            receipt_id: receipt_id.clone(),
            note_id: request.note_id.clone(),
            deposit_id: note.deposit_id.clone(),
            receipt_issuer_id: request.receipt_issuer_id,
            fast_entry_root: request.fast_entry_root,
            availability_root: request.availability_root,
            preconfirmation_root: request.preconfirmation_root,
            receipt_nullifier: request.receipt_nullifier.clone(),
            replay_fence: request.replay_fence.clone(),
            fee_bps: request.fee_bps,
            issued_at_height: request.issued_at_height,
            expires_at_height: request
                .issued_at_height
                .saturating_add(self.config.fast_receipt_ttl_blocks),
            status: FastEntryReceiptStatus::Issued,
        };

        note.status = DepositNoteStatus::FastEntryReceipted;
        note.receipt_id = Some(receipt_id.clone());
        deposit.status = DepositRequestStatus::FastEntryReceipted;
        deposit.receipt_id = Some(receipt_id.clone());
        self.consumed_nullifiers.insert(request.receipt_nullifier);
        self.replay_fences.insert(
            request.replay_fence.clone(),
            ReplayFenceRecord {
                replay_fence: request.replay_fence,
                domain: self.config.replay_domain.clone(),
                consumed_by: receipt_id.clone(),
                consumed_at_height: request.issued_at_height,
            },
        );
        self.receipts.insert(receipt_id.clone(), record.clone());
        self.counters.fast_entry_receipts_issued += 1;
        self.counters.nullifiers_consumed += 1;
        self.counters.replay_fences_consumed += 1;
        self.push_event(
            "fast_entry_receipt_issued",
            &receipt_id,
            record.public_record(),
        );
        Ok(record)
    }

    pub fn settle_deposit_note_batch(
        &mut self,
        request: SettleDepositNoteBatchRequest,
    ) -> MoneroL2PrivateDepositNoteMintRuntimeResult<DepositNoteBatchRecord> {
        self.config.validate()?;
        require(
            self.batches.len() < self.config.max_batches,
            "deposit note batch capacity reached",
        )?;
        required("batch_coordinator_id", &request.batch_coordinator_id)?;
        required("settlement_root", &request.settlement_root)?;
        required("recursive_proof_root", &request.recursive_proof_root)?;
        required("monero_anchor_root", &request.monero_anchor_root)?;
        required("reserve_snapshot_root", &request.reserve_snapshot_root)?;
        required("view_key_privacy_root", &request.view_key_privacy_root)?;
        required(
            "pq_aggregate_authorization_root",
            &request.pq_aggregate_authorization_root,
        )?;
        required("replay_fence", &request.replay_fence)?;
        require(
            !request.note_ids.is_empty(),
            "batch requires at least one note",
        )?;
        require(
            request.privacy_set_size >= self.config.batch_privacy_set_size,
            "batch privacy set below runtime minimum",
        )?;
        require(
            !self.replay_fences.contains_key(&request.replay_fence),
            "batch replay fence already consumed",
        )?;
        let unique_notes = request.note_ids.iter().collect::<BTreeSet<_>>();
        require(
            unique_notes.len() == request.note_ids.len(),
            "batch note ids must be unique",
        )?;
        let unique_receipts = request.receipt_ids.iter().collect::<BTreeSet<_>>();
        require(
            unique_receipts.len() == request.receipt_ids.len(),
            "batch receipt ids must be unique",
        )?;

        let batch_id = deposit_note_batch_id(&request);
        require(
            !self.batches.contains_key(&batch_id),
            "deposit note batch already exists",
        )?;

        let mut total_amount = 0_u128;
        for note_id in &request.note_ids {
            let note = self
                .notes
                .get(note_id)
                .ok_or_else(|| format!("deposit note not found: {note_id}"))?;
            require(
                note.status.settlement_eligible(),
                "deposit note is not settlement eligible",
            )?;
            require(note.batch_id.is_none(), "deposit note already batched")?;
            total_amount = total_amount.saturating_add(note.amount);
        }
        for receipt_id in &request.receipt_ids {
            let receipt = self
                .receipts
                .get(receipt_id)
                .ok_or_else(|| format!("fast entry receipt not found: {receipt_id}"))?;
            require(receipt.status.live(), "receipt is not live")?;
            require(
                request.note_ids.contains(&receipt.note_id),
                "receipt note is not in settlement batch",
            )?;
        }

        let record = DepositNoteBatchRecord {
            batch_id: batch_id.clone(),
            batch_coordinator_id: request.batch_coordinator_id,
            note_ids: request.note_ids.clone(),
            receipt_ids: request.receipt_ids.clone(),
            settlement_root: request.settlement_root,
            recursive_proof_root: request.recursive_proof_root,
            monero_anchor_root: request.monero_anchor_root,
            reserve_snapshot_root: request.reserve_snapshot_root,
            view_key_privacy_root: request.view_key_privacy_root,
            pq_aggregate_authorization_root: request.pq_aggregate_authorization_root,
            replay_fence: request.replay_fence.clone(),
            privacy_set_size: request.privacy_set_size,
            total_amount,
            settled_at_height: request.settled_at_height,
            status: DepositBatchStatus::Settled,
        };

        for note_id in &request.note_ids {
            let note = self
                .notes
                .get_mut(note_id)
                .ok_or_else(|| format!("deposit note not found: {note_id}"))?;
            note.status = DepositNoteStatus::Settled;
            note.batch_id = Some(batch_id.clone());
            let deposit = self
                .deposits
                .get_mut(&note.deposit_id)
                .ok_or_else(|| "private deposit missing for note".to_string())?;
            deposit.status = DepositRequestStatus::Settled;
            deposit.batch_id = Some(batch_id.clone());
        }
        for receipt_id in &request.receipt_ids {
            let receipt = self
                .receipts
                .get_mut(receipt_id)
                .ok_or_else(|| format!("fast entry receipt not found: {receipt_id}"))?;
            receipt.status = FastEntryReceiptStatus::Finalized;
        }

        self.replay_fences.insert(
            request.replay_fence.clone(),
            ReplayFenceRecord {
                replay_fence: request.replay_fence,
                domain: self.config.replay_domain.clone(),
                consumed_by: batch_id.clone(),
                consumed_at_height: request.settled_at_height,
            },
        );
        self.batches.insert(batch_id.clone(), record.clone());
        self.counters.deposit_note_batches_settled += 1;
        self.counters.replay_fences_consumed += 1;
        self.push_event(
            "deposit_note_batch_settled",
            &batch_id,
            record.public_record(),
        );
        Ok(record)
    }

    pub fn roots(&self) -> Roots {
        let window_records = self
            .windows
            .values()
            .map(DepositWindowRecord::public_record)
            .collect::<Vec<_>>();
        let open_window_records = self
            .windows
            .values()
            .filter(|window| window.status.accepts_deposits())
            .map(DepositWindowRecord::public_record)
            .collect::<Vec<_>>();
        let deposit_records = self
            .deposits
            .values()
            .map(PrivateDepositRecord::public_record)
            .collect::<Vec<_>>();
        let live_deposit_records = self
            .deposits
            .values()
            .filter(|deposit| deposit.status.live())
            .map(PrivateDepositRecord::public_record)
            .collect::<Vec<_>>();
        let pq_authorization_records = self
            .pq_authorizations
            .values()
            .map(PqDepositAuthorizationRecord::public_record)
            .collect::<Vec<_>>();
        let reserve_attestation_records = self
            .reserve_attestations
            .values()
            .map(ReserveAttestationRecord::public_record)
            .collect::<Vec<_>>();
        let note_records = self
            .notes
            .values()
            .map(L2DepositNoteRecord::public_record)
            .collect::<Vec<_>>();
        let unsettled_note_records = self
            .notes
            .values()
            .filter(|note| note.status.settlement_eligible())
            .map(L2DepositNoteRecord::public_record)
            .collect::<Vec<_>>();
        let receipt_records = self
            .receipts
            .values()
            .map(FastEntryReceiptRecord::public_record)
            .collect::<Vec<_>>();
        let batch_records = self
            .batches
            .values()
            .map(DepositNoteBatchRecord::public_record)
            .collect::<Vec<_>>();
        let nullifier_records = self
            .consumed_nullifiers
            .iter()
            .map(|nullifier| json!({ "nullifier": nullifier }))
            .collect::<Vec<_>>();
        let replay_records = self
            .replay_fences
            .values()
            .map(ReplayFenceRecord::public_record)
            .collect::<Vec<_>>();
        let reserve_privacy_records = self
            .reserve_attestations
            .values()
            .map(|attestation| {
                json!({
                    "attestation_id": attestation.attestation_id,
                    "reserve_privacy_root": attestation.reserve_privacy_root,
                    "reserve_snapshot_root": attestation.reserve_snapshot_root,
                    "reserve_liability_root": attestation.reserve_liability_root,
                })
            })
            .collect::<Vec<_>>();
        let view_key_privacy_records = self
            .reserve_attestations
            .values()
            .map(|attestation| {
                json!({
                    "attestation_id": attestation.attestation_id,
                    "view_key_privacy_root": attestation.view_key_privacy_root,
                })
            })
            .chain(self.notes.values().map(|note| {
                json!({
                    "note_id": note.note_id,
                    "note_view_key_root": note.note_view_key_root,
                })
            }))
            .collect::<Vec<_>>();
        let sponsor_records = self
            .notes
            .values()
            .filter(|note| !note.low_fee_sponsor_root.is_empty())
            .map(|note| {
                json!({
                    "note_id": note.note_id,
                    "low_fee_sponsor_root": note.low_fee_sponsor_root,
                    "sponsor_receipt_root": note.sponsor_receipt_root,
                    "sponsor_fee_bps": note.sponsor_fee_bps,
                })
            })
            .collect::<Vec<_>>();

        Roots {
            config_root: self.config.state_root(),
            counters_root: self.counters.state_root(),
            window_root: merkle_root(
                "MONERO-L2-PRIVATE-DEPOSIT-NOTE-MINT-WINDOWS",
                &window_records,
            ),
            open_window_root: merkle_root(
                "MONERO-L2-PRIVATE-DEPOSIT-NOTE-MINT-OPEN-WINDOWS",
                &open_window_records,
            ),
            deposit_root: merkle_root(
                "MONERO-L2-PRIVATE-DEPOSIT-NOTE-MINT-DEPOSITS",
                &deposit_records,
            ),
            live_deposit_root: merkle_root(
                "MONERO-L2-PRIVATE-DEPOSIT-NOTE-MINT-LIVE-DEPOSITS",
                &live_deposit_records,
            ),
            pq_authorization_root: merkle_root(
                "MONERO-L2-PRIVATE-DEPOSIT-NOTE-MINT-PQ-AUTHORIZATIONS",
                &pq_authorization_records,
            ),
            reserve_attestation_root: merkle_root(
                "MONERO-L2-PRIVATE-DEPOSIT-NOTE-MINT-RESERVE-ATTESTATIONS",
                &reserve_attestation_records,
            ),
            note_root: merkle_root("MONERO-L2-PRIVATE-DEPOSIT-NOTE-MINT-NOTES", &note_records),
            unsettled_note_root: merkle_root(
                "MONERO-L2-PRIVATE-DEPOSIT-NOTE-MINT-UNSETTLED-NOTES",
                &unsettled_note_records,
            ),
            receipt_root: merkle_root(
                "MONERO-L2-PRIVATE-DEPOSIT-NOTE-MINT-RECEIPTS",
                &receipt_records,
            ),
            batch_root: merkle_root(
                "MONERO-L2-PRIVATE-DEPOSIT-NOTE-MINT-BATCHES",
                &batch_records,
            ),
            consumed_nullifier_root: merkle_root(
                "MONERO-L2-PRIVATE-DEPOSIT-NOTE-MINT-CONSUMED-NULLIFIERS",
                &nullifier_records,
            ),
            replay_fence_root: merkle_root(
                "MONERO-L2-PRIVATE-DEPOSIT-NOTE-MINT-REPLAY-FENCES",
                &replay_records,
            ),
            reserve_privacy_root: merkle_root(
                "MONERO-L2-PRIVATE-DEPOSIT-NOTE-MINT-RESERVE-PRIVACY-ROOTS",
                &reserve_privacy_records,
            ),
            view_key_privacy_root: merkle_root(
                "MONERO-L2-PRIVATE-DEPOSIT-NOTE-MINT-VIEW-KEY-PRIVACY-ROOTS",
                &view_key_privacy_records,
            ),
            sponsor_root: merkle_root(
                "MONERO-L2-PRIVATE-DEPOSIT-NOTE-MINT-SPONSORS",
                &sponsor_records,
            ),
            event_root: merkle_root("MONERO-L2-PRIVATE-DEPOSIT-NOTE-MINT-EVENTS", &self.events),
        }
    }

    pub fn public_record_without_state_root(&self) -> Value {
        let roots = self.roots();
        json!({
            "protocol_version": self.config.protocol_version,
            "schema_version": self.config.schema_version,
            "chain_id": CHAIN_ID,
            "config_root": roots.config_root,
            "counters_root": roots.counters_root,
            "roots_root": roots.state_root(),
            "roots": roots.public_record(),
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        set_json_field(&mut record, "state_root", json!(self.state_root()));
        record
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "MONERO-L2-PRIVATE-DEPOSIT-NOTE-MINT-STATE",
            &[HashPart::Json(&self.public_record_without_state_root())],
            32,
        )
    }

    fn push_event(&mut self, kind: &str, record_id: &str, payload: Value) {
        let event_id = domain_hash(
            "MONERO-L2-PRIVATE-DEPOSIT-NOTE-MINT-EVENT-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(kind),
                HashPart::Str(record_id),
                HashPart::Int(self.events.len() as i128),
            ],
            32,
        );
        self.events.push(json!({
            "event_id": event_id,
            "kind": kind,
            "record_id": record_id,
            "payload_root": record_hash("MONERO-L2-PRIVATE-DEPOSIT-NOTE-MINT-EVENT-PAYLOAD", &payload),
        }));
    }
}

pub fn monero_l2_private_deposit_note_mint_runtime_devnet() -> State {
    State::devnet()
}

pub fn monero_l2_private_deposit_note_mint_runtime_state_root(state: &State) -> String {
    state.state_root()
}

pub fn monero_l2_private_deposit_note_mint_runtime_public_record(state: &State) -> Value {
    state.public_record()
}

pub fn deposit_window_id(request: &RegisterDepositWindowRequest) -> String {
    domain_hash(
        "MONERO-L2-PRIVATE-DEPOSIT-NOTE-MINT-WINDOW-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.monero_window_id),
            HashPart::Str(&request.coordinator_id),
            HashPart::Str(&request.reserve_vault_commitment),
            HashPart::Int(request.opens_at_height as i128),
            HashPart::Int(request.closes_at_height as i128),
        ],
        32,
    )
}

pub fn private_deposit_id(request: &SubmitPrivateDepositRequest) -> String {
    domain_hash(
        "MONERO-L2-PRIVATE-DEPOSIT-NOTE-MINT-DEPOSIT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.window_id),
            HashPart::Str(&request.monero_tx_commitment),
            HashPart::Str(&request.monero_output_commitment),
            HashPart::Str(&request.deposit_nullifier),
            HashPart::Str(request.priority.as_str()),
        ],
        32,
    )
}

pub fn pq_deposit_authorization_id(
    deposit_id: &str,
    pq_authorization_root: &str,
    pq_authorization_nullifier: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PRIVATE-DEPOSIT-NOTE-MINT-PQ-AUTHORIZATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(deposit_id),
            HashPart::Str(pq_authorization_root),
            HashPart::Str(pq_authorization_nullifier),
        ],
        32,
    )
}

pub fn reserve_attestation_id(request: &AttestDepositReserveRequest) -> String {
    domain_hash(
        "MONERO-L2-PRIVATE-DEPOSIT-NOTE-MINT-RESERVE-ATTESTATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.deposit_id),
            HashPart::Str(&request.reserve_attestor_id),
            HashPart::Str(&request.reserve_snapshot_root),
            HashPart::Str(&request.reserve_liability_root),
            HashPart::Str(&request.pq_attestation_root),
            HashPart::Int(request.attested_at_height as i128),
        ],
        32,
    )
}

pub fn l2_deposit_note_id(request: &MintL2DepositNoteRequest, attestation_id: &str) -> String {
    domain_hash(
        "MONERO-L2-PRIVATE-DEPOSIT-NOTE-MINT-NOTE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.deposit_id),
            HashPart::Str(attestation_id),
            HashPart::Str(&request.note_commitment),
            HashPart::Str(&request.note_owner_root),
            HashPart::Str(&request.note_entropy_root),
        ],
        32,
    )
}

pub fn fast_entry_receipt_id(request: &IssueFastEntryReceiptRequest, deposit_id: &str) -> String {
    domain_hash(
        "MONERO-L2-PRIVATE-DEPOSIT-NOTE-MINT-FAST-ENTRY-RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(deposit_id),
            HashPart::Str(&request.note_id),
            HashPart::Str(&request.receipt_issuer_id),
            HashPart::Str(&request.receipt_nullifier),
            HashPart::Str(&request.preconfirmation_root),
        ],
        32,
    )
}

pub fn deposit_note_batch_id(request: &SettleDepositNoteBatchRequest) -> String {
    let note_root = id_merkle_root(
        "MONERO-L2-PRIVATE-DEPOSIT-NOTE-MINT-BATCH-NOTE-IDS",
        &request.note_ids,
    );
    let receipt_root = id_merkle_root(
        "MONERO-L2-PRIVATE-DEPOSIT-NOTE-MINT-BATCH-RECEIPT-IDS",
        &request.receipt_ids,
    );
    domain_hash(
        "MONERO-L2-PRIVATE-DEPOSIT-NOTE-MINT-BATCH-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.batch_coordinator_id),
            HashPart::Str(&note_root),
            HashPart::Str(&receipt_root),
            HashPart::Str(&request.settlement_root),
            HashPart::Str(&request.recursive_proof_root),
            HashPart::Str(&request.replay_fence),
        ],
        32,
    )
}

fn fee_amount(amount: u128, fee_bps: u64) -> u128 {
    amount.saturating_mul(fee_bps as u128)
        / MONERO_L2_PRIVATE_DEPOSIT_NOTE_MINT_RUNTIME_MAX_BPS as u128
}

fn id_merkle_root(domain: &str, ids: &[String]) -> String {
    let leaves = ids.iter().map(|id| json!({ "id": id })).collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn record_hash(domain: &str, record: &Value) -> String {
    domain_hash(
        domain,
        &[HashPart::Str(CHAIN_ID), HashPart::Json(record)],
        32,
    )
}

fn required(field: &str, value: &str) -> MoneroL2PrivateDepositNoteMintRuntimeResult<()> {
    require(!value.is_empty(), &format!("{field} is required"))
}

fn require(condition: bool, message: &str) -> MoneroL2PrivateDepositNoteMintRuntimeResult<()> {
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
