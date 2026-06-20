use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type MoneroL2PqPrivateSubaddressBatchSettlementRuntimeResult<T> =
    std::result::Result<T, String>;
pub type Result<T> = MoneroL2PqPrivateSubaddressBatchSettlementRuntimeResult<T>;

pub const MONERO_L2_PQ_PRIVATE_SUBADDRESS_BATCH_SETTLEMENT_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-private-subaddress-batch-settlement-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_PRIVATE_SUBADDRESS_BATCH_SETTLEMENT_RUNTIME_PROTOCOL_VERSION;
pub const MONERO_L2_PQ_PRIVATE_SUBADDRESS_BATCH_SETTLEMENT_RUNTIME_SCHEMA_VERSION: u64 = 1;
pub const MONERO_L2_PQ_PRIVATE_SUBADDRESS_BATCH_SETTLEMENT_RUNTIME_DEVNET_HEIGHT: u64 = 444_000;
pub const MONERO_L2_PQ_PRIVATE_SUBADDRESS_BATCH_SETTLEMENT_RUNTIME_DEVNET_MONERO_NETWORK: &str =
    "monero-devnet";
pub const MONERO_L2_PQ_PRIVATE_SUBADDRESS_BATCH_SETTLEMENT_RUNTIME_DEVNET_L2_NETWORK: &str =
    "nebula-devnet";
pub const MONERO_L2_PQ_PRIVATE_SUBADDRESS_BATCH_SETTLEMENT_RUNTIME_DEVNET_ASSET_ID: &str =
    "wxmr-devnet";
pub const MONERO_L2_PQ_PRIVATE_SUBADDRESS_BATCH_SETTLEMENT_RUNTIME_DEVNET_FEE_ASSET_ID: &str =
    "piconero-devnet";
pub const MONERO_L2_PQ_PRIVATE_SUBADDRESS_BATCH_SETTLEMENT_RUNTIME_HASH_SUITE: &str =
    "SHAKE256-domain-separated-canonical-json";
pub const MONERO_L2_PQ_PRIVATE_SUBADDRESS_BATCH_SETTLEMENT_RUNTIME_PQ_VIEW_KEY_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-subaddress-view-key-v1";
pub const MONERO_L2_PQ_PRIVATE_SUBADDRESS_BATCH_SETTLEMENT_RUNTIME_BUCKET_SCHEME: &str =
    "ml-kem-1024-sealed-encrypted-subaddress-bucket-root-v1";
pub const MONERO_L2_PQ_PRIVATE_SUBADDRESS_BATCH_SETTLEMENT_RUNTIME_VIEW_ATTESTATION_SCHEME: &str =
    "ml-dsa-87-slh-dsa-private-subaddress-view-attestation-root-v1";
pub const MONERO_L2_PQ_PRIVATE_SUBADDRESS_BATCH_SETTLEMENT_RUNTIME_MANIFEST_SCHEME: &str =
    "private-subaddress-deposit-withdraw-manifest-root-v1";
pub const MONERO_L2_PQ_PRIVATE_SUBADDRESS_BATCH_SETTLEMENT_RUNTIME_PAYMENT_ID_SCHEME: &str =
    "private-payment-id-commitment-root-v1";
pub const MONERO_L2_PQ_PRIVATE_SUBADDRESS_BATCH_SETTLEMENT_RUNTIME_SPONSOR_SCHEME: &str =
    "low-fee-subaddress-settlement-sponsor-reservation-root-v1";
pub const MONERO_L2_PQ_PRIVATE_SUBADDRESS_BATCH_SETTLEMENT_RUNTIME_RECEIPT_SCHEME: &str =
    "fast-private-subaddress-settlement-receipt-root-v1";
pub const MONERO_L2_PQ_PRIVATE_SUBADDRESS_BATCH_SETTLEMENT_RUNTIME_ANCHOR_SCHEME: &str =
    "reorg-safe-monero-anchor-window-root-v1";
pub const MONERO_L2_PQ_PRIVATE_SUBADDRESS_BATCH_SETTLEMENT_RUNTIME_SCAN_HINT_SCHEME: &str =
    "wallet-subaddress-scan-hint-root-v1";
pub const MONERO_L2_PQ_PRIVATE_SUBADDRESS_BATCH_SETTLEMENT_RUNTIME_NULLIFIER_SCHEME: &str =
    "subaddress-settlement-nullifier-fence-root-v1";
pub const MONERO_L2_PQ_PRIVATE_SUBADDRESS_BATCH_SETTLEMENT_RUNTIME_SLASHING_SCHEME: &str =
    "subaddress-settlement-slasher-evidence-root-v1";
pub const MONERO_L2_PQ_PRIVATE_SUBADDRESS_BATCH_SETTLEMENT_RUNTIME_REPLAY_DOMAIN: &str =
    "monero-l2-pq-private-subaddress-batch-settlement-devnet";
pub const MONERO_L2_PQ_PRIVATE_SUBADDRESS_BATCH_SETTLEMENT_RUNTIME_MAX_BPS: u64 = 10_000;
pub const MONERO_L2_PQ_PRIVATE_SUBADDRESS_BATCH_SETTLEMENT_RUNTIME_DEFAULT_BUCKET_TTL_BLOCKS: u64 =
    144;
pub const MONERO_L2_PQ_PRIVATE_SUBADDRESS_BATCH_SETTLEMENT_RUNTIME_DEFAULT_ATTESTATION_TTL_BLOCKS: u64 = 72;
pub const MONERO_L2_PQ_PRIVATE_SUBADDRESS_BATCH_SETTLEMENT_RUNTIME_DEFAULT_MANIFEST_TTL_BLOCKS:
    u64 = 96;
pub const MONERO_L2_PQ_PRIVATE_SUBADDRESS_BATCH_SETTLEMENT_RUNTIME_DEFAULT_SPONSOR_TTL_BLOCKS: u64 =
    18;
pub const MONERO_L2_PQ_PRIVATE_SUBADDRESS_BATCH_SETTLEMENT_RUNTIME_DEFAULT_ANCHOR_WINDOW_BLOCKS:
    u64 = 36;
pub const MONERO_L2_PQ_PRIVATE_SUBADDRESS_BATCH_SETTLEMENT_RUNTIME_DEFAULT_RECEIPT_TTL_BLOCKS: u64 =
    12;
pub const MONERO_L2_PQ_PRIVATE_SUBADDRESS_BATCH_SETTLEMENT_RUNTIME_DEFAULT_MIN_PRIVACY_SET_SIZE:
    u64 = 32_768;
pub const MONERO_L2_PQ_PRIVATE_SUBADDRESS_BATCH_SETTLEMENT_RUNTIME_DEFAULT_BATCH_PRIVACY_SET_SIZE: u64 = 131_072;
pub const MONERO_L2_PQ_PRIVATE_SUBADDRESS_BATCH_SETTLEMENT_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS:
    u16 = 256;
pub const MONERO_L2_PQ_PRIVATE_SUBADDRESS_BATCH_SETTLEMENT_RUNTIME_DEFAULT_MIN_VIEW_QUORUM_BPS:
    u64 = 6_700;
pub const MONERO_L2_PQ_PRIVATE_SUBADDRESS_BATCH_SETTLEMENT_RUNTIME_DEFAULT_MAX_USER_FEE_BPS: u64 =
    20;
pub const MONERO_L2_PQ_PRIVATE_SUBADDRESS_BATCH_SETTLEMENT_RUNTIME_DEFAULT_LOW_FEE_BPS: u64 = 3;
pub const MONERO_L2_PQ_PRIVATE_SUBADDRESS_BATCH_SETTLEMENT_RUNTIME_DEFAULT_DEFI_FEE_BPS: u64 = 8;
pub const MONERO_L2_PQ_PRIVATE_SUBADDRESS_BATCH_SETTLEMENT_RUNTIME_DEFAULT_SPONSOR_COVER_BPS: u64 =
    9_250;
pub const MONERO_L2_PQ_PRIVATE_SUBADDRESS_BATCH_SETTLEMENT_RUNTIME_MAX_BUCKETS: usize = 524_288;
pub const MONERO_L2_PQ_PRIVATE_SUBADDRESS_BATCH_SETTLEMENT_RUNTIME_MAX_ATTESTATIONS: usize =
    1_048_576;
pub const MONERO_L2_PQ_PRIVATE_SUBADDRESS_BATCH_SETTLEMENT_RUNTIME_MAX_MANIFESTS: usize = 524_288;
pub const MONERO_L2_PQ_PRIVATE_SUBADDRESS_BATCH_SETTLEMENT_RUNTIME_MAX_PAYMENT_IDS: usize =
    1_048_576;
pub const MONERO_L2_PQ_PRIVATE_SUBADDRESS_BATCH_SETTLEMENT_RUNTIME_MAX_SPONSOR_RESERVATIONS: usize =
    524_288;
pub const MONERO_L2_PQ_PRIVATE_SUBADDRESS_BATCH_SETTLEMENT_RUNTIME_MAX_RECEIPTS: usize = 524_288;
pub const MONERO_L2_PQ_PRIVATE_SUBADDRESS_BATCH_SETTLEMENT_RUNTIME_MAX_ANCHOR_WINDOWS: usize =
    262_144;
pub const MONERO_L2_PQ_PRIVATE_SUBADDRESS_BATCH_SETTLEMENT_RUNTIME_MAX_SCAN_HINTS: usize =
    1_048_576;
pub const MONERO_L2_PQ_PRIVATE_SUBADDRESS_BATCH_SETTLEMENT_RUNTIME_MAX_NULLIFIER_FENCES: usize =
    1_048_576;
pub const MONERO_L2_PQ_PRIVATE_SUBADDRESS_BATCH_SETTLEMENT_RUNTIME_MAX_SLASHING_EVIDENCE: usize =
    262_144;
pub const MONERO_L2_PQ_PRIVATE_SUBADDRESS_BATCH_SETTLEMENT_RUNTIME_MAX_PUBLIC_RECORDS: usize =
    2_097_152;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementLane {
    LowFee,
    Fast,
    Defi,
    Token,
    SmartContract,
    Emergency,
}

impl SettlementLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LowFee => "low_fee",
            Self::Fast => "fast",
            Self::Defi => "defi",
            Self::Token => "token",
            Self::SmartContract => "smart_contract",
            Self::Emergency => "emergency",
        }
    }

    pub fn fee_bps(self, config: &Config) -> u64 {
        match self {
            Self::LowFee => config.low_fee_bps,
            Self::Defi | Self::Token | Self::SmartContract => config.defi_fee_bps,
            Self::Fast | Self::Emergency => config.max_user_fee_bps,
        }
    }

    pub fn priority_weight(self) -> u64 {
        match self {
            Self::Emergency => 10_000,
            Self::Fast => 9_200,
            Self::SmartContract => 8_800,
            Self::Defi => 8_500,
            Self::Token => 8_000,
            Self::LowFee => 7_200,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BucketStatus {
    Open,
    Attested,
    Manifested,
    Settled,
    Expired,
    Slashed,
}

impl BucketStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Attested => "attested",
            Self::Manifested => "manifested",
            Self::Settled => "settled",
            Self::Expired => "expired",
            Self::Slashed => "slashed",
        }
    }

    pub fn live(self) -> bool {
        matches!(self, Self::Open | Self::Attested | Self::Manifested)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ViewAttestationStatus {
    Submitted,
    Accepted,
    WeakQuorum,
    Superseded,
    Replayed,
    Revoked,
    Expired,
}

impl ViewAttestationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Accepted => "accepted",
            Self::WeakQuorum => "weak_quorum",
            Self::Superseded => "superseded",
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
pub enum ManifestKind {
    Deposit,
    Withdrawal,
    Mixed,
    DefiCall,
    TokenTransfer,
    ContractSettlement,
}

impl ManifestKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Deposit => "deposit",
            Self::Withdrawal => "withdrawal",
            Self::Mixed => "mixed",
            Self::DefiCall => "defi_call",
            Self::TokenTransfer => "token_transfer",
            Self::ContractSettlement => "contract_settlement",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ManifestStatus {
    Draft,
    Anchored,
    SponsorReserved,
    Receipted,
    Settled,
    Reorged,
    Rejected,
    Expired,
}

impl ManifestStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Anchored => "anchored",
            Self::SponsorReserved => "sponsor_reserved",
            Self::Receipted => "receipted",
            Self::Settled => "settled",
            Self::Reorged => "reorged",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }

    pub fn live(self) -> bool {
        !matches!(
            self,
            Self::Settled | Self::Expired | Self::Reorged | Self::Rejected
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorReservationStatus {
    Held,
    Assigned,
    Consumed,
    Released,
    Expired,
    Slashed,
}

impl SponsorReservationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Held => "held",
            Self::Assigned => "assigned",
            Self::Consumed => "consumed",
            Self::Released => "released",
            Self::Expired => "expired",
            Self::Slashed => "slashed",
        }
    }

    pub fn live(self) -> bool {
        matches!(self, Self::Held | Self::Assigned)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnchorWindowStatus {
    Open,
    Finalizing,
    Finalized,
    Reorged,
    Expired,
}

impl AnchorWindowStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Finalizing => "finalizing",
            Self::Finalized => "finalized",
            Self::Reorged => "reorged",
            Self::Expired => "expired",
        }
    }

    pub fn accepts_manifests(self) -> bool {
        matches!(self, Self::Open | Self::Finalizing)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptStatus {
    Issued,
    Confirmed,
    Reorged,
    Challenged,
    Settled,
    Expired,
}

impl ReceiptStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Issued => "issued",
            Self::Confirmed => "confirmed",
            Self::Reorged => "reorged",
            Self::Challenged => "challenged",
            Self::Settled => "settled",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanHintStatus {
    Published,
    Claimed,
    Batched,
    Settled,
    Expired,
}

impl ScanHintStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Published => "published",
            Self::Claimed => "claimed",
            Self::Batched => "batched",
            Self::Settled => "settled",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NullifierFenceStatus {
    Open,
    Locked,
    Consumed,
    Replayed,
    Released,
    Slashed,
}

impl NullifierFenceStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Locked => "locked",
            Self::Consumed => "consumed",
            Self::Replayed => "replayed",
            Self::Released => "released",
            Self::Slashed => "slashed",
        }
    }

    pub fn blocks_replay(self) -> bool {
        matches!(self, Self::Open | Self::Locked | Self::Consumed)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SlashingEvidenceStatus {
    Submitted,
    Accepted,
    Rewarded,
    Rejected,
    Expired,
}

impl SlashingEvidenceStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Accepted => "accepted",
            Self::Rewarded => "rewarded",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
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
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub pq_view_key_suite: String,
    pub bucket_scheme: String,
    pub view_attestation_scheme: String,
    pub manifest_scheme: String,
    pub payment_id_scheme: String,
    pub sponsor_scheme: String,
    pub receipt_scheme: String,
    pub anchor_scheme: String,
    pub scan_hint_scheme: String,
    pub nullifier_scheme: String,
    pub slashing_scheme: String,
    pub replay_domain: String,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub batch_privacy_set_size: u64,
    pub bucket_ttl_blocks: u64,
    pub attestation_ttl_blocks: u64,
    pub manifest_ttl_blocks: u64,
    pub sponsor_ttl_blocks: u64,
    pub anchor_window_blocks: u64,
    pub receipt_ttl_blocks: u64,
    pub min_view_quorum_bps: u64,
    pub max_user_fee_bps: u64,
    pub low_fee_bps: u64,
    pub defi_fee_bps: u64,
    pub sponsor_cover_bps: u64,
    pub max_buckets: usize,
    pub max_attestations: usize,
    pub max_manifests: usize,
    pub max_payment_ids: usize,
    pub max_sponsor_reservations: usize,
    pub max_receipts: usize,
    pub max_anchor_windows: usize,
    pub max_scan_hints: usize,
    pub max_nullifier_fences: usize,
    pub max_slashing_evidence: usize,
    pub max_public_records: usize,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(), monero_network: MONERO_L2_PQ_PRIVATE_SUBADDRESS_BATCH_SETTLEMENT_RUNTIME_DEVNET_MONERO_NETWORK.to_string(), l2_network: MONERO_L2_PQ_PRIVATE_SUBADDRESS_BATCH_SETTLEMENT_RUNTIME_DEVNET_L2_NETWORK.to_string(), asset_id: MONERO_L2_PQ_PRIVATE_SUBADDRESS_BATCH_SETTLEMENT_RUNTIME_DEVNET_ASSET_ID.to_string(), fee_asset_id: MONERO_L2_PQ_PRIVATE_SUBADDRESS_BATCH_SETTLEMENT_RUNTIME_DEVNET_FEE_ASSET_ID.to_string(), protocol_version: PROTOCOL_VERSION.to_string(), schema_version: MONERO_L2_PQ_PRIVATE_SUBADDRESS_BATCH_SETTLEMENT_RUNTIME_SCHEMA_VERSION, hash_suite: MONERO_L2_PQ_PRIVATE_SUBADDRESS_BATCH_SETTLEMENT_RUNTIME_HASH_SUITE.to_string(), pq_view_key_suite: MONERO_L2_PQ_PRIVATE_SUBADDRESS_BATCH_SETTLEMENT_RUNTIME_PQ_VIEW_KEY_SUITE.to_string(), bucket_scheme: MONERO_L2_PQ_PRIVATE_SUBADDRESS_BATCH_SETTLEMENT_RUNTIME_BUCKET_SCHEME.to_string(), view_attestation_scheme: MONERO_L2_PQ_PRIVATE_SUBADDRESS_BATCH_SETTLEMENT_RUNTIME_VIEW_ATTESTATION_SCHEME.to_string(), manifest_scheme: MONERO_L2_PQ_PRIVATE_SUBADDRESS_BATCH_SETTLEMENT_RUNTIME_MANIFEST_SCHEME.to_string(), payment_id_scheme: MONERO_L2_PQ_PRIVATE_SUBADDRESS_BATCH_SETTLEMENT_RUNTIME_PAYMENT_ID_SCHEME.to_string(), sponsor_scheme: MONERO_L2_PQ_PRIVATE_SUBADDRESS_BATCH_SETTLEMENT_RUNTIME_SPONSOR_SCHEME.to_string(), receipt_scheme: MONERO_L2_PQ_PRIVATE_SUBADDRESS_BATCH_SETTLEMENT_RUNTIME_RECEIPT_SCHEME.to_string(), anchor_scheme: MONERO_L2_PQ_PRIVATE_SUBADDRESS_BATCH_SETTLEMENT_RUNTIME_ANCHOR_SCHEME.to_string(), scan_hint_scheme: MONERO_L2_PQ_PRIVATE_SUBADDRESS_BATCH_SETTLEMENT_RUNTIME_SCAN_HINT_SCHEME.to_string(), nullifier_scheme: MONERO_L2_PQ_PRIVATE_SUBADDRESS_BATCH_SETTLEMENT_RUNTIME_NULLIFIER_SCHEME.to_string(), slashing_scheme: MONERO_L2_PQ_PRIVATE_SUBADDRESS_BATCH_SETTLEMENT_RUNTIME_SLASHING_SCHEME.to_string(), replay_domain: MONERO_L2_PQ_PRIVATE_SUBADDRESS_BATCH_SETTLEMENT_RUNTIME_REPLAY_DOMAIN.to_string(), min_pq_security_bits: MONERO_L2_PQ_PRIVATE_SUBADDRESS_BATCH_SETTLEMENT_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS, min_privacy_set_size: MONERO_L2_PQ_PRIVATE_SUBADDRESS_BATCH_SETTLEMENT_RUNTIME_DEFAULT_MIN_PRIVACY_SET_SIZE, batch_privacy_set_size: MONERO_L2_PQ_PRIVATE_SUBADDRESS_BATCH_SETTLEMENT_RUNTIME_DEFAULT_BATCH_PRIVACY_SET_SIZE, bucket_ttl_blocks: MONERO_L2_PQ_PRIVATE_SUBADDRESS_BATCH_SETTLEMENT_RUNTIME_DEFAULT_BUCKET_TTL_BLOCKS, attestation_ttl_blocks: MONERO_L2_PQ_PRIVATE_SUBADDRESS_BATCH_SETTLEMENT_RUNTIME_DEFAULT_ATTESTATION_TTL_BLOCKS, manifest_ttl_blocks: MONERO_L2_PQ_PRIVATE_SUBADDRESS_BATCH_SETTLEMENT_RUNTIME_DEFAULT_MANIFEST_TTL_BLOCKS, sponsor_ttl_blocks: MONERO_L2_PQ_PRIVATE_SUBADDRESS_BATCH_SETTLEMENT_RUNTIME_DEFAULT_SPONSOR_TTL_BLOCKS, anchor_window_blocks: MONERO_L2_PQ_PRIVATE_SUBADDRESS_BATCH_SETTLEMENT_RUNTIME_DEFAULT_ANCHOR_WINDOW_BLOCKS, receipt_ttl_blocks: MONERO_L2_PQ_PRIVATE_SUBADDRESS_BATCH_SETTLEMENT_RUNTIME_DEFAULT_RECEIPT_TTL_BLOCKS, min_view_quorum_bps: MONERO_L2_PQ_PRIVATE_SUBADDRESS_BATCH_SETTLEMENT_RUNTIME_DEFAULT_MIN_VIEW_QUORUM_BPS, max_user_fee_bps: MONERO_L2_PQ_PRIVATE_SUBADDRESS_BATCH_SETTLEMENT_RUNTIME_DEFAULT_MAX_USER_FEE_BPS, low_fee_bps: MONERO_L2_PQ_PRIVATE_SUBADDRESS_BATCH_SETTLEMENT_RUNTIME_DEFAULT_LOW_FEE_BPS, defi_fee_bps: MONERO_L2_PQ_PRIVATE_SUBADDRESS_BATCH_SETTLEMENT_RUNTIME_DEFAULT_DEFI_FEE_BPS, sponsor_cover_bps: MONERO_L2_PQ_PRIVATE_SUBADDRESS_BATCH_SETTLEMENT_RUNTIME_DEFAULT_SPONSOR_COVER_BPS, max_buckets: MONERO_L2_PQ_PRIVATE_SUBADDRESS_BATCH_SETTLEMENT_RUNTIME_MAX_BUCKETS, max_attestations: MONERO_L2_PQ_PRIVATE_SUBADDRESS_BATCH_SETTLEMENT_RUNTIME_MAX_ATTESTATIONS, max_manifests: MONERO_L2_PQ_PRIVATE_SUBADDRESS_BATCH_SETTLEMENT_RUNTIME_MAX_MANIFESTS, max_payment_ids: MONERO_L2_PQ_PRIVATE_SUBADDRESS_BATCH_SETTLEMENT_RUNTIME_MAX_PAYMENT_IDS, max_sponsor_reservations: MONERO_L2_PQ_PRIVATE_SUBADDRESS_BATCH_SETTLEMENT_RUNTIME_MAX_SPONSOR_RESERVATIONS, max_receipts: MONERO_L2_PQ_PRIVATE_SUBADDRESS_BATCH_SETTLEMENT_RUNTIME_MAX_RECEIPTS, max_anchor_windows: MONERO_L2_PQ_PRIVATE_SUBADDRESS_BATCH_SETTLEMENT_RUNTIME_MAX_ANCHOR_WINDOWS, max_scan_hints: MONERO_L2_PQ_PRIVATE_SUBADDRESS_BATCH_SETTLEMENT_RUNTIME_MAX_SCAN_HINTS, max_nullifier_fences: MONERO_L2_PQ_PRIVATE_SUBADDRESS_BATCH_SETTLEMENT_RUNTIME_MAX_NULLIFIER_FENCES, max_slashing_evidence: MONERO_L2_PQ_PRIVATE_SUBADDRESS_BATCH_SETTLEMENT_RUNTIME_MAX_SLASHING_EVIDENCE, max_public_records: MONERO_L2_PQ_PRIVATE_SUBADDRESS_BATCH_SETTLEMENT_RUNTIME_MAX_PUBLIC_RECORDS,
        }
    }

    pub fn validate(&self) -> Result<()> {
        ensure_nonempty("chain_id", &self.chain_id)?;
        ensure_nonempty("asset_id", &self.asset_id)?;
        ensure_nonempty("fee_asset_id", &self.fee_asset_id)?;
        if self.min_pq_security_bits < 192 {
            return Err("min_pq_security_bits must be at least 192".to_string());
        }
        if self.min_view_quorum_bps
            > MONERO_L2_PQ_PRIVATE_SUBADDRESS_BATCH_SETTLEMENT_RUNTIME_MAX_BPS
        {
            return Err("min_view_quorum_bps exceeds max bps".to_string());
        }
        if self.max_user_fee_bps > MONERO_L2_PQ_PRIVATE_SUBADDRESS_BATCH_SETTLEMENT_RUNTIME_MAX_BPS
        {
            return Err("max_user_fee_bps exceeds max bps".to_string());
        }
        if self.low_fee_bps > self.max_user_fee_bps {
            return Err("low_fee_bps exceeds max_user_fee_bps".to_string());
        }
        if self.defi_fee_bps > self.max_user_fee_bps {
            return Err("defi_fee_bps exceeds max_user_fee_bps".to_string());
        }
        if self.sponsor_cover_bps > MONERO_L2_PQ_PRIVATE_SUBADDRESS_BATCH_SETTLEMENT_RUNTIME_MAX_BPS
        {
            return Err("sponsor_cover_bps exceeds max bps".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "monero_l2_pq_private_subaddress_batch_settlement:config",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Counters {
    pub buckets: usize,
    pub attestations: usize,
    pub manifests: usize,
    pub payment_ids: usize,
    pub sponsor_reservations: usize,
    pub receipts: usize,
    pub anchor_windows: usize,
    pub scan_hints: usize,
    pub nullifier_fences: usize,
    pub slashing_evidence: usize,
    pub public_records: usize,
    pub events: usize,
}
impl Counters {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn state_root(&self) -> String {
        domain_hash(
            "monero_l2_pq_private_subaddress_batch_settlement:counters",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Roots {
    pub config_root: String,
    pub counters_root: String,
    pub bucket_root: String,
    pub view_attestation_root: String,
    pub manifest_root: String,
    pub payment_id_root: String,
    pub sponsor_reservation_root: String,
    pub receipt_root: String,
    pub anchor_window_root: String,
    pub scan_hint_root: String,
    pub nullifier_fence_root: String,
    pub slashing_evidence_root: String,
    pub public_record_root: String,
    pub event_root: String,
}
impl Roots {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn state_root(&self) -> String {
        domain_hash(
            "monero_l2_pq_private_subaddress_batch_settlement:roots",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncryptedSubaddressBucket {
    pub bucket_id: String,
    pub status: BucketStatus,
    pub owner_view_commitment: String,
    pub encrypted_subaddress_bundle: String,
    pub bucket_ciphertext_root: String,
    pub bucket_tag_root: String,
    pub decoy_set_root: String,
    pub anchor_window_id: String,
    pub lane: SettlementLane,
    pub opened_height: u64,
    pub expires_height: u64,
    pub subaddress_count: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub sponsor_reservation_id: Option<String>,
    pub attestation_id: Option<String>,
    pub manifest_id: Option<String>,
}

impl EncryptedSubaddressBucket {
    pub fn public_record(&self) -> Value {
        json!({
            "bucket_id": self.bucket_id,
            "status": self.status.as_str(),
            "owner_view_commitment": self.owner_view_commitment,
            "encrypted_subaddress_bundle": self.encrypted_subaddress_bundle,
            "bucket_ciphertext_root": self.bucket_ciphertext_root,
            "bucket_tag_root": self.bucket_tag_root,
            "decoy_set_root": self.decoy_set_root,
            "anchor_window_id": self.anchor_window_id,
            "lane": self.lane.as_str(),
            "opened_height": self.opened_height,
            "expires_height": self.expires_height,
            "subaddress_count": self.subaddress_count,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "sponsor_reservation_id": self.sponsor_reservation_id,
            "attestation_id": self.attestation_id,
            "manifest_id": self.manifest_id,
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "monero_l2_pq_private_subaddress_batch_settlement:EncryptedSubaddressBucket",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PqViewKeyAttestation {
    pub attestation_id: String,
    pub status: ViewAttestationStatus,
    pub bucket_id: String,
    pub attestor_id: String,
    pub view_key_commitment: String,
    pub pq_public_key_root: String,
    pub signature_root: String,
    pub quorum_bps: u64,
    pub security_bits: u16,
    pub created_height: u64,
    pub expires_height: u64,
    pub nullifier: String,
}

impl PqViewKeyAttestation {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "status": self.status.as_str(),
            "bucket_id": self.bucket_id,
            "attestor_id": self.attestor_id,
            "view_key_commitment": self.view_key_commitment,
            "pq_public_key_root": self.pq_public_key_root,
            "signature_root": self.signature_root,
            "quorum_bps": self.quorum_bps,
            "security_bits": self.security_bits,
            "created_height": self.created_height,
            "expires_height": self.expires_height,
            "nullifier": self.nullifier,
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "monero_l2_pq_private_subaddress_batch_settlement:PqViewKeyAttestation",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BatchSettlementManifest {
    pub manifest_id: String,
    pub status: ManifestStatus,
    pub kind: ManifestKind,
    pub lane: SettlementLane,
    pub bucket_ids: Vec<String>,
    pub deposit_note_root: String,
    pub withdrawal_note_root: String,
    pub private_payment_id_root: String,
    pub anchor_window_id: String,
    pub sponsor_reservation_id: Option<String>,
    pub total_input_piconero: u128,
    pub total_output_piconero: u128,
    pub fee_piconero: u128,
    pub privacy_set_size: u64,
    pub created_height: u64,
    pub expires_height: u64,
    pub receipt_id: Option<String>,
}

impl BatchSettlementManifest {
    pub fn public_record(&self) -> Value {
        json!({
            "manifest_id": self.manifest_id,
            "status": self.status.as_str(),
            "kind": self.kind.as_str(),
            "lane": self.lane.as_str(),
            "bucket_ids": self.bucket_ids,
            "deposit_note_root": self.deposit_note_root,
            "withdrawal_note_root": self.withdrawal_note_root,
            "private_payment_id_root": self.private_payment_id_root,
            "anchor_window_id": self.anchor_window_id,
            "sponsor_reservation_id": self.sponsor_reservation_id,
            "total_input_piconero": self.total_input_piconero,
            "total_output_piconero": self.total_output_piconero,
            "fee_piconero": self.fee_piconero,
            "privacy_set_size": self.privacy_set_size,
            "created_height": self.created_height,
            "expires_height": self.expires_height,
            "receipt_id": self.receipt_id,
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "monero_l2_pq_private_subaddress_batch_settlement:BatchSettlementManifest",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrivatePaymentIdCommitment {
    pub payment_id: String,
    pub status: NullifierFenceStatus,
    pub manifest_id: String,
    pub bucket_id: String,
    pub encrypted_payment_id: String,
    pub payment_id_commitment: String,
    pub recipient_hint: String,
    pub asset_id: String,
    pub amount_commitment: String,
    pub created_height: u64,
}

impl PrivatePaymentIdCommitment {
    pub fn public_record(&self) -> Value {
        json!({
            "payment_id": self.payment_id,
            "status": self.status.as_str(),
            "manifest_id": self.manifest_id,
            "bucket_id": self.bucket_id,
            "encrypted_payment_id": self.encrypted_payment_id,
            "payment_id_commitment": self.payment_id_commitment,
            "recipient_hint": self.recipient_hint,
            "asset_id": self.asset_id,
            "amount_commitment": self.amount_commitment,
            "created_height": self.created_height,
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "monero_l2_pq_private_subaddress_batch_settlement:PrivatePaymentIdCommitment",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LowFeeSponsorReservation {
    pub reservation_id: String,
    pub status: SponsorReservationStatus,
    pub sponsor_id: String,
    pub lane: SettlementLane,
    pub reserved_fee_piconero: u128,
    pub covered_fee_bps: u64,
    pub manifest_id: Option<String>,
    pub bucket_id: Option<String>,
    pub created_height: u64,
    pub expires_height: u64,
    pub consumed_height: Option<u64>,
}

impl LowFeeSponsorReservation {
    pub fn public_record(&self) -> Value {
        json!({
            "reservation_id": self.reservation_id,
            "status": self.status.as_str(),
            "sponsor_id": self.sponsor_id,
            "lane": self.lane.as_str(),
            "reserved_fee_piconero": self.reserved_fee_piconero,
            "covered_fee_bps": self.covered_fee_bps,
            "manifest_id": self.manifest_id,
            "bucket_id": self.bucket_id,
            "created_height": self.created_height,
            "expires_height": self.expires_height,
            "consumed_height": self.consumed_height,
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "monero_l2_pq_private_subaddress_batch_settlement:LowFeeSponsorReservation",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FastSettlementReceipt {
    pub receipt_id: String,
    pub status: ReceiptStatus,
    pub manifest_id: String,
    pub anchor_window_id: String,
    pub settlement_root: String,
    pub receipt_ciphertext: String,
    pub sequencer_id: String,
    pub issued_height: u64,
    pub expires_height: u64,
    pub confirmation_height: Option<u64>,
    pub fee_piconero: u128,
}

impl FastSettlementReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "status": self.status.as_str(),
            "manifest_id": self.manifest_id,
            "anchor_window_id": self.anchor_window_id,
            "settlement_root": self.settlement_root,
            "receipt_ciphertext": self.receipt_ciphertext,
            "sequencer_id": self.sequencer_id,
            "issued_height": self.issued_height,
            "expires_height": self.expires_height,
            "confirmation_height": self.confirmation_height,
            "fee_piconero": self.fee_piconero,
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "monero_l2_pq_private_subaddress_batch_settlement:FastSettlementReceipt",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReorgSafeAnchorWindow {
    pub anchor_window_id: String,
    pub status: AnchorWindowStatus,
    pub monero_start_height: u64,
    pub monero_end_height: u64,
    pub l2_start_height: u64,
    pub l2_end_height: u64,
    pub anchor_block_hash_root: String,
    pub finality_depth: u64,
    pub created_height: u64,
    pub expires_height: u64,
    pub manifest_root: String,
}

impl ReorgSafeAnchorWindow {
    pub fn public_record(&self) -> Value {
        json!({
            "anchor_window_id": self.anchor_window_id,
            "status": self.status.as_str(),
            "monero_start_height": self.monero_start_height,
            "monero_end_height": self.monero_end_height,
            "l2_start_height": self.l2_start_height,
            "l2_end_height": self.l2_end_height,
            "anchor_block_hash_root": self.anchor_block_hash_root,
            "finality_depth": self.finality_depth,
            "created_height": self.created_height,
            "expires_height": self.expires_height,
            "manifest_root": self.manifest_root,
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "monero_l2_pq_private_subaddress_batch_settlement:ReorgSafeAnchorWindow",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WalletScanHint {
    pub scan_hint_id: String,
    pub status: ScanHintStatus,
    pub bucket_id: String,
    pub manifest_id: Option<String>,
    pub view_tag_prefix: String,
    pub encrypted_hint: String,
    pub hint_key_commitment: String,
    pub recipient_domain: String,
    pub created_height: u64,
    pub expires_height: u64,
    pub lane: SettlementLane,
}

impl WalletScanHint {
    pub fn public_record(&self) -> Value {
        json!({
            "scan_hint_id": self.scan_hint_id,
            "status": self.status.as_str(),
            "bucket_id": self.bucket_id,
            "manifest_id": self.manifest_id,
            "view_tag_prefix": self.view_tag_prefix,
            "encrypted_hint": self.encrypted_hint,
            "hint_key_commitment": self.hint_key_commitment,
            "recipient_domain": self.recipient_domain,
            "created_height": self.created_height,
            "expires_height": self.expires_height,
            "lane": self.lane.as_str(),
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "monero_l2_pq_private_subaddress_batch_settlement:WalletScanHint",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NullifierFence {
    pub nullifier: String,
    pub status: NullifierFenceStatus,
    pub source_id: String,
    pub source_kind: String,
    pub fence_root: String,
    pub created_height: u64,
    pub locked_until_height: u64,
    pub spent_height: Option<u64>,
}

impl NullifierFence {
    pub fn public_record(&self) -> Value {
        json!({
            "nullifier": self.nullifier,
            "status": self.status.as_str(),
            "source_id": self.source_id,
            "source_kind": self.source_kind,
            "fence_root": self.fence_root,
            "created_height": self.created_height,
            "locked_until_height": self.locked_until_height,
            "spent_height": self.spent_height,
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "monero_l2_pq_private_subaddress_batch_settlement:NullifierFence",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SlashingEvidence {
    pub evidence_id: String,
    pub status: SlashingEvidenceStatus,
    pub accused_id: String,
    pub source_id: String,
    pub source_kind: String,
    pub evidence_root: String,
    pub penalty_piconero: u128,
    pub reward_piconero: u128,
    pub created_height: u64,
    pub resolved_height: Option<u64>,
}

impl SlashingEvidence {
    pub fn public_record(&self) -> Value {
        json!({
            "evidence_id": self.evidence_id,
            "status": self.status.as_str(),
            "accused_id": self.accused_id,
            "source_id": self.source_id,
            "source_kind": self.source_kind,
            "evidence_root": self.evidence_root,
            "penalty_piconero": self.penalty_piconero,
            "reward_piconero": self.reward_piconero,
            "created_height": self.created_height,
            "resolved_height": self.resolved_height,
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "monero_l2_pq_private_subaddress_batch_settlement:SlashingEvidence",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RuntimeEvent {
    pub event_id: String,
    pub status: String,
    pub event_type: String,
    pub subject_id: String,
    pub height: u64,
    pub sequence: u64,
    pub payload: Value,
}

impl RuntimeEvent {
    pub fn public_record(&self) -> Value {
        json!({
            "event_id": self.event_id,
            "status": self.status,
            "event_type": self.event_type,
            "subject_id": self.subject_id,
            "height": self.height,
            "sequence": self.sequence,
            "payload": self.payload,
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "monero_l2_pq_private_subaddress_batch_settlement:RuntimeEvent",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub height: u64,
    pub buckets: BTreeMap<String, EncryptedSubaddressBucket>,
    pub attestations: BTreeMap<String, PqViewKeyAttestation>,
    pub manifests: BTreeMap<String, BatchSettlementManifest>,
    pub payment_ids: BTreeMap<String, PrivatePaymentIdCommitment>,
    pub sponsor_reservations: BTreeMap<String, LowFeeSponsorReservation>,
    pub receipts: BTreeMap<String, FastSettlementReceipt>,
    pub anchor_windows: BTreeMap<String, ReorgSafeAnchorWindow>,
    pub scan_hints: BTreeMap<String, WalletScanHint>,
    pub nullifier_fences: BTreeMap<String, NullifierFence>,
    pub slashing_evidence: BTreeMap<String, SlashingEvidence>,
    pub public_records: BTreeMap<String, Value>,
    pub events: Vec<RuntimeEvent>,
}

pub type Runtime = State;

impl State {
    pub fn devnet() -> Self {
        let config = Config::devnet();
        let height = MONERO_L2_PQ_PRIVATE_SUBADDRESS_BATCH_SETTLEMENT_RUNTIME_DEVNET_HEIGHT;
        let mut state = Self {
            config,
            height,
            buckets: BTreeMap::new(),
            attestations: BTreeMap::new(),
            manifests: BTreeMap::new(),
            payment_ids: BTreeMap::new(),
            sponsor_reservations: BTreeMap::new(),
            receipts: BTreeMap::new(),
            anchor_windows: BTreeMap::new(),
            scan_hints: BTreeMap::new(),
            nullifier_fences: BTreeMap::new(),
            slashing_evidence: BTreeMap::new(),
            public_records: BTreeMap::new(),
            events: Vec::new(),
        };
        let anchor = state.derive_anchor_window(
            "devnet-anchor-window-0",
            height.saturating_sub(12),
            height.saturating_add(24),
        );
        let _ = state.insert_anchor_window(anchor);
        let reservation = state.derive_sponsor_reservation(
            "devnet-sponsor-0",
            SettlementLane::LowFee,
            2_500_000,
            height,
        );
        let _ = state.reserve_sponsor(reservation);
        let bucket = state.derive_bucket(
            "devnet-wallet-view-commitment",
            "devnet-encrypted-subaddress-bundle",
            "devnet-anchor-window-0",
            SettlementLane::LowFee,
            64,
        );
        let bucket_id = bucket.bucket_id.clone();
        let _ = state.open_bucket(bucket);
        let attestation =
            state.derive_view_attestation(&bucket_id, "devnet-view-attestor-0", 7_200);
        let _ = state.submit_view_attestation(attestation);
        let hint = state.derive_scan_hint(&bucket_id, None, "7f", SettlementLane::LowFee);
        let _ = state.publish_scan_hint(hint);
        state
    }

    pub fn validate_config(&self) -> Result<()> {
        self.config.validate()
    }
    pub fn advance_height(&mut self, height: u64) -> Result<()> {
        if height < self.height {
            return Err("height cannot move backwards".to_string());
        }
        self.height = height;
        self.expire_stale_records();
        Ok(())
    }
    pub fn derive_anchor_window(
        &self,
        seed: &str,
        monero_start_height: u64,
        monero_end_height: u64,
    ) -> ReorgSafeAnchorWindow {
        let anchor_window_id = deterministic_id(
            "anchor_window",
            &[
                HashPart::Str(seed),
                HashPart::U64(monero_start_height),
                HashPart::U64(monero_end_height),
            ],
        );
        ReorgSafeAnchorWindow {
            anchor_window_id,
            status: AnchorWindowStatus::Open,
            monero_start_height,
            monero_end_height,
            l2_start_height: self.height,
            l2_end_height: self.height.saturating_add(self.config.anchor_window_blocks),
            anchor_block_hash_root: deterministic_id(
                "anchor_block_hash_root",
                &[HashPart::Str(seed)],
            ),
            finality_depth: self.config.anchor_window_blocks,
            created_height: self.height,
            expires_height: self.height.saturating_add(self.config.anchor_window_blocks),
            manifest_root: public_record_root("empty_anchor_manifest", &[]),
        }
    }
    pub fn derive_sponsor_reservation(
        &self,
        sponsor_id: &str,
        lane: SettlementLane,
        reserved_fee_piconero: u128,
        created_height: u64,
    ) -> LowFeeSponsorReservation {
        let reservation_id = deterministic_id(
            "sponsor_reservation",
            &[
                HashPart::Str(sponsor_id),
                HashPart::Str(lane.as_str()),
                HashPart::Int(reserved_fee_piconero as i128),
                HashPart::U64(created_height),
            ],
        );
        LowFeeSponsorReservation {
            reservation_id,
            status: SponsorReservationStatus::Held,
            sponsor_id: sponsor_id.to_string(),
            lane,
            reserved_fee_piconero,
            covered_fee_bps: self.config.sponsor_cover_bps,
            manifest_id: None,
            bucket_id: None,
            created_height,
            expires_height: created_height.saturating_add(self.config.sponsor_ttl_blocks),
            consumed_height: None,
        }
    }
    pub fn derive_bucket(
        &self,
        owner_view_commitment: &str,
        encrypted_subaddress_bundle: &str,
        anchor_window_id: &str,
        lane: SettlementLane,
        subaddress_count: u64,
    ) -> EncryptedSubaddressBucket {
        let bucket_id = deterministic_id(
            "encrypted_subaddress_bucket",
            &[
                HashPart::Str(owner_view_commitment),
                HashPart::Str(encrypted_subaddress_bundle),
                HashPart::Str(anchor_window_id),
                HashPart::U64(subaddress_count),
            ],
        );
        EncryptedSubaddressBucket {
            bucket_id,
            status: BucketStatus::Open,
            owner_view_commitment: owner_view_commitment.to_string(),
            encrypted_subaddress_bundle: encrypted_subaddress_bundle.to_string(),
            bucket_ciphertext_root: deterministic_id(
                "bucket_ciphertext_root",
                &[HashPart::Str(encrypted_subaddress_bundle)],
            ),
            bucket_tag_root: deterministic_id(
                "bucket_tag_root",
                &[HashPart::Str(owner_view_commitment)],
            ),
            decoy_set_root: deterministic_id(
                "bucket_decoy_set_root",
                &[HashPart::Str(anchor_window_id)],
            ),
            anchor_window_id: anchor_window_id.to_string(),
            lane,
            opened_height: self.height,
            expires_height: self.height.saturating_add(self.config.bucket_ttl_blocks),
            subaddress_count,
            privacy_set_size: self.config.batch_privacy_set_size,
            pq_security_bits: self.config.min_pq_security_bits,
            sponsor_reservation_id: None,
            attestation_id: None,
            manifest_id: None,
        }
    }
    pub fn derive_view_attestation(
        &self,
        bucket_id: &str,
        attestor_id: &str,
        quorum_bps: u64,
    ) -> PqViewKeyAttestation {
        let nullifier = deterministic_id(
            "view_attestation_nullifier",
            &[HashPart::Str(bucket_id), HashPart::Str(attestor_id)],
        );
        PqViewKeyAttestation {
            attestation_id: deterministic_id("view_attestation", &[HashPart::Str(&nullifier)]),
            status: ViewAttestationStatus::Submitted,
            bucket_id: bucket_id.to_string(),
            attestor_id: attestor_id.to_string(),
            view_key_commitment: deterministic_id(
                "view_key_commitment",
                &[HashPart::Str(bucket_id)],
            ),
            pq_public_key_root: deterministic_id(
                "pq_public_key_root",
                &[HashPart::Str(attestor_id)],
            ),
            signature_root: deterministic_id("view_signature_root", &[HashPart::Str(&nullifier)]),
            quorum_bps,
            security_bits: self.config.min_pq_security_bits,
            created_height: self.height,
            expires_height: self
                .height
                .saturating_add(self.config.attestation_ttl_blocks),
            nullifier,
        }
    }
    pub fn derive_scan_hint(
        &self,
        bucket_id: &str,
        manifest_id: Option<String>,
        view_tag_prefix: &str,
        lane: SettlementLane,
    ) -> WalletScanHint {
        WalletScanHint {
            scan_hint_id: deterministic_id(
                "wallet_scan_hint",
                &[HashPart::Str(bucket_id), HashPart::Str(view_tag_prefix)],
            ),
            status: ScanHintStatus::Published,
            bucket_id: bucket_id.to_string(),
            manifest_id,
            view_tag_prefix: view_tag_prefix.to_string(),
            encrypted_hint: deterministic_id("encrypted_scan_hint", &[HashPart::Str(bucket_id)]),
            hint_key_commitment: deterministic_id(
                "scan_hint_key",
                &[HashPart::Str(view_tag_prefix)],
            ),
            recipient_domain: self.config.replay_domain.clone(),
            created_height: self.height,
            expires_height: self.height.saturating_add(self.config.bucket_ttl_blocks),
            lane,
        }
    }
    pub fn build_manifest(
        &self,
        kind: ManifestKind,
        lane: SettlementLane,
        bucket_ids: Vec<String>,
        anchor_window_id: &str,
        total_input_piconero: u128,
        total_output_piconero: u128,
    ) -> Result<BatchSettlementManifest> {
        if bucket_ids.is_empty() {
            return Err("manifest must include at least one bucket".to_string());
        }
        let fee_piconero = total_input_piconero.saturating_sub(total_output_piconero);
        let bucket_records = bucket_ids.iter().map(|id| json!(id)).collect::<Vec<_>>();
        let manifest_id = deterministic_id(
            "batch_settlement_manifest",
            &[
                HashPart::Str(kind.as_str()),
                HashPart::Str(lane.as_str()),
                HashPart::Json(&json!(bucket_ids)),
                HashPart::Str(anchor_window_id),
            ],
        );
        Ok(BatchSettlementManifest {
            manifest_id,
            status: ManifestStatus::Draft,
            kind,
            lane,
            bucket_ids,
            deposit_note_root: merkle_root("manifest_deposit_notes", &bucket_records),
            withdrawal_note_root: merkle_root("manifest_withdrawal_notes", &bucket_records),
            private_payment_id_root: public_record_root("manifest_payment_ids", &[]),
            anchor_window_id: anchor_window_id.to_string(),
            sponsor_reservation_id: None,
            total_input_piconero,
            total_output_piconero,
            fee_piconero,
            privacy_set_size: self.config.batch_privacy_set_size,
            created_height: self.height,
            expires_height: self.height.saturating_add(self.config.manifest_ttl_blocks),
            receipt_id: None,
        })
    }
    pub fn insert_anchor_window(&mut self, window: ReorgSafeAnchorWindow) -> Result<String> {
        self.validate_anchor_window(&window)?;
        ensure_capacity(
            self.anchor_windows.len(),
            self.config.max_anchor_windows,
            "anchor_windows",
        )?;
        let id = window.anchor_window_id.clone();
        if self.anchor_windows.contains_key(&id) {
            return Err(format!("anchor window already exists: {id}"));
        }
        self.record_public(format!("anchor_window:{id}"), window.public_record())?;
        self.anchor_windows.insert(id.clone(), window);
        self.push_event("anchor_window_opened", &id, json!({"anchor_window_id": id}))?;
        Ok(id)
    }
    pub fn reserve_sponsor(&mut self, reservation: LowFeeSponsorReservation) -> Result<String> {
        self.validate_sponsor_reservation(&reservation)?;
        ensure_capacity(
            self.sponsor_reservations.len(),
            self.config.max_sponsor_reservations,
            "sponsor_reservations",
        )?;
        let id = reservation.reservation_id.clone();
        if self.sponsor_reservations.contains_key(&id) {
            return Err(format!("sponsor reservation already exists: {id}"));
        }
        self.record_public(
            format!("sponsor_reservation:{id}"),
            reservation.public_record(),
        )?;
        self.sponsor_reservations.insert(id.clone(), reservation);
        self.push_event("sponsor_reserved", &id, json!({"reservation_id": id}))?;
        Ok(id)
    }
    pub fn open_bucket(&mut self, bucket: EncryptedSubaddressBucket) -> Result<String> {
        self.validate_bucket(&bucket)?;
        ensure_capacity(self.buckets.len(), self.config.max_buckets, "buckets")?;
        if !self.anchor_windows.contains_key(&bucket.anchor_window_id) {
            return Err(format!(
                "missing anchor window: {}",
                bucket.anchor_window_id
            ));
        }
        let id = bucket.bucket_id.clone();
        if self.buckets.contains_key(&id) {
            return Err(format!("bucket already exists: {id}"));
        }
        self.record_public(format!("bucket:{id}"), bucket.public_record())?;
        self.buckets.insert(id.clone(), bucket);
        self.push_event(
            "encrypted_subaddress_bucket_opened",
            &id,
            json!({"bucket_id": id}),
        )?;
        Ok(id)
    }
    pub fn submit_view_attestation(&mut self, attestation: PqViewKeyAttestation) -> Result<String> {
        self.validate_view_attestation(&attestation)?;
        ensure_capacity(
            self.attestations.len(),
            self.config.max_attestations,
            "attestations",
        )?;
        if self.nullifier_fences.contains_key(&attestation.nullifier) {
            return Err(format!(
                "view attestation replay: {}",
                attestation.nullifier
            ));
        }
        let id = attestation.attestation_id.clone();
        let bucket_id = attestation.bucket_id.clone();
        if !self.buckets.contains_key(&bucket_id) {
            return Err(format!("missing bucket: {bucket_id}"));
        }
        let accepted = attestation.quorum_bps >= self.config.min_view_quorum_bps;
        let mut stored = attestation;
        stored.status = if accepted {
            ViewAttestationStatus::Accepted
        } else {
            ViewAttestationStatus::WeakQuorum
        };
        if let Some(bucket) = self.buckets.get_mut(&bucket_id) {
            if accepted {
                bucket.status = BucketStatus::Attested;
                bucket.attestation_id = Some(id.clone());
            }
            let record = bucket.public_record();
            self.record_public(format!("bucket:{bucket_id}"), record)?;
        }
        let fence = NullifierFence {
            nullifier: stored.nullifier.clone(),
            status: NullifierFenceStatus::Locked,
            source_id: id.clone(),
            source_kind: "view_attestation".to_string(),
            fence_root: stored.state_root(),
            created_height: self.height,
            locked_until_height: stored.expires_height,
            spent_height: None,
        };
        self.nullifier_fences
            .insert(fence.nullifier.clone(), fence.clone());
        self.record_public(
            format!("nullifier_fence:{}", fence.nullifier),
            fence.public_record(),
        )?;
        self.record_public(format!("view_attestation:{id}"), stored.public_record())?;
        self.attestations.insert(id.clone(), stored);
        self.push_event(
            "pq_view_key_attested",
            &id,
            json!({"attestation_id": id, "accepted": accepted}),
        )?;
        Ok(id)
    }
    pub fn attach_sponsor_to_bucket(
        &mut self,
        bucket_id: &str,
        reservation_id: &str,
    ) -> Result<()> {
        let reservation_record;
        {
            let reservation = self
                .sponsor_reservations
                .get_mut(reservation_id)
                .ok_or_else(|| format!("missing reservation: {reservation_id}"))?;
            if !reservation.status.live() {
                return Err(format!("reservation is not live: {reservation_id}"));
            }
            if reservation.expires_height < self.height {
                reservation.status = SponsorReservationStatus::Expired;
                return Err(format!("reservation expired: {reservation_id}"));
            }
            reservation.status = SponsorReservationStatus::Assigned;
            reservation.bucket_id = Some(bucket_id.to_string());
            reservation_record = reservation.public_record();
        }
        let bucket_record;
        {
            let bucket = self
                .buckets
                .get_mut(bucket_id)
                .ok_or_else(|| format!("missing bucket: {bucket_id}"))?;
            if !bucket.status.live() {
                return Err(format!("bucket is not live: {bucket_id}"));
            }
            bucket.sponsor_reservation_id = Some(reservation_id.to_string());
            bucket_record = bucket.public_record();
        }
        self.record_public(
            format!("sponsor_reservation:{reservation_id}"),
            reservation_record,
        )?;
        self.record_public(format!("bucket:{bucket_id}"), bucket_record)?;
        self.push_event(
            "sponsor_attached_to_bucket",
            bucket_id,
            json!({"bucket_id": bucket_id, "reservation_id": reservation_id}),
        )
    }
    pub fn publish_scan_hint(&mut self, hint: WalletScanHint) -> Result<String> {
        ensure_capacity(
            self.scan_hints.len(),
            self.config.max_scan_hints,
            "scan_hints",
        )?;
        if !self.buckets.contains_key(&hint.bucket_id) {
            return Err(format!("missing bucket: {}", hint.bucket_id));
        }
        let id = hint.scan_hint_id.clone();
        self.record_public(format!("scan_hint:{id}"), hint.public_record())?;
        self.scan_hints.insert(id.clone(), hint);
        self.push_event(
            "wallet_scan_hint_published",
            &id,
            json!({"scan_hint_id": id}),
        )?;
        Ok(id)
    }
    pub fn commit_payment_id(&mut self, payment_id: PrivatePaymentIdCommitment) -> Result<String> {
        ensure_capacity(
            self.payment_ids.len(),
            self.config.max_payment_ids,
            "payment_ids",
        )?;
        if self.payment_ids.contains_key(&payment_id.payment_id) {
            return Err(format!(
                "payment id already exists: {}",
                payment_id.payment_id
            ));
        }
        if !self.buckets.contains_key(&payment_id.bucket_id) {
            return Err(format!("missing bucket: {}", payment_id.bucket_id));
        }
        if !self.manifests.contains_key(&payment_id.manifest_id) {
            return Err(format!("missing manifest: {}", payment_id.manifest_id));
        }
        let id = payment_id.payment_id.clone();
        self.record_public(format!("payment_id:{id}"), payment_id.public_record())?;
        self.payment_ids.insert(id.clone(), payment_id);
        self.push_event(
            "private_payment_id_committed",
            &id,
            json!({"payment_id": id}),
        )?;
        Ok(id)
    }
    pub fn anchor_manifest(&mut self, mut manifest: BatchSettlementManifest) -> Result<String> {
        self.validate_manifest(&manifest)?;
        ensure_capacity(self.manifests.len(), self.config.max_manifests, "manifests")?;
        let window = self
            .anchor_windows
            .get(&manifest.anchor_window_id)
            .ok_or_else(|| format!("missing anchor window: {}", manifest.anchor_window_id))?;
        if !window.status.accepts_manifests() {
            return Err(format!(
                "anchor window does not accept manifests: {}",
                manifest.anchor_window_id
            ));
        }
        let id = manifest.manifest_id.clone();
        if self.manifests.contains_key(&id) {
            return Err(format!("manifest already exists: {id}"));
        }
        for bucket_id in &manifest.bucket_ids {
            let bucket = self
                .buckets
                .get(bucket_id)
                .ok_or_else(|| format!("missing bucket: {bucket_id}"))?;
            if !matches!(bucket.status, BucketStatus::Attested | BucketStatus::Open) {
                return Err(format!("bucket cannot be manifested: {bucket_id}"));
            }
        }
        manifest.status = ManifestStatus::Anchored;
        for bucket_id in &manifest.bucket_ids {
            if let Some(bucket) = self.buckets.get_mut(bucket_id) {
                bucket.status = BucketStatus::Manifested;
                bucket.manifest_id = Some(id.clone());
                let record = bucket.public_record();
                self.record_public(format!("bucket:{bucket_id}"), record)?;
            }
        }
        self.record_public(format!("manifest:{id}"), manifest.public_record())?;
        self.manifests.insert(id.clone(), manifest);
        self.push_event(
            "batch_settlement_manifest_anchored",
            &id,
            json!({"manifest_id": id}),
        )?;
        Ok(id)
    }
    pub fn issue_fast_receipt(&mut self, manifest_id: &str, sequencer_id: &str) -> Result<String> {
        ensure_capacity(self.receipts.len(), self.config.max_receipts, "receipts")?;
        let receipt_id;
        let receipt;
        let manifest_record;
        {
            let manifest = self
                .manifests
                .get_mut(manifest_id)
                .ok_or_else(|| format!("missing manifest: {manifest_id}"))?;
            if !manifest.status.live() {
                return Err(format!("manifest is not live: {manifest_id}"));
            }
            receipt_id = deterministic_id(
                "fast_settlement_receipt",
                &[
                    HashPart::Str(manifest_id),
                    HashPart::Str(sequencer_id),
                    HashPart::U64(self.height),
                ],
            );
            receipt = FastSettlementReceipt {
                receipt_id: receipt_id.clone(),
                status: ReceiptStatus::Issued,
                manifest_id: manifest_id.to_string(),
                anchor_window_id: manifest.anchor_window_id.clone(),
                settlement_root: manifest.state_root(),
                receipt_ciphertext: deterministic_id(
                    "receipt_ciphertext",
                    &[HashPart::Str(manifest_id)],
                ),
                sequencer_id: sequencer_id.to_string(),
                issued_height: self.height,
                expires_height: self.height.saturating_add(self.config.receipt_ttl_blocks),
                confirmation_height: None,
                fee_piconero: manifest.fee_piconero,
            };
            manifest.status = ManifestStatus::Receipted;
            manifest.receipt_id = Some(receipt_id.clone());
            manifest_record = manifest.public_record();
        }
        self.record_public(format!("manifest:{manifest_id}"), manifest_record)?;
        self.record_public(format!("receipt:{receipt_id}"), receipt.public_record())?;
        self.receipts.insert(receipt_id.clone(), receipt);
        self.push_event(
            "fast_settlement_receipt_issued",
            &receipt_id,
            json!({"receipt_id": receipt_id, "manifest_id": manifest_id}),
        )?;
        Ok(receipt_id)
    }
    pub fn settle_manifest(&mut self, manifest_id: &str) -> Result<()> {
        let (bucket_ids, reservation_id, receipt_id, manifest_record);
        {
            let manifest = self
                .manifests
                .get_mut(manifest_id)
                .ok_or_else(|| format!("missing manifest: {manifest_id}"))?;
            if !manifest.status.live() {
                return Err(format!("manifest cannot settle: {manifest_id}"));
            }
            manifest.status = ManifestStatus::Settled;
            bucket_ids = manifest.bucket_ids.clone();
            reservation_id = manifest.sponsor_reservation_id.clone();
            receipt_id = manifest.receipt_id.clone();
            manifest_record = manifest.public_record();
        }
        for bucket_id in &bucket_ids {
            if let Some(bucket) = self.buckets.get_mut(bucket_id) {
                bucket.status = BucketStatus::Settled;
                let record = bucket.public_record();
                self.record_public(format!("bucket:{bucket_id}"), record)?;
            }
        }
        if let Some(reservation_id) = reservation_id {
            if let Some(reservation) = self.sponsor_reservations.get_mut(&reservation_id) {
                reservation.status = SponsorReservationStatus::Consumed;
                reservation.consumed_height = Some(self.height);
                let record = reservation.public_record();
                self.record_public(format!("sponsor_reservation:{reservation_id}"), record)?;
            }
        }
        if let Some(receipt_id) = receipt_id {
            if let Some(receipt) = self.receipts.get_mut(&receipt_id) {
                receipt.status = ReceiptStatus::Settled;
                receipt.confirmation_height = Some(self.height);
                let record = receipt.public_record();
                self.record_public(format!("receipt:{receipt_id}"), record)?;
            }
        }
        self.record_public(format!("manifest:{manifest_id}"), manifest_record)?;
        self.push_event(
            "manifest_settled",
            manifest_id,
            json!({"manifest_id": manifest_id}),
        )
    }
    pub fn mark_reorg(&mut self, anchor_window_id: &str, evidence_root: &str) -> Result<String> {
        let window_record;
        {
            let window = self
                .anchor_windows
                .get_mut(anchor_window_id)
                .ok_or_else(|| format!("missing anchor window: {anchor_window_id}"))?;
            window.status = AnchorWindowStatus::Reorged;
            window_record = window.public_record();
        }
        self.record_public(format!("anchor_window:{anchor_window_id}"), window_record)?;
        let affected = self
            .manifests
            .values_mut()
            .filter(|m| m.anchor_window_id == anchor_window_id && m.status.live())
            .map(|m| {
                m.status = ManifestStatus::Reorged;
                (m.manifest_id.clone(), m.public_record())
            })
            .collect::<Vec<_>>();
        for (manifest_id, record) in affected {
            self.record_public(format!("manifest:{manifest_id}"), record)?;
        }
        let evidence = SlashingEvidence {
            evidence_id: deterministic_id(
                "reorg_slashing_evidence",
                &[
                    HashPart::Str(anchor_window_id),
                    HashPart::Str(evidence_root),
                ],
            ),
            status: SlashingEvidenceStatus::Submitted,
            accused_id: anchor_window_id.to_string(),
            source_id: anchor_window_id.to_string(),
            source_kind: "anchor_reorg".to_string(),
            evidence_root: evidence_root.to_string(),
            penalty_piconero: 0,
            reward_piconero: 0,
            created_height: self.height,
            resolved_height: None,
        };
        let id = evidence.evidence_id.clone();
        self.slashing_evidence.insert(id.clone(), evidence.clone());
        self.record_public(format!("slashing_evidence:{id}"), evidence.public_record())?;
        self.push_event(
            "anchor_window_reorged",
            anchor_window_id,
            json!({"anchor_window_id": anchor_window_id, "evidence_id": id}),
        )?;
        Ok(id)
    }
    pub fn submit_slashing_evidence(&mut self, evidence: SlashingEvidence) -> Result<String> {
        ensure_capacity(
            self.slashing_evidence.len(),
            self.config.max_slashing_evidence,
            "slashing_evidence",
        )?;
        let id = evidence.evidence_id.clone();
        if self.slashing_evidence.contains_key(&id) {
            return Err(format!("slashing evidence already exists: {id}"));
        }
        self.record_public(format!("slashing_evidence:{id}"), evidence.public_record())?;
        self.slashing_evidence.insert(id.clone(), evidence);
        self.push_event(
            "slashing_evidence_submitted",
            &id,
            json!({"evidence_id": id}),
        )?;
        Ok(id)
    }
    pub fn accept_slashing_evidence(&mut self, evidence_id: &str) -> Result<()> {
        let record;
        {
            let evidence = self
                .slashing_evidence
                .get_mut(evidence_id)
                .ok_or_else(|| format!("missing evidence: {evidence_id}"))?;
            evidence.status = SlashingEvidenceStatus::Accepted;
            evidence.resolved_height = Some(self.height);
            record = evidence.public_record();
        }
        self.record_public(format!("slashing_evidence:{evidence_id}"), record)?;
        self.push_event(
            "slashing_evidence_accepted",
            evidence_id,
            json!({"evidence_id": evidence_id}),
        )
    }
    pub fn counters(&self) -> Counters {
        Counters {
            buckets: self.buckets.len(),
            attestations: self.attestations.len(),
            manifests: self.manifests.len(),
            payment_ids: self.payment_ids.len(),
            sponsor_reservations: self.sponsor_reservations.len(),
            receipts: self.receipts.len(),
            anchor_windows: self.anchor_windows.len(),
            scan_hints: self.scan_hints.len(),
            nullifier_fences: self.nullifier_fences.len(),
            slashing_evidence: self.slashing_evidence.len(),
            public_records: self.public_records.len(),
            events: self.events.len(),
        }
    }
    pub fn roots(&self) -> Roots {
        Roots {
            config_root: self.config.state_root(),
            counters_root: self.counters().state_root(),
            bucket_root: public_record_root(
                "bucket_root",
                &self
                    .buckets
                    .values()
                    .map(EncryptedSubaddressBucket::public_record)
                    .collect::<Vec<_>>(),
            ),
            view_attestation_root: public_record_root(
                "view_attestation_root",
                &self
                    .attestations
                    .values()
                    .map(PqViewKeyAttestation::public_record)
                    .collect::<Vec<_>>(),
            ),
            manifest_root: public_record_root(
                "manifest_root",
                &self
                    .manifests
                    .values()
                    .map(BatchSettlementManifest::public_record)
                    .collect::<Vec<_>>(),
            ),
            payment_id_root: public_record_root(
                "payment_id_root",
                &self
                    .payment_ids
                    .values()
                    .map(PrivatePaymentIdCommitment::public_record)
                    .collect::<Vec<_>>(),
            ),
            sponsor_reservation_root: public_record_root(
                "sponsor_reservation_root",
                &self
                    .sponsor_reservations
                    .values()
                    .map(LowFeeSponsorReservation::public_record)
                    .collect::<Vec<_>>(),
            ),
            receipt_root: public_record_root(
                "receipt_root",
                &self
                    .receipts
                    .values()
                    .map(FastSettlementReceipt::public_record)
                    .collect::<Vec<_>>(),
            ),
            anchor_window_root: public_record_root(
                "anchor_window_root",
                &self
                    .anchor_windows
                    .values()
                    .map(ReorgSafeAnchorWindow::public_record)
                    .collect::<Vec<_>>(),
            ),
            scan_hint_root: public_record_root(
                "scan_hint_root",
                &self
                    .scan_hints
                    .values()
                    .map(WalletScanHint::public_record)
                    .collect::<Vec<_>>(),
            ),
            nullifier_fence_root: public_record_root(
                "nullifier_fence_root",
                &self
                    .nullifier_fences
                    .values()
                    .map(NullifierFence::public_record)
                    .collect::<Vec<_>>(),
            ),
            slashing_evidence_root: public_record_root(
                "slashing_evidence_root",
                &self
                    .slashing_evidence
                    .values()
                    .map(SlashingEvidence::public_record)
                    .collect::<Vec<_>>(),
            ),
            public_record_root: public_record_root(
                "public_record_root",
                &self.public_records.values().cloned().collect::<Vec<_>>(),
            ),
            event_root: public_record_root(
                "event_root",
                &self
                    .events
                    .iter()
                    .map(RuntimeEvent::public_record)
                    .collect::<Vec<_>>(),
            ),
        }
    }
    pub fn public_record_without_state_root(&self) -> Value {
        let roots = self.roots();
        json!({ "protocol_version": PROTOCOL_VERSION, "height": self.height, "config": self.config.public_record(), "counters": self.counters().public_record(), "roots_root": roots.state_root(), "roots": roots.public_record() })
    }
    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        record["state_root"] = json!(self.state_root());
        record
    }
    pub fn state_root(&self) -> String {
        domain_hash(
            "monero_l2_pq_private_subaddress_batch_settlement:state",
            &[HashPart::Json(&self.public_record_without_state_root())],
            32,
        )
    }
    fn validate_bucket(&self, bucket: &EncryptedSubaddressBucket) -> Result<()> {
        ensure_nonempty("bucket_id", &bucket.bucket_id)?;
        ensure_nonempty("owner_view_commitment", &bucket.owner_view_commitment)?;
        ensure_nonempty(
            "encrypted_subaddress_bundle",
            &bucket.encrypted_subaddress_bundle,
        )?;
        if bucket.privacy_set_size < self.config.min_privacy_set_size {
            return Err("bucket privacy set is too small".to_string());
        }
        if bucket.pq_security_bits < self.config.min_pq_security_bits {
            return Err("bucket pq security bits too low".to_string());
        }
        if bucket.expires_height <= bucket.opened_height {
            return Err("bucket expiry must exceed opened height".to_string());
        }
        Ok(())
    }
    fn validate_view_attestation(&self, attestation: &PqViewKeyAttestation) -> Result<()> {
        ensure_nonempty("attestation_id", &attestation.attestation_id)?;
        ensure_nonempty("bucket_id", &attestation.bucket_id)?;
        ensure_nonempty("attestor_id", &attestation.attestor_id)?;
        ensure_nonempty("nullifier", &attestation.nullifier)?;
        if attestation.security_bits < self.config.min_pq_security_bits {
            return Err("attestation pq security bits too low".to_string());
        }
        if attestation.quorum_bps > MONERO_L2_PQ_PRIVATE_SUBADDRESS_BATCH_SETTLEMENT_RUNTIME_MAX_BPS
        {
            return Err("attestation quorum exceeds max bps".to_string());
        }
        Ok(())
    }
    fn validate_manifest(&self, manifest: &BatchSettlementManifest) -> Result<()> {
        ensure_nonempty("manifest_id", &manifest.manifest_id)?;
        ensure_nonempty("anchor_window_id", &manifest.anchor_window_id)?;
        if manifest.bucket_ids.is_empty() {
            return Err("manifest bucket_ids cannot be empty".to_string());
        }
        let unique = manifest.bucket_ids.iter().collect::<BTreeSet<_>>();
        if unique.len() != manifest.bucket_ids.len() {
            return Err("manifest contains duplicate bucket ids".to_string());
        }
        if manifest.total_input_piconero < manifest.total_output_piconero {
            return Err("manifest outputs exceed inputs".to_string());
        }
        if manifest.privacy_set_size < self.config.min_privacy_set_size {
            return Err("manifest privacy set is too small".to_string());
        }
        Ok(())
    }
    fn validate_anchor_window(&self, window: &ReorgSafeAnchorWindow) -> Result<()> {
        ensure_nonempty("anchor_window_id", &window.anchor_window_id)?;
        ensure_nonempty("anchor_block_hash_root", &window.anchor_block_hash_root)?;
        if window.monero_end_height <= window.monero_start_height {
            return Err("anchor monero_end_height must exceed start".to_string());
        }
        if window.l2_end_height <= window.l2_start_height {
            return Err("anchor l2_end_height must exceed start".to_string());
        }
        Ok(())
    }
    fn validate_sponsor_reservation(&self, reservation: &LowFeeSponsorReservation) -> Result<()> {
        ensure_nonempty("reservation_id", &reservation.reservation_id)?;
        ensure_nonempty("sponsor_id", &reservation.sponsor_id)?;
        if reservation.covered_fee_bps
            > MONERO_L2_PQ_PRIVATE_SUBADDRESS_BATCH_SETTLEMENT_RUNTIME_MAX_BPS
        {
            return Err("reservation covered_fee_bps exceeds max".to_string());
        }
        if reservation.expires_height <= reservation.created_height {
            return Err("reservation expiry must exceed created height".to_string());
        }
        Ok(())
    }
    fn expire_stale_records(&mut self) {
        for bucket in self.buckets.values_mut() {
            if bucket.status.live() && bucket.expires_height < self.height {
                bucket.status = BucketStatus::Expired;
            }
        }
        for attestation in self.attestations.values_mut() {
            if attestation.status.usable() && attestation.expires_height < self.height {
                attestation.status = ViewAttestationStatus::Expired;
            }
        }
        for manifest in self.manifests.values_mut() {
            if manifest.status.live() && manifest.expires_height < self.height {
                manifest.status = ManifestStatus::Expired;
            }
        }
        for reservation in self.sponsor_reservations.values_mut() {
            if reservation.status.live() && reservation.expires_height < self.height {
                reservation.status = SponsorReservationStatus::Expired;
            }
        }
        for receipt in self.receipts.values_mut() {
            if matches!(
                receipt.status,
                ReceiptStatus::Issued | ReceiptStatus::Confirmed
            ) && receipt.expires_height < self.height
            {
                receipt.status = ReceiptStatus::Expired;
            }
        }
        for hint in self.scan_hints.values_mut() {
            if matches!(
                hint.status,
                ScanHintStatus::Published | ScanHintStatus::Claimed
            ) && hint.expires_height < self.height
            {
                hint.status = ScanHintStatus::Expired;
            }
        }
    }
    fn record_public(&mut self, key: String, record: Value) -> Result<()> {
        if !self.public_records.contains_key(&key) {
            ensure_capacity(
                self.public_records.len(),
                self.config.max_public_records,
                "public_records",
            )?;
        }
        self.public_records.insert(key, record);
        Ok(())
    }
    fn push_event(&mut self, event_type: &str, subject_id: &str, payload: Value) -> Result<()> {
        let sequence = self.events.len() as u64;
        let event_id = deterministic_id(
            "runtime_event",
            &[
                HashPart::Str(event_type),
                HashPart::Str(subject_id),
                HashPart::U64(sequence),
            ],
        );
        let event = RuntimeEvent {
            event_id: event_id.clone(),
            status: "recorded".to_string(),
            event_type: event_type.to_string(),
            subject_id: subject_id.to_string(),
            height: self.height,
            sequence,
            payload,
        };
        self.record_public(format!("event:{event_id}"), event.public_record())?;
        self.events.push(event);
        Ok(())
    }
}

pub fn deterministic_id(domain: &str, parts: &[HashPart<'_>]) -> String {
    domain_hash(
        &format!("monero_l2_pq_private_subaddress_batch_settlement:{domain}"),
        parts,
        32,
    )
}
pub fn public_record_root(domain: &str, records: &[Value]) -> String {
    merkle_root(
        &format!("monero_l2_pq_private_subaddress_batch_settlement:{domain}"),
        records,
    )
}
pub fn state_root_from_record(record: &Value) -> String {
    domain_hash(
        "monero_l2_pq_private_subaddress_batch_settlement:record_state",
        &[HashPart::Json(record)],
        32,
    )
}
pub fn monero_l2_pq_private_subaddress_batch_settlement_runtime_devnet() -> State {
    State::devnet()
}
pub fn monero_l2_pq_private_subaddress_batch_settlement_runtime_state_root(
    state: &State,
) -> String {
    state.state_root()
}
pub fn monero_l2_pq_private_subaddress_batch_settlement_runtime_public_record(
    state: &State,
) -> Value {
    state.public_record()
}
fn ensure_nonempty(name: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        Err(format!("{name} cannot be empty"))
    } else {
        Ok(())
    }
}
fn ensure_capacity(current: usize, max: usize, name: &str) -> Result<()> {
    if current >= max {
        Err(format!("{name} capacity exceeded"))
    } else {
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuditProjection1 {
    pub projection_id: String,
    pub source_root: String,
    pub bucket_root: String,
    pub manifest_root: String,
    pub receipt_root: String,
    pub nullifier_root: String,
    pub height: u64,
    pub lane: SettlementLane,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
}

impl AuditProjection1 {
    pub fn public_record(&self) -> Value {
        json!({
            "projection_id": self.projection_id,
            "source_root": self.source_root,
            "bucket_root": self.bucket_root,
            "manifest_root": self.manifest_root,
            "receipt_root": self.receipt_root,
            "nullifier_root": self.nullifier_root,
            "height": self.height,
            "lane": self.lane.as_str(),
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "monero_l2_pq_private_subaddress_batch_settlement:audit_projection_1",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

pub fn derive_audit_projection_1(state: &State, lane: SettlementLane) -> AuditProjection1 {
    let roots = state.roots();
    let source_root = roots.state_root();
    AuditProjection1 {
        projection_id: deterministic_id(
            "audit_projection_1",
            &[HashPart::Str(&source_root), HashPart::Str(lane.as_str())],
        ),
        source_root,
        bucket_root: roots.bucket_root,
        manifest_root: roots.manifest_root,
        receipt_root: roots.receipt_root,
        nullifier_root: roots.nullifier_fence_root,
        height: state.height,
        lane,
        privacy_set_size: state.config.batch_privacy_set_size,
        pq_security_bits: state.config.min_pq_security_bits,
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuditProjection2 {
    pub projection_id: String,
    pub source_root: String,
    pub bucket_root: String,
    pub manifest_root: String,
    pub receipt_root: String,
    pub nullifier_root: String,
    pub height: u64,
    pub lane: SettlementLane,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
}

impl AuditProjection2 {
    pub fn public_record(&self) -> Value {
        json!({
            "projection_id": self.projection_id,
            "source_root": self.source_root,
            "bucket_root": self.bucket_root,
            "manifest_root": self.manifest_root,
            "receipt_root": self.receipt_root,
            "nullifier_root": self.nullifier_root,
            "height": self.height,
            "lane": self.lane.as_str(),
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "monero_l2_pq_private_subaddress_batch_settlement:audit_projection_2",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

pub fn derive_audit_projection_2(state: &State, lane: SettlementLane) -> AuditProjection2 {
    let roots = state.roots();
    let source_root = roots.state_root();
    AuditProjection2 {
        projection_id: deterministic_id(
            "audit_projection_2",
            &[HashPart::Str(&source_root), HashPart::Str(lane.as_str())],
        ),
        source_root,
        bucket_root: roots.bucket_root,
        manifest_root: roots.manifest_root,
        receipt_root: roots.receipt_root,
        nullifier_root: roots.nullifier_fence_root,
        height: state.height,
        lane,
        privacy_set_size: state.config.batch_privacy_set_size,
        pq_security_bits: state.config.min_pq_security_bits,
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuditProjection3 {
    pub projection_id: String,
    pub source_root: String,
    pub bucket_root: String,
    pub manifest_root: String,
    pub receipt_root: String,
    pub nullifier_root: String,
    pub height: u64,
    pub lane: SettlementLane,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
}

impl AuditProjection3 {
    pub fn public_record(&self) -> Value {
        json!({
            "projection_id": self.projection_id,
            "source_root": self.source_root,
            "bucket_root": self.bucket_root,
            "manifest_root": self.manifest_root,
            "receipt_root": self.receipt_root,
            "nullifier_root": self.nullifier_root,
            "height": self.height,
            "lane": self.lane.as_str(),
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "monero_l2_pq_private_subaddress_batch_settlement:audit_projection_3",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

pub fn derive_audit_projection_3(state: &State, lane: SettlementLane) -> AuditProjection3 {
    let roots = state.roots();
    let source_root = roots.state_root();
    AuditProjection3 {
        projection_id: deterministic_id(
            "audit_projection_3",
            &[HashPart::Str(&source_root), HashPart::Str(lane.as_str())],
        ),
        source_root,
        bucket_root: roots.bucket_root,
        manifest_root: roots.manifest_root,
        receipt_root: roots.receipt_root,
        nullifier_root: roots.nullifier_fence_root,
        height: state.height,
        lane,
        privacy_set_size: state.config.batch_privacy_set_size,
        pq_security_bits: state.config.min_pq_security_bits,
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuditProjection4 {
    pub projection_id: String,
    pub source_root: String,
    pub bucket_root: String,
    pub manifest_root: String,
    pub receipt_root: String,
    pub nullifier_root: String,
    pub height: u64,
    pub lane: SettlementLane,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
}

impl AuditProjection4 {
    pub fn public_record(&self) -> Value {
        json!({
            "projection_id": self.projection_id,
            "source_root": self.source_root,
            "bucket_root": self.bucket_root,
            "manifest_root": self.manifest_root,
            "receipt_root": self.receipt_root,
            "nullifier_root": self.nullifier_root,
            "height": self.height,
            "lane": self.lane.as_str(),
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "monero_l2_pq_private_subaddress_batch_settlement:audit_projection_4",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

pub fn derive_audit_projection_4(state: &State, lane: SettlementLane) -> AuditProjection4 {
    let roots = state.roots();
    let source_root = roots.state_root();
    AuditProjection4 {
        projection_id: deterministic_id(
            "audit_projection_4",
            &[HashPart::Str(&source_root), HashPart::Str(lane.as_str())],
        ),
        source_root,
        bucket_root: roots.bucket_root,
        manifest_root: roots.manifest_root,
        receipt_root: roots.receipt_root,
        nullifier_root: roots.nullifier_fence_root,
        height: state.height,
        lane,
        privacy_set_size: state.config.batch_privacy_set_size,
        pq_security_bits: state.config.min_pq_security_bits,
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuditProjection5 {
    pub projection_id: String,
    pub source_root: String,
    pub bucket_root: String,
    pub manifest_root: String,
    pub receipt_root: String,
    pub nullifier_root: String,
    pub height: u64,
    pub lane: SettlementLane,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
}

impl AuditProjection5 {
    pub fn public_record(&self) -> Value {
        json!({
            "projection_id": self.projection_id,
            "source_root": self.source_root,
            "bucket_root": self.bucket_root,
            "manifest_root": self.manifest_root,
            "receipt_root": self.receipt_root,
            "nullifier_root": self.nullifier_root,
            "height": self.height,
            "lane": self.lane.as_str(),
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "monero_l2_pq_private_subaddress_batch_settlement:audit_projection_5",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

pub fn derive_audit_projection_5(state: &State, lane: SettlementLane) -> AuditProjection5 {
    let roots = state.roots();
    let source_root = roots.state_root();
    AuditProjection5 {
        projection_id: deterministic_id(
            "audit_projection_5",
            &[HashPart::Str(&source_root), HashPart::Str(lane.as_str())],
        ),
        source_root,
        bucket_root: roots.bucket_root,
        manifest_root: roots.manifest_root,
        receipt_root: roots.receipt_root,
        nullifier_root: roots.nullifier_fence_root,
        height: state.height,
        lane,
        privacy_set_size: state.config.batch_privacy_set_size,
        pq_security_bits: state.config.min_pq_security_bits,
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuditProjection6 {
    pub projection_id: String,
    pub source_root: String,
    pub bucket_root: String,
    pub manifest_root: String,
    pub receipt_root: String,
    pub nullifier_root: String,
    pub height: u64,
    pub lane: SettlementLane,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
}

impl AuditProjection6 {
    pub fn public_record(&self) -> Value {
        json!({
            "projection_id": self.projection_id,
            "source_root": self.source_root,
            "bucket_root": self.bucket_root,
            "manifest_root": self.manifest_root,
            "receipt_root": self.receipt_root,
            "nullifier_root": self.nullifier_root,
            "height": self.height,
            "lane": self.lane.as_str(),
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "monero_l2_pq_private_subaddress_batch_settlement:audit_projection_6",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

pub fn derive_audit_projection_6(state: &State, lane: SettlementLane) -> AuditProjection6 {
    let roots = state.roots();
    let source_root = roots.state_root();
    AuditProjection6 {
        projection_id: deterministic_id(
            "audit_projection_6",
            &[HashPart::Str(&source_root), HashPart::Str(lane.as_str())],
        ),
        source_root,
        bucket_root: roots.bucket_root,
        manifest_root: roots.manifest_root,
        receipt_root: roots.receipt_root,
        nullifier_root: roots.nullifier_fence_root,
        height: state.height,
        lane,
        privacy_set_size: state.config.batch_privacy_set_size,
        pq_security_bits: state.config.min_pq_security_bits,
    }
}
