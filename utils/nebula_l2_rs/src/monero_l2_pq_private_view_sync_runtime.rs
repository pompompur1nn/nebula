use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type MoneroL2PqPrivateViewSyncRuntimeResult<T> = Result<T, String>;

pub const MONERO_L2_PQ_PRIVATE_VIEW_SYNC_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-private-view-sync-runtime-v1";
pub const PROTOCOL_VERSION: &str = MONERO_L2_PQ_PRIVATE_VIEW_SYNC_RUNTIME_PROTOCOL_VERSION;
pub const MONERO_L2_PQ_PRIVATE_VIEW_SYNC_RUNTIME_SCHEMA_VERSION: u64 = 1;
pub const MONERO_L2_PQ_PRIVATE_VIEW_SYNC_RUNTIME_DEVNET_HEIGHT: u64 = 420_000;
pub const MONERO_L2_PQ_PRIVATE_VIEW_SYNC_RUNTIME_DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const MONERO_L2_PQ_PRIVATE_VIEW_SYNC_RUNTIME_DEVNET_L2_NETWORK: &str = "nebula-devnet";
pub const MONERO_L2_PQ_PRIVATE_VIEW_SYNC_RUNTIME_DEVNET_ASSET_ID: &str = "wxmr-devnet";
pub const MONERO_L2_PQ_PRIVATE_VIEW_SYNC_RUNTIME_DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const MONERO_L2_PQ_PRIVATE_VIEW_SYNC_RUNTIME_HASH_SUITE: &str =
    "SHAKE256-domain-separated-canonical-json";
pub const MONERO_L2_PQ_PRIVATE_VIEW_SYNC_RUNTIME_PQ_VIEW_KEY_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-192f-private-view-sync-v1";
pub const MONERO_L2_PQ_PRIVATE_VIEW_SYNC_RUNTIME_VIEW_TAG_COMMITMENT_SCHEME: &str =
    "roots-only-monero-view-tag-range-commitment-v1";
pub const MONERO_L2_PQ_PRIVATE_VIEW_SYNC_RUNTIME_SCAN_JOB_SCHEME: &str =
    "ml-kem-1024-sealed-encrypted-monero-scan-job-v1";
pub const MONERO_L2_PQ_PRIVATE_VIEW_SYNC_RUNTIME_RELAY_RESERVATION_SCHEME: &str =
    "low-fee-private-view-sync-relay-reservation-root-v1";
pub const MONERO_L2_PQ_PRIVATE_VIEW_SYNC_RUNTIME_WATCHER_ATTESTATION_SCHEME: &str =
    "ml-dsa-87-private-view-sync-watcher-attestation-root-v1";
pub const MONERO_L2_PQ_PRIVATE_VIEW_SYNC_RUNTIME_SYNC_BATCH_SCHEME: &str =
    "fast-wallet-sync-batch-root-v1";
pub const MONERO_L2_PQ_PRIVATE_VIEW_SYNC_RUNTIME_SETTLEMENT_RECEIPT_SCHEME: &str =
    "private-view-sync-settlement-receipt-root-v1";
pub const MONERO_L2_PQ_PRIVATE_VIEW_SYNC_RUNTIME_NULLIFIER_SCHEME: &str =
    "monero-l2-pq-private-view-sync-nullifier-root-v1";
pub const MONERO_L2_PQ_PRIVATE_VIEW_SYNC_RUNTIME_REPLAY_DOMAIN: &str =
    "monero-l2-pq-private-view-sync-devnet";
pub const MONERO_L2_PQ_PRIVATE_VIEW_SYNC_RUNTIME_MAX_BPS: u64 = 10_000;
pub const MONERO_L2_PQ_PRIVATE_VIEW_SYNC_RUNTIME_DEFAULT_SCAN_TTL_BLOCKS: u64 = 18;
pub const MONERO_L2_PQ_PRIVATE_VIEW_SYNC_RUNTIME_DEFAULT_RESERVATION_TTL_BLOCKS: u64 = 12;
pub const MONERO_L2_PQ_PRIVATE_VIEW_SYNC_RUNTIME_DEFAULT_BATCH_WINDOW_BLOCKS: u64 = 3;
pub const MONERO_L2_PQ_PRIVATE_VIEW_SYNC_RUNTIME_DEFAULT_SETTLEMENT_TTL_BLOCKS: u64 = 72;
pub const MONERO_L2_PQ_PRIVATE_VIEW_SYNC_RUNTIME_DEFAULT_MAX_VIEW_TAG_SPAN: u64 = 64;
pub const MONERO_L2_PQ_PRIVATE_VIEW_SYNC_RUNTIME_DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 16_384;
pub const MONERO_L2_PQ_PRIVATE_VIEW_SYNC_RUNTIME_DEFAULT_MIN_WATCHER_COUNT: u64 = 2;
pub const MONERO_L2_PQ_PRIVATE_VIEW_SYNC_RUNTIME_DEFAULT_WATCHER_QUORUM_BPS: u64 = 6_700;
pub const MONERO_L2_PQ_PRIVATE_VIEW_SYNC_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 192;
pub const MONERO_L2_PQ_PRIVATE_VIEW_SYNC_RUNTIME_DEFAULT_TARGET_PQ_SECURITY_BITS: u16 = 256;
pub const MONERO_L2_PQ_PRIVATE_VIEW_SYNC_RUNTIME_DEFAULT_MAX_USER_FEE_BPS: u64 = 18;
pub const MONERO_L2_PQ_PRIVATE_VIEW_SYNC_RUNTIME_DEFAULT_LOW_FEE_BPS: u64 = 4;
pub const MONERO_L2_PQ_PRIVATE_VIEW_SYNC_RUNTIME_DEFAULT_DEFI_FEE_BPS: u64 = 9;
pub const MONERO_L2_PQ_PRIVATE_VIEW_SYNC_RUNTIME_MAX_VIEW_COMMITMENTS: usize = 524_288;
pub const MONERO_L2_PQ_PRIVATE_VIEW_SYNC_RUNTIME_MAX_SCAN_JOBS: usize = 524_288;
pub const MONERO_L2_PQ_PRIVATE_VIEW_SYNC_RUNTIME_MAX_RELAY_RESERVATIONS: usize = 524_288;
pub const MONERO_L2_PQ_PRIVATE_VIEW_SYNC_RUNTIME_MAX_WATCHER_ATTESTATIONS: usize = 1_048_576;
pub const MONERO_L2_PQ_PRIVATE_VIEW_SYNC_RUNTIME_MAX_SYNC_BATCHES: usize = 262_144;
pub const MONERO_L2_PQ_PRIVATE_VIEW_SYNC_RUNTIME_MAX_SETTLEMENT_RECEIPTS: usize = 524_288;
pub const MONERO_L2_PQ_PRIVATE_VIEW_SYNC_RUNTIME_MAX_PUBLIC_RECORDS: usize = 1_048_576;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ViewSyncLane {
    LowFee,
    Fast,
    Defi,
    Token,
    SmartContract,
    Emergency,
}

impl ViewSyncLane {
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
            Self::Emergency => 1_000,
            Self::Fast => 920,
            Self::SmartContract => 850,
            Self::Defi => 820,
            Self::Token => 760,
            Self::LowFee => 700,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanPrivacyMode {
    ViewTagsOnly,
    DecoyExpanded,
    DefiStateAware,
    ContractEventAware,
}

impl ScanPrivacyMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ViewTagsOnly => "view_tags_only",
            Self::DecoyExpanded => "decoy_expanded",
            Self::DefiStateAware => "defi_state_aware",
            Self::ContractEventAware => "contract_event_aware",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CommitmentStatus {
    Open,
    Reserved,
    Scanning,
    Batched,
    Settled,
    Expired,
}

impl CommitmentStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Reserved => "reserved",
            Self::Scanning => "scanning",
            Self::Batched => "batched",
            Self::Settled => "settled",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanJobStatus {
    Queued,
    Reserved,
    Attested,
    Batched,
    Settled,
    Expired,
    Rejected,
}

impl ScanJobStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Reserved => "reserved",
            Self::Attested => "attested",
            Self::Batched => "batched",
            Self::Settled => "settled",
            Self::Expired => "expired",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReservationStatus {
    Held,
    Assigned,
    Batched,
    Settled,
    Released,
    Expired,
}

impl ReservationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Held => "held",
            Self::Assigned => "assigned",
            Self::Batched => "batched",
            Self::Settled => "settled",
            Self::Released => "released",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WatcherAttestationStatus {
    Submitted,
    Accepted,
    WeakQuorum,
    Superseded,
    Rejected,
}

impl WatcherAttestationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Accepted => "accepted",
            Self::WeakQuorum => "weak_quorum",
            Self::Superseded => "superseded",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SyncBatchStatus {
    Open,
    Sealed,
    SettlementReady,
    Settled,
    Disputed,
    Expired,
}

impl SyncBatchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Sealed => "sealed",
            Self::SettlementReady => "settlement_ready",
            Self::Settled => "settled",
            Self::Disputed => "disputed",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementStatus {
    Published,
    Finalized,
    Reconciled,
    Failed,
    Disputed,
}

impl SettlementStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Published => "published",
            Self::Finalized => "finalized",
            Self::Reconciled => "reconciled",
            Self::Failed => "failed",
            Self::Disputed => "disputed",
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
    pub pq_view_key_suite: String,
    pub replay_domain: String,
    pub scan_ttl_blocks: u64,
    pub reservation_ttl_blocks: u64,
    pub batch_window_blocks: u64,
    pub settlement_ttl_blocks: u64,
    pub max_view_tag_span: u64,
    pub min_privacy_set_size: u64,
    pub min_watcher_count: u64,
    pub watcher_quorum_bps: u64,
    pub min_pq_security_bits: u16,
    pub target_pq_security_bits: u16,
    pub max_user_fee_bps: u64,
    pub low_fee_bps: u64,
    pub defi_fee_bps: u64,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: MONERO_L2_PQ_PRIVATE_VIEW_SYNC_RUNTIME_SCHEMA_VERSION,
            monero_network: MONERO_L2_PQ_PRIVATE_VIEW_SYNC_RUNTIME_DEVNET_MONERO_NETWORK
                .to_string(),
            l2_network: MONERO_L2_PQ_PRIVATE_VIEW_SYNC_RUNTIME_DEVNET_L2_NETWORK.to_string(),
            asset_id: MONERO_L2_PQ_PRIVATE_VIEW_SYNC_RUNTIME_DEVNET_ASSET_ID.to_string(),
            fee_asset_id: MONERO_L2_PQ_PRIVATE_VIEW_SYNC_RUNTIME_DEVNET_FEE_ASSET_ID.to_string(),
            hash_suite: MONERO_L2_PQ_PRIVATE_VIEW_SYNC_RUNTIME_HASH_SUITE.to_string(),
            pq_view_key_suite: MONERO_L2_PQ_PRIVATE_VIEW_SYNC_RUNTIME_PQ_VIEW_KEY_SUITE.to_string(),
            replay_domain: MONERO_L2_PQ_PRIVATE_VIEW_SYNC_RUNTIME_REPLAY_DOMAIN.to_string(),
            scan_ttl_blocks: MONERO_L2_PQ_PRIVATE_VIEW_SYNC_RUNTIME_DEFAULT_SCAN_TTL_BLOCKS,
            reservation_ttl_blocks:
                MONERO_L2_PQ_PRIVATE_VIEW_SYNC_RUNTIME_DEFAULT_RESERVATION_TTL_BLOCKS,
            batch_window_blocks: MONERO_L2_PQ_PRIVATE_VIEW_SYNC_RUNTIME_DEFAULT_BATCH_WINDOW_BLOCKS,
            settlement_ttl_blocks:
                MONERO_L2_PQ_PRIVATE_VIEW_SYNC_RUNTIME_DEFAULT_SETTLEMENT_TTL_BLOCKS,
            max_view_tag_span: MONERO_L2_PQ_PRIVATE_VIEW_SYNC_RUNTIME_DEFAULT_MAX_VIEW_TAG_SPAN,
            min_privacy_set_size:
                MONERO_L2_PQ_PRIVATE_VIEW_SYNC_RUNTIME_DEFAULT_MIN_PRIVACY_SET_SIZE,
            min_watcher_count: MONERO_L2_PQ_PRIVATE_VIEW_SYNC_RUNTIME_DEFAULT_MIN_WATCHER_COUNT,
            watcher_quorum_bps: MONERO_L2_PQ_PRIVATE_VIEW_SYNC_RUNTIME_DEFAULT_WATCHER_QUORUM_BPS,
            min_pq_security_bits:
                MONERO_L2_PQ_PRIVATE_VIEW_SYNC_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS,
            target_pq_security_bits:
                MONERO_L2_PQ_PRIVATE_VIEW_SYNC_RUNTIME_DEFAULT_TARGET_PQ_SECURITY_BITS,
            max_user_fee_bps: MONERO_L2_PQ_PRIVATE_VIEW_SYNC_RUNTIME_DEFAULT_MAX_USER_FEE_BPS,
            low_fee_bps: MONERO_L2_PQ_PRIVATE_VIEW_SYNC_RUNTIME_DEFAULT_LOW_FEE_BPS,
            defi_fee_bps: MONERO_L2_PQ_PRIVATE_VIEW_SYNC_RUNTIME_DEFAULT_DEFI_FEE_BPS,
        }
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    pub view_commitment_counter: u64,
    pub scan_job_counter: u64,
    pub relay_reservation_counter: u64,
    pub watcher_attestation_counter: u64,
    pub sync_batch_counter: u64,
    pub settlement_receipt_counter: u64,
    pub public_records: usize,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roots {
    pub config_root: String,
    pub counter_root: String,
    pub view_commitment_root: String,
    pub scan_job_root: String,
    pub relay_reservation_root: String,
    pub watcher_attestation_root: String,
    pub sync_batch_root: String,
    pub settlement_receipt_root: String,
    pub nullifier_root: String,
    pub public_record_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ViewTagRangeCommitmentRequest {
    pub wallet_id: String,
    pub commitment_nonce: String,
    pub monero_start_height: u64,
    pub monero_end_height: u64,
    pub view_tag_range_root: String,
    pub decoy_set_root: String,
    pub encrypted_view_hint_root: String,
    pub pq_view_key_commitment: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub lane: ViewSyncLane,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ViewTagRangeCommitment {
    pub commitment_id: String,
    pub sequence: u64,
    pub wallet_id: String,
    pub commitment_nonce: String,
    pub monero_start_height: u64,
    pub monero_end_height: u64,
    pub view_tag_range_root: String,
    pub decoy_set_root: String,
    pub encrypted_view_hint_root: String,
    pub pq_view_key_commitment: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub lane: ViewSyncLane,
    pub status: CommitmentStatus,
    pub expires_at_l2_height: u64,
}

impl ViewTagRangeCommitment {
    pub fn public_record(&self) -> Value {
        json!({
            "commitment_id": self.commitment_id,
            "sequence": self.sequence,
            "wallet_id": self.wallet_id,
            "monero_start_height": self.monero_start_height,
            "monero_end_height": self.monero_end_height,
            "view_tag_range_root": self.view_tag_range_root,
            "decoy_set_root": self.decoy_set_root,
            "encrypted_view_hint_root": self.encrypted_view_hint_root,
            "pq_view_key_commitment": self.pq_view_key_commitment,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "lane": self.lane.as_str(),
            "status": self.status.as_str(),
            "expires_at_l2_height": self.expires_at_l2_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedScanJobRequest {
    pub commitment_id: String,
    pub relay_id: String,
    pub encrypted_scan_payload_root: String,
    pub pq_ciphertext_root: String,
    pub scan_privacy_mode: ScanPrivacyMode,
    pub requested_output_root: String,
    pub max_fee_piconero: u64,
    pub nullifier: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedScanJob {
    pub scan_job_id: String,
    pub sequence: u64,
    pub commitment_id: String,
    pub relay_id: String,
    pub encrypted_scan_payload_root: String,
    pub pq_ciphertext_root: String,
    pub scan_privacy_mode: ScanPrivacyMode,
    pub requested_output_root: String,
    pub max_fee_piconero: u64,
    pub nullifier: String,
    pub status: ScanJobStatus,
    pub created_at_l2_height: u64,
    pub expires_at_l2_height: u64,
}

impl EncryptedScanJob {
    pub fn public_record(&self) -> Value {
        json!({
            "scan_job_id": self.scan_job_id,
            "sequence": self.sequence,
            "commitment_id": self.commitment_id,
            "relay_id": self.relay_id,
            "encrypted_scan_payload_root": self.encrypted_scan_payload_root,
            "pq_ciphertext_root": self.pq_ciphertext_root,
            "scan_privacy_mode": self.scan_privacy_mode.as_str(),
            "requested_output_root": self.requested_output_root,
            "max_fee_piconero": self.max_fee_piconero,
            "nullifier": self.nullifier,
            "status": self.status.as_str(),
            "created_at_l2_height": self.created_at_l2_height,
            "expires_at_l2_height": self.expires_at_l2_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeRelayReservationRequest {
    pub scan_job_id: String,
    pub relay_id: String,
    pub lane: ViewSyncLane,
    pub reserved_fee_piconero: u64,
    pub sponsor_commitment_root: String,
    pub relay_capacity_root: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeRelayReservation {
    pub reservation_id: String,
    pub sequence: u64,
    pub scan_job_id: String,
    pub relay_id: String,
    pub lane: ViewSyncLane,
    pub fee_bps: u64,
    pub reserved_fee_piconero: u64,
    pub sponsor_commitment_root: String,
    pub relay_capacity_root: String,
    pub status: ReservationStatus,
    pub expires_at_l2_height: u64,
}

impl LowFeeRelayReservation {
    pub fn public_record(&self) -> Value {
        json!({
            "reservation_id": self.reservation_id,
            "sequence": self.sequence,
            "scan_job_id": self.scan_job_id,
            "relay_id": self.relay_id,
            "lane": self.lane.as_str(),
            "fee_bps": self.fee_bps,
            "reserved_fee_piconero": self.reserved_fee_piconero,
            "sponsor_commitment_root": self.sponsor_commitment_root,
            "relay_capacity_root": self.relay_capacity_root,
            "status": self.status.as_str(),
            "expires_at_l2_height": self.expires_at_l2_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WatcherAttestationRequest {
    pub scan_job_id: String,
    pub watcher_id: String,
    pub observed_monero_height: u64,
    pub encrypted_match_result_root: String,
    pub output_commitment_root: String,
    pub token_delta_root: String,
    pub contract_event_root: String,
    pub pq_signature_root: String,
    pub watcher_weight: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WatcherAttestation {
    pub attestation_id: String,
    pub sequence: u64,
    pub scan_job_id: String,
    pub watcher_id: String,
    pub observed_monero_height: u64,
    pub encrypted_match_result_root: String,
    pub output_commitment_root: String,
    pub token_delta_root: String,
    pub contract_event_root: String,
    pub pq_signature_root: String,
    pub watcher_weight: u64,
    pub quorum_bps: u64,
    pub status: WatcherAttestationStatus,
}

impl WatcherAttestation {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "sequence": self.sequence,
            "scan_job_id": self.scan_job_id,
            "watcher_id": self.watcher_id,
            "observed_monero_height": self.observed_monero_height,
            "encrypted_match_result_root": self.encrypted_match_result_root,
            "output_commitment_root": self.output_commitment_root,
            "token_delta_root": self.token_delta_root,
            "contract_event_root": self.contract_event_root,
            "pq_signature_root": self.pq_signature_root,
            "watcher_weight": self.watcher_weight,
            "quorum_bps": self.quorum_bps,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FastWalletSyncBatchRequest {
    pub relay_id: String,
    pub scan_job_ids: Vec<String>,
    pub reservation_ids: Vec<String>,
    pub attestation_ids: Vec<String>,
    pub encrypted_wallet_delta_root: String,
    pub l2_token_delta_root: String,
    pub smart_contract_receipt_root: String,
    pub batch_fee_piconero: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FastWalletSyncBatch {
    pub batch_id: String,
    pub sequence: u64,
    pub relay_id: String,
    pub scan_job_ids: Vec<String>,
    pub reservation_ids: Vec<String>,
    pub attestation_ids: Vec<String>,
    pub encrypted_wallet_delta_root: String,
    pub l2_token_delta_root: String,
    pub smart_contract_receipt_root: String,
    pub batch_fee_piconero: u64,
    pub status: SyncBatchStatus,
    pub opened_at_l2_height: u64,
    pub settles_after_l2_height: u64,
}

impl FastWalletSyncBatch {
    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "sequence": self.sequence,
            "relay_id": self.relay_id,
            "scan_job_ids": self.scan_job_ids,
            "reservation_ids": self.reservation_ids,
            "attestation_ids": self.attestation_ids,
            "encrypted_wallet_delta_root": self.encrypted_wallet_delta_root,
            "l2_token_delta_root": self.l2_token_delta_root,
            "smart_contract_receipt_root": self.smart_contract_receipt_root,
            "batch_fee_piconero": self.batch_fee_piconero,
            "status": self.status.as_str(),
            "opened_at_l2_height": self.opened_at_l2_height,
            "settles_after_l2_height": self.settles_after_l2_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementReceiptRequest {
    pub batch_id: String,
    pub settlement_operator_id: String,
    pub monero_anchor_height: u64,
    pub monero_anchor_hash: String,
    pub l2_state_transition_root: String,
    pub settlement_proof_root: String,
    pub fee_rebate_root: String,
    pub status: SettlementStatus,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementReceipt {
    pub settlement_id: String,
    pub sequence: u64,
    pub batch_id: String,
    pub settlement_operator_id: String,
    pub monero_anchor_height: u64,
    pub monero_anchor_hash: String,
    pub l2_state_transition_root: String,
    pub settlement_proof_root: String,
    pub fee_rebate_root: String,
    pub status: SettlementStatus,
    pub expires_at_l2_height: u64,
}

impl SettlementReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "settlement_id": self.settlement_id,
            "sequence": self.sequence,
            "batch_id": self.batch_id,
            "settlement_operator_id": self.settlement_operator_id,
            "monero_anchor_height": self.monero_anchor_height,
            "monero_anchor_hash": self.monero_anchor_hash,
            "l2_state_transition_root": self.l2_state_transition_root,
            "settlement_proof_root": self.settlement_proof_root,
            "fee_rebate_root": self.fee_rebate_root,
            "status": self.status.as_str(),
            "expires_at_l2_height": self.expires_at_l2_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub current_l2_height: u64,
    pub view_commitments: BTreeMap<String, ViewTagRangeCommitment>,
    pub scan_jobs: BTreeMap<String, EncryptedScanJob>,
    pub relay_reservations: BTreeMap<String, LowFeeRelayReservation>,
    pub watcher_attestations: BTreeMap<String, WatcherAttestation>,
    pub sync_batches: BTreeMap<String, FastWalletSyncBatch>,
    pub settlement_receipts: BTreeMap<String, SettlementReceipt>,
    pub nullifiers: BTreeSet<String>,
    pub public_records: BTreeMap<String, Value>,
}

impl State {
    pub fn devnet() -> MoneroL2PqPrivateViewSyncRuntimeResult<Self> {
        let mut state = Self::new(Config::devnet());
        let commitment = state.commit_view_tag_range(ViewTagRangeCommitmentRequest {
            wallet_id: "devnet-wallet-view-sync-0".to_string(),
            commitment_nonce: "devnet-view-tag-range-nonce-0".to_string(),
            monero_start_height: MONERO_L2_PQ_PRIVATE_VIEW_SYNC_RUNTIME_DEVNET_HEIGHT,
            monero_end_height: MONERO_L2_PQ_PRIVATE_VIEW_SYNC_RUNTIME_DEVNET_HEIGHT + 48,
            view_tag_range_root: root_from_parts(
                "DEVNET-VIEW-TAG-RANGE",
                &[HashPart::Str("view-tags")],
            ),
            decoy_set_root: root_from_parts("DEVNET-DECOY-SET", &[HashPart::Str("decoys")]),
            encrypted_view_hint_root: root_from_parts(
                "DEVNET-ENCRYPTED-VIEW-HINTS",
                &[HashPart::Str("hints")],
            ),
            pq_view_key_commitment: root_from_parts(
                "DEVNET-PQ-VIEW-KEY-COMMITMENT",
                &[HashPart::Str("pq-view-key")],
            ),
            privacy_set_size: state.config.min_privacy_set_size,
            pq_security_bits: state.config.target_pq_security_bits,
            lane: ViewSyncLane::LowFee,
        })?;
        let job = state.enqueue_encrypted_scan_job(EncryptedScanJobRequest {
            commitment_id: commitment.commitment_id,
            relay_id: "devnet-private-view-relay-0".to_string(),
            encrypted_scan_payload_root: root_from_parts(
                "DEVNET-ENCRYPTED-SCAN-PAYLOAD",
                &[HashPart::Str("scan-payload")],
            ),
            pq_ciphertext_root: root_from_parts(
                "DEVNET-PQ-CIPHERTEXT",
                &[HashPart::Str("ciphertext")],
            ),
            scan_privacy_mode: ScanPrivacyMode::DecoyExpanded,
            requested_output_root: root_from_parts(
                "DEVNET-REQUESTED-OUTPUT",
                &[HashPart::Str("wallet-delta")],
            ),
            max_fee_piconero: 4_000,
            nullifier: "devnet-private-view-sync-nullifier-0".to_string(),
        })?;
        let reservation = state.reserve_low_fee_relay(LowFeeRelayReservationRequest {
            scan_job_id: job.scan_job_id.clone(),
            relay_id: job.relay_id.clone(),
            lane: ViewSyncLane::LowFee,
            reserved_fee_piconero: 1_600,
            sponsor_commitment_root: root_from_parts(
                "DEVNET-SPONSOR-COMMITMENT",
                &[HashPart::Str("sponsor")],
            ),
            relay_capacity_root: root_from_parts(
                "DEVNET-RELAY-CAPACITY",
                &[HashPart::Str("capacity")],
            ),
        })?;
        let attestation = state.submit_watcher_attestation(WatcherAttestationRequest {
            scan_job_id: job.scan_job_id.clone(),
            watcher_id: "devnet-view-sync-watcher-0".to_string(),
            observed_monero_height: MONERO_L2_PQ_PRIVATE_VIEW_SYNC_RUNTIME_DEVNET_HEIGHT + 49,
            encrypted_match_result_root: root_from_parts(
                "DEVNET-ENCRYPTED-MATCH-RESULT",
                &[HashPart::Str("matches")],
            ),
            output_commitment_root: root_from_parts(
                "DEVNET-OUTPUT-COMMITMENTS",
                &[HashPart::Str("outputs")],
            ),
            token_delta_root: root_from_parts(
                "DEVNET-TOKEN-DELTAS",
                &[HashPart::Str("token-deltas")],
            ),
            contract_event_root: root_from_parts(
                "DEVNET-CONTRACT-EVENTS",
                &[HashPart::Str("contract-events")],
            ),
            pq_signature_root: root_from_parts(
                "DEVNET-PQ-WATCHER-SIGNATURE",
                &[HashPart::Str("watcher-sig")],
            ),
            watcher_weight: state.config.min_watcher_count,
        })?;
        let batch = state.build_fast_wallet_sync_batch(FastWalletSyncBatchRequest {
            relay_id: "devnet-private-view-relay-0".to_string(),
            scan_job_ids: vec![job.scan_job_id],
            reservation_ids: vec![reservation.reservation_id],
            attestation_ids: vec![attestation.attestation_id],
            encrypted_wallet_delta_root: root_from_parts(
                "DEVNET-ENCRYPTED-WALLET-DELTAS",
                &[HashPart::Str("wallet-deltas")],
            ),
            l2_token_delta_root: root_from_parts(
                "DEVNET-L2-TOKEN-DELTAS",
                &[HashPart::Str("l2-token-deltas")],
            ),
            smart_contract_receipt_root: root_from_parts(
                "DEVNET-SMART-CONTRACT-RECEIPTS",
                &[HashPart::Str("contract-receipts")],
            ),
            batch_fee_piconero: 1_600,
        })?;
        state.issue_settlement_receipt(SettlementReceiptRequest {
            batch_id: batch.batch_id,
            settlement_operator_id: "devnet-view-sync-settlement-operator-0".to_string(),
            monero_anchor_height: MONERO_L2_PQ_PRIVATE_VIEW_SYNC_RUNTIME_DEVNET_HEIGHT + 60,
            monero_anchor_hash: root_from_parts("DEVNET-MONERO-ANCHOR", &[HashPart::Str("anchor")]),
            l2_state_transition_root: state.state_root(),
            settlement_proof_root: root_from_parts(
                "DEVNET-SETTLEMENT-PROOF",
                &[HashPart::Str("proof")],
            ),
            fee_rebate_root: root_from_parts("DEVNET-FEE-REBATE", &[HashPart::Str("rebate")]),
            status: SettlementStatus::Finalized,
        })?;
        Ok(state)
    }

    pub fn new(config: Config) -> Self {
        Self {
            config,
            counters: Counters::default(),
            current_l2_height: MONERO_L2_PQ_PRIVATE_VIEW_SYNC_RUNTIME_DEVNET_HEIGHT,
            view_commitments: BTreeMap::new(),
            scan_jobs: BTreeMap::new(),
            relay_reservations: BTreeMap::new(),
            watcher_attestations: BTreeMap::new(),
            sync_batches: BTreeMap::new(),
            settlement_receipts: BTreeMap::new(),
            nullifiers: BTreeSet::new(),
            public_records: BTreeMap::new(),
        }
    }

    pub fn commit_view_tag_range(
        &mut self,
        request: ViewTagRangeCommitmentRequest,
    ) -> MoneroL2PqPrivateViewSyncRuntimeResult<ViewTagRangeCommitment> {
        require_non_empty("wallet_id", &request.wallet_id)?;
        require_non_empty("commitment_nonce", &request.commitment_nonce)?;
        require_non_empty("view_tag_range_root", &request.view_tag_range_root)?;
        require_non_empty("decoy_set_root", &request.decoy_set_root)?;
        require_non_empty(
            "encrypted_view_hint_root",
            &request.encrypted_view_hint_root,
        )?;
        require_non_empty("pq_view_key_commitment", &request.pq_view_key_commitment)?;
        if request.monero_end_height < request.monero_start_height {
            return Err("monero_end_height must be >= monero_start_height".to_string());
        }
        let span = request
            .monero_end_height
            .saturating_sub(request.monero_start_height)
            .saturating_add(1);
        if span > self.config.max_view_tag_span {
            return Err("view-tag range exceeds configured privacy span".to_string());
        }
        if request.privacy_set_size < self.config.min_privacy_set_size {
            return Err("privacy set below configured minimum".to_string());
        }
        if request.pq_security_bits < self.config.min_pq_security_bits {
            return Err("PQ security bits below configured minimum".to_string());
        }
        ensure_capacity(
            self.view_commitments.len(),
            MONERO_L2_PQ_PRIVATE_VIEW_SYNC_RUNTIME_MAX_VIEW_COMMITMENTS,
            "view commitments",
        )?;
        self.counters.view_commitment_counter += 1;
        let sequence = self.counters.view_commitment_counter;
        let commitment_id = root_from_parts(
            "MONERO-L2-PQ-PRIVATE-VIEW-SYNC-COMMITMENT-ID",
            &[
                HashPart::U64(sequence),
                HashPart::Str(&request.wallet_id),
                HashPart::Str(&request.commitment_nonce),
            ],
        );
        let commitment = ViewTagRangeCommitment {
            commitment_id,
            sequence,
            wallet_id: request.wallet_id,
            commitment_nonce: request.commitment_nonce,
            monero_start_height: request.monero_start_height,
            monero_end_height: request.monero_end_height,
            view_tag_range_root: request.view_tag_range_root,
            decoy_set_root: request.decoy_set_root,
            encrypted_view_hint_root: request.encrypted_view_hint_root,
            pq_view_key_commitment: request.pq_view_key_commitment,
            privacy_set_size: request.privacy_set_size,
            pq_security_bits: request.pq_security_bits,
            lane: request.lane,
            status: CommitmentStatus::Open,
            expires_at_l2_height: self
                .current_l2_height
                .saturating_add(self.config.scan_ttl_blocks),
        };
        self.record_public(
            format!("view_commitment:{}", commitment.commitment_id),
            commitment.public_record(),
        )?;
        self.view_commitments
            .insert(commitment.commitment_id.clone(), commitment.clone());
        Ok(commitment)
    }

    pub fn enqueue_encrypted_scan_job(
        &mut self,
        request: EncryptedScanJobRequest,
    ) -> MoneroL2PqPrivateViewSyncRuntimeResult<EncryptedScanJob> {
        require_non_empty("commitment_id", &request.commitment_id)?;
        require_non_empty("relay_id", &request.relay_id)?;
        require_non_empty(
            "encrypted_scan_payload_root",
            &request.encrypted_scan_payload_root,
        )?;
        require_non_empty("pq_ciphertext_root", &request.pq_ciphertext_root)?;
        require_non_empty("requested_output_root", &request.requested_output_root)?;
        require_non_empty("nullifier", &request.nullifier)?;
        ensure_capacity(
            self.scan_jobs.len(),
            MONERO_L2_PQ_PRIVATE_VIEW_SYNC_RUNTIME_MAX_SCAN_JOBS,
            "scan jobs",
        )?;
        if self.nullifiers.contains(&request.nullifier) {
            return Err("scan job nullifier already consumed".to_string());
        }
        let commitment_record = {
            let commitment = self
                .view_commitments
                .get_mut(&request.commitment_id)
                .ok_or_else(|| "unknown view-tag commitment".to_string())?;
            commitment.status = CommitmentStatus::Scanning;
            (
                format!("view_commitment:{}", commitment.commitment_id),
                commitment.public_record(),
            )
        };
        self.counters.scan_job_counter += 1;
        let sequence = self.counters.scan_job_counter;
        let scan_job_id = root_from_parts(
            "MONERO-L2-PQ-PRIVATE-VIEW-SYNC-SCAN-JOB-ID",
            &[
                HashPart::U64(sequence),
                HashPart::Str(&request.commitment_id),
                HashPart::Str(&request.nullifier),
            ],
        );
        let job = EncryptedScanJob {
            scan_job_id,
            sequence,
            commitment_id: request.commitment_id,
            relay_id: request.relay_id,
            encrypted_scan_payload_root: request.encrypted_scan_payload_root,
            pq_ciphertext_root: request.pq_ciphertext_root,
            scan_privacy_mode: request.scan_privacy_mode,
            requested_output_root: request.requested_output_root,
            max_fee_piconero: request.max_fee_piconero,
            nullifier: request.nullifier,
            status: ScanJobStatus::Queued,
            created_at_l2_height: self.current_l2_height,
            expires_at_l2_height: self
                .current_l2_height
                .saturating_add(self.config.scan_ttl_blocks),
        };
        self.nullifiers.insert(job.nullifier.clone());
        self.record_public(format!("scan_job:{}", job.scan_job_id), job.public_record())?;
        self.record_public(commitment_record.0, commitment_record.1)?;
        self.scan_jobs.insert(job.scan_job_id.clone(), job.clone());
        Ok(job)
    }

    pub fn reserve_low_fee_relay(
        &mut self,
        request: LowFeeRelayReservationRequest,
    ) -> MoneroL2PqPrivateViewSyncRuntimeResult<LowFeeRelayReservation> {
        require_non_empty("scan_job_id", &request.scan_job_id)?;
        require_non_empty("relay_id", &request.relay_id)?;
        require_non_empty("sponsor_commitment_root", &request.sponsor_commitment_root)?;
        require_non_empty("relay_capacity_root", &request.relay_capacity_root)?;
        ensure_capacity(
            self.relay_reservations.len(),
            MONERO_L2_PQ_PRIVATE_VIEW_SYNC_RUNTIME_MAX_RELAY_RESERVATIONS,
            "relay reservations",
        )?;
        let job_record = {
            let job = self
                .scan_jobs
                .get_mut(&request.scan_job_id)
                .ok_or_else(|| "unknown encrypted scan job".to_string())?;
            if request.reserved_fee_piconero > job.max_fee_piconero {
                return Err("reserved fee exceeds encrypted scan job maximum".to_string());
            }
            job.status = ScanJobStatus::Reserved;
            (format!("scan_job:{}", job.scan_job_id), job.public_record())
        };
        self.counters.relay_reservation_counter += 1;
        let sequence = self.counters.relay_reservation_counter;
        let reservation_id = root_from_parts(
            "MONERO-L2-PQ-PRIVATE-VIEW-SYNC-RELAY-RESERVATION-ID",
            &[
                HashPart::U64(sequence),
                HashPart::Str(&request.scan_job_id),
                HashPart::Str(&request.relay_id),
            ],
        );
        let reservation = LowFeeRelayReservation {
            reservation_id,
            sequence,
            scan_job_id: request.scan_job_id,
            relay_id: request.relay_id,
            lane: request.lane,
            fee_bps: request.lane.fee_bps(&self.config),
            reserved_fee_piconero: request.reserved_fee_piconero,
            sponsor_commitment_root: request.sponsor_commitment_root,
            relay_capacity_root: request.relay_capacity_root,
            status: ReservationStatus::Held,
            expires_at_l2_height: self
                .current_l2_height
                .saturating_add(self.config.reservation_ttl_blocks),
        };
        self.record_public(
            format!("relay_reservation:{}", reservation.reservation_id),
            reservation.public_record(),
        )?;
        self.record_public(job_record.0, job_record.1)?;
        self.relay_reservations
            .insert(reservation.reservation_id.clone(), reservation.clone());
        Ok(reservation)
    }

    pub fn submit_watcher_attestation(
        &mut self,
        request: WatcherAttestationRequest,
    ) -> MoneroL2PqPrivateViewSyncRuntimeResult<WatcherAttestation> {
        require_non_empty("scan_job_id", &request.scan_job_id)?;
        require_non_empty("watcher_id", &request.watcher_id)?;
        require_non_empty(
            "encrypted_match_result_root",
            &request.encrypted_match_result_root,
        )?;
        require_non_empty("output_commitment_root", &request.output_commitment_root)?;
        require_non_empty("token_delta_root", &request.token_delta_root)?;
        require_non_empty("contract_event_root", &request.contract_event_root)?;
        require_non_empty("pq_signature_root", &request.pq_signature_root)?;
        ensure_capacity(
            self.watcher_attestations.len(),
            MONERO_L2_PQ_PRIVATE_VIEW_SYNC_RUNTIME_MAX_WATCHER_ATTESTATIONS,
            "watcher attestations",
        )?;
        let quorum_bps = if request.watcher_weight >= self.config.min_watcher_count {
            self.config.watcher_quorum_bps
        } else {
            self.config.watcher_quorum_bps / 2
        };
        let status = if quorum_bps >= self.config.watcher_quorum_bps {
            WatcherAttestationStatus::Accepted
        } else {
            WatcherAttestationStatus::WeakQuorum
        };
        let job_record = {
            let job = self
                .scan_jobs
                .get_mut(&request.scan_job_id)
                .ok_or_else(|| "unknown encrypted scan job".to_string())?;
            if status == WatcherAttestationStatus::Accepted {
                job.status = ScanJobStatus::Attested;
            }
            (format!("scan_job:{}", job.scan_job_id), job.public_record())
        };
        self.counters.watcher_attestation_counter += 1;
        let sequence = self.counters.watcher_attestation_counter;
        let attestation_id = root_from_parts(
            "MONERO-L2-PQ-PRIVATE-VIEW-SYNC-WATCHER-ATTESTATION-ID",
            &[
                HashPart::U64(sequence),
                HashPart::Str(&request.scan_job_id),
                HashPart::Str(&request.watcher_id),
            ],
        );
        let attestation = WatcherAttestation {
            attestation_id,
            sequence,
            scan_job_id: request.scan_job_id,
            watcher_id: request.watcher_id,
            observed_monero_height: request.observed_monero_height,
            encrypted_match_result_root: request.encrypted_match_result_root,
            output_commitment_root: request.output_commitment_root,
            token_delta_root: request.token_delta_root,
            contract_event_root: request.contract_event_root,
            pq_signature_root: request.pq_signature_root,
            watcher_weight: request.watcher_weight,
            quorum_bps,
            status,
        };
        self.record_public(
            format!("watcher_attestation:{}", attestation.attestation_id),
            attestation.public_record(),
        )?;
        self.record_public(job_record.0, job_record.1)?;
        self.watcher_attestations
            .insert(attestation.attestation_id.clone(), attestation.clone());
        Ok(attestation)
    }

    pub fn build_fast_wallet_sync_batch(
        &mut self,
        request: FastWalletSyncBatchRequest,
    ) -> MoneroL2PqPrivateViewSyncRuntimeResult<FastWalletSyncBatch> {
        require_non_empty("relay_id", &request.relay_id)?;
        require_non_empty(
            "encrypted_wallet_delta_root",
            &request.encrypted_wallet_delta_root,
        )?;
        require_non_empty("l2_token_delta_root", &request.l2_token_delta_root)?;
        require_non_empty(
            "smart_contract_receipt_root",
            &request.smart_contract_receipt_root,
        )?;
        if request.scan_job_ids.is_empty() {
            return Err("sync batch must include at least one scan job".to_string());
        }
        ensure_capacity(
            self.sync_batches.len(),
            MONERO_L2_PQ_PRIVATE_VIEW_SYNC_RUNTIME_MAX_SYNC_BATCHES,
            "sync batches",
        )?;
        for scan_job_id in &request.scan_job_ids {
            let (job_record, commitment_id) = {
                let job = self
                    .scan_jobs
                    .get_mut(scan_job_id)
                    .ok_or_else(|| format!("unknown encrypted scan job: {scan_job_id}"))?;
                job.status = ScanJobStatus::Batched;
                (
                    (format!("scan_job:{scan_job_id}"), job.public_record()),
                    job.commitment_id.clone(),
                )
            };
            self.record_public(job_record.0, job_record.1)?;
            if let Some(commitment_record) =
                self.view_commitments
                    .get_mut(&commitment_id)
                    .map(|commitment| {
                        commitment.status = CommitmentStatus::Batched;
                        (
                            format!("view_commitment:{}", commitment.commitment_id),
                            commitment.public_record(),
                        )
                    })
            {
                self.record_public(commitment_record.0, commitment_record.1)?;
            }
        }
        for reservation_id in &request.reservation_ids {
            let reservation_record = {
                let reservation = self
                    .relay_reservations
                    .get_mut(reservation_id)
                    .ok_or_else(|| format!("unknown relay reservation: {reservation_id}"))?;
                reservation.status = ReservationStatus::Batched;
                (
                    format!("relay_reservation:{reservation_id}"),
                    reservation.public_record(),
                )
            };
            self.record_public(reservation_record.0, reservation_record.1)?;
        }
        for attestation_id in &request.attestation_ids {
            if !self.watcher_attestations.contains_key(attestation_id) {
                return Err(format!("unknown watcher attestation: {attestation_id}"));
            }
        }
        self.counters.sync_batch_counter += 1;
        let sequence = self.counters.sync_batch_counter;
        let batch_id = root_from_parts(
            "MONERO-L2-PQ-PRIVATE-VIEW-SYNC-BATCH-ID",
            &[HashPart::U64(sequence), HashPart::Str(&request.relay_id)],
        );
        let batch = FastWalletSyncBatch {
            batch_id,
            sequence,
            relay_id: request.relay_id,
            scan_job_ids: request.scan_job_ids,
            reservation_ids: request.reservation_ids,
            attestation_ids: request.attestation_ids,
            encrypted_wallet_delta_root: request.encrypted_wallet_delta_root,
            l2_token_delta_root: request.l2_token_delta_root,
            smart_contract_receipt_root: request.smart_contract_receipt_root,
            batch_fee_piconero: request.batch_fee_piconero,
            status: SyncBatchStatus::SettlementReady,
            opened_at_l2_height: self.current_l2_height,
            settles_after_l2_height: self
                .current_l2_height
                .saturating_add(self.config.batch_window_blocks),
        };
        self.record_public(
            format!("sync_batch:{}", batch.batch_id),
            batch.public_record(),
        )?;
        self.sync_batches
            .insert(batch.batch_id.clone(), batch.clone());
        Ok(batch)
    }

    pub fn issue_settlement_receipt(
        &mut self,
        request: SettlementReceiptRequest,
    ) -> MoneroL2PqPrivateViewSyncRuntimeResult<SettlementReceipt> {
        require_non_empty("batch_id", &request.batch_id)?;
        require_non_empty("settlement_operator_id", &request.settlement_operator_id)?;
        require_non_empty("monero_anchor_hash", &request.monero_anchor_hash)?;
        require_non_empty(
            "l2_state_transition_root",
            &request.l2_state_transition_root,
        )?;
        require_non_empty("settlement_proof_root", &request.settlement_proof_root)?;
        require_non_empty("fee_rebate_root", &request.fee_rebate_root)?;
        ensure_capacity(
            self.settlement_receipts.len(),
            MONERO_L2_PQ_PRIVATE_VIEW_SYNC_RUNTIME_MAX_SETTLEMENT_RECEIPTS,
            "settlement receipts",
        )?;
        let (batch_record, scan_job_ids, reservation_ids) = {
            let batch = self
                .sync_batches
                .get_mut(&request.batch_id)
                .ok_or_else(|| "unknown fast wallet sync batch".to_string())?;
            batch.status = if request.status == SettlementStatus::Disputed {
                SyncBatchStatus::Disputed
            } else {
                SyncBatchStatus::Settled
            };
            (
                (
                    format!("sync_batch:{}", batch.batch_id),
                    batch.public_record(),
                ),
                batch.scan_job_ids.clone(),
                batch.reservation_ids.clone(),
            )
        };
        self.counters.settlement_receipt_counter += 1;
        let sequence = self.counters.settlement_receipt_counter;
        let settlement_id = root_from_parts(
            "MONERO-L2-PQ-PRIVATE-VIEW-SYNC-SETTLEMENT-ID",
            &[
                HashPart::U64(sequence),
                HashPart::Str(&request.batch_id),
                HashPart::Str(&request.monero_anchor_hash),
            ],
        );
        let receipt = SettlementReceipt {
            settlement_id,
            sequence,
            batch_id: request.batch_id,
            settlement_operator_id: request.settlement_operator_id,
            monero_anchor_height: request.monero_anchor_height,
            monero_anchor_hash: request.monero_anchor_hash,
            l2_state_transition_root: request.l2_state_transition_root,
            settlement_proof_root: request.settlement_proof_root,
            fee_rebate_root: request.fee_rebate_root,
            status: request.status,
            expires_at_l2_height: self
                .current_l2_height
                .saturating_add(self.config.settlement_ttl_blocks),
        };
        self.record_public(batch_record.0, batch_record.1)?;
        for scan_job_id in scan_job_ids {
            if let Some((job_record, commitment_id)) =
                self.scan_jobs.get_mut(&scan_job_id).map(|job| {
                    job.status = ScanJobStatus::Settled;
                    (
                        (format!("scan_job:{scan_job_id}"), job.public_record()),
                        job.commitment_id.clone(),
                    )
                })
            {
                self.record_public(job_record.0, job_record.1)?;
                if let Some(commitment_record) =
                    self.view_commitments
                        .get_mut(&commitment_id)
                        .map(|commitment| {
                            commitment.status = CommitmentStatus::Settled;
                            (
                                format!("view_commitment:{}", commitment.commitment_id),
                                commitment.public_record(),
                            )
                        })
                {
                    self.record_public(commitment_record.0, commitment_record.1)?;
                }
            }
        }
        for reservation_id in reservation_ids {
            if let Some(reservation_record) =
                self.relay_reservations
                    .get_mut(&reservation_id)
                    .map(|reservation| {
                        reservation.status = ReservationStatus::Settled;
                        (
                            format!("relay_reservation:{reservation_id}"),
                            reservation.public_record(),
                        )
                    })
            {
                self.record_public(reservation_record.0, reservation_record.1)?;
            }
        }
        self.record_public(
            format!("settlement_receipt:{}", receipt.settlement_id),
            receipt.public_record(),
        )?;
        self.settlement_receipts
            .insert(receipt.settlement_id.clone(), receipt.clone());
        Ok(receipt)
    }

    pub fn advance_l2_height(&mut self, next_height: u64) {
        self.current_l2_height = self.current_l2_height.max(next_height);
    }

    pub fn counters(&self) -> Counters {
        let mut counters = self.counters.clone();
        counters.public_records = self.public_records.len();
        counters
    }

    pub fn roots(&self) -> Roots {
        Roots {
            config_root: root_from_record(
                "MONERO-L2-PQ-PRIVATE-VIEW-SYNC-CONFIG",
                &self.config.public_record(),
            ),
            counter_root: root_from_record(
                "MONERO-L2-PQ-PRIVATE-VIEW-SYNC-COUNTERS",
                &self.counters().public_record(),
            ),
            view_commitment_root: public_record_root(
                "MONERO-L2-PQ-PRIVATE-VIEW-SYNC-VIEW-COMMITMENTS",
                &self
                    .view_commitments
                    .values()
                    .map(ViewTagRangeCommitment::public_record)
                    .collect::<Vec<_>>(),
            ),
            scan_job_root: public_record_root(
                "MONERO-L2-PQ-PRIVATE-VIEW-SYNC-SCAN-JOBS",
                &self
                    .scan_jobs
                    .values()
                    .map(EncryptedScanJob::public_record)
                    .collect::<Vec<_>>(),
            ),
            relay_reservation_root: public_record_root(
                "MONERO-L2-PQ-PRIVATE-VIEW-SYNC-RELAY-RESERVATIONS",
                &self
                    .relay_reservations
                    .values()
                    .map(LowFeeRelayReservation::public_record)
                    .collect::<Vec<_>>(),
            ),
            watcher_attestation_root: public_record_root(
                "MONERO-L2-PQ-PRIVATE-VIEW-SYNC-WATCHER-ATTESTATIONS",
                &self
                    .watcher_attestations
                    .values()
                    .map(WatcherAttestation::public_record)
                    .collect::<Vec<_>>(),
            ),
            sync_batch_root: public_record_root(
                "MONERO-L2-PQ-PRIVATE-VIEW-SYNC-BATCHES",
                &self
                    .sync_batches
                    .values()
                    .map(FastWalletSyncBatch::public_record)
                    .collect::<Vec<_>>(),
            ),
            settlement_receipt_root: public_record_root(
                "MONERO-L2-PQ-PRIVATE-VIEW-SYNC-SETTLEMENT-RECEIPTS",
                &self
                    .settlement_receipts
                    .values()
                    .map(SettlementReceipt::public_record)
                    .collect::<Vec<_>>(),
            ),
            nullifier_root: public_record_root(
                "MONERO-L2-PQ-PRIVATE-VIEW-SYNC-NULLIFIERS",
                &self.nullifiers.iter().map(|n| json!(n)).collect::<Vec<_>>(),
            ),
            public_record_root: public_record_root(
                "MONERO-L2-PQ-PRIVATE-VIEW-SYNC-PUBLIC-RECORDS",
                &self.public_records.values().cloned().collect::<Vec<_>>(),
            ),
        }
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "protocol_version": self.config.protocol_version,
            "schema_version": self.config.schema_version,
            "current_l2_height": self.current_l2_height,
            "config": self.config.public_record(),
            "roots": self.roots().public_record(),
            "counters": self.counters().public_record(),
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_root();
        record["state_root"] = json!(self.state_root());
        record
    }

    pub fn state_root(&self) -> String {
        root_from_record(
            "MONERO-L2-PQ-PRIVATE-VIEW-SYNC-STATE",
            &self.public_record_without_root(),
        )
    }

    fn record_public(
        &mut self,
        key: String,
        record: Value,
    ) -> MoneroL2PqPrivateViewSyncRuntimeResult<()> {
        if !self.public_records.contains_key(&key) {
            ensure_capacity(
                self.public_records.len(),
                MONERO_L2_PQ_PRIVATE_VIEW_SYNC_RUNTIME_MAX_PUBLIC_RECORDS,
                "public records",
            )?;
        }
        self.public_records.insert(key, record);
        Ok(())
    }
}

pub fn monero_l2_pq_private_view_sync_runtime_state_root(state: &State) -> String {
    state.state_root()
}

pub fn monero_l2_pq_private_view_sync_runtime_public_record(state: &State) -> Value {
    state.public_record()
}

pub fn public_record_root(domain: &str, records: &[Value]) -> String {
    let mut sorted = records.to_vec();
    sorted.sort_by_key(crate::hash::canonical_json_string);
    merkle_root(domain, &sorted)
}

pub fn state_root_from_record(record: &Value) -> String {
    root_from_record("MONERO-L2-PQ-PRIVATE-VIEW-SYNC-STATE", record)
}

pub fn root_from_record(domain: &str, record: &Value) -> String {
    domain_hash(
        domain,
        &[HashPart::Str(&crate::hash::canonical_json_string(record))],
        32,
    )
}

pub fn root_from_parts(domain: &str, parts: &[HashPart<'_>]) -> String {
    domain_hash(domain, parts, 32)
}

fn ensure_capacity(
    current: usize,
    max: usize,
    label: &str,
) -> MoneroL2PqPrivateViewSyncRuntimeResult<()> {
    if current >= max {
        Err(format!("{label} capacity exceeded"))
    } else {
        Ok(())
    }
}

fn require_non_empty(field: &str, value: &str) -> MoneroL2PqPrivateViewSyncRuntimeResult<()> {
    if value.trim().is_empty() {
        Err(format!("{field} is required"))
    } else {
        Ok(())
    }
}
