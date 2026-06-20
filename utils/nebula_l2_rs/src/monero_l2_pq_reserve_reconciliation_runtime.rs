use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type MoneroL2PqReserveReconciliationRuntimeResult<T> = Result<T, String>;

pub const MONERO_L2_PQ_RESERVE_RECONCILIATION_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-reserve-reconciliation-runtime-v1";
pub const PROTOCOL_VERSION: &str = MONERO_L2_PQ_RESERVE_RECONCILIATION_RUNTIME_PROTOCOL_VERSION;
pub const MONERO_L2_PQ_RESERVE_RECONCILIATION_RUNTIME_SCHEMA_VERSION: u64 = 1;
pub const MONERO_L2_PQ_RESERVE_RECONCILIATION_RUNTIME_DEVNET_HEIGHT: u64 = 512_000;
pub const MONERO_L2_PQ_RESERVE_RECONCILIATION_RUNTIME_DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const MONERO_L2_PQ_RESERVE_RECONCILIATION_RUNTIME_DEVNET_L2_NETWORK: &str = "nebula-devnet";
pub const MONERO_L2_PQ_RESERVE_RECONCILIATION_RUNTIME_DEVNET_ASSET_ID: &str = "wxmr-devnet";
pub const MONERO_L2_PQ_RESERVE_RECONCILIATION_RUNTIME_DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const MONERO_L2_PQ_RESERVE_RECONCILIATION_RUNTIME_DEVNET_COMMITTEE_ID: &str =
    "monero-l2-pq-reserve-reconciliation-devnet-watchers";
pub const MONERO_L2_PQ_RESERVE_RECONCILIATION_RUNTIME_HASH_SUITE: &str =
    "SHAKE256-domain-separated-canonical-json";
pub const MONERO_L2_PQ_RESERVE_RECONCILIATION_RUNTIME_PQ_ATTESTATION_SUITE: &str =
    "ML-DSA-87+SLH-DSA-SHAKE-192f-reserve-reconciliation-v1";
pub const MONERO_L2_PQ_RESERVE_RECONCILIATION_RUNTIME_SNAPSHOT_SCHEME: &str =
    "roots-only-monero-l2-pq-reserve-snapshot-v1";
pub const MONERO_L2_PQ_RESERVE_RECONCILIATION_RUNTIME_REPORT_SCHEME: &str =
    "ml-kem-1024-sealed-encrypted-reserve-reconciliation-report-v1";
pub const MONERO_L2_PQ_RESERVE_RECONCILIATION_RUNTIME_WATCHER_QUORUM_SCHEME: &str =
    "privacy-preserving-reserve-watcher-quorum-root-v1";
pub const MONERO_L2_PQ_RESERVE_RECONCILIATION_RUNTIME_DISPUTE_RESERVATION_SCHEME: &str =
    "low-fee-private-reserve-dispute-reservation-root-v1";
pub const MONERO_L2_PQ_RESERVE_RECONCILIATION_RUNTIME_DELTA_BATCH_SCHEME: &str =
    "monero-reserve-delta-batch-root-v1";
pub const MONERO_L2_PQ_RESERVE_RECONCILIATION_RUNTIME_SETTLEMENT_MANIFEST_SCHEME: &str =
    "reserve-safe-private-settlement-manifest-root-v1";
pub const MONERO_L2_PQ_RESERVE_RECONCILIATION_RUNTIME_RECEIPT_SCHEME: &str =
    "monero-l2-pq-reserve-reconciliation-receipt-v1";
pub const MONERO_L2_PQ_RESERVE_RECONCILIATION_RUNTIME_REPLAY_DOMAIN: &str =
    "monero-l2-pq-reserve-reconciliation-devnet";
pub const MONERO_L2_PQ_RESERVE_RECONCILIATION_RUNTIME_MAX_BPS: u64 = 10_000;
pub const MONERO_L2_PQ_RESERVE_RECONCILIATION_RUNTIME_DEFAULT_SNAPSHOT_TTL_BLOCKS: u64 = 36;
pub const MONERO_L2_PQ_RESERVE_RECONCILIATION_RUNTIME_DEFAULT_REPORT_TTL_BLOCKS: u64 = 24;
pub const MONERO_L2_PQ_RESERVE_RECONCILIATION_RUNTIME_DEFAULT_DISPUTE_TTL_BLOCKS: u64 = 72;
pub const MONERO_L2_PQ_RESERVE_RECONCILIATION_RUNTIME_DEFAULT_SETTLEMENT_TTL_BLOCKS: u64 = 144;
pub const MONERO_L2_PQ_RESERVE_RECONCILIATION_RUNTIME_DEFAULT_MIN_RESERVE_COVERAGE_BPS: u64 =
    10_000;
pub const MONERO_L2_PQ_RESERVE_RECONCILIATION_RUNTIME_DEFAULT_TARGET_RESERVE_COVERAGE_BPS: u64 =
    12_000;
pub const MONERO_L2_PQ_RESERVE_RECONCILIATION_RUNTIME_DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 16_384;
pub const MONERO_L2_PQ_RESERVE_RECONCILIATION_RUNTIME_DEFAULT_MIN_WATCHER_COUNT: u64 = 2;
pub const MONERO_L2_PQ_RESERVE_RECONCILIATION_RUNTIME_DEFAULT_MIN_WATCHER_WEIGHT: u64 = 3;
pub const MONERO_L2_PQ_RESERVE_RECONCILIATION_RUNTIME_DEFAULT_WATCHER_QUORUM_BPS: u64 = 6_700;
pub const MONERO_L2_PQ_RESERVE_RECONCILIATION_RUNTIME_DEFAULT_STRONG_QUORUM_BPS: u64 = 8_000;
pub const MONERO_L2_PQ_RESERVE_RECONCILIATION_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 192;
pub const MONERO_L2_PQ_RESERVE_RECONCILIATION_RUNTIME_DEFAULT_TARGET_PQ_SECURITY_BITS: u16 = 256;
pub const MONERO_L2_PQ_RESERVE_RECONCILIATION_RUNTIME_DEFAULT_LOW_FEE_BPS: u64 = 5;
pub const MONERO_L2_PQ_RESERVE_RECONCILIATION_RUNTIME_DEFAULT_MAX_USER_FEE_BPS: u64 = 24;
pub const MONERO_L2_PQ_RESERVE_RECONCILIATION_RUNTIME_DEFAULT_MAX_DELTA_BATCH_ITEMS: usize = 512;
pub const MONERO_L2_PQ_RESERVE_RECONCILIATION_RUNTIME_MAX_SNAPSHOTS: usize = 262_144;
pub const MONERO_L2_PQ_RESERVE_RECONCILIATION_RUNTIME_MAX_REPORTS: usize = 524_288;
pub const MONERO_L2_PQ_RESERVE_RECONCILIATION_RUNTIME_MAX_ATTESTATIONS: usize = 1_048_576;
pub const MONERO_L2_PQ_RESERVE_RECONCILIATION_RUNTIME_MAX_DISPUTES: usize = 262_144;
pub const MONERO_L2_PQ_RESERVE_RECONCILIATION_RUNTIME_MAX_DELTA_BATCHES: usize = 262_144;
pub const MONERO_L2_PQ_RESERVE_RECONCILIATION_RUNTIME_MAX_MANIFESTS: usize = 262_144;
pub const MONERO_L2_PQ_RESERVE_RECONCILIATION_RUNTIME_MAX_RECEIPTS: usize = 524_288;
pub const MONERO_L2_PQ_RESERVE_RECONCILIATION_RUNTIME_MAX_PUBLIC_RECORDS: usize = 1_048_576;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReconciliationLane {
    LowFee,
    Fast,
    Defi,
    Token,
    SmartContract,
    Emergency,
}

impl ReconciliationLane {
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
            Self::Defi | Self::Token | Self::SmartContract => {
                config.max_user_fee_bps.saturating_mul(2) / 3
            }
            Self::Fast | Self::Emergency => config.max_user_fee_bps,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotStatus {
    Open,
    Reported,
    QuorumAttested,
    DeltaBatched,
    Settled,
    Disputed,
    Expired,
}

impl SnapshotStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Reported => "reported",
            Self::QuorumAttested => "quorum_attested",
            Self::DeltaBatched => "delta_batched",
            Self::Settled => "settled",
            Self::Disputed => "disputed",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReportStatus {
    Submitted,
    Accepted,
    QuorumAttested,
    Batched,
    Settled,
    Disputed,
    Rejected,
}

impl ReportStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Accepted => "accepted",
            Self::QuorumAttested => "quorum_attested",
            Self::Batched => "batched",
            Self::Settled => "settled",
            Self::Disputed => "disputed",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationStatus {
    Submitted,
    Accepted,
    StrongQuorum,
    WeakQuorum,
    Superseded,
    Rejected,
}

impl AttestationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Accepted => "accepted",
            Self::StrongQuorum => "strong_quorum",
            Self::WeakQuorum => "weak_quorum",
            Self::Superseded => "superseded",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DisputeStatus {
    Reserved,
    EvidenceSubmitted,
    Sustained,
    Rejected,
    Released,
    Expired,
}

impl DisputeStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::EvidenceSubmitted => "evidence_submitted",
            Self::Sustained => "sustained",
            Self::Rejected => "rejected",
            Self::Released => "released",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeltaBatchStatus {
    Built,
    ManifestReady,
    Settled,
    Disputed,
    Rejected,
}

impl DeltaBatchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Built => "built",
            Self::ManifestReady => "manifest_ready",
            Self::Settled => "settled",
            Self::Disputed => "disputed",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ManifestStatus {
    Published,
    Finalized,
    Reconciled,
    Disputed,
    Failed,
}

impl ManifestStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Published => "published",
            Self::Finalized => "finalized",
            Self::Reconciled => "reconciled",
            Self::Disputed => "disputed",
            Self::Failed => "failed",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptKind {
    SnapshotRecorded,
    ReportAccepted,
    WatcherQuorumAccepted,
    DisputeReserved,
    DeltaBatchBuilt,
    SettlementManifestFinalized,
}

impl ReceiptKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SnapshotRecorded => "snapshot_recorded",
            Self::ReportAccepted => "report_accepted",
            Self::WatcherQuorumAccepted => "watcher_quorum_accepted",
            Self::DisputeReserved => "dispute_reserved",
            Self::DeltaBatchBuilt => "delta_batch_built",
            Self::SettlementManifestFinalized => "settlement_manifest_finalized",
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
    pub committee_id: String,
    pub hash_suite: String,
    pub pq_attestation_suite: String,
    pub snapshot_scheme: String,
    pub report_scheme: String,
    pub watcher_quorum_scheme: String,
    pub dispute_reservation_scheme: String,
    pub delta_batch_scheme: String,
    pub settlement_manifest_scheme: String,
    pub receipt_scheme: String,
    pub replay_domain: String,
    pub genesis_height: u64,
    pub snapshot_ttl_blocks: u64,
    pub report_ttl_blocks: u64,
    pub dispute_ttl_blocks: u64,
    pub settlement_ttl_blocks: u64,
    pub min_reserve_coverage_bps: u64,
    pub target_reserve_coverage_bps: u64,
    pub min_privacy_set_size: u64,
    pub min_watcher_count: u64,
    pub min_watcher_weight: u64,
    pub watcher_quorum_bps: u64,
    pub strong_quorum_bps: u64,
    pub min_pq_security_bits: u16,
    pub target_pq_security_bits: u16,
    pub low_fee_bps: u64,
    pub max_user_fee_bps: u64,
    pub max_delta_batch_items: usize,
    pub roots_only: bool,
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
            schema_version: MONERO_L2_PQ_RESERVE_RECONCILIATION_RUNTIME_SCHEMA_VERSION,
            monero_network: MONERO_L2_PQ_RESERVE_RECONCILIATION_RUNTIME_DEVNET_MONERO_NETWORK
                .to_string(),
            l2_network: MONERO_L2_PQ_RESERVE_RECONCILIATION_RUNTIME_DEVNET_L2_NETWORK.to_string(),
            asset_id: MONERO_L2_PQ_RESERVE_RECONCILIATION_RUNTIME_DEVNET_ASSET_ID.to_string(),
            fee_asset_id: MONERO_L2_PQ_RESERVE_RECONCILIATION_RUNTIME_DEVNET_FEE_ASSET_ID
                .to_string(),
            committee_id: MONERO_L2_PQ_RESERVE_RECONCILIATION_RUNTIME_DEVNET_COMMITTEE_ID
                .to_string(),
            hash_suite: MONERO_L2_PQ_RESERVE_RECONCILIATION_RUNTIME_HASH_SUITE.to_string(),
            pq_attestation_suite: MONERO_L2_PQ_RESERVE_RECONCILIATION_RUNTIME_PQ_ATTESTATION_SUITE
                .to_string(),
            snapshot_scheme: MONERO_L2_PQ_RESERVE_RECONCILIATION_RUNTIME_SNAPSHOT_SCHEME
                .to_string(),
            report_scheme: MONERO_L2_PQ_RESERVE_RECONCILIATION_RUNTIME_REPORT_SCHEME.to_string(),
            watcher_quorum_scheme:
                MONERO_L2_PQ_RESERVE_RECONCILIATION_RUNTIME_WATCHER_QUORUM_SCHEME.to_string(),
            dispute_reservation_scheme:
                MONERO_L2_PQ_RESERVE_RECONCILIATION_RUNTIME_DISPUTE_RESERVATION_SCHEME.to_string(),
            delta_batch_scheme: MONERO_L2_PQ_RESERVE_RECONCILIATION_RUNTIME_DELTA_BATCH_SCHEME
                .to_string(),
            settlement_manifest_scheme:
                MONERO_L2_PQ_RESERVE_RECONCILIATION_RUNTIME_SETTLEMENT_MANIFEST_SCHEME.to_string(),
            receipt_scheme: MONERO_L2_PQ_RESERVE_RECONCILIATION_RUNTIME_RECEIPT_SCHEME.to_string(),
            replay_domain: MONERO_L2_PQ_RESERVE_RECONCILIATION_RUNTIME_REPLAY_DOMAIN.to_string(),
            genesis_height: MONERO_L2_PQ_RESERVE_RECONCILIATION_RUNTIME_DEVNET_HEIGHT,
            snapshot_ttl_blocks:
                MONERO_L2_PQ_RESERVE_RECONCILIATION_RUNTIME_DEFAULT_SNAPSHOT_TTL_BLOCKS,
            report_ttl_blocks:
                MONERO_L2_PQ_RESERVE_RECONCILIATION_RUNTIME_DEFAULT_REPORT_TTL_BLOCKS,
            dispute_ttl_blocks:
                MONERO_L2_PQ_RESERVE_RECONCILIATION_RUNTIME_DEFAULT_DISPUTE_TTL_BLOCKS,
            settlement_ttl_blocks:
                MONERO_L2_PQ_RESERVE_RECONCILIATION_RUNTIME_DEFAULT_SETTLEMENT_TTL_BLOCKS,
            min_reserve_coverage_bps:
                MONERO_L2_PQ_RESERVE_RECONCILIATION_RUNTIME_DEFAULT_MIN_RESERVE_COVERAGE_BPS,
            target_reserve_coverage_bps:
                MONERO_L2_PQ_RESERVE_RECONCILIATION_RUNTIME_DEFAULT_TARGET_RESERVE_COVERAGE_BPS,
            min_privacy_set_size:
                MONERO_L2_PQ_RESERVE_RECONCILIATION_RUNTIME_DEFAULT_MIN_PRIVACY_SET_SIZE,
            min_watcher_count:
                MONERO_L2_PQ_RESERVE_RECONCILIATION_RUNTIME_DEFAULT_MIN_WATCHER_COUNT,
            min_watcher_weight:
                MONERO_L2_PQ_RESERVE_RECONCILIATION_RUNTIME_DEFAULT_MIN_WATCHER_WEIGHT,
            watcher_quorum_bps:
                MONERO_L2_PQ_RESERVE_RECONCILIATION_RUNTIME_DEFAULT_WATCHER_QUORUM_BPS,
            strong_quorum_bps:
                MONERO_L2_PQ_RESERVE_RECONCILIATION_RUNTIME_DEFAULT_STRONG_QUORUM_BPS,
            min_pq_security_bits:
                MONERO_L2_PQ_RESERVE_RECONCILIATION_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS,
            target_pq_security_bits:
                MONERO_L2_PQ_RESERVE_RECONCILIATION_RUNTIME_DEFAULT_TARGET_PQ_SECURITY_BITS,
            low_fee_bps: MONERO_L2_PQ_RESERVE_RECONCILIATION_RUNTIME_DEFAULT_LOW_FEE_BPS,
            max_user_fee_bps: MONERO_L2_PQ_RESERVE_RECONCILIATION_RUNTIME_DEFAULT_MAX_USER_FEE_BPS,
            max_delta_batch_items:
                MONERO_L2_PQ_RESERVE_RECONCILIATION_RUNTIME_DEFAULT_MAX_DELTA_BATCH_ITEMS,
            roots_only: true,
        }
    }

    pub fn validate(&self) -> MoneroL2PqReserveReconciliationRuntimeResult<()> {
        require(self.chain_id == CHAIN_ID, "chain id mismatch")?;
        require(
            self.protocol_version == PROTOCOL_VERSION,
            "protocol version mismatch",
        )?;
        require(
            self.schema_version == MONERO_L2_PQ_RESERVE_RECONCILIATION_RUNTIME_SCHEMA_VERSION,
            "schema version mismatch",
        )?;
        require(
            self.roots_only,
            "reserve reconciliation must remain roots-only",
        )?;
        required("monero_network", &self.monero_network)?;
        required("l2_network", &self.l2_network)?;
        required("asset_id", &self.asset_id)?;
        required("fee_asset_id", &self.fee_asset_id)?;
        required("committee_id", &self.committee_id)?;
        require(self.snapshot_ttl_blocks > 0, "snapshot ttl is zero")?;
        require(self.report_ttl_blocks > 0, "report ttl is zero")?;
        require(self.dispute_ttl_blocks > 0, "dispute ttl is zero")?;
        require(self.settlement_ttl_blocks > 0, "settlement ttl is zero")?;
        require(
            self.min_reserve_coverage_bps >= MONERO_L2_PQ_RESERVE_RECONCILIATION_RUNTIME_MAX_BPS,
            "reserve coverage floor below full backing",
        )?;
        require(
            self.target_reserve_coverage_bps >= self.min_reserve_coverage_bps,
            "reserve coverage target below floor",
        )?;
        require(self.min_privacy_set_size > 0, "privacy set size is zero")?;
        require(
            self.min_watcher_count > 0 && self.min_watcher_weight > 0,
            "watcher quorum minimums are zero",
        )?;
        require(
            self.watcher_quorum_bps > 0
                && self.watcher_quorum_bps <= MONERO_L2_PQ_RESERVE_RECONCILIATION_RUNTIME_MAX_BPS
                && self.strong_quorum_bps >= self.watcher_quorum_bps
                && self.strong_quorum_bps <= MONERO_L2_PQ_RESERVE_RECONCILIATION_RUNTIME_MAX_BPS,
            "watcher quorum bps invalid",
        )?;
        require(
            self.min_pq_security_bits >= 192
                && self.target_pq_security_bits >= self.min_pq_security_bits,
            "pq security policy invalid",
        )?;
        require(
            self.low_fee_bps <= self.max_user_fee_bps
                && self.max_user_fee_bps <= MONERO_L2_PQ_RESERVE_RECONCILIATION_RUNTIME_MAX_BPS,
            "fee bps policy invalid",
        )?;
        require(
            self.max_delta_batch_items > 0,
            "max delta batch items is zero",
        )?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn state_root(&self) -> String {
        record_root(
            "MONERO-L2-PQ-RESERVE-RECONCILIATION-CONFIG",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    pub snapshot_counter: u64,
    pub report_counter: u64,
    pub watcher_attestation_counter: u64,
    pub dispute_reservation_counter: u64,
    pub delta_batch_counter: u64,
    pub settlement_manifest_counter: u64,
    pub receipt_counter: u64,
    pub snapshots_settled: u64,
    pub reports_disputed: u64,
    pub low_fee_disputes_reserved: u64,
    pub reserve_shortfalls_detected: u64,
    pub total_positive_delta_piconero: u128,
    pub total_negative_delta_piconero: u128,
    pub total_reserved_dispute_fee_piconero: u128,
    pub public_records: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn state_root(&self) -> String {
        record_root(
            "MONERO-L2-PQ-RESERVE-RECONCILIATION-COUNTERS",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roots {
    pub config_root: String,
    pub counters_root: String,
    pub snapshot_root: String,
    pub encrypted_report_root: String,
    pub watcher_attestation_root: String,
    pub dispute_reservation_root: String,
    pub delta_batch_root: String,
    pub settlement_manifest_root: String,
    pub receipt_root: String,
    pub nullifier_root: String,
    pub public_record_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn state_root(&self) -> String {
        record_root(
            "MONERO-L2-PQ-RESERVE-RECONCILIATION-ROOTS",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqReserveSnapshotRequest {
    pub operator_id: String,
    pub monero_height: u64,
    pub l2_height: u64,
    pub reserve_commitment_root: String,
    pub view_tag_set_root: String,
    pub output_set_root: String,
    pub key_image_exclusion_root: String,
    pub l2_liability_root: String,
    pub token_liability_root: String,
    pub defi_liability_root: String,
    pub smart_contract_liability_root: String,
    pub reserve_amount_piconero: u128,
    pub liability_amount_piconero: u128,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub snapshot_nonce: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqReserveSnapshotRecord {
    pub snapshot_id: String,
    pub sequence: u64,
    pub operator_id: String,
    pub monero_height: u64,
    pub l2_height: u64,
    pub reserve_commitment_root: String,
    pub view_tag_set_root: String,
    pub output_set_root: String,
    pub key_image_exclusion_root: String,
    pub l2_liability_root: String,
    pub token_liability_root: String,
    pub defi_liability_root: String,
    pub smart_contract_liability_root: String,
    pub reserve_amount_piconero: u128,
    pub liability_amount_piconero: u128,
    pub coverage_bps: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub status: SnapshotStatus,
    pub expires_at_l2_height: u64,
    pub snapshot_root: String,
}

impl PqReserveSnapshotRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "snapshot_id": self.snapshot_id,
            "sequence": self.sequence,
            "operator_id": self.operator_id,
            "monero_height": self.monero_height,
            "l2_height": self.l2_height,
            "reserve_commitment_root": self.reserve_commitment_root,
            "view_tag_set_root": self.view_tag_set_root,
            "output_set_root": self.output_set_root,
            "key_image_exclusion_root": self.key_image_exclusion_root,
            "l2_liability_root": self.l2_liability_root,
            "token_liability_root": self.token_liability_root,
            "defi_liability_root": self.defi_liability_root,
            "smart_contract_liability_root": self.smart_contract_liability_root,
            "reserve_amount_piconero": self.reserve_amount_piconero,
            "liability_amount_piconero": self.liability_amount_piconero,
            "coverage_bps": self.coverage_bps,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "status": self.status.as_str(),
            "expires_at_l2_height": self.expires_at_l2_height,
            "snapshot_root": self.snapshot_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedReconciliationReportRequest {
    pub snapshot_id: String,
    pub reporter_id: String,
    pub encrypted_report_root: String,
    pub pq_ciphertext_root: String,
    pub reserve_delta_root: String,
    pub token_delta_root: String,
    pub defi_delta_root: String,
    pub contract_delta_root: String,
    pub selective_disclosure_root: String,
    pub reported_reserve_delta_piconero: i128,
    pub max_fee_piconero: u64,
    pub lane: ReconciliationLane,
    pub nullifier: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedReconciliationReportRecord {
    pub report_id: String,
    pub sequence: u64,
    pub snapshot_id: String,
    pub reporter_id: String,
    pub encrypted_report_root: String,
    pub pq_ciphertext_root: String,
    pub reserve_delta_root: String,
    pub token_delta_root: String,
    pub defi_delta_root: String,
    pub contract_delta_root: String,
    pub selective_disclosure_root: String,
    pub reported_reserve_delta_piconero: i128,
    pub max_fee_piconero: u64,
    pub fee_bps: u64,
    pub lane: ReconciliationLane,
    pub nullifier: String,
    pub status: ReportStatus,
    pub expires_at_l2_height: u64,
}

impl EncryptedReconciliationReportRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "report_id": self.report_id,
            "sequence": self.sequence,
            "snapshot_id": self.snapshot_id,
            "reporter_id": self.reporter_id,
            "encrypted_report_root": self.encrypted_report_root,
            "pq_ciphertext_root": self.pq_ciphertext_root,
            "reserve_delta_root": self.reserve_delta_root,
            "token_delta_root": self.token_delta_root,
            "defi_delta_root": self.defi_delta_root,
            "contract_delta_root": self.contract_delta_root,
            "selective_disclosure_root": self.selective_disclosure_root,
            "reported_reserve_delta_piconero": self.reported_reserve_delta_piconero,
            "max_fee_piconero": self.max_fee_piconero,
            "fee_bps": self.fee_bps,
            "lane": self.lane.as_str(),
            "nullifier": self.nullifier,
            "status": self.status.as_str(),
            "expires_at_l2_height": self.expires_at_l2_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WatcherQuorumAttestationRequest {
    pub report_id: String,
    pub watcher_id: String,
    pub observed_monero_height: u64,
    pub watcher_set_root: String,
    pub reserve_safety_root: String,
    pub encrypted_evidence_root: String,
    pub aggregate_pq_signature_root: String,
    pub watcher_count: u64,
    pub watcher_weight: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WatcherQuorumAttestationRecord {
    pub attestation_id: String,
    pub sequence: u64,
    pub report_id: String,
    pub watcher_id: String,
    pub observed_monero_height: u64,
    pub watcher_set_root: String,
    pub reserve_safety_root: String,
    pub encrypted_evidence_root: String,
    pub aggregate_pq_signature_root: String,
    pub watcher_count: u64,
    pub watcher_weight: u64,
    pub quorum_bps: u64,
    pub status: AttestationStatus,
}

impl WatcherQuorumAttestationRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "sequence": self.sequence,
            "report_id": self.report_id,
            "watcher_id": self.watcher_id,
            "observed_monero_height": self.observed_monero_height,
            "watcher_set_root": self.watcher_set_root,
            "reserve_safety_root": self.reserve_safety_root,
            "encrypted_evidence_root": self.encrypted_evidence_root,
            "aggregate_pq_signature_root": self.aggregate_pq_signature_root,
            "watcher_count": self.watcher_count,
            "watcher_weight": self.watcher_weight,
            "quorum_bps": self.quorum_bps,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeDisputeReservationRequest {
    pub report_id: String,
    pub challenger_id: String,
    pub dispute_evidence_root: String,
    pub encrypted_challenge_root: String,
    pub fee_sponsor_root: String,
    pub reserved_fee_piconero: u64,
    pub lane: ReconciliationLane,
    pub dispute_nonce: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeDisputeReservationRecord {
    pub dispute_id: String,
    pub sequence: u64,
    pub report_id: String,
    pub challenger_id: String,
    pub dispute_evidence_root: String,
    pub encrypted_challenge_root: String,
    pub fee_sponsor_root: String,
    pub reserved_fee_piconero: u64,
    pub fee_bps: u64,
    pub lane: ReconciliationLane,
    pub status: DisputeStatus,
    pub expires_at_l2_height: u64,
}

impl LowFeeDisputeReservationRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "dispute_id": self.dispute_id,
            "sequence": self.sequence,
            "report_id": self.report_id,
            "challenger_id": self.challenger_id,
            "dispute_evidence_root": self.dispute_evidence_root,
            "encrypted_challenge_root": self.encrypted_challenge_root,
            "fee_sponsor_root": self.fee_sponsor_root,
            "reserved_fee_piconero": self.reserved_fee_piconero,
            "fee_bps": self.fee_bps,
            "lane": self.lane.as_str(),
            "status": self.status.as_str(),
            "expires_at_l2_height": self.expires_at_l2_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroReserveDeltaBatchRequest {
    pub coordinator_id: String,
    pub report_ids: Vec<String>,
    pub attestation_ids: Vec<String>,
    pub dispute_ids: Vec<String>,
    pub positive_delta_root: String,
    pub negative_delta_root: String,
    pub token_supply_delta_root: String,
    pub defi_position_delta_root: String,
    pub smart_contract_delta_root: String,
    pub reserve_release_root: String,
    pub aggregate_proof_root: String,
    pub batch_nonce: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroReserveDeltaBatchRecord {
    pub batch_id: String,
    pub sequence: u64,
    pub coordinator_id: String,
    pub report_ids: Vec<String>,
    pub attestation_ids: Vec<String>,
    pub dispute_ids: Vec<String>,
    pub positive_delta_root: String,
    pub negative_delta_root: String,
    pub token_supply_delta_root: String,
    pub defi_position_delta_root: String,
    pub smart_contract_delta_root: String,
    pub reserve_release_root: String,
    pub aggregate_proof_root: String,
    pub net_delta_piconero: i128,
    pub status: DeltaBatchStatus,
    pub opened_l2_height: u64,
}

impl MoneroReserveDeltaBatchRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "sequence": self.sequence,
            "coordinator_id": self.coordinator_id,
            "report_ids": self.report_ids,
            "attestation_ids": self.attestation_ids,
            "dispute_ids": self.dispute_ids,
            "positive_delta_root": self.positive_delta_root,
            "negative_delta_root": self.negative_delta_root,
            "token_supply_delta_root": self.token_supply_delta_root,
            "defi_position_delta_root": self.defi_position_delta_root,
            "smart_contract_delta_root": self.smart_contract_delta_root,
            "reserve_release_root": self.reserve_release_root,
            "aggregate_proof_root": self.aggregate_proof_root,
            "net_delta_piconero": self.net_delta_piconero,
            "status": self.status.as_str(),
            "opened_l2_height": self.opened_l2_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementManifestRequest {
    pub batch_id: String,
    pub settlement_operator_id: String,
    pub monero_anchor_height: u64,
    pub monero_anchor_hash_root: String,
    pub l2_state_transition_root: String,
    pub reserve_accounting_root: String,
    pub withdrawal_release_root: String,
    pub token_contract_update_root: String,
    pub defi_settlement_root: String,
    pub smart_contract_receipt_root: String,
    pub fee_rebate_root: String,
    pub settlement_proof_root: String,
    pub pq_signature_root: String,
    pub status: ManifestStatus,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementManifestRecord {
    pub manifest_id: String,
    pub sequence: u64,
    pub batch_id: String,
    pub settlement_operator_id: String,
    pub monero_anchor_height: u64,
    pub monero_anchor_hash_root: String,
    pub l2_state_transition_root: String,
    pub reserve_accounting_root: String,
    pub withdrawal_release_root: String,
    pub token_contract_update_root: String,
    pub defi_settlement_root: String,
    pub smart_contract_receipt_root: String,
    pub fee_rebate_root: String,
    pub settlement_proof_root: String,
    pub pq_signature_root: String,
    pub status: ManifestStatus,
    pub expires_at_l2_height: u64,
}

impl SettlementManifestRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "manifest_id": self.manifest_id,
            "sequence": self.sequence,
            "batch_id": self.batch_id,
            "settlement_operator_id": self.settlement_operator_id,
            "monero_anchor_height": self.monero_anchor_height,
            "monero_anchor_hash_root": self.monero_anchor_hash_root,
            "l2_state_transition_root": self.l2_state_transition_root,
            "reserve_accounting_root": self.reserve_accounting_root,
            "withdrawal_release_root": self.withdrawal_release_root,
            "token_contract_update_root": self.token_contract_update_root,
            "defi_settlement_root": self.defi_settlement_root,
            "smart_contract_receipt_root": self.smart_contract_receipt_root,
            "fee_rebate_root": self.fee_rebate_root,
            "settlement_proof_root": self.settlement_proof_root,
            "pq_signature_root": self.pq_signature_root,
            "status": self.status.as_str(),
            "expires_at_l2_height": self.expires_at_l2_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReconciliationReceiptRecord {
    pub receipt_id: String,
    pub sequence: u64,
    pub kind: ReceiptKind,
    pub actor_id: String,
    pub snapshot_id: Option<String>,
    pub report_id: Option<String>,
    pub attestation_id: Option<String>,
    pub dispute_id: Option<String>,
    pub batch_id: Option<String>,
    pub manifest_id: Option<String>,
    pub issued_l2_height: u64,
    pub event_root: String,
    pub receipt_root: String,
}

impl ReconciliationReceiptRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "sequence": self.sequence,
            "kind": self.kind.as_str(),
            "actor_id": self.actor_id,
            "snapshot_id": self.snapshot_id,
            "report_id": self.report_id,
            "attestation_id": self.attestation_id,
            "dispute_id": self.dispute_id,
            "batch_id": self.batch_id,
            "manifest_id": self.manifest_id,
            "issued_l2_height": self.issued_l2_height,
            "event_root": self.event_root,
            "receipt_root": self.receipt_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub current_l2_height: u64,
    pub snapshots: BTreeMap<String, PqReserveSnapshotRecord>,
    pub reports: BTreeMap<String, EncryptedReconciliationReportRecord>,
    pub attestations: BTreeMap<String, WatcherQuorumAttestationRecord>,
    pub disputes: BTreeMap<String, LowFeeDisputeReservationRecord>,
    pub delta_batches: BTreeMap<String, MoneroReserveDeltaBatchRecord>,
    pub manifests: BTreeMap<String, SettlementManifestRecord>,
    pub receipts: BTreeMap<String, ReconciliationReceiptRecord>,
    pub nullifiers: BTreeSet<String>,
    pub public_records: BTreeMap<String, Value>,
    pub counters: Counters,
}

impl Default for State {
    fn default() -> Self {
        Self::devnet()
    }
}

impl State {
    pub fn devnet() -> Self {
        Self::new(Config::devnet())
    }

    pub fn new(config: Config) -> Self {
        let current_l2_height = config.genesis_height;
        let mut state = Self {
            config,
            current_l2_height,
            snapshots: BTreeMap::new(),
            reports: BTreeMap::new(),
            attestations: BTreeMap::new(),
            disputes: BTreeMap::new(),
            delta_batches: BTreeMap::new(),
            manifests: BTreeMap::new(),
            receipts: BTreeMap::new(),
            nullifiers: BTreeSet::new(),
            public_records: BTreeMap::new(),
            counters: Counters::default(),
        };
        let _ = state.record_public("config".to_string(), state.config.public_record());
        state
    }

    pub fn record_pq_reserve_snapshot(
        &mut self,
        request: PqReserveSnapshotRequest,
    ) -> MoneroL2PqReserveReconciliationRuntimeResult<PqReserveSnapshotRecord> {
        self.config.validate()?;
        required("operator_id", &request.operator_id)?;
        validate_root("reserve_commitment_root", &request.reserve_commitment_root)?;
        validate_root("view_tag_set_root", &request.view_tag_set_root)?;
        validate_root("output_set_root", &request.output_set_root)?;
        validate_root(
            "key_image_exclusion_root",
            &request.key_image_exclusion_root,
        )?;
        validate_root("l2_liability_root", &request.l2_liability_root)?;
        validate_root("token_liability_root", &request.token_liability_root)?;
        validate_root("defi_liability_root", &request.defi_liability_root)?;
        validate_root(
            "smart_contract_liability_root",
            &request.smart_contract_liability_root,
        )?;
        required("snapshot_nonce", &request.snapshot_nonce)?;
        ensure_capacity(
            self.snapshots.len(),
            MONERO_L2_PQ_RESERVE_RECONCILIATION_RUNTIME_MAX_SNAPSHOTS,
            "reserve snapshots",
        )?;
        require(
            request.privacy_set_size >= self.config.min_privacy_set_size,
            "privacy set below floor",
        )?;
        require(
            request.pq_security_bits >= self.config.min_pq_security_bits,
            "pq security below floor",
        )?;
        let coverage_bps = bps_u128(
            request.reserve_amount_piconero,
            request.liability_amount_piconero,
        );
        require(
            coverage_bps >= self.config.min_reserve_coverage_bps,
            "reserve snapshot below full backing floor",
        )?;
        self.current_l2_height = self.current_l2_height.max(request.l2_height);
        self.counters.snapshot_counter = self.counters.snapshot_counter.saturating_add(1);
        let sequence = self.counters.snapshot_counter;
        let snapshot_root = record_root(
            "MONERO-L2-PQ-RESERVE-RECONCILIATION-SNAPSHOT-COMMITMENT",
            &json!({
                "sequence": sequence,
                "request": request.public_record(),
                "coverage_bps": coverage_bps,
            }),
        );
        let snapshot_id = pq_reserve_snapshot_id(&request, sequence, &snapshot_root);
        require(
            !self.snapshots.contains_key(&snapshot_id),
            "reserve snapshot already exists",
        )?;
        let record = PqReserveSnapshotRecord {
            snapshot_id: snapshot_id.clone(),
            sequence,
            operator_id: request.operator_id.clone(),
            monero_height: request.monero_height,
            l2_height: request.l2_height,
            reserve_commitment_root: request.reserve_commitment_root,
            view_tag_set_root: request.view_tag_set_root,
            output_set_root: request.output_set_root,
            key_image_exclusion_root: request.key_image_exclusion_root,
            l2_liability_root: request.l2_liability_root,
            token_liability_root: request.token_liability_root,
            defi_liability_root: request.defi_liability_root,
            smart_contract_liability_root: request.smart_contract_liability_root,
            reserve_amount_piconero: request.reserve_amount_piconero,
            liability_amount_piconero: request.liability_amount_piconero,
            coverage_bps,
            privacy_set_size: request.privacy_set_size,
            pq_security_bits: request.pq_security_bits,
            status: SnapshotStatus::Open,
            expires_at_l2_height: request
                .l2_height
                .saturating_add(self.config.snapshot_ttl_blocks),
            snapshot_root,
        };
        self.snapshots.insert(snapshot_id.clone(), record.clone());
        self.record_public(format!("snapshot:{snapshot_id}"), record.public_record())?;
        let _ = self.issue_receipt(
            ReceiptKind::SnapshotRecorded,
            &request.operator_id,
            Some(&snapshot_id),
            None,
            None,
            None,
            None,
            None,
            record.snapshot_root.clone(),
        )?;
        Ok(record)
    }

    pub fn submit_encrypted_reconciliation_report(
        &mut self,
        request: EncryptedReconciliationReportRequest,
    ) -> MoneroL2PqReserveReconciliationRuntimeResult<EncryptedReconciliationReportRecord> {
        required("snapshot_id", &request.snapshot_id)?;
        required("reporter_id", &request.reporter_id)?;
        validate_root("encrypted_report_root", &request.encrypted_report_root)?;
        validate_root("pq_ciphertext_root", &request.pq_ciphertext_root)?;
        validate_root("reserve_delta_root", &request.reserve_delta_root)?;
        validate_root("token_delta_root", &request.token_delta_root)?;
        validate_root("defi_delta_root", &request.defi_delta_root)?;
        validate_root("contract_delta_root", &request.contract_delta_root)?;
        validate_root(
            "selective_disclosure_root",
            &request.selective_disclosure_root,
        )?;
        required("nullifier", &request.nullifier)?;
        require(
            !self.nullifiers.contains(&request.nullifier),
            "reconciliation report nullifier already used",
        )?;
        ensure_capacity(
            self.reports.len(),
            MONERO_L2_PQ_RESERVE_RECONCILIATION_RUNTIME_MAX_REPORTS,
            "encrypted reports",
        )?;
        let snapshot_public = {
            let snapshot = self
                .snapshots
                .get_mut(&request.snapshot_id)
                .ok_or_else(|| "unknown reserve snapshot".to_string())?;
            snapshot.status = SnapshotStatus::Reported;
            snapshot.public_record()
        };
        self.counters.report_counter = self.counters.report_counter.saturating_add(1);
        let sequence = self.counters.report_counter;
        let report_id = encrypted_reconciliation_report_id(&request, sequence);
        require(
            !self.reports.contains_key(&report_id),
            "report already exists",
        )?;
        let record = EncryptedReconciliationReportRecord {
            report_id: report_id.clone(),
            sequence,
            snapshot_id: request.snapshot_id.clone(),
            reporter_id: request.reporter_id.clone(),
            encrypted_report_root: request.encrypted_report_root,
            pq_ciphertext_root: request.pq_ciphertext_root,
            reserve_delta_root: request.reserve_delta_root,
            token_delta_root: request.token_delta_root,
            defi_delta_root: request.defi_delta_root,
            contract_delta_root: request.contract_delta_root,
            selective_disclosure_root: request.selective_disclosure_root,
            reported_reserve_delta_piconero: request.reported_reserve_delta_piconero,
            max_fee_piconero: request.max_fee_piconero,
            fee_bps: request.lane.fee_bps(&self.config),
            lane: request.lane,
            nullifier: request.nullifier.clone(),
            status: ReportStatus::Accepted,
            expires_at_l2_height: self
                .current_l2_height
                .saturating_add(self.config.report_ttl_blocks),
        };
        self.nullifiers.insert(request.nullifier);
        self.reports.insert(report_id.clone(), record.clone());
        self.record_public(format!("snapshot:{}", request.snapshot_id), snapshot_public)?;
        self.record_public(format!("report:{report_id}"), record.public_record())?;
        let _ = self.issue_receipt(
            ReceiptKind::ReportAccepted,
            &request.reporter_id,
            Some(&request.snapshot_id),
            Some(&report_id),
            None,
            None,
            None,
            None,
            record.encrypted_report_root.clone(),
        )?;
        Ok(record)
    }

    pub fn submit_watcher_quorum_attestation(
        &mut self,
        request: WatcherQuorumAttestationRequest,
    ) -> MoneroL2PqReserveReconciliationRuntimeResult<WatcherQuorumAttestationRecord> {
        required("report_id", &request.report_id)?;
        required("watcher_id", &request.watcher_id)?;
        validate_root("watcher_set_root", &request.watcher_set_root)?;
        validate_root("reserve_safety_root", &request.reserve_safety_root)?;
        validate_root("encrypted_evidence_root", &request.encrypted_evidence_root)?;
        validate_root(
            "aggregate_pq_signature_root",
            &request.aggregate_pq_signature_root,
        )?;
        ensure_capacity(
            self.attestations.len(),
            MONERO_L2_PQ_RESERVE_RECONCILIATION_RUNTIME_MAX_ATTESTATIONS,
            "watcher attestations",
        )?;
        let quorum_bps = bps(request.watcher_weight, self.config.min_watcher_weight);
        let status = if request.watcher_count < self.config.min_watcher_count {
            AttestationStatus::WeakQuorum
        } else if quorum_bps >= self.config.strong_quorum_bps {
            AttestationStatus::StrongQuorum
        } else if quorum_bps >= self.config.watcher_quorum_bps {
            AttestationStatus::Accepted
        } else {
            AttestationStatus::WeakQuorum
        };
        let (snapshot_id, report_public) = {
            let report = self
                .reports
                .get_mut(&request.report_id)
                .ok_or_else(|| "unknown encrypted reconciliation report".to_string())?;
            if matches!(
                status,
                AttestationStatus::Accepted | AttestationStatus::StrongQuorum
            ) {
                report.status = ReportStatus::QuorumAttested;
            }
            (report.snapshot_id.clone(), report.public_record())
        };
        if matches!(
            status,
            AttestationStatus::Accepted | AttestationStatus::StrongQuorum
        ) {
            if let Some(snapshot) = self.snapshots.get_mut(&snapshot_id) {
                snapshot.status = SnapshotStatus::QuorumAttested;
            }
        }
        self.current_l2_height = self.current_l2_height.max(request.observed_monero_height);
        self.counters.watcher_attestation_counter =
            self.counters.watcher_attestation_counter.saturating_add(1);
        let sequence = self.counters.watcher_attestation_counter;
        let attestation_id = watcher_quorum_attestation_id(&request, sequence);
        let record = WatcherQuorumAttestationRecord {
            attestation_id: attestation_id.clone(),
            sequence,
            report_id: request.report_id.clone(),
            watcher_id: request.watcher_id.clone(),
            observed_monero_height: request.observed_monero_height,
            watcher_set_root: request.watcher_set_root,
            reserve_safety_root: request.reserve_safety_root,
            encrypted_evidence_root: request.encrypted_evidence_root,
            aggregate_pq_signature_root: request.aggregate_pq_signature_root,
            watcher_count: request.watcher_count,
            watcher_weight: request.watcher_weight,
            quorum_bps,
            status,
        };
        self.attestations
            .insert(attestation_id.clone(), record.clone());
        self.record_public(format!("report:{}", request.report_id), report_public)?;
        self.record_public(
            format!("attestation:{attestation_id}"),
            record.public_record(),
        )?;
        let _ = self.issue_receipt(
            ReceiptKind::WatcherQuorumAccepted,
            &request.watcher_id,
            Some(&snapshot_id),
            Some(&request.report_id),
            Some(&attestation_id),
            None,
            None,
            None,
            record.reserve_safety_root.clone(),
        )?;
        Ok(record)
    }

    pub fn reserve_low_fee_dispute(
        &mut self,
        request: LowFeeDisputeReservationRequest,
    ) -> MoneroL2PqReserveReconciliationRuntimeResult<LowFeeDisputeReservationRecord> {
        required("report_id", &request.report_id)?;
        required("challenger_id", &request.challenger_id)?;
        validate_root("dispute_evidence_root", &request.dispute_evidence_root)?;
        validate_root(
            "encrypted_challenge_root",
            &request.encrypted_challenge_root,
        )?;
        validate_root("fee_sponsor_root", &request.fee_sponsor_root)?;
        required("dispute_nonce", &request.dispute_nonce)?;
        ensure_capacity(
            self.disputes.len(),
            MONERO_L2_PQ_RESERVE_RECONCILIATION_RUNTIME_MAX_DISPUTES,
            "dispute reservations",
        )?;
        let (snapshot_id, report_public) = {
            let report = self
                .reports
                .get_mut(&request.report_id)
                .ok_or_else(|| "unknown encrypted reconciliation report".to_string())?;
            report.status = ReportStatus::Disputed;
            (report.snapshot_id.clone(), report.public_record())
        };
        if let Some(snapshot) = self.snapshots.get_mut(&snapshot_id) {
            snapshot.status = SnapshotStatus::Disputed;
        }
        self.counters.dispute_reservation_counter =
            self.counters.dispute_reservation_counter.saturating_add(1);
        self.counters.low_fee_disputes_reserved =
            self.counters.low_fee_disputes_reserved.saturating_add(1);
        self.counters.total_reserved_dispute_fee_piconero = self
            .counters
            .total_reserved_dispute_fee_piconero
            .saturating_add(request.reserved_fee_piconero as u128);
        let sequence = self.counters.dispute_reservation_counter;
        let dispute_id = low_fee_dispute_reservation_id(&request, sequence);
        let record = LowFeeDisputeReservationRecord {
            dispute_id: dispute_id.clone(),
            sequence,
            report_id: request.report_id.clone(),
            challenger_id: request.challenger_id.clone(),
            dispute_evidence_root: request.dispute_evidence_root,
            encrypted_challenge_root: request.encrypted_challenge_root,
            fee_sponsor_root: request.fee_sponsor_root,
            reserved_fee_piconero: request.reserved_fee_piconero,
            fee_bps: request.lane.fee_bps(&self.config),
            lane: request.lane,
            status: DisputeStatus::Reserved,
            expires_at_l2_height: self
                .current_l2_height
                .saturating_add(self.config.dispute_ttl_blocks),
        };
        self.disputes.insert(dispute_id.clone(), record.clone());
        self.record_public(format!("report:{}", request.report_id), report_public)?;
        self.record_public(format!("dispute:{dispute_id}"), record.public_record())?;
        let _ = self.issue_receipt(
            ReceiptKind::DisputeReserved,
            &request.challenger_id,
            Some(&snapshot_id),
            Some(&request.report_id),
            None,
            Some(&dispute_id),
            None,
            None,
            record.dispute_evidence_root.clone(),
        )?;
        Ok(record)
    }

    pub fn build_monero_reserve_delta_batch(
        &mut self,
        request: MoneroReserveDeltaBatchRequest,
    ) -> MoneroL2PqReserveReconciliationRuntimeResult<MoneroReserveDeltaBatchRecord> {
        required("coordinator_id", &request.coordinator_id)?;
        validate_root("positive_delta_root", &request.positive_delta_root)?;
        validate_root("negative_delta_root", &request.negative_delta_root)?;
        validate_root("token_supply_delta_root", &request.token_supply_delta_root)?;
        validate_root(
            "defi_position_delta_root",
            &request.defi_position_delta_root,
        )?;
        validate_root(
            "smart_contract_delta_root",
            &request.smart_contract_delta_root,
        )?;
        validate_root("reserve_release_root", &request.reserve_release_root)?;
        validate_root("aggregate_proof_root", &request.aggregate_proof_root)?;
        required("batch_nonce", &request.batch_nonce)?;
        require(!request.report_ids.is_empty(), "delta batch has no reports")?;
        require(
            request.report_ids.len() <= self.config.max_delta_batch_items,
            "delta batch item count exceeds policy",
        )?;
        ensure_capacity(
            self.delta_batches.len(),
            MONERO_L2_PQ_RESERVE_RECONCILIATION_RUNTIME_MAX_DELTA_BATCHES,
            "delta batches",
        )?;
        let mut net_delta_piconero = 0i128;
        for report_id in &request.report_ids {
            let (snapshot_id, report_public, delta) = {
                let report = self.reports.get_mut(report_id).ok_or_else(|| {
                    format!("unknown encrypted reconciliation report: {report_id}")
                })?;
                report.status = ReportStatus::Batched;
                (
                    report.snapshot_id.clone(),
                    report.public_record(),
                    report.reported_reserve_delta_piconero,
                )
            };
            net_delta_piconero = net_delta_piconero.saturating_add(delta);
            if let Some(snapshot) = self.snapshots.get_mut(&snapshot_id) {
                snapshot.status = SnapshotStatus::DeltaBatched;
            }
            self.record_public(format!("report:{report_id}"), report_public)?;
        }
        for attestation_id in &request.attestation_ids {
            require(
                self.attestations.contains_key(attestation_id),
                &format!("unknown watcher attestation: {attestation_id}"),
            )?;
        }
        for dispute_id in &request.dispute_ids {
            require(
                self.disputes.contains_key(dispute_id),
                &format!("unknown dispute reservation: {dispute_id}"),
            )?;
        }
        self.counters.delta_batch_counter = self.counters.delta_batch_counter.saturating_add(1);
        if net_delta_piconero < 0 {
            self.counters.reserve_shortfalls_detected =
                self.counters.reserve_shortfalls_detected.saturating_add(1);
            self.counters.total_negative_delta_piconero = self
                .counters
                .total_negative_delta_piconero
                .saturating_add(net_delta_piconero.unsigned_abs());
        } else {
            self.counters.total_positive_delta_piconero = self
                .counters
                .total_positive_delta_piconero
                .saturating_add(net_delta_piconero as u128);
        }
        let sequence = self.counters.delta_batch_counter;
        let batch_id = monero_reserve_delta_batch_id(&request, sequence);
        let record = MoneroReserveDeltaBatchRecord {
            batch_id: batch_id.clone(),
            sequence,
            coordinator_id: request.coordinator_id.clone(),
            report_ids: request.report_ids,
            attestation_ids: request.attestation_ids,
            dispute_ids: request.dispute_ids,
            positive_delta_root: request.positive_delta_root,
            negative_delta_root: request.negative_delta_root,
            token_supply_delta_root: request.token_supply_delta_root,
            defi_position_delta_root: request.defi_position_delta_root,
            smart_contract_delta_root: request.smart_contract_delta_root,
            reserve_release_root: request.reserve_release_root,
            aggregate_proof_root: request.aggregate_proof_root,
            net_delta_piconero,
            status: DeltaBatchStatus::ManifestReady,
            opened_l2_height: self.current_l2_height,
        };
        self.delta_batches.insert(batch_id.clone(), record.clone());
        self.record_public(format!("delta_batch:{batch_id}"), record.public_record())?;
        let _ = self.issue_receipt(
            ReceiptKind::DeltaBatchBuilt,
            &request.coordinator_id,
            None,
            None,
            None,
            None,
            Some(&batch_id),
            None,
            record.aggregate_proof_root.clone(),
        )?;
        Ok(record)
    }

    pub fn publish_settlement_manifest(
        &mut self,
        request: SettlementManifestRequest,
    ) -> MoneroL2PqReserveReconciliationRuntimeResult<SettlementManifestRecord> {
        required("batch_id", &request.batch_id)?;
        required("settlement_operator_id", &request.settlement_operator_id)?;
        validate_root("monero_anchor_hash_root", &request.monero_anchor_hash_root)?;
        validate_root(
            "l2_state_transition_root",
            &request.l2_state_transition_root,
        )?;
        validate_root("reserve_accounting_root", &request.reserve_accounting_root)?;
        validate_root("withdrawal_release_root", &request.withdrawal_release_root)?;
        validate_root(
            "token_contract_update_root",
            &request.token_contract_update_root,
        )?;
        validate_root("defi_settlement_root", &request.defi_settlement_root)?;
        validate_root(
            "smart_contract_receipt_root",
            &request.smart_contract_receipt_root,
        )?;
        validate_root("fee_rebate_root", &request.fee_rebate_root)?;
        validate_root("settlement_proof_root", &request.settlement_proof_root)?;
        validate_root("pq_signature_root", &request.pq_signature_root)?;
        ensure_capacity(
            self.manifests.len(),
            MONERO_L2_PQ_RESERVE_RECONCILIATION_RUNTIME_MAX_MANIFESTS,
            "settlement manifests",
        )?;
        let (report_ids, batch_public) = {
            let batch = self
                .delta_batches
                .get_mut(&request.batch_id)
                .ok_or_else(|| "unknown reserve delta batch".to_string())?;
            batch.status = if request.status == ManifestStatus::Disputed {
                DeltaBatchStatus::Disputed
            } else {
                DeltaBatchStatus::Settled
            };
            (batch.report_ids.clone(), batch.public_record())
        };
        self.current_l2_height = self.current_l2_height.max(request.monero_anchor_height);
        self.counters.settlement_manifest_counter =
            self.counters.settlement_manifest_counter.saturating_add(1);
        let sequence = self.counters.settlement_manifest_counter;
        let manifest_id = settlement_manifest_id(&request, sequence);
        let record = SettlementManifestRecord {
            manifest_id: manifest_id.clone(),
            sequence,
            batch_id: request.batch_id.clone(),
            settlement_operator_id: request.settlement_operator_id.clone(),
            monero_anchor_height: request.monero_anchor_height,
            monero_anchor_hash_root: request.monero_anchor_hash_root,
            l2_state_transition_root: request.l2_state_transition_root,
            reserve_accounting_root: request.reserve_accounting_root,
            withdrawal_release_root: request.withdrawal_release_root,
            token_contract_update_root: request.token_contract_update_root,
            defi_settlement_root: request.defi_settlement_root,
            smart_contract_receipt_root: request.smart_contract_receipt_root,
            fee_rebate_root: request.fee_rebate_root,
            settlement_proof_root: request.settlement_proof_root,
            pq_signature_root: request.pq_signature_root,
            status: request.status,
            expires_at_l2_height: self
                .current_l2_height
                .saturating_add(self.config.settlement_ttl_blocks),
        };
        for report_id in report_ids {
            if let Some((snapshot_id, report_public)) =
                self.reports.get_mut(&report_id).map(|report| {
                    report.status = if record.status == ManifestStatus::Disputed {
                        ReportStatus::Disputed
                    } else {
                        ReportStatus::Settled
                    };
                    (report.snapshot_id.clone(), report.public_record())
                })
            {
                self.record_public(format!("report:{report_id}"), report_public)?;
                if let Some(snapshot_public) =
                    self.snapshots.get_mut(&snapshot_id).map(|snapshot| {
                        snapshot.status = if record.status == ManifestStatus::Disputed {
                            SnapshotStatus::Disputed
                        } else {
                            SnapshotStatus::Settled
                        };
                        snapshot.public_record()
                    })
                {
                    self.record_public(format!("snapshot:{snapshot_id}"), snapshot_public)?;
                }
            }
        }
        if record.status != ManifestStatus::Disputed && record.status != ManifestStatus::Failed {
            self.counters.snapshots_settled = self.counters.snapshots_settled.saturating_add(1);
        }
        if record.status == ManifestStatus::Disputed {
            self.counters.reports_disputed = self.counters.reports_disputed.saturating_add(1);
        }
        self.manifests.insert(manifest_id.clone(), record.clone());
        self.record_public(format!("delta_batch:{}", request.batch_id), batch_public)?;
        self.record_public(format!("manifest:{manifest_id}"), record.public_record())?;
        let _ = self.issue_receipt(
            ReceiptKind::SettlementManifestFinalized,
            &request.settlement_operator_id,
            None,
            None,
            None,
            None,
            Some(&request.batch_id),
            Some(&manifest_id),
            record.settlement_proof_root.clone(),
        )?;
        Ok(record)
    }

    pub fn advance_l2_height(&mut self, next_height: u64) {
        self.current_l2_height = self.current_l2_height.max(next_height);
    }

    pub fn counters(&self) -> Counters {
        let mut counters = self.counters.clone();
        counters.public_records = self.public_records.len() as u64;
        counters
    }

    pub fn roots(&self) -> Roots {
        Roots {
            config_root: self.config.state_root(),
            counters_root: self.counters().state_root(),
            snapshot_root: map_root(
                "MONERO-L2-PQ-RESERVE-RECONCILIATION-SNAPSHOTS",
                &self.snapshots,
                PqReserveSnapshotRecord::public_record,
            ),
            encrypted_report_root: map_root(
                "MONERO-L2-PQ-RESERVE-RECONCILIATION-REPORTS",
                &self.reports,
                EncryptedReconciliationReportRecord::public_record,
            ),
            watcher_attestation_root: map_root(
                "MONERO-L2-PQ-RESERVE-RECONCILIATION-ATTESTATIONS",
                &self.attestations,
                WatcherQuorumAttestationRecord::public_record,
            ),
            dispute_reservation_root: map_root(
                "MONERO-L2-PQ-RESERVE-RECONCILIATION-DISPUTES",
                &self.disputes,
                LowFeeDisputeReservationRecord::public_record,
            ),
            delta_batch_root: map_root(
                "MONERO-L2-PQ-RESERVE-RECONCILIATION-DELTA-BATCHES",
                &self.delta_batches,
                MoneroReserveDeltaBatchRecord::public_record,
            ),
            settlement_manifest_root: map_root(
                "MONERO-L2-PQ-RESERVE-RECONCILIATION-MANIFESTS",
                &self.manifests,
                SettlementManifestRecord::public_record,
            ),
            receipt_root: map_root(
                "MONERO-L2-PQ-RESERVE-RECONCILIATION-RECEIPTS",
                &self.receipts,
                ReconciliationReceiptRecord::public_record,
            ),
            nullifier_root: set_root(
                "MONERO-L2-PQ-RESERVE-RECONCILIATION-NULLIFIERS",
                &self.nullifiers,
            ),
            public_record_root: map_value_root(
                "MONERO-L2-PQ-RESERVE-RECONCILIATION-PUBLIC-RECORDS",
                &self.public_records,
            ),
        }
    }

    pub fn public_record_without_state_root(&self) -> Value {
        let roots = self.roots();
        json!({
            "kind": "monero_l2_pq_reserve_reconciliation_runtime_state",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": MONERO_L2_PQ_RESERVE_RECONCILIATION_RUNTIME_SCHEMA_VERSION,
            "privacy_boundary": "roots_only_no_plaintext_monero_addresses_no_view_keys_encrypted_reports_only",
            "current_l2_height": self.current_l2_height,
            "config": self.config.public_record(),
            "roots": roots.public_record(),
            "roots_root": roots.state_root(),
            "counters": self.counters().public_record(),
            "snapshot_count": self.snapshots.len(),
            "report_count": self.reports.len(),
            "attestation_count": self.attestations.len(),
            "dispute_count": self.disputes.len(),
            "delta_batch_count": self.delta_batches.len(),
            "manifest_count": self.manifests.len(),
            "receipt_count": self.receipts.len(),
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        set_json_field(&mut record, "state_root", json!(self.state_root()));
        record
    }

    pub fn state_root(&self) -> String {
        monero_l2_pq_reserve_reconciliation_runtime_state_root_from_record(
            &self.public_record_without_state_root(),
        )
    }

    pub fn validate(&self) -> MoneroL2PqReserveReconciliationRuntimeResult<()> {
        self.config.validate()?;
        require(
            self.snapshots.len() <= MONERO_L2_PQ_RESERVE_RECONCILIATION_RUNTIME_MAX_SNAPSHOTS,
            "too many snapshots",
        )?;
        require(
            self.reports.len() <= MONERO_L2_PQ_RESERVE_RECONCILIATION_RUNTIME_MAX_REPORTS,
            "too many reports",
        )?;
        require(
            self.attestations.len() <= MONERO_L2_PQ_RESERVE_RECONCILIATION_RUNTIME_MAX_ATTESTATIONS,
            "too many attestations",
        )?;
        require(
            self.disputes.len() <= MONERO_L2_PQ_RESERVE_RECONCILIATION_RUNTIME_MAX_DISPUTES,
            "too many disputes",
        )?;
        require(
            self.delta_batches.len()
                <= MONERO_L2_PQ_RESERVE_RECONCILIATION_RUNTIME_MAX_DELTA_BATCHES,
            "too many delta batches",
        )?;
        require(
            self.manifests.len() <= MONERO_L2_PQ_RESERVE_RECONCILIATION_RUNTIME_MAX_MANIFESTS,
            "too many manifests",
        )?;
        require(
            self.receipts.len() <= MONERO_L2_PQ_RESERVE_RECONCILIATION_RUNTIME_MAX_RECEIPTS,
            "too many receipts",
        )?;
        require(
            self.public_records.len()
                <= MONERO_L2_PQ_RESERVE_RECONCILIATION_RUNTIME_MAX_PUBLIC_RECORDS,
            "too many public records",
        )?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn issue_receipt(
        &mut self,
        kind: ReceiptKind,
        actor_id: &str,
        snapshot_id: Option<&str>,
        report_id: Option<&str>,
        attestation_id: Option<&str>,
        dispute_id: Option<&str>,
        batch_id: Option<&str>,
        manifest_id: Option<&str>,
        event_root: String,
    ) -> MoneroL2PqReserveReconciliationRuntimeResult<ReconciliationReceiptRecord> {
        ensure_capacity(
            self.receipts.len(),
            MONERO_L2_PQ_RESERVE_RECONCILIATION_RUNTIME_MAX_RECEIPTS,
            "receipts",
        )?;
        required("actor_id", actor_id)?;
        validate_root("event_root", &event_root)?;
        self.counters.receipt_counter = self.counters.receipt_counter.saturating_add(1);
        let sequence = self.counters.receipt_counter;
        let receipt_root = reconciliation_receipt_commitment(
            sequence,
            kind,
            actor_id,
            snapshot_id,
            report_id,
            attestation_id,
            dispute_id,
            batch_id,
            manifest_id,
            self.current_l2_height,
            &event_root,
        );
        let receipt_id = reconciliation_receipt_id(sequence, &receipt_root);
        let record = ReconciliationReceiptRecord {
            receipt_id: receipt_id.clone(),
            sequence,
            kind,
            actor_id: actor_id.to_string(),
            snapshot_id: snapshot_id.map(str::to_string),
            report_id: report_id.map(str::to_string),
            attestation_id: attestation_id.map(str::to_string),
            dispute_id: dispute_id.map(str::to_string),
            batch_id: batch_id.map(str::to_string),
            manifest_id: manifest_id.map(str::to_string),
            issued_l2_height: self.current_l2_height,
            event_root,
            receipt_root,
        };
        self.receipts.insert(receipt_id.clone(), record.clone());
        self.record_public(format!("receipt:{receipt_id}"), record.public_record())?;
        Ok(record)
    }

    fn record_public(
        &mut self,
        key: String,
        record: Value,
    ) -> MoneroL2PqReserveReconciliationRuntimeResult<()> {
        if !self.public_records.contains_key(&key) {
            ensure_capacity(
                self.public_records.len(),
                MONERO_L2_PQ_RESERVE_RECONCILIATION_RUNTIME_MAX_PUBLIC_RECORDS,
                "public records",
            )?;
        }
        self.public_records.insert(key, record);
        self.counters.public_records = self.public_records.len() as u64;
        Ok(())
    }
}

impl PqReserveSnapshotRequest {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

pub fn monero_l2_pq_reserve_reconciliation_runtime_devnet() -> State {
    State::devnet()
}

pub fn monero_l2_pq_reserve_reconciliation_runtime_state_root(state: &State) -> String {
    state.state_root()
}

pub fn monero_l2_pq_reserve_reconciliation_runtime_public_record(state: &State) -> Value {
    state.public_record()
}

pub fn monero_l2_pq_reserve_reconciliation_runtime_state_root_from_record(
    record: &Value,
) -> String {
    record_root("MONERO-L2-PQ-RESERVE-RECONCILIATION-STATE", record)
}

pub fn pq_reserve_snapshot_id(
    request: &PqReserveSnapshotRequest,
    sequence: u64,
    snapshot_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-RESERVE-RECONCILIATION-SNAPSHOT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Int(sequence as i128),
            HashPart::Str(&request.operator_id),
            HashPart::Int(request.monero_height as i128),
            HashPart::Int(request.l2_height as i128),
            HashPart::Str(snapshot_root),
            HashPart::Str(&request.snapshot_nonce),
        ],
        32,
    )
}

pub fn encrypted_reconciliation_report_id(
    request: &EncryptedReconciliationReportRequest,
    sequence: u64,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-RESERVE-RECONCILIATION-REPORT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Int(sequence as i128),
            HashPart::Str(&request.snapshot_id),
            HashPart::Str(&request.reporter_id),
            HashPart::Str(&request.encrypted_report_root),
            HashPart::Str(&request.nullifier),
        ],
        32,
    )
}

pub fn watcher_quorum_attestation_id(
    request: &WatcherQuorumAttestationRequest,
    sequence: u64,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-RESERVE-RECONCILIATION-WATCHER-ATTESTATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Int(sequence as i128),
            HashPart::Str(&request.report_id),
            HashPart::Str(&request.watcher_id),
            HashPart::Str(&request.watcher_set_root),
            HashPart::Str(&request.aggregate_pq_signature_root),
        ],
        32,
    )
}

pub fn low_fee_dispute_reservation_id(
    request: &LowFeeDisputeReservationRequest,
    sequence: u64,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-RESERVE-RECONCILIATION-DISPUTE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Int(sequence as i128),
            HashPart::Str(&request.report_id),
            HashPart::Str(&request.challenger_id),
            HashPart::Str(&request.dispute_evidence_root),
            HashPart::Str(&request.dispute_nonce),
        ],
        32,
    )
}

pub fn monero_reserve_delta_batch_id(
    request: &MoneroReserveDeltaBatchRequest,
    sequence: u64,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-RESERVE-RECONCILIATION-DELTA-BATCH-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Int(sequence as i128),
            HashPart::Str(&request.coordinator_id),
            HashPart::Str(&id_list_root("REPORTS", &request.report_ids)),
            HashPart::Str(&request.positive_delta_root),
            HashPart::Str(&request.negative_delta_root),
            HashPart::Str(&request.batch_nonce),
        ],
        32,
    )
}

pub fn settlement_manifest_id(request: &SettlementManifestRequest, sequence: u64) -> String {
    domain_hash(
        "MONERO-L2-PQ-RESERVE-RECONCILIATION-MANIFEST-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Int(sequence as i128),
            HashPart::Str(&request.batch_id),
            HashPart::Str(&request.settlement_operator_id),
            HashPart::Int(request.monero_anchor_height as i128),
            HashPart::Str(&request.monero_anchor_hash_root),
            HashPart::Str(&request.settlement_proof_root),
            HashPart::Str(&request.pq_signature_root),
        ],
        32,
    )
}

pub fn reconciliation_receipt_id(sequence: u64, receipt_root: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-RESERVE-RECONCILIATION-RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Int(sequence as i128),
            HashPart::Str(receipt_root),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
fn reconciliation_receipt_commitment(
    sequence: u64,
    kind: ReceiptKind,
    actor_id: &str,
    snapshot_id: Option<&str>,
    report_id: Option<&str>,
    attestation_id: Option<&str>,
    dispute_id: Option<&str>,
    batch_id: Option<&str>,
    manifest_id: Option<&str>,
    issued_l2_height: u64,
    event_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-RESERVE-RECONCILIATION-RECEIPT-COMMITMENT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Int(sequence as i128),
            HashPart::Str(kind.as_str()),
            HashPart::Str(actor_id),
            HashPart::Str(snapshot_id.unwrap_or("")),
            HashPart::Str(report_id.unwrap_or("")),
            HashPart::Str(attestation_id.unwrap_or("")),
            HashPart::Str(dispute_id.unwrap_or("")),
            HashPart::Str(batch_id.unwrap_or("")),
            HashPart::Str(manifest_id.unwrap_or("")),
            HashPart::Int(issued_l2_height as i128),
            HashPart::Str(event_root),
        ],
        32,
    )
}

fn record_root(domain: &str, record: &Value) -> String {
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

fn map_root<T, F>(domain: &str, map: &BTreeMap<String, T>, public_record: F) -> String
where
    F: Fn(&T) -> Value,
{
    let records = map
        .iter()
        .map(|(key, value)| json!({ "key": key, "record": public_record(value) }))
        .collect::<Vec<_>>();
    merkle_root(domain, &records)
}

fn map_value_root(domain: &str, map: &BTreeMap<String, Value>) -> String {
    let records = map
        .iter()
        .map(|(key, value)| json!({ "key": key, "record": value }))
        .collect::<Vec<_>>();
    merkle_root(domain, &records)
}

fn set_root(domain: &str, set: &BTreeSet<String>) -> String {
    let records = set.iter().map(|value| json!(value)).collect::<Vec<_>>();
    merkle_root(domain, &records)
}

fn id_list_root(label: &str, ids: &[String]) -> String {
    let records = ids.iter().map(|id| json!({ "id": id })).collect::<Vec<_>>();
    merkle_root(
        &format!("MONERO-L2-PQ-RESERVE-RECONCILIATION-{label}-ID-LIST"),
        &records,
    )
}

fn bps(numerator: u64, denominator: u64) -> u64 {
    if denominator == 0 {
        return 0;
    }
    numerator.saturating_mul(MONERO_L2_PQ_RESERVE_RECONCILIATION_RUNTIME_MAX_BPS) / denominator
}

fn bps_u128(numerator: u128, denominator: u128) -> u64 {
    if denominator == 0 {
        return MONERO_L2_PQ_RESERVE_RECONCILIATION_RUNTIME_DEFAULT_TARGET_RESERVE_COVERAGE_BPS;
    }
    numerator
        .saturating_mul(MONERO_L2_PQ_RESERVE_RECONCILIATION_RUNTIME_MAX_BPS as u128)
        .saturating_div(denominator)
        .min(u64::MAX as u128) as u64
}

fn ensure_capacity(
    current: usize,
    max: usize,
    label: &str,
) -> MoneroL2PqReserveReconciliationRuntimeResult<()> {
    require(current < max, &format!("{label} capacity exceeded"))
}

fn validate_root(field: &str, value: &str) -> MoneroL2PqReserveReconciliationRuntimeResult<()> {
    required(field, value)
}

fn required(field: &str, value: &str) -> MoneroL2PqReserveReconciliationRuntimeResult<()> {
    require(!value.trim().is_empty(), &format!("{field} is required"))
}

fn require(condition: bool, message: &str) -> MoneroL2PqReserveReconciliationRuntimeResult<()> {
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
