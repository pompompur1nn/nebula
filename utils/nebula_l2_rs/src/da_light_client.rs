use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type DaLightClientResult<T> = Result<T, String>;

pub const DA_LIGHT_CLIENT_PROTOCOL_VERSION: u64 = 1;
pub const DA_LIGHT_CLIENT_PROTOCOL_ID: &str = "nebula-da-light-client-v1";
pub const DA_LIGHT_CLIENT_PQ_SIGNATURE_SCHEME: &str = "ML-DSA-65";
pub const DA_LIGHT_CLIENT_PQ_BACKUP_SCHEME: &str = "SLH-DSA-SHAKE-128s";
pub const DA_LIGHT_CLIENT_PQ_KEM_SCHEME: &str = "ML-KEM-768";
pub const DA_LIGHT_CLIENT_COMMITMENT_SCHEME: &str = "shake256-rs-fri-pq";
pub const DA_LIGHT_CLIENT_DEFAULT_HEADER_QUORUM_BPS: u64 = 6_667;
pub const DA_LIGHT_CLIENT_DEFAULT_SAMPLING_QUORUM_BPS: u64 = 6_000;
pub const DA_LIGHT_CLIENT_DEFAULT_SAMPLE_COUNT: u64 = 12;
pub const DA_LIGHT_CLIENT_MAX_SAMPLE_COUNT: u64 = 256;
pub const DA_LIGHT_CLIENT_DEFAULT_CHALLENGE_WINDOW_BLOCKS: u64 = 32;
pub const DA_LIGHT_CLIENT_EQUIVOCATION_WINDOW_BLOCKS: u64 = 96;
pub const DA_LIGHT_CLIENT_RETENTION_CHALLENGE_WINDOW_BLOCKS: u64 = 720;
pub const DA_LIGHT_CLIENT_ARCHIVE_RECEIPT_TTL_BLOCKS: u64 = 1_440;
pub const DA_LIGHT_CLIENT_DEFAULT_CHECKPOINT_INTERVAL_BLOCKS: u64 = 20;
pub const DA_LIGHT_CLIENT_DEFAULT_CHECKPOINT_FINALITY_DELAY_BLOCKS: u64 = 8;
pub const DA_LIGHT_CLIENT_DEFAULT_RETENTION_BLOCKS: u64 = 14_400;
pub const DA_LIGHT_CLIENT_DEFAULT_ORIGINAL_SHARDS: u64 = 16;
pub const DA_LIGHT_CLIENT_DEFAULT_PARITY_SHARDS: u64 = 16;
pub const DA_LIGHT_CLIENT_DEFAULT_SHARD_SIZE_BYTES: u64 = 1_024;
pub const DA_LIGHT_CLIENT_MAX_BLOB_BYTES: u64 = 2 * 1024 * 1024;
pub const DA_LIGHT_CLIENT_MAX_SHARDS_PER_BLOB: u64 = 16_384;
pub const DA_LIGHT_CLIENT_MIN_ARCHIVAL_PROVIDERS: u64 = 2;
pub const DA_LIGHT_CLIENT_LOW_FEE_MIN_BUDGET_MICROUNITS: u64 = 25_000;
pub const DA_LIGHT_CLIENT_LOW_FEE_TARGET_FEE_MICROUNITS: u64 = 4;
pub const DA_LIGHT_CLIENT_DEFAULT_FEE_ASSET_ID: &str = "dxmr";
pub const DA_LIGHT_CLIENT_DEVNET_OPERATOR_ID: &str = "nebula-da-operator-devnet";
pub const DA_LIGHT_CLIENT_DEVNET_WATCHTOWER_ID: &str = "nebula-da-watchtower-devnet";
pub const DA_LIGHT_CLIENT_DEVNET_ARCHIVE_ID: &str = "nebula-da-archive-devnet";
pub const DA_LIGHT_CLIENT_DEVNET_WALLET_ID: &str = "wallet-commitment-devnet";
pub const DA_LIGHT_CLIENT_STATUS_ACTIVE: &str = "active";
pub const DA_LIGHT_CLIENT_STATUS_PENDING: &str = "pending";
pub const DA_LIGHT_CLIENT_STATUS_ACCEPTED: &str = "accepted";
pub const DA_LIGHT_CLIENT_STATUS_REJECTED: &str = "rejected";
pub const DA_LIGHT_CLIENT_STATUS_VERIFIED: &str = "verified";
pub const DA_LIGHT_CLIENT_STATUS_FINALIZED: &str = "finalized";
pub const DA_LIGHT_CLIENT_STATUS_EXPIRED: &str = "expired";
pub const DA_LIGHT_CLIENT_STATUS_SLASHED: &str = "slashed";
pub const DA_LIGHT_CLIENT_STATUS_RESOLVED: &str = "resolved";
pub const DA_LIGHT_CLIENT_STATUS_DISMISSED: &str = "dismissed";
pub const DA_LIGHT_CLIENT_STATUS_WITHHELD: &str = "withheld";
pub const DA_LIGHT_CLIENT_STATUS_RETAINED: &str = "retained";
pub const DA_LIGHT_CLIENT_STATUS_DEGRADED: &str = "degraded";
pub const DA_LIGHT_CLIENT_STATUS_PAUSED: &str = "paused";
pub const DA_LIGHT_CLIENT_STATUS_ACKNOWLEDGED: &str = "acknowledged";
pub const DA_LIGHT_CLIENT_LOW_FEE_PRIVATE_LANE_KEY: &str = "private_transfer_da";
pub const DA_LIGHT_CLIENT_LOW_FEE_MONERO_LANE_KEY: &str = "monero_bridge_da";
pub const DA_LIGHT_CLIENT_LOW_FEE_TOKEN_LANE_KEY: &str = "token_defi_da";
pub const DA_LIGHT_CLIENT_LOW_FEE_CONTRACT_LANE_KEY: &str = "contract_call_da";
pub const DA_LIGHT_CLIENT_LOW_FEE_PROOF_LANE_KEY: &str = "proof_aggregation_da";
pub const DA_LIGHT_CLIENT_LOW_FEE_ARCHIVE_LANE_KEY: &str = "archive_replay_da";
pub const DA_LIGHT_CLIENT_LOW_FEE_EMERGENCY_LANE_KEY: &str = "emergency_da";

const VALID_STATE_STATUSES: &[&str] = &[
    DA_LIGHT_CLIENT_STATUS_ACTIVE,
    DA_LIGHT_CLIENT_STATUS_PAUSED,
    DA_LIGHT_CLIENT_STATUS_DEGRADED,
];
const VALID_HEADER_STATUSES: &[&str] = &[
    DA_LIGHT_CLIENT_STATUS_PENDING,
    DA_LIGHT_CLIENT_STATUS_ACCEPTED,
    DA_LIGHT_CLIENT_STATUS_FINALIZED,
    DA_LIGHT_CLIENT_STATUS_REJECTED,
    DA_LIGHT_CLIENT_STATUS_SLASHED,
];
const VALID_COMMITMENT_STATUSES: &[&str] = &[
    DA_LIGHT_CLIENT_STATUS_PENDING,
    DA_LIGHT_CLIENT_STATUS_ACCEPTED,
    DA_LIGHT_CLIENT_STATUS_VERIFIED,
    DA_LIGHT_CLIENT_STATUS_FINALIZED,
    DA_LIGHT_CLIENT_STATUS_WITHHELD,
    DA_LIGHT_CLIENT_STATUS_REJECTED,
];
const VALID_PROOF_STATUSES: &[&str] = &[
    DA_LIGHT_CLIENT_STATUS_PENDING,
    DA_LIGHT_CLIENT_STATUS_ACCEPTED,
    DA_LIGHT_CLIENT_STATUS_VERIFIED,
    DA_LIGHT_CLIENT_STATUS_REJECTED,
    DA_LIGHT_CLIENT_STATUS_EXPIRED,
];
const VALID_CHECKPOINT_STATUSES: &[&str] = &[
    DA_LIGHT_CLIENT_STATUS_PENDING,
    DA_LIGHT_CLIENT_STATUS_ACCEPTED,
    DA_LIGHT_CLIENT_STATUS_FINALIZED,
    DA_LIGHT_CLIENT_STATUS_REJECTED,
    DA_LIGHT_CLIENT_STATUS_SLASHED,
];
const VALID_EVIDENCE_STATUSES: &[&str] = &[
    DA_LIGHT_CLIENT_STATUS_PENDING,
    DA_LIGHT_CLIENT_STATUS_ACCEPTED,
    DA_LIGHT_CLIENT_STATUS_VERIFIED,
    DA_LIGHT_CLIENT_STATUS_RESOLVED,
    DA_LIGHT_CLIENT_STATUS_DISMISSED,
    DA_LIGHT_CLIENT_STATUS_SLASHED,
];
const VALID_RECEIPT_STATUSES: &[&str] = &[
    DA_LIGHT_CLIENT_STATUS_PENDING,
    DA_LIGHT_CLIENT_STATUS_ACCEPTED,
    DA_LIGHT_CLIENT_STATUS_VERIFIED,
    DA_LIGHT_CLIENT_STATUS_REJECTED,
    DA_LIGHT_CLIENT_STATUS_EXPIRED,
];
const VALID_RETENTION_STATUSES: &[&str] = &[
    DA_LIGHT_CLIENT_STATUS_PENDING,
    DA_LIGHT_CLIENT_STATUS_RETAINED,
    DA_LIGHT_CLIENT_STATUS_VERIFIED,
    DA_LIGHT_CLIENT_STATUS_REJECTED,
    DA_LIGHT_CLIENT_STATUS_EXPIRED,
];
const VALID_LANE_STATUSES: &[&str] = &[
    DA_LIGHT_CLIENT_STATUS_ACTIVE,
    DA_LIGHT_CLIENT_STATUS_PAUSED,
    DA_LIGHT_CLIENT_STATUS_DEGRADED,
    DA_LIGHT_CLIENT_STATUS_EXPIRED,
];
const VALID_WINDOW_STATUSES: &[&str] = &[
    DA_LIGHT_CLIENT_STATUS_ACTIVE,
    DA_LIGHT_CLIENT_STATUS_EXPIRED,
    DA_LIGHT_CLIENT_STATUS_RESOLVED,
    DA_LIGHT_CLIENT_STATUS_DISMISSED,
];
const VALID_ALERT_STATUSES: &[&str] = &[
    DA_LIGHT_CLIENT_STATUS_PENDING,
    DA_LIGHT_CLIENT_STATUS_ACTIVE,
    DA_LIGHT_CLIENT_STATUS_ACKNOWLEDGED,
    DA_LIGHT_CLIENT_STATUS_RESOLVED,
    DA_LIGHT_CLIENT_STATUS_EXPIRED,
];
const VALID_PUBLIC_RECORD_STATUSES: &[&str] = &[
    DA_LIGHT_CLIENT_STATUS_ACTIVE,
    DA_LIGHT_CLIENT_STATUS_ACCEPTED,
    DA_LIGHT_CLIENT_STATUS_FINALIZED,
    DA_LIGHT_CLIENT_STATUS_REJECTED,
    DA_LIGHT_CLIENT_STATUS_EXPIRED,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DaBlobNamespace {
    PrivateTransfer,
    MoneroBridge,
    TokenTransfer,
    DefiCall,
    ContractCall,
    StateDiff,
    ProofAggregation,
    ForcedInclusion,
    Governance,
    ArchiveReplay,
    Emergency,
}

impl DaBlobNamespace {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::PrivateTransfer => "private_transfer",
            Self::MoneroBridge => "monero_bridge",
            Self::TokenTransfer => "token_transfer",
            Self::DefiCall => "defi_call",
            Self::ContractCall => "contract_call",
            Self::StateDiff => "state_diff",
            Self::ProofAggregation => "proof_aggregation",
            Self::ForcedInclusion => "forced_inclusion",
            Self::Governance => "governance",
            Self::ArchiveReplay => "archive_replay",
            Self::Emergency => "emergency",
        }
    }

    pub fn default_retention_blocks(&self) -> u64 {
        match self {
            Self::Emergency => DA_LIGHT_CLIENT_DEFAULT_RETENTION_BLOCKS * 4,
            Self::MoneroBridge | Self::ForcedInclusion => {
                DA_LIGHT_CLIENT_DEFAULT_RETENTION_BLOCKS * 2
            }
            Self::ArchiveReplay | Self::Governance => DA_LIGHT_CLIENT_DEFAULT_RETENTION_BLOCKS * 3,
            Self::StateDiff => DA_LIGHT_CLIENT_DEFAULT_RETENTION_BLOCKS,
            Self::ProofAggregation => DA_LIGHT_CLIENT_DEFAULT_RETENTION_BLOCKS / 2,
            Self::PrivateTransfer | Self::TokenTransfer | Self::DefiCall | Self::ContractCall => {
                DA_LIGHT_CLIENT_DEFAULT_RETENTION_BLOCKS
            }
        }
    }

    pub fn privacy_preserving_by_default(&self) -> bool {
        matches!(
            self,
            Self::PrivateTransfer | Self::MoneroBridge | Self::ForcedInclusion | Self::Emergency
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DaErasureCodecKind {
    ReedSolomon,
    RaptorQ,
    ShakeFri,
    HybridRsFri,
    HybridRsMerkle,
}

impl DaErasureCodecKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ReedSolomon => "reed_solomon",
            Self::RaptorQ => "raptor_q",
            Self::ShakeFri => "shake_fri",
            Self::HybridRsFri => "hybrid_rs_fri",
            Self::HybridRsMerkle => "hybrid_rs_merkle",
        }
    }

    pub fn commitment_scheme(&self) -> &'static str {
        match self {
            Self::ReedSolomon => "rs-merkle-shake256",
            Self::RaptorQ => "raptorq-merkle-shake256",
            Self::ShakeFri => "fri-shake256",
            Self::HybridRsFri => DA_LIGHT_CLIENT_COMMITMENT_SCHEME,
            Self::HybridRsMerkle => "rs-merkle-fri-shake256",
        }
    }

    pub fn is_quantum_resistant(&self) -> bool {
        true
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DaSamplingRole {
    CommitteeMember,
    Wallet,
    LightClient,
    Watchtower,
    ArchiveProvider,
    Sequencer,
    Operator,
}

impl DaSamplingRole {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::CommitteeMember => "committee_member",
            Self::Wallet => "wallet",
            Self::LightClient => "light_client",
            Self::Watchtower => "watchtower",
            Self::ArchiveProvider => "archive_provider",
            Self::Sequencer => "sequencer",
            Self::Operator => "operator",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DaEvidenceKind {
    UnavailableShard,
    InvalidShardProof,
    InvalidErasureRoot,
    HeaderEquivocation,
    CheckpointEquivocation,
    WithheldBlob,
    LateRetention,
    InvalidArchiveReceipt,
    SamplingForgery,
    LowFeeLaneMispricing,
}

impl DaEvidenceKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::UnavailableShard => "unavailable_shard",
            Self::InvalidShardProof => "invalid_shard_proof",
            Self::InvalidErasureRoot => "invalid_erasure_root",
            Self::HeaderEquivocation => "header_equivocation",
            Self::CheckpointEquivocation => "checkpoint_equivocation",
            Self::WithheldBlob => "withheld_blob",
            Self::LateRetention => "late_retention",
            Self::InvalidArchiveReceipt => "invalid_archive_receipt",
            Self::SamplingForgery => "sampling_forgery",
            Self::LowFeeLaneMispricing => "low_fee_lane_mispricing",
        }
    }

    pub fn default_slash_bps(&self) -> u64 {
        match self {
            Self::HeaderEquivocation | Self::CheckpointEquivocation => 2_500,
            Self::InvalidErasureRoot | Self::SamplingForgery => 1_500,
            Self::UnavailableShard | Self::WithheldBlob => 1_000,
            Self::LateRetention | Self::InvalidArchiveReceipt => 500,
            Self::InvalidShardProof | Self::LowFeeLaneMispricing => 750,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DaAlertSeverity {
    Info,
    Watch,
    Warning,
    Critical,
}

impl DaAlertSeverity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Watch => "watch",
            Self::Warning => "warning",
            Self::Critical => "critical",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LowFeeDaLaneKind {
    PrivateTransfers,
    MoneroBridge,
    TokenDefi,
    ContractCalls,
    ProofAggregation,
    ArchiveReplay,
    Emergency,
}

impl LowFeeDaLaneKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::PrivateTransfers => "private_transfers",
            Self::MoneroBridge => "monero_bridge",
            Self::TokenDefi => "token_defi",
            Self::ContractCalls => "contract_calls",
            Self::ProofAggregation => "proof_aggregation",
            Self::ArchiveReplay => "archive_replay",
            Self::Emergency => "emergency",
        }
    }

    pub fn default_lane_key(&self) -> &'static str {
        match self {
            Self::PrivateTransfers => DA_LIGHT_CLIENT_LOW_FEE_PRIVATE_LANE_KEY,
            Self::MoneroBridge => DA_LIGHT_CLIENT_LOW_FEE_MONERO_LANE_KEY,
            Self::TokenDefi => DA_LIGHT_CLIENT_LOW_FEE_TOKEN_LANE_KEY,
            Self::ContractCalls => DA_LIGHT_CLIENT_LOW_FEE_CONTRACT_LANE_KEY,
            Self::ProofAggregation => DA_LIGHT_CLIENT_LOW_FEE_PROOF_LANE_KEY,
            Self::ArchiveReplay => DA_LIGHT_CLIENT_LOW_FEE_ARCHIVE_LANE_KEY,
            Self::Emergency => DA_LIGHT_CLIENT_LOW_FEE_EMERGENCY_LANE_KEY,
        }
    }

    pub fn default_display_name(&self) -> &'static str {
        match self {
            Self::PrivateTransfers => "Private transfer DA",
            Self::MoneroBridge => "Monero bridge DA",
            Self::TokenDefi => "Token and DeFi DA",
            Self::ContractCalls => "Smart contract DA",
            Self::ProofAggregation => "Proof aggregation DA",
            Self::ArchiveReplay => "Archive replay DA",
            Self::Emergency => "Emergency DA",
        }
    }

    pub fn default_namespace(&self) -> DaBlobNamespace {
        match self {
            Self::PrivateTransfers => DaBlobNamespace::PrivateTransfer,
            Self::MoneroBridge => DaBlobNamespace::MoneroBridge,
            Self::TokenDefi => DaBlobNamespace::DefiCall,
            Self::ContractCalls => DaBlobNamespace::ContractCall,
            Self::ProofAggregation => DaBlobNamespace::ProofAggregation,
            Self::ArchiveReplay => DaBlobNamespace::ArchiveReplay,
            Self::Emergency => DaBlobNamespace::Emergency,
        }
    }

    pub fn default_priority(&self) -> u64 {
        match self {
            Self::Emergency => 1_000_000,
            Self::MoneroBridge => 900_000,
            Self::PrivateTransfers => 850_000,
            Self::TokenDefi => 725_000,
            Self::ContractCalls => 650_000,
            Self::ProofAggregation => 500_000,
            Self::ArchiveReplay => 250_000,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DaChallengeWindowKind {
    Sampling,
    FraudProof,
    Equivocation,
    Retention,
    ArchiveReceipt,
    CheckpointFinality,
    LowFeeLane,
}

impl DaChallengeWindowKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Sampling => "sampling",
            Self::FraudProof => "fraud_proof",
            Self::Equivocation => "equivocation",
            Self::Retention => "retention",
            Self::ArchiveReceipt => "archive_receipt",
            Self::CheckpointFinality => "checkpoint_finality",
            Self::LowFeeLane => "low_fee_lane",
        }
    }

    pub fn default_window_blocks(&self) -> u64 {
        match self {
            Self::Sampling => DA_LIGHT_CLIENT_DEFAULT_CHALLENGE_WINDOW_BLOCKS,
            Self::FraudProof => DA_LIGHT_CLIENT_DEFAULT_CHALLENGE_WINDOW_BLOCKS * 2,
            Self::Equivocation => DA_LIGHT_CLIENT_EQUIVOCATION_WINDOW_BLOCKS,
            Self::Retention => DA_LIGHT_CLIENT_RETENTION_CHALLENGE_WINDOW_BLOCKS,
            Self::ArchiveReceipt => DA_LIGHT_CLIENT_ARCHIVE_RECEIPT_TTL_BLOCKS,
            Self::CheckpointFinality => DA_LIGHT_CLIENT_DEFAULT_CHECKPOINT_FINALITY_DELAY_BLOCKS,
            Self::LowFeeLane => DA_LIGHT_CLIENT_DEFAULT_CHALLENGE_WINDOW_BLOCKS,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DaLightClientConfig {
    pub protocol_version: u64,
    pub protocol_id: String,
    pub min_header_quorum_bps: u64,
    pub min_sampling_quorum_bps: u64,
    pub default_sample_count: u64,
    pub max_sample_count: u64,
    pub default_challenge_window_blocks: u64,
    pub equivocation_window_blocks: u64,
    pub retention_challenge_window_blocks: u64,
    pub archive_receipt_ttl_blocks: u64,
    pub checkpoint_interval_blocks: u64,
    pub checkpoint_finality_delay_blocks: u64,
    pub default_retention_blocks: u64,
    pub min_archival_providers: u64,
    pub max_blob_bytes: u64,
    pub low_fee_min_budget_microunits: u64,
    pub low_fee_target_fee_microunits: u64,
    pub pq_signature_scheme: String,
    pub pq_backup_scheme: String,
    pub pq_kem_scheme: String,
    pub commitment_scheme: String,
}

impl Default for DaLightClientConfig {
    fn default() -> Self {
        Self {
            protocol_version: DA_LIGHT_CLIENT_PROTOCOL_VERSION,
            protocol_id: DA_LIGHT_CLIENT_PROTOCOL_ID.to_string(),
            min_header_quorum_bps: DA_LIGHT_CLIENT_DEFAULT_HEADER_QUORUM_BPS,
            min_sampling_quorum_bps: DA_LIGHT_CLIENT_DEFAULT_SAMPLING_QUORUM_BPS,
            default_sample_count: DA_LIGHT_CLIENT_DEFAULT_SAMPLE_COUNT,
            max_sample_count: DA_LIGHT_CLIENT_MAX_SAMPLE_COUNT,
            default_challenge_window_blocks: DA_LIGHT_CLIENT_DEFAULT_CHALLENGE_WINDOW_BLOCKS,
            equivocation_window_blocks: DA_LIGHT_CLIENT_EQUIVOCATION_WINDOW_BLOCKS,
            retention_challenge_window_blocks: DA_LIGHT_CLIENT_RETENTION_CHALLENGE_WINDOW_BLOCKS,
            archive_receipt_ttl_blocks: DA_LIGHT_CLIENT_ARCHIVE_RECEIPT_TTL_BLOCKS,
            checkpoint_interval_blocks: DA_LIGHT_CLIENT_DEFAULT_CHECKPOINT_INTERVAL_BLOCKS,
            checkpoint_finality_delay_blocks:
                DA_LIGHT_CLIENT_DEFAULT_CHECKPOINT_FINALITY_DELAY_BLOCKS,
            default_retention_blocks: DA_LIGHT_CLIENT_DEFAULT_RETENTION_BLOCKS,
            min_archival_providers: DA_LIGHT_CLIENT_MIN_ARCHIVAL_PROVIDERS,
            max_blob_bytes: DA_LIGHT_CLIENT_MAX_BLOB_BYTES,
            low_fee_min_budget_microunits: DA_LIGHT_CLIENT_LOW_FEE_MIN_BUDGET_MICROUNITS,
            low_fee_target_fee_microunits: DA_LIGHT_CLIENT_LOW_FEE_TARGET_FEE_MICROUNITS,
            pq_signature_scheme: DA_LIGHT_CLIENT_PQ_SIGNATURE_SCHEME.to_string(),
            pq_backup_scheme: DA_LIGHT_CLIENT_PQ_BACKUP_SCHEME.to_string(),
            pq_kem_scheme: DA_LIGHT_CLIENT_PQ_KEM_SCHEME.to_string(),
            commitment_scheme: DA_LIGHT_CLIENT_COMMITMENT_SCHEME.to_string(),
        }
    }
}

impl DaLightClientConfig {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "da_light_client_config",
            "chain_id": CHAIN_ID,
            "protocol_version": self.protocol_version,
            "protocol_id": self.protocol_id,
            "min_header_quorum_bps": self.min_header_quorum_bps,
            "min_sampling_quorum_bps": self.min_sampling_quorum_bps,
            "default_sample_count": self.default_sample_count,
            "max_sample_count": self.max_sample_count,
            "default_challenge_window_blocks": self.default_challenge_window_blocks,
            "equivocation_window_blocks": self.equivocation_window_blocks,
            "retention_challenge_window_blocks": self.retention_challenge_window_blocks,
            "archive_receipt_ttl_blocks": self.archive_receipt_ttl_blocks,
            "checkpoint_interval_blocks": self.checkpoint_interval_blocks,
            "checkpoint_finality_delay_blocks": self.checkpoint_finality_delay_blocks,
            "default_retention_blocks": self.default_retention_blocks,
            "min_archival_providers": self.min_archival_providers,
            "max_blob_bytes": self.max_blob_bytes,
            "low_fee_min_budget_microunits": self.low_fee_min_budget_microunits,
            "low_fee_target_fee_microunits": self.low_fee_target_fee_microunits,
            "pq_signature_scheme": self.pq_signature_scheme,
            "pq_backup_scheme": self.pq_backup_scheme,
            "pq_kem_scheme": self.pq_kem_scheme,
            "commitment_scheme": self.commitment_scheme,
        })
    }

    pub fn config_root(&self) -> String {
        da_light_client_config_root(&self.public_record())
    }

    pub fn validate(&self) -> DaLightClientResult<String> {
        if self.protocol_version != DA_LIGHT_CLIENT_PROTOCOL_VERSION {
            return Err("DA light client protocol version mismatch".to_string());
        }
        ensure_non_empty(&self.protocol_id, "DA light client protocol id")?;
        ensure_bps(self.min_header_quorum_bps, "DA header quorum bps")?;
        ensure_bps(self.min_sampling_quorum_bps, "DA sampling quorum bps")?;
        if self.min_header_quorum_bps == 0 {
            return Err("DA header quorum cannot be zero".to_string());
        }
        if self.min_sampling_quorum_bps == 0 {
            return Err("DA sampling quorum cannot be zero".to_string());
        }
        if self.default_sample_count == 0 {
            return Err("DA default sample count cannot be zero".to_string());
        }
        if self.default_sample_count > self.max_sample_count {
            return Err("DA default sample count exceeds max sample count".to_string());
        }
        if self.default_challenge_window_blocks == 0 {
            return Err("DA challenge window cannot be zero".to_string());
        }
        if self.equivocation_window_blocks < self.default_challenge_window_blocks {
            return Err("DA equivocation window is shorter than challenge window".to_string());
        }
        if self.archive_receipt_ttl_blocks == 0 {
            return Err("DA archive receipt ttl cannot be zero".to_string());
        }
        if self.checkpoint_interval_blocks == 0 {
            return Err("DA checkpoint interval cannot be zero".to_string());
        }
        if self.checkpoint_finality_delay_blocks == 0 {
            return Err("DA checkpoint finality delay cannot be zero".to_string());
        }
        if self.default_retention_blocks == 0 {
            return Err("DA default retention cannot be zero".to_string());
        }
        if self.min_archival_providers == 0 {
            return Err("DA minimum archival providers cannot be zero".to_string());
        }
        if self.max_blob_bytes == 0 {
            return Err("DA max blob bytes cannot be zero".to_string());
        }
        ensure_non_empty(&self.pq_signature_scheme, "DA PQ signature scheme")?;
        ensure_non_empty(&self.pq_backup_scheme, "DA PQ backup scheme")?;
        ensure_non_empty(&self.pq_kem_scheme, "DA PQ KEM scheme")?;
        ensure_non_empty(&self.commitment_scheme, "DA commitment scheme")?;
        Ok(self.config_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DaCommitteeHeader {
    pub header_id: String,
    pub committee_id: String,
    pub epoch: u64,
    pub start_height: u64,
    pub end_height: u64,
    pub member_root: String,
    pub signer_set_root: String,
    pub aggregate_da_public_key_root: String,
    pub signer_weight: u64,
    pub total_weight: u64,
    pub quorum_bps: u64,
    pub erasure_codec: DaErasureCodecKind,
    pub min_sample_count: u64,
    pub challenge_window_blocks: u64,
    pub retention_blocks: u64,
    pub sampling_seed: String,
    pub parent_header_id: String,
    pub l1_anchor_root: String,
    pub posted_at_height: u64,
    pub status: String,
}

impl DaCommitteeHeader {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        committee_id: impl Into<String>,
        epoch: u64,
        start_height: u64,
        end_height: u64,
        member_root: impl Into<String>,
        signer_set_root: impl Into<String>,
        aggregate_da_public_key_root: impl Into<String>,
        signer_weight: u64,
        total_weight: u64,
        quorum_bps: u64,
        erasure_codec: DaErasureCodecKind,
        min_sample_count: u64,
        challenge_window_blocks: u64,
        retention_blocks: u64,
        sampling_seed: impl Into<String>,
        parent_header_id: impl Into<String>,
        l1_anchor_root: impl Into<String>,
        posted_at_height: u64,
    ) -> DaLightClientResult<Self> {
        let mut header = Self {
            header_id: String::new(),
            committee_id: committee_id.into(),
            epoch,
            start_height,
            end_height,
            member_root: member_root.into(),
            signer_set_root: signer_set_root.into(),
            aggregate_da_public_key_root: aggregate_da_public_key_root.into(),
            signer_weight,
            total_weight,
            quorum_bps,
            erasure_codec,
            min_sample_count,
            challenge_window_blocks,
            retention_blocks,
            sampling_seed: sampling_seed.into(),
            parent_header_id: parent_header_id.into(),
            l1_anchor_root: l1_anchor_root.into(),
            posted_at_height,
            status: DA_LIGHT_CLIENT_STATUS_ACCEPTED.to_string(),
        };
        header.header_id = da_committee_header_id(&header.identity_record());
        header.validate()?;
        Ok(header)
    }

    pub fn devnet(epoch: u64, start_height: u64, end_height: u64, parent_header_id: &str) -> Self {
        let member_records = (0..4)
            .map(|index| {
                json!({
                    "member": format!("da-devnet-{index}"),
                    "public_key": devnet_hash("DA-HEADER-MEMBER-PK", &format!("member-{index}")),
                    "stake": 1_000_000_u64 + index * 100_000,
                })
            })
            .collect::<Vec<_>>();
        let member_root = merkle_root("DA-LIGHT-DEVNET-COMMITTEE-MEMBER", &member_records);
        let signer_set_root = merkle_root("DA-LIGHT-DEVNET-SIGNER-SET", &member_records);
        let aggregate_da_public_key_root =
            devnet_hash("DA-LIGHT-DEVNET-AGGREGATE-DA-PK", &format!("epoch-{epoch}"));
        let sampling_seed = devnet_hash("DA-LIGHT-DEVNET-SAMPLING-SEED", &format!("epoch-{epoch}"));
        let l1_anchor_root = devnet_hash("DA-LIGHT-DEVNET-L1-ANCHOR", &format!("epoch-{epoch}"));
        Self::new(
            format!("da-committee-devnet-{epoch}"),
            epoch,
            start_height,
            end_height,
            member_root,
            signer_set_root,
            aggregate_da_public_key_root,
            3_500_000,
            4_600_000,
            DA_LIGHT_CLIENT_DEFAULT_HEADER_QUORUM_BPS,
            DaErasureCodecKind::HybridRsFri,
            DA_LIGHT_CLIENT_DEFAULT_SAMPLE_COUNT,
            DA_LIGHT_CLIENT_DEFAULT_CHALLENGE_WINDOW_BLOCKS,
            DA_LIGHT_CLIENT_DEFAULT_RETENTION_BLOCKS,
            sampling_seed,
            parent_header_id.to_string(),
            l1_anchor_root,
            start_height,
        )
        .expect("deterministic DA committee header")
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "da_committee_header_identity",
            "chain_id": CHAIN_ID,
            "protocol_version": DA_LIGHT_CLIENT_PROTOCOL_VERSION,
            "committee_id": self.committee_id,
            "epoch": self.epoch,
            "start_height": self.start_height,
            "end_height": self.end_height,
            "member_root": self.member_root,
            "signer_set_root": self.signer_set_root,
            "aggregate_da_public_key_root": self.aggregate_da_public_key_root,
            "signer_weight": self.signer_weight,
            "total_weight": self.total_weight,
            "quorum_bps": self.quorum_bps,
            "erasure_codec": self.erasure_codec.as_str(),
            "commitment_scheme": self.erasure_codec.commitment_scheme(),
            "min_sample_count": self.min_sample_count,
            "challenge_window_blocks": self.challenge_window_blocks,
            "retention_blocks": self.retention_blocks,
            "sampling_seed": self.sampling_seed,
            "parent_header_id": self.parent_header_id,
            "l1_anchor_root": self.l1_anchor_root,
            "posted_at_height": self.posted_at_height,
        })
    }

    pub fn public_record_without_root(&self) -> Value {
        let mut record = self.identity_record();
        let object = record
            .as_object_mut()
            .expect("DA committee header record object");
        object.insert(
            "kind".to_string(),
            Value::String("da_committee_header".to_string()),
        );
        object.insert(
            "header_id".to_string(),
            Value::String(self.header_id.clone()),
        );
        object.insert("status".to_string(), Value::String(self.status.clone()));
        object.insert(
            "quantum_resistant".to_string(),
            Value::Bool(self.erasure_codec.is_quantum_resistant()),
        );
        record
    }

    pub fn header_root(&self) -> String {
        da_committee_header_payload_root(&self.public_record_without_root())
    }

    pub fn public_record(&self) -> Value {
        with_root_field(
            self.public_record_without_root(),
            "header_root",
            self.header_root(),
        )
    }

    pub fn contains_height(&self, height: u64) -> bool {
        height >= self.start_height && height <= self.end_height
    }

    pub fn has_quorum(&self) -> bool {
        quorum_reached(self.signer_weight, self.total_weight, self.quorum_bps)
    }

    pub fn validate(&self) -> DaLightClientResult<String> {
        ensure_non_empty(&self.committee_id, "DA committee header committee id")?;
        ensure_non_empty(&self.member_root, "DA committee header member root")?;
        ensure_non_empty(&self.signer_set_root, "DA committee header signer set root")?;
        ensure_non_empty(
            &self.aggregate_da_public_key_root,
            "DA committee header aggregate key root",
        )?;
        ensure_non_empty(&self.sampling_seed, "DA committee header sampling seed")?;
        ensure_non_empty(&self.l1_anchor_root, "DA committee header L1 anchor root")?;
        ensure_bps(self.quorum_bps, "DA committee header quorum bps")?;
        if self.start_height > self.end_height {
            return Err("DA committee header start exceeds end height".to_string());
        }
        if self.total_weight == 0 {
            return Err("DA committee header total weight cannot be zero".to_string());
        }
        if self.signer_weight > self.total_weight {
            return Err("DA committee header signer weight exceeds total weight".to_string());
        }
        if !self.has_quorum() {
            return Err("DA committee header signer weight does not meet quorum".to_string());
        }
        if self.min_sample_count == 0 {
            return Err("DA committee header sample count cannot be zero".to_string());
        }
        if self.min_sample_count > DA_LIGHT_CLIENT_MAX_SAMPLE_COUNT {
            return Err("DA committee header sample count exceeds max".to_string());
        }
        if self.challenge_window_blocks == 0 {
            return Err("DA committee header challenge window cannot be zero".to_string());
        }
        if self.retention_blocks == 0 {
            return Err("DA committee header retention blocks cannot be zero".to_string());
        }
        ensure_status(
            &self.status,
            VALID_HEADER_STATUSES,
            "DA committee header status",
        )?;
        if self.header_id != da_committee_header_id(&self.identity_record()) {
            return Err("DA committee header id mismatch".to_string());
        }
        Ok(self.header_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DaErasureCommitment {
    pub commitment_id: String,
    pub blob_id: String,
    pub block_height: u64,
    pub l2_block_hash: String,
    pub lane_id: String,
    pub namespace: DaBlobNamespace,
    pub payload_commitment: String,
    pub encoded_commitment: String,
    pub shard_commitment_root: String,
    pub sample_index_root: String,
    pub original_shards: u64,
    pub parity_shards: u64,
    pub shard_size_bytes: u64,
    pub payload_bytes: u64,
    pub encoded_bytes: u64,
    pub codec: DaErasureCodecKind,
    pub low_fee_eligible: bool,
    pub fee_asset_id: String,
    pub max_fee_microunits: u64,
    pub poster_id: String,
    pub committee_header_id: String,
    pub posted_at_height: u64,
    pub challenge_window_end: u64,
    pub retention_until_height: u64,
    pub status: String,
}

impl DaErasureCommitment {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        blob_id: impl Into<String>,
        block_height: u64,
        l2_block_hash: impl Into<String>,
        lane_id: impl Into<String>,
        namespace: DaBlobNamespace,
        payload_commitment: impl Into<String>,
        encoded_commitment: impl Into<String>,
        shard_commitment_root: impl Into<String>,
        sample_index_root: impl Into<String>,
        original_shards: u64,
        parity_shards: u64,
        shard_size_bytes: u64,
        payload_bytes: u64,
        codec: DaErasureCodecKind,
        low_fee_eligible: bool,
        fee_asset_id: impl Into<String>,
        max_fee_microunits: u64,
        poster_id: impl Into<String>,
        committee_header_id: impl Into<String>,
        posted_at_height: u64,
        challenge_window_end: u64,
        retention_until_height: u64,
    ) -> DaLightClientResult<Self> {
        let encoded_bytes = (original_shards + parity_shards).saturating_mul(shard_size_bytes);
        let mut commitment = Self {
            commitment_id: String::new(),
            blob_id: blob_id.into(),
            block_height,
            l2_block_hash: l2_block_hash.into(),
            lane_id: lane_id.into(),
            namespace,
            payload_commitment: payload_commitment.into(),
            encoded_commitment: encoded_commitment.into(),
            shard_commitment_root: shard_commitment_root.into(),
            sample_index_root: sample_index_root.into(),
            original_shards,
            parity_shards,
            shard_size_bytes,
            payload_bytes,
            encoded_bytes,
            codec,
            low_fee_eligible,
            fee_asset_id: fee_asset_id.into(),
            max_fee_microunits,
            poster_id: poster_id.into(),
            committee_header_id: committee_header_id.into(),
            posted_at_height,
            challenge_window_end,
            retention_until_height,
            status: DA_LIGHT_CLIENT_STATUS_ACCEPTED.to_string(),
        };
        commitment.commitment_id = da_erasure_commitment_id(&commitment.identity_record());
        commitment.validate()?;
        Ok(commitment)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn devnet(
        label: &str,
        lane_id: &str,
        committee_header_id: &str,
        namespace: DaBlobNamespace,
        block_height: u64,
        payload_bytes: u64,
    ) -> Self {
        let original_shards = DA_LIGHT_CLIENT_DEFAULT_ORIGINAL_SHARDS;
        let parity_shards = DA_LIGHT_CLIENT_DEFAULT_PARITY_SHARDS;
        let total_shards = original_shards.saturating_add(parity_shards).max(1);
        let min_payload_shard_size = payload_bytes
            .saturating_add(total_shards.saturating_sub(1))
            .saturating_div(total_shards);
        let shard_size_bytes = DA_LIGHT_CLIENT_DEFAULT_SHARD_SIZE_BYTES.max(min_payload_shard_size);
        let shard_records = (0..(original_shards + parity_shards))
            .map(|index| {
                json!({
                    "blob": label,
                    "shard_index": index,
                    "commitment": devnet_hash("DA-LIGHT-DEVNET-SHARD", &format!("{label}-{index}")),
                })
            })
            .collect::<Vec<_>>();
        let sample_indices = derive_da_sample_indices(
            &devnet_hash("DA-LIGHT-DEVNET-SAMPLE-SEED", label),
            original_shards + parity_shards,
            DA_LIGHT_CLIENT_DEFAULT_SAMPLE_COUNT,
        )
        .expect("deterministic devnet sample indices");
        let sample_index_values = sample_indices
            .iter()
            .map(|index| json!({ "sample_index": index }))
            .collect::<Vec<_>>();
        Self::new(
            format!("blob-{label}"),
            block_height,
            devnet_hash("DA-LIGHT-DEVNET-L2-BLOCK", label),
            lane_id.to_string(),
            namespace,
            devnet_hash("DA-LIGHT-DEVNET-PAYLOAD", label),
            devnet_hash("DA-LIGHT-DEVNET-ENCODED", label),
            merkle_root("DA-LIGHT-DEVNET-SHARD-COMMITMENT", &shard_records),
            merkle_root("DA-LIGHT-DEVNET-SAMPLE-INDEX", &sample_index_values),
            original_shards,
            parity_shards,
            shard_size_bytes,
            payload_bytes,
            DaErasureCodecKind::HybridRsFri,
            true,
            DA_LIGHT_CLIENT_DEFAULT_FEE_ASSET_ID,
            payload_bytes.saturating_mul(DA_LIGHT_CLIENT_LOW_FEE_TARGET_FEE_MICROUNITS),
            DA_LIGHT_CLIENT_DEVNET_OPERATOR_ID,
            committee_header_id.to_string(),
            block_height,
            block_height + DA_LIGHT_CLIENT_DEFAULT_CHALLENGE_WINDOW_BLOCKS,
            block_height + namespace.default_retention_blocks(),
        )
        .expect("deterministic DA erasure commitment")
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "da_erasure_commitment_identity",
            "chain_id": CHAIN_ID,
            "protocol_version": DA_LIGHT_CLIENT_PROTOCOL_VERSION,
            "blob_id": self.blob_id,
            "block_height": self.block_height,
            "l2_block_hash": self.l2_block_hash,
            "lane_id": self.lane_id,
            "namespace": self.namespace.as_str(),
            "payload_commitment": self.payload_commitment,
            "encoded_commitment": self.encoded_commitment,
            "shard_commitment_root": self.shard_commitment_root,
            "sample_index_root": self.sample_index_root,
            "original_shards": self.original_shards,
            "parity_shards": self.parity_shards,
            "shard_size_bytes": self.shard_size_bytes,
            "payload_bytes": self.payload_bytes,
            "encoded_bytes": self.encoded_bytes,
            "codec": self.codec.as_str(),
            "commitment_scheme": self.codec.commitment_scheme(),
            "low_fee_eligible": self.low_fee_eligible,
            "fee_asset_id": self.fee_asset_id,
            "max_fee_microunits": self.max_fee_microunits,
            "poster_id": self.poster_id,
            "committee_header_id": self.committee_header_id,
            "posted_at_height": self.posted_at_height,
            "challenge_window_end": self.challenge_window_end,
            "retention_until_height": self.retention_until_height,
        })
    }

    pub fn public_record_without_root(&self) -> Value {
        let mut record = self.identity_record();
        let object = record
            .as_object_mut()
            .expect("DA erasure commitment record object");
        object.insert(
            "kind".to_string(),
            Value::String("da_erasure_commitment".to_string()),
        );
        object.insert(
            "commitment_id".to_string(),
            Value::String(self.commitment_id.clone()),
        );
        object.insert("status".to_string(), Value::String(self.status.clone()));
        object.insert(
            "quantum_resistant".to_string(),
            Value::Bool(self.codec.is_quantum_resistant()),
        );
        record
    }

    pub fn commitment_root(&self) -> String {
        da_erasure_commitment_payload_root(&self.public_record_without_root())
    }

    pub fn public_record(&self) -> Value {
        with_root_field(
            self.public_record_without_root(),
            "commitment_root",
            self.commitment_root(),
        )
    }

    pub fn total_shards(&self) -> u64 {
        self.original_shards.saturating_add(self.parity_shards)
    }

    pub fn sample_indices(&self, sample_count: u64) -> DaLightClientResult<Vec<u64>> {
        derive_da_sample_indices(&self.sample_seed(), self.total_shards(), sample_count)
    }

    pub fn sample_seed(&self) -> String {
        domain_hash(
            "DA-LIGHT-CLIENT-COMMITMENT-SAMPLE-SEED",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&self.commitment_id),
                HashPart::Str(&self.encoded_commitment),
                HashPart::Str(&self.shard_commitment_root),
            ],
            32,
        )
    }

    pub fn validate(&self) -> DaLightClientResult<String> {
        ensure_non_empty(&self.blob_id, "DA erasure commitment blob id")?;
        ensure_non_empty(&self.l2_block_hash, "DA erasure commitment L2 block hash")?;
        ensure_non_empty(&self.lane_id, "DA erasure commitment lane id")?;
        ensure_non_empty(
            &self.payload_commitment,
            "DA erasure commitment payload commitment",
        )?;
        ensure_non_empty(
            &self.encoded_commitment,
            "DA erasure commitment encoded commitment",
        )?;
        ensure_non_empty(
            &self.shard_commitment_root,
            "DA erasure commitment shard commitment root",
        )?;
        ensure_non_empty(
            &self.sample_index_root,
            "DA erasure commitment sample index root",
        )?;
        ensure_non_empty(&self.fee_asset_id, "DA erasure commitment fee asset id")?;
        ensure_non_empty(&self.poster_id, "DA erasure commitment poster id")?;
        ensure_non_empty(
            &self.committee_header_id,
            "DA erasure commitment committee header id",
        )?;
        if self.original_shards == 0 {
            return Err("DA erasure commitment original shard count cannot be zero".to_string());
        }
        if self.parity_shards == 0 {
            return Err("DA erasure commitment parity shard count cannot be zero".to_string());
        }
        if self.total_shards() > DA_LIGHT_CLIENT_MAX_SHARDS_PER_BLOB {
            return Err("DA erasure commitment shard count exceeds max".to_string());
        }
        if self.shard_size_bytes == 0 {
            return Err("DA erasure commitment shard size cannot be zero".to_string());
        }
        if self.payload_bytes == 0 {
            return Err("DA erasure commitment payload bytes cannot be zero".to_string());
        }
        if self.payload_bytes > DA_LIGHT_CLIENT_MAX_BLOB_BYTES {
            return Err("DA erasure commitment payload exceeds max blob bytes".to_string());
        }
        let expected_encoded_bytes = self.total_shards().saturating_mul(self.shard_size_bytes);
        if self.encoded_bytes != expected_encoded_bytes {
            return Err("DA erasure commitment encoded byte count mismatch".to_string());
        }
        if self.challenge_window_end <= self.posted_at_height {
            return Err("DA erasure commitment challenge window ended before posting".to_string());
        }
        if self.retention_until_height <= self.challenge_window_end {
            return Err("DA erasure commitment retention ends before challenge window".to_string());
        }
        ensure_status(
            &self.status,
            VALID_COMMITMENT_STATUSES,
            "DA erasure commitment status",
        )?;
        if self.commitment_id != da_erasure_commitment_id(&self.identity_record()) {
            return Err("DA erasure commitment id mismatch".to_string());
        }
        Ok(self.commitment_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DaSamplingProof {
    pub proof_id: String,
    pub commitment_id: String,
    pub sampler_id: String,
    pub sampler_role: DaSamplingRole,
    pub sample_seed: String,
    pub sample_indices: Vec<u64>,
    pub available_indices: Vec<u64>,
    pub missing_indices: Vec<u64>,
    pub shard_proof_root: String,
    pub transcript_root: String,
    pub verifier_root: String,
    pub response_height: u64,
    pub status: String,
}

impl DaSamplingProof {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        commitment_id: impl Into<String>,
        sampler_id: impl Into<String>,
        sampler_role: DaSamplingRole,
        sample_seed: impl Into<String>,
        sample_indices: Vec<u64>,
        available_indices: Vec<u64>,
        missing_indices: Vec<u64>,
        shard_proof_root: impl Into<String>,
        transcript_root: impl Into<String>,
        verifier_root: impl Into<String>,
        response_height: u64,
    ) -> DaLightClientResult<Self> {
        let mut proof = Self {
            proof_id: String::new(),
            commitment_id: commitment_id.into(),
            sampler_id: sampler_id.into(),
            sampler_role,
            sample_seed: sample_seed.into(),
            sample_indices,
            available_indices,
            missing_indices,
            shard_proof_root: shard_proof_root.into(),
            transcript_root: transcript_root.into(),
            verifier_root: verifier_root.into(),
            response_height,
            status: DA_LIGHT_CLIENT_STATUS_VERIFIED.to_string(),
        };
        proof.proof_id = da_sampling_proof_id(&proof.identity_record());
        proof.validate()?;
        Ok(proof)
    }

    pub fn from_commitment(
        commitment: &DaErasureCommitment,
        sampler_id: &str,
        sampler_role: DaSamplingRole,
        sample_count: u64,
        response_height: u64,
    ) -> DaLightClientResult<Self> {
        let sample_seed = commitment.sample_seed();
        let sample_indices =
            derive_da_sample_indices(&sample_seed, commitment.total_shards(), sample_count)?;
        let shard_proof_values = sample_indices
            .iter()
            .map(|index| {
                json!({
                    "commitment_id": commitment.commitment_id,
                    "sample_index": index,
                    "shard_root": devnet_hash("DA-LIGHT-CLIENT-SAMPLED-SHARD", &format!("{}-{index}", commitment.commitment_id)),
                })
            })
            .collect::<Vec<_>>();
        let transcript = json!({
            "commitment_id": commitment.commitment_id,
            "sampler_id": sampler_id,
            "sampler_role": sampler_role.as_str(),
            "sample_seed": sample_seed,
            "sample_indices": sample_indices,
        });
        Self::new(
            commitment.commitment_id.clone(),
            sampler_id.to_string(),
            sampler_role,
            sample_seed,
            sample_indices.clone(),
            sample_indices,
            Vec::new(),
            merkle_root("DA-LIGHT-SAMPLED-SHARD-PROOF", &shard_proof_values),
            da_light_client_payload_root("DA-LIGHT-SAMPLING-TRANSCRIPT", &transcript),
            devnet_hash("DA-LIGHT-SAMPLING-VERIFIER", sampler_id),
            response_height,
        )
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "da_sampling_proof_identity",
            "chain_id": CHAIN_ID,
            "protocol_version": DA_LIGHT_CLIENT_PROTOCOL_VERSION,
            "commitment_id": self.commitment_id,
            "sampler_id": self.sampler_id,
            "sampler_role": self.sampler_role.as_str(),
            "sample_seed": self.sample_seed,
            "sample_indices": self.sample_indices,
            "available_indices": self.available_indices,
            "missing_indices": self.missing_indices,
            "shard_proof_root": self.shard_proof_root,
            "transcript_root": self.transcript_root,
            "verifier_root": self.verifier_root,
            "response_height": self.response_height,
        })
    }

    pub fn public_record_without_root(&self) -> Value {
        let mut record = self.identity_record();
        let object = record
            .as_object_mut()
            .expect("DA sampling proof record object");
        object.insert(
            "kind".to_string(),
            Value::String("da_sampling_proof".to_string()),
        );
        object.insert("proof_id".to_string(), Value::String(self.proof_id.clone()));
        object.insert("status".to_string(), Value::String(self.status.clone()));
        record
    }

    pub fn proof_root(&self) -> String {
        da_sampling_proof_payload_root(&self.public_record_without_root())
    }

    pub fn public_record(&self) -> Value {
        with_root_field(
            self.public_record_without_root(),
            "proof_root",
            self.proof_root(),
        )
    }

    pub fn validate(&self) -> DaLightClientResult<String> {
        ensure_non_empty(&self.commitment_id, "DA sampling proof commitment id")?;
        ensure_non_empty(&self.sampler_id, "DA sampling proof sampler id")?;
        ensure_non_empty(&self.sample_seed, "DA sampling proof seed")?;
        ensure_non_empty(&self.shard_proof_root, "DA sampling proof shard proof root")?;
        ensure_non_empty(&self.transcript_root, "DA sampling proof transcript root")?;
        ensure_non_empty(&self.verifier_root, "DA sampling proof verifier root")?;
        if self.sample_indices.is_empty() {
            return Err("DA sampling proof indices cannot be empty".to_string());
        }
        if self.sample_indices.len() as u64 > DA_LIGHT_CLIENT_MAX_SAMPLE_COUNT {
            return Err("DA sampling proof exceeds max sample count".to_string());
        }
        ensure_unique_u64(&self.sample_indices, "DA sampling proof sample index")?;
        ensure_unique_u64(&self.available_indices, "DA sampling proof available index")?;
        ensure_unique_u64(&self.missing_indices, "DA sampling proof missing index")?;
        ensure_subset_u64(
            &self.available_indices,
            &self.sample_indices,
            "DA sampling proof available index",
        )?;
        ensure_subset_u64(
            &self.missing_indices,
            &self.sample_indices,
            "DA sampling proof missing index",
        )?;
        ensure_disjoint_u64(
            &self.available_indices,
            &self.missing_indices,
            "DA sampling proof availability partition",
        )?;
        ensure_status(
            &self.status,
            VALID_PROOF_STATUSES,
            "DA sampling proof status",
        )?;
        if self.proof_id != da_sampling_proof_id(&self.identity_record()) {
            return Err("DA sampling proof id mismatch".to_string());
        }
        Ok(self.proof_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DaLightClientCheckpoint {
    pub checkpoint_id: String,
    pub checkpoint_index: u64,
    pub height: u64,
    pub block_hash: String,
    pub da_state_root: String,
    pub committee_header_root: String,
    pub erasure_commitment_root: String,
    pub sampling_proof_root: String,
    pub retention_root: String,
    pub archive_receipt_root: String,
    pub previous_checkpoint_id: String,
    pub monero_anchor_root: String,
    pub quorum_certificate_root: String,
    pub generated_at_height: u64,
    pub finality_delay_blocks: u64,
    pub challenge_window_end: u64,
    pub status: String,
}

impl DaLightClientCheckpoint {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        checkpoint_index: u64,
        height: u64,
        block_hash: impl Into<String>,
        da_state_root: impl Into<String>,
        committee_header_root: impl Into<String>,
        erasure_commitment_root: impl Into<String>,
        sampling_proof_root: impl Into<String>,
        retention_root: impl Into<String>,
        archive_receipt_root: impl Into<String>,
        previous_checkpoint_id: impl Into<String>,
        monero_anchor_root: impl Into<String>,
        quorum_certificate_root: impl Into<String>,
        generated_at_height: u64,
        finality_delay_blocks: u64,
        challenge_window_end: u64,
    ) -> DaLightClientResult<Self> {
        let mut checkpoint = Self {
            checkpoint_id: String::new(),
            checkpoint_index,
            height,
            block_hash: block_hash.into(),
            da_state_root: da_state_root.into(),
            committee_header_root: committee_header_root.into(),
            erasure_commitment_root: erasure_commitment_root.into(),
            sampling_proof_root: sampling_proof_root.into(),
            retention_root: retention_root.into(),
            archive_receipt_root: archive_receipt_root.into(),
            previous_checkpoint_id: previous_checkpoint_id.into(),
            monero_anchor_root: monero_anchor_root.into(),
            quorum_certificate_root: quorum_certificate_root.into(),
            generated_at_height,
            finality_delay_blocks,
            challenge_window_end,
            status: DA_LIGHT_CLIENT_STATUS_ACCEPTED.to_string(),
        };
        checkpoint.checkpoint_id = da_light_client_checkpoint_id(&checkpoint.identity_record());
        checkpoint.validate()?;
        Ok(checkpoint)
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "da_light_client_checkpoint_identity",
            "chain_id": CHAIN_ID,
            "protocol_version": DA_LIGHT_CLIENT_PROTOCOL_VERSION,
            "checkpoint_index": self.checkpoint_index,
            "height": self.height,
            "block_hash": self.block_hash,
            "da_state_root": self.da_state_root,
            "committee_header_root": self.committee_header_root,
            "erasure_commitment_root": self.erasure_commitment_root,
            "sampling_proof_root": self.sampling_proof_root,
            "retention_root": self.retention_root,
            "archive_receipt_root": self.archive_receipt_root,
            "previous_checkpoint_id": self.previous_checkpoint_id,
            "monero_anchor_root": self.monero_anchor_root,
            "quorum_certificate_root": self.quorum_certificate_root,
            "generated_at_height": self.generated_at_height,
            "finality_delay_blocks": self.finality_delay_blocks,
            "challenge_window_end": self.challenge_window_end,
        })
    }

    pub fn public_record_without_root(&self) -> Value {
        let mut record = self.identity_record();
        let object = record
            .as_object_mut()
            .expect("DA light client checkpoint record object");
        object.insert(
            "kind".to_string(),
            Value::String("da_light_client_checkpoint".to_string()),
        );
        object.insert(
            "checkpoint_id".to_string(),
            Value::String(self.checkpoint_id.clone()),
        );
        object.insert("status".to_string(), Value::String(self.status.clone()));
        record
    }

    pub fn checkpoint_root(&self) -> String {
        da_light_client_checkpoint_payload_root(&self.public_record_without_root())
    }

    pub fn public_record(&self) -> Value {
        with_root_field(
            self.public_record_without_root(),
            "checkpoint_root",
            self.checkpoint_root(),
        )
    }

    pub fn finalized_height(&self) -> u64 {
        self.generated_at_height
            .saturating_add(self.finality_delay_blocks)
    }

    pub fn validate(&self) -> DaLightClientResult<String> {
        ensure_non_empty(&self.block_hash, "DA checkpoint block hash")?;
        ensure_non_empty(&self.da_state_root, "DA checkpoint state root")?;
        ensure_non_empty(
            &self.committee_header_root,
            "DA checkpoint committee header root",
        )?;
        ensure_non_empty(
            &self.erasure_commitment_root,
            "DA checkpoint erasure commitment root",
        )?;
        ensure_non_empty(
            &self.sampling_proof_root,
            "DA checkpoint sampling proof root",
        )?;
        ensure_non_empty(&self.retention_root, "DA checkpoint retention root")?;
        ensure_non_empty(
            &self.archive_receipt_root,
            "DA checkpoint archive receipt root",
        )?;
        ensure_non_empty(&self.monero_anchor_root, "DA checkpoint Monero anchor root")?;
        ensure_non_empty(
            &self.quorum_certificate_root,
            "DA checkpoint quorum certificate root",
        )?;
        if self.finality_delay_blocks == 0 {
            return Err("DA checkpoint finality delay cannot be zero".to_string());
        }
        if self.generated_at_height < self.height {
            return Err("DA checkpoint generated before checkpoint height".to_string());
        }
        if self.challenge_window_end <= self.generated_at_height {
            return Err("DA checkpoint challenge window ended before generation".to_string());
        }
        ensure_status(
            &self.status,
            VALID_CHECKPOINT_STATUSES,
            "DA checkpoint status",
        )?;
        if self.checkpoint_id != da_light_client_checkpoint_id(&self.identity_record()) {
            return Err("DA light client checkpoint id mismatch".to_string());
        }
        Ok(self.checkpoint_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DaFraudEvidence {
    pub evidence_id: String,
    pub evidence_kind: DaEvidenceKind,
    pub commitment_id: Option<String>,
    pub checkpoint_id: Option<String>,
    pub header_id: Option<String>,
    pub challenger_id: String,
    pub subject_id: String,
    pub observed_height: u64,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub evidence_root: String,
    pub witness_root: String,
    pub slashing_bps: u64,
    pub status: String,
}

impl DaFraudEvidence {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        evidence_kind: DaEvidenceKind,
        commitment_id: Option<String>,
        checkpoint_id: Option<String>,
        header_id: Option<String>,
        challenger_id: impl Into<String>,
        subject_id: impl Into<String>,
        observed_height: u64,
        opened_at_height: u64,
        expires_at_height: u64,
        evidence_root: impl Into<String>,
        witness_root: impl Into<String>,
        slashing_bps: u64,
    ) -> DaLightClientResult<Self> {
        let mut evidence = Self {
            evidence_id: String::new(),
            evidence_kind,
            commitment_id,
            checkpoint_id,
            header_id,
            challenger_id: challenger_id.into(),
            subject_id: subject_id.into(),
            observed_height,
            opened_at_height,
            expires_at_height,
            evidence_root: evidence_root.into(),
            witness_root: witness_root.into(),
            slashing_bps,
            status: DA_LIGHT_CLIENT_STATUS_ACCEPTED.to_string(),
        };
        evidence.evidence_id = da_fraud_evidence_id(&evidence.identity_record());
        evidence.validate()?;
        Ok(evidence)
    }

    pub fn devnet(commitment_id: &str, opened_at_height: u64) -> Self {
        Self::new(
            DaEvidenceKind::UnavailableShard,
            Some(commitment_id.to_string()),
            None,
            None,
            DA_LIGHT_CLIENT_DEVNET_WATCHTOWER_ID,
            "da-devnet-voter-2",
            opened_at_height.saturating_sub(1),
            opened_at_height,
            opened_at_height + DA_LIGHT_CLIENT_DEFAULT_CHALLENGE_WINDOW_BLOCKS,
            devnet_hash("DA-LIGHT-DEVNET-FRAUD-EVIDENCE", commitment_id),
            devnet_hash("DA-LIGHT-DEVNET-FRAUD-WITNESS", commitment_id),
            DaEvidenceKind::UnavailableShard.default_slash_bps(),
        )
        .expect("deterministic DA fraud evidence")
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "da_fraud_evidence_identity",
            "chain_id": CHAIN_ID,
            "protocol_version": DA_LIGHT_CLIENT_PROTOCOL_VERSION,
            "evidence_kind": self.evidence_kind.as_str(),
            "commitment_id": self.commitment_id,
            "checkpoint_id": self.checkpoint_id,
            "header_id": self.header_id,
            "challenger_id": self.challenger_id,
            "subject_id": self.subject_id,
            "observed_height": self.observed_height,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "evidence_root": self.evidence_root,
            "witness_root": self.witness_root,
            "slashing_bps": self.slashing_bps,
        })
    }

    pub fn public_record_without_root(&self) -> Value {
        let mut record = self.identity_record();
        let object = record
            .as_object_mut()
            .expect("DA fraud evidence record object");
        object.insert(
            "kind".to_string(),
            Value::String("da_fraud_evidence".to_string()),
        );
        object.insert(
            "evidence_id".to_string(),
            Value::String(self.evidence_id.clone()),
        );
        object.insert("status".to_string(), Value::String(self.status.clone()));
        record
    }

    pub fn fraud_root(&self) -> String {
        da_fraud_evidence_payload_root(&self.public_record_without_root())
    }

    pub fn public_record(&self) -> Value {
        with_root_field(
            self.public_record_without_root(),
            "fraud_root",
            self.fraud_root(),
        )
    }

    pub fn validate(&self) -> DaLightClientResult<String> {
        ensure_non_empty(&self.challenger_id, "DA fraud evidence challenger id")?;
        ensure_non_empty(&self.subject_id, "DA fraud evidence subject id")?;
        ensure_non_empty(&self.evidence_root, "DA fraud evidence root")?;
        ensure_non_empty(&self.witness_root, "DA fraud evidence witness root")?;
        if self.commitment_id.is_none() && self.checkpoint_id.is_none() && self.header_id.is_none()
        {
            return Err(
                "DA fraud evidence must reference a commitment, checkpoint, or header".to_string(),
            );
        }
        if self.opened_at_height < self.observed_height {
            return Err("DA fraud evidence opened before observation".to_string());
        }
        if self.expires_at_height <= self.opened_at_height {
            return Err("DA fraud evidence expiry precedes opening".to_string());
        }
        ensure_bps(self.slashing_bps, "DA fraud evidence slashing bps")?;
        ensure_status(
            &self.status,
            VALID_EVIDENCE_STATUSES,
            "DA fraud evidence status",
        )?;
        if self.evidence_id != da_fraud_evidence_id(&self.identity_record()) {
            return Err("DA fraud evidence id mismatch".to_string());
        }
        Ok(self.fraud_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DaEquivocationEvidence {
    pub evidence_id: String,
    pub subject_id: String,
    pub subject_role: String,
    pub first_header_id: String,
    pub second_header_id: String,
    pub first_root: String,
    pub second_root: String,
    pub first_height: u64,
    pub second_height: u64,
    pub detector_id: String,
    pub evidence_root: String,
    pub slashing_bps: u64,
    pub status: String,
}

impl DaEquivocationEvidence {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        subject_id: impl Into<String>,
        subject_role: impl Into<String>,
        first_header_id: impl Into<String>,
        second_header_id: impl Into<String>,
        first_root: impl Into<String>,
        second_root: impl Into<String>,
        first_height: u64,
        second_height: u64,
        detector_id: impl Into<String>,
        evidence_root: impl Into<String>,
        slashing_bps: u64,
    ) -> DaLightClientResult<Self> {
        let mut evidence = Self {
            evidence_id: String::new(),
            subject_id: subject_id.into(),
            subject_role: subject_role.into(),
            first_header_id: first_header_id.into(),
            second_header_id: second_header_id.into(),
            first_root: first_root.into(),
            second_root: second_root.into(),
            first_height,
            second_height,
            detector_id: detector_id.into(),
            evidence_root: evidence_root.into(),
            slashing_bps,
            status: DA_LIGHT_CLIENT_STATUS_ACCEPTED.to_string(),
        };
        evidence.evidence_id = da_equivocation_evidence_id(&evidence.identity_record());
        evidence.validate()?;
        Ok(evidence)
    }

    pub fn devnet(header: &DaCommitteeHeader) -> Self {
        Self::new(
            "da-devnet-voter-1",
            "committee_member",
            header.header_id.clone(),
            devnet_hash("DA-LIGHT-DEVNET-CONFLICTING-HEADER-ID", &header.header_id),
            header.header_root(),
            devnet_hash("DA-LIGHT-DEVNET-CONFLICTING-HEADER-ROOT", &header.header_id),
            header.posted_at_height,
            header.posted_at_height,
            DA_LIGHT_CLIENT_DEVNET_WATCHTOWER_ID,
            devnet_hash("DA-LIGHT-DEVNET-EQUIVOCATION", &header.header_id),
            DaEvidenceKind::HeaderEquivocation.default_slash_bps(),
        )
        .expect("deterministic DA equivocation evidence")
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "da_equivocation_evidence_identity",
            "chain_id": CHAIN_ID,
            "protocol_version": DA_LIGHT_CLIENT_PROTOCOL_VERSION,
            "subject_id": self.subject_id,
            "subject_role": self.subject_role,
            "first_header_id": self.first_header_id,
            "second_header_id": self.second_header_id,
            "first_root": self.first_root,
            "second_root": self.second_root,
            "first_height": self.first_height,
            "second_height": self.second_height,
            "detector_id": self.detector_id,
            "evidence_root": self.evidence_root,
            "slashing_bps": self.slashing_bps,
        })
    }

    pub fn public_record_without_root(&self) -> Value {
        let mut record = self.identity_record();
        let object = record
            .as_object_mut()
            .expect("DA equivocation evidence record object");
        object.insert(
            "kind".to_string(),
            Value::String("da_equivocation_evidence".to_string()),
        );
        object.insert(
            "evidence_id".to_string(),
            Value::String(self.evidence_id.clone()),
        );
        object.insert("status".to_string(), Value::String(self.status.clone()));
        record
    }

    pub fn equivocation_root(&self) -> String {
        da_equivocation_evidence_payload_root(&self.public_record_without_root())
    }

    pub fn public_record(&self) -> Value {
        with_root_field(
            self.public_record_without_root(),
            "equivocation_root",
            self.equivocation_root(),
        )
    }

    pub fn validate(&self) -> DaLightClientResult<String> {
        ensure_non_empty(&self.subject_id, "DA equivocation subject id")?;
        ensure_non_empty(&self.subject_role, "DA equivocation subject role")?;
        ensure_non_empty(&self.first_header_id, "DA equivocation first header id")?;
        ensure_non_empty(&self.second_header_id, "DA equivocation second header id")?;
        ensure_non_empty(&self.first_root, "DA equivocation first root")?;
        ensure_non_empty(&self.second_root, "DA equivocation second root")?;
        ensure_non_empty(&self.detector_id, "DA equivocation detector id")?;
        ensure_non_empty(&self.evidence_root, "DA equivocation evidence root")?;
        if self.first_header_id == self.second_header_id {
            return Err("DA equivocation evidence must reference distinct headers".to_string());
        }
        if self.first_root == self.second_root {
            return Err("DA equivocation evidence roots must conflict".to_string());
        }
        ensure_bps(self.slashing_bps, "DA equivocation slashing bps")?;
        ensure_status(
            &self.status,
            VALID_EVIDENCE_STATUSES,
            "DA equivocation evidence status",
        )?;
        if self.evidence_id != da_equivocation_evidence_id(&self.identity_record()) {
            return Err("DA equivocation evidence id mismatch".to_string());
        }
        Ok(self.equivocation_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DaArchivalProviderReceipt {
    pub receipt_id: String,
    pub provider_id: String,
    pub provider_public_key: String,
    pub commitment_id: String,
    pub blob_id: String,
    pub range_start_height: u64,
    pub range_end_height: u64,
    pub retained_bytes: u64,
    pub retrieval_price_microunits: u64,
    pub receipt_height: u64,
    pub retention_until_height: u64,
    pub availability_root: String,
    pub audit_sample_root: String,
    pub signature_root: String,
    pub status: String,
}

impl DaArchivalProviderReceipt {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        provider_id: impl Into<String>,
        provider_public_key: impl Into<String>,
        commitment_id: impl Into<String>,
        blob_id: impl Into<String>,
        range_start_height: u64,
        range_end_height: u64,
        retained_bytes: u64,
        retrieval_price_microunits: u64,
        receipt_height: u64,
        retention_until_height: u64,
        availability_root: impl Into<String>,
        audit_sample_root: impl Into<String>,
    ) -> DaLightClientResult<Self> {
        let mut receipt = Self {
            receipt_id: String::new(),
            provider_id: provider_id.into(),
            provider_public_key: provider_public_key.into(),
            commitment_id: commitment_id.into(),
            blob_id: blob_id.into(),
            range_start_height,
            range_end_height,
            retained_bytes,
            retrieval_price_microunits,
            receipt_height,
            retention_until_height,
            availability_root: availability_root.into(),
            audit_sample_root: audit_sample_root.into(),
            signature_root: String::new(),
            status: DA_LIGHT_CLIENT_STATUS_ACCEPTED.to_string(),
        };
        receipt.receipt_id = da_archival_provider_receipt_id(&receipt.identity_record());
        receipt.signature_root = da_archive_receipt_signature_root(
            &receipt.receipt_id,
            &receipt.provider_public_key,
            &receipt.audit_sample_root,
        );
        receipt.validate()?;
        Ok(receipt)
    }

    pub fn from_commitment(commitment: &DaErasureCommitment, provider_id: &str) -> Self {
        Self::new(
            provider_id.to_string(),
            devnet_hash("DA-LIGHT-DEVNET-ARCHIVE-PK", provider_id),
            commitment.commitment_id.clone(),
            commitment.blob_id.clone(),
            commitment.posted_at_height,
            commitment.retention_until_height,
            commitment.encoded_bytes,
            commitment.payload_bytes / 8 + 1,
            commitment.posted_at_height + 1,
            commitment.retention_until_height,
            commitment.encoded_commitment.clone(),
            devnet_hash("DA-LIGHT-DEVNET-ARCHIVE-AUDIT", &commitment.commitment_id),
        )
        .expect("deterministic DA archive receipt")
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "da_archival_provider_receipt_identity",
            "chain_id": CHAIN_ID,
            "protocol_version": DA_LIGHT_CLIENT_PROTOCOL_VERSION,
            "provider_id": self.provider_id,
            "provider_public_key": self.provider_public_key,
            "commitment_id": self.commitment_id,
            "blob_id": self.blob_id,
            "range_start_height": self.range_start_height,
            "range_end_height": self.range_end_height,
            "retained_bytes": self.retained_bytes,
            "retrieval_price_microunits": self.retrieval_price_microunits,
            "receipt_height": self.receipt_height,
            "retention_until_height": self.retention_until_height,
            "availability_root": self.availability_root,
            "audit_sample_root": self.audit_sample_root,
        })
    }

    pub fn public_record_without_root(&self) -> Value {
        let mut record = self.identity_record();
        let object = record
            .as_object_mut()
            .expect("DA archival receipt record object");
        object.insert(
            "kind".to_string(),
            Value::String("da_archival_provider_receipt".to_string()),
        );
        object.insert(
            "receipt_id".to_string(),
            Value::String(self.receipt_id.clone()),
        );
        object.insert(
            "signature_root".to_string(),
            Value::String(self.signature_root.clone()),
        );
        object.insert("status".to_string(), Value::String(self.status.clone()));
        record
    }

    pub fn receipt_root(&self) -> String {
        da_archival_provider_receipt_payload_root(&self.public_record_without_root())
    }

    pub fn public_record(&self) -> Value {
        with_root_field(
            self.public_record_without_root(),
            "receipt_root",
            self.receipt_root(),
        )
    }

    pub fn validate(&self) -> DaLightClientResult<String> {
        ensure_non_empty(&self.provider_id, "DA archive receipt provider id")?;
        ensure_non_empty(
            &self.provider_public_key,
            "DA archive receipt provider public key",
        )?;
        ensure_non_empty(&self.commitment_id, "DA archive receipt commitment id")?;
        ensure_non_empty(&self.blob_id, "DA archive receipt blob id")?;
        ensure_non_empty(
            &self.availability_root,
            "DA archive receipt availability root",
        )?;
        ensure_non_empty(
            &self.audit_sample_root,
            "DA archive receipt audit sample root",
        )?;
        ensure_non_empty(&self.signature_root, "DA archive receipt signature root")?;
        if self.range_start_height > self.range_end_height {
            return Err("DA archive receipt range start exceeds end".to_string());
        }
        if self.retained_bytes == 0 {
            return Err("DA archive receipt retained bytes cannot be zero".to_string());
        }
        if self.retention_until_height < self.range_end_height {
            return Err("DA archive receipt retention ends before range".to_string());
        }
        ensure_status(
            &self.status,
            VALID_RECEIPT_STATUSES,
            "DA archive receipt status",
        )?;
        if self.receipt_id != da_archival_provider_receipt_id(&self.identity_record()) {
            return Err("DA archive receipt id mismatch".to_string());
        }
        let expected = da_archive_receipt_signature_root(
            &self.receipt_id,
            &self.provider_public_key,
            &self.audit_sample_root,
        );
        if self.signature_root != expected {
            return Err("DA archive receipt signature root mismatch".to_string());
        }
        Ok(self.receipt_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DaBlobRetentionAttestation {
    pub attestation_id: String,
    pub commitment_id: String,
    pub provider_id: String,
    pub attester_id: String,
    pub retained_from_height: u64,
    pub retained_until_height: u64,
    pub retention_epoch: u64,
    pub retained_shard_indices: Vec<u64>,
    pub retention_root: String,
    pub proof_root: String,
    pub signed_at_height: u64,
    pub status: String,
}

impl DaBlobRetentionAttestation {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        commitment_id: impl Into<String>,
        provider_id: impl Into<String>,
        attester_id: impl Into<String>,
        retained_from_height: u64,
        retained_until_height: u64,
        retention_epoch: u64,
        retained_shard_indices: Vec<u64>,
        retention_root: impl Into<String>,
        proof_root: impl Into<String>,
        signed_at_height: u64,
    ) -> DaLightClientResult<Self> {
        let mut attestation = Self {
            attestation_id: String::new(),
            commitment_id: commitment_id.into(),
            provider_id: provider_id.into(),
            attester_id: attester_id.into(),
            retained_from_height,
            retained_until_height,
            retention_epoch,
            retained_shard_indices,
            retention_root: retention_root.into(),
            proof_root: proof_root.into(),
            signed_at_height,
            status: DA_LIGHT_CLIENT_STATUS_RETAINED.to_string(),
        };
        attestation.attestation_id =
            da_blob_retention_attestation_id(&attestation.identity_record());
        attestation.validate()?;
        Ok(attestation)
    }

    pub fn from_commitment(
        commitment: &DaErasureCommitment,
        provider_id: &str,
        retention_epoch: u64,
    ) -> Self {
        let retained_shard_indices = (0..commitment.total_shards()).collect::<Vec<_>>();
        let index_values = retained_shard_indices
            .iter()
            .map(|index| json!({ "retained_shard_index": index }))
            .collect::<Vec<_>>();
        Self::new(
            commitment.commitment_id.clone(),
            provider_id.to_string(),
            DA_LIGHT_CLIENT_DEVNET_WATCHTOWER_ID,
            commitment.posted_at_height,
            commitment.retention_until_height,
            retention_epoch,
            retained_shard_indices,
            merkle_root("DA-LIGHT-RETENTION-SHARD", &index_values),
            devnet_hash("DA-LIGHT-DEVNET-RETENTION-PROOF", &commitment.commitment_id),
            commitment.posted_at_height + 2,
        )
        .expect("deterministic DA retention attestation")
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "da_blob_retention_attestation_identity",
            "chain_id": CHAIN_ID,
            "protocol_version": DA_LIGHT_CLIENT_PROTOCOL_VERSION,
            "commitment_id": self.commitment_id,
            "provider_id": self.provider_id,
            "attester_id": self.attester_id,
            "retained_from_height": self.retained_from_height,
            "retained_until_height": self.retained_until_height,
            "retention_epoch": self.retention_epoch,
            "retained_shard_indices": self.retained_shard_indices,
            "retention_root": self.retention_root,
            "proof_root": self.proof_root,
            "signed_at_height": self.signed_at_height,
        })
    }

    pub fn public_record_without_root(&self) -> Value {
        let mut record = self.identity_record();
        let object = record
            .as_object_mut()
            .expect("DA blob retention attestation record object");
        object.insert(
            "kind".to_string(),
            Value::String("da_blob_retention_attestation".to_string()),
        );
        object.insert(
            "attestation_id".to_string(),
            Value::String(self.attestation_id.clone()),
        );
        object.insert("status".to_string(), Value::String(self.status.clone()));
        record
    }

    pub fn attestation_root(&self) -> String {
        da_blob_retention_attestation_payload_root(&self.public_record_without_root())
    }

    pub fn public_record(&self) -> Value {
        with_root_field(
            self.public_record_without_root(),
            "attestation_root",
            self.attestation_root(),
        )
    }

    pub fn validate(&self) -> DaLightClientResult<String> {
        ensure_non_empty(
            &self.commitment_id,
            "DA retention attestation commitment id",
        )?;
        ensure_non_empty(&self.provider_id, "DA retention attestation provider id")?;
        ensure_non_empty(&self.attester_id, "DA retention attestation attester id")?;
        ensure_non_empty(
            &self.retention_root,
            "DA retention attestation retention root",
        )?;
        ensure_non_empty(&self.proof_root, "DA retention attestation proof root")?;
        if self.retained_from_height > self.retained_until_height {
            return Err("DA retention attestation start exceeds end".to_string());
        }
        if self.retained_shard_indices.is_empty() {
            return Err("DA retention attestation must retain at least one shard".to_string());
        }
        ensure_unique_u64(
            &self.retained_shard_indices,
            "DA retention attestation retained shard index",
        )?;
        if self.signed_at_height < self.retained_from_height {
            return Err("DA retention attestation signed before retained range".to_string());
        }
        ensure_status(
            &self.status,
            VALID_RETENTION_STATUSES,
            "DA retention attestation status",
        )?;
        if self.attestation_id != da_blob_retention_attestation_id(&self.identity_record()) {
            return Err("DA retention attestation id mismatch".to_string());
        }
        Ok(self.attestation_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalletClientSamplingProof {
    pub proof_id: String,
    pub wallet_id_commitment: String,
    pub client_session_root: String,
    pub commitment_id: String,
    pub checkpoint_id: String,
    pub sample_seed: String,
    pub sample_indices: Vec<u64>,
    pub redaction_root: String,
    pub transcript_root: String,
    pub fee_lane_id: String,
    pub observed_height: u64,
    pub proof_height: u64,
    pub status: String,
}

impl WalletClientSamplingProof {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        wallet_id_commitment: impl Into<String>,
        client_session_root: impl Into<String>,
        commitment_id: impl Into<String>,
        checkpoint_id: impl Into<String>,
        sample_seed: impl Into<String>,
        sample_indices: Vec<u64>,
        redaction_root: impl Into<String>,
        transcript_root: impl Into<String>,
        fee_lane_id: impl Into<String>,
        observed_height: u64,
        proof_height: u64,
    ) -> DaLightClientResult<Self> {
        let mut proof = Self {
            proof_id: String::new(),
            wallet_id_commitment: wallet_id_commitment.into(),
            client_session_root: client_session_root.into(),
            commitment_id: commitment_id.into(),
            checkpoint_id: checkpoint_id.into(),
            sample_seed: sample_seed.into(),
            sample_indices,
            redaction_root: redaction_root.into(),
            transcript_root: transcript_root.into(),
            fee_lane_id: fee_lane_id.into(),
            observed_height,
            proof_height,
            status: DA_LIGHT_CLIENT_STATUS_VERIFIED.to_string(),
        };
        proof.proof_id = wallet_client_sampling_proof_id(&proof.identity_record());
        proof.validate()?;
        Ok(proof)
    }

    pub fn from_commitment(
        wallet_id_commitment: &str,
        commitment: &DaErasureCommitment,
        checkpoint_id: &str,
        fee_lane_id: &str,
        sample_count: u64,
    ) -> DaLightClientResult<Self> {
        let sample_seed = domain_hash(
            "DA-LIGHT-WALLET-SAMPLING-SEED",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(wallet_id_commitment),
                HashPart::Str(&commitment.commitment_id),
                HashPart::Str(checkpoint_id),
            ],
            32,
        );
        let sample_indices =
            derive_da_sample_indices(&sample_seed, commitment.total_shards(), sample_count)?;
        let transcript = json!({
            "wallet_id_commitment": wallet_id_commitment,
            "commitment_id": commitment.commitment_id,
            "checkpoint_id": checkpoint_id,
            "sample_seed": sample_seed,
            "sample_indices": sample_indices,
        });
        Self::new(
            wallet_id_commitment.to_string(),
            devnet_hash("DA-LIGHT-DEVNET-WALLET-SESSION", wallet_id_commitment),
            commitment.commitment_id.clone(),
            checkpoint_id.to_string(),
            sample_seed,
            sample_indices,
            devnet_hash("DA-LIGHT-DEVNET-WALLET-REDACTION", wallet_id_commitment),
            da_light_client_payload_root("DA-LIGHT-WALLET-SAMPLING-TRANSCRIPT", &transcript),
            fee_lane_id.to_string(),
            commitment.block_height,
            commitment.block_height + 1,
        )
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "wallet_client_sampling_proof_identity",
            "chain_id": CHAIN_ID,
            "protocol_version": DA_LIGHT_CLIENT_PROTOCOL_VERSION,
            "wallet_id_commitment": self.wallet_id_commitment,
            "client_session_root": self.client_session_root,
            "commitment_id": self.commitment_id,
            "checkpoint_id": self.checkpoint_id,
            "sample_seed": self.sample_seed,
            "sample_indices": self.sample_indices,
            "redaction_root": self.redaction_root,
            "transcript_root": self.transcript_root,
            "fee_lane_id": self.fee_lane_id,
            "observed_height": self.observed_height,
            "proof_height": self.proof_height,
        })
    }

    pub fn public_record_without_root(&self) -> Value {
        let mut record = self.identity_record();
        let object = record
            .as_object_mut()
            .expect("wallet client sampling proof record object");
        object.insert(
            "kind".to_string(),
            Value::String("wallet_client_sampling_proof".to_string()),
        );
        object.insert("proof_id".to_string(), Value::String(self.proof_id.clone()));
        object.insert("status".to_string(), Value::String(self.status.clone()));
        record
    }

    pub fn proof_root(&self) -> String {
        wallet_client_sampling_proof_payload_root(&self.public_record_without_root())
    }

    pub fn public_record(&self) -> Value {
        with_root_field(
            self.public_record_without_root(),
            "proof_root",
            self.proof_root(),
        )
    }

    pub fn validate(&self) -> DaLightClientResult<String> {
        ensure_non_empty(
            &self.wallet_id_commitment,
            "wallet sampling wallet id commitment",
        )?;
        ensure_non_empty(
            &self.client_session_root,
            "wallet sampling client session root",
        )?;
        ensure_non_empty(&self.commitment_id, "wallet sampling commitment id")?;
        ensure_non_empty(&self.checkpoint_id, "wallet sampling checkpoint id")?;
        ensure_non_empty(&self.sample_seed, "wallet sampling seed")?;
        ensure_non_empty(&self.redaction_root, "wallet sampling redaction root")?;
        ensure_non_empty(&self.transcript_root, "wallet sampling transcript root")?;
        ensure_non_empty(&self.fee_lane_id, "wallet sampling fee lane id")?;
        if self.sample_indices.is_empty() {
            return Err("wallet sampling proof must include samples".to_string());
        }
        ensure_unique_u64(&self.sample_indices, "wallet sampling sample index")?;
        if self.proof_height < self.observed_height {
            return Err("wallet sampling proof predates observation".to_string());
        }
        ensure_status(
            &self.status,
            VALID_PROOF_STATUSES,
            "wallet sampling proof status",
        )?;
        if self.proof_id != wallet_client_sampling_proof_id(&self.identity_record()) {
            return Err("wallet sampling proof id mismatch".to_string());
        }
        Ok(self.proof_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeDaLane {
    pub lane_id: String,
    pub lane_kind: LowFeeDaLaneKind,
    pub lane_key: String,
    pub display_name: String,
    pub namespace: DaBlobNamespace,
    pub fee_asset_id: String,
    pub epoch_index: u64,
    pub start_height: u64,
    pub end_height: u64,
    pub budget_microunits: u64,
    pub spent_microunits: u64,
    pub reserved_microunits: u64,
    pub target_fee_microunits: u64,
    pub max_blob_bytes: u64,
    pub priority: u64,
    pub privacy_preserving: bool,
    pub status: String,
}

impl LowFeeDaLane {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        lane_kind: LowFeeDaLaneKind,
        lane_key: impl Into<String>,
        display_name: impl Into<String>,
        namespace: DaBlobNamespace,
        fee_asset_id: impl Into<String>,
        epoch_index: u64,
        start_height: u64,
        end_height: u64,
        budget_microunits: u64,
        target_fee_microunits: u64,
        max_blob_bytes: u64,
        priority: u64,
        privacy_preserving: bool,
    ) -> DaLightClientResult<Self> {
        let mut lane = Self {
            lane_id: String::new(),
            lane_kind,
            lane_key: lane_key.into(),
            display_name: display_name.into(),
            namespace,
            fee_asset_id: fee_asset_id.into(),
            epoch_index,
            start_height,
            end_height,
            budget_microunits,
            spent_microunits: 0,
            reserved_microunits: 0,
            target_fee_microunits,
            max_blob_bytes,
            priority,
            privacy_preserving,
            status: DA_LIGHT_CLIENT_STATUS_ACTIVE.to_string(),
        };
        lane.lane_id = low_fee_da_lane_id(&lane.identity_record());
        lane.validate()?;
        Ok(lane)
    }

    pub fn devnet(lane_kind: LowFeeDaLaneKind, epoch_index: u64) -> Self {
        let namespace = lane_kind.default_namespace();
        Self::new(
            lane_kind,
            lane_kind.default_lane_key(),
            lane_kind.default_display_name(),
            namespace,
            DA_LIGHT_CLIENT_DEFAULT_FEE_ASSET_ID,
            epoch_index,
            1,
            DA_LIGHT_CLIENT_DEFAULT_RETENTION_BLOCKS,
            DA_LIGHT_CLIENT_LOW_FEE_MIN_BUDGET_MICROUNITS
                * (lane_kind.default_priority() / 250_000),
            DA_LIGHT_CLIENT_LOW_FEE_TARGET_FEE_MICROUNITS,
            match lane_kind {
                LowFeeDaLaneKind::Emergency => DA_LIGHT_CLIENT_MAX_BLOB_BYTES,
                LowFeeDaLaneKind::ArchiveReplay => DA_LIGHT_CLIENT_MAX_BLOB_BYTES / 2,
                _ => DA_LIGHT_CLIENT_MAX_BLOB_BYTES / 4,
            },
            lane_kind.default_priority(),
            namespace.privacy_preserving_by_default(),
        )
        .expect("deterministic low fee DA lane")
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "low_fee_da_lane_identity",
            "chain_id": CHAIN_ID,
            "protocol_version": DA_LIGHT_CLIENT_PROTOCOL_VERSION,
            "lane_kind": self.lane_kind.as_str(),
            "lane_key": self.lane_key,
            "display_name": self.display_name,
            "namespace": self.namespace.as_str(),
            "fee_asset_id": self.fee_asset_id,
            "epoch_index": self.epoch_index,
            "start_height": self.start_height,
            "end_height": self.end_height,
            "budget_microunits": self.budget_microunits,
            "target_fee_microunits": self.target_fee_microunits,
            "max_blob_bytes": self.max_blob_bytes,
            "priority": self.priority,
            "privacy_preserving": self.privacy_preserving,
        })
    }

    pub fn public_record_without_root(&self) -> Value {
        let mut record = self.identity_record();
        let object = record
            .as_object_mut()
            .expect("low fee DA lane record object");
        object.insert(
            "kind".to_string(),
            Value::String("low_fee_da_lane".to_string()),
        );
        object.insert("lane_id".to_string(), Value::String(self.lane_id.clone()));
        object.insert(
            "spent_microunits".to_string(),
            Value::from(self.spent_microunits),
        );
        object.insert(
            "reserved_microunits".to_string(),
            Value::from(self.reserved_microunits),
        );
        object.insert(
            "available_microunits".to_string(),
            Value::from(self.available_microunits()),
        );
        object.insert("status".to_string(), Value::String(self.status.clone()));
        record
    }

    pub fn lane_root(&self) -> String {
        low_fee_da_lane_payload_root(&self.public_record_without_root())
    }

    pub fn public_record(&self) -> Value {
        with_root_field(
            self.public_record_without_root(),
            "lane_root",
            self.lane_root(),
        )
    }

    pub fn available_microunits(&self) -> u64 {
        self.budget_microunits
            .saturating_sub(self.spent_microunits)
            .saturating_sub(self.reserved_microunits)
    }

    pub fn contains_height(&self, height: u64) -> bool {
        height >= self.start_height && height <= self.end_height
    }

    pub fn reserve(&mut self, amount: u64) -> DaLightClientResult<String> {
        if amount > self.available_microunits() {
            return Err("low fee DA lane budget exhausted".to_string());
        }
        self.reserved_microunits = self.reserved_microunits.saturating_add(amount);
        Ok(self.lane_root())
    }

    pub fn spend_reserved(&mut self, amount: u64) -> DaLightClientResult<String> {
        if amount > self.reserved_microunits {
            return Err("low fee DA lane spend exceeds reserved amount".to_string());
        }
        self.reserved_microunits = self.reserved_microunits.saturating_sub(amount);
        self.spent_microunits = self.spent_microunits.saturating_add(amount);
        Ok(self.lane_root())
    }

    pub fn validate(&self) -> DaLightClientResult<String> {
        ensure_non_empty(&self.lane_key, "low fee DA lane key")?;
        ensure_non_empty(&self.display_name, "low fee DA lane display name")?;
        ensure_non_empty(&self.fee_asset_id, "low fee DA lane fee asset id")?;
        if self.start_height > self.end_height {
            return Err("low fee DA lane start exceeds end height".to_string());
        }
        if self.budget_microunits == 0 {
            return Err("low fee DA lane budget cannot be zero".to_string());
        }
        if self
            .spent_microunits
            .saturating_add(self.reserved_microunits)
            > self.budget_microunits
        {
            return Err("low fee DA lane spent and reserved exceeds budget".to_string());
        }
        if self.target_fee_microunits == 0 {
            return Err("low fee DA lane target fee cannot be zero".to_string());
        }
        if self.max_blob_bytes == 0 {
            return Err("low fee DA lane max blob bytes cannot be zero".to_string());
        }
        ensure_status(&self.status, VALID_LANE_STATUSES, "low fee DA lane status")?;
        if self.lane_id != low_fee_da_lane_id(&self.identity_record()) {
            return Err("low fee DA lane id mismatch".to_string());
        }
        Ok(self.lane_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DaChallengeWindow {
    pub window_id: String,
    pub window_kind: DaChallengeWindowKind,
    pub subject_id: String,
    pub start_height: u64,
    pub end_height: u64,
    pub bond_microunits: u64,
    pub challenger_count: u64,
    pub evidence_root: String,
    pub resolution_root: String,
    pub opened_by: String,
    pub status: String,
}

impl DaChallengeWindow {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        window_kind: DaChallengeWindowKind,
        subject_id: impl Into<String>,
        start_height: u64,
        end_height: u64,
        bond_microunits: u64,
        challenger_count: u64,
        evidence_root: impl Into<String>,
        resolution_root: impl Into<String>,
        opened_by: impl Into<String>,
    ) -> DaLightClientResult<Self> {
        let mut window = Self {
            window_id: String::new(),
            window_kind,
            subject_id: subject_id.into(),
            start_height,
            end_height,
            bond_microunits,
            challenger_count,
            evidence_root: evidence_root.into(),
            resolution_root: resolution_root.into(),
            opened_by: opened_by.into(),
            status: DA_LIGHT_CLIENT_STATUS_ACTIVE.to_string(),
        };
        window.window_id = da_challenge_window_id(&window.identity_record());
        window.validate()?;
        Ok(window)
    }

    pub fn for_subject(
        window_kind: DaChallengeWindowKind,
        subject_id: &str,
        start_height: u64,
        opened_by: &str,
    ) -> Self {
        let end_height = start_height + window_kind.default_window_blocks();
        Self::new(
            window_kind,
            subject_id.to_string(),
            start_height,
            end_height,
            1_000,
            0,
            merkle_root("DA-LIGHT-EMPTY-CHALLENGE-EVIDENCE", &[]),
            devnet_hash("DA-LIGHT-DEVNET-CHALLENGE-RESOLUTION", subject_id),
            opened_by.to_string(),
        )
        .expect("deterministic DA challenge window")
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "da_challenge_window_identity",
            "chain_id": CHAIN_ID,
            "protocol_version": DA_LIGHT_CLIENT_PROTOCOL_VERSION,
            "window_kind": self.window_kind.as_str(),
            "subject_id": self.subject_id,
            "start_height": self.start_height,
            "end_height": self.end_height,
            "bond_microunits": self.bond_microunits,
            "challenger_count": self.challenger_count,
            "evidence_root": self.evidence_root,
            "resolution_root": self.resolution_root,
            "opened_by": self.opened_by,
        })
    }

    pub fn public_record_without_root(&self) -> Value {
        let mut record = self.identity_record();
        let object = record
            .as_object_mut()
            .expect("DA challenge window record object");
        object.insert(
            "kind".to_string(),
            Value::String("da_challenge_window".to_string()),
        );
        object.insert(
            "window_id".to_string(),
            Value::String(self.window_id.clone()),
        );
        object.insert("status".to_string(), Value::String(self.status.clone()));
        record
    }

    pub fn window_root(&self) -> String {
        da_challenge_window_payload_root(&self.public_record_without_root())
    }

    pub fn public_record(&self) -> Value {
        with_root_field(
            self.public_record_without_root(),
            "window_root",
            self.window_root(),
        )
    }

    pub fn contains_height(&self, height: u64) -> bool {
        height >= self.start_height && height <= self.end_height
    }

    pub fn validate(&self) -> DaLightClientResult<String> {
        ensure_non_empty(&self.subject_id, "DA challenge window subject id")?;
        ensure_non_empty(&self.evidence_root, "DA challenge window evidence root")?;
        ensure_non_empty(&self.resolution_root, "DA challenge window resolution root")?;
        ensure_non_empty(&self.opened_by, "DA challenge window opener")?;
        if self.start_height >= self.end_height {
            return Err("DA challenge window start must precede end".to_string());
        }
        ensure_status(
            &self.status,
            VALID_WINDOW_STATUSES,
            "DA challenge window status",
        )?;
        if self.window_id != da_challenge_window_id(&self.identity_record()) {
            return Err("DA challenge window id mismatch".to_string());
        }
        Ok(self.window_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DaOperatorAlert {
    pub alert_id: String,
    pub severity: DaAlertSeverity,
    pub alert_key: String,
    pub subject_id: String,
    pub height: u64,
    pub expires_at_height: u64,
    pub root: String,
    pub message: String,
    pub acknowledged_by: Option<String>,
    pub status: String,
}

impl DaOperatorAlert {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        severity: DaAlertSeverity,
        alert_key: impl Into<String>,
        subject_id: impl Into<String>,
        height: u64,
        expires_at_height: u64,
        root: impl Into<String>,
        message: impl Into<String>,
    ) -> DaLightClientResult<Self> {
        let mut alert = Self {
            alert_id: String::new(),
            severity,
            alert_key: alert_key.into(),
            subject_id: subject_id.into(),
            height,
            expires_at_height,
            root: root.into(),
            message: message.into(),
            acknowledged_by: None,
            status: DA_LIGHT_CLIENT_STATUS_ACTIVE.to_string(),
        };
        alert.alert_id = da_operator_alert_id(&alert.identity_record());
        alert.validate()?;
        Ok(alert)
    }

    pub fn devnet(subject_id: &str, height: u64) -> Self {
        Self::new(
            DaAlertSeverity::Watch,
            "retention_receipt_gap",
            subject_id.to_string(),
            height,
            height + DA_LIGHT_CLIENT_ARCHIVE_RECEIPT_TTL_BLOCKS,
            devnet_hash("DA-LIGHT-DEVNET-ALERT", subject_id),
            "devnet archive receipt should be rechecked before retention expiry",
        )
        .expect("deterministic DA operator alert")
    }

    pub fn acknowledge(&mut self, operator_id: &str) -> DaLightClientResult<String> {
        ensure_non_empty(operator_id, "DA operator alert acknowledgement id")?;
        self.acknowledged_by = Some(operator_id.to_string());
        self.status = DA_LIGHT_CLIENT_STATUS_ACKNOWLEDGED.to_string();
        Ok(self.alert_root())
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "da_operator_alert_identity",
            "chain_id": CHAIN_ID,
            "protocol_version": DA_LIGHT_CLIENT_PROTOCOL_VERSION,
            "severity": self.severity.as_str(),
            "alert_key": self.alert_key,
            "subject_id": self.subject_id,
            "height": self.height,
            "expires_at_height": self.expires_at_height,
            "root": self.root,
            "message": self.message,
        })
    }

    pub fn public_record_without_root(&self) -> Value {
        let mut record = self.identity_record();
        let object = record
            .as_object_mut()
            .expect("DA operator alert record object");
        object.insert(
            "kind".to_string(),
            Value::String("da_operator_alert".to_string()),
        );
        object.insert("alert_id".to_string(), Value::String(self.alert_id.clone()));
        object.insert("acknowledged_by".to_string(), json!(self.acknowledged_by));
        object.insert("status".to_string(), Value::String(self.status.clone()));
        record
    }

    pub fn alert_root(&self) -> String {
        da_operator_alert_payload_root(&self.public_record_without_root())
    }

    pub fn public_record(&self) -> Value {
        with_root_field(
            self.public_record_without_root(),
            "alert_root",
            self.alert_root(),
        )
    }

    pub fn validate(&self) -> DaLightClientResult<String> {
        ensure_non_empty(&self.alert_key, "DA operator alert key")?;
        ensure_non_empty(&self.subject_id, "DA operator alert subject id")?;
        ensure_non_empty(&self.root, "DA operator alert root")?;
        ensure_non_empty(&self.message, "DA operator alert message")?;
        if self.expires_at_height <= self.height {
            return Err("DA operator alert expiry precedes height".to_string());
        }
        ensure_status(
            &self.status,
            VALID_ALERT_STATUSES,
            "DA operator alert status",
        )?;
        if self.alert_id != da_operator_alert_id(&self.identity_record()) {
            return Err("DA operator alert id mismatch".to_string());
        }
        Ok(self.alert_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DaLightClientPublicRecord {
    pub record_id: String,
    pub record_kind: String,
    pub subject_id: String,
    pub height: u64,
    pub state_root: String,
    pub payload_root: String,
    pub summary: String,
    pub status: String,
}

impl DaLightClientPublicRecord {
    pub fn new(
        record_kind: impl Into<String>,
        subject_id: impl Into<String>,
        height: u64,
        state_root: impl Into<String>,
        payload_root: impl Into<String>,
        summary: impl Into<String>,
    ) -> DaLightClientResult<Self> {
        let mut record = Self {
            record_id: String::new(),
            record_kind: record_kind.into(),
            subject_id: subject_id.into(),
            height,
            state_root: state_root.into(),
            payload_root: payload_root.into(),
            summary: summary.into(),
            status: DA_LIGHT_CLIENT_STATUS_ACTIVE.to_string(),
        };
        record.record_id = da_light_client_public_record_id(&record.identity_record());
        record.validate()?;
        Ok(record)
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "da_light_client_public_record_identity",
            "chain_id": CHAIN_ID,
            "protocol_version": DA_LIGHT_CLIENT_PROTOCOL_VERSION,
            "record_kind": self.record_kind,
            "subject_id": self.subject_id,
            "height": self.height,
            "state_root": self.state_root,
            "payload_root": self.payload_root,
            "summary": self.summary,
        })
    }

    pub fn public_record_without_root(&self) -> Value {
        let mut record = self.identity_record();
        let object = record
            .as_object_mut()
            .expect("DA light client public record object");
        object.insert(
            "kind".to_string(),
            Value::String("da_light_client_public_record".to_string()),
        );
        object.insert(
            "record_id".to_string(),
            Value::String(self.record_id.clone()),
        );
        object.insert("status".to_string(), Value::String(self.status.clone()));
        record
    }

    pub fn record_root(&self) -> String {
        da_light_client_public_record_payload_root(&self.public_record_without_root())
    }

    pub fn public_record(&self) -> Value {
        with_root_field(
            self.public_record_without_root(),
            "record_root",
            self.record_root(),
        )
    }

    pub fn validate(&self) -> DaLightClientResult<String> {
        ensure_non_empty(&self.record_kind, "DA light client public record kind")?;
        ensure_non_empty(&self.subject_id, "DA light client public record subject id")?;
        ensure_non_empty(&self.state_root, "DA light client public record state root")?;
        ensure_non_empty(
            &self.payload_root,
            "DA light client public record payload root",
        )?;
        ensure_non_empty(&self.summary, "DA light client public record summary")?;
        ensure_status(
            &self.status,
            VALID_PUBLIC_RECORD_STATUSES,
            "DA light client public record status",
        )?;
        if self.record_id != da_light_client_public_record_id(&self.identity_record()) {
            return Err("DA light client public record id mismatch".to_string());
        }
        Ok(self.record_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DaLightClientState {
    pub current_height: u64,
    pub status: String,
    pub config: DaLightClientConfig,
    pub committee_headers: BTreeMap<String, DaCommitteeHeader>,
    pub erasure_commitments: BTreeMap<String, DaErasureCommitment>,
    pub sampling_proofs: BTreeMap<String, DaSamplingProof>,
    pub checkpoints: BTreeMap<String, DaLightClientCheckpoint>,
    pub fraud_evidence: BTreeMap<String, DaFraudEvidence>,
    pub equivocation_evidence: BTreeMap<String, DaEquivocationEvidence>,
    pub archival_receipts: BTreeMap<String, DaArchivalProviderReceipt>,
    pub retention_attestations: BTreeMap<String, DaBlobRetentionAttestation>,
    pub wallet_sampling_proofs: BTreeMap<String, WalletClientSamplingProof>,
    pub low_fee_lanes: BTreeMap<String, LowFeeDaLane>,
    pub challenge_windows: BTreeMap<String, DaChallengeWindow>,
    pub operator_alerts: BTreeMap<String, DaOperatorAlert>,
    pub public_records: BTreeMap<String, DaLightClientPublicRecord>,
}

impl Default for DaLightClientState {
    fn default() -> Self {
        Self::new()
    }
}

impl DaLightClientState {
    pub fn new() -> Self {
        let mut state = Self::empty(0);
        for lane_kind in [
            LowFeeDaLaneKind::PrivateTransfers,
            LowFeeDaLaneKind::MoneroBridge,
            LowFeeDaLaneKind::TokenDefi,
            LowFeeDaLaneKind::ContractCalls,
            LowFeeDaLaneKind::ProofAggregation,
            LowFeeDaLaneKind::ArchiveReplay,
            LowFeeDaLaneKind::Emergency,
        ] {
            let lane = LowFeeDaLane::devnet(lane_kind, 0);
            state.low_fee_lanes.insert(lane.lane_id.clone(), lane);
        }
        state
    }

    pub fn empty(current_height: u64) -> Self {
        Self {
            current_height,
            status: DA_LIGHT_CLIENT_STATUS_ACTIVE.to_string(),
            config: DaLightClientConfig::default(),
            committee_headers: BTreeMap::new(),
            erasure_commitments: BTreeMap::new(),
            sampling_proofs: BTreeMap::new(),
            checkpoints: BTreeMap::new(),
            fraud_evidence: BTreeMap::new(),
            equivocation_evidence: BTreeMap::new(),
            archival_receipts: BTreeMap::new(),
            retention_attestations: BTreeMap::new(),
            wallet_sampling_proofs: BTreeMap::new(),
            low_fee_lanes: BTreeMap::new(),
            challenge_windows: BTreeMap::new(),
            operator_alerts: BTreeMap::new(),
            public_records: BTreeMap::new(),
        }
    }

    pub fn devnet() -> DaLightClientResult<Self> {
        let mut state = Self::new();
        state.set_height(64)?;

        let genesis_header = DaCommitteeHeader::devnet(0, 1, 40, "");
        let genesis_header_id = genesis_header.header_id.clone();
        state.apply_committee_header(genesis_header.clone())?;

        let next_header = DaCommitteeHeader::devnet(1, 41, 80, &genesis_header_id);
        let next_header_id = next_header.header_id.clone();
        state.apply_committee_header(next_header.clone())?;

        let private_lane_id = state
            .find_low_fee_lane_by_key(DA_LIGHT_CLIENT_LOW_FEE_PRIVATE_LANE_KEY)
            .ok_or_else(|| "devnet private DA lane missing".to_string())?;
        let monero_lane_id = state
            .find_low_fee_lane_by_key(DA_LIGHT_CLIENT_LOW_FEE_MONERO_LANE_KEY)
            .ok_or_else(|| "devnet Monero DA lane missing".to_string())?;
        let contract_lane_id = state
            .find_low_fee_lane_by_key(DA_LIGHT_CLIENT_LOW_FEE_CONTRACT_LANE_KEY)
            .ok_or_else(|| "devnet contract DA lane missing".to_string())?;

        let private_commitment = DaErasureCommitment::devnet(
            "private-transfer-0001",
            &private_lane_id,
            &genesis_header_id,
            DaBlobNamespace::PrivateTransfer,
            12,
            48 * 1024,
        );
        let monero_commitment = DaErasureCommitment::devnet(
            "monero-bridge-0001",
            &monero_lane_id,
            &next_header_id,
            DaBlobNamespace::MoneroBridge,
            44,
            72 * 1024,
        );
        let contract_commitment = DaErasureCommitment::devnet(
            "contract-call-0001",
            &contract_lane_id,
            &next_header_id,
            DaBlobNamespace::ContractCall,
            48,
            96 * 1024,
        );
        state.apply_erasure_commitment(private_commitment.clone())?;
        state.apply_erasure_commitment(monero_commitment.clone())?;
        state.apply_erasure_commitment(contract_commitment.clone())?;

        let private_sampling = DaSamplingProof::from_commitment(
            &private_commitment,
            DA_LIGHT_CLIENT_DEVNET_WATCHTOWER_ID,
            DaSamplingRole::Watchtower,
            DA_LIGHT_CLIENT_DEFAULT_SAMPLE_COUNT,
            private_commitment.block_height + 1,
        )?;
        let monero_sampling = DaSamplingProof::from_commitment(
            &monero_commitment,
            "nebula-da-light-client-devnet",
            DaSamplingRole::LightClient,
            DA_LIGHT_CLIENT_DEFAULT_SAMPLE_COUNT,
            monero_commitment.block_height + 1,
        )?;
        state.apply_sampling_proof(private_sampling)?;
        state.apply_sampling_proof(monero_sampling)?;

        let private_receipt = DaArchivalProviderReceipt::from_commitment(
            &private_commitment,
            DA_LIGHT_CLIENT_DEVNET_ARCHIVE_ID,
        );
        let monero_receipt = DaArchivalProviderReceipt::from_commitment(
            &monero_commitment,
            "nebula-da-archive-devnet-2",
        );
        state.apply_archival_receipt(private_receipt)?;
        state.apply_archival_receipt(monero_receipt)?;

        let private_retention = DaBlobRetentionAttestation::from_commitment(
            &private_commitment,
            DA_LIGHT_CLIENT_DEVNET_ARCHIVE_ID,
            0,
        );
        let monero_retention = DaBlobRetentionAttestation::from_commitment(
            &monero_commitment,
            "nebula-da-archive-devnet-2",
            0,
        );
        state.apply_retention_attestation(private_retention)?;
        state.apply_retention_attestation(monero_retention)?;

        let checkpoint_preimage_root = state.state_root();
        let checkpoint = DaLightClientCheckpoint::new(
            0,
            60,
            devnet_hash("DA-LIGHT-DEVNET-CHECKPOINT-BLOCK", "checkpoint-0"),
            checkpoint_preimage_root,
            state.committee_header_root(),
            state.erasure_commitment_root(),
            state.sampling_proof_root(),
            state.retention_attestation_root(),
            state.archival_receipt_root(),
            "",
            devnet_hash("DA-LIGHT-DEVNET-MONERO-ANCHOR", "checkpoint-0"),
            devnet_hash("DA-LIGHT-DEVNET-QUORUM-CERT", "checkpoint-0"),
            64,
            DA_LIGHT_CLIENT_DEFAULT_CHECKPOINT_FINALITY_DELAY_BLOCKS,
            64 + DA_LIGHT_CLIENT_DEFAULT_CHALLENGE_WINDOW_BLOCKS,
        )?;
        let checkpoint_id = checkpoint.checkpoint_id.clone();
        state.apply_checkpoint(checkpoint)?;

        let wallet_proof = WalletClientSamplingProof::from_commitment(
            DA_LIGHT_CLIENT_DEVNET_WALLET_ID,
            &private_commitment,
            &checkpoint_id,
            &private_lane_id,
            8,
        )?;
        state.apply_wallet_sampling_proof(wallet_proof)?;

        let sampling_window = DaChallengeWindow::for_subject(
            DaChallengeWindowKind::Sampling,
            &private_commitment.commitment_id,
            private_commitment.posted_at_height,
            DA_LIGHT_CLIENT_DEVNET_WATCHTOWER_ID,
        );
        let checkpoint_window = DaChallengeWindow::for_subject(
            DaChallengeWindowKind::CheckpointFinality,
            &checkpoint_id,
            64,
            DA_LIGHT_CLIENT_DEVNET_OPERATOR_ID,
        );
        state.apply_challenge_window(sampling_window)?;
        state.apply_challenge_window(checkpoint_window)?;

        state.apply_fraud_evidence(DaFraudEvidence::devnet(
            &contract_commitment.commitment_id,
            50,
        ))?;
        state.apply_equivocation_evidence(DaEquivocationEvidence::devnet(&next_header))?;
        state.apply_operator_alert(DaOperatorAlert::devnet(
            &monero_commitment.commitment_id,
            65,
        ))?;

        let state_root = state.state_root();
        let header_record = DaLightClientPublicRecord::new(
            "committee_header",
            next_header_id,
            state.current_height,
            state_root.clone(),
            next_header.header_root(),
            "devnet DA committee header accepted with post-quantum commitment policy",
        )?;
        state.publish_public_record(header_record)?;
        let checkpoint_record = DaLightClientPublicRecord::new(
            "checkpoint",
            checkpoint_id,
            state.current_height,
            state_root.clone(),
            state.checkpoint_root(),
            "devnet DA light-client checkpoint covers headers, sampling, receipts, and retention",
        )?;
        state.publish_public_record(checkpoint_record)?;
        let lanes_record = DaLightClientPublicRecord::new(
            "low_fee_lanes",
            "devnet-low-fee-da-lanes",
            state.current_height,
            state_root,
            state.low_fee_lane_root(),
            "devnet low-fee DA lanes reserve cheap private, Monero, token, DeFi, and contract data",
        )?;
        state.publish_public_record(lanes_record)?;

        state.validate()?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) -> DaLightClientResult<String> {
        self.current_height = height;
        Ok(self.state_root())
    }

    pub fn set_status(&mut self, status: &str) -> DaLightClientResult<String> {
        ensure_status(status, VALID_STATE_STATUSES, "DA light client state status")?;
        self.status = status.to_string();
        Ok(self.state_root())
    }

    pub fn apply_committee_header(
        &mut self,
        header: DaCommitteeHeader,
    ) -> DaLightClientResult<String> {
        let root = header.validate()?;
        insert_unique_record(
            &mut self.committee_headers,
            header.header_id.clone(),
            header,
            "DA committee header",
        )?;
        Ok(root)
    }

    pub fn apply_erasure_commitment(
        &mut self,
        commitment: DaErasureCommitment,
    ) -> DaLightClientResult<String> {
        let root = commitment.validate()?;
        let header = self
            .committee_headers
            .get(&commitment.committee_header_id)
            .ok_or_else(|| {
                "DA erasure commitment references unknown committee header".to_string()
            })?;
        if !header.contains_height(commitment.block_height) {
            return Err("DA erasure commitment block height outside committee header".to_string());
        }
        if !self.low_fee_lanes.contains_key(&commitment.lane_id) {
            return Err("DA erasure commitment references unknown low-fee DA lane".to_string());
        }
        insert_unique_record(
            &mut self.erasure_commitments,
            commitment.commitment_id.clone(),
            commitment,
            "DA erasure commitment",
        )?;
        Ok(root)
    }

    pub fn apply_sampling_proof(&mut self, proof: DaSamplingProof) -> DaLightClientResult<String> {
        let root = proof.validate()?;
        let commitment = self
            .erasure_commitments
            .get(&proof.commitment_id)
            .ok_or_else(|| "DA sampling proof references unknown commitment".to_string())?;
        for index in &proof.sample_indices {
            if *index >= commitment.total_shards() {
                return Err("DA sampling proof sample index exceeds shard count".to_string());
            }
        }
        if proof.response_height > commitment.challenge_window_end {
            return Err("DA sampling proof arrived after challenge window".to_string());
        }
        insert_unique_record(
            &mut self.sampling_proofs,
            proof.proof_id.clone(),
            proof,
            "DA sampling proof",
        )?;
        Ok(root)
    }

    pub fn apply_checkpoint(
        &mut self,
        checkpoint: DaLightClientCheckpoint,
    ) -> DaLightClientResult<String> {
        let root = checkpoint.validate()?;
        insert_unique_record(
            &mut self.checkpoints,
            checkpoint.checkpoint_id.clone(),
            checkpoint,
            "DA light client checkpoint",
        )?;
        Ok(root)
    }

    pub fn apply_fraud_evidence(
        &mut self,
        evidence: DaFraudEvidence,
    ) -> DaLightClientResult<String> {
        let root = evidence.validate()?;
        if let Some(commitment_id) = &evidence.commitment_id {
            if !self.erasure_commitments.contains_key(commitment_id) {
                return Err("DA fraud evidence references unknown commitment".to_string());
            }
        }
        if let Some(checkpoint_id) = &evidence.checkpoint_id {
            if !self.checkpoints.contains_key(checkpoint_id) {
                return Err("DA fraud evidence references unknown checkpoint".to_string());
            }
        }
        if let Some(header_id) = &evidence.header_id {
            if !self.committee_headers.contains_key(header_id) {
                return Err("DA fraud evidence references unknown header".to_string());
            }
        }
        insert_unique_record(
            &mut self.fraud_evidence,
            evidence.evidence_id.clone(),
            evidence,
            "DA fraud evidence",
        )?;
        Ok(root)
    }

    pub fn apply_equivocation_evidence(
        &mut self,
        evidence: DaEquivocationEvidence,
    ) -> DaLightClientResult<String> {
        let root = evidence.validate()?;
        if !self
            .committee_headers
            .contains_key(&evidence.first_header_id)
        {
            return Err("DA equivocation evidence references unknown first header".to_string());
        }
        insert_unique_record(
            &mut self.equivocation_evidence,
            evidence.evidence_id.clone(),
            evidence,
            "DA equivocation evidence",
        )?;
        Ok(root)
    }

    pub fn apply_archival_receipt(
        &mut self,
        receipt: DaArchivalProviderReceipt,
    ) -> DaLightClientResult<String> {
        let root = receipt.validate()?;
        let commitment = self
            .erasure_commitments
            .get(&receipt.commitment_id)
            .ok_or_else(|| "DA archive receipt references unknown commitment".to_string())?;
        if receipt.blob_id != commitment.blob_id {
            return Err("DA archive receipt blob id mismatch".to_string());
        }
        if receipt.retained_bytes < commitment.payload_bytes {
            return Err("DA archive receipt retained bytes below payload bytes".to_string());
        }
        insert_unique_record(
            &mut self.archival_receipts,
            receipt.receipt_id.clone(),
            receipt,
            "DA archive receipt",
        )?;
        Ok(root)
    }

    pub fn apply_retention_attestation(
        &mut self,
        attestation: DaBlobRetentionAttestation,
    ) -> DaLightClientResult<String> {
        let root = attestation.validate()?;
        let commitment = self
            .erasure_commitments
            .get(&attestation.commitment_id)
            .ok_or_else(|| "DA retention attestation references unknown commitment".to_string())?;
        for index in &attestation.retained_shard_indices {
            if *index >= commitment.total_shards() {
                return Err("DA retention attestation shard index exceeds shard count".to_string());
            }
        }
        insert_unique_record(
            &mut self.retention_attestations,
            attestation.attestation_id.clone(),
            attestation,
            "DA retention attestation",
        )?;
        Ok(root)
    }

    pub fn apply_wallet_sampling_proof(
        &mut self,
        proof: WalletClientSamplingProof,
    ) -> DaLightClientResult<String> {
        let root = proof.validate()?;
        let commitment = self
            .erasure_commitments
            .get(&proof.commitment_id)
            .ok_or_else(|| "wallet sampling proof references unknown commitment".to_string())?;
        if !self.checkpoints.contains_key(&proof.checkpoint_id) {
            return Err("wallet sampling proof references unknown checkpoint".to_string());
        }
        if !self.low_fee_lanes.contains_key(&proof.fee_lane_id) {
            return Err("wallet sampling proof references unknown low-fee DA lane".to_string());
        }
        for index in &proof.sample_indices {
            if *index >= commitment.total_shards() {
                return Err("wallet sampling proof sample index exceeds shard count".to_string());
            }
        }
        insert_unique_record(
            &mut self.wallet_sampling_proofs,
            proof.proof_id.clone(),
            proof,
            "wallet sampling proof",
        )?;
        Ok(root)
    }

    pub fn apply_low_fee_lane(&mut self, lane: LowFeeDaLane) -> DaLightClientResult<String> {
        let root = lane.validate()?;
        self.low_fee_lanes.insert(lane.lane_id.clone(), lane);
        Ok(root)
    }

    pub fn apply_challenge_window(
        &mut self,
        window: DaChallengeWindow,
    ) -> DaLightClientResult<String> {
        let root = window.validate()?;
        insert_unique_record(
            &mut self.challenge_windows,
            window.window_id.clone(),
            window,
            "DA challenge window",
        )?;
        Ok(root)
    }

    pub fn apply_operator_alert(&mut self, alert: DaOperatorAlert) -> DaLightClientResult<String> {
        let root = alert.validate()?;
        insert_unique_record(
            &mut self.operator_alerts,
            alert.alert_id.clone(),
            alert,
            "DA operator alert",
        )?;
        Ok(root)
    }

    pub fn publish_public_record(
        &mut self,
        record: DaLightClientPublicRecord,
    ) -> DaLightClientResult<String> {
        let root = record.validate()?;
        insert_unique_record(
            &mut self.public_records,
            record.record_id.clone(),
            record,
            "DA light client public record",
        )?;
        Ok(root)
    }

    pub fn find_low_fee_lane_by_key(&self, lane_key: &str) -> Option<String> {
        self.low_fee_lanes
            .values()
            .find(|lane| lane.lane_key == lane_key)
            .map(|lane| lane.lane_id.clone())
    }

    pub fn committee_header_root(&self) -> String {
        da_committee_header_root(&self.committee_headers.values().cloned().collect::<Vec<_>>())
    }

    pub fn erasure_commitment_root(&self) -> String {
        da_erasure_commitment_root(
            &self
                .erasure_commitments
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn sampling_proof_root(&self) -> String {
        da_sampling_proof_root(&self.sampling_proofs.values().cloned().collect::<Vec<_>>())
    }

    pub fn checkpoint_root(&self) -> String {
        da_light_client_checkpoint_root(&self.checkpoints.values().cloned().collect::<Vec<_>>())
    }

    pub fn fraud_evidence_root(&self) -> String {
        da_fraud_evidence_root(&self.fraud_evidence.values().cloned().collect::<Vec<_>>())
    }

    pub fn equivocation_evidence_root(&self) -> String {
        da_equivocation_evidence_root(
            &self
                .equivocation_evidence
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn archival_receipt_root(&self) -> String {
        da_archival_provider_receipt_root(
            &self.archival_receipts.values().cloned().collect::<Vec<_>>(),
        )
    }

    pub fn retention_attestation_root(&self) -> String {
        da_blob_retention_attestation_root(
            &self
                .retention_attestations
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn wallet_sampling_proof_root(&self) -> String {
        wallet_client_sampling_proof_root(
            &self
                .wallet_sampling_proofs
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn low_fee_lane_root(&self) -> String {
        low_fee_da_lane_root(&self.low_fee_lanes.values().cloned().collect::<Vec<_>>())
    }

    pub fn challenge_window_root(&self) -> String {
        da_challenge_window_root(&self.challenge_windows.values().cloned().collect::<Vec<_>>())
    }

    pub fn operator_alert_root(&self) -> String {
        da_operator_alert_root(&self.operator_alerts.values().cloned().collect::<Vec<_>>())
    }

    pub fn public_record_root(&self) -> String {
        da_light_client_public_record_root(
            &self.public_records.values().cloned().collect::<Vec<_>>(),
        )
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "da_light_client_state",
            "chain_id": CHAIN_ID,
            "protocol_version": DA_LIGHT_CLIENT_PROTOCOL_VERSION,
            "current_height": self.current_height,
            "status": self.status,
            "config_root": self.config.config_root(),
            "committee_header_root": self.committee_header_root(),
            "erasure_commitment_root": self.erasure_commitment_root(),
            "sampling_proof_root": self.sampling_proof_root(),
            "checkpoint_root": self.checkpoint_root(),
            "fraud_evidence_root": self.fraud_evidence_root(),
            "equivocation_evidence_root": self.equivocation_evidence_root(),
            "archival_receipt_root": self.archival_receipt_root(),
            "retention_attestation_root": self.retention_attestation_root(),
            "wallet_sampling_proof_root": self.wallet_sampling_proof_root(),
            "low_fee_lane_root": self.low_fee_lane_root(),
            "challenge_window_root": self.challenge_window_root(),
            "operator_alert_root": self.operator_alert_root(),
            "public_record_root": self.public_record_root(),
            "committee_header_count": self.committee_headers.len() as u64,
            "erasure_commitment_count": self.erasure_commitments.len() as u64,
            "sampling_proof_count": self.sampling_proofs.len() as u64,
            "checkpoint_count": self.checkpoints.len() as u64,
            "fraud_evidence_count": self.fraud_evidence.len() as u64,
            "equivocation_evidence_count": self.equivocation_evidence.len() as u64,
            "archival_receipt_count": self.archival_receipts.len() as u64,
            "retention_attestation_count": self.retention_attestations.len() as u64,
            "wallet_sampling_proof_count": self.wallet_sampling_proofs.len() as u64,
            "low_fee_lane_count": self.low_fee_lanes.len() as u64,
            "challenge_window_count": self.challenge_windows.len() as u64,
            "operator_alert_count": self.operator_alerts.len() as u64,
            "public_record_count": self.public_records.len() as u64,
        })
    }

    pub fn state_root(&self) -> String {
        da_light_client_state_root_from_record(&self.public_record_without_root())
    }

    pub fn public_record(&self) -> Value {
        with_root_field(
            self.public_record_without_root(),
            "da_light_client_state_root",
            self.state_root(),
        )
    }

    pub fn validate(&self) -> DaLightClientResult<String> {
        ensure_status(
            &self.status,
            VALID_STATE_STATUSES,
            "DA light client state status",
        )?;
        self.config.validate()?;
        for header in self.committee_headers.values() {
            header.validate()?;
        }
        for commitment in self.erasure_commitments.values() {
            commitment.validate()?;
            if !self
                .committee_headers
                .contains_key(&commitment.committee_header_id)
            {
                return Err("DA state has commitment for unknown committee header".to_string());
            }
            if !self.low_fee_lanes.contains_key(&commitment.lane_id) {
                return Err("DA state has commitment for unknown low-fee lane".to_string());
            }
        }
        for proof in self.sampling_proofs.values() {
            proof.validate()?;
            if !self.erasure_commitments.contains_key(&proof.commitment_id) {
                return Err("DA state has sampling proof for unknown commitment".to_string());
            }
        }
        for checkpoint in self.checkpoints.values() {
            checkpoint.validate()?;
        }
        for evidence in self.fraud_evidence.values() {
            evidence.validate()?;
        }
        for evidence in self.equivocation_evidence.values() {
            evidence.validate()?;
        }
        for receipt in self.archival_receipts.values() {
            receipt.validate()?;
            if !self
                .erasure_commitments
                .contains_key(&receipt.commitment_id)
            {
                return Err("DA state has archive receipt for unknown commitment".to_string());
            }
        }
        for attestation in self.retention_attestations.values() {
            attestation.validate()?;
            if !self
                .erasure_commitments
                .contains_key(&attestation.commitment_id)
            {
                return Err("DA state has retention attestation for unknown commitment".to_string());
            }
        }
        for proof in self.wallet_sampling_proofs.values() {
            proof.validate()?;
            if !self.erasure_commitments.contains_key(&proof.commitment_id) {
                return Err("DA state has wallet proof for unknown commitment".to_string());
            }
            if !self.checkpoints.contains_key(&proof.checkpoint_id) {
                return Err("DA state has wallet proof for unknown checkpoint".to_string());
            }
        }
        for lane in self.low_fee_lanes.values() {
            lane.validate()?;
        }
        for window in self.challenge_windows.values() {
            window.validate()?;
        }
        for alert in self.operator_alerts.values() {
            alert.validate()?;
        }
        for record in self.public_records.values() {
            record.validate()?;
        }
        Ok(self.state_root())
    }
}

pub fn da_light_client_payload_root(domain: &str, record: &Value) -> String {
    domain_hash(domain, &[HashPart::Json(record)], 32)
}

pub fn da_light_client_config_root(record: &Value) -> String {
    da_light_client_payload_root("DA-LIGHT-CLIENT-CONFIG", record)
}

pub fn da_committee_header_id(record: &Value) -> String {
    domain_hash(
        "DA-LIGHT-COMMITTEE-HEADER-ID",
        &[HashPart::Str(CHAIN_ID), HashPart::Json(record)],
        32,
    )
}

pub fn da_committee_header_payload_root(record: &Value) -> String {
    da_light_client_payload_root("DA-LIGHT-COMMITTEE-HEADER", record)
}

pub fn da_erasure_commitment_id(record: &Value) -> String {
    domain_hash(
        "DA-LIGHT-ERASURE-COMMITMENT-ID",
        &[HashPart::Str(CHAIN_ID), HashPart::Json(record)],
        32,
    )
}

pub fn da_erasure_commitment_payload_root(record: &Value) -> String {
    da_light_client_payload_root("DA-LIGHT-ERASURE-COMMITMENT", record)
}

pub fn da_sampling_proof_id(record: &Value) -> String {
    domain_hash(
        "DA-LIGHT-SAMPLING-PROOF-ID",
        &[HashPart::Str(CHAIN_ID), HashPart::Json(record)],
        32,
    )
}

pub fn da_sampling_proof_payload_root(record: &Value) -> String {
    da_light_client_payload_root("DA-LIGHT-SAMPLING-PROOF", record)
}

pub fn da_light_client_checkpoint_id(record: &Value) -> String {
    domain_hash(
        "DA-LIGHT-CHECKPOINT-ID",
        &[HashPart::Str(CHAIN_ID), HashPart::Json(record)],
        32,
    )
}

pub fn da_light_client_checkpoint_payload_root(record: &Value) -> String {
    da_light_client_payload_root("DA-LIGHT-CHECKPOINT", record)
}

pub fn da_fraud_evidence_id(record: &Value) -> String {
    domain_hash(
        "DA-LIGHT-FRAUD-EVIDENCE-ID",
        &[HashPart::Str(CHAIN_ID), HashPart::Json(record)],
        32,
    )
}

pub fn da_fraud_evidence_payload_root(record: &Value) -> String {
    da_light_client_payload_root("DA-LIGHT-FRAUD-EVIDENCE", record)
}

pub fn da_equivocation_evidence_id(record: &Value) -> String {
    domain_hash(
        "DA-LIGHT-EQUIVOCATION-EVIDENCE-ID",
        &[HashPart::Str(CHAIN_ID), HashPart::Json(record)],
        32,
    )
}

pub fn da_equivocation_evidence_payload_root(record: &Value) -> String {
    da_light_client_payload_root("DA-LIGHT-EQUIVOCATION-EVIDENCE", record)
}

pub fn da_archival_provider_receipt_id(record: &Value) -> String {
    domain_hash(
        "DA-LIGHT-ARCHIVAL-RECEIPT-ID",
        &[HashPart::Str(CHAIN_ID), HashPart::Json(record)],
        32,
    )
}

pub fn da_archive_receipt_signature_root(
    receipt_id: &str,
    provider_public_key: &str,
    audit_sample_root: &str,
) -> String {
    domain_hash(
        "DA-LIGHT-ARCHIVAL-RECEIPT-SIGNATURE",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(receipt_id),
            HashPart::Str(provider_public_key),
            HashPart::Str(audit_sample_root),
            HashPart::Str(DA_LIGHT_CLIENT_PQ_SIGNATURE_SCHEME),
        ],
        32,
    )
}

pub fn da_archival_provider_receipt_payload_root(record: &Value) -> String {
    da_light_client_payload_root("DA-LIGHT-ARCHIVAL-RECEIPT", record)
}

pub fn da_blob_retention_attestation_id(record: &Value) -> String {
    domain_hash(
        "DA-LIGHT-BLOB-RETENTION-ATTESTATION-ID",
        &[HashPart::Str(CHAIN_ID), HashPart::Json(record)],
        32,
    )
}

pub fn da_blob_retention_attestation_payload_root(record: &Value) -> String {
    da_light_client_payload_root("DA-LIGHT-BLOB-RETENTION-ATTESTATION", record)
}

pub fn wallet_client_sampling_proof_id(record: &Value) -> String {
    domain_hash(
        "DA-LIGHT-WALLET-SAMPLING-PROOF-ID",
        &[HashPart::Str(CHAIN_ID), HashPart::Json(record)],
        32,
    )
}

pub fn wallet_client_sampling_proof_payload_root(record: &Value) -> String {
    da_light_client_payload_root("DA-LIGHT-WALLET-SAMPLING-PROOF", record)
}

pub fn low_fee_da_lane_id(record: &Value) -> String {
    domain_hash(
        "DA-LIGHT-LOW-FEE-LANE-ID",
        &[HashPart::Str(CHAIN_ID), HashPart::Json(record)],
        32,
    )
}

pub fn low_fee_da_lane_payload_root(record: &Value) -> String {
    da_light_client_payload_root("DA-LIGHT-LOW-FEE-LANE", record)
}

pub fn da_challenge_window_id(record: &Value) -> String {
    domain_hash(
        "DA-LIGHT-CHALLENGE-WINDOW-ID",
        &[HashPart::Str(CHAIN_ID), HashPart::Json(record)],
        32,
    )
}

pub fn da_challenge_window_payload_root(record: &Value) -> String {
    da_light_client_payload_root("DA-LIGHT-CHALLENGE-WINDOW", record)
}

pub fn da_operator_alert_id(record: &Value) -> String {
    domain_hash(
        "DA-LIGHT-OPERATOR-ALERT-ID",
        &[HashPart::Str(CHAIN_ID), HashPart::Json(record)],
        32,
    )
}

pub fn da_operator_alert_payload_root(record: &Value) -> String {
    da_light_client_payload_root("DA-LIGHT-OPERATOR-ALERT", record)
}

pub fn da_light_client_public_record_id(record: &Value) -> String {
    domain_hash(
        "DA-LIGHT-PUBLIC-RECORD-ID",
        &[HashPart::Str(CHAIN_ID), HashPart::Json(record)],
        32,
    )
}

pub fn da_light_client_public_record_payload_root(record: &Value) -> String {
    da_light_client_payload_root("DA-LIGHT-PUBLIC-RECORD", record)
}

pub fn da_light_client_state_root_from_record(record: &Value) -> String {
    da_light_client_payload_root("DA-LIGHT-CLIENT-STATE", record)
}

pub fn da_committee_header_root(values: &[DaCommitteeHeader]) -> String {
    let records = values
        .iter()
        .map(|value| (value.header_id.clone(), value.public_record()))
        .collect::<Vec<_>>();
    sorted_record_root("DA-LIGHT-COMMITTEE-HEADER", records)
}

pub fn da_erasure_commitment_root(values: &[DaErasureCommitment]) -> String {
    let records = values
        .iter()
        .map(|value| (value.commitment_id.clone(), value.public_record()))
        .collect::<Vec<_>>();
    sorted_record_root("DA-LIGHT-ERASURE-COMMITMENT", records)
}

pub fn da_sampling_proof_root(values: &[DaSamplingProof]) -> String {
    let records = values
        .iter()
        .map(|value| (value.proof_id.clone(), value.public_record()))
        .collect::<Vec<_>>();
    sorted_record_root("DA-LIGHT-SAMPLING-PROOF", records)
}

pub fn da_light_client_checkpoint_root(values: &[DaLightClientCheckpoint]) -> String {
    let records = values
        .iter()
        .map(|value| (value.checkpoint_id.clone(), value.public_record()))
        .collect::<Vec<_>>();
    sorted_record_root("DA-LIGHT-CHECKPOINT", records)
}

pub fn da_fraud_evidence_root(values: &[DaFraudEvidence]) -> String {
    let records = values
        .iter()
        .map(|value| (value.evidence_id.clone(), value.public_record()))
        .collect::<Vec<_>>();
    sorted_record_root("DA-LIGHT-FRAUD-EVIDENCE", records)
}

pub fn da_equivocation_evidence_root(values: &[DaEquivocationEvidence]) -> String {
    let records = values
        .iter()
        .map(|value| (value.evidence_id.clone(), value.public_record()))
        .collect::<Vec<_>>();
    sorted_record_root("DA-LIGHT-EQUIVOCATION-EVIDENCE", records)
}

pub fn da_archival_provider_receipt_root(values: &[DaArchivalProviderReceipt]) -> String {
    let records = values
        .iter()
        .map(|value| (value.receipt_id.clone(), value.public_record()))
        .collect::<Vec<_>>();
    sorted_record_root("DA-LIGHT-ARCHIVAL-RECEIPT", records)
}

pub fn da_blob_retention_attestation_root(values: &[DaBlobRetentionAttestation]) -> String {
    let records = values
        .iter()
        .map(|value| (value.attestation_id.clone(), value.public_record()))
        .collect::<Vec<_>>();
    sorted_record_root("DA-LIGHT-BLOB-RETENTION-ATTESTATION", records)
}

pub fn wallet_client_sampling_proof_root(values: &[WalletClientSamplingProof]) -> String {
    let records = values
        .iter()
        .map(|value| (value.proof_id.clone(), value.public_record()))
        .collect::<Vec<_>>();
    sorted_record_root("DA-LIGHT-WALLET-SAMPLING-PROOF", records)
}

pub fn low_fee_da_lane_root(values: &[LowFeeDaLane]) -> String {
    let records = values
        .iter()
        .map(|value| (value.lane_id.clone(), value.public_record()))
        .collect::<Vec<_>>();
    sorted_record_root("DA-LIGHT-LOW-FEE-LANE", records)
}

pub fn da_challenge_window_root(values: &[DaChallengeWindow]) -> String {
    let records = values
        .iter()
        .map(|value| (value.window_id.clone(), value.public_record()))
        .collect::<Vec<_>>();
    sorted_record_root("DA-LIGHT-CHALLENGE-WINDOW", records)
}

pub fn da_operator_alert_root(values: &[DaOperatorAlert]) -> String {
    let records = values
        .iter()
        .map(|value| (value.alert_id.clone(), value.public_record()))
        .collect::<Vec<_>>();
    sorted_record_root("DA-LIGHT-OPERATOR-ALERT", records)
}

pub fn da_light_client_public_record_root(values: &[DaLightClientPublicRecord]) -> String {
    let records = values
        .iter()
        .map(|value| (value.record_id.clone(), value.public_record()))
        .collect::<Vec<_>>();
    sorted_record_root("DA-LIGHT-PUBLIC-RECORD", records)
}

pub fn derive_da_sample_indices(
    seed: &str,
    shard_count: u64,
    sample_count: u64,
) -> DaLightClientResult<Vec<u64>> {
    ensure_non_empty(seed, "DA sample seed")?;
    if shard_count == 0 {
        return Err("cannot derive DA samples from zero shards".to_string());
    }
    if sample_count == 0 {
        return Err("DA sample count cannot be zero".to_string());
    }
    let target = std::cmp::min(sample_count, shard_count);
    let mut selected = BTreeSet::new();
    let mut nonce = 0_u64;
    while selected.len() < target as usize {
        let candidate_hash = domain_hash(
            "DA-LIGHT-SAMPLING-CANDIDATE",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(seed),
                HashPart::Int(nonce as i128),
            ],
            32,
        );
        selected.insert(hash_to_u64(&candidate_hash) % shard_count);
        nonce = nonce.saturating_add(1);
    }
    Ok(selected.into_iter().collect())
}

pub fn da_sample_index_root(indices: &[u64]) -> String {
    let values = indices
        .iter()
        .map(|index| json!({ "sample_index": index }))
        .collect::<Vec<_>>();
    merkle_root("DA-LIGHT-SAMPLE-INDEX", &values)
}

pub fn da_string_root(domain: &str, value: &str) -> String {
    domain_hash(domain, &[HashPart::Str(CHAIN_ID), HashPart::Str(value)], 32)
}

pub fn da_string_set_root(domain: &str, values: &[String]) -> String {
    let mut values = values
        .iter()
        .map(|value| (value.clone(), json!({ "value": value })))
        .collect::<Vec<_>>();
    values.sort_by(|left, right| left.0.cmp(&right.0));
    merkle_root(
        domain,
        &values
            .into_iter()
            .map(|(_, record)| record)
            .collect::<Vec<_>>(),
    )
}

pub fn devnet_hash(domain: &str, label: &str) -> String {
    domain_hash(domain, &[HashPart::Str(CHAIN_ID), HashPart::Str(label)], 32)
}

pub fn devnet_commitment(kind: &str, label: &str) -> String {
    domain_hash(
        "DA-LIGHT-DEVNET-COMMITMENT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(kind),
            HashPart::Str(label),
        ],
        32,
    )
}

fn sorted_record_root(domain: &str, mut records: Vec<(String, Value)>) -> String {
    records.sort_by(|left, right| left.0.cmp(&right.0));
    merkle_root(
        domain,
        &records
            .into_iter()
            .map(|(_, record)| record)
            .collect::<Vec<_>>(),
    )
}

fn with_root_field(mut record: Value, field: &str, root: String) -> Value {
    record
        .as_object_mut()
        .expect("DA light client root target record object")
        .insert(field.to_string(), Value::String(root));
    record
}

fn ensure_non_empty(value: &str, label: &str) -> DaLightClientResult<()> {
    if value.trim().is_empty() {
        return Err(format!("{label} cannot be empty"));
    }
    Ok(())
}

fn ensure_bps(value: u64, label: &str) -> DaLightClientResult<()> {
    if value > 10_000 {
        return Err(format!("{label} basis points exceed 100%"));
    }
    Ok(())
}

fn ensure_status(value: &str, allowed: &[&str], label: &str) -> DaLightClientResult<()> {
    if allowed.iter().any(|allowed| *allowed == value) {
        Ok(())
    } else {
        Err(format!("{label} is not supported"))
    }
}

fn ensure_unique_u64(values: &[u64], label: &str) -> DaLightClientResult<()> {
    let mut seen = BTreeSet::new();
    for value in values {
        if !seen.insert(*value) {
            return Err(format!("{label} must be unique"));
        }
    }
    Ok(())
}

fn ensure_subset_u64(values: &[u64], allowed: &[u64], label: &str) -> DaLightClientResult<()> {
    let allowed = allowed.iter().copied().collect::<BTreeSet<_>>();
    for value in values {
        if !allowed.contains(value) {
            return Err(format!("{label} is outside the allowed set"));
        }
    }
    Ok(())
}

fn ensure_disjoint_u64(left: &[u64], right: &[u64], label: &str) -> DaLightClientResult<()> {
    let left = left.iter().copied().collect::<BTreeSet<_>>();
    for value in right {
        if left.contains(value) {
            return Err(format!("{label} contains overlapping values"));
        }
    }
    Ok(())
}

fn insert_unique_record<T>(
    records: &mut BTreeMap<String, T>,
    id: String,
    record: T,
    label: &str,
) -> DaLightClientResult<()> {
    if records.contains_key(&id) {
        return Err(format!("{label} already exists"));
    }
    records.insert(id, record);
    Ok(())
}

fn quorum_reached(weight: u64, total_weight: u64, quorum_bps: u64) -> bool {
    if total_weight == 0 {
        return false;
    }
    (weight as u128) * 10_000_u128 >= (total_weight as u128) * (quorum_bps as u128)
}

fn hash_to_u64(hash: &str) -> u64 {
    let prefix = hash.get(0..16).unwrap_or(hash);
    u64::from_str_radix(prefix, 16).unwrap_or(0)
}
