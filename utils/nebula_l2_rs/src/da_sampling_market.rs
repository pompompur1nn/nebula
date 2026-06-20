use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type DaSamplingMarketResult<T> = Result<T, String>;

pub const DA_SAMPLING_MARKET_PROTOCOL_VERSION: u64 = 1;
pub const DA_SAMPLING_MARKET_PROTOCOL_ID: &str = "nebula-da-sampling-market-v1";
pub const DA_SAMPLING_MARKET_COMMITMENT_SCHEME: &str = "shake256-rs-fri-pq";
pub const DA_SAMPLING_MARKET_PQ_SIGNATURE_SCHEME: &str = "ML-DSA-65";
pub const DA_SAMPLING_MARKET_PQ_BACKUP_SCHEME: &str = "SLH-DSA-SHAKE-128s";
pub const DA_SAMPLING_MARKET_DEFAULT_FEE_ASSET_ID: &str = "dxmr";
pub const DA_SAMPLING_MARKET_DEFAULT_EPOCH_LENGTH_BLOCKS: u64 = 720;
pub const DA_SAMPLING_MARKET_DEFAULT_RETENTION_BLOCKS: u64 = 14_400;
pub const DA_SAMPLING_MARKET_DEFAULT_CHALLENGE_WINDOW_BLOCKS: u64 = 32;
pub const DA_SAMPLING_MARKET_DEFAULT_FINALITY_DELAY_BLOCKS: u64 = 8;
pub const DA_SAMPLING_MARKET_DEFAULT_SAMPLE_COUNT: u64 = 16;
pub const DA_SAMPLING_MARKET_MAX_SAMPLE_COUNT: u64 = 512;
pub const DA_SAMPLING_MARKET_DEFAULT_ORIGINAL_SHARDS: u64 = 16;
pub const DA_SAMPLING_MARKET_DEFAULT_PARITY_SHARDS: u64 = 16;
pub const DA_SAMPLING_MARKET_DEFAULT_SHARD_SIZE_BYTES: u64 = 1_024;
pub const DA_SAMPLING_MARKET_MAX_SHARDS_PER_BLOB: u64 = 16_384;
pub const DA_SAMPLING_MARKET_MAX_BLOB_BYTES: u64 = 4 * 1024 * 1024;
pub const DA_SAMPLING_MARKET_MIN_COMMITTEE_NODES: u64 = 4;
pub const DA_SAMPLING_MARKET_DEFAULT_COMMITTEE_QUORUM_BPS: u64 = 6_667;
pub const DA_SAMPLING_MARKET_DEFAULT_SAMPLING_QUORUM_BPS: u64 = 6_000;
pub const DA_SAMPLING_MARKET_DEFAULT_SLASH_BPS: u64 = 1_000;
pub const DA_SAMPLING_MARKET_WITHHELD_SHARD_SLASH_BPS: u64 = 2_500;
pub const DA_SAMPLING_MARKET_FALSE_EVIDENCE_SLASH_BPS: u64 = 500;
pub const DA_SAMPLING_MARKET_REPORTER_REWARD_BPS: u64 = 2_000;
pub const DA_SAMPLING_MARKET_SPONSOR_REFUND_BPS: u64 = 5_000;
pub const DA_SAMPLING_MARKET_DEFAULT_LOW_FEE_TARGET_MICROUNITS: u64 = 4;
pub const DA_SAMPLING_MARKET_DEFAULT_BASE_FEE_PER_ENCODED_BYTE: u64 = 1;
pub const DA_SAMPLING_MARKET_DEFAULT_SAMPLE_FEE_MICROUNITS: u64 = 2;
pub const DA_SAMPLING_MARKET_DEFAULT_RETENTION_FEE_QUANTUM_BLOCKS: u64 = 720;
pub const DA_SAMPLING_MARKET_DEFAULT_RETENTION_FEE_PER_BYTE_QUANTUM: u64 = 1;
pub const DA_SAMPLING_MARKET_DEFAULT_SPONSOR_REBATE_BPS: u64 = 7_500;
pub const DA_SAMPLING_MARKET_DEVNET_OPERATOR_ID: &str = "nebula-da-market-operator-devnet";
pub const DA_SAMPLING_MARKET_DEVNET_WATCHTOWER_ID: &str = "nebula-da-market-watchtower-devnet";
pub const DA_SAMPLING_MARKET_DEVNET_ARCHIVE_ID: &str = "nebula-da-market-archive-devnet";
pub const DA_SAMPLING_MARKET_DEVNET_LIGHT_CLIENT_ID: &str = "nebula-da-market-light-client-devnet";

pub const DA_SAMPLING_STATUS_ACTIVE: &str = "active";
pub const DA_SAMPLING_STATUS_PAUSED: &str = "paused";
pub const DA_SAMPLING_STATUS_PENDING: &str = "pending";
pub const DA_SAMPLING_STATUS_OPEN: &str = "open";
pub const DA_SAMPLING_STATUS_ACCEPTED: &str = "accepted";
pub const DA_SAMPLING_STATUS_ATTESTED: &str = "attested";
pub const DA_SAMPLING_STATUS_ANSWERED: &str = "answered";
pub const DA_SAMPLING_STATUS_PARTIAL: &str = "partial";
pub const DA_SAMPLING_STATUS_VERIFIED: &str = "verified";
pub const DA_SAMPLING_STATUS_FINALIZED: &str = "finalized";
pub const DA_SAMPLING_STATUS_SETTLED: &str = "settled";
pub const DA_SAMPLING_STATUS_WITHHELD: &str = "withheld";
pub const DA_SAMPLING_STATUS_CHALLENGED: &str = "challenged";
pub const DA_SAMPLING_STATUS_SLASHED: &str = "slashed";
pub const DA_SAMPLING_STATUS_SLASHED_OUT: &str = "slashed_out";
pub const DA_SAMPLING_STATUS_REJECTED: &str = "rejected";
pub const DA_SAMPLING_STATUS_EXPIRED: &str = "expired";
pub const DA_SAMPLING_STATUS_SPONSORED: &str = "sponsored";
pub const DA_SAMPLING_STATUS_EXHAUSTED: &str = "exhausted";
pub const DA_SAMPLING_STATUS_RETAINED: &str = "retained";
pub const DA_SAMPLING_STATUS_DISMISSED: &str = "dismissed";

const VALID_STATE_STATUSES: &[&str] = &[
    DA_SAMPLING_STATUS_ACTIVE,
    DA_SAMPLING_STATUS_PAUSED,
    DA_SAMPLING_STATUS_CHALLENGED,
];
const VALID_MARKET_RECORD_STATUSES: &[&str] = &[
    DA_SAMPLING_STATUS_ACTIVE,
    DA_SAMPLING_STATUS_PAUSED,
    DA_SAMPLING_STATUS_EXPIRED,
];
const VALID_BLOB_STATUSES: &[&str] = &[
    DA_SAMPLING_STATUS_PENDING,
    DA_SAMPLING_STATUS_ACCEPTED,
    DA_SAMPLING_STATUS_ATTESTED,
    DA_SAMPLING_STATUS_VERIFIED,
    DA_SAMPLING_STATUS_FINALIZED,
    DA_SAMPLING_STATUS_WITHHELD,
    DA_SAMPLING_STATUS_REJECTED,
    DA_SAMPLING_STATUS_EXPIRED,
];
const VALID_SHARD_STATUSES: &[&str] = &[
    DA_SAMPLING_STATUS_PENDING,
    DA_SAMPLING_STATUS_ACCEPTED,
    DA_SAMPLING_STATUS_RETAINED,
    DA_SAMPLING_STATUS_WITHHELD,
    DA_SAMPLING_STATUS_SLASHED,
    DA_SAMPLING_STATUS_EXPIRED,
];
const VALID_NODE_STATUSES: &[&str] = &[
    DA_SAMPLING_STATUS_ACTIVE,
    DA_SAMPLING_STATUS_PAUSED,
    DA_SAMPLING_STATUS_SLASHED,
    DA_SAMPLING_STATUS_SLASHED_OUT,
    DA_SAMPLING_STATUS_EXPIRED,
];
const VALID_ATTESTATION_STATUSES: &[&str] = &[
    DA_SAMPLING_STATUS_ATTESTED,
    DA_SAMPLING_STATUS_ACCEPTED,
    DA_SAMPLING_STATUS_REJECTED,
    DA_SAMPLING_STATUS_CHALLENGED,
    DA_SAMPLING_STATUS_SLASHED,
];
const VALID_REQUEST_STATUSES: &[&str] = &[
    DA_SAMPLING_STATUS_OPEN,
    DA_SAMPLING_STATUS_ANSWERED,
    DA_SAMPLING_STATUS_PARTIAL,
    DA_SAMPLING_STATUS_EXPIRED,
    DA_SAMPLING_STATUS_REJECTED,
];
const VALID_RECEIPT_STATUSES: &[&str] = &[
    DA_SAMPLING_STATUS_ANSWERED,
    DA_SAMPLING_STATUS_PARTIAL,
    DA_SAMPLING_STATUS_VERIFIED,
    DA_SAMPLING_STATUS_REJECTED,
    DA_SAMPLING_STATUS_EXPIRED,
];
const VALID_SPONSORSHIP_STATUSES: &[&str] = &[
    DA_SAMPLING_STATUS_ACTIVE,
    DA_SAMPLING_STATUS_SPONSORED,
    DA_SAMPLING_STATUS_EXHAUSTED,
    DA_SAMPLING_STATUS_EXPIRED,
    DA_SAMPLING_STATUS_PAUSED,
];
const VALID_EVIDENCE_STATUSES: &[&str] = &[
    DA_SAMPLING_STATUS_OPEN,
    DA_SAMPLING_STATUS_VERIFIED,
    DA_SAMPLING_STATUS_SETTLED,
    DA_SAMPLING_STATUS_DISMISSED,
    DA_SAMPLING_STATUS_REJECTED,
];
const VALID_SETTLEMENT_STATUSES: &[&str] = &[
    DA_SAMPLING_STATUS_PENDING,
    DA_SAMPLING_STATUS_SETTLED,
    DA_SAMPLING_STATUS_REJECTED,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DaBlobClass {
    PrivateTransfer,
    MoneroBridge,
    TokenTransfer,
    DefiSwap,
    Lending,
    ContractCall,
    RollupStateDiff,
    ProofBundle,
    Governance,
    ArchiveReplay,
    Emergency,
}

impl DaBlobClass {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::PrivateTransfer => "private_transfer",
            Self::MoneroBridge => "monero_bridge",
            Self::TokenTransfer => "token_transfer",
            Self::DefiSwap => "defi_swap",
            Self::Lending => "lending",
            Self::ContractCall => "contract_call",
            Self::RollupStateDiff => "rollup_state_diff",
            Self::ProofBundle => "proof_bundle",
            Self::Governance => "governance",
            Self::ArchiveReplay => "archive_replay",
            Self::Emergency => "emergency",
        }
    }

    pub fn default_lane_key(&self) -> &'static str {
        match self {
            Self::PrivateTransfer => "private_transfer_da",
            Self::MoneroBridge => "monero_bridge_da",
            Self::TokenTransfer => "token_transfer_da",
            Self::DefiSwap => "defi_swap_da",
            Self::Lending => "lending_da",
            Self::ContractCall => "contract_call_da",
            Self::RollupStateDiff => "rollup_state_diff_da",
            Self::ProofBundle => "proof_bundle_da",
            Self::Governance => "governance_da",
            Self::ArchiveReplay => "archive_replay_da",
            Self::Emergency => "emergency_da",
        }
    }

    pub fn default_priority(&self) -> u64 {
        match self {
            Self::Emergency => 0,
            Self::MoneroBridge => 2,
            Self::PrivateTransfer => 3,
            Self::RollupStateDiff => 4,
            Self::ContractCall | Self::DefiSwap | Self::Lending => 5,
            Self::TokenTransfer => 6,
            Self::ProofBundle => 7,
            Self::Governance => 8,
            Self::ArchiveReplay => 9,
        }
    }

    pub fn default_retention_blocks(&self) -> u64 {
        match self {
            Self::Emergency => DA_SAMPLING_MARKET_DEFAULT_RETENTION_BLOCKS * 4,
            Self::MoneroBridge | Self::Governance => {
                DA_SAMPLING_MARKET_DEFAULT_RETENTION_BLOCKS * 3
            }
            Self::ArchiveReplay | Self::RollupStateDiff => {
                DA_SAMPLING_MARKET_DEFAULT_RETENTION_BLOCKS * 2
            }
            Self::ProofBundle => DA_SAMPLING_MARKET_DEFAULT_RETENTION_BLOCKS,
            Self::PrivateTransfer
            | Self::TokenTransfer
            | Self::DefiSwap
            | Self::Lending
            | Self::ContractCall => DA_SAMPLING_MARKET_DEFAULT_RETENTION_BLOCKS,
        }
    }

    pub fn default_sample_count(&self) -> u64 {
        match self {
            Self::Emergency | Self::MoneroBridge => 32,
            Self::RollupStateDiff | Self::Governance => 24,
            Self::PrivateTransfer | Self::ContractCall | Self::ProofBundle => 16,
            Self::TokenTransfer | Self::DefiSwap | Self::Lending | Self::ArchiveReplay => 12,
        }
    }

    pub fn privacy_preserving_by_default(&self) -> bool {
        matches!(
            self,
            Self::PrivateTransfer | Self::MoneroBridge | Self::DefiSwap | Self::Lending
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DaPrivacyMode {
    Public,
    MetadataOnly,
    CommitmentOnly,
    ThresholdEncrypted,
    FullyPrivate,
}

impl DaPrivacyMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::MetadataOnly => "metadata_only",
            Self::CommitmentOnly => "commitment_only",
            Self::ThresholdEncrypted => "threshold_encrypted",
            Self::FullyPrivate => "fully_private",
        }
    }

    pub fn hides_payload(&self) -> bool {
        !matches!(self, Self::Public | Self::MetadataOnly)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DaErasureCodec {
    ReedSolomon,
    CauchyReedSolomon,
    RaptorQ,
    ShakeFri,
    HybridRsFri,
}

impl DaErasureCodec {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ReedSolomon => "reed_solomon",
            Self::CauchyReedSolomon => "cauchy_reed_solomon",
            Self::RaptorQ => "raptor_q",
            Self::ShakeFri => "shake_fri",
            Self::HybridRsFri => "hybrid_rs_fri",
        }
    }

    pub fn commitment_scheme(&self) -> &'static str {
        match self {
            Self::ReedSolomon => "rs-merkle-shake256",
            Self::CauchyReedSolomon => "cauchy-rs-merkle-shake256",
            Self::RaptorQ => "raptorq-merkle-shake256",
            Self::ShakeFri => "fri-shake256",
            Self::HybridRsFri => DA_SAMPLING_MARKET_COMMITMENT_SCHEME,
        }
    }

    pub fn is_quantum_resistant(&self) -> bool {
        true
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DaCommitteeRole {
    Encoder,
    Sampler,
    Attester,
    ArchiveProvider,
    Watchtower,
    Sponsor,
    LightClient,
}

impl DaCommitteeRole {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Encoder => "encoder",
            Self::Sampler => "sampler",
            Self::Attester => "attester",
            Self::ArchiveProvider => "archive_provider",
            Self::Watchtower => "watchtower",
            Self::Sponsor => "sponsor",
            Self::LightClient => "light_client",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WithheldShardEvidenceKind {
    MissingSample,
    InvalidShardOpening,
    MismatchedCommitment,
    ExpiredRetention,
    EquivocatedReceipt,
}

impl WithheldShardEvidenceKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::MissingSample => "missing_sample",
            Self::InvalidShardOpening => "invalid_shard_opening",
            Self::MismatchedCommitment => "mismatched_commitment",
            Self::ExpiredRetention => "expired_retention",
            Self::EquivocatedReceipt => "equivocated_receipt",
        }
    }

    pub fn default_severity_bps(&self) -> u64 {
        match self {
            Self::MissingSample => DA_SAMPLING_MARKET_WITHHELD_SHARD_SLASH_BPS,
            Self::InvalidShardOpening | Self::MismatchedCommitment => 4_000,
            Self::ExpiredRetention => 1_500,
            Self::EquivocatedReceipt => 5_000,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DaSamplingMarketConfig {
    pub protocol_version: u64,
    pub protocol_id: String,
    pub default_fee_asset_id: String,
    pub epoch_length_blocks: u64,
    pub default_retention_blocks: u64,
    pub challenge_window_blocks: u64,
    pub finality_delay_blocks: u64,
    pub default_sample_count: u64,
    pub max_sample_count: u64,
    pub default_original_shards: u64,
    pub default_parity_shards: u64,
    pub default_shard_size_bytes: u64,
    pub max_shards_per_blob: u64,
    pub max_blob_bytes: u64,
    pub min_committee_nodes: u64,
    pub committee_quorum_bps: u64,
    pub sampling_quorum_bps: u64,
    pub default_slash_bps: u64,
    pub withheld_shard_slash_bps: u64,
    pub false_evidence_slash_bps: u64,
    pub reporter_reward_bps: u64,
    pub sponsor_refund_bps: u64,
    pub low_fee_target_microunits: u64,
    pub base_fee_per_encoded_byte: u64,
    pub sample_fee_microunits: u64,
    pub retention_fee_quantum_blocks: u64,
    pub retention_fee_per_byte_quantum: u64,
    pub sponsor_rebate_bps: u64,
    pub commitment_scheme: String,
    pub pq_signature_scheme: String,
    pub pq_backup_scheme: String,
}

impl Default for DaSamplingMarketConfig {
    fn default() -> Self {
        Self {
            protocol_version: DA_SAMPLING_MARKET_PROTOCOL_VERSION,
            protocol_id: DA_SAMPLING_MARKET_PROTOCOL_ID.to_string(),
            default_fee_asset_id: DA_SAMPLING_MARKET_DEFAULT_FEE_ASSET_ID.to_string(),
            epoch_length_blocks: DA_SAMPLING_MARKET_DEFAULT_EPOCH_LENGTH_BLOCKS,
            default_retention_blocks: DA_SAMPLING_MARKET_DEFAULT_RETENTION_BLOCKS,
            challenge_window_blocks: DA_SAMPLING_MARKET_DEFAULT_CHALLENGE_WINDOW_BLOCKS,
            finality_delay_blocks: DA_SAMPLING_MARKET_DEFAULT_FINALITY_DELAY_BLOCKS,
            default_sample_count: DA_SAMPLING_MARKET_DEFAULT_SAMPLE_COUNT,
            max_sample_count: DA_SAMPLING_MARKET_MAX_SAMPLE_COUNT,
            default_original_shards: DA_SAMPLING_MARKET_DEFAULT_ORIGINAL_SHARDS,
            default_parity_shards: DA_SAMPLING_MARKET_DEFAULT_PARITY_SHARDS,
            default_shard_size_bytes: DA_SAMPLING_MARKET_DEFAULT_SHARD_SIZE_BYTES,
            max_shards_per_blob: DA_SAMPLING_MARKET_MAX_SHARDS_PER_BLOB,
            max_blob_bytes: DA_SAMPLING_MARKET_MAX_BLOB_BYTES,
            min_committee_nodes: DA_SAMPLING_MARKET_MIN_COMMITTEE_NODES,
            committee_quorum_bps: DA_SAMPLING_MARKET_DEFAULT_COMMITTEE_QUORUM_BPS,
            sampling_quorum_bps: DA_SAMPLING_MARKET_DEFAULT_SAMPLING_QUORUM_BPS,
            default_slash_bps: DA_SAMPLING_MARKET_DEFAULT_SLASH_BPS,
            withheld_shard_slash_bps: DA_SAMPLING_MARKET_WITHHELD_SHARD_SLASH_BPS,
            false_evidence_slash_bps: DA_SAMPLING_MARKET_FALSE_EVIDENCE_SLASH_BPS,
            reporter_reward_bps: DA_SAMPLING_MARKET_REPORTER_REWARD_BPS,
            sponsor_refund_bps: DA_SAMPLING_MARKET_SPONSOR_REFUND_BPS,
            low_fee_target_microunits: DA_SAMPLING_MARKET_DEFAULT_LOW_FEE_TARGET_MICROUNITS,
            base_fee_per_encoded_byte: DA_SAMPLING_MARKET_DEFAULT_BASE_FEE_PER_ENCODED_BYTE,
            sample_fee_microunits: DA_SAMPLING_MARKET_DEFAULT_SAMPLE_FEE_MICROUNITS,
            retention_fee_quantum_blocks: DA_SAMPLING_MARKET_DEFAULT_RETENTION_FEE_QUANTUM_BLOCKS,
            retention_fee_per_byte_quantum:
                DA_SAMPLING_MARKET_DEFAULT_RETENTION_FEE_PER_BYTE_QUANTUM,
            sponsor_rebate_bps: DA_SAMPLING_MARKET_DEFAULT_SPONSOR_REBATE_BPS,
            commitment_scheme: DA_SAMPLING_MARKET_COMMITMENT_SCHEME.to_string(),
            pq_signature_scheme: DA_SAMPLING_MARKET_PQ_SIGNATURE_SCHEME.to_string(),
            pq_backup_scheme: DA_SAMPLING_MARKET_PQ_BACKUP_SCHEME.to_string(),
        }
    }
}

impl DaSamplingMarketConfig {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "da_sampling_market_config",
            "chain_id": CHAIN_ID,
            "protocol_version": self.protocol_version,
            "protocol_id": self.protocol_id,
            "default_fee_asset_id": self.default_fee_asset_id,
            "epoch_length_blocks": self.epoch_length_blocks,
            "default_retention_blocks": self.default_retention_blocks,
            "challenge_window_blocks": self.challenge_window_blocks,
            "finality_delay_blocks": self.finality_delay_blocks,
            "default_sample_count": self.default_sample_count,
            "max_sample_count": self.max_sample_count,
            "default_original_shards": self.default_original_shards,
            "default_parity_shards": self.default_parity_shards,
            "default_shard_size_bytes": self.default_shard_size_bytes,
            "max_shards_per_blob": self.max_shards_per_blob,
            "max_blob_bytes": self.max_blob_bytes,
            "min_committee_nodes": self.min_committee_nodes,
            "committee_quorum_bps": self.committee_quorum_bps,
            "sampling_quorum_bps": self.sampling_quorum_bps,
            "default_slash_bps": self.default_slash_bps,
            "withheld_shard_slash_bps": self.withheld_shard_slash_bps,
            "false_evidence_slash_bps": self.false_evidence_slash_bps,
            "reporter_reward_bps": self.reporter_reward_bps,
            "sponsor_refund_bps": self.sponsor_refund_bps,
            "low_fee_target_microunits": self.low_fee_target_microunits,
            "base_fee_per_encoded_byte": self.base_fee_per_encoded_byte,
            "sample_fee_microunits": self.sample_fee_microunits,
            "retention_fee_quantum_blocks": self.retention_fee_quantum_blocks,
            "retention_fee_per_byte_quantum": self.retention_fee_per_byte_quantum,
            "sponsor_rebate_bps": self.sponsor_rebate_bps,
            "commitment_scheme": self.commitment_scheme,
            "pq_signature_scheme": self.pq_signature_scheme,
            "pq_backup_scheme": self.pq_backup_scheme,
        })
    }

    pub fn config_root(&self) -> String {
        da_sampling_market_payload_root("DA-SAMPLING-MARKET-CONFIG", &self.public_record())
    }

    pub fn validate(&self) -> DaSamplingMarketResult<String> {
        ensure_non_empty(&self.protocol_id, "DA sampling market protocol id")?;
        ensure_non_empty(
            &self.default_fee_asset_id,
            "DA sampling market default fee asset id",
        )?;
        ensure_non_empty(
            &self.commitment_scheme,
            "DA sampling market commitment scheme",
        )?;
        ensure_non_empty(
            &self.pq_signature_scheme,
            "DA sampling market signature scheme",
        )?;
        ensure_non_empty(
            &self.pq_backup_scheme,
            "DA sampling market backup signature scheme",
        )?;
        if self.protocol_version != DA_SAMPLING_MARKET_PROTOCOL_VERSION {
            return Err("DA sampling market protocol version mismatch".to_string());
        }
        if self.epoch_length_blocks == 0 {
            return Err("DA sampling market epoch length cannot be zero".to_string());
        }
        if self.default_retention_blocks <= self.challenge_window_blocks {
            return Err("DA sampling market retention must exceed challenge window".to_string());
        }
        if self.default_sample_count == 0 || self.default_sample_count > self.max_sample_count {
            return Err("DA sampling market default sample count is invalid".to_string());
        }
        if self.default_original_shards == 0 || self.default_parity_shards == 0 {
            return Err("DA sampling market shard counts cannot be zero".to_string());
        }
        if self.default_original_shards + self.default_parity_shards > self.max_shards_per_blob {
            return Err("DA sampling market default shard counts exceed max shards".to_string());
        }
        if self.default_shard_size_bytes == 0 {
            return Err("DA sampling market shard size cannot be zero".to_string());
        }
        if self.max_blob_bytes == 0 {
            return Err("DA sampling market max blob bytes cannot be zero".to_string());
        }
        ensure_bps(self.committee_quorum_bps, "committee quorum")?;
        ensure_bps(self.sampling_quorum_bps, "sampling quorum")?;
        ensure_bps(self.default_slash_bps, "default slash")?;
        ensure_bps(self.withheld_shard_slash_bps, "withheld shard slash")?;
        ensure_bps(self.false_evidence_slash_bps, "false evidence slash")?;
        ensure_bps(self.reporter_reward_bps, "reporter reward")?;
        ensure_bps(self.sponsor_refund_bps, "sponsor refund")?;
        ensure_bps(self.sponsor_rebate_bps, "sponsor rebate")?;
        if self.retention_fee_quantum_blocks == 0 {
            return Err("DA sampling market retention fee quantum cannot be zero".to_string());
        }
        Ok(self.config_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DaSamplingMarketRoots {
    pub config_root: String,
    pub pricing_model_root: String,
    pub blob_manifest_root: String,
    pub shard_commitment_root: String,
    pub committee_node_root: String,
    pub committee_attestation_root: String,
    pub sample_request_root: String,
    pub sample_receipt_root: String,
    pub sponsorship_root: String,
    pub withheld_evidence_root: String,
    pub redundancy_epoch_root: String,
    pub sampling_window_root: String,
    pub pricing_quote_root: String,
    pub slashing_settlement_root: String,
    pub public_record_root: String,
}

impl DaSamplingMarketRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "da_sampling_market_roots",
            "chain_id": CHAIN_ID,
            "protocol_version": DA_SAMPLING_MARKET_PROTOCOL_VERSION,
            "config_root": self.config_root,
            "pricing_model_root": self.pricing_model_root,
            "blob_manifest_root": self.blob_manifest_root,
            "shard_commitment_root": self.shard_commitment_root,
            "committee_node_root": self.committee_node_root,
            "committee_attestation_root": self.committee_attestation_root,
            "sample_request_root": self.sample_request_root,
            "sample_receipt_root": self.sample_receipt_root,
            "sponsorship_root": self.sponsorship_root,
            "withheld_evidence_root": self.withheld_evidence_root,
            "redundancy_epoch_root": self.redundancy_epoch_root,
            "sampling_window_root": self.sampling_window_root,
            "pricing_quote_root": self.pricing_quote_root,
            "slashing_settlement_root": self.slashing_settlement_root,
            "public_record_root": self.public_record_root,
        })
    }

    pub fn roots_root(&self) -> String {
        da_sampling_market_payload_root("DA-SAMPLING-MARKET-ROOTS", &self.public_record())
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DaSamplingMarketCounters {
    pub pricing_model_count: u64,
    pub blob_manifest_count: u64,
    pub shard_commitment_count: u64,
    pub committee_node_count: u64,
    pub committee_attestation_count: u64,
    pub sample_request_count: u64,
    pub sample_receipt_count: u64,
    pub sponsorship_count: u64,
    pub withheld_evidence_count: u64,
    pub redundancy_epoch_count: u64,
    pub sampling_window_count: u64,
    pub pricing_quote_count: u64,
    pub slashing_settlement_count: u64,
    pub public_record_count: u64,
    pub total_payload_bytes: u64,
    pub total_encoded_bytes: u64,
    pub total_sampled_shards: u64,
    pub total_missing_shards: u64,
    pub total_gross_fee_microunits: u64,
    pub total_net_fee_microunits: u64,
    pub total_sponsored_microunits: u64,
    pub total_slashed_units: u64,
}

impl DaSamplingMarketCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "da_sampling_market_counters",
            "chain_id": CHAIN_ID,
            "protocol_version": DA_SAMPLING_MARKET_PROTOCOL_VERSION,
            "pricing_model_count": self.pricing_model_count,
            "blob_manifest_count": self.blob_manifest_count,
            "shard_commitment_count": self.shard_commitment_count,
            "committee_node_count": self.committee_node_count,
            "committee_attestation_count": self.committee_attestation_count,
            "sample_request_count": self.sample_request_count,
            "sample_receipt_count": self.sample_receipt_count,
            "sponsorship_count": self.sponsorship_count,
            "withheld_evidence_count": self.withheld_evidence_count,
            "redundancy_epoch_count": self.redundancy_epoch_count,
            "sampling_window_count": self.sampling_window_count,
            "pricing_quote_count": self.pricing_quote_count,
            "slashing_settlement_count": self.slashing_settlement_count,
            "public_record_count": self.public_record_count,
            "total_payload_bytes": self.total_payload_bytes,
            "total_encoded_bytes": self.total_encoded_bytes,
            "total_sampled_shards": self.total_sampled_shards,
            "total_missing_shards": self.total_missing_shards,
            "total_gross_fee_microunits": self.total_gross_fee_microunits,
            "total_net_fee_microunits": self.total_net_fee_microunits,
            "total_sponsored_microunits": self.total_sponsored_microunits,
            "total_slashed_units": self.total_slashed_units,
        })
    }

    pub fn counters_root(&self) -> String {
        da_sampling_market_payload_root("DA-SAMPLING-MARKET-COUNTERS", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeDaPricingModel {
    pub pricing_model_id: String,
    pub lane_key: String,
    pub blob_class: DaBlobClass,
    pub fee_asset_id: String,
    pub priority: u64,
    pub base_fee_per_encoded_byte: u64,
    pub sample_fee_microunits: u64,
    pub retention_fee_per_byte_quantum: u64,
    pub retention_fee_quantum_blocks: u64,
    pub floor_fee_microunits: u64,
    pub target_fee_microunits: u64,
    pub target_bytes_per_block: u64,
    pub max_blob_bytes: u64,
    pub max_sample_count: u64,
    pub sponsor_rebate_bps: u64,
    pub congestion_multiplier_bps: u64,
    pub privacy_discount_bps: u64,
    pub status: String,
}

impl LowFeeDaPricingModel {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        lane_key: impl Into<String>,
        blob_class: DaBlobClass,
        fee_asset_id: impl Into<String>,
        priority: u64,
        base_fee_per_encoded_byte: u64,
        sample_fee_microunits: u64,
        retention_fee_per_byte_quantum: u64,
        retention_fee_quantum_blocks: u64,
        floor_fee_microunits: u64,
        target_fee_microunits: u64,
        target_bytes_per_block: u64,
        max_blob_bytes: u64,
        max_sample_count: u64,
        sponsor_rebate_bps: u64,
        congestion_multiplier_bps: u64,
        privacy_discount_bps: u64,
    ) -> DaSamplingMarketResult<Self> {
        let lane_key = lane_key.into();
        let fee_asset_id = fee_asset_id.into();
        let pricing_model_id = da_pricing_model_id(&lane_key, blob_class, &fee_asset_id);
        let model = Self {
            pricing_model_id,
            lane_key,
            blob_class,
            fee_asset_id,
            priority,
            base_fee_per_encoded_byte,
            sample_fee_microunits,
            retention_fee_per_byte_quantum,
            retention_fee_quantum_blocks,
            floor_fee_microunits,
            target_fee_microunits,
            target_bytes_per_block,
            max_blob_bytes,
            max_sample_count,
            sponsor_rebate_bps,
            congestion_multiplier_bps,
            privacy_discount_bps,
            status: DA_SAMPLING_STATUS_ACTIVE.to_string(),
        };
        model.validate()?;
        Ok(model)
    }

    pub fn devnet(blob_class: DaBlobClass, fee_asset_id: &str) -> Self {
        let class_weight = blob_class.default_priority().saturating_add(1);
        Self::new(
            blob_class.default_lane_key(),
            blob_class,
            fee_asset_id,
            blob_class.default_priority(),
            DA_SAMPLING_MARKET_DEFAULT_BASE_FEE_PER_ENCODED_BYTE,
            DA_SAMPLING_MARKET_DEFAULT_SAMPLE_FEE_MICROUNITS.saturating_add(class_weight / 3),
            DA_SAMPLING_MARKET_DEFAULT_RETENTION_FEE_PER_BYTE_QUANTUM,
            DA_SAMPLING_MARKET_DEFAULT_RETENTION_FEE_QUANTUM_BLOCKS,
            DA_SAMPLING_MARKET_DEFAULT_LOW_FEE_TARGET_MICROUNITS,
            DA_SAMPLING_MARKET_DEFAULT_LOW_FEE_TARGET_MICROUNITS,
            256 * 1024,
            DA_SAMPLING_MARKET_MAX_BLOB_BYTES,
            blob_class.default_sample_count(),
            DA_SAMPLING_MARKET_DEFAULT_SPONSOR_REBATE_BPS,
            10_000,
            if blob_class.privacy_preserving_by_default() {
                1_000
            } else {
                0
            },
        )
        .expect("deterministic devnet DA pricing model")
    }

    pub fn quote(
        &self,
        payload_bytes: u64,
        encoded_bytes: u64,
        sample_count: u64,
        retention_blocks: u64,
        payer_commitment: &str,
        current_height: u64,
        ttl_blocks: u64,
    ) -> DaSamplingMarketResult<DaPricingQuote> {
        DaPricingQuote::from_model(
            self,
            payload_bytes,
            encoded_bytes,
            sample_count,
            retention_blocks,
            payer_commitment,
            current_height,
            ttl_blocks,
        )
    }

    pub fn raw_fee_microunits(
        &self,
        encoded_bytes: u64,
        sample_count: u64,
        retention_blocks: u64,
    ) -> u64 {
        let encoded_fee = saturating_mul(encoded_bytes, self.base_fee_per_encoded_byte);
        let sample_fee = saturating_mul(sample_count, self.sample_fee_microunits);
        let retention_quanta = retention_blocks.div_ceil(self.retention_fee_quantum_blocks);
        let retention_fee = saturating_mul(
            saturating_mul(encoded_bytes, self.retention_fee_per_byte_quantum),
            retention_quanta,
        );
        let gross = encoded_fee
            .saturating_add(sample_fee)
            .saturating_add(retention_fee);
        let adjusted = mul_div_ceil(gross, self.congestion_multiplier_bps, 10_000);
        std::cmp::max(adjusted, self.floor_fee_microunits)
    }

    pub fn sponsored_fee_microunits(&self, gross_fee: u64, privacy_mode: DaPrivacyMode) -> u64 {
        let rebate_bps = if privacy_mode.hides_payload() {
            self.sponsor_rebate_bps
                .saturating_add(self.privacy_discount_bps)
                .min(10_000)
        } else {
            self.sponsor_rebate_bps
        };
        mul_div_floor(gross_fee, rebate_bps, 10_000)
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "low_fee_da_pricing_model",
            "chain_id": CHAIN_ID,
            "protocol_version": DA_SAMPLING_MARKET_PROTOCOL_VERSION,
            "pricing_model_id": self.pricing_model_id,
            "lane_key": self.lane_key,
            "blob_class": self.blob_class.as_str(),
            "fee_asset_id": self.fee_asset_id,
            "priority": self.priority,
            "base_fee_per_encoded_byte": self.base_fee_per_encoded_byte,
            "sample_fee_microunits": self.sample_fee_microunits,
            "retention_fee_per_byte_quantum": self.retention_fee_per_byte_quantum,
            "retention_fee_quantum_blocks": self.retention_fee_quantum_blocks,
            "floor_fee_microunits": self.floor_fee_microunits,
            "target_fee_microunits": self.target_fee_microunits,
            "target_bytes_per_block": self.target_bytes_per_block,
            "max_blob_bytes": self.max_blob_bytes,
            "max_sample_count": self.max_sample_count,
            "sponsor_rebate_bps": self.sponsor_rebate_bps,
            "congestion_multiplier_bps": self.congestion_multiplier_bps,
            "privacy_discount_bps": self.privacy_discount_bps,
            "status": self.status,
        })
    }

    pub fn pricing_model_root(&self) -> String {
        da_sampling_market_payload_root(
            "DA-SAMPLING-MARKET-PRICING-MODEL",
            &self.public_record_without_root(),
        )
    }

    pub fn public_record(&self) -> Value {
        with_root_field(
            self.public_record_without_root(),
            "pricing_model_root",
            self.pricing_model_root(),
        )
    }

    pub fn validate(&self) -> DaSamplingMarketResult<String> {
        ensure_non_empty(&self.lane_key, "DA pricing model lane key")?;
        ensure_non_empty(&self.fee_asset_id, "DA pricing model fee asset id")?;
        if self.max_blob_bytes == 0 {
            return Err("DA pricing model max blob bytes cannot be zero".to_string());
        }
        if self.max_sample_count == 0 {
            return Err("DA pricing model max sample count cannot be zero".to_string());
        }
        if self.retention_fee_quantum_blocks == 0 {
            return Err("DA pricing model retention quantum cannot be zero".to_string());
        }
        ensure_bps(self.sponsor_rebate_bps, "DA pricing model sponsor rebate")?;
        ensure_bps(
            self.congestion_multiplier_bps,
            "DA pricing model congestion multiplier",
        )?;
        ensure_bps(
            self.privacy_discount_bps,
            "DA pricing model privacy discount",
        )?;
        ensure_status(
            &self.status,
            VALID_MARKET_RECORD_STATUSES,
            "DA pricing model status",
        )?;
        if self.pricing_model_id
            != da_pricing_model_id(&self.lane_key, self.blob_class, &self.fee_asset_id)
        {
            return Err("DA pricing model id mismatch".to_string());
        }
        Ok(self.pricing_model_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DaBlobManifest {
    pub blob_id: String,
    pub rollup_batch_id: String,
    pub sequencer_id: String,
    pub lane_key: String,
    pub blob_class: DaBlobClass,
    pub privacy_mode: DaPrivacyMode,
    pub payload_hash: String,
    pub payload_bytes: u64,
    pub metadata_root: String,
    pub encryption_key_commitment: String,
    pub codec: DaErasureCodec,
    pub original_shards: u64,
    pub parity_shards: u64,
    pub shard_size_bytes: u64,
    pub encoded_bytes: u64,
    pub shard_commitment_root: String,
    pub sponsorship_id: String,
    pub pricing_quote_id: String,
    pub posted_at_height: u64,
    pub challenge_window_end: u64,
    pub retention_until_height: u64,
    pub sample_seed: String,
    pub status: String,
}

impl DaBlobManifest {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        rollup_batch_id: impl Into<String>,
        sequencer_id: impl Into<String>,
        lane_key: impl Into<String>,
        blob_class: DaBlobClass,
        privacy_mode: DaPrivacyMode,
        payload_hash: impl Into<String>,
        payload_bytes: u64,
        metadata_root: impl Into<String>,
        encryption_key_commitment: impl Into<String>,
        codec: DaErasureCodec,
        original_shards: u64,
        parity_shards: u64,
        shard_size_bytes: u64,
        shard_commitment_root: impl Into<String>,
        sponsorship_id: impl Into<String>,
        pricing_quote_id: impl Into<String>,
        posted_at_height: u64,
        challenge_window_end: u64,
        retention_until_height: u64,
    ) -> DaSamplingMarketResult<Self> {
        let rollup_batch_id = rollup_batch_id.into();
        let sequencer_id = sequencer_id.into();
        let lane_key = lane_key.into();
        let payload_hash = payload_hash.into();
        let metadata_root = metadata_root.into();
        let encryption_key_commitment = encryption_key_commitment.into();
        let encoded_bytes = encoded_blob_size(payload_bytes, original_shards, parity_shards);
        let sample_seed = da_blob_sample_seed(
            &rollup_batch_id,
            &sequencer_id,
            &payload_hash,
            posted_at_height,
        );
        let blob_id = da_blob_manifest_id(
            &rollup_batch_id,
            &sequencer_id,
            &lane_key,
            blob_class,
            &payload_hash,
            payload_bytes,
            posted_at_height,
        );
        let blob = Self {
            blob_id,
            rollup_batch_id,
            sequencer_id,
            lane_key,
            blob_class,
            privacy_mode,
            payload_hash,
            payload_bytes,
            metadata_root,
            encryption_key_commitment,
            codec,
            original_shards,
            parity_shards,
            shard_size_bytes,
            encoded_bytes,
            shard_commitment_root: shard_commitment_root.into(),
            sponsorship_id: sponsorship_id.into(),
            pricing_quote_id: pricing_quote_id.into(),
            posted_at_height,
            challenge_window_end,
            retention_until_height,
            sample_seed,
            status: DA_SAMPLING_STATUS_PENDING.to_string(),
        };
        blob.validate()?;
        Ok(blob)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn devnet(
        label: &str,
        lane_key: &str,
        blob_class: DaBlobClass,
        privacy_mode: DaPrivacyMode,
        payload_bytes: u64,
        posted_at_height: u64,
        shard_commitment_root: &str,
        sponsorship_id: &str,
        pricing_quote_id: &str,
    ) -> Self {
        let payload_hash = devnet_hash("DA-SAMPLING-MARKET-DEVNET-BLOB-PAYLOAD", label);
        let metadata_root = devnet_hash("DA-SAMPLING-MARKET-DEVNET-BLOB-METADATA", label);
        let key_commitment = devnet_hash("DA-SAMPLING-MARKET-DEVNET-ENCRYPTION-KEY", label);
        let mut blob = Self::new(
            format!("devnet-rollup-batch-{label}"),
            "devnet-sequencer",
            lane_key,
            blob_class,
            privacy_mode,
            payload_hash,
            payload_bytes,
            metadata_root,
            key_commitment,
            DaErasureCodec::HybridRsFri,
            DA_SAMPLING_MARKET_DEFAULT_ORIGINAL_SHARDS,
            DA_SAMPLING_MARKET_DEFAULT_PARITY_SHARDS,
            DA_SAMPLING_MARKET_DEFAULT_SHARD_SIZE_BYTES,
            shard_commitment_root,
            sponsorship_id,
            pricing_quote_id,
            posted_at_height,
            posted_at_height + DA_SAMPLING_MARKET_DEFAULT_CHALLENGE_WINDOW_BLOCKS,
            posted_at_height + blob_class.default_retention_blocks(),
        )
        .expect("deterministic devnet DA blob manifest");
        blob.status = DA_SAMPLING_STATUS_ACCEPTED.to_string();
        blob
    }

    pub fn total_shards(&self) -> u64 {
        self.original_shards.saturating_add(self.parity_shards)
    }

    pub fn redundancy_bps(&self) -> u64 {
        if self.original_shards == 0 {
            return 0;
        }
        mul_div_floor(self.parity_shards, 10_000, self.original_shards)
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "da_blob_manifest_identity",
            "chain_id": CHAIN_ID,
            "protocol_version": DA_SAMPLING_MARKET_PROTOCOL_VERSION,
            "rollup_batch_id": self.rollup_batch_id,
            "sequencer_id": self.sequencer_id,
            "lane_key": self.lane_key,
            "blob_class": self.blob_class.as_str(),
            "payload_hash": self.payload_hash,
            "payload_bytes": self.payload_bytes,
            "posted_at_height": self.posted_at_height,
        })
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "da_blob_manifest",
            "chain_id": CHAIN_ID,
            "protocol_version": DA_SAMPLING_MARKET_PROTOCOL_VERSION,
            "blob_id": self.blob_id,
            "rollup_batch_id": self.rollup_batch_id,
            "sequencer_id": self.sequencer_id,
            "lane_key": self.lane_key,
            "blob_class": self.blob_class.as_str(),
            "privacy_mode": self.privacy_mode.as_str(),
            "payload_hash": self.payload_hash,
            "payload_bytes": self.payload_bytes,
            "metadata_root": self.metadata_root,
            "encryption_key_commitment": self.encryption_key_commitment,
            "codec": self.codec.as_str(),
            "commitment_scheme": self.codec.commitment_scheme(),
            "quantum_resistant": self.codec.is_quantum_resistant(),
            "original_shards": self.original_shards,
            "parity_shards": self.parity_shards,
            "total_shards": self.total_shards(),
            "redundancy_bps": self.redundancy_bps(),
            "shard_size_bytes": self.shard_size_bytes,
            "encoded_bytes": self.encoded_bytes,
            "shard_commitment_root": self.shard_commitment_root,
            "sponsorship_id": self.sponsorship_id,
            "pricing_quote_id": self.pricing_quote_id,
            "posted_at_height": self.posted_at_height,
            "challenge_window_end": self.challenge_window_end,
            "retention_until_height": self.retention_until_height,
            "sample_seed": self.sample_seed,
            "status": self.status,
        })
    }

    pub fn blob_root(&self) -> String {
        da_sampling_market_payload_root(
            "DA-SAMPLING-MARKET-BLOB-MANIFEST",
            &self.public_record_without_root(),
        )
    }

    pub fn public_record(&self) -> Value {
        with_root_field(
            self.public_record_without_root(),
            "blob_root",
            self.blob_root(),
        )
    }

    pub fn validate(&self) -> DaSamplingMarketResult<String> {
        ensure_non_empty(&self.blob_id, "DA blob id")?;
        ensure_non_empty(&self.rollup_batch_id, "DA blob rollup batch id")?;
        ensure_non_empty(&self.sequencer_id, "DA blob sequencer id")?;
        ensure_non_empty(&self.lane_key, "DA blob lane key")?;
        ensure_non_empty(&self.payload_hash, "DA blob payload hash")?;
        ensure_non_empty(&self.metadata_root, "DA blob metadata root")?;
        ensure_non_empty(
            &self.encryption_key_commitment,
            "DA blob encryption key commitment",
        )?;
        ensure_non_empty(&self.shard_commitment_root, "DA blob shard commitment root")?;
        if self.payload_bytes == 0 {
            return Err("DA blob payload bytes cannot be zero".to_string());
        }
        if self.payload_bytes > DA_SAMPLING_MARKET_MAX_BLOB_BYTES {
            return Err("DA blob payload exceeds max blob bytes".to_string());
        }
        if self.original_shards == 0 || self.parity_shards == 0 {
            return Err("DA blob shard counts cannot be zero".to_string());
        }
        if self.total_shards() > DA_SAMPLING_MARKET_MAX_SHARDS_PER_BLOB {
            return Err("DA blob shard count exceeds max".to_string());
        }
        if self.shard_size_bytes == 0 {
            return Err("DA blob shard size cannot be zero".to_string());
        }
        if self.encoded_bytes < self.payload_bytes {
            return Err("DA blob encoded bytes below payload bytes".to_string());
        }
        if self.challenge_window_end <= self.posted_at_height {
            return Err("DA blob challenge window does not follow post height".to_string());
        }
        if self.retention_until_height <= self.challenge_window_end {
            return Err("DA blob retention must exceed challenge window".to_string());
        }
        ensure_status(&self.status, VALID_BLOB_STATUSES, "DA blob status")?;
        let expected_id = da_blob_manifest_id(
            &self.rollup_batch_id,
            &self.sequencer_id,
            &self.lane_key,
            self.blob_class,
            &self.payload_hash,
            self.payload_bytes,
            self.posted_at_height,
        );
        if self.blob_id != expected_id {
            return Err("DA blob manifest id mismatch".to_string());
        }
        let expected_seed = da_blob_sample_seed(
            &self.rollup_batch_id,
            &self.sequencer_id,
            &self.payload_hash,
            self.posted_at_height,
        );
        if self.sample_seed != expected_seed {
            return Err("DA blob sample seed mismatch".to_string());
        }
        Ok(self.blob_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DaErasureShardCommitment {
    pub shard_id: String,
    pub blob_id: String,
    pub lane_key: String,
    pub shard_index: u64,
    pub is_parity: bool,
    pub codec: DaErasureCodec,
    pub shard_size_bytes: u64,
    pub encoded_size_bytes: u64,
    pub commitment: String,
    pub provider_node_id: String,
    pub provider_commitment: String,
    pub merkle_path_root: String,
    pub cell_proof_root: String,
    pub retained_until_height: u64,
    pub status: String,
}

impl DaErasureShardCommitment {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        blob_id: impl Into<String>,
        lane_key: impl Into<String>,
        shard_index: u64,
        is_parity: bool,
        codec: DaErasureCodec,
        shard_size_bytes: u64,
        encoded_size_bytes: u64,
        commitment: impl Into<String>,
        provider_node_id: impl Into<String>,
        provider_commitment: impl Into<String>,
        merkle_path_root: impl Into<String>,
        cell_proof_root: impl Into<String>,
        retained_until_height: u64,
    ) -> DaSamplingMarketResult<Self> {
        let blob_id = blob_id.into();
        let lane_key = lane_key.into();
        let commitment = commitment.into();
        let provider_node_id = provider_node_id.into();
        let provider_commitment = provider_commitment.into();
        let merkle_path_root = merkle_path_root.into();
        let cell_proof_root = cell_proof_root.into();
        let shard_id = da_erasure_shard_commitment_id(
            &blob_id,
            shard_index,
            is_parity,
            &commitment,
            &provider_node_id,
        );
        let shard = Self {
            shard_id,
            blob_id,
            lane_key,
            shard_index,
            is_parity,
            codec,
            shard_size_bytes,
            encoded_size_bytes,
            commitment,
            provider_node_id,
            provider_commitment,
            merkle_path_root,
            cell_proof_root,
            retained_until_height,
            status: DA_SAMPLING_STATUS_ACCEPTED.to_string(),
        };
        shard.validate()?;
        Ok(shard)
    }

    pub fn devnet(blob_id: &str, lane_key: &str, shard_index: u64, original_shards: u64) -> Self {
        let is_parity = shard_index >= original_shards;
        let label = format!("{blob_id}:{shard_index}");
        Self::new(
            blob_id,
            lane_key,
            shard_index,
            is_parity,
            DaErasureCodec::HybridRsFri,
            DA_SAMPLING_MARKET_DEFAULT_SHARD_SIZE_BYTES,
            DA_SAMPLING_MARKET_DEFAULT_SHARD_SIZE_BYTES,
            devnet_hash("DA-SAMPLING-MARKET-DEVNET-SHARD-COMMITMENT", &label),
            devnet_provider_node_id(shard_index),
            devnet_hash("DA-SAMPLING-MARKET-DEVNET-SHARD-PROVIDER", &label),
            devnet_hash("DA-SAMPLING-MARKET-DEVNET-SHARD-MERKLE-PATH", &label),
            devnet_hash("DA-SAMPLING-MARKET-DEVNET-SHARD-CELL-PROOF", &label),
            DA_SAMPLING_MARKET_DEFAULT_RETENTION_BLOCKS,
        )
        .expect("deterministic devnet erasure shard")
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "da_erasure_shard_commitment",
            "chain_id": CHAIN_ID,
            "protocol_version": DA_SAMPLING_MARKET_PROTOCOL_VERSION,
            "shard_id": self.shard_id,
            "blob_id": self.blob_id,
            "lane_key": self.lane_key,
            "shard_index": self.shard_index,
            "is_parity": self.is_parity,
            "codec": self.codec.as_str(),
            "commitment_scheme": self.codec.commitment_scheme(),
            "shard_size_bytes": self.shard_size_bytes,
            "encoded_size_bytes": self.encoded_size_bytes,
            "commitment": self.commitment,
            "provider_node_id": self.provider_node_id,
            "provider_commitment": self.provider_commitment,
            "merkle_path_root": self.merkle_path_root,
            "cell_proof_root": self.cell_proof_root,
            "retained_until_height": self.retained_until_height,
            "status": self.status,
        })
    }

    pub fn shard_root(&self) -> String {
        da_sampling_market_payload_root(
            "DA-SAMPLING-MARKET-ERASURE-SHARD",
            &self.public_record_without_root(),
        )
    }

    pub fn public_record(&self) -> Value {
        with_root_field(
            self.public_record_without_root(),
            "shard_root",
            self.shard_root(),
        )
    }

    pub fn validate(&self) -> DaSamplingMarketResult<String> {
        ensure_non_empty(&self.shard_id, "DA shard id")?;
        ensure_non_empty(&self.blob_id, "DA shard blob id")?;
        ensure_non_empty(&self.lane_key, "DA shard lane key")?;
        ensure_non_empty(&self.commitment, "DA shard commitment")?;
        ensure_non_empty(&self.provider_node_id, "DA shard provider node id")?;
        ensure_non_empty(&self.provider_commitment, "DA shard provider commitment")?;
        ensure_non_empty(&self.merkle_path_root, "DA shard merkle path root")?;
        ensure_non_empty(&self.cell_proof_root, "DA shard cell proof root")?;
        if self.shard_size_bytes == 0 || self.encoded_size_bytes == 0 {
            return Err("DA shard sizes cannot be zero".to_string());
        }
        ensure_status(&self.status, VALID_SHARD_STATUSES, "DA shard status")?;
        let expected_id = da_erasure_shard_commitment_id(
            &self.blob_id,
            self.shard_index,
            self.is_parity,
            &self.commitment,
            &self.provider_node_id,
        );
        if self.shard_id != expected_id {
            return Err("DA shard id mismatch".to_string());
        }
        Ok(self.shard_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DaCommitteeNode {
    pub node_id: String,
    pub operator_id: String,
    pub label: String,
    pub role: DaCommitteeRole,
    pub network_public_key: String,
    pub pq_signing_public_key: String,
    pub stake_bond_units: u64,
    pub effective_stake_units: u64,
    pub max_shards_per_epoch: u64,
    pub available_capacity_bytes: u64,
    pub region_commitment: String,
    pub joined_at_height: u64,
    pub exit_at_height: u64,
    pub successful_sample_count: u64,
    pub missed_sample_count: u64,
    pub slashed_units: u64,
    pub status: String,
}

impl DaCommitteeNode {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        operator_id: impl Into<String>,
        label: impl Into<String>,
        role: DaCommitteeRole,
        stake_bond_units: u64,
        max_shards_per_epoch: u64,
        available_capacity_bytes: u64,
        region_commitment: impl Into<String>,
        joined_at_height: u64,
    ) -> DaSamplingMarketResult<Self> {
        let operator_id = operator_id.into();
        let label = label.into();
        let region_commitment = region_commitment.into();
        let network_public_key = da_market_devnet_key("network", &label);
        let pq_signing_public_key = da_market_devnet_key("pq-signing", &label);
        let node_id = da_committee_node_id(
            &operator_id,
            role,
            &network_public_key,
            &pq_signing_public_key,
        );
        let node = Self {
            node_id,
            operator_id,
            label,
            role,
            network_public_key,
            pq_signing_public_key,
            stake_bond_units,
            effective_stake_units: stake_bond_units,
            max_shards_per_epoch,
            available_capacity_bytes,
            region_commitment,
            joined_at_height,
            exit_at_height: 0,
            successful_sample_count: 0,
            missed_sample_count: 0,
            slashed_units: 0,
            status: DA_SAMPLING_STATUS_ACTIVE.to_string(),
        };
        node.validate()?;
        Ok(node)
    }

    pub fn devnet(index: u64, role: DaCommitteeRole) -> Self {
        let label = format!("devnet-da-node-{index}");
        Self::new(
            format!("devnet-da-operator-{index}"),
            label,
            role,
            250_000 + index.saturating_mul(25_000),
            16_384,
            512 * 1024 * 1024,
            devnet_hash(
                "DA-SAMPLING-MARKET-DEVNET-REGION",
                &format!("region-{index}"),
            ),
            0,
        )
        .expect("deterministic devnet DA committee node")
    }

    pub fn is_active_at(&self, height: u64) -> bool {
        self.status == DA_SAMPLING_STATUS_ACTIVE
            && self.effective_stake_units > 0
            && self.joined_at_height <= height
            && (self.exit_at_height == 0 || height < self.exit_at_height)
    }

    pub fn available_stake_units(&self) -> u64 {
        self.stake_bond_units.saturating_sub(self.slashed_units)
    }

    pub fn slash(&mut self, units: u64) -> u64 {
        let slashed = std::cmp::min(units, self.available_stake_units());
        self.slashed_units = self.slashed_units.saturating_add(slashed);
        self.effective_stake_units = self.effective_stake_units.saturating_sub(slashed);
        if self.effective_stake_units == 0 {
            self.status = DA_SAMPLING_STATUS_SLASHED_OUT.to_string();
        } else if slashed > 0 {
            self.status = DA_SAMPLING_STATUS_SLASHED.to_string();
        }
        slashed
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "da_committee_node",
            "chain_id": CHAIN_ID,
            "protocol_version": DA_SAMPLING_MARKET_PROTOCOL_VERSION,
            "node_id": self.node_id,
            "operator_id": self.operator_id,
            "label": self.label,
            "role": self.role.as_str(),
            "network_public_key": self.network_public_key,
            "pq_signing_public_key": self.pq_signing_public_key,
            "signature_scheme": DA_SAMPLING_MARKET_PQ_SIGNATURE_SCHEME,
            "stake_bond_units": self.stake_bond_units,
            "effective_stake_units": self.effective_stake_units,
            "max_shards_per_epoch": self.max_shards_per_epoch,
            "available_capacity_bytes": self.available_capacity_bytes,
            "region_commitment": self.region_commitment,
            "joined_at_height": self.joined_at_height,
            "exit_at_height": self.exit_at_height,
            "successful_sample_count": self.successful_sample_count,
            "missed_sample_count": self.missed_sample_count,
            "slashed_units": self.slashed_units,
            "status": self.status,
        })
    }

    pub fn node_root(&self) -> String {
        da_sampling_market_payload_root(
            "DA-SAMPLING-MARKET-COMMITTEE-NODE",
            &self.public_record_without_root(),
        )
    }

    pub fn public_record(&self) -> Value {
        with_root_field(
            self.public_record_without_root(),
            "node_root",
            self.node_root(),
        )
    }

    pub fn validate(&self) -> DaSamplingMarketResult<String> {
        ensure_non_empty(&self.node_id, "DA committee node id")?;
        ensure_non_empty(&self.operator_id, "DA committee node operator id")?;
        ensure_non_empty(&self.label, "DA committee node label")?;
        ensure_non_empty(
            &self.network_public_key,
            "DA committee node network public key",
        )?;
        ensure_non_empty(
            &self.pq_signing_public_key,
            "DA committee node signing public key",
        )?;
        ensure_non_empty(
            &self.region_commitment,
            "DA committee node region commitment",
        )?;
        if self.stake_bond_units == 0 {
            return Err("DA committee node stake bond cannot be zero".to_string());
        }
        if self.effective_stake_units > self.stake_bond_units {
            return Err("DA committee node effective stake exceeds bond".to_string());
        }
        if self.slashed_units > self.stake_bond_units {
            return Err("DA committee node slashed units exceed bond".to_string());
        }
        if self.max_shards_per_epoch == 0 {
            return Err("DA committee node max shards cannot be zero".to_string());
        }
        if self.exit_at_height > 0 && self.exit_at_height <= self.joined_at_height {
            return Err("DA committee node exit precedes join".to_string());
        }
        ensure_status(
            &self.status,
            VALID_NODE_STATUSES,
            "DA committee node status",
        )?;
        let expected_id = da_committee_node_id(
            &self.operator_id,
            self.role,
            &self.network_public_key,
            &self.pq_signing_public_key,
        );
        if self.node_id != expected_id {
            return Err("DA committee node id mismatch".to_string());
        }
        Ok(self.node_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DaCommitteeAttestation {
    pub attestation_id: String,
    pub blob_id: String,
    pub epoch_id: String,
    pub node_id: String,
    pub role: DaCommitteeRole,
    pub shard_indices: Vec<u64>,
    pub shard_root: String,
    pub sample_seed: String,
    pub attested_at_height: u64,
    pub retained_until_height: u64,
    pub stake_weight_units: u64,
    pub availability_claim: String,
    pub transcript_hash: String,
    pub signature: String,
    pub status: String,
}

impl DaCommitteeAttestation {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        blob: &DaBlobManifest,
        epoch_id: impl Into<String>,
        node: &DaCommitteeNode,
        shard_indices: Vec<u64>,
        attested_at_height: u64,
        availability_claim: impl Into<String>,
    ) -> DaSamplingMarketResult<Self> {
        let epoch_id = epoch_id.into();
        let availability_claim = availability_claim.into();
        let shard_root = da_sample_index_root(&shard_indices);
        let transcript_hash = da_committee_attestation_transcript(
            &blob.blob_id,
            &epoch_id,
            &node.node_id,
            &shard_root,
            attested_at_height,
            &availability_claim,
        );
        let signature = da_market_devnet_signature(&node.label, &transcript_hash);
        let attestation_id =
            da_committee_attestation_id(&blob.blob_id, &epoch_id, &node.node_id, &transcript_hash);
        let attestation = Self {
            attestation_id,
            blob_id: blob.blob_id.clone(),
            epoch_id,
            node_id: node.node_id.clone(),
            role: node.role,
            shard_indices,
            shard_root,
            sample_seed: blob.sample_seed.clone(),
            attested_at_height,
            retained_until_height: blob.retention_until_height,
            stake_weight_units: node.effective_stake_units,
            availability_claim,
            transcript_hash,
            signature,
            status: DA_SAMPLING_STATUS_ATTESTED.to_string(),
        };
        attestation.validate()?;
        Ok(attestation)
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "da_committee_attestation",
            "chain_id": CHAIN_ID,
            "protocol_version": DA_SAMPLING_MARKET_PROTOCOL_VERSION,
            "attestation_id": self.attestation_id,
            "blob_id": self.blob_id,
            "epoch_id": self.epoch_id,
            "node_id": self.node_id,
            "role": self.role.as_str(),
            "shard_indices": self.shard_indices,
            "shard_root": self.shard_root,
            "sample_seed": self.sample_seed,
            "attested_at_height": self.attested_at_height,
            "retained_until_height": self.retained_until_height,
            "stake_weight_units": self.stake_weight_units,
            "availability_claim": self.availability_claim,
            "signature_scheme": DA_SAMPLING_MARKET_PQ_SIGNATURE_SCHEME,
            "transcript_hash": self.transcript_hash,
            "signature": self.signature,
            "status": self.status,
        })
    }

    pub fn attestation_root(&self) -> String {
        da_sampling_market_payload_root(
            "DA-SAMPLING-MARKET-COMMITTEE-ATTESTATION",
            &self.public_record_without_root(),
        )
    }

    pub fn public_record(&self) -> Value {
        with_root_field(
            self.public_record_without_root(),
            "attestation_root",
            self.attestation_root(),
        )
    }

    pub fn validate(&self) -> DaSamplingMarketResult<String> {
        ensure_non_empty(&self.attestation_id, "DA attestation id")?;
        ensure_non_empty(&self.blob_id, "DA attestation blob id")?;
        ensure_non_empty(&self.epoch_id, "DA attestation epoch id")?;
        ensure_non_empty(&self.node_id, "DA attestation node id")?;
        ensure_non_empty(&self.shard_root, "DA attestation shard root")?;
        ensure_non_empty(&self.sample_seed, "DA attestation sample seed")?;
        ensure_non_empty(
            &self.availability_claim,
            "DA attestation availability claim",
        )?;
        ensure_non_empty(&self.transcript_hash, "DA attestation transcript hash")?;
        ensure_non_empty(&self.signature, "DA attestation signature")?;
        ensure_unique_u64(&self.shard_indices, "DA attestation shard index")?;
        if self.shard_indices.is_empty() {
            return Err("DA attestation shard indices cannot be empty".to_string());
        }
        if self.retained_until_height <= self.attested_at_height {
            return Err("DA attestation retention must exceed attestation height".to_string());
        }
        if self.stake_weight_units == 0 {
            return Err("DA attestation stake weight cannot be zero".to_string());
        }
        ensure_status(
            &self.availability_claim,
            &["available", "sampled", "retained", "unavailable"],
            "DA attestation availability claim",
        )?;
        ensure_status(
            &self.status,
            VALID_ATTESTATION_STATUSES,
            "DA attestation status",
        )?;
        if self.shard_root != da_sample_index_root(&self.shard_indices) {
            return Err("DA attestation shard root mismatch".to_string());
        }
        let expected_id = da_committee_attestation_id(
            &self.blob_id,
            &self.epoch_id,
            &self.node_id,
            &self.transcript_hash,
        );
        if self.attestation_id != expected_id {
            return Err("DA attestation id mismatch".to_string());
        }
        Ok(self.attestation_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DaSampleRequest {
    pub request_id: String,
    pub blob_id: String,
    pub requester_commitment: String,
    pub requester_role: DaCommitteeRole,
    pub sample_seed: String,
    pub sample_indices: Vec<u64>,
    pub sample_index_root: String,
    pub request_height: u64,
    pub max_response_height: u64,
    pub reward_microunits: u64,
    pub bond_microunits: u64,
    pub light_client_window_id: String,
    pub status: String,
}

impl DaSampleRequest {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        blob: &DaBlobManifest,
        requester_commitment: impl Into<String>,
        requester_role: DaCommitteeRole,
        sample_count: u64,
        request_height: u64,
        max_response_height: u64,
        reward_microunits: u64,
        bond_microunits: u64,
        light_client_window_id: impl Into<String>,
    ) -> DaSamplingMarketResult<Self> {
        let requester_commitment = requester_commitment.into();
        let sample_indices = derive_da_sampling_market_sample_indices(
            &blob.sample_seed,
            blob.total_shards(),
            sample_count,
        )?;
        let sample_index_root = da_sample_index_root(&sample_indices);
        let request_id = da_sample_request_id(
            &blob.blob_id,
            &requester_commitment,
            &sample_index_root,
            request_height,
        );
        let request = Self {
            request_id,
            blob_id: blob.blob_id.clone(),
            requester_commitment,
            requester_role,
            sample_seed: blob.sample_seed.clone(),
            sample_indices,
            sample_index_root,
            request_height,
            max_response_height,
            reward_microunits,
            bond_microunits,
            light_client_window_id: light_client_window_id.into(),
            status: DA_SAMPLING_STATUS_OPEN.to_string(),
        };
        request.validate()?;
        Ok(request)
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "da_sample_request",
            "chain_id": CHAIN_ID,
            "protocol_version": DA_SAMPLING_MARKET_PROTOCOL_VERSION,
            "request_id": self.request_id,
            "blob_id": self.blob_id,
            "requester_commitment": self.requester_commitment,
            "requester_role": self.requester_role.as_str(),
            "sample_seed": self.sample_seed,
            "sample_indices": self.sample_indices,
            "sample_index_root": self.sample_index_root,
            "sample_count": self.sample_indices.len() as u64,
            "request_height": self.request_height,
            "max_response_height": self.max_response_height,
            "reward_microunits": self.reward_microunits,
            "bond_microunits": self.bond_microunits,
            "light_client_window_id": self.light_client_window_id,
            "status": self.status,
        })
    }

    pub fn request_root(&self) -> String {
        da_sampling_market_payload_root(
            "DA-SAMPLING-MARKET-SAMPLE-REQUEST",
            &self.public_record_without_root(),
        )
    }

    pub fn public_record(&self) -> Value {
        with_root_field(
            self.public_record_without_root(),
            "request_root",
            self.request_root(),
        )
    }

    pub fn is_expired_at(&self, height: u64) -> bool {
        height > self.max_response_height
    }

    pub fn validate(&self) -> DaSamplingMarketResult<String> {
        ensure_non_empty(&self.request_id, "DA sample request id")?;
        ensure_non_empty(&self.blob_id, "DA sample request blob id")?;
        ensure_non_empty(
            &self.requester_commitment,
            "DA sample request requester commitment",
        )?;
        ensure_non_empty(&self.sample_seed, "DA sample request seed")?;
        ensure_non_empty(&self.sample_index_root, "DA sample request index root")?;
        ensure_unique_u64(&self.sample_indices, "DA sample request index")?;
        if self.sample_indices.is_empty() {
            return Err("DA sample request indices cannot be empty".to_string());
        }
        if self.sample_indices.len() as u64 > DA_SAMPLING_MARKET_MAX_SAMPLE_COUNT {
            return Err("DA sample request exceeds max sample count".to_string());
        }
        if self.max_response_height <= self.request_height {
            return Err("DA sample request response height must follow request".to_string());
        }
        ensure_status(
            &self.status,
            VALID_REQUEST_STATUSES,
            "DA sample request status",
        )?;
        if self.sample_index_root != da_sample_index_root(&self.sample_indices) {
            return Err("DA sample request index root mismatch".to_string());
        }
        let expected_id = da_sample_request_id(
            &self.blob_id,
            &self.requester_commitment,
            &self.sample_index_root,
            self.request_height,
        );
        if self.request_id != expected_id {
            return Err("DA sample request id mismatch".to_string());
        }
        Ok(self.request_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DaSampleReceipt {
    pub receipt_id: String,
    pub request_id: String,
    pub blob_id: String,
    pub responder_node_id: String,
    pub returned_indices: Vec<u64>,
    pub missing_indices: Vec<u64>,
    pub returned_shard_root: String,
    pub missing_shard_root: String,
    pub response_height: u64,
    pub latency_blocks: u64,
    pub fee_paid_microunits: u64,
    pub proof_root: String,
    pub status: String,
}

impl DaSampleReceipt {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        request: &DaSampleRequest,
        responder_node_id: impl Into<String>,
        returned_indices: Vec<u64>,
        missing_indices: Vec<u64>,
        response_height: u64,
        fee_paid_microunits: u64,
        proof_root: impl Into<String>,
    ) -> DaSamplingMarketResult<Self> {
        let responder_node_id = responder_node_id.into();
        let returned_shard_root = da_sample_index_root(&returned_indices);
        let missing_shard_root = da_sample_index_root(&missing_indices);
        let receipt_id = da_sample_receipt_id(
            &request.request_id,
            &responder_node_id,
            &returned_shard_root,
            &missing_shard_root,
            response_height,
        );
        let status = if missing_indices.is_empty() {
            DA_SAMPLING_STATUS_ANSWERED
        } else {
            DA_SAMPLING_STATUS_PARTIAL
        };
        let receipt = Self {
            receipt_id,
            request_id: request.request_id.clone(),
            blob_id: request.blob_id.clone(),
            responder_node_id,
            returned_indices,
            missing_indices,
            returned_shard_root,
            missing_shard_root,
            response_height,
            latency_blocks: response_height.saturating_sub(request.request_height),
            fee_paid_microunits,
            proof_root: proof_root.into(),
            status: status.to_string(),
        };
        receipt.validate()?;
        Ok(receipt)
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "da_sample_receipt",
            "chain_id": CHAIN_ID,
            "protocol_version": DA_SAMPLING_MARKET_PROTOCOL_VERSION,
            "receipt_id": self.receipt_id,
            "request_id": self.request_id,
            "blob_id": self.blob_id,
            "responder_node_id": self.responder_node_id,
            "returned_indices": self.returned_indices,
            "missing_indices": self.missing_indices,
            "returned_shard_root": self.returned_shard_root,
            "missing_shard_root": self.missing_shard_root,
            "returned_count": self.returned_indices.len() as u64,
            "missing_count": self.missing_indices.len() as u64,
            "response_height": self.response_height,
            "latency_blocks": self.latency_blocks,
            "fee_paid_microunits": self.fee_paid_microunits,
            "proof_root": self.proof_root,
            "status": self.status,
        })
    }

    pub fn receipt_root(&self) -> String {
        da_sampling_market_payload_root(
            "DA-SAMPLING-MARKET-SAMPLE-RECEIPT",
            &self.public_record_without_root(),
        )
    }

    pub fn public_record(&self) -> Value {
        with_root_field(
            self.public_record_without_root(),
            "receipt_root",
            self.receipt_root(),
        )
    }

    pub fn validate(&self) -> DaSamplingMarketResult<String> {
        ensure_non_empty(&self.receipt_id, "DA sample receipt id")?;
        ensure_non_empty(&self.request_id, "DA sample receipt request id")?;
        ensure_non_empty(&self.blob_id, "DA sample receipt blob id")?;
        ensure_non_empty(
            &self.responder_node_id,
            "DA sample receipt responder node id",
        )?;
        ensure_non_empty(&self.returned_shard_root, "DA sample receipt returned root")?;
        ensure_non_empty(&self.missing_shard_root, "DA sample receipt missing root")?;
        ensure_non_empty(&self.proof_root, "DA sample receipt proof root")?;
        ensure_unique_u64(&self.returned_indices, "DA sample receipt returned index")?;
        ensure_unique_u64(&self.missing_indices, "DA sample receipt missing index")?;
        ensure_disjoint_u64(
            &self.returned_indices,
            &self.missing_indices,
            "DA sample receipt indices",
        )?;
        if self.returned_indices.is_empty() && self.missing_indices.is_empty() {
            return Err("DA sample receipt must include returned or missing indices".to_string());
        }
        ensure_status(
            &self.status,
            VALID_RECEIPT_STATUSES,
            "DA sample receipt status",
        )?;
        if self.returned_shard_root != da_sample_index_root(&self.returned_indices) {
            return Err("DA sample receipt returned root mismatch".to_string());
        }
        if self.missing_shard_root != da_sample_index_root(&self.missing_indices) {
            return Err("DA sample receipt missing root mismatch".to_string());
        }
        let expected_id = da_sample_receipt_id(
            &self.request_id,
            &self.responder_node_id,
            &self.returned_shard_root,
            &self.missing_shard_root,
            self.response_height,
        );
        if self.receipt_id != expected_id {
            return Err("DA sample receipt id mismatch".to_string());
        }
        Ok(self.receipt_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DaBlobSponsorship {
    pub sponsorship_id: String,
    pub sponsor_commitment: String,
    pub sponsor_kind: String,
    pub lane_key: String,
    pub blob_class: DaBlobClass,
    pub fee_asset_id: String,
    pub budget_microunits: u64,
    pub reserved_microunits: u64,
    pub spent_microunits: u64,
    pub max_rebate_bps: u64,
    pub per_blob_cap_microunits: u64,
    pub policy_root: String,
    pub nullifier_root: String,
    pub created_at_height: u64,
    pub expires_at_height: u64,
    pub status: String,
}

impl DaBlobSponsorship {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        sponsor_commitment: impl Into<String>,
        sponsor_kind: impl Into<String>,
        lane_key: impl Into<String>,
        blob_class: DaBlobClass,
        fee_asset_id: impl Into<String>,
        budget_microunits: u64,
        max_rebate_bps: u64,
        per_blob_cap_microunits: u64,
        policy: &Value,
        nullifier_root: impl Into<String>,
        created_at_height: u64,
        expires_at_height: u64,
    ) -> DaSamplingMarketResult<Self> {
        let sponsor_commitment = sponsor_commitment.into();
        let sponsor_kind = sponsor_kind.into();
        let lane_key = lane_key.into();
        let fee_asset_id = fee_asset_id.into();
        let policy_root =
            da_sampling_market_payload_root("DA-SAMPLING-MARKET-SPONSORSHIP-POLICY", policy);
        let nullifier_root = nullifier_root.into();
        let sponsorship_id = da_blob_sponsorship_id(
            &sponsor_commitment,
            &lane_key,
            blob_class,
            &fee_asset_id,
            created_at_height,
            &policy_root,
        );
        let sponsorship = Self {
            sponsorship_id,
            sponsor_commitment,
            sponsor_kind,
            lane_key,
            blob_class,
            fee_asset_id,
            budget_microunits,
            reserved_microunits: 0,
            spent_microunits: 0,
            max_rebate_bps,
            per_blob_cap_microunits,
            policy_root,
            nullifier_root,
            created_at_height,
            expires_at_height,
            status: DA_SAMPLING_STATUS_ACTIVE.to_string(),
        };
        sponsorship.validate()?;
        Ok(sponsorship)
    }

    pub fn available_microunits(&self) -> u64 {
        self.budget_microunits
            .saturating_sub(self.reserved_microunits)
            .saturating_sub(self.spent_microunits)
    }

    pub fn reserve(&mut self, amount: u64) -> DaSamplingMarketResult<String> {
        if amount == 0 {
            return Err("DA sponsorship reserve amount cannot be zero".to_string());
        }
        if amount > self.available_microunits() {
            return Err("DA sponsorship budget exhausted".to_string());
        }
        if amount > self.per_blob_cap_microunits {
            return Err("DA sponsorship reserve exceeds per-blob cap".to_string());
        }
        self.reserved_microunits = self.reserved_microunits.saturating_add(amount);
        Ok(self.sponsorship_root())
    }

    pub fn spend_reserved(&mut self, amount: u64) -> DaSamplingMarketResult<String> {
        if amount > self.reserved_microunits {
            return Err("DA sponsorship spend exceeds reserved budget".to_string());
        }
        self.reserved_microunits = self.reserved_microunits.saturating_sub(amount);
        self.spent_microunits = self.spent_microunits.saturating_add(amount);
        if self.available_microunits() == 0 {
            self.status = DA_SAMPLING_STATUS_EXHAUSTED.to_string();
        }
        Ok(self.sponsorship_root())
    }

    pub fn is_expired_at(&self, height: u64) -> bool {
        height > self.expires_at_height
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "da_blob_sponsorship",
            "chain_id": CHAIN_ID,
            "protocol_version": DA_SAMPLING_MARKET_PROTOCOL_VERSION,
            "sponsorship_id": self.sponsorship_id,
            "sponsor_commitment": self.sponsor_commitment,
            "sponsor_kind": self.sponsor_kind,
            "lane_key": self.lane_key,
            "blob_class": self.blob_class.as_str(),
            "fee_asset_id": self.fee_asset_id,
            "budget_microunits": self.budget_microunits,
            "reserved_microunits": self.reserved_microunits,
            "spent_microunits": self.spent_microunits,
            "available_microunits": self.available_microunits(),
            "max_rebate_bps": self.max_rebate_bps,
            "per_blob_cap_microunits": self.per_blob_cap_microunits,
            "policy_root": self.policy_root,
            "nullifier_root": self.nullifier_root,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status,
        })
    }

    pub fn sponsorship_root(&self) -> String {
        da_sampling_market_payload_root(
            "DA-SAMPLING-MARKET-BLOB-SPONSORSHIP",
            &self.public_record_without_root(),
        )
    }

    pub fn public_record(&self) -> Value {
        with_root_field(
            self.public_record_without_root(),
            "sponsorship_root",
            self.sponsorship_root(),
        )
    }

    pub fn validate(&self) -> DaSamplingMarketResult<String> {
        ensure_non_empty(&self.sponsorship_id, "DA sponsorship id")?;
        ensure_non_empty(
            &self.sponsor_commitment,
            "DA sponsorship sponsor commitment",
        )?;
        ensure_non_empty(&self.sponsor_kind, "DA sponsorship sponsor kind")?;
        ensure_non_empty(&self.lane_key, "DA sponsorship lane key")?;
        ensure_non_empty(&self.fee_asset_id, "DA sponsorship fee asset id")?;
        ensure_non_empty(&self.policy_root, "DA sponsorship policy root")?;
        ensure_non_empty(&self.nullifier_root, "DA sponsorship nullifier root")?;
        if self.budget_microunits == 0 {
            return Err("DA sponsorship budget cannot be zero".to_string());
        }
        if self.per_blob_cap_microunits == 0 {
            return Err("DA sponsorship per-blob cap cannot be zero".to_string());
        }
        if self
            .reserved_microunits
            .saturating_add(self.spent_microunits)
            > self.budget_microunits
        {
            return Err("DA sponsorship reserved and spent exceed budget".to_string());
        }
        ensure_bps(self.max_rebate_bps, "DA sponsorship rebate")?;
        if self.expires_at_height <= self.created_at_height {
            return Err("DA sponsorship expiry precedes creation".to_string());
        }
        ensure_status(
            &self.status,
            VALID_SPONSORSHIP_STATUSES,
            "DA sponsorship status",
        )?;
        let expected_id = da_blob_sponsorship_id(
            &self.sponsor_commitment,
            &self.lane_key,
            self.blob_class,
            &self.fee_asset_id,
            self.created_at_height,
            &self.policy_root,
        );
        if self.sponsorship_id != expected_id {
            return Err("DA sponsorship id mismatch".to_string());
        }
        Ok(self.sponsorship_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WithheldShardEvidence {
    pub evidence_id: String,
    pub evidence_kind: WithheldShardEvidenceKind,
    pub blob_id: String,
    pub shard_id: String,
    pub reporter_commitment: String,
    pub accused_node_id: String,
    pub request_id: String,
    pub receipt_id: String,
    pub missing_indices: Vec<u64>,
    pub missing_index_root: String,
    pub challenge_height: u64,
    pub challenge_window_end: u64,
    pub evidence_root: String,
    pub proof_system: String,
    pub severity_bps: u64,
    pub reporter_bond_microunits: u64,
    pub status: String,
}

impl WithheldShardEvidence {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        evidence_kind: WithheldShardEvidenceKind,
        blob_id: impl Into<String>,
        shard_id: impl Into<String>,
        reporter_commitment: impl Into<String>,
        accused_node_id: impl Into<String>,
        request_id: impl Into<String>,
        receipt_id: impl Into<String>,
        missing_indices: Vec<u64>,
        challenge_height: u64,
        challenge_window_end: u64,
        evidence_payload: &Value,
        reporter_bond_microunits: u64,
    ) -> DaSamplingMarketResult<Self> {
        let blob_id = blob_id.into();
        let shard_id = shard_id.into();
        let reporter_commitment = reporter_commitment.into();
        let accused_node_id = accused_node_id.into();
        let request_id = request_id.into();
        let receipt_id = receipt_id.into();
        let missing_index_root = da_sample_index_root(&missing_indices);
        let evidence_root = da_sampling_market_payload_root(
            "DA-SAMPLING-MARKET-WITHHELD-EVIDENCE-PAYLOAD",
            evidence_payload,
        );
        let severity_bps = evidence_kind.default_severity_bps();
        let evidence_id = da_withheld_shard_evidence_id(
            evidence_kind,
            &blob_id,
            &shard_id,
            &reporter_commitment,
            &accused_node_id,
            &missing_index_root,
            challenge_height,
        );
        let evidence = Self {
            evidence_id,
            evidence_kind,
            blob_id,
            shard_id,
            reporter_commitment,
            accused_node_id,
            request_id,
            receipt_id,
            missing_indices,
            missing_index_root,
            challenge_height,
            challenge_window_end,
            evidence_root,
            proof_system: "shake256-merkle-sample-nonresponse".to_string(),
            severity_bps,
            reporter_bond_microunits,
            status: DA_SAMPLING_STATUS_OPEN.to_string(),
        };
        evidence.validate()?;
        Ok(evidence)
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "withheld_shard_evidence",
            "chain_id": CHAIN_ID,
            "protocol_version": DA_SAMPLING_MARKET_PROTOCOL_VERSION,
            "evidence_id": self.evidence_id,
            "evidence_kind": self.evidence_kind.as_str(),
            "blob_id": self.blob_id,
            "shard_id": self.shard_id,
            "reporter_commitment": self.reporter_commitment,
            "accused_node_id": self.accused_node_id,
            "request_id": self.request_id,
            "receipt_id": self.receipt_id,
            "missing_indices": self.missing_indices,
            "missing_index_root": self.missing_index_root,
            "challenge_height": self.challenge_height,
            "challenge_window_end": self.challenge_window_end,
            "evidence_root": self.evidence_root,
            "proof_system": self.proof_system,
            "severity_bps": self.severity_bps,
            "reporter_bond_microunits": self.reporter_bond_microunits,
            "status": self.status,
        })
    }

    pub fn withheld_evidence_root(&self) -> String {
        da_sampling_market_payload_root(
            "DA-SAMPLING-MARKET-WITHHELD-SHARD-EVIDENCE",
            &self.public_record_without_root(),
        )
    }

    pub fn public_record(&self) -> Value {
        with_root_field(
            self.public_record_without_root(),
            "withheld_evidence_root",
            self.withheld_evidence_root(),
        )
    }

    pub fn validate(&self) -> DaSamplingMarketResult<String> {
        ensure_non_empty(&self.evidence_id, "withheld shard evidence id")?;
        ensure_non_empty(&self.blob_id, "withheld shard evidence blob id")?;
        ensure_non_empty(&self.shard_id, "withheld shard evidence shard id")?;
        ensure_non_empty(
            &self.reporter_commitment,
            "withheld shard evidence reporter commitment",
        )?;
        ensure_non_empty(
            &self.accused_node_id,
            "withheld shard evidence accused node id",
        )?;
        ensure_non_empty(&self.request_id, "withheld shard evidence request id")?;
        ensure_non_empty(&self.receipt_id, "withheld shard evidence receipt id")?;
        ensure_non_empty(
            &self.missing_index_root,
            "withheld shard evidence missing root",
        )?;
        ensure_non_empty(&self.evidence_root, "withheld shard evidence root")?;
        ensure_non_empty(&self.proof_system, "withheld shard evidence proof system")?;
        ensure_unique_u64(
            &self.missing_indices,
            "withheld shard evidence missing index",
        )?;
        if self.missing_indices.is_empty() {
            return Err("withheld shard evidence missing indices cannot be empty".to_string());
        }
        if self.challenge_window_end <= self.challenge_height {
            return Err("withheld shard evidence challenge window must follow height".to_string());
        }
        ensure_bps(self.severity_bps, "withheld shard evidence severity")?;
        ensure_status(
            &self.status,
            VALID_EVIDENCE_STATUSES,
            "withheld shard evidence status",
        )?;
        if self.missing_index_root != da_sample_index_root(&self.missing_indices) {
            return Err("withheld shard evidence missing root mismatch".to_string());
        }
        let expected_id = da_withheld_shard_evidence_id(
            self.evidence_kind,
            &self.blob_id,
            &self.shard_id,
            &self.reporter_commitment,
            &self.accused_node_id,
            &self.missing_index_root,
            self.challenge_height,
        );
        if self.evidence_id != expected_id {
            return Err("withheld shard evidence id mismatch".to_string());
        }
        Ok(self.withheld_evidence_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DaRedundancyEpoch {
    pub epoch_id: String,
    pub epoch_index: u64,
    pub start_height: u64,
    pub end_height: u64,
    pub original_shards: u64,
    pub parity_shards: u64,
    pub min_availability_quorum_bps: u64,
    pub sampling_quorum_bps: u64,
    pub committee_root: String,
    pub pricing_root: String,
    pub random_seed: String,
    pub blob_count: u64,
    pub encoded_bytes: u64,
    pub status: String,
}

impl DaRedundancyEpoch {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        epoch_index: u64,
        start_height: u64,
        end_height: u64,
        original_shards: u64,
        parity_shards: u64,
        min_availability_quorum_bps: u64,
        sampling_quorum_bps: u64,
        committee_root: impl Into<String>,
        pricing_root: impl Into<String>,
        random_seed: impl Into<String>,
    ) -> DaSamplingMarketResult<Self> {
        let committee_root = committee_root.into();
        let pricing_root = pricing_root.into();
        let random_seed = random_seed.into();
        let epoch_id = da_redundancy_epoch_id(
            epoch_index,
            start_height,
            end_height,
            original_shards,
            parity_shards,
            &random_seed,
        );
        let epoch = Self {
            epoch_id,
            epoch_index,
            start_height,
            end_height,
            original_shards,
            parity_shards,
            min_availability_quorum_bps,
            sampling_quorum_bps,
            committee_root,
            pricing_root,
            random_seed,
            blob_count: 0,
            encoded_bytes: 0,
            status: DA_SAMPLING_STATUS_ACTIVE.to_string(),
        };
        epoch.validate()?;
        Ok(epoch)
    }

    pub fn contains_height(&self, height: u64) -> bool {
        height >= self.start_height && height <= self.end_height
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "da_redundancy_epoch",
            "chain_id": CHAIN_ID,
            "protocol_version": DA_SAMPLING_MARKET_PROTOCOL_VERSION,
            "epoch_id": self.epoch_id,
            "epoch_index": self.epoch_index,
            "start_height": self.start_height,
            "end_height": self.end_height,
            "original_shards": self.original_shards,
            "parity_shards": self.parity_shards,
            "total_shards": self.original_shards.saturating_add(self.parity_shards),
            "min_availability_quorum_bps": self.min_availability_quorum_bps,
            "sampling_quorum_bps": self.sampling_quorum_bps,
            "committee_root": self.committee_root,
            "pricing_root": self.pricing_root,
            "random_seed": self.random_seed,
            "blob_count": self.blob_count,
            "encoded_bytes": self.encoded_bytes,
            "status": self.status,
        })
    }

    pub fn epoch_root(&self) -> String {
        da_sampling_market_payload_root(
            "DA-SAMPLING-MARKET-REDUNDANCY-EPOCH",
            &self.public_record_without_root(),
        )
    }

    pub fn public_record(&self) -> Value {
        with_root_field(
            self.public_record_without_root(),
            "epoch_root",
            self.epoch_root(),
        )
    }

    pub fn validate(&self) -> DaSamplingMarketResult<String> {
        ensure_non_empty(&self.epoch_id, "DA redundancy epoch id")?;
        ensure_non_empty(&self.committee_root, "DA redundancy epoch committee root")?;
        ensure_non_empty(&self.pricing_root, "DA redundancy epoch pricing root")?;
        ensure_non_empty(&self.random_seed, "DA redundancy epoch seed")?;
        if self.start_height > self.end_height {
            return Err("DA redundancy epoch start exceeds end".to_string());
        }
        if self.original_shards == 0 || self.parity_shards == 0 {
            return Err("DA redundancy epoch shard counts cannot be zero".to_string());
        }
        ensure_bps(
            self.min_availability_quorum_bps,
            "DA redundancy epoch availability quorum",
        )?;
        ensure_bps(
            self.sampling_quorum_bps,
            "DA redundancy epoch sampling quorum",
        )?;
        ensure_status(
            &self.status,
            VALID_MARKET_RECORD_STATUSES,
            "DA redundancy epoch status",
        )?;
        let expected_id = da_redundancy_epoch_id(
            self.epoch_index,
            self.start_height,
            self.end_height,
            self.original_shards,
            self.parity_shards,
            &self.random_seed,
        );
        if self.epoch_id != expected_id {
            return Err("DA redundancy epoch id mismatch".to_string());
        }
        Ok(self.epoch_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LightClientSamplingWindow {
    pub window_id: String,
    pub blob_id: String,
    pub requester_commitment: String,
    pub start_height: u64,
    pub end_height: u64,
    pub sample_count: u64,
    pub min_receipts: u64,
    pub request_root: String,
    pub receipt_root: String,
    pub missing_shard_root: String,
    pub finality_height: u64,
    pub status: String,
}

impl LightClientSamplingWindow {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        blob_id: impl Into<String>,
        requester_commitment: impl Into<String>,
        start_height: u64,
        end_height: u64,
        sample_count: u64,
        min_receipts: u64,
        request_root: impl Into<String>,
        receipt_root: impl Into<String>,
        missing_shard_root: impl Into<String>,
        finality_height: u64,
    ) -> DaSamplingMarketResult<Self> {
        let blob_id = blob_id.into();
        let requester_commitment = requester_commitment.into();
        let request_root = request_root.into();
        let receipt_root = receipt_root.into();
        let missing_shard_root = missing_shard_root.into();
        let window_id = da_light_client_sampling_window_id(
            &blob_id,
            &requester_commitment,
            start_height,
            end_height,
            sample_count,
        );
        let window = Self {
            window_id,
            blob_id,
            requester_commitment,
            start_height,
            end_height,
            sample_count,
            min_receipts,
            request_root,
            receipt_root,
            missing_shard_root,
            finality_height,
            status: DA_SAMPLING_STATUS_OPEN.to_string(),
        };
        window.validate()?;
        Ok(window)
    }

    pub fn contains_height(&self, height: u64) -> bool {
        height >= self.start_height && height <= self.end_height
    }

    pub fn is_expired_at(&self, height: u64) -> bool {
        height > self.end_height
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "light_client_sampling_window",
            "chain_id": CHAIN_ID,
            "protocol_version": DA_SAMPLING_MARKET_PROTOCOL_VERSION,
            "window_id": self.window_id,
            "blob_id": self.blob_id,
            "requester_commitment": self.requester_commitment,
            "start_height": self.start_height,
            "end_height": self.end_height,
            "sample_count": self.sample_count,
            "min_receipts": self.min_receipts,
            "request_root": self.request_root,
            "receipt_root": self.receipt_root,
            "missing_shard_root": self.missing_shard_root,
            "finality_height": self.finality_height,
            "status": self.status,
        })
    }

    pub fn window_root(&self) -> String {
        da_sampling_market_payload_root(
            "DA-SAMPLING-MARKET-LIGHT-CLIENT-WINDOW",
            &self.public_record_without_root(),
        )
    }

    pub fn public_record(&self) -> Value {
        with_root_field(
            self.public_record_without_root(),
            "window_root",
            self.window_root(),
        )
    }

    pub fn validate(&self) -> DaSamplingMarketResult<String> {
        ensure_non_empty(&self.window_id, "light-client sampling window id")?;
        ensure_non_empty(&self.blob_id, "light-client sampling window blob id")?;
        ensure_non_empty(
            &self.requester_commitment,
            "light-client sampling window requester",
        )?;
        ensure_non_empty(
            &self.request_root,
            "light-client sampling window request root",
        )?;
        ensure_non_empty(
            &self.receipt_root,
            "light-client sampling window receipt root",
        )?;
        ensure_non_empty(
            &self.missing_shard_root,
            "light-client sampling window missing root",
        )?;
        if self.start_height >= self.end_height {
            return Err("light-client sampling window start must precede end".to_string());
        }
        if self.finality_height < self.end_height {
            return Err("light-client sampling finality precedes window end".to_string());
        }
        if self.sample_count == 0 || self.min_receipts == 0 {
            return Err("light-client sampling counts cannot be zero".to_string());
        }
        if self.min_receipts > self.sample_count {
            return Err("light-client sampling min receipts exceed sample count".to_string());
        }
        ensure_status(
            &self.status,
            VALID_REQUEST_STATUSES,
            "light-client window status",
        )?;
        let expected_id = da_light_client_sampling_window_id(
            &self.blob_id,
            &self.requester_commitment,
            self.start_height,
            self.end_height,
            self.sample_count,
        );
        if self.window_id != expected_id {
            return Err("light-client sampling window id mismatch".to_string());
        }
        Ok(self.window_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DaPricingQuote {
    pub quote_id: String,
    pub pricing_model_id: String,
    pub lane_key: String,
    pub blob_class: DaBlobClass,
    pub payload_bytes: u64,
    pub encoded_bytes: u64,
    pub sample_count: u64,
    pub retention_blocks: u64,
    pub gross_fee_microunits: u64,
    pub sponsor_discount_microunits: u64,
    pub net_fee_microunits: u64,
    pub fee_asset_id: String,
    pub payer_commitment: String,
    pub pricing_root: String,
    pub created_at_height: u64,
    pub expires_at_height: u64,
    pub status: String,
}

impl DaPricingQuote {
    #[allow(clippy::too_many_arguments)]
    pub fn from_model(
        model: &LowFeeDaPricingModel,
        payload_bytes: u64,
        encoded_bytes: u64,
        sample_count: u64,
        retention_blocks: u64,
        payer_commitment: &str,
        current_height: u64,
        ttl_blocks: u64,
    ) -> DaSamplingMarketResult<Self> {
        if payload_bytes > model.max_blob_bytes {
            return Err("DA quote payload exceeds lane max blob bytes".to_string());
        }
        if sample_count == 0 || sample_count > model.max_sample_count {
            return Err("DA quote sample count is invalid for lane".to_string());
        }
        let gross_fee = model.raw_fee_microunits(encoded_bytes, sample_count, retention_blocks);
        let sponsor_discount = mul_div_floor(gross_fee, model.sponsor_rebate_bps, 10_000);
        let net_fee = gross_fee.saturating_sub(sponsor_discount);
        let pricing_root = model.pricing_model_root();
        let quote_id = da_pricing_quote_id(
            &model.pricing_model_id,
            payer_commitment,
            payload_bytes,
            encoded_bytes,
            current_height,
            &pricing_root,
        );
        let quote = Self {
            quote_id,
            pricing_model_id: model.pricing_model_id.clone(),
            lane_key: model.lane_key.clone(),
            blob_class: model.blob_class,
            payload_bytes,
            encoded_bytes,
            sample_count,
            retention_blocks,
            gross_fee_microunits: gross_fee,
            sponsor_discount_microunits: sponsor_discount,
            net_fee_microunits: net_fee,
            fee_asset_id: model.fee_asset_id.clone(),
            payer_commitment: payer_commitment.to_string(),
            pricing_root,
            created_at_height: current_height,
            expires_at_height: current_height.saturating_add(ttl_blocks),
            status: DA_SAMPLING_STATUS_OPEN.to_string(),
        };
        quote.validate()?;
        Ok(quote)
    }

    pub fn is_expired_at(&self, height: u64) -> bool {
        height > self.expires_at_height
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "da_pricing_quote",
            "chain_id": CHAIN_ID,
            "protocol_version": DA_SAMPLING_MARKET_PROTOCOL_VERSION,
            "quote_id": self.quote_id,
            "pricing_model_id": self.pricing_model_id,
            "lane_key": self.lane_key,
            "blob_class": self.blob_class.as_str(),
            "payload_bytes": self.payload_bytes,
            "encoded_bytes": self.encoded_bytes,
            "sample_count": self.sample_count,
            "retention_blocks": self.retention_blocks,
            "gross_fee_microunits": self.gross_fee_microunits,
            "sponsor_discount_microunits": self.sponsor_discount_microunits,
            "net_fee_microunits": self.net_fee_microunits,
            "fee_asset_id": self.fee_asset_id,
            "payer_commitment": self.payer_commitment,
            "pricing_root": self.pricing_root,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status,
        })
    }

    pub fn quote_root(&self) -> String {
        da_sampling_market_payload_root(
            "DA-SAMPLING-MARKET-PRICING-QUOTE",
            &self.public_record_without_root(),
        )
    }

    pub fn public_record(&self) -> Value {
        with_root_field(
            self.public_record_without_root(),
            "quote_root",
            self.quote_root(),
        )
    }

    pub fn validate(&self) -> DaSamplingMarketResult<String> {
        ensure_non_empty(&self.quote_id, "DA pricing quote id")?;
        ensure_non_empty(&self.pricing_model_id, "DA pricing quote model id")?;
        ensure_non_empty(&self.lane_key, "DA pricing quote lane key")?;
        ensure_non_empty(&self.fee_asset_id, "DA pricing quote fee asset id")?;
        ensure_non_empty(&self.payer_commitment, "DA pricing quote payer commitment")?;
        ensure_non_empty(&self.pricing_root, "DA pricing quote pricing root")?;
        if self.payload_bytes == 0 || self.encoded_bytes == 0 {
            return Err("DA pricing quote byte counts cannot be zero".to_string());
        }
        if self.encoded_bytes < self.payload_bytes {
            return Err("DA pricing quote encoded bytes below payload bytes".to_string());
        }
        if self.sample_count == 0 {
            return Err("DA pricing quote sample count cannot be zero".to_string());
        }
        if self.expires_at_height <= self.created_at_height {
            return Err("DA pricing quote expiry precedes creation".to_string());
        }
        if self.sponsor_discount_microunits > self.gross_fee_microunits {
            return Err("DA pricing quote sponsor discount exceeds gross fee".to_string());
        }
        if self.net_fee_microunits
            != self
                .gross_fee_microunits
                .saturating_sub(self.sponsor_discount_microunits)
        {
            return Err("DA pricing quote net fee mismatch".to_string());
        }
        ensure_status(
            &self.status,
            VALID_REQUEST_STATUSES,
            "DA pricing quote status",
        )?;
        let expected_id = da_pricing_quote_id(
            &self.pricing_model_id,
            &self.payer_commitment,
            self.payload_bytes,
            self.encoded_bytes,
            self.created_at_height,
            &self.pricing_root,
        );
        if self.quote_id != expected_id {
            return Err("DA pricing quote id mismatch".to_string());
        }
        Ok(self.quote_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DaSlashingSettlement {
    pub settlement_id: String,
    pub evidence_id: String,
    pub blob_id: String,
    pub accused_node_id: String,
    pub reporter_commitment: String,
    pub slash_units: u64,
    pub reporter_reward_units: u64,
    pub sponsor_refund_units: u64,
    pub burn_units: u64,
    pub settled_at_height: u64,
    pub settlement_root: String,
    pub status: String,
}

impl DaSlashingSettlement {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        evidence: &WithheldShardEvidence,
        accused_bond_units: u64,
        reporter_reward_bps: u64,
        sponsor_refund_bps: u64,
        settled_at_height: u64,
    ) -> DaSamplingMarketResult<Self> {
        ensure_bps(reporter_reward_bps, "DA slashing reporter reward")?;
        ensure_bps(sponsor_refund_bps, "DA slashing sponsor refund")?;
        let slash_units = mul_div_floor(accused_bond_units, evidence.severity_bps, 10_000);
        let reporter_reward_units = mul_div_floor(slash_units, reporter_reward_bps, 10_000);
        let sponsor_refund_units = mul_div_floor(slash_units, sponsor_refund_bps, 10_000);
        let burn_units = slash_units
            .saturating_sub(reporter_reward_units)
            .saturating_sub(sponsor_refund_units);
        let settlement_root = da_sampling_market_payload_root(
            "DA-SAMPLING-MARKET-SLASHING-SETTLEMENT-PREIMAGE",
            &json!({
                "evidence_id": evidence.evidence_id,
                "slash_units": slash_units,
                "reporter_reward_units": reporter_reward_units,
                "sponsor_refund_units": sponsor_refund_units,
                "burn_units": burn_units,
                "settled_at_height": settled_at_height,
            }),
        );
        let settlement_id = da_slashing_settlement_id(
            &evidence.evidence_id,
            &evidence.accused_node_id,
            slash_units,
            settled_at_height,
            &settlement_root,
        );
        let settlement = Self {
            settlement_id,
            evidence_id: evidence.evidence_id.clone(),
            blob_id: evidence.blob_id.clone(),
            accused_node_id: evidence.accused_node_id.clone(),
            reporter_commitment: evidence.reporter_commitment.clone(),
            slash_units,
            reporter_reward_units,
            sponsor_refund_units,
            burn_units,
            settled_at_height,
            settlement_root,
            status: DA_SAMPLING_STATUS_SETTLED.to_string(),
        };
        settlement.validate()?;
        Ok(settlement)
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "da_slashing_settlement",
            "chain_id": CHAIN_ID,
            "protocol_version": DA_SAMPLING_MARKET_PROTOCOL_VERSION,
            "settlement_id": self.settlement_id,
            "evidence_id": self.evidence_id,
            "blob_id": self.blob_id,
            "accused_node_id": self.accused_node_id,
            "reporter_commitment": self.reporter_commitment,
            "slash_units": self.slash_units,
            "reporter_reward_units": self.reporter_reward_units,
            "sponsor_refund_units": self.sponsor_refund_units,
            "burn_units": self.burn_units,
            "settled_at_height": self.settled_at_height,
            "settlement_root": self.settlement_root,
            "status": self.status,
        })
    }

    pub fn slashing_settlement_root(&self) -> String {
        da_sampling_market_payload_root(
            "DA-SAMPLING-MARKET-SLASHING-SETTLEMENT",
            &self.public_record_without_root(),
        )
    }

    pub fn public_record(&self) -> Value {
        with_root_field(
            self.public_record_without_root(),
            "slashing_settlement_root",
            self.slashing_settlement_root(),
        )
    }

    pub fn validate(&self) -> DaSamplingMarketResult<String> {
        ensure_non_empty(&self.settlement_id, "DA slashing settlement id")?;
        ensure_non_empty(&self.evidence_id, "DA slashing settlement evidence id")?;
        ensure_non_empty(&self.blob_id, "DA slashing settlement blob id")?;
        ensure_non_empty(
            &self.accused_node_id,
            "DA slashing settlement accused node id",
        )?;
        ensure_non_empty(
            &self.reporter_commitment,
            "DA slashing settlement reporter commitment",
        )?;
        ensure_non_empty(&self.settlement_root, "DA slashing settlement root")?;
        if self
            .reporter_reward_units
            .saturating_add(self.sponsor_refund_units)
            > self.slash_units
        {
            return Err("DA slashing settlement payouts exceed slash".to_string());
        }
        if self.burn_units
            != self
                .slash_units
                .saturating_sub(self.reporter_reward_units)
                .saturating_sub(self.sponsor_refund_units)
        {
            return Err("DA slashing settlement burn mismatch".to_string());
        }
        ensure_status(
            &self.status,
            VALID_SETTLEMENT_STATUSES,
            "DA slashing settlement status",
        )?;
        let expected_id = da_slashing_settlement_id(
            &self.evidence_id,
            &self.accused_node_id,
            self.slash_units,
            self.settled_at_height,
            &self.settlement_root,
        );
        if self.settlement_id != expected_id {
            return Err("DA slashing settlement id mismatch".to_string());
        }
        Ok(self.slashing_settlement_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DaSamplingMarketPublicRecord {
    pub record_id: String,
    pub record_kind: String,
    pub subject_id: String,
    pub height: u64,
    pub state_root: String,
    pub payload_root: String,
    pub summary: String,
    pub status: String,
}

impl DaSamplingMarketPublicRecord {
    pub fn new(
        record_kind: impl Into<String>,
        subject_id: impl Into<String>,
        height: u64,
        state_root: impl Into<String>,
        payload_root: impl Into<String>,
        summary: impl Into<String>,
    ) -> DaSamplingMarketResult<Self> {
        let record_kind = record_kind.into();
        let subject_id = subject_id.into();
        let state_root = state_root.into();
        let payload_root = payload_root.into();
        let summary = summary.into();
        let record_id =
            da_sampling_market_public_record_id(&record_kind, &subject_id, height, &payload_root);
        let record = Self {
            record_id,
            record_kind,
            subject_id,
            height,
            state_root,
            payload_root,
            summary,
            status: DA_SAMPLING_STATUS_ACTIVE.to_string(),
        };
        record.validate()?;
        Ok(record)
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "da_sampling_market_public_record",
            "chain_id": CHAIN_ID,
            "protocol_version": DA_SAMPLING_MARKET_PROTOCOL_VERSION,
            "record_id": self.record_id,
            "record_kind": self.record_kind,
            "subject_id": self.subject_id,
            "height": self.height,
            "state_root": self.state_root,
            "payload_root": self.payload_root,
            "summary": self.summary,
            "status": self.status,
        })
    }

    pub fn record_root(&self) -> String {
        da_sampling_market_payload_root(
            "DA-SAMPLING-MARKET-PUBLIC-RECORD",
            &self.public_record_without_root(),
        )
    }

    pub fn public_record(&self) -> Value {
        with_root_field(
            self.public_record_without_root(),
            "record_root",
            self.record_root(),
        )
    }

    pub fn validate(&self) -> DaSamplingMarketResult<String> {
        ensure_non_empty(&self.record_id, "DA sampling market public record id")?;
        ensure_non_empty(&self.record_kind, "DA sampling market public record kind")?;
        ensure_non_empty(&self.subject_id, "DA sampling market public record subject")?;
        ensure_non_empty(
            &self.state_root,
            "DA sampling market public record state root",
        )?;
        ensure_non_empty(
            &self.payload_root,
            "DA sampling market public record payload root",
        )?;
        ensure_non_empty(&self.summary, "DA sampling market public record summary")?;
        ensure_status(
            &self.status,
            VALID_MARKET_RECORD_STATUSES,
            "DA sampling market public record status",
        )?;
        let expected_id = da_sampling_market_public_record_id(
            &self.record_kind,
            &self.subject_id,
            self.height,
            &self.payload_root,
        );
        if self.record_id != expected_id {
            return Err("DA sampling market public record id mismatch".to_string());
        }
        Ok(self.record_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DaSamplingMarketState {
    pub current_height: u64,
    pub status: String,
    pub config: DaSamplingMarketConfig,
    pub current_epoch_id: String,
    pub pricing_models: BTreeMap<String, LowFeeDaPricingModel>,
    pub blob_manifests: BTreeMap<String, DaBlobManifest>,
    pub shard_commitments: BTreeMap<String, DaErasureShardCommitment>,
    pub committee_nodes: BTreeMap<String, DaCommitteeNode>,
    pub committee_attestations: BTreeMap<String, DaCommitteeAttestation>,
    pub sample_requests: BTreeMap<String, DaSampleRequest>,
    pub sample_receipts: BTreeMap<String, DaSampleReceipt>,
    pub sponsorships: BTreeMap<String, DaBlobSponsorship>,
    pub withheld_evidence: BTreeMap<String, WithheldShardEvidence>,
    pub redundancy_epochs: BTreeMap<String, DaRedundancyEpoch>,
    pub sampling_windows: BTreeMap<String, LightClientSamplingWindow>,
    pub pricing_quotes: BTreeMap<String, DaPricingQuote>,
    pub slashing_settlements: BTreeMap<String, DaSlashingSettlement>,
    pub public_records: BTreeMap<String, DaSamplingMarketPublicRecord>,
}

impl Default for DaSamplingMarketState {
    fn default() -> Self {
        Self::new()
    }
}

impl DaSamplingMarketState {
    pub fn new() -> Self {
        let mut state = Self::empty(0);
        for blob_class in [
            DaBlobClass::PrivateTransfer,
            DaBlobClass::MoneroBridge,
            DaBlobClass::TokenTransfer,
            DaBlobClass::DefiSwap,
            DaBlobClass::Lending,
            DaBlobClass::ContractCall,
            DaBlobClass::RollupStateDiff,
            DaBlobClass::ProofBundle,
            DaBlobClass::Governance,
            DaBlobClass::ArchiveReplay,
            DaBlobClass::Emergency,
        ] {
            let model =
                LowFeeDaPricingModel::devnet(blob_class, &state.config.default_fee_asset_id);
            state
                .pricing_models
                .insert(model.pricing_model_id.clone(), model);
        }
        state
    }

    pub fn empty(current_height: u64) -> Self {
        Self {
            current_height,
            status: DA_SAMPLING_STATUS_ACTIVE.to_string(),
            config: DaSamplingMarketConfig::default(),
            current_epoch_id: String::new(),
            pricing_models: BTreeMap::new(),
            blob_manifests: BTreeMap::new(),
            shard_commitments: BTreeMap::new(),
            committee_nodes: BTreeMap::new(),
            committee_attestations: BTreeMap::new(),
            sample_requests: BTreeMap::new(),
            sample_receipts: BTreeMap::new(),
            sponsorships: BTreeMap::new(),
            withheld_evidence: BTreeMap::new(),
            redundancy_epochs: BTreeMap::new(),
            sampling_windows: BTreeMap::new(),
            pricing_quotes: BTreeMap::new(),
            slashing_settlements: BTreeMap::new(),
            public_records: BTreeMap::new(),
        }
    }

    pub fn devnet() -> DaSamplingMarketResult<Self> {
        let mut state = Self::new();
        state.set_height(96)?;

        for (index, role) in [
            DaCommitteeRole::Encoder,
            DaCommitteeRole::Sampler,
            DaCommitteeRole::Attester,
            DaCommitteeRole::ArchiveProvider,
            DaCommitteeRole::Watchtower,
        ]
        .into_iter()
        .enumerate()
        {
            state.register_committee_node(DaCommitteeNode::devnet(index as u64, role))?;
        }

        let committee_root = state.committee_node_root();
        let pricing_root = state.pricing_model_root();
        let epoch = DaRedundancyEpoch::new(
            0,
            0,
            DA_SAMPLING_MARKET_DEFAULT_EPOCH_LENGTH_BLOCKS - 1,
            DA_SAMPLING_MARKET_DEFAULT_ORIGINAL_SHARDS,
            DA_SAMPLING_MARKET_DEFAULT_PARITY_SHARDS,
            state.config.committee_quorum_bps,
            state.config.sampling_quorum_bps,
            committee_root,
            pricing_root,
            devnet_hash("DA-SAMPLING-MARKET-DEVNET-EPOCH-SEED", "epoch-0"),
        )?;
        let epoch_id = epoch.epoch_id.clone();
        state.apply_redundancy_epoch(epoch)?;
        state.current_epoch_id = epoch_id.clone();

        let foundation_sponsorship = DaBlobSponsorship::new(
            da_account_commitment("devnet-foundation"),
            "foundation",
            DaBlobClass::PrivateTransfer.default_lane_key(),
            DaBlobClass::PrivateTransfer,
            &state.config.default_fee_asset_id,
            2_000_000,
            8_500,
            90_000,
            &json!({"purpose": "private transfers and low-fee onboarding"}),
            devnet_hash("DA-SAMPLING-MARKET-DEVNET-SPONSOR-NULLIFIER", "foundation"),
            0,
            720,
        )?;
        let bridge_sponsorship = DaBlobSponsorship::new(
            da_account_commitment("devnet-bridge-guild"),
            "bridge_guild",
            DaBlobClass::MoneroBridge.default_lane_key(),
            DaBlobClass::MoneroBridge,
            &state.config.default_fee_asset_id,
            1_500_000,
            9_000,
            120_000,
            &json!({"purpose": "monero bridge proofs and fast withdrawals"}),
            devnet_hash("DA-SAMPLING-MARKET-DEVNET-SPONSOR-NULLIFIER", "bridge"),
            0,
            720,
        )?;
        let contract_sponsorship = DaBlobSponsorship::new(
            da_account_commitment("devnet-contract-guild"),
            "contract_guild",
            DaBlobClass::ContractCall.default_lane_key(),
            DaBlobClass::ContractCall,
            &state.config.default_fee_asset_id,
            900_000,
            7_500,
            60_000,
            &json!({"purpose": "sealed contract call DA"}),
            devnet_hash("DA-SAMPLING-MARKET-DEVNET-SPONSOR-NULLIFIER", "contract"),
            0,
            720,
        )?;
        let foundation_sponsorship_id = foundation_sponsorship.sponsorship_id.clone();
        let bridge_sponsorship_id = bridge_sponsorship.sponsorship_id.clone();
        let contract_sponsorship_id = contract_sponsorship.sponsorship_id.clone();
        state.open_sponsorship(foundation_sponsorship)?;
        state.open_sponsorship(bridge_sponsorship)?;
        state.open_sponsorship(contract_sponsorship)?;

        let private_quote = state.quote_blob(
            DaBlobClass::PrivateTransfer.default_lane_key(),
            48 * 1024,
            encoded_blob_size(
                48 * 1024,
                DA_SAMPLING_MARKET_DEFAULT_ORIGINAL_SHARDS,
                DA_SAMPLING_MARKET_DEFAULT_PARITY_SHARDS,
            ),
            DaBlobClass::PrivateTransfer.default_sample_count(),
            DaBlobClass::PrivateTransfer.default_retention_blocks(),
            &da_account_commitment("alice-devnet"),
            16,
        )?;
        let bridge_quote = state.quote_blob(
            DaBlobClass::MoneroBridge.default_lane_key(),
            96 * 1024,
            encoded_blob_size(
                96 * 1024,
                DA_SAMPLING_MARKET_DEFAULT_ORIGINAL_SHARDS,
                DA_SAMPLING_MARKET_DEFAULT_PARITY_SHARDS,
            ),
            DaBlobClass::MoneroBridge.default_sample_count(),
            DaBlobClass::MoneroBridge.default_retention_blocks(),
            &da_account_commitment("bridge-user-devnet"),
            16,
        )?;
        let contract_quote = state.quote_blob(
            DaBlobClass::ContractCall.default_lane_key(),
            72 * 1024,
            encoded_blob_size(
                72 * 1024,
                DA_SAMPLING_MARKET_DEFAULT_ORIGINAL_SHARDS,
                DA_SAMPLING_MARKET_DEFAULT_PARITY_SHARDS,
            ),
            DaBlobClass::ContractCall.default_sample_count(),
            DaBlobClass::ContractCall.default_retention_blocks(),
            &da_account_commitment("solver-devnet"),
            16,
        )?;

        let private_blob_id = da_blob_manifest_id(
            "devnet-rollup-batch-private",
            "devnet-sequencer",
            DaBlobClass::PrivateTransfer.default_lane_key(),
            DaBlobClass::PrivateTransfer,
            &devnet_hash("DA-SAMPLING-MARKET-DEVNET-BLOB-PAYLOAD", "private"),
            48 * 1024,
            12,
        );
        let private_shards = devnet_shards_for_blob(
            &private_blob_id,
            DaBlobClass::PrivateTransfer.default_lane_key(),
            DA_SAMPLING_MARKET_DEFAULT_ORIGINAL_SHARDS,
            DA_SAMPLING_MARKET_DEFAULT_PARITY_SHARDS,
        )?;
        let private_shard_root = da_erasure_shard_commitment_root(&private_shards);
        let mut private_blob = DaBlobManifest::devnet(
            "private",
            DaBlobClass::PrivateTransfer.default_lane_key(),
            DaBlobClass::PrivateTransfer,
            DaPrivacyMode::FullyPrivate,
            48 * 1024,
            12,
            &private_shard_root,
            &foundation_sponsorship_id,
            &private_quote.quote_id,
        );
        private_blob.blob_id = private_blob_id;
        private_blob.validate()?;
        let private_blob_id = private_blob.blob_id.clone();
        state.publish_blob(private_blob)?;
        state.insert_shards(private_shards)?;

        let bridge_blob_id = da_blob_manifest_id(
            "devnet-rollup-batch-bridge",
            "devnet-sequencer",
            DaBlobClass::MoneroBridge.default_lane_key(),
            DaBlobClass::MoneroBridge,
            &devnet_hash("DA-SAMPLING-MARKET-DEVNET-BLOB-PAYLOAD", "bridge"),
            96 * 1024,
            40,
        );
        let bridge_shards = devnet_shards_for_blob(
            &bridge_blob_id,
            DaBlobClass::MoneroBridge.default_lane_key(),
            DA_SAMPLING_MARKET_DEFAULT_ORIGINAL_SHARDS,
            DA_SAMPLING_MARKET_DEFAULT_PARITY_SHARDS,
        )?;
        let bridge_shard_root = da_erasure_shard_commitment_root(&bridge_shards);
        let mut bridge_blob = DaBlobManifest::devnet(
            "bridge",
            DaBlobClass::MoneroBridge.default_lane_key(),
            DaBlobClass::MoneroBridge,
            DaPrivacyMode::ThresholdEncrypted,
            96 * 1024,
            40,
            &bridge_shard_root,
            &bridge_sponsorship_id,
            &bridge_quote.quote_id,
        );
        bridge_blob.blob_id = bridge_blob_id;
        bridge_blob.validate()?;
        let bridge_blob_id = bridge_blob.blob_id.clone();
        state.publish_blob(bridge_blob)?;
        state.insert_shards(bridge_shards)?;

        let contract_blob_id = da_blob_manifest_id(
            "devnet-rollup-batch-contract",
            "devnet-sequencer",
            DaBlobClass::ContractCall.default_lane_key(),
            DaBlobClass::ContractCall,
            &devnet_hash("DA-SAMPLING-MARKET-DEVNET-BLOB-PAYLOAD", "contract"),
            72 * 1024,
            48,
        );
        let contract_shards = devnet_shards_for_blob(
            &contract_blob_id,
            DaBlobClass::ContractCall.default_lane_key(),
            DA_SAMPLING_MARKET_DEFAULT_ORIGINAL_SHARDS,
            DA_SAMPLING_MARKET_DEFAULT_PARITY_SHARDS,
        )?;
        let contract_shard_root = da_erasure_shard_commitment_root(&contract_shards);
        let mut contract_blob = DaBlobManifest::devnet(
            "contract",
            DaBlobClass::ContractCall.default_lane_key(),
            DaBlobClass::ContractCall,
            DaPrivacyMode::CommitmentOnly,
            72 * 1024,
            48,
            &contract_shard_root,
            &contract_sponsorship_id,
            &contract_quote.quote_id,
        );
        contract_blob.blob_id = contract_blob_id;
        contract_blob.validate()?;
        let contract_blob_id = contract_blob.blob_id.clone();
        state.publish_blob(contract_blob)?;
        state.insert_shards(contract_shards)?;

        for blob_id in [&private_blob_id, &bridge_blob_id, &contract_blob_id] {
            let blob = state
                .blob_manifests
                .get(blob_id)
                .ok_or_else(|| "devnet blob missing before attestation".to_string())?
                .clone();
            let node = state
                .committee_nodes
                .values()
                .find(|node| matches!(node.role, DaCommitteeRole::Attester))
                .ok_or_else(|| "devnet attester node missing".to_string())?
                .clone();
            let sample_indices = derive_da_sampling_market_sample_indices(
                &blob.sample_seed,
                blob.total_shards(),
                blob.blob_class.default_sample_count(),
            )?;
            state.record_committee_attestation(DaCommitteeAttestation::new(
                &blob,
                &epoch_id,
                &node,
                sample_indices,
                blob.posted_at_height + 1,
                "sampled",
            )?)?;
        }

        let private_blob = state
            .blob_manifests
            .get(&private_blob_id)
            .ok_or_else(|| "devnet private blob missing".to_string())?
            .clone();
        let window = LightClientSamplingWindow::new(
            &private_blob.blob_id,
            da_account_commitment("wallet-light-client-devnet"),
            65,
            96,
            12,
            2,
            merkle_root("DA-SAMPLING-MARKET-EMPTY-REQUESTS", &[]),
            merkle_root("DA-SAMPLING-MARKET-EMPTY-RECEIPTS", &[]),
            merkle_root("DA-SAMPLING-MARKET-EMPTY-MISSING", &[]),
            104,
        )?;
        let window_id = window.window_id.clone();
        state.apply_sampling_window(window)?;

        let private_request = DaSampleRequest::new(
            &private_blob,
            da_account_commitment("wallet-light-client-devnet"),
            DaCommitteeRole::LightClient,
            12,
            66,
            96,
            8,
            4,
            &window_id,
        )?;
        let private_request_id = private_request.request_id.clone();
        state.request_samples(private_request)?;
        let sampler_node = state
            .committee_nodes
            .values()
            .find(|node| matches!(node.role, DaCommitteeRole::Sampler))
            .ok_or_else(|| "devnet sampler node missing".to_string())?
            .clone();
        let request = state
            .sample_requests
            .get(&private_request_id)
            .ok_or_else(|| "devnet private sample request missing".to_string())?
            .clone();
        let returned = request
            .sample_indices
            .iter()
            .copied()
            .take(10)
            .collect::<Vec<_>>();
        let missing = request
            .sample_indices
            .iter()
            .copied()
            .skip(10)
            .collect::<Vec<_>>();
        let receipt = DaSampleReceipt::new(
            &request,
            &sampler_node.node_id,
            returned,
            missing.clone(),
            68,
            8,
            devnet_hash("DA-SAMPLING-MARKET-DEVNET-SAMPLE-PROOF", "private"),
        )?;
        let receipt_id = receipt.receipt_id.clone();
        state.record_sample_receipt(receipt)?;

        let missing_shard_id = state
            .shard_commitments
            .values()
            .find(|shard| shard.blob_id == private_blob_id && missing.contains(&shard.shard_index))
            .map(|shard| shard.shard_id.clone())
            .ok_or_else(|| "devnet missing shard not found".to_string())?;
        let evidence = WithheldShardEvidence::new(
            WithheldShardEvidenceKind::MissingSample,
            &private_blob_id,
            missing_shard_id,
            da_account_commitment("watchtower-devnet"),
            &sampler_node.node_id,
            &private_request_id,
            &receipt_id,
            missing,
            69,
            101,
            &json!({
                "receipt_id": receipt_id,
                "non_response": "sampled shard opening not returned before challenge deadline"
            }),
            4,
        )?;
        let evidence_id = evidence.evidence_id.clone();
        state.submit_withheld_evidence(evidence)?;
        state.settle_withheld_evidence(&evidence_id, 70)?;

        let state_root = state.state_root();
        let market_record = DaSamplingMarketPublicRecord::new(
            "market_snapshot",
            "devnet-da-sampling-market",
            state.current_height,
            state_root.clone(),
            state.roots().roots_root(),
            "devnet DA sampling market covers low-fee private blobs, erasure shards, samples, sponsorships, and slashing",
        )?;
        state.publish_public_record(market_record)?;
        let blob_record = DaSamplingMarketPublicRecord::new(
            "private_blob",
            private_blob_id,
            state.current_height,
            state_root,
            state.blob_manifest_root(),
            "private transfer blob sampled by light client with withheld shard evidence",
        )?;
        state.publish_public_record(blob_record)?;

        state.validate()?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) -> DaSamplingMarketResult<String> {
        self.current_height = height;
        self.current_epoch_id = self
            .redundancy_epochs
            .values()
            .find(|epoch| epoch.contains_height(height))
            .map(|epoch| epoch.epoch_id.clone())
            .unwrap_or_default();
        for quote in self.pricing_quotes.values_mut() {
            if quote.is_expired_at(height) && quote.status == DA_SAMPLING_STATUS_OPEN {
                quote.status = DA_SAMPLING_STATUS_EXPIRED.to_string();
            }
        }
        for request in self.sample_requests.values_mut() {
            if request.is_expired_at(height) && request.status == DA_SAMPLING_STATUS_OPEN {
                request.status = DA_SAMPLING_STATUS_EXPIRED.to_string();
            }
        }
        for sponsorship in self.sponsorships.values_mut() {
            if sponsorship.is_expired_at(height)
                && matches!(
                    sponsorship.status.as_str(),
                    DA_SAMPLING_STATUS_ACTIVE | DA_SAMPLING_STATUS_SPONSORED
                )
            {
                sponsorship.status = DA_SAMPLING_STATUS_EXPIRED.to_string();
            }
        }
        for window in self.sampling_windows.values_mut() {
            if window.is_expired_at(height) && window.status == DA_SAMPLING_STATUS_OPEN {
                window.status = DA_SAMPLING_STATUS_EXPIRED.to_string();
            }
        }
        Ok(self.state_root())
    }

    pub fn set_status(&mut self, status: &str) -> DaSamplingMarketResult<String> {
        ensure_status(
            status,
            VALID_STATE_STATUSES,
            "DA sampling market state status",
        )?;
        self.status = status.to_string();
        Ok(self.state_root())
    }

    pub fn apply_pricing_model(
        &mut self,
        model: LowFeeDaPricingModel,
    ) -> DaSamplingMarketResult<String> {
        let root = model.validate()?;
        self.pricing_models
            .insert(model.pricing_model_id.clone(), model);
        Ok(root)
    }

    pub fn apply_redundancy_epoch(
        &mut self,
        epoch: DaRedundancyEpoch,
    ) -> DaSamplingMarketResult<String> {
        let root = epoch.validate()?;
        insert_unique_record(
            &mut self.redundancy_epochs,
            epoch.epoch_id.clone(),
            epoch,
            "DA redundancy epoch",
        )?;
        Ok(root)
    }

    pub fn register_committee_node(
        &mut self,
        node: DaCommitteeNode,
    ) -> DaSamplingMarketResult<String> {
        let root = node.validate()?;
        insert_unique_record(
            &mut self.committee_nodes,
            node.node_id.clone(),
            node,
            "DA committee node",
        )?;
        Ok(root)
    }

    pub fn open_sponsorship(
        &mut self,
        sponsorship: DaBlobSponsorship,
    ) -> DaSamplingMarketResult<String> {
        let root = sponsorship.validate()?;
        insert_unique_record(
            &mut self.sponsorships,
            sponsorship.sponsorship_id.clone(),
            sponsorship,
            "DA blob sponsorship",
        )?;
        Ok(root)
    }

    pub fn quote_blob(
        &mut self,
        lane_key: &str,
        payload_bytes: u64,
        encoded_bytes: u64,
        sample_count: u64,
        retention_blocks: u64,
        payer_commitment: &str,
        ttl_blocks: u64,
    ) -> DaSamplingMarketResult<DaPricingQuote> {
        let model = self
            .pricing_models
            .values()
            .find(|model| model.lane_key == lane_key && model.status == DA_SAMPLING_STATUS_ACTIVE)
            .cloned()
            .ok_or_else(|| "DA pricing quote references unknown active lane".to_string())?;
        let quote = model.quote(
            payload_bytes,
            encoded_bytes,
            sample_count,
            retention_blocks,
            payer_commitment,
            self.current_height,
            ttl_blocks,
        )?;
        self.pricing_quotes
            .insert(quote.quote_id.clone(), quote.clone());
        Ok(quote)
    }

    pub fn publish_blob(&mut self, blob: DaBlobManifest) -> DaSamplingMarketResult<String> {
        let root = blob.validate()?;
        if !self
            .pricing_models
            .values()
            .any(|model| model.lane_key == blob.lane_key)
        {
            return Err("DA blob references unknown pricing lane".to_string());
        }
        if !blob.sponsorship_id.is_empty() && !self.sponsorships.contains_key(&blob.sponsorship_id)
        {
            return Err("DA blob references unknown sponsorship".to_string());
        }
        if !blob.pricing_quote_id.is_empty()
            && !self.pricing_quotes.contains_key(&blob.pricing_quote_id)
        {
            return Err("DA blob references unknown pricing quote".to_string());
        }
        insert_unique_record(
            &mut self.blob_manifests,
            blob.blob_id.clone(),
            blob,
            "DA blob manifest",
        )?;
        self.refresh_epoch_counters();
        Ok(root)
    }

    pub fn insert_shards(
        &mut self,
        shards: Vec<DaErasureShardCommitment>,
    ) -> DaSamplingMarketResult<String> {
        let mut last_root = merkle_root("DA-SAMPLING-MARKET-EMPTY-SHARDS", &[]);
        for shard in shards {
            last_root = self.insert_shard(shard)?;
        }
        Ok(last_root)
    }

    pub fn insert_shard(
        &mut self,
        shard: DaErasureShardCommitment,
    ) -> DaSamplingMarketResult<String> {
        let root = shard.validate()?;
        let blob = self
            .blob_manifests
            .get(&shard.blob_id)
            .ok_or_else(|| "DA shard references unknown blob".to_string())?;
        if blob.lane_key != shard.lane_key {
            return Err("DA shard lane key mismatch".to_string());
        }
        if shard.shard_index >= blob.total_shards() {
            return Err("DA shard index exceeds blob shard count".to_string());
        }
        if shard.is_parity != (shard.shard_index >= blob.original_shards) {
            return Err("DA shard parity flag mismatch".to_string());
        }
        insert_unique_record(
            &mut self.shard_commitments,
            shard.shard_id.clone(),
            shard,
            "DA erasure shard",
        )?;
        Ok(root)
    }

    pub fn record_committee_attestation(
        &mut self,
        attestation: DaCommitteeAttestation,
    ) -> DaSamplingMarketResult<String> {
        let root = attestation.validate()?;
        let blob = self
            .blob_manifests
            .get(&attestation.blob_id)
            .ok_or_else(|| "DA attestation references unknown blob".to_string())?;
        if !self.redundancy_epochs.contains_key(&attestation.epoch_id) {
            return Err("DA attestation references unknown redundancy epoch".to_string());
        }
        let node = self
            .committee_nodes
            .get(&attestation.node_id)
            .ok_or_else(|| "DA attestation references unknown committee node".to_string())?;
        if !node.is_active_at(attestation.attested_at_height) {
            return Err("DA attestation node is not active at attestation height".to_string());
        }
        for index in &attestation.shard_indices {
            if *index >= blob.total_shards() {
                return Err("DA attestation shard index exceeds blob shard count".to_string());
            }
        }
        insert_unique_record(
            &mut self.committee_attestations,
            attestation.attestation_id.clone(),
            attestation,
            "DA committee attestation",
        )?;
        Ok(root)
    }

    pub fn apply_sampling_window(
        &mut self,
        window: LightClientSamplingWindow,
    ) -> DaSamplingMarketResult<String> {
        let root = window.validate()?;
        if !self.blob_manifests.contains_key(&window.blob_id) {
            return Err("light-client sampling window references unknown blob".to_string());
        }
        insert_unique_record(
            &mut self.sampling_windows,
            window.window_id.clone(),
            window,
            "light-client sampling window",
        )?;
        Ok(root)
    }

    pub fn request_samples(&mut self, request: DaSampleRequest) -> DaSamplingMarketResult<String> {
        let root = request.validate()?;
        let blob = self
            .blob_manifests
            .get(&request.blob_id)
            .ok_or_else(|| "DA sample request references unknown blob".to_string())?;
        for index in &request.sample_indices {
            if *index >= blob.total_shards() {
                return Err("DA sample request index exceeds blob shard count".to_string());
            }
        }
        if !request.light_client_window_id.is_empty()
            && !self
                .sampling_windows
                .contains_key(&request.light_client_window_id)
        {
            return Err("DA sample request references unknown light-client window".to_string());
        }
        insert_unique_record(
            &mut self.sample_requests,
            request.request_id.clone(),
            request,
            "DA sample request",
        )?;
        Ok(root)
    }

    pub fn record_sample_receipt(
        &mut self,
        receipt: DaSampleReceipt,
    ) -> DaSamplingMarketResult<String> {
        let root = receipt.validate()?;
        let request = self
            .sample_requests
            .get_mut(&receipt.request_id)
            .ok_or_else(|| "DA sample receipt references unknown request".to_string())?;
        if request.blob_id != receipt.blob_id {
            return Err("DA sample receipt blob mismatch".to_string());
        }
        if receipt.response_height > request.max_response_height {
            return Err("DA sample receipt arrived after max response height".to_string());
        }
        let requested = request
            .sample_indices
            .iter()
            .copied()
            .collect::<BTreeSet<_>>();
        for index in receipt
            .returned_indices
            .iter()
            .chain(receipt.missing_indices.iter())
        {
            if !requested.contains(index) {
                return Err("DA sample receipt contains unrequested index".to_string());
            }
        }
        if !self
            .committee_nodes
            .contains_key(&receipt.responder_node_id)
        {
            return Err("DA sample receipt references unknown responder".to_string());
        }
        request.status = if receipt.missing_indices.is_empty() {
            DA_SAMPLING_STATUS_ANSWERED.to_string()
        } else {
            DA_SAMPLING_STATUS_PARTIAL.to_string()
        };
        insert_unique_record(
            &mut self.sample_receipts,
            receipt.receipt_id.clone(),
            receipt,
            "DA sample receipt",
        )?;
        Ok(root)
    }

    pub fn submit_withheld_evidence(
        &mut self,
        evidence: WithheldShardEvidence,
    ) -> DaSamplingMarketResult<String> {
        let root = evidence.validate()?;
        if !self.blob_manifests.contains_key(&evidence.blob_id) {
            return Err("withheld evidence references unknown blob".to_string());
        }
        if !self.shard_commitments.contains_key(&evidence.shard_id) {
            return Err("withheld evidence references unknown shard".to_string());
        }
        if !self.committee_nodes.contains_key(&evidence.accused_node_id) {
            return Err("withheld evidence references unknown accused node".to_string());
        }
        if !self.sample_requests.contains_key(&evidence.request_id) {
            return Err("withheld evidence references unknown sample request".to_string());
        }
        if !self.sample_receipts.contains_key(&evidence.receipt_id) {
            return Err("withheld evidence references unknown sample receipt".to_string());
        }
        insert_unique_record(
            &mut self.withheld_evidence,
            evidence.evidence_id.clone(),
            evidence,
            "withheld shard evidence",
        )?;
        Ok(root)
    }

    pub fn settle_withheld_evidence(
        &mut self,
        evidence_id: &str,
        settled_at_height: u64,
    ) -> DaSamplingMarketResult<DaSlashingSettlement> {
        let evidence = self
            .withheld_evidence
            .get(evidence_id)
            .ok_or_else(|| "unknown withheld evidence".to_string())?
            .clone();
        let node = self
            .committee_nodes
            .get(&evidence.accused_node_id)
            .ok_or_else(|| "withheld evidence accused node missing".to_string())?
            .clone();
        let settlement = DaSlashingSettlement::new(
            &evidence,
            node.stake_bond_units,
            self.config.reporter_reward_bps,
            self.config.sponsor_refund_bps,
            settled_at_height,
        )?;
        if let Some(accused) = self.committee_nodes.get_mut(&evidence.accused_node_id) {
            accused.slash(settlement.slash_units);
        }
        if let Some(evidence) = self.withheld_evidence.get_mut(evidence_id) {
            evidence.status = DA_SAMPLING_STATUS_SETTLED.to_string();
        }
        self.slashing_settlements
            .insert(settlement.settlement_id.clone(), settlement.clone());
        Ok(settlement)
    }

    pub fn publish_public_record(
        &mut self,
        record: DaSamplingMarketPublicRecord,
    ) -> DaSamplingMarketResult<String> {
        let root = record.validate()?;
        insert_unique_record(
            &mut self.public_records,
            record.record_id.clone(),
            record,
            "DA sampling market public record",
        )?;
        Ok(root)
    }

    pub fn pricing_model_root(&self) -> String {
        low_fee_da_pricing_model_root(&self.pricing_models.values().cloned().collect::<Vec<_>>())
    }

    pub fn blob_manifest_root(&self) -> String {
        da_blob_manifest_root(&self.blob_manifests.values().cloned().collect::<Vec<_>>())
    }

    pub fn shard_commitment_root(&self) -> String {
        da_erasure_shard_commitment_root(
            &self.shard_commitments.values().cloned().collect::<Vec<_>>(),
        )
    }

    pub fn committee_node_root(&self) -> String {
        da_committee_node_root(&self.committee_nodes.values().cloned().collect::<Vec<_>>())
    }

    pub fn committee_attestation_root(&self) -> String {
        da_committee_attestation_root(
            &self
                .committee_attestations
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn sample_request_root(&self) -> String {
        da_sample_request_root(&self.sample_requests.values().cloned().collect::<Vec<_>>())
    }

    pub fn sample_receipt_root(&self) -> String {
        da_sample_receipt_root(&self.sample_receipts.values().cloned().collect::<Vec<_>>())
    }

    pub fn sponsorship_root(&self) -> String {
        da_blob_sponsorship_root(&self.sponsorships.values().cloned().collect::<Vec<_>>())
    }

    pub fn withheld_evidence_root(&self) -> String {
        withheld_shard_evidence_root(&self.withheld_evidence.values().cloned().collect::<Vec<_>>())
    }

    pub fn redundancy_epoch_root(&self) -> String {
        da_redundancy_epoch_root(&self.redundancy_epochs.values().cloned().collect::<Vec<_>>())
    }

    pub fn sampling_window_root(&self) -> String {
        light_client_sampling_window_root(
            &self.sampling_windows.values().cloned().collect::<Vec<_>>(),
        )
    }

    pub fn pricing_quote_root(&self) -> String {
        da_pricing_quote_root(&self.pricing_quotes.values().cloned().collect::<Vec<_>>())
    }

    pub fn slashing_settlement_root(&self) -> String {
        da_slashing_settlement_root(
            &self
                .slashing_settlements
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn public_record_root(&self) -> String {
        da_sampling_market_public_record_root(
            &self.public_records.values().cloned().collect::<Vec<_>>(),
        )
    }

    pub fn roots(&self) -> DaSamplingMarketRoots {
        DaSamplingMarketRoots {
            config_root: self.config.config_root(),
            pricing_model_root: self.pricing_model_root(),
            blob_manifest_root: self.blob_manifest_root(),
            shard_commitment_root: self.shard_commitment_root(),
            committee_node_root: self.committee_node_root(),
            committee_attestation_root: self.committee_attestation_root(),
            sample_request_root: self.sample_request_root(),
            sample_receipt_root: self.sample_receipt_root(),
            sponsorship_root: self.sponsorship_root(),
            withheld_evidence_root: self.withheld_evidence_root(),
            redundancy_epoch_root: self.redundancy_epoch_root(),
            sampling_window_root: self.sampling_window_root(),
            pricing_quote_root: self.pricing_quote_root(),
            slashing_settlement_root: self.slashing_settlement_root(),
            public_record_root: self.public_record_root(),
        }
    }

    pub fn counters(&self) -> DaSamplingMarketCounters {
        DaSamplingMarketCounters {
            pricing_model_count: self.pricing_models.len() as u64,
            blob_manifest_count: self.blob_manifests.len() as u64,
            shard_commitment_count: self.shard_commitments.len() as u64,
            committee_node_count: self.committee_nodes.len() as u64,
            committee_attestation_count: self.committee_attestations.len() as u64,
            sample_request_count: self.sample_requests.len() as u64,
            sample_receipt_count: self.sample_receipts.len() as u64,
            sponsorship_count: self.sponsorships.len() as u64,
            withheld_evidence_count: self.withheld_evidence.len() as u64,
            redundancy_epoch_count: self.redundancy_epochs.len() as u64,
            sampling_window_count: self.sampling_windows.len() as u64,
            pricing_quote_count: self.pricing_quotes.len() as u64,
            slashing_settlement_count: self.slashing_settlements.len() as u64,
            public_record_count: self.public_records.len() as u64,
            total_payload_bytes: self
                .blob_manifests
                .values()
                .map(|blob| blob.payload_bytes)
                .fold(0_u64, u64::saturating_add),
            total_encoded_bytes: self
                .blob_manifests
                .values()
                .map(|blob| blob.encoded_bytes)
                .fold(0_u64, u64::saturating_add),
            total_sampled_shards: self
                .sample_receipts
                .values()
                .map(|receipt| receipt.returned_indices.len() as u64)
                .fold(0_u64, u64::saturating_add),
            total_missing_shards: self
                .sample_receipts
                .values()
                .map(|receipt| receipt.missing_indices.len() as u64)
                .fold(0_u64, u64::saturating_add),
            total_gross_fee_microunits: self
                .pricing_quotes
                .values()
                .map(|quote| quote.gross_fee_microunits)
                .fold(0_u64, u64::saturating_add),
            total_net_fee_microunits: self
                .pricing_quotes
                .values()
                .map(|quote| quote.net_fee_microunits)
                .fold(0_u64, u64::saturating_add),
            total_sponsored_microunits: self
                .sponsorships
                .values()
                .map(|sponsorship| sponsorship.spent_microunits)
                .fold(0_u64, u64::saturating_add),
            total_slashed_units: self
                .slashing_settlements
                .values()
                .map(|settlement| settlement.slash_units)
                .fold(0_u64, u64::saturating_add),
        }
    }

    pub fn public_record_without_root(&self) -> Value {
        let roots = self.roots();
        let counters = self.counters();
        json!({
            "kind": "da_sampling_market_state",
            "chain_id": CHAIN_ID,
            "protocol_version": DA_SAMPLING_MARKET_PROTOCOL_VERSION,
            "current_height": self.current_height,
            "status": self.status,
            "current_epoch_id": self.current_epoch_id,
            "roots": roots.public_record(),
            "roots_root": roots.roots_root(),
            "counters": counters.public_record(),
            "counters_root": counters.counters_root(),
        })
    }

    pub fn state_root(&self) -> String {
        da_sampling_market_state_root_from_record(&self.public_record_without_root())
    }

    pub fn public_record(&self) -> Value {
        with_root_field(
            self.public_record_without_root(),
            "da_sampling_market_state_root",
            self.state_root(),
        )
    }

    pub fn validate(&self) -> DaSamplingMarketResult<String> {
        self.config.validate()?;
        ensure_status(
            &self.status,
            VALID_STATE_STATUSES,
            "DA sampling market state status",
        )?;
        for model in self.pricing_models.values() {
            model.validate()?;
        }
        for epoch in self.redundancy_epochs.values() {
            epoch.validate()?;
        }
        for node in self.committee_nodes.values() {
            node.validate()?;
        }
        for sponsorship in self.sponsorships.values() {
            sponsorship.validate()?;
            if !self
                .pricing_models
                .values()
                .any(|model| model.lane_key == sponsorship.lane_key)
            {
                return Err("DA sponsorship references unknown pricing lane".to_string());
            }
        }
        for quote in self.pricing_quotes.values() {
            quote.validate()?;
            if !self.pricing_models.contains_key(&quote.pricing_model_id) {
                return Err("DA pricing quote references unknown pricing model".to_string());
            }
        }
        for blob in self.blob_manifests.values() {
            blob.validate()?;
            if !self
                .pricing_models
                .values()
                .any(|model| model.lane_key == blob.lane_key)
            {
                return Err("DA blob references unknown pricing lane".to_string());
            }
            if !blob.pricing_quote_id.is_empty()
                && !self.pricing_quotes.contains_key(&blob.pricing_quote_id)
            {
                return Err("DA blob references unknown pricing quote".to_string());
            }
            if !blob.sponsorship_id.is_empty()
                && !self.sponsorships.contains_key(&blob.sponsorship_id)
            {
                return Err("DA blob references unknown sponsorship".to_string());
            }
            let shard_records = self
                .shard_commitments
                .values()
                .filter(|shard| shard.blob_id == blob.blob_id)
                .cloned()
                .collect::<Vec<_>>();
            if !shard_records.is_empty()
                && da_erasure_shard_commitment_root(&shard_records) != blob.shard_commitment_root
            {
                return Err("DA blob shard commitment root mismatch".to_string());
            }
        }
        for shard in self.shard_commitments.values() {
            shard.validate()?;
            let blob = self
                .blob_manifests
                .get(&shard.blob_id)
                .ok_or_else(|| "DA shard references unknown blob".to_string())?;
            if shard.shard_index >= blob.total_shards() {
                return Err("DA shard index exceeds blob shard count".to_string());
            }
            if !self.committee_nodes.contains_key(&shard.provider_node_id) {
                return Err("DA shard references unknown provider node".to_string());
            }
        }
        for attestation in self.committee_attestations.values() {
            attestation.validate()?;
            if !self.blob_manifests.contains_key(&attestation.blob_id) {
                return Err("DA attestation references unknown blob".to_string());
            }
            if !self.redundancy_epochs.contains_key(&attestation.epoch_id) {
                return Err("DA attestation references unknown redundancy epoch".to_string());
            }
            if !self.committee_nodes.contains_key(&attestation.node_id) {
                return Err("DA attestation references unknown committee node".to_string());
            }
        }
        for window in self.sampling_windows.values() {
            window.validate()?;
            if !self.blob_manifests.contains_key(&window.blob_id) {
                return Err("DA sampling window references unknown blob".to_string());
            }
        }
        for request in self.sample_requests.values() {
            request.validate()?;
            let blob = self
                .blob_manifests
                .get(&request.blob_id)
                .ok_or_else(|| "DA sample request references unknown blob".to_string())?;
            for index in &request.sample_indices {
                if *index >= blob.total_shards() {
                    return Err("DA sample request index exceeds blob shard count".to_string());
                }
            }
        }
        for receipt in self.sample_receipts.values() {
            receipt.validate()?;
            let request = self
                .sample_requests
                .get(&receipt.request_id)
                .ok_or_else(|| "DA sample receipt references unknown request".to_string())?;
            if request.blob_id != receipt.blob_id {
                return Err("DA sample receipt blob mismatch".to_string());
            }
            if !self
                .committee_nodes
                .contains_key(&receipt.responder_node_id)
            {
                return Err("DA sample receipt references unknown responder".to_string());
            }
        }
        for evidence in self.withheld_evidence.values() {
            evidence.validate()?;
            if !self.blob_manifests.contains_key(&evidence.blob_id) {
                return Err("withheld evidence references unknown blob".to_string());
            }
            if !self.shard_commitments.contains_key(&evidence.shard_id) {
                return Err("withheld evidence references unknown shard".to_string());
            }
            if !self.committee_nodes.contains_key(&evidence.accused_node_id) {
                return Err("withheld evidence references unknown accused node".to_string());
            }
        }
        for settlement in self.slashing_settlements.values() {
            settlement.validate()?;
            if !self.withheld_evidence.contains_key(&settlement.evidence_id) {
                return Err("DA slashing settlement references unknown evidence".to_string());
            }
        }
        for record in self.public_records.values() {
            record.validate()?;
        }
        Ok(self.state_root())
    }

    fn refresh_epoch_counters(&mut self) {
        let current_epoch_id = self.current_epoch_id.clone();
        if current_epoch_id.is_empty() {
            return;
        }
        if let Some(epoch) = self.redundancy_epochs.get_mut(&current_epoch_id) {
            epoch.blob_count = self.blob_manifests.len() as u64;
            epoch.encoded_bytes = self
                .blob_manifests
                .values()
                .map(|blob| blob.encoded_bytes)
                .fold(0_u64, u64::saturating_add);
        }
    }
}

pub fn da_sampling_market_state_root_from_record(record: &Value) -> String {
    domain_hash(
        "DA-SAMPLING-MARKET-STATE-ROOT",
        &[HashPart::Json(record)],
        32,
    )
}

pub fn da_sampling_market_payload_root(domain: &str, record: &Value) -> String {
    domain_hash(
        domain,
        &[HashPart::Str(CHAIN_ID), HashPart::Json(record)],
        32,
    )
}

pub fn da_sampling_market_string_root(domain: &str, value: &str) -> String {
    domain_hash(domain, &[HashPart::Str(CHAIN_ID), HashPart::Str(value)], 32)
}

pub fn da_account_commitment(label: &str) -> String {
    da_sampling_market_string_root("DA-SAMPLING-MARKET-ACCOUNT-COMMITMENT", label)
}

pub fn da_pricing_model_id(lane_key: &str, blob_class: DaBlobClass, fee_asset_id: &str) -> String {
    domain_hash(
        "DA-SAMPLING-MARKET-PRICING-MODEL-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(lane_key),
            HashPart::Str(blob_class.as_str()),
            HashPart::Str(fee_asset_id),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn da_blob_manifest_id(
    rollup_batch_id: &str,
    sequencer_id: &str,
    lane_key: &str,
    blob_class: DaBlobClass,
    payload_hash: &str,
    payload_bytes: u64,
    posted_at_height: u64,
) -> String {
    domain_hash(
        "DA-SAMPLING-MARKET-BLOB-MANIFEST-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(rollup_batch_id),
            HashPart::Str(sequencer_id),
            HashPart::Str(lane_key),
            HashPart::Str(blob_class.as_str()),
            HashPart::Str(payload_hash),
            HashPart::Int(payload_bytes as i128),
            HashPart::Int(posted_at_height as i128),
        ],
        32,
    )
}

pub fn da_blob_sample_seed(
    rollup_batch_id: &str,
    sequencer_id: &str,
    payload_hash: &str,
    posted_at_height: u64,
) -> String {
    domain_hash(
        "DA-SAMPLING-MARKET-BLOB-SAMPLE-SEED",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(rollup_batch_id),
            HashPart::Str(sequencer_id),
            HashPart::Str(payload_hash),
            HashPart::Int(posted_at_height as i128),
        ],
        32,
    )
}

pub fn da_erasure_shard_commitment_id(
    blob_id: &str,
    shard_index: u64,
    is_parity: bool,
    commitment: &str,
    provider_node_id: &str,
) -> String {
    domain_hash(
        "DA-SAMPLING-MARKET-ERASURE-SHARD-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(blob_id),
            HashPart::Int(shard_index as i128),
            HashPart::Str(if is_parity { "parity" } else { "original" }),
            HashPart::Str(commitment),
            HashPart::Str(provider_node_id),
        ],
        32,
    )
}

pub fn da_committee_node_id(
    operator_id: &str,
    role: DaCommitteeRole,
    network_public_key: &str,
    pq_signing_public_key: &str,
) -> String {
    domain_hash(
        "DA-SAMPLING-MARKET-COMMITTEE-NODE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(operator_id),
            HashPart::Str(role.as_str()),
            HashPart::Str(network_public_key),
            HashPart::Str(pq_signing_public_key),
        ],
        32,
    )
}

pub fn da_committee_attestation_transcript(
    blob_id: &str,
    epoch_id: &str,
    node_id: &str,
    shard_root: &str,
    attested_at_height: u64,
    availability_claim: &str,
) -> String {
    domain_hash(
        "DA-SAMPLING-MARKET-COMMITTEE-ATTESTATION-TRANSCRIPT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(blob_id),
            HashPart::Str(epoch_id),
            HashPart::Str(node_id),
            HashPart::Str(shard_root),
            HashPart::Int(attested_at_height as i128),
            HashPart::Str(availability_claim),
        ],
        32,
    )
}

pub fn da_committee_attestation_id(
    blob_id: &str,
    epoch_id: &str,
    node_id: &str,
    transcript_hash: &str,
) -> String {
    domain_hash(
        "DA-SAMPLING-MARKET-COMMITTEE-ATTESTATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(blob_id),
            HashPart::Str(epoch_id),
            HashPart::Str(node_id),
            HashPart::Str(transcript_hash),
        ],
        32,
    )
}

pub fn da_sample_request_id(
    blob_id: &str,
    requester_commitment: &str,
    sample_index_root: &str,
    request_height: u64,
) -> String {
    domain_hash(
        "DA-SAMPLING-MARKET-SAMPLE-REQUEST-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(blob_id),
            HashPart::Str(requester_commitment),
            HashPart::Str(sample_index_root),
            HashPart::Int(request_height as i128),
        ],
        32,
    )
}

pub fn da_sample_receipt_id(
    request_id: &str,
    responder_node_id: &str,
    returned_shard_root: &str,
    missing_shard_root: &str,
    response_height: u64,
) -> String {
    domain_hash(
        "DA-SAMPLING-MARKET-SAMPLE-RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(request_id),
            HashPart::Str(responder_node_id),
            HashPart::Str(returned_shard_root),
            HashPart::Str(missing_shard_root),
            HashPart::Int(response_height as i128),
        ],
        32,
    )
}

pub fn da_blob_sponsorship_id(
    sponsor_commitment: &str,
    lane_key: &str,
    blob_class: DaBlobClass,
    fee_asset_id: &str,
    created_at_height: u64,
    policy_root: &str,
) -> String {
    domain_hash(
        "DA-SAMPLING-MARKET-BLOB-SPONSORSHIP-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(sponsor_commitment),
            HashPart::Str(lane_key),
            HashPart::Str(blob_class.as_str()),
            HashPart::Str(fee_asset_id),
            HashPart::Int(created_at_height as i128),
            HashPart::Str(policy_root),
        ],
        32,
    )
}

pub fn da_withheld_shard_evidence_id(
    evidence_kind: WithheldShardEvidenceKind,
    blob_id: &str,
    shard_id: &str,
    reporter_commitment: &str,
    accused_node_id: &str,
    missing_index_root: &str,
    challenge_height: u64,
) -> String {
    domain_hash(
        "DA-SAMPLING-MARKET-WITHHELD-SHARD-EVIDENCE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(evidence_kind.as_str()),
            HashPart::Str(blob_id),
            HashPart::Str(shard_id),
            HashPart::Str(reporter_commitment),
            HashPart::Str(accused_node_id),
            HashPart::Str(missing_index_root),
            HashPart::Int(challenge_height as i128),
        ],
        32,
    )
}

pub fn da_redundancy_epoch_id(
    epoch_index: u64,
    start_height: u64,
    end_height: u64,
    original_shards: u64,
    parity_shards: u64,
    random_seed: &str,
) -> String {
    domain_hash(
        "DA-SAMPLING-MARKET-REDUNDANCY-EPOCH-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(epoch_index as i128),
            HashPart::Int(start_height as i128),
            HashPart::Int(end_height as i128),
            HashPart::Int(original_shards as i128),
            HashPart::Int(parity_shards as i128),
            HashPart::Str(random_seed),
        ],
        32,
    )
}

pub fn da_light_client_sampling_window_id(
    blob_id: &str,
    requester_commitment: &str,
    start_height: u64,
    end_height: u64,
    sample_count: u64,
) -> String {
    domain_hash(
        "DA-SAMPLING-MARKET-LIGHT-CLIENT-WINDOW-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(blob_id),
            HashPart::Str(requester_commitment),
            HashPart::Int(start_height as i128),
            HashPart::Int(end_height as i128),
            HashPart::Int(sample_count as i128),
        ],
        32,
    )
}

pub fn da_pricing_quote_id(
    pricing_model_id: &str,
    payer_commitment: &str,
    payload_bytes: u64,
    encoded_bytes: u64,
    created_at_height: u64,
    pricing_root: &str,
) -> String {
    domain_hash(
        "DA-SAMPLING-MARKET-PRICING-QUOTE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(pricing_model_id),
            HashPart::Str(payer_commitment),
            HashPart::Int(payload_bytes as i128),
            HashPart::Int(encoded_bytes as i128),
            HashPart::Int(created_at_height as i128),
            HashPart::Str(pricing_root),
        ],
        32,
    )
}

pub fn da_slashing_settlement_id(
    evidence_id: &str,
    accused_node_id: &str,
    slash_units: u64,
    settled_at_height: u64,
    settlement_root: &str,
) -> String {
    domain_hash(
        "DA-SAMPLING-MARKET-SLASHING-SETTLEMENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(evidence_id),
            HashPart::Str(accused_node_id),
            HashPart::Int(slash_units as i128),
            HashPart::Int(settled_at_height as i128),
            HashPart::Str(settlement_root),
        ],
        32,
    )
}

pub fn da_sampling_market_public_record_id(
    record_kind: &str,
    subject_id: &str,
    height: u64,
    payload_root: &str,
) -> String {
    domain_hash(
        "DA-SAMPLING-MARKET-PUBLIC-RECORD-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(record_kind),
            HashPart::Str(subject_id),
            HashPart::Int(height as i128),
            HashPart::Str(payload_root),
        ],
        32,
    )
}

pub fn low_fee_da_pricing_model_root(models: &[LowFeeDaPricingModel]) -> String {
    sorted_record_root(
        "DA-SAMPLING-MARKET-PRICING-MODEL-ROOT",
        models
            .iter()
            .map(|model| (model.pricing_model_id.clone(), model.public_record()))
            .collect(),
    )
}

pub fn da_blob_manifest_root(blobs: &[DaBlobManifest]) -> String {
    sorted_record_root(
        "DA-SAMPLING-MARKET-BLOB-MANIFEST-ROOT",
        blobs
            .iter()
            .map(|blob| (blob.blob_id.clone(), blob.public_record()))
            .collect(),
    )
}

pub fn da_erasure_shard_commitment_root(shards: &[DaErasureShardCommitment]) -> String {
    sorted_record_root(
        "DA-SAMPLING-MARKET-ERASURE-SHARD-ROOT",
        shards
            .iter()
            .map(|shard| (shard.shard_id.clone(), shard.public_record()))
            .collect(),
    )
}

pub fn da_committee_node_root(nodes: &[DaCommitteeNode]) -> String {
    sorted_record_root(
        "DA-SAMPLING-MARKET-COMMITTEE-NODE-ROOT",
        nodes
            .iter()
            .map(|node| (node.node_id.clone(), node.public_record()))
            .collect(),
    )
}

pub fn da_committee_attestation_root(attestations: &[DaCommitteeAttestation]) -> String {
    sorted_record_root(
        "DA-SAMPLING-MARKET-COMMITTEE-ATTESTATION-ROOT",
        attestations
            .iter()
            .map(|attestation| {
                (
                    attestation.attestation_id.clone(),
                    attestation.public_record(),
                )
            })
            .collect(),
    )
}

pub fn da_sample_request_root(requests: &[DaSampleRequest]) -> String {
    sorted_record_root(
        "DA-SAMPLING-MARKET-SAMPLE-REQUEST-ROOT",
        requests
            .iter()
            .map(|request| (request.request_id.clone(), request.public_record()))
            .collect(),
    )
}

pub fn da_sample_receipt_root(receipts: &[DaSampleReceipt]) -> String {
    sorted_record_root(
        "DA-SAMPLING-MARKET-SAMPLE-RECEIPT-ROOT",
        receipts
            .iter()
            .map(|receipt| (receipt.receipt_id.clone(), receipt.public_record()))
            .collect(),
    )
}

pub fn da_blob_sponsorship_root(sponsorships: &[DaBlobSponsorship]) -> String {
    sorted_record_root(
        "DA-SAMPLING-MARKET-BLOB-SPONSORSHIP-ROOT",
        sponsorships
            .iter()
            .map(|sponsorship| {
                (
                    sponsorship.sponsorship_id.clone(),
                    sponsorship.public_record(),
                )
            })
            .collect(),
    )
}

pub fn withheld_shard_evidence_root(evidence: &[WithheldShardEvidence]) -> String {
    sorted_record_root(
        "DA-SAMPLING-MARKET-WITHHELD-SHARD-EVIDENCE-ROOT",
        evidence
            .iter()
            .map(|evidence| (evidence.evidence_id.clone(), evidence.public_record()))
            .collect(),
    )
}

pub fn da_redundancy_epoch_root(epochs: &[DaRedundancyEpoch]) -> String {
    sorted_record_root(
        "DA-SAMPLING-MARKET-REDUNDANCY-EPOCH-ROOT",
        epochs
            .iter()
            .map(|epoch| (epoch.epoch_id.clone(), epoch.public_record()))
            .collect(),
    )
}

pub fn light_client_sampling_window_root(windows: &[LightClientSamplingWindow]) -> String {
    sorted_record_root(
        "DA-SAMPLING-MARKET-LIGHT-CLIENT-WINDOW-ROOT",
        windows
            .iter()
            .map(|window| (window.window_id.clone(), window.public_record()))
            .collect(),
    )
}

pub fn da_pricing_quote_root(quotes: &[DaPricingQuote]) -> String {
    sorted_record_root(
        "DA-SAMPLING-MARKET-PRICING-QUOTE-ROOT",
        quotes
            .iter()
            .map(|quote| (quote.quote_id.clone(), quote.public_record()))
            .collect(),
    )
}

pub fn da_slashing_settlement_root(settlements: &[DaSlashingSettlement]) -> String {
    sorted_record_root(
        "DA-SAMPLING-MARKET-SLASHING-SETTLEMENT-ROOT",
        settlements
            .iter()
            .map(|settlement| (settlement.settlement_id.clone(), settlement.public_record()))
            .collect(),
    )
}

pub fn da_sampling_market_public_record_root(records: &[DaSamplingMarketPublicRecord]) -> String {
    sorted_record_root(
        "DA-SAMPLING-MARKET-PUBLIC-RECORD-ROOT",
        records
            .iter()
            .map(|record| (record.record_id.clone(), record.public_record()))
            .collect(),
    )
}

pub fn da_sample_index_root(indices: &[u64]) -> String {
    let values = indices
        .iter()
        .map(|index| json!({ "sample_index": index }))
        .collect::<Vec<_>>();
    merkle_root("DA-SAMPLING-MARKET-SAMPLE-INDEX", &values)
}

pub fn derive_da_sampling_market_sample_indices(
    seed: &str,
    shard_count: u64,
    sample_count: u64,
) -> DaSamplingMarketResult<Vec<u64>> {
    ensure_non_empty(seed, "DA sampling seed")?;
    if shard_count == 0 {
        return Err("cannot sample from zero DA shards".to_string());
    }
    if sample_count == 0 {
        return Err("DA sampling count cannot be zero".to_string());
    }
    let target = std::cmp::min(sample_count, shard_count);
    let mut selected = BTreeSet::new();
    let mut nonce = 0_u64;
    while selected.len() < target as usize {
        let candidate_hash = domain_hash(
            "DA-SAMPLING-MARKET-SAMPLING-CANDIDATE",
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

pub fn encoded_blob_size(payload_bytes: u64, original_shards: u64, parity_shards: u64) -> u64 {
    if original_shards == 0 {
        return payload_bytes;
    }
    mul_div_ceil(
        payload_bytes,
        original_shards.saturating_add(parity_shards),
        original_shards,
    )
}

pub fn devnet_hash(domain: &str, label: &str) -> String {
    domain_hash(domain, &[HashPart::Str(CHAIN_ID), HashPart::Str(label)], 32)
}

pub fn da_market_devnet_key(kind: &str, label: &str) -> String {
    domain_hash(
        "DA-SAMPLING-MARKET-DEVNET-KEY",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(kind),
            HashPart::Str(label),
        ],
        32,
    )
}

pub fn da_market_devnet_signature(label: &str, transcript_hash: &str) -> String {
    domain_hash(
        "DA-SAMPLING-MARKET-DEVNET-SIGNATURE",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Str(DA_SAMPLING_MARKET_PQ_SIGNATURE_SCHEME),
            HashPart::Str(transcript_hash),
        ],
        64,
    )
}

fn devnet_provider_node_id(shard_index: u64) -> String {
    let provider_index = shard_index % 5;
    let role = match provider_index {
        0 => DaCommitteeRole::Encoder,
        1 => DaCommitteeRole::Sampler,
        2 => DaCommitteeRole::Attester,
        3 => DaCommitteeRole::ArchiveProvider,
        _ => DaCommitteeRole::Watchtower,
    };
    let label = format!("devnet-da-node-{provider_index}");
    let network_public_key = da_market_devnet_key("network", &label);
    let pq_signing_public_key = da_market_devnet_key("pq-signing", &label);
    da_committee_node_id(
        &format!("devnet-da-operator-{provider_index}"),
        role,
        &network_public_key,
        &pq_signing_public_key,
    )
}

fn devnet_shards_for_blob(
    blob_id: &str,
    lane_key: &str,
    original_shards: u64,
    parity_shards: u64,
) -> DaSamplingMarketResult<Vec<DaErasureShardCommitment>> {
    let total = original_shards.saturating_add(parity_shards);
    let mut shards = Vec::with_capacity(total as usize);
    for index in 0..total {
        shards.push(DaErasureShardCommitment::devnet(
            blob_id,
            lane_key,
            index,
            original_shards,
        ));
    }
    Ok(shards)
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
        .expect("DA sampling market root target record object")
        .insert(field.to_string(), Value::String(root));
    record
}

fn ensure_non_empty(value: &str, label: &str) -> DaSamplingMarketResult<()> {
    if value.trim().is_empty() {
        return Err(format!("{label} cannot be empty"));
    }
    Ok(())
}

fn ensure_bps(value: u64, label: &str) -> DaSamplingMarketResult<()> {
    if value > 10_000 {
        return Err(format!("{label} basis points exceed 100%"));
    }
    Ok(())
}

fn ensure_status(value: &str, allowed: &[&str], label: &str) -> DaSamplingMarketResult<()> {
    if allowed.iter().any(|allowed| *allowed == value) {
        Ok(())
    } else {
        Err(format!("{label} is not supported"))
    }
}

fn ensure_unique_u64(values: &[u64], label: &str) -> DaSamplingMarketResult<()> {
    let mut seen = BTreeSet::new();
    for value in values {
        if !seen.insert(*value) {
            return Err(format!("{label} must be unique"));
        }
    }
    Ok(())
}

fn ensure_disjoint_u64(left: &[u64], right: &[u64], label: &str) -> DaSamplingMarketResult<()> {
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
) -> DaSamplingMarketResult<()> {
    if records.contains_key(&id) {
        return Err(format!("{label} already exists"));
    }
    records.insert(id, record);
    Ok(())
}

fn mul_div_floor(value: u64, multiplier: u64, divisor: u64) -> u64 {
    if divisor == 0 {
        return 0;
    }
    ((value as u128) * (multiplier as u128) / (divisor as u128)).min(u64::MAX as u128) as u64
}

fn mul_div_ceil(value: u64, multiplier: u64, divisor: u64) -> u64 {
    if divisor == 0 {
        return 0;
    }
    ((value as u128) * (multiplier as u128))
        .div_ceil(divisor as u128)
        .min(u64::MAX as u128) as u64
}

fn saturating_mul(left: u64, right: u64) -> u64 {
    ((left as u128) * (right as u128)).min(u64::MAX as u128) as u64
}

fn hash_to_u64(hash: &str) -> u64 {
    let prefix = hash.get(0..16).unwrap_or(hash);
    u64::from_str_radix(prefix, 16).unwrap_or(0)
}
