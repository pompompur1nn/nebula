use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type MoneroViewTagIndexerResult<T> = Result<T, String>;

pub const MONERO_VIEW_TAG_INDEXER_PROTOCOL_VERSION: u32 = 1;
pub const MONERO_VIEW_TAG_INDEXER_PROTOCOL_LABEL: &str = "nebula-monero-view-tag-indexer-v1";
pub const MONERO_VIEW_TAG_INDEXER_DEVNET_NETWORK: &str = "monero-devnet";
pub const MONERO_VIEW_TAG_INDEXER_DEVNET_ASSET_ID: &str = "wxmr-devnet";
pub const MONERO_VIEW_TAG_INDEXER_DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const MONERO_VIEW_TAG_INDEXER_DEFAULT_VIEW_TAG_BITS: u16 = 8;
pub const MONERO_VIEW_TAG_INDEXER_DEFAULT_SHARD_COUNT: u16 = 16;
pub const MONERO_VIEW_TAG_INDEXER_DEFAULT_BUCKET_COUNT: u16 = 64;
pub const MONERO_VIEW_TAG_INDEXER_DEFAULT_EPOCH_BLOCKS: u64 = 8;
pub const MONERO_VIEW_TAG_INDEXER_DEFAULT_FINALITY_DEPTH: u64 = 10;
pub const MONERO_VIEW_TAG_INDEXER_DEFAULT_REORG_WINDOW_BLOCKS: u64 = 32;
pub const MONERO_VIEW_TAG_INDEXER_DEFAULT_SCAN_ASSIGNMENT_TTL_BLOCKS: u64 = 24;
pub const MONERO_VIEW_TAG_INDEXER_DEFAULT_CURSOR_TTL_BLOCKS: u64 = 720;
pub const MONERO_VIEW_TAG_INDEXER_DEFAULT_PRIVACY_BUDGET_EPOCH_BLOCKS: u64 = 96;
pub const MONERO_VIEW_TAG_INDEXER_DEFAULT_COMPACTION_INTERVAL_BLOCKS: u64 = 64;
pub const MONERO_VIEW_TAG_INDEXER_DEFAULT_LOW_FEE_SCAN_UNIT_PRICE: u64 = 250;
pub const MONERO_VIEW_TAG_INDEXER_DEFAULT_MAX_TAGS_PER_SHARD: u64 = 256;
pub const MONERO_VIEW_TAG_INDEXER_DEFAULT_MAX_ASSIGNMENTS_PER_EPOCH: u64 = 4_096;
pub const MONERO_VIEW_TAG_INDEXER_DEFAULT_MIN_SCANNER_QUORUM_WEIGHT: u64 = 3;
pub const MONERO_VIEW_TAG_INDEXER_DEFAULT_PQ_SECURITY_BITS: u16 = 192;
pub const MONERO_VIEW_TAG_INDEXER_PQ_SIGNATURE_SCHEME: &str = "ML-DSA-65";
pub const MONERO_VIEW_TAG_INDEXER_PQ_KEM_SCHEME: &str = "ML-KEM-768";
pub const MONERO_VIEW_TAG_INDEXER_FILTER_SCHEME: &str = "view-tag-bucket-shake256-v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ViewTagShardStatus {
    Open,
    Sealed,
    Compacting,
    Reorged,
    Retired,
}

impl ViewTagShardStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Sealed => "sealed",
            Self::Compacting => "compacting",
            Self::Reorged => "reorged",
            Self::Retired => "retired",
        }
    }

    pub fn is_indexable(self) -> bool {
        matches!(self, Self::Open | Self::Sealed | Self::Compacting)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanAssignmentKind {
    WalletSync,
    BridgeWatch,
    ReserveAudit,
    ContractIngress,
    SponsorBatch,
    ReorgReplay,
}

impl ScanAssignmentKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WalletSync => "wallet_sync",
            Self::BridgeWatch => "bridge_watch",
            Self::ReserveAudit => "reserve_audit",
            Self::ContractIngress => "contract_ingress",
            Self::SponsorBatch => "sponsor_batch",
            Self::ReorgReplay => "reorg_replay",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanAssignmentStatus {
    Queued,
    Leased,
    Proved,
    Settled,
    Expired,
    Reorged,
}

impl ScanAssignmentStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Leased => "leased",
            Self::Proved => "proved",
            Self::Settled => "settled",
            Self::Expired => "expired",
            Self::Reorged => "reorged",
        }
    }

    pub fn is_active(self) -> bool {
        matches!(self, Self::Queued | Self::Leased | Self::Proved)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutputBucketKind {
    DepositCandidate,
    WithdrawalChange,
    ContractNote,
    ReserveOutput,
    DustSuppressed,
    Unknown,
}

impl OutputBucketKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DepositCandidate => "deposit_candidate",
            Self::WithdrawalChange => "withdrawal_change",
            Self::ContractNote => "contract_note",
            Self::ReserveOutput => "reserve_output",
            Self::DustSuppressed => "dust_suppressed",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WalletCursorStatus {
    Active,
    Rotating,
    Parked,
    Expired,
    Revoked,
}

impl WalletCursorStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Rotating => "rotating",
            Self::Parked => "parked",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
        }
    }

    pub fn can_advance(self) -> bool {
        matches!(self, Self::Active | Self::Rotating)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReserveScanLaneKind {
    HotBuffer,
    ColdReserve,
    BridgeLiquidity,
    EmergencyExit,
    ProofOfReserve,
}

impl ReserveScanLaneKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::HotBuffer => "hot_buffer",
            Self::ColdReserve => "cold_reserve",
            Self::BridgeLiquidity => "bridge_liquidity",
            Self::EmergencyExit => "emergency_exit",
            Self::ProofOfReserve => "proof_of_reserve",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReorgWindowStatus {
    Watching,
    Replaying,
    Finalized,
    Disputed,
}

impl ReorgWindowStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Watching => "watching",
            Self::Replaying => "replaying",
            Self::Finalized => "finalized",
            Self::Disputed => "disputed",
        }
    }

    pub fn is_open(self) -> bool {
        matches!(self, Self::Watching | Self::Replaying | Self::Disputed)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqScannerRole {
    Indexer,
    BridgeScanner,
    ReserveScanner,
    WalletRelayer,
    Watchtower,
}

impl PqScannerRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Indexer => "indexer",
            Self::BridgeScanner => "bridge_scanner",
            Self::ReserveScanner => "reserve_scanner",
            Self::WalletRelayer => "wallet_relayer",
            Self::Watchtower => "watchtower",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScannerAttestationStatus {
    Pending,
    Accepted,
    Challenged,
    Slashed,
    Expired,
}

impl ScannerAttestationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Accepted => "accepted",
            Self::Challenged => "challenged",
            Self::Slashed => "slashed",
            Self::Expired => "expired",
        }
    }

    pub fn counts_for_quorum(self) -> bool {
        matches!(self, Self::Accepted)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorshipStatus {
    Offered,
    Reserved,
    Consumed,
    Refunded,
    Expired,
    Slashed,
}

impl SponsorshipStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Offered => "offered",
            Self::Reserved => "reserved",
            Self::Consumed => "consumed",
            Self::Refunded => "refunded",
            Self::Expired => "expired",
            Self::Slashed => "slashed",
        }
    }

    pub fn is_live(self) -> bool {
        matches!(self, Self::Offered | Self::Reserved)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivacyBudgetScope {
    WalletSync,
    BridgeScanning,
    ReserveProof,
    ContractIngress,
    LowFeeSponsor,
}

impl PrivacyBudgetScope {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WalletSync => "wallet_sync",
            Self::BridgeScanning => "bridge_scanning",
            Self::ReserveProof => "reserve_proof",
            Self::ContractIngress => "contract_ingress",
            Self::LowFeeSponsor => "low_fee_sponsor",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompactionStatus {
    Scheduled,
    Running,
    Sealed,
    Verified,
    Reorged,
}

impl CompactionStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Scheduled => "scheduled",
            Self::Running => "running",
            Self::Sealed => "sealed",
            Self::Verified => "verified",
            Self::Reorged => "reorged",
        }
    }

    pub fn is_current(self) -> bool {
        matches!(self, Self::Scheduled | Self::Running | Self::Sealed)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroViewTagIndexerConfig {
    pub protocol_version: u32,
    pub protocol_label: String,
    pub network: String,
    pub asset_id: String,
    pub fee_asset_id: String,
    pub pq_signature_scheme: String,
    pub pq_kem_scheme: String,
    pub filter_scheme: String,
    pub view_tag_bits: u16,
    pub shard_count: u16,
    pub output_bucket_count: u16,
    pub epoch_blocks: u64,
    pub finality_depth: u64,
    pub reorg_window_blocks: u64,
    pub scan_assignment_ttl_blocks: u64,
    pub cursor_ttl_blocks: u64,
    pub privacy_budget_epoch_blocks: u64,
    pub compaction_interval_blocks: u64,
    pub low_fee_scan_unit_price: u64,
    pub max_tags_per_shard: u64,
    pub max_assignments_per_epoch: u64,
    pub min_scanner_quorum_weight: u64,
    pub pq_security_bits: u16,
    pub metadata_root: String,
}

impl Default for MoneroViewTagIndexerConfig {
    fn default() -> Self {
        Self {
            protocol_version: MONERO_VIEW_TAG_INDEXER_PROTOCOL_VERSION,
            protocol_label: MONERO_VIEW_TAG_INDEXER_PROTOCOL_LABEL.to_string(),
            network: MONERO_VIEW_TAG_INDEXER_DEVNET_NETWORK.to_string(),
            asset_id: MONERO_VIEW_TAG_INDEXER_DEVNET_ASSET_ID.to_string(),
            fee_asset_id: MONERO_VIEW_TAG_INDEXER_DEVNET_FEE_ASSET_ID.to_string(),
            pq_signature_scheme: MONERO_VIEW_TAG_INDEXER_PQ_SIGNATURE_SCHEME.to_string(),
            pq_kem_scheme: MONERO_VIEW_TAG_INDEXER_PQ_KEM_SCHEME.to_string(),
            filter_scheme: MONERO_VIEW_TAG_INDEXER_FILTER_SCHEME.to_string(),
            view_tag_bits: MONERO_VIEW_TAG_INDEXER_DEFAULT_VIEW_TAG_BITS,
            shard_count: MONERO_VIEW_TAG_INDEXER_DEFAULT_SHARD_COUNT,
            output_bucket_count: MONERO_VIEW_TAG_INDEXER_DEFAULT_BUCKET_COUNT,
            epoch_blocks: MONERO_VIEW_TAG_INDEXER_DEFAULT_EPOCH_BLOCKS,
            finality_depth: MONERO_VIEW_TAG_INDEXER_DEFAULT_FINALITY_DEPTH,
            reorg_window_blocks: MONERO_VIEW_TAG_INDEXER_DEFAULT_REORG_WINDOW_BLOCKS,
            scan_assignment_ttl_blocks: MONERO_VIEW_TAG_INDEXER_DEFAULT_SCAN_ASSIGNMENT_TTL_BLOCKS,
            cursor_ttl_blocks: MONERO_VIEW_TAG_INDEXER_DEFAULT_CURSOR_TTL_BLOCKS,
            privacy_budget_epoch_blocks:
                MONERO_VIEW_TAG_INDEXER_DEFAULT_PRIVACY_BUDGET_EPOCH_BLOCKS,
            compaction_interval_blocks: MONERO_VIEW_TAG_INDEXER_DEFAULT_COMPACTION_INTERVAL_BLOCKS,
            low_fee_scan_unit_price: MONERO_VIEW_TAG_INDEXER_DEFAULT_LOW_FEE_SCAN_UNIT_PRICE,
            max_tags_per_shard: MONERO_VIEW_TAG_INDEXER_DEFAULT_MAX_TAGS_PER_SHARD,
            max_assignments_per_epoch: MONERO_VIEW_TAG_INDEXER_DEFAULT_MAX_ASSIGNMENTS_PER_EPOCH,
            min_scanner_quorum_weight: MONERO_VIEW_TAG_INDEXER_DEFAULT_MIN_SCANNER_QUORUM_WEIGHT,
            pq_security_bits: MONERO_VIEW_TAG_INDEXER_DEFAULT_PQ_SECURITY_BITS,
            metadata_root: monero_view_tag_indexer_payload_root(
                "MONERO-VIEW-TAG-INDEXER-CONFIG-METADATA",
                &json!({
                    "mode": "devnet",
                    "privacy": "committed view-tag buckets with encrypted wallet work",
                    "goal": "accelerate bridge scanning and wallet sync without linkability"
                }),
            ),
        }
    }
}

impl MoneroViewTagIndexerConfig {
    pub fn validate(&self) -> MoneroViewTagIndexerResult<()> {
        ensure_non_empty(&self.protocol_label, "view tag indexer protocol label")?;
        ensure_non_empty(&self.network, "view tag indexer network")?;
        ensure_non_empty(&self.asset_id, "view tag indexer asset")?;
        ensure_non_empty(&self.fee_asset_id, "view tag indexer fee asset")?;
        ensure_non_empty(
            &self.pq_signature_scheme,
            "view tag indexer pq signature scheme",
        )?;
        ensure_non_empty(&self.pq_kem_scheme, "view tag indexer pq kem scheme")?;
        ensure_non_empty(&self.filter_scheme, "view tag indexer filter scheme")?;
        ensure_non_empty(&self.metadata_root, "view tag indexer metadata root")?;
        if self.protocol_version != MONERO_VIEW_TAG_INDEXER_PROTOCOL_VERSION {
            return Err("view tag indexer protocol version mismatch".to_string());
        }
        if self.view_tag_bits == 0 || self.view_tag_bits > 16 {
            return Err("view tag bits must be between 1 and 16".to_string());
        }
        if self.shard_count == 0 || self.output_bucket_count == 0 {
            return Err("view tag shard and bucket counts must be positive".to_string());
        }
        if self.epoch_blocks == 0
            || self.finality_depth == 0
            || self.reorg_window_blocks == 0
            || self.scan_assignment_ttl_blocks == 0
            || self.cursor_ttl_blocks == 0
            || self.privacy_budget_epoch_blocks == 0
            || self.compaction_interval_blocks == 0
        {
            return Err("view tag indexer block windows must be positive".to_string());
        }
        if self.max_tags_per_shard == 0 || self.max_assignments_per_epoch == 0 {
            return Err("view tag indexer per-epoch limits must be positive".to_string());
        }
        if self.min_scanner_quorum_weight == 0 {
            return Err("view tag indexer scanner quorum weight must be positive".to_string());
        }
        if self.pq_security_bits < 128 {
            return Err("view tag indexer pq security bits must be at least 128".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_view_tag_indexer_config",
            "chain_id": CHAIN_ID,
            "protocol_version": self.protocol_version,
            "protocol_label": self.protocol_label,
            "network": self.network,
            "asset_id": self.asset_id,
            "fee_asset_id": self.fee_asset_id,
            "pq_signature_scheme": self.pq_signature_scheme,
            "pq_kem_scheme": self.pq_kem_scheme,
            "filter_scheme": self.filter_scheme,
            "view_tag_bits": self.view_tag_bits,
            "shard_count": self.shard_count,
            "output_bucket_count": self.output_bucket_count,
            "epoch_blocks": self.epoch_blocks,
            "finality_depth": self.finality_depth,
            "reorg_window_blocks": self.reorg_window_blocks,
            "scan_assignment_ttl_blocks": self.scan_assignment_ttl_blocks,
            "cursor_ttl_blocks": self.cursor_ttl_blocks,
            "privacy_budget_epoch_blocks": self.privacy_budget_epoch_blocks,
            "compaction_interval_blocks": self.compaction_interval_blocks,
            "low_fee_scan_unit_price": self.low_fee_scan_unit_price,
            "max_tags_per_shard": self.max_tags_per_shard,
            "max_assignments_per_epoch": self.max_assignments_per_epoch,
            "min_scanner_quorum_weight": self.min_scanner_quorum_weight,
            "pq_security_bits": self.pq_security_bits,
            "metadata_root": self.metadata_root,
        })
    }

    pub fn config_root(&self) -> String {
        monero_view_tag_indexer_payload_root(
            "MONERO-VIEW-TAG-INDEXER-CONFIG",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ViewTagShard {
    pub shard_id: String,
    pub shard_index: u16,
    pub epoch: u64,
    pub start_height: u64,
    pub end_height: u64,
    pub view_tag_prefix: String,
    pub tag_commitment_root: String,
    pub output_bucket_root: String,
    pub scanner_set_root: String,
    pub assignment_root: String,
    pub false_positive_budget: u64,
    pub encrypted_hint_bytes: u64,
    pub indexed_output_count: u64,
    pub candidate_match_count: u64,
    pub status: ViewTagShardStatus,
}

impl ViewTagShard {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        shard_index: u16,
        epoch: u64,
        start_height: u64,
        end_height: u64,
        view_tag_prefix: &str,
        tag_commitment_root: &str,
        output_bucket_root: &str,
        scanner_set_root: &str,
        assignment_root: &str,
        false_positive_budget: u64,
        encrypted_hint_bytes: u64,
        indexed_output_count: u64,
        candidate_match_count: u64,
        status: ViewTagShardStatus,
    ) -> MoneroViewTagIndexerResult<Self> {
        ensure_height_range(start_height, end_height, "view tag shard")?;
        ensure_non_empty(view_tag_prefix, "view tag shard prefix")?;
        ensure_non_empty(tag_commitment_root, "view tag shard tag commitment root")?;
        ensure_non_empty(output_bucket_root, "view tag shard output bucket root")?;
        ensure_non_empty(scanner_set_root, "view tag shard scanner set root")?;
        ensure_non_empty(assignment_root, "view tag shard assignment root")?;
        let shard_id = monero_view_tag_shard_id(shard_index, epoch, view_tag_prefix);
        Ok(Self {
            shard_id,
            shard_index,
            epoch,
            start_height,
            end_height,
            view_tag_prefix: view_tag_prefix.to_string(),
            tag_commitment_root: tag_commitment_root.to_string(),
            output_bucket_root: output_bucket_root.to_string(),
            scanner_set_root: scanner_set_root.to_string(),
            assignment_root: assignment_root.to_string(),
            false_positive_budget,
            encrypted_hint_bytes,
            indexed_output_count,
            candidate_match_count,
            status,
        })
    }

    pub fn validate(&self) -> MoneroViewTagIndexerResult<()> {
        ensure_non_empty(&self.shard_id, "view tag shard id")?;
        ensure_height_range(self.start_height, self.end_height, "view tag shard")?;
        ensure_non_empty(&self.view_tag_prefix, "view tag shard prefix")?;
        ensure_non_empty(&self.tag_commitment_root, "view tag shard tag root")?;
        ensure_non_empty(&self.output_bucket_root, "view tag shard bucket root")?;
        ensure_non_empty(&self.scanner_set_root, "view tag shard scanner root")?;
        ensure_non_empty(&self.assignment_root, "view tag shard assignment root")?;
        if self.candidate_match_count > self.indexed_output_count {
            return Err("view tag shard candidates cannot exceed indexed outputs".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "view_tag_shard",
            "chain_id": CHAIN_ID,
            "shard_id": self.shard_id,
            "shard_index": self.shard_index,
            "epoch": self.epoch,
            "start_height": self.start_height,
            "end_height": self.end_height,
            "view_tag_prefix": self.view_tag_prefix,
            "tag_commitment_root": self.tag_commitment_root,
            "output_bucket_root": self.output_bucket_root,
            "scanner_set_root": self.scanner_set_root,
            "assignment_root": self.assignment_root,
            "false_positive_budget": self.false_positive_budget,
            "encrypted_hint_bytes": self.encrypted_hint_bytes,
            "indexed_output_count": self.indexed_output_count,
            "candidate_match_count": self.candidate_match_count,
            "status": self.status.as_str(),
            "indexable": self.status.is_indexable(),
        })
    }

    pub fn shard_root(&self) -> String {
        monero_view_tag_indexer_payload_root("MONERO-VIEW-TAG-SHARD", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedScanAssignment {
    pub assignment_id: String,
    pub shard_id: String,
    pub assignment_kind: ScanAssignmentKind,
    pub wallet_cohort_commitment: String,
    pub scanner_committee_root: String,
    pub pq_ciphertext_hash: String,
    pub encrypted_hint_root: String,
    pub relay_path_commitment: String,
    pub leased_at_height: u64,
    pub expires_at_height: u64,
    pub scan_unit_count: u64,
    pub priority_score: u64,
    pub status: ScanAssignmentStatus,
}

impl EncryptedScanAssignment {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        shard_id: &str,
        assignment_kind: ScanAssignmentKind,
        wallet_cohort_label: &str,
        scanner_committee_root: &str,
        pq_ciphertext_hash: &str,
        encrypted_hint_root: &str,
        relay_path_commitment: &str,
        leased_at_height: u64,
        expires_at_height: u64,
        scan_unit_count: u64,
        priority_score: u64,
        status: ScanAssignmentStatus,
    ) -> MoneroViewTagIndexerResult<Self> {
        ensure_non_empty(shard_id, "scan assignment shard id")?;
        ensure_non_empty(wallet_cohort_label, "scan assignment wallet cohort")?;
        ensure_non_empty(
            scanner_committee_root,
            "scan assignment scanner committee root",
        )?;
        ensure_non_empty(pq_ciphertext_hash, "scan assignment pq ciphertext hash")?;
        ensure_non_empty(encrypted_hint_root, "scan assignment encrypted hint root")?;
        ensure_non_empty(
            relay_path_commitment,
            "scan assignment relay path commitment",
        )?;
        ensure_height_range(
            leased_at_height,
            expires_at_height,
            "encrypted scan assignment",
        )?;
        if scan_unit_count == 0 {
            return Err("scan assignment units must be positive".to_string());
        }
        let wallet_cohort_commitment =
            monero_view_tag_string_root("MONERO-VIEW-TAG-WALLET-COHORT", wallet_cohort_label);
        let assignment_id = monero_scan_assignment_id(
            shard_id,
            assignment_kind.as_str(),
            &wallet_cohort_commitment,
            pq_ciphertext_hash,
            leased_at_height,
        );
        Ok(Self {
            assignment_id,
            shard_id: shard_id.to_string(),
            assignment_kind,
            wallet_cohort_commitment,
            scanner_committee_root: scanner_committee_root.to_string(),
            pq_ciphertext_hash: pq_ciphertext_hash.to_string(),
            encrypted_hint_root: encrypted_hint_root.to_string(),
            relay_path_commitment: relay_path_commitment.to_string(),
            leased_at_height,
            expires_at_height,
            scan_unit_count,
            priority_score,
            status,
        })
    }

    pub fn validate(&self) -> MoneroViewTagIndexerResult<()> {
        ensure_non_empty(&self.assignment_id, "scan assignment id")?;
        ensure_non_empty(&self.shard_id, "scan assignment shard id")?;
        ensure_non_empty(
            &self.wallet_cohort_commitment,
            "scan assignment wallet cohort commitment",
        )?;
        ensure_non_empty(
            &self.scanner_committee_root,
            "scan assignment scanner committee root",
        )?;
        ensure_non_empty(
            &self.pq_ciphertext_hash,
            "scan assignment pq ciphertext hash",
        )?;
        ensure_non_empty(
            &self.encrypted_hint_root,
            "scan assignment encrypted hint root",
        )?;
        ensure_non_empty(
            &self.relay_path_commitment,
            "scan assignment relay path commitment",
        )?;
        ensure_height_range(
            self.leased_at_height,
            self.expires_at_height,
            "encrypted scan assignment",
        )?;
        if self.scan_unit_count == 0 {
            return Err("scan assignment units must be positive".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "encrypted_scan_assignment",
            "chain_id": CHAIN_ID,
            "assignment_id": self.assignment_id,
            "shard_id": self.shard_id,
            "assignment_kind": self.assignment_kind.as_str(),
            "wallet_cohort_commitment": self.wallet_cohort_commitment,
            "scanner_committee_root": self.scanner_committee_root,
            "pq_ciphertext_hash": self.pq_ciphertext_hash,
            "encrypted_hint_root": self.encrypted_hint_root,
            "relay_path_commitment": self.relay_path_commitment,
            "leased_at_height": self.leased_at_height,
            "expires_at_height": self.expires_at_height,
            "scan_unit_count": self.scan_unit_count,
            "priority_score": self.priority_score,
            "status": self.status.as_str(),
            "active": self.status.is_active(),
        })
    }

    pub fn assignment_root(&self) -> String {
        monero_view_tag_indexer_payload_root(
            "MONERO-VIEW-TAG-SCAN-ASSIGNMENT",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutputBucketCommitment {
    pub bucket_id: String,
    pub bucket_index: u16,
    pub shard_id: String,
    pub bucket_kind: OutputBucketKind,
    pub amount_bucket_commitment: String,
    pub output_key_commitment_root: String,
    pub txid_commitment_root: String,
    pub bridge_contract_root: String,
    pub output_count: u64,
    pub min_height: u64,
    pub max_height: u64,
    pub sealed: bool,
}

impl OutputBucketCommitment {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        bucket_index: u16,
        shard_id: &str,
        bucket_kind: OutputBucketKind,
        amount_bucket_label: &str,
        output_key_commitment_root: &str,
        txid_commitment_root: &str,
        bridge_contract_root: &str,
        output_count: u64,
        min_height: u64,
        max_height: u64,
        sealed: bool,
    ) -> MoneroViewTagIndexerResult<Self> {
        ensure_non_empty(shard_id, "output bucket shard id")?;
        ensure_non_empty(amount_bucket_label, "output amount bucket label")?;
        ensure_non_empty(
            output_key_commitment_root,
            "output bucket output key commitment root",
        )?;
        ensure_non_empty(txid_commitment_root, "output bucket txid commitment root")?;
        ensure_non_empty(bridge_contract_root, "output bucket bridge contract root")?;
        ensure_height_range(min_height, max_height, "output bucket")?;
        let amount_bucket_commitment =
            monero_view_tag_string_root("MONERO-VIEW-TAG-AMOUNT-BUCKET", amount_bucket_label);
        let bucket_id = monero_output_bucket_id(
            bucket_index,
            shard_id,
            bucket_kind.as_str(),
            &amount_bucket_commitment,
        );
        Ok(Self {
            bucket_id,
            bucket_index,
            shard_id: shard_id.to_string(),
            bucket_kind,
            amount_bucket_commitment,
            output_key_commitment_root: output_key_commitment_root.to_string(),
            txid_commitment_root: txid_commitment_root.to_string(),
            bridge_contract_root: bridge_contract_root.to_string(),
            output_count,
            min_height,
            max_height,
            sealed,
        })
    }

    pub fn validate(&self) -> MoneroViewTagIndexerResult<()> {
        ensure_non_empty(&self.bucket_id, "output bucket id")?;
        ensure_non_empty(&self.shard_id, "output bucket shard id")?;
        ensure_non_empty(
            &self.amount_bucket_commitment,
            "output bucket amount commitment",
        )?;
        ensure_non_empty(
            &self.output_key_commitment_root,
            "output bucket output key root",
        )?;
        ensure_non_empty(&self.txid_commitment_root, "output bucket txid root")?;
        ensure_non_empty(
            &self.bridge_contract_root,
            "output bucket bridge contract root",
        )?;
        ensure_height_range(self.min_height, self.max_height, "output bucket")?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "output_bucket_commitment",
            "chain_id": CHAIN_ID,
            "bucket_id": self.bucket_id,
            "bucket_index": self.bucket_index,
            "shard_id": self.shard_id,
            "bucket_kind": self.bucket_kind.as_str(),
            "amount_bucket_commitment": self.amount_bucket_commitment,
            "output_key_commitment_root": self.output_key_commitment_root,
            "txid_commitment_root": self.txid_commitment_root,
            "bridge_contract_root": self.bridge_contract_root,
            "output_count": self.output_count,
            "min_height": self.min_height,
            "max_height": self.max_height,
            "sealed": self.sealed,
        })
    }

    pub fn bucket_root(&self) -> String {
        monero_view_tag_indexer_payload_root("MONERO-VIEW-TAG-OUTPUT-BUCKET", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalletSyncCursor {
    pub cursor_id: String,
    pub wallet_cohort_commitment: String,
    pub cursor_key_commitment: String,
    pub last_scanned_height: u64,
    pub target_height: u64,
    pub shard_cursor_root: String,
    pub encrypted_delta_root: String,
    pub null_response_root: String,
    pub disclosure_nullifier_root: String,
    pub false_positive_count: u64,
    pub match_count: u64,
    pub expires_at_height: u64,
    pub status: WalletCursorStatus,
}

impl WalletSyncCursor {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        wallet_cohort_label: &str,
        cursor_key_label: &str,
        last_scanned_height: u64,
        target_height: u64,
        shard_cursor_root: &str,
        encrypted_delta_root: &str,
        null_response_root: &str,
        disclosure_nullifier_root: &str,
        false_positive_count: u64,
        match_count: u64,
        expires_at_height: u64,
        status: WalletCursorStatus,
    ) -> MoneroViewTagIndexerResult<Self> {
        ensure_non_empty(wallet_cohort_label, "wallet cursor cohort")?;
        ensure_non_empty(cursor_key_label, "wallet cursor key")?;
        ensure_height_range(
            last_scanned_height,
            target_height,
            "wallet cursor scan range",
        )?;
        ensure_height_range(target_height, expires_at_height, "wallet cursor ttl")?;
        ensure_non_empty(shard_cursor_root, "wallet cursor shard root")?;
        ensure_non_empty(encrypted_delta_root, "wallet cursor encrypted delta root")?;
        ensure_non_empty(null_response_root, "wallet cursor null response root")?;
        ensure_non_empty(
            disclosure_nullifier_root,
            "wallet cursor disclosure nullifier root",
        )?;
        let wallet_cohort_commitment =
            monero_view_tag_string_root("MONERO-VIEW-TAG-CURSOR-COHORT", wallet_cohort_label);
        let cursor_key_commitment =
            monero_view_tag_string_root("MONERO-VIEW-TAG-CURSOR-KEY", cursor_key_label);
        let cursor_id = monero_wallet_cursor_id(
            &wallet_cohort_commitment,
            &cursor_key_commitment,
            last_scanned_height,
            target_height,
        );
        Ok(Self {
            cursor_id,
            wallet_cohort_commitment,
            cursor_key_commitment,
            last_scanned_height,
            target_height,
            shard_cursor_root: shard_cursor_root.to_string(),
            encrypted_delta_root: encrypted_delta_root.to_string(),
            null_response_root: null_response_root.to_string(),
            disclosure_nullifier_root: disclosure_nullifier_root.to_string(),
            false_positive_count,
            match_count,
            expires_at_height,
            status,
        })
    }

    pub fn validate(&self) -> MoneroViewTagIndexerResult<()> {
        ensure_non_empty(&self.cursor_id, "wallet cursor id")?;
        ensure_non_empty(
            &self.wallet_cohort_commitment,
            "wallet cursor cohort commitment",
        )?;
        ensure_non_empty(&self.cursor_key_commitment, "wallet cursor key commitment")?;
        ensure_height_range(
            self.last_scanned_height,
            self.target_height,
            "wallet cursor scan range",
        )?;
        ensure_height_range(
            self.target_height,
            self.expires_at_height,
            "wallet cursor ttl",
        )?;
        ensure_non_empty(&self.shard_cursor_root, "wallet cursor shard root")?;
        ensure_non_empty(
            &self.encrypted_delta_root,
            "wallet cursor encrypted delta root",
        )?;
        ensure_non_empty(&self.null_response_root, "wallet cursor null response root")?;
        ensure_non_empty(
            &self.disclosure_nullifier_root,
            "wallet cursor disclosure nullifier root",
        )?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "wallet_sync_cursor",
            "chain_id": CHAIN_ID,
            "cursor_id": self.cursor_id,
            "wallet_cohort_commitment": self.wallet_cohort_commitment,
            "cursor_key_commitment": self.cursor_key_commitment,
            "last_scanned_height": self.last_scanned_height,
            "target_height": self.target_height,
            "shard_cursor_root": self.shard_cursor_root,
            "encrypted_delta_root": self.encrypted_delta_root,
            "null_response_root": self.null_response_root,
            "disclosure_nullifier_root": self.disclosure_nullifier_root,
            "false_positive_count": self.false_positive_count,
            "match_count": self.match_count,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
            "can_advance": self.status.can_advance(),
        })
    }

    pub fn cursor_root(&self) -> String {
        monero_view_tag_indexer_payload_root("MONERO-VIEW-TAG-WALLET-CURSOR", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReserveScanLane {
    pub lane_id: String,
    pub lane_kind: ReserveScanLaneKind,
    pub reserve_account_commitment: String,
    pub shard_root: String,
    pub output_bucket_root: String,
    pub key_image_commitment_root: String,
    pub min_confirmations: u64,
    pub last_scanned_height: u64,
    pub target_height: u64,
    pub outstanding_output_count: u64,
    pub lane_weight: u64,
    pub active: bool,
}

impl ReserveScanLane {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        lane_kind: ReserveScanLaneKind,
        reserve_account_label: &str,
        shard_root: &str,
        output_bucket_root: &str,
        key_image_commitment_root: &str,
        min_confirmations: u64,
        last_scanned_height: u64,
        target_height: u64,
        outstanding_output_count: u64,
        lane_weight: u64,
        active: bool,
    ) -> MoneroViewTagIndexerResult<Self> {
        ensure_non_empty(reserve_account_label, "reserve scan lane account")?;
        ensure_non_empty(shard_root, "reserve scan lane shard root")?;
        ensure_non_empty(output_bucket_root, "reserve scan lane output bucket root")?;
        ensure_non_empty(
            key_image_commitment_root,
            "reserve scan lane key image commitment root",
        )?;
        ensure_height_range(
            last_scanned_height,
            target_height,
            "reserve scan lane height range",
        )?;
        if min_confirmations == 0 || lane_weight == 0 {
            return Err("reserve scan lane confirmation and weight must be positive".to_string());
        }
        let reserve_account_commitment =
            monero_view_tag_string_root("MONERO-VIEW-TAG-RESERVE-ACCOUNT", reserve_account_label);
        let lane_id = monero_reserve_scan_lane_id(
            lane_kind.as_str(),
            &reserve_account_commitment,
            target_height,
        );
        Ok(Self {
            lane_id,
            lane_kind,
            reserve_account_commitment,
            shard_root: shard_root.to_string(),
            output_bucket_root: output_bucket_root.to_string(),
            key_image_commitment_root: key_image_commitment_root.to_string(),
            min_confirmations,
            last_scanned_height,
            target_height,
            outstanding_output_count,
            lane_weight,
            active,
        })
    }

    pub fn validate(&self) -> MoneroViewTagIndexerResult<()> {
        ensure_non_empty(&self.lane_id, "reserve scan lane id")?;
        ensure_non_empty(
            &self.reserve_account_commitment,
            "reserve scan lane account commitment",
        )?;
        ensure_non_empty(&self.shard_root, "reserve scan lane shard root")?;
        ensure_non_empty(
            &self.output_bucket_root,
            "reserve scan lane output bucket root",
        )?;
        ensure_non_empty(
            &self.key_image_commitment_root,
            "reserve scan lane key image root",
        )?;
        ensure_height_range(
            self.last_scanned_height,
            self.target_height,
            "reserve scan lane height range",
        )?;
        if self.min_confirmations == 0 || self.lane_weight == 0 {
            return Err("reserve scan lane confirmation and weight must be positive".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "reserve_scan_lane",
            "chain_id": CHAIN_ID,
            "lane_id": self.lane_id,
            "lane_kind": self.lane_kind.as_str(),
            "reserve_account_commitment": self.reserve_account_commitment,
            "shard_root": self.shard_root,
            "output_bucket_root": self.output_bucket_root,
            "key_image_commitment_root": self.key_image_commitment_root,
            "min_confirmations": self.min_confirmations,
            "last_scanned_height": self.last_scanned_height,
            "target_height": self.target_height,
            "outstanding_output_count": self.outstanding_output_count,
            "lane_weight": self.lane_weight,
            "active": self.active,
        })
    }

    pub fn lane_root(&self) -> String {
        monero_view_tag_indexer_payload_root("MONERO-VIEW-TAG-RESERVE-LANE", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReorgScanWindow {
    pub window_id: String,
    pub old_anchor_root: String,
    pub new_anchor_root: String,
    pub start_height: u64,
    pub end_height: u64,
    pub replay_assignment_root: String,
    pub invalidated_shard_root: String,
    pub replacement_shard_root: String,
    pub affected_cursor_root: String,
    pub affected_bucket_root: String,
    pub status: ReorgWindowStatus,
}

impl ReorgScanWindow {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        old_anchor_root: &str,
        new_anchor_root: &str,
        start_height: u64,
        end_height: u64,
        replay_assignment_root: &str,
        invalidated_shard_root: &str,
        replacement_shard_root: &str,
        affected_cursor_root: &str,
        affected_bucket_root: &str,
        status: ReorgWindowStatus,
    ) -> MoneroViewTagIndexerResult<Self> {
        ensure_non_empty(old_anchor_root, "reorg old anchor root")?;
        ensure_non_empty(new_anchor_root, "reorg new anchor root")?;
        ensure_height_range(start_height, end_height, "reorg scan window")?;
        ensure_non_empty(replay_assignment_root, "reorg replay assignment root")?;
        ensure_non_empty(invalidated_shard_root, "reorg invalidated shard root")?;
        ensure_non_empty(replacement_shard_root, "reorg replacement shard root")?;
        ensure_non_empty(affected_cursor_root, "reorg affected cursor root")?;
        ensure_non_empty(affected_bucket_root, "reorg affected bucket root")?;
        let window_id =
            monero_reorg_window_id(old_anchor_root, new_anchor_root, start_height, end_height);
        Ok(Self {
            window_id,
            old_anchor_root: old_anchor_root.to_string(),
            new_anchor_root: new_anchor_root.to_string(),
            start_height,
            end_height,
            replay_assignment_root: replay_assignment_root.to_string(),
            invalidated_shard_root: invalidated_shard_root.to_string(),
            replacement_shard_root: replacement_shard_root.to_string(),
            affected_cursor_root: affected_cursor_root.to_string(),
            affected_bucket_root: affected_bucket_root.to_string(),
            status,
        })
    }

    pub fn validate(&self) -> MoneroViewTagIndexerResult<()> {
        ensure_non_empty(&self.window_id, "reorg scan window id")?;
        ensure_non_empty(&self.old_anchor_root, "reorg old anchor root")?;
        ensure_non_empty(&self.new_anchor_root, "reorg new anchor root")?;
        ensure_height_range(self.start_height, self.end_height, "reorg scan window")?;
        ensure_non_empty(&self.replay_assignment_root, "reorg replay assignment root")?;
        ensure_non_empty(&self.invalidated_shard_root, "reorg invalidated shard root")?;
        ensure_non_empty(&self.replacement_shard_root, "reorg replacement shard root")?;
        ensure_non_empty(&self.affected_cursor_root, "reorg affected cursor root")?;
        ensure_non_empty(&self.affected_bucket_root, "reorg affected bucket root")?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "reorg_scan_window",
            "chain_id": CHAIN_ID,
            "window_id": self.window_id,
            "old_anchor_root": self.old_anchor_root,
            "new_anchor_root": self.new_anchor_root,
            "start_height": self.start_height,
            "end_height": self.end_height,
            "replay_assignment_root": self.replay_assignment_root,
            "invalidated_shard_root": self.invalidated_shard_root,
            "replacement_shard_root": self.replacement_shard_root,
            "affected_cursor_root": self.affected_cursor_root,
            "affected_bucket_root": self.affected_bucket_root,
            "status": self.status.as_str(),
            "open": self.status.is_open(),
        })
    }

    pub fn window_root(&self) -> String {
        monero_view_tag_indexer_payload_root("MONERO-VIEW-TAG-REORG-WINDOW", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqScannerAttestation {
    pub attestation_id: String,
    pub scanner_commitment: String,
    pub scanner_role: PqScannerRole,
    pub pq_public_key_root: String,
    pub endpoint_commitment: String,
    pub assignment_root: String,
    pub scan_result_root: String,
    pub signature_root: String,
    pub attested_at_height: u64,
    pub valid_until_height: u64,
    pub quorum_weight: u64,
    pub security_bits: u16,
    pub status: ScannerAttestationStatus,
}

impl PqScannerAttestation {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        scanner_label: &str,
        scanner_role: PqScannerRole,
        pq_public_key_root: &str,
        endpoint_commitment: &str,
        assignment_root: &str,
        scan_result_root: &str,
        signature_root: &str,
        attested_at_height: u64,
        valid_until_height: u64,
        quorum_weight: u64,
        security_bits: u16,
        status: ScannerAttestationStatus,
    ) -> MoneroViewTagIndexerResult<Self> {
        ensure_non_empty(scanner_label, "pq scanner label")?;
        ensure_non_empty(pq_public_key_root, "pq scanner public key root")?;
        ensure_non_empty(endpoint_commitment, "pq scanner endpoint commitment")?;
        ensure_non_empty(assignment_root, "pq scanner assignment root")?;
        ensure_non_empty(scan_result_root, "pq scanner result root")?;
        ensure_non_empty(signature_root, "pq scanner signature root")?;
        ensure_height_range(
            attested_at_height,
            valid_until_height,
            "pq scanner attestation",
        )?;
        if quorum_weight == 0 || security_bits < 128 {
            return Err(
                "pq scanner quorum weight and security bits must be sufficient".to_string(),
            );
        }
        let scanner_commitment =
            monero_view_tag_string_root("MONERO-VIEW-TAG-SCANNER", scanner_label);
        let attestation_id = monero_pq_scanner_attestation_id(
            &scanner_commitment,
            scanner_role.as_str(),
            assignment_root,
            attested_at_height,
        );
        Ok(Self {
            attestation_id,
            scanner_commitment,
            scanner_role,
            pq_public_key_root: pq_public_key_root.to_string(),
            endpoint_commitment: endpoint_commitment.to_string(),
            assignment_root: assignment_root.to_string(),
            scan_result_root: scan_result_root.to_string(),
            signature_root: signature_root.to_string(),
            attested_at_height,
            valid_until_height,
            quorum_weight,
            security_bits,
            status,
        })
    }

    pub fn validate(&self) -> MoneroViewTagIndexerResult<()> {
        ensure_non_empty(&self.attestation_id, "pq scanner attestation id")?;
        ensure_non_empty(&self.scanner_commitment, "pq scanner commitment")?;
        ensure_non_empty(&self.pq_public_key_root, "pq scanner public key root")?;
        ensure_non_empty(&self.endpoint_commitment, "pq scanner endpoint commitment")?;
        ensure_non_empty(&self.assignment_root, "pq scanner assignment root")?;
        ensure_non_empty(&self.scan_result_root, "pq scanner result root")?;
        ensure_non_empty(&self.signature_root, "pq scanner signature root")?;
        ensure_height_range(
            self.attested_at_height,
            self.valid_until_height,
            "pq scanner attestation",
        )?;
        if self.quorum_weight == 0 || self.security_bits < 128 {
            return Err(
                "pq scanner quorum weight and security bits must be sufficient".to_string(),
            );
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_scanner_attestation",
            "chain_id": CHAIN_ID,
            "attestation_id": self.attestation_id,
            "scanner_commitment": self.scanner_commitment,
            "scanner_role": self.scanner_role.as_str(),
            "pq_public_key_root": self.pq_public_key_root,
            "endpoint_commitment": self.endpoint_commitment,
            "assignment_root": self.assignment_root,
            "scan_result_root": self.scan_result_root,
            "signature_root": self.signature_root,
            "attested_at_height": self.attested_at_height,
            "valid_until_height": self.valid_until_height,
            "quorum_weight": self.quorum_weight,
            "security_bits": self.security_bits,
            "status": self.status.as_str(),
            "counts_for_quorum": self.status.counts_for_quorum(),
        })
    }

    pub fn attestation_root(&self) -> String {
        monero_view_tag_indexer_payload_root(
            "MONERO-VIEW-TAG-PQ-SCANNER-ATTESTATION",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeScanSponsorship {
    pub sponsorship_id: String,
    pub sponsor_commitment: String,
    pub beneficiary_cohort_commitment: String,
    pub assignment_root: String,
    pub fee_asset_id: String,
    pub prepaid_units: u64,
    pub consumed_units: u64,
    pub unit_price: u64,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub receipt_root: String,
    pub status: SponsorshipStatus,
}

impl LowFeeScanSponsorship {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        sponsor_label: &str,
        beneficiary_cohort_label: &str,
        assignment_root: &str,
        fee_asset_id: &str,
        prepaid_units: u64,
        consumed_units: u64,
        unit_price: u64,
        opened_at_height: u64,
        expires_at_height: u64,
        receipt_root: &str,
        status: SponsorshipStatus,
    ) -> MoneroViewTagIndexerResult<Self> {
        ensure_non_empty(sponsor_label, "scan sponsorship sponsor")?;
        ensure_non_empty(beneficiary_cohort_label, "scan sponsorship beneficiary")?;
        ensure_non_empty(assignment_root, "scan sponsorship assignment root")?;
        ensure_non_empty(fee_asset_id, "scan sponsorship fee asset")?;
        ensure_non_empty(receipt_root, "scan sponsorship receipt root")?;
        ensure_height_range(opened_at_height, expires_at_height, "scan sponsorship")?;
        if prepaid_units == 0 || consumed_units > prepaid_units {
            return Err("scan sponsorship units are invalid".to_string());
        }
        let sponsor_commitment =
            monero_view_tag_string_root("MONERO-VIEW-TAG-SPONSOR", sponsor_label);
        let beneficiary_cohort_commitment = monero_view_tag_string_root(
            "MONERO-VIEW-TAG-SPONSORED-COHORT",
            beneficiary_cohort_label,
        );
        let sponsorship_id = monero_scan_sponsorship_id(
            &sponsor_commitment,
            &beneficiary_cohort_commitment,
            assignment_root,
            opened_at_height,
        );
        Ok(Self {
            sponsorship_id,
            sponsor_commitment,
            beneficiary_cohort_commitment,
            assignment_root: assignment_root.to_string(),
            fee_asset_id: fee_asset_id.to_string(),
            prepaid_units,
            consumed_units,
            unit_price,
            opened_at_height,
            expires_at_height,
            receipt_root: receipt_root.to_string(),
            status,
        })
    }

    pub fn validate(&self) -> MoneroViewTagIndexerResult<()> {
        ensure_non_empty(&self.sponsorship_id, "scan sponsorship id")?;
        ensure_non_empty(&self.sponsor_commitment, "scan sponsorship sponsor")?;
        ensure_non_empty(
            &self.beneficiary_cohort_commitment,
            "scan sponsorship beneficiary",
        )?;
        ensure_non_empty(&self.assignment_root, "scan sponsorship assignment root")?;
        ensure_non_empty(&self.fee_asset_id, "scan sponsorship fee asset")?;
        ensure_non_empty(&self.receipt_root, "scan sponsorship receipt root")?;
        ensure_height_range(
            self.opened_at_height,
            self.expires_at_height,
            "scan sponsorship",
        )?;
        if self.prepaid_units == 0 || self.consumed_units > self.prepaid_units {
            return Err("scan sponsorship units are invalid".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "low_fee_scan_sponsorship",
            "chain_id": CHAIN_ID,
            "sponsorship_id": self.sponsorship_id,
            "sponsor_commitment": self.sponsor_commitment,
            "beneficiary_cohort_commitment": self.beneficiary_cohort_commitment,
            "assignment_root": self.assignment_root,
            "fee_asset_id": self.fee_asset_id,
            "prepaid_units": self.prepaid_units,
            "consumed_units": self.consumed_units,
            "remaining_units": self.prepaid_units.saturating_sub(self.consumed_units),
            "unit_price": self.unit_price,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "receipt_root": self.receipt_root,
            "status": self.status.as_str(),
            "live": self.status.is_live(),
        })
    }

    pub fn sponsorship_root(&self) -> String {
        monero_view_tag_indexer_payload_root(
            "MONERO-VIEW-TAG-SCAN-SPONSORSHIP",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivacyBudget {
    pub budget_id: String,
    pub scope: PrivacyBudgetScope,
    pub cohort_commitment: String,
    pub epoch: u64,
    pub window_start_height: u64,
    pub window_end_height: u64,
    pub max_queries: u64,
    pub used_queries: u64,
    pub max_false_positive_reveals: u64,
    pub used_false_positive_reveals: u64,
    pub disclosure_nullifier_root: String,
    pub rate_limit_root: String,
}

impl PrivacyBudget {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        scope: PrivacyBudgetScope,
        cohort_label: &str,
        epoch: u64,
        window_start_height: u64,
        window_end_height: u64,
        max_queries: u64,
        used_queries: u64,
        max_false_positive_reveals: u64,
        used_false_positive_reveals: u64,
        disclosure_nullifier_root: &str,
        rate_limit_root: &str,
    ) -> MoneroViewTagIndexerResult<Self> {
        ensure_non_empty(cohort_label, "privacy budget cohort")?;
        ensure_height_range(window_start_height, window_end_height, "privacy budget")?;
        ensure_non_empty(
            disclosure_nullifier_root,
            "privacy budget disclosure nullifier root",
        )?;
        ensure_non_empty(rate_limit_root, "privacy budget rate limit root")?;
        if max_queries == 0
            || used_queries > max_queries
            || used_false_positive_reveals > max_false_positive_reveals
        {
            return Err("privacy budget limits are invalid".to_string());
        }
        let cohort_commitment =
            monero_view_tag_string_root("MONERO-VIEW-TAG-PRIVACY-COHORT", cohort_label);
        let budget_id = monero_privacy_budget_id(
            scope.as_str(),
            &cohort_commitment,
            epoch,
            window_start_height,
        );
        Ok(Self {
            budget_id,
            scope,
            cohort_commitment,
            epoch,
            window_start_height,
            window_end_height,
            max_queries,
            used_queries,
            max_false_positive_reveals,
            used_false_positive_reveals,
            disclosure_nullifier_root: disclosure_nullifier_root.to_string(),
            rate_limit_root: rate_limit_root.to_string(),
        })
    }

    pub fn validate(&self) -> MoneroViewTagIndexerResult<()> {
        ensure_non_empty(&self.budget_id, "privacy budget id")?;
        ensure_non_empty(&self.cohort_commitment, "privacy budget cohort commitment")?;
        ensure_height_range(
            self.window_start_height,
            self.window_end_height,
            "privacy budget",
        )?;
        ensure_non_empty(
            &self.disclosure_nullifier_root,
            "privacy budget disclosure nullifier root",
        )?;
        ensure_non_empty(&self.rate_limit_root, "privacy budget rate limit root")?;
        if self.max_queries == 0
            || self.used_queries > self.max_queries
            || self.used_false_positive_reveals > self.max_false_positive_reveals
        {
            return Err("privacy budget limits are invalid".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "privacy_budget",
            "chain_id": CHAIN_ID,
            "budget_id": self.budget_id,
            "scope": self.scope.as_str(),
            "cohort_commitment": self.cohort_commitment,
            "epoch": self.epoch,
            "window_start_height": self.window_start_height,
            "window_end_height": self.window_end_height,
            "max_queries": self.max_queries,
            "used_queries": self.used_queries,
            "remaining_queries": self.max_queries.saturating_sub(self.used_queries),
            "max_false_positive_reveals": self.max_false_positive_reveals,
            "used_false_positive_reveals": self.used_false_positive_reveals,
            "disclosure_nullifier_root": self.disclosure_nullifier_root,
            "rate_limit_root": self.rate_limit_root,
        })
    }

    pub fn budget_root(&self) -> String {
        monero_view_tag_indexer_payload_root(
            "MONERO-VIEW-TAG-PRIVACY-BUDGET",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndexCompactionPlan {
    pub compaction_id: String,
    pub source_shard_root: String,
    pub compacted_shard_root: String,
    pub tombstone_root: String,
    pub carry_forward_cursor_root: String,
    pub start_height: u64,
    pub end_height: u64,
    pub before_bytes: u64,
    pub after_bytes: u64,
    pub retained_bucket_count: u64,
    pub pruned_hint_count: u64,
    pub status: CompactionStatus,
}

impl IndexCompactionPlan {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        source_shard_root: &str,
        compacted_shard_root: &str,
        tombstone_root: &str,
        carry_forward_cursor_root: &str,
        start_height: u64,
        end_height: u64,
        before_bytes: u64,
        after_bytes: u64,
        retained_bucket_count: u64,
        pruned_hint_count: u64,
        status: CompactionStatus,
    ) -> MoneroViewTagIndexerResult<Self> {
        ensure_non_empty(source_shard_root, "compaction source shard root")?;
        ensure_non_empty(compacted_shard_root, "compaction compacted shard root")?;
        ensure_non_empty(tombstone_root, "compaction tombstone root")?;
        ensure_non_empty(carry_forward_cursor_root, "compaction carry cursor root")?;
        ensure_height_range(start_height, end_height, "index compaction plan")?;
        if after_bytes > before_bytes {
            return Err("compaction after bytes cannot exceed before bytes".to_string());
        }
        let compaction_id = monero_index_compaction_id(
            source_shard_root,
            compacted_shard_root,
            start_height,
            end_height,
        );
        Ok(Self {
            compaction_id,
            source_shard_root: source_shard_root.to_string(),
            compacted_shard_root: compacted_shard_root.to_string(),
            tombstone_root: tombstone_root.to_string(),
            carry_forward_cursor_root: carry_forward_cursor_root.to_string(),
            start_height,
            end_height,
            before_bytes,
            after_bytes,
            retained_bucket_count,
            pruned_hint_count,
            status,
        })
    }

    pub fn validate(&self) -> MoneroViewTagIndexerResult<()> {
        ensure_non_empty(&self.compaction_id, "compaction id")?;
        ensure_non_empty(&self.source_shard_root, "compaction source shard root")?;
        ensure_non_empty(
            &self.compacted_shard_root,
            "compaction compacted shard root",
        )?;
        ensure_non_empty(&self.tombstone_root, "compaction tombstone root")?;
        ensure_non_empty(
            &self.carry_forward_cursor_root,
            "compaction carry cursor root",
        )?;
        ensure_height_range(self.start_height, self.end_height, "index compaction plan")?;
        if self.after_bytes > self.before_bytes {
            return Err("compaction after bytes cannot exceed before bytes".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "index_compaction_plan",
            "chain_id": CHAIN_ID,
            "compaction_id": self.compaction_id,
            "source_shard_root": self.source_shard_root,
            "compacted_shard_root": self.compacted_shard_root,
            "tombstone_root": self.tombstone_root,
            "carry_forward_cursor_root": self.carry_forward_cursor_root,
            "start_height": self.start_height,
            "end_height": self.end_height,
            "before_bytes": self.before_bytes,
            "after_bytes": self.after_bytes,
            "saved_bytes": self.before_bytes.saturating_sub(self.after_bytes),
            "retained_bucket_count": self.retained_bucket_count,
            "pruned_hint_count": self.pruned_hint_count,
            "status": self.status.as_str(),
            "current": self.status.is_current(),
        })
    }

    pub fn compaction_root(&self) -> String {
        monero_view_tag_indexer_payload_root(
            "MONERO-VIEW-TAG-INDEX-COMPACTION",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroViewTagIndexerRoots {
    pub config_root: String,
    pub shard_root: String,
    pub assignment_root: String,
    pub output_bucket_root: String,
    pub wallet_cursor_root: String,
    pub reserve_lane_root: String,
    pub reorg_window_root: String,
    pub pq_attestation_root: String,
    pub sponsorship_root: String,
    pub privacy_budget_root: String,
    pub compaction_root: String,
    pub public_record_root: String,
}

impl MoneroViewTagIndexerRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_view_tag_indexer_roots",
            "chain_id": CHAIN_ID,
            "config_root": self.config_root,
            "shard_root": self.shard_root,
            "assignment_root": self.assignment_root,
            "output_bucket_root": self.output_bucket_root,
            "wallet_cursor_root": self.wallet_cursor_root,
            "reserve_lane_root": self.reserve_lane_root,
            "reorg_window_root": self.reorg_window_root,
            "pq_attestation_root": self.pq_attestation_root,
            "sponsorship_root": self.sponsorship_root,
            "privacy_budget_root": self.privacy_budget_root,
            "compaction_root": self.compaction_root,
            "public_record_root": self.public_record_root,
        })
    }

    pub fn roots_root(&self) -> String {
        monero_view_tag_indexer_payload_root("MONERO-VIEW-TAG-INDEXER-ROOTS", &self.public_record())
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroViewTagIndexerCounters {
    pub shard_count: u64,
    pub active_shard_count: u64,
    pub assignment_count: u64,
    pub active_assignment_count: u64,
    pub output_bucket_count: u64,
    pub indexed_output_count: u64,
    pub candidate_match_count: u64,
    pub wallet_cursor_count: u64,
    pub active_wallet_cursor_count: u64,
    pub reserve_lane_count: u64,
    pub active_reserve_lane_count: u64,
    pub reorg_window_count: u64,
    pub open_reorg_window_count: u64,
    pub pq_attestation_count: u64,
    pub accepted_pq_attestation_count: u64,
    pub sponsorship_count: u64,
    pub live_sponsorship_count: u64,
    pub sponsored_scan_units: u64,
    pub privacy_budget_count: u64,
    pub total_privacy_queries: u64,
    pub used_privacy_queries: u64,
    pub compaction_count: u64,
    pub compacted_saved_bytes: u64,
}

impl MoneroViewTagIndexerCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_view_tag_indexer_counters",
            "chain_id": CHAIN_ID,
            "shard_count": self.shard_count,
            "active_shard_count": self.active_shard_count,
            "assignment_count": self.assignment_count,
            "active_assignment_count": self.active_assignment_count,
            "output_bucket_count": self.output_bucket_count,
            "indexed_output_count": self.indexed_output_count,
            "candidate_match_count": self.candidate_match_count,
            "wallet_cursor_count": self.wallet_cursor_count,
            "active_wallet_cursor_count": self.active_wallet_cursor_count,
            "reserve_lane_count": self.reserve_lane_count,
            "active_reserve_lane_count": self.active_reserve_lane_count,
            "reorg_window_count": self.reorg_window_count,
            "open_reorg_window_count": self.open_reorg_window_count,
            "pq_attestation_count": self.pq_attestation_count,
            "accepted_pq_attestation_count": self.accepted_pq_attestation_count,
            "sponsorship_count": self.sponsorship_count,
            "live_sponsorship_count": self.live_sponsorship_count,
            "sponsored_scan_units": self.sponsored_scan_units,
            "privacy_budget_count": self.privacy_budget_count,
            "total_privacy_queries": self.total_privacy_queries,
            "used_privacy_queries": self.used_privacy_queries,
            "compaction_count": self.compaction_count,
            "compacted_saved_bytes": self.compacted_saved_bytes,
        })
    }

    pub fn counters_root(&self) -> String {
        monero_view_tag_indexer_payload_root(
            "MONERO-VIEW-TAG-INDEXER-COUNTERS",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroViewTagIndexerState {
    pub height: u64,
    pub config: MoneroViewTagIndexerConfig,
    pub shards: BTreeMap<String, ViewTagShard>,
    pub encrypted_scan_assignments: BTreeMap<String, EncryptedScanAssignment>,
    pub output_bucket_commitments: BTreeMap<String, OutputBucketCommitment>,
    pub wallet_sync_cursors: BTreeMap<String, WalletSyncCursor>,
    pub reserve_scan_lanes: BTreeMap<String, ReserveScanLane>,
    pub reorg_windows: BTreeMap<String, ReorgScanWindow>,
    pub pq_scanner_attestations: BTreeMap<String, PqScannerAttestation>,
    pub low_fee_scan_sponsorships: BTreeMap<String, LowFeeScanSponsorship>,
    pub privacy_budgets: BTreeMap<String, PrivacyBudget>,
    pub index_compactions: BTreeMap<String, IndexCompactionPlan>,
}

impl MoneroViewTagIndexerState {
    pub fn devnet() -> MoneroViewTagIndexerResult<Self> {
        let config = MoneroViewTagIndexerConfig::default();
        config.validate()?;
        let height = 128;
        let empty = monero_view_tag_indexer_empty_root("MONERO-VIEW-TAG-EMPTY");
        let scanner_set_root = monero_view_tag_string_set_root(
            "MONERO-VIEW-TAG-DEVNET-SCANNERS",
            &["scanner-alpha", "scanner-beta", "scanner-gamma"],
        );
        let bridge_contract_root = monero_view_tag_string_set_root(
            "MONERO-VIEW-TAG-DEVNET-BRIDGE-CONTRACTS",
            &[
                "deposit-router",
                "reserve-accounting",
                "private-defi-ingress",
            ],
        );
        let shard_a_tag_root = monero_view_tag_string_set_root(
            "MONERO-VIEW-TAG-DEVNET-SHARD-A-TAGS",
            &["00", "01", "02", "03"],
        );
        let shard_b_tag_root = monero_view_tag_string_set_root(
            "MONERO-VIEW-TAG-DEVNET-SHARD-B-TAGS",
            &["10", "11", "12", "13"],
        );
        let bucket_a_output_root = monero_view_tag_string_set_root(
            "MONERO-VIEW-TAG-DEVNET-BUCKET-A-OUTPUTS",
            &[
                "output-key-cohort-a",
                "output-key-cohort-b",
                "output-key-cohort-c",
            ],
        );
        let bucket_b_output_root = monero_view_tag_string_set_root(
            "MONERO-VIEW-TAG-DEVNET-BUCKET-B-OUTPUTS",
            &["output-key-cohort-d", "output-key-cohort-e"],
        );
        let bucket_a_txid_root = monero_view_tag_string_set_root(
            "MONERO-VIEW-TAG-DEVNET-BUCKET-A-TXIDS",
            &["tx-cohort-a", "tx-cohort-b"],
        );
        let bucket_b_txid_root = monero_view_tag_string_set_root(
            "MONERO-VIEW-TAG-DEVNET-BUCKET-B-TXIDS",
            &["tx-cohort-c", "tx-cohort-d"],
        );

        let bucket_a = OutputBucketCommitment::new(
            0,
            "devnet-shard-anchor-a",
            OutputBucketKind::DepositCandidate,
            "0..0.1-xmr",
            &bucket_a_output_root,
            &bucket_a_txid_root,
            &bridge_contract_root,
            128,
            96,
            height,
            false,
        )?;
        let bucket_b = OutputBucketCommitment::new(
            1,
            "devnet-shard-anchor-b",
            OutputBucketKind::ContractNote,
            "0.1..1-xmr",
            &bucket_b_output_root,
            &bucket_b_txid_root,
            &bridge_contract_root,
            64,
            96,
            height,
            false,
        )?;
        let bucket_root = monero_view_tag_record_root(
            "MONERO-VIEW-TAG-DEVNET-BUCKET-ROOT",
            &[bucket_a.public_record(), bucket_b.public_record()],
        );
        let assignment_hint_root = monero_view_tag_indexer_payload_root(
            "MONERO-VIEW-TAG-DEVNET-ASSIGNMENT-HINTS",
            &json!({
                "hint_model": "encrypted-bucket-bitset",
                "view_tag_bits": config.view_tag_bits,
                "leakage": "cohort-only"
            }),
        );
        let assignment_a = EncryptedScanAssignment::new(
            "devnet-shard-anchor-a",
            ScanAssignmentKind::BridgeWatch,
            "bridge-wallet-cohort-alpha",
            &scanner_set_root,
            &monero_view_tag_string_root("MONERO-VIEW-TAG-DEVNET-CIPHERTEXT", "assignment-a"),
            &assignment_hint_root,
            &monero_view_tag_string_root("MONERO-VIEW-TAG-DEVNET-RELAY", "mix-route-a"),
            112,
            136,
            320,
            8_000,
            ScanAssignmentStatus::Leased,
        )?;
        let assignment_b = EncryptedScanAssignment::new(
            "devnet-shard-anchor-b",
            ScanAssignmentKind::WalletSync,
            "mobile-wallet-cohort-beta",
            &scanner_set_root,
            &monero_view_tag_string_root("MONERO-VIEW-TAG-DEVNET-CIPHERTEXT", "assignment-b"),
            &assignment_hint_root,
            &monero_view_tag_string_root("MONERO-VIEW-TAG-DEVNET-RELAY", "mix-route-b"),
            120,
            144,
            224,
            6_500,
            ScanAssignmentStatus::Queued,
        )?;
        let assignment_root = monero_view_tag_record_root(
            "MONERO-VIEW-TAG-DEVNET-ASSIGNMENT-ROOT",
            &[assignment_a.public_record(), assignment_b.public_record()],
        );

        let shard_a = ViewTagShard::new(
            0,
            16,
            96,
            height,
            "00",
            &shard_a_tag_root,
            &bucket_root,
            &scanner_set_root,
            &assignment_root,
            32,
            4096,
            128,
            9,
            ViewTagShardStatus::Open,
        )?;
        let shard_b = ViewTagShard::new(
            1,
            16,
            96,
            height,
            "10",
            &shard_b_tag_root,
            &bucket_root,
            &scanner_set_root,
            &assignment_root,
            24,
            3072,
            64,
            5,
            ViewTagShardStatus::Sealed,
        )?;
        let shard_root = monero_view_tag_record_root(
            "MONERO-VIEW-TAG-DEVNET-SHARD-ROOT",
            &[shard_a.public_record(), shard_b.public_record()],
        );

        let cursor_a = WalletSyncCursor::new(
            "mobile-wallet-cohort-beta",
            "cursor-rotation-2026-06",
            96,
            height,
            &shard_root,
            &monero_view_tag_string_root("MONERO-VIEW-TAG-DEVNET-DELTA", "cursor-a"),
            &monero_view_tag_string_root("MONERO-VIEW-TAG-DEVNET-NULLS", "cursor-a"),
            &monero_view_tag_string_root("MONERO-VIEW-TAG-DEVNET-DISCLOSURE", "cursor-a"),
            6,
            2,
            848,
            WalletCursorStatus::Active,
        )?;
        let cursor_b = WalletSyncCursor::new(
            "bridge-wallet-cohort-alpha",
            "cursor-bridge-rotation-2026-06",
            104,
            height,
            &shard_root,
            &monero_view_tag_string_root("MONERO-VIEW-TAG-DEVNET-DELTA", "cursor-b"),
            &monero_view_tag_string_root("MONERO-VIEW-TAG-DEVNET-NULLS", "cursor-b"),
            &monero_view_tag_string_root("MONERO-VIEW-TAG-DEVNET-DISCLOSURE", "cursor-b"),
            3,
            4,
            848,
            WalletCursorStatus::Rotating,
        )?;
        let cursor_root = monero_view_tag_record_root(
            "MONERO-VIEW-TAG-DEVNET-CURSOR-ROOT",
            &[cursor_a.public_record(), cursor_b.public_record()],
        );

        let reserve_lane = ReserveScanLane::new(
            ReserveScanLaneKind::BridgeLiquidity,
            "devnet-bridge-reserve-cohort",
            &shard_root,
            &bucket_root,
            &monero_view_tag_string_root("MONERO-VIEW-TAG-DEVNET-KEY-IMAGES", "reserve-lane"),
            12,
            96,
            height,
            27,
            3,
            true,
        )?;
        let proof_lane = ReserveScanLane::new(
            ReserveScanLaneKind::ProofOfReserve,
            "devnet-proof-reserve-cohort",
            &shard_root,
            &bucket_root,
            &monero_view_tag_string_root("MONERO-VIEW-TAG-DEVNET-KEY-IMAGES", "proof-lane"),
            12,
            96,
            height,
            18,
            2,
            true,
        )?;
        let _reserve_lane_root = monero_view_tag_record_root(
            "MONERO-VIEW-TAG-DEVNET-RESERVE-LANE-ROOT",
            &[reserve_lane.public_record(), proof_lane.public_record()],
        );

        let reorg_window = ReorgScanWindow::new(
            &monero_view_tag_string_root("MONERO-VIEW-TAG-DEVNET-OLD-ANCHOR", "height-120"),
            &monero_view_tag_string_root("MONERO-VIEW-TAG-DEVNET-NEW-ANCHOR", "height-120"),
            112,
            height,
            &assignment_root,
            &empty,
            &shard_root,
            &cursor_root,
            &bucket_root,
            ReorgWindowStatus::Watching,
        )?;
        let _reorg_window_root = monero_view_tag_record_root(
            "MONERO-VIEW-TAG-DEVNET-REORG-WINDOW-ROOT",
            &[reorg_window.public_record()],
        );

        let attestation_a = PqScannerAttestation::new(
            "scanner-alpha",
            PqScannerRole::BridgeScanner,
            &monero_view_tag_string_root("MONERO-VIEW-TAG-DEVNET-PQ-PK", "scanner-alpha"),
            &monero_view_tag_string_root("MONERO-VIEW-TAG-DEVNET-ENDPOINT", "scanner-alpha"),
            &assignment_root,
            &bucket_root,
            &monero_view_tag_string_root("MONERO-VIEW-TAG-DEVNET-SIGNATURE", "scanner-alpha"),
            124,
            156,
            2,
            config.pq_security_bits,
            ScannerAttestationStatus::Accepted,
        )?;
        let attestation_b = PqScannerAttestation::new(
            "scanner-beta",
            PqScannerRole::WalletRelayer,
            &monero_view_tag_string_root("MONERO-VIEW-TAG-DEVNET-PQ-PK", "scanner-beta"),
            &monero_view_tag_string_root("MONERO-VIEW-TAG-DEVNET-ENDPOINT", "scanner-beta"),
            &assignment_root,
            &cursor_root,
            &monero_view_tag_string_root("MONERO-VIEW-TAG-DEVNET-SIGNATURE", "scanner-beta"),
            124,
            156,
            1,
            config.pq_security_bits,
            ScannerAttestationStatus::Accepted,
        )?;
        let _attestation_root = monero_view_tag_record_root(
            "MONERO-VIEW-TAG-DEVNET-ATTESTATION-ROOT",
            &[attestation_a.public_record(), attestation_b.public_record()],
        );

        let sponsorship = LowFeeScanSponsorship::new(
            "devnet-sponsor-pool",
            "mobile-wallet-cohort-beta",
            &assignment_root,
            &config.fee_asset_id,
            2_000,
            544,
            config.low_fee_scan_unit_price,
            112,
            208,
            &monero_view_tag_string_root("MONERO-VIEW-TAG-DEVNET-SPONSOR-RECEIPT", "pool-a"),
            SponsorshipStatus::Reserved,
        )?;
        let _sponsorship_root = monero_view_tag_record_root(
            "MONERO-VIEW-TAG-DEVNET-SPONSORSHIP-ROOT",
            &[sponsorship.public_record()],
        );

        let privacy_a = PrivacyBudget::new(
            PrivacyBudgetScope::WalletSync,
            "mobile-wallet-cohort-beta",
            1,
            96,
            192,
            512,
            48,
            16,
            2,
            &monero_view_tag_string_root("MONERO-VIEW-TAG-DEVNET-PRIVACY-NULLIFIER", "wallet"),
            &monero_view_tag_string_root("MONERO-VIEW-TAG-DEVNET-RATE-LIMIT", "wallet"),
        )?;
        let privacy_b = PrivacyBudget::new(
            PrivacyBudgetScope::BridgeScanning,
            "bridge-wallet-cohort-alpha",
            1,
            96,
            192,
            256,
            36,
            12,
            1,
            &monero_view_tag_string_root("MONERO-VIEW-TAG-DEVNET-PRIVACY-NULLIFIER", "bridge"),
            &monero_view_tag_string_root("MONERO-VIEW-TAG-DEVNET-RATE-LIMIT", "bridge"),
        )?;
        let _privacy_root = monero_view_tag_record_root(
            "MONERO-VIEW-TAG-DEVNET-PRIVACY-ROOT",
            &[privacy_a.public_record(), privacy_b.public_record()],
        );

        let compaction = IndexCompactionPlan::new(
            &shard_root,
            &monero_view_tag_string_root("MONERO-VIEW-TAG-DEVNET-COMPACTED-SHARDS", "epoch-15"),
            &monero_view_tag_string_root("MONERO-VIEW-TAG-DEVNET-TOMBSTONES", "epoch-15"),
            &cursor_root,
            64,
            96,
            98_304,
            43_008,
            24,
            768,
            CompactionStatus::Scheduled,
        )?;

        let mut shards = BTreeMap::new();
        shards.insert(shard_a.shard_id.clone(), shard_a);
        shards.insert(shard_b.shard_id.clone(), shard_b);
        let mut encrypted_scan_assignments = BTreeMap::new();
        encrypted_scan_assignments.insert(assignment_a.assignment_id.clone(), assignment_a);
        encrypted_scan_assignments.insert(assignment_b.assignment_id.clone(), assignment_b);
        let mut output_bucket_commitments = BTreeMap::new();
        output_bucket_commitments.insert(bucket_a.bucket_id.clone(), bucket_a);
        output_bucket_commitments.insert(bucket_b.bucket_id.clone(), bucket_b);
        let mut wallet_sync_cursors = BTreeMap::new();
        wallet_sync_cursors.insert(cursor_a.cursor_id.clone(), cursor_a);
        wallet_sync_cursors.insert(cursor_b.cursor_id.clone(), cursor_b);
        let mut reserve_scan_lanes = BTreeMap::new();
        reserve_scan_lanes.insert(reserve_lane.lane_id.clone(), reserve_lane);
        reserve_scan_lanes.insert(proof_lane.lane_id.clone(), proof_lane);
        let mut reorg_windows = BTreeMap::new();
        reorg_windows.insert(reorg_window.window_id.clone(), reorg_window);
        let mut pq_scanner_attestations = BTreeMap::new();
        pq_scanner_attestations.insert(attestation_a.attestation_id.clone(), attestation_a);
        pq_scanner_attestations.insert(attestation_b.attestation_id.clone(), attestation_b);
        let mut low_fee_scan_sponsorships = BTreeMap::new();
        low_fee_scan_sponsorships.insert(sponsorship.sponsorship_id.clone(), sponsorship);
        let mut privacy_budgets = BTreeMap::new();
        privacy_budgets.insert(privacy_a.budget_id.clone(), privacy_a);
        privacy_budgets.insert(privacy_b.budget_id.clone(), privacy_b);
        let mut index_compactions = BTreeMap::new();
        index_compactions.insert(compaction.compaction_id.clone(), compaction);

        let state = Self {
            height,
            config,
            shards,
            encrypted_scan_assignments,
            output_bucket_commitments,
            wallet_sync_cursors,
            reserve_scan_lanes,
            reorg_windows,
            pq_scanner_attestations,
            low_fee_scan_sponsorships,
            privacy_budgets,
            index_compactions,
        };
        state.validate()?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) -> MoneroViewTagIndexerResult<()> {
        if height < self.height {
            return Err("view tag indexer height cannot move backwards".to_string());
        }
        self.height = height;
        self.validate()
    }

    pub fn roots(&self) -> MoneroViewTagIndexerRoots {
        let mut public_records = Vec::new();
        let config_root = self.config.config_root();
        let shard_root = self.shard_root();
        let assignment_root = self.assignment_root();
        let output_bucket_root = self.output_bucket_root();
        let wallet_cursor_root = self.wallet_cursor_root();
        let reserve_lane_root = self.reserve_lane_root();
        let reorg_window_root = self.reorg_window_root();
        let pq_attestation_root = self.pq_attestation_root();
        let sponsorship_root = self.sponsorship_root();
        let privacy_budget_root = self.privacy_budget_root();
        let compaction_root = self.compaction_root();
        public_records.push(self.config.public_record());
        public_records.extend(self.shards.values().map(ViewTagShard::public_record));
        public_records.extend(
            self.encrypted_scan_assignments
                .values()
                .map(EncryptedScanAssignment::public_record),
        );
        public_records.extend(
            self.output_bucket_commitments
                .values()
                .map(OutputBucketCommitment::public_record),
        );
        public_records.extend(
            self.wallet_sync_cursors
                .values()
                .map(WalletSyncCursor::public_record),
        );
        public_records.extend(
            self.reserve_scan_lanes
                .values()
                .map(ReserveScanLane::public_record),
        );
        public_records.extend(
            self.reorg_windows
                .values()
                .map(ReorgScanWindow::public_record),
        );
        public_records.extend(
            self.pq_scanner_attestations
                .values()
                .map(PqScannerAttestation::public_record),
        );
        public_records.extend(
            self.low_fee_scan_sponsorships
                .values()
                .map(LowFeeScanSponsorship::public_record),
        );
        public_records.extend(
            self.privacy_budgets
                .values()
                .map(PrivacyBudget::public_record),
        );
        public_records.extend(
            self.index_compactions
                .values()
                .map(IndexCompactionPlan::public_record),
        );
        let public_record_root =
            monero_view_tag_record_root("MONERO-VIEW-TAG-INDEXER-PUBLIC-RECORDS", &public_records);
        MoneroViewTagIndexerRoots {
            config_root,
            shard_root,
            assignment_root,
            output_bucket_root,
            wallet_cursor_root,
            reserve_lane_root,
            reorg_window_root,
            pq_attestation_root,
            sponsorship_root,
            privacy_budget_root,
            compaction_root,
            public_record_root,
        }
    }

    pub fn counters(&self) -> MoneroViewTagIndexerCounters {
        let shard_count = self.shards.len() as u64;
        let active_shard_count = self
            .shards
            .values()
            .filter(|shard| shard.status.is_indexable())
            .count() as u64;
        let assignment_count = self.encrypted_scan_assignments.len() as u64;
        let active_assignment_count = self
            .encrypted_scan_assignments
            .values()
            .filter(|assignment| assignment.status.is_active())
            .count() as u64;
        let output_bucket_count = self.output_bucket_commitments.len() as u64;
        let indexed_output_count = self
            .output_bucket_commitments
            .values()
            .map(|bucket| bucket.output_count)
            .sum();
        let candidate_match_count = self
            .shards
            .values()
            .map(|shard| shard.candidate_match_count)
            .sum();
        let wallet_cursor_count = self.wallet_sync_cursors.len() as u64;
        let active_wallet_cursor_count = self
            .wallet_sync_cursors
            .values()
            .filter(|cursor| cursor.status.can_advance())
            .count() as u64;
        let reserve_lane_count = self.reserve_scan_lanes.len() as u64;
        let active_reserve_lane_count = self
            .reserve_scan_lanes
            .values()
            .filter(|lane| lane.active)
            .count() as u64;
        let reorg_window_count = self.reorg_windows.len() as u64;
        let open_reorg_window_count = self
            .reorg_windows
            .values()
            .filter(|window| window.status.is_open())
            .count() as u64;
        let pq_attestation_count = self.pq_scanner_attestations.len() as u64;
        let accepted_pq_attestation_count = self
            .pq_scanner_attestations
            .values()
            .filter(|attestation| attestation.status.counts_for_quorum())
            .count() as u64;
        let sponsorship_count = self.low_fee_scan_sponsorships.len() as u64;
        let live_sponsorship_count = self
            .low_fee_scan_sponsorships
            .values()
            .filter(|sponsorship| sponsorship.status.is_live())
            .count() as u64;
        let sponsored_scan_units = self
            .low_fee_scan_sponsorships
            .values()
            .map(|sponsorship| sponsorship.consumed_units)
            .sum();
        let privacy_budget_count = self.privacy_budgets.len() as u64;
        let total_privacy_queries = self
            .privacy_budgets
            .values()
            .map(|budget| budget.max_queries)
            .sum();
        let used_privacy_queries = self
            .privacy_budgets
            .values()
            .map(|budget| budget.used_queries)
            .sum();
        let compaction_count = self.index_compactions.len() as u64;
        let compacted_saved_bytes = self
            .index_compactions
            .values()
            .map(|plan| plan.before_bytes.saturating_sub(plan.after_bytes))
            .sum();
        MoneroViewTagIndexerCounters {
            shard_count,
            active_shard_count,
            assignment_count,
            active_assignment_count,
            output_bucket_count,
            indexed_output_count,
            candidate_match_count,
            wallet_cursor_count,
            active_wallet_cursor_count,
            reserve_lane_count,
            active_reserve_lane_count,
            reorg_window_count,
            open_reorg_window_count,
            pq_attestation_count,
            accepted_pq_attestation_count,
            sponsorship_count,
            live_sponsorship_count,
            sponsored_scan_units,
            privacy_budget_count,
            total_privacy_queries,
            used_privacy_queries,
            compaction_count,
            compacted_saved_bytes,
        }
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        let counters = self.counters();
        json!({
            "kind": "monero_view_tag_indexer_state",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_VIEW_TAG_INDEXER_PROTOCOL_VERSION,
            "protocol_label": MONERO_VIEW_TAG_INDEXER_PROTOCOL_LABEL,
            "height": self.height,
            "network": self.config.network,
            "asset_id": self.config.asset_id,
            "fee_asset_id": self.config.fee_asset_id,
            "roots": roots.public_record(),
            "counters": counters.public_record(),
        })
    }

    pub fn state_root(&self) -> String {
        monero_view_tag_indexer_state_root_from_record(&self.public_record())
    }

    pub fn validate(&self) -> MoneroViewTagIndexerResult<()> {
        self.config.validate()?;
        let mut shard_ids = BTreeSet::new();
        for (id, shard) in &self.shards {
            shard.validate()?;
            if id != &shard.shard_id {
                return Err("view tag shard map key mismatch".to_string());
            }
            if !shard_ids.insert(shard.shard_id.clone()) {
                return Err("duplicate view tag shard id".to_string());
            }
            if shard.end_height > self.height {
                return Err("view tag shard cannot end above state height".to_string());
            }
        }
        for (id, assignment) in &self.encrypted_scan_assignments {
            assignment.validate()?;
            if id != &assignment.assignment_id {
                return Err("scan assignment map key mismatch".to_string());
            }
            if assignment.leased_at_height > self.height {
                return Err("scan assignment cannot lease above state height".to_string());
            }
        }
        for (id, bucket) in &self.output_bucket_commitments {
            bucket.validate()?;
            if id != &bucket.bucket_id {
                return Err("output bucket map key mismatch".to_string());
            }
            if bucket.max_height > self.height {
                return Err("output bucket cannot exceed state height".to_string());
            }
        }
        for (id, cursor) in &self.wallet_sync_cursors {
            cursor.validate()?;
            if id != &cursor.cursor_id {
                return Err("wallet cursor map key mismatch".to_string());
            }
            if cursor.target_height > self.height {
                return Err("wallet cursor cannot target above state height".to_string());
            }
        }
        for (id, lane) in &self.reserve_scan_lanes {
            lane.validate()?;
            if id != &lane.lane_id {
                return Err("reserve scan lane map key mismatch".to_string());
            }
            if lane.target_height > self.height {
                return Err("reserve scan lane cannot target above state height".to_string());
            }
        }
        for (id, window) in &self.reorg_windows {
            window.validate()?;
            if id != &window.window_id {
                return Err("reorg window map key mismatch".to_string());
            }
            if window.end_height > self.height {
                return Err("reorg window cannot end above state height".to_string());
            }
        }
        let accepted_weight = self
            .pq_scanner_attestations
            .values()
            .filter(|attestation| attestation.status.counts_for_quorum())
            .map(|attestation| attestation.quorum_weight)
            .sum::<u64>();
        for (id, attestation) in &self.pq_scanner_attestations {
            attestation.validate()?;
            if id != &attestation.attestation_id {
                return Err("pq scanner attestation map key mismatch".to_string());
            }
            if attestation.attested_at_height > self.height {
                return Err("pq scanner attestation cannot be above state height".to_string());
            }
        }
        if !self.pq_scanner_attestations.is_empty()
            && accepted_weight < self.config.min_scanner_quorum_weight
        {
            return Err("accepted pq scanner quorum weight is below configuration".to_string());
        }
        for (id, sponsorship) in &self.low_fee_scan_sponsorships {
            sponsorship.validate()?;
            if id != &sponsorship.sponsorship_id {
                return Err("scan sponsorship map key mismatch".to_string());
            }
            if sponsorship.opened_at_height > self.height {
                return Err("scan sponsorship cannot open above state height".to_string());
            }
        }
        for (id, budget) in &self.privacy_budgets {
            budget.validate()?;
            if id != &budget.budget_id {
                return Err("privacy budget map key mismatch".to_string());
            }
            if budget.window_start_height > self.height {
                return Err("privacy budget cannot start above state height".to_string());
            }
        }
        for (id, plan) in &self.index_compactions {
            plan.validate()?;
            if id != &plan.compaction_id {
                return Err("index compaction map key mismatch".to_string());
            }
            if plan.end_height > self.height {
                return Err("index compaction cannot end above state height".to_string());
            }
        }
        let counters = self.counters();
        if counters.used_privacy_queries > counters.total_privacy_queries {
            return Err("privacy budget used queries exceed total queries".to_string());
        }
        Ok(())
    }

    fn shard_root(&self) -> String {
        monero_view_tag_record_root(
            "MONERO-VIEW-TAG-SHARD-SET",
            &self
                .shards
                .values()
                .map(ViewTagShard::public_record)
                .collect::<Vec<_>>(),
        )
    }

    fn assignment_root(&self) -> String {
        monero_view_tag_record_root(
            "MONERO-VIEW-TAG-SCAN-ASSIGNMENT-SET",
            &self
                .encrypted_scan_assignments
                .values()
                .map(EncryptedScanAssignment::public_record)
                .collect::<Vec<_>>(),
        )
    }

    fn output_bucket_root(&self) -> String {
        monero_view_tag_record_root(
            "MONERO-VIEW-TAG-OUTPUT-BUCKET-SET",
            &self
                .output_bucket_commitments
                .values()
                .map(OutputBucketCommitment::public_record)
                .collect::<Vec<_>>(),
        )
    }

    fn wallet_cursor_root(&self) -> String {
        monero_view_tag_record_root(
            "MONERO-VIEW-TAG-WALLET-CURSOR-SET",
            &self
                .wallet_sync_cursors
                .values()
                .map(WalletSyncCursor::public_record)
                .collect::<Vec<_>>(),
        )
    }

    fn reserve_lane_root(&self) -> String {
        monero_view_tag_record_root(
            "MONERO-VIEW-TAG-RESERVE-LANE-SET",
            &self
                .reserve_scan_lanes
                .values()
                .map(ReserveScanLane::public_record)
                .collect::<Vec<_>>(),
        )
    }

    fn reorg_window_root(&self) -> String {
        monero_view_tag_record_root(
            "MONERO-VIEW-TAG-REORG-WINDOW-SET",
            &self
                .reorg_windows
                .values()
                .map(ReorgScanWindow::public_record)
                .collect::<Vec<_>>(),
        )
    }

    fn pq_attestation_root(&self) -> String {
        monero_view_tag_record_root(
            "MONERO-VIEW-TAG-PQ-SCANNER-ATTESTATION-SET",
            &self
                .pq_scanner_attestations
                .values()
                .map(PqScannerAttestation::public_record)
                .collect::<Vec<_>>(),
        )
    }

    fn sponsorship_root(&self) -> String {
        monero_view_tag_record_root(
            "MONERO-VIEW-TAG-SPONSORSHIP-SET",
            &self
                .low_fee_scan_sponsorships
                .values()
                .map(LowFeeScanSponsorship::public_record)
                .collect::<Vec<_>>(),
        )
    }

    fn privacy_budget_root(&self) -> String {
        monero_view_tag_record_root(
            "MONERO-VIEW-TAG-PRIVACY-BUDGET-SET",
            &self
                .privacy_budgets
                .values()
                .map(PrivacyBudget::public_record)
                .collect::<Vec<_>>(),
        )
    }

    fn compaction_root(&self) -> String {
        monero_view_tag_record_root(
            "MONERO-VIEW-TAG-COMPACTION-SET",
            &self
                .index_compactions
                .values()
                .map(IndexCompactionPlan::public_record)
                .collect::<Vec<_>>(),
        )
    }
}

pub fn monero_view_tag_indexer_state_root_from_record(record: &Value) -> String {
    domain_hash(
        "MONERO-VIEW-TAG-INDEXER-STATE",
        &[HashPart::Json(record)],
        32,
    )
}

pub fn monero_view_tag_indexer_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(domain, &[HashPart::Json(payload)], 32)
}

pub fn monero_view_tag_string_root(domain: &str, value: &str) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(MONERO_VIEW_TAG_INDEXER_PROTOCOL_LABEL),
            HashPart::Str(value),
        ],
        32,
    )
}

pub fn monero_view_tag_string_set_root(domain: &str, values: &[&str]) -> String {
    let records = values
        .iter()
        .map(|value| Value::String(monero_view_tag_string_root(domain, value)))
        .collect::<Vec<_>>();
    merkle_root(domain, &records)
}

pub fn monero_view_tag_record_root(domain: &str, records: &[Value]) -> String {
    merkle_root(domain, records)
}

pub fn monero_view_tag_indexer_empty_root(domain: &str) -> String {
    merkle_root(domain, &[])
}

pub fn monero_view_tag_shard_id(shard_index: u16, epoch: u64, view_tag_prefix: &str) -> String {
    domain_hash(
        "MONERO-VIEW-TAG-SHARD-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(shard_index as i128),
            HashPart::Int(epoch as i128),
            HashPart::Str(view_tag_prefix),
        ],
        32,
    )
}

pub fn monero_scan_assignment_id(
    shard_id: &str,
    assignment_kind: &str,
    wallet_cohort_commitment: &str,
    pq_ciphertext_hash: &str,
    leased_at_height: u64,
) -> String {
    domain_hash(
        "MONERO-VIEW-TAG-SCAN-ASSIGNMENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(shard_id),
            HashPart::Str(assignment_kind),
            HashPart::Str(wallet_cohort_commitment),
            HashPart::Str(pq_ciphertext_hash),
            HashPart::Int(leased_at_height as i128),
        ],
        32,
    )
}

pub fn monero_output_bucket_id(
    bucket_index: u16,
    shard_id: &str,
    bucket_kind: &str,
    amount_bucket_commitment: &str,
) -> String {
    domain_hash(
        "MONERO-VIEW-TAG-OUTPUT-BUCKET-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(bucket_index as i128),
            HashPart::Str(shard_id),
            HashPart::Str(bucket_kind),
            HashPart::Str(amount_bucket_commitment),
        ],
        32,
    )
}

pub fn monero_wallet_cursor_id(
    wallet_cohort_commitment: &str,
    cursor_key_commitment: &str,
    last_scanned_height: u64,
    target_height: u64,
) -> String {
    domain_hash(
        "MONERO-VIEW-TAG-WALLET-CURSOR-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(wallet_cohort_commitment),
            HashPart::Str(cursor_key_commitment),
            HashPart::Int(last_scanned_height as i128),
            HashPart::Int(target_height as i128),
        ],
        32,
    )
}

pub fn monero_reserve_scan_lane_id(
    lane_kind: &str,
    reserve_account_commitment: &str,
    target_height: u64,
) -> String {
    domain_hash(
        "MONERO-VIEW-TAG-RESERVE-SCAN-LANE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(lane_kind),
            HashPart::Str(reserve_account_commitment),
            HashPart::Int(target_height as i128),
        ],
        32,
    )
}

pub fn monero_reorg_window_id(
    old_anchor_root: &str,
    new_anchor_root: &str,
    start_height: u64,
    end_height: u64,
) -> String {
    domain_hash(
        "MONERO-VIEW-TAG-REORG-WINDOW-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(old_anchor_root),
            HashPart::Str(new_anchor_root),
            HashPart::Int(start_height as i128),
            HashPart::Int(end_height as i128),
        ],
        32,
    )
}

pub fn monero_pq_scanner_attestation_id(
    scanner_commitment: &str,
    scanner_role: &str,
    assignment_root: &str,
    attested_at_height: u64,
) -> String {
    domain_hash(
        "MONERO-VIEW-TAG-PQ-SCANNER-ATTESTATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(scanner_commitment),
            HashPart::Str(scanner_role),
            HashPart::Str(assignment_root),
            HashPart::Int(attested_at_height as i128),
        ],
        32,
    )
}

pub fn monero_scan_sponsorship_id(
    sponsor_commitment: &str,
    beneficiary_cohort_commitment: &str,
    assignment_root: &str,
    opened_at_height: u64,
) -> String {
    domain_hash(
        "MONERO-VIEW-TAG-SCAN-SPONSORSHIP-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(sponsor_commitment),
            HashPart::Str(beneficiary_cohort_commitment),
            HashPart::Str(assignment_root),
            HashPart::Int(opened_at_height as i128),
        ],
        32,
    )
}

pub fn monero_privacy_budget_id(
    scope: &str,
    cohort_commitment: &str,
    epoch: u64,
    window_start_height: u64,
) -> String {
    domain_hash(
        "MONERO-VIEW-TAG-PRIVACY-BUDGET-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(scope),
            HashPart::Str(cohort_commitment),
            HashPart::Int(epoch as i128),
            HashPart::Int(window_start_height as i128),
        ],
        32,
    )
}

pub fn monero_index_compaction_id(
    source_shard_root: &str,
    compacted_shard_root: &str,
    start_height: u64,
    end_height: u64,
) -> String {
    domain_hash(
        "MONERO-VIEW-TAG-INDEX-COMPACTION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(source_shard_root),
            HashPart::Str(compacted_shard_root),
            HashPart::Int(start_height as i128),
            HashPart::Int(end_height as i128),
        ],
        32,
    )
}

fn ensure_non_empty(value: &str, label: &str) -> MoneroViewTagIndexerResult<()> {
    if value.trim().is_empty() {
        return Err(format!("{label} cannot be empty"));
    }
    Ok(())
}

fn ensure_height_range(start: u64, end: u64, label: &str) -> MoneroViewTagIndexerResult<()> {
    if start > end {
        return Err(format!("{label} start height cannot exceed end height"));
    }
    Ok(())
}
