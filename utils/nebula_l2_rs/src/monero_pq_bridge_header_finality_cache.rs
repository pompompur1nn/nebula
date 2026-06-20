use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type MoneroPqBridgeHeaderFinalityCacheResult<T> = Result<T, String>;

pub const MONERO_PQ_BRIDGE_HEADER_FINALITY_CACHE_PROTOCOL_VERSION: &str =
    "nebula-monero-pq-bridge-header-finality-cache-v1";
pub const MONERO_PQ_BRIDGE_HEADER_FINALITY_CACHE_SCHEMA_VERSION: u64 = 1;
pub const MONERO_PQ_BRIDGE_HEADER_FINALITY_CACHE_DEVNET_NETWORK: &str = "monero-devnet";
pub const MONERO_PQ_BRIDGE_HEADER_FINALITY_CACHE_DEVNET_ASSET_ID: &str = "wxmr-devnet";
pub const MONERO_PQ_BRIDGE_HEADER_FINALITY_CACHE_DEVNET_COMMITTEE_ID: &str =
    "monero-pq-bridge-header-finality-cache-devnet-committee";
pub const MONERO_PQ_BRIDGE_HEADER_FINALITY_CACHE_DEVNET_HEIGHT: u64 = 19_200;
pub const MONERO_PQ_BRIDGE_HEADER_FINALITY_CACHE_HEADER_COMMITMENT_SCHEME: &str =
    "monero-header-commitment-shake256-v1";
pub const MONERO_PQ_BRIDGE_HEADER_FINALITY_CACHE_PQ_SIGNATURE_SCHEME: &str = "ML-DSA-87";
pub const MONERO_PQ_BRIDGE_HEADER_FINALITY_CACHE_BACKUP_SIGNATURE_SCHEME: &str =
    "SLH-DSA-SHAKE-192s";
pub const MONERO_PQ_BRIDGE_HEADER_FINALITY_CACHE_LIGHT_WALLET_PROOF_SCHEME: &str =
    "monero-light-wallet-sync-proof-v1";
pub const MONERO_PQ_BRIDGE_HEADER_FINALITY_CACHE_RESERVE_LINK_SCHEME: &str =
    "reserve-attestation-link-v1";
pub const MONERO_PQ_BRIDGE_HEADER_FINALITY_CACHE_FAST_EXIT_LOCK_SCHEME: &str =
    "fast-exit-safety-lock-v1";
pub const MONERO_PQ_BRIDGE_HEADER_FINALITY_CACHE_DEFAULT_FINALITY_DEPTH: u64 = 20;
pub const MONERO_PQ_BRIDGE_HEADER_FINALITY_CACHE_DEFAULT_REORG_ALERT_DEPTH: u64 = 12;
pub const MONERO_PQ_BRIDGE_HEADER_FINALITY_CACHE_DEFAULT_REORG_SLASH_DEPTH: u64 = 32;
pub const MONERO_PQ_BRIDGE_HEADER_FINALITY_CACHE_DEFAULT_CHECKPOINT_WINDOW: u64 = 120;
pub const MONERO_PQ_BRIDGE_HEADER_FINALITY_CACHE_DEFAULT_CACHE_RETENTION: u64 = 720;
pub const MONERO_PQ_BRIDGE_HEADER_FINALITY_CACHE_DEFAULT_LIGHT_WALLET_RETENTION: u64 = 360;
pub const MONERO_PQ_BRIDGE_HEADER_FINALITY_CACHE_DEFAULT_MIN_SIGNER_WEIGHT: u64 = 67;
pub const MONERO_PQ_BRIDGE_HEADER_FINALITY_CACHE_DEFAULT_QUORUM_BPS: u64 = 6_700;
pub const MONERO_PQ_BRIDGE_HEADER_FINALITY_CACHE_DEFAULT_STRONG_QUORUM_BPS: u64 = 8_000;
pub const MONERO_PQ_BRIDGE_HEADER_FINALITY_CACHE_MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HeaderCommitmentStatus {
    Observed,
    Candidate,
    Signed,
    Checkpointed,
    Finalized,
    Reorged,
    Evicted,
    Rejected,
}

impl HeaderCommitmentStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Observed => "observed",
            Self::Candidate => "candidate",
            Self::Signed => "signed",
            Self::Checkpointed => "checkpointed",
            Self::Finalized => "finalized",
            Self::Reorged => "reorged",
            Self::Evicted => "evicted",
            Self::Rejected => "rejected",
        }
    }

    pub fn usable_for_sync(self) -> bool {
        matches!(self, Self::Signed | Self::Checkpointed | Self::Finalized)
    }

    pub fn counts_as_live(self) -> bool {
        matches!(
            self,
            Self::Observed | Self::Candidate | Self::Signed | Self::Checkpointed
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqFinalitySignatureStatus {
    Submitted,
    Accepted,
    Superseded,
    Disputed,
    Slashed,
    Expired,
}

impl PqFinalitySignatureStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Accepted => "accepted",
            Self::Superseded => "superseded",
            Self::Disputed => "disputed",
            Self::Slashed => "slashed",
            Self::Expired => "expired",
        }
    }

    pub fn counts_for_quorum(self) -> bool {
        matches!(self, Self::Submitted | Self::Accepted)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReorgRiskLevel {
    Stable,
    Watch,
    Deep,
    Critical,
}

impl ReorgRiskLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Stable => "stable",
            Self::Watch => "watch",
            Self::Deep => "deep",
            Self::Critical => "critical",
        }
    }

    pub fn from_depth(depth: u64, alert_depth: u64, slash_depth: u64) -> Self {
        if depth == 0 {
            Self::Stable
        } else if depth < alert_depth {
            Self::Watch
        } else if depth < slash_depth {
            Self::Deep
        } else {
            Self::Critical
        }
    }

    pub fn score_bps(self) -> u64 {
        match self {
            Self::Stable => 10_000,
            Self::Watch => 8_000,
            Self::Deep => 4_000,
            Self::Critical => 0,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckpointWindowStatus {
    Open,
    Sealed,
    Finalized,
    ReorgReview,
    Expired,
}

impl CheckpointWindowStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Sealed => "sealed",
            Self::Finalized => "finalized",
            Self::ReorgReview => "reorg_review",
            Self::Expired => "expired",
        }
    }

    pub fn accepts_headers(self) -> bool {
        matches!(self, Self::Open | Self::ReorgReview)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReserveAttestationLinkStatus {
    Pending,
    Linked,
    Confirmed,
    Stale,
    Disputed,
}

impl ReserveAttestationLinkStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Linked => "linked",
            Self::Confirmed => "confirmed",
            Self::Stale => "stale",
            Self::Disputed => "disputed",
        }
    }

    pub fn usable_for_exit(self) -> bool {
        matches!(self, Self::Linked | Self::Confirmed)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FastExitSafetyLockStatus {
    Armed,
    Locked,
    Released,
    ReorgFrozen,
    Expired,
}

impl FastExitSafetyLockStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Armed => "armed",
            Self::Locked => "locked",
            Self::Released => "released",
            Self::ReorgFrozen => "reorg_frozen",
            Self::Expired => "expired",
        }
    }

    pub fn blocks_fast_exit(self) -> bool {
        matches!(self, Self::Locked | Self::ReorgFrozen)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LightWalletSyncProofStatus {
    Draft,
    Submitted,
    Verified,
    Served,
    Expired,
    Rejected,
}

impl LightWalletSyncProofStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Submitted => "submitted",
            Self::Verified => "verified",
            Self::Served => "served",
            Self::Expired => "expired",
            Self::Rejected => "rejected",
        }
    }

    pub fn is_publicly_served(self) -> bool {
        matches!(self, Self::Verified | Self::Served)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CacheEvictionReason {
    RetentionDepth,
    ReorgSuperseded,
    InvalidSignature,
    CheckpointCompacted,
    OperatorPruned,
}

impl CacheEvictionReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RetentionDepth => "retention_depth",
            Self::ReorgSuperseded => "reorg_superseded",
            Self::InvalidSignature => "invalid_signature",
            Self::CheckpointCompacted => "checkpoint_compacted",
            Self::OperatorPruned => "operator_pruned",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub protocol_version: String,
    pub schema_version: u64,
    pub network: String,
    pub asset_id: String,
    pub committee_id: String,
    pub header_commitment_scheme: String,
    pub pq_signature_scheme: String,
    pub backup_signature_scheme: String,
    pub light_wallet_proof_scheme: String,
    pub reserve_link_scheme: String,
    pub fast_exit_lock_scheme: String,
    pub finality_depth: u64,
    pub reorg_alert_depth: u64,
    pub reorg_slash_depth: u64,
    pub checkpoint_window_blocks: u64,
    pub cache_retention_blocks: u64,
    pub light_wallet_retention_blocks: u64,
    pub min_signer_weight: u64,
    pub quorum_bps: u64,
    pub strong_quorum_bps: u64,
    pub max_headers_per_window: u64,
    pub max_light_wallet_proofs_per_window: u64,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version: MONERO_PQ_BRIDGE_HEADER_FINALITY_CACHE_PROTOCOL_VERSION.to_string(),
            schema_version: MONERO_PQ_BRIDGE_HEADER_FINALITY_CACHE_SCHEMA_VERSION,
            network: MONERO_PQ_BRIDGE_HEADER_FINALITY_CACHE_DEVNET_NETWORK.to_string(),
            asset_id: MONERO_PQ_BRIDGE_HEADER_FINALITY_CACHE_DEVNET_ASSET_ID.to_string(),
            committee_id: MONERO_PQ_BRIDGE_HEADER_FINALITY_CACHE_DEVNET_COMMITTEE_ID.to_string(),
            header_commitment_scheme:
                MONERO_PQ_BRIDGE_HEADER_FINALITY_CACHE_HEADER_COMMITMENT_SCHEME.to_string(),
            pq_signature_scheme: MONERO_PQ_BRIDGE_HEADER_FINALITY_CACHE_PQ_SIGNATURE_SCHEME
                .to_string(),
            backup_signature_scheme: MONERO_PQ_BRIDGE_HEADER_FINALITY_CACHE_BACKUP_SIGNATURE_SCHEME
                .to_string(),
            light_wallet_proof_scheme:
                MONERO_PQ_BRIDGE_HEADER_FINALITY_CACHE_LIGHT_WALLET_PROOF_SCHEME.to_string(),
            reserve_link_scheme: MONERO_PQ_BRIDGE_HEADER_FINALITY_CACHE_RESERVE_LINK_SCHEME
                .to_string(),
            fast_exit_lock_scheme: MONERO_PQ_BRIDGE_HEADER_FINALITY_CACHE_FAST_EXIT_LOCK_SCHEME
                .to_string(),
            finality_depth: MONERO_PQ_BRIDGE_HEADER_FINALITY_CACHE_DEFAULT_FINALITY_DEPTH,
            reorg_alert_depth: MONERO_PQ_BRIDGE_HEADER_FINALITY_CACHE_DEFAULT_REORG_ALERT_DEPTH,
            reorg_slash_depth: MONERO_PQ_BRIDGE_HEADER_FINALITY_CACHE_DEFAULT_REORG_SLASH_DEPTH,
            checkpoint_window_blocks:
                MONERO_PQ_BRIDGE_HEADER_FINALITY_CACHE_DEFAULT_CHECKPOINT_WINDOW,
            cache_retention_blocks: MONERO_PQ_BRIDGE_HEADER_FINALITY_CACHE_DEFAULT_CACHE_RETENTION,
            light_wallet_retention_blocks:
                MONERO_PQ_BRIDGE_HEADER_FINALITY_CACHE_DEFAULT_LIGHT_WALLET_RETENTION,
            min_signer_weight: MONERO_PQ_BRIDGE_HEADER_FINALITY_CACHE_DEFAULT_MIN_SIGNER_WEIGHT,
            quorum_bps: MONERO_PQ_BRIDGE_HEADER_FINALITY_CACHE_DEFAULT_QUORUM_BPS,
            strong_quorum_bps: MONERO_PQ_BRIDGE_HEADER_FINALITY_CACHE_DEFAULT_STRONG_QUORUM_BPS,
            max_headers_per_window: 192,
            max_light_wallet_proofs_per_window: 256,
        }
    }

    pub fn validate(&self) -> MoneroPqBridgeHeaderFinalityCacheResult<()> {
        ensure_non_empty("protocol_version", &self.protocol_version)?;
        ensure_non_empty("network", &self.network)?;
        ensure_non_empty("asset_id", &self.asset_id)?;
        ensure_non_empty("committee_id", &self.committee_id)?;
        ensure_non_empty("header_commitment_scheme", &self.header_commitment_scheme)?;
        ensure_non_empty("pq_signature_scheme", &self.pq_signature_scheme)?;
        ensure_non_empty("backup_signature_scheme", &self.backup_signature_scheme)?;
        ensure_non_empty("light_wallet_proof_scheme", &self.light_wallet_proof_scheme)?;
        ensure_non_empty("reserve_link_scheme", &self.reserve_link_scheme)?;
        ensure_non_empty("fast_exit_lock_scheme", &self.fast_exit_lock_scheme)?;
        ensure_positive("finality_depth", self.finality_depth)?;
        ensure_positive("reorg_alert_depth", self.reorg_alert_depth)?;
        ensure_positive("reorg_slash_depth", self.reorg_slash_depth)?;
        ensure_positive("checkpoint_window_blocks", self.checkpoint_window_blocks)?;
        ensure_positive("cache_retention_blocks", self.cache_retention_blocks)?;
        ensure_positive(
            "light_wallet_retention_blocks",
            self.light_wallet_retention_blocks,
        )?;
        ensure_positive("min_signer_weight", self.min_signer_weight)?;
        ensure_bps("quorum_bps", self.quorum_bps)?;
        ensure_bps("strong_quorum_bps", self.strong_quorum_bps)?;
        ensure_positive("max_headers_per_window", self.max_headers_per_window)?;
        ensure_positive(
            "max_light_wallet_proofs_per_window",
            self.max_light_wallet_proofs_per_window,
        )?;
        if self.reorg_alert_depth >= self.reorg_slash_depth {
            return Err("reorg_alert_depth must be below reorg_slash_depth".to_string());
        }
        if self.finality_depth > self.cache_retention_blocks {
            return Err("finality_depth must fit inside cache_retention_blocks".to_string());
        }
        if self.quorum_bps > self.strong_quorum_bps {
            return Err("quorum_bps must not exceed strong_quorum_bps".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "network": self.network,
            "asset_id": self.asset_id,
            "committee_id": self.committee_id,
            "header_commitment_scheme": self.header_commitment_scheme,
            "pq_signature_scheme": self.pq_signature_scheme,
            "backup_signature_scheme": self.backup_signature_scheme,
            "light_wallet_proof_scheme": self.light_wallet_proof_scheme,
            "reserve_link_scheme": self.reserve_link_scheme,
            "fast_exit_lock_scheme": self.fast_exit_lock_scheme,
            "finality_depth": self.finality_depth,
            "reorg_alert_depth": self.reorg_alert_depth,
            "reorg_slash_depth": self.reorg_slash_depth,
            "checkpoint_window_blocks": self.checkpoint_window_blocks,
            "cache_retention_blocks": self.cache_retention_blocks,
            "light_wallet_retention_blocks": self.light_wallet_retention_blocks,
            "min_signer_weight": self.min_signer_weight,
            "quorum_bps": self.quorum_bps,
            "strong_quorum_bps": self.strong_quorum_bps,
            "max_headers_per_window": self.max_headers_per_window,
            "max_light_wallet_proofs_per_window": self.max_light_wallet_proofs_per_window
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroHeaderCommitment {
    pub header_id: String,
    pub block_hash: String,
    pub previous_block_hash: String,
    pub long_term_weight_root: String,
    pub pow_seed_hash: String,
    pub miner_tx_commitment: String,
    pub tx_merkle_root: String,
    pub bridge_observation_root: String,
    pub height: u64,
    pub timestamp: u64,
    pub difficulty: u64,
    pub cumulative_difficulty_low: u64,
    pub cumulative_difficulty_high: u64,
    pub observed_at_height: u64,
    pub status: HeaderCommitmentStatus,
}

impl MoneroHeaderCommitment {
    pub fn public_record(&self) -> Value {
        json!({
            "header_id": self.header_id,
            "block_hash": self.block_hash,
            "previous_block_hash": self.previous_block_hash,
            "long_term_weight_root": self.long_term_weight_root,
            "pow_seed_hash": self.pow_seed_hash,
            "miner_tx_commitment": self.miner_tx_commitment,
            "tx_merkle_root": self.tx_merkle_root,
            "bridge_observation_root": self.bridge_observation_root,
            "height": self.height,
            "timestamp": self.timestamp,
            "difficulty": self.difficulty,
            "cumulative_difficulty_low": self.cumulative_difficulty_low,
            "cumulative_difficulty_high": self.cumulative_difficulty_high,
            "observed_at_height": self.observed_at_height,
            "status": self.status.as_str()
        })
    }

    pub fn commitment_root(&self) -> String {
        cache_hash(
            "HEADER-COMMITMENT",
            &[HashPart::Json(&self.public_record())],
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqFinalitySignature {
    pub signature_id: String,
    pub header_id: String,
    pub signer_id: String,
    pub signer_weight: u64,
    pub signature_root: String,
    pub aggregate_public_key_root: String,
    pub transcript_root: String,
    pub signed_at_height: u64,
    pub expires_at_height: u64,
    pub status: PqFinalitySignatureStatus,
}

impl PqFinalitySignature {
    pub fn public_record(&self) -> Value {
        json!({
            "signature_id": self.signature_id,
            "header_id": self.header_id,
            "signer_id": self.signer_id,
            "signer_weight": self.signer_weight,
            "signature_root": self.signature_root,
            "aggregate_public_key_root": self.aggregate_public_key_root,
            "transcript_root": self.transcript_root,
            "signed_at_height": self.signed_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str()
        })
    }

    pub fn counts_for_quorum(&self, height: u64) -> bool {
        self.status.counts_for_quorum() && self.expires_at_height >= height
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReorgDepthScore {
    pub score_id: String,
    pub canonical_header_id: String,
    pub competing_header_id: String,
    pub fork_height: u64,
    pub observed_tip_height: u64,
    pub depth: u64,
    pub competing_work_delta: i64,
    pub risk_level: ReorgRiskLevel,
    pub penalty_bps: u64,
    pub watcher_evidence_root: String,
}

impl ReorgDepthScore {
    pub fn public_record(&self) -> Value {
        json!({
            "score_id": self.score_id,
            "canonical_header_id": self.canonical_header_id,
            "competing_header_id": self.competing_header_id,
            "fork_height": self.fork_height,
            "observed_tip_height": self.observed_tip_height,
            "depth": self.depth,
            "competing_work_delta": self.competing_work_delta,
            "risk_level": self.risk_level.as_str(),
            "penalty_bps": self.penalty_bps,
            "watcher_evidence_root": self.watcher_evidence_root
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckpointWindow {
    pub window_id: String,
    pub start_height: u64,
    pub end_height: u64,
    pub anchor_header_id: String,
    pub header_root: String,
    pub signature_root: String,
    pub reserve_link_root: String,
    pub finalized_height: u64,
    pub status: CheckpointWindowStatus,
}

impl CheckpointWindow {
    pub fn public_record(&self) -> Value {
        json!({
            "window_id": self.window_id,
            "start_height": self.start_height,
            "end_height": self.end_height,
            "anchor_header_id": self.anchor_header_id,
            "header_root": self.header_root,
            "signature_root": self.signature_root,
            "reserve_link_root": self.reserve_link_root,
            "finalized_height": self.finalized_height,
            "status": self.status.as_str()
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReserveAttestationLink {
    pub link_id: String,
    pub header_id: String,
    pub reserve_attestation_id: String,
    pub reserve_root: String,
    pub liability_root: String,
    pub coverage_bps: u64,
    pub linked_at_height: u64,
    pub expires_at_height: u64,
    pub status: ReserveAttestationLinkStatus,
}

impl ReserveAttestationLink {
    pub fn public_record(&self) -> Value {
        json!({
            "link_id": self.link_id,
            "header_id": self.header_id,
            "reserve_attestation_id": self.reserve_attestation_id,
            "reserve_root": self.reserve_root,
            "liability_root": self.liability_root,
            "coverage_bps": self.coverage_bps,
            "linked_at_height": self.linked_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str()
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FastExitSafetyLock {
    pub lock_id: String,
    pub header_id: String,
    pub exit_batch_id: String,
    pub reserve_link_id: String,
    pub locked_amount_piconero: u64,
    pub lock_reason_root: String,
    pub opened_at_height: u64,
    pub releases_at_height: u64,
    pub status: FastExitSafetyLockStatus,
}

impl FastExitSafetyLock {
    pub fn public_record(&self) -> Value {
        json!({
            "lock_id": self.lock_id,
            "header_id": self.header_id,
            "exit_batch_id": self.exit_batch_id,
            "reserve_link_id": self.reserve_link_id,
            "locked_amount_piconero": self.locked_amount_piconero,
            "lock_reason_root": self.lock_reason_root,
            "opened_at_height": self.opened_at_height,
            "releases_at_height": self.releases_at_height,
            "status": self.status.as_str()
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LightWalletSyncProof {
    pub proof_id: String,
    pub wallet_view_tag_root: String,
    pub header_id: String,
    pub checkpoint_window_id: String,
    pub inclusion_root: String,
    pub output_scan_root: String,
    pub nullifier_hint_root: String,
    pub proved_from_height: u64,
    pub proved_to_height: u64,
    pub served_at_height: u64,
    pub expires_at_height: u64,
    pub status: LightWalletSyncProofStatus,
}

impl LightWalletSyncProof {
    pub fn public_record(&self) -> Value {
        json!({
            "proof_id": self.proof_id,
            "wallet_view_tag_root": self.wallet_view_tag_root,
            "header_id": self.header_id,
            "checkpoint_window_id": self.checkpoint_window_id,
            "inclusion_root": self.inclusion_root,
            "output_scan_root": self.output_scan_root,
            "nullifier_hint_root": self.nullifier_hint_root,
            "proved_from_height": self.proved_from_height,
            "proved_to_height": self.proved_to_height,
            "served_at_height": self.served_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str()
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CacheEvictionEntry {
    pub eviction_id: String,
    pub subject_id: String,
    pub subject_kind: String,
    pub evicted_at_height: u64,
    pub retention_floor_height: u64,
    pub reason: CacheEvictionReason,
    pub replacement_root: String,
}

impl CacheEvictionEntry {
    pub fn public_record(&self) -> Value {
        json!({
            "eviction_id": self.eviction_id,
            "subject_id": self.subject_id,
            "subject_kind": self.subject_kind,
            "evicted_at_height": self.evicted_at_height,
            "retention_floor_height": self.retention_floor_height,
            "reason": self.reason.as_str(),
            "replacement_root": self.replacement_root
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roots {
    pub config_root: String,
    pub header_commitment_root: String,
    pub pq_signature_root: String,
    pub reorg_score_root: String,
    pub checkpoint_window_root: String,
    pub reserve_attestation_link_root: String,
    pub fast_exit_safety_lock_root: String,
    pub light_wallet_sync_proof_root: String,
    pub cache_eviction_root: String,
    pub canonical_chain_root: String,
    pub finality_index_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "header_commitment_root": self.header_commitment_root,
            "pq_signature_root": self.pq_signature_root,
            "reorg_score_root": self.reorg_score_root,
            "checkpoint_window_root": self.checkpoint_window_root,
            "reserve_attestation_link_root": self.reserve_attestation_link_root,
            "fast_exit_safety_lock_root": self.fast_exit_safety_lock_root,
            "light_wallet_sync_proof_root": self.light_wallet_sync_proof_root,
            "cache_eviction_root": self.cache_eviction_root,
            "canonical_chain_root": self.canonical_chain_root,
            "finality_index_root": self.finality_index_root,
            "state_root": self.state_root
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    pub header_commitments: u64,
    pub finalized_headers: u64,
    pub pq_signatures: u64,
    pub accepted_pq_signatures: u64,
    pub reorg_scores: u64,
    pub critical_reorg_scores: u64,
    pub checkpoint_windows: u64,
    pub finalized_checkpoint_windows: u64,
    pub reserve_attestation_links: u64,
    pub usable_reserve_attestation_links: u64,
    pub fast_exit_safety_locks: u64,
    pub blocking_fast_exit_safety_locks: u64,
    pub light_wallet_sync_proofs: u64,
    pub served_light_wallet_sync_proofs: u64,
    pub cache_evictions: u64,
    pub canonical_chain_entries: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "header_commitments": self.header_commitments,
            "finalized_headers": self.finalized_headers,
            "pq_signatures": self.pq_signatures,
            "accepted_pq_signatures": self.accepted_pq_signatures,
            "reorg_scores": self.reorg_scores,
            "critical_reorg_scores": self.critical_reorg_scores,
            "checkpoint_windows": self.checkpoint_windows,
            "finalized_checkpoint_windows": self.finalized_checkpoint_windows,
            "reserve_attestation_links": self.reserve_attestation_links,
            "usable_reserve_attestation_links": self.usable_reserve_attestation_links,
            "fast_exit_safety_locks": self.fast_exit_safety_locks,
            "blocking_fast_exit_safety_locks": self.blocking_fast_exit_safety_locks,
            "light_wallet_sync_proofs": self.light_wallet_sync_proofs,
            "served_light_wallet_sync_proofs": self.served_light_wallet_sync_proofs,
            "cache_evictions": self.cache_evictions,
            "canonical_chain_entries": self.canonical_chain_entries
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub height: u64,
    pub config: Config,
    pub header_commitments: BTreeMap<String, MoneroHeaderCommitment>,
    pub pq_finality_signatures: BTreeMap<String, PqFinalitySignature>,
    pub reorg_depth_scores: BTreeMap<String, ReorgDepthScore>,
    pub checkpoint_windows: BTreeMap<String, CheckpointWindow>,
    pub reserve_attestation_links: BTreeMap<String, ReserveAttestationLink>,
    pub fast_exit_safety_locks: BTreeMap<String, FastExitSafetyLock>,
    pub light_wallet_sync_proofs: BTreeMap<String, LightWalletSyncProof>,
    pub cache_evictions: BTreeMap<String, CacheEvictionEntry>,
    pub canonical_chain: BTreeMap<u64, String>,
    pub finalized_headers: BTreeSet<String>,
    pub frozen_exit_batches: BTreeSet<String>,
}

impl State {
    pub fn devnet() -> MoneroPqBridgeHeaderFinalityCacheResult<Self> {
        let config = Config::devnet();
        let height = MONERO_PQ_BRIDGE_HEADER_FINALITY_CACHE_DEVNET_HEIGHT;
        let mut header_commitments = BTreeMap::new();
        let mut canonical_chain = BTreeMap::new();
        let mut finalized_headers = BTreeSet::new();
        let mut previous_block_hash = cache_hash("DEVNET-GENESIS", &[HashPart::Str("monero")]);

        for offset in 0..8_u64 {
            let monero_height = height - 7 + offset;
            let status = if offset < 4 {
                HeaderCommitmentStatus::Finalized
            } else if offset < 6 {
                HeaderCommitmentStatus::Checkpointed
            } else {
                HeaderCommitmentStatus::Signed
            };
            let block_hash = cache_hash(
                "DEVNET-BLOCK-HASH",
                &[
                    HashPart::Str(&previous_block_hash),
                    HashPart::Int(monero_height as i128),
                    HashPart::Str("canonical"),
                ],
            );
            let header_id = header_id(&block_hash, monero_height);
            let commitment = MoneroHeaderCommitment {
                header_id: header_id.clone(),
                block_hash: block_hash.clone(),
                previous_block_hash,
                long_term_weight_root: cache_hash(
                    "DEVNET-LONG-TERM-WEIGHT",
                    &[HashPart::Int(monero_height as i128)],
                ),
                pow_seed_hash: cache_hash(
                    "DEVNET-POW-SEED",
                    &[HashPart::Int((monero_height / 2_048) as i128)],
                ),
                miner_tx_commitment: cache_hash(
                    "DEVNET-MINER-TX",
                    &[HashPart::Str(&block_hash), HashPart::Int(offset as i128)],
                ),
                tx_merkle_root: cache_hash(
                    "DEVNET-TX-MERKLE",
                    &[
                        HashPart::Str(&block_hash),
                        HashPart::Int(3 + offset as i128),
                    ],
                ),
                bridge_observation_root: cache_hash(
                    "DEVNET-BRIDGE-OBSERVATION",
                    &[
                        HashPart::Str(MONERO_PQ_BRIDGE_HEADER_FINALITY_CACHE_DEVNET_ASSET_ID),
                        HashPart::Str(&block_hash),
                    ],
                ),
                height: monero_height,
                timestamp: 1_716_000_000 + monero_height * 120,
                difficulty: 2_000_000 + offset * 11_111,
                cumulative_difficulty_low: 880_000_000 + monero_height * 1_999,
                cumulative_difficulty_high: monero_height / 50_000,
                observed_at_height: monero_height + 1,
                status,
            };
            if status == HeaderCommitmentStatus::Finalized {
                finalized_headers.insert(header_id.clone());
            }
            canonical_chain.insert(monero_height, header_id.clone());
            previous_block_hash = block_hash;
            header_commitments.insert(header_id, commitment);
        }

        let header_ids = header_commitments.keys().cloned().collect::<Vec<_>>();
        let mut pq_finality_signatures = BTreeMap::new();
        for (index, header_id_value) in header_ids.iter().enumerate() {
            for signer_index in 0..3_u64 {
                let signature_id = signature_id(header_id_value, signer_index);
                let signer_id = format!("pq-cache-signer-{signer_index}");
                let signature = PqFinalitySignature {
                    signature_id: signature_id.clone(),
                    header_id: header_id_value.clone(),
                    signer_id: signer_id.clone(),
                    signer_weight: 34,
                    signature_root: cache_hash(
                        "DEVNET-PQ-SIGNATURE",
                        &[
                            HashPart::Str(header_id_value),
                            HashPart::Str(&signer_id),
                            HashPart::Int(index as i128),
                        ],
                    ),
                    aggregate_public_key_root: cache_hash(
                        "DEVNET-PQ-AGG-KEY",
                        &[HashPart::Str(&signer_id)],
                    ),
                    transcript_root: cache_hash(
                        "DEVNET-PQ-TRANSCRIPT",
                        &[HashPart::Str(header_id_value), HashPart::Str(&signer_id)],
                    ),
                    signed_at_height: height - 7 + index as u64,
                    expires_at_height: height + config.cache_retention_blocks,
                    status: PqFinalitySignatureStatus::Accepted,
                };
                pq_finality_signatures.insert(signature_id, signature);
            }
        }

        let canonical_tip = header_ids
            .last()
            .cloned()
            .ok_or_else(|| "devnet requires at least one header".to_string())?;
        let fork_parent = header_ids
            .get(5)
            .cloned()
            .ok_or_else(|| "devnet requires fork parent header".to_string())?;
        let competing_header_id = cache_hash(
            "DEVNET-REORG-COMPETING-HEADER",
            &[HashPart::Str(&fork_parent), HashPart::Int(height as i128)],
        );
        let reorg_score = ReorgDepthScore {
            score_id: cache_hash(
                "DEVNET-REORG-SCORE-ID",
                &[
                    HashPart::Str(&fork_parent),
                    HashPart::Str(&competing_header_id),
                ],
            ),
            canonical_header_id: canonical_tip.clone(),
            competing_header_id,
            fork_height: height - 2,
            observed_tip_height: height,
            depth: 2,
            competing_work_delta: -44_000,
            risk_level: ReorgRiskLevel::from_depth(
                2,
                config.reorg_alert_depth,
                config.reorg_slash_depth,
            ),
            penalty_bps: 200,
            watcher_evidence_root: cache_hash(
                "DEVNET-WATCHER-EVIDENCE",
                &[HashPart::Str(&fork_parent)],
            ),
        };
        let mut reorg_depth_scores = BTreeMap::new();
        reorg_depth_scores.insert(reorg_score.score_id.clone(), reorg_score);

        let header_records = header_commitments
            .values()
            .map(MoneroHeaderCommitment::public_record)
            .collect::<Vec<_>>();
        let signature_records = pq_finality_signatures
            .values()
            .map(PqFinalitySignature::public_record)
            .collect::<Vec<_>>();
        let reserve_link_id = cache_hash(
            "DEVNET-RESERVE-LINK-ID",
            &[
                HashPart::Str(&canonical_tip),
                HashPart::Str("reserve-attestation-0"),
            ],
        );
        let reserve_link = ReserveAttestationLink {
            link_id: reserve_link_id.clone(),
            header_id: canonical_tip.clone(),
            reserve_attestation_id: "reserve-attestation-0".to_string(),
            reserve_root: cache_hash("DEVNET-RESERVE-ROOT", &[HashPart::Str(&canonical_tip)]),
            liability_root: cache_hash("DEVNET-LIABILITY-ROOT", &[HashPart::Str(&canonical_tip)]),
            coverage_bps: 10_850,
            linked_at_height: height,
            expires_at_height: height + config.cache_retention_blocks,
            status: ReserveAttestationLinkStatus::Confirmed,
        };
        let mut reserve_attestation_links = BTreeMap::new();
        reserve_attestation_links.insert(reserve_link_id.clone(), reserve_link);

        let checkpoint_window = CheckpointWindow {
            window_id: checkpoint_window_id(height - config.checkpoint_window_blocks + 1, height),
            start_height: height - config.checkpoint_window_blocks + 1,
            end_height: height,
            anchor_header_id: canonical_tip.clone(),
            header_root: merkle_root("MONERO-PQ-CACHE-DEVNET-WINDOW-HEADER", &header_records),
            signature_root: merkle_root(
                "MONERO-PQ-CACHE-DEVNET-WINDOW-SIGNATURE",
                &signature_records,
            ),
            reserve_link_root: merkle_root(
                "MONERO-PQ-CACHE-DEVNET-WINDOW-RESERVE-LINK",
                &[reserve_attestation_links
                    .get(&reserve_link_id)
                    .map(ReserveAttestationLink::public_record)
                    .ok_or_else(|| "devnet reserve link missing".to_string())?],
            ),
            finalized_height: height - config.finality_depth,
            status: CheckpointWindowStatus::Finalized,
        };
        let window_id = checkpoint_window.window_id.clone();
        let mut checkpoint_windows = BTreeMap::new();
        checkpoint_windows.insert(window_id.clone(), checkpoint_window);

        let fast_exit_lock = FastExitSafetyLock {
            lock_id: cache_hash(
                "DEVNET-FAST-EXIT-LOCK-ID",
                &[HashPart::Str(&canonical_tip), HashPart::Str("exit-batch-0")],
            ),
            header_id: canonical_tip.clone(),
            exit_batch_id: "exit-batch-0".to_string(),
            reserve_link_id,
            locked_amount_piconero: 4_200_000_000,
            lock_reason_root: cache_hash(
                "DEVNET-FAST-EXIT-LOCK-REASON",
                &[HashPart::Str("finality")],
            ),
            opened_at_height: height - 1,
            releases_at_height: height + config.finality_depth,
            status: FastExitSafetyLockStatus::Armed,
        };
        let mut fast_exit_safety_locks = BTreeMap::new();
        fast_exit_safety_locks.insert(fast_exit_lock.lock_id.clone(), fast_exit_lock);

        let light_wallet_proof = LightWalletSyncProof {
            proof_id: cache_hash(
                "DEVNET-LIGHT-WALLET-PROOF-ID",
                &[
                    HashPart::Str(&canonical_tip),
                    HashPart::Str("view-tag-bucket-0"),
                ],
            ),
            wallet_view_tag_root: cache_hash(
                "DEVNET-LIGHT-WALLET-VIEW-TAGS",
                &[HashPart::Str("bucket-0")],
            ),
            header_id: canonical_tip.clone(),
            checkpoint_window_id: window_id,
            inclusion_root: cache_hash(
                "DEVNET-LIGHT-WALLET-INCLUSION",
                &[HashPart::Str(&canonical_tip)],
            ),
            output_scan_root: cache_hash(
                "DEVNET-LIGHT-WALLET-OUTPUT-SCAN",
                &[HashPart::Str(&canonical_tip)],
            ),
            nullifier_hint_root: cache_hash(
                "DEVNET-LIGHT-WALLET-NULLIFIER-HINT",
                &[HashPart::Str(&canonical_tip)],
            ),
            proved_from_height: height - 64,
            proved_to_height: height,
            served_at_height: height,
            expires_at_height: height + config.light_wallet_retention_blocks,
            status: LightWalletSyncProofStatus::Served,
        };
        let mut light_wallet_sync_proofs = BTreeMap::new();
        light_wallet_sync_proofs.insert(light_wallet_proof.proof_id.clone(), light_wallet_proof);

        let eviction = CacheEvictionEntry {
            eviction_id: cache_hash(
                "DEVNET-CACHE-EVICTION-ID",
                &[
                    HashPart::Str("old-header"),
                    HashPart::Int((height - 721) as i128),
                ],
            ),
            subject_id: "devnet-old-header-compacted".to_string(),
            subject_kind: "header_commitment".to_string(),
            evicted_at_height: height,
            retention_floor_height: height - config.cache_retention_blocks,
            reason: CacheEvictionReason::RetentionDepth,
            replacement_root: cache_hash(
                "DEVNET-CACHE-EVICTION-REPLACEMENT",
                &[HashPart::Str("checkpoint")],
            ),
        };
        let mut cache_evictions = BTreeMap::new();
        cache_evictions.insert(eviction.eviction_id.clone(), eviction);

        let state = Self {
            height,
            config,
            header_commitments,
            pq_finality_signatures,
            reorg_depth_scores,
            checkpoint_windows,
            reserve_attestation_links,
            fast_exit_safety_locks,
            light_wallet_sync_proofs,
            cache_evictions,
            canonical_chain,
            finalized_headers,
            frozen_exit_batches: BTreeSet::new(),
        };
        state.validate()?;
        Ok(state)
    }

    pub fn validate(&self) -> MoneroPqBridgeHeaderFinalityCacheResult<()> {
        self.config.validate()?;
        ensure_positive("height", self.height)?;
        for (id, header) in &self.header_commitments {
            ensure_id_match("header_commitments", id, &header.header_id)?;
            validate_header(header)?;
            if header.observed_at_height > self.height + self.config.cache_retention_blocks {
                return Err(format!(
                    "header {} observed too far in future",
                    header.header_id
                ));
            }
        }
        for (height, header_id_value) in &self.canonical_chain {
            if !self.header_commitments.contains_key(header_id_value) {
                return Err(format!(
                    "canonical chain height {height} points to missing header"
                ));
            }
            let header = self
                .header_commitments
                .get(header_id_value)
                .ok_or_else(|| format!("canonical chain height {height} missing header"))?;
            if header.height != *height {
                return Err(format!(
                    "canonical chain height {height} mismatches header height"
                ));
            }
        }
        for header_id_value in &self.finalized_headers {
            let header = self
                .header_commitments
                .get(header_id_value)
                .ok_or_else(|| format!("finalized header {header_id_value} missing"))?;
            if header.status != HeaderCommitmentStatus::Finalized {
                return Err(format!(
                    "finalized header {header_id_value} is not finalized"
                ));
            }
        }
        for (id, signature) in &self.pq_finality_signatures {
            ensure_id_match("pq_finality_signatures", id, &signature.signature_id)?;
            validate_signature(signature)?;
            if !self.header_commitments.contains_key(&signature.header_id) {
                return Err(format!("signature {id} references missing header"));
            }
        }
        for (id, score) in &self.reorg_depth_scores {
            ensure_id_match("reorg_depth_scores", id, &score.score_id)?;
            validate_reorg_score(score)?;
            if !self
                .header_commitments
                .contains_key(&score.canonical_header_id)
            {
                return Err(format!(
                    "reorg score {id} references missing canonical header"
                ));
            }
        }
        for (id, window) in &self.checkpoint_windows {
            ensure_id_match("checkpoint_windows", id, &window.window_id)?;
            validate_checkpoint_window(window)?;
            if !self
                .header_commitments
                .contains_key(&window.anchor_header_id)
            {
                return Err(format!("checkpoint window {id} references missing anchor"));
            }
            if window.end_height < window.start_height {
                return Err(format!("checkpoint window {id} has inverted range"));
            }
        }
        for (id, link) in &self.reserve_attestation_links {
            ensure_id_match("reserve_attestation_links", id, &link.link_id)?;
            validate_reserve_link(link)?;
            if !self.header_commitments.contains_key(&link.header_id) {
                return Err(format!("reserve link {id} references missing header"));
            }
        }
        for (id, lock) in &self.fast_exit_safety_locks {
            ensure_id_match("fast_exit_safety_locks", id, &lock.lock_id)?;
            validate_fast_exit_lock(lock)?;
            if !self.header_commitments.contains_key(&lock.header_id) {
                return Err(format!("fast exit lock {id} references missing header"));
            }
            if !self
                .reserve_attestation_links
                .contains_key(&lock.reserve_link_id)
            {
                return Err(format!(
                    "fast exit lock {id} references missing reserve link"
                ));
            }
        }
        for (id, proof) in &self.light_wallet_sync_proofs {
            ensure_id_match("light_wallet_sync_proofs", id, &proof.proof_id)?;
            validate_light_wallet_proof(proof)?;
            if !self.header_commitments.contains_key(&proof.header_id) {
                return Err(format!("light wallet proof {id} references missing header"));
            }
            if !self
                .checkpoint_windows
                .contains_key(&proof.checkpoint_window_id)
            {
                return Err(format!(
                    "light wallet proof {id} references missing checkpoint"
                ));
            }
        }
        for (id, eviction) in &self.cache_evictions {
            ensure_id_match("cache_evictions", id, &eviction.eviction_id)?;
            validate_eviction(eviction)?;
        }
        for batch_id in &self.frozen_exit_batches {
            ensure_non_empty("frozen_exit_batch", batch_id)?;
        }
        Ok(())
    }

    pub fn set_height(&mut self, height: u64) -> MoneroPqBridgeHeaderFinalityCacheResult<()> {
        ensure_positive("height", height)?;
        self.height = height;
        self.apply_height_status_updates();
        self.validate()
    }

    pub fn update_height(&mut self, delta: u64) -> MoneroPqBridgeHeaderFinalityCacheResult<()> {
        let next = self
            .height
            .checked_add(delta)
            .ok_or_else(|| "height overflow".to_string())?;
        self.set_height(next)
    }

    pub fn roots(&self) -> Roots {
        let config_root = cache_hash("CONFIG", &[HashPart::Json(&self.config.public_record())]);
        let header_records =
            values_public_records(&self.header_commitments, |item| item.public_record());
        let signature_records =
            values_public_records(&self.pq_finality_signatures, |item| item.public_record());
        let reorg_records =
            values_public_records(&self.reorg_depth_scores, |item| item.public_record());
        let window_records =
            values_public_records(&self.checkpoint_windows, |item| item.public_record());
        let reserve_records =
            values_public_records(&self.reserve_attestation_links, |item| item.public_record());
        let lock_records =
            values_public_records(&self.fast_exit_safety_locks, |item| item.public_record());
        let proof_records =
            values_public_records(&self.light_wallet_sync_proofs, |item| item.public_record());
        let eviction_records =
            values_public_records(&self.cache_evictions, |item| item.public_record());
        let canonical_records = self
            .canonical_chain
            .iter()
            .map(|(height, header_id_value)| {
                json!({
                    "height": height,
                    "header_id": header_id_value
                })
            })
            .collect::<Vec<_>>();
        let finality_records = self
            .finalized_headers
            .iter()
            .map(|header_id_value| json!({ "header_id": header_id_value }))
            .collect::<Vec<_>>();
        let header_commitment_root =
            merkle_root("MONERO-PQ-CACHE-HEADER-COMMITMENT", &header_records);
        let pq_signature_root = merkle_root("MONERO-PQ-CACHE-PQ-SIGNATURE", &signature_records);
        let reorg_score_root = merkle_root("MONERO-PQ-CACHE-REORG-SCORE", &reorg_records);
        let checkpoint_window_root =
            merkle_root("MONERO-PQ-CACHE-CHECKPOINT-WINDOW", &window_records);
        let reserve_attestation_link_root =
            merkle_root("MONERO-PQ-CACHE-RESERVE-ATTESTATION-LINK", &reserve_records);
        let fast_exit_safety_lock_root =
            merkle_root("MONERO-PQ-CACHE-FAST-EXIT-SAFETY-LOCK", &lock_records);
        let light_wallet_sync_proof_root =
            merkle_root("MONERO-PQ-CACHE-LIGHT-WALLET-SYNC-PROOF", &proof_records);
        let cache_eviction_root = merkle_root("MONERO-PQ-CACHE-EVICTION", &eviction_records);
        let canonical_chain_root =
            merkle_root("MONERO-PQ-CACHE-CANONICAL-CHAIN", &canonical_records);
        let finality_index_root = merkle_root("MONERO-PQ-CACHE-FINALITY-INDEX", &finality_records);
        let state_root = cache_hash(
            "STATE",
            &[
                HashPart::Int(self.height as i128),
                HashPart::Str(&config_root),
                HashPart::Str(&header_commitment_root),
                HashPart::Str(&pq_signature_root),
                HashPart::Str(&reorg_score_root),
                HashPart::Str(&checkpoint_window_root),
                HashPart::Str(&reserve_attestation_link_root),
                HashPart::Str(&fast_exit_safety_lock_root),
                HashPart::Str(&light_wallet_sync_proof_root),
                HashPart::Str(&cache_eviction_root),
                HashPart::Str(&canonical_chain_root),
                HashPart::Str(&finality_index_root),
            ],
        );
        Roots {
            config_root,
            header_commitment_root,
            pq_signature_root,
            reorg_score_root,
            checkpoint_window_root,
            reserve_attestation_link_root,
            fast_exit_safety_lock_root,
            light_wallet_sync_proof_root,
            cache_eviction_root,
            canonical_chain_root,
            finality_index_root,
            state_root,
        }
    }

    pub fn counters(&self) -> Counters {
        Counters {
            header_commitments: self.header_commitments.len() as u64,
            finalized_headers: self.finalized_headers.len() as u64,
            pq_signatures: self.pq_finality_signatures.len() as u64,
            accepted_pq_signatures: self
                .pq_finality_signatures
                .values()
                .filter(|signature| signature.counts_for_quorum(self.height))
                .count() as u64,
            reorg_scores: self.reorg_depth_scores.len() as u64,
            critical_reorg_scores: self
                .reorg_depth_scores
                .values()
                .filter(|score| score.risk_level == ReorgRiskLevel::Critical)
                .count() as u64,
            checkpoint_windows: self.checkpoint_windows.len() as u64,
            finalized_checkpoint_windows: self
                .checkpoint_windows
                .values()
                .filter(|window| window.status == CheckpointWindowStatus::Finalized)
                .count() as u64,
            reserve_attestation_links: self.reserve_attestation_links.len() as u64,
            usable_reserve_attestation_links: self
                .reserve_attestation_links
                .values()
                .filter(|link| {
                    link.status.usable_for_exit() && link.expires_at_height >= self.height
                })
                .count() as u64,
            fast_exit_safety_locks: self.fast_exit_safety_locks.len() as u64,
            blocking_fast_exit_safety_locks: self
                .fast_exit_safety_locks
                .values()
                .filter(|lock| lock.status.blocks_fast_exit())
                .count() as u64,
            light_wallet_sync_proofs: self.light_wallet_sync_proofs.len() as u64,
            served_light_wallet_sync_proofs: self
                .light_wallet_sync_proofs
                .values()
                .filter(|proof| {
                    proof.status.is_publicly_served() && proof.expires_at_height >= self.height
                })
                .count() as u64,
            cache_evictions: self.cache_evictions.len() as u64,
            canonical_chain_entries: self.canonical_chain.len() as u64,
        }
    }

    pub fn state_root(&self) -> String {
        self.roots().state_root
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        let counters = self.counters();
        json!({
            "protocol_version": MONERO_PQ_BRIDGE_HEADER_FINALITY_CACHE_PROTOCOL_VERSION,
            "height": self.height,
            "config": self.config.public_record(),
            "roots": roots.public_record(),
            "counters": counters.public_record(),
            "header_commitments": values_public_records(&self.header_commitments, |item| item.public_record()),
            "pq_finality_signatures": values_public_records(&self.pq_finality_signatures, |item| item.public_record()),
            "reorg_depth_scores": values_public_records(&self.reorg_depth_scores, |item| item.public_record()),
            "checkpoint_windows": values_public_records(&self.checkpoint_windows, |item| item.public_record()),
            "reserve_attestation_links": values_public_records(&self.reserve_attestation_links, |item| item.public_record()),
            "fast_exit_safety_locks": values_public_records(&self.fast_exit_safety_locks, |item| item.public_record()),
            "light_wallet_sync_proofs": values_public_records(&self.light_wallet_sync_proofs, |item| item.public_record()),
            "cache_evictions": values_public_records(&self.cache_evictions, |item| item.public_record()),
            "canonical_chain": self.canonical_chain.iter().map(|(height, header_id_value)| json!({
                "height": height,
                "header_id": header_id_value
            })).collect::<Vec<_>>(),
            "finalized_headers": self.finalized_headers.iter().cloned().collect::<Vec<_>>(),
            "frozen_exit_batches": self.frozen_exit_batches.iter().cloned().collect::<Vec<_>>()
        })
    }

    fn apply_height_status_updates(&mut self) {
        let retention_floor = self
            .height
            .saturating_sub(self.config.cache_retention_blocks);
        for header in self.header_commitments.values_mut() {
            if header.height < retention_floor && header.status != HeaderCommitmentStatus::Finalized
            {
                header.status = HeaderCommitmentStatus::Evicted;
            } else if self.height >= header.height + self.config.finality_depth
                && header.status.usable_for_sync()
            {
                header.status = HeaderCommitmentStatus::Finalized;
                self.finalized_headers.insert(header.header_id.clone());
            }
        }
        for signature in self.pq_finality_signatures.values_mut() {
            if signature.expires_at_height < self.height
                && signature.status != PqFinalitySignatureStatus::Slashed
            {
                signature.status = PqFinalitySignatureStatus::Expired;
            }
        }
        for link in self.reserve_attestation_links.values_mut() {
            if link.expires_at_height < self.height
                && link.status != ReserveAttestationLinkStatus::Disputed
            {
                link.status = ReserveAttestationLinkStatus::Stale;
            }
        }
        for lock in self.fast_exit_safety_locks.values_mut() {
            if lock.releases_at_height <= self.height
                && lock.status == FastExitSafetyLockStatus::Armed
            {
                lock.status = FastExitSafetyLockStatus::Released;
            } else if lock.releases_at_height + self.config.cache_retention_blocks < self.height {
                lock.status = FastExitSafetyLockStatus::Expired;
            }
        }
        for proof in self.light_wallet_sync_proofs.values_mut() {
            if proof.expires_at_height < self.height
                && proof.status != LightWalletSyncProofStatus::Rejected
            {
                proof.status = LightWalletSyncProofStatus::Expired;
            }
        }
    }
}

pub fn root_from_record(record: &Value) -> String {
    cache_hash("STATE-FROM-RECORD", &[HashPart::Json(record)])
}

pub fn devnet() -> MoneroPqBridgeHeaderFinalityCacheResult<State> {
    State::devnet()
}

fn validate_header(header: &MoneroHeaderCommitment) -> MoneroPqBridgeHeaderFinalityCacheResult<()> {
    ensure_non_empty("header_id", &header.header_id)?;
    ensure_non_empty("block_hash", &header.block_hash)?;
    ensure_non_empty("previous_block_hash", &header.previous_block_hash)?;
    ensure_non_empty("long_term_weight_root", &header.long_term_weight_root)?;
    ensure_non_empty("pow_seed_hash", &header.pow_seed_hash)?;
    ensure_non_empty("miner_tx_commitment", &header.miner_tx_commitment)?;
    ensure_non_empty("tx_merkle_root", &header.tx_merkle_root)?;
    ensure_non_empty("bridge_observation_root", &header.bridge_observation_root)?;
    ensure_positive("header.height", header.height)?;
    ensure_positive("timestamp", header.timestamp)?;
    ensure_positive("difficulty", header.difficulty)?;
    ensure_positive("observed_at_height", header.observed_at_height)?;
    Ok(())
}

fn validate_signature(
    signature: &PqFinalitySignature,
) -> MoneroPqBridgeHeaderFinalityCacheResult<()> {
    ensure_non_empty("signature_id", &signature.signature_id)?;
    ensure_non_empty("header_id", &signature.header_id)?;
    ensure_non_empty("signer_id", &signature.signer_id)?;
    ensure_positive("signer_weight", signature.signer_weight)?;
    ensure_non_empty("signature_root", &signature.signature_root)?;
    ensure_non_empty(
        "aggregate_public_key_root",
        &signature.aggregate_public_key_root,
    )?;
    ensure_non_empty("transcript_root", &signature.transcript_root)?;
    ensure_positive("signed_at_height", signature.signed_at_height)?;
    if signature.expires_at_height < signature.signed_at_height {
        return Err("signature expires before signed height".to_string());
    }
    Ok(())
}

fn validate_reorg_score(score: &ReorgDepthScore) -> MoneroPqBridgeHeaderFinalityCacheResult<()> {
    ensure_non_empty("score_id", &score.score_id)?;
    ensure_non_empty("canonical_header_id", &score.canonical_header_id)?;
    ensure_non_empty("competing_header_id", &score.competing_header_id)?;
    ensure_positive("fork_height", score.fork_height)?;
    ensure_positive("observed_tip_height", score.observed_tip_height)?;
    ensure_bps("penalty_bps", score.penalty_bps)?;
    ensure_non_empty("watcher_evidence_root", &score.watcher_evidence_root)?;
    if score.observed_tip_height < score.fork_height {
        return Err("reorg score observed tip below fork height".to_string());
    }
    Ok(())
}

fn validate_checkpoint_window(
    window: &CheckpointWindow,
) -> MoneroPqBridgeHeaderFinalityCacheResult<()> {
    ensure_non_empty("window_id", &window.window_id)?;
    ensure_positive("start_height", window.start_height)?;
    ensure_positive("end_height", window.end_height)?;
    ensure_non_empty("anchor_header_id", &window.anchor_header_id)?;
    ensure_non_empty("header_root", &window.header_root)?;
    ensure_non_empty("signature_root", &window.signature_root)?;
    ensure_non_empty("reserve_link_root", &window.reserve_link_root)?;
    ensure_positive("finalized_height", window.finalized_height)?;
    Ok(())
}

fn validate_reserve_link(
    link: &ReserveAttestationLink,
) -> MoneroPqBridgeHeaderFinalityCacheResult<()> {
    ensure_non_empty("link_id", &link.link_id)?;
    ensure_non_empty("header_id", &link.header_id)?;
    ensure_non_empty("reserve_attestation_id", &link.reserve_attestation_id)?;
    ensure_non_empty("reserve_root", &link.reserve_root)?;
    ensure_non_empty("liability_root", &link.liability_root)?;
    ensure_bps("coverage_bps", link.coverage_bps)?;
    ensure_positive("linked_at_height", link.linked_at_height)?;
    if link.expires_at_height < link.linked_at_height {
        return Err("reserve link expires before linked height".to_string());
    }
    Ok(())
}

fn validate_fast_exit_lock(
    lock: &FastExitSafetyLock,
) -> MoneroPqBridgeHeaderFinalityCacheResult<()> {
    ensure_non_empty("lock_id", &lock.lock_id)?;
    ensure_non_empty("header_id", &lock.header_id)?;
    ensure_non_empty("exit_batch_id", &lock.exit_batch_id)?;
    ensure_non_empty("reserve_link_id", &lock.reserve_link_id)?;
    ensure_positive("locked_amount_piconero", lock.locked_amount_piconero)?;
    ensure_non_empty("lock_reason_root", &lock.lock_reason_root)?;
    ensure_positive("opened_at_height", lock.opened_at_height)?;
    if lock.releases_at_height < lock.opened_at_height {
        return Err("fast exit lock releases before opened height".to_string());
    }
    Ok(())
}

fn validate_light_wallet_proof(
    proof: &LightWalletSyncProof,
) -> MoneroPqBridgeHeaderFinalityCacheResult<()> {
    ensure_non_empty("proof_id", &proof.proof_id)?;
    ensure_non_empty("wallet_view_tag_root", &proof.wallet_view_tag_root)?;
    ensure_non_empty("header_id", &proof.header_id)?;
    ensure_non_empty("checkpoint_window_id", &proof.checkpoint_window_id)?;
    ensure_non_empty("inclusion_root", &proof.inclusion_root)?;
    ensure_non_empty("output_scan_root", &proof.output_scan_root)?;
    ensure_non_empty("nullifier_hint_root", &proof.nullifier_hint_root)?;
    ensure_positive("proved_from_height", proof.proved_from_height)?;
    ensure_positive("proved_to_height", proof.proved_to_height)?;
    ensure_positive("served_at_height", proof.served_at_height)?;
    if proof.proved_to_height < proof.proved_from_height {
        return Err("light wallet proof range is inverted".to_string());
    }
    if proof.expires_at_height < proof.served_at_height {
        return Err("light wallet proof expires before served height".to_string());
    }
    Ok(())
}

fn validate_eviction(eviction: &CacheEvictionEntry) -> MoneroPqBridgeHeaderFinalityCacheResult<()> {
    ensure_non_empty("eviction_id", &eviction.eviction_id)?;
    ensure_non_empty("subject_id", &eviction.subject_id)?;
    ensure_non_empty("subject_kind", &eviction.subject_kind)?;
    ensure_positive("evicted_at_height", eviction.evicted_at_height)?;
    ensure_non_empty("replacement_root", &eviction.replacement_root)?;
    Ok(())
}

fn values_public_records<T, F>(items: &BTreeMap<String, T>, mut to_record: F) -> Vec<Value>
where
    F: FnMut(&T) -> Value,
{
    items
        .values()
        .map(|item| to_record(item))
        .collect::<Vec<_>>()
}

fn header_id(block_hash: &str, height: u64) -> String {
    cache_hash(
        "HEADER-ID",
        &[HashPart::Str(block_hash), HashPart::Int(height as i128)],
    )
}

fn signature_id(header_id_value: &str, signer_index: u64) -> String {
    cache_hash(
        "SIGNATURE-ID",
        &[
            HashPart::Str(header_id_value),
            HashPart::Int(signer_index as i128),
        ],
    )
}

fn checkpoint_window_id(start_height: u64, end_height: u64) -> String {
    cache_hash(
        "CHECKPOINT-WINDOW-ID",
        &[
            HashPart::Int(start_height as i128),
            HashPart::Int(end_height as i128),
        ],
    )
}

fn ensure_id_match(
    collection: &str,
    key: &str,
    id: &str,
) -> MoneroPqBridgeHeaderFinalityCacheResult<()> {
    if key == id {
        Ok(())
    } else {
        Err(format!("{collection} key does not match embedded id"))
    }
}

fn ensure_non_empty(name: &str, value: &str) -> MoneroPqBridgeHeaderFinalityCacheResult<()> {
    if value.trim().is_empty() {
        Err(format!("{name} must not be empty"))
    } else {
        Ok(())
    }
}

fn ensure_positive(name: &str, value: u64) -> MoneroPqBridgeHeaderFinalityCacheResult<()> {
    if value == 0 {
        Err(format!("{name} must be positive"))
    } else {
        Ok(())
    }
}

fn ensure_bps(name: &str, value: u64) -> MoneroPqBridgeHeaderFinalityCacheResult<()> {
    if value > MONERO_PQ_BRIDGE_HEADER_FINALITY_CACHE_MAX_BPS {
        Err(format!("{name} exceeds max bps"))
    } else {
        Ok(())
    }
}

fn cache_hash(label: &str, parts: &[HashPart<'_>]) -> String {
    domain_hash(
        &format!(
            "MONERO-PQ-BRIDGE-HEADER-FINALITY-CACHE:{CHAIN_ID}:{}:{label}",
            MONERO_PQ_BRIDGE_HEADER_FINALITY_CACHE_PROTOCOL_VERSION
        ),
        parts,
        32,
    )
}
