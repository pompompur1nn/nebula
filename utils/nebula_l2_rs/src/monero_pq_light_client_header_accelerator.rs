use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type MoneroPqLightClientHeaderAcceleratorResult<T> = Result<T, String>;

pub const MONERO_PQ_LIGHT_CLIENT_HEADER_ACCELERATOR_PROTOCOL_VERSION: &str =
    "nebula-monero-pq-light-client-header-accelerator-v1";
pub const MONERO_PQ_LIGHT_CLIENT_HEADER_ACCELERATOR_SCHEMA_VERSION: u64 = 1;
pub const MONERO_PQ_LIGHT_CLIENT_HEADER_ACCELERATOR_SECURITY_MODEL: &str =
    "deterministic-devnet-records-not-real-crypto";
pub const MONERO_PQ_LIGHT_CLIENT_HEADER_ACCELERATOR_HASH_SUITE: &str = "SHAKE256";
pub const MONERO_PQ_LIGHT_CLIENT_HEADER_ACCELERATOR_HEADER_COMMITMENT_SCHEME: &str =
    "compact-monero-header-commitment-v1";
pub const MONERO_PQ_LIGHT_CLIENT_HEADER_ACCELERATOR_PQ_SIGNATURE_SCHEME: &str = "ML-DSA-87";
pub const MONERO_PQ_LIGHT_CLIENT_HEADER_ACCELERATOR_BACKUP_SIGNATURE_SCHEME: &str =
    "SLH-DSA-SHAKE-192s";
pub const MONERO_PQ_LIGHT_CLIENT_HEADER_ACCELERATOR_KEM_SCHEME: &str = "ML-KEM-1024";
pub const MONERO_PQ_LIGHT_CLIENT_HEADER_ACCELERATOR_REPORT_ENCRYPTION_SCHEME: &str =
    "sealed-watcher-report-ml-kem-aead-v1";
pub const MONERO_PQ_LIGHT_CLIENT_HEADER_ACCELERATOR_BATCH_RECEIPT_SCHEME: &str =
    "pq-batch-header-verification-receipt-v1";
pub const MONERO_PQ_LIGHT_CLIENT_HEADER_ACCELERATOR_SLASHING_HANDOFF_SCHEME: &str =
    "pq-validator-slashing-handoff-v1";
pub const MONERO_PQ_LIGHT_CLIENT_HEADER_ACCELERATOR_DEVNET_NETWORK: &str = "monero-devnet";
pub const MONERO_PQ_LIGHT_CLIENT_HEADER_ACCELERATOR_DEVNET_ASSET_ID: &str = "wxmr-devnet";
pub const MONERO_PQ_LIGHT_CLIENT_HEADER_ACCELERATOR_DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const MONERO_PQ_LIGHT_CLIENT_HEADER_ACCELERATOR_DEVNET_COMMITTEE_ID: &str =
    "monero-pq-header-accelerator-devnet-committee";
pub const MONERO_PQ_LIGHT_CLIENT_HEADER_ACCELERATOR_DEVNET_HEIGHT: u64 = 12_288;
pub const MONERO_PQ_LIGHT_CLIENT_HEADER_ACCELERATOR_DEFAULT_EPOCH_BLOCKS: u64 = 240;
pub const MONERO_PQ_LIGHT_CLIENT_HEADER_ACCELERATOR_DEFAULT_REORG_WINDOW_BLOCKS: u64 = 64;
pub const MONERO_PQ_LIGHT_CLIENT_HEADER_ACCELERATOR_DEFAULT_HEADER_BATCH_SIZE: u64 = 32;
pub const MONERO_PQ_LIGHT_CLIENT_HEADER_ACCELERATOR_DEFAULT_FINALITY_DEPTH: u64 = 20;
pub const MONERO_PQ_LIGHT_CLIENT_HEADER_ACCELERATOR_DEFAULT_MIN_VALIDATOR_WEIGHT: u64 = 67;
pub const MONERO_PQ_LIGHT_CLIENT_HEADER_ACCELERATOR_DEFAULT_SAFE_QUORUM_BPS: u64 = 6_700;
pub const MONERO_PQ_LIGHT_CLIENT_HEADER_ACCELERATOR_DEFAULT_FAST_QUORUM_BPS: u64 = 8_000;
pub const MONERO_PQ_LIGHT_CLIENT_HEADER_ACCELERATOR_DEFAULT_WATCHER_QUORUM: u64 = 2;
pub const MONERO_PQ_LIGHT_CLIENT_HEADER_ACCELERATOR_DEFAULT_LOW_FEE_SUBSIDY_BUDGET: u64 =
    250_000_000;
pub const MONERO_PQ_LIGHT_CLIENT_HEADER_ACCELERATOR_DEFAULT_SUBSIDY_UNIT_PRICE: u64 = 250;
pub const MONERO_PQ_LIGHT_CLIENT_HEADER_ACCELERATOR_DEFAULT_PRIVATE_LANE_TTL_BLOCKS: u64 = 96;
pub const MONERO_PQ_LIGHT_CLIENT_HEADER_ACCELERATOR_DEFAULT_REPORT_TTL_BLOCKS: u64 = 96;
pub const MONERO_PQ_LIGHT_CLIENT_HEADER_ACCELERATOR_DEFAULT_SLASHING_TTL_BLOCKS: u64 = 720;
pub const MONERO_PQ_LIGHT_CLIENT_HEADER_ACCELERATOR_DEFAULT_MAX_HEADERS_PER_RECEIPT: u64 = 128;
pub const MONERO_PQ_LIGHT_CLIENT_HEADER_ACCELERATOR_DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const MONERO_PQ_LIGHT_CLIENT_HEADER_ACCELERATOR_MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HeaderCommitmentStatus {
    Draft,
    Observed,
    Attested,
    Checkpointed,
    Reorged,
    Finalized,
    Rejected,
}

impl HeaderCommitmentStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Observed => "observed",
            Self::Attested => "attested",
            Self::Checkpointed => "checkpointed",
            Self::Reorged => "reorged",
            Self::Finalized => "finalized",
            Self::Rejected => "rejected",
        }
    }

    pub fn usable_for_sync(self) -> bool {
        matches!(self, Self::Attested | Self::Checkpointed | Self::Finalized)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqHeaderValidatorRole {
    HeaderProducer,
    BridgeValidator,
    Watcher,
    SubsidySponsor,
    SlashingGuardian,
    EmergencyCouncil,
}

impl PqHeaderValidatorRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::HeaderProducer => "header_producer",
            Self::BridgeValidator => "bridge_validator",
            Self::Watcher => "watcher",
            Self::SubsidySponsor => "subsidy_sponsor",
            Self::SlashingGuardian => "slashing_guardian",
            Self::EmergencyCouncil => "emergency_council",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqHeaderValidatorStatus {
    Pending,
    Active,
    Rotating,
    Jailed,
    Retired,
}

impl PqHeaderValidatorStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Active => "active",
            Self::Rotating => "rotating",
            Self::Jailed => "jailed",
            Self::Retired => "retired",
        }
    }

    pub fn can_attest(self) -> bool {
        matches!(self, Self::Active | Self::Rotating)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReorgProofStatus {
    Watching,
    Proposed,
    Challenged,
    Accepted,
    Rejected,
    Expired,
}

impl ReorgProofStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Watching => "watching",
            Self::Proposed => "proposed",
            Self::Challenged => "challenged",
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }

    pub fn is_open(self) -> bool {
        matches!(self, Self::Watching | Self::Proposed | Self::Challenged)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivateBridgeLaneKind {
    DepositSync,
    WithdrawalSync,
    ReserveAudit,
    EmergencyExit,
    LiquidityProof,
    WatchOnlyReplay,
}

impl PrivateBridgeLaneKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DepositSync => "deposit_sync",
            Self::WithdrawalSync => "withdrawal_sync",
            Self::ReserveAudit => "reserve_audit",
            Self::EmergencyExit => "emergency_exit",
            Self::LiquidityProof => "liquidity_proof",
            Self::WatchOnlyReplay => "watch_only_replay",
        }
    }

    pub fn privacy_critical(self) -> bool {
        matches!(
            self,
            Self::DepositSync | Self::WithdrawalSync | Self::EmergencyExit | Self::LiquidityProof
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BridgeLaneStatus {
    Open,
    Sealed,
    Proving,
    Subsidized,
    ReorgReplay,
    Expired,
}

impl BridgeLaneStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Sealed => "sealed",
            Self::Proving => "proving",
            Self::Subsidized => "subsidized",
            Self::ReorgReplay => "reorg_replay",
            Self::Expired => "expired",
        }
    }

    pub fn active(self) -> bool {
        matches!(
            self,
            Self::Open | Self::Sealed | Self::Proving | Self::Subsidized
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubsidyStatus {
    Offered,
    Reserved,
    Consumed,
    Exhausted,
    Expired,
    Slashed,
}

impl SubsidyStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Offered => "offered",
            Self::Reserved => "reserved",
            Self::Consumed => "consumed",
            Self::Exhausted => "exhausted",
            Self::Expired => "expired",
            Self::Slashed => "slashed",
        }
    }

    pub fn live(self) -> bool {
        matches!(self, Self::Offered | Self::Reserved | Self::Consumed)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WatcherReportKind {
    MissingHeader,
    InvalidPow,
    InvalidTimestamp,
    ReorgObserved,
    BatchMismatch,
    BridgeLaneLeak,
    Equivocation,
}

impl WatcherReportKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MissingHeader => "missing_header",
            Self::InvalidPow => "invalid_pow",
            Self::InvalidTimestamp => "invalid_timestamp",
            Self::ReorgObserved => "reorg_observed",
            Self::BatchMismatch => "batch_mismatch",
            Self::BridgeLaneLeak => "bridge_lane_leak",
            Self::Equivocation => "equivocation",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WatcherReportStatus {
    Sealed,
    Submitted,
    Accepted,
    Disputed,
    SlashingReady,
    Expired,
}

impl WatcherReportStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sealed => "sealed",
            Self::Submitted => "submitted",
            Self::Accepted => "accepted",
            Self::Disputed => "disputed",
            Self::SlashingReady => "slashing_ready",
            Self::Expired => "expired",
        }
    }

    pub fn counts_for_quorum(self) -> bool {
        matches!(self, Self::Submitted | Self::Accepted | Self::SlashingReady)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchReceiptStatus {
    Draft,
    Verified,
    Anchored,
    Challenged,
    Finalized,
    Reorged,
}

impl BatchReceiptStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Verified => "verified",
            Self::Anchored => "anchored",
            Self::Challenged => "challenged",
            Self::Finalized => "finalized",
            Self::Reorged => "reorged",
        }
    }

    pub fn verified(self) -> bool {
        matches!(self, Self::Verified | Self::Anchored | Self::Finalized)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SlashingEvidenceKind {
    DoubleAttestation,
    InvalidHeaderRoot,
    InvalidReorgProof,
    WatcherReportLeak,
    SubsidyFraud,
    BatchReceiptForgery,
}

impl SlashingEvidenceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DoubleAttestation => "double_attestation",
            Self::InvalidHeaderRoot => "invalid_header_root",
            Self::InvalidReorgProof => "invalid_reorg_proof",
            Self::WatcherReportLeak => "watcher_report_leak",
            Self::SubsidyFraud => "subsidy_fraud",
            Self::BatchReceiptForgery => "batch_receipt_forgery",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SlashingHandoffStatus {
    Prepared,
    Submitted,
    Accepted,
    Rejected,
    Executed,
    Expired,
}

impl SlashingHandoffStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Prepared => "prepared",
            Self::Submitted => "submitted",
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
            Self::Executed => "executed",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroPqHeaderAcceleratorConfig {
    pub protocol_version: String,
    pub schema_version: u64,
    pub monero_network: String,
    pub asset_id: String,
    pub fee_asset_id: String,
    pub committee_id: String,
    pub epoch_blocks: u64,
    pub reorg_window_blocks: u64,
    pub header_batch_size: u64,
    pub finality_depth: u64,
    pub min_validator_weight: u64,
    pub safe_quorum_bps: u64,
    pub fast_quorum_bps: u64,
    pub watcher_quorum: u64,
    pub low_fee_subsidy_budget: u64,
    pub subsidy_unit_price: u64,
    pub private_lane_ttl_blocks: u64,
    pub report_ttl_blocks: u64,
    pub slashing_ttl_blocks: u64,
    pub max_headers_per_receipt: u64,
    pub min_pq_security_bits: u16,
    pub header_commitment_scheme: String,
    pub pq_signature_scheme: String,
    pub backup_signature_scheme: String,
    pub kem_scheme: String,
    pub report_encryption_scheme: String,
    pub batch_receipt_scheme: String,
    pub slashing_handoff_scheme: String,
}

impl MoneroPqHeaderAcceleratorConfig {
    pub fn devnet() -> Self {
        Self {
            protocol_version: MONERO_PQ_LIGHT_CLIENT_HEADER_ACCELERATOR_PROTOCOL_VERSION
                .to_string(),
            schema_version: MONERO_PQ_LIGHT_CLIENT_HEADER_ACCELERATOR_SCHEMA_VERSION,
            monero_network: MONERO_PQ_LIGHT_CLIENT_HEADER_ACCELERATOR_DEVNET_NETWORK.to_string(),
            asset_id: MONERO_PQ_LIGHT_CLIENT_HEADER_ACCELERATOR_DEVNET_ASSET_ID.to_string(),
            fee_asset_id: MONERO_PQ_LIGHT_CLIENT_HEADER_ACCELERATOR_DEVNET_FEE_ASSET_ID.to_string(),
            committee_id: MONERO_PQ_LIGHT_CLIENT_HEADER_ACCELERATOR_DEVNET_COMMITTEE_ID.to_string(),
            epoch_blocks: MONERO_PQ_LIGHT_CLIENT_HEADER_ACCELERATOR_DEFAULT_EPOCH_BLOCKS,
            reorg_window_blocks:
                MONERO_PQ_LIGHT_CLIENT_HEADER_ACCELERATOR_DEFAULT_REORG_WINDOW_BLOCKS,
            header_batch_size: MONERO_PQ_LIGHT_CLIENT_HEADER_ACCELERATOR_DEFAULT_HEADER_BATCH_SIZE,
            finality_depth: MONERO_PQ_LIGHT_CLIENT_HEADER_ACCELERATOR_DEFAULT_FINALITY_DEPTH,
            min_validator_weight:
                MONERO_PQ_LIGHT_CLIENT_HEADER_ACCELERATOR_DEFAULT_MIN_VALIDATOR_WEIGHT,
            safe_quorum_bps: MONERO_PQ_LIGHT_CLIENT_HEADER_ACCELERATOR_DEFAULT_SAFE_QUORUM_BPS,
            fast_quorum_bps: MONERO_PQ_LIGHT_CLIENT_HEADER_ACCELERATOR_DEFAULT_FAST_QUORUM_BPS,
            watcher_quorum: MONERO_PQ_LIGHT_CLIENT_HEADER_ACCELERATOR_DEFAULT_WATCHER_QUORUM,
            low_fee_subsidy_budget:
                MONERO_PQ_LIGHT_CLIENT_HEADER_ACCELERATOR_DEFAULT_LOW_FEE_SUBSIDY_BUDGET,
            subsidy_unit_price:
                MONERO_PQ_LIGHT_CLIENT_HEADER_ACCELERATOR_DEFAULT_SUBSIDY_UNIT_PRICE,
            private_lane_ttl_blocks:
                MONERO_PQ_LIGHT_CLIENT_HEADER_ACCELERATOR_DEFAULT_PRIVATE_LANE_TTL_BLOCKS,
            report_ttl_blocks: MONERO_PQ_LIGHT_CLIENT_HEADER_ACCELERATOR_DEFAULT_REPORT_TTL_BLOCKS,
            slashing_ttl_blocks:
                MONERO_PQ_LIGHT_CLIENT_HEADER_ACCELERATOR_DEFAULT_SLASHING_TTL_BLOCKS,
            max_headers_per_receipt:
                MONERO_PQ_LIGHT_CLIENT_HEADER_ACCELERATOR_DEFAULT_MAX_HEADERS_PER_RECEIPT,
            min_pq_security_bits:
                MONERO_PQ_LIGHT_CLIENT_HEADER_ACCELERATOR_DEFAULT_MIN_PQ_SECURITY_BITS,
            header_commitment_scheme:
                MONERO_PQ_LIGHT_CLIENT_HEADER_ACCELERATOR_HEADER_COMMITMENT_SCHEME.to_string(),
            pq_signature_scheme: MONERO_PQ_LIGHT_CLIENT_HEADER_ACCELERATOR_PQ_SIGNATURE_SCHEME
                .to_string(),
            backup_signature_scheme:
                MONERO_PQ_LIGHT_CLIENT_HEADER_ACCELERATOR_BACKUP_SIGNATURE_SCHEME.to_string(),
            kem_scheme: MONERO_PQ_LIGHT_CLIENT_HEADER_ACCELERATOR_KEM_SCHEME.to_string(),
            report_encryption_scheme:
                MONERO_PQ_LIGHT_CLIENT_HEADER_ACCELERATOR_REPORT_ENCRYPTION_SCHEME.to_string(),
            batch_receipt_scheme: MONERO_PQ_LIGHT_CLIENT_HEADER_ACCELERATOR_BATCH_RECEIPT_SCHEME
                .to_string(),
            slashing_handoff_scheme:
                MONERO_PQ_LIGHT_CLIENT_HEADER_ACCELERATOR_SLASHING_HANDOFF_SCHEME.to_string(),
        }
    }

    pub fn validate(&self) -> MoneroPqLightClientHeaderAcceleratorResult<()> {
        ensure_non_empty(
            &self.protocol_version,
            "header accelerator protocol version",
        )?;
        ensure_non_empty(&self.monero_network, "header accelerator monero network")?;
        ensure_non_empty(&self.asset_id, "header accelerator asset id")?;
        ensure_non_empty(&self.fee_asset_id, "header accelerator fee asset id")?;
        ensure_non_empty(&self.committee_id, "header accelerator committee id")?;
        ensure_non_empty(&self.header_commitment_scheme, "header commitment scheme")?;
        ensure_non_empty(&self.pq_signature_scheme, "pq signature scheme")?;
        ensure_non_empty(&self.backup_signature_scheme, "backup signature scheme")?;
        ensure_non_empty(&self.kem_scheme, "kem scheme")?;
        ensure_non_empty(&self.report_encryption_scheme, "report encryption scheme")?;
        ensure_non_empty(&self.batch_receipt_scheme, "batch receipt scheme")?;
        ensure_non_empty(&self.slashing_handoff_scheme, "slashing handoff scheme")?;
        ensure_positive(self.schema_version, "schema version")?;
        ensure_positive(self.epoch_blocks, "epoch blocks")?;
        ensure_positive(self.reorg_window_blocks, "reorg window blocks")?;
        ensure_positive(self.header_batch_size, "header batch size")?;
        ensure_positive(self.finality_depth, "finality depth")?;
        ensure_positive(self.min_validator_weight, "minimum validator weight")?;
        ensure_positive(self.safe_quorum_bps, "safe quorum bps")?;
        ensure_positive(self.fast_quorum_bps, "fast quorum bps")?;
        ensure_positive(self.watcher_quorum, "watcher quorum")?;
        ensure_positive(self.subsidy_unit_price, "subsidy unit price")?;
        ensure_positive(self.private_lane_ttl_blocks, "private lane ttl blocks")?;
        ensure_positive(self.report_ttl_blocks, "report ttl blocks")?;
        ensure_positive(self.slashing_ttl_blocks, "slashing ttl blocks")?;
        ensure_positive(self.max_headers_per_receipt, "max headers per receipt")?;
        if self.safe_quorum_bps > MONERO_PQ_LIGHT_CLIENT_HEADER_ACCELERATOR_MAX_BPS
            || self.fast_quorum_bps > MONERO_PQ_LIGHT_CLIENT_HEADER_ACCELERATOR_MAX_BPS
        {
            return Err("header accelerator quorum bps exceeds maximum".to_string());
        }
        if self.safe_quorum_bps > self.fast_quorum_bps {
            return Err("safe quorum cannot exceed fast quorum".to_string());
        }
        if self.header_batch_size > self.max_headers_per_receipt {
            return Err("default header batch cannot exceed receipt maximum".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_pq_header_accelerator_config",
            "chain_id": CHAIN_ID,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "monero_network": self.monero_network,
            "asset_id": self.asset_id,
            "fee_asset_id": self.fee_asset_id,
            "committee_id": self.committee_id,
            "epoch_blocks": self.epoch_blocks,
            "reorg_window_blocks": self.reorg_window_blocks,
            "header_batch_size": self.header_batch_size,
            "finality_depth": self.finality_depth,
            "min_validator_weight": self.min_validator_weight,
            "safe_quorum_bps": self.safe_quorum_bps,
            "fast_quorum_bps": self.fast_quorum_bps,
            "watcher_quorum": self.watcher_quorum,
            "low_fee_subsidy_budget": self.low_fee_subsidy_budget,
            "subsidy_unit_price": self.subsidy_unit_price,
            "private_lane_ttl_blocks": self.private_lane_ttl_blocks,
            "report_ttl_blocks": self.report_ttl_blocks,
            "slashing_ttl_blocks": self.slashing_ttl_blocks,
            "max_headers_per_receipt": self.max_headers_per_receipt,
            "min_pq_security_bits": self.min_pq_security_bits,
            "header_commitment_scheme": self.header_commitment_scheme,
            "pq_signature_scheme": self.pq_signature_scheme,
            "backup_signature_scheme": self.backup_signature_scheme,
            "kem_scheme": self.kem_scheme,
            "report_encryption_scheme": self.report_encryption_scheme,
            "batch_receipt_scheme": self.batch_receipt_scheme,
            "slashing_handoff_scheme": self.slashing_handoff_scheme,
            "security_model": MONERO_PQ_LIGHT_CLIENT_HEADER_ACCELERATOR_SECURITY_MODEL,
            "hash_suite": MONERO_PQ_LIGHT_CLIENT_HEADER_ACCELERATOR_HASH_SUITE,
        })
    }

    pub fn config_root(&self) -> String {
        accelerator_payload_root("MONERO-PQ-HCA-CONFIG", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompactHeaderCommitment {
    pub commitment_id: String,
    pub block_height: u64,
    pub epoch: u64,
    pub monero_block_hash: String,
    pub previous_block_hash: String,
    pub header_commitment_root: String,
    pub pow_digest_root: String,
    pub tx_tree_root: String,
    pub output_commitment_root: String,
    pub difficulty_commitment: String,
    pub timestamp_commitment: String,
    pub observed_at_height: u64,
    pub status: HeaderCommitmentStatus,
}

impl CompactHeaderCommitment {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        block_height: u64,
        epoch: u64,
        monero_block_hash: &str,
        previous_block_hash: &str,
        header_commitment_root: &str,
        pow_digest_root: &str,
        tx_tree_root: &str,
        output_commitment_root: &str,
        difficulty_commitment: &str,
        timestamp_commitment: &str,
        observed_at_height: u64,
        status: HeaderCommitmentStatus,
    ) -> MoneroPqLightClientHeaderAcceleratorResult<Self> {
        ensure_non_empty(monero_block_hash, "compact header monero block hash")?;
        ensure_non_empty(previous_block_hash, "compact header previous block hash")?;
        ensure_non_empty(header_commitment_root, "compact header commitment root")?;
        ensure_non_empty(pow_digest_root, "compact header pow digest root")?;
        ensure_non_empty(tx_tree_root, "compact header tx tree root")?;
        ensure_non_empty(output_commitment_root, "compact header output root")?;
        ensure_non_empty(
            difficulty_commitment,
            "compact header difficulty commitment",
        )?;
        ensure_non_empty(timestamp_commitment, "compact header timestamp commitment")?;
        ensure_positive(block_height, "compact header block height")?;
        let commitment_id = accelerator_id(
            "compact-header",
            &[
                HashPart::Int(block_height as i128),
                HashPart::Str(monero_block_hash),
                HashPart::Str(header_commitment_root),
            ],
        );
        Ok(Self {
            commitment_id,
            block_height,
            epoch,
            monero_block_hash: monero_block_hash.to_string(),
            previous_block_hash: previous_block_hash.to_string(),
            header_commitment_root: header_commitment_root.to_string(),
            pow_digest_root: pow_digest_root.to_string(),
            tx_tree_root: tx_tree_root.to_string(),
            output_commitment_root: output_commitment_root.to_string(),
            difficulty_commitment: difficulty_commitment.to_string(),
            timestamp_commitment: timestamp_commitment.to_string(),
            observed_at_height,
            status,
        })
    }

    pub fn devnet(
        block_height: u64,
        observed_at_height: u64,
        status: HeaderCommitmentStatus,
    ) -> Self {
        let seed = format!("compact-header-{block_height}");
        let monero_block_hash = devnet_root("monero-block-hash", &seed);
        let previous_block_hash = devnet_root("monero-prev-block-hash", &seed);
        let header_commitment_root = devnet_root("header-commitment", &seed);
        let pow_digest_root = devnet_root("pow-digest", &seed);
        let tx_tree_root = devnet_root("tx-tree", &seed);
        let output_commitment_root = devnet_root("output-commitment", &seed);
        let difficulty_commitment = devnet_root("difficulty", &seed);
        let timestamp_commitment = devnet_root("timestamp", &seed);
        let commitment_id = accelerator_id(
            "compact-header",
            &[
                HashPart::Int(block_height as i128),
                HashPart::Str(&monero_block_hash),
                HashPart::Str(&header_commitment_root),
            ],
        );
        Self {
            commitment_id,
            block_height,
            epoch: block_height / MONERO_PQ_LIGHT_CLIENT_HEADER_ACCELERATOR_DEFAULT_EPOCH_BLOCKS,
            monero_block_hash,
            previous_block_hash,
            header_commitment_root,
            pow_digest_root,
            tx_tree_root,
            output_commitment_root,
            difficulty_commitment,
            timestamp_commitment,
            observed_at_height,
            status,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "compact_header_commitment",
            "chain_id": CHAIN_ID,
            "commitment_id": self.commitment_id,
            "block_height": self.block_height,
            "epoch": self.epoch,
            "monero_block_hash": self.monero_block_hash,
            "previous_block_hash": self.previous_block_hash,
            "header_commitment_root": self.header_commitment_root,
            "pow_digest_root": self.pow_digest_root,
            "tx_tree_root": self.tx_tree_root,
            "output_commitment_root": self.output_commitment_root,
            "difficulty_commitment": self.difficulty_commitment,
            "timestamp_commitment": self.timestamp_commitment,
            "observed_at_height": self.observed_at_height,
            "status": self.status.as_str(),
            "usable_for_sync": self.status.usable_for_sync(),
        })
    }

    pub fn commitment_root(&self) -> String {
        accelerator_payload_root("MONERO-PQ-HCA-COMPACT-HEADER", &self.public_record())
    }

    pub fn validate(&self) -> MoneroPqLightClientHeaderAcceleratorResult<String> {
        ensure_non_empty(&self.commitment_id, "compact header commitment id")?;
        ensure_non_empty(&self.monero_block_hash, "compact header monero block hash")?;
        ensure_non_empty(
            &self.previous_block_hash,
            "compact header previous block hash",
        )?;
        ensure_non_empty(
            &self.header_commitment_root,
            "compact header commitment root",
        )?;
        ensure_non_empty(&self.pow_digest_root, "compact header pow digest root")?;
        ensure_non_empty(&self.tx_tree_root, "compact header tx tree root")?;
        ensure_non_empty(&self.output_commitment_root, "compact header output root")?;
        ensure_non_empty(
            &self.difficulty_commitment,
            "compact header difficulty commitment",
        )?;
        ensure_non_empty(
            &self.timestamp_commitment,
            "compact header timestamp commitment",
        )?;
        ensure_positive(self.block_height, "compact header block height")?;
        Ok(self.commitment_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqHeaderValidator {
    pub validator_id: String,
    pub role: PqHeaderValidatorRole,
    pub status: PqHeaderValidatorStatus,
    pub weight: u64,
    pub pq_public_key_commitment: String,
    pub backup_public_key_commitment: String,
    pub encryption_key_commitment: String,
    pub stake_commitment_root: String,
    pub last_attested_height: u64,
    pub joined_at_height: u64,
}

impl PqHeaderValidator {
    pub fn devnet(
        index: u64,
        role: PqHeaderValidatorRole,
        weight: u64,
        joined_at_height: u64,
    ) -> Self {
        let seed = format!("validator-{index}-{}", role.as_str());
        let pq_public_key_commitment = devnet_root("validator-pq-key", &seed);
        let backup_public_key_commitment = devnet_root("validator-backup-key", &seed);
        let encryption_key_commitment = devnet_root("validator-enc-key", &seed);
        let stake_commitment_root = devnet_root("validator-stake", &seed);
        let validator_id = accelerator_id(
            "validator",
            &[
                HashPart::Str(role.as_str()),
                HashPart::Int(index as i128),
                HashPart::Str(&pq_public_key_commitment),
            ],
        );
        Self {
            validator_id,
            role,
            status: PqHeaderValidatorStatus::Active,
            weight,
            pq_public_key_commitment,
            backup_public_key_commitment,
            encryption_key_commitment,
            stake_commitment_root,
            last_attested_height: joined_at_height,
            joined_at_height,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_header_validator",
            "chain_id": CHAIN_ID,
            "validator_id": self.validator_id,
            "role": self.role.as_str(),
            "status": self.status.as_str(),
            "weight": self.weight,
            "pq_public_key_commitment": self.pq_public_key_commitment,
            "backup_public_key_commitment": self.backup_public_key_commitment,
            "encryption_key_commitment": self.encryption_key_commitment,
            "stake_commitment_root": self.stake_commitment_root,
            "last_attested_height": self.last_attested_height,
            "joined_at_height": self.joined_at_height,
            "can_attest": self.status.can_attest(),
        })
    }

    pub fn validator_root(&self) -> String {
        accelerator_payload_root("MONERO-PQ-HCA-VALIDATOR", &self.public_record())
    }

    pub fn validate(&self) -> MoneroPqLightClientHeaderAcceleratorResult<String> {
        ensure_non_empty(&self.validator_id, "pq header validator id")?;
        ensure_non_empty(&self.pq_public_key_commitment, "pq header validator key")?;
        ensure_non_empty(&self.backup_public_key_commitment, "backup validator key")?;
        ensure_non_empty(&self.encryption_key_commitment, "validator encryption key")?;
        ensure_non_empty(&self.stake_commitment_root, "validator stake root")?;
        ensure_positive(self.weight, "validator weight")?;
        Ok(self.validator_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqValidatorAttestation {
    pub attestation_id: String,
    pub validator_id: String,
    pub commitment_id: String,
    pub block_height: u64,
    pub validator_weight: u64,
    pub attested_header_root: String,
    pub aggregate_signature_root: String,
    pub transcript_root: String,
    pub attested_at_height: u64,
    pub status: HeaderCommitmentStatus,
}

impl PqValidatorAttestation {
    pub fn new(
        validator: &PqHeaderValidator,
        header: &CompactHeaderCommitment,
        attested_at_height: u64,
    ) -> Self {
        let attested_header_root = header.commitment_root();
        let aggregate_signature_root = devnet_root(
            "validator-attestation-signature",
            &format!("{}-{}", validator.validator_id, header.commitment_id),
        );
        let transcript_root = devnet_root(
            "validator-attestation-transcript",
            &format!("{}-{}", validator.validator_id, header.commitment_id),
        );
        let attestation_id = accelerator_id(
            "validator-attestation",
            &[
                HashPart::Str(&validator.validator_id),
                HashPart::Str(&header.commitment_id),
                HashPart::Str(&attested_header_root),
            ],
        );
        Self {
            attestation_id,
            validator_id: validator.validator_id.clone(),
            commitment_id: header.commitment_id.clone(),
            block_height: header.block_height,
            validator_weight: validator.weight,
            attested_header_root,
            aggregate_signature_root,
            transcript_root,
            attested_at_height,
            status: HeaderCommitmentStatus::Attested,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_validator_attestation",
            "chain_id": CHAIN_ID,
            "attestation_id": self.attestation_id,
            "validator_id": self.validator_id,
            "commitment_id": self.commitment_id,
            "block_height": self.block_height,
            "validator_weight": self.validator_weight,
            "attested_header_root": self.attested_header_root,
            "aggregate_signature_root": self.aggregate_signature_root,
            "transcript_root": self.transcript_root,
            "attested_at_height": self.attested_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn attestation_root(&self) -> String {
        accelerator_payload_root("MONERO-PQ-HCA-VALIDATOR-ATTESTATION", &self.public_record())
    }

    pub fn validate(&self) -> MoneroPqLightClientHeaderAcceleratorResult<String> {
        ensure_non_empty(&self.attestation_id, "validator attestation id")?;
        ensure_non_empty(&self.validator_id, "validator attestation validator id")?;
        ensure_non_empty(&self.commitment_id, "validator attestation commitment id")?;
        ensure_non_empty(
            &self.attested_header_root,
            "validator attestation header root",
        )?;
        ensure_non_empty(
            &self.aggregate_signature_root,
            "validator attestation signature root",
        )?;
        ensure_non_empty(
            &self.transcript_root,
            "validator attestation transcript root",
        )?;
        ensure_positive(self.block_height, "validator attestation block height")?;
        ensure_positive(self.validator_weight, "validator attestation weight")?;
        Ok(self.attestation_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReorgWindowProof {
    pub proof_id: String,
    pub canonical_commitment_id: String,
    pub competing_commitment_id: String,
    pub start_height: u64,
    pub end_height: u64,
    pub canonical_root: String,
    pub competing_root: String,
    pub window_proof_root: String,
    pub watcher_quorum_root: String,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub status: ReorgProofStatus,
}

impl ReorgWindowProof {
    pub fn new(
        canonical: &CompactHeaderCommitment,
        competing: &CompactHeaderCommitment,
        opened_at_height: u64,
        ttl_blocks: u64,
        status: ReorgProofStatus,
    ) -> Self {
        let start_height = canonical.block_height.min(competing.block_height);
        let end_height = canonical.block_height.max(competing.block_height);
        let canonical_root = canonical.commitment_root();
        let competing_root = competing.commitment_root();
        let window_proof_root = devnet_root(
            "reorg-window-proof",
            &format!("{}-{}", canonical.commitment_id, competing.commitment_id),
        );
        let watcher_quorum_root = devnet_root(
            "reorg-watcher-quorum",
            &format!("{}-{}", canonical.commitment_id, competing.commitment_id),
        );
        let proof_id = accelerator_id(
            "reorg-proof",
            &[
                HashPart::Str(&canonical.commitment_id),
                HashPart::Str(&competing.commitment_id),
                HashPart::Str(&window_proof_root),
            ],
        );
        Self {
            proof_id,
            canonical_commitment_id: canonical.commitment_id.clone(),
            competing_commitment_id: competing.commitment_id.clone(),
            start_height,
            end_height,
            canonical_root,
            competing_root,
            window_proof_root,
            watcher_quorum_root,
            opened_at_height,
            expires_at_height: opened_at_height.saturating_add(ttl_blocks),
            status,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "reorg_window_proof",
            "chain_id": CHAIN_ID,
            "proof_id": self.proof_id,
            "canonical_commitment_id": self.canonical_commitment_id,
            "competing_commitment_id": self.competing_commitment_id,
            "start_height": self.start_height,
            "end_height": self.end_height,
            "canonical_root": self.canonical_root,
            "competing_root": self.competing_root,
            "window_proof_root": self.window_proof_root,
            "watcher_quorum_root": self.watcher_quorum_root,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
            "is_open": self.status.is_open(),
        })
    }

    pub fn proof_root(&self) -> String {
        accelerator_payload_root("MONERO-PQ-HCA-REORG-PROOF", &self.public_record())
    }

    pub fn validate(
        &self,
        max_window_blocks: u64,
    ) -> MoneroPqLightClientHeaderAcceleratorResult<String> {
        ensure_non_empty(&self.proof_id, "reorg proof id")?;
        ensure_non_empty(
            &self.canonical_commitment_id,
            "reorg canonical commitment id",
        )?;
        ensure_non_empty(
            &self.competing_commitment_id,
            "reorg competing commitment id",
        )?;
        ensure_non_empty(&self.canonical_root, "reorg canonical root")?;
        ensure_non_empty(&self.competing_root, "reorg competing root")?;
        ensure_non_empty(&self.window_proof_root, "reorg window proof root")?;
        ensure_non_empty(&self.watcher_quorum_root, "reorg watcher quorum root")?;
        ensure_height_range(self.start_height, self.end_height, "reorg proof window")?;
        ensure_height_range(
            self.opened_at_height,
            self.expires_at_height,
            "reorg proof ttl",
        )?;
        if self.end_height.saturating_sub(self.start_height) > max_window_blocks {
            return Err(format!(
                "reorg proof {} exceeds configured window",
                self.proof_id
            ));
        }
        Ok(self.proof_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateBridgeSyncLane {
    pub lane_id: String,
    pub lane_kind: PrivateBridgeLaneKind,
    pub wallet_cohort_commitment: String,
    pub encrypted_header_delta_root: String,
    pub nullifier_root: String,
    pub bridge_contract_root: String,
    pub start_height: u64,
    pub target_height: u64,
    pub lane_weight: u64,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub status: BridgeLaneStatus,
}

impl PrivateBridgeSyncLane {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        lane_kind: PrivateBridgeLaneKind,
        wallet_cohort_label: &str,
        encrypted_header_delta_root: &str,
        nullifier_root: &str,
        bridge_contract_root: &str,
        start_height: u64,
        target_height: u64,
        lane_weight: u64,
        opened_at_height: u64,
        ttl_blocks: u64,
        status: BridgeLaneStatus,
    ) -> MoneroPqLightClientHeaderAcceleratorResult<Self> {
        ensure_non_empty(wallet_cohort_label, "private bridge lane wallet cohort")?;
        ensure_non_empty(
            encrypted_header_delta_root,
            "private bridge encrypted delta root",
        )?;
        ensure_non_empty(nullifier_root, "private bridge nullifier root")?;
        ensure_non_empty(bridge_contract_root, "private bridge contract root")?;
        ensure_height_range(start_height, target_height, "private bridge lane range")?;
        ensure_positive(lane_weight, "private bridge lane weight")?;
        let wallet_cohort_commitment =
            accelerator_string_root("MONERO-PQ-HCA-BRIDGE-LANE-COHORT", wallet_cohort_label);
        let lane_id = accelerator_id(
            "private-bridge-lane",
            &[
                HashPart::Str(lane_kind.as_str()),
                HashPart::Str(&wallet_cohort_commitment),
                HashPart::Int(start_height as i128),
                HashPart::Int(target_height as i128),
            ],
        );
        Ok(Self {
            lane_id,
            lane_kind,
            wallet_cohort_commitment,
            encrypted_header_delta_root: encrypted_header_delta_root.to_string(),
            nullifier_root: nullifier_root.to_string(),
            bridge_contract_root: bridge_contract_root.to_string(),
            start_height,
            target_height,
            lane_weight,
            opened_at_height,
            expires_at_height: opened_at_height.saturating_add(ttl_blocks),
            status,
        })
    }

    pub fn devnet(
        lane_kind: PrivateBridgeLaneKind,
        index: u64,
        start_height: u64,
        target_height: u64,
        opened_at_height: u64,
        ttl_blocks: u64,
    ) -> Self {
        let seed = format!("lane-{index}-{}", lane_kind.as_str());
        let wallet_cohort_commitment = accelerator_string_root(
            "MONERO-PQ-HCA-BRIDGE-LANE-COHORT",
            &format!("devnet-cohort-{index}"),
        );
        let encrypted_header_delta_root = devnet_root("private-lane-delta", &seed);
        let nullifier_root = devnet_root("private-lane-nullifier", &seed);
        let bridge_contract_root = devnet_root("private-lane-contract", &seed);
        let lane_id = accelerator_id(
            "private-bridge-lane",
            &[
                HashPart::Str(lane_kind.as_str()),
                HashPart::Str(&wallet_cohort_commitment),
                HashPart::Int(start_height as i128),
                HashPart::Int(target_height as i128),
            ],
        );
        Self {
            lane_id,
            lane_kind,
            wallet_cohort_commitment,
            encrypted_header_delta_root,
            nullifier_root,
            bridge_contract_root,
            start_height,
            target_height,
            lane_weight: index.saturating_add(1),
            opened_at_height,
            expires_at_height: opened_at_height.saturating_add(ttl_blocks),
            status: BridgeLaneStatus::Subsidized,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_bridge_sync_lane",
            "chain_id": CHAIN_ID,
            "lane_id": self.lane_id,
            "lane_kind": self.lane_kind.as_str(),
            "wallet_cohort_commitment": self.wallet_cohort_commitment,
            "encrypted_header_delta_root": self.encrypted_header_delta_root,
            "nullifier_root": self.nullifier_root,
            "bridge_contract_root": self.bridge_contract_root,
            "start_height": self.start_height,
            "target_height": self.target_height,
            "lane_weight": self.lane_weight,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
            "active": self.status.active(),
            "privacy_critical": self.lane_kind.privacy_critical(),
        })
    }

    pub fn lane_root(&self) -> String {
        accelerator_payload_root("MONERO-PQ-HCA-PRIVATE-BRIDGE-LANE", &self.public_record())
    }

    pub fn validate(&self) -> MoneroPqLightClientHeaderAcceleratorResult<String> {
        ensure_non_empty(&self.lane_id, "private bridge lane id")?;
        ensure_non_empty(
            &self.wallet_cohort_commitment,
            "private bridge cohort commitment",
        )?;
        ensure_non_empty(
            &self.encrypted_header_delta_root,
            "private bridge encrypted delta root",
        )?;
        ensure_non_empty(&self.nullifier_root, "private bridge nullifier root")?;
        ensure_non_empty(&self.bridge_contract_root, "private bridge contract root")?;
        ensure_height_range(
            self.start_height,
            self.target_height,
            "private bridge lane range",
        )?;
        ensure_height_range(
            self.opened_at_height,
            self.expires_at_height,
            "private bridge lane ttl",
        )?;
        ensure_positive(self.lane_weight, "private bridge lane weight")?;
        Ok(self.lane_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeCheckpointSubsidy {
    pub subsidy_id: String,
    pub sponsor_id: String,
    pub commitment_id: String,
    pub lane_id: String,
    pub fee_asset_id: String,
    pub reserved_fee_units: u64,
    pub consumed_fee_units: u64,
    pub proof_credit_root: String,
    pub privacy_nullifier_root: String,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub status: SubsidyStatus,
}

impl LowFeeCheckpointSubsidy {
    pub fn new(
        sponsor_id: &str,
        header: &CompactHeaderCommitment,
        lane: &PrivateBridgeSyncLane,
        fee_asset_id: &str,
        opened_at_height: u64,
        ttl_blocks: u64,
        reserved_fee_units: u64,
    ) -> Self {
        let proof_credit_root = devnet_root(
            "checkpoint-subsidy-credit",
            &format!("{}-{sponsor_id}", header.commitment_id),
        );
        let privacy_nullifier_root = devnet_root(
            "checkpoint-subsidy-nullifier",
            &format!("{}-{sponsor_id}", lane.lane_id),
        );
        let subsidy_id = accelerator_id(
            "checkpoint-subsidy",
            &[
                HashPart::Str(sponsor_id),
                HashPart::Str(&header.commitment_id),
                HashPart::Str(&lane.lane_id),
                HashPart::Str(&proof_credit_root),
            ],
        );
        Self {
            subsidy_id,
            sponsor_id: sponsor_id.to_string(),
            commitment_id: header.commitment_id.clone(),
            lane_id: lane.lane_id.clone(),
            fee_asset_id: fee_asset_id.to_string(),
            reserved_fee_units,
            consumed_fee_units: reserved_fee_units,
            proof_credit_root,
            privacy_nullifier_root,
            opened_at_height,
            expires_at_height: opened_at_height.saturating_add(ttl_blocks),
            status: SubsidyStatus::Consumed,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "low_fee_checkpoint_subsidy",
            "chain_id": CHAIN_ID,
            "subsidy_id": self.subsidy_id,
            "sponsor_id": self.sponsor_id,
            "commitment_id": self.commitment_id,
            "lane_id": self.lane_id,
            "fee_asset_id": self.fee_asset_id,
            "reserved_fee_units": self.reserved_fee_units,
            "consumed_fee_units": self.consumed_fee_units,
            "proof_credit_root": self.proof_credit_root,
            "privacy_nullifier_root": self.privacy_nullifier_root,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
            "live": self.status.live(),
        })
    }

    pub fn subsidy_root(&self) -> String {
        accelerator_payload_root("MONERO-PQ-HCA-CHECKPOINT-SUBSIDY", &self.public_record())
    }

    pub fn validate(
        &self,
        budget_units: u64,
    ) -> MoneroPqLightClientHeaderAcceleratorResult<String> {
        ensure_non_empty(&self.subsidy_id, "checkpoint subsidy id")?;
        ensure_non_empty(&self.sponsor_id, "checkpoint subsidy sponsor id")?;
        ensure_non_empty(&self.commitment_id, "checkpoint subsidy commitment id")?;
        ensure_non_empty(&self.lane_id, "checkpoint subsidy lane id")?;
        ensure_non_empty(&self.fee_asset_id, "checkpoint subsidy fee asset id")?;
        ensure_non_empty(&self.proof_credit_root, "checkpoint subsidy credit root")?;
        ensure_non_empty(
            &self.privacy_nullifier_root,
            "checkpoint subsidy nullifier root",
        )?;
        ensure_height_range(
            self.opened_at_height,
            self.expires_at_height,
            "checkpoint subsidy ttl",
        )?;
        if self.reserved_fee_units > budget_units {
            return Err(format!(
                "checkpoint subsidy {} exceeds budget",
                self.subsidy_id
            ));
        }
        if self.consumed_fee_units > self.reserved_fee_units {
            return Err(format!(
                "checkpoint subsidy {} over-consumed",
                self.subsidy_id
            ));
        }
        Ok(self.subsidy_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedWatcherReport {
    pub report_id: String,
    pub watcher_id: String,
    pub report_kind: WatcherReportKind,
    pub commitment_id: String,
    pub encrypted_report_root: String,
    pub report_ciphertext_root: String,
    pub disclosure_nullifier_root: String,
    pub watcher_signature_root: String,
    pub observed_at_height: u64,
    pub expires_at_height: u64,
    pub status: WatcherReportStatus,
}

impl EncryptedWatcherReport {
    pub fn new(
        watcher_id: &str,
        report_kind: WatcherReportKind,
        header: &CompactHeaderCommitment,
        observed_at_height: u64,
        ttl_blocks: u64,
    ) -> Self {
        let seed = format!(
            "{watcher_id}-{}-{}",
            report_kind.as_str(),
            header.commitment_id
        );
        let encrypted_report_root = devnet_root("encrypted-watcher-report", &seed);
        let report_ciphertext_root = devnet_root("watcher-report-ciphertext", &seed);
        let disclosure_nullifier_root = devnet_root("watcher-report-nullifier", &seed);
        let watcher_signature_root = devnet_root("watcher-report-signature", &seed);
        let report_id = accelerator_id(
            "watcher-report",
            &[
                HashPart::Str(watcher_id),
                HashPart::Str(report_kind.as_str()),
                HashPart::Str(&header.commitment_id),
                HashPart::Str(&encrypted_report_root),
            ],
        );
        Self {
            report_id,
            watcher_id: watcher_id.to_string(),
            report_kind,
            commitment_id: header.commitment_id.clone(),
            encrypted_report_root,
            report_ciphertext_root,
            disclosure_nullifier_root,
            watcher_signature_root,
            observed_at_height,
            expires_at_height: observed_at_height.saturating_add(ttl_blocks),
            status: WatcherReportStatus::Submitted,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "encrypted_watcher_report",
            "chain_id": CHAIN_ID,
            "report_id": self.report_id,
            "watcher_id": self.watcher_id,
            "report_kind": self.report_kind.as_str(),
            "commitment_id": self.commitment_id,
            "encrypted_report_root": self.encrypted_report_root,
            "report_ciphertext_root": self.report_ciphertext_root,
            "disclosure_nullifier_root": self.disclosure_nullifier_root,
            "watcher_signature_root": self.watcher_signature_root,
            "observed_at_height": self.observed_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
            "counts_for_quorum": self.status.counts_for_quorum(),
        })
    }

    pub fn report_root(&self) -> String {
        accelerator_payload_root(
            "MONERO-PQ-HCA-ENCRYPTED-WATCHER-REPORT",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> MoneroPqLightClientHeaderAcceleratorResult<String> {
        ensure_non_empty(&self.report_id, "encrypted watcher report id")?;
        ensure_non_empty(&self.watcher_id, "encrypted watcher report watcher id")?;
        ensure_non_empty(
            &self.commitment_id,
            "encrypted watcher report commitment id",
        )?;
        ensure_non_empty(&self.encrypted_report_root, "encrypted watcher report root")?;
        ensure_non_empty(
            &self.report_ciphertext_root,
            "watcher report ciphertext root",
        )?;
        ensure_non_empty(
            &self.disclosure_nullifier_root,
            "watcher report nullifier root",
        )?;
        ensure_non_empty(
            &self.watcher_signature_root,
            "watcher report signature root",
        )?;
        ensure_height_range(
            self.observed_at_height,
            self.expires_at_height,
            "watcher report ttl",
        )?;
        Ok(self.report_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchVerificationReceipt {
    pub receipt_id: String,
    pub start_height: u64,
    pub end_height: u64,
    pub header_count: u64,
    pub header_root: String,
    pub attestation_root: String,
    pub validator_bitmap_root: String,
    pub aggregate_signature_root: String,
    pub verification_transcript_root: String,
    pub receipt_fee_units: u64,
    pub verified_at_height: u64,
    pub status: BatchReceiptStatus,
}

impl BatchVerificationReceipt {
    pub fn new(
        headers: &[CompactHeaderCommitment],
        attestations: &[PqValidatorAttestation],
        verified_at_height: u64,
        receipt_fee_units: u64,
        status: BatchReceiptStatus,
    ) -> MoneroPqLightClientHeaderAcceleratorResult<Self> {
        if headers.is_empty() {
            return Err("batch receipt requires at least one header".to_string());
        }
        let first = headers
            .first()
            .ok_or_else(|| "batch receipt missing first header".to_string())?;
        let last = headers
            .last()
            .ok_or_else(|| "batch receipt missing last header".to_string())?;
        let header_leaves = headers
            .iter()
            .map(CompactHeaderCommitment::public_record)
            .collect::<Vec<_>>();
        let attestation_leaves = attestations
            .iter()
            .map(PqValidatorAttestation::public_record)
            .collect::<Vec<_>>();
        let header_root = accelerator_merkle_root("MONERO-PQ-HCA-BATCH-HEADERS", &header_leaves);
        let attestation_root =
            accelerator_merkle_root("MONERO-PQ-HCA-BATCH-ATTESTATIONS", &attestation_leaves);
        let validator_bitmap_root = devnet_root(
            "batch-validator-bitmap",
            &format!("{}-{}", first.block_height, last.block_height),
        );
        let aggregate_signature_root = devnet_root("batch-aggregate-signature", &header_root);
        let verification_transcript_root =
            devnet_root("batch-verification-transcript", &attestation_root);
        let receipt_id = accelerator_id(
            "batch-receipt",
            &[
                HashPart::Int(first.block_height as i128),
                HashPart::Int(last.block_height as i128),
                HashPart::Str(&header_root),
                HashPart::Str(&attestation_root),
            ],
        );
        Ok(Self {
            receipt_id,
            start_height: first.block_height,
            end_height: last.block_height,
            header_count: headers.len() as u64,
            header_root,
            attestation_root,
            validator_bitmap_root,
            aggregate_signature_root,
            verification_transcript_root,
            receipt_fee_units,
            verified_at_height,
            status,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "batch_verification_receipt",
            "chain_id": CHAIN_ID,
            "receipt_id": self.receipt_id,
            "start_height": self.start_height,
            "end_height": self.end_height,
            "header_count": self.header_count,
            "header_root": self.header_root,
            "attestation_root": self.attestation_root,
            "validator_bitmap_root": self.validator_bitmap_root,
            "aggregate_signature_root": self.aggregate_signature_root,
            "verification_transcript_root": self.verification_transcript_root,
            "receipt_fee_units": self.receipt_fee_units,
            "verified_at_height": self.verified_at_height,
            "status": self.status.as_str(),
            "verified": self.status.verified(),
        })
    }

    pub fn receipt_root(&self) -> String {
        accelerator_payload_root("MONERO-PQ-HCA-BATCH-RECEIPT", &self.public_record())
    }

    pub fn validate(&self, max_headers: u64) -> MoneroPqLightClientHeaderAcceleratorResult<String> {
        ensure_non_empty(&self.receipt_id, "batch receipt id")?;
        ensure_non_empty(&self.header_root, "batch receipt header root")?;
        ensure_non_empty(&self.attestation_root, "batch receipt attestation root")?;
        ensure_non_empty(
            &self.validator_bitmap_root,
            "batch receipt validator bitmap root",
        )?;
        ensure_non_empty(
            &self.aggregate_signature_root,
            "batch receipt signature root",
        )?;
        ensure_non_empty(
            &self.verification_transcript_root,
            "batch receipt transcript root",
        )?;
        ensure_height_range(self.start_height, self.end_height, "batch receipt range")?;
        ensure_positive(self.header_count, "batch receipt header count")?;
        if self.header_count > max_headers {
            return Err(format!(
                "batch receipt {} exceeds max header count",
                self.receipt_id
            ));
        }
        Ok(self.receipt_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlashingHandoffEvidence {
    pub evidence_id: String,
    pub offender_validator_id: String,
    pub evidence_kind: SlashingEvidenceKind,
    pub related_commitment_id: String,
    pub evidence_root: String,
    pub watcher_report_root: String,
    pub destination_chain: String,
    pub handoff_packet_root: String,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub status: SlashingHandoffStatus,
}

impl SlashingHandoffEvidence {
    pub fn new(
        offender_validator_id: &str,
        evidence_kind: SlashingEvidenceKind,
        related_commitment_id: &str,
        watcher_report_root: &str,
        destination_chain: &str,
        opened_at_height: u64,
        ttl_blocks: u64,
    ) -> Self {
        let seed = format!(
            "{offender_validator_id}-{}-{related_commitment_id}",
            evidence_kind.as_str()
        );
        let evidence_root = devnet_root("slashing-evidence", &seed);
        let handoff_packet_root = devnet_root("slashing-handoff-packet", &seed);
        let evidence_id = accelerator_id(
            "slashing-handoff",
            &[
                HashPart::Str(offender_validator_id),
                HashPart::Str(evidence_kind.as_str()),
                HashPart::Str(related_commitment_id),
                HashPart::Str(&evidence_root),
            ],
        );
        Self {
            evidence_id,
            offender_validator_id: offender_validator_id.to_string(),
            evidence_kind,
            related_commitment_id: related_commitment_id.to_string(),
            evidence_root,
            watcher_report_root: watcher_report_root.to_string(),
            destination_chain: destination_chain.to_string(),
            handoff_packet_root,
            opened_at_height,
            expires_at_height: opened_at_height.saturating_add(ttl_blocks),
            status: SlashingHandoffStatus::Submitted,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "slashing_handoff_evidence",
            "chain_id": CHAIN_ID,
            "evidence_id": self.evidence_id,
            "offender_validator_id": self.offender_validator_id,
            "evidence_kind": self.evidence_kind.as_str(),
            "related_commitment_id": self.related_commitment_id,
            "evidence_root": self.evidence_root,
            "watcher_report_root": self.watcher_report_root,
            "destination_chain": self.destination_chain,
            "handoff_packet_root": self.handoff_packet_root,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn handoff_root(&self) -> String {
        accelerator_payload_root("MONERO-PQ-HCA-SLASHING-HANDOFF", &self.public_record())
    }

    pub fn validate(&self) -> MoneroPqLightClientHeaderAcceleratorResult<String> {
        ensure_non_empty(&self.evidence_id, "slashing evidence id")?;
        ensure_non_empty(
            &self.offender_validator_id,
            "slashing offender validator id",
        )?;
        ensure_non_empty(
            &self.related_commitment_id,
            "slashing related commitment id",
        )?;
        ensure_non_empty(&self.evidence_root, "slashing evidence root")?;
        ensure_non_empty(&self.watcher_report_root, "slashing watcher report root")?;
        ensure_non_empty(&self.destination_chain, "slashing destination chain")?;
        ensure_non_empty(&self.handoff_packet_root, "slashing handoff packet root")?;
        ensure_height_range(
            self.opened_at_height,
            self.expires_at_height,
            "slashing handoff ttl",
        )?;
        Ok(self.handoff_root())
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroPqHeaderAcceleratorCounters {
    pub validators: u64,
    pub active_validators: u64,
    pub header_commitments: u64,
    pub finalized_headers: u64,
    pub validator_attestations: u64,
    pub reorg_proofs: u64,
    pub open_reorg_proofs: u64,
    pub private_lanes: u64,
    pub active_private_lanes: u64,
    pub checkpoint_subsidies: u64,
    pub live_subsidies: u64,
    pub encrypted_watcher_reports: u64,
    pub quorum_watcher_reports: u64,
    pub batch_receipts: u64,
    pub verified_batch_receipts: u64,
    pub slashing_handoffs: u64,
    pub subsidy_units_reserved: u64,
    pub subsidy_units_consumed: u64,
    pub validator_weight: u64,
    pub attested_weight: u64,
}

impl MoneroPqHeaderAcceleratorCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_pq_header_accelerator_counters",
            "chain_id": CHAIN_ID,
            "validators": self.validators,
            "active_validators": self.active_validators,
            "header_commitments": self.header_commitments,
            "finalized_headers": self.finalized_headers,
            "validator_attestations": self.validator_attestations,
            "reorg_proofs": self.reorg_proofs,
            "open_reorg_proofs": self.open_reorg_proofs,
            "private_lanes": self.private_lanes,
            "active_private_lanes": self.active_private_lanes,
            "checkpoint_subsidies": self.checkpoint_subsidies,
            "live_subsidies": self.live_subsidies,
            "encrypted_watcher_reports": self.encrypted_watcher_reports,
            "quorum_watcher_reports": self.quorum_watcher_reports,
            "batch_receipts": self.batch_receipts,
            "verified_batch_receipts": self.verified_batch_receipts,
            "slashing_handoffs": self.slashing_handoffs,
            "subsidy_units_reserved": self.subsidy_units_reserved,
            "subsidy_units_consumed": self.subsidy_units_consumed,
            "validator_weight": self.validator_weight,
            "attested_weight": self.attested_weight,
        })
    }

    pub fn counters_root(&self) -> String {
        accelerator_payload_root("MONERO-PQ-HCA-COUNTERS", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroPqHeaderAcceleratorRoots {
    pub config_root: String,
    pub validator_root: String,
    pub header_commitment_root: String,
    pub attestation_root: String,
    pub reorg_proof_root: String,
    pub private_lane_root: String,
    pub subsidy_root: String,
    pub watcher_report_root: String,
    pub batch_receipt_root: String,
    pub slashing_handoff_root: String,
    pub counters_root: String,
    pub state_root: String,
}

impl MoneroPqHeaderAcceleratorRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_pq_header_accelerator_roots",
            "chain_id": CHAIN_ID,
            "config_root": self.config_root,
            "validator_root": self.validator_root,
            "header_commitment_root": self.header_commitment_root,
            "attestation_root": self.attestation_root,
            "reorg_proof_root": self.reorg_proof_root,
            "private_lane_root": self.private_lane_root,
            "subsidy_root": self.subsidy_root,
            "watcher_report_root": self.watcher_report_root,
            "batch_receipt_root": self.batch_receipt_root,
            "slashing_handoff_root": self.slashing_handoff_root,
            "counters_root": self.counters_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroPqHeaderAcceleratorState {
    pub config: MoneroPqHeaderAcceleratorConfig,
    pub current_l2_height: u64,
    pub last_monero_height: u64,
    pub safe_checkpoint_height: u64,
    pub latest_finalized_commitment_id: String,
    pub validators: BTreeMap<String, PqHeaderValidator>,
    pub header_commitments: BTreeMap<String, CompactHeaderCommitment>,
    pub validator_attestations: BTreeMap<String, PqValidatorAttestation>,
    pub reorg_proofs: BTreeMap<String, ReorgWindowProof>,
    pub private_lanes: BTreeMap<String, PrivateBridgeSyncLane>,
    pub checkpoint_subsidies: BTreeMap<String, LowFeeCheckpointSubsidy>,
    pub encrypted_watcher_reports: BTreeMap<String, EncryptedWatcherReport>,
    pub batch_receipts: BTreeMap<String, BatchVerificationReceipt>,
    pub slashing_handoffs: BTreeMap<String, SlashingHandoffEvidence>,
}

impl MoneroPqHeaderAcceleratorState {
    pub fn new(
        config: MoneroPqHeaderAcceleratorConfig,
        current_l2_height: u64,
        last_monero_height: u64,
    ) -> Self {
        Self {
            config,
            current_l2_height,
            last_monero_height,
            safe_checkpoint_height: 0,
            latest_finalized_commitment_id: String::new(),
            validators: BTreeMap::new(),
            header_commitments: BTreeMap::new(),
            validator_attestations: BTreeMap::new(),
            reorg_proofs: BTreeMap::new(),
            private_lanes: BTreeMap::new(),
            checkpoint_subsidies: BTreeMap::new(),
            encrypted_watcher_reports: BTreeMap::new(),
            batch_receipts: BTreeMap::new(),
            slashing_handoffs: BTreeMap::new(),
        }
    }

    pub fn devnet() -> MoneroPqLightClientHeaderAcceleratorResult<Self> {
        let config = MoneroPqHeaderAcceleratorConfig::devnet();
        let mut state = Self::new(
            config.clone(),
            MONERO_PQ_LIGHT_CLIENT_HEADER_ACCELERATOR_DEVNET_HEIGHT,
            90_000,
        );
        let producer = PqHeaderValidator::devnet(
            0,
            PqHeaderValidatorRole::HeaderProducer,
            40,
            state.current_l2_height,
        );
        let bridge = PqHeaderValidator::devnet(
            1,
            PqHeaderValidatorRole::BridgeValidator,
            35,
            state.current_l2_height,
        );
        let watcher = PqHeaderValidator::devnet(
            2,
            PqHeaderValidatorRole::Watcher,
            20,
            state.current_l2_height,
        );
        let sponsor = PqHeaderValidator::devnet(
            3,
            PqHeaderValidatorRole::SubsidySponsor,
            10,
            state.current_l2_height,
        );
        state
            .validators
            .insert(producer.validator_id.clone(), producer.clone());
        state
            .validators
            .insert(bridge.validator_id.clone(), bridge.clone());
        state
            .validators
            .insert(watcher.validator_id.clone(), watcher.clone());
        state
            .validators
            .insert(sponsor.validator_id.clone(), sponsor);

        let base_height = state.last_monero_height;
        for offset in 0..4 {
            let status = if offset < 3 {
                HeaderCommitmentStatus::Finalized
            } else {
                HeaderCommitmentStatus::Attested
            };
            let header = CompactHeaderCommitment::devnet(
                base_height.saturating_add(offset),
                state.current_l2_height,
                status,
            );
            let attestation_a =
                PqValidatorAttestation::new(&producer, &header, state.current_l2_height);
            let attestation_b =
                PqValidatorAttestation::new(&bridge, &header, state.current_l2_height);
            state
                .validator_attestations
                .insert(attestation_a.attestation_id.clone(), attestation_a);
            state
                .validator_attestations
                .insert(attestation_b.attestation_id.clone(), attestation_b);
            if status == HeaderCommitmentStatus::Finalized {
                state.safe_checkpoint_height = header.block_height;
                state.latest_finalized_commitment_id = header.commitment_id.clone();
            }
            state
                .header_commitments
                .insert(header.commitment_id.clone(), header);
        }

        let finalized = state
            .header_commitments
            .values()
            .filter(|header| header.status == HeaderCommitmentStatus::Finalized)
            .cloned()
            .collect::<Vec<_>>();
        let attestations = state
            .validator_attestations
            .values()
            .cloned()
            .collect::<Vec<_>>();
        let receipt = BatchVerificationReceipt::new(
            &finalized,
            &attestations,
            state.current_l2_height,
            config
                .subsidy_unit_price
                .saturating_mul(finalized.len() as u64),
            BatchReceiptStatus::Finalized,
        )?;
        state
            .batch_receipts
            .insert(receipt.receipt_id.clone(), receipt);

        let lane = PrivateBridgeSyncLane::devnet(
            PrivateBridgeLaneKind::DepositSync,
            0,
            base_height,
            base_height.saturating_add(config.header_batch_size),
            state.current_l2_height,
            config.private_lane_ttl_blocks,
        );
        let subsidy_header = state
            .header_commitments
            .values()
            .next()
            .cloned()
            .ok_or_else(|| "devnet header accelerator missing header".to_string())?;
        let subsidy = LowFeeCheckpointSubsidy::new(
            "devnet-sponsor",
            &subsidy_header,
            &lane,
            &config.fee_asset_id,
            state.current_l2_height,
            config.private_lane_ttl_blocks,
            config.subsidy_unit_price,
        );
        let report = EncryptedWatcherReport::new(
            &watcher.validator_id,
            WatcherReportKind::ReorgObserved,
            &subsidy_header,
            state.current_l2_height,
            config.report_ttl_blocks,
        );
        let slashing = SlashingHandoffEvidence::new(
            &bridge.validator_id,
            SlashingEvidenceKind::InvalidHeaderRoot,
            &subsidy_header.commitment_id,
            &report.report_root(),
            CHAIN_ID,
            state.current_l2_height,
            config.slashing_ttl_blocks,
        );
        state.private_lanes.insert(lane.lane_id.clone(), lane);
        state
            .checkpoint_subsidies
            .insert(subsidy.subsidy_id.clone(), subsidy);
        state
            .encrypted_watcher_reports
            .insert(report.report_id.clone(), report);
        state
            .slashing_handoffs
            .insert(slashing.evidence_id.clone(), slashing);

        let mut headers = state
            .header_commitments
            .values()
            .cloned()
            .collect::<Vec<_>>();
        headers.sort_by_key(|header| header.block_height);
        if headers.len() >= 2 {
            let canonical = headers[headers.len() - 2].clone();
            let competing = CompactHeaderCommitment::devnet(
                canonical.block_height,
                state.current_l2_height,
                HeaderCommitmentStatus::Reorged,
            );
            let reorg = ReorgWindowProof::new(
                &canonical,
                &competing,
                state.current_l2_height,
                config.reorg_window_blocks,
                ReorgProofStatus::Watching,
            );
            state.reorg_proofs.insert(reorg.proof_id.clone(), reorg);
        }
        state.validate()?;
        Ok(state)
    }

    pub fn update_height(
        &mut self,
        new_l2_height: u64,
        new_monero_height: u64,
    ) -> MoneroPqLightClientHeaderAcceleratorResult<()> {
        if new_l2_height < self.current_l2_height {
            return Err(format!(
                "l2 height cannot move backward from {} to {}",
                self.current_l2_height, new_l2_height
            ));
        }
        if new_monero_height < self.last_monero_height {
            return Err(format!(
                "monero height cannot move backward from {} to {}",
                self.last_monero_height, new_monero_height
            ));
        }
        self.current_l2_height = new_l2_height;
        self.last_monero_height = new_monero_height;
        Ok(())
    }

    pub fn add_header_commitment(
        &mut self,
        header: CompactHeaderCommitment,
    ) -> MoneroPqLightClientHeaderAcceleratorResult<String> {
        let root = header.validate()?;
        if header.block_height > self.last_monero_height {
            self.last_monero_height = header.block_height;
        }
        if header.status == HeaderCommitmentStatus::Finalized {
            self.safe_checkpoint_height = self.safe_checkpoint_height.max(header.block_height);
            self.latest_finalized_commitment_id = header.commitment_id.clone();
        }
        self.header_commitments
            .insert(header.commitment_id.clone(), header);
        Ok(root)
    }

    pub fn counters(&self) -> MoneroPqHeaderAcceleratorCounters {
        let validator_weight = self
            .validators
            .values()
            .map(|validator| validator.weight)
            .sum();
        let attested_weight = self
            .validator_attestations
            .values()
            .map(|attestation| attestation.validator_weight)
            .sum();
        MoneroPqHeaderAcceleratorCounters {
            validators: self.validators.len() as u64,
            active_validators: self
                .validators
                .values()
                .filter(|validator| validator.status.can_attest())
                .count() as u64,
            header_commitments: self.header_commitments.len() as u64,
            finalized_headers: self
                .header_commitments
                .values()
                .filter(|header| header.status == HeaderCommitmentStatus::Finalized)
                .count() as u64,
            validator_attestations: self.validator_attestations.len() as u64,
            reorg_proofs: self.reorg_proofs.len() as u64,
            open_reorg_proofs: self
                .reorg_proofs
                .values()
                .filter(|proof| proof.status.is_open())
                .count() as u64,
            private_lanes: self.private_lanes.len() as u64,
            active_private_lanes: self
                .private_lanes
                .values()
                .filter(|lane| lane.status.active())
                .count() as u64,
            checkpoint_subsidies: self.checkpoint_subsidies.len() as u64,
            live_subsidies: self
                .checkpoint_subsidies
                .values()
                .filter(|subsidy| subsidy.status.live())
                .count() as u64,
            encrypted_watcher_reports: self.encrypted_watcher_reports.len() as u64,
            quorum_watcher_reports: self
                .encrypted_watcher_reports
                .values()
                .filter(|report| report.status.counts_for_quorum())
                .count() as u64,
            batch_receipts: self.batch_receipts.len() as u64,
            verified_batch_receipts: self
                .batch_receipts
                .values()
                .filter(|receipt| receipt.status.verified())
                .count() as u64,
            slashing_handoffs: self.slashing_handoffs.len() as u64,
            subsidy_units_reserved: self
                .checkpoint_subsidies
                .values()
                .map(|subsidy| subsidy.reserved_fee_units)
                .sum(),
            subsidy_units_consumed: self
                .checkpoint_subsidies
                .values()
                .map(|subsidy| subsidy.consumed_fee_units)
                .sum(),
            validator_weight,
            attested_weight,
        }
    }

    pub fn roots(&self) -> MoneroPqHeaderAcceleratorRoots {
        let counters = self.counters();
        let config_root = self.config.config_root();
        let validator_root = map_root(
            "MONERO-PQ-HCA-VALIDATORS",
            self.validators
                .values()
                .map(PqHeaderValidator::public_record),
        );
        let header_commitment_root = map_root(
            "MONERO-PQ-HCA-HEADERS",
            self.header_commitments
                .values()
                .map(CompactHeaderCommitment::public_record),
        );
        let attestation_root = map_root(
            "MONERO-PQ-HCA-ATTESTATIONS",
            self.validator_attestations
                .values()
                .map(PqValidatorAttestation::public_record),
        );
        let reorg_proof_root = map_root(
            "MONERO-PQ-HCA-REORG-PROOFS",
            self.reorg_proofs
                .values()
                .map(ReorgWindowProof::public_record),
        );
        let private_lane_root = map_root(
            "MONERO-PQ-HCA-PRIVATE-LANES",
            self.private_lanes
                .values()
                .map(PrivateBridgeSyncLane::public_record),
        );
        let subsidy_root = map_root(
            "MONERO-PQ-HCA-SUBSIDIES",
            self.checkpoint_subsidies
                .values()
                .map(LowFeeCheckpointSubsidy::public_record),
        );
        let watcher_report_root = map_root(
            "MONERO-PQ-HCA-WATCHER-REPORTS",
            self.encrypted_watcher_reports
                .values()
                .map(EncryptedWatcherReport::public_record),
        );
        let batch_receipt_root = map_root(
            "MONERO-PQ-HCA-BATCH-RECEIPTS",
            self.batch_receipts
                .values()
                .map(BatchVerificationReceipt::public_record),
        );
        let slashing_handoff_root = map_root(
            "MONERO-PQ-HCA-SLASHING-HANDOFFS",
            self.slashing_handoffs
                .values()
                .map(SlashingHandoffEvidence::public_record),
        );
        let counters_root = counters.counters_root();
        let root_payload = json!({
            "chain_id": CHAIN_ID,
            "protocol_version": self.config.protocol_version,
            "current_l2_height": self.current_l2_height,
            "last_monero_height": self.last_monero_height,
            "safe_checkpoint_height": self.safe_checkpoint_height,
            "latest_finalized_commitment_id": self.latest_finalized_commitment_id,
            "config_root": config_root,
            "validator_root": validator_root,
            "header_commitment_root": header_commitment_root,
            "attestation_root": attestation_root,
            "reorg_proof_root": reorg_proof_root,
            "private_lane_root": private_lane_root,
            "subsidy_root": subsidy_root,
            "watcher_report_root": watcher_report_root,
            "batch_receipt_root": batch_receipt_root,
            "slashing_handoff_root": slashing_handoff_root,
            "counters_root": counters_root,
        });
        let state_root = accelerator_payload_root("MONERO-PQ-HCA-STATE", &root_payload);
        MoneroPqHeaderAcceleratorRoots {
            config_root,
            validator_root,
            header_commitment_root,
            attestation_root,
            reorg_proof_root,
            private_lane_root,
            subsidy_root,
            watcher_report_root,
            batch_receipt_root,
            slashing_handoff_root,
            counters_root,
            state_root,
        }
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        json!({
            "kind": "monero_pq_light_client_header_accelerator_state",
            "chain_id": CHAIN_ID,
            "protocol_version": self.config.protocol_version,
            "schema_version": self.config.schema_version,
            "current_l2_height": self.current_l2_height,
            "last_monero_height": self.last_monero_height,
            "safe_checkpoint_height": self.safe_checkpoint_height,
            "latest_finalized_commitment_id": self.latest_finalized_commitment_id,
            "roots": roots.public_record(),
            "counters": self.counters().public_record(),
        })
    }

    pub fn state_root(&self) -> String {
        self.roots().state_root
    }

    pub fn validate(&self) -> MoneroPqLightClientHeaderAcceleratorResult<String> {
        self.config.validate()?;
        ensure_positive(self.current_l2_height, "header accelerator l2 height")?;
        ensure_positive(self.last_monero_height, "header accelerator monero height")?;
        let mut heights = BTreeSet::new();
        for validator in self.validators.values() {
            validator.validate()?;
        }
        for header in self.header_commitments.values() {
            header.validate()?;
            if !heights.insert(header.block_height)
                && header.status != HeaderCommitmentStatus::Reorged
            {
                return Err(format!(
                    "duplicate non-reorg header at height {}",
                    header.block_height
                ));
            }
        }
        for attestation in self.validator_attestations.values() {
            attestation.validate()?;
            if !self.validators.contains_key(&attestation.validator_id) {
                return Err(format!(
                    "attestation {} references unknown validator",
                    attestation.attestation_id
                ));
            }
            if !self
                .header_commitments
                .contains_key(&attestation.commitment_id)
            {
                return Err(format!(
                    "attestation {} references unknown header",
                    attestation.attestation_id
                ));
            }
        }
        for proof in self.reorg_proofs.values() {
            proof.validate(self.config.reorg_window_blocks)?;
        }
        for lane in self.private_lanes.values() {
            lane.validate()?;
        }
        for subsidy in self.checkpoint_subsidies.values() {
            subsidy.validate(self.config.low_fee_subsidy_budget)?;
        }
        for report in self.encrypted_watcher_reports.values() {
            report.validate()?;
        }
        for receipt in self.batch_receipts.values() {
            receipt.validate(self.config.max_headers_per_receipt)?;
        }
        for evidence in self.slashing_handoffs.values() {
            evidence.validate()?;
        }
        if !self.latest_finalized_commitment_id.is_empty()
            && !self
                .header_commitments
                .contains_key(&self.latest_finalized_commitment_id)
        {
            return Err("latest finalized commitment id is not known".to_string());
        }
        Ok(self.state_root())
    }
}

fn ensure_non_empty(value: &str, label: &str) -> MoneroPqLightClientHeaderAcceleratorResult<()> {
    if value.trim().is_empty() {
        Err(format!("{label} must not be empty"))
    } else {
        Ok(())
    }
}

fn ensure_positive(value: u64, label: &str) -> MoneroPqLightClientHeaderAcceleratorResult<()> {
    if value == 0 {
        Err(format!("{label} must be positive"))
    } else {
        Ok(())
    }
}

fn ensure_height_range(
    start: u64,
    end: u64,
    label: &str,
) -> MoneroPqLightClientHeaderAcceleratorResult<()> {
    if end < start {
        Err(format!("{label} end height cannot be below start height"))
    } else {
        Ok(())
    }
}

fn accelerator_string_root(domain: &str, value: &str) -> String {
    domain_hash(domain, &[HashPart::Str(value)], 32)
}

fn accelerator_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(domain, &[HashPart::Json(payload)], 32)
}

fn accelerator_id(domain: &str, parts: &[HashPart<'_>]) -> String {
    domain_hash(&format!("MONERO-PQ-HCA-ID-{domain}"), parts, 20)
}

fn accelerator_merkle_root(domain: &str, leaves: &[Value]) -> String {
    merkle_root(domain, leaves)
}

fn map_root<I>(domain: &str, records: I) -> String
where
    I: IntoIterator<Item = Value>,
{
    let leaves = records.into_iter().collect::<Vec<_>>();
    accelerator_merkle_root(domain, &leaves)
}

fn devnet_root(domain: &str, seed: &str) -> String {
    domain_hash(
        &format!("MONERO-PQ-HCA-DEVNET-{domain}"),
        &[
            HashPart::Str(MONERO_PQ_LIGHT_CLIENT_HEADER_ACCELERATOR_PROTOCOL_VERSION),
            HashPart::Str(seed),
        ],
        32,
    )
}
