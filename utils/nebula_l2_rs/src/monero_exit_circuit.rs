use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type MoneroExitCircuitResult<T> = Result<T, String>;
pub type MoneroExitResult<T> = MoneroExitCircuitResult<T>;

pub const PROTOCOL_VERSION: &str = "nebula-monero-exit-circuit-v1";
pub const MONERO_EXIT_CIRCUIT_PROTOCOL_VERSION: &str = PROTOCOL_VERSION;
pub const MONERO_EXIT_CIRCUIT_SCHEMA_VERSION: u64 = 1;
pub const MONERO_EXIT_DEVNET_HEIGHT: u64 = 144;
pub const MONERO_EXIT_DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const MONERO_EXIT_DEVNET_ASSET_ID: &str = "wxmr-devnet";
pub const MONERO_EXIT_DEVNET_FEE_ASSET_ID: &str = "wxmr-devnet";
pub const MONERO_EXIT_HASH_SUITE: &str = "SHAKE256-domain-separated";
pub const MONERO_EXIT_PQ_COORDINATOR_SUITE: &str = "ML-KEM-768+ML-DSA-65+SLH-DSA-SHAKE-128s-devnet";
pub const MONERO_EXIT_PQ_ATTESTATION_SCHEME: &str = "ML-DSA-65-devnet-monero-exit";
pub const MONERO_EXIT_VIEW_KEY_AUDIT_SCHEME: &str = "view-key-audit-commitment-v1";
pub const MONERO_EXIT_RECEIPT_SCHEME: &str = "private-nullifier-receipt-root-v1";
pub const MONERO_EXIT_RESERVE_PROOF_SCHEME: &str = "monero-reserve-coverage-v1";
pub const MONERO_EXIT_DEFAULT_BATCH_MAX_EXITS: usize = 64;
pub const MONERO_EXIT_DEFAULT_BATCH_MAX_UNITS: u64 = 1_000_000;
pub const MONERO_EXIT_DEFAULT_EXIT_TTL_BLOCKS: u64 = 96;
pub const MONERO_EXIT_DEFAULT_CHALLENGE_WINDOW_BLOCKS: u64 = 18;
pub const MONERO_EXIT_DEFAULT_REORG_WINDOW_BLOCKS: u64 = 10;
pub const MONERO_EXIT_DEFAULT_MONERO_FINALITY_DEPTH: u64 = 10;
pub const MONERO_EXIT_DEFAULT_SOFT_CONFIRMATIONS: u64 = 3;
pub const MONERO_EXIT_DEFAULT_NULLIFIER_RETENTION_BLOCKS: u64 = 2_880;
pub const MONERO_EXIT_DEFAULT_VIEW_AUDIT_TTL_BLOCKS: u64 = 24;
pub const MONERO_EXIT_DEFAULT_RECEIPT_REVEAL_DELAY_BLOCKS: u64 = 6;
pub const MONERO_EXIT_DEFAULT_MIN_RESERVE_COVERAGE_BPS: u64 = 10_500;
pub const MONERO_EXIT_DEFAULT_WARN_RESERVE_COVERAGE_BPS: u64 = 11_000;
pub const MONERO_EXIT_DEFAULT_FEE_FLOOR_UNITS: u64 = 2;
pub const MONERO_EXIT_DEFAULT_FEE_BPS: u64 = 20;
pub const MONERO_EXIT_DEFAULT_PRIORITY_FEE_BPS: u64 = 60;
pub const MONERO_EXIT_DEFAULT_SPONSOR_POOL_UNITS: u64 = 75_000;
pub const MONERO_EXIT_DEFAULT_MAX_SPONSOR_REBATE_BPS: u64 = 9_500;
pub const MONERO_EXIT_DEFAULT_COORDINATOR_QUORUM: u64 = 2;
pub const MONERO_EXIT_DEFAULT_WATCHTOWER_QUORUM: u64 = 2;
pub const MONERO_EXIT_DEFAULT_MIN_COORDINATOR_WEIGHT_BPS: u64 = 6_700;
pub const MONERO_EXIT_DEFAULT_AMOUNT_BUCKET: u64 = 10_000;
pub const MONERO_EXIT_MAX_BPS: u64 = 10_000;
pub const MONERO_EXIT_STATUS_ACCEPTED: &str = "accepted";
pub const MONERO_EXIT_STATUS_QUEUED: &str = "queued";
pub const MONERO_EXIT_STATUS_BATCHED: &str = "batched";
pub const MONERO_EXIT_STATUS_CHALLENGED: &str = "challenged";
pub const MONERO_EXIT_STATUS_RELEASED: &str = "released";
pub const MONERO_EXIT_STATUS_CANCELLED: &str = "cancelled";
pub const MONERO_EXIT_STATUS_EXPIRED: &str = "expired";

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExitPriority {
    Normal,
    LowFee,
    Fast,
    Sponsored,
    Emergency,
}

impl ExitPriority {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Normal => "normal",
            Self::LowFee => "low_fee",
            Self::Fast => "fast",
            Self::Sponsored => "sponsored",
            Self::Emergency => "emergency",
        }
    }

    pub fn fee_bps(self) -> u64 {
        match self {
            Self::LowFee => MONERO_EXIT_DEFAULT_FEE_BPS / 2,
            Self::Normal => MONERO_EXIT_DEFAULT_FEE_BPS,
            Self::Sponsored => MONERO_EXIT_DEFAULT_FEE_BPS,
            Self::Fast => MONERO_EXIT_DEFAULT_PRIORITY_FEE_BPS,
            Self::Emergency => MONERO_EXIT_DEFAULT_PRIORITY_FEE_BPS.saturating_mul(2),
        }
    }

    pub fn ttl_blocks(self, config: &MoneroExitCircuitConfig) -> u64 {
        match self {
            Self::Emergency => config.exit_ttl_blocks.min(12).max(1),
            Self::Fast => config.exit_ttl_blocks.min(32).max(1),
            Self::LowFee => config.exit_ttl_blocks.saturating_mul(2).max(1),
            Self::Sponsored | Self::Normal => config.exit_ttl_blocks.max(1),
        }
    }

    pub fn challenge_window_blocks(self, config: &MoneroExitCircuitConfig) -> u64 {
        match self {
            Self::Emergency => config.challenge_window_blocks.min(6).max(1),
            Self::Fast => config.challenge_window_blocks.min(12).max(1),
            Self::LowFee => config.challenge_window_blocks.saturating_add(4).max(1),
            Self::Sponsored | Self::Normal => config.challenge_window_blocks.max(1),
        }
    }

    pub fn scheduling_score(self) -> u64 {
        match self {
            Self::Emergency => 1_000,
            Self::Fast => 850,
            Self::Sponsored => 650,
            Self::Normal => 500,
            Self::LowFee => 350,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExitStatus {
    Accepted,
    Queued,
    Batched,
    ChallengeOpen,
    ChallengeResolved,
    Broadcast,
    MoneroConfirmed,
    Released,
    Cancelled,
    Expired,
    Reorged,
}

impl ExitStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Queued => "queued",
            Self::Batched => "batched",
            Self::ChallengeOpen => "challenge_open",
            Self::ChallengeResolved => "challenge_resolved",
            Self::Broadcast => "broadcast",
            Self::MoneroConfirmed => "monero_confirmed",
            Self::Released => "released",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
            Self::Reorged => "reorged",
        }
    }

    pub fn is_open(self) -> bool {
        matches!(
            self,
            Self::Accepted
                | Self::Queued
                | Self::Batched
                | Self::ChallengeOpen
                | Self::ChallengeResolved
                | Self::Broadcast
                | Self::MoneroConfirmed
        )
    }

    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Released | Self::Cancelled | Self::Expired | Self::Reorged
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExitBatchStatus {
    Open,
    Sealed,
    Attested,
    ChallengeOpen,
    Ready,
    Broadcast,
    Confirmed,
    Released,
    Cancelled,
    Reorged,
}

impl ExitBatchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Sealed => "sealed",
            Self::Attested => "attested",
            Self::ChallengeOpen => "challenge_open",
            Self::Ready => "ready",
            Self::Broadcast => "broadcast",
            Self::Confirmed => "confirmed",
            Self::Released => "released",
            Self::Cancelled => "cancelled",
            Self::Reorged => "reorged",
        }
    }

    pub fn accepts_attestations(self) -> bool {
        matches!(self, Self::Sealed | Self::Attested | Self::ChallengeOpen)
    }

    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Released | Self::Cancelled | Self::Reorged)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NullifierStatus {
    Registered,
    Reserved,
    SeenOnMonero,
    Matched,
    Spent,
    Challenged,
    Expired,
}

impl NullifierStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Registered => "registered",
            Self::Reserved => "reserved",
            Self::SeenOnMonero => "seen_on_monero",
            Self::Matched => "matched",
            Self::Spent => "spent",
            Self::Challenged => "challenged",
            Self::Expired => "expired",
        }
    }

    pub fn blocks_replay(self) -> bool {
        !matches!(self, Self::Expired)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ViewKeyAuditStatus {
    Requested,
    Committed,
    Satisfied,
    Late,
    Disputed,
    Expired,
}

impl ViewKeyAuditStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Requested => "requested",
            Self::Committed => "committed",
            Self::Satisfied => "satisfied",
            Self::Late => "late",
            Self::Disputed => "disputed",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReserveCoverageStatus {
    Healthy,
    Watch,
    Shortfall,
    Frozen,
    Disputed,
}

impl ReserveCoverageStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Healthy => "healthy",
            Self::Watch => "watch",
            Self::Shortfall => "shortfall",
            Self::Frozen => "frozen",
            Self::Disputed => "disputed",
        }
    }

    pub fn admits_exits(self) -> bool {
        matches!(self, Self::Healthy | Self::Watch)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqCoordinatorRole {
    Scheduler,
    ReserveAuditor,
    BatchSigner,
    Watchtower,
    SponsorAuditor,
    ChallengeResolver,
}

impl PqCoordinatorRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Scheduler => "scheduler",
            Self::ReserveAuditor => "reserve_auditor",
            Self::BatchSigner => "batch_signer",
            Self::Watchtower => "watchtower",
            Self::SponsorAuditor => "sponsor_auditor",
            Self::ChallengeResolver => "challenge_resolver",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CoordinatorStatus {
    Active,
    Throttled,
    Paused,
    Slashed,
    Retired,
}

impl CoordinatorStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Throttled => "throttled",
            Self::Paused => "paused",
            Self::Slashed => "slashed",
            Self::Retired => "retired",
        }
    }

    pub fn can_attest(self) -> bool {
        matches!(self, Self::Active | Self::Throttled)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqAttestationStatus {
    Pending,
    Accepted,
    Superseded,
    Challenged,
    Expired,
    Rejected,
}

impl PqAttestationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Accepted => "accepted",
            Self::Superseded => "superseded",
            Self::Challenged => "challenged",
            Self::Expired => "expired",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeKind {
    Replay,
    ReserveShortfall,
    ViewKeyMismatch,
    Reorg,
    InvalidAttestation,
    FeeSponsorshipAbuse,
    ReceiptRootMismatch,
}

impl ChallengeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Replay => "replay",
            Self::ReserveShortfall => "reserve_shortfall",
            Self::ViewKeyMismatch => "view_key_mismatch",
            Self::Reorg => "reorg",
            Self::InvalidAttestation => "invalid_attestation",
            Self::FeeSponsorshipAbuse => "fee_sponsorship_abuse",
            Self::ReceiptRootMismatch => "receipt_root_mismatch",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeStatus {
    Open,
    EvidenceSubmitted,
    Upheld,
    Rejected,
    TimedOut,
    Cancelled,
}

impl ChallengeStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::EvidenceSubmitted => "evidence_submitted",
            Self::Upheld => "upheld",
            Self::Rejected => "rejected",
            Self::TimedOut => "timed_out",
            Self::Cancelled => "cancelled",
        }
    }

    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Upheld | Self::Rejected | Self::TimedOut | Self::Cancelled
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReorgWindowStatus {
    Tracking,
    SoftFinal,
    HardFinal,
    Challenged,
    Reorged,
    Closed,
}

impl ReorgWindowStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tracking => "tracking",
            Self::SoftFinal => "soft_final",
            Self::HardFinal => "hard_final",
            Self::Challenged => "challenged",
            Self::Reorged => "reorged",
            Self::Closed => "closed",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorshipStatus {
    Open,
    Reserved,
    Applied,
    Reclaimed,
    Exhausted,
    Expired,
    Revoked,
}

impl SponsorshipStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Reserved => "reserved",
            Self::Applied => "applied",
            Self::Reclaimed => "reclaimed",
            Self::Exhausted => "exhausted",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
        }
    }

    pub fn is_usable(self) -> bool {
        matches!(self, Self::Open | Self::Reserved)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptStatus {
    Pending,
    Committed,
    Revealed,
    Spent,
    Cancelled,
    Disputed,
}

impl ReceiptStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Committed => "committed",
            Self::Revealed => "revealed",
            Self::Spent => "spent",
            Self::Cancelled => "cancelled",
            Self::Disputed => "disputed",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptVisibility {
    Private,
    AuditorOnly,
    PublicHint,
    FullyRevealed,
}

impl ReceiptVisibility {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Private => "private",
            Self::AuditorOnly => "auditor_only",
            Self::PublicHint => "public_hint",
            Self::FullyRevealed => "fully_revealed",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExitEventKind {
    ExitAccepted,
    NullifierRegistered,
    ViewKeyAuditCommitted,
    ReserveSnapshotAccepted,
    BatchSealed,
    PqAttested,
    ChallengeOpened,
    ChallengeResolved,
    SponsorshipReserved,
    ReceiptCommitted,
    MoneroTxObserved,
    ReorgDetected,
    StateAdvanced,
}

impl ExitEventKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ExitAccepted => "exit_accepted",
            Self::NullifierRegistered => "nullifier_registered",
            Self::ViewKeyAuditCommitted => "view_key_audit_committed",
            Self::ReserveSnapshotAccepted => "reserve_snapshot_accepted",
            Self::BatchSealed => "batch_sealed",
            Self::PqAttested => "pq_attested",
            Self::ChallengeOpened => "challenge_opened",
            Self::ChallengeResolved => "challenge_resolved",
            Self::SponsorshipReserved => "sponsorship_reserved",
            Self::ReceiptCommitted => "receipt_committed",
            Self::MoneroTxObserved => "monero_tx_observed",
            Self::ReorgDetected => "reorg_detected",
            Self::StateAdvanced => "state_advanced",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroExitCircuitConfig {
    pub schema_version: u64,
    pub monero_network: String,
    pub asset_id: String,
    pub fee_asset_id: String,
    pub max_batch_exits: usize,
    pub max_batch_units: u64,
    pub exit_ttl_blocks: u64,
    pub challenge_window_blocks: u64,
    pub reorg_window_blocks: u64,
    pub monero_finality_depth: u64,
    pub soft_confirmations: u64,
    pub nullifier_retention_blocks: u64,
    pub view_audit_ttl_blocks: u64,
    pub receipt_reveal_delay_blocks: u64,
    pub min_reserve_coverage_bps: u64,
    pub warn_reserve_coverage_bps: u64,
    pub coordinator_quorum: u64,
    pub watchtower_quorum: u64,
    pub min_coordinator_weight_bps: u64,
    pub fee_floor_units: u64,
    pub base_fee_bps: u64,
    pub priority_fee_bps: u64,
    pub sponsor_pool_units: u64,
    pub max_sponsor_rebate_bps: u64,
    pub amount_bucket_units: u64,
    pub pq_coordinator_suite: String,
    pub pq_attestation_scheme: String,
    pub view_key_audit_scheme: String,
    pub receipt_scheme: String,
    pub reserve_proof_scheme: String,
}

impl Default for MoneroExitCircuitConfig {
    fn default() -> Self {
        Self {
            schema_version: MONERO_EXIT_CIRCUIT_SCHEMA_VERSION,
            monero_network: MONERO_EXIT_DEVNET_MONERO_NETWORK.to_string(),
            asset_id: MONERO_EXIT_DEVNET_ASSET_ID.to_string(),
            fee_asset_id: MONERO_EXIT_DEVNET_FEE_ASSET_ID.to_string(),
            max_batch_exits: MONERO_EXIT_DEFAULT_BATCH_MAX_EXITS,
            max_batch_units: MONERO_EXIT_DEFAULT_BATCH_MAX_UNITS,
            exit_ttl_blocks: MONERO_EXIT_DEFAULT_EXIT_TTL_BLOCKS,
            challenge_window_blocks: MONERO_EXIT_DEFAULT_CHALLENGE_WINDOW_BLOCKS,
            reorg_window_blocks: MONERO_EXIT_DEFAULT_REORG_WINDOW_BLOCKS,
            monero_finality_depth: MONERO_EXIT_DEFAULT_MONERO_FINALITY_DEPTH,
            soft_confirmations: MONERO_EXIT_DEFAULT_SOFT_CONFIRMATIONS,
            nullifier_retention_blocks: MONERO_EXIT_DEFAULT_NULLIFIER_RETENTION_BLOCKS,
            view_audit_ttl_blocks: MONERO_EXIT_DEFAULT_VIEW_AUDIT_TTL_BLOCKS,
            receipt_reveal_delay_blocks: MONERO_EXIT_DEFAULT_RECEIPT_REVEAL_DELAY_BLOCKS,
            min_reserve_coverage_bps: MONERO_EXIT_DEFAULT_MIN_RESERVE_COVERAGE_BPS,
            warn_reserve_coverage_bps: MONERO_EXIT_DEFAULT_WARN_RESERVE_COVERAGE_BPS,
            coordinator_quorum: MONERO_EXIT_DEFAULT_COORDINATOR_QUORUM,
            watchtower_quorum: MONERO_EXIT_DEFAULT_WATCHTOWER_QUORUM,
            min_coordinator_weight_bps: MONERO_EXIT_DEFAULT_MIN_COORDINATOR_WEIGHT_BPS,
            fee_floor_units: MONERO_EXIT_DEFAULT_FEE_FLOOR_UNITS,
            base_fee_bps: MONERO_EXIT_DEFAULT_FEE_BPS,
            priority_fee_bps: MONERO_EXIT_DEFAULT_PRIORITY_FEE_BPS,
            sponsor_pool_units: MONERO_EXIT_DEFAULT_SPONSOR_POOL_UNITS,
            max_sponsor_rebate_bps: MONERO_EXIT_DEFAULT_MAX_SPONSOR_REBATE_BPS,
            amount_bucket_units: MONERO_EXIT_DEFAULT_AMOUNT_BUCKET,
            pq_coordinator_suite: MONERO_EXIT_PQ_COORDINATOR_SUITE.to_string(),
            pq_attestation_scheme: MONERO_EXIT_PQ_ATTESTATION_SCHEME.to_string(),
            view_key_audit_scheme: MONERO_EXIT_VIEW_KEY_AUDIT_SCHEME.to_string(),
            receipt_scheme: MONERO_EXIT_RECEIPT_SCHEME.to_string(),
            reserve_proof_scheme: MONERO_EXIT_RESERVE_PROOF_SCHEME.to_string(),
        }
    }
}

impl MoneroExitCircuitConfig {
    pub fn devnet() -> Self {
        Self::default()
    }

    pub fn validate(&self) -> MoneroExitCircuitResult<()> {
        if self.schema_version != MONERO_EXIT_CIRCUIT_SCHEMA_VERSION {
            return Err(format!(
                "unsupported monero exit circuit schema version: {}",
                self.schema_version
            ));
        }
        ensure_non_empty(&self.monero_network, "monero exit network")?;
        ensure_non_empty(&self.asset_id, "monero exit asset id")?;
        ensure_non_empty(&self.fee_asset_id, "monero exit fee asset id")?;
        if self.max_batch_exits == 0 {
            return Err("monero exit max batch exits must be positive".to_string());
        }
        ensure_positive(self.max_batch_units, "monero exit max batch units")?;
        ensure_positive(self.exit_ttl_blocks, "monero exit ttl blocks")?;
        ensure_positive(
            self.challenge_window_blocks,
            "monero exit challenge window blocks",
        )?;
        ensure_positive(self.reorg_window_blocks, "monero exit reorg window blocks")?;
        ensure_positive(self.monero_finality_depth, "monero exit finality depth")?;
        if self.soft_confirmations > self.monero_finality_depth {
            return Err("monero exit soft confirmations cannot exceed finality depth".to_string());
        }
        ensure_positive(
            self.nullifier_retention_blocks,
            "monero exit nullifier retention blocks",
        )?;
        ensure_positive(
            self.view_audit_ttl_blocks,
            "monero exit view audit ttl blocks",
        )?;
        ensure_positive(
            self.receipt_reveal_delay_blocks,
            "monero exit receipt reveal delay blocks",
        )?;
        validate_coverage_bps(
            self.min_reserve_coverage_bps,
            "monero exit min reserve coverage bps",
        )?;
        validate_coverage_bps(
            self.warn_reserve_coverage_bps,
            "monero exit warn reserve coverage bps",
        )?;
        if self.warn_reserve_coverage_bps < self.min_reserve_coverage_bps {
            return Err("monero exit warn coverage must be at least minimum coverage".to_string());
        }
        ensure_positive(self.coordinator_quorum, "monero exit coordinator quorum")?;
        ensure_positive(self.watchtower_quorum, "monero exit watchtower quorum")?;
        validate_bps(
            self.min_coordinator_weight_bps,
            "monero exit coordinator weight bps",
        )?;
        validate_bps(self.base_fee_bps, "monero exit base fee bps")?;
        validate_bps(self.priority_fee_bps, "monero exit priority fee bps")?;
        validate_bps(
            self.max_sponsor_rebate_bps,
            "monero exit sponsor rebate bps",
        )?;
        ensure_positive(self.amount_bucket_units, "monero exit amount bucket units")?;
        ensure_non_empty(
            &self.pq_coordinator_suite,
            "monero exit pq coordinator suite",
        )?;
        ensure_non_empty(
            &self.pq_attestation_scheme,
            "monero exit pq attestation scheme",
        )?;
        ensure_non_empty(
            &self.view_key_audit_scheme,
            "monero exit view key audit scheme",
        )?;
        ensure_non_empty(&self.receipt_scheme, "monero exit receipt scheme")?;
        ensure_non_empty(
            &self.reserve_proof_scheme,
            "monero exit reserve proof scheme",
        )?;
        Ok(())
    }

    pub fn fee_for(&self, amount_units: u64, priority: ExitPriority) -> u64 {
        let priority_bps = match priority {
            ExitPriority::Fast | ExitPriority::Emergency => self.priority_fee_bps,
            _ => priority.fee_bps().max(self.base_fee_bps),
        };
        mul_bps(amount_units, priority_bps).max(self.fee_floor_units)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_exit_circuit_config",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": self.schema_version,
            "hash_suite": MONERO_EXIT_HASH_SUITE,
            "monero_network": self.monero_network,
            "asset_id": self.asset_id,
            "fee_asset_id": self.fee_asset_id,
            "max_batch_exits": self.max_batch_exits as u64,
            "max_batch_units": self.max_batch_units,
            "exit_ttl_blocks": self.exit_ttl_blocks,
            "challenge_window_blocks": self.challenge_window_blocks,
            "reorg_window_blocks": self.reorg_window_blocks,
            "monero_finality_depth": self.monero_finality_depth,
            "soft_confirmations": self.soft_confirmations,
            "nullifier_retention_blocks": self.nullifier_retention_blocks,
            "view_audit_ttl_blocks": self.view_audit_ttl_blocks,
            "receipt_reveal_delay_blocks": self.receipt_reveal_delay_blocks,
            "min_reserve_coverage_bps": self.min_reserve_coverage_bps,
            "warn_reserve_coverage_bps": self.warn_reserve_coverage_bps,
            "coordinator_quorum": self.coordinator_quorum,
            "watchtower_quorum": self.watchtower_quorum,
            "min_coordinator_weight_bps": self.min_coordinator_weight_bps,
            "fee_floor_units": self.fee_floor_units,
            "base_fee_bps": self.base_fee_bps,
            "priority_fee_bps": self.priority_fee_bps,
            "sponsor_pool_units": self.sponsor_pool_units,
            "max_sponsor_rebate_bps": self.max_sponsor_rebate_bps,
            "amount_bucket_units": self.amount_bucket_units,
            "pq_coordinator_suite": self.pq_coordinator_suite,
            "pq_attestation_scheme": self.pq_attestation_scheme,
            "view_key_audit_scheme": self.view_key_audit_scheme,
            "receipt_scheme": self.receipt_scheme,
            "reserve_proof_scheme": self.reserve_proof_scheme,
        })
    }

    pub fn config_root(&self) -> String {
        monero_exit_payload_root("MONERO-EXIT-CONFIG", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroExitRequest {
    pub exit_id: String,
    pub requester_commitment: String,
    pub l2_account_commitment: String,
    pub recipient_address_hash: String,
    pub amount_units: u64,
    pub amount_bucket: u64,
    pub fee_asset_id: String,
    pub max_fee_units: u64,
    pub sponsored_fee_units: u64,
    pub net_amount_units: u64,
    pub priority: ExitPriority,
    pub privacy_tag_root: String,
    pub nullifier_hash: String,
    pub key_image_hash: String,
    pub view_key_commitment: String,
    pub audit_hint_root: String,
    pub memo_commitment: String,
    pub requested_at_height: u64,
    pub expires_at_height: u64,
    pub challenge_window_end_height: u64,
    pub reserve_snapshot_id: Option<String>,
    pub sponsorship_id: Option<String>,
    pub batch_id: Option<String>,
    pub receipt_id: Option<String>,
    pub status: ExitStatus,
}

impl MoneroExitRequest {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        requester_commitment: &str,
        l2_account_commitment: &str,
        recipient_address: &str,
        amount_units: u64,
        fee_asset_id: &str,
        priority: ExitPriority,
        privacy_tag: &str,
        nullifier: &str,
        key_image: &str,
        view_key_label: &str,
        memo: &str,
        height: u64,
        config: &MoneroExitCircuitConfig,
    ) -> MoneroExitCircuitResult<Self> {
        ensure_non_empty(requester_commitment, "monero exit requester commitment")?;
        ensure_non_empty(l2_account_commitment, "monero exit l2 account commitment")?;
        ensure_non_empty(recipient_address, "monero exit recipient address")?;
        ensure_positive(amount_units, "monero exit amount")?;
        ensure_non_empty(fee_asset_id, "monero exit fee asset id")?;
        ensure_non_empty(privacy_tag, "monero exit privacy tag")?;
        ensure_non_empty(nullifier, "monero exit nullifier")?;
        ensure_non_empty(key_image, "monero exit key image")?;
        ensure_non_empty(view_key_label, "monero exit view key label")?;
        let recipient_address_hash =
            monero_exit_string_root("MONERO-EXIT-RECIPIENT-ADDRESS", recipient_address);
        let privacy_tag_root = monero_exit_string_root("MONERO-EXIT-PRIVACY-TAG", privacy_tag);
        let nullifier_hash = monero_exit_nullifier_hash(nullifier);
        let key_image_hash = monero_exit_key_image_hash(key_image);
        let view_key_commitment = monero_exit_string_root("MONERO-EXIT-VIEW-KEY", view_key_label);
        let audit_hint_root = monero_exit_payload_root(
            "MONERO-EXIT-AUDIT-HINT",
            &json!({
                "view_key_commitment": view_key_commitment,
                "privacy_tag_root": privacy_tag_root,
                "requested_at_height": height,
            }),
        );
        let memo_commitment = monero_exit_string_root("MONERO-EXIT-MEMO", memo);
        let max_fee_units = config.fee_for(amount_units, priority);
        let net_amount_units = amount_units.saturating_sub(max_fee_units);
        let amount_bucket = monero_exit_amount_bucket(amount_units, config.amount_bucket_units);
        let expires_at_height = height.saturating_add(priority.ttl_blocks(config));
        let challenge_window_end_height =
            height.saturating_add(priority.challenge_window_blocks(config));
        let body = json!({
            "requester_commitment": requester_commitment,
            "l2_account_commitment": l2_account_commitment,
            "recipient_address_hash": recipient_address_hash,
            "amount_units": amount_units,
            "fee_asset_id": fee_asset_id,
            "max_fee_units": max_fee_units,
            "priority": priority.as_str(),
            "privacy_tag_root": privacy_tag_root,
            "nullifier_hash": nullifier_hash,
            "key_image_hash": key_image_hash,
            "view_key_commitment": view_key_commitment,
            "memo_commitment": memo_commitment,
            "requested_at_height": height,
        });
        let exit_id = monero_exit_request_id(&body);
        Ok(Self {
            exit_id,
            requester_commitment: requester_commitment.to_string(),
            l2_account_commitment: l2_account_commitment.to_string(),
            recipient_address_hash,
            amount_units,
            amount_bucket,
            fee_asset_id: fee_asset_id.to_string(),
            max_fee_units,
            sponsored_fee_units: 0,
            net_amount_units,
            priority,
            privacy_tag_root,
            nullifier_hash,
            key_image_hash,
            view_key_commitment,
            audit_hint_root,
            memo_commitment,
            requested_at_height: height,
            expires_at_height,
            challenge_window_end_height,
            reserve_snapshot_id: None,
            sponsorship_id: None,
            batch_id: None,
            receipt_id: None,
            status: ExitStatus::Accepted,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_exit_request",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "exit_id": self.exit_id,
            "requester_commitment": self.requester_commitment,
            "l2_account_commitment": self.l2_account_commitment,
            "recipient_address_hash": self.recipient_address_hash,
            "amount_units": self.amount_units,
            "amount_bucket": self.amount_bucket,
            "fee_asset_id": self.fee_asset_id,
            "max_fee_units": self.max_fee_units,
            "sponsored_fee_units": self.sponsored_fee_units,
            "net_amount_units": self.net_amount_units,
            "priority": self.priority.as_str(),
            "privacy_tag_root": self.privacy_tag_root,
            "nullifier_hash": self.nullifier_hash,
            "key_image_hash": self.key_image_hash,
            "view_key_commitment": self.view_key_commitment,
            "audit_hint_root": self.audit_hint_root,
            "memo_commitment": self.memo_commitment,
            "requested_at_height": self.requested_at_height,
            "expires_at_height": self.expires_at_height,
            "challenge_window_end_height": self.challenge_window_end_height,
            "reserve_snapshot_id": self.reserve_snapshot_id,
            "sponsorship_id": self.sponsorship_id,
            "batch_id": self.batch_id,
            "receipt_id": self.receipt_id,
            "status": self.status.as_str(),
        })
    }

    pub fn exit_root(&self) -> String {
        monero_exit_record_root_from_record(&self.public_record())
    }

    pub fn challenge_subject_root(&self) -> String {
        monero_exit_payload_root(
            "MONERO-EXIT-CHALLENGE-SUBJECT",
            &json!({
                "exit_id": self.exit_id,
                "nullifier_hash": self.nullifier_hash,
                "key_image_hash": self.key_image_hash,
                "recipient_address_hash": self.recipient_address_hash,
                "amount_bucket": self.amount_bucket,
            }),
        )
    }

    pub fn can_batch_at(&self, height: u64) -> bool {
        matches!(self.status, ExitStatus::Accepted | ExitStatus::Queued)
            && height <= self.expires_at_height
            && height >= self.requested_at_height
    }

    pub fn mark_queued(&mut self) {
        if self.status == ExitStatus::Accepted {
            self.status = ExitStatus::Queued;
        }
    }

    pub fn mark_batched(&mut self, batch_id: String, reserve_snapshot_id: String) {
        self.batch_id = Some(batch_id);
        self.reserve_snapshot_id = Some(reserve_snapshot_id);
        self.status = ExitStatus::Batched;
    }

    pub fn apply_sponsorship(&mut self, sponsorship_id: String, sponsored_fee_units: u64) {
        self.sponsorship_id = Some(sponsorship_id);
        self.sponsored_fee_units = self.max_fee_units.min(sponsored_fee_units);
        self.net_amount_units = self
            .amount_units
            .saturating_sub(self.max_fee_units.saturating_sub(self.sponsored_fee_units));
    }

    pub fn attach_receipt(&mut self, receipt_id: String) {
        self.receipt_id = Some(receipt_id);
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroExitBatch {
    pub batch_id: String,
    pub coordinator_id: String,
    pub monero_network: String,
    pub asset_id: String,
    pub exit_ids: Vec<String>,
    pub exit_root: String,
    pub nullifier_root: String,
    pub recipient_root: String,
    pub total_amount_units: u64,
    pub total_fee_units: u64,
    pub sponsored_fee_units: u64,
    pub reserve_snapshot_id: String,
    pub receipt_root: String,
    pub pq_attestation_root: String,
    pub challenge_window_id: String,
    pub created_at_height: u64,
    pub challenge_end_height: u64,
    pub scheduled_monero_height: u64,
    pub monero_txid_hash: Option<String>,
    pub monero_block_height: Option<u64>,
    pub monero_block_hash: Option<String>,
    pub confirmations: u64,
    pub status: ExitBatchStatus,
}

impl MoneroExitBatch {
    #[allow(clippy::too_many_arguments)]
    pub fn seal(
        coordinator_id: &str,
        monero_network: &str,
        asset_id: &str,
        reserve_snapshot_id: &str,
        exits: &[MoneroExitRequest],
        height: u64,
        config: &MoneroExitCircuitConfig,
    ) -> MoneroExitCircuitResult<Self> {
        ensure_non_empty(coordinator_id, "monero exit batch coordinator id")?;
        ensure_non_empty(monero_network, "monero exit batch network")?;
        ensure_non_empty(asset_id, "monero exit batch asset id")?;
        ensure_non_empty(reserve_snapshot_id, "monero exit batch reserve snapshot")?;
        if exits.is_empty() {
            return Err("monero exit batch requires at least one exit".to_string());
        }
        if exits.len() > config.max_batch_exits {
            return Err("monero exit batch exceeds max exit count".to_string());
        }
        let mut exit_ids = Vec::with_capacity(exits.len());
        let mut exit_records = Vec::with_capacity(exits.len());
        let mut nullifier_records = Vec::with_capacity(exits.len());
        let mut recipient_records = Vec::with_capacity(exits.len());
        let mut total_amount_units = 0_u64;
        let mut total_fee_units = 0_u64;
        let mut sponsored_fee_units = 0_u64;
        for exit in exits {
            if !exit.can_batch_at(height) {
                return Err(format!("exit {} is not batchable", exit.exit_id));
            }
            if exit.fee_asset_id != config.fee_asset_id {
                return Err("exit fee asset mismatch".to_string());
            }
            exit_ids.push(exit.exit_id.clone());
            exit_records.push(exit.public_record());
            nullifier_records.push(json!({
                "exit_id": exit.exit_id,
                "nullifier_hash": exit.nullifier_hash,
                "key_image_hash": exit.key_image_hash,
            }));
            recipient_records.push(json!({
                "exit_id": exit.exit_id,
                "recipient_address_hash": exit.recipient_address_hash,
                "amount_bucket": exit.amount_bucket,
            }));
            total_amount_units = total_amount_units.saturating_add(exit.amount_units);
            total_fee_units = total_fee_units.saturating_add(exit.max_fee_units);
            sponsored_fee_units = sponsored_fee_units.saturating_add(exit.sponsored_fee_units);
        }
        if total_amount_units > config.max_batch_units {
            return Err("monero exit batch exceeds max amount units".to_string());
        }
        exit_ids.sort();
        let exit_root = merkle_root("MONERO-EXIT-BATCH-EXIT", &exit_records);
        let nullifier_root = merkle_root("MONERO-EXIT-BATCH-NULLIFIER", &nullifier_records);
        let recipient_root = merkle_root("MONERO-EXIT-BATCH-RECIPIENT", &recipient_records);
        let receipt_root = merkle_root("MONERO-EXIT-BATCH-RECEIPT-EMPTY", &[]);
        let pq_attestation_root = merkle_root("MONERO-EXIT-BATCH-ATTESTATION-EMPTY", &[]);
        let challenge_end_height = height.saturating_add(config.challenge_window_blocks);
        let body = json!({
            "coordinator_id": coordinator_id,
            "monero_network": monero_network,
            "asset_id": asset_id,
            "reserve_snapshot_id": reserve_snapshot_id,
            "exit_root": exit_root,
            "nullifier_root": nullifier_root,
            "recipient_root": recipient_root,
            "total_amount_units": total_amount_units,
            "created_at_height": height,
        });
        let batch_id = monero_exit_batch_id(&body);
        let challenge_window_id =
            monero_exit_reorg_window_id("batch", &batch_id, height, challenge_end_height);
        Ok(Self {
            batch_id,
            coordinator_id: coordinator_id.to_string(),
            monero_network: monero_network.to_string(),
            asset_id: asset_id.to_string(),
            exit_ids,
            exit_root,
            nullifier_root,
            recipient_root,
            total_amount_units,
            total_fee_units,
            sponsored_fee_units,
            reserve_snapshot_id: reserve_snapshot_id.to_string(),
            receipt_root,
            pq_attestation_root,
            challenge_window_id,
            created_at_height: height,
            challenge_end_height,
            scheduled_monero_height: 0,
            monero_txid_hash: None,
            monero_block_height: None,
            monero_block_hash: None,
            confirmations: 0,
            status: ExitBatchStatus::Sealed,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_exit_batch",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "batch_id": self.batch_id,
            "coordinator_id": self.coordinator_id,
            "monero_network": self.monero_network,
            "asset_id": self.asset_id,
            "exit_ids": self.exit_ids,
            "exit_count": self.exit_ids.len() as u64,
            "exit_root": self.exit_root,
            "nullifier_root": self.nullifier_root,
            "recipient_root": self.recipient_root,
            "total_amount_units": self.total_amount_units,
            "total_fee_units": self.total_fee_units,
            "sponsored_fee_units": self.sponsored_fee_units,
            "reserve_snapshot_id": self.reserve_snapshot_id,
            "receipt_root": self.receipt_root,
            "pq_attestation_root": self.pq_attestation_root,
            "challenge_window_id": self.challenge_window_id,
            "created_at_height": self.created_at_height,
            "challenge_end_height": self.challenge_end_height,
            "scheduled_monero_height": self.scheduled_monero_height,
            "monero_txid_hash": self.monero_txid_hash,
            "monero_block_height": self.monero_block_height,
            "monero_block_hash": self.monero_block_hash,
            "confirmations": self.confirmations,
            "status": self.status.as_str(),
        })
    }

    pub fn batch_root(&self) -> String {
        monero_exit_batch_root_from_record(&self.public_record())
    }

    pub fn subject_root(&self) -> String {
        monero_exit_payload_root(
            "MONERO-EXIT-BATCH-SUBJECT",
            &json!({
                "batch_id": self.batch_id,
                "exit_root": self.exit_root,
                "nullifier_root": self.nullifier_root,
                "recipient_root": self.recipient_root,
                "reserve_snapshot_id": self.reserve_snapshot_id,
                "total_amount_units": self.total_amount_units,
            }),
        )
    }

    pub fn update_attestation_root(&mut self, attestations: &[PqCoordinatorAttestation]) {
        let records = attestations
            .iter()
            .filter(|attestation| {
                attestation.subject_kind == "batch"
                    && attestation.subject_id == self.batch_id
                    && attestation.status == PqAttestationStatus::Accepted
            })
            .map(PqCoordinatorAttestation::public_record)
            .collect::<Vec<_>>();
        self.pq_attestation_root = merkle_root("MONERO-EXIT-BATCH-PQ-ATTESTATION", &records);
        if !records.is_empty() && self.status == ExitBatchStatus::Sealed {
            self.status = ExitBatchStatus::Attested;
        }
    }

    pub fn attach_receipt_root(&mut self, receipts: &[PrivacyPreservingExitReceipt]) {
        let records = receipts
            .iter()
            .filter(|receipt| receipt.batch_id.as_deref() == Some(self.batch_id.as_str()))
            .map(PrivacyPreservingExitReceipt::public_record)
            .collect::<Vec<_>>();
        self.receipt_root = merkle_root("MONERO-EXIT-BATCH-RECEIPT", &records);
    }

    pub fn mark_ready_if_window_closed(&mut self, height: u64) {
        if matches!(
            self.status,
            ExitBatchStatus::Sealed | ExitBatchStatus::Attested
        ) && height >= self.challenge_end_height
        {
            self.status = ExitBatchStatus::Ready;
        }
    }

    pub fn observe_monero_tx(
        &mut self,
        txid: &str,
        block_height: u64,
        block_hash: &str,
        current_monero_height: u64,
        finality_depth: u64,
    ) -> MoneroExitCircuitResult<()> {
        ensure_non_empty(txid, "monero exit batch txid")?;
        ensure_non_empty(block_hash, "monero exit batch block hash")?;
        self.monero_txid_hash = Some(monero_exit_txid_hash(txid));
        self.monero_block_height = Some(block_height);
        self.monero_block_hash = Some(monero_exit_string_root("MONERO-EXIT-BLOCK", block_hash));
        self.confirmations = confirmations(current_monero_height, block_height);
        self.status = if self.confirmations >= finality_depth {
            ExitBatchStatus::Confirmed
        } else {
            ExitBatchStatus::Broadcast
        };
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NullifierReplayEntry {
    pub registry_entry_id: String,
    pub exit_id: String,
    pub nullifier_hash: String,
    pub key_image_hash: String,
    pub spend_domain: String,
    pub first_registered_height: u64,
    pub expires_at_height: u64,
    pub first_seen_monero_height: Option<u64>,
    pub first_seen_txid_hash: Option<String>,
    pub matched_batch_id: Option<String>,
    pub witness_root: String,
    pub status: NullifierStatus,
}

impl NullifierReplayEntry {
    pub fn new(
        exit_id: &str,
        nullifier_hash: &str,
        key_image_hash: &str,
        spend_domain: &str,
        height: u64,
        retention_blocks: u64,
    ) -> MoneroExitCircuitResult<Self> {
        ensure_non_empty(exit_id, "monero exit nullifier exit id")?;
        ensure_non_empty(nullifier_hash, "monero exit nullifier hash")?;
        ensure_non_empty(key_image_hash, "monero exit key image hash")?;
        ensure_non_empty(spend_domain, "monero exit spend domain")?;
        let expires_at_height = height.saturating_add(retention_blocks.max(1));
        let body = json!({
            "exit_id": exit_id,
            "nullifier_hash": nullifier_hash,
            "key_image_hash": key_image_hash,
            "spend_domain": spend_domain,
            "height": height,
        });
        Ok(Self {
            registry_entry_id: monero_exit_nullifier_registry_entry_id(&body),
            exit_id: exit_id.to_string(),
            nullifier_hash: nullifier_hash.to_string(),
            key_image_hash: key_image_hash.to_string(),
            spend_domain: spend_domain.to_string(),
            first_registered_height: height,
            expires_at_height,
            first_seen_monero_height: None,
            first_seen_txid_hash: None,
            matched_batch_id: None,
            witness_root: merkle_root("MONERO-EXIT-NULLIFIER-WITNESS-EMPTY", &[]),
            status: NullifierStatus::Registered,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_exit_nullifier_replay_entry",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "registry_entry_id": self.registry_entry_id,
            "exit_id": self.exit_id,
            "nullifier_hash": self.nullifier_hash,
            "key_image_hash": self.key_image_hash,
            "spend_domain": self.spend_domain,
            "first_registered_height": self.first_registered_height,
            "expires_at_height": self.expires_at_height,
            "first_seen_monero_height": self.first_seen_monero_height,
            "first_seen_txid_hash": self.first_seen_txid_hash,
            "matched_batch_id": self.matched_batch_id,
            "witness_root": self.witness_root,
            "status": self.status.as_str(),
        })
    }

    pub fn mark_reserved(&mut self, batch_id: &str) {
        self.matched_batch_id = Some(batch_id.to_string());
        if self.status == NullifierStatus::Registered {
            self.status = NullifierStatus::Reserved;
        }
    }

    pub fn observe_spend(
        &mut self,
        txid: &str,
        monero_height: u64,
        witness_payload: &Value,
    ) -> MoneroExitCircuitResult<()> {
        ensure_non_empty(txid, "monero exit key image txid")?;
        self.first_seen_txid_hash = Some(monero_exit_txid_hash(txid));
        self.first_seen_monero_height = Some(monero_height);
        self.witness_root =
            monero_exit_payload_root("MONERO-EXIT-KEY-IMAGE-WITNESS", witness_payload);
        self.status = NullifierStatus::SeenOnMonero;
        Ok(())
    }

    pub fn match_spend(&mut self, batch_id: &str) {
        self.matched_batch_id = Some(batch_id.to_string());
        self.status = NullifierStatus::Matched;
    }

    pub fn expire_if_due(&mut self, height: u64) {
        if height >= self.expires_at_height && !matches!(self.status, NullifierStatus::Spent) {
            self.status = NullifierStatus::Expired;
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ViewKeyAuditCommitment {
    pub audit_id: String,
    pub exit_id: String,
    pub auditor_id: String,
    pub view_key_commitment: String,
    pub scan_window_start_height: u64,
    pub scan_window_end_height: u64,
    pub address_set_root: String,
    pub output_commitment_root: String,
    pub balance_delta_commitment: String,
    pub encrypted_report_root: String,
    pub disclosure_policy_root: String,
    pub requested_at_height: u64,
    pub due_at_height: u64,
    pub completed_at_height: Option<u64>,
    pub status: ViewKeyAuditStatus,
}

impl ViewKeyAuditCommitment {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        exit_id: &str,
        auditor_id: &str,
        view_key_commitment: &str,
        scan_window_start_height: u64,
        scan_window_end_height: u64,
        address_commitments: &[String],
        output_commitments: &[String],
        encrypted_report_payload: &Value,
        disclosure_policy: &Value,
        requested_at_height: u64,
        ttl_blocks: u64,
    ) -> MoneroExitCircuitResult<Self> {
        ensure_non_empty(exit_id, "monero exit view audit exit id")?;
        ensure_non_empty(auditor_id, "monero exit view audit auditor id")?;
        ensure_non_empty(view_key_commitment, "monero exit view audit key commitment")?;
        if scan_window_end_height < scan_window_start_height {
            return Err("monero exit view audit scan window is inverted".to_string());
        }
        let address_set_root =
            monero_exit_string_set_root("MONERO-EXIT-AUDIT-ADDRESS-SET", address_commitments);
        let output_commitment_root =
            monero_exit_string_set_root("MONERO-EXIT-AUDIT-OUTPUT-SET", output_commitments);
        let balance_delta_commitment = monero_exit_payload_root(
            "MONERO-EXIT-AUDIT-BALANCE-DELTA",
            &json!({
                "exit_id": exit_id,
                "output_commitment_root": output_commitment_root,
                "scan_window_start_height": scan_window_start_height,
                "scan_window_end_height": scan_window_end_height,
            }),
        );
        let encrypted_report_root = monero_exit_payload_root(
            "MONERO-EXIT-AUDIT-ENCRYPTED-REPORT",
            encrypted_report_payload,
        );
        let disclosure_policy_root =
            monero_exit_payload_root("MONERO-EXIT-AUDIT-DISCLOSURE-POLICY", disclosure_policy);
        let body = json!({
            "exit_id": exit_id,
            "auditor_id": auditor_id,
            "view_key_commitment": view_key_commitment,
            "address_set_root": address_set_root,
            "output_commitment_root": output_commitment_root,
            "requested_at_height": requested_at_height,
        });
        Ok(Self {
            audit_id: monero_exit_view_key_audit_id(&body),
            exit_id: exit_id.to_string(),
            auditor_id: auditor_id.to_string(),
            view_key_commitment: view_key_commitment.to_string(),
            scan_window_start_height,
            scan_window_end_height,
            address_set_root,
            output_commitment_root,
            balance_delta_commitment,
            encrypted_report_root,
            disclosure_policy_root,
            requested_at_height,
            due_at_height: requested_at_height.saturating_add(ttl_blocks.max(1)),
            completed_at_height: None,
            status: ViewKeyAuditStatus::Committed,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_exit_view_key_audit_commitment",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "audit_scheme": MONERO_EXIT_VIEW_KEY_AUDIT_SCHEME,
            "audit_id": self.audit_id,
            "exit_id": self.exit_id,
            "auditor_id": self.auditor_id,
            "view_key_commitment": self.view_key_commitment,
            "scan_window_start_height": self.scan_window_start_height,
            "scan_window_end_height": self.scan_window_end_height,
            "address_set_root": self.address_set_root,
            "output_commitment_root": self.output_commitment_root,
            "balance_delta_commitment": self.balance_delta_commitment,
            "encrypted_report_root": self.encrypted_report_root,
            "disclosure_policy_root": self.disclosure_policy_root,
            "requested_at_height": self.requested_at_height,
            "due_at_height": self.due_at_height,
            "completed_at_height": self.completed_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn complete(&mut self, height: u64, encrypted_report_payload: &Value) {
        self.encrypted_report_root = monero_exit_payload_root(
            "MONERO-EXIT-AUDIT-ENCRYPTED-REPORT",
            encrypted_report_payload,
        );
        self.completed_at_height = Some(height);
        self.status = if height <= self.due_at_height {
            ViewKeyAuditStatus::Satisfied
        } else {
            ViewKeyAuditStatus::Late
        };
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReserveCoverageSnapshot {
    pub snapshot_id: String,
    pub monero_network: String,
    pub asset_id: String,
    pub reserve_address_root: String,
    pub reserve_proof_root: String,
    pub view_key_audit_root: String,
    pub available_reserve_units: u64,
    pub pending_inbound_units: u64,
    pub pending_exit_units: u64,
    pub challenged_units: u64,
    pub insurance_units: u64,
    pub total_obligation_units: u64,
    pub required_reserve_units: u64,
    pub coverage_bps: u64,
    pub min_coverage_bps: u64,
    pub warn_coverage_bps: u64,
    pub monero_height: u64,
    pub observed_at_l2_height: u64,
    pub signer_set_root: String,
    pub status: ReserveCoverageStatus,
}

impl ReserveCoverageSnapshot {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        monero_network: &str,
        asset_id: &str,
        reserve_addresses: &[String],
        reserve_proof_payload: &Value,
        view_key_audit_root: &str,
        available_reserve_units: u64,
        pending_inbound_units: u64,
        pending_exit_units: u64,
        challenged_units: u64,
        insurance_units: u64,
        monero_height: u64,
        observed_at_l2_height: u64,
        signer_labels: &[String],
        config: &MoneroExitCircuitConfig,
    ) -> MoneroExitCircuitResult<Self> {
        ensure_non_empty(monero_network, "monero exit reserve network")?;
        ensure_non_empty(asset_id, "monero exit reserve asset id")?;
        ensure_non_empty(view_key_audit_root, "monero exit reserve view audit root")?;
        let reserve_address_root =
            monero_exit_string_set_root("MONERO-EXIT-RESERVE-ADDRESS-SET", reserve_addresses);
        let reserve_proof_root =
            monero_exit_payload_root("MONERO-EXIT-RESERVE-PROOF", reserve_proof_payload);
        let signer_set_root =
            monero_exit_string_set_root("MONERO-EXIT-RESERVE-SIGNER-SET", signer_labels);
        let total_obligation_units = pending_exit_units.saturating_add(challenged_units);
        let required_reserve_units =
            mul_bps(total_obligation_units, config.min_reserve_coverage_bps);
        let effective_reserve_units = available_reserve_units
            .saturating_add(pending_inbound_units)
            .saturating_add(insurance_units);
        let coverage_bps = ratio_bps(effective_reserve_units, total_obligation_units.max(1));
        let status = reserve_status(
            coverage_bps,
            config.min_reserve_coverage_bps,
            config.warn_reserve_coverage_bps,
        );
        let body = json!({
            "monero_network": monero_network,
            "asset_id": asset_id,
            "reserve_address_root": reserve_address_root,
            "reserve_proof_root": reserve_proof_root,
            "view_key_audit_root": view_key_audit_root,
            "available_reserve_units": available_reserve_units,
            "pending_exit_units": pending_exit_units,
            "monero_height": monero_height,
            "observed_at_l2_height": observed_at_l2_height,
        });
        Ok(Self {
            snapshot_id: monero_exit_reserve_coverage_snapshot_id(&body),
            monero_network: monero_network.to_string(),
            asset_id: asset_id.to_string(),
            reserve_address_root,
            reserve_proof_root,
            view_key_audit_root: view_key_audit_root.to_string(),
            available_reserve_units,
            pending_inbound_units,
            pending_exit_units,
            challenged_units,
            insurance_units,
            total_obligation_units,
            required_reserve_units,
            coverage_bps,
            min_coverage_bps: config.min_reserve_coverage_bps,
            warn_coverage_bps: config.warn_reserve_coverage_bps,
            monero_height,
            observed_at_l2_height,
            signer_set_root,
            status,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_exit_reserve_coverage_snapshot",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "reserve_proof_scheme": MONERO_EXIT_RESERVE_PROOF_SCHEME,
            "snapshot_id": self.snapshot_id,
            "monero_network": self.monero_network,
            "asset_id": self.asset_id,
            "reserve_address_root": self.reserve_address_root,
            "reserve_proof_root": self.reserve_proof_root,
            "view_key_audit_root": self.view_key_audit_root,
            "available_reserve_units": self.available_reserve_units,
            "pending_inbound_units": self.pending_inbound_units,
            "pending_exit_units": self.pending_exit_units,
            "challenged_units": self.challenged_units,
            "insurance_units": self.insurance_units,
            "total_obligation_units": self.total_obligation_units,
            "required_reserve_units": self.required_reserve_units,
            "coverage_bps": self.coverage_bps,
            "min_coverage_bps": self.min_coverage_bps,
            "warn_coverage_bps": self.warn_coverage_bps,
            "monero_height": self.monero_height,
            "observed_at_l2_height": self.observed_at_l2_height,
            "signer_set_root": self.signer_set_root,
            "status": self.status.as_str(),
        })
    }

    pub fn admits_amount(&self, amount_units: u64, config: &MoneroExitCircuitConfig) -> bool {
        let future_obligation = self.total_obligation_units.saturating_add(amount_units);
        let future_required = mul_bps(future_obligation, config.min_reserve_coverage_bps);
        self.status.admits_exits()
            && self
                .available_reserve_units
                .saturating_add(self.pending_inbound_units)
                .saturating_add(self.insurance_units)
                >= future_required
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqExitCoordinator {
    pub coordinator_id: String,
    pub operator_label: String,
    pub roles: Vec<PqCoordinatorRole>,
    pub pq_public_key_root: String,
    pub kem_key_root: String,
    pub stake_commitment: String,
    pub weight_bps: u64,
    pub joined_at_height: u64,
    pub last_attested_height: u64,
    pub slash_count: u64,
    pub status: CoordinatorStatus,
}

impl PqExitCoordinator {
    pub fn new(
        operator_label: &str,
        roles: Vec<PqCoordinatorRole>,
        pq_public_key: &str,
        kem_key: &str,
        stake_label: &str,
        weight_bps: u64,
        joined_at_height: u64,
    ) -> MoneroExitCircuitResult<Self> {
        ensure_non_empty(operator_label, "monero exit coordinator label")?;
        if roles.is_empty() {
            return Err("monero exit coordinator requires at least one role".to_string());
        }
        validate_bps(weight_bps, "monero exit coordinator weight bps")?;
        ensure_non_empty(pq_public_key, "monero exit coordinator pq key")?;
        ensure_non_empty(kem_key, "monero exit coordinator kem key")?;
        ensure_non_empty(stake_label, "monero exit coordinator stake label")?;
        let roles = canonical_roles(roles);
        let pq_public_key_root =
            monero_exit_string_root("MONERO-EXIT-COORDINATOR-PQ-KEY", pq_public_key);
        let kem_key_root = monero_exit_string_root("MONERO-EXIT-COORDINATOR-KEM", kem_key);
        let stake_commitment =
            monero_exit_string_root("MONERO-EXIT-COORDINATOR-STAKE", stake_label);
        let role_root = coordinator_role_root(&roles);
        let coordinator_id = monero_exit_pq_coordinator_id(&json!({
            "operator_label": operator_label,
            "role_root": role_root,
            "pq_public_key_root": pq_public_key_root,
            "kem_key_root": kem_key_root,
            "joined_at_height": joined_at_height,
        }));
        Ok(Self {
            coordinator_id,
            operator_label: operator_label.to_string(),
            roles,
            pq_public_key_root,
            kem_key_root,
            stake_commitment,
            weight_bps,
            joined_at_height,
            last_attested_height: 0,
            slash_count: 0,
            status: CoordinatorStatus::Active,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_exit_pq_coordinator",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "pq_suite": MONERO_EXIT_PQ_COORDINATOR_SUITE,
            "coordinator_id": self.coordinator_id,
            "operator_label": self.operator_label,
            "roles": self.roles.iter().map(|role| role.as_str()).collect::<Vec<_>>(),
            "role_root": coordinator_role_root(&self.roles),
            "pq_public_key_root": self.pq_public_key_root,
            "kem_key_root": self.kem_key_root,
            "stake_commitment": self.stake_commitment,
            "weight_bps": self.weight_bps,
            "joined_at_height": self.joined_at_height,
            "last_attested_height": self.last_attested_height,
            "slash_count": self.slash_count,
            "status": self.status.as_str(),
        })
    }

    pub fn has_role(&self, role: PqCoordinatorRole) -> bool {
        self.roles.contains(&role)
    }

    pub fn can_attest_for(&self, role: PqCoordinatorRole) -> bool {
        self.status.can_attest() && self.has_role(role)
    }

    pub fn mark_attested(&mut self, height: u64) {
        self.last_attested_height = self.last_attested_height.max(height);
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqCoordinatorAttestation {
    pub attestation_id: String,
    pub coordinator_id: String,
    pub coordinator_role: PqCoordinatorRole,
    pub subject_kind: String,
    pub subject_id: String,
    pub subject_root: String,
    pub statement_root: String,
    pub signature_root: String,
    pub pq_scheme: String,
    pub attested_at_height: u64,
    pub expires_at_height: u64,
    pub status: PqAttestationStatus,
}

impl PqCoordinatorAttestation {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        coordinator_id: &str,
        coordinator_role: PqCoordinatorRole,
        subject_kind: &str,
        subject_id: &str,
        subject_root: &str,
        statement: &Value,
        signature_label: &str,
        attested_at_height: u64,
        ttl_blocks: u64,
        pq_scheme: &str,
    ) -> MoneroExitCircuitResult<Self> {
        ensure_non_empty(coordinator_id, "monero exit attestation coordinator id")?;
        ensure_non_empty(subject_kind, "monero exit attestation subject kind")?;
        ensure_non_empty(subject_id, "monero exit attestation subject id")?;
        ensure_non_empty(subject_root, "monero exit attestation subject root")?;
        ensure_non_empty(signature_label, "monero exit attestation signature")?;
        ensure_non_empty(pq_scheme, "monero exit attestation scheme")?;
        let statement_root =
            monero_exit_payload_root("MONERO-EXIT-ATTESTATION-STATEMENT", statement);
        let signature_root =
            monero_exit_string_root("MONERO-EXIT-ATTESTATION-SIGNATURE", signature_label);
        let body = json!({
            "coordinator_id": coordinator_id,
            "coordinator_role": coordinator_role.as_str(),
            "subject_kind": subject_kind,
            "subject_id": subject_id,
            "subject_root": subject_root,
            "statement_root": statement_root,
            "attested_at_height": attested_at_height,
        });
        Ok(Self {
            attestation_id: monero_exit_pq_attestation_id(&body),
            coordinator_id: coordinator_id.to_string(),
            coordinator_role,
            subject_kind: subject_kind.to_string(),
            subject_id: subject_id.to_string(),
            subject_root: subject_root.to_string(),
            statement_root,
            signature_root,
            pq_scheme: pq_scheme.to_string(),
            attested_at_height,
            expires_at_height: attested_at_height.saturating_add(ttl_blocks.max(1)),
            status: PqAttestationStatus::Accepted,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_exit_pq_coordinator_attestation",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "attestation_id": self.attestation_id,
            "coordinator_id": self.coordinator_id,
            "coordinator_role": self.coordinator_role.as_str(),
            "subject_kind": self.subject_kind,
            "subject_id": self.subject_id,
            "subject_root": self.subject_root,
            "statement_root": self.statement_root,
            "signature_root": self.signature_root,
            "pq_scheme": self.pq_scheme,
            "attested_at_height": self.attested_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn expires_if_due(&mut self, height: u64) {
        if height >= self.expires_at_height && self.status == PqAttestationStatus::Accepted {
            self.status = PqAttestationStatus::Expired;
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReorgChallengeWindow {
    pub window_id: String,
    pub subject_kind: String,
    pub subject_id: String,
    pub subject_root: String,
    pub start_height: u64,
    pub soft_final_height: u64,
    pub hard_final_height: u64,
    pub challenge_deadline_height: u64,
    pub observed_monero_height: u64,
    pub canonical_block_hash: String,
    pub competing_block_hash: Option<String>,
    pub reorg_depth: u64,
    pub evidence_root: String,
    pub status: ReorgWindowStatus,
}

impl ReorgChallengeWindow {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        subject_kind: &str,
        subject_id: &str,
        subject_root: &str,
        start_height: u64,
        observed_monero_height: u64,
        canonical_block_hash: &str,
        config: &MoneroExitCircuitConfig,
    ) -> MoneroExitCircuitResult<Self> {
        ensure_non_empty(subject_kind, "monero exit reorg subject kind")?;
        ensure_non_empty(subject_id, "monero exit reorg subject id")?;
        ensure_non_empty(subject_root, "monero exit reorg subject root")?;
        ensure_non_empty(
            canonical_block_hash,
            "monero exit reorg canonical block hash",
        )?;
        let soft_final_height = start_height.saturating_add(config.soft_confirmations);
        let hard_final_height = start_height.saturating_add(config.monero_finality_depth);
        let challenge_deadline_height =
            hard_final_height.saturating_add(config.reorg_window_blocks);
        Ok(Self {
            window_id: monero_exit_reorg_window_id(
                subject_kind,
                subject_id,
                start_height,
                challenge_deadline_height,
            ),
            subject_kind: subject_kind.to_string(),
            subject_id: subject_id.to_string(),
            subject_root: subject_root.to_string(),
            start_height,
            soft_final_height,
            hard_final_height,
            challenge_deadline_height,
            observed_monero_height,
            canonical_block_hash: monero_exit_string_root(
                "MONERO-EXIT-CANONICAL-BLOCK",
                canonical_block_hash,
            ),
            competing_block_hash: None,
            reorg_depth: 0,
            evidence_root: merkle_root("MONERO-EXIT-REORG-EVIDENCE-EMPTY", &[]),
            status: ReorgWindowStatus::Tracking,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_exit_reorg_challenge_window",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "window_id": self.window_id,
            "subject_kind": self.subject_kind,
            "subject_id": self.subject_id,
            "subject_root": self.subject_root,
            "start_height": self.start_height,
            "soft_final_height": self.soft_final_height,
            "hard_final_height": self.hard_final_height,
            "challenge_deadline_height": self.challenge_deadline_height,
            "observed_monero_height": self.observed_monero_height,
            "canonical_block_hash": self.canonical_block_hash,
            "competing_block_hash": self.competing_block_hash,
            "reorg_depth": self.reorg_depth,
            "evidence_root": self.evidence_root,
            "status": self.status.as_str(),
        })
    }

    pub fn advance(&mut self, height: u64) {
        if matches!(
            self.status,
            ReorgWindowStatus::Challenged | ReorgWindowStatus::Reorged | ReorgWindowStatus::Closed
        ) {
            return;
        }
        if height >= self.challenge_deadline_height {
            self.status = ReorgWindowStatus::Closed;
        } else if height >= self.hard_final_height {
            self.status = ReorgWindowStatus::HardFinal;
        } else if height >= self.soft_final_height {
            self.status = ReorgWindowStatus::SoftFinal;
        }
    }

    pub fn observe_reorg(
        &mut self,
        competing_block_hash: &str,
        reorg_depth: u64,
        evidence: &Value,
    ) -> MoneroExitCircuitResult<()> {
        ensure_non_empty(competing_block_hash, "monero exit competing block hash")?;
        ensure_positive(reorg_depth, "monero exit reorg depth")?;
        self.competing_block_hash = Some(monero_exit_string_root(
            "MONERO-EXIT-COMPETING-BLOCK",
            competing_block_hash,
        ));
        self.reorg_depth = reorg_depth;
        self.evidence_root = monero_exit_payload_root("MONERO-EXIT-REORG-EVIDENCE", evidence);
        self.status = ReorgWindowStatus::Reorged;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExitChallenge {
    pub challenge_id: String,
    pub challenger_commitment: String,
    pub challenge_kind: ChallengeKind,
    pub subject_kind: String,
    pub subject_id: String,
    pub subject_root: String,
    pub evidence_root: String,
    pub bond_units: u64,
    pub opened_at_height: u64,
    pub response_deadline_height: u64,
    pub resolved_at_height: Option<u64>,
    pub resolution_root: Option<String>,
    pub status: ChallengeStatus,
}

impl ExitChallenge {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        challenger_commitment: &str,
        challenge_kind: ChallengeKind,
        subject_kind: &str,
        subject_id: &str,
        subject_root: &str,
        evidence: &Value,
        bond_units: u64,
        opened_at_height: u64,
        response_window_blocks: u64,
    ) -> MoneroExitCircuitResult<Self> {
        ensure_non_empty(challenger_commitment, "monero exit challenge challenger")?;
        ensure_non_empty(subject_kind, "monero exit challenge subject kind")?;
        ensure_non_empty(subject_id, "monero exit challenge subject id")?;
        ensure_non_empty(subject_root, "monero exit challenge subject root")?;
        let evidence_root = monero_exit_payload_root("MONERO-EXIT-CHALLENGE-EVIDENCE", evidence);
        let body = json!({
            "challenger_commitment": challenger_commitment,
            "challenge_kind": challenge_kind.as_str(),
            "subject_kind": subject_kind,
            "subject_id": subject_id,
            "subject_root": subject_root,
            "evidence_root": evidence_root,
            "opened_at_height": opened_at_height,
        });
        Ok(Self {
            challenge_id: monero_exit_challenge_id(&body),
            challenger_commitment: challenger_commitment.to_string(),
            challenge_kind,
            subject_kind: subject_kind.to_string(),
            subject_id: subject_id.to_string(),
            subject_root: subject_root.to_string(),
            evidence_root,
            bond_units,
            opened_at_height,
            response_deadline_height: opened_at_height
                .saturating_add(response_window_blocks.max(1)),
            resolved_at_height: None,
            resolution_root: None,
            status: ChallengeStatus::Open,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_exit_challenge",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "challenge_id": self.challenge_id,
            "challenger_commitment": self.challenger_commitment,
            "challenge_kind": self.challenge_kind.as_str(),
            "subject_kind": self.subject_kind,
            "subject_id": self.subject_id,
            "subject_root": self.subject_root,
            "evidence_root": self.evidence_root,
            "bond_units": self.bond_units,
            "opened_at_height": self.opened_at_height,
            "response_deadline_height": self.response_deadline_height,
            "resolved_at_height": self.resolved_at_height,
            "resolution_root": self.resolution_root,
            "status": self.status.as_str(),
        })
    }

    pub fn resolve(
        &mut self,
        upheld: bool,
        resolution: &Value,
        height: u64,
    ) -> MoneroExitCircuitResult<()> {
        if self.status.is_terminal() {
            return Err("monero exit challenge is already terminal".to_string());
        }
        self.resolution_root = Some(monero_exit_payload_root(
            "MONERO-EXIT-CHALLENGE-RESOLUTION",
            resolution,
        ));
        self.resolved_at_height = Some(height);
        self.status = if upheld {
            ChallengeStatus::Upheld
        } else {
            ChallengeStatus::Rejected
        };
        Ok(())
    }

    pub fn timeout_if_due(&mut self, height: u64) {
        if !self.status.is_terminal() && height >= self.response_deadline_height {
            self.status = ChallengeStatus::TimedOut;
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExitFeeSponsor {
    pub sponsor_id: String,
    pub sponsor_commitment: String,
    pub fee_asset_id: String,
    pub budget_units: u64,
    pub reserved_units: u64,
    pub spent_units: u64,
    pub max_fee_per_exit_units: u64,
    pub rebate_bps: u64,
    pub valid_from_height: u64,
    pub valid_until_height: u64,
    pub policy_root: String,
    pub status: SponsorshipStatus,
}

impl ExitFeeSponsor {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        sponsor_commitment: &str,
        fee_asset_id: &str,
        budget_units: u64,
        max_fee_per_exit_units: u64,
        rebate_bps: u64,
        valid_from_height: u64,
        valid_until_height: u64,
        policy: &Value,
    ) -> MoneroExitCircuitResult<Self> {
        ensure_non_empty(sponsor_commitment, "monero exit sponsor commitment")?;
        ensure_non_empty(fee_asset_id, "monero exit sponsor fee asset")?;
        ensure_positive(budget_units, "monero exit sponsor budget")?;
        ensure_positive(
            max_fee_per_exit_units,
            "monero exit sponsor max fee per exit",
        )?;
        validate_bps(rebate_bps, "monero exit sponsor rebate bps")?;
        if valid_until_height <= valid_from_height {
            return Err("monero exit sponsor validity window is inverted".to_string());
        }
        let policy_root = monero_exit_payload_root("MONERO-EXIT-SPONSOR-POLICY", policy);
        let body = json!({
            "sponsor_commitment": sponsor_commitment,
            "fee_asset_id": fee_asset_id,
            "budget_units": budget_units,
            "max_fee_per_exit_units": max_fee_per_exit_units,
            "rebate_bps": rebate_bps,
            "valid_from_height": valid_from_height,
            "valid_until_height": valid_until_height,
            "policy_root": policy_root,
        });
        Ok(Self {
            sponsor_id: monero_exit_fee_sponsor_id(&body),
            sponsor_commitment: sponsor_commitment.to_string(),
            fee_asset_id: fee_asset_id.to_string(),
            budget_units,
            reserved_units: 0,
            spent_units: 0,
            max_fee_per_exit_units,
            rebate_bps,
            valid_from_height,
            valid_until_height,
            policy_root,
            status: SponsorshipStatus::Open,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_exit_fee_sponsor",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "sponsor_id": self.sponsor_id,
            "sponsor_commitment": self.sponsor_commitment,
            "fee_asset_id": self.fee_asset_id,
            "budget_units": self.budget_units,
            "reserved_units": self.reserved_units,
            "spent_units": self.spent_units,
            "available_units": self.available_units(),
            "max_fee_per_exit_units": self.max_fee_per_exit_units,
            "rebate_bps": self.rebate_bps,
            "valid_from_height": self.valid_from_height,
            "valid_until_height": self.valid_until_height,
            "policy_root": self.policy_root,
            "status": self.status.as_str(),
        })
    }

    pub fn available_units(&self) -> u64 {
        self.budget_units
            .saturating_sub(self.reserved_units)
            .saturating_sub(self.spent_units)
    }

    pub fn usable_at(&self, height: u64) -> bool {
        self.status.is_usable()
            && height >= self.valid_from_height
            && height <= self.valid_until_height
            && self.available_units() > 0
    }

    pub fn reserve(&mut self, fee_units: u64, height: u64) -> MoneroExitCircuitResult<u64> {
        if !self.usable_at(height) {
            return Err("monero exit sponsor is not usable".to_string());
        }
        let discounted_fee = mul_bps(fee_units, self.rebate_bps).max(1);
        let reserved = discounted_fee
            .min(self.max_fee_per_exit_units)
            .min(self.available_units());
        ensure_positive(reserved, "monero exit sponsored fee reservation")?;
        self.reserved_units = self.reserved_units.saturating_add(reserved);
        self.status = if self.available_units() == 0 {
            SponsorshipStatus::Exhausted
        } else {
            SponsorshipStatus::Reserved
        };
        Ok(reserved)
    }

    pub fn apply_reserved(&mut self, reserved_units: u64) {
        let applied = reserved_units.min(self.reserved_units);
        self.reserved_units = self.reserved_units.saturating_sub(applied);
        self.spent_units = self.spent_units.saturating_add(applied);
        self.status = if self.available_units() == 0 && self.reserved_units == 0 {
            SponsorshipStatus::Exhausted
        } else {
            SponsorshipStatus::Applied
        };
    }

    pub fn expire_if_due(&mut self, height: u64) {
        if height > self.valid_until_height && !matches!(self.status, SponsorshipStatus::Revoked) {
            self.status = SponsorshipStatus::Expired;
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExitFeeSponsorship {
    pub sponsorship_id: String,
    pub sponsor_id: String,
    pub exit_id: String,
    pub fee_asset_id: String,
    pub requested_fee_units: u64,
    pub reserved_fee_units: u64,
    pub applied_fee_units: u64,
    pub rebate_bps: u64,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub status: SponsorshipStatus,
}

impl ExitFeeSponsorship {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        sponsor_id: &str,
        exit_id: &str,
        fee_asset_id: &str,
        requested_fee_units: u64,
        reserved_fee_units: u64,
        rebate_bps: u64,
        opened_at_height: u64,
        ttl_blocks: u64,
    ) -> MoneroExitCircuitResult<Self> {
        ensure_non_empty(sponsor_id, "monero exit sponsorship sponsor id")?;
        ensure_non_empty(exit_id, "monero exit sponsorship exit id")?;
        ensure_non_empty(fee_asset_id, "monero exit sponsorship fee asset id")?;
        ensure_positive(requested_fee_units, "monero exit sponsorship requested fee")?;
        ensure_positive(reserved_fee_units, "monero exit sponsorship reserved fee")?;
        validate_bps(rebate_bps, "monero exit sponsorship rebate bps")?;
        let body = json!({
            "sponsor_id": sponsor_id,
            "exit_id": exit_id,
            "fee_asset_id": fee_asset_id,
            "requested_fee_units": requested_fee_units,
            "reserved_fee_units": reserved_fee_units,
            "opened_at_height": opened_at_height,
        });
        Ok(Self {
            sponsorship_id: monero_exit_fee_sponsorship_id(&body),
            sponsor_id: sponsor_id.to_string(),
            exit_id: exit_id.to_string(),
            fee_asset_id: fee_asset_id.to_string(),
            requested_fee_units,
            reserved_fee_units,
            applied_fee_units: 0,
            rebate_bps,
            opened_at_height,
            expires_at_height: opened_at_height.saturating_add(ttl_blocks.max(1)),
            status: SponsorshipStatus::Reserved,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_exit_fee_sponsorship",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "sponsorship_id": self.sponsorship_id,
            "sponsor_id": self.sponsor_id,
            "exit_id": self.exit_id,
            "fee_asset_id": self.fee_asset_id,
            "requested_fee_units": self.requested_fee_units,
            "reserved_fee_units": self.reserved_fee_units,
            "applied_fee_units": self.applied_fee_units,
            "rebate_bps": self.rebate_bps,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn apply(&mut self) {
        self.applied_fee_units = self.reserved_fee_units;
        self.status = SponsorshipStatus::Applied;
    }

    pub fn expire_if_due(&mut self, height: u64) {
        if height >= self.expires_at_height && self.status == SponsorshipStatus::Reserved {
            self.status = SponsorshipStatus::Expired;
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivacyPreservingExitReceipt {
    pub receipt_id: String,
    pub exit_id: String,
    pub batch_id: Option<String>,
    pub nullifier_commitment: String,
    pub key_image_commitment: String,
    pub recipient_tag_root: String,
    pub amount_bucket: u64,
    pub fee_bucket: u64,
    pub private_payload_root: String,
    pub public_hint_root: String,
    pub reveal_after_height: u64,
    pub created_at_height: u64,
    pub spent_at_monero_height: Option<u64>,
    pub visibility: ReceiptVisibility,
    pub status: ReceiptStatus,
}

impl PrivacyPreservingExitReceipt {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        exit: &MoneroExitRequest,
        batch_id: Option<&str>,
        private_payload: &Value,
        public_hint: &Value,
        height: u64,
        reveal_delay_blocks: u64,
        amount_bucket_units: u64,
    ) -> MoneroExitCircuitResult<Self> {
        ensure_non_empty(&exit.exit_id, "monero exit receipt exit id")?;
        let nullifier_commitment = monero_exit_payload_root(
            "MONERO-EXIT-RECEIPT-NULLIFIER",
            &json!({
                "exit_id": exit.exit_id,
                "nullifier_hash": exit.nullifier_hash,
            }),
        );
        let key_image_commitment = monero_exit_payload_root(
            "MONERO-EXIT-RECEIPT-KEY-IMAGE",
            &json!({
                "exit_id": exit.exit_id,
                "key_image_hash": exit.key_image_hash,
            }),
        );
        let recipient_tag_root = monero_exit_payload_root(
            "MONERO-EXIT-RECEIPT-RECIPIENT-TAG",
            &json!({
                "recipient_address_hash": exit.recipient_address_hash,
                "privacy_tag_root": exit.privacy_tag_root,
            }),
        );
        let private_payload_root =
            monero_exit_payload_root("MONERO-EXIT-RECEIPT-PRIVATE-PAYLOAD", private_payload);
        let public_hint_root =
            monero_exit_payload_root("MONERO-EXIT-RECEIPT-PUBLIC-HINT", public_hint);
        let body = json!({
            "exit_id": exit.exit_id,
            "batch_id": batch_id,
            "nullifier_commitment": nullifier_commitment,
            "key_image_commitment": key_image_commitment,
            "private_payload_root": private_payload_root,
            "created_at_height": height,
        });
        Ok(Self {
            receipt_id: monero_exit_receipt_id(&body),
            exit_id: exit.exit_id.clone(),
            batch_id: batch_id.map(str::to_string),
            nullifier_commitment,
            key_image_commitment,
            recipient_tag_root,
            amount_bucket: monero_exit_amount_bucket(exit.amount_units, amount_bucket_units),
            fee_bucket: monero_exit_amount_bucket(exit.max_fee_units, amount_bucket_units),
            private_payload_root,
            public_hint_root,
            reveal_after_height: height.saturating_add(reveal_delay_blocks.max(1)),
            created_at_height: height,
            spent_at_monero_height: None,
            visibility: ReceiptVisibility::Private,
            status: ReceiptStatus::Committed,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_exit_privacy_preserving_receipt",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "receipt_scheme": MONERO_EXIT_RECEIPT_SCHEME,
            "receipt_id": self.receipt_id,
            "exit_id": self.exit_id,
            "batch_id": self.batch_id,
            "nullifier_commitment": self.nullifier_commitment,
            "key_image_commitment": self.key_image_commitment,
            "recipient_tag_root": self.recipient_tag_root,
            "amount_bucket": self.amount_bucket,
            "fee_bucket": self.fee_bucket,
            "private_payload_root": self.private_payload_root,
            "public_hint_root": self.public_hint_root,
            "reveal_after_height": self.reveal_after_height,
            "created_at_height": self.created_at_height,
            "spent_at_monero_height": self.spent_at_monero_height,
            "visibility": self.visibility.as_str(),
            "status": self.status.as_str(),
        })
    }

    pub fn receipt_root(&self) -> String {
        monero_exit_receipt_root_from_record(&self.public_record())
    }

    pub fn reveal_if_due(&mut self, height: u64) {
        if height >= self.reveal_after_height
            && self.visibility == ReceiptVisibility::Private
            && self.status == ReceiptStatus::Committed
        {
            self.visibility = ReceiptVisibility::PublicHint;
            self.status = ReceiptStatus::Revealed;
        }
    }

    pub fn mark_spent(&mut self, monero_height: u64) {
        self.spent_at_monero_height = Some(monero_height);
        self.status = ReceiptStatus::Spent;
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroExitEvent {
    pub event_id: String,
    pub event_kind: ExitEventKind,
    pub subject_kind: String,
    pub subject_id: String,
    pub subject_root: String,
    pub height: u64,
    pub sequence: u64,
    pub payload_root: String,
}

impl MoneroExitEvent {
    pub fn new(
        event_kind: ExitEventKind,
        subject_kind: &str,
        subject_id: &str,
        subject_root: &str,
        height: u64,
        sequence: u64,
        payload: &Value,
    ) -> MoneroExitCircuitResult<Self> {
        ensure_non_empty(subject_kind, "monero exit event subject kind")?;
        ensure_non_empty(subject_id, "monero exit event subject id")?;
        ensure_non_empty(subject_root, "monero exit event subject root")?;
        let payload_root = monero_exit_payload_root("MONERO-EXIT-EVENT-PAYLOAD", payload);
        let body = json!({
            "event_kind": event_kind.as_str(),
            "subject_kind": subject_kind,
            "subject_id": subject_id,
            "subject_root": subject_root,
            "height": height,
            "sequence": sequence,
            "payload_root": payload_root,
        });
        Ok(Self {
            event_id: monero_exit_event_id(&body),
            event_kind,
            subject_kind: subject_kind.to_string(),
            subject_id: subject_id.to_string(),
            subject_root: subject_root.to_string(),
            height,
            sequence,
            payload_root,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_exit_event",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "event_id": self.event_id,
            "event_kind": self.event_kind.as_str(),
            "subject_kind": self.subject_kind,
            "subject_id": self.subject_id,
            "subject_root": self.subject_root,
            "height": self.height,
            "sequence": self.sequence,
            "payload_root": self.payload_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroExitCircuitRoots {
    pub config_root: String,
    pub exit_request_root: String,
    pub batch_root: String,
    pub nullifier_registry_root: String,
    pub view_key_audit_root: String,
    pub reserve_coverage_root: String,
    pub pq_coordinator_root: String,
    pub pq_attestation_root: String,
    pub reorg_window_root: String,
    pub challenge_root: String,
    pub sponsor_root: String,
    pub sponsorship_root: String,
    pub receipt_root: String,
    pub event_root: String,
    pub public_record_root: String,
}

impl MoneroExitCircuitRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_exit_circuit_roots",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "config_root": self.config_root,
            "exit_request_root": self.exit_request_root,
            "batch_root": self.batch_root,
            "nullifier_registry_root": self.nullifier_registry_root,
            "view_key_audit_root": self.view_key_audit_root,
            "reserve_coverage_root": self.reserve_coverage_root,
            "pq_coordinator_root": self.pq_coordinator_root,
            "pq_attestation_root": self.pq_attestation_root,
            "reorg_window_root": self.reorg_window_root,
            "challenge_root": self.challenge_root,
            "sponsor_root": self.sponsor_root,
            "sponsorship_root": self.sponsorship_root,
            "receipt_root": self.receipt_root,
            "event_root": self.event_root,
            "public_record_root": self.public_record_root,
        })
    }

    pub fn state_root(&self) -> String {
        monero_exit_payload_root("MONERO-EXIT-ROOT-VECTOR", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroExitCircuitState {
    pub height: u64,
    pub monero_network: String,
    pub asset_id: String,
    pub config: MoneroExitCircuitConfig,
    pub exit_requests: BTreeMap<String, MoneroExitRequest>,
    pub batches: BTreeMap<String, MoneroExitBatch>,
    pub nullifier_registry: BTreeMap<String, NullifierReplayEntry>,
    pub nullifier_index: BTreeMap<String, String>,
    pub key_image_index: BTreeMap<String, String>,
    pub view_key_audits: BTreeMap<String, ViewKeyAuditCommitment>,
    pub reserve_snapshots: BTreeMap<String, ReserveCoverageSnapshot>,
    pub pq_coordinators: BTreeMap<String, PqExitCoordinator>,
    pub pq_attestations: BTreeMap<String, PqCoordinatorAttestation>,
    pub reorg_windows: BTreeMap<String, ReorgChallengeWindow>,
    pub challenges: BTreeMap<String, ExitChallenge>,
    pub sponsors: BTreeMap<String, ExitFeeSponsor>,
    pub sponsorships: BTreeMap<String, ExitFeeSponsorship>,
    pub receipts: BTreeMap<String, PrivacyPreservingExitReceipt>,
    pub events: BTreeMap<String, MoneroExitEvent>,
    pub public_records: BTreeMap<String, Value>,
}

impl Default for MoneroExitCircuitState {
    fn default() -> Self {
        let config = MoneroExitCircuitConfig::default();
        Self {
            height: 0,
            monero_network: config.monero_network.clone(),
            asset_id: config.asset_id.clone(),
            config,
            exit_requests: BTreeMap::new(),
            batches: BTreeMap::new(),
            nullifier_registry: BTreeMap::new(),
            nullifier_index: BTreeMap::new(),
            key_image_index: BTreeMap::new(),
            view_key_audits: BTreeMap::new(),
            reserve_snapshots: BTreeMap::new(),
            pq_coordinators: BTreeMap::new(),
            pq_attestations: BTreeMap::new(),
            reorg_windows: BTreeMap::new(),
            challenges: BTreeMap::new(),
            sponsors: BTreeMap::new(),
            sponsorships: BTreeMap::new(),
            receipts: BTreeMap::new(),
            events: BTreeMap::new(),
            public_records: BTreeMap::new(),
        }
    }
}

impl MoneroExitCircuitState {
    pub fn new(config: MoneroExitCircuitConfig) -> MoneroExitCircuitResult<Self> {
        config.validate()?;
        Ok(Self {
            height: 0,
            monero_network: config.monero_network.clone(),
            asset_id: config.asset_id.clone(),
            config,
            ..Self::default()
        })
    }

    pub fn devnet() -> MoneroExitCircuitResult<Self> {
        let config = MoneroExitCircuitConfig::devnet();
        let mut state = Self::new(config)?;
        state.set_height(MONERO_EXIT_DEVNET_HEIGHT);

        let coordinator_a = PqExitCoordinator::new(
            "devnet-exit-coordinator-a",
            vec![
                PqCoordinatorRole::Scheduler,
                PqCoordinatorRole::BatchSigner,
                PqCoordinatorRole::ReserveAuditor,
            ],
            "devnet-exit-coordinator-a-ml-dsa",
            "devnet-exit-coordinator-a-kem",
            "devnet-exit-coordinator-a-stake",
            3_700,
            100,
        )?;
        let coordinator_b = PqExitCoordinator::new(
            "devnet-exit-coordinator-b",
            vec![
                PqCoordinatorRole::BatchSigner,
                PqCoordinatorRole::Watchtower,
                PqCoordinatorRole::ChallengeResolver,
            ],
            "devnet-exit-coordinator-b-ml-dsa",
            "devnet-exit-coordinator-b-kem",
            "devnet-exit-coordinator-b-stake",
            3_500,
            100,
        )?;
        let coordinator_c = PqExitCoordinator::new(
            "devnet-exit-coordinator-c",
            vec![
                PqCoordinatorRole::SponsorAuditor,
                PqCoordinatorRole::ReserveAuditor,
                PqCoordinatorRole::Watchtower,
            ],
            "devnet-exit-coordinator-c-ml-dsa",
            "devnet-exit-coordinator-c-kem",
            "devnet-exit-coordinator-c-stake",
            2_800,
            100,
        )?;
        let coordinator_a_id = coordinator_a.coordinator_id.clone();
        let coordinator_b_id = coordinator_b.coordinator_id.clone();
        let coordinator_c_id = coordinator_c.coordinator_id.clone();
        state.add_coordinator(coordinator_a)?;
        state.add_coordinator(coordinator_b)?;
        state.add_coordinator(coordinator_c)?;

        let reserve_snapshot = ReserveCoverageSnapshot::new(
            &state.monero_network,
            &state.asset_id,
            &[
                "devnet-reserve-hot-address".to_string(),
                "devnet-reserve-warm-address".to_string(),
                "devnet-reserve-cold-address".to_string(),
            ],
            &json!({
                "reserve_statement": "devnet reserve covers queued exits",
                "monero_view_scan_height": 71,
                "proof_system": MONERO_EXIT_RESERVE_PROOF_SCHEME,
            }),
            &monero_exit_payload_root(
                "MONERO-EXIT-DEVNET-AUDIT-ROOT",
                &json!({"auditor": "devnet-auditor", "window": "genesis"}),
            ),
            2_750_000,
            125_000,
            410_000,
            20_000,
            250_000,
            72,
            state.height,
            &[
                "devnet-reserve-signer-a".to_string(),
                "devnet-reserve-signer-b".to_string(),
            ],
            &state.config,
        )?;
        let reserve_snapshot_id = reserve_snapshot.snapshot_id.clone();
        state.add_reserve_snapshot(reserve_snapshot)?;

        let sponsor = ExitFeeSponsor::new(
            "devnet-low-fee-sponsor",
            &state.config.fee_asset_id,
            MONERO_EXIT_DEFAULT_SPONSOR_POOL_UNITS,
            100,
            9_000,
            state.height.saturating_sub(12),
            state.height.saturating_add(240),
            &json!({
                "lane": "low_fee_exits",
                "eligibility": "amount_bucket<=50000",
                "auditor": coordinator_c_id,
            }),
        )?;
        let sponsor_id = sponsor.sponsor_id.clone();
        state.add_sponsor(sponsor)?;

        let exit_a = state.queue_exit(
            "devnet-requester-a",
            "devnet-l2-account-a",
            "48DevnetRecipientAddressA",
            120_000,
            ExitPriority::Sponsored,
            "devnet-privacy-tag-a",
            "devnet-nullifier-a",
            "devnet-key-image-a",
            "devnet-view-key-a",
            "seeded devnet sponsored withdrawal",
        )?;
        let exit_b = state.queue_exit(
            "devnet-requester-b",
            "devnet-l2-account-b",
            "48DevnetRecipientAddressB",
            210_000,
            ExitPriority::Fast,
            "devnet-privacy-tag-b",
            "devnet-nullifier-b",
            "devnet-key-image-b",
            "devnet-view-key-b",
            "seeded devnet fast withdrawal",
        )?;
        let exit_c = state.queue_exit(
            "devnet-requester-c",
            "devnet-l2-account-c",
            "48DevnetRecipientAddressC",
            80_000,
            ExitPriority::LowFee,
            "devnet-privacy-tag-c",
            "devnet-nullifier-c",
            "devnet-key-image-c",
            "devnet-view-key-c",
            "seeded devnet low fee withdrawal",
        )?;
        state.reserve_sponsorship_for_exit(&sponsor_id, &exit_a.exit_id)?;

        state.commit_view_key_audit(
            &exit_a.exit_id,
            "devnet-auditor-a",
            &exit_a.view_key_commitment,
            60,
            72,
            &[
                exit_a.recipient_address_hash.clone(),
                exit_b.recipient_address_hash.clone(),
            ],
            &[
                monero_exit_string_root("MONERO-EXIT-DEVNET-OUTPUT", "output-a"),
                monero_exit_string_root("MONERO-EXIT-DEVNET-OUTPUT", "output-b"),
            ],
            &json!({"encrypted": "devnet-audit-report-a"}),
            &json!({"mode": "auditor_only", "retention_blocks": 2880}),
        )?;
        state.commit_view_key_audit(
            &exit_b.exit_id,
            "devnet-auditor-b",
            &exit_b.view_key_commitment,
            61,
            73,
            &[exit_b.recipient_address_hash.clone()],
            &[monero_exit_string_root(
                "MONERO-EXIT-DEVNET-OUTPUT",
                "output-c",
            )],
            &json!({"encrypted": "devnet-audit-report-b"}),
            &json!({"mode": "challenge_reveal", "retention_blocks": 1440}),
        )?;

        let batch = state.seal_next_batch(&coordinator_a_id, &reserve_snapshot_id, 64)?;
        let batch_id = batch.batch_id.clone();
        let batch_subject = batch.subject_root();
        state.attest_subject(
            &coordinator_a_id,
            PqCoordinatorRole::BatchSigner,
            "batch",
            &batch_id,
            &batch_subject,
            &json!({"decision": "accept", "reserve_snapshot_id": reserve_snapshot_id}),
            "devnet-coordinator-a-batch-signature",
            96,
        )?;
        state.attest_subject(
            &coordinator_b_id,
            PqCoordinatorRole::BatchSigner,
            "batch",
            &batch_id,
            &batch_subject,
            &json!({"decision": "accept", "watchtower": true}),
            "devnet-coordinator-b-batch-signature",
            96,
        )?;
        state.refresh_batch_roots(&batch_id)?;
        state.issue_receipt(
            &exit_a.exit_id,
            Some(&batch_id),
            &json!({"encrypted_receipt": "exit-a-private"}),
            &json!({"bucket": exit_a.amount_bucket, "lane": "sponsored"}),
        )?;
        state.issue_receipt(
            &exit_b.exit_id,
            Some(&batch_id),
            &json!({"encrypted_receipt": "exit-b-private"}),
            &json!({"bucket": exit_b.amount_bucket, "lane": "fast"}),
        )?;
        state.issue_receipt(
            &exit_c.exit_id,
            Some(&batch_id),
            &json!({"encrypted_receipt": "exit-c-private"}),
            &json!({"bucket": exit_c.amount_bucket, "lane": "low_fee"}),
        )?;
        state.refresh_batch_roots(&batch_id)?;

        let window = ReorgChallengeWindow::new(
            "batch",
            &batch_id,
            &batch_subject,
            72,
            72,
            "devnet-monero-block-72",
            &state.config,
        )?;
        state.add_reorg_window(window)?;
        state.open_challenge(
            "devnet-watchtower-challenger",
            ChallengeKind::ReceiptRootMismatch,
            "batch",
            &batch_id,
            &batch_subject,
            &json!({
                "claimed_receipt_root": "legacy-devnet-root",
                "observed_receipt_root": state.batches.get(&batch_id).map(|b| b.receipt_root.clone()),
            }),
            25,
        )?;
        state.observe_batch_monero_tx(
            &batch_id,
            "devnet-monero-exit-txid-0",
            73,
            "devnet-monero-block-hash-73",
            82,
        )?;
        state.observe_nullifier_spend(
            &exit_a.nullifier_hash,
            "devnet-monero-exit-txid-0",
            73,
            &json!({"source": "devnet", "key_image": "devnet-key-image-a"}),
        )?;
        state.validate()?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) {
        self.height = height;
        for entry in self.nullifier_registry.values_mut() {
            entry.expire_if_due(height);
        }
        for sponsor in self.sponsors.values_mut() {
            sponsor.expire_if_due(height);
        }
        for sponsorship in self.sponsorships.values_mut() {
            sponsorship.expire_if_due(height);
        }
        for attestation in self.pq_attestations.values_mut() {
            attestation.expires_if_due(height);
        }
        for window in self.reorg_windows.values_mut() {
            window.advance(height);
        }
        for challenge in self.challenges.values_mut() {
            challenge.timeout_if_due(height);
        }
        for receipt in self.receipts.values_mut() {
            receipt.reveal_if_due(height);
        }
        for batch in self.batches.values_mut() {
            batch.mark_ready_if_window_closed(height);
        }
        let _ = self.record_event(
            ExitEventKind::StateAdvanced,
            "state",
            "monero_exit_circuit",
            &self.state_root(),
            &json!({"height": height}),
        );
        self.refresh_public_records();
    }

    #[allow(clippy::too_many_arguments)]
    pub fn queue_exit(
        &mut self,
        requester_commitment: &str,
        l2_account_commitment: &str,
        recipient_address: &str,
        amount_units: u64,
        priority: ExitPriority,
        privacy_tag: &str,
        nullifier: &str,
        key_image: &str,
        view_key_label: &str,
        memo: &str,
    ) -> MoneroExitCircuitResult<MoneroExitRequest> {
        let mut exit = MoneroExitRequest::new(
            requester_commitment,
            l2_account_commitment,
            recipient_address,
            amount_units,
            &self.config.fee_asset_id,
            priority,
            privacy_tag,
            nullifier,
            key_image,
            view_key_label,
            memo,
            self.height,
            &self.config,
        )?;
        self.ensure_replay_free(&exit.nullifier_hash, &exit.key_image_hash)?;
        exit.mark_queued();
        let exit_id = exit.exit_id.clone();
        self.register_nullifier_for_exit(&exit)?;
        self.exit_requests.insert(exit_id.clone(), exit.clone());
        self.record_event(
            ExitEventKind::ExitAccepted,
            "exit",
            &exit_id,
            &exit.exit_root(),
            &exit.public_record(),
        )?;
        self.refresh_public_records();
        Ok(exit)
    }

    pub fn add_coordinator(
        &mut self,
        coordinator: PqExitCoordinator,
    ) -> MoneroExitCircuitResult<String> {
        if self
            .pq_coordinators
            .contains_key(&coordinator.coordinator_id)
        {
            return Err("monero exit coordinator already exists".to_string());
        }
        let coordinator_id = coordinator.coordinator_id.clone();
        self.pq_coordinators
            .insert(coordinator_id.clone(), coordinator.clone());
        self.record_event(
            ExitEventKind::PqAttested,
            "coordinator",
            &coordinator_id,
            &monero_exit_pq_coordinator_root_from_record(&coordinator.public_record()),
            &coordinator.public_record(),
        )?;
        self.refresh_public_records();
        Ok(coordinator_id)
    }

    pub fn add_reserve_snapshot(
        &mut self,
        snapshot: ReserveCoverageSnapshot,
    ) -> MoneroExitCircuitResult<String> {
        if snapshot.monero_network != self.monero_network {
            return Err("monero exit reserve snapshot network mismatch".to_string());
        }
        if snapshot.asset_id != self.asset_id {
            return Err("monero exit reserve snapshot asset mismatch".to_string());
        }
        let snapshot_id = snapshot.snapshot_id.clone();
        self.reserve_snapshots
            .insert(snapshot_id.clone(), snapshot.clone());
        self.record_event(
            ExitEventKind::ReserveSnapshotAccepted,
            "reserve_snapshot",
            &snapshot_id,
            &monero_exit_reserve_coverage_root_from_record(&snapshot.public_record()),
            &snapshot.public_record(),
        )?;
        self.refresh_public_records();
        Ok(snapshot_id)
    }

    pub fn latest_healthy_reserve_snapshot(&self) -> Option<&ReserveCoverageSnapshot> {
        self.reserve_snapshots
            .values()
            .rev()
            .find(|snapshot| snapshot.status.admits_exits())
    }

    pub fn add_sponsor(&mut self, sponsor: ExitFeeSponsor) -> MoneroExitCircuitResult<String> {
        if sponsor.fee_asset_id != self.config.fee_asset_id {
            return Err("monero exit sponsor fee asset mismatch".to_string());
        }
        let sponsor_id = sponsor.sponsor_id.clone();
        self.sponsors.insert(sponsor_id.clone(), sponsor.clone());
        self.record_event(
            ExitEventKind::SponsorshipReserved,
            "sponsor",
            &sponsor_id,
            &monero_exit_fee_sponsor_root_from_record(&sponsor.public_record()),
            &sponsor.public_record(),
        )?;
        self.refresh_public_records();
        Ok(sponsor_id)
    }

    pub fn reserve_sponsorship_for_exit(
        &mut self,
        sponsor_id: &str,
        exit_id: &str,
    ) -> MoneroExitCircuitResult<ExitFeeSponsorship> {
        let exit = self
            .exit_requests
            .get(exit_id)
            .cloned()
            .ok_or_else(|| "unknown monero exit request".to_string())?;
        let sponsor = self
            .sponsors
            .get_mut(sponsor_id)
            .ok_or_else(|| "unknown monero exit fee sponsor".to_string())?;
        let reserved = sponsor.reserve(exit.max_fee_units, self.height)?;
        let sponsorship = ExitFeeSponsorship::new(
            sponsor_id,
            exit_id,
            &self.config.fee_asset_id,
            exit.max_fee_units,
            reserved,
            sponsor.rebate_bps,
            self.height,
            self.config.exit_ttl_blocks,
        )?;
        let sponsorship_id = sponsorship.sponsorship_id.clone();
        self.sponsorships
            .insert(sponsorship_id.clone(), sponsorship.clone());
        if let Some(exit) = self.exit_requests.get_mut(exit_id) {
            exit.apply_sponsorship(sponsorship_id.clone(), reserved);
        }
        self.record_event(
            ExitEventKind::SponsorshipReserved,
            "exit",
            exit_id,
            &monero_exit_fee_sponsorship_root_from_record(&sponsorship.public_record()),
            &sponsorship.public_record(),
        )?;
        self.refresh_public_records();
        Ok(sponsorship)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn commit_view_key_audit(
        &mut self,
        exit_id: &str,
        auditor_id: &str,
        view_key_commitment: &str,
        scan_window_start_height: u64,
        scan_window_end_height: u64,
        address_commitments: &[String],
        output_commitments: &[String],
        encrypted_report_payload: &Value,
        disclosure_policy: &Value,
    ) -> MoneroExitCircuitResult<ViewKeyAuditCommitment> {
        if !self.exit_requests.contains_key(exit_id) {
            return Err("unknown monero exit request for view key audit".to_string());
        }
        let audit = ViewKeyAuditCommitment::new(
            exit_id,
            auditor_id,
            view_key_commitment,
            scan_window_start_height,
            scan_window_end_height,
            address_commitments,
            output_commitments,
            encrypted_report_payload,
            disclosure_policy,
            self.height,
            self.config.view_audit_ttl_blocks,
        )?;
        let audit_id = audit.audit_id.clone();
        self.view_key_audits.insert(audit_id.clone(), audit.clone());
        self.record_event(
            ExitEventKind::ViewKeyAuditCommitted,
            "view_key_audit",
            &audit_id,
            &monero_exit_view_key_audit_root_from_record(&audit.public_record()),
            &audit.public_record(),
        )?;
        self.refresh_public_records();
        Ok(audit)
    }

    pub fn complete_view_key_audit(
        &mut self,
        audit_id: &str,
        encrypted_report_payload: &Value,
    ) -> MoneroExitCircuitResult<ViewKeyAuditCommitment> {
        let audit = self
            .view_key_audits
            .get_mut(audit_id)
            .ok_or_else(|| "unknown monero exit view key audit".to_string())?;
        audit.complete(self.height, encrypted_report_payload);
        let audit = audit.clone();
        self.record_event(
            ExitEventKind::ViewKeyAuditCommitted,
            "view_key_audit",
            audit_id,
            &monero_exit_view_key_audit_root_from_record(&audit.public_record()),
            &audit.public_record(),
        )?;
        self.refresh_public_records();
        Ok(audit)
    }

    pub fn seal_next_batch(
        &mut self,
        coordinator_id: &str,
        reserve_snapshot_id: &str,
        max_exits: usize,
    ) -> MoneroExitCircuitResult<MoneroExitBatch> {
        let coordinator = self
            .pq_coordinators
            .get(coordinator_id)
            .ok_or_else(|| "unknown monero exit coordinator".to_string())?;
        if !coordinator.can_attest_for(PqCoordinatorRole::Scheduler) {
            return Err("monero exit coordinator cannot schedule batches".to_string());
        }
        let reserve_snapshot = self
            .reserve_snapshots
            .get(reserve_snapshot_id)
            .ok_or_else(|| "unknown monero exit reserve snapshot".to_string())?;
        let mut selected = Vec::new();
        let mut total_units = 0_u64;
        let mut candidates = self
            .exit_requests
            .values()
            .filter(|exit| exit.can_batch_at(self.height))
            .cloned()
            .collect::<Vec<_>>();
        candidates.sort_by(|left, right| {
            right
                .priority
                .scheduling_score()
                .cmp(&left.priority.scheduling_score())
                .then_with(|| left.requested_at_height.cmp(&right.requested_at_height))
                .then_with(|| left.exit_id.cmp(&right.exit_id))
        });
        for exit in candidates {
            if selected.len() >= max_exits.min(self.config.max_batch_exits) {
                break;
            }
            let next_total = total_units.saturating_add(exit.amount_units);
            if next_total > self.config.max_batch_units {
                continue;
            }
            if !reserve_snapshot.admits_amount(next_total, &self.config) {
                continue;
            }
            selected.push(exit);
            total_units = next_total;
        }
        let batch = MoneroExitBatch::seal(
            coordinator_id,
            &self.monero_network,
            &self.asset_id,
            reserve_snapshot_id,
            &selected,
            self.height,
            &self.config,
        )?;
        let batch_id = batch.batch_id.clone();
        for exit_id in &batch.exit_ids {
            if let Some(exit) = self.exit_requests.get_mut(exit_id) {
                exit.mark_batched(batch_id.clone(), reserve_snapshot_id.to_string());
            }
            let key = self
                .nullifier_index
                .get(
                    &self
                        .exit_requests
                        .get(exit_id)
                        .map(|exit| exit.nullifier_hash.clone())
                        .unwrap_or_default(),
                )
                .cloned();
            if let Some(entry_id) = key {
                if let Some(entry) = self.nullifier_registry.get_mut(&entry_id) {
                    entry.mark_reserved(&batch_id);
                }
            }
        }
        self.batches.insert(batch_id.clone(), batch.clone());
        self.record_event(
            ExitEventKind::BatchSealed,
            "batch",
            &batch_id,
            &batch.batch_root(),
            &batch.public_record(),
        )?;
        self.refresh_public_records();
        Ok(batch)
    }

    pub fn attest_subject(
        &mut self,
        coordinator_id: &str,
        coordinator_role: PqCoordinatorRole,
        subject_kind: &str,
        subject_id: &str,
        subject_root: &str,
        statement: &Value,
        signature_label: &str,
        ttl_blocks: u64,
    ) -> MoneroExitCircuitResult<PqCoordinatorAttestation> {
        let coordinator = self
            .pq_coordinators
            .get_mut(coordinator_id)
            .ok_or_else(|| "unknown monero exit coordinator".to_string())?;
        if !coordinator.can_attest_for(coordinator_role) {
            return Err("monero exit coordinator lacks attestation role".to_string());
        }
        let attestation = PqCoordinatorAttestation::new(
            coordinator_id,
            coordinator_role,
            subject_kind,
            subject_id,
            subject_root,
            statement,
            signature_label,
            self.height,
            ttl_blocks,
            &self.config.pq_attestation_scheme,
        )?;
        coordinator.mark_attested(self.height);
        let attestation_id = attestation.attestation_id.clone();
        self.pq_attestations
            .insert(attestation_id.clone(), attestation.clone());
        self.record_event(
            ExitEventKind::PqAttested,
            subject_kind,
            subject_id,
            &attestation.subject_root,
            &attestation.public_record(),
        )?;
        self.refresh_public_records();
        Ok(attestation)
    }

    pub fn add_reorg_window(
        &mut self,
        window: ReorgChallengeWindow,
    ) -> MoneroExitCircuitResult<String> {
        let window_id = window.window_id.clone();
        self.reorg_windows.insert(window_id.clone(), window.clone());
        self.record_event(
            ExitEventKind::ReorgDetected,
            "reorg_window",
            &window_id,
            &monero_exit_reorg_window_root_from_record(&window.public_record()),
            &window.public_record(),
        )?;
        self.refresh_public_records();
        Ok(window_id)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn open_challenge(
        &mut self,
        challenger_commitment: &str,
        challenge_kind: ChallengeKind,
        subject_kind: &str,
        subject_id: &str,
        subject_root: &str,
        evidence: &Value,
        bond_units: u64,
    ) -> MoneroExitCircuitResult<ExitChallenge> {
        let challenge = ExitChallenge::new(
            challenger_commitment,
            challenge_kind,
            subject_kind,
            subject_id,
            subject_root,
            evidence,
            bond_units,
            self.height,
            self.config.challenge_window_blocks,
        )?;
        let challenge_id = challenge.challenge_id.clone();
        if subject_kind == "exit" {
            if let Some(exit) = self.exit_requests.get_mut(subject_id) {
                exit.status = ExitStatus::ChallengeOpen;
            }
        }
        if subject_kind == "batch" {
            if let Some(batch) = self.batches.get_mut(subject_id) {
                batch.status = ExitBatchStatus::ChallengeOpen;
            }
        }
        self.challenges
            .insert(challenge_id.clone(), challenge.clone());
        self.record_event(
            ExitEventKind::ChallengeOpened,
            subject_kind,
            subject_id,
            subject_root,
            &challenge.public_record(),
        )?;
        self.refresh_public_records();
        Ok(challenge)
    }

    pub fn resolve_challenge(
        &mut self,
        challenge_id: &str,
        upheld: bool,
        resolution: &Value,
    ) -> MoneroExitCircuitResult<ExitChallenge> {
        let challenge = self
            .challenges
            .get_mut(challenge_id)
            .ok_or_else(|| "unknown monero exit challenge".to_string())?;
        challenge.resolve(upheld, resolution, self.height)?;
        let challenge = challenge.clone();
        if challenge.subject_kind == "exit" {
            if let Some(exit) = self.exit_requests.get_mut(&challenge.subject_id) {
                exit.status = if upheld {
                    ExitStatus::Cancelled
                } else {
                    ExitStatus::ChallengeResolved
                };
            }
        }
        if challenge.subject_kind == "batch" {
            if let Some(batch) = self.batches.get_mut(&challenge.subject_id) {
                batch.status = if upheld {
                    ExitBatchStatus::Cancelled
                } else {
                    ExitBatchStatus::Ready
                };
            }
        }
        self.record_event(
            ExitEventKind::ChallengeResolved,
            &challenge.subject_kind,
            &challenge.subject_id,
            &challenge.subject_root,
            &challenge.public_record(),
        )?;
        self.refresh_public_records();
        Ok(challenge)
    }

    pub fn issue_receipt(
        &mut self,
        exit_id: &str,
        batch_id: Option<&str>,
        private_payload: &Value,
        public_hint: &Value,
    ) -> MoneroExitCircuitResult<PrivacyPreservingExitReceipt> {
        let exit = self
            .exit_requests
            .get(exit_id)
            .cloned()
            .ok_or_else(|| "unknown monero exit for receipt".to_string())?;
        if let Some(batch_id) = batch_id {
            if !self.batches.contains_key(batch_id) {
                return Err("unknown monero exit batch for receipt".to_string());
            }
        }
        let receipt = PrivacyPreservingExitReceipt::new(
            &exit,
            batch_id,
            private_payload,
            public_hint,
            self.height,
            self.config.receipt_reveal_delay_blocks,
            self.config.amount_bucket_units,
        )?;
        let receipt_id = receipt.receipt_id.clone();
        if let Some(exit) = self.exit_requests.get_mut(exit_id) {
            exit.attach_receipt(receipt_id.clone());
        }
        self.receipts.insert(receipt_id.clone(), receipt.clone());
        self.record_event(
            ExitEventKind::ReceiptCommitted,
            "receipt",
            &receipt_id,
            &receipt.receipt_root(),
            &receipt.public_record(),
        )?;
        self.refresh_public_records();
        Ok(receipt)
    }

    pub fn refresh_batch_roots(&mut self, batch_id: &str) -> MoneroExitCircuitResult<()> {
        let attestations = self.pq_attestations.values().cloned().collect::<Vec<_>>();
        let receipts = self.receipts.values().cloned().collect::<Vec<_>>();
        let batch = self
            .batches
            .get_mut(batch_id)
            .ok_or_else(|| "unknown monero exit batch".to_string())?;
        batch.update_attestation_root(&attestations);
        batch.attach_receipt_root(&receipts);
        self.refresh_public_records();
        Ok(())
    }

    pub fn observe_batch_monero_tx(
        &mut self,
        batch_id: &str,
        txid: &str,
        block_height: u64,
        block_hash: &str,
        current_monero_height: u64,
    ) -> MoneroExitCircuitResult<MoneroExitBatch> {
        let batch = self
            .batches
            .get_mut(batch_id)
            .ok_or_else(|| "unknown monero exit batch".to_string())?;
        batch.observe_monero_tx(
            txid,
            block_height,
            block_hash,
            current_monero_height,
            self.config.monero_finality_depth,
        )?;
        let batch = batch.clone();
        if batch.status == ExitBatchStatus::Confirmed {
            for exit_id in &batch.exit_ids {
                if let Some(exit) = self.exit_requests.get_mut(exit_id) {
                    exit.status = ExitStatus::MoneroConfirmed;
                }
            }
        }
        self.record_event(
            ExitEventKind::MoneroTxObserved,
            "batch",
            batch_id,
            &batch.batch_root(),
            &batch.public_record(),
        )?;
        self.refresh_public_records();
        Ok(batch)
    }

    pub fn observe_nullifier_spend(
        &mut self,
        nullifier_hash: &str,
        txid: &str,
        monero_height: u64,
        witness_payload: &Value,
    ) -> MoneroExitCircuitResult<NullifierReplayEntry> {
        let entry_id = self
            .nullifier_index
            .get(nullifier_hash)
            .cloned()
            .ok_or_else(|| "unknown monero exit nullifier".to_string())?;
        let entry = self
            .nullifier_registry
            .get_mut(&entry_id)
            .ok_or_else(|| "unknown monero exit nullifier entry".to_string())?;
        entry.observe_spend(txid, monero_height, witness_payload)?;
        let entry = entry.clone();
        for receipt in self
            .receipts
            .values_mut()
            .filter(|receipt| receipt.exit_id == entry.exit_id)
        {
            receipt.mark_spent(monero_height);
        }
        self.record_event(
            ExitEventKind::NullifierRegistered,
            "nullifier",
            &entry.registry_entry_id,
            &monero_exit_nullifier_registry_root_from_record(&entry.public_record()),
            &entry.public_record(),
        )?;
        self.refresh_public_records();
        Ok(entry)
    }

    pub fn raise_reorg(
        &mut self,
        window_id: &str,
        competing_block_hash: &str,
        reorg_depth: u64,
        evidence: &Value,
    ) -> MoneroExitCircuitResult<ReorgChallengeWindow> {
        let window = self
            .reorg_windows
            .get_mut(window_id)
            .ok_or_else(|| "unknown monero exit reorg window".to_string())?;
        window.observe_reorg(competing_block_hash, reorg_depth, evidence)?;
        let window = window.clone();
        if window.subject_kind == "batch" {
            if let Some(batch) = self.batches.get_mut(&window.subject_id) {
                batch.status = ExitBatchStatus::Reorged;
                for exit_id in &batch.exit_ids {
                    if let Some(exit) = self.exit_requests.get_mut(exit_id) {
                        exit.status = ExitStatus::Reorged;
                    }
                }
            }
        }
        self.record_event(
            ExitEventKind::ReorgDetected,
            &window.subject_kind,
            &window.subject_id,
            &window.subject_root,
            &window.public_record(),
        )?;
        self.refresh_public_records();
        Ok(window)
    }

    pub fn ready_exit_ids(&self) -> Vec<String> {
        self.exit_requests
            .values()
            .filter(|exit| exit.can_batch_at(self.height))
            .map(|exit| exit.exit_id.clone())
            .collect()
    }

    pub fn pending_exit_units(&self) -> u64 {
        self.exit_requests
            .values()
            .filter(|exit| exit.status.is_open())
            .map(|exit| exit.amount_units)
            .sum()
    }

    pub fn challenged_units(&self) -> u64 {
        self.exit_requests
            .values()
            .filter(|exit| exit.status == ExitStatus::ChallengeOpen)
            .map(|exit| exit.amount_units)
            .sum()
    }

    pub fn total_sponsored_fee_units(&self) -> u64 {
        self.exit_requests
            .values()
            .map(|exit| exit.sponsored_fee_units)
            .sum()
    }

    pub fn coordinator_weight_for_role(&self, role: PqCoordinatorRole) -> u64 {
        self.pq_coordinators
            .values()
            .filter(|coordinator| coordinator.can_attest_for(role))
            .map(|coordinator| coordinator.weight_bps)
            .sum::<u64>()
            .min(MONERO_EXIT_MAX_BPS)
    }

    pub fn attestation_quorum_met(&self, subject_kind: &str, subject_id: &str) -> bool {
        let mut coordinators = BTreeSet::new();
        let mut weight = 0_u64;
        for attestation in self.pq_attestations.values().filter(|attestation| {
            attestation.subject_kind == subject_kind
                && attestation.subject_id == subject_id
                && attestation.status == PqAttestationStatus::Accepted
        }) {
            if coordinators.insert(attestation.coordinator_id.clone()) {
                weight = weight.saturating_add(
                    self.pq_coordinators
                        .get(&attestation.coordinator_id)
                        .map(|coordinator| coordinator.weight_bps)
                        .unwrap_or(0),
                );
            }
        }
        coordinators.len() as u64 >= self.config.coordinator_quorum
            && weight >= self.config.min_coordinator_weight_bps
    }

    pub fn roots(&self) -> MoneroExitCircuitRoots {
        let public_record_root = keyed_record_root(
            "MONERO-EXIT-PUBLIC-RECORD-SET",
            self.public_records
                .iter()
                .map(|(key, record)| (key.clone(), record.clone()))
                .collect(),
        );
        MoneroExitCircuitRoots {
            config_root: self.config.config_root(),
            exit_request_root: monero_exit_request_set_root(
                &self.exit_requests.values().cloned().collect::<Vec<_>>(),
            ),
            batch_root: monero_exit_batch_set_root(
                &self.batches.values().cloned().collect::<Vec<_>>(),
            ),
            nullifier_registry_root: monero_exit_nullifier_registry_set_root(
                &self
                    .nullifier_registry
                    .values()
                    .cloned()
                    .collect::<Vec<_>>(),
            ),
            view_key_audit_root: monero_exit_view_key_audit_set_root(
                &self.view_key_audits.values().cloned().collect::<Vec<_>>(),
            ),
            reserve_coverage_root: monero_exit_reserve_coverage_set_root(
                &self.reserve_snapshots.values().cloned().collect::<Vec<_>>(),
            ),
            pq_coordinator_root: monero_exit_pq_coordinator_set_root(
                &self.pq_coordinators.values().cloned().collect::<Vec<_>>(),
            ),
            pq_attestation_root: monero_exit_pq_attestation_set_root(
                &self.pq_attestations.values().cloned().collect::<Vec<_>>(),
            ),
            reorg_window_root: monero_exit_reorg_window_set_root(
                &self.reorg_windows.values().cloned().collect::<Vec<_>>(),
            ),
            challenge_root: monero_exit_challenge_set_root(
                &self.challenges.values().cloned().collect::<Vec<_>>(),
            ),
            sponsor_root: monero_exit_fee_sponsor_set_root(
                &self.sponsors.values().cloned().collect::<Vec<_>>(),
            ),
            sponsorship_root: monero_exit_fee_sponsorship_set_root(
                &self.sponsorships.values().cloned().collect::<Vec<_>>(),
            ),
            receipt_root: monero_exit_receipt_set_root(
                &self.receipts.values().cloned().collect::<Vec<_>>(),
            ),
            event_root: monero_exit_event_set_root(
                &self.events.values().cloned().collect::<Vec<_>>(),
            ),
            public_record_root,
        }
    }

    pub fn state_root(&self) -> String {
        monero_exit_circuit_state_root_from_record(&self.public_record_without_root())
    }

    pub fn public_record(&self) -> Value {
        with_root_field(
            self.public_record_without_root(),
            "monero_exit_circuit_state_root",
            self.state_root(),
        )
    }

    pub fn validate(&self) -> MoneroExitCircuitResult<String> {
        self.config.validate()?;
        if self.monero_network != self.config.monero_network {
            return Err("monero exit state network mismatch".to_string());
        }
        if self.asset_id != self.config.asset_id {
            return Err("monero exit state asset mismatch".to_string());
        }
        for exit in self.exit_requests.values() {
            ensure_non_empty(&exit.exit_id, "monero exit request id")?;
            ensure_positive(exit.amount_units, "monero exit amount")?;
            if exit.fee_asset_id != self.config.fee_asset_id {
                return Err("monero exit fee asset mismatch".to_string());
            }
            if let Some(batch_id) = &exit.batch_id {
                let batch = self
                    .batches
                    .get(batch_id)
                    .ok_or_else(|| "monero exit references missing batch".to_string())?;
                if !batch.exit_ids.contains(&exit.exit_id) {
                    return Err("monero exit batch reverse link mismatch".to_string());
                }
            }
            if !self.nullifier_index.contains_key(&exit.nullifier_hash) {
                return Err("monero exit missing nullifier registry entry".to_string());
            }
        }
        for batch in self.batches.values() {
            if batch.monero_network != self.monero_network {
                return Err("monero exit batch network mismatch".to_string());
            }
            if batch.asset_id != self.asset_id {
                return Err("monero exit batch asset mismatch".to_string());
            }
            if !self
                .reserve_snapshots
                .contains_key(&batch.reserve_snapshot_id)
            {
                return Err("monero exit batch references missing reserve snapshot".to_string());
            }
            for exit_id in &batch.exit_ids {
                if !self.exit_requests.contains_key(exit_id) {
                    return Err("monero exit batch references missing exit".to_string());
                }
            }
        }
        for entry in self.nullifier_registry.values() {
            if !self.exit_requests.contains_key(&entry.exit_id) {
                return Err("monero exit nullifier references missing exit".to_string());
            }
        }
        for audit in self.view_key_audits.values() {
            if !self.exit_requests.contains_key(&audit.exit_id) {
                return Err("monero exit audit references missing exit".to_string());
            }
        }
        for snapshot in self.reserve_snapshots.values() {
            if snapshot.monero_network != self.monero_network || snapshot.asset_id != self.asset_id
            {
                return Err("monero exit reserve snapshot state mismatch".to_string());
            }
        }
        for attestation in self.pq_attestations.values() {
            if !self
                .pq_coordinators
                .contains_key(&attestation.coordinator_id)
            {
                return Err("monero exit attestation references missing coordinator".to_string());
            }
        }
        for sponsorship in self.sponsorships.values() {
            if !self.sponsors.contains_key(&sponsorship.sponsor_id) {
                return Err("monero exit sponsorship references missing sponsor".to_string());
            }
            if !self.exit_requests.contains_key(&sponsorship.exit_id) {
                return Err("monero exit sponsorship references missing exit".to_string());
            }
        }
        for receipt in self.receipts.values() {
            if !self.exit_requests.contains_key(&receipt.exit_id) {
                return Err("monero exit receipt references missing exit".to_string());
            }
            if let Some(batch_id) = &receipt.batch_id {
                if !self.batches.contains_key(batch_id) {
                    return Err("monero exit receipt references missing batch".to_string());
                }
            }
        }
        Ok(self.state_root())
    }

    fn ensure_replay_free(
        &self,
        nullifier_hash: &str,
        key_image_hash: &str,
    ) -> MoneroExitCircuitResult<()> {
        if let Some(entry_id) = self.nullifier_index.get(nullifier_hash) {
            let entry = self
                .nullifier_registry
                .get(entry_id)
                .ok_or_else(|| "monero exit nullifier index is stale".to_string())?;
            if entry.status.blocks_replay() {
                return Err("monero exit nullifier replay detected".to_string());
            }
        }
        if let Some(entry_id) = self.key_image_index.get(key_image_hash) {
            let entry = self
                .nullifier_registry
                .get(entry_id)
                .ok_or_else(|| "monero exit key image index is stale".to_string())?;
            if entry.status.blocks_replay() {
                return Err("monero exit key image replay detected".to_string());
            }
        }
        Ok(())
    }

    fn register_nullifier_for_exit(
        &mut self,
        exit: &MoneroExitRequest,
    ) -> MoneroExitCircuitResult<String> {
        let entry = NullifierReplayEntry::new(
            &exit.exit_id,
            &exit.nullifier_hash,
            &exit.key_image_hash,
            "nebula_l2_to_monero_exit",
            self.height,
            self.config.nullifier_retention_blocks,
        )?;
        let entry_id = entry.registry_entry_id.clone();
        self.nullifier_index
            .insert(entry.nullifier_hash.clone(), entry_id.clone());
        self.key_image_index
            .insert(entry.key_image_hash.clone(), entry_id.clone());
        self.nullifier_registry
            .insert(entry_id.clone(), entry.clone());
        self.record_event(
            ExitEventKind::NullifierRegistered,
            "nullifier",
            &entry_id,
            &monero_exit_nullifier_registry_root_from_record(&entry.public_record()),
            &entry.public_record(),
        )?;
        Ok(entry_id)
    }

    fn public_record_without_root(&self) -> Value {
        let roots = self.roots();
        json!({
            "kind": "monero_exit_circuit_state",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": MONERO_EXIT_CIRCUIT_SCHEMA_VERSION,
            "height": self.height,
            "monero_network": self.monero_network,
            "asset_id": self.asset_id,
            "config": self.config.public_record(),
            "roots": roots.public_record(),
            "root_commitment": roots.state_root(),
            "exit_request_count": self.exit_requests.len() as u64,
            "batch_count": self.batches.len() as u64,
            "nullifier_registry_count": self.nullifier_registry.len() as u64,
            "view_key_audit_count": self.view_key_audits.len() as u64,
            "reserve_snapshot_count": self.reserve_snapshots.len() as u64,
            "pq_coordinator_count": self.pq_coordinators.len() as u64,
            "pq_attestation_count": self.pq_attestations.len() as u64,
            "reorg_window_count": self.reorg_windows.len() as u64,
            "challenge_count": self.challenges.len() as u64,
            "sponsor_count": self.sponsors.len() as u64,
            "sponsorship_count": self.sponsorships.len() as u64,
            "receipt_count": self.receipts.len() as u64,
            "event_count": self.events.len() as u64,
            "ready_exit_count": self.ready_exit_ids().len() as u64,
            "pending_exit_units": self.pending_exit_units(),
            "challenged_units": self.challenged_units(),
            "total_sponsored_fee_units": self.total_sponsored_fee_units(),
            "batch_signer_weight_bps": self.coordinator_weight_for_role(PqCoordinatorRole::BatchSigner),
            "reserve_auditor_weight_bps": self.coordinator_weight_for_role(PqCoordinatorRole::ReserveAuditor),
        })
    }

    fn record_event(
        &mut self,
        event_kind: ExitEventKind,
        subject_kind: &str,
        subject_id: &str,
        subject_root: &str,
        payload: &Value,
    ) -> MoneroExitCircuitResult<String> {
        let sequence = self.events.len() as u64;
        let event = MoneroExitEvent::new(
            event_kind,
            subject_kind,
            subject_id,
            subject_root,
            self.height,
            sequence,
            payload,
        )?;
        let event_id = event.event_id.clone();
        self.events.insert(event_id.clone(), event);
        Ok(event_id)
    }

    fn refresh_public_records(&mut self) {
        self.public_records.clear();
        self.public_records
            .insert("config".to_string(), self.config.public_record());
        for exit in self.exit_requests.values() {
            self.public_records
                .insert(format!("exit:{}", exit.exit_id), exit.public_record());
        }
        for batch in self.batches.values() {
            self.public_records
                .insert(format!("batch:{}", batch.batch_id), batch.public_record());
        }
        for entry in self.nullifier_registry.values() {
            self.public_records.insert(
                format!("nullifier:{}", entry.registry_entry_id),
                entry.public_record(),
            );
        }
        for audit in self.view_key_audits.values() {
            self.public_records.insert(
                format!("view_key_audit:{}", audit.audit_id),
                audit.public_record(),
            );
        }
        for snapshot in self.reserve_snapshots.values() {
            self.public_records.insert(
                format!("reserve:{}", snapshot.snapshot_id),
                snapshot.public_record(),
            );
        }
        for coordinator in self.pq_coordinators.values() {
            self.public_records.insert(
                format!("coordinator:{}", coordinator.coordinator_id),
                coordinator.public_record(),
            );
        }
        for attestation in self.pq_attestations.values() {
            self.public_records.insert(
                format!("attestation:{}", attestation.attestation_id),
                attestation.public_record(),
            );
        }
        for window in self.reorg_windows.values() {
            self.public_records.insert(
                format!("reorg_window:{}", window.window_id),
                window.public_record(),
            );
        }
        for challenge in self.challenges.values() {
            self.public_records.insert(
                format!("challenge:{}", challenge.challenge_id),
                challenge.public_record(),
            );
        }
        for sponsor in self.sponsors.values() {
            self.public_records.insert(
                format!("sponsor:{}", sponsor.sponsor_id),
                sponsor.public_record(),
            );
        }
        for sponsorship in self.sponsorships.values() {
            self.public_records.insert(
                format!("sponsorship:{}", sponsorship.sponsorship_id),
                sponsorship.public_record(),
            );
        }
        for receipt in self.receipts.values() {
            self.public_records.insert(
                format!("receipt:{}", receipt.receipt_id),
                receipt.public_record(),
            );
        }
        for event in self.events.values() {
            self.public_records
                .insert(format!("event:{}", event.event_id), event.public_record());
        }
    }
}

pub fn monero_exit_request_id(record: &Value) -> String {
    monero_exit_payload_root("MONERO-EXIT-REQUEST-ID", record)
}

pub fn monero_exit_batch_id(record: &Value) -> String {
    monero_exit_payload_root("MONERO-EXIT-BATCH-ID", record)
}

pub fn monero_exit_nullifier_registry_entry_id(record: &Value) -> String {
    monero_exit_payload_root("MONERO-EXIT-NULLIFIER-ENTRY-ID", record)
}

pub fn monero_exit_view_key_audit_id(record: &Value) -> String {
    monero_exit_payload_root("MONERO-EXIT-VIEW-KEY-AUDIT-ID", record)
}

pub fn monero_exit_reserve_coverage_snapshot_id(record: &Value) -> String {
    monero_exit_payload_root("MONERO-EXIT-RESERVE-COVERAGE-SNAPSHOT-ID", record)
}

pub fn monero_exit_pq_coordinator_id(record: &Value) -> String {
    monero_exit_payload_root("MONERO-EXIT-PQ-COORDINATOR-ID", record)
}

pub fn monero_exit_pq_attestation_id(record: &Value) -> String {
    monero_exit_payload_root("MONERO-EXIT-PQ-ATTESTATION-ID", record)
}

pub fn monero_exit_reorg_window_id(
    subject_kind: &str,
    subject_id: &str,
    start_height: u64,
    deadline_height: u64,
) -> String {
    monero_exit_payload_root(
        "MONERO-EXIT-REORG-WINDOW-ID",
        &json!({
            "subject_kind": subject_kind,
            "subject_id": subject_id,
            "start_height": start_height,
            "deadline_height": deadline_height,
        }),
    )
}

pub fn monero_exit_challenge_id(record: &Value) -> String {
    monero_exit_payload_root("MONERO-EXIT-CHALLENGE-ID", record)
}

pub fn monero_exit_fee_sponsor_id(record: &Value) -> String {
    monero_exit_payload_root("MONERO-EXIT-FEE-SPONSOR-ID", record)
}

pub fn monero_exit_fee_sponsorship_id(record: &Value) -> String {
    monero_exit_payload_root("MONERO-EXIT-FEE-SPONSORSHIP-ID", record)
}

pub fn monero_exit_receipt_id(record: &Value) -> String {
    monero_exit_payload_root("MONERO-EXIT-RECEIPT-ID", record)
}

pub fn monero_exit_event_id(record: &Value) -> String {
    monero_exit_payload_root("MONERO-EXIT-EVENT-ID", record)
}

pub fn monero_exit_record_root_from_record(record: &Value) -> String {
    monero_exit_payload_root("MONERO-EXIT-REQUEST-ROOT", record)
}

pub fn monero_exit_batch_root_from_record(record: &Value) -> String {
    monero_exit_payload_root("MONERO-EXIT-BATCH-ROOT", record)
}

pub fn monero_exit_nullifier_registry_root_from_record(record: &Value) -> String {
    monero_exit_payload_root("MONERO-EXIT-NULLIFIER-ROOT", record)
}

pub fn monero_exit_view_key_audit_root_from_record(record: &Value) -> String {
    monero_exit_payload_root("MONERO-EXIT-VIEW-KEY-AUDIT-ROOT", record)
}

pub fn monero_exit_reserve_coverage_root_from_record(record: &Value) -> String {
    monero_exit_payload_root("MONERO-EXIT-RESERVE-COVERAGE-ROOT", record)
}

pub fn monero_exit_pq_coordinator_root_from_record(record: &Value) -> String {
    monero_exit_payload_root("MONERO-EXIT-PQ-COORDINATOR-ROOT", record)
}

pub fn monero_exit_pq_attestation_root_from_record(record: &Value) -> String {
    monero_exit_payload_root("MONERO-EXIT-PQ-ATTESTATION-ROOT", record)
}

pub fn monero_exit_reorg_window_root_from_record(record: &Value) -> String {
    monero_exit_payload_root("MONERO-EXIT-REORG-WINDOW-ROOT", record)
}

pub fn monero_exit_challenge_root_from_record(record: &Value) -> String {
    monero_exit_payload_root("MONERO-EXIT-CHALLENGE-ROOT", record)
}

pub fn monero_exit_fee_sponsor_root_from_record(record: &Value) -> String {
    monero_exit_payload_root("MONERO-EXIT-FEE-SPONSOR-ROOT", record)
}

pub fn monero_exit_fee_sponsorship_root_from_record(record: &Value) -> String {
    monero_exit_payload_root("MONERO-EXIT-FEE-SPONSORSHIP-ROOT", record)
}

pub fn monero_exit_receipt_root_from_record(record: &Value) -> String {
    monero_exit_payload_root("MONERO-EXIT-RECEIPT-ROOT", record)
}

pub fn monero_exit_event_root_from_record(record: &Value) -> String {
    monero_exit_payload_root("MONERO-EXIT-EVENT-ROOT", record)
}

pub fn monero_exit_circuit_state_root_from_record(record: &Value) -> String {
    monero_exit_payload_root("MONERO-EXIT-CIRCUIT-STATE", record)
}

pub fn monero_exit_circuit_state_root(state: &MoneroExitCircuitState) -> String {
    state.state_root()
}

pub fn monero_exit_request_set_root(exits: &[MoneroExitRequest]) -> String {
    keyed_record_root(
        "MONERO-EXIT-REQUEST-SET",
        exits
            .iter()
            .map(|exit| (exit.exit_id.clone(), exit.public_record()))
            .collect(),
    )
}

pub fn monero_exit_batch_set_root(batches: &[MoneroExitBatch]) -> String {
    keyed_record_root(
        "MONERO-EXIT-BATCH-SET",
        batches
            .iter()
            .map(|batch| (batch.batch_id.clone(), batch.public_record()))
            .collect(),
    )
}

pub fn monero_exit_nullifier_registry_set_root(entries: &[NullifierReplayEntry]) -> String {
    keyed_record_root(
        "MONERO-EXIT-NULLIFIER-SET",
        entries
            .iter()
            .map(|entry| (entry.registry_entry_id.clone(), entry.public_record()))
            .collect(),
    )
}

pub fn monero_exit_view_key_audit_set_root(audits: &[ViewKeyAuditCommitment]) -> String {
    keyed_record_root(
        "MONERO-EXIT-VIEW-KEY-AUDIT-SET",
        audits
            .iter()
            .map(|audit| (audit.audit_id.clone(), audit.public_record()))
            .collect(),
    )
}

pub fn monero_exit_reserve_coverage_set_root(snapshots: &[ReserveCoverageSnapshot]) -> String {
    keyed_record_root(
        "MONERO-EXIT-RESERVE-COVERAGE-SET",
        snapshots
            .iter()
            .map(|snapshot| (snapshot.snapshot_id.clone(), snapshot.public_record()))
            .collect(),
    )
}

pub fn monero_exit_pq_coordinator_set_root(coordinators: &[PqExitCoordinator]) -> String {
    keyed_record_root(
        "MONERO-EXIT-PQ-COORDINATOR-SET",
        coordinators
            .iter()
            .map(|coordinator| {
                (
                    coordinator.coordinator_id.clone(),
                    coordinator.public_record(),
                )
            })
            .collect(),
    )
}

pub fn monero_exit_pq_attestation_set_root(attestations: &[PqCoordinatorAttestation]) -> String {
    keyed_record_root(
        "MONERO-EXIT-PQ-ATTESTATION-SET",
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

pub fn monero_exit_reorg_window_set_root(windows: &[ReorgChallengeWindow]) -> String {
    keyed_record_root(
        "MONERO-EXIT-REORG-WINDOW-SET",
        windows
            .iter()
            .map(|window| (window.window_id.clone(), window.public_record()))
            .collect(),
    )
}

pub fn monero_exit_challenge_set_root(challenges: &[ExitChallenge]) -> String {
    keyed_record_root(
        "MONERO-EXIT-CHALLENGE-SET",
        challenges
            .iter()
            .map(|challenge| (challenge.challenge_id.clone(), challenge.public_record()))
            .collect(),
    )
}

pub fn monero_exit_fee_sponsor_set_root(sponsors: &[ExitFeeSponsor]) -> String {
    keyed_record_root(
        "MONERO-EXIT-FEE-SPONSOR-SET",
        sponsors
            .iter()
            .map(|sponsor| (sponsor.sponsor_id.clone(), sponsor.public_record()))
            .collect(),
    )
}

pub fn monero_exit_fee_sponsorship_set_root(sponsorships: &[ExitFeeSponsorship]) -> String {
    keyed_record_root(
        "MONERO-EXIT-FEE-SPONSORSHIP-SET",
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

pub fn monero_exit_receipt_set_root(receipts: &[PrivacyPreservingExitReceipt]) -> String {
    keyed_record_root(
        "MONERO-EXIT-RECEIPT-SET",
        receipts
            .iter()
            .map(|receipt| (receipt.receipt_id.clone(), receipt.public_record()))
            .collect(),
    )
}

pub fn monero_exit_event_set_root(events: &[MoneroExitEvent]) -> String {
    keyed_record_root(
        "MONERO-EXIT-EVENT-SET",
        events
            .iter()
            .map(|event| (event.event_id.clone(), event.public_record()))
            .collect(),
    )
}

pub fn monero_exit_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub fn monero_exit_string_root(domain: &str, value: &str) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(value),
        ],
        32,
    )
}

pub fn monero_exit_string_set_root(domain: &str, values: &[String]) -> String {
    let mut values = values.to_vec();
    values.sort();
    values.dedup();
    let leaves = values.into_iter().map(Value::String).collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

pub fn monero_exit_nullifier_hash(nullifier: &str) -> String {
    monero_exit_string_root("MONERO-EXIT-NULLIFIER-HASH", nullifier)
}

pub fn monero_exit_key_image_hash(key_image: &str) -> String {
    monero_exit_string_root("MONERO-EXIT-KEY-IMAGE-HASH", key_image)
}

pub fn monero_exit_txid_hash(txid: &str) -> String {
    monero_exit_string_root("MONERO-EXIT-TXID-HASH", txid)
}

pub fn monero_exit_amount_bucket(amount_units: u64, bucket_units: u64) -> u64 {
    if bucket_units == 0 {
        amount_units
    } else {
        amount_units
            .div_ceil(bucket_units)
            .saturating_mul(bucket_units)
    }
}

pub fn ratio_bps(numerator: u64, denominator: u64) -> u64 {
    if denominator == 0 {
        return MONERO_EXIT_MAX_BPS;
    }
    ((numerator as u128).saturating_mul(MONERO_EXIT_MAX_BPS as u128) / denominator as u128)
        .min(u64::MAX as u128) as u64
}

pub fn mul_bps(amount_units: u64, bps: u64) -> u64 {
    ((amount_units as u128).saturating_mul(bps as u128) / MONERO_EXIT_MAX_BPS as u128)
        .min(u64::MAX as u128) as u64
}

pub fn confirmations(current_height: u64, block_height: u64) -> u64 {
    current_height
        .saturating_sub(block_height)
        .saturating_add(1)
}

fn reserve_status(
    coverage_bps: u64,
    min_coverage_bps: u64,
    warn_coverage_bps: u64,
) -> ReserveCoverageStatus {
    if coverage_bps < min_coverage_bps {
        ReserveCoverageStatus::Shortfall
    } else if coverage_bps < warn_coverage_bps {
        ReserveCoverageStatus::Watch
    } else {
        ReserveCoverageStatus::Healthy
    }
}

fn coordinator_role_root(roles: &[PqCoordinatorRole]) -> String {
    let role_values = roles
        .iter()
        .map(|role| Value::String(role.as_str().to_string()))
        .collect::<Vec<_>>();
    merkle_root("MONERO-EXIT-COORDINATOR-ROLE", &role_values)
}

fn canonical_roles(roles: Vec<PqCoordinatorRole>) -> Vec<PqCoordinatorRole> {
    roles
        .into_iter()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn keyed_record_root(domain: &str, records: BTreeMap<String, Value>) -> String {
    let leaves = records
        .into_iter()
        .map(|(key, record)| {
            json!({
                "key": key,
                "record": record,
            })
        })
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn with_root_field(mut record: Value, field_name: &str, root: String) -> Value {
    if let Some(object) = record.as_object_mut() {
        object.insert(field_name.to_string(), Value::String(root));
    }
    record
}

fn ensure_non_empty(value: &str, label: &str) -> MoneroExitCircuitResult<()> {
    if value.trim().is_empty() {
        Err(format!("{label} is required"))
    } else {
        Ok(())
    }
}

fn ensure_positive(value: u64, label: &str) -> MoneroExitCircuitResult<()> {
    if value == 0 {
        Err(format!("{label} must be positive"))
    } else {
        Ok(())
    }
}

fn validate_bps(value: u64, label: &str) -> MoneroExitCircuitResult<()> {
    if value > MONERO_EXIT_MAX_BPS {
        Err(format!("{label} cannot exceed {MONERO_EXIT_MAX_BPS}"))
    } else {
        Ok(())
    }
}

fn validate_coverage_bps(value: u64, label: &str) -> MoneroExitCircuitResult<()> {
    if value == 0 {
        return Err(format!("{label} must be positive"));
    }
    if value > MONERO_EXIT_MAX_BPS.saturating_mul(4) {
        Err(format!(
            "{label} cannot exceed {}",
            MONERO_EXIT_MAX_BPS.saturating_mul(4)
        ))
    } else {
        Ok(())
    }
}
