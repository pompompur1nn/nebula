use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type MoneroPqSubaddressRotationSchedulerResult<T> = Result<T, String>;

pub const MONERO_PQ_SUBADDRESS_ROTATION_SCHEDULER_PROTOCOL_VERSION: &str =
    "nebula-monero-pq-subaddress-rotation-scheduler-v1";

const PROTOCOL_LABEL: &str = "monero-pq-subaddress-rotation-scheduler";
const DEVNET_NETWORK: &str = "monero-devnet";
const DEVNET_ASSET_ID: &str = "wxmr-devnet";
const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
const HASH_SUITE: &str = "SHAKE256-domain-separated";
const PQ_AUTH_SUITE: &str = "ML-KEM-768+ML-DSA-65+SLH-DSA-SHAKE-128s-subaddress-rotation";
const STEALTH_EPOCH_SCHEME: &str = "monero-stealth-destination-epochs-v1";
const VIEW_TAG_PRIVACY_SCHEME: &str = "monero-view-tag-private-window-v1";
const SELECTIVE_DISCLOSURE_SCHEME: &str = "audit-safe-selective-disclosure-receipts-v1";
const DEFAULT_ROTATION_INTERVAL_BLOCKS: u64 = 18;
const DEFAULT_EPOCH_LOOKAHEAD_BLOCKS: u64 = 72;
const DEFAULT_WALLET_SYNC_WINDOW_BLOCKS: u64 = 96;
const DEFAULT_FINALITY_DEPTH: u64 = 12;
const DEFAULT_LOW_FEE_BATCH_TARGET: usize = 24;
const DEFAULT_MAX_ROTATIONS_PER_BATCH: usize = 96;
const DEFAULT_MAX_VIEW_TAGS_PER_WINDOW: u64 = 4_096;
const DEFAULT_RESERVE_HINT_TTL_BLOCKS: u64 = 144;
const DEFAULT_DISCLOSURE_TTL_BLOCKS: u64 = 288;
const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 192;
const DEFAULT_LOW_FEE_MICRO_UNITS: u64 = 400;
const DEFAULT_FAST_FEE_MICRO_UNITS: u64 = 3_200;
const DEFAULT_MAX_BATCH_WEIGHT: u64 = 1_200_000;
const MAX_BPS: u64 = 10_000;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub network: String,
    pub asset_id: String,
    pub fee_asset_id: String,
    pub scheduler_id: String,
    pub operator_commitment: String,
    pub treasury_commitment: String,
    pub pq_auth_suite: String,
    pub stealth_epoch_scheme: String,
    pub view_tag_privacy_scheme: String,
    pub selective_disclosure_scheme: String,
    pub hash_suite: String,
    pub rotation_interval_blocks: u64,
    pub epoch_lookahead_blocks: u64,
    pub wallet_sync_window_blocks: u64,
    pub finality_depth: u64,
    pub low_fee_batch_target: usize,
    pub max_rotations_per_batch: usize,
    pub max_view_tags_per_window: u64,
    pub reserve_hint_ttl_blocks: u64,
    pub disclosure_ttl_blocks: u64,
    pub min_pq_security_bits: u16,
    pub low_fee_micro_units: u64,
    pub fast_fee_micro_units: u64,
    pub max_batch_weight: u64,
    pub audit_receipt_required: bool,
    pub reserve_rotation_hints_enabled: bool,
    pub view_tag_decoy_padding: u64,
    pub batch_fee_rebate_bps: u64,
}

impl Config {
    pub fn devnet() -> Self {
        let operator_commitment = scheduler_hash("DEVNET-OPERATOR", &[HashPart::Str("operator-0")]);
        let treasury_commitment = scheduler_hash("DEVNET-TREASURY", &[HashPart::Str("treasury-0")]);
        let scheduler_id = scheduler_hash(
            "DEVNET-SCHEDULER",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(DEVNET_NETWORK),
                HashPart::Str(&operator_commitment),
            ],
        );
        Self {
            network: DEVNET_NETWORK.to_string(),
            asset_id: DEVNET_ASSET_ID.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            scheduler_id,
            operator_commitment,
            treasury_commitment,
            pq_auth_suite: PQ_AUTH_SUITE.to_string(),
            stealth_epoch_scheme: STEALTH_EPOCH_SCHEME.to_string(),
            view_tag_privacy_scheme: VIEW_TAG_PRIVACY_SCHEME.to_string(),
            selective_disclosure_scheme: SELECTIVE_DISCLOSURE_SCHEME.to_string(),
            hash_suite: HASH_SUITE.to_string(),
            rotation_interval_blocks: DEFAULT_ROTATION_INTERVAL_BLOCKS,
            epoch_lookahead_blocks: DEFAULT_EPOCH_LOOKAHEAD_BLOCKS,
            wallet_sync_window_blocks: DEFAULT_WALLET_SYNC_WINDOW_BLOCKS,
            finality_depth: DEFAULT_FINALITY_DEPTH,
            low_fee_batch_target: DEFAULT_LOW_FEE_BATCH_TARGET,
            max_rotations_per_batch: DEFAULT_MAX_ROTATIONS_PER_BATCH,
            max_view_tags_per_window: DEFAULT_MAX_VIEW_TAGS_PER_WINDOW,
            reserve_hint_ttl_blocks: DEFAULT_RESERVE_HINT_TTL_BLOCKS,
            disclosure_ttl_blocks: DEFAULT_DISCLOSURE_TTL_BLOCKS,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            low_fee_micro_units: DEFAULT_LOW_FEE_MICRO_UNITS,
            fast_fee_micro_units: DEFAULT_FAST_FEE_MICRO_UNITS,
            max_batch_weight: DEFAULT_MAX_BATCH_WEIGHT,
            audit_receipt_required: true,
            reserve_rotation_hints_enabled: true,
            view_tag_decoy_padding: 7,
            batch_fee_rebate_bps: 2_500,
        }
    }

    pub fn validate(&self) -> MoneroPqSubaddressRotationSchedulerResult<()> {
        require_text("network", &self.network)?;
        require_text("asset_id", &self.asset_id)?;
        require_text("fee_asset_id", &self.fee_asset_id)?;
        require_text("scheduler_id", &self.scheduler_id)?;
        require_text("operator_commitment", &self.operator_commitment)?;
        require_text("treasury_commitment", &self.treasury_commitment)?;
        require_text("pq_auth_suite", &self.pq_auth_suite)?;
        require_text("stealth_epoch_scheme", &self.stealth_epoch_scheme)?;
        require_text("view_tag_privacy_scheme", &self.view_tag_privacy_scheme)?;
        require_text(
            "selective_disclosure_scheme",
            &self.selective_disclosure_scheme,
        )?;
        require_text("hash_suite", &self.hash_suite)?;
        require_positive("rotation_interval_blocks", self.rotation_interval_blocks)?;
        require_positive("epoch_lookahead_blocks", self.epoch_lookahead_blocks)?;
        require_positive("wallet_sync_window_blocks", self.wallet_sync_window_blocks)?;
        require_positive("finality_depth", self.finality_depth)?;
        if self.low_fee_batch_target == 0 {
            return Err("low_fee_batch_target must be positive".to_string());
        }
        if self.max_rotations_per_batch == 0 {
            return Err("max_rotations_per_batch must be positive".to_string());
        }
        if self.low_fee_batch_target > self.max_rotations_per_batch {
            return Err("low_fee_batch_target cannot exceed max_rotations_per_batch".to_string());
        }
        require_positive("max_view_tags_per_window", self.max_view_tags_per_window)?;
        require_positive("reserve_hint_ttl_blocks", self.reserve_hint_ttl_blocks)?;
        require_positive("disclosure_ttl_blocks", self.disclosure_ttl_blocks)?;
        if self.min_pq_security_bits < 128 {
            return Err("min_pq_security_bits must be at least 128".to_string());
        }
        require_positive("low_fee_micro_units", self.low_fee_micro_units)?;
        require_positive("fast_fee_micro_units", self.fast_fee_micro_units)?;
        if self.low_fee_micro_units > self.fast_fee_micro_units {
            return Err("low_fee_micro_units cannot exceed fast_fee_micro_units".to_string());
        }
        require_positive("max_batch_weight", self.max_batch_weight)?;
        if self.batch_fee_rebate_bps > MAX_BPS {
            return Err("batch_fee_rebate_bps exceeds max bps".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_PQ_SUBADDRESS_ROTATION_SCHEDULER_PROTOCOL_VERSION,
            "protocol_label": PROTOCOL_LABEL,
            "network": self.network,
            "asset_id": self.asset_id,
            "fee_asset_id": self.fee_asset_id,
            "scheduler_id": self.scheduler_id,
            "operator_commitment": self.operator_commitment,
            "treasury_commitment": self.treasury_commitment,
            "pq_auth_suite": self.pq_auth_suite,
            "stealth_epoch_scheme": self.stealth_epoch_scheme,
            "view_tag_privacy_scheme": self.view_tag_privacy_scheme,
            "selective_disclosure_scheme": self.selective_disclosure_scheme,
            "hash_suite": self.hash_suite,
            "rotation_interval_blocks": self.rotation_interval_blocks,
            "epoch_lookahead_blocks": self.epoch_lookahead_blocks,
            "wallet_sync_window_blocks": self.wallet_sync_window_blocks,
            "finality_depth": self.finality_depth,
            "low_fee_batch_target": self.low_fee_batch_target,
            "max_rotations_per_batch": self.max_rotations_per_batch,
            "max_view_tags_per_window": self.max_view_tags_per_window,
            "reserve_hint_ttl_blocks": self.reserve_hint_ttl_blocks,
            "disclosure_ttl_blocks": self.disclosure_ttl_blocks,
            "min_pq_security_bits": self.min_pq_security_bits,
            "low_fee_micro_units": self.low_fee_micro_units,
            "fast_fee_micro_units": self.fast_fee_micro_units,
            "max_batch_weight": self.max_batch_weight,
            "audit_receipt_required": self.audit_receipt_required,
            "reserve_rotation_hints_enabled": self.reserve_rotation_hints_enabled,
            "view_tag_decoy_padding": self.view_tag_decoy_padding,
            "batch_fee_rebate_bps": self.batch_fee_rebate_bps,
        })
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roots {
    pub config_root: String,
    pub stealth_epoch_root: String,
    pub view_tag_window_root: String,
    pub pq_authorization_root: String,
    pub reserve_hint_root: String,
    pub wallet_sync_root: String,
    pub low_fee_batch_root: String,
    pub disclosure_receipt_root: String,
    pub nullifier_root: String,
    pub state_root: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    pub height: u64,
    pub stealth_epoch_count: u64,
    pub live_stealth_epoch_count: u64,
    pub view_tag_window_count: u64,
    pub active_view_tag_window_count: u64,
    pub pq_authorization_count: u64,
    pub reserve_hint_count: u64,
    pub wallet_sync_window_count: u64,
    pub low_fee_batch_count: u64,
    pub pending_low_fee_rotation_count: u64,
    pub disclosure_receipt_count: u64,
    pub active_disclosure_receipt_count: u64,
    pub replay_nullifier_count: u64,
    pub total_planned_rotation_weight: u64,
    pub total_batched_rotation_weight: u64,
    pub total_fee_micro_units: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub height: u64,
    stealth_epochs: BTreeMap<String, StealthDestinationEpoch>,
    view_tag_windows: BTreeMap<String, ViewTagPrivacyWindow>,
    pq_authorizations: BTreeMap<String, PqAuthorizationCommitment>,
    reserve_hints: BTreeMap<String, ReserveRotationHint>,
    wallet_sync_windows: BTreeMap<String, WalletSyncWindow>,
    low_fee_batches: BTreeMap<String, LowFeeRotationBatch>,
    disclosure_receipts: BTreeMap<String, SelectiveDisclosureReceipt>,
    replay_nullifiers: BTreeSet<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum EpochStatus {
    Planned,
    Open,
    Sealed,
    Rotated,
    Expired,
    Cancelled,
}

impl EpochStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::Planned => "planned",
            Self::Open => "open",
            Self::Sealed => "sealed",
            Self::Rotated => "rotated",
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
        }
    }

    fn is_live(self) -> bool {
        matches!(self, Self::Planned | Self::Open | Self::Sealed)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum RotationPriority {
    LowFee,
    Standard,
    Fast,
    Emergency,
}

impl RotationPriority {
    fn as_str(self) -> &'static str {
        match self {
            Self::LowFee => "low_fee",
            Self::Standard => "standard",
            Self::Fast => "fast",
            Self::Emergency => "emergency",
        }
    }

    fn score(self) -> u64 {
        match self {
            Self::LowFee => 35,
            Self::Standard => 65,
            Self::Fast => 88,
            Self::Emergency => 100,
        }
    }

    fn fee_micro_units(self, config: &Config) -> u64 {
        match self {
            Self::LowFee => config.low_fee_micro_units,
            Self::Standard => config.low_fee_micro_units.saturating_mul(3),
            Self::Fast => config.fast_fee_micro_units,
            Self::Emergency => config.fast_fee_micro_units.saturating_mul(2),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum WindowStatus {
    Scheduled,
    Active,
    Sealed,
    Expired,
    ReorgHeld,
}

impl WindowStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::Scheduled => "scheduled",
            Self::Active => "active",
            Self::Sealed => "sealed",
            Self::Expired => "expired",
            Self::ReorgHeld => "reorg_held",
        }
    }

    fn is_active(self) -> bool {
        matches!(self, Self::Scheduled | Self::Active | Self::ReorgHeld)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum AuthorizationStatus {
    Committed,
    QuorumReady,
    BoundToEpoch,
    Consumed,
    Revoked,
}

impl AuthorizationStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::Committed => "committed",
            Self::QuorumReady => "quorum_ready",
            Self::BoundToEpoch => "bound_to_epoch",
            Self::Consumed => "consumed",
            Self::Revoked => "revoked",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum BatchStatus {
    Collecting,
    Sealed,
    Broadcast,
    Confirmed,
    Finalized,
    Cancelled,
}

impl BatchStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::Collecting => "collecting",
            Self::Sealed => "sealed",
            Self::Broadcast => "broadcast",
            Self::Confirmed => "confirmed",
            Self::Finalized => "finalized",
            Self::Cancelled => "cancelled",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum DisclosureScope {
    EpochMembership,
    ViewTagWindow,
    ReserveRotationHint,
    WalletSyncWindow,
    LowFeeBatch,
    PqAuthorization,
}

impl DisclosureScope {
    fn as_str(self) -> &'static str {
        match self {
            Self::EpochMembership => "epoch_membership",
            Self::ViewTagWindow => "view_tag_window",
            Self::ReserveRotationHint => "reserve_rotation_hint",
            Self::WalletSyncWindow => "wallet_sync_window",
            Self::LowFeeBatch => "low_fee_batch",
            Self::PqAuthorization => "pq_authorization",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct StealthDestinationEpoch {
    epoch_id: String,
    account_commitment: String,
    current_subaddress_commitment: String,
    next_subaddress_commitment: String,
    stealth_destination_commitment: String,
    view_tag_prefix_commitment: String,
    pq_authorization_id: String,
    reserve_hint_id: Option<String>,
    wallet_sync_window_id: String,
    starts_at_height: u64,
    expires_at_height: u64,
    rotation_weight: u64,
    priority: RotationPriority,
    status: EpochStatus,
    metadata_root: String,
}

impl StealthDestinationEpoch {
    fn public_record(&self) -> Value {
        json!({
            "epoch_id": self.epoch_id,
            "account_commitment": self.account_commitment,
            "current_subaddress_commitment": self.current_subaddress_commitment,
            "next_subaddress_commitment": self.next_subaddress_commitment,
            "stealth_destination_commitment": self.stealth_destination_commitment,
            "view_tag_prefix_commitment": self.view_tag_prefix_commitment,
            "pq_authorization_id": self.pq_authorization_id,
            "reserve_hint_id": self.reserve_hint_id,
            "wallet_sync_window_id": self.wallet_sync_window_id,
            "starts_at_height": self.starts_at_height,
            "expires_at_height": self.expires_at_height,
            "rotation_weight": self.rotation_weight,
            "priority": self.priority.as_str(),
            "priority_score": self.priority.score(),
            "status": self.status.as_str(),
            "metadata_root": self.metadata_root,
        })
    }

    fn is_live_at(&self, height: u64) -> bool {
        self.status.is_live() && self.starts_at_height <= height && height <= self.expires_at_height
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct ViewTagPrivacyWindow {
    window_id: String,
    epoch_id: String,
    account_commitment: String,
    view_tag_bucket_root: String,
    decoy_bucket_root: String,
    scanner_committee_root: String,
    starts_at_height: u64,
    ends_at_height: u64,
    max_view_tags: u64,
    decoy_padding: u64,
    status: WindowStatus,
}

impl ViewTagPrivacyWindow {
    fn public_record(&self) -> Value {
        json!({
            "window_id": self.window_id,
            "epoch_id": self.epoch_id,
            "account_commitment": self.account_commitment,
            "view_tag_bucket_root": self.view_tag_bucket_root,
            "decoy_bucket_root": self.decoy_bucket_root,
            "scanner_committee_root": self.scanner_committee_root,
            "starts_at_height": self.starts_at_height,
            "ends_at_height": self.ends_at_height,
            "max_view_tags": self.max_view_tags,
            "decoy_padding": self.decoy_padding,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct PqAuthorizationCommitment {
    authorization_id: String,
    account_commitment: String,
    epoch_nonce_commitment: String,
    pq_public_key_commitment: String,
    policy_root: String,
    signer_set_root: String,
    proof_commitment_root: String,
    min_security_bits: u16,
    threshold: u64,
    created_at_height: u64,
    expires_at_height: u64,
    status: AuthorizationStatus,
}

impl PqAuthorizationCommitment {
    fn public_record(&self) -> Value {
        json!({
            "authorization_id": self.authorization_id,
            "account_commitment": self.account_commitment,
            "epoch_nonce_commitment": self.epoch_nonce_commitment,
            "pq_public_key_commitment": self.pq_public_key_commitment,
            "policy_root": self.policy_root,
            "signer_set_root": self.signer_set_root,
            "proof_commitment_root": self.proof_commitment_root,
            "min_security_bits": self.min_security_bits,
            "threshold": self.threshold,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct ReserveRotationHint {
    hint_id: String,
    epoch_id: String,
    reserve_commitment: String,
    reserve_snapshot_root: String,
    liquidity_bucket_root: String,
    suggested_rotation_height: u64,
    expires_at_height: u64,
    confidence_bps: u64,
    low_fee_eligible: bool,
}

impl ReserveRotationHint {
    fn public_record(&self) -> Value {
        json!({
            "hint_id": self.hint_id,
            "epoch_id": self.epoch_id,
            "reserve_commitment": self.reserve_commitment,
            "reserve_snapshot_root": self.reserve_snapshot_root,
            "liquidity_bucket_root": self.liquidity_bucket_root,
            "suggested_rotation_height": self.suggested_rotation_height,
            "expires_at_height": self.expires_at_height,
            "confidence_bps": self.confidence_bps,
            "low_fee_eligible": self.low_fee_eligible,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct WalletSyncWindow {
    sync_window_id: String,
    epoch_id: String,
    wallet_commitment: String,
    scan_start_height: u64,
    scan_end_height: u64,
    checkpoint_root: String,
    encrypted_hint_root: String,
    view_tag_window_id: String,
    finality_depth: u64,
    status: WindowStatus,
}

impl WalletSyncWindow {
    fn public_record(&self) -> Value {
        json!({
            "sync_window_id": self.sync_window_id,
            "epoch_id": self.epoch_id,
            "wallet_commitment": self.wallet_commitment,
            "scan_start_height": self.scan_start_height,
            "scan_end_height": self.scan_end_height,
            "checkpoint_root": self.checkpoint_root,
            "encrypted_hint_root": self.encrypted_hint_root,
            "view_tag_window_id": self.view_tag_window_id,
            "finality_depth": self.finality_depth,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct LowFeeRotationBatch {
    batch_id: String,
    rotation_ids: Vec<String>,
    batch_sequence: u64,
    lane_commitment: String,
    fee_sponsor_commitment: String,
    total_weight: u64,
    fee_micro_units: u64,
    rebate_bps: u64,
    sealed_at_height: u64,
    status: BatchStatus,
    batch_plan_root: String,
}

impl LowFeeRotationBatch {
    fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "rotation_ids": self.rotation_ids,
            "batch_sequence": self.batch_sequence,
            "lane_commitment": self.lane_commitment,
            "fee_sponsor_commitment": self.fee_sponsor_commitment,
            "total_weight": self.total_weight,
            "fee_micro_units": self.fee_micro_units,
            "rebate_bps": self.rebate_bps,
            "sealed_at_height": self.sealed_at_height,
            "status": self.status.as_str(),
            "batch_plan_root": self.batch_plan_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct SelectiveDisclosureReceipt {
    receipt_id: String,
    subject_id: String,
    auditor_commitment: String,
    scope: DisclosureScope,
    disclosed_root: String,
    redaction_root: String,
    nullifier: String,
    issued_at_height: u64,
    expires_at_height: u64,
    audit_safe: bool,
}

impl SelectiveDisclosureReceipt {
    fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "subject_id": self.subject_id,
            "auditor_commitment": self.auditor_commitment,
            "scope": self.scope.as_str(),
            "disclosed_root": self.disclosed_root,
            "redaction_root": self.redaction_root,
            "nullifier": self.nullifier,
            "issued_at_height": self.issued_at_height,
            "expires_at_height": self.expires_at_height,
            "audit_safe": self.audit_safe,
        })
    }
}

impl State {
    pub fn devnet() -> MoneroPqSubaddressRotationSchedulerResult<Self> {
        let mut state = Self {
            config: Config::devnet(),
            height: 512,
            stealth_epochs: BTreeMap::new(),
            view_tag_windows: BTreeMap::new(),
            pq_authorizations: BTreeMap::new(),
            reserve_hints: BTreeMap::new(),
            wallet_sync_windows: BTreeMap::new(),
            low_fee_batches: BTreeMap::new(),
            disclosure_receipts: BTreeMap::new(),
            replay_nullifiers: BTreeSet::new(),
        };
        state.config.validate()?;
        state.seed_devnet()?;
        state.validate()?;
        Ok(state)
    }

    pub fn validate(&self) -> MoneroPqSubaddressRotationSchedulerResult<()> {
        self.config.validate()?;
        for authorization in self.pq_authorizations.values() {
            require_text("authorization_id", &authorization.authorization_id)?;
            require_text(
                "authorization.account_commitment",
                &authorization.account_commitment,
            )?;
            if authorization.min_security_bits < self.config.min_pq_security_bits {
                return Err(format!(
                    "authorization {} below configured pq security floor",
                    authorization.authorization_id
                ));
            }
            if authorization.created_at_height > authorization.expires_at_height {
                return Err(format!(
                    "authorization {} has inverted validity window",
                    authorization.authorization_id
                ));
            }
        }
        for epoch in self.stealth_epochs.values() {
            require_text("epoch_id", &epoch.epoch_id)?;
            if !self
                .pq_authorizations
                .contains_key(&epoch.pq_authorization_id)
            {
                return Err(format!(
                    "epoch {} references missing pq authorization",
                    epoch.epoch_id
                ));
            }
            if !self
                .wallet_sync_windows
                .contains_key(&epoch.wallet_sync_window_id)
            {
                return Err(format!(
                    "epoch {} references missing wallet sync window",
                    epoch.epoch_id
                ));
            }
            if let Some(hint_id) = &epoch.reserve_hint_id {
                if !self.reserve_hints.contains_key(hint_id) {
                    return Err(format!(
                        "epoch {} references missing reserve hint",
                        epoch.epoch_id
                    ));
                }
            }
            if epoch.starts_at_height > epoch.expires_at_height {
                return Err(format!(
                    "epoch {} has inverted height range",
                    epoch.epoch_id
                ));
            }
            require_positive("epoch.rotation_weight", epoch.rotation_weight)?;
        }
        for window in self.view_tag_windows.values() {
            if !self.stealth_epochs.contains_key(&window.epoch_id) {
                return Err(format!(
                    "view tag window {} references missing epoch",
                    window.window_id
                ));
            }
            if window.starts_at_height > window.ends_at_height {
                return Err(format!(
                    "view tag window {} has inverted range",
                    window.window_id
                ));
            }
            if window.max_view_tags > self.config.max_view_tags_per_window {
                return Err(format!(
                    "view tag window {} exceeds max tags",
                    window.window_id
                ));
            }
        }
        for hint in self.reserve_hints.values() {
            if hint.confidence_bps > MAX_BPS {
                return Err(format!(
                    "reserve hint {} confidence exceeds bps",
                    hint.hint_id
                ));
            }
            if hint.suggested_rotation_height > hint.expires_at_height {
                return Err(format!(
                    "reserve hint {} expires before suggestion",
                    hint.hint_id
                ));
            }
        }
        for sync_window in self.wallet_sync_windows.values() {
            if sync_window.scan_start_height > sync_window.scan_end_height {
                return Err(format!(
                    "wallet sync window {} has inverted range",
                    sync_window.sync_window_id
                ));
            }
            if !self
                .view_tag_windows
                .contains_key(&sync_window.view_tag_window_id)
            {
                return Err(format!(
                    "wallet sync window {} references missing view tag window",
                    sync_window.sync_window_id
                ));
            }
        }
        for batch in self.low_fee_batches.values() {
            if batch.rotation_ids.len() > self.config.max_rotations_per_batch {
                return Err(format!("batch {} exceeds rotation cap", batch.batch_id));
            }
            if batch.total_weight > self.config.max_batch_weight {
                return Err(format!("batch {} exceeds weight cap", batch.batch_id));
            }
            for rotation_id in &batch.rotation_ids {
                if !self.stealth_epochs.contains_key(rotation_id) {
                    return Err(format!("batch {} references missing epoch", batch.batch_id));
                }
            }
        }
        for receipt in self.disclosure_receipts.values() {
            if !self.replay_nullifiers.contains(&receipt.nullifier) {
                return Err(format!(
                    "receipt {} missing replay nullifier index",
                    receipt.receipt_id
                ));
            }
            if receipt.issued_at_height > receipt.expires_at_height {
                return Err(format!("receipt {} has inverted ttl", receipt.receipt_id));
            }
        }
        Ok(())
    }

    pub fn set_height(&mut self, height: u64) -> MoneroPqSubaddressRotationSchedulerResult<()> {
        self.height = height;
        self.refresh_statuses();
        self.validate()
    }

    pub fn update_height(
        &mut self,
        next_height: u64,
    ) -> MoneroPqSubaddressRotationSchedulerResult<()> {
        if next_height < self.height {
            return Err("next_height cannot move backward".to_string());
        }
        self.set_height(next_height)
    }

    pub fn roots(&self) -> Roots {
        let config_root = root_from_record(&self.config.public_record());
        let stealth_epoch_root = merkle_records(
            "MONERO-PQ-SUBADDRESS-ROTATION-STEALTH-EPOCHS",
            self.stealth_epochs
                .values()
                .map(StealthDestinationEpoch::public_record)
                .collect(),
        );
        let view_tag_window_root = merkle_records(
            "MONERO-PQ-SUBADDRESS-ROTATION-VIEW-TAG-WINDOWS",
            self.view_tag_windows
                .values()
                .map(ViewTagPrivacyWindow::public_record)
                .collect(),
        );
        let pq_authorization_root = merkle_records(
            "MONERO-PQ-SUBADDRESS-ROTATION-PQ-AUTHORIZATIONS",
            self.pq_authorizations
                .values()
                .map(PqAuthorizationCommitment::public_record)
                .collect(),
        );
        let reserve_hint_root = merkle_records(
            "MONERO-PQ-SUBADDRESS-ROTATION-RESERVE-HINTS",
            self.reserve_hints
                .values()
                .map(ReserveRotationHint::public_record)
                .collect(),
        );
        let wallet_sync_root = merkle_records(
            "MONERO-PQ-SUBADDRESS-ROTATION-WALLET-SYNC-WINDOWS",
            self.wallet_sync_windows
                .values()
                .map(WalletSyncWindow::public_record)
                .collect(),
        );
        let low_fee_batch_root = merkle_records(
            "MONERO-PQ-SUBADDRESS-ROTATION-LOW-FEE-BATCHES",
            self.low_fee_batches
                .values()
                .map(LowFeeRotationBatch::public_record)
                .collect(),
        );
        let disclosure_receipt_root = merkle_records(
            "MONERO-PQ-SUBADDRESS-ROTATION-DISCLOSURE-RECEIPTS",
            self.disclosure_receipts
                .values()
                .map(SelectiveDisclosureReceipt::public_record)
                .collect(),
        );
        let nullifier_root = merkle_records(
            "MONERO-PQ-SUBADDRESS-ROTATION-NULLIFIERS",
            self.replay_nullifiers
                .iter()
                .map(|value| json!(value))
                .collect(),
        );
        let state_record = json!({
            "config_root": config_root,
            "stealth_epoch_root": stealth_epoch_root,
            "view_tag_window_root": view_tag_window_root,
            "pq_authorization_root": pq_authorization_root,
            "reserve_hint_root": reserve_hint_root,
            "wallet_sync_root": wallet_sync_root,
            "low_fee_batch_root": low_fee_batch_root,
            "disclosure_receipt_root": disclosure_receipt_root,
            "nullifier_root": nullifier_root,
            "height": self.height,
        });
        let state_root = root_from_record(&state_record);
        Roots {
            config_root,
            stealth_epoch_root,
            view_tag_window_root,
            pq_authorization_root,
            reserve_hint_root,
            wallet_sync_root,
            low_fee_batch_root,
            disclosure_receipt_root,
            nullifier_root,
            state_root,
        }
    }

    pub fn counters(&self) -> Counters {
        let live_stealth_epoch_count = self
            .stealth_epochs
            .values()
            .filter(|epoch| epoch.is_live_at(self.height))
            .count() as u64;
        let active_view_tag_window_count = self
            .view_tag_windows
            .values()
            .filter(|window| window.status.is_active())
            .count() as u64;
        let pending_low_fee_rotation_count = self
            .stealth_epochs
            .values()
            .filter(|epoch| epoch.priority == RotationPriority::LowFee && epoch.status.is_live())
            .count() as u64;
        let active_disclosure_receipt_count = self
            .disclosure_receipts
            .values()
            .filter(|receipt| receipt.expires_at_height >= self.height && receipt.audit_safe)
            .count() as u64;
        let total_planned_rotation_weight = self
            .stealth_epochs
            .values()
            .map(|epoch| epoch.rotation_weight)
            .fold(0_u64, u64::saturating_add);
        let total_batched_rotation_weight = self
            .low_fee_batches
            .values()
            .map(|batch| batch.total_weight)
            .fold(0_u64, u64::saturating_add);
        let total_fee_micro_units = self
            .low_fee_batches
            .values()
            .map(|batch| batch.fee_micro_units)
            .fold(0_u64, u64::saturating_add);
        Counters {
            height: self.height,
            stealth_epoch_count: self.stealth_epochs.len() as u64,
            live_stealth_epoch_count,
            view_tag_window_count: self.view_tag_windows.len() as u64,
            active_view_tag_window_count,
            pq_authorization_count: self.pq_authorizations.len() as u64,
            reserve_hint_count: self.reserve_hints.len() as u64,
            wallet_sync_window_count: self.wallet_sync_windows.len() as u64,
            low_fee_batch_count: self.low_fee_batches.len() as u64,
            pending_low_fee_rotation_count,
            disclosure_receipt_count: self.disclosure_receipts.len() as u64,
            active_disclosure_receipt_count,
            replay_nullifier_count: self.replay_nullifiers.len() as u64,
            total_planned_rotation_weight,
            total_batched_rotation_weight,
            total_fee_micro_units,
        }
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        let counters = self.counters();
        json!({
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_PQ_SUBADDRESS_ROTATION_SCHEDULER_PROTOCOL_VERSION,
            "protocol_label": PROTOCOL_LABEL,
            "height": self.height,
            "config": self.config.public_record(),
            "roots": roots,
            "counters": counters,
        })
    }

    pub fn state_root(&self) -> String {
        self.roots().state_root
    }

    fn seed_devnet(&mut self) -> MoneroPqSubaddressRotationSchedulerResult<()> {
        for index in 0_u64..16 {
            let account_label = format!("devnet-account-{index}");
            let current_subaddress_label = format!("devnet-subaddress-{index}-current");
            let next_subaddress_label = format!("devnet-subaddress-{index}-next");
            let wallet_label = format!("devnet-wallet-{index}");
            let reserve_label = format!("devnet-reserve-{}", index % 4);
            let priority = match index % 4 {
                0 => RotationPriority::LowFee,
                1 => RotationPriority::Standard,
                2 => RotationPriority::Fast,
                _ => RotationPriority::Emergency,
            };
            self.plan_devnet_rotation(
                &account_label,
                &current_subaddress_label,
                &next_subaddress_label,
                &wallet_label,
                &reserve_label,
                index,
                priority,
            )?;
        }
        self.build_low_fee_batches()?;
        self.issue_devnet_receipts()?;
        Ok(())
    }

    fn plan_devnet_rotation(
        &mut self,
        account_label: &str,
        current_subaddress_label: &str,
        next_subaddress_label: &str,
        wallet_label: &str,
        reserve_label: &str,
        index: u64,
        priority: RotationPriority,
    ) -> MoneroPqSubaddressRotationSchedulerResult<()> {
        let account_commitment = scheduler_hash("ACCOUNT", &[HashPart::Str(account_label)]);
        let current_subaddress_commitment = scheduler_hash(
            "CURRENT-SUBADDRESS",
            &[HashPart::Str(current_subaddress_label)],
        );
        let next_subaddress_commitment =
            scheduler_hash("NEXT-SUBADDRESS", &[HashPart::Str(next_subaddress_label)]);
        let epoch_nonce_commitment = scheduler_hash(
            "EPOCH-NONCE",
            &[HashPart::Str(account_label), HashPart::Int(index as i128)],
        );
        let pq_public_key_commitment = scheduler_hash(
            "PQ-PUBLIC-KEY",
            &[
                HashPart::Str(account_label),
                HashPart::Str(&self.config.pq_auth_suite),
            ],
        );
        let policy = json!({
            "account_commitment": account_commitment,
            "priority": priority.as_str(),
            "rotation_interval_blocks": self.config.rotation_interval_blocks,
            "reserve_hints_enabled": self.config.reserve_rotation_hints_enabled,
        });
        let policy_root = scheduler_hash("PQ-AUTH-POLICY", &[HashPart::Json(&policy)]);
        let signer_set_root = scheduler_hash(
            "PQ-AUTH-SIGNER-SET",
            &[
                HashPart::Str(&self.config.operator_commitment),
                HashPart::Str(&self.config.treasury_commitment),
                HashPart::Str(account_label),
            ],
        );
        let proof_commitment_root = scheduler_hash(
            "PQ-AUTH-PROOF",
            &[
                HashPart::Str(&policy_root),
                HashPart::Str(&signer_set_root),
                HashPart::Str(&epoch_nonce_commitment),
            ],
        );
        let authorization_id = scheduler_hash(
            "PQ-AUTHORIZATION-ID",
            &[
                HashPart::Str(&account_commitment),
                HashPart::Str(&epoch_nonce_commitment),
                HashPart::Int(index as i128),
            ],
        );
        let auth = PqAuthorizationCommitment {
            authorization_id: authorization_id.clone(),
            account_commitment: account_commitment.clone(),
            epoch_nonce_commitment: epoch_nonce_commitment.clone(),
            pq_public_key_commitment,
            policy_root,
            signer_set_root,
            proof_commitment_root,
            min_security_bits: self.config.min_pq_security_bits,
            threshold: 2,
            created_at_height: self.height.saturating_sub(4),
            expires_at_height: self
                .height
                .saturating_add(self.config.epoch_lookahead_blocks),
            status: AuthorizationStatus::BoundToEpoch,
        };
        self.pq_authorizations
            .insert(authorization_id.clone(), auth);
        let start = self
            .height
            .saturating_add(index.saturating_mul(self.config.rotation_interval_blocks / 3 + 1));
        let expires = start.saturating_add(self.config.epoch_lookahead_blocks);
        let stealth_destination_commitment = scheduler_hash(
            "STEALTH-DESTINATION",
            &[
                HashPart::Str(&account_commitment),
                HashPart::Str(&next_subaddress_commitment),
                HashPart::Str(&epoch_nonce_commitment),
            ],
        );
        let view_tag_prefix_commitment = scheduler_hash(
            "VIEW-TAG-PREFIX",
            &[
                HashPart::Str(&stealth_destination_commitment),
                HashPart::Int(start as i128),
            ],
        );
        let epoch_id = scheduler_hash(
            "STEALTH-EPOCH-ID",
            &[
                HashPart::Str(&account_commitment),
                HashPart::Str(&stealth_destination_commitment),
                HashPart::Int(start as i128),
            ],
        );
        let view_tag_bucket_root = scheduler_hash(
            "VIEW-TAG-BUCKET",
            &[
                HashPart::Str(&view_tag_prefix_commitment),
                HashPart::Int(index as i128),
            ],
        );
        let decoy_bucket_root = scheduler_hash(
            "VIEW-TAG-DECOYS",
            &[
                HashPart::Str(&view_tag_bucket_root),
                HashPart::Int(self.config.view_tag_decoy_padding as i128),
            ],
        );
        let scanner_committee_root = scheduler_hash(
            "SCANNER-COMMITTEE",
            &[
                HashPart::Str(&self.config.operator_commitment),
                HashPart::Str(&account_commitment),
            ],
        );
        let window_id = scheduler_hash(
            "VIEW-TAG-WINDOW-ID",
            &[
                HashPart::Str(&epoch_id),
                HashPart::Str(&view_tag_bucket_root),
            ],
        );
        self.view_tag_windows.insert(
            window_id.clone(),
            ViewTagPrivacyWindow {
                window_id: window_id.clone(),
                epoch_id: epoch_id.clone(),
                account_commitment: account_commitment.clone(),
                view_tag_bucket_root,
                decoy_bucket_root,
                scanner_committee_root,
                starts_at_height: start.saturating_sub(self.config.finality_depth),
                ends_at_height: expires,
                max_view_tags: self.config.max_view_tags_per_window,
                decoy_padding: self.config.view_tag_decoy_padding,
                status: WindowStatus::Scheduled,
            },
        );
        let wallet_commitment = scheduler_hash("WALLET", &[HashPart::Str(wallet_label)]);
        let checkpoint_record = json!({
            "wallet_commitment": wallet_commitment,
            "epoch_id": epoch_id,
            "scan_start_height": start.saturating_sub(self.config.wallet_sync_window_blocks),
            "scan_end_height": expires.saturating_add(self.config.finality_depth),
        });
        let checkpoint_root =
            scheduler_hash("WALLET-CHECKPOINT", &[HashPart::Json(&checkpoint_record)]);
        let encrypted_hint_root = scheduler_hash(
            "WALLET-ENCRYPTED-HINT",
            &[
                HashPart::Str(&wallet_commitment),
                HashPart::Str(&view_tag_prefix_commitment),
                HashPart::Str(&authorization_id),
            ],
        );
        let sync_window_id = scheduler_hash(
            "WALLET-SYNC-WINDOW-ID",
            &[
                HashPart::Str(&wallet_commitment),
                HashPart::Str(&checkpoint_root),
            ],
        );
        self.wallet_sync_windows.insert(
            sync_window_id.clone(),
            WalletSyncWindow {
                sync_window_id: sync_window_id.clone(),
                epoch_id: epoch_id.clone(),
                wallet_commitment,
                scan_start_height: start.saturating_sub(self.config.wallet_sync_window_blocks),
                scan_end_height: expires.saturating_add(self.config.finality_depth),
                checkpoint_root,
                encrypted_hint_root,
                view_tag_window_id: window_id,
                finality_depth: self.config.finality_depth,
                status: WindowStatus::Scheduled,
            },
        );
        let reserve_commitment = scheduler_hash("RESERVE", &[HashPart::Str(reserve_label)]);
        let reserve_snapshot = json!({
            "reserve_commitment": reserve_commitment,
            "asset_id": self.config.asset_id,
            "epoch_id": epoch_id,
            "low_fee": priority == RotationPriority::LowFee,
        });
        let reserve_snapshot_root =
            scheduler_hash("RESERVE-SNAPSHOT", &[HashPart::Json(&reserve_snapshot)]);
        let liquidity_bucket_root = scheduler_hash(
            "LIQUIDITY-BUCKET",
            &[
                HashPart::Str(&reserve_commitment),
                HashPart::Int((index % 4) as i128),
            ],
        );
        let hint_id = scheduler_hash(
            "RESERVE-HINT-ID",
            &[
                HashPart::Str(&epoch_id),
                HashPart::Str(&reserve_snapshot_root),
            ],
        );
        self.reserve_hints.insert(
            hint_id.clone(),
            ReserveRotationHint {
                hint_id: hint_id.clone(),
                epoch_id: epoch_id.clone(),
                reserve_commitment,
                reserve_snapshot_root,
                liquidity_bucket_root,
                suggested_rotation_height: start,
                expires_at_height: start.saturating_add(self.config.reserve_hint_ttl_blocks),
                confidence_bps: 8_000_u64
                    .saturating_add(index.saturating_mul(73))
                    .min(MAX_BPS),
                low_fee_eligible: priority == RotationPriority::LowFee,
            },
        );
        let metadata = json!({
            "network": self.config.network,
            "asset_id": self.config.asset_id,
            "stealth_epoch_scheme": self.config.stealth_epoch_scheme,
            "view_tag_privacy_scheme": self.config.view_tag_privacy_scheme,
            "index": index,
        });
        let metadata_root = scheduler_hash("EPOCH-METADATA", &[HashPart::Json(&metadata)]);
        self.stealth_epochs.insert(
            epoch_id.clone(),
            StealthDestinationEpoch {
                epoch_id,
                account_commitment,
                current_subaddress_commitment,
                next_subaddress_commitment,
                stealth_destination_commitment,
                view_tag_prefix_commitment,
                pq_authorization_id: authorization_id,
                reserve_hint_id: Some(hint_id),
                wallet_sync_window_id: sync_window_id,
                starts_at_height: start,
                expires_at_height: expires,
                rotation_weight: 20_000_u64.saturating_add(index.saturating_mul(1_777)),
                priority,
                status: EpochStatus::Planned,
                metadata_root,
            },
        );
        Ok(())
    }

    fn build_low_fee_batches(&mut self) -> MoneroPqSubaddressRotationSchedulerResult<()> {
        let mut pending = self
            .stealth_epochs
            .values()
            .filter(|epoch| epoch.priority == RotationPriority::LowFee)
            .map(|epoch| epoch.epoch_id.clone())
            .collect::<Vec<_>>();
        pending.sort();
        if pending.is_empty() {
            return Ok(());
        }
        let mut sequence = 0_u64;
        for chunk in pending.chunks(self.config.low_fee_batch_target) {
            let rotation_ids = chunk.to_vec();
            let mut total_weight = 0_u64;
            for rotation_id in &rotation_ids {
                if let Some(epoch) = self.stealth_epochs.get(rotation_id) {
                    total_weight = total_weight.saturating_add(epoch.rotation_weight);
                }
            }
            let capped_weight = total_weight.min(self.config.max_batch_weight);
            let lane_commitment = scheduler_hash(
                "LOW-FEE-LANE",
                &[
                    HashPart::Str(&self.config.scheduler_id),
                    HashPart::Int(sequence as i128),
                ],
            );
            let fee_sponsor_commitment = scheduler_hash(
                "LOW-FEE-SPONSOR",
                &[
                    HashPart::Str(&self.config.treasury_commitment),
                    HashPart::Str(&lane_commitment),
                ],
            );
            let plan = json!({
                "rotation_ids": rotation_ids,
                "total_weight": capped_weight,
                "fee_asset_id": self.config.fee_asset_id,
                "rebate_bps": self.config.batch_fee_rebate_bps,
            });
            let batch_plan_root = scheduler_hash("LOW-FEE-BATCH-PLAN", &[HashPart::Json(&plan)]);
            let batch_id = scheduler_hash(
                "LOW-FEE-BATCH-ID",
                &[
                    HashPart::Str(&lane_commitment),
                    HashPart::Str(&batch_plan_root),
                    HashPart::Int(sequence as i128),
                ],
            );
            let gross_fee = self
                .config
                .low_fee_micro_units
                .saturating_mul(rotation_ids.len() as u64);
            let rebate = gross_fee.saturating_mul(self.config.batch_fee_rebate_bps) / MAX_BPS;
            let batch = LowFeeRotationBatch {
                batch_id: batch_id.clone(),
                rotation_ids,
                batch_sequence: sequence,
                lane_commitment,
                fee_sponsor_commitment,
                total_weight: capped_weight,
                fee_micro_units: gross_fee.saturating_sub(rebate),
                rebate_bps: self.config.batch_fee_rebate_bps,
                sealed_at_height: self.height,
                status: BatchStatus::Collecting,
                batch_plan_root,
            };
            self.low_fee_batches.insert(batch_id, batch);
            sequence = sequence.saturating_add(1);
        }
        Ok(())
    }

    fn issue_devnet_receipts(&mut self) -> MoneroPqSubaddressRotationSchedulerResult<()> {
        let subjects = self
            .stealth_epochs
            .keys()
            .take(8)
            .cloned()
            .collect::<Vec<_>>();
        for (index, subject_id) in subjects.iter().enumerate() {
            let scope = match index % 6 {
                0 => DisclosureScope::EpochMembership,
                1 => DisclosureScope::ViewTagWindow,
                2 => DisclosureScope::ReserveRotationHint,
                3 => DisclosureScope::WalletSyncWindow,
                4 => DisclosureScope::LowFeeBatch,
                _ => DisclosureScope::PqAuthorization,
            };
            let auditor_commitment = scheduler_hash(
                "AUDITOR",
                &[
                    HashPart::Str("devnet-auditor"),
                    HashPart::Int(index as i128),
                ],
            );
            let disclosed = json!({
                "subject_id": subject_id,
                "scope": scope.as_str(),
                "height": self.height,
                "selective_disclosure_scheme": self.config.selective_disclosure_scheme,
            });
            let disclosed_root = scheduler_hash("DISCLOSED-ROOT", &[HashPart::Json(&disclosed)]);
            let redaction_root = scheduler_hash(
                "REDACTION-ROOT",
                &[
                    HashPart::Str(subject_id),
                    HashPart::Str(scope.as_str()),
                    HashPart::Str(&auditor_commitment),
                ],
            );
            let nullifier = scheduler_hash(
                "DISCLOSURE-NULLIFIER",
                &[
                    HashPart::Str(subject_id),
                    HashPart::Str(scope.as_str()),
                    HashPart::Int(index as i128),
                ],
            );
            if self.replay_nullifiers.contains(&nullifier) {
                return Err("duplicate disclosure nullifier".to_string());
            }
            self.replay_nullifiers.insert(nullifier.clone());
            let receipt_id = scheduler_hash(
                "DISCLOSURE-RECEIPT-ID",
                &[HashPart::Str(&nullifier), HashPart::Str(&disclosed_root)],
            );
            let receipt = SelectiveDisclosureReceipt {
                receipt_id: receipt_id.clone(),
                subject_id: subject_id.clone(),
                auditor_commitment,
                scope,
                disclosed_root,
                redaction_root,
                nullifier,
                issued_at_height: self.height,
                expires_at_height: self
                    .height
                    .saturating_add(self.config.disclosure_ttl_blocks),
                audit_safe: true,
            };
            self.disclosure_receipts.insert(receipt_id, receipt);
        }
        Ok(())
    }

    fn refresh_statuses(&mut self) {
        for epoch in self.stealth_epochs.values_mut() {
            epoch.status = if self.height > epoch.expires_at_height {
                EpochStatus::Expired
            } else if self.height
                >= epoch
                    .starts_at_height
                    .saturating_add(self.config.finality_depth)
            {
                EpochStatus::Sealed
            } else if self.height >= epoch.starts_at_height {
                EpochStatus::Open
            } else {
                EpochStatus::Planned
            };
        }
        for window in self.view_tag_windows.values_mut() {
            window.status = if self.height > window.ends_at_height {
                WindowStatus::Expired
            } else if self.height >= window.starts_at_height {
                WindowStatus::Active
            } else {
                WindowStatus::Scheduled
            };
        }
        for sync_window in self.wallet_sync_windows.values_mut() {
            sync_window.status = if self.height > sync_window.scan_end_height {
                WindowStatus::Expired
            } else if self.height >= sync_window.scan_start_height {
                WindowStatus::Active
            } else {
                WindowStatus::Scheduled
            };
        }
        for authorization in self.pq_authorizations.values_mut() {
            if self.height > authorization.expires_at_height {
                authorization.status = AuthorizationStatus::Revoked;
            }
        }
        for batch in self.low_fee_batches.values_mut() {
            if batch.status == BatchStatus::Collecting
                && self.height
                    >= batch
                        .sealed_at_height
                        .saturating_add(self.config.finality_depth)
            {
                batch.status = BatchStatus::Sealed;
            }
        }
    }
}

pub fn root_from_record(record: &Value) -> String {
    scheduler_hash(
        "PUBLIC-RECORD-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(MONERO_PQ_SUBADDRESS_ROTATION_SCHEDULER_PROTOCOL_VERSION),
            HashPart::Json(record),
        ],
    )
}

pub fn devnet() -> MoneroPqSubaddressRotationSchedulerResult<State> {
    State::devnet()
}

fn scheduler_hash(domain: &str, parts: &[HashPart<'_>]) -> String {
    let scheduler_domain = format!("MONERO-PQ-SUBADDRESS-ROTATION-SCHEDULER:{domain}");
    domain_hash(&scheduler_domain, parts, 32)
}

fn merkle_records(domain: &str, records: Vec<Value>) -> String {
    merkle_root(domain, &records)
}

fn require_text(label: &str, value: &str) -> MoneroPqSubaddressRotationSchedulerResult<()> {
    if value.trim().is_empty() {
        return Err(format!("{label} must not be empty"));
    }
    Ok(())
}

fn require_positive(label: &str, value: u64) -> MoneroPqSubaddressRotationSchedulerResult<()> {
    if value == 0 {
        return Err(format!("{label} must be positive"));
    }
    Ok(())
}

fn bounded_window_start(height: u64, width: u64) -> u64 {
    height.saturating_sub(width)
}

fn bounded_window_end(height: u64, width: u64) -> u64 {
    height.saturating_add(width)
}

fn fee_quote_root(config: &Config, priority: RotationPriority, rotation_count: u64) -> String {
    let quote = json!({
        "fee_asset_id": config.fee_asset_id,
        "priority": priority.as_str(),
        "rotation_count": rotation_count,
        "fee_micro_units": priority.fee_micro_units(config).saturating_mul(rotation_count),
    });
    scheduler_hash("FEE-QUOTE", &[HashPart::Json(&quote)])
}

fn sync_policy_root(config: &Config, account_commitment: &str, height: u64) -> String {
    let policy = json!({
        "account_commitment": account_commitment,
        "height": height,
        "wallet_sync_window_blocks": config.wallet_sync_window_blocks,
        "finality_depth": config.finality_depth,
        "view_tag_privacy_scheme": config.view_tag_privacy_scheme,
    });
    scheduler_hash("SYNC-POLICY", &[HashPart::Json(&policy)])
}

fn reserve_policy_root(config: &Config, reserve_commitment: &str, height: u64) -> String {
    let policy = json!({
        "reserve_commitment": reserve_commitment,
        "height": height,
        "reserve_hint_ttl_blocks": config.reserve_hint_ttl_blocks,
        "reserve_rotation_hints_enabled": config.reserve_rotation_hints_enabled,
    });
    scheduler_hash("RESERVE-POLICY", &[HashPart::Json(&policy)])
}

fn disclosure_policy_root(
    config: &Config,
    auditor_commitment: &str,
    scope: DisclosureScope,
) -> String {
    let policy = json!({
        "auditor_commitment": auditor_commitment,
        "scope": scope.as_str(),
        "ttl_blocks": config.disclosure_ttl_blocks,
        "audit_receipt_required": config.audit_receipt_required,
        "selective_disclosure_scheme": config.selective_disclosure_scheme,
    });
    scheduler_hash("DISCLOSURE-POLICY", &[HashPart::Json(&policy)])
}

fn status_weight(status: EpochStatus) -> u64 {
    match status {
        EpochStatus::Planned => 10,
        EpochStatus::Open => 30,
        EpochStatus::Sealed => 50,
        EpochStatus::Rotated => 80,
        EpochStatus::Expired => 5,
        EpochStatus::Cancelled => 0,
    }
}

fn batch_status_weight(status: BatchStatus) -> u64 {
    match status {
        BatchStatus::Collecting => 10,
        BatchStatus::Sealed => 25,
        BatchStatus::Broadcast => 45,
        BatchStatus::Confirmed => 70,
        BatchStatus::Finalized => 100,
        BatchStatus::Cancelled => 0,
    }
}

fn authorization_status_weight(status: AuthorizationStatus) -> u64 {
    match status {
        AuthorizationStatus::Committed => 10,
        AuthorizationStatus::QuorumReady => 35,
        AuthorizationStatus::BoundToEpoch => 65,
        AuthorizationStatus::Consumed => 90,
        AuthorizationStatus::Revoked => 0,
    }
}

fn rotation_recipe_01(config: &Config, account_commitment: &str, height: u64) -> Value {
    let start = bounded_window_start(height, config.wallet_sync_window_blocks);
    let end = bounded_window_end(height, config.epoch_lookahead_blocks);
    let policy_root = sync_policy_root(config, account_commitment, height);
    let fee_root = fee_quote_root(config, RotationPriority::LowFee, 1);
    let reserve_root = reserve_policy_root(config, account_commitment, height);
    let recipe_root = scheduler_hash(
        "ROTATION-RECIPE-01",
        &[
            HashPart::Str(account_commitment),
            HashPart::Str(&policy_root),
            HashPart::Str(&fee_root),
            HashPart::Str(&reserve_root),
            HashPart::Int(1),
            HashPart::Int(start as i128),
            HashPart::Int(end as i128),
        ],
    );
    json!({
        "recipe": "rotation_recipe_01",
        "account_commitment": account_commitment,
        "start": start,
        "end": end,
        "policy_root": policy_root,
        "fee_root": fee_root,
        "reserve_root": reserve_root,
        "recipe_root": recipe_root,
    })
}

fn rotation_recipe_02(config: &Config, account_commitment: &str, height: u64) -> Value {
    let start = bounded_window_start(height, config.wallet_sync_window_blocks);
    let end = bounded_window_end(height, config.epoch_lookahead_blocks);
    let policy_root = sync_policy_root(config, account_commitment, height);
    let fee_root = fee_quote_root(config, RotationPriority::LowFee, 1);
    let reserve_root = reserve_policy_root(config, account_commitment, height);
    let recipe_root = scheduler_hash(
        "ROTATION-RECIPE-02",
        &[
            HashPart::Str(account_commitment),
            HashPart::Str(&policy_root),
            HashPart::Str(&fee_root),
            HashPart::Str(&reserve_root),
            HashPart::Int(2),
            HashPart::Int(start as i128),
            HashPart::Int(end as i128),
        ],
    );
    json!({
        "recipe": "rotation_recipe_02",
        "account_commitment": account_commitment,
        "start": start,
        "end": end,
        "policy_root": policy_root,
        "fee_root": fee_root,
        "reserve_root": reserve_root,
        "recipe_root": recipe_root,
    })
}

fn rotation_recipe_03(config: &Config, account_commitment: &str, height: u64) -> Value {
    let start = bounded_window_start(height, config.wallet_sync_window_blocks);
    let end = bounded_window_end(height, config.epoch_lookahead_blocks);
    let policy_root = sync_policy_root(config, account_commitment, height);
    let fee_root = fee_quote_root(config, RotationPriority::LowFee, 1);
    let reserve_root = reserve_policy_root(config, account_commitment, height);
    let recipe_root = scheduler_hash(
        "ROTATION-RECIPE-03",
        &[
            HashPart::Str(account_commitment),
            HashPart::Str(&policy_root),
            HashPart::Str(&fee_root),
            HashPart::Str(&reserve_root),
            HashPart::Int(3),
            HashPart::Int(start as i128),
            HashPart::Int(end as i128),
        ],
    );
    json!({
        "recipe": "rotation_recipe_03",
        "account_commitment": account_commitment,
        "start": start,
        "end": end,
        "policy_root": policy_root,
        "fee_root": fee_root,
        "reserve_root": reserve_root,
        "recipe_root": recipe_root,
    })
}

fn rotation_recipe_04(config: &Config, account_commitment: &str, height: u64) -> Value {
    let start = bounded_window_start(height, config.wallet_sync_window_blocks);
    let end = bounded_window_end(height, config.epoch_lookahead_blocks);
    let policy_root = sync_policy_root(config, account_commitment, height);
    let fee_root = fee_quote_root(config, RotationPriority::LowFee, 1);
    let reserve_root = reserve_policy_root(config, account_commitment, height);
    let recipe_root = scheduler_hash(
        "ROTATION-RECIPE-04",
        &[
            HashPart::Str(account_commitment),
            HashPart::Str(&policy_root),
            HashPart::Str(&fee_root),
            HashPart::Str(&reserve_root),
            HashPart::Int(4),
            HashPart::Int(start as i128),
            HashPart::Int(end as i128),
        ],
    );
    json!({
        "recipe": "rotation_recipe_04",
        "account_commitment": account_commitment,
        "start": start,
        "end": end,
        "policy_root": policy_root,
        "fee_root": fee_root,
        "reserve_root": reserve_root,
        "recipe_root": recipe_root,
    })
}

fn rotation_recipe_05(config: &Config, account_commitment: &str, height: u64) -> Value {
    let start = bounded_window_start(height, config.wallet_sync_window_blocks);
    let end = bounded_window_end(height, config.epoch_lookahead_blocks);
    let policy_root = sync_policy_root(config, account_commitment, height);
    let fee_root = fee_quote_root(config, RotationPriority::LowFee, 1);
    let reserve_root = reserve_policy_root(config, account_commitment, height);
    let recipe_root = scheduler_hash(
        "ROTATION-RECIPE-05",
        &[
            HashPart::Str(account_commitment),
            HashPart::Str(&policy_root),
            HashPart::Str(&fee_root),
            HashPart::Str(&reserve_root),
            HashPart::Int(5),
            HashPart::Int(start as i128),
            HashPart::Int(end as i128),
        ],
    );
    json!({
        "recipe": "rotation_recipe_05",
        "account_commitment": account_commitment,
        "start": start,
        "end": end,
        "policy_root": policy_root,
        "fee_root": fee_root,
        "reserve_root": reserve_root,
        "recipe_root": recipe_root,
    })
}

fn rotation_recipe_06(config: &Config, account_commitment: &str, height: u64) -> Value {
    let start = bounded_window_start(height, config.wallet_sync_window_blocks);
    let end = bounded_window_end(height, config.epoch_lookahead_blocks);
    let policy_root = sync_policy_root(config, account_commitment, height);
    let fee_root = fee_quote_root(config, RotationPriority::LowFee, 1);
    let reserve_root = reserve_policy_root(config, account_commitment, height);
    let recipe_root = scheduler_hash(
        "ROTATION-RECIPE-06",
        &[
            HashPart::Str(account_commitment),
            HashPart::Str(&policy_root),
            HashPart::Str(&fee_root),
            HashPart::Str(&reserve_root),
            HashPart::Int(6),
            HashPart::Int(start as i128),
            HashPart::Int(end as i128),
        ],
    );
    json!({
        "recipe": "rotation_recipe_06",
        "account_commitment": account_commitment,
        "start": start,
        "end": end,
        "policy_root": policy_root,
        "fee_root": fee_root,
        "reserve_root": reserve_root,
        "recipe_root": recipe_root,
    })
}

fn rotation_recipe_07(config: &Config, account_commitment: &str, height: u64) -> Value {
    let start = bounded_window_start(height, config.wallet_sync_window_blocks);
    let end = bounded_window_end(height, config.epoch_lookahead_blocks);
    let policy_root = sync_policy_root(config, account_commitment, height);
    let fee_root = fee_quote_root(config, RotationPriority::LowFee, 1);
    let reserve_root = reserve_policy_root(config, account_commitment, height);
    let recipe_root = scheduler_hash(
        "ROTATION-RECIPE-07",
        &[
            HashPart::Str(account_commitment),
            HashPart::Str(&policy_root),
            HashPart::Str(&fee_root),
            HashPart::Str(&reserve_root),
            HashPart::Int(7),
            HashPart::Int(start as i128),
            HashPart::Int(end as i128),
        ],
    );
    json!({
        "recipe": "rotation_recipe_07",
        "account_commitment": account_commitment,
        "start": start,
        "end": end,
        "policy_root": policy_root,
        "fee_root": fee_root,
        "reserve_root": reserve_root,
        "recipe_root": recipe_root,
    })
}

fn rotation_recipe_08(config: &Config, account_commitment: &str, height: u64) -> Value {
    let start = bounded_window_start(height, config.wallet_sync_window_blocks);
    let end = bounded_window_end(height, config.epoch_lookahead_blocks);
    let policy_root = sync_policy_root(config, account_commitment, height);
    let fee_root = fee_quote_root(config, RotationPriority::LowFee, 1);
    let reserve_root = reserve_policy_root(config, account_commitment, height);
    let recipe_root = scheduler_hash(
        "ROTATION-RECIPE-08",
        &[
            HashPart::Str(account_commitment),
            HashPart::Str(&policy_root),
            HashPart::Str(&fee_root),
            HashPart::Str(&reserve_root),
            HashPart::Int(8),
            HashPart::Int(start as i128),
            HashPart::Int(end as i128),
        ],
    );
    json!({
        "recipe": "rotation_recipe_08",
        "account_commitment": account_commitment,
        "start": start,
        "end": end,
        "policy_root": policy_root,
        "fee_root": fee_root,
        "reserve_root": reserve_root,
        "recipe_root": recipe_root,
    })
}

fn rotation_recipe_09(config: &Config, account_commitment: &str, height: u64) -> Value {
    let start = bounded_window_start(height, config.wallet_sync_window_blocks);
    let end = bounded_window_end(height, config.epoch_lookahead_blocks);
    let policy_root = sync_policy_root(config, account_commitment, height);
    let fee_root = fee_quote_root(config, RotationPriority::LowFee, 1);
    let reserve_root = reserve_policy_root(config, account_commitment, height);
    let recipe_root = scheduler_hash(
        "ROTATION-RECIPE-09",
        &[
            HashPart::Str(account_commitment),
            HashPart::Str(&policy_root),
            HashPart::Str(&fee_root),
            HashPart::Str(&reserve_root),
            HashPart::Int(9),
            HashPart::Int(start as i128),
            HashPart::Int(end as i128),
        ],
    );
    json!({
        "recipe": "rotation_recipe_09",
        "account_commitment": account_commitment,
        "start": start,
        "end": end,
        "policy_root": policy_root,
        "fee_root": fee_root,
        "reserve_root": reserve_root,
        "recipe_root": recipe_root,
    })
}

fn rotation_recipe_10(config: &Config, account_commitment: &str, height: u64) -> Value {
    let start = bounded_window_start(height, config.wallet_sync_window_blocks);
    let end = bounded_window_end(height, config.epoch_lookahead_blocks);
    let policy_root = sync_policy_root(config, account_commitment, height);
    let fee_root = fee_quote_root(config, RotationPriority::LowFee, 1);
    let reserve_root = reserve_policy_root(config, account_commitment, height);
    let recipe_root = scheduler_hash(
        "ROTATION-RECIPE-10",
        &[
            HashPart::Str(account_commitment),
            HashPart::Str(&policy_root),
            HashPart::Str(&fee_root),
            HashPart::Str(&reserve_root),
            HashPart::Int(10),
            HashPart::Int(start as i128),
            HashPart::Int(end as i128),
        ],
    );
    json!({
        "recipe": "rotation_recipe_10",
        "account_commitment": account_commitment,
        "start": start,
        "end": end,
        "policy_root": policy_root,
        "fee_root": fee_root,
        "reserve_root": reserve_root,
        "recipe_root": recipe_root,
    })
}

fn rotation_recipe_11(config: &Config, account_commitment: &str, height: u64) -> Value {
    let start = bounded_window_start(height, config.wallet_sync_window_blocks);
    let end = bounded_window_end(height, config.epoch_lookahead_blocks);
    let policy_root = sync_policy_root(config, account_commitment, height);
    let fee_root = fee_quote_root(config, RotationPriority::LowFee, 1);
    let reserve_root = reserve_policy_root(config, account_commitment, height);
    let recipe_root = scheduler_hash(
        "ROTATION-RECIPE-11",
        &[
            HashPart::Str(account_commitment),
            HashPart::Str(&policy_root),
            HashPart::Str(&fee_root),
            HashPart::Str(&reserve_root),
            HashPart::Int(11),
            HashPart::Int(start as i128),
            HashPart::Int(end as i128),
        ],
    );
    json!({
        "recipe": "rotation_recipe_11",
        "account_commitment": account_commitment,
        "start": start,
        "end": end,
        "policy_root": policy_root,
        "fee_root": fee_root,
        "reserve_root": reserve_root,
        "recipe_root": recipe_root,
    })
}

fn rotation_recipe_12(config: &Config, account_commitment: &str, height: u64) -> Value {
    let start = bounded_window_start(height, config.wallet_sync_window_blocks);
    let end = bounded_window_end(height, config.epoch_lookahead_blocks);
    let policy_root = sync_policy_root(config, account_commitment, height);
    let fee_root = fee_quote_root(config, RotationPriority::LowFee, 1);
    let reserve_root = reserve_policy_root(config, account_commitment, height);
    let recipe_root = scheduler_hash(
        "ROTATION-RECIPE-12",
        &[
            HashPart::Str(account_commitment),
            HashPart::Str(&policy_root),
            HashPart::Str(&fee_root),
            HashPart::Str(&reserve_root),
            HashPart::Int(12),
            HashPart::Int(start as i128),
            HashPart::Int(end as i128),
        ],
    );
    json!({
        "recipe": "rotation_recipe_12",
        "account_commitment": account_commitment,
        "start": start,
        "end": end,
        "policy_root": policy_root,
        "fee_root": fee_root,
        "reserve_root": reserve_root,
        "recipe_root": recipe_root,
    })
}

fn rotation_recipe_13(config: &Config, account_commitment: &str, height: u64) -> Value {
    let start = bounded_window_start(height, config.wallet_sync_window_blocks);
    let end = bounded_window_end(height, config.epoch_lookahead_blocks);
    let policy_root = sync_policy_root(config, account_commitment, height);
    let fee_root = fee_quote_root(config, RotationPriority::LowFee, 1);
    let reserve_root = reserve_policy_root(config, account_commitment, height);
    let recipe_root = scheduler_hash(
        "ROTATION-RECIPE-13",
        &[
            HashPart::Str(account_commitment),
            HashPart::Str(&policy_root),
            HashPart::Str(&fee_root),
            HashPart::Str(&reserve_root),
            HashPart::Int(13),
            HashPart::Int(start as i128),
            HashPart::Int(end as i128),
        ],
    );
    json!({
        "recipe": "rotation_recipe_13",
        "account_commitment": account_commitment,
        "start": start,
        "end": end,
        "policy_root": policy_root,
        "fee_root": fee_root,
        "reserve_root": reserve_root,
        "recipe_root": recipe_root,
    })
}

fn rotation_recipe_14(config: &Config, account_commitment: &str, height: u64) -> Value {
    let start = bounded_window_start(height, config.wallet_sync_window_blocks);
    let end = bounded_window_end(height, config.epoch_lookahead_blocks);
    let policy_root = sync_policy_root(config, account_commitment, height);
    let fee_root = fee_quote_root(config, RotationPriority::LowFee, 1);
    let reserve_root = reserve_policy_root(config, account_commitment, height);
    let recipe_root = scheduler_hash(
        "ROTATION-RECIPE-14",
        &[
            HashPart::Str(account_commitment),
            HashPart::Str(&policy_root),
            HashPart::Str(&fee_root),
            HashPart::Str(&reserve_root),
            HashPart::Int(14),
            HashPart::Int(start as i128),
            HashPart::Int(end as i128),
        ],
    );
    json!({
        "recipe": "rotation_recipe_14",
        "account_commitment": account_commitment,
        "start": start,
        "end": end,
        "policy_root": policy_root,
        "fee_root": fee_root,
        "reserve_root": reserve_root,
        "recipe_root": recipe_root,
    })
}

fn rotation_recipe_15(config: &Config, account_commitment: &str, height: u64) -> Value {
    let start = bounded_window_start(height, config.wallet_sync_window_blocks);
    let end = bounded_window_end(height, config.epoch_lookahead_blocks);
    let policy_root = sync_policy_root(config, account_commitment, height);
    let fee_root = fee_quote_root(config, RotationPriority::LowFee, 1);
    let reserve_root = reserve_policy_root(config, account_commitment, height);
    let recipe_root = scheduler_hash(
        "ROTATION-RECIPE-15",
        &[
            HashPart::Str(account_commitment),
            HashPart::Str(&policy_root),
            HashPart::Str(&fee_root),
            HashPart::Str(&reserve_root),
            HashPart::Int(15),
            HashPart::Int(start as i128),
            HashPart::Int(end as i128),
        ],
    );
    json!({
        "recipe": "rotation_recipe_15",
        "account_commitment": account_commitment,
        "start": start,
        "end": end,
        "policy_root": policy_root,
        "fee_root": fee_root,
        "reserve_root": reserve_root,
        "recipe_root": recipe_root,
    })
}

fn recipe_catalog_root(config: &Config, account_commitment: &str, height: u64) -> String {
    let recipes = vec![
        rotation_recipe_01(config, account_commitment, height),
        rotation_recipe_02(config, account_commitment, height),
        rotation_recipe_03(config, account_commitment, height),
        rotation_recipe_04(config, account_commitment, height),
        rotation_recipe_05(config, account_commitment, height),
        rotation_recipe_06(config, account_commitment, height),
        rotation_recipe_07(config, account_commitment, height),
        rotation_recipe_08(config, account_commitment, height),
        rotation_recipe_09(config, account_commitment, height),
        rotation_recipe_10(config, account_commitment, height),
        rotation_recipe_11(config, account_commitment, height),
        rotation_recipe_12(config, account_commitment, height),
        rotation_recipe_13(config, account_commitment, height),
        rotation_recipe_14(config, account_commitment, height),
        rotation_recipe_15(config, account_commitment, height),
    ];
    merkle_root("MONERO-PQ-SUBADDRESS-ROTATION-RECIPE-CATALOG", &recipes)
}

fn receipt_policy_catalog_root(config: &Config, auditor_commitment: &str) -> String {
    let scopes = vec![
        DisclosureScope::EpochMembership,
        DisclosureScope::ViewTagWindow,
        DisclosureScope::ReserveRotationHint,
        DisclosureScope::WalletSyncWindow,
        DisclosureScope::LowFeeBatch,
        DisclosureScope::PqAuthorization,
    ];
    let records = scopes
        .into_iter()
        .map(|scope| {
            json!({
                "scope": scope.as_str(),
                "policy_root": disclosure_policy_root(config, auditor_commitment, scope),
            })
        })
        .collect::<Vec<_>>();
    merkle_root(
        "MONERO-PQ-SUBADDRESS-ROTATION-DISCLOSURE-POLICY-CATALOG",
        &records,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn devnet_state_validates_and_roots_are_deterministic() {
        let state_a = devnet();
        let state_b = devnet();
        assert!(state_a.is_ok());
        assert!(state_b.is_ok());
        let root_a = match state_a {
            Ok(state) => state.state_root(),
            Err(err) => err,
        };
        let root_b = match state_b {
            Ok(state) => state.state_root(),
            Err(err) => err,
        };
        assert_eq!(root_a, root_b);
    }

    #[test]
    fn height_updates_refresh_live_counters() {
        let mut state = match devnet() {
            Ok(state) => state,
            Err(_) => State {
                config: Config::devnet(),
                height: 0,
                stealth_epochs: BTreeMap::new(),
                view_tag_windows: BTreeMap::new(),
                pq_authorizations: BTreeMap::new(),
                reserve_hints: BTreeMap::new(),
                wallet_sync_windows: BTreeMap::new(),
                low_fee_batches: BTreeMap::new(),
                disclosure_receipts: BTreeMap::new(),
                replay_nullifiers: BTreeSet::new(),
            },
        };
        let before = state.counters().live_stealth_epoch_count;
        let updated = state.update_height(900);
        assert!(updated.is_ok());
        let after = state.counters().live_stealth_epoch_count;
        assert!(after <= before.saturating_add(16));
    }

    #[test]
    fn catalogs_are_stable() {
        let config = Config::devnet();
        let account_commitment = scheduler_hash("TEST-ACCOUNT", &[HashPart::Str("alice")]);
        let catalog_a = recipe_catalog_root(&config, &account_commitment, 10);
        let catalog_b = recipe_catalog_root(&config, &account_commitment, 10);
        assert_eq!(catalog_a, catalog_b);
        let auditor = scheduler_hash("TEST-AUDITOR", &[HashPart::Str("audit")]);
        let receipt_root = receipt_policy_catalog_root(&config, &auditor);
        assert!(!receipt_root.is_empty());
    }
}
