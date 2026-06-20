use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqPrivateViewkeyRecoveryRotationRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_PRIVATE_VIEWKEY_RECOVERY_ROTATION_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-private-viewkey-recovery-rotation-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_PRIVATE_VIEWKEY_RECOVERY_ROTATION_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const DEVNET_L2_NETWORK: &str = "nebula-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_BRIDGE_ID: &str = "monero-l2-pq-private-viewkey-recovery-rotation-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEVNET_RECOVERY_ASSET_ID: &str = "wxmr-devnet";
pub const DEVNET_HEIGHT: u64 = 934_400;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_RECOVERY_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-viewkey-recovery-rotation-v1";
pub const SELECTIVE_DISCLOSURE_SCHEME: &str =
    "monero-selective-disclosure-viewkey-recovery-root-v1";
pub const SUBADDRESS_CHURN_SCHEME: &str = "monero-private-subaddress-churn-root-v1";
pub const VIEW_TAG_SCAN_CACHE_SCHEME: &str = "monero-l2-private-view-tag-scan-cache-root-v1";
pub const WATCHER_ATTESTATION_SCHEME: &str = "pq-watcher-viewkey-recovery-attestation-root-v1";
pub const ENCRYPTED_RECOVERY_SHARE_SCHEME: &str = "ml-kem-sealed-viewkey-recovery-share-root-v1";
pub const PQ_SIGNER_ROTATION_SCHEME: &str = "ml-dsa-slh-dsa-pq-viewkey-signer-rotation-root-v1";
pub const PRIVACY_BUDGET_SCHEME: &str = "viewkey-recovery-privacy-budget-root-v1";
pub const LOW_FEE_BATCH_SCHEME: &str = "low-fee-viewkey-recovery-batch-root-v1";
pub const BRIDGE_AUDIT_WINDOW_SCHEME: &str = "monero-l2-viewkey-bridge-audit-window-root-v1";
pub const OPERATOR_REDACTION_SCHEME: &str = "operator-viewkey-redaction-root-v1";
pub const RECOVERY_RECEIPT_SCHEME: &str = "private-viewkey-recovery-rotation-receipt-root-v1";
pub const PUBLIC_RECORD_SCHEME: &str = "viewkey-recovery-rotation-public-record-root-v1";
pub const STATE_ROOT_DOMAIN: &str = "MONERO-L2-PQ-PRIVATE-VIEWKEY-RECOVERY-ROTATION-STATE";
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 192;
pub const DEFAULT_TARGET_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_RECOVERY_TTL_BLOCKS: u64 = 720;
pub const DEFAULT_DISCLOSURE_TTL_BLOCKS: u64 = 144;
pub const DEFAULT_SHARE_TTL_BLOCKS: u64 = 288;
pub const DEFAULT_ROTATION_TTL_BLOCKS: u64 = 360;
pub const DEFAULT_SCAN_CACHE_TTL_BLOCKS: u64 = 96;
pub const DEFAULT_AUDIT_WINDOW_BLOCKS: u64 = 1_440;
pub const DEFAULT_MIN_RECOVERY_THRESHOLD: u16 = 3;
pub const DEFAULT_MIN_RECOVERY_SHARES: u16 = 5;
pub const DEFAULT_MIN_WATCHER_WEIGHT: u64 = 3;
pub const DEFAULT_WATCHER_QUORUM_BPS: u64 = 6_700;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_MIN_CHURN_SUBADDRESSES: u32 = 8;
pub const DEFAULT_MAX_CHURN_SUBADDRESSES: u32 = 512;
pub const DEFAULT_VIEW_TAG_CACHE_BUCKETS: u32 = 256;
pub const DEFAULT_MAX_VIEW_TAG_CACHE_HITS: u64 = 4_096;
pub const DEFAULT_DAILY_DISCLOSURE_BUDGET: u64 = 64;
pub const DEFAULT_DAILY_SCAN_BUDGET: u64 = 262_144;
pub const DEFAULT_DAILY_ROTATION_BUDGET: u64 = 16;
pub const DEFAULT_MAX_USER_FEE_MICRO_UNITS: u64 = 20_000;
pub const DEFAULT_LOW_FEE_TARGET_MICRO_UNITS: u64 = 3_000;
pub const DEFAULT_BATCH_REBATE_BPS: u64 = 7_500;
pub const DEFAULT_BRIDGE_AUDIT_HOLD_BLOCKS: u64 = 72;
pub const DEFAULT_OPERATOR_REDACTION_DEPTH: u8 = 12;
pub const MAX_RECOVERY_REQUESTS: usize = 1_048_576;
pub const MAX_DISCLOSURE_GRANTS: usize = 2_097_152;
pub const MAX_SUBADDRESS_CHURNS: usize = 2_097_152;
pub const MAX_VIEW_TAG_CACHE_ENTRIES: usize = 4_194_304;
pub const MAX_WATCHER_ATTESTATIONS: usize = 4_194_304;
pub const MAX_RECOVERY_SHARES: usize = 4_194_304;
pub const MAX_SIGNER_ROTATIONS: usize = 1_048_576;
pub const MAX_PRIVACY_BUDGETS: usize = 1_048_576;
pub const MAX_LOW_FEE_BATCHES: usize = 524_288;
pub const MAX_BRIDGE_AUDIT_WINDOWS: usize = 524_288;
pub const MAX_OPERATOR_REDACTION_ROOTS: usize = 524_288;
pub const MAX_RECOVERY_RECEIPTS: usize = 2_097_152;
pub const MAX_PUBLIC_RECORDS: usize = 8_388_608;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryLane {
    LowFee,
    Fast,
    Defi,
    Token,
    SmartContract,
    BridgeAudit,
    Emergency,
}

impl RecoveryLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LowFee => "low_fee",
            Self::Fast => "fast",
            Self::Defi => "defi",
            Self::Token => "token",
            Self::SmartContract => "smart_contract",
            Self::BridgeAudit => "bridge_audit",
            Self::Emergency => "emergency",
        }
    }

    pub fn priority_weight(self) -> u64 {
        match self {
            Self::Emergency => 1_000,
            Self::BridgeAudit => 960,
            Self::Fast => 930,
            Self::SmartContract => 890,
            Self::Defi => 850,
            Self::Token => 810,
            Self::LowFee => 700,
        }
    }

    pub fn fee_cap(self, config: &Config) -> u64 {
        match self {
            Self::LowFee => config.low_fee_target_micro_units,
            Self::Fast | Self::Emergency => config.max_user_fee_micro_units,
            Self::Defi | Self::Token | Self::SmartContract | Self::BridgeAudit => {
                config.max_user_fee_micro_units.saturating_mul(8) / 10
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DisclosureScope {
    ViewTagsOnly,
    IncomingOutputs,
    KeyImages,
    SubaddressMap,
    RecoveryShares,
    SignerRotation,
    DefiPosition,
    TokenBalance,
    ContractCall,
    BridgeAuditWindow,
}

impl DisclosureScope {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ViewTagsOnly => "view_tags_only",
            Self::IncomingOutputs => "incoming_outputs",
            Self::KeyImages => "key_images",
            Self::SubaddressMap => "subaddress_map",
            Self::RecoveryShares => "recovery_shares",
            Self::SignerRotation => "signer_rotation",
            Self::DefiPosition => "defi_position",
            Self::TokenBalance => "token_balance",
            Self::ContractCall => "contract_call",
            Self::BridgeAuditWindow => "bridge_audit_window",
        }
    }

    pub fn privacy_cost(self) -> u64 {
        match self {
            Self::ViewTagsOnly => 1,
            Self::IncomingOutputs => 4,
            Self::KeyImages => 5,
            Self::SubaddressMap => 8,
            Self::RecoveryShares => 10,
            Self::SignerRotation => 7,
            Self::DefiPosition => 6,
            Self::TokenBalance => 5,
            Self::ContractCall => 6,
            Self::BridgeAuditWindow => 9,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryStatus {
    Drafted,
    Open,
    Disclosed,
    SharesSealed,
    WatcherQuorum,
    RotationQueued,
    Rotated,
    Batched,
    Auditing,
    Completed,
    Cancelled,
    Rejected,
    Expired,
    Slashed,
}

impl RecoveryStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Drafted => "drafted",
            Self::Open => "open",
            Self::Disclosed => "disclosed",
            Self::SharesSealed => "shares_sealed",
            Self::WatcherQuorum => "watcher_quorum",
            Self::RotationQueued => "rotation_queued",
            Self::Rotated => "rotated",
            Self::Batched => "batched",
            Self::Auditing => "auditing",
            Self::Completed => "completed",
            Self::Cancelled => "cancelled",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
            Self::Slashed => "slashed",
        }
    }

    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Open
                | Self::Disclosed
                | Self::SharesSealed
                | Self::WatcherQuorum
                | Self::RotationQueued
                | Self::Rotated
                | Self::Batched
                | Self::Auditing
        )
    }

    pub fn batchable(self) -> bool {
        matches!(
            self,
            Self::WatcherQuorum | Self::RotationQueued | Self::Rotated
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DisclosureStatus {
    Requested,
    PolicyLinked,
    BudgetReserved,
    ShareLinked,
    WatcherAttested,
    Released,
    Revoked,
    Rejected,
    Expired,
}

impl DisclosureStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Requested => "requested",
            Self::PolicyLinked => "policy_linked",
            Self::BudgetReserved => "budget_reserved",
            Self::ShareLinked => "share_linked",
            Self::WatcherAttested => "watcher_attested",
            Self::Released => "released",
            Self::Revoked => "revoked",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ChurnStatus {
    Planned,
    Reserved,
    CachePrimed,
    RotationLinked,
    Published,
    Settled,
    ReorgLocked,
    Expired,
}

impl ChurnStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Planned => "planned",
            Self::Reserved => "reserved",
            Self::CachePrimed => "cache_primed",
            Self::RotationLinked => "rotation_linked",
            Self::Published => "published",
            Self::Settled => "settled",
            Self::ReorgLocked => "reorg_locked",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CacheStatus {
    Warm,
    Primed,
    Attested,
    Consumed,
    ReorgLocked,
    Stale,
    Slashed,
}

impl CacheStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Warm => "warm",
            Self::Primed => "primed",
            Self::Attested => "attested",
            Self::Consumed => "consumed",
            Self::ReorgLocked => "reorg_locked",
            Self::Stale => "stale",
            Self::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WatcherRole {
    RecoveryShareWitness,
    ViewTagCacheWitness,
    SubaddressChurnWitness,
    BridgeAuditor,
    RedactionAuditor,
    RotationSigner,
}

impl WatcherRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RecoveryShareWitness => "recovery_share_witness",
            Self::ViewTagCacheWitness => "view_tag_cache_witness",
            Self::SubaddressChurnWitness => "subaddress_churn_witness",
            Self::BridgeAuditor => "bridge_auditor",
            Self::RedactionAuditor => "redaction_auditor",
            Self::RotationSigner => "rotation_signer",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationStatus {
    Submitted,
    Weighted,
    QuorumCounted,
    Disputed,
    Rejected,
    Slashed,
}

impl AttestationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Weighted => "weighted",
            Self::QuorumCounted => "quorum_counted",
            Self::Disputed => "disputed",
            Self::Rejected => "rejected",
            Self::Slashed => "slashed",
        }
    }

    pub fn counts_for_quorum(self) -> bool {
        matches!(self, Self::Weighted | Self::QuorumCounted)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ShareStatus {
    Advertised,
    Sealed,
    ThresholdCounted,
    Reconstructed,
    Revoked,
    Rejected,
    Slashed,
}

impl ShareStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Advertised => "advertised",
            Self::Sealed => "sealed",
            Self::ThresholdCounted => "threshold_counted",
            Self::Reconstructed => "reconstructed",
            Self::Revoked => "revoked",
            Self::Rejected => "rejected",
            Self::Slashed => "slashed",
        }
    }

    pub fn counts_for_threshold(self) -> bool {
        matches!(
            self,
            Self::Sealed | Self::ThresholdCounted | Self::Reconstructed
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RotationStatus {
    Proposed,
    ShareBound,
    WatcherAttested,
    CachePrimed,
    BridgeHold,
    Active,
    Superseded,
    Cancelled,
    Expired,
}

impl RotationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::ShareBound => "share_bound",
            Self::WatcherAttested => "watcher_attested",
            Self::CachePrimed => "cache_primed",
            Self::BridgeHold => "bridge_hold",
            Self::Active => "active",
            Self::Superseded => "superseded",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BudgetStatus {
    Open,
    Reserved,
    Consumed,
    Exhausted,
    Frozen,
    Reset,
}

impl BudgetStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Reserved => "reserved",
            Self::Consumed => "consumed",
            Self::Exhausted => "exhausted",
            Self::Frozen => "frozen",
            Self::Reset => "reset",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchStatus {
    Open,
    Packed,
    Sponsored,
    Submitted,
    Auditing,
    Settled,
    Rejected,
    Expired,
}

impl BatchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Packed => "packed",
            Self::Sponsored => "sponsored",
            Self::Submitted => "submitted",
            Self::Auditing => "auditing",
            Self::Settled => "settled",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditWindowStatus {
    Open,
    EvidenceCollecting,
    RedactionReview,
    Challengeable,
    Passed,
    Failed,
    Closed,
}

impl AuditWindowStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::EvidenceCollecting => "evidence_collecting",
            Self::RedactionReview => "redaction_review",
            Self::Challengeable => "challengeable",
            Self::Passed => "passed",
            Self::Failed => "failed",
            Self::Closed => "closed",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RedactionStatus {
    Drafted,
    Committed,
    WatcherAttested,
    AuditWindowLinked,
    Published,
    Challenged,
    Revoked,
}

impl RedactionStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Drafted => "drafted",
            Self::Committed => "committed",
            Self::WatcherAttested => "watcher_attested",
            Self::AuditWindowLinked => "audit_window_linked",
            Self::Published => "published",
            Self::Challenged => "challenged",
            Self::Revoked => "revoked",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub l2_network: String,
    pub monero_network: String,
    pub bridge_id: String,
    pub fee_asset_id: String,
    pub recovery_asset_id: String,
    pub operator_id: String,
    pub min_pq_security_bits: u16,
    pub target_pq_security_bits: u16,
    pub recovery_ttl_blocks: u64,
    pub disclosure_ttl_blocks: u64,
    pub share_ttl_blocks: u64,
    pub rotation_ttl_blocks: u64,
    pub scan_cache_ttl_blocks: u64,
    pub audit_window_blocks: u64,
    pub bridge_audit_hold_blocks: u64,
    pub min_recovery_threshold: u16,
    pub min_recovery_shares: u16,
    pub min_watcher_weight: u64,
    pub watcher_quorum_bps: u64,
    pub min_privacy_set_size: u64,
    pub min_churn_subaddresses: u32,
    pub max_churn_subaddresses: u32,
    pub view_tag_cache_buckets: u32,
    pub max_view_tag_cache_hits: u64,
    pub daily_disclosure_budget: u64,
    pub daily_scan_budget: u64,
    pub daily_rotation_budget: u64,
    pub max_user_fee_micro_units: u64,
    pub low_fee_target_micro_units: u64,
    pub batch_rebate_bps: u64,
    pub operator_redaction_depth: u8,
}

impl Config {
    pub fn devnet(operator_id: &str) -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            l2_network: DEVNET_L2_NETWORK.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            bridge_id: DEVNET_BRIDGE_ID.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            recovery_asset_id: DEVNET_RECOVERY_ASSET_ID.to_string(),
            operator_id: operator_id.to_string(),
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            target_pq_security_bits: DEFAULT_TARGET_PQ_SECURITY_BITS,
            recovery_ttl_blocks: DEFAULT_RECOVERY_TTL_BLOCKS,
            disclosure_ttl_blocks: DEFAULT_DISCLOSURE_TTL_BLOCKS,
            share_ttl_blocks: DEFAULT_SHARE_TTL_BLOCKS,
            rotation_ttl_blocks: DEFAULT_ROTATION_TTL_BLOCKS,
            scan_cache_ttl_blocks: DEFAULT_SCAN_CACHE_TTL_BLOCKS,
            audit_window_blocks: DEFAULT_AUDIT_WINDOW_BLOCKS,
            bridge_audit_hold_blocks: DEFAULT_BRIDGE_AUDIT_HOLD_BLOCKS,
            min_recovery_threshold: DEFAULT_MIN_RECOVERY_THRESHOLD,
            min_recovery_shares: DEFAULT_MIN_RECOVERY_SHARES,
            min_watcher_weight: DEFAULT_MIN_WATCHER_WEIGHT,
            watcher_quorum_bps: DEFAULT_WATCHER_QUORUM_BPS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            min_churn_subaddresses: DEFAULT_MIN_CHURN_SUBADDRESSES,
            max_churn_subaddresses: DEFAULT_MAX_CHURN_SUBADDRESSES,
            view_tag_cache_buckets: DEFAULT_VIEW_TAG_CACHE_BUCKETS,
            max_view_tag_cache_hits: DEFAULT_MAX_VIEW_TAG_CACHE_HITS,
            daily_disclosure_budget: DEFAULT_DAILY_DISCLOSURE_BUDGET,
            daily_scan_budget: DEFAULT_DAILY_SCAN_BUDGET,
            daily_rotation_budget: DEFAULT_DAILY_ROTATION_BUDGET,
            max_user_fee_micro_units: DEFAULT_MAX_USER_FEE_MICRO_UNITS,
            low_fee_target_micro_units: DEFAULT_LOW_FEE_TARGET_MICRO_UNITS,
            batch_rebate_bps: DEFAULT_BATCH_REBATE_BPS,
            operator_redaction_depth: DEFAULT_OPERATOR_REDACTION_DEPTH,
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.chain_id.trim().is_empty() {
            return Err("chain_id cannot be empty".to_string());
        }
        if self.operator_id.trim().is_empty() {
            return Err("operator_id cannot be empty".to_string());
        }
        if self.min_pq_security_bits < DEFAULT_MIN_PQ_SECURITY_BITS {
            return Err("min_pq_security_bits below runtime floor".to_string());
        }
        if self.target_pq_security_bits < self.min_pq_security_bits {
            return Err("target_pq_security_bits below min_pq_security_bits".to_string());
        }
        if self.min_recovery_threshold == 0 {
            return Err("min_recovery_threshold cannot be zero".to_string());
        }
        if self.min_recovery_shares < self.min_recovery_threshold {
            return Err("min_recovery_shares below recovery threshold".to_string());
        }
        if self.watcher_quorum_bps > MAX_BPS {
            return Err("watcher_quorum_bps exceeds MAX_BPS".to_string());
        }
        if self.batch_rebate_bps > MAX_BPS {
            return Err("batch_rebate_bps exceeds MAX_BPS".to_string());
        }
        if self.min_churn_subaddresses > self.max_churn_subaddresses {
            return Err("min_churn_subaddresses exceeds max_churn_subaddresses".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "l2_network": self.l2_network,
            "monero_network": self.monero_network,
            "bridge_id": self.bridge_id,
            "fee_asset_id": self.fee_asset_id,
            "recovery_asset_id": self.recovery_asset_id,
            "operator_id": self.operator_id,
            "min_pq_security_bits": self.min_pq_security_bits,
            "target_pq_security_bits": self.target_pq_security_bits,
            "recovery_ttl_blocks": self.recovery_ttl_blocks,
            "disclosure_ttl_blocks": self.disclosure_ttl_blocks,
            "share_ttl_blocks": self.share_ttl_blocks,
            "rotation_ttl_blocks": self.rotation_ttl_blocks,
            "scan_cache_ttl_blocks": self.scan_cache_ttl_blocks,
            "audit_window_blocks": self.audit_window_blocks,
            "bridge_audit_hold_blocks": self.bridge_audit_hold_blocks,
            "min_recovery_threshold": self.min_recovery_threshold,
            "min_recovery_shares": self.min_recovery_shares,
            "min_watcher_weight": self.min_watcher_weight,
            "watcher_quorum_bps": self.watcher_quorum_bps,
            "min_privacy_set_size": self.min_privacy_set_size,
            "min_churn_subaddresses": self.min_churn_subaddresses,
            "max_churn_subaddresses": self.max_churn_subaddresses,
            "view_tag_cache_buckets": self.view_tag_cache_buckets,
            "max_view_tag_cache_hits": self.max_view_tag_cache_hits,
            "daily_disclosure_budget": self.daily_disclosure_budget,
            "daily_scan_budget": self.daily_scan_budget,
            "daily_rotation_budget": self.daily_rotation_budget,
            "max_user_fee_micro_units": self.max_user_fee_micro_units,
            "low_fee_target_micro_units": self.low_fee_target_micro_units,
            "batch_rebate_bps": self.batch_rebate_bps,
            "operator_redaction_depth": self.operator_redaction_depth,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Counters {
    pub recovery_requests_opened: u64,
    pub recovery_requests_completed: u64,
    pub disclosure_grants_registered: u64,
    pub disclosures_released: u64,
    pub subaddress_churns_planned: u64,
    pub subaddress_churns_settled: u64,
    pub view_tag_cache_entries_primed: u64,
    pub view_tag_cache_hits: u64,
    pub watcher_attestations_counted: u64,
    pub encrypted_recovery_shares_sealed: u64,
    pub encrypted_recovery_shares_used: u64,
    pub pq_signer_rotations_activated: u64,
    pub privacy_budget_units_reserved: u64,
    pub privacy_budget_units_consumed: u64,
    pub low_fee_batches_settled: u64,
    pub low_fee_rebate_micro_units: u64,
    pub bridge_audit_windows_closed: u64,
    pub operator_redaction_roots_published: u64,
    pub recovery_receipts_issued: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "recovery_requests_opened": self.recovery_requests_opened,
            "recovery_requests_completed": self.recovery_requests_completed,
            "disclosure_grants_registered": self.disclosure_grants_registered,
            "disclosures_released": self.disclosures_released,
            "subaddress_churns_planned": self.subaddress_churns_planned,
            "subaddress_churns_settled": self.subaddress_churns_settled,
            "view_tag_cache_entries_primed": self.view_tag_cache_entries_primed,
            "view_tag_cache_hits": self.view_tag_cache_hits,
            "watcher_attestations_counted": self.watcher_attestations_counted,
            "encrypted_recovery_shares_sealed": self.encrypted_recovery_shares_sealed,
            "encrypted_recovery_shares_used": self.encrypted_recovery_shares_used,
            "pq_signer_rotations_activated": self.pq_signer_rotations_activated,
            "privacy_budget_units_reserved": self.privacy_budget_units_reserved,
            "privacy_budget_units_consumed": self.privacy_budget_units_consumed,
            "low_fee_batches_settled": self.low_fee_batches_settled,
            "low_fee_rebate_micro_units": self.low_fee_rebate_micro_units,
            "bridge_audit_windows_closed": self.bridge_audit_windows_closed,
            "operator_redaction_roots_published": self.operator_redaction_roots_published,
            "recovery_receipts_issued": self.recovery_receipts_issued,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Roots {
    pub recovery_request_root: String,
    pub disclosure_grant_root: String,
    pub subaddress_churn_root: String,
    pub view_tag_cache_root: String,
    pub watcher_attestation_root: String,
    pub recovery_share_root: String,
    pub signer_rotation_root: String,
    pub privacy_budget_root: String,
    pub low_fee_batch_root: String,
    pub bridge_audit_window_root: String,
    pub operator_redaction_root: String,
    pub recovery_receipt_root: String,
    pub public_record_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "recovery_request_root": self.recovery_request_root,
            "disclosure_grant_root": self.disclosure_grant_root,
            "subaddress_churn_root": self.subaddress_churn_root,
            "view_tag_cache_root": self.view_tag_cache_root,
            "watcher_attestation_root": self.watcher_attestation_root,
            "recovery_share_root": self.recovery_share_root,
            "signer_rotation_root": self.signer_rotation_root,
            "privacy_budget_root": self.privacy_budget_root,
            "low_fee_batch_root": self.low_fee_batch_root,
            "bridge_audit_window_root": self.bridge_audit_window_root,
            "operator_redaction_root": self.operator_redaction_root,
            "recovery_receipt_root": self.recovery_receipt_root,
            "public_record_root": self.public_record_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RecoveryRequest {
    pub request_id: String,
    pub owner_commitment: String,
    pub account_commitment: String,
    pub previous_viewkey_commitment: String,
    pub target_viewkey_commitment: String,
    pub recovery_policy_root: String,
    pub privacy_budget_id: String,
    pub lane: RecoveryLane,
    pub status: RecoveryStatus,
    pub opened_height: u64,
    pub expires_height: u64,
    pub min_share_threshold: u16,
    pub min_watcher_weight: u64,
    pub disclosure_scope_root: String,
    pub subaddress_churn_id: String,
    pub view_tag_cache_id: String,
    pub bridge_audit_window_id: String,
    pub fee_cap_micro_units: u64,
    pub redaction_root_id: String,
    pub notes_commitment: String,
}

impl RecoveryRequest {
    pub fn new(input: RecoveryRequestInput, config: &Config) -> Result<Self> {
        if input.owner_commitment.trim().is_empty() {
            return Err("owner_commitment cannot be empty".to_string());
        }
        if input.account_commitment.trim().is_empty() {
            return Err("account_commitment cannot be empty".to_string());
        }
        if input.previous_viewkey_commitment == input.target_viewkey_commitment {
            return Err("target_viewkey_commitment must rotate away from previous".to_string());
        }
        if input.min_share_threshold < config.min_recovery_threshold {
            return Err("min_share_threshold below configured threshold".to_string());
        }
        if input.fee_cap_micro_units > input.lane.fee_cap(config) {
            return Err("fee_cap_micro_units exceeds lane fee cap".to_string());
        }
        let expires_height = input
            .opened_height
            .saturating_add(config.recovery_ttl_blocks);
        let disclosure_scope_root = scope_root(&input.disclosure_scopes);
        let request_id = public_record_id(
            "RECOVERY-REQUEST-ID",
            &json!({
                "owner_commitment": input.owner_commitment,
                "account_commitment": input.account_commitment,
                "previous_viewkey_commitment": input.previous_viewkey_commitment,
                "target_viewkey_commitment": input.target_viewkey_commitment,
                "opened_height": input.opened_height,
                "lane": input.lane.as_str(),
                "disclosure_scope_root": disclosure_scope_root,
            }),
        );
        Ok(Self {
            request_id,
            owner_commitment: input.owner_commitment,
            account_commitment: input.account_commitment,
            previous_viewkey_commitment: input.previous_viewkey_commitment,
            target_viewkey_commitment: input.target_viewkey_commitment,
            recovery_policy_root: input.recovery_policy_root,
            privacy_budget_id: input.privacy_budget_id,
            lane: input.lane,
            status: RecoveryStatus::Open,
            opened_height: input.opened_height,
            expires_height,
            min_share_threshold: input.min_share_threshold,
            min_watcher_weight: input.min_watcher_weight,
            disclosure_scope_root,
            subaddress_churn_id: input.subaddress_churn_id,
            view_tag_cache_id: input.view_tag_cache_id,
            bridge_audit_window_id: input.bridge_audit_window_id,
            fee_cap_micro_units: input.fee_cap_micro_units,
            redaction_root_id: input.redaction_root_id,
            notes_commitment: input.notes_commitment,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "request_id": self.request_id,
            "owner_commitment": self.owner_commitment,
            "account_commitment": self.account_commitment,
            "previous_viewkey_commitment": self.previous_viewkey_commitment,
            "target_viewkey_commitment": self.target_viewkey_commitment,
            "recovery_policy_root": self.recovery_policy_root,
            "privacy_budget_id": self.privacy_budget_id,
            "lane": self.lane.as_str(),
            "status": self.status.as_str(),
            "opened_height": self.opened_height,
            "expires_height": self.expires_height,
            "min_share_threshold": self.min_share_threshold,
            "min_watcher_weight": self.min_watcher_weight,
            "disclosure_scope_root": self.disclosure_scope_root,
            "subaddress_churn_id": self.subaddress_churn_id,
            "view_tag_cache_id": self.view_tag_cache_id,
            "bridge_audit_window_id": self.bridge_audit_window_id,
            "fee_cap_micro_units": self.fee_cap_micro_units,
            "redaction_root_id": self.redaction_root_id,
            "notes_commitment": self.notes_commitment,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RecoveryRequestInput {
    pub owner_commitment: String,
    pub account_commitment: String,
    pub previous_viewkey_commitment: String,
    pub target_viewkey_commitment: String,
    pub recovery_policy_root: String,
    pub privacy_budget_id: String,
    pub lane: RecoveryLane,
    pub opened_height: u64,
    pub min_share_threshold: u16,
    pub min_watcher_weight: u64,
    pub disclosure_scopes: Vec<DisclosureScope>,
    pub subaddress_churn_id: String,
    pub view_tag_cache_id: String,
    pub bridge_audit_window_id: String,
    pub fee_cap_micro_units: u64,
    pub redaction_root_id: String,
    pub notes_commitment: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SelectiveDisclosureGrant {
    pub grant_id: String,
    pub request_id: String,
    pub auditor_commitment: String,
    pub scope: DisclosureScope,
    pub status: DisclosureStatus,
    pub policy_root: String,
    pub encrypted_payload_root: String,
    pub nullifier: String,
    pub opened_height: u64,
    pub expires_height: u64,
    pub privacy_cost_units: u64,
    pub release_commitment: String,
}

impl SelectiveDisclosureGrant {
    pub fn new(input: SelectiveDisclosureGrantInput, config: &Config) -> Result<Self> {
        if input.request_id.trim().is_empty() {
            return Err("request_id cannot be empty".to_string());
        }
        if input.nullifier.trim().is_empty() {
            return Err("nullifier cannot be empty".to_string());
        }
        let privacy_cost_units = input.scope.privacy_cost();
        let expires_height = input
            .opened_height
            .saturating_add(config.disclosure_ttl_blocks);
        let grant_id = public_record_id(
            "DISCLOSURE-GRANT-ID",
            &json!({
                "request_id": input.request_id,
                "auditor_commitment": input.auditor_commitment,
                "scope": input.scope.as_str(),
                "nullifier": input.nullifier,
                "opened_height": input.opened_height,
            }),
        );
        Ok(Self {
            grant_id,
            request_id: input.request_id,
            auditor_commitment: input.auditor_commitment,
            scope: input.scope,
            status: DisclosureStatus::Requested,
            policy_root: input.policy_root,
            encrypted_payload_root: input.encrypted_payload_root,
            nullifier: input.nullifier,
            opened_height: input.opened_height,
            expires_height,
            privacy_cost_units,
            release_commitment: input.release_commitment,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "grant_id": self.grant_id,
            "request_id": self.request_id,
            "auditor_commitment": self.auditor_commitment,
            "scope": self.scope.as_str(),
            "status": self.status.as_str(),
            "policy_root": self.policy_root,
            "encrypted_payload_root": self.encrypted_payload_root,
            "nullifier": self.nullifier,
            "opened_height": self.opened_height,
            "expires_height": self.expires_height,
            "privacy_cost_units": self.privacy_cost_units,
            "release_commitment": self.release_commitment,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SelectiveDisclosureGrantInput {
    pub request_id: String,
    pub auditor_commitment: String,
    pub scope: DisclosureScope,
    pub policy_root: String,
    pub encrypted_payload_root: String,
    pub nullifier: String,
    pub opened_height: u64,
    pub release_commitment: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SubaddressChurnPlan {
    pub churn_id: String,
    pub account_commitment: String,
    pub request_id: String,
    pub status: ChurnStatus,
    pub planned_height: u64,
    pub valid_until_height: u64,
    pub old_subaddress_root: String,
    pub new_subaddress_root: String,
    pub churn_count: u32,
    pub decoy_set_root: String,
    pub scan_cache_hint_root: String,
    pub fee_sponsor_commitment: String,
}

impl SubaddressChurnPlan {
    pub fn new(input: SubaddressChurnPlanInput, config: &Config) -> Result<Self> {
        if input.churn_count < config.min_churn_subaddresses {
            return Err("churn_count below min_churn_subaddresses".to_string());
        }
        if input.churn_count > config.max_churn_subaddresses {
            return Err("churn_count exceeds max_churn_subaddresses".to_string());
        }
        let valid_until_height = input
            .planned_height
            .saturating_add(config.rotation_ttl_blocks);
        let churn_id = public_record_id(
            "SUBADDRESS-CHURN-ID",
            &json!({
                "account_commitment": input.account_commitment,
                "request_id": input.request_id,
                "old_subaddress_root": input.old_subaddress_root,
                "new_subaddress_root": input.new_subaddress_root,
                "planned_height": input.planned_height,
                "churn_count": input.churn_count,
            }),
        );
        Ok(Self {
            churn_id,
            account_commitment: input.account_commitment,
            request_id: input.request_id,
            status: ChurnStatus::Planned,
            planned_height: input.planned_height,
            valid_until_height,
            old_subaddress_root: input.old_subaddress_root,
            new_subaddress_root: input.new_subaddress_root,
            churn_count: input.churn_count,
            decoy_set_root: input.decoy_set_root,
            scan_cache_hint_root: input.scan_cache_hint_root,
            fee_sponsor_commitment: input.fee_sponsor_commitment,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "churn_id": self.churn_id,
            "account_commitment": self.account_commitment,
            "request_id": self.request_id,
            "status": self.status.as_str(),
            "planned_height": self.planned_height,
            "valid_until_height": self.valid_until_height,
            "old_subaddress_root": self.old_subaddress_root,
            "new_subaddress_root": self.new_subaddress_root,
            "churn_count": self.churn_count,
            "decoy_set_root": self.decoy_set_root,
            "scan_cache_hint_root": self.scan_cache_hint_root,
            "fee_sponsor_commitment": self.fee_sponsor_commitment,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SubaddressChurnPlanInput {
    pub account_commitment: String,
    pub request_id: String,
    pub planned_height: u64,
    pub old_subaddress_root: String,
    pub new_subaddress_root: String,
    pub churn_count: u32,
    pub decoy_set_root: String,
    pub scan_cache_hint_root: String,
    pub fee_sponsor_commitment: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ViewTagScanCacheEntry {
    pub cache_id: String,
    pub request_id: String,
    pub account_commitment: String,
    pub status: CacheStatus,
    pub bucket_index: u32,
    pub view_tag_prefix: String,
    pub encrypted_match_root: String,
    pub scan_window_start: u64,
    pub scan_window_end: u64,
    pub hit_count: u64,
    pub cache_provider_commitment: String,
    pub watcher_attestation_root: String,
    pub expires_height: u64,
}

impl ViewTagScanCacheEntry {
    pub fn new(input: ViewTagScanCacheEntryInput, config: &Config) -> Result<Self> {
        if input.scan_window_end < input.scan_window_start {
            return Err("scan_window_end before scan_window_start".to_string());
        }
        if input.bucket_index >= config.view_tag_cache_buckets {
            return Err("bucket_index exceeds configured bucket count".to_string());
        }
        if input.hit_count > config.max_view_tag_cache_hits {
            return Err("hit_count exceeds max_view_tag_cache_hits".to_string());
        }
        let expires_height = input
            .scan_window_end
            .saturating_add(config.scan_cache_ttl_blocks);
        let cache_id = public_record_id(
            "VIEW-TAG-CACHE-ID",
            &json!({
                "request_id": input.request_id,
                "account_commitment": input.account_commitment,
                "bucket_index": input.bucket_index,
                "view_tag_prefix": input.view_tag_prefix,
                "scan_window_start": input.scan_window_start,
                "scan_window_end": input.scan_window_end,
            }),
        );
        Ok(Self {
            cache_id,
            request_id: input.request_id,
            account_commitment: input.account_commitment,
            status: CacheStatus::Warm,
            bucket_index: input.bucket_index,
            view_tag_prefix: input.view_tag_prefix,
            encrypted_match_root: input.encrypted_match_root,
            scan_window_start: input.scan_window_start,
            scan_window_end: input.scan_window_end,
            hit_count: input.hit_count,
            cache_provider_commitment: input.cache_provider_commitment,
            watcher_attestation_root: input.watcher_attestation_root,
            expires_height,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "cache_id": self.cache_id,
            "request_id": self.request_id,
            "account_commitment": self.account_commitment,
            "status": self.status.as_str(),
            "bucket_index": self.bucket_index,
            "view_tag_prefix": self.view_tag_prefix,
            "encrypted_match_root": self.encrypted_match_root,
            "scan_window_start": self.scan_window_start,
            "scan_window_end": self.scan_window_end,
            "hit_count": self.hit_count,
            "cache_provider_commitment": self.cache_provider_commitment,
            "watcher_attestation_root": self.watcher_attestation_root,
            "expires_height": self.expires_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ViewTagScanCacheEntryInput {
    pub request_id: String,
    pub account_commitment: String,
    pub bucket_index: u32,
    pub view_tag_prefix: String,
    pub encrypted_match_root: String,
    pub scan_window_start: u64,
    pub scan_window_end: u64,
    pub hit_count: u64,
    pub cache_provider_commitment: String,
    pub watcher_attestation_root: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WatcherAttestation {
    pub attestation_id: String,
    pub request_id: String,
    pub watcher_commitment: String,
    pub role: WatcherRole,
    pub status: AttestationStatus,
    pub weight: u64,
    pub attested_height: u64,
    pub evidence_root: String,
    pub signature_root: String,
    pub slashing_nullifier: String,
}

impl WatcherAttestation {
    pub fn new(input: WatcherAttestationInput, config: &Config) -> Result<Self> {
        if input.weight < config.min_watcher_weight {
            return Err("watcher attestation weight below minimum".to_string());
        }
        if input.slashing_nullifier.trim().is_empty() {
            return Err("slashing_nullifier cannot be empty".to_string());
        }
        let attestation_id = public_record_id(
            "WATCHER-ATTESTATION-ID",
            &json!({
                "request_id": input.request_id,
                "watcher_commitment": input.watcher_commitment,
                "role": input.role.as_str(),
                "attested_height": input.attested_height,
                "slashing_nullifier": input.slashing_nullifier,
            }),
        );
        Ok(Self {
            attestation_id,
            request_id: input.request_id,
            watcher_commitment: input.watcher_commitment,
            role: input.role,
            status: AttestationStatus::Submitted,
            weight: input.weight,
            attested_height: input.attested_height,
            evidence_root: input.evidence_root,
            signature_root: input.signature_root,
            slashing_nullifier: input.slashing_nullifier,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "request_id": self.request_id,
            "watcher_commitment": self.watcher_commitment,
            "role": self.role.as_str(),
            "status": self.status.as_str(),
            "weight": self.weight,
            "attested_height": self.attested_height,
            "evidence_root": self.evidence_root,
            "signature_root": self.signature_root,
            "slashing_nullifier": self.slashing_nullifier,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WatcherAttestationInput {
    pub request_id: String,
    pub watcher_commitment: String,
    pub role: WatcherRole,
    pub weight: u64,
    pub attested_height: u64,
    pub evidence_root: String,
    pub signature_root: String,
    pub slashing_nullifier: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct EncryptedRecoveryShare {
    pub share_id: String,
    pub request_id: String,
    pub custodian_commitment: String,
    pub status: ShareStatus,
    pub share_index: u16,
    pub threshold: u16,
    pub pq_security_bits: u16,
    pub kem_ciphertext_root: String,
    pub share_commitment: String,
    pub recipient_commitment: String,
    pub sealed_height: u64,
    pub expires_height: u64,
    pub disclosure_grant_id: String,
}

impl EncryptedRecoveryShare {
    pub fn new(input: EncryptedRecoveryShareInput, config: &Config) -> Result<Self> {
        if input.threshold < config.min_recovery_threshold {
            return Err("share threshold below configured minimum".to_string());
        }
        if input.pq_security_bits < config.min_pq_security_bits {
            return Err("pq_security_bits below configured minimum".to_string());
        }
        let expires_height = input.sealed_height.saturating_add(config.share_ttl_blocks);
        let share_id = public_record_id(
            "ENCRYPTED-RECOVERY-SHARE-ID",
            &json!({
                "request_id": input.request_id,
                "custodian_commitment": input.custodian_commitment,
                "share_index": input.share_index,
                "threshold": input.threshold,
                "share_commitment": input.share_commitment,
                "sealed_height": input.sealed_height,
            }),
        );
        Ok(Self {
            share_id,
            request_id: input.request_id,
            custodian_commitment: input.custodian_commitment,
            status: ShareStatus::Sealed,
            share_index: input.share_index,
            threshold: input.threshold,
            pq_security_bits: input.pq_security_bits,
            kem_ciphertext_root: input.kem_ciphertext_root,
            share_commitment: input.share_commitment,
            recipient_commitment: input.recipient_commitment,
            sealed_height: input.sealed_height,
            expires_height,
            disclosure_grant_id: input.disclosure_grant_id,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "share_id": self.share_id,
            "request_id": self.request_id,
            "custodian_commitment": self.custodian_commitment,
            "status": self.status.as_str(),
            "share_index": self.share_index,
            "threshold": self.threshold,
            "pq_security_bits": self.pq_security_bits,
            "kem_ciphertext_root": self.kem_ciphertext_root,
            "share_commitment": self.share_commitment,
            "recipient_commitment": self.recipient_commitment,
            "sealed_height": self.sealed_height,
            "expires_height": self.expires_height,
            "disclosure_grant_id": self.disclosure_grant_id,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct EncryptedRecoveryShareInput {
    pub request_id: String,
    pub custodian_commitment: String,
    pub share_index: u16,
    pub threshold: u16,
    pub pq_security_bits: u16,
    pub kem_ciphertext_root: String,
    pub share_commitment: String,
    pub recipient_commitment: String,
    pub sealed_height: u64,
    pub disclosure_grant_id: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PqSignerRotation {
    pub rotation_id: String,
    pub request_id: String,
    pub account_commitment: String,
    pub status: RotationStatus,
    pub old_signer_root: String,
    pub new_signer_root: String,
    pub pq_auth_root: String,
    pub watcher_quorum_root: String,
    pub subaddress_churn_id: String,
    pub proposed_height: u64,
    pub activates_height: u64,
    pub expires_height: u64,
}

impl PqSignerRotation {
    pub fn new(input: PqSignerRotationInput, config: &Config) -> Result<Self> {
        if input.old_signer_root == input.new_signer_root {
            return Err("new_signer_root must differ from old_signer_root".to_string());
        }
        let activates_height = input
            .proposed_height
            .saturating_add(config.bridge_audit_hold_blocks);
        let expires_height = input
            .proposed_height
            .saturating_add(config.rotation_ttl_blocks);
        let rotation_id = public_record_id(
            "PQ-SIGNER-ROTATION-ID",
            &json!({
                "request_id": input.request_id,
                "account_commitment": input.account_commitment,
                "old_signer_root": input.old_signer_root,
                "new_signer_root": input.new_signer_root,
                "proposed_height": input.proposed_height,
            }),
        );
        Ok(Self {
            rotation_id,
            request_id: input.request_id,
            account_commitment: input.account_commitment,
            status: RotationStatus::Proposed,
            old_signer_root: input.old_signer_root,
            new_signer_root: input.new_signer_root,
            pq_auth_root: input.pq_auth_root,
            watcher_quorum_root: input.watcher_quorum_root,
            subaddress_churn_id: input.subaddress_churn_id,
            proposed_height: input.proposed_height,
            activates_height,
            expires_height,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "rotation_id": self.rotation_id,
            "request_id": self.request_id,
            "account_commitment": self.account_commitment,
            "status": self.status.as_str(),
            "old_signer_root": self.old_signer_root,
            "new_signer_root": self.new_signer_root,
            "pq_auth_root": self.pq_auth_root,
            "watcher_quorum_root": self.watcher_quorum_root,
            "subaddress_churn_id": self.subaddress_churn_id,
            "proposed_height": self.proposed_height,
            "activates_height": self.activates_height,
            "expires_height": self.expires_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PqSignerRotationInput {
    pub request_id: String,
    pub account_commitment: String,
    pub old_signer_root: String,
    pub new_signer_root: String,
    pub pq_auth_root: String,
    pub watcher_quorum_root: String,
    pub subaddress_churn_id: String,
    pub proposed_height: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PrivacyBudgetAccount {
    pub budget_id: String,
    pub account_commitment: String,
    pub epoch: u64,
    pub status: BudgetStatus,
    pub disclosure_limit: u64,
    pub disclosure_reserved: u64,
    pub disclosure_consumed: u64,
    pub scan_limit: u64,
    pub scan_reserved: u64,
    pub scan_consumed: u64,
    pub rotation_limit: u64,
    pub rotation_reserved: u64,
    pub rotation_consumed: u64,
    pub policy_root: String,
}

impl PrivacyBudgetAccount {
    pub fn new(input: PrivacyBudgetInput, config: &Config) -> Result<Self> {
        if input.account_commitment.trim().is_empty() {
            return Err("account_commitment cannot be empty".to_string());
        }
        let budget_id = public_record_id(
            "PRIVACY-BUDGET-ID",
            &json!({
                "account_commitment": input.account_commitment,
                "epoch": input.epoch,
                "policy_root": input.policy_root,
            }),
        );
        Ok(Self {
            budget_id,
            account_commitment: input.account_commitment,
            epoch: input.epoch,
            status: BudgetStatus::Open,
            disclosure_limit: input.disclosure_limit.min(config.daily_disclosure_budget),
            disclosure_reserved: 0,
            disclosure_consumed: 0,
            scan_limit: input.scan_limit.min(config.daily_scan_budget),
            scan_reserved: 0,
            scan_consumed: 0,
            rotation_limit: input.rotation_limit.min(config.daily_rotation_budget),
            rotation_reserved: 0,
            rotation_consumed: 0,
            policy_root: input.policy_root,
        })
    }

    pub fn reserve_disclosure(&mut self, units: u64) -> Result<()> {
        let next = self.disclosure_reserved.saturating_add(units);
        if next.saturating_add(self.disclosure_consumed) > self.disclosure_limit {
            self.status = BudgetStatus::Exhausted;
            return Err("disclosure privacy budget exhausted".to_string());
        }
        self.disclosure_reserved = next;
        self.status = BudgetStatus::Reserved;
        Ok(())
    }

    pub fn consume_disclosure(&mut self, units: u64) -> Result<()> {
        if units > self.disclosure_reserved {
            return Err("cannot consume unreserved disclosure budget".to_string());
        }
        self.disclosure_reserved = self.disclosure_reserved.saturating_sub(units);
        self.disclosure_consumed = self.disclosure_consumed.saturating_add(units);
        self.status = BudgetStatus::Consumed;
        Ok(())
    }

    pub fn reserve_scan(&mut self, units: u64) -> Result<()> {
        let next = self.scan_reserved.saturating_add(units);
        if next.saturating_add(self.scan_consumed) > self.scan_limit {
            self.status = BudgetStatus::Exhausted;
            return Err("scan privacy budget exhausted".to_string());
        }
        self.scan_reserved = next;
        self.status = BudgetStatus::Reserved;
        Ok(())
    }

    pub fn reserve_rotation(&mut self, units: u64) -> Result<()> {
        let next = self.rotation_reserved.saturating_add(units);
        if next.saturating_add(self.rotation_consumed) > self.rotation_limit {
            self.status = BudgetStatus::Exhausted;
            return Err("rotation privacy budget exhausted".to_string());
        }
        self.rotation_reserved = next;
        self.status = BudgetStatus::Reserved;
        Ok(())
    }

    pub fn consume_rotation(&mut self, units: u64) -> Result<()> {
        if units > self.rotation_reserved {
            return Err("cannot consume unreserved rotation budget".to_string());
        }
        self.rotation_reserved = self.rotation_reserved.saturating_sub(units);
        self.rotation_consumed = self.rotation_consumed.saturating_add(units);
        self.status = BudgetStatus::Consumed;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "budget_id": self.budget_id,
            "account_commitment": self.account_commitment,
            "epoch": self.epoch,
            "status": self.status.as_str(),
            "disclosure_limit": self.disclosure_limit,
            "disclosure_reserved": self.disclosure_reserved,
            "disclosure_consumed": self.disclosure_consumed,
            "scan_limit": self.scan_limit,
            "scan_reserved": self.scan_reserved,
            "scan_consumed": self.scan_consumed,
            "rotation_limit": self.rotation_limit,
            "rotation_reserved": self.rotation_reserved,
            "rotation_consumed": self.rotation_consumed,
            "policy_root": self.policy_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PrivacyBudgetInput {
    pub account_commitment: String,
    pub epoch: u64,
    pub disclosure_limit: u64,
    pub scan_limit: u64,
    pub rotation_limit: u64,
    pub policy_root: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LowFeeRecoveryBatch {
    pub batch_id: String,
    pub status: BatchStatus,
    pub lane: RecoveryLane,
    pub request_ids: Vec<String>,
    pub disclosure_grant_ids: Vec<String>,
    pub share_ids: Vec<String>,
    pub rotation_ids: Vec<String>,
    pub packed_height: u64,
    pub settlement_height: u64,
    pub gross_fee_micro_units: u64,
    pub rebate_micro_units: u64,
    pub sponsor_commitment: String,
    pub batch_root: String,
    pub audit_window_id: String,
}

impl LowFeeRecoveryBatch {
    pub fn new(input: LowFeeRecoveryBatchInput, config: &Config) -> Result<Self> {
        if input.request_ids.is_empty() {
            return Err("batch must include at least one recovery request".to_string());
        }
        let gross_fee_micro_units = input
            .request_ids
            .len()
            .saturating_mul(config.low_fee_target_micro_units as usize)
            as u64;
        let rebate_micro_units =
            gross_fee_micro_units.saturating_mul(config.batch_rebate_bps) / MAX_BPS;
        let mut leaves = Vec::new();
        leaves.extend(
            input
                .request_ids
                .iter()
                .map(|item| Value::String(item.clone())),
        );
        leaves.extend(
            input
                .disclosure_grant_ids
                .iter()
                .map(|item| Value::String(item.clone())),
        );
        leaves.extend(
            input
                .share_ids
                .iter()
                .map(|item| Value::String(item.clone())),
        );
        leaves.extend(
            input
                .rotation_ids
                .iter()
                .map(|item| Value::String(item.clone())),
        );
        let batch_root = merkle_root(LOW_FEE_BATCH_SCHEME, &leaves);
        let batch_id = public_record_id(
            "LOW-FEE-RECOVERY-BATCH-ID",
            &json!({
                "lane": input.lane.as_str(),
                "packed_height": input.packed_height,
                "batch_root": batch_root,
                "sponsor_commitment": input.sponsor_commitment,
            }),
        );
        Ok(Self {
            batch_id,
            status: BatchStatus::Open,
            lane: input.lane,
            request_ids: input.request_ids,
            disclosure_grant_ids: input.disclosure_grant_ids,
            share_ids: input.share_ids,
            rotation_ids: input.rotation_ids,
            packed_height: input.packed_height,
            settlement_height: input.settlement_height,
            gross_fee_micro_units,
            rebate_micro_units,
            sponsor_commitment: input.sponsor_commitment,
            batch_root,
            audit_window_id: input.audit_window_id,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "status": self.status.as_str(),
            "lane": self.lane.as_str(),
            "request_ids": self.request_ids,
            "disclosure_grant_ids": self.disclosure_grant_ids,
            "share_ids": self.share_ids,
            "rotation_ids": self.rotation_ids,
            "packed_height": self.packed_height,
            "settlement_height": self.settlement_height,
            "gross_fee_micro_units": self.gross_fee_micro_units,
            "rebate_micro_units": self.rebate_micro_units,
            "sponsor_commitment": self.sponsor_commitment,
            "batch_root": self.batch_root,
            "audit_window_id": self.audit_window_id,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LowFeeRecoveryBatchInput {
    pub lane: RecoveryLane,
    pub request_ids: Vec<String>,
    pub disclosure_grant_ids: Vec<String>,
    pub share_ids: Vec<String>,
    pub rotation_ids: Vec<String>,
    pub packed_height: u64,
    pub settlement_height: u64,
    pub sponsor_commitment: String,
    pub audit_window_id: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BridgeAuditWindow {
    pub audit_window_id: String,
    pub request_id: String,
    pub status: AuditWindowStatus,
    pub bridge_epoch: u64,
    pub start_height: u64,
    pub end_height: u64,
    pub evidence_root: String,
    pub watcher_quorum_root: String,
    pub redaction_root_id: String,
    pub challenged_nullifiers: Vec<String>,
    pub settlement_root: String,
}

impl BridgeAuditWindow {
    pub fn new(input: BridgeAuditWindowInput, config: &Config) -> Result<Self> {
        if input.end_height < input.start_height {
            return Err("audit window end_height before start_height".to_string());
        }
        if input.end_height.saturating_sub(input.start_height) > config.audit_window_blocks {
            return Err("audit window exceeds configured block span".to_string());
        }
        let audit_window_id = public_record_id(
            "BRIDGE-AUDIT-WINDOW-ID",
            &json!({
                "request_id": input.request_id,
                "bridge_epoch": input.bridge_epoch,
                "start_height": input.start_height,
                "end_height": input.end_height,
                "evidence_root": input.evidence_root,
            }),
        );
        Ok(Self {
            audit_window_id,
            request_id: input.request_id,
            status: AuditWindowStatus::Open,
            bridge_epoch: input.bridge_epoch,
            start_height: input.start_height,
            end_height: input.end_height,
            evidence_root: input.evidence_root,
            watcher_quorum_root: input.watcher_quorum_root,
            redaction_root_id: input.redaction_root_id,
            challenged_nullifiers: input.challenged_nullifiers,
            settlement_root: input.settlement_root,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "audit_window_id": self.audit_window_id,
            "request_id": self.request_id,
            "status": self.status.as_str(),
            "bridge_epoch": self.bridge_epoch,
            "start_height": self.start_height,
            "end_height": self.end_height,
            "evidence_root": self.evidence_root,
            "watcher_quorum_root": self.watcher_quorum_root,
            "redaction_root_id": self.redaction_root_id,
            "challenged_nullifiers": self.challenged_nullifiers,
            "settlement_root": self.settlement_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BridgeAuditWindowInput {
    pub request_id: String,
    pub bridge_epoch: u64,
    pub start_height: u64,
    pub end_height: u64,
    pub evidence_root: String,
    pub watcher_quorum_root: String,
    pub redaction_root_id: String,
    pub challenged_nullifiers: Vec<String>,
    pub settlement_root: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OperatorRedactionRoot {
    pub redaction_root_id: String,
    pub operator_id: String,
    pub status: RedactionStatus,
    pub epoch: u64,
    pub redaction_root: String,
    pub visible_field_root: String,
    pub sealed_field_root: String,
    pub watcher_attestation_root: String,
    pub audit_window_id: String,
    pub depth: u8,
    pub published_height: u64,
}

impl OperatorRedactionRoot {
    pub fn new(input: OperatorRedactionRootInput, config: &Config) -> Result<Self> {
        if input.depth < config.operator_redaction_depth {
            return Err("redaction depth below configured minimum".to_string());
        }
        let redaction_root_id = public_record_id(
            "OPERATOR-REDACTION-ROOT-ID",
            &json!({
                "operator_id": input.operator_id,
                "epoch": input.epoch,
                "redaction_root": input.redaction_root,
                "published_height": input.published_height,
            }),
        );
        Ok(Self {
            redaction_root_id,
            operator_id: input.operator_id,
            status: RedactionStatus::Committed,
            epoch: input.epoch,
            redaction_root: input.redaction_root,
            visible_field_root: input.visible_field_root,
            sealed_field_root: input.sealed_field_root,
            watcher_attestation_root: input.watcher_attestation_root,
            audit_window_id: input.audit_window_id,
            depth: input.depth,
            published_height: input.published_height,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "redaction_root_id": self.redaction_root_id,
            "operator_id": self.operator_id,
            "status": self.status.as_str(),
            "epoch": self.epoch,
            "redaction_root": self.redaction_root,
            "visible_field_root": self.visible_field_root,
            "sealed_field_root": self.sealed_field_root,
            "watcher_attestation_root": self.watcher_attestation_root,
            "audit_window_id": self.audit_window_id,
            "depth": self.depth,
            "published_height": self.published_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OperatorRedactionRootInput {
    pub operator_id: String,
    pub epoch: u64,
    pub redaction_root: String,
    pub visible_field_root: String,
    pub sealed_field_root: String,
    pub watcher_attestation_root: String,
    pub audit_window_id: String,
    pub depth: u8,
    pub published_height: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RecoveryReceipt {
    pub receipt_id: String,
    pub request_id: String,
    pub batch_id: String,
    pub rotation_id: String,
    pub receipt_height: u64,
    pub status_root: String,
    pub public_outcome_root: String,
    pub private_outcome_commitment: String,
    pub audit_window_id: String,
}

impl RecoveryReceipt {
    pub fn new(input: RecoveryReceiptInput) -> Result<Self> {
        if input.request_id.trim().is_empty() {
            return Err("request_id cannot be empty".to_string());
        }
        let receipt_id = public_record_id(
            "RECOVERY-RECEIPT-ID",
            &json!({
                "request_id": input.request_id,
                "batch_id": input.batch_id,
                "rotation_id": input.rotation_id,
                "receipt_height": input.receipt_height,
                "public_outcome_root": input.public_outcome_root,
            }),
        );
        Ok(Self {
            receipt_id,
            request_id: input.request_id,
            batch_id: input.batch_id,
            rotation_id: input.rotation_id,
            receipt_height: input.receipt_height,
            status_root: input.status_root,
            public_outcome_root: input.public_outcome_root,
            private_outcome_commitment: input.private_outcome_commitment,
            audit_window_id: input.audit_window_id,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "request_id": self.request_id,
            "batch_id": self.batch_id,
            "rotation_id": self.rotation_id,
            "receipt_height": self.receipt_height,
            "status_root": self.status_root,
            "public_outcome_root": self.public_outcome_root,
            "private_outcome_commitment": self.private_outcome_commitment,
            "audit_window_id": self.audit_window_id,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RecoveryReceiptInput {
    pub request_id: String,
    pub batch_id: String,
    pub rotation_id: String,
    pub receipt_height: u64,
    pub status_root: String,
    pub public_outcome_root: String,
    pub private_outcome_commitment: String,
    pub audit_window_id: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PublicRecord {
    pub record_id: String,
    pub record_type: String,
    pub subject_id: String,
    pub visibility: String,
    pub payload_root: String,
    pub redaction_root_id: String,
    pub height: u64,
}

impl PublicRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "record_id": self.record_id,
            "record_type": self.record_type,
            "subject_id": self.subject_id,
            "visibility": self.visibility,
            "payload_root": self.payload_root,
            "redaction_root_id": self.redaction_root_id,
            "height": self.height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub height: u64,
    pub epoch: u64,
    pub counters: Counters,
    pub recovery_requests: BTreeMap<String, RecoveryRequest>,
    pub disclosure_grants: BTreeMap<String, SelectiveDisclosureGrant>,
    pub subaddress_churns: BTreeMap<String, SubaddressChurnPlan>,
    pub view_tag_cache_entries: BTreeMap<String, ViewTagScanCacheEntry>,
    pub watcher_attestations: BTreeMap<String, WatcherAttestation>,
    pub encrypted_recovery_shares: BTreeMap<String, EncryptedRecoveryShare>,
    pub pq_signer_rotations: BTreeMap<String, PqSignerRotation>,
    pub privacy_budgets: BTreeMap<String, PrivacyBudgetAccount>,
    pub low_fee_batches: BTreeMap<String, LowFeeRecoveryBatch>,
    pub bridge_audit_windows: BTreeMap<String, BridgeAuditWindow>,
    pub operator_redaction_roots: BTreeMap<String, OperatorRedactionRoot>,
    pub recovery_receipts: BTreeMap<String, RecoveryReceipt>,
    pub public_records: BTreeMap<String, PublicRecord>,
    pub nullifiers: BTreeSet<String>,
}

impl State {
    pub fn new(config: Config, height: u64, epoch: u64) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            config,
            height,
            epoch,
            counters: Counters::default(),
            recovery_requests: BTreeMap::new(),
            disclosure_grants: BTreeMap::new(),
            subaddress_churns: BTreeMap::new(),
            view_tag_cache_entries: BTreeMap::new(),
            watcher_attestations: BTreeMap::new(),
            encrypted_recovery_shares: BTreeMap::new(),
            pq_signer_rotations: BTreeMap::new(),
            privacy_budgets: BTreeMap::new(),
            low_fee_batches: BTreeMap::new(),
            bridge_audit_windows: BTreeMap::new(),
            operator_redaction_roots: BTreeMap::new(),
            recovery_receipts: BTreeMap::new(),
            public_records: BTreeMap::new(),
            nullifiers: BTreeSet::new(),
        })
    }

    pub fn devnet(operator_id: &str) -> Result<Self> {
        Self::new(Config::devnet(operator_id), DEVNET_HEIGHT, 0)
    }

    pub fn demo() -> Self {
        let mut state = Self::devnet("operator-demo-viewkey-rotation").value_or_fallback();
        let policy_root = deterministic_root("demo-policy", "selective-disclosure");
        let privacy = PrivacyBudgetAccount::new(
            PrivacyBudgetInput {
                account_commitment: deterministic_root("account", "alice"),
                epoch: 1,
                disclosure_limit: DEFAULT_DAILY_DISCLOSURE_BUDGET,
                scan_limit: DEFAULT_DAILY_SCAN_BUDGET,
                rotation_limit: DEFAULT_DAILY_ROTATION_BUDGET,
                policy_root: policy_root.clone(),
            },
            &state.config,
        )
        .value_or_fallback();
        let budget_id = privacy.budget_id.clone();
        let _ = state.register_privacy_budget(privacy);

        let redaction = OperatorRedactionRoot::new(
            OperatorRedactionRootInput {
                operator_id: state.config.operator_id.clone(),
                epoch: 1,
                redaction_root: deterministic_root("redaction", "demo"),
                visible_field_root: deterministic_root("redaction-visible", "demo"),
                sealed_field_root: deterministic_root("redaction-sealed", "demo"),
                watcher_attestation_root: deterministic_root("redaction-watchers", "demo"),
                audit_window_id: "pending-audit-window".to_string(),
                depth: DEFAULT_OPERATOR_REDACTION_DEPTH,
                published_height: state.height,
            },
            &state.config,
        )
        .value_or_fallback();
        let redaction_root_id = redaction.redaction_root_id.clone();
        let _ = state.register_operator_redaction_root(redaction);

        let churn = SubaddressChurnPlan::new(
            SubaddressChurnPlanInput {
                account_commitment: deterministic_root("account", "alice"),
                request_id: "pending-request".to_string(),
                planned_height: state.height,
                old_subaddress_root: deterministic_root("subaddress-old", "alice"),
                new_subaddress_root: deterministic_root("subaddress-new", "alice"),
                churn_count: DEFAULT_MIN_CHURN_SUBADDRESSES,
                decoy_set_root: deterministic_root("decoy-set", "alice"),
                scan_cache_hint_root: deterministic_root("scan-cache-hint", "alice"),
                fee_sponsor_commitment: deterministic_root("sponsor", "low-fee"),
            },
            &state.config,
        )
        .value_or_fallback();
        let churn_id = churn.churn_id.clone();
        let _ = state.register_subaddress_churn(churn);

        let cache = ViewTagScanCacheEntry::new(
            ViewTagScanCacheEntryInput {
                request_id: "pending-request".to_string(),
                account_commitment: deterministic_root("account", "alice"),
                bucket_index: 7,
                view_tag_prefix: "7f".to_string(),
                encrypted_match_root: deterministic_root("encrypted-matches", "alice"),
                scan_window_start: state.height.saturating_sub(64),
                scan_window_end: state.height,
                hit_count: 13,
                cache_provider_commitment: deterministic_root("cache-provider", "one"),
                watcher_attestation_root: deterministic_root("cache-watchers", "one"),
            },
            &state.config,
        )
        .value_or_fallback();
        let cache_id = cache.cache_id.clone();
        let _ = state.register_view_tag_cache_entry(cache);

        let audit_window = BridgeAuditWindow::new(
            BridgeAuditWindowInput {
                request_id: "pending-request".to_string(),
                bridge_epoch: 1,
                start_height: state.height,
                end_height: state
                    .height
                    .saturating_add(DEFAULT_BRIDGE_AUDIT_HOLD_BLOCKS),
                evidence_root: deterministic_root("audit-evidence", "demo"),
                watcher_quorum_root: deterministic_root("audit-watchers", "demo"),
                redaction_root_id: redaction_root_id.clone(),
                challenged_nullifiers: Vec::new(),
                settlement_root: deterministic_root("audit-settlement", "demo"),
            },
            &state.config,
        )
        .value_or_fallback();
        let audit_window_id = audit_window.audit_window_id.clone();
        let _ = state.register_bridge_audit_window(audit_window);

        let request = RecoveryRequest::new(
            RecoveryRequestInput {
                owner_commitment: deterministic_root("owner", "alice"),
                account_commitment: deterministic_root("account", "alice"),
                previous_viewkey_commitment: deterministic_root("viewkey-old", "alice"),
                target_viewkey_commitment: deterministic_root("viewkey-new", "alice"),
                recovery_policy_root: policy_root.clone(),
                privacy_budget_id: budget_id.clone(),
                lane: RecoveryLane::LowFee,
                opened_height: state.height,
                min_share_threshold: DEFAULT_MIN_RECOVERY_THRESHOLD,
                min_watcher_weight: DEFAULT_MIN_WATCHER_WEIGHT,
                disclosure_scopes: vec![
                    DisclosureScope::ViewTagsOnly,
                    DisclosureScope::RecoveryShares,
                    DisclosureScope::SignerRotation,
                ],
                subaddress_churn_id: churn_id.clone(),
                view_tag_cache_id: cache_id.clone(),
                bridge_audit_window_id: audit_window_id.clone(),
                fee_cap_micro_units: DEFAULT_LOW_FEE_TARGET_MICRO_UNITS,
                redaction_root_id,
                notes_commitment: deterministic_root("notes", "demo"),
            },
            &state.config,
        )
        .value_or_fallback();
        let request_id = request.request_id.clone();
        let _ = state.open_recovery_request(request);

        let grant = SelectiveDisclosureGrant::new(
            SelectiveDisclosureGrantInput {
                request_id: request_id.clone(),
                auditor_commitment: deterministic_root("auditor", "one"),
                scope: DisclosureScope::RecoveryShares,
                policy_root,
                encrypted_payload_root: deterministic_root("encrypted-disclosure", "demo"),
                nullifier: deterministic_root("grant-nullifier", "demo"),
                opened_height: state.height,
                release_commitment: deterministic_root("release", "demo"),
            },
            &state.config,
        )
        .value_or_fallback();
        let grant_id = grant.grant_id.clone();
        let _ = state.register_disclosure_grant(grant);

        for index in 0..DEFAULT_MIN_RECOVERY_THRESHOLD {
            let share = EncryptedRecoveryShare::new(
                EncryptedRecoveryShareInput {
                    request_id: request_id.clone(),
                    custodian_commitment: deterministic_root("custodian", &index.to_string()),
                    share_index: index,
                    threshold: DEFAULT_MIN_RECOVERY_THRESHOLD,
                    pq_security_bits: DEFAULT_TARGET_PQ_SECURITY_BITS,
                    kem_ciphertext_root: deterministic_root("kem-share", &index.to_string()),
                    share_commitment: deterministic_root("share", &index.to_string()),
                    recipient_commitment: deterministic_root("recipient", "alice"),
                    sealed_height: state.height,
                    disclosure_grant_id: grant_id.clone(),
                },
                &state.config,
            )
            .value_or_fallback();
            let _ = state.register_encrypted_recovery_share(share);
        }

        for role in [
            WatcherRole::RecoveryShareWitness,
            WatcherRole::ViewTagCacheWitness,
            WatcherRole::SubaddressChurnWitness,
        ] {
            let attestation = WatcherAttestation::new(
                WatcherAttestationInput {
                    request_id: request_id.clone(),
                    watcher_commitment: deterministic_root("watcher", role.as_str()),
                    role,
                    weight: DEFAULT_MIN_WATCHER_WEIGHT,
                    attested_height: state.height,
                    evidence_root: deterministic_root("watcher-evidence", role.as_str()),
                    signature_root: deterministic_root("watcher-signature", role.as_str()),
                    slashing_nullifier: deterministic_root("watcher-nullifier", role.as_str()),
                },
                &state.config,
            )
            .value_or_fallback();
            let _ = state.register_watcher_attestation(attestation);
        }

        let rotation = PqSignerRotation::new(
            PqSignerRotationInput {
                request_id: request_id.clone(),
                account_commitment: deterministic_root("account", "alice"),
                old_signer_root: deterministic_root("signer-old", "alice"),
                new_signer_root: deterministic_root("signer-new", "alice"),
                pq_auth_root: deterministic_root("pq-auth", "alice"),
                watcher_quorum_root: state.watcher_quorum_root(&request_id),
                subaddress_churn_id: churn_id,
                proposed_height: state.height,
            },
            &state.config,
        )
        .value_or_fallback();
        let rotation_id = rotation.rotation_id.clone();
        let _ = state.register_pq_signer_rotation(rotation);

        let batch = LowFeeRecoveryBatch::new(
            LowFeeRecoveryBatchInput {
                lane: RecoveryLane::LowFee,
                request_ids: vec![request_id.clone()],
                disclosure_grant_ids: vec![grant_id],
                share_ids: state
                    .encrypted_recovery_shares
                    .values()
                    .map(|share| share.share_id.clone())
                    .collect::<Vec<_>>(),
                rotation_ids: vec![rotation_id.clone()],
                packed_height: state.height,
                settlement_height: state.height.saturating_add(12),
                sponsor_commitment: deterministic_root("sponsor", "low-fee"),
                audit_window_id: audit_window_id.clone(),
            },
            &state.config,
        )
        .value_or_fallback();
        let batch_id = batch.batch_id.clone();
        let _ = state.register_low_fee_batch(batch);

        let receipt = RecoveryReceipt::new(RecoveryReceiptInput {
            request_id,
            batch_id,
            rotation_id,
            receipt_height: state.height.saturating_add(12),
            status_root: deterministic_root("status", "completed"),
            public_outcome_root: deterministic_root("outcome-public", "demo"),
            private_outcome_commitment: deterministic_root("outcome-private", "demo"),
            audit_window_id,
        })
        .value_or_fallback();
        let _ = state.register_recovery_receipt(receipt);
        state
    }

    pub fn open_recovery_request(&mut self, mut request: RecoveryRequest) -> Result<String> {
        bounded_insert_len(
            self.recovery_requests.len(),
            MAX_RECOVERY_REQUESTS,
            "recovery_requests",
        )?;
        if self.recovery_requests.contains_key(&request.request_id) {
            return Err("recovery request already exists".to_string());
        }
        self.reserve_budget_for_request(&request)?;
        request.status = RecoveryStatus::Open;
        let request_id = request.request_id.clone();
        self.recovery_requests
            .insert(request_id.clone(), request.clone());
        self.counters.recovery_requests_opened =
            self.counters.recovery_requests_opened.saturating_add(1);
        self.publish_record(
            "recovery_request",
            &request_id,
            "redacted",
            &request.public_record(),
            &request.redaction_root_id,
            request.opened_height,
        )?;
        Ok(request_id)
    }

    pub fn register_disclosure_grant(
        &mut self,
        mut grant: SelectiveDisclosureGrant,
    ) -> Result<String> {
        bounded_insert_len(
            self.disclosure_grants.len(),
            MAX_DISCLOSURE_GRANTS,
            "disclosure_grants",
        )?;
        if self.disclosure_grants.contains_key(&grant.grant_id) {
            return Err("disclosure grant already exists".to_string());
        }
        if !self.nullifiers.insert(grant.nullifier.clone()) {
            return Err("disclosure nullifier already used".to_string());
        }
        self.reserve_disclosure_budget(&grant.request_id, grant.privacy_cost_units)?;
        grant.status = DisclosureStatus::BudgetReserved;
        let grant_id = grant.grant_id.clone();
        self.disclosure_grants
            .insert(grant_id.clone(), grant.clone());
        self.counters.disclosure_grants_registered =
            self.counters.disclosure_grants_registered.saturating_add(1);
        self.publish_record(
            "selective_disclosure_grant",
            &grant_id,
            "redacted",
            &grant.public_record(),
            "",
            grant.opened_height,
        )?;
        self.refresh_recovery_status(&grant.request_id)?;
        Ok(grant_id)
    }

    pub fn release_disclosure(&mut self, grant_id: &str) -> Result<()> {
        let (request_id, units) = {
            let grant = self
                .disclosure_grants
                .get_mut(grant_id)
                .ok_or_else(|| "disclosure grant not found".to_string())?;
            grant.status = DisclosureStatus::Released;
            (grant.request_id.clone(), grant.privacy_cost_units)
        };
        self.consume_disclosure_budget(&request_id, units)?;
        self.counters.disclosures_released = self.counters.disclosures_released.saturating_add(1);
        self.refresh_recovery_status(&request_id)
    }

    pub fn register_subaddress_churn(&mut self, churn: SubaddressChurnPlan) -> Result<String> {
        bounded_insert_len(
            self.subaddress_churns.len(),
            MAX_SUBADDRESS_CHURNS,
            "subaddress_churns",
        )?;
        if self.subaddress_churns.contains_key(&churn.churn_id) {
            return Err("subaddress churn already exists".to_string());
        }
        let churn_id = churn.churn_id.clone();
        self.subaddress_churns
            .insert(churn_id.clone(), churn.clone());
        self.counters.subaddress_churns_planned =
            self.counters.subaddress_churns_planned.saturating_add(1);
        self.publish_record(
            "subaddress_churn",
            &churn_id,
            "commitment_only",
            &churn.public_record(),
            "",
            churn.planned_height,
        )?;
        Ok(churn_id)
    }

    pub fn settle_subaddress_churn(&mut self, churn_id: &str) -> Result<()> {
        let request_id = {
            let churn = self
                .subaddress_churns
                .get_mut(churn_id)
                .ok_or_else(|| "subaddress churn not found".to_string())?;
            churn.status = ChurnStatus::Settled;
            churn.request_id.clone()
        };
        self.counters.subaddress_churns_settled =
            self.counters.subaddress_churns_settled.saturating_add(1);
        self.refresh_recovery_status(&request_id)
    }

    pub fn register_view_tag_cache_entry(
        &mut self,
        mut entry: ViewTagScanCacheEntry,
    ) -> Result<String> {
        bounded_insert_len(
            self.view_tag_cache_entries.len(),
            MAX_VIEW_TAG_CACHE_ENTRIES,
            "view_tag_cache_entries",
        )?;
        if self.view_tag_cache_entries.contains_key(&entry.cache_id) {
            return Err("view tag cache entry already exists".to_string());
        }
        self.reserve_scan_budget(&entry.request_id, entry.hit_count)?;
        entry.status = CacheStatus::Primed;
        let cache_id = entry.cache_id.clone();
        self.counters.view_tag_cache_entries_primed = self
            .counters
            .view_tag_cache_entries_primed
            .saturating_add(1);
        self.counters.view_tag_cache_hits = self
            .counters
            .view_tag_cache_hits
            .saturating_add(entry.hit_count);
        self.view_tag_cache_entries
            .insert(cache_id.clone(), entry.clone());
        self.publish_record(
            "view_tag_scan_cache",
            &cache_id,
            "cache_root_only",
            &entry.public_record(),
            "",
            entry.scan_window_end,
        )?;
        self.refresh_recovery_status(&entry.request_id)?;
        Ok(cache_id)
    }

    pub fn register_watcher_attestation(
        &mut self,
        mut attestation: WatcherAttestation,
    ) -> Result<String> {
        bounded_insert_len(
            self.watcher_attestations.len(),
            MAX_WATCHER_ATTESTATIONS,
            "watcher_attestations",
        )?;
        if self
            .watcher_attestations
            .contains_key(&attestation.attestation_id)
        {
            return Err("watcher attestation already exists".to_string());
        }
        attestation.status = AttestationStatus::Weighted;
        let attestation_id = attestation.attestation_id.clone();
        let request_id = attestation.request_id.clone();
        self.watcher_attestations
            .insert(attestation_id.clone(), attestation.clone());
        self.counters.watcher_attestations_counted =
            self.counters.watcher_attestations_counted.saturating_add(1);
        self.publish_record(
            "watcher_attestation",
            &attestation_id,
            "commitment_only",
            &attestation.public_record(),
            "",
            attestation.attested_height,
        )?;
        self.refresh_recovery_status(&request_id)?;
        Ok(attestation_id)
    }

    pub fn register_encrypted_recovery_share(
        &mut self,
        share: EncryptedRecoveryShare,
    ) -> Result<String> {
        bounded_insert_len(
            self.encrypted_recovery_shares.len(),
            MAX_RECOVERY_SHARES,
            "encrypted_recovery_shares",
        )?;
        if self.encrypted_recovery_shares.contains_key(&share.share_id) {
            return Err("encrypted recovery share already exists".to_string());
        }
        let share_id = share.share_id.clone();
        let request_id = share.request_id.clone();
        self.encrypted_recovery_shares
            .insert(share_id.clone(), share.clone());
        self.counters.encrypted_recovery_shares_sealed = self
            .counters
            .encrypted_recovery_shares_sealed
            .saturating_add(1);
        self.publish_record(
            "encrypted_recovery_share",
            &share_id,
            "sealed",
            &share.public_record(),
            "",
            share.sealed_height,
        )?;
        self.refresh_recovery_status(&request_id)?;
        Ok(share_id)
    }

    pub fn mark_share_used(&mut self, share_id: &str) -> Result<()> {
        let request_id = {
            let share = self
                .encrypted_recovery_shares
                .get_mut(share_id)
                .ok_or_else(|| "encrypted recovery share not found".to_string())?;
            share.status = ShareStatus::Reconstructed;
            share.request_id.clone()
        };
        self.counters.encrypted_recovery_shares_used = self
            .counters
            .encrypted_recovery_shares_used
            .saturating_add(1);
        self.refresh_recovery_status(&request_id)
    }

    pub fn register_pq_signer_rotation(&mut self, rotation: PqSignerRotation) -> Result<String> {
        bounded_insert_len(
            self.pq_signer_rotations.len(),
            MAX_SIGNER_ROTATIONS,
            "pq_signer_rotations",
        )?;
        if self.pq_signer_rotations.contains_key(&rotation.rotation_id) {
            return Err("pq signer rotation already exists".to_string());
        }
        self.reserve_rotation_budget(&rotation.request_id, 1)?;
        let rotation_id = rotation.rotation_id.clone();
        let request_id = rotation.request_id.clone();
        self.pq_signer_rotations
            .insert(rotation_id.clone(), rotation.clone());
        self.publish_record(
            "pq_signer_rotation",
            &rotation_id,
            "redacted",
            &rotation.public_record(),
            "",
            rotation.proposed_height,
        )?;
        self.refresh_recovery_status(&request_id)?;
        Ok(rotation_id)
    }

    pub fn activate_pq_signer_rotation(&mut self, rotation_id: &str) -> Result<()> {
        let request_id = {
            let rotation = self
                .pq_signer_rotations
                .get_mut(rotation_id)
                .ok_or_else(|| "pq signer rotation not found".to_string())?;
            rotation.status = RotationStatus::Active;
            rotation.request_id.clone()
        };
        self.consume_rotation_budget(&request_id, 1)?;
        self.counters.pq_signer_rotations_activated = self
            .counters
            .pq_signer_rotations_activated
            .saturating_add(1);
        self.refresh_recovery_status(&request_id)
    }

    pub fn register_privacy_budget(&mut self, budget: PrivacyBudgetAccount) -> Result<String> {
        bounded_insert_len(
            self.privacy_budgets.len(),
            MAX_PRIVACY_BUDGETS,
            "privacy_budgets",
        )?;
        if self.privacy_budgets.contains_key(&budget.budget_id) {
            return Err("privacy budget already exists".to_string());
        }
        let budget_id = budget.budget_id.clone();
        self.privacy_budgets
            .insert(budget_id.clone(), budget.clone());
        self.publish_record(
            "privacy_budget",
            &budget_id,
            "accounting",
            &budget.public_record(),
            "",
            self.height,
        )?;
        Ok(budget_id)
    }

    pub fn register_low_fee_batch(&mut self, mut batch: LowFeeRecoveryBatch) -> Result<String> {
        bounded_insert_len(
            self.low_fee_batches.len(),
            MAX_LOW_FEE_BATCHES,
            "low_fee_batches",
        )?;
        if self.low_fee_batches.contains_key(&batch.batch_id) {
            return Err("low fee batch already exists".to_string());
        }
        batch.status = BatchStatus::Packed;
        for request_id in &batch.request_ids {
            if let Some(request) = self.recovery_requests.get_mut(request_id) {
                request.status = RecoveryStatus::Batched;
            }
        }
        let batch_id = batch.batch_id.clone();
        self.counters.low_fee_rebate_micro_units = self
            .counters
            .low_fee_rebate_micro_units
            .saturating_add(batch.rebate_micro_units);
        self.low_fee_batches.insert(batch_id.clone(), batch.clone());
        self.publish_record(
            "low_fee_recovery_batch",
            &batch_id,
            "batch_root",
            &batch.public_record(),
            "",
            batch.packed_height,
        )?;
        Ok(batch_id)
    }

    pub fn settle_low_fee_batch(&mut self, batch_id: &str) -> Result<()> {
        let request_ids = {
            let batch = self
                .low_fee_batches
                .get_mut(batch_id)
                .ok_or_else(|| "low fee batch not found".to_string())?;
            batch.status = BatchStatus::Settled;
            batch.request_ids.clone()
        };
        self.counters.low_fee_batches_settled =
            self.counters.low_fee_batches_settled.saturating_add(1);
        for request_id in request_ids {
            self.refresh_recovery_status(&request_id)?;
        }
        Ok(())
    }

    pub fn register_bridge_audit_window(&mut self, window: BridgeAuditWindow) -> Result<String> {
        bounded_insert_len(
            self.bridge_audit_windows.len(),
            MAX_BRIDGE_AUDIT_WINDOWS,
            "bridge_audit_windows",
        )?;
        if self
            .bridge_audit_windows
            .contains_key(&window.audit_window_id)
        {
            return Err("bridge audit window already exists".to_string());
        }
        let audit_window_id = window.audit_window_id.clone();
        self.bridge_audit_windows
            .insert(audit_window_id.clone(), window.clone());
        self.publish_record(
            "bridge_audit_window",
            &audit_window_id,
            "audit_root",
            &window.public_record(),
            &window.redaction_root_id,
            window.start_height,
        )?;
        Ok(audit_window_id)
    }

    pub fn close_bridge_audit_window(&mut self, audit_window_id: &str, passed: bool) -> Result<()> {
        let request_id = {
            let window = self
                .bridge_audit_windows
                .get_mut(audit_window_id)
                .ok_or_else(|| "bridge audit window not found".to_string())?;
            window.status = if passed {
                AuditWindowStatus::Closed
            } else {
                AuditWindowStatus::Failed
            };
            window.request_id.clone()
        };
        self.counters.bridge_audit_windows_closed =
            self.counters.bridge_audit_windows_closed.saturating_add(1);
        self.refresh_recovery_status(&request_id)
    }

    pub fn register_operator_redaction_root(
        &mut self,
        root: OperatorRedactionRoot,
    ) -> Result<String> {
        bounded_insert_len(
            self.operator_redaction_roots.len(),
            MAX_OPERATOR_REDACTION_ROOTS,
            "operator_redaction_roots",
        )?;
        if self
            .operator_redaction_roots
            .contains_key(&root.redaction_root_id)
        {
            return Err("operator redaction root already exists".to_string());
        }
        let redaction_root_id = root.redaction_root_id.clone();
        self.operator_redaction_roots
            .insert(redaction_root_id.clone(), root.clone());
        self.counters.operator_redaction_roots_published = self
            .counters
            .operator_redaction_roots_published
            .saturating_add(1);
        self.publish_record(
            "operator_redaction_root",
            &redaction_root_id,
            "redaction_root",
            &root.public_record(),
            &redaction_root_id,
            root.published_height,
        )?;
        Ok(redaction_root_id)
    }

    pub fn register_recovery_receipt(&mut self, receipt: RecoveryReceipt) -> Result<String> {
        bounded_insert_len(
            self.recovery_receipts.len(),
            MAX_RECOVERY_RECEIPTS,
            "recovery_receipts",
        )?;
        if self.recovery_receipts.contains_key(&receipt.receipt_id) {
            return Err("recovery receipt already exists".to_string());
        }
        let receipt_id = receipt.receipt_id.clone();
        let request_id = receipt.request_id.clone();
        self.recovery_receipts
            .insert(receipt_id.clone(), receipt.clone());
        self.counters.recovery_receipts_issued =
            self.counters.recovery_receipts_issued.saturating_add(1);
        self.publish_record(
            "recovery_receipt",
            &receipt_id,
            "receipt",
            &receipt.public_record(),
            "",
            receipt.receipt_height,
        )?;
        self.complete_recovery_request(&request_id)?;
        Ok(receipt_id)
    }

    pub fn complete_recovery_request(&mut self, request_id: &str) -> Result<()> {
        let request = self
            .recovery_requests
            .get_mut(request_id)
            .ok_or_else(|| "recovery request not found".to_string())?;
        request.status = RecoveryStatus::Completed;
        self.counters.recovery_requests_completed =
            self.counters.recovery_requests_completed.saturating_add(1);
        Ok(())
    }

    pub fn watcher_quorum_weight(&self, request_id: &str) -> u64 {
        self.watcher_attestations
            .values()
            .filter(|attestation| {
                attestation.request_id == request_id && attestation.status.counts_for_quorum()
            })
            .map(|attestation| attestation.weight)
            .sum()
    }

    pub fn watcher_quorum_root(&self, request_id: &str) -> String {
        let leaves = self
            .watcher_attestations
            .values()
            .filter(|attestation| {
                attestation.request_id == request_id && attestation.status.counts_for_quorum()
            })
            .map(WatcherAttestation::public_record)
            .collect::<Vec<_>>();
        merkle_root(WATCHER_ATTESTATION_SCHEME, &leaves)
    }

    pub fn recovery_share_count(&self, request_id: &str) -> u16 {
        self.encrypted_recovery_shares
            .values()
            .filter(|share| share.request_id == request_id && share.status.counts_for_threshold())
            .count()
            .min(u16::MAX as usize) as u16
    }

    pub fn roots(&self) -> Roots {
        Roots {
            recovery_request_root: map_root(
                "RECOVERY-REQUEST-ROOT",
                self.recovery_requests
                    .values()
                    .map(RecoveryRequest::public_record)
                    .collect::<Vec<_>>(),
            ),
            disclosure_grant_root: map_root(
                SELECTIVE_DISCLOSURE_SCHEME,
                self.disclosure_grants
                    .values()
                    .map(SelectiveDisclosureGrant::public_record)
                    .collect::<Vec<_>>(),
            ),
            subaddress_churn_root: map_root(
                SUBADDRESS_CHURN_SCHEME,
                self.subaddress_churns
                    .values()
                    .map(SubaddressChurnPlan::public_record)
                    .collect::<Vec<_>>(),
            ),
            view_tag_cache_root: map_root(
                VIEW_TAG_SCAN_CACHE_SCHEME,
                self.view_tag_cache_entries
                    .values()
                    .map(ViewTagScanCacheEntry::public_record)
                    .collect::<Vec<_>>(),
            ),
            watcher_attestation_root: map_root(
                WATCHER_ATTESTATION_SCHEME,
                self.watcher_attestations
                    .values()
                    .map(WatcherAttestation::public_record)
                    .collect::<Vec<_>>(),
            ),
            recovery_share_root: map_root(
                ENCRYPTED_RECOVERY_SHARE_SCHEME,
                self.encrypted_recovery_shares
                    .values()
                    .map(EncryptedRecoveryShare::public_record)
                    .collect::<Vec<_>>(),
            ),
            signer_rotation_root: map_root(
                PQ_SIGNER_ROTATION_SCHEME,
                self.pq_signer_rotations
                    .values()
                    .map(PqSignerRotation::public_record)
                    .collect::<Vec<_>>(),
            ),
            privacy_budget_root: map_root(
                PRIVACY_BUDGET_SCHEME,
                self.privacy_budgets
                    .values()
                    .map(PrivacyBudgetAccount::public_record)
                    .collect::<Vec<_>>(),
            ),
            low_fee_batch_root: map_root(
                LOW_FEE_BATCH_SCHEME,
                self.low_fee_batches
                    .values()
                    .map(LowFeeRecoveryBatch::public_record)
                    .collect::<Vec<_>>(),
            ),
            bridge_audit_window_root: map_root(
                BRIDGE_AUDIT_WINDOW_SCHEME,
                self.bridge_audit_windows
                    .values()
                    .map(BridgeAuditWindow::public_record)
                    .collect::<Vec<_>>(),
            ),
            operator_redaction_root: map_root(
                OPERATOR_REDACTION_SCHEME,
                self.operator_redaction_roots
                    .values()
                    .map(OperatorRedactionRoot::public_record)
                    .collect::<Vec<_>>(),
            ),
            recovery_receipt_root: map_root(
                RECOVERY_RECEIPT_SCHEME,
                self.recovery_receipts
                    .values()
                    .map(RecoveryReceipt::public_record)
                    .collect::<Vec<_>>(),
            ),
            public_record_root: self.public_record_root(),
        }
    }

    pub fn public_record_root(&self) -> String {
        map_root(
            PUBLIC_RECORD_SCHEME,
            self.public_records
                .values()
                .map(PublicRecord::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn state_root(&self) -> String {
        state_root_from_record(&self.public_record_without_root())
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_root();
        if let Value::Object(ref mut object) = record {
            object.insert("state_root".to_string(), Value::String(self.state_root()));
        }
        record
    }

    pub fn public_record_without_root(&self) -> Value {
        let roots = self.roots();
        json!({
            "kind": "monero_l2_pq_private_viewkey_recovery_rotation_runtime",
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "hash_suite": HASH_SUITE,
            "pq_recovery_suite": PQ_RECOVERY_SUITE,
            "height": self.height,
            "epoch": self.epoch,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": roots.public_record(),
            "counts": {
                "recovery_requests": self.recovery_requests.len() as u64,
                "disclosure_grants": self.disclosure_grants.len() as u64,
                "subaddress_churns": self.subaddress_churns.len() as u64,
                "view_tag_cache_entries": self.view_tag_cache_entries.len() as u64,
                "watcher_attestations": self.watcher_attestations.len() as u64,
                "encrypted_recovery_shares": self.encrypted_recovery_shares.len() as u64,
                "pq_signer_rotations": self.pq_signer_rotations.len() as u64,
                "privacy_budgets": self.privacy_budgets.len() as u64,
                "low_fee_batches": self.low_fee_batches.len() as u64,
                "bridge_audit_windows": self.bridge_audit_windows.len() as u64,
                "operator_redaction_roots": self.operator_redaction_roots.len() as u64,
                "recovery_receipts": self.recovery_receipts.len() as u64,
                "public_records": self.public_records.len() as u64,
                "nullifiers": self.nullifiers.len() as u64,
            }
        })
    }

    fn reserve_budget_for_request(&mut self, request: &RecoveryRequest) -> Result<()> {
        let budget = self
            .privacy_budgets
            .get_mut(&request.privacy_budget_id)
            .ok_or_else(|| "privacy budget not found for recovery request".to_string())?;
        budget.reserve_rotation(1)?;
        self.counters.privacy_budget_units_reserved = self
            .counters
            .privacy_budget_units_reserved
            .saturating_add(1);
        Ok(())
    }

    fn reserve_disclosure_budget(&mut self, request_id: &str, units: u64) -> Result<()> {
        let budget_id = self
            .recovery_requests
            .get(request_id)
            .map(|request| request.privacy_budget_id.clone())
            .ok_or_else(|| "recovery request not found for disclosure budget".to_string())?;
        let budget = self
            .privacy_budgets
            .get_mut(&budget_id)
            .ok_or_else(|| "privacy budget not found for disclosure".to_string())?;
        budget.reserve_disclosure(units)?;
        self.counters.privacy_budget_units_reserved = self
            .counters
            .privacy_budget_units_reserved
            .saturating_add(units);
        Ok(())
    }

    fn consume_disclosure_budget(&mut self, request_id: &str, units: u64) -> Result<()> {
        let budget_id = self
            .recovery_requests
            .get(request_id)
            .map(|request| request.privacy_budget_id.clone())
            .ok_or_else(|| "recovery request not found for disclosure consume".to_string())?;
        let budget = self
            .privacy_budgets
            .get_mut(&budget_id)
            .ok_or_else(|| "privacy budget not found for disclosure consume".to_string())?;
        budget.consume_disclosure(units)?;
        self.counters.privacy_budget_units_consumed = self
            .counters
            .privacy_budget_units_consumed
            .saturating_add(units);
        Ok(())
    }

    fn reserve_scan_budget(&mut self, request_id: &str, units: u64) -> Result<()> {
        let budget_id = self
            .recovery_requests
            .get(request_id)
            .map(|request| request.privacy_budget_id.clone());
        if let Some(budget_id) = budget_id {
            let budget = self
                .privacy_budgets
                .get_mut(&budget_id)
                .ok_or_else(|| "privacy budget not found for scan".to_string())?;
            budget.reserve_scan(units)?;
            self.counters.privacy_budget_units_reserved = self
                .counters
                .privacy_budget_units_reserved
                .saturating_add(units);
        }
        Ok(())
    }

    fn reserve_rotation_budget(&mut self, request_id: &str, units: u64) -> Result<()> {
        let budget_id = self
            .recovery_requests
            .get(request_id)
            .map(|request| request.privacy_budget_id.clone())
            .ok_or_else(|| "recovery request not found for rotation budget".to_string())?;
        let budget = self
            .privacy_budgets
            .get_mut(&budget_id)
            .ok_or_else(|| "privacy budget not found for rotation".to_string())?;
        budget.reserve_rotation(units)?;
        self.counters.privacy_budget_units_reserved = self
            .counters
            .privacy_budget_units_reserved
            .saturating_add(units);
        Ok(())
    }

    fn consume_rotation_budget(&mut self, request_id: &str, units: u64) -> Result<()> {
        let budget_id = self
            .recovery_requests
            .get(request_id)
            .map(|request| request.privacy_budget_id.clone())
            .ok_or_else(|| "recovery request not found for rotation consume".to_string())?;
        let budget = self
            .privacy_budgets
            .get_mut(&budget_id)
            .ok_or_else(|| "privacy budget not found for rotation consume".to_string())?;
        budget.consume_rotation(units)?;
        self.counters.privacy_budget_units_consumed = self
            .counters
            .privacy_budget_units_consumed
            .saturating_add(units);
        Ok(())
    }

    fn refresh_recovery_status(&mut self, request_id: &str) -> Result<()> {
        let share_count = self.recovery_share_count(request_id);
        let quorum_weight = self.watcher_quorum_weight(request_id);
        let active_rotation = self.pq_signer_rotations.values().any(|rotation| {
            rotation.request_id == request_id && rotation.status == RotationStatus::Active
        });
        let has_batch = self.low_fee_batches.values().any(|batch| {
            batch.request_ids.iter().any(|item| item == request_id)
                && matches!(batch.status, BatchStatus::Packed | BatchStatus::Settled)
        });
        let has_disclosure = self
            .disclosure_grants
            .values()
            .any(|grant| grant.request_id == request_id);
        let request = self
            .recovery_requests
            .get_mut(request_id)
            .ok_or_else(|| "recovery request not found".to_string())?;
        if matches!(
            request.status,
            RecoveryStatus::Completed | RecoveryStatus::Cancelled
        ) {
            return Ok(());
        }
        if active_rotation {
            request.status = RecoveryStatus::Rotated;
        } else if has_batch {
            request.status = RecoveryStatus::Batched;
        } else if quorum_weight >= request.min_watcher_weight {
            request.status = RecoveryStatus::WatcherQuorum;
        } else if share_count >= request.min_share_threshold {
            request.status = RecoveryStatus::SharesSealed;
        } else if has_disclosure {
            request.status = RecoveryStatus::Disclosed;
        }
        Ok(())
    }

    fn publish_record(
        &mut self,
        record_type: &str,
        subject_id: &str,
        visibility: &str,
        payload: &Value,
        redaction_root_id: &str,
        height: u64,
    ) -> Result<String> {
        bounded_insert_len(
            self.public_records.len(),
            MAX_PUBLIC_RECORDS,
            "public_records",
        )?;
        let payload_root = domain_hash(
            "PUBLIC-RECORD-PAYLOAD",
            &[HashPart::Json(payload), HashPart::Str(visibility)],
            32,
        );
        let record_id = public_record_id(
            "PUBLIC-RECORD-ID",
            &json!({
                "record_type": record_type,
                "subject_id": subject_id,
                "visibility": visibility,
                "payload_root": payload_root,
                "redaction_root_id": redaction_root_id,
                "height": height,
            }),
        );
        let record = PublicRecord {
            record_id: record_id.clone(),
            record_type: record_type.to_string(),
            subject_id: subject_id.to_string(),
            visibility: visibility.to_string(),
            payload_root,
            redaction_root_id: redaction_root_id.to_string(),
            height,
        };
        self.public_records.insert(record_id.clone(), record);
        Ok(record_id)
    }
}

trait FallbackValue {
    fn fallback() -> Self;
}

trait ResultFallback<T> {
    fn value_or_fallback(self) -> T;
}

impl<T: FallbackValue> ResultFallback<T> for Result<T> {
    fn value_or_fallback(self) -> T {
        match self {
            Ok(value) => value,
            Err(_) => T::fallback(),
        }
    }
}

impl FallbackValue for State {
    fn fallback() -> Self {
        Self {
            config: Config::devnet("operator-demo-viewkey-rotation"),
            height: DEVNET_HEIGHT,
            epoch: 0,
            counters: Counters::default(),
            recovery_requests: BTreeMap::new(),
            disclosure_grants: BTreeMap::new(),
            subaddress_churns: BTreeMap::new(),
            view_tag_cache_entries: BTreeMap::new(),
            watcher_attestations: BTreeMap::new(),
            encrypted_recovery_shares: BTreeMap::new(),
            pq_signer_rotations: BTreeMap::new(),
            privacy_budgets: BTreeMap::new(),
            low_fee_batches: BTreeMap::new(),
            bridge_audit_windows: BTreeMap::new(),
            operator_redaction_roots: BTreeMap::new(),
            recovery_receipts: BTreeMap::new(),
            public_records: BTreeMap::new(),
            nullifiers: BTreeSet::new(),
        }
    }
}

impl FallbackValue for PrivacyBudgetAccount {
    fn fallback() -> Self {
        Self {
            budget_id: deterministic_root("fallback-budget", "id"),
            account_commitment: deterministic_root("fallback-account", "budget"),
            epoch: 0,
            status: BudgetStatus::Open,
            disclosure_limit: DEFAULT_DAILY_DISCLOSURE_BUDGET,
            disclosure_reserved: 0,
            disclosure_consumed: 0,
            scan_limit: DEFAULT_DAILY_SCAN_BUDGET,
            scan_reserved: 0,
            scan_consumed: 0,
            rotation_limit: DEFAULT_DAILY_ROTATION_BUDGET,
            rotation_reserved: 0,
            rotation_consumed: 0,
            policy_root: deterministic_root("fallback-policy", "budget"),
        }
    }
}

impl FallbackValue for OperatorRedactionRoot {
    fn fallback() -> Self {
        Self {
            redaction_root_id: deterministic_root("fallback-redaction", "id"),
            operator_id: "operator-demo-viewkey-rotation".to_string(),
            status: RedactionStatus::Committed,
            epoch: 0,
            redaction_root: deterministic_root("fallback-redaction", "root"),
            visible_field_root: deterministic_root("fallback-redaction", "visible"),
            sealed_field_root: deterministic_root("fallback-redaction", "sealed"),
            watcher_attestation_root: deterministic_root("fallback-redaction", "watcher"),
            audit_window_id: "fallback-audit-window".to_string(),
            depth: DEFAULT_OPERATOR_REDACTION_DEPTH,
            published_height: DEVNET_HEIGHT,
        }
    }
}

impl FallbackValue for SubaddressChurnPlan {
    fn fallback() -> Self {
        Self {
            churn_id: deterministic_root("fallback-churn", "id"),
            account_commitment: deterministic_root("fallback-account", "churn"),
            request_id: "fallback-request".to_string(),
            status: ChurnStatus::Planned,
            planned_height: DEVNET_HEIGHT,
            valid_until_height: DEVNET_HEIGHT.saturating_add(DEFAULT_ROTATION_TTL_BLOCKS),
            old_subaddress_root: deterministic_root("fallback-subaddress", "old"),
            new_subaddress_root: deterministic_root("fallback-subaddress", "new"),
            churn_count: DEFAULT_MIN_CHURN_SUBADDRESSES,
            decoy_set_root: deterministic_root("fallback-decoy", "set"),
            scan_cache_hint_root: deterministic_root("fallback-scan", "hint"),
            fee_sponsor_commitment: deterministic_root("fallback-sponsor", "fee"),
        }
    }
}

impl FallbackValue for ViewTagScanCacheEntry {
    fn fallback() -> Self {
        Self {
            cache_id: deterministic_root("fallback-cache", "id"),
            request_id: "fallback-request".to_string(),
            account_commitment: deterministic_root("fallback-account", "cache"),
            status: CacheStatus::Warm,
            bucket_index: 0,
            view_tag_prefix: "00".to_string(),
            encrypted_match_root: deterministic_root("fallback-cache", "matches"),
            scan_window_start: DEVNET_HEIGHT,
            scan_window_end: DEVNET_HEIGHT,
            hit_count: 0,
            cache_provider_commitment: deterministic_root("fallback-cache", "provider"),
            watcher_attestation_root: deterministic_root("fallback-cache", "watcher"),
            expires_height: DEVNET_HEIGHT.saturating_add(DEFAULT_SCAN_CACHE_TTL_BLOCKS),
        }
    }
}

impl FallbackValue for BridgeAuditWindow {
    fn fallback() -> Self {
        Self {
            audit_window_id: deterministic_root("fallback-audit", "id"),
            request_id: "fallback-request".to_string(),
            status: AuditWindowStatus::Open,
            bridge_epoch: 0,
            start_height: DEVNET_HEIGHT,
            end_height: DEVNET_HEIGHT.saturating_add(DEFAULT_BRIDGE_AUDIT_HOLD_BLOCKS),
            evidence_root: deterministic_root("fallback-audit", "evidence"),
            watcher_quorum_root: deterministic_root("fallback-audit", "watcher"),
            redaction_root_id: deterministic_root("fallback-redaction", "id"),
            challenged_nullifiers: Vec::new(),
            settlement_root: deterministic_root("fallback-audit", "settlement"),
        }
    }
}

impl FallbackValue for RecoveryRequest {
    fn fallback() -> Self {
        Self {
            request_id: deterministic_root("fallback-request", "id"),
            owner_commitment: deterministic_root("fallback-owner", "request"),
            account_commitment: deterministic_root("fallback-account", "request"),
            previous_viewkey_commitment: deterministic_root("fallback-viewkey", "old"),
            target_viewkey_commitment: deterministic_root("fallback-viewkey", "new"),
            recovery_policy_root: deterministic_root("fallback-policy", "request"),
            privacy_budget_id: deterministic_root("fallback-budget", "id"),
            lane: RecoveryLane::LowFee,
            status: RecoveryStatus::Open,
            opened_height: DEVNET_HEIGHT,
            expires_height: DEVNET_HEIGHT.saturating_add(DEFAULT_RECOVERY_TTL_BLOCKS),
            min_share_threshold: DEFAULT_MIN_RECOVERY_THRESHOLD,
            min_watcher_weight: DEFAULT_MIN_WATCHER_WEIGHT,
            disclosure_scope_root: deterministic_root("fallback-scope", "request"),
            subaddress_churn_id: deterministic_root("fallback-churn", "id"),
            view_tag_cache_id: deterministic_root("fallback-cache", "id"),
            bridge_audit_window_id: deterministic_root("fallback-audit", "id"),
            fee_cap_micro_units: DEFAULT_LOW_FEE_TARGET_MICRO_UNITS,
            redaction_root_id: deterministic_root("fallback-redaction", "id"),
            notes_commitment: deterministic_root("fallback-notes", "request"),
        }
    }
}

impl FallbackValue for SelectiveDisclosureGrant {
    fn fallback() -> Self {
        Self {
            grant_id: deterministic_root("fallback-grant", "id"),
            request_id: deterministic_root("fallback-request", "id"),
            auditor_commitment: deterministic_root("fallback-auditor", "grant"),
            scope: DisclosureScope::RecoveryShares,
            status: DisclosureStatus::Requested,
            policy_root: deterministic_root("fallback-policy", "grant"),
            encrypted_payload_root: deterministic_root("fallback-payload", "grant"),
            nullifier: deterministic_root("fallback-nullifier", "grant"),
            opened_height: DEVNET_HEIGHT,
            expires_height: DEVNET_HEIGHT.saturating_add(DEFAULT_DISCLOSURE_TTL_BLOCKS),
            privacy_cost_units: DisclosureScope::RecoveryShares.privacy_cost(),
            release_commitment: deterministic_root("fallback-release", "grant"),
        }
    }
}

impl FallbackValue for EncryptedRecoveryShare {
    fn fallback() -> Self {
        Self {
            share_id: deterministic_root("fallback-share", "id"),
            request_id: deterministic_root("fallback-request", "id"),
            custodian_commitment: deterministic_root("fallback-custodian", "share"),
            status: ShareStatus::Sealed,
            share_index: 0,
            threshold: DEFAULT_MIN_RECOVERY_THRESHOLD,
            pq_security_bits: DEFAULT_TARGET_PQ_SECURITY_BITS,
            kem_ciphertext_root: deterministic_root("fallback-kem", "share"),
            share_commitment: deterministic_root("fallback-share", "commitment"),
            recipient_commitment: deterministic_root("fallback-recipient", "share"),
            sealed_height: DEVNET_HEIGHT,
            expires_height: DEVNET_HEIGHT.saturating_add(DEFAULT_SHARE_TTL_BLOCKS),
            disclosure_grant_id: deterministic_root("fallback-grant", "id"),
        }
    }
}

impl FallbackValue for WatcherAttestation {
    fn fallback() -> Self {
        Self {
            attestation_id: deterministic_root("fallback-attestation", "id"),
            request_id: deterministic_root("fallback-request", "id"),
            watcher_commitment: deterministic_root("fallback-watcher", "attestation"),
            role: WatcherRole::RecoveryShareWitness,
            status: AttestationStatus::Submitted,
            weight: DEFAULT_MIN_WATCHER_WEIGHT,
            attested_height: DEVNET_HEIGHT,
            evidence_root: deterministic_root("fallback-evidence", "attestation"),
            signature_root: deterministic_root("fallback-signature", "attestation"),
            slashing_nullifier: deterministic_root("fallback-nullifier", "attestation"),
        }
    }
}

impl FallbackValue for PqSignerRotation {
    fn fallback() -> Self {
        Self {
            rotation_id: deterministic_root("fallback-rotation", "id"),
            request_id: deterministic_root("fallback-request", "id"),
            account_commitment: deterministic_root("fallback-account", "rotation"),
            status: RotationStatus::Proposed,
            old_signer_root: deterministic_root("fallback-signer", "old"),
            new_signer_root: deterministic_root("fallback-signer", "new"),
            pq_auth_root: deterministic_root("fallback-pq-auth", "rotation"),
            watcher_quorum_root: deterministic_root("fallback-watcher", "rotation"),
            subaddress_churn_id: deterministic_root("fallback-churn", "id"),
            proposed_height: DEVNET_HEIGHT,
            activates_height: DEVNET_HEIGHT.saturating_add(DEFAULT_BRIDGE_AUDIT_HOLD_BLOCKS),
            expires_height: DEVNET_HEIGHT.saturating_add(DEFAULT_ROTATION_TTL_BLOCKS),
        }
    }
}

impl FallbackValue for LowFeeRecoveryBatch {
    fn fallback() -> Self {
        Self {
            batch_id: deterministic_root("fallback-batch", "id"),
            status: BatchStatus::Open,
            lane: RecoveryLane::LowFee,
            request_ids: Vec::new(),
            disclosure_grant_ids: Vec::new(),
            share_ids: Vec::new(),
            rotation_ids: Vec::new(),
            packed_height: DEVNET_HEIGHT,
            settlement_height: DEVNET_HEIGHT.saturating_add(12),
            gross_fee_micro_units: 0,
            rebate_micro_units: 0,
            sponsor_commitment: deterministic_root("fallback-sponsor", "batch"),
            batch_root: deterministic_root("fallback-batch", "root"),
            audit_window_id: deterministic_root("fallback-audit", "id"),
        }
    }
}

impl FallbackValue for RecoveryReceipt {
    fn fallback() -> Self {
        Self {
            receipt_id: deterministic_root("fallback-receipt", "id"),
            request_id: deterministic_root("fallback-request", "id"),
            batch_id: deterministic_root("fallback-batch", "id"),
            rotation_id: deterministic_root("fallback-rotation", "id"),
            receipt_height: DEVNET_HEIGHT,
            status_root: deterministic_root("fallback-status", "receipt"),
            public_outcome_root: deterministic_root("fallback-outcome", "public"),
            private_outcome_commitment: deterministic_root("fallback-outcome", "private"),
            audit_window_id: deterministic_root("fallback-audit", "id"),
        }
    }
}

pub fn devnet(operator_id: &str) -> Result<State> {
    State::devnet(operator_id)
}

pub fn demo() -> State {
    State::demo()
}

pub fn public_record(state: &State) -> Value {
    state.public_record()
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}

pub fn state_root_from_record(record: &Value) -> String {
    domain_hash(STATE_ROOT_DOMAIN, &[HashPart::Json(record)], 32)
}

pub fn public_record_root(records: &[PublicRecord]) -> String {
    map_root(
        PUBLIC_RECORD_SCHEME,
        records
            .iter()
            .map(PublicRecord::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn scope_root(scopes: &[DisclosureScope]) -> String {
    let leaves = scopes
        .iter()
        .map(|scope| Value::String(scope.as_str().to_string()))
        .collect::<Vec<_>>();
    merkle_root("DISCLOSURE-SCOPE-ROOT", &leaves)
}

pub fn public_record_id(domain: &str, record: &Value) -> String {
    domain_hash(domain, &[HashPart::Json(record)], 16)
}

pub fn deterministic_root(label: &str, value: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-PRIVATE-VIEWKEY-RECOVERY-ROTATION-DETERMINISTIC",
        &[HashPart::Str(label), HashPart::Str(value)],
        32,
    )
}

pub fn map_root(domain: &str, mut records: Vec<Value>) -> String {
    records.sort_by(|left, right| left.to_string().cmp(&right.to_string()));
    merkle_root(domain, &records)
}

pub fn bounded_insert_len(current_len: usize, max_len: usize, label: &str) -> Result<()> {
    if current_len >= max_len {
        return Err(format!("{label} capacity exceeded"));
    }
    Ok(())
}
