use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type Runtime = State;

pub const PROTOCOL_VERSION: &str =
    "nebula-private-l2-fast-confidential-batch-settlement-queue-runtime-v1";
pub const SCHEMA_VERSION: u64 = 1;
pub const DEVNET_HEIGHT: u64 = 1_512_000;
pub const DEVNET_EPOCH: u64 = 2_100;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_AUTH_SUITE: &str = "ml-dsa-87+slh-dsa-shake-256s-batch-settlement-auth-v1";
pub const ENCRYPTED_WORK_ITEM_SUITE: &str = "ml-kem-1024+xwing-sealed-settlement-work-item-v1";
pub const PRIVACY_FENCE_SUITE: &str = "zk-private-work-item-nullifier-fence-v1";
pub const BUNDLE_PROOF_SUITE: &str = "recursive-confidential-batch-settlement-proof-v1";
pub const RECEIPT_SUITE: &str = "zk-confidential-batch-settlement-receipt-v1";
pub const DA_VOUCHER_SUITE: &str = "low-fee-confidential-settlement-da-voucher-v1";
pub const DEFAULT_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEFAULT_MIN_PRIVACY_SET: u64 = 16_384;
pub const DEFAULT_TARGET_PRIVACY_SET: u64 = 131_072;
pub const DEFAULT_MAX_WORK_ITEMS_PER_BUNDLE: usize = 4_096;
pub const DEFAULT_MAX_QUEUE_DEPTH: usize = 1_048_576;
pub const DEFAULT_BUNDLE_TTL_BLOCKS: u64 = 24;
pub const DEFAULT_WORK_ITEM_TTL_BLOCKS: u64 = 48;
pub const DEFAULT_RECEIPT_WINDOW_BLOCKS: u64 = 72;
pub const DEFAULT_MAX_FEE_BPS: u64 = 20;
pub const DEFAULT_TARGET_FEE_BPS: u64 = 6;
pub const DEFAULT_REBATE_BPS: u64 = 8;
pub const DEFAULT_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MAX_DA_BYTES_PER_BUNDLE: u64 = 2_097_152;
pub const DEFAULT_MIN_WORKER_BOND: u64 = 1_000_000;
pub const MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QueueLane {
    ContractCalls,
    TokenTransfers,
    DefiClearing,
    BridgeReceipts,
    OracleUpdates,
    PaymasterRefunds,
    AccountAbstraction,
    Emergency,
}

impl QueueLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ContractCalls => "contract_calls",
            Self::TokenTransfers => "token_transfers",
            Self::DefiClearing => "defi_clearing",
            Self::BridgeReceipts => "bridge_receipts",
            Self::OracleUpdates => "oracle_updates",
            Self::PaymasterRefunds => "paymaster_refunds",
            Self::AccountAbstraction => "account_abstraction",
            Self::Emergency => "emergency",
        }
    }

    pub fn target_fee_bps(self, config: &Config) -> u64 {
        match self {
            Self::ContractCalls | Self::TokenTransfers => config.target_fee_bps,
            Self::DefiClearing | Self::AccountAbstraction => config.target_fee_bps + 1,
            Self::BridgeReceipts | Self::OracleUpdates => config.target_fee_bps + 2,
            Self::PaymasterRefunds => config.target_fee_bps.saturating_sub(2),
            Self::Emergency => config.max_fee_bps,
        }
        .min(config.max_fee_bps)
    }

    pub fn default_priority(self) -> SettlementPriority {
        match self {
            Self::Emergency => SettlementPriority::Critical,
            Self::BridgeReceipts | Self::OracleUpdates => SettlementPriority::High,
            Self::DefiClearing | Self::AccountAbstraction => SettlementPriority::Normal,
            Self::ContractCalls | Self::TokenTransfers | Self::PaymasterRefunds => {
                SettlementPriority::LowFee
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementPriority {
    LowFee,
    Normal,
    High,
    Critical,
}

impl SettlementPriority {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LowFee => "low_fee",
            Self::Normal => "normal",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }

    pub fn queue_weight(self) -> u64 {
        match self {
            Self::LowFee => 1,
            Self::Normal => 3,
            Self::High => 9,
            Self::Critical => 27,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkItemStatus {
    Enqueued,
    FeeQuoted,
    Reserved,
    Bundled,
    Proving,
    Settled,
    Rejected,
    Expired,
}

impl WorkItemStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Enqueued => "enqueued",
            Self::FeeQuoted => "fee_quoted",
            Self::Reserved => "reserved",
            Self::Bundled => "bundled",
            Self::Proving => "proving",
            Self::Settled => "settled",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }

    pub fn bundleable(self) -> bool {
        matches!(self, Self::Enqueued | Self::FeeQuoted | Self::Reserved)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkerStatus {
    Active,
    Draining,
    Suspended,
    Slashed,
    Retired,
}

impl WorkerStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Draining => "draining",
            Self::Suspended => "suspended",
            Self::Slashed => "slashed",
            Self::Retired => "retired",
        }
    }

    pub fn can_accept_work(self) -> bool {
        matches!(self, Self::Active | Self::Draining)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BundleStatus {
    Open,
    Sealed,
    Proving,
    ProofPublished,
    SettlementReady,
    Settled,
    Disputed,
    Expired,
}

impl BundleStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Sealed => "sealed",
            Self::Proving => "proving",
            Self::ProofPublished => "proof_published",
            Self::SettlementReady => "settlement_ready",
            Self::Settled => "settled",
            Self::Disputed => "disputed",
            Self::Expired => "expired",
        }
    }

    pub fn accepts_items(self) -> bool {
        matches!(self, Self::Open)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofStatus {
    Submitted,
    Verified,
    Rejected,
    Superseded,
}

impl ProofStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Verified => "verified",
            Self::Rejected => "rejected",
            Self::Superseded => "superseded",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptStatus {
    Published,
    Challenged,
    Finalized,
    Reverted,
}

impl ReceiptStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Published => "published",
            Self::Challenged => "challenged",
            Self::Finalized => "finalized",
            Self::Reverted => "reverted",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RebateStatus {
    Accrued,
    Claimed,
    Expired,
    Slashed,
}

impl RebateStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Accrued => "accrued",
            Self::Claimed => "claimed",
            Self::Expired => "expired",
            Self::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub protocol_version: String,
    pub chain_id: String,
    pub fee_asset_id: String,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub max_work_items_per_bundle: usize,
    pub max_queue_depth: usize,
    pub bundle_ttl_blocks: u64,
    pub work_item_ttl_blocks: u64,
    pub receipt_window_blocks: u64,
    pub max_fee_bps: u64,
    pub target_fee_bps: u64,
    pub rebate_bps: u64,
    pub pq_security_bits: u16,
    pub max_da_bytes_per_bundle: u64,
    pub min_worker_bond_micro_units: u64,
    pub require_pq_worker_auth: bool,
    pub require_privacy_fence: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            chain_id: CHAIN_ID.to_string(),
            fee_asset_id: DEFAULT_FEE_ASSET_ID.to_string(),
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET,
            target_privacy_set_size: DEFAULT_TARGET_PRIVACY_SET,
            max_work_items_per_bundle: DEFAULT_MAX_WORK_ITEMS_PER_BUNDLE,
            max_queue_depth: DEFAULT_MAX_QUEUE_DEPTH,
            bundle_ttl_blocks: DEFAULT_BUNDLE_TTL_BLOCKS,
            work_item_ttl_blocks: DEFAULT_WORK_ITEM_TTL_BLOCKS,
            receipt_window_blocks: DEFAULT_RECEIPT_WINDOW_BLOCKS,
            max_fee_bps: DEFAULT_MAX_FEE_BPS,
            target_fee_bps: DEFAULT_TARGET_FEE_BPS,
            rebate_bps: DEFAULT_REBATE_BPS,
            pq_security_bits: DEFAULT_PQ_SECURITY_BITS,
            max_da_bytes_per_bundle: DEFAULT_MAX_DA_BYTES_PER_BUNDLE,
            min_worker_bond_micro_units: DEFAULT_MIN_WORKER_BOND,
            require_pq_worker_auth: true,
            require_privacy_fence: true,
        }
    }

    pub fn validate(&self) -> Result<()> {
        require_nonempty("protocol_version", &self.protocol_version)?;
        require_nonempty("chain_id", &self.chain_id)?;
        require_nonempty("fee_asset_id", &self.fee_asset_id)?;
        if self.min_privacy_set_size == 0 {
            return Err("min privacy set must be positive".to_string());
        }
        if self.target_privacy_set_size < self.min_privacy_set_size {
            return Err("target privacy set cannot be below minimum".to_string());
        }
        if self.max_work_items_per_bundle == 0 {
            return Err("max work items per bundle must be positive".to_string());
        }
        if self.max_queue_depth < self.max_work_items_per_bundle {
            return Err("queue depth must cover at least one full bundle".to_string());
        }
        if self.bundle_ttl_blocks == 0 || self.work_item_ttl_blocks == 0 {
            return Err("ttl values must be positive".to_string());
        }
        if self.target_fee_bps > self.max_fee_bps || self.max_fee_bps > MAX_BPS {
            return Err("fee bps configuration is invalid".to_string());
        }
        if self.rebate_bps > self.max_fee_bps {
            return Err("rebate cannot exceed max fee".to_string());
        }
        if self.pq_security_bits < 192 {
            return Err("pq security bits below minimum".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.protocol_version,
            "chain_id": self.chain_id,
            "fee_asset_id": self.fee_asset_id,
            "min_privacy_set_size": self.min_privacy_set_size,
            "target_privacy_set_size": self.target_privacy_set_size,
            "max_work_items_per_bundle": self.max_work_items_per_bundle,
            "max_queue_depth": self.max_queue_depth,
            "bundle_ttl_blocks": self.bundle_ttl_blocks,
            "work_item_ttl_blocks": self.work_item_ttl_blocks,
            "receipt_window_blocks": self.receipt_window_blocks,
            "max_fee_bps": self.max_fee_bps,
            "target_fee_bps": self.target_fee_bps,
            "rebate_bps": self.rebate_bps,
            "pq_security_bits": self.pq_security_bits,
            "max_da_bytes_per_bundle": self.max_da_bytes_per_bundle,
            "min_worker_bond_micro_units": self.min_worker_bond_micro_units,
            "require_pq_worker_auth": self.require_pq_worker_auth,
            "require_privacy_fence": self.require_privacy_fence,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub policy_sequence: u64,
    pub fence_sequence: u64,
    pub work_item_sequence: u64,
    pub worker_sequence: u64,
    pub quote_sequence: u64,
    pub bundle_sequence: u64,
    pub proof_sequence: u64,
    pub receipt_sequence: u64,
    pub rebate_sequence: u64,
    pub da_voucher_sequence: u64,
    pub slashing_sequence: u64,
    pub checkpoint_sequence: u64,
    pub event_sequence: u64,
}

impl Counters {
    pub fn next_policy(&mut self) -> u64 {
        self.policy_sequence += 1;
        self.policy_sequence
    }

    pub fn next_fence(&mut self) -> u64 {
        self.fence_sequence += 1;
        self.fence_sequence
    }

    pub fn next_work_item(&mut self) -> u64 {
        self.work_item_sequence += 1;
        self.work_item_sequence
    }

    pub fn next_worker(&mut self) -> u64 {
        self.worker_sequence += 1;
        self.worker_sequence
    }

    pub fn next_quote(&mut self) -> u64 {
        self.quote_sequence += 1;
        self.quote_sequence
    }

    pub fn next_bundle(&mut self) -> u64 {
        self.bundle_sequence += 1;
        self.bundle_sequence
    }

    pub fn next_proof(&mut self) -> u64 {
        self.proof_sequence += 1;
        self.proof_sequence
    }

    pub fn next_receipt(&mut self) -> u64 {
        self.receipt_sequence += 1;
        self.receipt_sequence
    }

    pub fn next_rebate(&mut self) -> u64 {
        self.rebate_sequence += 1;
        self.rebate_sequence
    }

    pub fn next_da_voucher(&mut self) -> u64 {
        self.da_voucher_sequence += 1;
        self.da_voucher_sequence
    }

    pub fn next_slashing(&mut self) -> u64 {
        self.slashing_sequence += 1;
        self.slashing_sequence
    }

    pub fn next_checkpoint(&mut self) -> u64 {
        self.checkpoint_sequence += 1;
        self.checkpoint_sequence
    }

    pub fn next_event(&mut self) -> u64 {
        self.event_sequence += 1;
        self.event_sequence
    }

    pub fn public_record(&self) -> Value {
        json!({
            "policy_sequence": self.policy_sequence,
            "fence_sequence": self.fence_sequence,
            "work_item_sequence": self.work_item_sequence,
            "worker_sequence": self.worker_sequence,
            "quote_sequence": self.quote_sequence,
            "bundle_sequence": self.bundle_sequence,
            "proof_sequence": self.proof_sequence,
            "receipt_sequence": self.receipt_sequence,
            "rebate_sequence": self.rebate_sequence,
            "da_voucher_sequence": self.da_voucher_sequence,
            "slashing_sequence": self.slashing_sequence,
            "checkpoint_sequence": self.checkpoint_sequence,
            "event_sequence": self.event_sequence,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub policy_root: String,
    pub privacy_fence_root: String,
    pub work_item_root: String,
    pub worker_root: String,
    pub fee_quote_root: String,
    pub bundle_root: String,
    pub proof_root: String,
    pub receipt_root: String,
    pub rebate_root: String,
    pub da_voucher_root: String,
    pub slashing_evidence_root: String,
    pub checkpoint_root: String,
    pub event_root: String,
    pub config_root: String,
    pub counter_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "policy_root": self.policy_root,
            "privacy_fence_root": self.privacy_fence_root,
            "work_item_root": self.work_item_root,
            "worker_root": self.worker_root,
            "fee_quote_root": self.fee_quote_root,
            "bundle_root": self.bundle_root,
            "proof_root": self.proof_root,
            "receipt_root": self.receipt_root,
            "rebate_root": self.rebate_root,
            "da_voucher_root": self.da_voucher_root,
            "slashing_evidence_root": self.slashing_evidence_root,
            "checkpoint_root": self.checkpoint_root,
            "event_root": self.event_root,
            "config_root": self.config_root,
            "counter_root": self.counter_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct QueuePolicy {
    pub policy_id: String,
    pub lane: QueueLane,
    pub priority: SettlementPriority,
    pub max_fee_bps: u64,
    pub target_fee_bps: u64,
    pub max_items_per_bundle: usize,
    pub max_da_bytes: u64,
    pub min_privacy_set_size: u64,
    pub target_bundle_latency_blocks: u64,
    pub sponsor_commitment: String,
    pub verifier_policy_root: String,
    pub pq_auth_required: bool,
    pub active: bool,
    pub created_at_height: u64,
}

impl QueuePolicy {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "confidential_batch_settlement_queue_policy",
            "policy_id": self.policy_id,
            "lane": self.lane.as_str(),
            "priority": self.priority.as_str(),
            "priority_weight": self.priority.queue_weight(),
            "max_fee_bps": self.max_fee_bps,
            "target_fee_bps": self.target_fee_bps,
            "max_items_per_bundle": self.max_items_per_bundle,
            "max_da_bytes": self.max_da_bytes,
            "min_privacy_set_size": self.min_privacy_set_size,
            "target_bundle_latency_blocks": self.target_bundle_latency_blocks,
            "sponsor_commitment": self.sponsor_commitment,
            "verifier_policy_root": self.verifier_policy_root,
            "pq_auth_required": self.pq_auth_required,
            "active": self.active,
            "created_at_height": self.created_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivacyFence {
    pub fence_id: String,
    pub lane: QueueLane,
    pub epoch: u64,
    pub privacy_set_size: u64,
    pub nullifier_root: String,
    pub encrypted_membership_root: String,
    pub opening_policy_root: String,
    pub expires_at_height: u64,
    pub created_at_height: u64,
}

impl PrivacyFence {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "confidential_batch_settlement_privacy_fence",
            "fence_id": self.fence_id,
            "lane": self.lane.as_str(),
            "epoch": self.epoch,
            "privacy_set_size": self.privacy_set_size,
            "nullifier_root": self.nullifier_root,
            "encrypted_membership_root": self.encrypted_membership_root,
            "opening_policy_root": self.opening_policy_root,
            "expires_at_height": self.expires_at_height,
            "created_at_height": self.created_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SettlementWorker {
    pub worker_id: String,
    pub operator_commitment: String,
    pub pq_auth_key_root: String,
    pub lanes: Vec<QueueLane>,
    pub status: WorkerStatus,
    pub bond_micro_units: u64,
    pub performance_score: u64,
    pub last_seen_height: u64,
    pub registered_at_height: u64,
}

impl SettlementWorker {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "confidential_batch_settlement_worker",
            "worker_id": self.worker_id,
            "operator_commitment": self.operator_commitment,
            "pq_auth_key_root": self.pq_auth_key_root,
            "lanes": self.lanes.iter().map(|lane| lane.as_str()).collect::<Vec<_>>(),
            "status": self.status.as_str(),
            "bond_micro_units": self.bond_micro_units,
            "performance_score": self.performance_score,
            "last_seen_height": self.last_seen_height,
            "registered_at_height": self.registered_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WorkItem {
    pub work_item_id: String,
    pub lane: QueueLane,
    pub priority: SettlementPriority,
    pub owner_commitment: String,
    pub policy_id: String,
    pub privacy_fence_id: String,
    pub encrypted_payload_root: String,
    pub contract_call_root: String,
    pub state_read_root: String,
    pub state_write_commitment_root: String,
    pub nullifier_commitment: String,
    pub fee_budget_micro_units: u64,
    pub da_bytes_estimate: u64,
    pub status: WorkItemStatus,
    pub submitted_at_height: u64,
    pub expires_at_height: u64,
}

impl WorkItem {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "confidential_batch_settlement_work_item",
            "work_item_id": self.work_item_id,
            "lane": self.lane.as_str(),
            "priority": self.priority.as_str(),
            "owner_commitment": self.owner_commitment,
            "policy_id": self.policy_id,
            "privacy_fence_id": self.privacy_fence_id,
            "encrypted_payload_root": self.encrypted_payload_root,
            "contract_call_root": self.contract_call_root,
            "state_read_root": self.state_read_root,
            "state_write_commitment_root": self.state_write_commitment_root,
            "nullifier_commitment": self.nullifier_commitment,
            "fee_budget_micro_units": self.fee_budget_micro_units,
            "da_bytes_estimate": self.da_bytes_estimate,
            "status": self.status.as_str(),
            "submitted_at_height": self.submitted_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FeeQuote {
    pub quote_id: String,
    pub work_item_id: String,
    pub worker_id: String,
    pub lane: QueueLane,
    pub fee_bps: u64,
    pub fee_micro_units: u64,
    pub rebate_bps: u64,
    pub expires_at_height: u64,
    pub created_at_height: u64,
}

impl FeeQuote {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "confidential_batch_settlement_fee_quote",
            "quote_id": self.quote_id,
            "work_item_id": self.work_item_id,
            "worker_id": self.worker_id,
            "lane": self.lane.as_str(),
            "fee_bps": self.fee_bps,
            "fee_micro_units": self.fee_micro_units,
            "rebate_bps": self.rebate_bps,
            "expires_at_height": self.expires_at_height,
            "created_at_height": self.created_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SettlementBundle {
    pub bundle_id: String,
    pub lane: QueueLane,
    pub priority: SettlementPriority,
    pub worker_id: String,
    pub policy_id: String,
    pub work_item_ids: Vec<String>,
    pub work_item_root: String,
    pub fee_quote_root: String,
    pub da_commitment_root: String,
    pub aggregate_nullifier_root: String,
    pub aggregate_state_write_root: String,
    pub total_fee_micro_units: u64,
    pub total_da_bytes: u64,
    pub status: BundleStatus,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
}

impl SettlementBundle {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "confidential_batch_settlement_bundle",
            "bundle_id": self.bundle_id,
            "lane": self.lane.as_str(),
            "priority": self.priority.as_str(),
            "worker_id": self.worker_id,
            "policy_id": self.policy_id,
            "work_item_ids": self.work_item_ids,
            "work_item_root": self.work_item_root,
            "fee_quote_root": self.fee_quote_root,
            "da_commitment_root": self.da_commitment_root,
            "aggregate_nullifier_root": self.aggregate_nullifier_root,
            "aggregate_state_write_root": self.aggregate_state_write_root,
            "total_fee_micro_units": self.total_fee_micro_units,
            "total_da_bytes": self.total_da_bytes,
            "status": self.status.as_str(),
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BundleProof {
    pub proof_id: String,
    pub bundle_id: String,
    pub worker_id: String,
    pub proof_root: String,
    pub recursive_claim_root: String,
    pub verifier_key_root: String,
    pub public_input_root: String,
    pub pq_signature_root: String,
    pub status: ProofStatus,
    pub submitted_at_height: u64,
}

impl BundleProof {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "confidential_batch_settlement_bundle_proof",
            "proof_id": self.proof_id,
            "bundle_id": self.bundle_id,
            "worker_id": self.worker_id,
            "proof_root": self.proof_root,
            "recursive_claim_root": self.recursive_claim_root,
            "verifier_key_root": self.verifier_key_root,
            "public_input_root": self.public_input_root,
            "pq_signature_root": self.pq_signature_root,
            "status": self.status.as_str(),
            "submitted_at_height": self.submitted_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SettlementReceipt {
    pub receipt_id: String,
    pub bundle_id: String,
    pub proof_id: String,
    pub state_delta_root: String,
    pub fee_settlement_root: String,
    pub da_voucher_id: String,
    pub status: ReceiptStatus,
    pub published_at_height: u64,
    pub finalizes_at_height: u64,
}

impl SettlementReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "confidential_batch_settlement_receipt",
            "receipt_id": self.receipt_id,
            "bundle_id": self.bundle_id,
            "proof_id": self.proof_id,
            "state_delta_root": self.state_delta_root,
            "fee_settlement_root": self.fee_settlement_root,
            "da_voucher_id": self.da_voucher_id,
            "status": self.status.as_str(),
            "published_at_height": self.published_at_height,
            "finalizes_at_height": self.finalizes_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FeeRebate {
    pub rebate_id: String,
    pub receipt_id: String,
    pub beneficiary_commitment: String,
    pub asset_id: String,
    pub amount_micro_units: u64,
    pub status: RebateStatus,
    pub expires_at_height: u64,
    pub created_at_height: u64,
}

impl FeeRebate {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "confidential_batch_settlement_fee_rebate",
            "rebate_id": self.rebate_id,
            "receipt_id": self.receipt_id,
            "beneficiary_commitment": self.beneficiary_commitment,
            "asset_id": self.asset_id,
            "amount_micro_units": self.amount_micro_units,
            "status": self.status.as_str(),
            "expires_at_height": self.expires_at_height,
            "created_at_height": self.created_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DaVoucher {
    pub voucher_id: String,
    pub bundle_id: String,
    pub da_commitment_root: String,
    pub byte_count: u64,
    pub sponsor_commitment: String,
    pub fee_micro_units: u64,
    pub created_at_height: u64,
}

impl DaVoucher {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "confidential_batch_settlement_da_voucher",
            "voucher_id": self.voucher_id,
            "bundle_id": self.bundle_id,
            "da_commitment_root": self.da_commitment_root,
            "byte_count": self.byte_count,
            "sponsor_commitment": self.sponsor_commitment,
            "fee_micro_units": self.fee_micro_units,
            "created_at_height": self.created_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SlashingEvidence {
    pub evidence_id: String,
    pub worker_id: String,
    pub bundle_id: String,
    pub evidence_root: String,
    pub penalty_micro_units: u64,
    pub resolved: bool,
    pub created_at_height: u64,
}

impl SlashingEvidence {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "confidential_batch_settlement_slashing_evidence",
            "evidence_id": self.evidence_id,
            "worker_id": self.worker_id,
            "bundle_id": self.bundle_id,
            "evidence_root": self.evidence_root,
            "penalty_micro_units": self.penalty_micro_units,
            "resolved": self.resolved,
            "created_at_height": self.created_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct QueueCheckpoint {
    pub checkpoint_id: String,
    pub height: u64,
    pub epoch: u64,
    pub roots: Roots,
    pub queue_depth: usize,
    pub active_bundle_count: usize,
    pub created_at_height: u64,
}

impl QueueCheckpoint {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "confidential_batch_settlement_queue_checkpoint",
            "checkpoint_id": self.checkpoint_id,
            "height": self.height,
            "epoch": self.epoch,
            "roots": self.roots.public_record(),
            "queue_depth": self.queue_depth,
            "active_bundle_count": self.active_bundle_count,
            "created_at_height": self.created_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub height: u64,
    pub epoch: u64,
    pub counters: Counters,
    pub roots: Roots,
    pub policies: BTreeMap<String, QueuePolicy>,
    pub privacy_fences: BTreeMap<String, PrivacyFence>,
    pub workers: BTreeMap<String, SettlementWorker>,
    pub work_items: BTreeMap<String, WorkItem>,
    pub fee_quotes: BTreeMap<String, FeeQuote>,
    pub bundles: BTreeMap<String, SettlementBundle>,
    pub proofs: BTreeMap<String, BundleProof>,
    pub receipts: BTreeMap<String, SettlementReceipt>,
    pub rebates: BTreeMap<String, FeeRebate>,
    pub da_vouchers: BTreeMap<String, DaVoucher>,
    pub slashing_evidence: BTreeMap<String, SlashingEvidence>,
    pub checkpoints: BTreeMap<String, QueueCheckpoint>,
    pub events: Vec<Value>,
}

impl State {
    pub fn new(config: Config, height: u64, epoch: u64) -> Result<Self> {
        config.validate()?;
        let mut state = Self {
            config,
            height,
            epoch,
            counters: Counters::default(),
            roots: Roots::default(),
            policies: BTreeMap::new(),
            privacy_fences: BTreeMap::new(),
            workers: BTreeMap::new(),
            work_items: BTreeMap::new(),
            fee_quotes: BTreeMap::new(),
            bundles: BTreeMap::new(),
            proofs: BTreeMap::new(),
            receipts: BTreeMap::new(),
            rebates: BTreeMap::new(),
            da_vouchers: BTreeMap::new(),
            slashing_evidence: BTreeMap::new(),
            checkpoints: BTreeMap::new(),
            events: Vec::new(),
        };
        state.recompute_roots();
        Ok(state)
    }

    pub fn devnet() -> Result<Self> {
        let mut state = Self::new(Config::devnet(), DEVNET_HEIGHT, DEVNET_EPOCH)?;
        let contract_policy = state.open_policy(
            QueueLane::ContractCalls,
            SettlementPriority::Normal,
            "devnet:sponsor:contract-settlement",
            &json!({"lane": "contract_calls", "verifier": BUNDLE_PROOF_SUITE}),
        )?;
        let defi_policy = state.open_policy(
            QueueLane::DefiClearing,
            SettlementPriority::High,
            "devnet:sponsor:defi-clearing",
            &json!({"lane": "defi_clearing", "verifier": BUNDLE_PROOF_SUITE}),
        )?;
        let bridge_policy = state.open_policy(
            QueueLane::BridgeReceipts,
            SettlementPriority::High,
            "devnet:sponsor:bridge-receipts",
            &json!({"lane": "bridge_receipts", "verifier": BUNDLE_PROOF_SUITE}),
        )?;

        let contract_fence = state.publish_privacy_fence(
            QueueLane::ContractCalls,
            state.epoch,
            state.config.target_privacy_set_size,
            &json!({"nullifiers": ["devnet-contract-nullifier-root"]}),
            &json!({"members": "encrypted contract-call queue members"}),
        )?;
        let defi_fence = state.publish_privacy_fence(
            QueueLane::DefiClearing,
            state.epoch,
            state.config.target_privacy_set_size * 2,
            &json!({"nullifiers": ["devnet-defi-nullifier-root"]}),
            &json!({"members": "encrypted defi clearing queue members"}),
        )?;
        let bridge_fence = state.publish_privacy_fence(
            QueueLane::BridgeReceipts,
            state.epoch,
            state.config.target_privacy_set_size,
            &json!({"nullifiers": ["devnet-bridge-nullifier-root"]}),
            &json!({"members": "encrypted bridge receipt queue members"}),
        )?;

        let worker_a = state.register_worker(
            "devnet:worker:fast-settlement-a",
            &json!({"scheme": PQ_AUTH_SUITE, "worker": "a"}),
            vec![QueueLane::ContractCalls, QueueLane::DefiClearing],
            4_000_000,
        )?;
        let worker_b = state.register_worker(
            "devnet:worker:fast-settlement-b",
            &json!({"scheme": PQ_AUTH_SUITE, "worker": "b"}),
            vec![QueueLane::BridgeReceipts, QueueLane::TokenTransfers],
            3_500_000,
        )?;

        let item_a = state.enqueue_work(EnqueueWorkRequest {
            lane: QueueLane::ContractCalls,
            priority: SettlementPriority::Normal,
            owner_commitment: "devnet:owner:contract:1".to_string(),
            policy_id: contract_policy.policy_id.clone(),
            privacy_fence_id: contract_fence.fence_id.clone(),
            encrypted_payload: json!({"call": "swap_and_stake", "suite": ENCRYPTED_WORK_ITEM_SUITE}),
            contract_call: json!({"contract": "amm-router", "selector": "private_swap"}),
            state_read: json!({"read_set": ["pool:xmr-usdc", "oracle:xmr-usdc"]}),
            state_write_commitment: json!({"write_set_commitment": "devnet-write-1"}),
            fee_budget_micro_units: 250,
            da_bytes_estimate: 920,
        })?;
        let item_b = state.enqueue_work(EnqueueWorkRequest {
            lane: QueueLane::DefiClearing,
            priority: SettlementPriority::High,
            owner_commitment: "devnet:owner:defi:2".to_string(),
            policy_id: defi_policy.policy_id.clone(),
            privacy_fence_id: defi_fence.fence_id.clone(),
            encrypted_payload: json!({"call": "clear_margin_net", "suite": ENCRYPTED_WORK_ITEM_SUITE}),
            contract_call: json!({"contract": "margin-netter", "selector": "clear"}),
            state_read: json!({"read_set": ["vault:xmr", "perp:xmr-usd"]}),
            state_write_commitment: json!({"write_set_commitment": "devnet-write-2"}),
            fee_budget_micro_units: 360,
            da_bytes_estimate: 1_280,
        })?;
        let item_c = state.enqueue_work(EnqueueWorkRequest {
            lane: QueueLane::BridgeReceipts,
            priority: SettlementPriority::High,
            owner_commitment: "devnet:owner:bridge:3".to_string(),
            policy_id: bridge_policy.policy_id.clone(),
            privacy_fence_id: bridge_fence.fence_id.clone(),
            encrypted_payload: json!({"call": "settle_exit_receipt", "suite": ENCRYPTED_WORK_ITEM_SUITE}),
            contract_call: json!({"contract": "bridge-exit", "selector": "receipt"}),
            state_read: json!({"read_set": ["bridge:exit-root", "monero:anchor"]}),
            state_write_commitment: json!({"write_set_commitment": "devnet-write-3"}),
            fee_budget_micro_units: 410,
            da_bytes_estimate: 1_024,
        })?;

        let quote_a = state.quote_fee(&item_a.work_item_id, &worker_a.worker_id, 210)?;
        let quote_b = state.quote_fee(&item_b.work_item_id, &worker_a.worker_id, 320)?;
        let quote_c = state.quote_fee(&item_c.work_item_id, &worker_b.worker_id, 380)?;

        let bundle_a = state.open_bundle(
            QueueLane::ContractCalls,
            SettlementPriority::Normal,
            &worker_a.worker_id,
            &contract_policy.policy_id,
        )?;
        state.attach_item_to_bundle(
            &bundle_a.bundle_id,
            &item_a.work_item_id,
            &quote_a.quote_id,
        )?;
        state.seal_bundle(
            &bundle_a.bundle_id,
            &json!({"da": "contract-call-bundle-a"}),
        )?;
        let proof_a = state.publish_proof(
            &bundle_a.bundle_id,
            &worker_a.worker_id,
            &json!({"recursive_proof": "devnet-proof-a"}),
        )?;
        let voucher_a = state.record_da_voucher(
            &bundle_a.bundle_id,
            &json!({"da": "devnet-contract-bundle"}),
            "devnet:sponsor:contract-settlement",
            32,
        )?;
        state.settle_bundle(
            &bundle_a.bundle_id,
            &proof_a.proof_id,
            &voucher_a.voucher_id,
            &json!({"state_delta": "devnet-contract-delta"}),
        )?;

        let bundle_b = state.open_bundle(
            QueueLane::DefiClearing,
            SettlementPriority::High,
            &worker_a.worker_id,
            &defi_policy.policy_id,
        )?;
        state.attach_item_to_bundle(
            &bundle_b.bundle_id,
            &item_b.work_item_id,
            &quote_b.quote_id,
        )?;
        state.seal_bundle(
            &bundle_b.bundle_id,
            &json!({"da": "defi-clearing-bundle-b"}),
        )?;
        let proof_b = state.publish_proof(
            &bundle_b.bundle_id,
            &worker_a.worker_id,
            &json!({"recursive_proof": "devnet-proof-b"}),
        )?;
        let voucher_b = state.record_da_voucher(
            &bundle_b.bundle_id,
            &json!({"da": "devnet-defi-bundle"}),
            "devnet:sponsor:defi-clearing",
            48,
        )?;
        state.settle_bundle(
            &bundle_b.bundle_id,
            &proof_b.proof_id,
            &voucher_b.voucher_id,
            &json!({"state_delta": "devnet-defi-delta"}),
        )?;

        let bundle_c = state.open_bundle(
            QueueLane::BridgeReceipts,
            SettlementPriority::High,
            &worker_b.worker_id,
            &bridge_policy.policy_id,
        )?;
        state.attach_item_to_bundle(
            &bundle_c.bundle_id,
            &item_c.work_item_id,
            &quote_c.quote_id,
        )?;
        state.seal_bundle(
            &bundle_c.bundle_id,
            &json!({"da": "bridge-receipt-bundle-c"}),
        )?;
        let proof_c = state.publish_proof(
            &bundle_c.bundle_id,
            &worker_b.worker_id,
            &json!({"recursive_proof": "devnet-proof-c"}),
        )?;
        let voucher_c = state.record_da_voucher(
            &bundle_c.bundle_id,
            &json!({"da": "devnet-bridge-bundle"}),
            "devnet:sponsor:bridge-receipts",
            52,
        )?;
        state.settle_bundle(
            &bundle_c.bundle_id,
            &proof_c.proof_id,
            &voucher_c.voucher_id,
            &json!({"state_delta": "devnet-bridge-delta"}),
        )?;

        state.record_checkpoint()?;
        Ok(state)
    }

    pub fn open_policy(
        &mut self,
        lane: QueueLane,
        priority: SettlementPriority,
        sponsor_commitment: &str,
        verifier_policy: &Value,
    ) -> Result<QueuePolicy> {
        require_nonempty("sponsor_commitment", sponsor_commitment)?;
        let sequence = self.counters.next_policy();
        let policy = QueuePolicy {
            policy_id: policy_id(lane, self.epoch, sequence),
            lane,
            priority,
            max_fee_bps: self.config.max_fee_bps,
            target_fee_bps: lane.target_fee_bps(&self.config),
            max_items_per_bundle: self.config.max_work_items_per_bundle,
            max_da_bytes: self.config.max_da_bytes_per_bundle,
            min_privacy_set_size: self.config.min_privacy_set_size,
            target_bundle_latency_blocks: self.config.bundle_ttl_blocks / 2,
            sponsor_commitment: sponsor_commitment.to_string(),
            verifier_policy_root: payload_root("QUEUE-POLICY-VERIFIER", verifier_policy),
            pq_auth_required: self.config.require_pq_worker_auth,
            active: true,
            created_at_height: self.height,
        };
        self.policies
            .insert(policy.policy_id.clone(), policy.clone());
        self.emit_event("policy_opened", &policy.public_record());
        self.recompute_roots();
        Ok(policy)
    }

    pub fn publish_privacy_fence(
        &mut self,
        lane: QueueLane,
        epoch: u64,
        privacy_set_size: u64,
        nullifier_payload: &Value,
        membership_payload: &Value,
    ) -> Result<PrivacyFence> {
        if privacy_set_size < self.config.min_privacy_set_size {
            return Err("privacy set below configured minimum".to_string());
        }
        let sequence = self.counters.next_fence();
        let fence = PrivacyFence {
            fence_id: privacy_fence_id(lane, epoch, sequence),
            lane,
            epoch,
            privacy_set_size,
            nullifier_root: payload_root("PRIVACY-FENCE-NULLIFIERS", nullifier_payload),
            encrypted_membership_root: payload_root("PRIVACY-FENCE-MEMBERSHIP", membership_payload),
            opening_policy_root: payload_root(
                "PRIVACY-FENCE-OPENING-POLICY",
                &json!({"suite": PRIVACY_FENCE_SUITE, "lane": lane.as_str(), "epoch": epoch}),
            ),
            expires_at_height: self.height + self.config.receipt_window_blocks,
            created_at_height: self.height,
        };
        self.privacy_fences
            .insert(fence.fence_id.clone(), fence.clone());
        self.emit_event("privacy_fence_published", &fence.public_record());
        self.recompute_roots();
        Ok(fence)
    }

    pub fn register_worker(
        &mut self,
        operator_commitment: &str,
        pq_auth_key: &Value,
        lanes: Vec<QueueLane>,
        bond_micro_units: u64,
    ) -> Result<SettlementWorker> {
        require_nonempty("operator_commitment", operator_commitment)?;
        ensure_unique_lanes(&lanes)?;
        if bond_micro_units < self.config.min_worker_bond_micro_units {
            return Err("worker bond is below configured minimum".to_string());
        }
        let sequence = self.counters.next_worker();
        let worker = SettlementWorker {
            worker_id: worker_id(operator_commitment, sequence),
            operator_commitment: operator_commitment.to_string(),
            pq_auth_key_root: payload_root("WORKER-PQ-AUTH-KEY", pq_auth_key),
            lanes,
            status: WorkerStatus::Active,
            bond_micro_units,
            performance_score: 100,
            last_seen_height: self.height,
            registered_at_height: self.height,
        };
        self.workers
            .insert(worker.worker_id.clone(), worker.clone());
        self.emit_event("worker_registered", &worker.public_record());
        self.recompute_roots();
        Ok(worker)
    }

    pub fn enqueue_work(&mut self, request: EnqueueWorkRequest) -> Result<WorkItem> {
        if self.work_items.len() >= self.config.max_queue_depth {
            return Err("queue depth exceeded".to_string());
        }
        require_nonempty("owner_commitment", &request.owner_commitment)?;
        let policy = self
            .policies
            .get(&request.policy_id)
            .ok_or_else(|| "policy not found".to_string())?;
        if !policy.active {
            return Err("policy is inactive".to_string());
        }
        if policy.lane != request.lane {
            return Err("policy lane mismatch".to_string());
        }
        let fence = self
            .privacy_fences
            .get(&request.privacy_fence_id)
            .ok_or_else(|| "privacy fence not found".to_string())?;
        if fence.lane != request.lane {
            return Err("privacy fence lane mismatch".to_string());
        }
        if fence.expires_at_height <= self.height {
            return Err("privacy fence expired".to_string());
        }
        if request.da_bytes_estimate > policy.max_da_bytes {
            return Err("work item da estimate exceeds policy".to_string());
        }
        let encrypted_payload_root =
            payload_root("WORK-ITEM-ENCRYPTED-PAYLOAD", &request.encrypted_payload);
        let sequence = self.counters.next_work_item();
        let item = WorkItem {
            work_item_id: work_item_id(
                request.lane,
                &request.owner_commitment,
                &encrypted_payload_root,
                sequence,
            ),
            lane: request.lane,
            priority: request.priority,
            owner_commitment: request.owner_commitment,
            policy_id: request.policy_id,
            privacy_fence_id: request.privacy_fence_id,
            encrypted_payload_root,
            contract_call_root: payload_root("WORK-ITEM-CONTRACT-CALL", &request.contract_call),
            state_read_root: payload_root("WORK-ITEM-STATE-READ", &request.state_read),
            state_write_commitment_root: payload_root(
                "WORK-ITEM-STATE-WRITE-COMMITMENT",
                &request.state_write_commitment,
            ),
            nullifier_commitment: nullifier_commitment(
                request.lane,
                &request.contract_call,
                &request.state_write_commitment,
                sequence,
            ),
            fee_budget_micro_units: request.fee_budget_micro_units,
            da_bytes_estimate: request.da_bytes_estimate,
            status: WorkItemStatus::Enqueued,
            submitted_at_height: self.height,
            expires_at_height: self.height + self.config.work_item_ttl_blocks,
        };
        self.work_items
            .insert(item.work_item_id.clone(), item.clone());
        self.emit_event("work_item_enqueued", &item.public_record());
        self.recompute_roots();
        Ok(item)
    }

    pub fn quote_fee(
        &mut self,
        work_item_id: &str,
        worker_id: &str,
        fee_micro_units: u64,
    ) -> Result<FeeQuote> {
        let item = self
            .work_items
            .get(work_item_id)
            .ok_or_else(|| "work item not found".to_string())?
            .clone();
        let worker = self
            .workers
            .get(worker_id)
            .ok_or_else(|| "worker not found".to_string())?;
        if !worker.status.can_accept_work() {
            return Err("worker cannot accept work".to_string());
        }
        if !worker.lanes.contains(&item.lane) {
            return Err("worker does not serve lane".to_string());
        }
        if !item.status.bundleable() {
            return Err("work item cannot be quoted".to_string());
        }
        if fee_micro_units > item.fee_budget_micro_units {
            return Err("fee exceeds user budget".to_string());
        }
        let fee_bps = item.lane.target_fee_bps(&self.config);
        let sequence = self.counters.next_quote();
        let quote = FeeQuote {
            quote_id: fee_quote_id(work_item_id, worker_id, sequence),
            work_item_id: work_item_id.to_string(),
            worker_id: worker_id.to_string(),
            lane: item.lane,
            fee_bps,
            fee_micro_units,
            rebate_bps: self.config.rebate_bps,
            expires_at_height: self.height + self.config.bundle_ttl_blocks,
            created_at_height: self.height,
        };
        self.fee_quotes
            .insert(quote.quote_id.clone(), quote.clone());
        if let Some(item) = self.work_items.get_mut(work_item_id) {
            item.status = WorkItemStatus::FeeQuoted;
        }
        self.emit_event("fee_quote_created", &quote.public_record());
        self.recompute_roots();
        Ok(quote)
    }

    pub fn open_bundle(
        &mut self,
        lane: QueueLane,
        priority: SettlementPriority,
        worker_id: &str,
        policy_id: &str,
    ) -> Result<SettlementBundle> {
        let policy = self
            .policies
            .get(policy_id)
            .ok_or_else(|| "policy not found".to_string())?;
        if policy.lane != lane {
            return Err("bundle policy lane mismatch".to_string());
        }
        let worker = self
            .workers
            .get(worker_id)
            .ok_or_else(|| "worker not found".to_string())?;
        if !worker.status.can_accept_work() || !worker.lanes.contains(&lane) {
            return Err("worker cannot open bundle for lane".to_string());
        }
        let sequence = self.counters.next_bundle();
        let bundle = SettlementBundle {
            bundle_id: bundle_id(lane, worker_id, self.epoch, sequence),
            lane,
            priority,
            worker_id: worker_id.to_string(),
            policy_id: policy_id.to_string(),
            work_item_ids: Vec::new(),
            work_item_root: records_root("BUNDLE-WORK-ITEMS", Vec::new()),
            fee_quote_root: records_root("BUNDLE-FEE-QUOTES", Vec::new()),
            da_commitment_root: payload_root("BUNDLE-DA-COMMITMENT", &json!({})),
            aggregate_nullifier_root: records_root("BUNDLE-NULLIFIERS", Vec::new()),
            aggregate_state_write_root: records_root("BUNDLE-STATE-WRITES", Vec::new()),
            total_fee_micro_units: 0,
            total_da_bytes: 0,
            status: BundleStatus::Open,
            opened_at_height: self.height,
            expires_at_height: self.height + self.config.bundle_ttl_blocks,
        };
        self.bundles
            .insert(bundle.bundle_id.clone(), bundle.clone());
        self.emit_event("bundle_opened", &bundle.public_record());
        self.recompute_roots();
        Ok(bundle)
    }

    pub fn attach_item_to_bundle(
        &mut self,
        bundle_id: &str,
        work_item_id: &str,
        quote_id: &str,
    ) -> Result<()> {
        let item = self
            .work_items
            .get(work_item_id)
            .ok_or_else(|| "work item not found".to_string())?
            .clone();
        if !item.status.bundleable() {
            return Err("work item cannot be bundled".to_string());
        }
        let quote = self
            .fee_quotes
            .get(quote_id)
            .ok_or_else(|| "fee quote not found".to_string())?
            .clone();
        if quote.work_item_id != work_item_id {
            return Err("quote does not belong to work item".to_string());
        }
        if quote.expires_at_height <= self.height {
            return Err("fee quote expired".to_string());
        }
        let bundle = self
            .bundles
            .get_mut(bundle_id)
            .ok_or_else(|| "bundle not found".to_string())?;
        if !bundle.status.accepts_items() {
            return Err("bundle is not open".to_string());
        }
        if bundle.lane != item.lane {
            return Err("bundle lane mismatch".to_string());
        }
        if bundle.worker_id != quote.worker_id {
            return Err("bundle worker and quote worker mismatch".to_string());
        }
        if bundle.work_item_ids.len() >= self.config.max_work_items_per_bundle {
            return Err("bundle item limit exceeded".to_string());
        }
        let next_da_bytes = bundle.total_da_bytes.saturating_add(item.da_bytes_estimate);
        if next_da_bytes > self.config.max_da_bytes_per_bundle {
            return Err("bundle da byte limit exceeded".to_string());
        }
        if bundle.work_item_ids.iter().any(|id| id == work_item_id) {
            return Err("work item already attached".to_string());
        }
        bundle.work_item_ids.push(work_item_id.to_string());
        bundle.total_fee_micro_units = bundle
            .total_fee_micro_units
            .saturating_add(quote.fee_micro_units);
        bundle.total_da_bytes = next_da_bytes;
        bundle.work_item_root = records_root(
            "BUNDLE-WORK-ITEMS",
            bundle
                .work_item_ids
                .iter()
                .filter_map(|id| self.work_items.get(id))
                .map(WorkItem::public_record)
                .collect(),
        );
        bundle.fee_quote_root = records_root("BUNDLE-FEE-QUOTES", vec![quote.public_record()]);
        bundle.aggregate_nullifier_root = records_root(
            "BUNDLE-NULLIFIERS",
            bundle
                .work_item_ids
                .iter()
                .filter_map(|id| self.work_items.get(id))
                .map(|item| json!(item.nullifier_commitment))
                .collect(),
        );
        bundle.aggregate_state_write_root = records_root(
            "BUNDLE-STATE-WRITES",
            bundle
                .work_item_ids
                .iter()
                .filter_map(|id| self.work_items.get(id))
                .map(|item| json!(item.state_write_commitment_root))
                .collect(),
        );
        if let Some(item) = self.work_items.get_mut(work_item_id) {
            item.status = WorkItemStatus::Bundled;
        }
        self.emit_event(
            "work_item_attached",
            &json!({"bundle_id": bundle_id, "work_item_id": work_item_id, "quote_id": quote_id}),
        );
        self.recompute_roots();
        Ok(())
    }

    pub fn seal_bundle(&mut self, bundle_id: &str, da_payload: &Value) -> Result<()> {
        let bundle = self
            .bundles
            .get_mut(bundle_id)
            .ok_or_else(|| "bundle not found".to_string())?;
        if !bundle.status.accepts_items() {
            return Err("bundle cannot be sealed".to_string());
        }
        if bundle.work_item_ids.is_empty() {
            return Err("empty bundle cannot be sealed".to_string());
        }
        bundle.da_commitment_root = payload_root("BUNDLE-SEALED-DA", da_payload);
        bundle.status = BundleStatus::Sealed;
        for id in bundle.work_item_ids.clone() {
            if let Some(item) = self.work_items.get_mut(&id) {
                item.status = WorkItemStatus::Proving;
            }
        }
        self.emit_event("bundle_sealed", &json!({"bundle_id": bundle_id}));
        self.recompute_roots();
        Ok(())
    }

    pub fn publish_proof(
        &mut self,
        bundle_id: &str,
        worker_id: &str,
        proof_payload: &Value,
    ) -> Result<BundleProof> {
        let bundle = self
            .bundles
            .get_mut(bundle_id)
            .ok_or_else(|| "bundle not found".to_string())?;
        if bundle.worker_id != worker_id {
            return Err("proof worker mismatch".to_string());
        }
        if !matches!(bundle.status, BundleStatus::Sealed | BundleStatus::Proving) {
            return Err("bundle is not ready for proof".to_string());
        }
        bundle.status = BundleStatus::ProofPublished;
        let sequence = self.counters.next_proof();
        let public_input = json!({
            "bundle_id": bundle.bundle_id,
            "work_item_root": bundle.work_item_root,
            "fee_quote_root": bundle.fee_quote_root,
            "da_commitment_root": bundle.da_commitment_root,
            "aggregate_nullifier_root": bundle.aggregate_nullifier_root,
            "aggregate_state_write_root": bundle.aggregate_state_write_root,
        });
        let proof = BundleProof {
            proof_id: proof_id(bundle_id, worker_id, sequence),
            bundle_id: bundle_id.to_string(),
            worker_id: worker_id.to_string(),
            proof_root: payload_root("BUNDLE-PROOF", proof_payload),
            recursive_claim_root: payload_root(
                "BUNDLE-RECURSIVE-CLAIM",
                &json!({"suite": BUNDLE_PROOF_SUITE, "bundle": bundle_id}),
            ),
            verifier_key_root: payload_root(
                "BUNDLE-VERIFIER-KEY",
                &json!({"suite": BUNDLE_PROOF_SUITE, "pq_security_bits": self.config.pq_security_bits}),
            ),
            public_input_root: payload_root("BUNDLE-PUBLIC-INPUT", &public_input),
            pq_signature_root: payload_root(
                "BUNDLE-PQ-SIGNATURE",
                &json!({"worker_id": worker_id, "suite": PQ_AUTH_SUITE}),
            ),
            status: ProofStatus::Verified,
            submitted_at_height: self.height,
        };
        self.proofs.insert(proof.proof_id.clone(), proof.clone());
        self.emit_event("proof_published", &proof.public_record());
        self.recompute_roots();
        Ok(proof)
    }

    pub fn record_da_voucher(
        &mut self,
        bundle_id: &str,
        da_payload: &Value,
        sponsor_commitment: &str,
        fee_micro_units: u64,
    ) -> Result<DaVoucher> {
        require_nonempty("sponsor_commitment", sponsor_commitment)?;
        let bundle = self
            .bundles
            .get(bundle_id)
            .ok_or_else(|| "bundle not found".to_string())?;
        let sequence = self.counters.next_da_voucher();
        let da_commitment_root = payload_root("DA-VOUCHER-PAYLOAD", da_payload);
        let voucher = DaVoucher {
            voucher_id: da_voucher_id(bundle_id, &da_commitment_root, sequence),
            bundle_id: bundle_id.to_string(),
            da_commitment_root,
            byte_count: bundle.total_da_bytes,
            sponsor_commitment: sponsor_commitment.to_string(),
            fee_micro_units,
            created_at_height: self.height,
        };
        self.da_vouchers
            .insert(voucher.voucher_id.clone(), voucher.clone());
        self.emit_event("da_voucher_recorded", &voucher.public_record());
        self.recompute_roots();
        Ok(voucher)
    }

    pub fn settle_bundle(
        &mut self,
        bundle_id: &str,
        proof_id: &str,
        da_voucher_id: &str,
        state_delta: &Value,
    ) -> Result<SettlementReceipt> {
        let proof = self
            .proofs
            .get(proof_id)
            .ok_or_else(|| "proof not found".to_string())?;
        if proof.bundle_id != bundle_id || proof.status != ProofStatus::Verified {
            return Err("proof is not verified for bundle".to_string());
        }
        let voucher = self
            .da_vouchers
            .get(da_voucher_id)
            .ok_or_else(|| "da voucher not found".to_string())?;
        if voucher.bundle_id != bundle_id {
            return Err("da voucher bundle mismatch".to_string());
        }
        let bundle = self
            .bundles
            .get_mut(bundle_id)
            .ok_or_else(|| "bundle not found".to_string())?;
        if !matches!(
            bundle.status,
            BundleStatus::ProofPublished | BundleStatus::SettlementReady
        ) {
            return Err("bundle is not ready to settle".to_string());
        }
        bundle.status = BundleStatus::Settled;
        let work_item_ids = bundle.work_item_ids.clone();
        let total_fee_micro_units = bundle.total_fee_micro_units;
        let sequence = self.counters.next_receipt();
        let receipt = SettlementReceipt {
            receipt_id: receipt_id(bundle_id, proof_id, sequence),
            bundle_id: bundle_id.to_string(),
            proof_id: proof_id.to_string(),
            state_delta_root: payload_root("SETTLEMENT-STATE-DELTA", state_delta),
            fee_settlement_root: payload_root(
                "SETTLEMENT-FEE-ROOT",
                &json!({"asset": self.config.fee_asset_id, "total_fee_micro_units": total_fee_micro_units}),
            ),
            da_voucher_id: da_voucher_id.to_string(),
            status: ReceiptStatus::Published,
            published_at_height: self.height,
            finalizes_at_height: self.height + self.config.receipt_window_blocks,
        };
        self.receipts
            .insert(receipt.receipt_id.clone(), receipt.clone());
        for work_item_id in &work_item_ids {
            if let Some(item) = self.work_items.get_mut(work_item_id) {
                item.status = WorkItemStatus::Settled;
            }
        }
        self.create_rebates_for_receipt(&receipt, &work_item_ids, total_fee_micro_units)?;
        self.emit_event("bundle_settled", &receipt.public_record());
        self.recompute_roots();
        Ok(receipt)
    }

    pub fn record_slashing_evidence(
        &mut self,
        worker_id: &str,
        bundle_id: &str,
        evidence_payload: &Value,
        penalty_micro_units: u64,
    ) -> Result<SlashingEvidence> {
        if !self.workers.contains_key(worker_id) {
            return Err("worker not found".to_string());
        }
        if !self.bundles.contains_key(bundle_id) {
            return Err("bundle not found".to_string());
        }
        let evidence_root = payload_root("SLASHING-EVIDENCE", evidence_payload);
        let sequence = self.counters.next_slashing();
        let evidence = SlashingEvidence {
            evidence_id: slashing_evidence_id(worker_id, bundle_id, &evidence_root, sequence),
            worker_id: worker_id.to_string(),
            bundle_id: bundle_id.to_string(),
            evidence_root,
            penalty_micro_units,
            resolved: false,
            created_at_height: self.height,
        };
        if let Some(worker) = self.workers.get_mut(worker_id) {
            worker.status = WorkerStatus::Slashed;
            worker.bond_micro_units = worker.bond_micro_units.saturating_sub(penalty_micro_units);
            worker.performance_score = worker.performance_score.saturating_sub(50);
        }
        self.slashing_evidence
            .insert(evidence.evidence_id.clone(), evidence.clone());
        self.emit_event("slashing_evidence_recorded", &evidence.public_record());
        self.recompute_roots();
        Ok(evidence)
    }

    pub fn claim_rebate(&mut self, rebate_id: &str) -> Result<()> {
        let rebate = self
            .rebates
            .get_mut(rebate_id)
            .ok_or_else(|| "rebate not found".to_string())?;
        if rebate.status != RebateStatus::Accrued {
            return Err("rebate is not claimable".to_string());
        }
        if rebate.expires_at_height <= self.height {
            rebate.status = RebateStatus::Expired;
            self.recompute_roots();
            return Err("rebate expired".to_string());
        }
        rebate.status = RebateStatus::Claimed;
        self.emit_event("rebate_claimed", &json!({"rebate_id": rebate_id}));
        self.recompute_roots();
        Ok(())
    }

    pub fn advance_height(&mut self, new_height: u64) -> Result<()> {
        if new_height < self.height {
            return Err("height cannot move backwards".to_string());
        }
        self.height = new_height;
        self.expire_old_records();
        self.recompute_roots();
        Ok(())
    }

    pub fn record_checkpoint(&mut self) -> Result<QueueCheckpoint> {
        self.recompute_roots();
        let sequence = self.counters.next_checkpoint();
        let checkpoint = QueueCheckpoint {
            checkpoint_id: checkpoint_id(self.height, self.epoch, sequence),
            height: self.height,
            epoch: self.epoch,
            roots: self.roots.clone(),
            queue_depth: self
                .work_items
                .values()
                .filter(|item| item.status.bundleable())
                .count(),
            active_bundle_count: self
                .bundles
                .values()
                .filter(|bundle| {
                    matches!(
                        bundle.status,
                        BundleStatus::Open | BundleStatus::Sealed | BundleStatus::Proving
                    )
                })
                .count(),
            created_at_height: self.height,
        };
        self.checkpoints
            .insert(checkpoint.checkpoint_id.clone(), checkpoint.clone());
        self.emit_event("checkpoint_recorded", &checkpoint.public_record());
        self.recompute_roots();
        Ok(checkpoint)
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        if let Some(object) = record.as_object_mut() {
            object.insert("state_root".to_string(), json!(self.state_root()));
        }
        record
    }

    pub fn state_root(&self) -> String {
        state_root_from_record(&self.public_record_without_state_root())
    }

    pub fn roots(&self) -> &Roots {
        &self.roots
    }

    pub fn counters(&self) -> &Counters {
        &self.counters
    }

    fn public_record_without_state_root(&self) -> Value {
        json!({
            "kind": "private_l2_fast_confidential_batch_settlement_queue_runtime",
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "hash_suite": HASH_SUITE,
            "pq_auth_suite": PQ_AUTH_SUITE,
            "encrypted_work_item_suite": ENCRYPTED_WORK_ITEM_SUITE,
            "privacy_fence_suite": PRIVACY_FENCE_SUITE,
            "bundle_proof_suite": BUNDLE_PROOF_SUITE,
            "receipt_suite": RECEIPT_SUITE,
            "da_voucher_suite": DA_VOUCHER_SUITE,
            "height": self.height,
            "epoch": self.epoch,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": roots_without_self_reference(&self.roots),
            "policies": self.policies.values().map(QueuePolicy::public_record).collect::<Vec<_>>(),
            "privacy_fences": self.privacy_fences.values().map(PrivacyFence::public_record).collect::<Vec<_>>(),
            "workers": self.workers.values().map(SettlementWorker::public_record).collect::<Vec<_>>(),
            "work_items": self.work_items.values().map(WorkItem::public_record).collect::<Vec<_>>(),
            "fee_quotes": self.fee_quotes.values().map(FeeQuote::public_record).collect::<Vec<_>>(),
            "bundles": self.bundles.values().map(SettlementBundle::public_record).collect::<Vec<_>>(),
            "proofs": self.proofs.values().map(BundleProof::public_record).collect::<Vec<_>>(),
            "receipts": self.receipts.values().map(SettlementReceipt::public_record).collect::<Vec<_>>(),
            "rebates": self.rebates.values().map(FeeRebate::public_record).collect::<Vec<_>>(),
            "da_vouchers": self.da_vouchers.values().map(DaVoucher::public_record).collect::<Vec<_>>(),
            "slashing_evidence": self.slashing_evidence.values().map(SlashingEvidence::public_record).collect::<Vec<_>>(),
            "checkpoints": self.checkpoints.values().map(QueueCheckpoint::public_record).collect::<Vec<_>>(),
            "events": self.events,
        })
    }

    fn create_rebates_for_receipt(
        &mut self,
        receipt: &SettlementReceipt,
        work_item_ids: &[String],
        total_fee_micro_units: u64,
    ) -> Result<()> {
        if work_item_ids.is_empty() || total_fee_micro_units == 0 {
            return Ok(());
        }
        let per_item_fee = total_fee_micro_units / work_item_ids.len() as u64;
        for work_item_id in work_item_ids {
            let Some(item) = self.work_items.get(work_item_id) else {
                continue;
            };
            let rebate_amount = per_item_fee.saturating_mul(self.config.rebate_bps) / MAX_BPS;
            let sequence = self.counters.next_rebate();
            let rebate = FeeRebate {
                rebate_id: rebate_id(&receipt.receipt_id, &item.owner_commitment, sequence),
                receipt_id: receipt.receipt_id.clone(),
                beneficiary_commitment: item.owner_commitment.clone(),
                asset_id: self.config.fee_asset_id.clone(),
                amount_micro_units: rebate_amount,
                status: RebateStatus::Accrued,
                expires_at_height: self.height + self.config.receipt_window_blocks * 4,
                created_at_height: self.height,
            };
            self.rebates.insert(rebate.rebate_id.clone(), rebate);
        }
        Ok(())
    }

    fn expire_old_records(&mut self) {
        for item in self.work_items.values_mut() {
            if item.status.bundleable() && item.expires_at_height <= self.height {
                item.status = WorkItemStatus::Expired;
            }
        }
        for bundle in self.bundles.values_mut() {
            if matches!(
                bundle.status,
                BundleStatus::Open | BundleStatus::Sealed | BundleStatus::Proving
            ) && bundle.expires_at_height <= self.height
            {
                bundle.status = BundleStatus::Expired;
            }
        }
        for rebate in self.rebates.values_mut() {
            if rebate.status == RebateStatus::Accrued && rebate.expires_at_height <= self.height {
                rebate.status = RebateStatus::Expired;
            }
        }
    }

    fn emit_event(&mut self, event_kind: &str, payload: &Value) {
        let sequence = self.counters.next_event();
        self.events.push(json!({
            "event_id": event_id(event_kind, self.height, sequence),
            "kind": event_kind,
            "height": self.height,
            "sequence": sequence,
            "payload_root": payload_root("EVENT-PAYLOAD", payload),
        }));
    }

    fn recompute_roots(&mut self) {
        self.roots.policy_root = records_root(
            "CONFIDENTIAL-BATCH-SETTLEMENT:POLICIES",
            self.policies
                .values()
                .map(QueuePolicy::public_record)
                .collect(),
        );
        self.roots.privacy_fence_root = records_root(
            "CONFIDENTIAL-BATCH-SETTLEMENT:PRIVACY-FENCES",
            self.privacy_fences
                .values()
                .map(PrivacyFence::public_record)
                .collect(),
        );
        self.roots.work_item_root = records_root(
            "CONFIDENTIAL-BATCH-SETTLEMENT:WORK-ITEMS",
            self.work_items
                .values()
                .map(WorkItem::public_record)
                .collect(),
        );
        self.roots.worker_root = records_root(
            "CONFIDENTIAL-BATCH-SETTLEMENT:WORKERS",
            self.workers
                .values()
                .map(SettlementWorker::public_record)
                .collect(),
        );
        self.roots.fee_quote_root = records_root(
            "CONFIDENTIAL-BATCH-SETTLEMENT:FEE-QUOTES",
            self.fee_quotes
                .values()
                .map(FeeQuote::public_record)
                .collect(),
        );
        self.roots.bundle_root = records_root(
            "CONFIDENTIAL-BATCH-SETTLEMENT:BUNDLES",
            self.bundles
                .values()
                .map(SettlementBundle::public_record)
                .collect(),
        );
        self.roots.proof_root = records_root(
            "CONFIDENTIAL-BATCH-SETTLEMENT:PROOFS",
            self.proofs
                .values()
                .map(BundleProof::public_record)
                .collect(),
        );
        self.roots.receipt_root = records_root(
            "CONFIDENTIAL-BATCH-SETTLEMENT:RECEIPTS",
            self.receipts
                .values()
                .map(SettlementReceipt::public_record)
                .collect(),
        );
        self.roots.rebate_root = records_root(
            "CONFIDENTIAL-BATCH-SETTLEMENT:REBATES",
            self.rebates
                .values()
                .map(FeeRebate::public_record)
                .collect(),
        );
        self.roots.da_voucher_root = records_root(
            "CONFIDENTIAL-BATCH-SETTLEMENT:DA-VOUCHERS",
            self.da_vouchers
                .values()
                .map(DaVoucher::public_record)
                .collect(),
        );
        self.roots.slashing_evidence_root = records_root(
            "CONFIDENTIAL-BATCH-SETTLEMENT:SLASHING-EVIDENCE",
            self.slashing_evidence
                .values()
                .map(SlashingEvidence::public_record)
                .collect(),
        );
        self.roots.checkpoint_root = records_root(
            "CONFIDENTIAL-BATCH-SETTLEMENT:CHECKPOINTS",
            self.checkpoints
                .values()
                .map(QueueCheckpoint::public_record)
                .collect(),
        );
        self.roots.event_root =
            records_root("CONFIDENTIAL-BATCH-SETTLEMENT:EVENTS", self.events.clone());
        self.roots.config_root = payload_root(
            "CONFIDENTIAL-BATCH-SETTLEMENT:CONFIG",
            &self.config.public_record(),
        );
        self.roots.counter_root = payload_root(
            "CONFIDENTIAL-BATCH-SETTLEMENT:COUNTERS",
            &self.counters.public_record(),
        );
        self.roots.state_root = self.state_root();
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EnqueueWorkRequest {
    pub lane: QueueLane,
    pub priority: SettlementPriority,
    pub owner_commitment: String,
    pub policy_id: String,
    pub privacy_fence_id: String,
    pub encrypted_payload: Value,
    pub contract_call: Value,
    pub state_read: Value,
    pub state_write_commitment: Value,
    pub fee_budget_micro_units: u64,
    pub da_bytes_estimate: u64,
}

pub fn private_l2_fast_confidential_batch_settlement_queue_runtime_public_record() -> Value {
    State::devnet()
        .expect("devnet confidential batch settlement queue")
        .public_record()
}

pub fn private_l2_fast_confidential_batch_settlement_queue_runtime_state_root() -> String {
    State::devnet()
        .expect("devnet confidential batch settlement queue")
        .state_root()
}

pub fn devnet() -> Result<State> {
    State::devnet()
}

pub fn policy_id(lane: QueueLane, epoch: u64, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-FAST-CONFIDENTIAL-BATCH-SETTLEMENT-QUEUE:POLICY-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(lane.as_str()),
            HashPart::U64(epoch),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn privacy_fence_id(lane: QueueLane, epoch: u64, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-FAST-CONFIDENTIAL-BATCH-SETTLEMENT-QUEUE:PRIVACY-FENCE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(lane.as_str()),
            HashPart::U64(epoch),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn worker_id(operator_commitment: &str, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-FAST-CONFIDENTIAL-BATCH-SETTLEMENT-QUEUE:WORKER-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(operator_commitment),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn work_item_id(
    lane: QueueLane,
    owner_commitment: &str,
    encrypted_payload_root: &str,
    sequence: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-FAST-CONFIDENTIAL-BATCH-SETTLEMENT-QUEUE:WORK-ITEM-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(lane.as_str()),
            HashPart::Str(owner_commitment),
            HashPart::Str(encrypted_payload_root),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn fee_quote_id(work_item_id: &str, worker_id: &str, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-FAST-CONFIDENTIAL-BATCH-SETTLEMENT-QUEUE:FEE-QUOTE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(work_item_id),
            HashPart::Str(worker_id),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn bundle_id(lane: QueueLane, worker_id: &str, epoch: u64, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-FAST-CONFIDENTIAL-BATCH-SETTLEMENT-QUEUE:BUNDLE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(lane.as_str()),
            HashPart::Str(worker_id),
            HashPart::U64(epoch),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn proof_id(bundle_id: &str, worker_id: &str, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-FAST-CONFIDENTIAL-BATCH-SETTLEMENT-QUEUE:PROOF-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(bundle_id),
            HashPart::Str(worker_id),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn receipt_id(bundle_id: &str, proof_id: &str, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-FAST-CONFIDENTIAL-BATCH-SETTLEMENT-QUEUE:RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(bundle_id),
            HashPart::Str(proof_id),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn rebate_id(receipt_id: &str, beneficiary_commitment: &str, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-FAST-CONFIDENTIAL-BATCH-SETTLEMENT-QUEUE:REBATE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(receipt_id),
            HashPart::Str(beneficiary_commitment),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn da_voucher_id(bundle_id: &str, da_commitment_root: &str, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-FAST-CONFIDENTIAL-BATCH-SETTLEMENT-QUEUE:DA-VOUCHER-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(bundle_id),
            HashPart::Str(da_commitment_root),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn slashing_evidence_id(
    worker_id: &str,
    bundle_id: &str,
    evidence_root: &str,
    sequence: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-FAST-CONFIDENTIAL-BATCH-SETTLEMENT-QUEUE:SLASHING-EVIDENCE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(worker_id),
            HashPart::Str(bundle_id),
            HashPart::Str(evidence_root),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn checkpoint_id(height: u64, epoch: u64, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-FAST-CONFIDENTIAL-BATCH-SETTLEMENT-QUEUE:CHECKPOINT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::U64(height),
            HashPart::U64(epoch),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn event_id(event_kind: &str, height: u64, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-FAST-CONFIDENTIAL-BATCH-SETTLEMENT-QUEUE:EVENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(event_kind),
            HashPart::U64(height),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn nullifier_commitment(
    lane: QueueLane,
    contract_call: &Value,
    state_write_commitment: &Value,
    sequence: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-FAST-CONFIDENTIAL-BATCH-SETTLEMENT-QUEUE:NULLIFIER-COMMITMENT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(lane.as_str()),
            HashPart::Json(contract_call),
            HashPart::Json(state_write_commitment),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        &format!("PRIVATE-L2-FAST-CONFIDENTIAL-BATCH-SETTLEMENT-QUEUE:{domain}"),
        &[HashPart::Str(CHAIN_ID), HashPart::Json(payload)],
        32,
    )
}

pub fn root_from_record(domain: &str, record: &Value) -> String {
    domain_hash(
        &format!("PRIVATE-L2-FAST-CONFIDENTIAL-BATCH-SETTLEMENT-QUEUE:{domain}"),
        &[HashPart::Str(CHAIN_ID), HashPart::Json(record)],
        32,
    )
}

pub fn state_root_from_record(record: &Value) -> String {
    root_from_record("STATE-ROOT", record)
}

fn records_root(domain: &str, records: Vec<Value>) -> String {
    merkle_root(
        &format!("PRIVATE-L2-FAST-CONFIDENTIAL-BATCH-SETTLEMENT-QUEUE:{domain}"),
        &records,
    )
}

fn roots_without_self_reference(roots: &Roots) -> Value {
    json!({
        "policy_root": roots.policy_root,
        "privacy_fence_root": roots.privacy_fence_root,
        "work_item_root": roots.work_item_root,
        "worker_root": roots.worker_root,
        "fee_quote_root": roots.fee_quote_root,
        "bundle_root": roots.bundle_root,
        "proof_root": roots.proof_root,
        "receipt_root": roots.receipt_root,
        "rebate_root": roots.rebate_root,
        "da_voucher_root": roots.da_voucher_root,
        "slashing_evidence_root": roots.slashing_evidence_root,
        "checkpoint_root": roots.checkpoint_root,
        "event_root": roots.event_root,
        "config_root": roots.config_root,
        "counter_root": roots.counter_root,
    })
}

fn require_nonempty(label: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        return Err(format!("{label} cannot be empty"));
    }
    Ok(())
}

fn ensure_unique_lanes(lanes: &[QueueLane]) -> Result<()> {
    if lanes.is_empty() {
        return Err("worker must serve at least one lane".to_string());
    }
    let mut seen = BTreeSet::new();
    for lane in lanes {
        if !seen.insert(*lane) {
            return Err("duplicate worker lane".to_string());
        }
    }
    Ok(())
}
