use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2PqConfidentialContractEncryptedStorageCompactionMarketRuntimeResult<T> =
    std::result::Result<T, String>;
pub type Result<T> =
    PrivateL2PqConfidentialContractEncryptedStorageCompactionMarketRuntimeResult<T>;
pub type Runtime = State;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_ENCRYPTED_STORAGE_COMPACTION_MARKET_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-confidential-contract-encrypted-storage-compaction-market-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_ENCRYPTED_STORAGE_COMPACTION_MARKET_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const DEVNET_HEIGHT: u64 = 1_524_000;
pub const DEVNET_EPOCH: u64 = 42;
pub const DEVNET_L2_NETWORK: &str = "nebula-devnet";
pub const DEFAULT_FEE_ASSET_ID: &str = "piconero-devnet";
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_ENCRYPTION_SUITE: &str =
    "ML-KEM-1024+XChaCha20Poly1305+view-tagged-storage-envelope-v1";
pub const PQ_ATTESTATION_SUITE: &str = "ML-DSA-87+SLH-DSA-SHAKE-256f-compaction-attestation-v1";
pub const SEGMENT_COMMITMENT_SCHEME: &str = "private-contract-encrypted-storage-segment-root-v1";
pub const COMPACTION_ORDER_SCHEME: &str = "confidential-contract-storage-compaction-order-root-v1";
pub const PROVIDER_BID_SCHEME: &str = "sealed-provider-compaction-bid-root-v1";
pub const REBATE_COUPON_SCHEME: &str = "low-fee-storage-compaction-rebate-coupon-root-v1";
pub const PRUNING_WINDOW_SCHEME: &str = "private-contract-storage-pruning-window-root-v1";
pub const EVICTION_GUARD_SCHEME: &str = "encrypted-storage-eviction-guard-root-v1";
pub const REDACTION_BUDGET_SCHEME: &str = "private-contract-storage-redaction-budget-root-v1";
pub const OPERATOR_SUMMARY_SCHEME: &str = "public-operator-compaction-summary-root-v1";
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_TARGET_PRIVACY_SET_SIZE: u64 = 524_288;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MAX_SEGMENTS: usize = 33_554_432;
pub const DEFAULT_MAX_ORDERS: usize = 8_388_608;
pub const DEFAULT_MAX_BIDS: usize = 33_554_432;
pub const DEFAULT_MAX_ATTESTATIONS: usize = 33_554_432;
pub const DEFAULT_MAX_REBATES: usize = 16_777_216;
pub const DEFAULT_MAX_PRUNING_WINDOWS: usize = 4_194_304;
pub const DEFAULT_MAX_EVICTION_GUARDS: usize = 16_777_216;
pub const DEFAULT_MAX_REDACTION_BUDGETS: usize = 16_777_216;
pub const DEFAULT_MAX_OPERATOR_SUMMARIES: usize = 2_097_152;
pub const DEFAULT_ORDER_TTL_BLOCKS: u64 = 720;
pub const DEFAULT_BID_TTL_BLOCKS: u64 = 96;
pub const DEFAULT_ATTESTATION_TTL_BLOCKS: u64 = 7_200;
pub const DEFAULT_REBATE_TTL_BLOCKS: u64 = 21_600;
pub const DEFAULT_PRUNING_WINDOW_TTL_BLOCKS: u64 = 172_800;
pub const DEFAULT_EVICTION_GUARD_TTL_BLOCKS: u64 = 86_400;
pub const DEFAULT_MAX_SEGMENTS_PER_ORDER: usize = 4_096;
pub const DEFAULT_MAX_INPUT_BYTES_PER_ORDER: u64 = 1_073_741_824;
pub const DEFAULT_MAX_OUTPUT_BYTES_PER_ORDER: u64 = 805_306_368;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 12;
pub const DEFAULT_MAX_PROVIDER_FEE_BPS: u64 = 8;
pub const DEFAULT_TARGET_REBATE_BPS: u64 = 5;
pub const DEFAULT_SLASHING_PENALTY_BPS: u64 = 2_000;
pub const DEFAULT_MAX_REDACTION_UNITS: u64 = 1_000_000;
pub const DEFAULT_REDACTION_REPLENISH_PER_BLOCK: u64 = 500;
pub const DEFAULT_FAST_LANE_MAX_LATENCY_MS: u64 = 1_500;
pub const DEFAULT_LOW_FEE_MAX_LATENCY_MS: u64 = 10_000;
pub const MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SegmentClass {
    ContractState,
    EventLog,
    WitnessCache,
    MerkleFrontier,
    RollupInbox,
    RollupOutbox,
    OracleSnapshot,
    GovernanceState,
    AccountAbstractionState,
    CustomEncryptedBlob,
}

impl SegmentClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ContractState => "contract_state",
            Self::EventLog => "event_log",
            Self::WitnessCache => "witness_cache",
            Self::MerkleFrontier => "merkle_frontier",
            Self::RollupInbox => "rollup_inbox",
            Self::RollupOutbox => "rollup_outbox",
            Self::OracleSnapshot => "oracle_snapshot",
            Self::GovernanceState => "governance_state",
            Self::AccountAbstractionState => "account_abstraction_state",
            Self::CustomEncryptedBlob => "custom_encrypted_blob",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SegmentStatus {
    PendingSeal,
    Sealed,
    Indexed,
    Eligible,
    LockedForCompaction,
    Compacted,
    Pruned,
    Guarded,
    Disputed,
    Revoked,
}

impl SegmentStatus {
    pub fn compactable(self) -> bool {
        matches!(self, Self::Sealed | Self::Indexed | Self::Eligible)
    }

    pub fn terminal(self) -> bool {
        matches!(self, Self::Compacted | Self::Pruned | Self::Revoked)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CompactionOrderKind {
    Defragment,
    Deduplicate,
    Reencrypt,
    PruneTombstones,
    MergeSmallSegments,
    SplitHotSegment,
    ArchiveColdState,
    RotatePqEnvelope,
    RebuildIndex,
    EmergencyEvacuation,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OrderStatus {
    Open,
    Bidding,
    Awarded,
    Executing,
    Attested,
    Settled,
    Expired,
    Cancelled,
    Challenged,
    Slashed,
}

impl OrderStatus {
    pub fn accepts_bid(self) -> bool {
        matches!(self, Self::Open | Self::Bidding)
    }

    pub fn terminal(self) -> bool {
        matches!(
            self,
            Self::Settled | Self::Expired | Self::Cancelled | Self::Slashed
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BidStatus {
    Sealed,
    Revealed,
    Shortlisted,
    Awarded,
    Rejected,
    Withdrawn,
    Expired,
    Slashed,
}

impl BidStatus {
    pub fn live(self) -> bool {
        matches!(self, Self::Sealed | Self::Revealed | Self::Shortlisted)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationKind {
    CiphertextIntegrity,
    SegmentPermutation,
    RedactionBoundary,
    PruningSafety,
    ReencryptionCorrectness,
    IndexRebuild,
    FeeAccounting,
    PrivacySetMembership,
    QuantumSafeSignature,
    EmergencyRecovery,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationStatus {
    Submitted,
    QuorumAccepted,
    Superseded,
    Disputed,
    Rejected,
    Expired,
    Revoked,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RebateStatus {
    Pending,
    Claimable,
    Claimed,
    DonatedToMarket,
    Expired,
    Denied,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PruningWindowStatus {
    Scheduled,
    Open,
    Closing,
    Closed,
    Paused,
    Disputed,
    Cancelled,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvictionGuardStatus {
    Armed,
    GracePeriod,
    Tripped,
    Released,
    Expired,
    Slashed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BudgetStatus {
    Active,
    Throttled,
    Exhausted,
    Replenishing,
    Frozen,
    Revoked,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OperatorRole {
    Sequencer,
    Compactor,
    StorageProvider,
    Auditor,
    Watchtower,
    Paymaster,
    Pruner,
    EmergencyCouncil,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivacyTier {
    Standard,
    High,
    VeryHigh,
    ShieldedWhale,
    GovernanceSensitive,
}

impl PrivacyTier {
    pub fn minimum_set(self) -> u64 {
        match self {
            Self::Standard => DEFAULT_MIN_PRIVACY_SET_SIZE,
            Self::High => DEFAULT_TARGET_PRIVACY_SET_SIZE,
            Self::VeryHigh => DEFAULT_TARGET_PRIVACY_SET_SIZE * 2,
            Self::ShieldedWhale => DEFAULT_TARGET_PRIVACY_SET_SIZE * 4,
            Self::GovernanceSensitive => DEFAULT_TARGET_PRIVACY_SET_SIZE * 8,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub market_id: String,
    pub l2_network: String,
    pub fee_asset_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub pq_encryption_suite: String,
    pub pq_attestation_suite: String,
    pub segment_commitment_scheme: String,
    pub compaction_order_scheme: String,
    pub provider_bid_scheme: String,
    pub rebate_coupon_scheme: String,
    pub pruning_window_scheme: String,
    pub eviction_guard_scheme: String,
    pub redaction_budget_scheme: String,
    pub operator_summary_scheme: String,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub order_ttl_blocks: u64,
    pub bid_ttl_blocks: u64,
    pub attestation_ttl_blocks: u64,
    pub rebate_ttl_blocks: u64,
    pub pruning_window_ttl_blocks: u64,
    pub eviction_guard_ttl_blocks: u64,
    pub max_segments_per_order: usize,
    pub max_input_bytes_per_order: u64,
    pub max_output_bytes_per_order: u64,
    pub max_user_fee_bps: u64,
    pub max_provider_fee_bps: u64,
    pub target_rebate_bps: u64,
    pub slashing_penalty_bps: u64,
    pub max_redaction_units: u64,
    pub redaction_replenish_per_block: u64,
    pub fast_lane_max_latency_ms: u64,
    pub low_fee_max_latency_ms: u64,
    pub max_segments: usize,
    pub max_orders: usize,
    pub max_bids: usize,
    pub max_attestations: usize,
    pub max_rebates: usize,
    pub max_pruning_windows: usize,
    pub max_eviction_guards: usize,
    pub max_redaction_budgets: usize,
    pub max_operator_summaries: usize,
    pub allowed_privacy_tiers: BTreeSet<PrivacyTier>,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            market_id: "encrypted-storage-compaction-market-devnet".to_string(),
            l2_network: DEVNET_L2_NETWORK.to_string(),
            fee_asset_id: DEFAULT_FEE_ASSET_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            pq_encryption_suite: PQ_ENCRYPTION_SUITE.to_string(),
            pq_attestation_suite: PQ_ATTESTATION_SUITE.to_string(),
            segment_commitment_scheme: SEGMENT_COMMITMENT_SCHEME.to_string(),
            compaction_order_scheme: COMPACTION_ORDER_SCHEME.to_string(),
            provider_bid_scheme: PROVIDER_BID_SCHEME.to_string(),
            rebate_coupon_scheme: REBATE_COUPON_SCHEME.to_string(),
            pruning_window_scheme: PRUNING_WINDOW_SCHEME.to_string(),
            eviction_guard_scheme: EVICTION_GUARD_SCHEME.to_string(),
            redaction_budget_scheme: REDACTION_BUDGET_SCHEME.to_string(),
            operator_summary_scheme: OPERATOR_SUMMARY_SCHEME.to_string(),
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            order_ttl_blocks: DEFAULT_ORDER_TTL_BLOCKS,
            bid_ttl_blocks: DEFAULT_BID_TTL_BLOCKS,
            attestation_ttl_blocks: DEFAULT_ATTESTATION_TTL_BLOCKS,
            rebate_ttl_blocks: DEFAULT_REBATE_TTL_BLOCKS,
            pruning_window_ttl_blocks: DEFAULT_PRUNING_WINDOW_TTL_BLOCKS,
            eviction_guard_ttl_blocks: DEFAULT_EVICTION_GUARD_TTL_BLOCKS,
            max_segments_per_order: DEFAULT_MAX_SEGMENTS_PER_ORDER,
            max_input_bytes_per_order: DEFAULT_MAX_INPUT_BYTES_PER_ORDER,
            max_output_bytes_per_order: DEFAULT_MAX_OUTPUT_BYTES_PER_ORDER,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            max_provider_fee_bps: DEFAULT_MAX_PROVIDER_FEE_BPS,
            target_rebate_bps: DEFAULT_TARGET_REBATE_BPS,
            slashing_penalty_bps: DEFAULT_SLASHING_PENALTY_BPS,
            max_redaction_units: DEFAULT_MAX_REDACTION_UNITS,
            redaction_replenish_per_block: DEFAULT_REDACTION_REPLENISH_PER_BLOCK,
            fast_lane_max_latency_ms: DEFAULT_FAST_LANE_MAX_LATENCY_MS,
            low_fee_max_latency_ms: DEFAULT_LOW_FEE_MAX_LATENCY_MS,
            max_segments: DEFAULT_MAX_SEGMENTS,
            max_orders: DEFAULT_MAX_ORDERS,
            max_bids: DEFAULT_MAX_BIDS,
            max_attestations: DEFAULT_MAX_ATTESTATIONS,
            max_rebates: DEFAULT_MAX_REBATES,
            max_pruning_windows: DEFAULT_MAX_PRUNING_WINDOWS,
            max_eviction_guards: DEFAULT_MAX_EVICTION_GUARDS,
            max_redaction_budgets: DEFAULT_MAX_REDACTION_BUDGETS,
            max_operator_summaries: DEFAULT_MAX_OPERATOR_SUMMARIES,
            allowed_privacy_tiers: [
                PrivacyTier::Standard,
                PrivacyTier::High,
                PrivacyTier::VeryHigh,
                PrivacyTier::ShieldedWhale,
                PrivacyTier::GovernanceSensitive,
            ]
            .into_iter()
            .collect(),
        }
    }

    pub fn validate(&self) -> Result<()> {
        ensure_non_empty(&self.chain_id, "chain_id")?;
        ensure_non_empty(&self.market_id, "market_id")?;
        ensure_non_empty(&self.l2_network, "l2_network")?;
        ensure_non_empty(&self.fee_asset_id, "fee_asset_id")?;
        if self.protocol_version != PROTOCOL_VERSION {
            return Err(format!(
                "protocol_version mismatch: expected {PROTOCOL_VERSION}, got {}",
                self.protocol_version
            ));
        }
        ensure_bps(self.max_user_fee_bps, "max_user_fee_bps")?;
        ensure_bps(self.max_provider_fee_bps, "max_provider_fee_bps")?;
        ensure_bps(self.target_rebate_bps, "target_rebate_bps")?;
        ensure_bps(self.slashing_penalty_bps, "slashing_penalty_bps")?;
        if self.min_pq_security_bits < DEFAULT_MIN_PQ_SECURITY_BITS {
            return Err("min_pq_security_bits below runtime floor".to_string());
        }
        if self.target_privacy_set_size < self.min_privacy_set_size {
            return Err("target_privacy_set_size must be >= min_privacy_set_size".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "allowed_privacy_tiers": self.allowed_privacy_tiers,
            "attestation_ttl_blocks": self.attestation_ttl_blocks,
            "bid_ttl_blocks": self.bid_ttl_blocks,
            "chain_id": self.chain_id,
            "compaction_order_scheme": self.compaction_order_scheme,
            "eviction_guard_scheme": self.eviction_guard_scheme,
            "eviction_guard_ttl_blocks": self.eviction_guard_ttl_blocks,
            "fast_lane_max_latency_ms": self.fast_lane_max_latency_ms,
            "fee_asset_id": self.fee_asset_id,
            "hash_suite": self.hash_suite,
            "l2_network": self.l2_network,
            "low_fee_max_latency_ms": self.low_fee_max_latency_ms,
            "market_id": self.market_id,
            "max_input_bytes_per_order": self.max_input_bytes_per_order,
            "max_output_bytes_per_order": self.max_output_bytes_per_order,
            "max_provider_fee_bps": self.max_provider_fee_bps,
            "max_redaction_units": self.max_redaction_units,
            "max_segments_per_order": self.max_segments_per_order,
            "max_user_fee_bps": self.max_user_fee_bps,
            "min_pq_security_bits": self.min_pq_security_bits,
            "min_privacy_set_size": self.min_privacy_set_size,
            "operator_summary_scheme": self.operator_summary_scheme,
            "order_ttl_blocks": self.order_ttl_blocks,
            "pq_attestation_suite": self.pq_attestation_suite,
            "pq_encryption_suite": self.pq_encryption_suite,
            "protocol_version": self.protocol_version,
            "provider_bid_scheme": self.provider_bid_scheme,
            "pruning_window_scheme": self.pruning_window_scheme,
            "pruning_window_ttl_blocks": self.pruning_window_ttl_blocks,
            "rebate_coupon_scheme": self.rebate_coupon_scheme,
            "rebate_ttl_blocks": self.rebate_ttl_blocks,
            "redaction_budget_scheme": self.redaction_budget_scheme,
            "redaction_replenish_per_block": self.redaction_replenish_per_block,
            "schema_version": self.schema_version,
            "segment_commitment_scheme": self.segment_commitment_scheme,
            "slashing_penalty_bps": self.slashing_penalty_bps,
            "target_privacy_set_size": self.target_privacy_set_size,
            "target_rebate_bps": self.target_rebate_bps
        })
    }

    pub fn root(&self) -> String {
        record_root("CONFIG", &self.public_record())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Counters {
    pub segments_registered: u64,
    pub segments_locked: u64,
    pub segments_compacted: u64,
    pub segments_pruned: u64,
    pub orders_opened: u64,
    pub orders_awarded: u64,
    pub orders_settled: u64,
    pub bids_submitted: u64,
    pub bids_awarded: u64,
    pub attestations_submitted: u64,
    pub attestations_accepted: u64,
    pub rebates_issued: u64,
    pub rebates_claimed: u64,
    pub pruning_windows_opened: u64,
    pub eviction_guards_armed: u64,
    pub redaction_units_reserved: u64,
    pub redaction_units_spent: u64,
    pub operator_summaries_published: u64,
    pub privacy_violations_prevented: u64,
    pub low_fee_orders_routed: u64,
    pub fast_lane_orders_routed: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "attestations_accepted": self.attestations_accepted,
            "attestations_submitted": self.attestations_submitted,
            "bids_awarded": self.bids_awarded,
            "bids_submitted": self.bids_submitted,
            "eviction_guards_armed": self.eviction_guards_armed,
            "fast_lane_orders_routed": self.fast_lane_orders_routed,
            "low_fee_orders_routed": self.low_fee_orders_routed,
            "operator_summaries_published": self.operator_summaries_published,
            "orders_awarded": self.orders_awarded,
            "orders_opened": self.orders_opened,
            "orders_settled": self.orders_settled,
            "privacy_violations_prevented": self.privacy_violations_prevented,
            "pruning_windows_opened": self.pruning_windows_opened,
            "rebates_claimed": self.rebates_claimed,
            "rebates_issued": self.rebates_issued,
            "redaction_units_reserved": self.redaction_units_reserved,
            "redaction_units_spent": self.redaction_units_spent,
            "segments_compacted": self.segments_compacted,
            "segments_locked": self.segments_locked,
            "segments_pruned": self.segments_pruned,
            "segments_registered": self.segments_registered
        })
    }

    pub fn root(&self) -> String {
        record_root("COUNTERS", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub counters_root: String,
    pub segment_root: String,
    pub order_root: String,
    pub bid_root: String,
    pub attestation_root: String,
    pub rebate_root: String,
    pub pruning_window_root: String,
    pub eviction_guard_root: String,
    pub redaction_budget_root: String,
    pub operator_summary_root: String,
    pub public_record_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn empty() -> Self {
        let empty = json!({});
        let mut roots = Self {
            config_root: record_root("CONFIG-EMPTY", &empty),
            counters_root: record_root("COUNTERS-EMPTY", &empty),
            segment_root: record_root("SEGMENTS-EMPTY", &empty),
            order_root: record_root("ORDERS-EMPTY", &empty),
            bid_root: record_root("BIDS-EMPTY", &empty),
            attestation_root: record_root("ATTESTATIONS-EMPTY", &empty),
            rebate_root: record_root("REBATES-EMPTY", &empty),
            pruning_window_root: record_root("PRUNING-WINDOWS-EMPTY", &empty),
            eviction_guard_root: record_root("EVICTION-GUARDS-EMPTY", &empty),
            redaction_budget_root: record_root("REDACTION-BUDGETS-EMPTY", &empty),
            operator_summary_root: record_root("OPERATOR-SUMMARIES-EMPTY", &empty),
            public_record_root: record_root("PUBLIC-RECORD-EMPTY", &empty),
            state_root: record_root("STATE-EMPTY", &empty),
        };
        roots.state_root = roots.compute_state_root();
        roots
    }

    pub fn public_record(&self) -> Value {
        json!({
            "attestation_root": self.attestation_root,
            "bid_root": self.bid_root,
            "config_root": self.config_root,
            "counters_root": self.counters_root,
            "eviction_guard_root": self.eviction_guard_root,
            "operator_summary_root": self.operator_summary_root,
            "order_root": self.order_root,
            "pruning_window_root": self.pruning_window_root,
            "public_record_root": self.public_record_root,
            "rebate_root": self.rebate_root,
            "redaction_budget_root": self.redaction_budget_root,
            "segment_root": self.segment_root,
            "state_root": self.state_root
        })
    }

    pub fn compute_state_root(&self) -> String {
        domain_hash(
            "encrypted-storage-compaction-market:state-root",
            &[
                HashPart::Str(&self.config_root),
                HashPart::Str(&self.counters_root),
                HashPart::Str(&self.segment_root),
                HashPart::Str(&self.order_root),
                HashPart::Str(&self.bid_root),
                HashPart::Str(&self.attestation_root),
                HashPart::Str(&self.rebate_root),
                HashPart::Str(&self.pruning_window_root),
                HashPart::Str(&self.eviction_guard_root),
                HashPart::Str(&self.redaction_budget_root),
                HashPart::Str(&self.operator_summary_root),
                HashPart::Str(&self.public_record_root),
            ],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct EncryptedStorageSegment {
    pub segment_id: String,
    pub contract_id: String,
    pub owner_commitment: String,
    pub class: SegmentClass,
    pub status: SegmentStatus,
    pub encrypted_payload_root: String,
    pub ciphertext_commitment: String,
    pub index_commitment: String,
    pub nullifier_root: String,
    pub pq_envelope_root: String,
    pub size_bytes: u64,
    pub logical_records: u64,
    pub stale_records: u64,
    pub hotness_score: u64,
    pub privacy_tier: PrivacyTier,
    pub privacy_set_size: u64,
    pub created_height: u64,
    pub last_touched_height: u64,
    pub expires_height: u64,
    pub compaction_epoch: u64,
    pub guard_ids: BTreeSet<String>,
    pub tags: BTreeSet<String>,
}

impl EncryptedStorageSegment {
    pub fn public_record(&self) -> Value {
        json!({
            "ciphertext_commitment": self.ciphertext_commitment,
            "class": self.class,
            "compaction_epoch": self.compaction_epoch,
            "contract_id": self.contract_id,
            "created_height": self.created_height,
            "encrypted_payload_root": self.encrypted_payload_root,
            "expires_height": self.expires_height,
            "guard_ids": self.guard_ids,
            "hotness_score": self.hotness_score,
            "index_commitment": self.index_commitment,
            "last_touched_height": self.last_touched_height,
            "logical_records": self.logical_records,
            "nullifier_root": self.nullifier_root,
            "owner_commitment": self.owner_commitment,
            "pq_envelope_root": self.pq_envelope_root,
            "privacy_set_size": self.privacy_set_size,
            "privacy_tier": self.privacy_tier,
            "segment_id": self.segment_id,
            "size_bytes": self.size_bytes,
            "stale_records": self.stale_records,
            "status": self.status,
            "tags": self.tags
        })
    }

    pub fn root(&self) -> String {
        record_root("SEGMENT", &self.public_record())
    }

    pub fn stale_ratio_bps(&self) -> u64 {
        if self.logical_records == 0 {
            0
        } else {
            self.stale_records.saturating_mul(MAX_BPS) / self.logical_records
        }
    }

    pub fn can_compact_at(&self, height: u64) -> bool {
        self.status.compactable() && height <= self.expires_height && self.guard_ids.is_empty()
    }

    pub fn lock_for_compaction(&mut self, order_id: &str, height: u64) -> Result<()> {
        if !self.status.compactable() {
            return Err(format!(
                "segment {} is not compactable from status {:?}",
                self.segment_id, self.status
            ));
        }
        self.status = SegmentStatus::LockedForCompaction;
        self.last_touched_height = height;
        self.tags.insert(format!("locked_by:{order_id}"));
        Ok(())
    }

    pub fn mark_compacted(
        &mut self,
        new_payload_root: String,
        new_index_commitment: String,
        height: u64,
    ) -> Result<()> {
        if self.status != SegmentStatus::LockedForCompaction {
            return Err("segment must be locked before compaction".to_string());
        }
        ensure_non_empty(&new_payload_root, "new_payload_root")?;
        ensure_non_empty(&new_index_commitment, "new_index_commitment")?;
        self.encrypted_payload_root = new_payload_root;
        self.index_commitment = new_index_commitment;
        self.status = SegmentStatus::Compacted;
        self.last_touched_height = height;
        self.compaction_epoch = self.compaction_epoch.saturating_add(1);
        Ok(())
    }

    pub fn arm_guard(&mut self, guard_id: String) -> Result<()> {
        ensure_non_empty(&guard_id, "guard_id")?;
        self.guard_ids.insert(guard_id);
        self.status = SegmentStatus::Guarded;
        Ok(())
    }

    pub fn release_guard(&mut self, guard_id: &str) {
        self.guard_ids.remove(guard_id);
        if self.status == SegmentStatus::Guarded && self.guard_ids.is_empty() {
            self.status = SegmentStatus::Eligible;
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RegisterSegmentRequest {
    pub contract_id: String,
    pub owner_commitment: String,
    pub class: SegmentClass,
    pub encrypted_payload_root: String,
    pub ciphertext_commitment: String,
    pub index_commitment: String,
    pub nullifier_root: String,
    pub pq_envelope_root: String,
    pub size_bytes: u64,
    pub logical_records: u64,
    pub stale_records: u64,
    pub hotness_score: u64,
    pub privacy_tier: PrivacyTier,
    pub privacy_set_size: u64,
    pub created_height: u64,
    pub ttl_blocks: u64,
    pub tags: BTreeSet<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CompactionOrder {
    pub order_id: String,
    pub creator_commitment: String,
    pub contract_id: String,
    pub kind: CompactionOrderKind,
    pub status: OrderStatus,
    pub segment_ids: Vec<String>,
    pub input_segment_root: String,
    pub output_segment_root: Option<String>,
    pub max_fee_micro_units: u64,
    pub max_provider_fee_bps: u64,
    pub target_output_bytes: u64,
    pub min_stale_ratio_bps: u64,
    pub privacy_tier: PrivacyTier,
    pub privacy_set_size: u64,
    pub opened_height: u64,
    pub bid_deadline_height: u64,
    pub execution_deadline_height: u64,
    pub awarded_bid_id: Option<String>,
    pub attestation_ids: BTreeSet<String>,
    pub rebate_coupon_id: Option<String>,
    pub lane: String,
    pub encrypted_order_hint_root: String,
    pub redaction_budget_id: Option<String>,
}

impl CompactionOrder {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_ids": self.attestation_ids,
            "awarded_bid_id": self.awarded_bid_id,
            "bid_deadline_height": self.bid_deadline_height,
            "contract_id": self.contract_id,
            "creator_commitment": self.creator_commitment,
            "encrypted_order_hint_root": self.encrypted_order_hint_root,
            "execution_deadline_height": self.execution_deadline_height,
            "input_segment_root": self.input_segment_root,
            "kind": self.kind,
            "lane": self.lane,
            "max_fee_micro_units": self.max_fee_micro_units,
            "max_provider_fee_bps": self.max_provider_fee_bps,
            "min_stale_ratio_bps": self.min_stale_ratio_bps,
            "opened_height": self.opened_height,
            "order_id": self.order_id,
            "output_segment_root": self.output_segment_root,
            "privacy_set_size": self.privacy_set_size,
            "privacy_tier": self.privacy_tier,
            "rebate_coupon_id": self.rebate_coupon_id,
            "redaction_budget_id": self.redaction_budget_id,
            "segment_ids": self.segment_ids,
            "status": self.status,
            "target_output_bytes": self.target_output_bytes
        })
    }

    pub fn root(&self) -> String {
        record_root("ORDER", &self.public_record())
    }

    pub fn is_expired_at(&self, height: u64) -> bool {
        height > self.execution_deadline_height && !self.status.terminal()
    }

    pub fn accepts_bid_at(&self, height: u64) -> bool {
        self.status.accepts_bid() && height <= self.bid_deadline_height
    }

    pub fn assign_bid(&mut self, bid_id: String, height: u64) -> Result<()> {
        ensure_non_empty(&bid_id, "bid_id")?;
        if height > self.bid_deadline_height {
            return Err("cannot award bid after bid deadline".to_string());
        }
        self.awarded_bid_id = Some(bid_id);
        self.status = OrderStatus::Awarded;
        Ok(())
    }

    pub fn attach_attestation(&mut self, attestation_id: String) -> Result<()> {
        ensure_non_empty(&attestation_id, "attestation_id")?;
        self.attestation_ids.insert(attestation_id);
        self.status = OrderStatus::Attested;
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OpenCompactionOrderRequest {
    pub creator_commitment: String,
    pub contract_id: String,
    pub kind: CompactionOrderKind,
    pub segment_ids: Vec<String>,
    pub max_fee_micro_units: u64,
    pub max_provider_fee_bps: u64,
    pub target_output_bytes: u64,
    pub min_stale_ratio_bps: u64,
    pub privacy_tier: PrivacyTier,
    pub privacy_set_size: u64,
    pub opened_height: u64,
    pub encrypted_order_hint_root: String,
    pub redaction_budget_id: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ProviderBid {
    pub bid_id: String,
    pub order_id: String,
    pub provider_commitment: String,
    pub status: BidStatus,
    pub sealed_bid_root: String,
    pub revealed_price_micro_units: Option<u64>,
    pub provider_fee_bps: u64,
    pub expected_output_bytes: u64,
    pub max_latency_ms: u64,
    pub pq_capability_root: String,
    pub storage_proof_root: String,
    pub collateral_commitment: String,
    pub submitted_height: u64,
    pub expires_height: u64,
    pub award_weight: u64,
    pub privacy_set_size: u64,
}

impl ProviderBid {
    pub fn public_record(&self) -> Value {
        json!({
            "award_weight": self.award_weight,
            "bid_id": self.bid_id,
            "collateral_commitment": self.collateral_commitment,
            "expected_output_bytes": self.expected_output_bytes,
            "expires_height": self.expires_height,
            "max_latency_ms": self.max_latency_ms,
            "order_id": self.order_id,
            "pq_capability_root": self.pq_capability_root,
            "privacy_set_size": self.privacy_set_size,
            "provider_commitment": self.provider_commitment,
            "provider_fee_bps": self.provider_fee_bps,
            "revealed_price_micro_units": self.revealed_price_micro_units,
            "sealed_bid_root": self.sealed_bid_root,
            "status": self.status,
            "storage_proof_root": self.storage_proof_root,
            "submitted_height": self.submitted_height
        })
    }

    pub fn root(&self) -> String {
        record_root("BID", &self.public_record())
    }

    pub fn effective_fee(&self, order: &CompactionOrder) -> Option<u64> {
        self.revealed_price_micro_units.map(|price| {
            price
                .saturating_add(
                    order
                        .max_fee_micro_units
                        .saturating_mul(self.provider_fee_bps)
                        / MAX_BPS,
                )
                .saturating_add(self.expected_output_bytes / 1_048_576)
        })
    }

    pub fn reveal(&mut self, price_micro_units: u64, height: u64) -> Result<()> {
        if height > self.expires_height {
            return Err("cannot reveal expired bid".to_string());
        }
        if !matches!(self.status, BidStatus::Sealed) {
            return Err("only sealed bids can be revealed".to_string());
        }
        self.revealed_price_micro_units = Some(price_micro_units);
        self.status = BidStatus::Revealed;
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SubmitProviderBidRequest {
    pub order_id: String,
    pub provider_commitment: String,
    pub sealed_bid_root: String,
    pub revealed_price_micro_units: Option<u64>,
    pub provider_fee_bps: u64,
    pub expected_output_bytes: u64,
    pub max_latency_ms: u64,
    pub pq_capability_root: String,
    pub storage_proof_root: String,
    pub collateral_commitment: String,
    pub submitted_height: u64,
    pub privacy_set_size: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PqCompactionAttestation {
    pub attestation_id: String,
    pub order_id: String,
    pub bid_id: String,
    pub provider_commitment: String,
    pub kind: AttestationKind,
    pub status: AttestationStatus,
    pub input_root: String,
    pub output_root: String,
    pub transcript_root: String,
    pub pq_signature_root: String,
    pub verifier_set_root: String,
    pub quorum_bps: u64,
    pub proof_size_bytes: u64,
    pub gas_used_micro_units: u64,
    pub submitted_height: u64,
    pub expires_height: u64,
    pub redacted_fields: BTreeSet<String>,
}

impl PqCompactionAttestation {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "bid_id": self.bid_id,
            "expires_height": self.expires_height,
            "gas_used_micro_units": self.gas_used_micro_units,
            "input_root": self.input_root,
            "kind": self.kind,
            "order_id": self.order_id,
            "output_root": self.output_root,
            "pq_signature_root": self.pq_signature_root,
            "proof_size_bytes": self.proof_size_bytes,
            "provider_commitment": self.provider_commitment,
            "quorum_bps": self.quorum_bps,
            "redacted_fields": self.redacted_fields,
            "status": self.status,
            "submitted_height": self.submitted_height,
            "transcript_root": self.transcript_root,
            "verifier_set_root": self.verifier_set_root
        })
    }

    pub fn root(&self) -> String {
        record_root("ATTESTATION", &self.public_record())
    }

    pub fn accepted(&self) -> bool {
        matches!(self.status, AttestationStatus::QuorumAccepted)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SubmitAttestationRequest {
    pub order_id: String,
    pub bid_id: String,
    pub provider_commitment: String,
    pub kind: AttestationKind,
    pub input_root: String,
    pub output_root: String,
    pub transcript_root: String,
    pub pq_signature_root: String,
    pub verifier_set_root: String,
    pub quorum_bps: u64,
    pub proof_size_bytes: u64,
    pub gas_used_micro_units: u64,
    pub submitted_height: u64,
    pub redacted_fields: BTreeSet<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RebateCoupon {
    pub coupon_id: String,
    pub order_id: String,
    pub claimant_commitment: String,
    pub status: RebateStatus,
    pub fee_asset_id: String,
    pub amount_micro_units: u64,
    pub rebate_bps: u64,
    pub nullifier_root: String,
    pub claim_root: String,
    pub issued_height: u64,
    pub expires_height: u64,
    pub claimed_height: Option<u64>,
}

impl RebateCoupon {
    pub fn public_record(&self) -> Value {
        json!({
            "amount_micro_units": self.amount_micro_units,
            "claim_root": self.claim_root,
            "claimant_commitment": self.claimant_commitment,
            "claimed_height": self.claimed_height,
            "coupon_id": self.coupon_id,
            "expires_height": self.expires_height,
            "fee_asset_id": self.fee_asset_id,
            "issued_height": self.issued_height,
            "nullifier_root": self.nullifier_root,
            "order_id": self.order_id,
            "rebate_bps": self.rebate_bps,
            "status": self.status
        })
    }

    pub fn root(&self) -> String {
        record_root("REBATE", &self.public_record())
    }

    pub fn claim(&mut self, height: u64) -> Result<()> {
        if height > self.expires_height {
            self.status = RebateStatus::Expired;
            return Err("rebate coupon expired".to_string());
        }
        if !matches!(self.status, RebateStatus::Claimable | RebateStatus::Pending) {
            return Err("rebate coupon is not claimable".to_string());
        }
        self.status = RebateStatus::Claimed;
        self.claimed_height = Some(height);
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct IssueRebateCouponRequest {
    pub order_id: String,
    pub claimant_commitment: String,
    pub amount_micro_units: u64,
    pub rebate_bps: u64,
    pub nullifier_root: String,
    pub claim_root: String,
    pub issued_height: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PruningWindow {
    pub window_id: String,
    pub contract_id: String,
    pub status: PruningWindowStatus,
    pub start_height: u64,
    pub end_height: u64,
    pub min_age_blocks: u64,
    pub segment_class: SegmentClass,
    pub eligible_segment_root: String,
    pub exclusion_root: String,
    pub privacy_tier: PrivacyTier,
    pub max_prunable_bytes: u64,
    pub pruned_bytes: u64,
    pub opened_by_commitment: String,
}

impl PruningWindow {
    pub fn public_record(&self) -> Value {
        json!({
            "contract_id": self.contract_id,
            "eligible_segment_root": self.eligible_segment_root,
            "end_height": self.end_height,
            "exclusion_root": self.exclusion_root,
            "max_prunable_bytes": self.max_prunable_bytes,
            "min_age_blocks": self.min_age_blocks,
            "opened_by_commitment": self.opened_by_commitment,
            "privacy_tier": self.privacy_tier,
            "pruned_bytes": self.pruned_bytes,
            "segment_class": self.segment_class,
            "start_height": self.start_height,
            "status": self.status,
            "window_id": self.window_id
        })
    }

    pub fn root(&self) -> String {
        record_root("PRUNING-WINDOW", &self.public_record())
    }

    pub fn contains(&self, height: u64) -> bool {
        height >= self.start_height && height <= self.end_height
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OpenPruningWindowRequest {
    pub contract_id: String,
    pub start_height: u64,
    pub end_height: u64,
    pub min_age_blocks: u64,
    pub segment_class: SegmentClass,
    pub eligible_segment_root: String,
    pub exclusion_root: String,
    pub privacy_tier: PrivacyTier,
    pub max_prunable_bytes: u64,
    pub opened_by_commitment: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct EvictionGuard {
    pub guard_id: String,
    pub segment_id: String,
    pub owner_commitment: String,
    pub status: EvictionGuardStatus,
    pub reason_root: String,
    pub armed_height: u64,
    pub expires_height: u64,
    pub bond_commitment: String,
    pub release_root: Option<String>,
    pub prevented_order_ids: BTreeSet<String>,
}

impl EvictionGuard {
    pub fn public_record(&self) -> Value {
        json!({
            "armed_height": self.armed_height,
            "bond_commitment": self.bond_commitment,
            "expires_height": self.expires_height,
            "guard_id": self.guard_id,
            "owner_commitment": self.owner_commitment,
            "prevented_order_ids": self.prevented_order_ids,
            "reason_root": self.reason_root,
            "release_root": self.release_root,
            "segment_id": self.segment_id,
            "status": self.status
        })
    }

    pub fn root(&self) -> String {
        record_root("EVICTION-GUARD", &self.public_record())
    }

    pub fn active_at(&self, height: u64) -> bool {
        matches!(
            self.status,
            EvictionGuardStatus::Armed | EvictionGuardStatus::GracePeriod
        ) && height <= self.expires_height
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ArmEvictionGuardRequest {
    pub segment_id: String,
    pub owner_commitment: String,
    pub reason_root: String,
    pub armed_height: u64,
    pub bond_commitment: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RedactionBudget {
    pub budget_id: String,
    pub owner_commitment: String,
    pub contract_id: String,
    pub status: BudgetStatus,
    pub max_units: u64,
    pub remaining_units: u64,
    pub spent_units: u64,
    pub replenish_per_block: u64,
    pub last_replenished_height: u64,
    pub allowed_fields_root: String,
    pub redacted_fields: BTreeSet<String>,
    pub privacy_set_size: u64,
}

impl RedactionBudget {
    pub fn public_record(&self) -> Value {
        json!({
            "allowed_fields_root": self.allowed_fields_root,
            "budget_id": self.budget_id,
            "contract_id": self.contract_id,
            "last_replenished_height": self.last_replenished_height,
            "max_units": self.max_units,
            "owner_commitment": self.owner_commitment,
            "privacy_set_size": self.privacy_set_size,
            "redacted_fields": self.redacted_fields,
            "remaining_units": self.remaining_units,
            "replenish_per_block": self.replenish_per_block,
            "spent_units": self.spent_units,
            "status": self.status
        })
    }

    pub fn root(&self) -> String {
        record_root("REDACTION-BUDGET", &self.public_record())
    }

    pub fn replenish(&mut self, height: u64) {
        if height <= self.last_replenished_height {
            return;
        }
        let delta = height
            .saturating_sub(self.last_replenished_height)
            .saturating_mul(self.replenish_per_block);
        self.remaining_units = self
            .remaining_units
            .saturating_add(delta)
            .min(self.max_units);
        self.last_replenished_height = height;
        if self.remaining_units > 0 && self.status == BudgetStatus::Exhausted {
            self.status = BudgetStatus::Replenishing;
        }
    }

    pub fn reserve(&mut self, units: u64, height: u64) -> Result<()> {
        self.replenish(height);
        if matches!(self.status, BudgetStatus::Frozen | BudgetStatus::Revoked) {
            return Err("redaction budget is frozen or revoked".to_string());
        }
        if units > self.remaining_units {
            self.status = BudgetStatus::Exhausted;
            return Err("insufficient redaction units".to_string());
        }
        self.remaining_units -= units;
        self.spent_units = self.spent_units.saturating_add(units);
        if self.remaining_units == 0 {
            self.status = BudgetStatus::Exhausted;
        } else {
            self.status = BudgetStatus::Active;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CreateRedactionBudgetRequest {
    pub owner_commitment: String,
    pub contract_id: String,
    pub max_units: u64,
    pub replenish_per_block: u64,
    pub opened_height: u64,
    pub allowed_fields_root: String,
    pub redacted_fields: BTreeSet<String>,
    pub privacy_set_size: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OperatorSummary {
    pub summary_id: String,
    pub operator_commitment: String,
    pub role: OperatorRole,
    pub epoch: u64,
    pub orders_processed: u64,
    pub bytes_compacted: u64,
    pub median_latency_ms: u64,
    pub median_fee_bps: u64,
    pub rebate_bps_paid: u64,
    pub attestation_quorum_bps: u64,
    pub slashing_events: u64,
    pub privacy_incidents: u64,
    pub summary_root: String,
    pub published_height: u64,
}

impl OperatorSummary {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_quorum_bps": self.attestation_quorum_bps,
            "bytes_compacted": self.bytes_compacted,
            "epoch": self.epoch,
            "median_fee_bps": self.median_fee_bps,
            "median_latency_ms": self.median_latency_ms,
            "operator_commitment": self.operator_commitment,
            "orders_processed": self.orders_processed,
            "privacy_incidents": self.privacy_incidents,
            "published_height": self.published_height,
            "rebate_bps_paid": self.rebate_bps_paid,
            "role": self.role,
            "slashing_events": self.slashing_events,
            "summary_id": self.summary_id,
            "summary_root": self.summary_root
        })
    }

    pub fn root(&self) -> String {
        record_root("OPERATOR-SUMMARY", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PublishOperatorSummaryRequest {
    pub operator_commitment: String,
    pub role: OperatorRole,
    pub epoch: u64,
    pub orders_processed: u64,
    pub bytes_compacted: u64,
    pub median_latency_ms: u64,
    pub median_fee_bps: u64,
    pub rebate_bps_paid: u64,
    pub attestation_quorum_bps: u64,
    pub slashing_events: u64,
    pub privacy_incidents: u64,
    pub summary_root: String,
    pub published_height: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub segments: BTreeMap<String, EncryptedStorageSegment>,
    pub orders: BTreeMap<String, CompactionOrder>,
    pub bids: BTreeMap<String, ProviderBid>,
    pub attestations: BTreeMap<String, PqCompactionAttestation>,
    pub rebates: BTreeMap<String, RebateCoupon>,
    pub pruning_windows: BTreeMap<String, PruningWindow>,
    pub eviction_guards: BTreeMap<String, EvictionGuard>,
    pub redaction_budgets: BTreeMap<String, RedactionBudget>,
    pub operator_summaries: BTreeMap<String, OperatorSummary>,
}

impl State {
    pub fn devnet() -> Self {
        let mut state = Self {
            config: Config::devnet(),
            counters: Counters::default(),
            roots: Roots::empty(),
            segments: BTreeMap::new(),
            orders: BTreeMap::new(),
            bids: BTreeMap::new(),
            attestations: BTreeMap::new(),
            rebates: BTreeMap::new(),
            pruning_windows: BTreeMap::new(),
            eviction_guards: BTreeMap::new(),
            redaction_budgets: BTreeMap::new(),
            operator_summaries: BTreeMap::new(),
        };
        state.refresh_roots();
        state
    }

    pub fn public_record(&self) -> Value {
        json!({
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "protocol_version": PROTOCOL_VERSION,
            "roots": self.roots.public_record(),
            "schema_version": SCHEMA_VERSION
        })
    }

    pub fn state_root(&self) -> String {
        self.roots.state_root.clone()
    }

    pub fn refresh_roots(&mut self) {
        self.roots.config_root = self.config.root();
        self.roots.counters_root = self.counters.root();
        self.roots.segment_root = map_root("SEGMENTS", &self.segments);
        self.roots.order_root = map_root("ORDERS", &self.orders);
        self.roots.bid_root = map_root("BIDS", &self.bids);
        self.roots.attestation_root = map_root("ATTESTATIONS", &self.attestations);
        self.roots.rebate_root = map_root("REBATES", &self.rebates);
        self.roots.pruning_window_root = map_root("PRUNING-WINDOWS", &self.pruning_windows);
        self.roots.eviction_guard_root = map_root("EVICTION-GUARDS", &self.eviction_guards);
        self.roots.redaction_budget_root = map_root("REDACTION-BUDGETS", &self.redaction_budgets);
        self.roots.operator_summary_root = map_root("OPERATOR-SUMMARIES", &self.operator_summaries);
        self.roots.public_record_root = record_root(
            "PUBLIC-RECORD",
            &self.public_record_without_roots_state_root(),
        );
        self.roots.state_root = self.roots.compute_state_root();
    }

    pub fn register_segment(
        &mut self,
        request: RegisterSegmentRequest,
    ) -> Result<EncryptedStorageSegment> {
        self.config.validate()?;
        ensure_capacity(self.segments.len(), self.config.max_segments, "segments")?;
        ensure_non_empty(&request.contract_id, "contract_id")?;
        ensure_non_empty(&request.owner_commitment, "owner_commitment")?;
        ensure_non_empty(&request.encrypted_payload_root, "encrypted_payload_root")?;
        ensure_non_empty(&request.ciphertext_commitment, "ciphertext_commitment")?;
        ensure_non_empty(&request.index_commitment, "index_commitment")?;
        ensure_non_empty(&request.nullifier_root, "nullifier_root")?;
        ensure_non_empty(&request.pq_envelope_root, "pq_envelope_root")?;
        ensure_privacy(&self.config, request.privacy_tier, request.privacy_set_size)?;
        if request.stale_records > request.logical_records {
            return Err("stale_records must be <= logical_records".to_string());
        }
        let segment_id = stable_id(
            "segment",
            &[
                HashPart::Str(&request.contract_id),
                HashPart::Str(&request.owner_commitment),
                HashPart::Str(request.class.as_str()),
                HashPart::Str(&request.encrypted_payload_root),
                HashPart::U64(request.created_height),
            ],
        );
        if self.segments.contains_key(&segment_id) {
            return Err(format!("segment {segment_id} already exists"));
        }
        let segment = EncryptedStorageSegment {
            segment_id: segment_id.clone(),
            contract_id: request.contract_id,
            owner_commitment: request.owner_commitment,
            class: request.class,
            status: SegmentStatus::Sealed,
            encrypted_payload_root: request.encrypted_payload_root,
            ciphertext_commitment: request.ciphertext_commitment,
            index_commitment: request.index_commitment,
            nullifier_root: request.nullifier_root,
            pq_envelope_root: request.pq_envelope_root,
            size_bytes: request.size_bytes,
            logical_records: request.logical_records,
            stale_records: request.stale_records,
            hotness_score: request.hotness_score,
            privacy_tier: request.privacy_tier,
            privacy_set_size: request.privacy_set_size,
            created_height: request.created_height,
            last_touched_height: request.created_height,
            expires_height: request.created_height.saturating_add(request.ttl_blocks),
            compaction_epoch: 0,
            guard_ids: BTreeSet::new(),
            tags: request.tags,
        };
        self.segments.insert(segment_id, segment.clone());
        self.counters.segments_registered = self.counters.segments_registered.saturating_add(1);
        self.refresh_roots();
        Ok(segment)
    }

    pub fn open_compaction_order(
        &mut self,
        request: OpenCompactionOrderRequest,
    ) -> Result<CompactionOrder> {
        self.config.validate()?;
        ensure_capacity(self.orders.len(), self.config.max_orders, "orders")?;
        ensure_non_empty(&request.creator_commitment, "creator_commitment")?;
        ensure_non_empty(&request.contract_id, "contract_id")?;
        ensure_non_empty(
            &request.encrypted_order_hint_root,
            "encrypted_order_hint_root",
        )?;
        ensure_bps(request.max_provider_fee_bps, "max_provider_fee_bps")?;
        ensure_bps(request.min_stale_ratio_bps, "min_stale_ratio_bps")?;
        ensure_privacy(&self.config, request.privacy_tier, request.privacy_set_size)?;
        if request.segment_ids.is_empty() {
            return Err("compaction order requires at least one segment".to_string());
        }
        if request.segment_ids.len() > self.config.max_segments_per_order {
            return Err("too many segments for compaction order".to_string());
        }
        if request.target_output_bytes > self.config.max_output_bytes_per_order {
            return Err("target_output_bytes exceeds runtime cap".to_string());
        }
        let mut input_bytes = 0u64;
        let mut segment_records = Vec::with_capacity(request.segment_ids.len());
        for segment_id in &request.segment_ids {
            let segment = self
                .segments
                .get(segment_id)
                .ok_or_else(|| format!("unknown segment {segment_id}"))?;
            if segment.contract_id != request.contract_id {
                return Err(format!("segment {segment_id} belongs to another contract"));
            }
            if !segment.can_compact_at(request.opened_height) {
                return Err(format!("segment {segment_id} cannot be compacted"));
            }
            if segment.privacy_set_size < request.privacy_set_size {
                return Err(format!("segment {segment_id} privacy set too small"));
            }
            input_bytes = input_bytes.saturating_add(segment.size_bytes);
            segment_records.push(segment.public_record());
        }
        if input_bytes > self.config.max_input_bytes_per_order {
            return Err("input segment bytes exceed runtime cap".to_string());
        }
        let input_segment_root = merkle_root("ORDER-INPUT-SEGMENTS", &segment_records);
        let lane = if input_bytes <= request.target_output_bytes.saturating_mul(2)
            && request.max_provider_fee_bps <= self.config.max_provider_fee_bps
        {
            self.counters.low_fee_orders_routed =
                self.counters.low_fee_orders_routed.saturating_add(1);
            "low_fee".to_string()
        } else {
            self.counters.fast_lane_orders_routed =
                self.counters.fast_lane_orders_routed.saturating_add(1);
            "fast".to_string()
        };
        if let Some(budget_id) = &request.redaction_budget_id {
            let budget = self
                .redaction_budgets
                .get_mut(budget_id)
                .ok_or_else(|| format!("unknown redaction budget {budget_id}"))?;
            budget.reserve(request.segment_ids.len() as u64, request.opened_height)?;
            self.counters.redaction_units_reserved = self
                .counters
                .redaction_units_reserved
                .saturating_add(request.segment_ids.len() as u64);
        }
        let order_id = stable_id(
            "order",
            &[
                HashPart::Str(&request.creator_commitment),
                HashPart::Str(&request.contract_id),
                HashPart::Str(&input_segment_root),
                HashPart::U64(request.opened_height),
            ],
        );
        if self.orders.contains_key(&order_id) {
            return Err(format!("order {order_id} already exists"));
        }
        for segment_id in &request.segment_ids {
            self.segments
                .get_mut(segment_id)
                .expect("segment validated")
                .lock_for_compaction(&order_id, request.opened_height)?;
            self.counters.segments_locked = self.counters.segments_locked.saturating_add(1);
        }
        let order = CompactionOrder {
            order_id: order_id.clone(),
            creator_commitment: request.creator_commitment,
            contract_id: request.contract_id,
            kind: request.kind,
            status: OrderStatus::Bidding,
            segment_ids: request.segment_ids,
            input_segment_root,
            output_segment_root: None,
            max_fee_micro_units: request.max_fee_micro_units,
            max_provider_fee_bps: request.max_provider_fee_bps,
            target_output_bytes: request.target_output_bytes,
            min_stale_ratio_bps: request.min_stale_ratio_bps,
            privacy_tier: request.privacy_tier,
            privacy_set_size: request.privacy_set_size,
            opened_height: request.opened_height,
            bid_deadline_height: request
                .opened_height
                .saturating_add(self.config.bid_ttl_blocks),
            execution_deadline_height: request
                .opened_height
                .saturating_add(self.config.order_ttl_blocks),
            awarded_bid_id: None,
            attestation_ids: BTreeSet::new(),
            rebate_coupon_id: None,
            lane,
            encrypted_order_hint_root: request.encrypted_order_hint_root,
            redaction_budget_id: request.redaction_budget_id,
        };
        self.orders.insert(order_id, order.clone());
        self.counters.orders_opened = self.counters.orders_opened.saturating_add(1);
        self.refresh_roots();
        Ok(order)
    }

    pub fn submit_provider_bid(
        &mut self,
        request: SubmitProviderBidRequest,
    ) -> Result<ProviderBid> {
        self.config.validate()?;
        ensure_capacity(self.bids.len(), self.config.max_bids, "bids")?;
        ensure_non_empty(&request.order_id, "order_id")?;
        ensure_non_empty(&request.provider_commitment, "provider_commitment")?;
        ensure_non_empty(&request.sealed_bid_root, "sealed_bid_root")?;
        ensure_non_empty(&request.pq_capability_root, "pq_capability_root")?;
        ensure_non_empty(&request.storage_proof_root, "storage_proof_root")?;
        ensure_non_empty(&request.collateral_commitment, "collateral_commitment")?;
        ensure_bps(request.provider_fee_bps, "provider_fee_bps")?;
        let order = self
            .orders
            .get(&request.order_id)
            .ok_or_else(|| format!("unknown order {}", request.order_id))?;
        if !order.accepts_bid_at(request.submitted_height) {
            return Err("order is not accepting bids".to_string());
        }
        if request.provider_fee_bps > order.max_provider_fee_bps {
            return Err("provider fee exceeds order cap".to_string());
        }
        if request.privacy_set_size < order.privacy_set_size {
            return Err("bid privacy set below order requirement".to_string());
        }
        let bid_id = stable_id(
            "bid",
            &[
                HashPart::Str(&request.order_id),
                HashPart::Str(&request.provider_commitment),
                HashPart::Str(&request.sealed_bid_root),
                HashPart::U64(request.submitted_height),
            ],
        );
        if self.bids.contains_key(&bid_id) {
            return Err(format!("bid {bid_id} already exists"));
        }
        let status = if request.revealed_price_micro_units.is_some() {
            BidStatus::Revealed
        } else {
            BidStatus::Sealed
        };
        let latency_weight = self.config.low_fee_max_latency_ms.saturating_sub(
            request
                .max_latency_ms
                .min(self.config.low_fee_max_latency_ms),
        );
        let fee_weight = MAX_BPS.saturating_sub(request.provider_fee_bps);
        let award_weight = latency_weight.saturating_add(fee_weight);
        let bid = ProviderBid {
            bid_id: bid_id.clone(),
            order_id: request.order_id,
            provider_commitment: request.provider_commitment,
            status,
            sealed_bid_root: request.sealed_bid_root,
            revealed_price_micro_units: request.revealed_price_micro_units,
            provider_fee_bps: request.provider_fee_bps,
            expected_output_bytes: request.expected_output_bytes,
            max_latency_ms: request.max_latency_ms,
            pq_capability_root: request.pq_capability_root,
            storage_proof_root: request.storage_proof_root,
            collateral_commitment: request.collateral_commitment,
            submitted_height: request.submitted_height,
            expires_height: request
                .submitted_height
                .saturating_add(self.config.bid_ttl_blocks),
            award_weight,
            privacy_set_size: request.privacy_set_size,
        };
        self.bids.insert(bid_id, bid.clone());
        self.counters.bids_submitted = self.counters.bids_submitted.saturating_add(1);
        self.refresh_roots();
        Ok(bid)
    }

    pub fn award_best_bid(&mut self, order_id: &str, height: u64) -> Result<ProviderBid> {
        ensure_non_empty(order_id, "order_id")?;
        let order = self
            .orders
            .get(order_id)
            .ok_or_else(|| format!("unknown order {order_id}"))?
            .clone();
        if !matches!(order.status, OrderStatus::Bidding | OrderStatus::Open) {
            return Err("order cannot be awarded from current status".to_string());
        }
        let best_bid_id = self
            .bids
            .values()
            .filter(|bid| {
                bid.order_id == order_id && bid.status.live() && height <= bid.expires_height
            })
            .max_by_key(|bid| {
                let price_penalty = bid.revealed_price_micro_units.unwrap_or(u64::MAX / 4) / 1_000;
                bid.award_weight.saturating_sub(price_penalty)
            })
            .map(|bid| bid.bid_id.clone())
            .ok_or_else(|| "no live bids for order".to_string())?;
        let bid = self
            .bids
            .get_mut(&best_bid_id)
            .expect("best bid exists after selection");
        bid.status = BidStatus::Awarded;
        let awarded_bid = bid.clone();
        self.orders
            .get_mut(order_id)
            .expect("order exists after selection")
            .assign_bid(best_bid_id, height)?;
        self.counters.orders_awarded = self.counters.orders_awarded.saturating_add(1);
        self.counters.bids_awarded = self.counters.bids_awarded.saturating_add(1);
        self.refresh_roots();
        Ok(awarded_bid)
    }

    pub fn submit_attestation(
        &mut self,
        request: SubmitAttestationRequest,
    ) -> Result<PqCompactionAttestation> {
        self.config.validate()?;
        ensure_capacity(
            self.attestations.len(),
            self.config.max_attestations,
            "attestations",
        )?;
        ensure_non_empty(&request.order_id, "order_id")?;
        ensure_non_empty(&request.bid_id, "bid_id")?;
        ensure_non_empty(&request.provider_commitment, "provider_commitment")?;
        ensure_non_empty(&request.input_root, "input_root")?;
        ensure_non_empty(&request.output_root, "output_root")?;
        ensure_non_empty(&request.transcript_root, "transcript_root")?;
        ensure_non_empty(&request.pq_signature_root, "pq_signature_root")?;
        ensure_non_empty(&request.verifier_set_root, "verifier_set_root")?;
        ensure_bps(request.quorum_bps, "quorum_bps")?;
        let order = self
            .orders
            .get(&request.order_id)
            .ok_or_else(|| format!("unknown order {}", request.order_id))?;
        if order.awarded_bid_id.as_deref() != Some(request.bid_id.as_str()) {
            return Err("attestation bid is not awarded for order".to_string());
        }
        let bid = self
            .bids
            .get(&request.bid_id)
            .ok_or_else(|| format!("unknown bid {}", request.bid_id))?;
        if bid.provider_commitment != request.provider_commitment {
            return Err("attestation provider does not match awarded bid".to_string());
        }
        let attestation_id = stable_id(
            "attestation",
            &[
                HashPart::Str(&request.order_id),
                HashPart::Str(&request.bid_id),
                HashPart::Str(&request.output_root),
                HashPart::Str(&request.pq_signature_root),
                HashPart::U64(request.submitted_height),
            ],
        );
        if self.attestations.contains_key(&attestation_id) {
            return Err(format!("attestation {attestation_id} already exists"));
        }
        let status = if request.quorum_bps >= 6_667 {
            AttestationStatus::QuorumAccepted
        } else {
            AttestationStatus::Submitted
        };
        let attestation = PqCompactionAttestation {
            attestation_id: attestation_id.clone(),
            order_id: request.order_id.clone(),
            bid_id: request.bid_id,
            provider_commitment: request.provider_commitment,
            kind: request.kind,
            status,
            input_root: request.input_root,
            output_root: request.output_root.clone(),
            transcript_root: request.transcript_root,
            pq_signature_root: request.pq_signature_root,
            verifier_set_root: request.verifier_set_root,
            quorum_bps: request.quorum_bps,
            proof_size_bytes: request.proof_size_bytes,
            gas_used_micro_units: request.gas_used_micro_units,
            submitted_height: request.submitted_height,
            expires_height: request
                .submitted_height
                .saturating_add(self.config.attestation_ttl_blocks),
            redacted_fields: request.redacted_fields,
        };
        if attestation.accepted() {
            let order = self
                .orders
                .get_mut(&request.order_id)
                .expect("order validated");
            order.output_segment_root = Some(request.output_root.clone());
            order.attach_attestation(attestation_id.clone())?;
            for segment_id in order.segment_ids.clone() {
                if let Some(segment) = self.segments.get_mut(&segment_id) {
                    segment.mark_compacted(
                        request.output_root.clone(),
                        sample_hash("compacted-index", self.counters.segments_compacted + 1),
                        request.submitted_height,
                    )?;
                    self.counters.segments_compacted =
                        self.counters.segments_compacted.saturating_add(1);
                }
            }
            self.counters.attestations_accepted =
                self.counters.attestations_accepted.saturating_add(1);
        }
        self.attestations
            .insert(attestation_id, attestation.clone());
        self.counters.attestations_submitted =
            self.counters.attestations_submitted.saturating_add(1);
        self.refresh_roots();
        Ok(attestation)
    }

    pub fn issue_rebate_coupon(
        &mut self,
        request: IssueRebateCouponRequest,
    ) -> Result<RebateCoupon> {
        self.config.validate()?;
        ensure_capacity(self.rebates.len(), self.config.max_rebates, "rebates")?;
        ensure_non_empty(&request.order_id, "order_id")?;
        ensure_non_empty(&request.claimant_commitment, "claimant_commitment")?;
        ensure_non_empty(&request.nullifier_root, "nullifier_root")?;
        ensure_non_empty(&request.claim_root, "claim_root")?;
        ensure_bps(request.rebate_bps, "rebate_bps")?;
        if !self.orders.contains_key(&request.order_id) {
            return Err(format!("unknown order {}", request.order_id));
        }
        let coupon_id = stable_id(
            "rebate",
            &[
                HashPart::Str(&request.order_id),
                HashPart::Str(&request.claimant_commitment),
                HashPart::Str(&request.nullifier_root),
                HashPart::U64(request.issued_height),
            ],
        );
        if self.rebates.contains_key(&coupon_id) {
            return Err(format!("rebate coupon {coupon_id} already exists"));
        }
        let coupon = RebateCoupon {
            coupon_id: coupon_id.clone(),
            order_id: request.order_id.clone(),
            claimant_commitment: request.claimant_commitment,
            status: RebateStatus::Claimable,
            fee_asset_id: self.config.fee_asset_id.clone(),
            amount_micro_units: request.amount_micro_units,
            rebate_bps: request.rebate_bps,
            nullifier_root: request.nullifier_root,
            claim_root: request.claim_root,
            issued_height: request.issued_height,
            expires_height: request
                .issued_height
                .saturating_add(self.config.rebate_ttl_blocks),
            claimed_height: None,
        };
        if let Some(order) = self.orders.get_mut(&request.order_id) {
            order.rebate_coupon_id = Some(coupon_id.clone());
        }
        self.rebates.insert(coupon_id, coupon.clone());
        self.counters.rebates_issued = self.counters.rebates_issued.saturating_add(1);
        self.refresh_roots();
        Ok(coupon)
    }

    pub fn claim_rebate_coupon(&mut self, coupon_id: &str, height: u64) -> Result<RebateCoupon> {
        ensure_non_empty(coupon_id, "coupon_id")?;
        let coupon = self
            .rebates
            .get_mut(coupon_id)
            .ok_or_else(|| format!("unknown rebate coupon {coupon_id}"))?;
        coupon.claim(height)?;
        let claimed = coupon.clone();
        self.counters.rebates_claimed = self.counters.rebates_claimed.saturating_add(1);
        self.refresh_roots();
        Ok(claimed)
    }

    pub fn open_pruning_window(
        &mut self,
        request: OpenPruningWindowRequest,
    ) -> Result<PruningWindow> {
        self.config.validate()?;
        ensure_capacity(
            self.pruning_windows.len(),
            self.config.max_pruning_windows,
            "pruning_windows",
        )?;
        ensure_non_empty(&request.contract_id, "contract_id")?;
        ensure_non_empty(&request.eligible_segment_root, "eligible_segment_root")?;
        ensure_non_empty(&request.exclusion_root, "exclusion_root")?;
        ensure_non_empty(&request.opened_by_commitment, "opened_by_commitment")?;
        if request.end_height <= request.start_height {
            return Err("pruning window end_height must exceed start_height".to_string());
        }
        ensure_privacy(
            &self.config,
            request.privacy_tier,
            request.privacy_tier.minimum_set(),
        )?;
        let window_id = stable_id(
            "pruning-window",
            &[
                HashPart::Str(&request.contract_id),
                HashPart::Str(request.segment_class.as_str()),
                HashPart::Str(&request.eligible_segment_root),
                HashPart::U64(request.start_height),
                HashPart::U64(request.end_height),
            ],
        );
        if self.pruning_windows.contains_key(&window_id) {
            return Err(format!("pruning window {window_id} already exists"));
        }
        let window = PruningWindow {
            window_id: window_id.clone(),
            contract_id: request.contract_id,
            status: PruningWindowStatus::Scheduled,
            start_height: request.start_height,
            end_height: request.end_height,
            min_age_blocks: request.min_age_blocks,
            segment_class: request.segment_class,
            eligible_segment_root: request.eligible_segment_root,
            exclusion_root: request.exclusion_root,
            privacy_tier: request.privacy_tier,
            max_prunable_bytes: request.max_prunable_bytes,
            pruned_bytes: 0,
            opened_by_commitment: request.opened_by_commitment,
        };
        self.pruning_windows.insert(window_id, window.clone());
        self.counters.pruning_windows_opened =
            self.counters.pruning_windows_opened.saturating_add(1);
        self.refresh_roots();
        Ok(window)
    }

    pub fn arm_eviction_guard(
        &mut self,
        request: ArmEvictionGuardRequest,
    ) -> Result<EvictionGuard> {
        self.config.validate()?;
        ensure_capacity(
            self.eviction_guards.len(),
            self.config.max_eviction_guards,
            "eviction_guards",
        )?;
        ensure_non_empty(&request.segment_id, "segment_id")?;
        ensure_non_empty(&request.owner_commitment, "owner_commitment")?;
        ensure_non_empty(&request.reason_root, "reason_root")?;
        ensure_non_empty(&request.bond_commitment, "bond_commitment")?;
        let segment = self
            .segments
            .get(&request.segment_id)
            .ok_or_else(|| format!("unknown segment {}", request.segment_id))?;
        if segment.owner_commitment != request.owner_commitment {
            return Err("eviction guard owner does not match segment owner".to_string());
        }
        let guard_id = stable_id(
            "eviction-guard",
            &[
                HashPart::Str(&request.segment_id),
                HashPart::Str(&request.owner_commitment),
                HashPart::Str(&request.reason_root),
                HashPart::U64(request.armed_height),
            ],
        );
        if self.eviction_guards.contains_key(&guard_id) {
            return Err(format!("eviction guard {guard_id} already exists"));
        }
        let guard = EvictionGuard {
            guard_id: guard_id.clone(),
            segment_id: request.segment_id.clone(),
            owner_commitment: request.owner_commitment,
            status: EvictionGuardStatus::Armed,
            reason_root: request.reason_root,
            armed_height: request.armed_height,
            expires_height: request
                .armed_height
                .saturating_add(self.config.eviction_guard_ttl_blocks),
            bond_commitment: request.bond_commitment,
            release_root: None,
            prevented_order_ids: BTreeSet::new(),
        };
        self.segments
            .get_mut(&request.segment_id)
            .expect("segment validated")
            .arm_guard(guard_id.clone())?;
        self.eviction_guards.insert(guard_id, guard.clone());
        self.counters.eviction_guards_armed = self.counters.eviction_guards_armed.saturating_add(1);
        self.refresh_roots();
        Ok(guard)
    }

    pub fn release_eviction_guard(
        &mut self,
        guard_id: &str,
        release_root: String,
        height: u64,
    ) -> Result<EvictionGuard> {
        ensure_non_empty(guard_id, "guard_id")?;
        ensure_non_empty(&release_root, "release_root")?;
        let guard = self
            .eviction_guards
            .get_mut(guard_id)
            .ok_or_else(|| format!("unknown eviction guard {guard_id}"))?;
        if height > guard.expires_height {
            guard.status = EvictionGuardStatus::Expired;
        } else {
            guard.status = EvictionGuardStatus::Released;
            guard.release_root = Some(release_root);
        }
        if let Some(segment) = self.segments.get_mut(&guard.segment_id) {
            segment.release_guard(guard_id);
        }
        let released = guard.clone();
        self.refresh_roots();
        Ok(released)
    }

    pub fn create_redaction_budget(
        &mut self,
        request: CreateRedactionBudgetRequest,
    ) -> Result<RedactionBudget> {
        self.config.validate()?;
        ensure_capacity(
            self.redaction_budgets.len(),
            self.config.max_redaction_budgets,
            "redaction_budgets",
        )?;
        ensure_non_empty(&request.owner_commitment, "owner_commitment")?;
        ensure_non_empty(&request.contract_id, "contract_id")?;
        ensure_non_empty(&request.allowed_fields_root, "allowed_fields_root")?;
        ensure_privacy(
            &self.config,
            PrivacyTier::Standard,
            request.privacy_set_size,
        )?;
        if request.max_units > self.config.max_redaction_units {
            return Err("redaction budget exceeds runtime cap".to_string());
        }
        let budget_id = stable_id(
            "redaction-budget",
            &[
                HashPart::Str(&request.owner_commitment),
                HashPart::Str(&request.contract_id),
                HashPart::Str(&request.allowed_fields_root),
                HashPart::U64(request.opened_height),
            ],
        );
        if self.redaction_budgets.contains_key(&budget_id) {
            return Err(format!("redaction budget {budget_id} already exists"));
        }
        let budget = RedactionBudget {
            budget_id: budget_id.clone(),
            owner_commitment: request.owner_commitment,
            contract_id: request.contract_id,
            status: BudgetStatus::Active,
            max_units: request.max_units,
            remaining_units: request.max_units,
            spent_units: 0,
            replenish_per_block: request.replenish_per_block,
            last_replenished_height: request.opened_height,
            allowed_fields_root: request.allowed_fields_root,
            redacted_fields: request.redacted_fields,
            privacy_set_size: request.privacy_set_size,
        };
        self.redaction_budgets.insert(budget_id, budget.clone());
        self.refresh_roots();
        Ok(budget)
    }

    pub fn publish_operator_summary(
        &mut self,
        request: PublishOperatorSummaryRequest,
    ) -> Result<OperatorSummary> {
        self.config.validate()?;
        ensure_capacity(
            self.operator_summaries.len(),
            self.config.max_operator_summaries,
            "operator_summaries",
        )?;
        ensure_non_empty(&request.operator_commitment, "operator_commitment")?;
        ensure_non_empty(&request.summary_root, "summary_root")?;
        ensure_bps(request.median_fee_bps, "median_fee_bps")?;
        ensure_bps(request.rebate_bps_paid, "rebate_bps_paid")?;
        ensure_bps(request.attestation_quorum_bps, "attestation_quorum_bps")?;
        let summary_id = stable_id(
            "operator-summary",
            &[
                HashPart::Str(&request.operator_commitment),
                HashPart::Str(&request.summary_root),
                HashPart::U64(request.epoch),
                HashPart::U64(request.published_height),
            ],
        );
        if self.operator_summaries.contains_key(&summary_id) {
            return Err(format!("operator summary {summary_id} already exists"));
        }
        let summary = OperatorSummary {
            summary_id: summary_id.clone(),
            operator_commitment: request.operator_commitment,
            role: request.role,
            epoch: request.epoch,
            orders_processed: request.orders_processed,
            bytes_compacted: request.bytes_compacted,
            median_latency_ms: request.median_latency_ms,
            median_fee_bps: request.median_fee_bps,
            rebate_bps_paid: request.rebate_bps_paid,
            attestation_quorum_bps: request.attestation_quorum_bps,
            slashing_events: request.slashing_events,
            privacy_incidents: request.privacy_incidents,
            summary_root: request.summary_root,
            published_height: request.published_height,
        };
        self.operator_summaries.insert(summary_id, summary.clone());
        self.counters.operator_summaries_published =
            self.counters.operator_summaries_published.saturating_add(1);
        self.refresh_roots();
        Ok(summary)
    }

    pub fn settle_order(&mut self, order_id: &str, height: u64) -> Result<CompactionOrder> {
        ensure_non_empty(order_id, "order_id")?;
        let order = self
            .orders
            .get_mut(order_id)
            .ok_or_else(|| format!("unknown order {order_id}"))?;
        if order.output_segment_root.is_none() {
            return Err("cannot settle order without output segment root".to_string());
        }
        if order.attestation_ids.is_empty() {
            return Err("cannot settle order without attestation".to_string());
        }
        if height > order.execution_deadline_height {
            order.status = OrderStatus::Expired;
            return Err("order expired before settlement".to_string());
        }
        order.status = OrderStatus::Settled;
        let settled = order.clone();
        self.counters.orders_settled = self.counters.orders_settled.saturating_add(1);
        self.refresh_roots();
        Ok(settled)
    }

    fn public_record_without_roots_state_root(&self) -> Value {
        json!({
            "config_root": self.roots.config_root,
            "counters_root": self.roots.counters_root,
            "domain": "encrypted-storage-compaction-market",
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION
        })
    }
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn demo() -> State {
    let mut state = State::devnet();
    let budget = state
        .create_redaction_budget(CreateRedactionBudgetRequest {
            owner_commitment: sample_hash("owner", 1),
            contract_id: "confidential-dex-vault".to_string(),
            max_units: 64_000,
            replenish_per_block: DEFAULT_REDACTION_REPLENISH_PER_BLOCK,
            opened_height: DEVNET_HEIGHT,
            allowed_fields_root: sample_hash("allowed-fields", 1),
            redacted_fields: ["ciphertext", "opening", "plain_slot", "owner_view_key"]
                .into_iter()
                .map(str::to_string)
                .collect(),
            privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
        })
        .expect("demo redaction budget created");
    let segment_a = state
        .register_segment(RegisterSegmentRequest {
            contract_id: "confidential-dex-vault".to_string(),
            owner_commitment: sample_hash("owner", 1),
            class: SegmentClass::ContractState,
            encrypted_payload_root: sample_hash("payload", 1),
            ciphertext_commitment: sample_hash("ciphertext", 1),
            index_commitment: sample_hash("index", 1),
            nullifier_root: sample_hash("nullifier", 1),
            pq_envelope_root: sample_hash("pq-envelope", 1),
            size_bytes: 64_000_000,
            logical_records: 2_000_000,
            stale_records: 840_000,
            hotness_score: 72,
            privacy_tier: PrivacyTier::High,
            privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            created_height: DEVNET_HEIGHT,
            ttl_blocks: DEFAULT_PRUNING_WINDOW_TTL_BLOCKS,
            tags: ["vault", "amm", "hot-state"]
                .into_iter()
                .map(str::to_string)
                .collect(),
        })
        .expect("demo segment A registered");
    let segment_b = state
        .register_segment(RegisterSegmentRequest {
            contract_id: "confidential-dex-vault".to_string(),
            owner_commitment: sample_hash("owner", 1),
            class: SegmentClass::MerkleFrontier,
            encrypted_payload_root: sample_hash("payload", 2),
            ciphertext_commitment: sample_hash("ciphertext", 2),
            index_commitment: sample_hash("index", 2),
            nullifier_root: sample_hash("nullifier", 2),
            pq_envelope_root: sample_hash("pq-envelope", 2),
            size_bytes: 21_000_000,
            logical_records: 700_000,
            stale_records: 210_000,
            hotness_score: 58,
            privacy_tier: PrivacyTier::High,
            privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            created_height: DEVNET_HEIGHT + 1,
            ttl_blocks: DEFAULT_PRUNING_WINDOW_TTL_BLOCKS,
            tags: ["vault", "frontier"]
                .into_iter()
                .map(str::to_string)
                .collect(),
        })
        .expect("demo segment B registered");
    state
        .open_pruning_window(OpenPruningWindowRequest {
            contract_id: "confidential-dex-vault".to_string(),
            start_height: DEVNET_HEIGHT + 64,
            end_height: DEVNET_HEIGHT + DEFAULT_PRUNING_WINDOW_TTL_BLOCKS,
            min_age_blocks: 128,
            segment_class: SegmentClass::ContractState,
            eligible_segment_root: sample_hash("eligible-segments", 1),
            exclusion_root: sample_hash("pruning-exclusions", 1),
            privacy_tier: PrivacyTier::High,
            max_prunable_bytes: 32_000_000,
            opened_by_commitment: sample_hash("operator", 1),
        })
        .expect("demo pruning window opened");
    let order = state
        .open_compaction_order(OpenCompactionOrderRequest {
            creator_commitment: sample_hash("creator", 1),
            contract_id: "confidential-dex-vault".to_string(),
            kind: CompactionOrderKind::Deduplicate,
            segment_ids: vec![segment_a.segment_id.clone(), segment_b.segment_id.clone()],
            max_fee_micro_units: 12_000,
            max_provider_fee_bps: DEFAULT_MAX_PROVIDER_FEE_BPS,
            target_output_bytes: 48_000_000,
            min_stale_ratio_bps: 2_000,
            privacy_tier: PrivacyTier::High,
            privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            opened_height: DEVNET_HEIGHT + 8,
            encrypted_order_hint_root: sample_hash("order-hint", 1),
            redaction_budget_id: Some(budget.budget_id.clone()),
        })
        .expect("demo compaction order opened");
    let bid = state
        .submit_provider_bid(SubmitProviderBidRequest {
            order_id: order.order_id.clone(),
            provider_commitment: sample_hash("provider", 1),
            sealed_bid_root: sample_hash("sealed-bid", 1),
            revealed_price_micro_units: Some(9_200),
            provider_fee_bps: 4,
            expected_output_bytes: 45_500_000,
            max_latency_ms: 1_200,
            pq_capability_root: sample_hash("pq-capability", 1),
            storage_proof_root: sample_hash("storage-proof", 1),
            collateral_commitment: sample_hash("collateral", 1),
            submitted_height: DEVNET_HEIGHT + 10,
            privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
        })
        .expect("demo bid submitted");
    state
        .award_best_bid(&order.order_id, DEVNET_HEIGHT + 12)
        .expect("demo bid awarded");
    state
        .submit_attestation(SubmitAttestationRequest {
            order_id: order.order_id.clone(),
            bid_id: bid.bid_id.clone(),
            provider_commitment: bid.provider_commitment.clone(),
            kind: AttestationKind::ReencryptionCorrectness,
            input_root: order.input_segment_root.clone(),
            output_root: sample_hash("compacted-output", 1),
            transcript_root: sample_hash("transcript", 1),
            pq_signature_root: sample_hash("pq-signature", 1),
            verifier_set_root: sample_hash("verifier-set", 1),
            quorum_bps: 8_000,
            proof_size_bytes: 16_384,
            gas_used_micro_units: 7_400,
            submitted_height: DEVNET_HEIGHT + 20,
            redacted_fields: ["plaintext_slots", "view_tags"]
                .into_iter()
                .map(str::to_string)
                .collect(),
        })
        .expect("demo attestation submitted");
    state
        .issue_rebate_coupon(IssueRebateCouponRequest {
            order_id: order.order_id.clone(),
            claimant_commitment: sample_hash("creator", 1),
            amount_micro_units: 600,
            rebate_bps: DEFAULT_TARGET_REBATE_BPS,
            nullifier_root: sample_hash("rebate-nullifier", 1),
            claim_root: sample_hash("rebate-claim", 1),
            issued_height: DEVNET_HEIGHT + 21,
        })
        .expect("demo rebate issued");
    state
        .publish_operator_summary(PublishOperatorSummaryRequest {
            operator_commitment: sample_hash("provider", 1),
            role: OperatorRole::Compactor,
            epoch: DEVNET_EPOCH,
            orders_processed: 1,
            bytes_compacted: 85_000_000,
            median_latency_ms: 1_200,
            median_fee_bps: 4,
            rebate_bps_paid: DEFAULT_TARGET_REBATE_BPS,
            attestation_quorum_bps: 8_000,
            slashing_events: 0,
            privacy_incidents: 0,
            summary_root: sample_hash("operator-summary", 1),
            published_height: DEVNET_HEIGHT + 24,
        })
        .expect("demo operator summary published");
    state
        .settle_order(&order.order_id, DEVNET_HEIGHT + 25)
        .expect("demo order settled");
    state.refresh_roots();
    state
}

pub fn public_record(state: &State) -> Value {
    state.public_record()
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}

fn stable_id(domain: &str, parts: &[HashPart<'_>]) -> String {
    domain_hash(
        &format!("encrypted-storage-compaction-market:{domain}:id"),
        parts,
        24,
    )
}

fn record_root(domain: &str, value: &Value) -> String {
    domain_hash(
        &format!("encrypted-storage-compaction-market:{domain}:record"),
        &[HashPart::Json(value)],
        32,
    )
}

fn map_root<T: Serialize>(domain: &str, records: &BTreeMap<String, T>) -> String {
    let leaves = records
        .iter()
        .map(|(key, value)| json!({ "key": key, "value": value }))
        .collect::<Vec<_>>();
    merkle_root(
        &format!("encrypted-storage-compaction-market:{domain}:map"),
        &leaves,
    )
}

fn sample_hash(label: &str, index: u64) -> String {
    domain_hash(
        "encrypted-storage-compaction-market:devnet-sample",
        &[HashPart::Str(label), HashPart::U64(index)],
        32,
    )
}

fn ensure_non_empty(value: &str, name: &str) -> Result<()> {
    if value.trim().is_empty() {
        return Err(format!("{name} must not be empty"));
    }
    Ok(())
}

fn ensure_bps(value: u64, name: &str) -> Result<()> {
    if value > MAX_BPS {
        return Err(format!("{name} must be <= {MAX_BPS}"));
    }
    Ok(())
}

fn ensure_capacity(current: usize, max: usize, name: &str) -> Result<()> {
    if current >= max {
        return Err(format!("{name} capacity exceeded"));
    }
    Ok(())
}

fn ensure_privacy(config: &Config, tier: PrivacyTier, privacy_set_size: u64) -> Result<()> {
    if !config.allowed_privacy_tiers.contains(&tier) {
        return Err(format!("privacy tier {:?} is not allowed", tier));
    }
    let floor = config.min_privacy_set_size.max(tier.minimum_set());
    if privacy_set_size < floor {
        return Err(format!(
            "privacy_set_size {privacy_set_size} below required floor {floor}"
        ));
    }
    Ok(())
}
