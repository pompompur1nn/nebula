use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = PrivateL2FastPqConfidentialBatchStateRootPrefetchRuntimeResult<T>;
pub type PrivateL2FastPqConfidentialBatchStateRootPrefetchRuntimeResult<T> =
    std::result::Result<T, String>;
pub type Runtime = State;

pub const PRIVATE_L2_FAST_PQ_CONFIDENTIAL_BATCH_STATE_ROOT_PREFETCH_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-fast-pq-confidential-batch-state-root-prefetch-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_FAST_PQ_CONFIDENTIAL_BATCH_STATE_ROOT_PREFETCH_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_PREFETCH_ATTESTATION_SUITE: &str =
    "ML-DSA-87+SLH-DSA-SHAKE-256f-confidential-batch-state-root-prefetch-v1";
pub const WITNESS_CACHE_LEASE_SUITE: &str = "pq-confidential-state-root-witness-cache-lease-v1";
pub const INVALIDATION_FENCE_SUITE: &str =
    "monero-l2-confidential-state-root-prefetch-invalidation-fence-v1";
pub const SCHEDULER_CREDIT_SUITE: &str = "fast-private-state-root-prefetch-scheduler-credit-v1";
pub const LOW_FEE_REBATE_SUITE: &str = "low-fee-confidential-batch-state-root-prefetch-rebate-v1";
pub const REDACTION_BUDGET_SUITE: &str = "confidential-state-root-prefetch-redaction-budget-v1";
pub const DEVNET_L2_NETWORK: &str = "nebula-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEVNET_L2_HEIGHT: u64 = 2_760_000;
pub const DEVNET_MONERO_HEIGHT: u64 = 3_520_000;
pub const DEVNET_EPOCH: u64 = 12_288;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 262_144;
pub const DEFAULT_TARGET_PREFETCH_MS: u64 = 80;
pub const DEFAULT_MAX_PREFETCH_MS: u64 = 280;
pub const DEFAULT_PAGE_TTL_BLOCKS: u64 = 10;
pub const DEFAULT_BATCH_TTL_BLOCKS: u64 = 14;
pub const DEFAULT_LEASE_TTL_BLOCKS: u64 = 8;
pub const DEFAULT_ATTESTATION_TTL_BLOCKS: u64 = 18;
pub const DEFAULT_FENCE_TTL_BLOCKS: u64 = 512;
pub const DEFAULT_CREDIT_EPOCH_BLOCKS: u64 = 32;
pub const DEFAULT_REBATE_TTL_BLOCKS: u64 = 96;
pub const DEFAULT_REDACTION_EPOCH_BLOCKS: u64 = 64;
pub const DEFAULT_CHALLENGE_WINDOW_BLOCKS: u64 = 64;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 12;
pub const DEFAULT_TARGET_REBATE_BPS: u64 = 7;
pub const DEFAULT_MAX_REBATE_BPS: u64 = 22;
pub const DEFAULT_QUORUM_WEIGHT_BPS: u64 = 6_700;
pub const DEFAULT_SUPERMAJORITY_WEIGHT_BPS: u64 = 8_000;
pub const DEFAULT_MAX_BATCHES: usize = 2_097_152;
pub const DEFAULT_MAX_STATE_ROOT_PAGES: usize = 8_388_608;
pub const DEFAULT_MAX_WITNESS_CACHE_LEASES: usize = 4_194_304;
pub const DEFAULT_MAX_PQ_ATTESTATIONS: usize = 4_194_304;
pub const DEFAULT_MAX_INVALIDATION_FENCES: usize = 1_048_576;
pub const DEFAULT_MAX_SCHEDULER_CREDITS: usize = 1_048_576;
pub const DEFAULT_MAX_LOW_FEE_REBATES: usize = 2_097_152;
pub const DEFAULT_MAX_REDACTION_BUDGETS: usize = 1_048_576;
pub const DEFAULT_MAX_OPERATOR_SUMMARIES: usize = 262_144;

macro_rules! status_enum {
    ($name:ident { $($variant:ident => $text:literal),+ $(,)? }) => {
        #[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(rename_all = "snake_case")]
        pub enum $name {
            $($variant),+
        }

        impl $name {
            pub fn as_str(self) -> &'static str {
                match self {
                    $(Self::$variant => $text),+
                }
            }
        }
    };
}

status_enum!(PrefetchBatchStatus {
    Queued => "queued",
    Reserving => "reserving",
    Prefetching => "prefetching",
    Warmed => "warmed",
    RootBound => "root_bound",
    Settled => "settled",
    Invalidated => "invalidated",
    Expired => "expired",
});
status_enum!(StateRootPageStatus {
    Announced => "announced",
    Fetching => "fetching",
    Warmed => "warmed",
    Bound => "bound",
    Evicted => "evicted",
    Invalidated => "invalidated",
    Expired => "expired",
});
status_enum!(WitnessCacheLeaseStatus {
    Offered => "offered",
    Reserved => "reserved",
    Active => "active",
    Released => "released",
    Slashed => "slashed",
    Expired => "expired",
});
status_enum!(PqPrefetchAttestationStatus {
    Draft => "draft",
    Published => "published",
    QuorumAccepted => "quorum_accepted",
    Finalized => "finalized",
    Challenged => "challenged",
    Rejected => "rejected",
    Expired => "expired",
});
status_enum!(InvalidationFenceStatus {
    Active => "active",
    Matched => "matched",
    Consumed => "consumed",
    Frozen => "frozen",
    Released => "released",
    Expired => "expired",
});
status_enum!(SchedulerCreditStatus {
    Granted => "granted",
    Reserved => "reserved",
    Spent => "spent",
    Rebalanced => "rebalanced",
    Slashed => "slashed",
    Expired => "expired",
});
status_enum!(LowFeeRebateStatus {
    Reserved => "reserved",
    Applied => "applied",
    Settled => "settled",
    Reclaimed => "reclaimed",
    Challenged => "challenged",
    Expired => "expired",
});
status_enum!(RedactionBudgetStatus {
    Open => "open",
    Debited => "debited",
    Exhausted => "exhausted",
    Frozen => "frozen",
    Closed => "closed",
    Expired => "expired",
});
status_enum!(OperatorHealth {
    Green => "green",
    Amber => "amber",
    Red => "red",
    Quarantined => "quarantined",
});

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeMode {
    Devnet,
    Canary,
    MainnetCandidate,
}

impl RuntimeMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Devnet => "devnet",
            Self::Canary => "canary",
            Self::MainnetCandidate => "mainnet_candidate",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PrefetchClass {
    BatchHeader,
    StateRootPage,
    ContractWitness,
    BridgeExit,
    DefiSettlement,
    LowFeeBulk,
    EmergencyEscape,
}

impl PrefetchClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BatchHeader => "batch_header",
            Self::StateRootPage => "state_root_page",
            Self::ContractWitness => "contract_witness",
            Self::BridgeExit => "bridge_exit",
            Self::DefiSettlement => "defi_settlement",
            Self::LowFeeBulk => "low_fee_bulk",
            Self::EmergencyEscape => "emergency_escape",
        }
    }

    pub fn priority_weight(self) -> u64 {
        match self {
            Self::EmergencyEscape => 1_000,
            Self::BridgeExit => 940,
            Self::DefiSettlement => 910,
            Self::ContractWitness => 880,
            Self::StateRootPage => 820,
            Self::BatchHeader => 760,
            Self::LowFeeBulk => 520,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub protocol_version: String,
    pub schema_version: u64,
    pub l2_network: String,
    pub monero_network: String,
    pub chain_id: String,
    pub fee_asset_id: String,
    pub hash_suite: String,
    pub pq_attestation_suite: String,
    pub witness_cache_lease_suite: String,
    pub invalidation_fence_suite: String,
    pub scheduler_credit_suite: String,
    pub low_fee_rebate_suite: String,
    pub redaction_budget_suite: String,
    pub mode: RuntimeMode,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub target_prefetch_ms: u64,
    pub max_prefetch_ms: u64,
    pub page_ttl_blocks: u64,
    pub batch_ttl_blocks: u64,
    pub lease_ttl_blocks: u64,
    pub attestation_ttl_blocks: u64,
    pub fence_ttl_blocks: u64,
    pub credit_epoch_blocks: u64,
    pub rebate_ttl_blocks: u64,
    pub redaction_epoch_blocks: u64,
    pub challenge_window_blocks: u64,
    pub max_user_fee_bps: u64,
    pub target_rebate_bps: u64,
    pub max_rebate_bps: u64,
    pub quorum_weight_bps: u64,
    pub supermajority_weight_bps: u64,
    pub max_batches: usize,
    pub max_state_root_pages: usize,
    pub max_witness_cache_leases: usize,
    pub max_pq_attestations: usize,
    pub max_invalidation_fences: usize,
    pub max_scheduler_credits: usize,
    pub max_low_fee_rebates: usize,
    pub max_redaction_budgets: usize,
    pub max_operator_summaries: usize,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            l2_network: DEVNET_L2_NETWORK.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            chain_id: CHAIN_ID.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            hash_suite: HASH_SUITE.to_string(),
            pq_attestation_suite: PQ_PREFETCH_ATTESTATION_SUITE.to_string(),
            witness_cache_lease_suite: WITNESS_CACHE_LEASE_SUITE.to_string(),
            invalidation_fence_suite: INVALIDATION_FENCE_SUITE.to_string(),
            scheduler_credit_suite: SCHEDULER_CREDIT_SUITE.to_string(),
            low_fee_rebate_suite: LOW_FEE_REBATE_SUITE.to_string(),
            redaction_budget_suite: REDACTION_BUDGET_SUITE.to_string(),
            mode: RuntimeMode::Devnet,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_prefetch_ms: DEFAULT_TARGET_PREFETCH_MS,
            max_prefetch_ms: DEFAULT_MAX_PREFETCH_MS,
            page_ttl_blocks: DEFAULT_PAGE_TTL_BLOCKS,
            batch_ttl_blocks: DEFAULT_BATCH_TTL_BLOCKS,
            lease_ttl_blocks: DEFAULT_LEASE_TTL_BLOCKS,
            attestation_ttl_blocks: DEFAULT_ATTESTATION_TTL_BLOCKS,
            fence_ttl_blocks: DEFAULT_FENCE_TTL_BLOCKS,
            credit_epoch_blocks: DEFAULT_CREDIT_EPOCH_BLOCKS,
            rebate_ttl_blocks: DEFAULT_REBATE_TTL_BLOCKS,
            redaction_epoch_blocks: DEFAULT_REDACTION_EPOCH_BLOCKS,
            challenge_window_blocks: DEFAULT_CHALLENGE_WINDOW_BLOCKS,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            target_rebate_bps: DEFAULT_TARGET_REBATE_BPS,
            max_rebate_bps: DEFAULT_MAX_REBATE_BPS,
            quorum_weight_bps: DEFAULT_QUORUM_WEIGHT_BPS,
            supermajority_weight_bps: DEFAULT_SUPERMAJORITY_WEIGHT_BPS,
            max_batches: DEFAULT_MAX_BATCHES,
            max_state_root_pages: DEFAULT_MAX_STATE_ROOT_PAGES,
            max_witness_cache_leases: DEFAULT_MAX_WITNESS_CACHE_LEASES,
            max_pq_attestations: DEFAULT_MAX_PQ_ATTESTATIONS,
            max_invalidation_fences: DEFAULT_MAX_INVALIDATION_FENCES,
            max_scheduler_credits: DEFAULT_MAX_SCHEDULER_CREDITS,
            max_low_fee_rebates: DEFAULT_MAX_LOW_FEE_REBATES,
            max_redaction_budgets: DEFAULT_MAX_REDACTION_BUDGETS,
            max_operator_summaries: DEFAULT_MAX_OPERATOR_SUMMARIES,
        }
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn state_root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub batches_prefetched: u64,
    pub batches_warmed: u64,
    pub batches_invalidated: u64,
    pub state_root_pages_warmed: u64,
    pub state_root_pages_evicted: u64,
    pub witness_cache_leases_active: u64,
    pub witness_cache_leases_released: u64,
    pub pq_attestations_published: u64,
    pub pq_attestations_finalized: u64,
    pub invalidation_fences_active: u64,
    pub scheduler_credits_granted: u64,
    pub scheduler_credits_spent: u64,
    pub low_fee_rebates_applied: u64,
    pub redaction_budget_debits: u64,
    pub operator_summaries_emitted: u64,
    pub challenge_events: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn state_root(&self) -> String {
        record_root("counters", &self.public_record())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub counters_root: String,
    pub prefetch_batch_root: String,
    pub state_root_page_root: String,
    pub witness_cache_lease_root: String,
    pub pq_prefetch_attestation_root: String,
    pub invalidation_fence_root: String,
    pub scheduler_credit_root: String,
    pub low_fee_rebate_root: String,
    pub redaction_budget_root: String,
    pub operator_summary_root: String,
    pub active_operator_root: String,
    pub live_batch_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record_without_state_root(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "counters_root": self.counters_root,
            "prefetch_batch_root": self.prefetch_batch_root,
            "state_root_page_root": self.state_root_page_root,
            "witness_cache_lease_root": self.witness_cache_lease_root,
            "pq_prefetch_attestation_root": self.pq_prefetch_attestation_root,
            "invalidation_fence_root": self.invalidation_fence_root,
            "scheduler_credit_root": self.scheduler_credit_root,
            "low_fee_rebate_root": self.low_fee_rebate_root,
            "redaction_budget_root": self.redaction_budget_root,
            "operator_summary_root": self.operator_summary_root,
            "active_operator_root": self.active_operator_root,
            "live_batch_root": self.live_batch_root,
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        record["state_root"] = json!(self.state_root);
        record
    }

    pub fn state_root(&self) -> String {
        record_root("roots", &self.public_record_without_state_root())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrefetchBatch {
    pub batch_id: String,
    pub class: PrefetchClass,
    pub status: PrefetchBatchStatus,
    pub encrypted_batch_root: String,
    pub state_root_before: String,
    pub predicted_state_root_after: String,
    pub page_set_root: String,
    pub witness_lease_root: String,
    pub attestation_root: String,
    pub invalidation_fence_root: String,
    pub redaction_budget_id: String,
    pub scheduler_credit_id: String,
    pub operator_id: String,
    pub fee_asset_id: String,
    pub user_fee_bps: u64,
    pub expected_rebate_bps: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub created_at_height: u64,
    pub expires_at_height: u64,
    pub warmed_at_height: Option<u64>,
    pub sequence: u64,
}

impl PrefetchBatch {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn state_root(&self) -> String {
        record_root("prefetch_batch", &self.public_record())
    }

    pub fn live(&self) -> bool {
        matches!(
            self.status,
            PrefetchBatchStatus::Queued
                | PrefetchBatchStatus::Reserving
                | PrefetchBatchStatus::Prefetching
                | PrefetchBatchStatus::Warmed
                | PrefetchBatchStatus::RootBound
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct StateRootPage {
    pub page_id: String,
    pub batch_id: String,
    pub status: StateRootPageStatus,
    pub page_index: u64,
    pub page_root: String,
    pub encrypted_delta_root: String,
    pub sibling_path_root: String,
    pub read_set_root: String,
    pub write_set_root: String,
    pub view_tag_root: String,
    pub lease_id: String,
    pub operator_id: String,
    pub byte_len: u64,
    pub privacy_set_size: u64,
    pub created_at_height: u64,
    pub expires_at_height: u64,
}

impl StateRootPage {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn state_root(&self) -> String {
        record_root("state_root_page", &self.public_record())
    }

    pub fn cacheable(&self) -> bool {
        matches!(
            self.status,
            StateRootPageStatus::Announced
                | StateRootPageStatus::Fetching
                | StateRootPageStatus::Warmed
                | StateRootPageStatus::Bound
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WitnessCacheLease {
    pub lease_id: String,
    pub operator_id: String,
    pub batch_id: String,
    pub page_root: String,
    pub status: WitnessCacheLeaseStatus,
    pub capacity_bytes: u64,
    pub reserved_bytes: u64,
    pub warmed_bytes: u64,
    pub lease_price_micro_units: u64,
    pub bond_micro_units: u64,
    pub pq_lease_commitment: String,
    pub created_at_height: u64,
    pub expires_at_height: u64,
}

impl WitnessCacheLease {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn state_root(&self) -> String {
        record_root("witness_cache_lease", &self.public_record())
    }

    pub fn utilization_bps(&self) -> u64 {
        if self.capacity_bytes == 0 {
            return 0;
        }
        self.reserved_bytes.saturating_mul(10_000) / self.capacity_bytes
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqPrefetchAttestation {
    pub attestation_id: String,
    pub batch_id: String,
    pub operator_id: String,
    pub status: PqPrefetchAttestationStatus,
    pub attested_state_root_before: String,
    pub attested_state_root_after: String,
    pub attested_page_root: String,
    pub lease_root: String,
    pub fence_root: String,
    pub pq_public_key_root: String,
    pub pq_signature_root: String,
    pub quorum_weight_bps: u64,
    pub latency_ms: u64,
    pub created_at_height: u64,
    pub expires_at_height: u64,
}

impl PqPrefetchAttestation {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn state_root(&self) -> String {
        record_root("pq_prefetch_attestation", &self.public_record())
    }

    pub fn accepted(&self) -> bool {
        matches!(
            self.status,
            PqPrefetchAttestationStatus::QuorumAccepted | PqPrefetchAttestationStatus::Finalized
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct InvalidationFence {
    pub fence_id: String,
    pub batch_id: String,
    pub operator_id: String,
    pub status: InvalidationFenceStatus,
    pub nullifier_root: String,
    pub view_tag_root: String,
    pub conflicting_state_root: String,
    pub reason_code: String,
    pub redaction_budget_id: String,
    pub created_at_height: u64,
    pub expires_at_height: u64,
}

impl InvalidationFence {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn state_root(&self) -> String {
        record_root("invalidation_fence", &self.public_record())
    }

    pub fn live(&self) -> bool {
        matches!(
            self.status,
            InvalidationFenceStatus::Active
                | InvalidationFenceStatus::Matched
                | InvalidationFenceStatus::Frozen
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SchedulerCredit {
    pub credit_id: String,
    pub operator_id: String,
    pub batch_id: String,
    pub status: SchedulerCreditStatus,
    pub epoch: u64,
    pub credits_granted: u64,
    pub credits_reserved: u64,
    pub credits_spent: u64,
    pub priority_weight: u64,
    pub fairness_debt: i64,
    pub created_at_height: u64,
    pub expires_at_height: u64,
}

impl SchedulerCredit {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn state_root(&self) -> String {
        record_root("scheduler_credit", &self.public_record())
    }

    pub fn available(&self) -> u64 {
        self.credits_granted
            .saturating_sub(self.credits_reserved)
            .saturating_sub(self.credits_spent)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LowFeeRebate {
    pub rebate_id: String,
    pub batch_id: String,
    pub operator_id: String,
    pub status: LowFeeRebateStatus,
    pub fee_asset_id: String,
    pub gross_fee_micro_units: u64,
    pub rebate_bps: u64,
    pub rebate_micro_units: u64,
    pub sponsor_root: String,
    pub settlement_root: String,
    pub created_at_height: u64,
    pub expires_at_height: u64,
}

impl LowFeeRebate {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn state_root(&self) -> String {
        record_root("low_fee_rebate", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RedactionBudget {
    pub budget_id: String,
    pub operator_id: String,
    pub batch_id: String,
    pub status: RedactionBudgetStatus,
    pub epoch: u64,
    pub max_redactions: u64,
    pub used_redactions: u64,
    pub max_disclosure_bytes: u64,
    pub disclosed_bytes: u64,
    pub redaction_policy_root: String,
    pub auditor_view_root: String,
    pub created_at_height: u64,
    pub expires_at_height: u64,
}

impl RedactionBudget {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn state_root(&self) -> String {
        record_root("redaction_budget", &self.public_record())
    }

    pub fn remaining_redactions(&self) -> u64 {
        self.max_redactions.saturating_sub(self.used_redactions)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OperatorSummary {
    pub operator_id: String,
    pub health: OperatorHealth,
    pub active_batches: u64,
    pub warmed_batches: u64,
    pub active_leases: u64,
    pub finalized_attestations: u64,
    pub active_fences: u64,
    pub credits_available: u64,
    pub rebates_applied_micro_units: u64,
    pub redactions_remaining: u64,
    pub avg_prefetch_latency_ms: u64,
    pub last_state_root: String,
    pub updated_at_height: u64,
}

impl OperatorSummary {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn state_root(&self) -> String {
        record_root("operator_summary", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub l2_height: u64,
    pub monero_height: u64,
    pub epoch: u64,
    pub prefetch_batches: BTreeMap<String, PrefetchBatch>,
    pub state_root_pages: BTreeMap<String, StateRootPage>,
    pub witness_cache_leases: BTreeMap<String, WitnessCacheLease>,
    pub pq_prefetch_attestations: BTreeMap<String, PqPrefetchAttestation>,
    pub invalidation_fences: BTreeMap<String, InvalidationFence>,
    pub scheduler_credits: BTreeMap<String, SchedulerCredit>,
    pub low_fee_rebates: BTreeMap<String, LowFeeRebate>,
    pub redaction_budgets: BTreeMap<String, RedactionBudget>,
    pub operator_summaries: BTreeMap<String, OperatorSummary>,
    pub active_operators: BTreeSet<String>,
    pub live_batches: BTreeSet<String>,
}

impl State {
    pub fn devnet() -> Self {
        let mut state = Self {
            config: Config::devnet(),
            counters: Counters::default(),
            roots: Roots::default(),
            l2_height: DEVNET_L2_HEIGHT,
            monero_height: DEVNET_MONERO_HEIGHT,
            epoch: DEVNET_EPOCH,
            prefetch_batches: BTreeMap::new(),
            state_root_pages: BTreeMap::new(),
            witness_cache_leases: BTreeMap::new(),
            pq_prefetch_attestations: BTreeMap::new(),
            invalidation_fences: BTreeMap::new(),
            scheduler_credits: BTreeMap::new(),
            low_fee_rebates: BTreeMap::new(),
            redaction_budgets: BTreeMap::new(),
            operator_summaries: BTreeMap::new(),
            active_operators: BTreeSet::new(),
            live_batches: BTreeSet::new(),
        };
        state.seed_devnet();
        state.refresh();
        state
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        record["state_root"] = json!(self.state_root());
        record
    }

    pub fn state_root(&self) -> String {
        state_root_from_record(&self.public_record_without_state_root())
    }

    pub fn queue_prefetch_batch(
        &mut self,
        batch_id: impl Into<String>,
        operator_id: impl Into<String>,
        class: PrefetchClass,
        encrypted_batch_root: impl Into<String>,
        state_root_before: impl Into<String>,
        predicted_state_root_after: impl Into<String>,
    ) -> Result<String> {
        if self.prefetch_batches.len() >= self.config.max_batches {
            return Err("prefetch batch capacity exhausted".to_string());
        }
        let batch_id = batch_id.into();
        if self.prefetch_batches.contains_key(&batch_id) {
            return Err(format!("prefetch batch already exists: {batch_id}"));
        }
        let operator_id = operator_id.into();
        self.active_operators.insert(operator_id.clone());
        let page_set_root = tagged_root("page-set", &batch_id);
        let lease_id = format!("{batch_id}-lease-0");
        let credit_id = format!("{batch_id}-credit");
        let budget_id = format!("{batch_id}-redaction");
        let batch = PrefetchBatch {
            batch_id: batch_id.clone(),
            class,
            status: PrefetchBatchStatus::Queued,
            encrypted_batch_root: encrypted_batch_root.into(),
            state_root_before: state_root_before.into(),
            predicted_state_root_after: predicted_state_root_after.into(),
            page_set_root,
            witness_lease_root: tagged_root("lease-set", &batch_id),
            attestation_root: tagged_root("attestation-set", &batch_id),
            invalidation_fence_root: tagged_root("fence-set", &batch_id),
            redaction_budget_id: budget_id,
            scheduler_credit_id: credit_id,
            operator_id,
            fee_asset_id: self.config.fee_asset_id.clone(),
            user_fee_bps: self.config.max_user_fee_bps,
            expected_rebate_bps: self.config.target_rebate_bps,
            privacy_set_size: self.config.min_privacy_set_size,
            pq_security_bits: self.config.min_pq_security_bits,
            created_at_height: self.l2_height,
            expires_at_height: self.l2_height + self.config.batch_ttl_blocks,
            warmed_at_height: None,
            sequence: self.prefetch_batches.len() as u64,
        };
        self.prefetch_batches.insert(batch_id.clone(), batch);
        self.live_batches.insert(batch_id.clone());
        self.counters.batches_prefetched += 1;
        self.reserve_witness_cache_lease(
            lease_id,
            batch_id.clone(),
            self.config.min_privacy_set_size / 4,
        )?;
        self.grant_scheduler_credit(
            format!("{batch_id}-credit"),
            batch_id.clone(),
            class.priority_weight(),
            128,
        )?;
        self.open_redaction_budget(
            format!("{batch_id}-redaction"),
            batch_id.clone(),
            16,
            64_000,
        )?;
        self.refresh();
        Ok(batch_id)
    }

    pub fn announce_state_root_page(
        &mut self,
        page_id: impl Into<String>,
        batch_id: impl Into<String>,
        page_index: u64,
        page_root: impl Into<String>,
        encrypted_delta_root: impl Into<String>,
    ) -> Result<String> {
        if self.state_root_pages.len() >= self.config.max_state_root_pages {
            return Err("state root page capacity exhausted".to_string());
        }
        let page_id = page_id.into();
        if self.state_root_pages.contains_key(&page_id) {
            return Err(format!("state root page already exists: {page_id}"));
        }
        let batch_id = batch_id.into();
        let batch = self
            .prefetch_batches
            .get(&batch_id)
            .ok_or_else(|| format!("unknown prefetch batch: {batch_id}"))?
            .clone();
        let page = StateRootPage {
            page_id: page_id.clone(),
            batch_id: batch_id.clone(),
            status: StateRootPageStatus::Announced,
            page_index,
            page_root: page_root.into(),
            encrypted_delta_root: encrypted_delta_root.into(),
            sibling_path_root: tagged_root("sibling-path", &page_id),
            read_set_root: tagged_root("read-set", &page_id),
            write_set_root: tagged_root("write-set", &page_id),
            view_tag_root: tagged_root("view-tag", &page_id),
            lease_id: format!("{batch_id}-lease-0"),
            operator_id: batch.operator_id,
            byte_len: 32_768,
            privacy_set_size: self.config.min_privacy_set_size,
            created_at_height: self.l2_height,
            expires_at_height: self.l2_height + self.config.page_ttl_blocks,
        };
        self.state_root_pages.insert(page_id.clone(), page);
        self.refresh_batch_page_root(&batch_id);
        self.refresh();
        Ok(page_id)
    }

    pub fn warm_state_root_page(&mut self, page_id: &str, latency_ms: u64) -> Result<()> {
        let page = self
            .state_root_pages
            .get_mut(page_id)
            .ok_or_else(|| format!("unknown state root page: {page_id}"))?;
        if latency_ms > self.config.max_prefetch_ms {
            page.status = StateRootPageStatus::Fetching;
        } else {
            page.status = StateRootPageStatus::Warmed;
            self.counters.state_root_pages_warmed += 1;
        }
        let batch_id = page.batch_id.clone();
        self.refresh_batch_page_root(&batch_id);
        self.refresh();
        Ok(())
    }

    pub fn reserve_witness_cache_lease(
        &mut self,
        lease_id: impl Into<String>,
        batch_id: impl Into<String>,
        capacity_bytes: u64,
    ) -> Result<String> {
        if self.witness_cache_leases.len() >= self.config.max_witness_cache_leases {
            return Err("witness cache lease capacity exhausted".to_string());
        }
        let lease_id = lease_id.into();
        if self.witness_cache_leases.contains_key(&lease_id) {
            return Ok(lease_id);
        }
        let batch_id = batch_id.into();
        let batch = self
            .prefetch_batches
            .get(&batch_id)
            .ok_or_else(|| format!("unknown prefetch batch: {batch_id}"))?
            .clone();
        let lease = WitnessCacheLease {
            lease_id: lease_id.clone(),
            operator_id: batch.operator_id,
            batch_id: batch_id.clone(),
            page_root: batch.page_set_root,
            status: WitnessCacheLeaseStatus::Reserved,
            capacity_bytes,
            reserved_bytes: capacity_bytes / 2,
            warmed_bytes: 0,
            lease_price_micro_units: capacity_bytes / 512,
            bond_micro_units: capacity_bytes / 64,
            pq_lease_commitment: tagged_root("pq-lease", &lease_id),
            created_at_height: self.l2_height,
            expires_at_height: self.l2_height + self.config.lease_ttl_blocks,
        };
        self.witness_cache_leases.insert(lease_id.clone(), lease);
        self.counters.witness_cache_leases_active += 1;
        self.refresh_batch_lease_root(&batch_id);
        self.refresh();
        Ok(lease_id)
    }

    pub fn activate_witness_cache_lease(
        &mut self,
        lease_id: &str,
        warmed_bytes: u64,
    ) -> Result<()> {
        let lease = self
            .witness_cache_leases
            .get_mut(lease_id)
            .ok_or_else(|| format!("unknown witness cache lease: {lease_id}"))?;
        lease.status = WitnessCacheLeaseStatus::Active;
        lease.warmed_bytes = warmed_bytes.min(lease.capacity_bytes);
        let batch_id = lease.batch_id.clone();
        self.refresh_batch_lease_root(&batch_id);
        self.refresh();
        Ok(())
    }

    pub fn publish_pq_prefetch_attestation(
        &mut self,
        attestation_id: impl Into<String>,
        batch_id: impl Into<String>,
        quorum_weight_bps: u64,
        latency_ms: u64,
    ) -> Result<String> {
        if self.pq_prefetch_attestations.len() >= self.config.max_pq_attestations {
            return Err("pq prefetch attestation capacity exhausted".to_string());
        }
        let attestation_id = attestation_id.into();
        if self.pq_prefetch_attestations.contains_key(&attestation_id) {
            return Err(format!(
                "pq prefetch attestation already exists: {attestation_id}"
            ));
        }
        let batch_id = batch_id.into();
        let batch = self
            .prefetch_batches
            .get(&batch_id)
            .ok_or_else(|| format!("unknown prefetch batch: {batch_id}"))?
            .clone();
        let status = if quorum_weight_bps >= self.config.quorum_weight_bps {
            PqPrefetchAttestationStatus::QuorumAccepted
        } else {
            PqPrefetchAttestationStatus::Published
        };
        let attestation = PqPrefetchAttestation {
            attestation_id: attestation_id.clone(),
            batch_id: batch_id.clone(),
            operator_id: batch.operator_id,
            status,
            attested_state_root_before: batch.state_root_before,
            attested_state_root_after: batch.predicted_state_root_after,
            attested_page_root: batch.page_set_root,
            lease_root: batch.witness_lease_root,
            fence_root: batch.invalidation_fence_root,
            pq_public_key_root: tagged_root("pq-public-keys", &attestation_id),
            pq_signature_root: tagged_root("pq-signature", &attestation_id),
            quorum_weight_bps,
            latency_ms,
            created_at_height: self.l2_height,
            expires_at_height: self.l2_height + self.config.attestation_ttl_blocks,
        };
        self.pq_prefetch_attestations
            .insert(attestation_id.clone(), attestation);
        self.counters.pq_attestations_published += 1;
        if status.accepted() {
            self.counters.pq_attestations_finalized += 1;
        }
        self.refresh_batch_attestation_root(&batch_id);
        self.refresh();
        Ok(attestation_id)
    }

    pub fn install_invalidation_fence(
        &mut self,
        fence_id: impl Into<String>,
        batch_id: impl Into<String>,
        reason_code: impl Into<String>,
    ) -> Result<String> {
        if self.invalidation_fences.len() >= self.config.max_invalidation_fences {
            return Err("invalidation fence capacity exhausted".to_string());
        }
        let fence_id = fence_id.into();
        if self.invalidation_fences.contains_key(&fence_id) {
            return Err(format!("invalidation fence already exists: {fence_id}"));
        }
        let batch_id = batch_id.into();
        let batch = self
            .prefetch_batches
            .get(&batch_id)
            .ok_or_else(|| format!("unknown prefetch batch: {batch_id}"))?
            .clone();
        let fence = InvalidationFence {
            fence_id: fence_id.clone(),
            batch_id: batch_id.clone(),
            operator_id: batch.operator_id,
            status: InvalidationFenceStatus::Active,
            nullifier_root: tagged_root("nullifier", &fence_id),
            view_tag_root: tagged_root("view-tag", &fence_id),
            conflicting_state_root: tagged_root("conflicting-state", &fence_id),
            reason_code: reason_code.into(),
            redaction_budget_id: batch.redaction_budget_id,
            created_at_height: self.l2_height,
            expires_at_height: self.l2_height + self.config.fence_ttl_blocks,
        };
        self.invalidation_fences.insert(fence_id.clone(), fence);
        self.counters.invalidation_fences_active += 1;
        self.refresh_batch_fence_root(&batch_id);
        self.refresh();
        Ok(fence_id)
    }

    pub fn grant_scheduler_credit(
        &mut self,
        credit_id: impl Into<String>,
        batch_id: impl Into<String>,
        priority_weight: u64,
        credits_granted: u64,
    ) -> Result<String> {
        if self.scheduler_credits.len() >= self.config.max_scheduler_credits {
            return Err("scheduler credit capacity exhausted".to_string());
        }
        let credit_id = credit_id.into();
        if self.scheduler_credits.contains_key(&credit_id) {
            return Ok(credit_id);
        }
        let batch_id = batch_id.into();
        let batch = self
            .prefetch_batches
            .get(&batch_id)
            .ok_or_else(|| format!("unknown prefetch batch: {batch_id}"))?
            .clone();
        let credit = SchedulerCredit {
            credit_id: credit_id.clone(),
            operator_id: batch.operator_id,
            batch_id,
            status: SchedulerCreditStatus::Granted,
            epoch: self.epoch,
            credits_granted,
            credits_reserved: 0,
            credits_spent: 0,
            priority_weight,
            fairness_debt: 0,
            created_at_height: self.l2_height,
            expires_at_height: self.l2_height + self.config.credit_epoch_blocks,
        };
        self.scheduler_credits.insert(credit_id.clone(), credit);
        self.counters.scheduler_credits_granted += credits_granted;
        self.refresh();
        Ok(credit_id)
    }

    pub fn spend_scheduler_credit(&mut self, credit_id: &str, credits: u64) -> Result<()> {
        let credit = self
            .scheduler_credits
            .get_mut(credit_id)
            .ok_or_else(|| format!("unknown scheduler credit: {credit_id}"))?;
        if credit.available() < credits {
            return Err(format!("insufficient scheduler credits: {credit_id}"));
        }
        credit.credits_spent += credits;
        credit.status = SchedulerCreditStatus::Spent;
        self.counters.scheduler_credits_spent += credits;
        self.refresh();
        Ok(())
    }

    pub fn apply_low_fee_rebate(
        &mut self,
        rebate_id: impl Into<String>,
        batch_id: impl Into<String>,
        gross_fee_micro_units: u64,
    ) -> Result<String> {
        if self.low_fee_rebates.len() >= self.config.max_low_fee_rebates {
            return Err("low fee rebate capacity exhausted".to_string());
        }
        let rebate_id = rebate_id.into();
        if self.low_fee_rebates.contains_key(&rebate_id) {
            return Err(format!("low fee rebate already exists: {rebate_id}"));
        }
        let batch_id = batch_id.into();
        let batch = self
            .prefetch_batches
            .get(&batch_id)
            .ok_or_else(|| format!("unknown prefetch batch: {batch_id}"))?
            .clone();
        let rebate_bps = batch.expected_rebate_bps.min(self.config.max_rebate_bps);
        let rebate = LowFeeRebate {
            rebate_id: rebate_id.clone(),
            batch_id,
            operator_id: batch.operator_id,
            status: LowFeeRebateStatus::Applied,
            fee_asset_id: self.config.fee_asset_id.clone(),
            gross_fee_micro_units,
            rebate_bps,
            rebate_micro_units: gross_fee_micro_units.saturating_mul(rebate_bps) / 10_000,
            sponsor_root: tagged_root("rebate-sponsor", &rebate_id),
            settlement_root: tagged_root("rebate-settlement", &rebate_id),
            created_at_height: self.l2_height,
            expires_at_height: self.l2_height + self.config.rebate_ttl_blocks,
        };
        self.low_fee_rebates.insert(rebate_id.clone(), rebate);
        self.counters.low_fee_rebates_applied += 1;
        self.refresh();
        Ok(rebate_id)
    }

    pub fn open_redaction_budget(
        &mut self,
        budget_id: impl Into<String>,
        batch_id: impl Into<String>,
        max_redactions: u64,
        max_disclosure_bytes: u64,
    ) -> Result<String> {
        if self.redaction_budgets.len() >= self.config.max_redaction_budgets {
            return Err("redaction budget capacity exhausted".to_string());
        }
        let budget_id = budget_id.into();
        if self.redaction_budgets.contains_key(&budget_id) {
            return Ok(budget_id);
        }
        let batch_id = batch_id.into();
        let batch = self
            .prefetch_batches
            .get(&batch_id)
            .ok_or_else(|| format!("unknown prefetch batch: {batch_id}"))?
            .clone();
        let budget = RedactionBudget {
            budget_id: budget_id.clone(),
            operator_id: batch.operator_id,
            batch_id,
            status: RedactionBudgetStatus::Open,
            epoch: self.epoch,
            max_redactions,
            used_redactions: 0,
            max_disclosure_bytes,
            disclosed_bytes: 0,
            redaction_policy_root: tagged_root("redaction-policy", &budget_id),
            auditor_view_root: tagged_root("auditor-view", &budget_id),
            created_at_height: self.l2_height,
            expires_at_height: self.l2_height + self.config.redaction_epoch_blocks,
        };
        self.redaction_budgets.insert(budget_id.clone(), budget);
        self.refresh();
        Ok(budget_id)
    }

    pub fn debit_redaction_budget(
        &mut self,
        budget_id: &str,
        redactions: u64,
        disclosure_bytes: u64,
    ) -> Result<()> {
        let budget = self
            .redaction_budgets
            .get_mut(budget_id)
            .ok_or_else(|| format!("unknown redaction budget: {budget_id}"))?;
        if budget.remaining_redactions() < redactions {
            return Err(format!("redaction budget exhausted: {budget_id}"));
        }
        if budget
            .max_disclosure_bytes
            .saturating_sub(budget.disclosed_bytes)
            < disclosure_bytes
        {
            return Err(format!(
                "redaction disclosure budget exhausted: {budget_id}"
            ));
        }
        budget.used_redactions += redactions;
        budget.disclosed_bytes += disclosure_bytes;
        budget.status = if budget.remaining_redactions() == 0 {
            RedactionBudgetStatus::Exhausted
        } else {
            RedactionBudgetStatus::Debited
        };
        self.counters.redaction_budget_debits += redactions;
        self.refresh();
        Ok(())
    }

    pub fn settle_prefetch_batch(&mut self, batch_id: &str) -> Result<()> {
        let accepted_attestations = self
            .pq_prefetch_attestations
            .values()
            .filter(|attestation| attestation.batch_id == batch_id && attestation.accepted())
            .count();
        if accepted_attestations == 0 {
            return Err(format!("batch lacks accepted pq attestation: {batch_id}"));
        }
        let warmed_pages = self
            .state_root_pages
            .values()
            .filter(|page| {
                page.batch_id == batch_id
                    && matches!(
                        page.status,
                        StateRootPageStatus::Warmed | StateRootPageStatus::Bound
                    )
            })
            .count();
        if warmed_pages == 0 {
            return Err(format!("batch lacks warmed state root page: {batch_id}"));
        }
        let batch = self
            .prefetch_batches
            .get_mut(batch_id)
            .ok_or_else(|| format!("unknown prefetch batch: {batch_id}"))?;
        batch.status = PrefetchBatchStatus::Settled;
        batch.warmed_at_height = Some(self.l2_height);
        self.live_batches.remove(batch_id);
        self.counters.batches_warmed += 1;
        self.refresh();
        Ok(())
    }

    pub fn invalidate_prefetch_batch(&mut self, batch_id: &str, reason_code: &str) -> Result<()> {
        self.install_invalidation_fence(format!("{batch_id}-invalidation"), batch_id, reason_code)?;
        let batch = self
            .prefetch_batches
            .get_mut(batch_id)
            .ok_or_else(|| format!("unknown prefetch batch: {batch_id}"))?;
        batch.status = PrefetchBatchStatus::Invalidated;
        self.live_batches.remove(batch_id);
        self.counters.batches_invalidated += 1;
        self.refresh();
        Ok(())
    }

    pub fn operator_summary(&self, operator_id: &str) -> OperatorSummary {
        let active_batches = self
            .prefetch_batches
            .values()
            .filter(|batch| batch.operator_id == operator_id && batch.live())
            .count() as u64;
        let warmed_batches = self
            .prefetch_batches
            .values()
            .filter(|batch| {
                batch.operator_id == operator_id
                    && matches!(
                        batch.status,
                        PrefetchBatchStatus::Warmed
                            | PrefetchBatchStatus::RootBound
                            | PrefetchBatchStatus::Settled
                    )
            })
            .count() as u64;
        let active_leases = self
            .witness_cache_leases
            .values()
            .filter(|lease| {
                lease.operator_id == operator_id
                    && matches!(
                        lease.status,
                        WitnessCacheLeaseStatus::Reserved | WitnessCacheLeaseStatus::Active
                    )
            })
            .count() as u64;
        let finalized_attestations = self
            .pq_prefetch_attestations
            .values()
            .filter(|attestation| {
                attestation.operator_id == operator_id
                    && matches!(
                        attestation.status,
                        PqPrefetchAttestationStatus::QuorumAccepted
                            | PqPrefetchAttestationStatus::Finalized
                    )
            })
            .count() as u64;
        let active_fences = self
            .invalidation_fences
            .values()
            .filter(|fence| fence.operator_id == operator_id && fence.live())
            .count() as u64;
        let credits_available = self
            .scheduler_credits
            .values()
            .filter(|credit| credit.operator_id == operator_id)
            .map(SchedulerCredit::available)
            .sum();
        let rebates_applied_micro_units = self
            .low_fee_rebates
            .values()
            .filter(|rebate| rebate.operator_id == operator_id)
            .map(|rebate| rebate.rebate_micro_units)
            .sum();
        let redactions_remaining = self
            .redaction_budgets
            .values()
            .filter(|budget| budget.operator_id == operator_id)
            .map(RedactionBudget::remaining_redactions)
            .sum();
        let latencies = self
            .pq_prefetch_attestations
            .values()
            .filter(|attestation| attestation.operator_id == operator_id)
            .map(|attestation| attestation.latency_ms)
            .collect::<Vec<_>>();
        let avg_prefetch_latency_ms = if latencies.is_empty() {
            0
        } else {
            latencies.iter().sum::<u64>() / latencies.len() as u64
        };
        let health = if active_fences > 2 {
            OperatorHealth::Red
        } else if avg_prefetch_latency_ms > self.config.max_prefetch_ms {
            OperatorHealth::Amber
        } else {
            OperatorHealth::Green
        };
        OperatorSummary {
            operator_id: operator_id.to_string(),
            health,
            active_batches,
            warmed_batches,
            active_leases,
            finalized_attestations,
            active_fences,
            credits_available,
            rebates_applied_micro_units,
            redactions_remaining,
            avg_prefetch_latency_ms,
            last_state_root: self.state_root(),
            updated_at_height: self.l2_height,
        }
    }

    pub fn refresh_operator_summaries(&mut self) {
        let operators = self.active_operators.iter().cloned().collect::<Vec<_>>();
        for operator_id in operators {
            let summary = self.operator_summary(&operator_id);
            self.operator_summaries.insert(operator_id, summary);
        }
        self.counters.operator_summaries_emitted = self.operator_summaries.len() as u64;
    }

    pub fn refresh(&mut self) {
        self.refresh_operator_summaries();
        self.roots = self.compute_roots_without_state_root();
        self.roots.state_root = self.state_root();
    }

    fn seed_devnet(&mut self) {
        let _ = self.queue_prefetch_batch(
            "devnet-prefetch-batch-0001",
            "operator-prefetch-east-0",
            PrefetchClass::StateRootPage,
            tagged_root("encrypted-batch", "0001"),
            tagged_root("state-before", "0001"),
            tagged_root("state-after", "0001"),
        );
        let _ = self.announce_state_root_page(
            "devnet-page-0001-a",
            "devnet-prefetch-batch-0001",
            0,
            tagged_root("page-root", "0001-a"),
            tagged_root("encrypted-delta", "0001-a"),
        );
        let _ = self.announce_state_root_page(
            "devnet-page-0001-b",
            "devnet-prefetch-batch-0001",
            1,
            tagged_root("page-root", "0001-b"),
            tagged_root("encrypted-delta", "0001-b"),
        );
        let _ = self.warm_state_root_page("devnet-page-0001-a", 64);
        let _ = self.warm_state_root_page("devnet-page-0001-b", 71);
        let _ = self.activate_witness_cache_lease("devnet-prefetch-batch-0001-lease-0", 131_072);
        let _ = self.publish_pq_prefetch_attestation(
            "devnet-attestation-0001",
            "devnet-prefetch-batch-0001",
            7_200,
            68,
        );
        let _ = self.apply_low_fee_rebate(
            "devnet-rebate-0001",
            "devnet-prefetch-batch-0001",
            4_200_000,
        );
        let _ = self.debit_redaction_budget("devnet-prefetch-batch-0001-redaction", 2, 2048);
        let _ = self.settle_prefetch_batch("devnet-prefetch-batch-0001");
        let _ = self.queue_prefetch_batch(
            "devnet-prefetch-batch-0002",
            "operator-prefetch-west-1",
            PrefetchClass::DefiSettlement,
            tagged_root("encrypted-batch", "0002"),
            tagged_root("state-before", "0002"),
            tagged_root("state-after", "0002"),
        );
        let _ = self.announce_state_root_page(
            "devnet-page-0002-a",
            "devnet-prefetch-batch-0002",
            0,
            tagged_root("page-root", "0002-a"),
            tagged_root("encrypted-delta", "0002-a"),
        );
        let _ = self.warm_state_root_page("devnet-page-0002-a", 110);
        let _ = self.publish_pq_prefetch_attestation(
            "devnet-attestation-0002",
            "devnet-prefetch-batch-0002",
            6_900,
            110,
        );
    }

    fn public_record_without_state_root(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "l2_height": self.l2_height,
            "monero_height": self.monero_height,
            "epoch": self.epoch,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record_without_state_root(),
            "prefetch_batches": map_values(&self.prefetch_batches),
            "state_root_pages": map_values(&self.state_root_pages),
            "witness_cache_leases": map_values(&self.witness_cache_leases),
            "pq_prefetch_attestations": map_values(&self.pq_prefetch_attestations),
            "invalidation_fences": map_values(&self.invalidation_fences),
            "scheduler_credits": map_values(&self.scheduler_credits),
            "low_fee_rebates": map_values(&self.low_fee_rebates),
            "redaction_budgets": map_values(&self.redaction_budgets),
            "operator_summaries": map_values(&self.operator_summaries),
            "active_operators": self.active_operators,
            "live_batches": self.live_batches,
        })
    }

    fn compute_roots_without_state_root(&self) -> Roots {
        Roots {
            config_root: self.config.state_root(),
            counters_root: self.counters.state_root(),
            prefetch_batch_root: collection_root("prefetch_batches", &self.prefetch_batches),
            state_root_page_root: collection_root("state_root_pages", &self.state_root_pages),
            witness_cache_lease_root: collection_root(
                "witness_cache_leases",
                &self.witness_cache_leases,
            ),
            pq_prefetch_attestation_root: collection_root(
                "pq_prefetch_attestations",
                &self.pq_prefetch_attestations,
            ),
            invalidation_fence_root: collection_root(
                "invalidation_fences",
                &self.invalidation_fences,
            ),
            scheduler_credit_root: collection_root("scheduler_credits", &self.scheduler_credits),
            low_fee_rebate_root: collection_root("low_fee_rebates", &self.low_fee_rebates),
            redaction_budget_root: collection_root("redaction_budgets", &self.redaction_budgets),
            operator_summary_root: collection_root("operator_summaries", &self.operator_summaries),
            active_operator_root: set_root("active_operators", &self.active_operators),
            live_batch_root: set_root("live_batches", &self.live_batches),
            state_root: String::new(),
        }
    }

    fn refresh_batch_page_root(&mut self, batch_id: &str) {
        let leaves = self
            .state_root_pages
            .values()
            .filter(|page| page.batch_id == batch_id)
            .map(StateRootPage::public_record)
            .collect::<Vec<_>>();
        if let Some(batch) = self.prefetch_batches.get_mut(batch_id) {
            batch.page_set_root = merkle_root("batch-state-root-pages", &leaves);
            if leaves
                .iter()
                .any(|page| page["status"] == json!(StateRootPageStatus::Warmed))
            {
                batch.status = PrefetchBatchStatus::Warmed;
                batch.warmed_at_height = Some(self.l2_height);
            } else if !leaves.is_empty() {
                batch.status = PrefetchBatchStatus::Prefetching;
            }
        }
    }

    fn refresh_batch_lease_root(&mut self, batch_id: &str) {
        let leaves = self
            .witness_cache_leases
            .values()
            .filter(|lease| lease.batch_id == batch_id)
            .map(WitnessCacheLease::public_record)
            .collect::<Vec<_>>();
        if let Some(batch) = self.prefetch_batches.get_mut(batch_id) {
            batch.witness_lease_root = merkle_root("batch-witness-cache-leases", &leaves);
        }
    }

    fn refresh_batch_attestation_root(&mut self, batch_id: &str) {
        let leaves = self
            .pq_prefetch_attestations
            .values()
            .filter(|attestation| attestation.batch_id == batch_id)
            .map(PqPrefetchAttestation::public_record)
            .collect::<Vec<_>>();
        if let Some(batch) = self.prefetch_batches.get_mut(batch_id) {
            batch.attestation_root = merkle_root("batch-pq-prefetch-attestations", &leaves);
            if leaves.iter().any(|attestation| {
                attestation["status"] == json!(PqPrefetchAttestationStatus::QuorumAccepted)
                    || attestation["status"] == json!(PqPrefetchAttestationStatus::Finalized)
            }) {
                batch.status = PrefetchBatchStatus::RootBound;
            }
        }
    }

    fn refresh_batch_fence_root(&mut self, batch_id: &str) {
        let leaves = self
            .invalidation_fences
            .values()
            .filter(|fence| fence.batch_id == batch_id)
            .map(InvalidationFence::public_record)
            .collect::<Vec<_>>();
        if let Some(batch) = self.prefetch_batches.get_mut(batch_id) {
            batch.invalidation_fence_root = merkle_root("batch-invalidation-fences", &leaves);
        }
    }
}

impl PqPrefetchAttestationStatus {
    fn accepted(self) -> bool {
        matches!(self, Self::QuorumAccepted | Self::Finalized)
    }
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn demo() -> State {
    let mut state = State::devnet();
    let _ = state.queue_prefetch_batch(
        "demo-prefetch-batch-0003",
        "operator-prefetch-central-2",
        PrefetchClass::EmergencyEscape,
        tagged_root("encrypted-batch", "demo-0003"),
        tagged_root("state-before", "demo-0003"),
        tagged_root("state-after", "demo-0003"),
    );
    let _ = state.announce_state_root_page(
        "demo-page-0003-a",
        "demo-prefetch-batch-0003",
        0,
        tagged_root("page-root", "demo-0003-a"),
        tagged_root("encrypted-delta", "demo-0003-a"),
    );
    let _ = state.warm_state_root_page("demo-page-0003-a", 42);
    let _ = state.publish_pq_prefetch_attestation(
        "demo-attestation-0003",
        "demo-prefetch-batch-0003",
        8_100,
        42,
    );
    let _ = state.apply_low_fee_rebate("demo-rebate-0003", "demo-prefetch-batch-0003", 6_100_000);
    let _ = state.settle_prefetch_batch("demo-prefetch-batch-0003");
    state.refresh();
    state
}

pub fn public_record(state: &State) -> Value {
    state.public_record()
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}

fn record_root(domain: &str, record: &Value) -> String {
    domain_hash(
        "private-l2-fast-pq-confidential-batch-state-root-prefetch-runtime:record",
        &[HashPart::Str(domain), HashPart::Json(record)],
        32,
    )
}

fn state_root_from_record(record: &Value) -> String {
    domain_hash(
        "private-l2-fast-pq-confidential-batch-state-root-prefetch-runtime:state-root",
        &[HashPart::Str(PROTOCOL_VERSION), HashPart::Json(record)],
        32,
    )
}

fn tagged_root(domain: &str, tag: &str) -> String {
    domain_hash(
        "private-l2-fast-pq-confidential-batch-state-root-prefetch-runtime:tag",
        &[HashPart::Str(domain), HashPart::Str(tag)],
        32,
    )
}

fn map_values<T: Serialize>(values: &BTreeMap<String, T>) -> Vec<Value> {
    values.values().map(|value| json!(value)).collect()
}

fn collection_root<T: Serialize>(domain: &str, values: &BTreeMap<String, T>) -> String {
    let leaves = values
        .iter()
        .map(|(key, value)| {
            json!({
                "key": key,
                "value": value,
            })
        })
        .collect::<Vec<_>>();
    merkle_root(
        &format!("private-l2-fast-pq-confidential-batch-state-root-prefetch-runtime:{domain}"),
        &leaves,
    )
}

fn set_root(domain: &str, values: &BTreeSet<String>) -> String {
    let leaves = values
        .iter()
        .map(|value| {
            json!({
                "value": value,
            })
        })
        .collect::<Vec<_>>();
    merkle_root(
        &format!("private-l2-fast-pq-confidential-batch-state-root-prefetch-runtime:{domain}"),
        &leaves,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn devnet_has_stable_public_record() {
        let state = State::devnet();
        assert_eq!(state.state_root(), state.roots.state_root);
        assert!(!state.public_record()["state_root"]
            .as_str()
            .unwrap()
            .is_empty());
    }

    #[test]
    fn demo_adds_emergency_prefetch_batch() {
        let state = demo();
        assert!(state
            .prefetch_batches
            .contains_key("demo-prefetch-batch-0003"));
    }
}
