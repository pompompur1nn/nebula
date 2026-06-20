use std::collections::{BTreeMap, BTreeSet, VecDeque};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2FastPqConfidentialParallelFraudProofPrefetchRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_FAST_PQ_CONFIDENTIAL_PARALLEL_FRAUD_PROOF_PREFETCH_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-private-l2-fast-pq-confidential-parallel-fraud-proof-prefetch-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_FAST_PQ_CONFIDENTIAL_PARALLEL_FRAUD_PROOF_PREFETCH_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_CHALLENGER_ATTESTATION_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-fraud-prefetch-v1";
pub const CONFIDENTIAL_WITNESS_METADATA_SUITE: &str =
    "viewtag-nullifier-redacted-fraud-witness-metadata-v1";
pub const PARALLEL_SHARD_ROOT_SUITE: &str = "parallel-fraud-proof-witness-shard-root-v1";
pub const INVALIDATION_FENCE_SUITE: &str = "fraud-proof-prefetch-invalidation-fence-root-v1";
pub const LOW_FEE_CREDIT_SUITE: &str = "low-fee-fraud-proof-credit-scheduling-root-v1";
pub const OPERATOR_SUMMARY_SUITE: &str = "redacted-operator-fraud-prefetch-summary-root-v1";
pub const DEFAULT_L2_NETWORK: &str = "nebula-devnet";
pub const DEFAULT_MONERO_NETWORK: &str = "monero-devnet";
pub const DEFAULT_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEFAULT_CREDIT_ASSET_ID: &str = "fraud-proof-credit-devnet";
pub const DEVNET_L2_HEIGHT: u64 = 2_940_000;
pub const DEVNET_MONERO_HEIGHT: u64 = 3_700_000;
pub const DEVNET_EPOCH: u64 = 18_432;
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 262_144;
pub const DEFAULT_TARGET_PRIVACY_SET_SIZE: u64 = 1_048_576;
pub const DEFAULT_SLOT_WIDTH_MS: u64 = 40;
pub const DEFAULT_TARGET_PREFETCH_MS: u64 = 55;
pub const DEFAULT_MAX_PREFETCH_MS: u64 = 240;
pub const DEFAULT_CHALLENGE_WINDOW_SLOTS: u64 = 160;
pub const DEFAULT_TICKET_TTL_SLOTS: u64 = 48;
pub const DEFAULT_SHARD_TTL_SLOTS: u64 = 96;
pub const DEFAULT_ATTESTATION_TTL_SLOTS: u64 = 128;
pub const DEFAULT_FENCE_TTL_SLOTS: u64 = 384;
pub const DEFAULT_CREDIT_TTL_SLOTS: u64 = 768;
pub const DEFAULT_SUMMARY_TTL_SLOTS: u64 = 1_024;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 10;
pub const DEFAULT_LOW_FEE_TARGET_BPS: u64 = 3;
pub const DEFAULT_CREDIT_REBATE_BPS: u64 = 5;
pub const DEFAULT_OPERATOR_FEE_BPS: u64 = 1;
pub const DEFAULT_MIN_CHALLENGER_BOND_MICRO_UNITS: u64 = 2_500_000;
pub const DEFAULT_MIN_OPERATOR_BOND_MICRO_UNITS: u64 = 35_000_000;
pub const DEFAULT_SLASH_BPS: u64 = 1_600;
pub const DEFAULT_QUORUM_WEIGHT_BPS: u64 = 6_700;
pub const DEFAULT_SUPERMAJORITY_WEIGHT_BPS: u64 = 8_000;
pub const DEFAULT_QUEUE_SOFT_LIMIT: u64 = 524_288;
pub const DEFAULT_QUEUE_HARD_LIMIT: u64 = 1_048_576;
pub const DEFAULT_MAX_LANES: usize = 65_536;
pub const DEFAULT_MAX_TICKETS: usize = 2_097_152;
pub const DEFAULT_MAX_ATTESTATIONS: usize = 2_097_152;
pub const DEFAULT_MAX_SHARDS: usize = 4_194_304;
pub const DEFAULT_MAX_FENCES: usize = 1_048_576;
pub const DEFAULT_MAX_CREDITS: usize = 2_097_152;
pub const DEFAULT_MAX_SUMMARIES: usize = 262_144;
pub const DEFAULT_MAX_EVENTS: usize = 8_388_608;

const D_STATE: &str = "PL2-FAST-PQ-CONF-PARALLEL-FRAUD-PROOF-PREFETCH:STATE";
const D_CONFIG: &str = "PL2-FAST-PQ-CONF-PARALLEL-FRAUD-PROOF-PREFETCH:CONFIG";
const D_COUNTERS: &str = "PL2-FAST-PQ-CONF-PARALLEL-FRAUD-PROOF-PREFETCH:COUNTERS";
const D_ROOTS: &str = "PL2-FAST-PQ-CONF-PARALLEL-FRAUD-PROOF-PREFETCH:ROOTS";
const D_LANES: &str = "PL2-FAST-PQ-CONF-PARALLEL-FRAUD-PROOF-PREFETCH:LANES";
const D_TICKETS: &str = "PL2-FAST-PQ-CONF-PARALLEL-FRAUD-PROOF-PREFETCH:TICKETS";
const D_ATTESTATIONS: &str = "PL2-FAST-PQ-CONF-PARALLEL-FRAUD-PROOF-PREFETCH:ATTESTATIONS";
const D_SHARDS: &str = "PL2-FAST-PQ-CONF-PARALLEL-FRAUD-PROOF-PREFETCH:SHARDS";
const D_FENCES: &str = "PL2-FAST-PQ-CONF-PARALLEL-FRAUD-PROOF-PREFETCH:FENCES";
const D_CREDITS: &str = "PL2-FAST-PQ-CONF-PARALLEL-FRAUD-PROOF-PREFETCH:CREDITS";
const D_SUMMARIES: &str = "PL2-FAST-PQ-CONF-PARALLEL-FRAUD-PROOF-PREFETCH:SUMMARIES";
const D_EVENTS: &str = "PL2-FAST-PQ-CONF-PARALLEL-FRAUD-PROOF-PREFETCH:EVENTS";
const D_NULLIFIERS: &str = "PL2-FAST-PQ-CONF-PARALLEL-FRAUD-PROOF-PREFETCH:NULLIFIERS";

macro_rules! ensure {
    ($condition:expr, $message:literal $(,)?) => {
        if !$condition {
            return Err($message.to_string());
        }
    };
    ($condition:expr, $($arg:tt)+) => {
        if !$condition {
            return Err(format!($($arg)+));
        }
    };
}

fn hash_json(domain: &str, value: &Value) -> String {
    domain_hash(domain, &[HashPart::Json(value)], 32)
}

fn hash_parts(domain: &str, parts: &[HashPart<'_>]) -> String {
    domain_hash(domain, parts, 32)
}

fn empty_root(domain: &str) -> String {
    merkle_root(domain, &[json!("empty")])
}

fn root_from_values(domain: &str, values: Vec<Value>) -> String {
    if values.is_empty() {
        empty_root(domain)
    } else {
        merkle_root(domain, &values)
    }
}

fn clamp_bps(value: u64) -> u64 {
    value.min(MAX_BPS)
}

fn sat_bps(amount: u64, bps: u64) -> u64 {
    amount.saturating_mul(clamp_bps(bps)) / MAX_BPS
}

fn redact(label: &str, secret: &str) -> String {
    hash_parts(
        D_NULLIFIERS,
        &[
            HashPart::Str(label),
            HashPart::Str(secret),
            HashPart::Str(CONFIDENTIAL_WITNESS_METADATA_SUITE),
        ],
    )
}

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
pub enum FraudProofKind {
    StateTransition,
    DataAvailability,
    InvalidWithdrawal,
    DoubleSpendNullifier,
    SequencerEquivocation,
    ContractInvariant,
    BridgeReserve,
    OracleMiscompute,
    EmergencyEscape,
    LowFeeBatch,
}

impl FraudProofKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::StateTransition => "state_transition",
            Self::DataAvailability => "data_availability",
            Self::InvalidWithdrawal => "invalid_withdrawal",
            Self::DoubleSpendNullifier => "double_spend_nullifier",
            Self::SequencerEquivocation => "sequencer_equivocation",
            Self::ContractInvariant => "contract_invariant",
            Self::BridgeReserve => "bridge_reserve",
            Self::OracleMiscompute => "oracle_miscompute",
            Self::EmergencyEscape => "emergency_escape",
            Self::LowFeeBatch => "low_fee_batch",
        }
    }

    pub fn base_priority(self) -> u64 {
        match self {
            Self::EmergencyEscape => 10_000,
            Self::SequencerEquivocation => 9_850,
            Self::DoubleSpendNullifier => 9_650,
            Self::InvalidWithdrawal => 9_500,
            Self::StateTransition => 9_300,
            Self::BridgeReserve => 9_100,
            Self::ContractInvariant => 8_900,
            Self::OracleMiscompute => 8_300,
            Self::DataAvailability => 8_000,
            Self::LowFeeBatch => 5_500,
        }
    }

    pub fn default_shards(self) -> u16 {
        match self {
            Self::EmergencyEscape => 16,
            Self::SequencerEquivocation => 12,
            Self::DoubleSpendNullifier => 12,
            Self::InvalidWithdrawal => 10,
            Self::StateTransition => 10,
            Self::BridgeReserve => 8,
            Self::ContractInvariant => 8,
            Self::OracleMiscompute => 6,
            Self::DataAvailability => 6,
            Self::LowFeeBatch => 4,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LaneClass {
    HotDispute,
    StateTransition,
    MoneroBridge,
    ContractInvariant,
    Watchtower,
    LowFeeBulk,
    Backfill,
    OperatorAudit,
}

impl LaneClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::HotDispute => "hot_dispute",
            Self::StateTransition => "state_transition",
            Self::MoneroBridge => "monero_bridge",
            Self::ContractInvariant => "contract_invariant",
            Self::Watchtower => "watchtower",
            Self::LowFeeBulk => "low_fee_bulk",
            Self::Backfill => "backfill",
            Self::OperatorAudit => "operator_audit",
        }
    }

    pub fn priority_weight(self) -> u64 {
        match self {
            Self::HotDispute => 1_000,
            Self::StateTransition => 930,
            Self::MoneroBridge => 900,
            Self::ContractInvariant => 850,
            Self::Watchtower => 800,
            Self::OperatorAudit => 720,
            Self::LowFeeBulk => 620,
            Self::Backfill => 480,
        }
    }
}

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

status_enum!(LaneStatus {
    Open => "open",
    PressureLimited => "pressure_limited",
    Prefetching => "prefetching",
    LowFeeOnly => "low_fee_only",
    Fenced => "fenced",
    Draining => "draining",
    Paused => "paused",
    Retired => "retired",
});
status_enum!(TicketStatus {
    Queued => "queued",
    Reserved => "reserved",
    Prefetching => "prefetching",
    Sharded => "sharded",
    Ready => "ready",
    Published => "published",
    Challenged => "challenged",
    Expired => "expired",
    Invalidated => "invalidated",
});
status_enum!(AttestationStatus {
    Draft => "draft",
    Submitted => "submitted",
    QuorumPending => "quorum_pending",
    Accepted => "accepted",
    Rejected => "rejected",
    Slashed => "slashed",
    Expired => "expired",
});
status_enum!(ShardStatus {
    Requested => "requested",
    Fetching => "fetching",
    Warmed => "warmed",
    Bound => "bound",
    Sealed => "sealed",
    Consumed => "consumed",
    Invalidated => "invalidated",
    Expired => "expired",
});
status_enum!(FenceStatus {
    Draft => "draft",
    Active => "active",
    Matched => "matched",
    Released => "released",
    Escalated => "escalated",
    Expired => "expired",
});
status_enum!(CreditStatus {
    Minted => "minted",
    Reserved => "reserved",
    Applied => "applied",
    Rebated => "rebated",
    Settled => "settled",
    Slashed => "slashed",
    Expired => "expired",
});
status_enum!(SummaryStatus {
    Draft => "draft",
    Published => "published",
    Audited => "audited",
    Fenced => "fenced",
    Retired => "retired",
});

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub protocol_version: String,
    pub schema_version: u64,
    pub chain_id: String,
    pub l2_network: String,
    pub monero_network: String,
    pub mode: RuntimeMode,
    pub fee_asset_id: String,
    pub credit_asset_id: String,
    pub hash_suite: String,
    pub pq_challenger_attestation_suite: String,
    pub confidential_witness_metadata_suite: String,
    pub parallel_shard_root_suite: String,
    pub invalidation_fence_suite: String,
    pub low_fee_credit_suite: String,
    pub operator_summary_suite: String,
    pub l2_height: u64,
    pub monero_height: u64,
    pub epoch: u64,
    pub slot_width_ms: u64,
    pub target_prefetch_ms: u64,
    pub max_prefetch_ms: u64,
    pub challenge_window_slots: u64,
    pub ticket_ttl_slots: u64,
    pub shard_ttl_slots: u64,
    pub attestation_ttl_slots: u64,
    pub fence_ttl_slots: u64,
    pub credit_ttl_slots: u64,
    pub summary_ttl_slots: u64,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub max_user_fee_bps: u64,
    pub low_fee_target_bps: u64,
    pub credit_rebate_bps: u64,
    pub operator_fee_bps: u64,
    pub min_challenger_bond_micro_units: u64,
    pub min_operator_bond_micro_units: u64,
    pub slash_bps: u64,
    pub quorum_weight_bps: u64,
    pub supermajority_weight_bps: u64,
    pub queue_soft_limit: u64,
    pub queue_hard_limit: u64,
    pub max_lanes: usize,
    pub max_tickets: usize,
    pub max_attestations: usize,
    pub max_shards: usize,
    pub max_fences: usize,
    pub max_credits: usize,
    pub max_summaries: usize,
    pub max_events: usize,
    pub require_pq_auth: bool,
    pub require_metadata_redaction: bool,
    pub require_fence_before_invalidation: bool,
    pub allow_low_fee_credit_recycling: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            chain_id: CHAIN_ID.to_string(),
            l2_network: DEFAULT_L2_NETWORK.to_string(),
            monero_network: DEFAULT_MONERO_NETWORK.to_string(),
            mode: RuntimeMode::Devnet,
            fee_asset_id: DEFAULT_FEE_ASSET_ID.to_string(),
            credit_asset_id: DEFAULT_CREDIT_ASSET_ID.to_string(),
            hash_suite: HASH_SUITE.to_string(),
            pq_challenger_attestation_suite: PQ_CHALLENGER_ATTESTATION_SUITE.to_string(),
            confidential_witness_metadata_suite: CONFIDENTIAL_WITNESS_METADATA_SUITE.to_string(),
            parallel_shard_root_suite: PARALLEL_SHARD_ROOT_SUITE.to_string(),
            invalidation_fence_suite: INVALIDATION_FENCE_SUITE.to_string(),
            low_fee_credit_suite: LOW_FEE_CREDIT_SUITE.to_string(),
            operator_summary_suite: OPERATOR_SUMMARY_SUITE.to_string(),
            l2_height: DEVNET_L2_HEIGHT,
            monero_height: DEVNET_MONERO_HEIGHT,
            epoch: DEVNET_EPOCH,
            slot_width_ms: DEFAULT_SLOT_WIDTH_MS,
            target_prefetch_ms: DEFAULT_TARGET_PREFETCH_MS,
            max_prefetch_ms: DEFAULT_MAX_PREFETCH_MS,
            challenge_window_slots: DEFAULT_CHALLENGE_WINDOW_SLOTS,
            ticket_ttl_slots: DEFAULT_TICKET_TTL_SLOTS,
            shard_ttl_slots: DEFAULT_SHARD_TTL_SLOTS,
            attestation_ttl_slots: DEFAULT_ATTESTATION_TTL_SLOTS,
            fence_ttl_slots: DEFAULT_FENCE_TTL_SLOTS,
            credit_ttl_slots: DEFAULT_CREDIT_TTL_SLOTS,
            summary_ttl_slots: DEFAULT_SUMMARY_TTL_SLOTS,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            low_fee_target_bps: DEFAULT_LOW_FEE_TARGET_BPS,
            credit_rebate_bps: DEFAULT_CREDIT_REBATE_BPS,
            operator_fee_bps: DEFAULT_OPERATOR_FEE_BPS,
            min_challenger_bond_micro_units: DEFAULT_MIN_CHALLENGER_BOND_MICRO_UNITS,
            min_operator_bond_micro_units: DEFAULT_MIN_OPERATOR_BOND_MICRO_UNITS,
            slash_bps: DEFAULT_SLASH_BPS,
            quorum_weight_bps: DEFAULT_QUORUM_WEIGHT_BPS,
            supermajority_weight_bps: DEFAULT_SUPERMAJORITY_WEIGHT_BPS,
            queue_soft_limit: DEFAULT_QUEUE_SOFT_LIMIT,
            queue_hard_limit: DEFAULT_QUEUE_HARD_LIMIT,
            max_lanes: DEFAULT_MAX_LANES,
            max_tickets: DEFAULT_MAX_TICKETS,
            max_attestations: DEFAULT_MAX_ATTESTATIONS,
            max_shards: DEFAULT_MAX_SHARDS,
            max_fences: DEFAULT_MAX_FENCES,
            max_credits: DEFAULT_MAX_CREDITS,
            max_summaries: DEFAULT_MAX_SUMMARIES,
            max_events: DEFAULT_MAX_EVENTS,
            require_pq_auth: true,
            require_metadata_redaction: true,
            require_fence_before_invalidation: true,
            allow_low_fee_credit_recycling: true,
        }
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.protocol_version == PROTOCOL_VERSION,
            "protocol version mismatch"
        );
        ensure!(
            self.schema_version == SCHEMA_VERSION,
            "schema version mismatch"
        );
        ensure!(self.min_pq_security_bits >= 128, "pq security bits too low");
        ensure!(
            self.min_privacy_set_size > 0,
            "privacy set must be non-zero"
        );
        ensure!(
            self.target_privacy_set_size >= self.min_privacy_set_size,
            "target privacy set below minimum"
        );
        ensure!(
            self.target_prefetch_ms <= self.max_prefetch_ms,
            "target prefetch above maximum"
        );
        ensure!(
            self.queue_soft_limit <= self.queue_hard_limit,
            "queue soft limit above hard limit"
        );
        ensure!(
            self.max_user_fee_bps <= MAX_BPS,
            "max user fee bps exceeds 100%"
        );
        ensure!(
            self.low_fee_target_bps <= self.max_user_fee_bps,
            "low fee target above user fee cap"
        );
        ensure!(
            self.credit_rebate_bps <= MAX_BPS,
            "credit rebate bps exceeds 100%"
        );
        ensure!(
            self.operator_fee_bps <= MAX_BPS,
            "operator fee bps exceeds 100%"
        );
        ensure!(self.slash_bps <= MAX_BPS, "slash bps exceeds 100%");
        ensure!(
            self.quorum_weight_bps <= self.supermajority_weight_bps,
            "quorum above supermajority"
        );
        ensure!(
            self.supermajority_weight_bps <= MAX_BPS,
            "supermajority bps exceeds 100%"
        );
        Ok(())
    }

    pub fn ticket_deadline_slot(&self, opened_slot: u64) -> u64 {
        opened_slot.saturating_add(self.ticket_ttl_slots)
    }

    pub fn shard_deadline_slot(&self, opened_slot: u64) -> u64 {
        opened_slot.saturating_add(self.shard_ttl_slots)
    }

    pub fn attestation_deadline_slot(&self, opened_slot: u64) -> u64 {
        opened_slot.saturating_add(self.attestation_ttl_slots)
    }

    pub fn fence_deadline_slot(&self, opened_slot: u64) -> u64 {
        opened_slot.saturating_add(self.fence_ttl_slots)
    }

    pub fn credit_deadline_slot(&self, opened_slot: u64) -> u64 {
        opened_slot.saturating_add(self.credit_ttl_slots)
    }
}

impl Default for Config {
    fn default() -> Self {
        Self::devnet()
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub lanes_opened: u64,
    pub lanes_pressure_limited: u64,
    pub lanes_retired: u64,
    pub tickets_queued: u64,
    pub tickets_reserved: u64,
    pub tickets_ready: u64,
    pub tickets_invalidated: u64,
    pub attestations_submitted: u64,
    pub attestations_accepted: u64,
    pub attestations_rejected: u64,
    pub shards_requested: u64,
    pub shards_warmed: u64,
    pub shards_sealed: u64,
    pub fences_activated: u64,
    pub fences_matched: u64,
    pub low_fee_credits_minted: u64,
    pub low_fee_credits_applied: u64,
    pub low_fee_credits_rebated: u64,
    pub operator_summaries_published: u64,
    pub public_events_recorded: u64,
    pub fee_micro_units_scheduled: u64,
    pub fee_micro_units_rebated: u64,
    pub slash_micro_units_reserved: u64,
    pub metadata_commitments_recorded: u64,
    pub root_recomputations: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "lanes_opened": self.lanes_opened,
            "tickets_queued": self.tickets_queued,
            "tickets_ready": self.tickets_ready,
            "tickets_invalidated": self.tickets_invalidated,
            "attestations_accepted": self.attestations_accepted,
            "shards_warmed": self.shards_warmed,
            "shards_sealed": self.shards_sealed,
            "fences_activated": self.fences_activated,
            "low_fee_credits_minted": self.low_fee_credits_minted,
            "low_fee_credits_applied": self.low_fee_credits_applied,
            "operator_summaries_published": self.operator_summaries_published,
            "fee_micro_units_scheduled": self.fee_micro_units_scheduled,
            "fee_micro_units_rebated": self.fee_micro_units_rebated,
            "metadata_commitments_recorded": self.metadata_commitments_recorded,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub counter_root: String,
    pub lane_root: String,
    pub ticket_root: String,
    pub attestation_root: String,
    pub shard_root: String,
    pub fence_root: String,
    pub credit_root: String,
    pub summary_root: String,
    pub event_root: String,
    pub public_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn empty() -> Self {
        Self {
            config_root: empty_root(D_CONFIG),
            counter_root: empty_root(D_COUNTERS),
            lane_root: empty_root(D_LANES),
            ticket_root: empty_root(D_TICKETS),
            attestation_root: empty_root(D_ATTESTATIONS),
            shard_root: empty_root(D_SHARDS),
            fence_root: empty_root(D_FENCES),
            credit_root: empty_root(D_CREDITS),
            summary_root: empty_root(D_SUMMARIES),
            event_root: empty_root(D_EVENTS),
            public_root: empty_root(D_STATE),
            state_root: empty_root(D_STATE),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "counter_root": self.counter_root,
            "lane_root": self.lane_root,
            "ticket_root": self.ticket_root,
            "attestation_root": self.attestation_root,
            "shard_root": self.shard_root,
            "fence_root": self.fence_root,
            "credit_root": self.credit_root,
            "summary_root": self.summary_root,
            "event_root": self.event_root,
            "public_root": self.public_root,
            "state_root": self.state_root,
        })
    }
}

impl Default for Roots {
    fn default() -> Self {
        Self::empty()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivacyWitnessMetadata {
    pub metadata_id: String,
    pub view_tag_commitment: String,
    pub nullifier_set_commitment: String,
    pub shard_hint_commitment: String,
    pub access_pattern_commitment: String,
    pub privacy_set_size: u64,
    pub decoy_epoch: u64,
    pub redaction_root: String,
}

impl PrivacyWitnessMetadata {
    pub fn redacted(
        metadata_id: &str,
        view_tag: &str,
        nullifier_set: &str,
        shard_hint: &str,
        access_pattern: &str,
        privacy_set_size: u64,
        decoy_epoch: u64,
    ) -> Self {
        let view_tag_commitment = redact("view_tag", view_tag);
        let nullifier_set_commitment = redact("nullifier_set", nullifier_set);
        let shard_hint_commitment = redact("shard_hint", shard_hint);
        let access_pattern_commitment = redact("access_pattern", access_pattern);
        let redaction_root = hash_json(
            D_NULLIFIERS,
            &json!({
                "metadata_id": metadata_id,
                "view_tag_commitment": view_tag_commitment,
                "nullifier_set_commitment": nullifier_set_commitment,
                "shard_hint_commitment": shard_hint_commitment,
                "access_pattern_commitment": access_pattern_commitment,
                "privacy_set_size": privacy_set_size,
                "decoy_epoch": decoy_epoch,
                "suite": CONFIDENTIAL_WITNESS_METADATA_SUITE,
            }),
        );
        Self {
            metadata_id: metadata_id.to_string(),
            view_tag_commitment,
            nullifier_set_commitment,
            shard_hint_commitment,
            access_pattern_commitment,
            privacy_set_size,
            decoy_epoch,
            redaction_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "metadata_id": self.metadata_id,
            "view_tag_commitment": self.view_tag_commitment,
            "nullifier_set_commitment": self.nullifier_set_commitment,
            "shard_hint_commitment": self.shard_hint_commitment,
            "access_pattern_commitment": self.access_pattern_commitment,
            "privacy_set_size": self.privacy_set_size,
            "decoy_epoch": self.decoy_epoch,
            "redaction_root": self.redaction_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FraudProofLane {
    pub lane_id: String,
    pub operator_id: String,
    pub class: LaneClass,
    pub status: LaneStatus,
    pub opened_slot: u64,
    pub last_update_slot: u64,
    pub capacity_units: u64,
    pub inflight_units: u64,
    pub reserved_low_fee_units: u64,
    pub target_prefetch_ms: u64,
    pub max_prefetch_ms: u64,
    pub priority_floor: u64,
    pub operator_bond_micro_units: u64,
    pub attestation_root: String,
    pub fence_root: String,
    pub metadata_policy_root: String,
}

impl FraudProofLane {
    pub fn new(
        lane_id: impl Into<String>,
        operator_id: impl Into<String>,
        class: LaneClass,
        opened_slot: u64,
        capacity_units: u64,
        config: &Config,
    ) -> Self {
        let lane_id = lane_id.into();
        let operator_id = operator_id.into();
        let metadata_policy_root = hash_parts(
            D_LANES,
            &[
                HashPart::Str(&lane_id),
                HashPart::Str(class.as_str()),
                HashPart::Str(CONFIDENTIAL_WITNESS_METADATA_SUITE),
            ],
        );
        Self {
            lane_id,
            operator_id,
            class,
            status: LaneStatus::Open,
            opened_slot,
            last_update_slot: opened_slot,
            capacity_units,
            inflight_units: 0,
            reserved_low_fee_units: capacity_units / 4,
            target_prefetch_ms: config.target_prefetch_ms,
            max_prefetch_ms: config.max_prefetch_ms,
            priority_floor: class.priority_weight(),
            operator_bond_micro_units: config.min_operator_bond_micro_units,
            attestation_root: empty_root(D_ATTESTATIONS),
            fence_root: empty_root(D_FENCES),
            metadata_policy_root,
        }
    }

    pub fn available_units(&self) -> u64 {
        self.capacity_units.saturating_sub(self.inflight_units)
    }
    pub fn pressure_bps(&self) -> u64 {
        if self.capacity_units == 0 {
            MAX_BPS
        } else {
            self.inflight_units.saturating_mul(MAX_BPS) / self.capacity_units
        }
    }
    pub fn accepts(&self, low_fee: bool) -> bool {
        matches!(
            self.status,
            LaneStatus::Open | LaneStatus::Prefetching | LaneStatus::PressureLimited
        ) || (self.status == LaneStatus::LowFeeOnly && low_fee)
    }

    pub fn reserve_units(&mut self, units: u64, slot: u64) -> Result<()> {
        ensure!(self.available_units() >= units, "lane capacity exceeded");
        self.inflight_units = self.inflight_units.saturating_add(units);
        self.last_update_slot = slot;
        if self.pressure_bps() >= 8_500 {
            self.status = LaneStatus::PressureLimited;
        } else if self.status == LaneStatus::Open {
            self.status = LaneStatus::Prefetching;
        }
        Ok(())
    }

    pub fn release_units(&mut self, units: u64, slot: u64) {
        self.inflight_units = self.inflight_units.saturating_sub(units);
        self.last_update_slot = slot;
        if self.status == LaneStatus::PressureLimited && self.pressure_bps() < 6_000 {
            self.status = LaneStatus::Open;
        }
    }

    pub fn root(&self) -> String {
        hash_json(D_LANES, &self.public_record())
    }
    pub fn public_record(&self) -> Value {
        json!({
            "lane_id": self.lane_id, "operator_id": self.operator_id, "class": self.class.as_str(), "status": self.status.as_str(),
            "opened_slot": self.opened_slot, "last_update_slot": self.last_update_slot, "capacity_units": self.capacity_units,
            "inflight_units": self.inflight_units, "reserved_low_fee_units": self.reserved_low_fee_units, "target_prefetch_ms": self.target_prefetch_ms,
            "max_prefetch_ms": self.max_prefetch_ms, "priority_floor": self.priority_floor, "operator_bond_micro_units": self.operator_bond_micro_units,
            "attestation_root": self.attestation_root, "fence_root": self.fence_root, "metadata_policy_root": self.metadata_policy_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrefetchTicket {
    pub ticket_id: String,
    pub lane_id: String,
    pub challenge_id: String,
    pub proof_kind: FraudProofKind,
    pub status: TicketStatus,
    pub opened_slot: u64,
    pub deadline_slot: u64,
    pub target_prefetch_ms: u64,
    pub estimated_units: u64,
    pub max_fee_micro_units: u64,
    pub scheduled_fee_micro_units: u64,
    pub low_fee_credit_id: Option<String>,
    pub priority_score: u64,
    pub challenger_commitment: String,
    pub disputed_state_root: String,
    pub expected_witness_root: String,
    pub metadata: PrivacyWitnessMetadata,
    pub shard_ids: BTreeSet<String>,
    pub attestation_ids: BTreeSet<String>,
    pub fence_id: Option<String>,
}

impl PrefetchTicket {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        ticket_id: impl Into<String>,
        lane_id: impl Into<String>,
        challenge_id: impl Into<String>,
        proof_kind: FraudProofKind,
        opened_slot: u64,
        estimated_units: u64,
        max_fee_micro_units: u64,
        challenger_secret: &str,
        disputed_state_root: impl Into<String>,
        metadata: PrivacyWitnessMetadata,
        config: &Config,
    ) -> Self {
        let ticket_id = ticket_id.into();
        let priority_score = proof_kind
            .base_priority()
            .saturating_add(estimated_units.min(2_000));
        let scheduled_fee_micro_units =
            sat_bps(max_fee_micro_units, config.max_user_fee_bps).max(1);
        Self {
            ticket_id,
            lane_id: lane_id.into(),
            challenge_id: challenge_id.into(),
            proof_kind,
            status: TicketStatus::Queued,
            opened_slot,
            deadline_slot: config.ticket_deadline_slot(opened_slot),
            target_prefetch_ms: config.target_prefetch_ms,
            estimated_units,
            max_fee_micro_units,
            scheduled_fee_micro_units,
            low_fee_credit_id: None,
            priority_score,
            challenger_commitment: redact("challenger", challenger_secret),
            disputed_state_root: disputed_state_root.into(),
            expected_witness_root: empty_root(D_SHARDS),
            metadata,
            shard_ids: BTreeSet::new(),
            attestation_ids: BTreeSet::new(),
            fence_id: None,
        }
    }

    pub fn low_fee(&self, config: &Config) -> bool {
        self.scheduled_fee_micro_units
            <= sat_bps(self.max_fee_micro_units, config.low_fee_target_bps).max(1)
            || self.proof_kind == FraudProofKind::LowFeeBatch
            || self.low_fee_credit_id.is_some()
    }

    pub fn expired(&self, slot: u64) -> bool {
        slot > self.deadline_slot
            && !matches!(
                self.status,
                TicketStatus::Ready | TicketStatus::Published | TicketStatus::Challenged
            )
    }
    pub fn attach_shard(&mut self, shard_id: impl Into<String>) {
        self.shard_ids.insert(shard_id.into());
        if !self.shard_ids.is_empty() && self.status < TicketStatus::Sharded {
            self.status = TicketStatus::Sharded;
        }
    }
    pub fn attach_attestation(&mut self, attestation_id: impl Into<String>) {
        self.attestation_ids.insert(attestation_id.into());
    }
    pub fn mark_ready(&mut self, witness_root: impl Into<String>) {
        self.expected_witness_root = witness_root.into();
        self.status = TicketStatus::Ready;
    }
    pub fn root(&self) -> String {
        hash_json(D_TICKETS, &self.public_record())
    }
    pub fn public_record(&self) -> Value {
        json!({
            "ticket_id": self.ticket_id, "lane_id": self.lane_id, "challenge_id": self.challenge_id, "proof_kind": self.proof_kind.as_str(),
            "status": self.status.as_str(), "opened_slot": self.opened_slot, "deadline_slot": self.deadline_slot, "target_prefetch_ms": self.target_prefetch_ms,
            "estimated_units": self.estimated_units, "max_fee_micro_units": self.max_fee_micro_units, "scheduled_fee_micro_units": self.scheduled_fee_micro_units,
            "low_fee_credit_id": self.low_fee_credit_id, "priority_score": self.priority_score, "challenger_commitment": self.challenger_commitment,
            "disputed_state_root": self.disputed_state_root, "expected_witness_root": self.expected_witness_root, "metadata": self.metadata.public_record(),
            "shard_ids": self.shard_ids.iter().cloned().collect::<Vec<_>>(), "attestation_ids": self.attestation_ids.iter().cloned().collect::<Vec<_>>(), "fence_id": self.fence_id,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqChallengerAttestation {
    pub attestation_id: String,
    pub ticket_id: String,
    pub challenger_commitment: String,
    pub suite: String,
    pub pq_public_key_commitment: String,
    pub signature_commitment: String,
    pub transcript_root: String,
    pub witness_claim_root: String,
    pub quorum_weight_bps: u64,
    pub opened_slot: u64,
    pub deadline_slot: u64,
    pub status: AttestationStatus,
}

impl PqChallengerAttestation {
    pub fn new(
        attestation_id: impl Into<String>,
        ticket: &PrefetchTicket,
        pq_public_key: &str,
        signature: &str,
        opened_slot: u64,
        config: &Config,
    ) -> Self {
        let attestation_id = attestation_id.into();
        let pq_public_key_commitment = redact("pq_public_key", pq_public_key);
        let signature_commitment = redact("pq_signature", signature);
        let transcript_root = hash_json(
            D_ATTESTATIONS,
            &json!({"ticket_id": ticket.ticket_id, "challenge_id": ticket.challenge_id, "challenger_commitment": ticket.challenger_commitment, "pq_public_key_commitment": pq_public_key_commitment, "signature_commitment": signature_commitment, "suite": PQ_CHALLENGER_ATTESTATION_SUITE}),
        );
        Self {
            attestation_id,
            ticket_id: ticket.ticket_id.clone(),
            challenger_commitment: ticket.challenger_commitment.clone(),
            suite: PQ_CHALLENGER_ATTESTATION_SUITE.to_string(),
            pq_public_key_commitment,
            signature_commitment,
            transcript_root,
            witness_claim_root: ticket.expected_witness_root.clone(),
            quorum_weight_bps: 0,
            opened_slot,
            deadline_slot: config.attestation_deadline_slot(opened_slot),
            status: AttestationStatus::Submitted,
        }
    }
    pub fn accept(&mut self, quorum_weight_bps: u64, config: &Config) {
        self.quorum_weight_bps = clamp_bps(quorum_weight_bps);
        self.status = if self.quorum_weight_bps >= config.quorum_weight_bps {
            AttestationStatus::Accepted
        } else {
            AttestationStatus::QuorumPending
        };
    }
    pub fn root(&self) -> String {
        hash_json(D_ATTESTATIONS, &self.public_record())
    }
    pub fn public_record(&self) -> Value {
        json!({"attestation_id": self.attestation_id, "ticket_id": self.ticket_id, "challenger_commitment": self.challenger_commitment, "suite": self.suite, "pq_public_key_commitment": self.pq_public_key_commitment, "signature_commitment": self.signature_commitment, "transcript_root": self.transcript_root, "witness_claim_root": self.witness_claim_root, "quorum_weight_bps": self.quorum_weight_bps, "opened_slot": self.opened_slot, "deadline_slot": self.deadline_slot, "status": self.status.as_str()})
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ParallelWitnessShard {
    pub shard_id: String,
    pub ticket_id: String,
    pub lane_id: String,
    pub shard_index: u16,
    pub shard_count: u16,
    pub status: ShardStatus,
    pub opened_slot: u64,
    pub deadline_slot: u64,
    pub byte_len: u64,
    pub compute_units: u64,
    pub metadata_root: String,
    pub encrypted_blob_commitment: String,
    pub local_witness_root: String,
    pub prefetch_worker_commitment: String,
}

impl ParallelWitnessShard {
    pub fn new(
        shard_id: impl Into<String>,
        ticket: &PrefetchTicket,
        shard_index: u16,
        shard_count: u16,
        byte_len: u64,
        compute_units: u64,
        worker_secret: &str,
        opened_slot: u64,
        config: &Config,
    ) -> Self {
        let shard_id = shard_id.into();
        let encrypted_blob_commitment = redact(
            "encrypted_blob",
            &format!("{}:{}:{}", ticket.ticket_id, shard_index, worker_secret),
        );
        let metadata_root = hash_json(D_SHARDS, &ticket.metadata.public_record());
        let local_witness_root = hash_json(
            D_SHARDS,
            &json!({"suite": PARALLEL_SHARD_ROOT_SUITE, "ticket_id": ticket.ticket_id, "shard_index": shard_index, "shard_count": shard_count, "byte_len": byte_len, "compute_units": compute_units, "metadata_root": metadata_root, "encrypted_blob_commitment": encrypted_blob_commitment}),
        );
        Self {
            shard_id,
            ticket_id: ticket.ticket_id.clone(),
            lane_id: ticket.lane_id.clone(),
            shard_index,
            shard_count,
            status: ShardStatus::Requested,
            opened_slot,
            deadline_slot: config.shard_deadline_slot(opened_slot),
            byte_len,
            compute_units,
            metadata_root,
            encrypted_blob_commitment,
            local_witness_root,
            prefetch_worker_commitment: redact("prefetch_worker", worker_secret),
        }
    }
    pub fn mark_warmed(&mut self) {
        self.status = ShardStatus::Warmed;
    }
    pub fn mark_sealed(&mut self) {
        self.status = ShardStatus::Sealed;
    }
    pub fn root(&self) -> String {
        hash_json(D_SHARDS, &self.public_record())
    }
    pub fn public_record(&self) -> Value {
        json!({"shard_id": self.shard_id, "ticket_id": self.ticket_id, "lane_id": self.lane_id, "shard_index": self.shard_index, "shard_count": self.shard_count, "status": self.status.as_str(), "opened_slot": self.opened_slot, "deadline_slot": self.deadline_slot, "byte_len": self.byte_len, "compute_units": self.compute_units, "metadata_root": self.metadata_root, "encrypted_blob_commitment": self.encrypted_blob_commitment, "local_witness_root": self.local_witness_root, "prefetch_worker_commitment": self.prefetch_worker_commitment})
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct InvalidationFence {
    pub fence_id: String,
    pub ticket_id: String,
    pub lane_id: String,
    pub status: FenceStatus,
    pub opened_slot: u64,
    pub deadline_slot: u64,
    pub invalid_before_slot: u64,
    pub disputed_state_root: String,
    pub invalidation_reason_commitment: String,
    pub affected_shard_root: String,
    pub challenger_attestation_root: String,
    pub fence_root: String,
}

impl InvalidationFence {
    pub fn new(
        fence_id: impl Into<String>,
        ticket: &PrefetchTicket,
        reason: &str,
        invalid_before_slot: u64,
        opened_slot: u64,
        config: &Config,
    ) -> Self {
        let fence_id = fence_id.into();
        let invalidation_reason_commitment = redact("invalidation_reason", reason);
        let affected_shard_root = root_from_values(
            D_SHARDS,
            ticket.shard_ids.iter().map(|id| json!(id)).collect(),
        );
        let challenger_attestation_root = root_from_values(
            D_ATTESTATIONS,
            ticket.attestation_ids.iter().map(|id| json!(id)).collect(),
        );
        let fence_root = hash_json(
            D_FENCES,
            &json!({"suite": INVALIDATION_FENCE_SUITE, "fence_id": fence_id, "ticket_id": ticket.ticket_id, "disputed_state_root": ticket.disputed_state_root, "reason": invalidation_reason_commitment, "affected_shard_root": affected_shard_root, "challenger_attestation_root": challenger_attestation_root}),
        );
        Self {
            fence_id,
            ticket_id: ticket.ticket_id.clone(),
            lane_id: ticket.lane_id.clone(),
            status: FenceStatus::Active,
            opened_slot,
            deadline_slot: config.fence_deadline_slot(opened_slot),
            invalid_before_slot,
            disputed_state_root: ticket.disputed_state_root.clone(),
            invalidation_reason_commitment,
            affected_shard_root,
            challenger_attestation_root,
            fence_root,
        }
    }
    pub fn matches_ticket(&self, ticket: &PrefetchTicket) -> bool {
        self.ticket_id == ticket.ticket_id && self.disputed_state_root == ticket.disputed_state_root
    }
    pub fn root(&self) -> String {
        hash_json(D_FENCES, &self.public_record())
    }
    pub fn public_record(&self) -> Value {
        json!({"fence_id": self.fence_id, "ticket_id": self.ticket_id, "lane_id": self.lane_id, "status": self.status.as_str(), "opened_slot": self.opened_slot, "deadline_slot": self.deadline_slot, "invalid_before_slot": self.invalid_before_slot, "disputed_state_root": self.disputed_state_root, "invalidation_reason_commitment": self.invalidation_reason_commitment, "affected_shard_root": self.affected_shard_root, "challenger_attestation_root": self.challenger_attestation_root, "fence_root": self.fence_root})
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LowFeeProofCredit {
    pub credit_id: String,
    pub owner_commitment: String,
    pub ticket_id: Option<String>,
    pub status: CreditStatus,
    pub minted_slot: u64,
    pub deadline_slot: u64,
    pub asset_id: String,
    pub face_value_micro_units: u64,
    pub applied_value_micro_units: u64,
    pub rebate_bps: u64,
    pub priority_boost: u64,
    pub credit_root: String,
}

impl LowFeeProofCredit {
    pub fn mint(
        credit_id: impl Into<String>,
        owner_secret: &str,
        face_value_micro_units: u64,
        minted_slot: u64,
        config: &Config,
    ) -> Self {
        let credit_id = credit_id.into();
        let owner_commitment = redact("credit_owner", owner_secret);
        let rebate_bps = config.credit_rebate_bps;
        let priority_boost = sat_bps(face_value_micro_units, rebate_bps).min(1_000);
        let credit_root = hash_json(
            D_CREDITS,
            &json!({"suite": LOW_FEE_CREDIT_SUITE, "credit_id": credit_id, "owner_commitment": owner_commitment, "face_value_micro_units": face_value_micro_units, "rebate_bps": rebate_bps, "priority_boost": priority_boost}),
        );
        Self {
            credit_id,
            owner_commitment,
            ticket_id: None,
            status: CreditStatus::Minted,
            minted_slot,
            deadline_slot: config.credit_deadline_slot(minted_slot),
            asset_id: config.credit_asset_id.clone(),
            face_value_micro_units,
            applied_value_micro_units: 0,
            rebate_bps,
            priority_boost,
            credit_root,
        }
    }
    pub fn apply_to_ticket(&mut self, ticket: &mut PrefetchTicket) -> u64 {
        let discount = sat_bps(ticket.scheduled_fee_micro_units, self.rebate_bps)
            .min(self.face_value_micro_units);
        ticket.scheduled_fee_micro_units = ticket
            .scheduled_fee_micro_units
            .saturating_sub(discount)
            .max(1);
        ticket.priority_score = ticket.priority_score.saturating_add(self.priority_boost);
        ticket.low_fee_credit_id = Some(self.credit_id.clone());
        self.ticket_id = Some(ticket.ticket_id.clone());
        self.applied_value_micro_units = discount;
        self.status = CreditStatus::Applied;
        discount
    }
    pub fn root(&self) -> String {
        hash_json(D_CREDITS, &self.public_record())
    }
    pub fn public_record(&self) -> Value {
        json!({"credit_id": self.credit_id, "owner_commitment": self.owner_commitment, "ticket_id": self.ticket_id, "status": self.status.as_str(), "minted_slot": self.minted_slot, "deadline_slot": self.deadline_slot, "asset_id": self.asset_id, "face_value_micro_units": self.face_value_micro_units, "applied_value_micro_units": self.applied_value_micro_units, "rebate_bps": self.rebate_bps, "priority_boost": self.priority_boost, "credit_root": self.credit_root})
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OperatorSummary {
    pub summary_id: String,
    pub operator_id: String,
    pub status: SummaryStatus,
    pub slot: u64,
    pub lane_count: u64,
    pub ticket_count: u64,
    pub ready_ticket_count: u64,
    pub invalidated_ticket_count: u64,
    pub sealed_shard_count: u64,
    pub accepted_attestation_count: u64,
    pub low_fee_credit_count: u64,
    pub average_prefetch_ms: u64,
    pub fee_scheduled_micro_units: u64,
    pub fee_rebated_micro_units: u64,
    pub slash_exposure_micro_units: u64,
    pub redacted_operator_root: String,
}

impl OperatorSummary {
    pub fn from_state(
        summary_id: impl Into<String>,
        operator_id: impl Into<String>,
        slot: u64,
        state: &State,
    ) -> Self {
        let operator_id = operator_id.into();
        let lanes = state
            .lanes
            .values()
            .filter(|lane| lane.operator_id == operator_id)
            .collect::<Vec<_>>();
        let lane_ids = lanes
            .iter()
            .map(|lane| lane.lane_id.clone())
            .collect::<BTreeSet<_>>();
        let tickets = state
            .tickets
            .values()
            .filter(|ticket| lane_ids.contains(&ticket.lane_id))
            .collect::<Vec<_>>();
        let ticket_ids = tickets
            .iter()
            .map(|ticket| ticket.ticket_id.clone())
            .collect::<BTreeSet<_>>();
        let ready_ticket_count = tickets
            .iter()
            .filter(|ticket| ticket.status == TicketStatus::Ready)
            .count() as u64;
        let invalidated_ticket_count = tickets
            .iter()
            .filter(|ticket| ticket.status == TicketStatus::Invalidated)
            .count() as u64;
        let sealed_shard_count = state
            .shards
            .values()
            .filter(|shard| {
                ticket_ids.contains(&shard.ticket_id) && shard.status == ShardStatus::Sealed
            })
            .count() as u64;
        let accepted_attestation_count = state
            .attestations
            .values()
            .filter(|att| {
                ticket_ids.contains(&att.ticket_id) && att.status == AttestationStatus::Accepted
            })
            .count() as u64;
        let low_fee_credit_count = state
            .credits
            .values()
            .filter(|credit| {
                credit
                    .ticket_id
                    .as_ref()
                    .is_some_and(|id| ticket_ids.contains(id))
            })
            .count() as u64;
        let average_prefetch_ms = if tickets.is_empty() {
            0
        } else {
            tickets
                .iter()
                .map(|ticket| ticket.target_prefetch_ms)
                .sum::<u64>()
                / tickets.len() as u64
        };
        let fee_scheduled_micro_units = tickets
            .iter()
            .map(|ticket| ticket.scheduled_fee_micro_units)
            .sum::<u64>();
        let fee_rebated_micro_units = state
            .credits
            .values()
            .filter(|credit| {
                credit
                    .ticket_id
                    .as_ref()
                    .is_some_and(|id| ticket_ids.contains(id))
            })
            .map(|credit| credit.applied_value_micro_units)
            .sum::<u64>();
        let slash_exposure_micro_units = lanes
            .iter()
            .map(|lane| sat_bps(lane.operator_bond_micro_units, state.config.slash_bps))
            .sum::<u64>();
        let summary_id = summary_id.into();
        let redacted_operator_root = hash_json(
            D_SUMMARIES,
            &json!({"suite": OPERATOR_SUMMARY_SUITE, "summary_id": summary_id, "operator_id": operator_id, "slot": slot, "lane_count": lanes.len(), "ticket_count": tickets.len(), "ready_ticket_count": ready_ticket_count, "invalidated_ticket_count": invalidated_ticket_count, "sealed_shard_count": sealed_shard_count, "accepted_attestation_count": accepted_attestation_count, "low_fee_credit_count": low_fee_credit_count}),
        );
        Self {
            summary_id,
            operator_id,
            status: SummaryStatus::Published,
            slot,
            lane_count: lanes.len() as u64,
            ticket_count: tickets.len() as u64,
            ready_ticket_count,
            invalidated_ticket_count,
            sealed_shard_count,
            accepted_attestation_count,
            low_fee_credit_count,
            average_prefetch_ms,
            fee_scheduled_micro_units,
            fee_rebated_micro_units,
            slash_exposure_micro_units,
            redacted_operator_root,
        }
    }
    pub fn root(&self) -> String {
        hash_json(D_SUMMARIES, &self.public_record())
    }
    pub fn public_record(&self) -> Value {
        json!({"summary_id": self.summary_id, "operator_id": self.operator_id, "status": self.status.as_str(), "slot": self.slot, "lane_count": self.lane_count, "ticket_count": self.ticket_count, "ready_ticket_count": self.ready_ticket_count, "invalidated_ticket_count": self.invalidated_ticket_count, "sealed_shard_count": self.sealed_shard_count, "accepted_attestation_count": self.accepted_attestation_count, "low_fee_credit_count": self.low_fee_credit_count, "average_prefetch_ms": self.average_prefetch_ms, "fee_scheduled_micro_units": self.fee_scheduled_micro_units, "fee_rebated_micro_units": self.fee_rebated_micro_units, "slash_exposure_micro_units": self.slash_exposure_micro_units, "redacted_operator_root": self.redacted_operator_root})
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublicEvent {
    pub event_id: String,
    pub slot: u64,
    pub kind: String,
    pub subject_id: String,
    pub commitment: String,
}

impl PublicEvent {
    pub fn new(
        event_id: impl Into<String>,
        slot: u64,
        kind: impl Into<String>,
        subject_id: impl Into<String>,
        payload: &Value,
    ) -> Self {
        let event_id = event_id.into();
        let kind = kind.into();
        let subject_id = subject_id.into();
        let commitment = hash_json(
            D_EVENTS,
            &json!({"event_id": event_id, "slot": slot, "kind": kind, "subject_id": subject_id, "payload": payload}),
        );
        Self {
            event_id,
            slot,
            kind,
            subject_id,
            commitment,
        }
    }
    pub fn public_record(&self) -> Value {
        json!({"event_id": self.event_id, "slot": self.slot, "kind": self.kind, "subject_id": self.subject_id, "commitment": self.commitment})
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub lanes: BTreeMap<String, FraudProofLane>,
    pub tickets: BTreeMap<String, PrefetchTicket>,
    pub attestations: BTreeMap<String, PqChallengerAttestation>,
    pub shards: BTreeMap<String, ParallelWitnessShard>,
    pub fences: BTreeMap<String, InvalidationFence>,
    pub credits: BTreeMap<String, LowFeeProofCredit>,
    pub summaries: BTreeMap<String, OperatorSummary>,
    pub events: VecDeque<PublicEvent>,
}

impl State {
    pub fn new(config: Config) -> Result<Self> {
        config.validate()?;
        let mut state = Self {
            config,
            counters: Counters::default(),
            roots: Roots::empty(),
            lanes: BTreeMap::new(),
            tickets: BTreeMap::new(),
            attestations: BTreeMap::new(),
            shards: BTreeMap::new(),
            fences: BTreeMap::new(),
            credits: BTreeMap::new(),
            summaries: BTreeMap::new(),
            events: VecDeque::new(),
        };
        state.recompute_roots();
        Ok(state)
    }
    pub fn devnet() -> Self {
        let mut state = Self::new(Config::devnet()).expect("devnet config is valid");
        state.install_devnet_fixtures();
        state
    }
    pub fn demo() -> Self {
        let mut state = Self::devnet();
        let _ = state.mint_low_fee_credit(
            "credit-demo-003",
            "demo-credit-owner-003",
            72_000,
            DEVNET_EPOCH + 18,
        );
        let _ = state.queue_ticket(
            "ticket-demo-003",
            "lane-low-fee-001",
            "challenge-low-fee-003",
            FraudProofKind::LowFeeBatch,
            DEVNET_EPOCH + 19,
            180,
            45_000,
            "demo-challenger-003",
            "state-root-demo-low-fee-003",
            PrivacyWitnessMetadata::redacted(
                "metadata-demo-003",
                "viewtag-demo-003",
                "nullifier-demo-003",
                "shard-hint-demo-003",
                "access-demo-003",
                DEFAULT_TARGET_PRIVACY_SET_SIZE,
                DEVNET_EPOCH,
            ),
        );
        let _ = state.apply_credit("credit-demo-003", "ticket-demo-003");
        let _ = state.submit_attestation(
            "att-demo-003",
            "ticket-demo-003",
            "pq-key-demo-003",
            "pq-sig-demo-003",
            DEVNET_EPOCH + 20,
            8_100,
        );
        let _ = state.prefetch_ticket_shards(
            "ticket-demo-003",
            4,
            512 * 1024,
            "worker-demo-003",
            DEVNET_EPOCH + 21,
        );
        let _ = state.seal_ticket("ticket-demo-003");
        let _ = state.publish_operator_summary(
            "summary-operator-c-demo",
            "operator-c",
            DEVNET_EPOCH + 22,
        );
        state
    }
    fn install_devnet_fixtures(&mut self) {
        let _ = self.open_lane(
            "lane-hot-001",
            "operator-a",
            LaneClass::HotDispute,
            DEVNET_EPOCH,
            18_000,
        );
        let _ = self.open_lane(
            "lane-bridge-001",
            "operator-b",
            LaneClass::MoneroBridge,
            DEVNET_EPOCH + 1,
            12_000,
        );
        let _ = self.open_lane(
            "lane-low-fee-001",
            "operator-c",
            LaneClass::LowFeeBulk,
            DEVNET_EPOCH + 2,
            24_000,
        );
        let metadata_a = PrivacyWitnessMetadata::redacted(
            "metadata-devnet-001",
            "viewtag-a",
            "nullifier-set-a",
            "state-shard-a",
            "access-a",
            DEFAULT_TARGET_PRIVACY_SET_SIZE,
            DEVNET_EPOCH,
        );
        let metadata_b = PrivacyWitnessMetadata::redacted(
            "metadata-devnet-002",
            "viewtag-b",
            "nullifier-set-b",
            "bridge-shard-b",
            "access-b",
            DEFAULT_TARGET_PRIVACY_SET_SIZE * 2,
            DEVNET_EPOCH + 1,
        );
        let _ = self.queue_ticket(
            "ticket-hot-001",
            "lane-hot-001",
            "challenge-state-001",
            FraudProofKind::StateTransition,
            DEVNET_EPOCH + 3,
            900,
            180_000,
            "challenger-a",
            "state-root-a",
            metadata_a,
        );
        let _ = self.queue_ticket(
            "ticket-bridge-001",
            "lane-bridge-001",
            "challenge-bridge-001",
            FraudProofKind::InvalidWithdrawal,
            DEVNET_EPOCH + 4,
            700,
            150_000,
            "challenger-b",
            "state-root-b",
            metadata_b,
        );
        let _ = self.mint_low_fee_credit(
            "credit-devnet-001",
            "credit-owner-a",
            50_000,
            DEVNET_EPOCH + 5,
        );
        let _ = self.apply_credit("credit-devnet-001", "ticket-bridge-001");
        let _ = self.submit_attestation(
            "att-hot-001",
            "ticket-hot-001",
            "pq-key-a",
            "pq-sig-a",
            DEVNET_EPOCH + 6,
            7_200,
        );
        let _ = self.submit_attestation(
            "att-bridge-001",
            "ticket-bridge-001",
            "pq-key-b",
            "pq-sig-b",
            DEVNET_EPOCH + 7,
            8_300,
        );
        let _ = self.prefetch_ticket_shards(
            "ticket-hot-001",
            8,
            768 * 1024,
            "worker-a",
            DEVNET_EPOCH + 8,
        );
        let _ = self.prefetch_ticket_shards(
            "ticket-bridge-001",
            6,
            640 * 1024,
            "worker-b",
            DEVNET_EPOCH + 9,
        );
        let _ = self.seal_ticket("ticket-hot-001");
        let _ = self.activate_fence(
            "fence-bridge-001",
            "ticket-bridge-001",
            "stale-monero-header",
            DEVNET_EPOCH + 6,
            DEVNET_EPOCH + 10,
        );
        let _ = self.invalidate_ticket("ticket-bridge-001", "fence-bridge-001", DEVNET_EPOCH + 11);
        let _ = self.publish_operator_summary(
            "summary-operator-a-devnet",
            "operator-a",
            DEVNET_EPOCH + 12,
        );
        let _ = self.publish_operator_summary(
            "summary-operator-b-devnet",
            "operator-b",
            DEVNET_EPOCH + 13,
        );
        self.recompute_roots();
    }

    pub fn open_lane(
        &mut self,
        lane_id: impl Into<String>,
        operator_id: impl Into<String>,
        class: LaneClass,
        opened_slot: u64,
        capacity_units: u64,
    ) -> Result<String> {
        ensure!(
            self.lanes.len() < self.config.max_lanes,
            "lane limit reached"
        );
        let lane_id = lane_id.into();
        ensure!(!self.lanes.contains_key(&lane_id), "lane already exists");
        let lane = FraudProofLane::new(
            lane_id.clone(),
            operator_id,
            class,
            opened_slot,
            capacity_units,
            &self.config,
        );
        self.lanes.insert(lane_id.clone(), lane);
        self.counters.lanes_opened = self.counters.lanes_opened.saturating_add(1);
        self.record_event(
            opened_slot,
            "lane_opened",
            &lane_id,
            &json!({"class": class.as_str(), "capacity_units": capacity_units}),
        );
        self.recompute_roots();
        Ok(lane_id)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn queue_ticket(
        &mut self,
        ticket_id: impl Into<String>,
        lane_id: impl Into<String>,
        challenge_id: impl Into<String>,
        proof_kind: FraudProofKind,
        opened_slot: u64,
        estimated_units: u64,
        max_fee_micro_units: u64,
        challenger_secret: &str,
        disputed_state_root: impl Into<String>,
        metadata: PrivacyWitnessMetadata,
    ) -> Result<String> {
        ensure!(
            self.tickets.len() < self.config.max_tickets,
            "ticket limit reached"
        );
        ensure!(
            metadata.privacy_set_size >= self.config.min_privacy_set_size,
            "metadata privacy set below minimum"
        );
        let ticket_id = ticket_id.into();
        ensure!(
            !self.tickets.contains_key(&ticket_id),
            "ticket already exists"
        );
        let lane_id = lane_id.into();
        let lane = self
            .lanes
            .get_mut(&lane_id)
            .ok_or_else(|| format!("unknown lane {lane_id}"))?;
        lane.reserve_units(estimated_units, opened_slot)?;
        let ticket = PrefetchTicket::new(
            ticket_id.clone(),
            lane_id,
            challenge_id,
            proof_kind,
            opened_slot,
            estimated_units,
            max_fee_micro_units,
            challenger_secret,
            disputed_state_root,
            metadata,
            &self.config,
        );
        self.counters.tickets_queued = self.counters.tickets_queued.saturating_add(1);
        self.counters.tickets_reserved = self.counters.tickets_reserved.saturating_add(1);
        self.counters.fee_micro_units_scheduled = self
            .counters
            .fee_micro_units_scheduled
            .saturating_add(ticket.scheduled_fee_micro_units);
        self.counters.metadata_commitments_recorded = self
            .counters
            .metadata_commitments_recorded
            .saturating_add(1);
        self.tickets.insert(ticket_id.clone(), ticket);
        self.record_event(
            opened_slot,
            "ticket_queued",
            &ticket_id,
            &json!({"proof_kind": proof_kind.as_str(), "estimated_units": estimated_units}),
        );
        self.recompute_roots();
        Ok(ticket_id)
    }

    pub fn mint_low_fee_credit(
        &mut self,
        credit_id: impl Into<String>,
        owner_secret: &str,
        face_value_micro_units: u64,
        minted_slot: u64,
    ) -> Result<String> {
        ensure!(
            self.credits.len() < self.config.max_credits,
            "credit limit reached"
        );
        let credit_id = credit_id.into();
        ensure!(
            !self.credits.contains_key(&credit_id),
            "credit already exists"
        );
        let credit = LowFeeProofCredit::mint(
            credit_id.clone(),
            owner_secret,
            face_value_micro_units,
            minted_slot,
            &self.config,
        );
        self.credits.insert(credit_id.clone(), credit);
        self.counters.low_fee_credits_minted =
            self.counters.low_fee_credits_minted.saturating_add(1);
        self.record_event(
            minted_slot,
            "low_fee_credit_minted",
            &credit_id,
            &json!({"face_value_micro_units": face_value_micro_units}),
        );
        self.recompute_roots();
        Ok(credit_id)
    }

    pub fn apply_credit(&mut self, credit_id: &str, ticket_id: &str) -> Result<u64> {
        let ticket = self
            .tickets
            .get_mut(ticket_id)
            .ok_or_else(|| format!("unknown ticket {ticket_id}"))?;
        let opened_slot = ticket.opened_slot;
        let credit = self
            .credits
            .get_mut(credit_id)
            .ok_or_else(|| format!("unknown credit {credit_id}"))?;
        ensure!(
            matches!(credit.status, CreditStatus::Minted | CreditStatus::Reserved),
            "credit cannot be applied"
        );
        let discount = credit.apply_to_ticket(ticket);
        self.counters.low_fee_credits_applied =
            self.counters.low_fee_credits_applied.saturating_add(1);
        self.counters.fee_micro_units_rebated = self
            .counters
            .fee_micro_units_rebated
            .saturating_add(discount);
        self.record_event(
            opened_slot,
            "low_fee_credit_applied",
            ticket_id,
            &json!({"credit_id": credit_id, "discount": discount}),
        );
        self.recompute_roots();
        Ok(discount)
    }

    pub fn submit_attestation(
        &mut self,
        attestation_id: impl Into<String>,
        ticket_id: &str,
        pq_public_key: &str,
        signature: &str,
        opened_slot: u64,
        quorum_weight_bps: u64,
    ) -> Result<String> {
        ensure!(
            self.attestations.len() < self.config.max_attestations,
            "attestation limit reached"
        );
        let attestation_id = attestation_id.into();
        ensure!(
            !self.attestations.contains_key(&attestation_id),
            "attestation already exists"
        );
        let ticket = self
            .tickets
            .get_mut(ticket_id)
            .ok_or_else(|| format!("unknown ticket {ticket_id}"))?;
        let mut attestation = PqChallengerAttestation::new(
            attestation_id.clone(),
            ticket,
            pq_public_key,
            signature,
            opened_slot,
            &self.config,
        );
        attestation.accept(quorum_weight_bps, &self.config);
        ticket.attach_attestation(attestation_id.clone());
        self.counters.attestations_submitted =
            self.counters.attestations_submitted.saturating_add(1);
        if attestation.status == AttestationStatus::Accepted {
            self.counters.attestations_accepted =
                self.counters.attestations_accepted.saturating_add(1);
        }
        self.attestations
            .insert(attestation_id.clone(), attestation);
        self.record_event(
            opened_slot,
            "pq_challenger_attestation",
            ticket_id,
            &json!({"attestation_id": attestation_id, "quorum_weight_bps": quorum_weight_bps}),
        );
        self.recompute_roots();
        Ok(attestation_id)
    }

    pub fn prefetch_ticket_shards(
        &mut self,
        ticket_id: &str,
        shard_count: u16,
        bytes_per_shard: u64,
        worker_secret: &str,
        opened_slot: u64,
    ) -> Result<Vec<String>> {
        ensure!(shard_count > 0, "shard count must be non-zero");
        let ticket = self
            .tickets
            .get(ticket_id)
            .cloned()
            .ok_or_else(|| format!("unknown ticket {ticket_id}"))?;
        let mut ids = Vec::with_capacity(shard_count as usize);
        for shard_index in 0..shard_count {
            let shard_id = format!("{ticket_id}-shard-{shard_index:04}");
            let mut shard = ParallelWitnessShard::new(
                &shard_id,
                &ticket,
                shard_index,
                shard_count,
                bytes_per_shard,
                ticket.estimated_units / shard_count as u64 + 1,
                worker_secret,
                opened_slot,
                &self.config,
            );
            shard.mark_warmed();
            self.shards.insert(shard_id.clone(), shard);
            ids.push(shard_id);
            self.counters.shards_requested = self.counters.shards_requested.saturating_add(1);
            self.counters.shards_warmed = self.counters.shards_warmed.saturating_add(1);
        }
        let witness_root = root_from_values(
            D_SHARDS,
            ids.iter()
                .filter_map(|id| self.shards.get(id))
                .map(|shard| json!(shard.root()))
                .collect(),
        );
        if let Some(ticket) = self.tickets.get_mut(ticket_id) {
            for id in &ids {
                ticket.attach_shard(id.clone());
            }
            ticket.expected_witness_root = witness_root;
            ticket.status = TicketStatus::Prefetching;
        }
        self.record_event(
            opened_slot,
            "witness_shards_prefetched",
            ticket_id,
            &json!({"shard_count": shard_count}),
        );
        self.recompute_roots();
        Ok(ids)
    }

    pub fn seal_ticket(&mut self, ticket_id: &str) -> Result<String> {
        let shard_ids = self
            .tickets
            .get(ticket_id)
            .ok_or_else(|| format!("unknown ticket {ticket_id}"))?
            .shard_ids
            .iter()
            .cloned()
            .collect::<Vec<_>>();
        ensure!(!shard_ids.is_empty(), "ticket has no shards");
        for shard_id in &shard_ids {
            if let Some(shard) = self.shards.get_mut(shard_id) {
                shard.mark_sealed();
                self.counters.shards_sealed = self.counters.shards_sealed.saturating_add(1);
            }
        }
        let witness_root = root_from_values(
            D_SHARDS,
            shard_ids
                .iter()
                .filter_map(|id| self.shards.get(id))
                .map(|shard| json!(shard.root()))
                .collect(),
        );
        if let Some(ticket) = self.tickets.get_mut(ticket_id) {
            ticket.mark_ready(witness_root.clone());
            self.counters.tickets_ready = self.counters.tickets_ready.saturating_add(1);
        }
        self.record_event(
            self.config.epoch,
            "ticket_ready",
            ticket_id,
            &json!({"witness_root": witness_root}),
        );
        self.recompute_roots();
        Ok(witness_root)
    }

    pub fn activate_fence(
        &mut self,
        fence_id: impl Into<String>,
        ticket_id: &str,
        reason: &str,
        invalid_before_slot: u64,
        opened_slot: u64,
    ) -> Result<String> {
        let fence_id = fence_id.into();
        let ticket = self
            .tickets
            .get(ticket_id)
            .ok_or_else(|| format!("unknown ticket {ticket_id}"))?;
        let fence = InvalidationFence::new(
            fence_id.clone(),
            ticket,
            reason,
            invalid_before_slot,
            opened_slot,
            &self.config,
        );
        if let Some(ticket) = self.tickets.get_mut(ticket_id) {
            ticket.fence_id = Some(fence_id.clone());
        }
        self.fences.insert(fence_id.clone(), fence);
        self.counters.fences_activated = self.counters.fences_activated.saturating_add(1);
        self.record_event(
            opened_slot,
            "invalidation_fence_active",
            ticket_id,
            &json!({"fence_id": fence_id}),
        );
        self.recompute_roots();
        Ok(fence_id)
    }

    pub fn invalidate_ticket(&mut self, ticket_id: &str, fence_id: &str, slot: u64) -> Result<()> {
        let fence = self
            .fences
            .get_mut(fence_id)
            .ok_or_else(|| format!("unknown fence {fence_id}"))?;
        let ticket = self
            .tickets
            .get_mut(ticket_id)
            .ok_or_else(|| format!("unknown ticket {ticket_id}"))?;
        ensure!(fence.matches_ticket(ticket), "fence does not match ticket");
        fence.status = FenceStatus::Matched;
        ticket.status = TicketStatus::Invalidated;
        for shard_id in ticket.shard_ids.clone() {
            if let Some(shard) = self.shards.get_mut(&shard_id) {
                shard.status = ShardStatus::Invalidated;
            }
        }
        self.counters.fences_matched = self.counters.fences_matched.saturating_add(1);
        self.counters.tickets_invalidated = self.counters.tickets_invalidated.saturating_add(1);
        self.record_event(
            slot,
            "ticket_invalidated",
            ticket_id,
            &json!({"fence_id": fence_id}),
        );
        self.recompute_roots();
        Ok(())
    }

    pub fn publish_operator_summary(
        &mut self,
        summary_id: impl Into<String>,
        operator_id: impl Into<String>,
        slot: u64,
    ) -> Result<String> {
        let summary_id = summary_id.into();
        let summary = OperatorSummary::from_state(summary_id.clone(), operator_id, slot, self);
        self.summaries.insert(summary_id.clone(), summary);
        self.counters.operator_summaries_published =
            self.counters.operator_summaries_published.saturating_add(1);
        self.record_event(slot, "operator_summary_published", &summary_id, &json!({}));
        self.recompute_roots();
        Ok(summary_id)
    }

    pub fn low_fee_backlog(&self) -> Vec<&PrefetchTicket> {
        self.tickets
            .values()
            .filter(|ticket| ticket.low_fee(&self.config))
            .collect()
    }

    pub fn fraud_ready_tickets(&self) -> Vec<&PrefetchTicket> {
        self.tickets
            .values()
            .filter(|ticket| ticket.status == TicketStatus::Ready)
            .collect()
    }

    fn record_event(&mut self, slot: u64, kind: &str, subject_id: &str, payload: &Value) {
        let event_id = format!("event-{:012}-{:06}", slot, self.events.len());
        self.events
            .push_back(PublicEvent::new(event_id, slot, kind, subject_id, payload));
        self.counters.public_events_recorded =
            self.counters.public_events_recorded.saturating_add(1);
    }

    pub fn recompute_roots(&mut self) {
        let config_root = hash_json(D_CONFIG, &json!(self.config));
        let counter_root = hash_json(D_COUNTERS, &json!(self.counters));
        let lane_root = root_from_values(
            D_LANES,
            self.lanes
                .values()
                .map(FraudProofLane::public_record)
                .collect(),
        );
        let ticket_root = root_from_values(
            D_TICKETS,
            self.tickets
                .values()
                .map(PrefetchTicket::public_record)
                .collect(),
        );
        let attestation_root = root_from_values(
            D_ATTESTATIONS,
            self.attestations
                .values()
                .map(PqChallengerAttestation::public_record)
                .collect(),
        );
        let shard_root = root_from_values(
            D_SHARDS,
            self.shards
                .values()
                .map(ParallelWitnessShard::public_record)
                .collect(),
        );
        let fence_root = root_from_values(
            D_FENCES,
            self.fences
                .values()
                .map(InvalidationFence::public_record)
                .collect(),
        );
        let credit_root = root_from_values(
            D_CREDITS,
            self.credits
                .values()
                .map(LowFeeProofCredit::public_record)
                .collect(),
        );
        let summary_root = root_from_values(
            D_SUMMARIES,
            self.summaries
                .values()
                .map(OperatorSummary::public_record)
                .collect(),
        );
        let event_root = root_from_values(
            D_EVENTS,
            self.events.iter().map(PublicEvent::public_record).collect(),
        );
        let public_root = hash_json(
            D_STATE,
            &json!({"counter_root": counter_root, "lane_root": lane_root, "ticket_root": ticket_root, "attestation_root": attestation_root, "shard_root": shard_root, "fence_root": fence_root, "credit_root": credit_root, "summary_root": summary_root, "event_root": event_root}),
        );
        let state_root = hash_json(
            D_STATE,
            &json!({"config_root": config_root, "counter_root": counter_root, "lane_root": lane_root, "ticket_root": ticket_root, "attestation_root": attestation_root, "shard_root": shard_root, "fence_root": fence_root, "credit_root": credit_root, "summary_root": summary_root, "event_root": event_root, "public_root": public_root}),
        );
        self.roots = Roots {
            config_root,
            counter_root,
            lane_root,
            ticket_root,
            attestation_root,
            shard_root,
            fence_root,
            credit_root,
            summary_root,
            event_root,
            public_root,
            state_root,
        };
        self.counters.root_recomputations = self.counters.root_recomputations.saturating_add(1);
    }

    pub fn public_record(&self) -> Value {
        public_record(self)
    }

    pub fn state_root(&self) -> String {
        state_root(self)
    }
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn demo() -> State {
    State::demo()
}

pub fn public_record(state: &State) -> Value {
    json!({"protocol_version": state.config.protocol_version, "schema_version": state.config.schema_version, "chain_id": state.config.chain_id, "l2_network": state.config.l2_network, "monero_network": state.config.monero_network, "mode": state.config.mode.as_str(), "counters": state.counters.public_record(), "roots": state.roots.public_record(), "lane_count": state.lanes.len(), "ticket_count": state.tickets.len(), "attestation_count": state.attestations.len(), "shard_count": state.shards.len(), "fence_count": state.fences.len(), "credit_count": state.credits.len(), "summary_count": state.summaries.len(), "ready_ticket_count": state.fraud_ready_tickets().len(), "low_fee_backlog_count": state.low_fee_backlog().len()})
}

pub fn state_root(state: &State) -> String {
    hash_json(D_STATE, &public_record(state))
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DeterministicRootProbe {
    pub probe_id: String,
    pub domain: String,
    pub commitment: String,
}

impl DeterministicRootProbe {
    pub fn new(probe_id: impl Into<String>, domain: impl Into<String>, payload: &Value) -> Self {
        let domain = domain.into();
        Self {
            probe_id: probe_id.into(),
            commitment: hash_json(&domain, payload),
            domain,
        }
    }
}

// Generated-style lane capacity profiles keep fixture data explicit and deterministic.
pub const GENERATED_LANE_CAPACITY_PROFILE_001: (&str, LaneClass, u64, u64) =
    ("generated-lane-001", LaneClass::StateTransition, 8037, 501);
pub const GENERATED_LANE_CAPACITY_PROFILE_002: (&str, LaneClass, u64, u64) =
    ("generated-lane-002", LaneClass::MoneroBridge, 8074, 502);
pub const GENERATED_LANE_CAPACITY_PROFILE_003: (&str, LaneClass, u64, u64) = (
    "generated-lane-003",
    LaneClass::ContractInvariant,
    8111,
    503,
);
pub const GENERATED_LANE_CAPACITY_PROFILE_004: (&str, LaneClass, u64, u64) =
    ("generated-lane-004", LaneClass::Watchtower, 8148, 504);
pub const GENERATED_LANE_CAPACITY_PROFILE_005: (&str, LaneClass, u64, u64) =
    ("generated-lane-005", LaneClass::LowFeeBulk, 8185, 505);
pub const GENERATED_LANE_CAPACITY_PROFILE_006: (&str, LaneClass, u64, u64) =
    ("generated-lane-006", LaneClass::Backfill, 8222, 506);
pub const GENERATED_LANE_CAPACITY_PROFILE_007: (&str, LaneClass, u64, u64) =
    ("generated-lane-007", LaneClass::OperatorAudit, 8259, 507);
pub const GENERATED_LANE_CAPACITY_PROFILE_008: (&str, LaneClass, u64, u64) =
    ("generated-lane-008", LaneClass::HotDispute, 8296, 508);
pub const GENERATED_LANE_CAPACITY_PROFILE_009: (&str, LaneClass, u64, u64) =
    ("generated-lane-009", LaneClass::StateTransition, 8333, 509);
pub const GENERATED_LANE_CAPACITY_PROFILE_010: (&str, LaneClass, u64, u64) =
    ("generated-lane-010", LaneClass::MoneroBridge, 8370, 510);
pub const GENERATED_LANE_CAPACITY_PROFILE_011: (&str, LaneClass, u64, u64) = (
    "generated-lane-011",
    LaneClass::ContractInvariant,
    8407,
    511,
);
pub const GENERATED_LANE_CAPACITY_PROFILE_012: (&str, LaneClass, u64, u64) =
    ("generated-lane-012", LaneClass::Watchtower, 8444, 512);
pub const GENERATED_LANE_CAPACITY_PROFILE_013: (&str, LaneClass, u64, u64) =
    ("generated-lane-013", LaneClass::LowFeeBulk, 8481, 513);
pub const GENERATED_LANE_CAPACITY_PROFILE_014: (&str, LaneClass, u64, u64) =
    ("generated-lane-014", LaneClass::Backfill, 8518, 514);
pub const GENERATED_LANE_CAPACITY_PROFILE_015: (&str, LaneClass, u64, u64) =
    ("generated-lane-015", LaneClass::OperatorAudit, 8555, 515);
pub const GENERATED_LANE_CAPACITY_PROFILE_016: (&str, LaneClass, u64, u64) =
    ("generated-lane-016", LaneClass::HotDispute, 8592, 516);
pub const GENERATED_LANE_CAPACITY_PROFILE_017: (&str, LaneClass, u64, u64) =
    ("generated-lane-017", LaneClass::StateTransition, 8629, 517);
pub const GENERATED_LANE_CAPACITY_PROFILE_018: (&str, LaneClass, u64, u64) =
    ("generated-lane-018", LaneClass::MoneroBridge, 8666, 518);
pub const GENERATED_LANE_CAPACITY_PROFILE_019: (&str, LaneClass, u64, u64) = (
    "generated-lane-019",
    LaneClass::ContractInvariant,
    8703,
    519,
);

impl State {
    pub fn generated_prefetch_probe_001(&self) -> DeterministicRootProbe {
        DeterministicRootProbe::new(
            "generated-prefetch-probe-001",
            D_STATE,
            &json!({
                "protocol_version": PROTOCOL_VERSION,
                "lane_id": "lane-bridge-001",
                "proof_kind": FraudProofKind::DataAvailability.as_str(),
                "base_priority": FraudProofKind::DataAvailability.base_priority(),
                "default_shards": FraudProofKind::DataAvailability.default_shards(),
                "state_root": self.roots.state_root,
                "ticket_count": self.tickets.len(),
                "low_fee_backlog": self.low_fee_backlog().len(),
            }),
        )
    }

    pub fn generated_prefetch_probe_002(&self) -> DeterministicRootProbe {
        DeterministicRootProbe::new(
            "generated-prefetch-probe-002",
            D_STATE,
            &json!({
                "protocol_version": PROTOCOL_VERSION,
                "lane_id": "lane-low-fee-001",
                "proof_kind": FraudProofKind::InvalidWithdrawal.as_str(),
                "base_priority": FraudProofKind::InvalidWithdrawal.base_priority(),
                "default_shards": FraudProofKind::InvalidWithdrawal.default_shards(),
                "state_root": self.roots.state_root,
                "ticket_count": self.tickets.len(),
                "low_fee_backlog": self.low_fee_backlog().len(),
            }),
        )
    }

    pub fn generated_prefetch_probe_003(&self) -> DeterministicRootProbe {
        DeterministicRootProbe::new(
            "generated-prefetch-probe-003",
            D_STATE,
            &json!({
                "protocol_version": PROTOCOL_VERSION,
                "lane_id": "lane-hot-001",
                "proof_kind": FraudProofKind::DoubleSpendNullifier.as_str(),
                "base_priority": FraudProofKind::DoubleSpendNullifier.base_priority(),
                "default_shards": FraudProofKind::DoubleSpendNullifier.default_shards(),
                "state_root": self.roots.state_root,
                "ticket_count": self.tickets.len(),
                "low_fee_backlog": self.low_fee_backlog().len(),
            }),
        )
    }

    pub fn generated_prefetch_probe_004(&self) -> DeterministicRootProbe {
        DeterministicRootProbe::new(
            "generated-prefetch-probe-004",
            D_STATE,
            &json!({
                "protocol_version": PROTOCOL_VERSION,
                "lane_id": "lane-bridge-001",
                "proof_kind": FraudProofKind::SequencerEquivocation.as_str(),
                "base_priority": FraudProofKind::SequencerEquivocation.base_priority(),
                "default_shards": FraudProofKind::SequencerEquivocation.default_shards(),
                "state_root": self.roots.state_root,
                "ticket_count": self.tickets.len(),
                "low_fee_backlog": self.low_fee_backlog().len(),
            }),
        )
    }

    pub fn generated_prefetch_probe_005(&self) -> DeterministicRootProbe {
        DeterministicRootProbe::new(
            "generated-prefetch-probe-005",
            D_STATE,
            &json!({
                "protocol_version": PROTOCOL_VERSION,
                "lane_id": "lane-low-fee-001",
                "proof_kind": FraudProofKind::ContractInvariant.as_str(),
                "base_priority": FraudProofKind::ContractInvariant.base_priority(),
                "default_shards": FraudProofKind::ContractInvariant.default_shards(),
                "state_root": self.roots.state_root,
                "ticket_count": self.tickets.len(),
                "low_fee_backlog": self.low_fee_backlog().len(),
            }),
        )
    }

    pub fn generated_prefetch_probe_006(&self) -> DeterministicRootProbe {
        DeterministicRootProbe::new(
            "generated-prefetch-probe-006",
            D_STATE,
            &json!({
                "protocol_version": PROTOCOL_VERSION,
                "lane_id": "lane-hot-001",
                "proof_kind": FraudProofKind::BridgeReserve.as_str(),
                "base_priority": FraudProofKind::BridgeReserve.base_priority(),
                "default_shards": FraudProofKind::BridgeReserve.default_shards(),
                "state_root": self.roots.state_root,
                "ticket_count": self.tickets.len(),
                "low_fee_backlog": self.low_fee_backlog().len(),
            }),
        )
    }

    pub fn generated_prefetch_probe_007(&self) -> DeterministicRootProbe {
        DeterministicRootProbe::new(
            "generated-prefetch-probe-007",
            D_STATE,
            &json!({
                "protocol_version": PROTOCOL_VERSION,
                "lane_id": "lane-bridge-001",
                "proof_kind": FraudProofKind::OracleMiscompute.as_str(),
                "base_priority": FraudProofKind::OracleMiscompute.base_priority(),
                "default_shards": FraudProofKind::OracleMiscompute.default_shards(),
                "state_root": self.roots.state_root,
                "ticket_count": self.tickets.len(),
                "low_fee_backlog": self.low_fee_backlog().len(),
            }),
        )
    }

    pub fn generated_prefetch_probe_008(&self) -> DeterministicRootProbe {
        DeterministicRootProbe::new(
            "generated-prefetch-probe-008",
            D_STATE,
            &json!({
                "protocol_version": PROTOCOL_VERSION,
                "lane_id": "lane-low-fee-001",
                "proof_kind": FraudProofKind::EmergencyEscape.as_str(),
                "base_priority": FraudProofKind::EmergencyEscape.base_priority(),
                "default_shards": FraudProofKind::EmergencyEscape.default_shards(),
                "state_root": self.roots.state_root,
                "ticket_count": self.tickets.len(),
                "low_fee_backlog": self.low_fee_backlog().len(),
            }),
        )
    }

    pub fn generated_prefetch_probe_009(&self) -> DeterministicRootProbe {
        DeterministicRootProbe::new(
            "generated-prefetch-probe-009",
            D_STATE,
            &json!({
                "protocol_version": PROTOCOL_VERSION,
                "lane_id": "lane-hot-001",
                "proof_kind": FraudProofKind::LowFeeBatch.as_str(),
                "base_priority": FraudProofKind::LowFeeBatch.base_priority(),
                "default_shards": FraudProofKind::LowFeeBatch.default_shards(),
                "state_root": self.roots.state_root,
                "ticket_count": self.tickets.len(),
                "low_fee_backlog": self.low_fee_backlog().len(),
            }),
        )
    }

    pub fn generated_prefetch_probe_010(&self) -> DeterministicRootProbe {
        DeterministicRootProbe::new(
            "generated-prefetch-probe-010",
            D_STATE,
            &json!({
                "protocol_version": PROTOCOL_VERSION,
                "lane_id": "lane-bridge-001",
                "proof_kind": FraudProofKind::StateTransition.as_str(),
                "base_priority": FraudProofKind::StateTransition.base_priority(),
                "default_shards": FraudProofKind::StateTransition.default_shards(),
                "state_root": self.roots.state_root,
                "ticket_count": self.tickets.len(),
                "low_fee_backlog": self.low_fee_backlog().len(),
            }),
        )
    }

    pub fn generated_prefetch_probe_011(&self) -> DeterministicRootProbe {
        DeterministicRootProbe::new(
            "generated-prefetch-probe-011",
            D_STATE,
            &json!({
                "protocol_version": PROTOCOL_VERSION,
                "lane_id": "lane-low-fee-001",
                "proof_kind": FraudProofKind::DataAvailability.as_str(),
                "base_priority": FraudProofKind::DataAvailability.base_priority(),
                "default_shards": FraudProofKind::DataAvailability.default_shards(),
                "state_root": self.roots.state_root,
                "ticket_count": self.tickets.len(),
                "low_fee_backlog": self.low_fee_backlog().len(),
            }),
        )
    }

    pub fn generated_prefetch_probe_012(&self) -> DeterministicRootProbe {
        DeterministicRootProbe::new(
            "generated-prefetch-probe-012",
            D_STATE,
            &json!({
                "protocol_version": PROTOCOL_VERSION,
                "lane_id": "lane-hot-001",
                "proof_kind": FraudProofKind::InvalidWithdrawal.as_str(),
                "base_priority": FraudProofKind::InvalidWithdrawal.base_priority(),
                "default_shards": FraudProofKind::InvalidWithdrawal.default_shards(),
                "state_root": self.roots.state_root,
                "ticket_count": self.tickets.len(),
                "low_fee_backlog": self.low_fee_backlog().len(),
            }),
        )
    }

    pub fn generated_prefetch_probe_013(&self) -> DeterministicRootProbe {
        DeterministicRootProbe::new(
            "generated-prefetch-probe-013",
            D_STATE,
            &json!({
                "protocol_version": PROTOCOL_VERSION,
                "lane_id": "lane-bridge-001",
                "proof_kind": FraudProofKind::DoubleSpendNullifier.as_str(),
                "base_priority": FraudProofKind::DoubleSpendNullifier.base_priority(),
                "default_shards": FraudProofKind::DoubleSpendNullifier.default_shards(),
                "state_root": self.roots.state_root,
                "ticket_count": self.tickets.len(),
                "low_fee_backlog": self.low_fee_backlog().len(),
            }),
        )
    }

    pub fn generated_prefetch_probe_014(&self) -> DeterministicRootProbe {
        DeterministicRootProbe::new(
            "generated-prefetch-probe-014",
            D_STATE,
            &json!({
                "protocol_version": PROTOCOL_VERSION,
                "lane_id": "lane-low-fee-001",
                "proof_kind": FraudProofKind::SequencerEquivocation.as_str(),
                "base_priority": FraudProofKind::SequencerEquivocation.base_priority(),
                "default_shards": FraudProofKind::SequencerEquivocation.default_shards(),
                "state_root": self.roots.state_root,
                "ticket_count": self.tickets.len(),
                "low_fee_backlog": self.low_fee_backlog().len(),
            }),
        )
    }

    pub fn generated_prefetch_probe_015(&self) -> DeterministicRootProbe {
        DeterministicRootProbe::new(
            "generated-prefetch-probe-015",
            D_STATE,
            &json!({
                "protocol_version": PROTOCOL_VERSION,
                "lane_id": "lane-hot-001",
                "proof_kind": FraudProofKind::ContractInvariant.as_str(),
                "base_priority": FraudProofKind::ContractInvariant.base_priority(),
                "default_shards": FraudProofKind::ContractInvariant.default_shards(),
                "state_root": self.roots.state_root,
                "ticket_count": self.tickets.len(),
                "low_fee_backlog": self.low_fee_backlog().len(),
            }),
        )
    }

    pub fn generated_prefetch_probe_016(&self) -> DeterministicRootProbe {
        DeterministicRootProbe::new(
            "generated-prefetch-probe-016",
            D_STATE,
            &json!({
                "protocol_version": PROTOCOL_VERSION,
                "lane_id": "lane-bridge-001",
                "proof_kind": FraudProofKind::BridgeReserve.as_str(),
                "base_priority": FraudProofKind::BridgeReserve.base_priority(),
                "default_shards": FraudProofKind::BridgeReserve.default_shards(),
                "state_root": self.roots.state_root,
                "ticket_count": self.tickets.len(),
                "low_fee_backlog": self.low_fee_backlog().len(),
            }),
        )
    }

    pub fn generated_prefetch_probe_017(&self) -> DeterministicRootProbe {
        DeterministicRootProbe::new(
            "generated-prefetch-probe-017",
            D_STATE,
            &json!({
                "protocol_version": PROTOCOL_VERSION,
                "lane_id": "lane-low-fee-001",
                "proof_kind": FraudProofKind::OracleMiscompute.as_str(),
                "base_priority": FraudProofKind::OracleMiscompute.base_priority(),
                "default_shards": FraudProofKind::OracleMiscompute.default_shards(),
                "state_root": self.roots.state_root,
                "ticket_count": self.tickets.len(),
                "low_fee_backlog": self.low_fee_backlog().len(),
            }),
        )
    }

    pub fn generated_prefetch_probe_018(&self) -> DeterministicRootProbe {
        DeterministicRootProbe::new(
            "generated-prefetch-probe-018",
            D_STATE,
            &json!({
                "protocol_version": PROTOCOL_VERSION,
                "lane_id": "lane-hot-001",
                "proof_kind": FraudProofKind::EmergencyEscape.as_str(),
                "base_priority": FraudProofKind::EmergencyEscape.base_priority(),
                "default_shards": FraudProofKind::EmergencyEscape.default_shards(),
                "state_root": self.roots.state_root,
                "ticket_count": self.tickets.len(),
                "low_fee_backlog": self.low_fee_backlog().len(),
            }),
        )
    }

    pub fn generated_prefetch_probe_019(&self) -> DeterministicRootProbe {
        DeterministicRootProbe::new(
            "generated-prefetch-probe-019",
            D_STATE,
            &json!({
                "protocol_version": PROTOCOL_VERSION,
                "lane_id": "lane-bridge-001",
                "proof_kind": FraudProofKind::LowFeeBatch.as_str(),
                "base_priority": FraudProofKind::LowFeeBatch.base_priority(),
                "default_shards": FraudProofKind::LowFeeBatch.default_shards(),
                "state_root": self.roots.state_root,
                "ticket_count": self.tickets.len(),
                "low_fee_backlog": self.low_fee_backlog().len(),
            }),
        )
    }
}
