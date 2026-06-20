use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2FastPqConfidentialMicrobatchPreconfirmationRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_FAST_PQ_CONFIDENTIAL_MICROBATCH_PRECONFIRMATION_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-private-l2-fast-pq-confidential-microbatch-preconfirmation-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_FAST_PQ_CONFIDENTIAL_MICROBATCH_PRECONFIRMATION_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_ATTESTATION_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-microbatch-preconfirmation-v1";
pub const ENCRYPTED_LANE_SUITE: &str = "ml-kem-threshold-confidential-microbatch-lane-envelope-v1";
pub const SEQUENCING_SLOT_SUITE: &str =
    "fast-private-l2-deterministic-microbatch-sequencing-slot-v1";
pub const NULLIFIER_FENCE_SUITE: &str =
    "monero-private-l2-fast-microbatch-cancellation-nullifier-fence-v1";
pub const RECURSIVE_PROOF_HINT_SUITE: &str = "pq-confidential-microbatch-recursive-proof-hint-v1";
pub const FEE_REBATE_SUITE: &str = "low-fee-confidential-microbatch-rebate-v1";
pub const MAKER_RESERVATION_SUITE: &str = "private-l2-confidential-microbatch-maker-reservation-v1";
pub const VERIFIER_RECEIPT_SUITE: &str =
    "pq-confidential-microbatch-preconfirmation-verifier-receipt-v1";
pub const SLASHING_EVIDENCE_SUITE: &str =
    "pq-confidential-microbatch-preconfirmation-slashing-evidence-v1";
pub const DEVNET_L2_NETWORK: &str = "nebula-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_EPOCH: u64 = 19_456;
pub const DEVNET_L2_HEIGHT: u64 = 2_880_000;
pub const DEVNET_MONERO_HEIGHT: u64 = 3_420_000;
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEVNET_REBATE_ASSET_ID: &str = "piconero-devnet-rebate";
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 131_072;
pub const DEFAULT_TARGET_PRIVACY_SET_SIZE: u64 = 1_048_576;
pub const DEFAULT_SLOT_WIDTH_MS: u64 = 40;
pub const DEFAULT_TARGET_PRECONFIRMATION_MS: u64 = 120;
pub const DEFAULT_SOFT_LATENCY_MS: u64 = 180;
pub const DEFAULT_HARD_LATENCY_MS: u64 = 520;
pub const DEFAULT_MICROBATCH_MAX_ITEMS: u32 = 512;
pub const DEFAULT_MICROBATCH_MAX_BYTES: u64 = 1_048_576;
pub const DEFAULT_MICROBATCH_TTL_SLOTS: u64 = 16;
pub const DEFAULT_CANCELLATION_TTL_SLOTS: u64 = 32;
pub const DEFAULT_RECEIPT_TTL_SLOTS: u64 = 96;
pub const DEFAULT_REBATE_TTL_SLOTS: u64 = 256;
pub const DEFAULT_RESERVATION_TTL_SLOTS: u64 = 12;
pub const DEFAULT_PROOF_HINT_TTL_SLOTS: u64 = 64;
pub const DEFAULT_QUORUM_WEIGHT_BPS: u64 = 6_700;
pub const DEFAULT_SUPERMAJORITY_WEIGHT_BPS: u64 = 8_000;
pub const DEFAULT_MAKER_QUORUM_BPS: u64 = 6_000;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 14;
pub const DEFAULT_TARGET_REBATE_BPS: u64 = 8;
pub const DEFAULT_MAX_REBATE_BPS: u64 = 32;
pub const DEFAULT_MAKER_REBATE_BPS: u64 = 5;
pub const DEFAULT_QOS_REBATE_BPS: u64 = 4;
pub const DEFAULT_SLASH_BPS: u64 = 1_500;
pub const DEFAULT_MIN_COMMITTEE_BOND_MICRO_UNITS: u64 = 50_000_000;
pub const DEFAULT_MIN_SEQUENCER_BOND_MICRO_UNITS: u64 = 75_000_000;
pub const DEFAULT_MIN_MAKER_BOND_MICRO_UNITS: u64 = 10_000_000;
pub const DEFAULT_MAX_LANES: usize = 8_192;
pub const DEFAULT_MAX_MICROBATCHES: usize = 1_048_576;
pub const DEFAULT_MAX_SEQUENCING_SLOTS: usize = 2_097_152;
pub const DEFAULT_MAX_COMMITTEES: usize = 262_144;
pub const DEFAULT_MAX_ATTESTATIONS: usize = 4_194_304;
pub const DEFAULT_MAX_QOS_SAMPLES: usize = 4_194_304;
pub const DEFAULT_MAX_NULLIFIER_FENCES: usize = 8_388_608;
pub const DEFAULT_MAX_RECURSIVE_PROOF_HINTS: usize = 1_048_576;
pub const DEFAULT_MAX_FEE_REBATES: usize = 1_048_576;
pub const DEFAULT_MAX_MAKER_RESERVATIONS: usize = 1_048_576;
pub const DEFAULT_MAX_VERIFIER_RECEIPTS: usize = 2_097_152;
pub const DEFAULT_MAX_SLASHING_EVIDENCE: usize = 524_288;
pub const DEFAULT_MAX_EVENTS: usize = 16_777_216;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LaneKind {
    Swap,
    Payment,
    ContractCall,
    DefiIntent,
    BridgeExit,
    MakerQuote,
    OracleUpdate,
    EmergencyCancel,
}

impl LaneKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Swap => "swap",
            Self::Payment => "payment",
            Self::ContractCall => "contract_call",
            Self::DefiIntent => "defi_intent",
            Self::BridgeExit => "bridge_exit",
            Self::MakerQuote => "maker_quote",
            Self::OracleUpdate => "oracle_update",
            Self::EmergencyCancel => "emergency_cancel",
        }
    }

    pub fn default_priority(self) -> u64 {
        match self {
            Self::EmergencyCancel => 10_000,
            Self::BridgeExit => 9_600,
            Self::ContractCall => 9_200,
            Self::DefiIntent => 9_000,
            Self::Swap => 8_800,
            Self::Payment => 8_400,
            Self::MakerQuote => 8_200,
            Self::OracleUpdate => 7_800,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LaneStatus {
    Registered,
    Open,
    Congested,
    Draining,
    Paused,
    Slashed,
    Retired,
}

impl LaneStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Registered => "registered",
            Self::Open => "open",
            Self::Congested => "congested",
            Self::Draining => "draining",
            Self::Paused => "paused",
            Self::Slashed => "slashed",
            Self::Retired => "retired",
        }
    }

    pub fn accepts_microbatches(self) -> bool {
        matches!(self, Self::Registered | Self::Open | Self::Congested)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MicrobatchStatus {
    Encrypted,
    Fenced,
    SlotAssigned,
    CommitteeAssigned,
    Attesting,
    Preconfirmed,
    Receipted,
    Settled,
    Cancelled,
    Challenged,
    Slashed,
    Expired,
}

impl MicrobatchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Encrypted => "encrypted",
            Self::Fenced => "fenced",
            Self::SlotAssigned => "slot_assigned",
            Self::CommitteeAssigned => "committee_assigned",
            Self::Attesting => "attesting",
            Self::Preconfirmed => "preconfirmed",
            Self::Receipted => "receipted",
            Self::Settled => "settled",
            Self::Cancelled => "cancelled",
            Self::Challenged => "challenged",
            Self::Slashed => "slashed",
            Self::Expired => "expired",
        }
    }

    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Encrypted
                | Self::Fenced
                | Self::SlotAssigned
                | Self::CommitteeAssigned
                | Self::Attesting
                | Self::Preconfirmed
                | Self::Receipted
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SlotStatus {
    Open,
    Filling,
    Sealed,
    Preconfirmed,
    Receipted,
    Reorged,
    Slashed,
    Expired,
}

impl SlotStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Filling => "filling",
            Self::Sealed => "sealed",
            Self::Preconfirmed => "preconfirmed",
            Self::Receipted => "receipted",
            Self::Reorged => "reorged",
            Self::Slashed => "slashed",
            Self::Expired => "expired",
        }
    }

    pub fn accepts_batch(self) -> bool {
        matches!(self, Self::Open | Self::Filling)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CommitteeStatus {
    Registered,
    Assigned,
    Attesting,
    QuorumReached,
    SupermajorityReached,
    Rotating,
    Challenged,
    Slashed,
    Retired,
}

impl CommitteeStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Registered => "registered",
            Self::Assigned => "assigned",
            Self::Attesting => "attesting",
            Self::QuorumReached => "quorum_reached",
            Self::SupermajorityReached => "supermajority_reached",
            Self::Rotating => "rotating",
            Self::Challenged => "challenged",
            Self::Slashed => "slashed",
            Self::Retired => "retired",
        }
    }

    pub fn can_attest(self) -> bool {
        matches!(
            self,
            Self::Registered | Self::Assigned | Self::Attesting | Self::QuorumReached
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationVerdict {
    Include,
    Hold,
    Cancel,
    Reject,
}

impl AttestationVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Include => "include",
            Self::Hold => "hold",
            Self::Cancel => "cancel",
            Self::Reject => "reject",
        }
    }

    pub fn contributes_to_quorum(self) -> bool {
        matches!(self, Self::Include | Self::Cancel)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QosClass {
    Critical,
    Fast,
    Standard,
    Backfill,
}

impl QosClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Critical => "critical",
            Self::Fast => "fast",
            Self::Standard => "standard",
            Self::Backfill => "backfill",
        }
    }

    pub fn latency_budget_ms(self, config: &Config) -> u64 {
        match self {
            Self::Critical => config.target_preconfirmation_ms,
            Self::Fast => config.soft_latency_ms,
            Self::Standard => config.hard_latency_ms,
            Self::Backfill => config.hard_latency_ms.saturating_mul(2),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FenceKind {
    Cancellation,
    Nullifier,
    Replay,
    MakerReservation,
    SequencerLease,
    EmergencyStop,
}

impl FenceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Cancellation => "cancellation",
            Self::Nullifier => "nullifier",
            Self::Replay => "replay",
            Self::MakerReservation => "maker_reservation",
            Self::SequencerLease => "sequencer_lease",
            Self::EmergencyStop => "emergency_stop",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofHintKind {
    RecursiveAggregation,
    WitnessPrefetch,
    BlobDa,
    StateDiff,
    VerifierCache,
    CircuitShard,
}

impl ProofHintKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RecursiveAggregation => "recursive_aggregation",
            Self::WitnessPrefetch => "witness_prefetch",
            Self::BlobDa => "blob_da",
            Self::StateDiff => "state_diff",
            Self::VerifierCache => "verifier_cache",
            Self::CircuitShard => "circuit_shard",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptStatus {
    Published,
    Verified,
    Finalized,
    RebateQueued,
    Challenged,
    Reorged,
    Slashed,
}

impl ReceiptStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Published => "published",
            Self::Verified => "verified",
            Self::Finalized => "finalized",
            Self::RebateQueued => "rebate_queued",
            Self::Challenged => "challenged",
            Self::Reorged => "reorged",
            Self::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RebateStatus {
    Accruing,
    Claimable,
    Claimed,
    Expired,
    Slashed,
}

impl RebateStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Accruing => "accruing",
            Self::Claimable => "claimable",
            Self::Claimed => "claimed",
            Self::Expired => "expired",
            Self::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReservationStatus {
    Open,
    Bound,
    Filled,
    Cancelled,
    Expired,
    Slashed,
}

impl ReservationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Bound => "bound",
            Self::Filled => "filled",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
            Self::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SlashingReason {
    Equivocation,
    LateAttestation,
    InvalidSignature,
    InvalidPreconfirmation,
    FenceBypass,
    ReceiptForgery,
    ReservationDefault,
    QosBreach,
}

impl SlashingReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Equivocation => "equivocation",
            Self::LateAttestation => "late_attestation",
            Self::InvalidSignature => "invalid_signature",
            Self::InvalidPreconfirmation => "invalid_preconfirmation",
            Self::FenceBypass => "fence_bypass",
            Self::ReceiptForgery => "receipt_forgery",
            Self::ReservationDefault => "reservation_default",
            Self::QosBreach => "qos_breach",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub l2_network: String,
    pub monero_network: String,
    pub fee_asset_id: String,
    pub rebate_asset_id: String,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub slot_width_ms: u64,
    pub target_preconfirmation_ms: u64,
    pub soft_latency_ms: u64,
    pub hard_latency_ms: u64,
    pub microbatch_max_items: u32,
    pub microbatch_max_bytes: u64,
    pub microbatch_ttl_slots: u64,
    pub cancellation_ttl_slots: u64,
    pub receipt_ttl_slots: u64,
    pub rebate_ttl_slots: u64,
    pub reservation_ttl_slots: u64,
    pub proof_hint_ttl_slots: u64,
    pub quorum_weight_bps: u64,
    pub supermajority_weight_bps: u64,
    pub maker_quorum_bps: u64,
    pub max_user_fee_bps: u64,
    pub target_rebate_bps: u64,
    pub max_rebate_bps: u64,
    pub maker_rebate_bps: u64,
    pub qos_rebate_bps: u64,
    pub slash_bps: u64,
    pub min_committee_bond_micro_units: u64,
    pub min_sequencer_bond_micro_units: u64,
    pub min_maker_bond_micro_units: u64,
    pub max_lanes: usize,
    pub max_microbatches: usize,
    pub max_sequencing_slots: usize,
    pub max_committees: usize,
    pub max_attestations: usize,
    pub max_qos_samples: usize,
    pub max_nullifier_fences: usize,
    pub max_recursive_proof_hints: usize,
    pub max_fee_rebates: usize,
    pub max_maker_reservations: usize,
    pub max_verifier_receipts: usize,
    pub max_slashing_evidence: usize,
    pub max_events: usize,
    pub require_cancellation_fence: bool,
    pub require_nullifier_fence: bool,
    pub require_pq_attestation: bool,
    pub require_verifier_receipt: bool,
    pub enable_qos_rebates: bool,
    pub enable_maker_reservations: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            l2_network: DEVNET_L2_NETWORK.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            rebate_asset_id: DEVNET_REBATE_ASSET_ID.to_string(),
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            slot_width_ms: DEFAULT_SLOT_WIDTH_MS,
            target_preconfirmation_ms: DEFAULT_TARGET_PRECONFIRMATION_MS,
            soft_latency_ms: DEFAULT_SOFT_LATENCY_MS,
            hard_latency_ms: DEFAULT_HARD_LATENCY_MS,
            microbatch_max_items: DEFAULT_MICROBATCH_MAX_ITEMS,
            microbatch_max_bytes: DEFAULT_MICROBATCH_MAX_BYTES,
            microbatch_ttl_slots: DEFAULT_MICROBATCH_TTL_SLOTS,
            cancellation_ttl_slots: DEFAULT_CANCELLATION_TTL_SLOTS,
            receipt_ttl_slots: DEFAULT_RECEIPT_TTL_SLOTS,
            rebate_ttl_slots: DEFAULT_REBATE_TTL_SLOTS,
            reservation_ttl_slots: DEFAULT_RESERVATION_TTL_SLOTS,
            proof_hint_ttl_slots: DEFAULT_PROOF_HINT_TTL_SLOTS,
            quorum_weight_bps: DEFAULT_QUORUM_WEIGHT_BPS,
            supermajority_weight_bps: DEFAULT_SUPERMAJORITY_WEIGHT_BPS,
            maker_quorum_bps: DEFAULT_MAKER_QUORUM_BPS,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            target_rebate_bps: DEFAULT_TARGET_REBATE_BPS,
            max_rebate_bps: DEFAULT_MAX_REBATE_BPS,
            maker_rebate_bps: DEFAULT_MAKER_REBATE_BPS,
            qos_rebate_bps: DEFAULT_QOS_REBATE_BPS,
            slash_bps: DEFAULT_SLASH_BPS,
            min_committee_bond_micro_units: DEFAULT_MIN_COMMITTEE_BOND_MICRO_UNITS,
            min_sequencer_bond_micro_units: DEFAULT_MIN_SEQUENCER_BOND_MICRO_UNITS,
            min_maker_bond_micro_units: DEFAULT_MIN_MAKER_BOND_MICRO_UNITS,
            max_lanes: DEFAULT_MAX_LANES,
            max_microbatches: DEFAULT_MAX_MICROBATCHES,
            max_sequencing_slots: DEFAULT_MAX_SEQUENCING_SLOTS,
            max_committees: DEFAULT_MAX_COMMITTEES,
            max_attestations: DEFAULT_MAX_ATTESTATIONS,
            max_qos_samples: DEFAULT_MAX_QOS_SAMPLES,
            max_nullifier_fences: DEFAULT_MAX_NULLIFIER_FENCES,
            max_recursive_proof_hints: DEFAULT_MAX_RECURSIVE_PROOF_HINTS,
            max_fee_rebates: DEFAULT_MAX_FEE_REBATES,
            max_maker_reservations: DEFAULT_MAX_MAKER_RESERVATIONS,
            max_verifier_receipts: DEFAULT_MAX_VERIFIER_RECEIPTS,
            max_slashing_evidence: DEFAULT_MAX_SLASHING_EVIDENCE,
            max_events: DEFAULT_MAX_EVENTS,
            require_cancellation_fence: true,
            require_nullifier_fence: true,
            require_pq_attestation: true,
            require_verifier_receipt: true,
            enable_qos_rebates: true,
            enable_maker_reservations: true,
        }
    }

    pub fn validate(&self) -> Result<()> {
        ensure_eq(&self.chain_id, CHAIN_ID, "config chain_id")?;
        ensure_non_empty(&self.l2_network, "l2_network")?;
        ensure_non_empty(&self.monero_network, "monero_network")?;
        ensure_non_empty(&self.fee_asset_id, "fee_asset_id")?;
        ensure_non_empty(&self.rebate_asset_id, "rebate_asset_id")?;
        if self.min_pq_security_bits < 128 {
            return Err("microbatch preconfirmation PQ security floor is too low".to_string());
        }
        if self.min_privacy_set_size == 0
            || self.target_privacy_set_size < self.min_privacy_set_size
        {
            return Err("microbatch preconfirmation privacy set policy is invalid".to_string());
        }
        if self.slot_width_ms == 0
            || self.target_preconfirmation_ms == 0
            || self.soft_latency_ms < self.target_preconfirmation_ms
            || self.hard_latency_ms < self.soft_latency_ms
        {
            return Err("microbatch preconfirmation latency policy is invalid".to_string());
        }
        if self.microbatch_max_items == 0 || self.microbatch_max_bytes == 0 {
            return Err("microbatch preconfirmation batch limits must be positive".to_string());
        }
        if self.microbatch_ttl_slots == 0
            || self.cancellation_ttl_slots == 0
            || self.receipt_ttl_slots == 0
            || self.rebate_ttl_slots == 0
            || self.reservation_ttl_slots == 0
            || self.proof_hint_ttl_slots == 0
        {
            return Err("microbatch preconfirmation TTL policy must be positive".to_string());
        }
        ensure_bps(self.quorum_weight_bps, "quorum_weight_bps")?;
        ensure_bps(self.supermajority_weight_bps, "supermajority_weight_bps")?;
        ensure_bps(self.maker_quorum_bps, "maker_quorum_bps")?;
        ensure_bps(self.max_user_fee_bps, "max_user_fee_bps")?;
        ensure_bps(self.target_rebate_bps, "target_rebate_bps")?;
        ensure_bps(self.max_rebate_bps, "max_rebate_bps")?;
        ensure_bps(self.maker_rebate_bps, "maker_rebate_bps")?;
        ensure_bps(self.qos_rebate_bps, "qos_rebate_bps")?;
        ensure_bps(self.slash_bps, "slash_bps")?;
        if self.supermajority_weight_bps < self.quorum_weight_bps {
            return Err("microbatch supermajority is below quorum".to_string());
        }
        if self.target_rebate_bps > self.max_rebate_bps {
            return Err("microbatch target rebate exceeds max rebate".to_string());
        }
        if self.min_committee_bond_micro_units == 0
            || self.min_sequencer_bond_micro_units == 0
            || self.min_maker_bond_micro_units == 0
        {
            return Err("microbatch bond floors must be positive".to_string());
        }
        if self.max_lanes == 0
            || self.max_microbatches == 0
            || self.max_sequencing_slots == 0
            || self.max_committees == 0
            || self.max_attestations == 0
            || self.max_qos_samples == 0
            || self.max_nullifier_fences == 0
            || self.max_recursive_proof_hints == 0
            || self.max_fee_rebates == 0
            || self.max_maker_reservations == 0
            || self.max_verifier_receipts == 0
            || self.max_slashing_evidence == 0
            || self.max_events == 0
        {
            return Err("microbatch preconfirmation capacities must be positive".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "l2_network": self.l2_network,
            "monero_network": self.monero_network,
            "fee_asset_id": self.fee_asset_id,
            "rebate_asset_id": self.rebate_asset_id,
            "min_pq_security_bits": self.min_pq_security_bits,
            "min_privacy_set_size": self.min_privacy_set_size,
            "target_privacy_set_size": self.target_privacy_set_size,
            "slot_width_ms": self.slot_width_ms,
            "target_preconfirmation_ms": self.target_preconfirmation_ms,
            "soft_latency_ms": self.soft_latency_ms,
            "hard_latency_ms": self.hard_latency_ms,
            "microbatch_max_items": self.microbatch_max_items,
            "microbatch_max_bytes": self.microbatch_max_bytes,
            "microbatch_ttl_slots": self.microbatch_ttl_slots,
            "cancellation_ttl_slots": self.cancellation_ttl_slots,
            "receipt_ttl_slots": self.receipt_ttl_slots,
            "rebate_ttl_slots": self.rebate_ttl_slots,
            "reservation_ttl_slots": self.reservation_ttl_slots,
            "proof_hint_ttl_slots": self.proof_hint_ttl_slots,
            "quorum_weight_bps": self.quorum_weight_bps,
            "supermajority_weight_bps": self.supermajority_weight_bps,
            "maker_quorum_bps": self.maker_quorum_bps,
            "max_user_fee_bps": self.max_user_fee_bps,
            "target_rebate_bps": self.target_rebate_bps,
            "max_rebate_bps": self.max_rebate_bps,
            "maker_rebate_bps": self.maker_rebate_bps,
            "qos_rebate_bps": self.qos_rebate_bps,
            "slash_bps": self.slash_bps,
            "min_committee_bond_micro_units": self.min_committee_bond_micro_units,
            "min_sequencer_bond_micro_units": self.min_sequencer_bond_micro_units,
            "min_maker_bond_micro_units": self.min_maker_bond_micro_units,
            "max_lanes": self.max_lanes,
            "max_microbatches": self.max_microbatches,
            "max_sequencing_slots": self.max_sequencing_slots,
            "max_committees": self.max_committees,
            "max_attestations": self.max_attestations,
            "max_qos_samples": self.max_qos_samples,
            "max_nullifier_fences": self.max_nullifier_fences,
            "max_recursive_proof_hints": self.max_recursive_proof_hints,
            "max_fee_rebates": self.max_fee_rebates,
            "max_maker_reservations": self.max_maker_reservations,
            "max_verifier_receipts": self.max_verifier_receipts,
            "max_slashing_evidence": self.max_slashing_evidence,
            "max_events": self.max_events,
            "require_cancellation_fence": self.require_cancellation_fence,
            "require_nullifier_fence": self.require_nullifier_fence,
            "require_pq_attestation": self.require_pq_attestation,
            "require_verifier_receipt": self.require_verifier_receipt,
            "enable_qos_rebates": self.enable_qos_rebates,
            "enable_maker_reservations": self.enable_maker_reservations,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub next_lane_index: u64,
    pub next_microbatch_index: u64,
    pub next_slot_index: u64,
    pub next_committee_index: u64,
    pub next_attestation_index: u64,
    pub next_qos_sample_index: u64,
    pub next_fence_index: u64,
    pub next_proof_hint_index: u64,
    pub next_rebate_index: u64,
    pub next_reservation_index: u64,
    pub next_receipt_index: u64,
    pub next_slashing_index: u64,
    pub next_event_index: u64,
    pub l2_height: u64,
    pub monero_height: u64,
    pub epoch: u64,
}

impl Counters {
    pub fn devnet() -> Self {
        Self {
            next_lane_index: 1,
            next_microbatch_index: 1,
            next_slot_index: 1,
            next_committee_index: 1,
            next_attestation_index: 1,
            next_qos_sample_index: 1,
            next_fence_index: 1,
            next_proof_hint_index: 1,
            next_rebate_index: 1,
            next_reservation_index: 1,
            next_receipt_index: 1,
            next_slashing_index: 1,
            next_event_index: 1,
            l2_height: DEVNET_L2_HEIGHT,
            monero_height: DEVNET_MONERO_HEIGHT,
            epoch: DEVNET_EPOCH,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "next_lane_index": self.next_lane_index,
            "next_microbatch_index": self.next_microbatch_index,
            "next_slot_index": self.next_slot_index,
            "next_committee_index": self.next_committee_index,
            "next_attestation_index": self.next_attestation_index,
            "next_qos_sample_index": self.next_qos_sample_index,
            "next_fence_index": self.next_fence_index,
            "next_proof_hint_index": self.next_proof_hint_index,
            "next_rebate_index": self.next_rebate_index,
            "next_reservation_index": self.next_reservation_index,
            "next_receipt_index": self.next_receipt_index,
            "next_slashing_index": self.next_slashing_index,
            "next_event_index": self.next_event_index,
            "l2_height": self.l2_height,
            "monero_height": self.monero_height,
            "epoch": self.epoch,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub counters_root: String,
    pub lanes_root: String,
    pub microbatches_root: String,
    pub sequencing_slots_root: String,
    pub committees_root: String,
    pub attestations_root: String,
    pub qos_samples_root: String,
    pub cancellation_nullifier_fences_root: String,
    pub recursive_proof_hints_root: String,
    pub fee_rebates_root: String,
    pub maker_reservations_root: String,
    pub verifier_receipts_root: String,
    pub slashing_evidence_root: String,
    pub events_root: String,
}

impl Roots {
    pub fn empty(config: &Config, counters: &Counters) -> Self {
        Self {
            config_root: value_root("config", &config.public_record()),
            counters_root: value_root("counters", &counters.public_record()),
            lanes_root: empty_root("lanes"),
            microbatches_root: empty_root("microbatches"),
            sequencing_slots_root: empty_root("sequencing_slots"),
            committees_root: empty_root("committees"),
            attestations_root: empty_root("attestations"),
            qos_samples_root: empty_root("qos_samples"),
            cancellation_nullifier_fences_root: empty_root("cancellation_nullifier_fences"),
            recursive_proof_hints_root: empty_root("recursive_proof_hints"),
            fee_rebates_root: empty_root("fee_rebates"),
            maker_reservations_root: empty_root("maker_reservations"),
            verifier_receipts_root: empty_root("verifier_receipts"),
            slashing_evidence_root: empty_root("slashing_evidence"),
            events_root: empty_root("events"),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "counters_root": self.counters_root,
            "lanes_root": self.lanes_root,
            "microbatches_root": self.microbatches_root,
            "sequencing_slots_root": self.sequencing_slots_root,
            "committees_root": self.committees_root,
            "attestations_root": self.attestations_root,
            "qos_samples_root": self.qos_samples_root,
            "cancellation_nullifier_fences_root": self.cancellation_nullifier_fences_root,
            "recursive_proof_hints_root": self.recursive_proof_hints_root,
            "fee_rebates_root": self.fee_rebates_root,
            "maker_reservations_root": self.maker_reservations_root,
            "verifier_receipts_root": self.verifier_receipts_root,
            "slashing_evidence_root": self.slashing_evidence_root,
            "events_root": self.events_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EncryptedMicrobatchLane {
    pub lane_id: String,
    pub lane_index: u64,
    pub kind: LaneKind,
    pub status: LaneStatus,
    pub owner_commitment: String,
    pub lane_public_key_commitment: String,
    pub threshold_key_commitment: String,
    pub admission_policy_root: String,
    pub priority: u64,
    pub max_inflight_microbatches: u32,
    pub max_microbatch_bytes: u64,
    pub min_privacy_set_size: u64,
    pub maker_reservation_required: bool,
    pub cancellation_fence_required: bool,
    pub nullifier_fence_required: bool,
    pub total_encrypted_microbatches: u64,
    pub inflight_microbatches: u64,
    pub total_preconfirmed_microbatches: u64,
    pub total_cancelled_microbatches: u64,
    pub qos_score_bps: u64,
    pub bond_micro_units: u64,
    pub created_slot: u64,
    pub updated_slot: u64,
}

impl EncryptedMicrobatchLane {
    pub fn new(
        lane_index: u64,
        kind: LaneKind,
        owner_commitment: impl Into<String>,
        lane_public_key_commitment: impl Into<String>,
        threshold_key_commitment: impl Into<String>,
        created_slot: u64,
        config: &Config,
    ) -> Result<Self> {
        let owner_commitment = owner_commitment.into();
        let lane_public_key_commitment = lane_public_key_commitment.into();
        let threshold_key_commitment = threshold_key_commitment.into();
        ensure_non_empty(&owner_commitment, "owner_commitment")?;
        ensure_non_empty(&lane_public_key_commitment, "lane_public_key_commitment")?;
        ensure_non_empty(&threshold_key_commitment, "threshold_key_commitment")?;
        let lane_id = deterministic_id(
            "lane-id",
            &[
                HashPart::Int(lane_index as i128),
                HashPart::Str(kind.as_str()),
                HashPart::Str(&owner_commitment),
                HashPart::Str(&lane_public_key_commitment),
            ],
        );
        Ok(Self {
            lane_id,
            lane_index,
            kind,
            status: LaneStatus::Registered,
            owner_commitment,
            lane_public_key_commitment,
            threshold_key_commitment,
            admission_policy_root: deterministic_id(
                "lane-admission-policy",
                &[
                    HashPart::Int(lane_index as i128),
                    HashPart::Str(kind.as_str()),
                ],
            ),
            priority: kind.default_priority(),
            max_inflight_microbatches: config.microbatch_max_items,
            max_microbatch_bytes: config.microbatch_max_bytes,
            min_privacy_set_size: config.min_privacy_set_size,
            maker_reservation_required: config.enable_maker_reservations,
            cancellation_fence_required: config.require_cancellation_fence,
            nullifier_fence_required: config.require_nullifier_fence,
            total_encrypted_microbatches: 0,
            inflight_microbatches: 0,
            total_preconfirmed_microbatches: 0,
            total_cancelled_microbatches: 0,
            qos_score_bps: MAX_BPS,
            bond_micro_units: config.min_sequencer_bond_micro_units,
            created_slot,
            updated_slot: created_slot,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "lane_id": self.lane_id,
            "lane_index": self.lane_index,
            "kind": self.kind,
            "status": self.status,
            "owner_commitment": self.owner_commitment,
            "lane_public_key_commitment": self.lane_public_key_commitment,
            "threshold_key_commitment": self.threshold_key_commitment,
            "admission_policy_root": self.admission_policy_root,
            "priority": self.priority,
            "max_inflight_microbatches": self.max_inflight_microbatches,
            "max_microbatch_bytes": self.max_microbatch_bytes,
            "min_privacy_set_size": self.min_privacy_set_size,
            "maker_reservation_required": self.maker_reservation_required,
            "cancellation_fence_required": self.cancellation_fence_required,
            "nullifier_fence_required": self.nullifier_fence_required,
            "total_encrypted_microbatches": self.total_encrypted_microbatches,
            "inflight_microbatches": self.inflight_microbatches,
            "total_preconfirmed_microbatches": self.total_preconfirmed_microbatches,
            "total_cancelled_microbatches": self.total_cancelled_microbatches,
            "qos_score_bps": self.qos_score_bps,
            "bond_micro_units": self.bond_micro_units,
            "created_slot": self.created_slot,
            "updated_slot": self.updated_slot,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ConfidentialMicrobatch {
    pub microbatch_id: String,
    pub microbatch_index: u64,
    pub lane_id: String,
    pub slot_id: Option<String>,
    pub committee_id: Option<String>,
    pub maker_reservation_id: Option<String>,
    pub status: MicrobatchStatus,
    pub qos_class: QosClass,
    pub encrypted_payload_commitment: String,
    pub ciphertext_root: String,
    pub item_commitment_root: String,
    pub amount_commitment_root: String,
    pub nullifier_root: String,
    pub cancellation_root: String,
    pub fee_commitment: String,
    pub fee_asset_id: String,
    pub max_user_fee_bps: u64,
    pub privacy_set_size: u64,
    pub item_count: u32,
    pub byte_size: u64,
    pub ingress_slot: u64,
    pub expiry_slot: u64,
    pub preconfirmed_slot: Option<u64>,
    pub receipt_id: Option<String>,
}

impl ConfidentialMicrobatch {
    pub fn new(
        microbatch_index: u64,
        lane_id: impl Into<String>,
        qos_class: QosClass,
        encrypted_payload_commitment: impl Into<String>,
        ciphertext_root: impl Into<String>,
        item_commitment_root: impl Into<String>,
        item_count: u32,
        byte_size: u64,
        ingress_slot: u64,
        config: &Config,
    ) -> Result<Self> {
        let lane_id = lane_id.into();
        let encrypted_payload_commitment = encrypted_payload_commitment.into();
        let ciphertext_root = ciphertext_root.into();
        let item_commitment_root = item_commitment_root.into();
        ensure_non_empty(&lane_id, "lane_id")?;
        ensure_non_empty(
            &encrypted_payload_commitment,
            "encrypted_payload_commitment",
        )?;
        ensure_non_empty(&ciphertext_root, "ciphertext_root")?;
        ensure_non_empty(&item_commitment_root, "item_commitment_root")?;
        if item_count == 0 || item_count > config.microbatch_max_items {
            return Err("microbatch item count is outside configured bounds".to_string());
        }
        if byte_size == 0 || byte_size > config.microbatch_max_bytes {
            return Err("microbatch byte size is outside configured bounds".to_string());
        }
        let microbatch_id = deterministic_id(
            "microbatch-id",
            &[
                HashPart::Int(microbatch_index as i128),
                HashPart::Str(&lane_id),
                HashPart::Str(&encrypted_payload_commitment),
                HashPart::Str(&ciphertext_root),
            ],
        );
        Ok(Self {
            microbatch_id,
            microbatch_index,
            lane_id,
            slot_id: None,
            committee_id: None,
            maker_reservation_id: None,
            status: MicrobatchStatus::Encrypted,
            qos_class,
            encrypted_payload_commitment,
            ciphertext_root,
            item_commitment_root,
            amount_commitment_root: deterministic_id(
                "microbatch-amount-root",
                &[HashPart::Int(microbatch_index as i128)],
            ),
            nullifier_root: deterministic_id(
                "microbatch-nullifier-root",
                &[HashPart::Int(microbatch_index as i128)],
            ),
            cancellation_root: deterministic_id(
                "microbatch-cancellation-root",
                &[HashPart::Int(microbatch_index as i128)],
            ),
            fee_commitment: deterministic_id(
                "microbatch-fee-commitment",
                &[
                    HashPart::Int(microbatch_index as i128),
                    HashPart::Str(&config.fee_asset_id),
                ],
            ),
            fee_asset_id: config.fee_asset_id.clone(),
            max_user_fee_bps: config.max_user_fee_bps,
            privacy_set_size: config.target_privacy_set_size,
            item_count,
            byte_size,
            ingress_slot,
            expiry_slot: ingress_slot.saturating_add(config.microbatch_ttl_slots),
            preconfirmed_slot: None,
            receipt_id: None,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "microbatch_id": self.microbatch_id,
            "microbatch_index": self.microbatch_index,
            "lane_id": self.lane_id,
            "slot_id": self.slot_id,
            "committee_id": self.committee_id,
            "maker_reservation_id": self.maker_reservation_id,
            "status": self.status,
            "qos_class": self.qos_class,
            "encrypted_payload_commitment": self.encrypted_payload_commitment,
            "ciphertext_root": self.ciphertext_root,
            "item_commitment_root": self.item_commitment_root,
            "amount_commitment_root": self.amount_commitment_root,
            "nullifier_root": self.nullifier_root,
            "cancellation_root": self.cancellation_root,
            "fee_commitment": self.fee_commitment,
            "fee_asset_id": self.fee_asset_id,
            "max_user_fee_bps": self.max_user_fee_bps,
            "privacy_set_size": self.privacy_set_size,
            "item_count": self.item_count,
            "byte_size": self.byte_size,
            "ingress_slot": self.ingress_slot,
            "expiry_slot": self.expiry_slot,
            "preconfirmed_slot": self.preconfirmed_slot,
            "receipt_id": self.receipt_id,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SequencingSlot {
    pub slot_id: String,
    pub slot_index: u64,
    pub lane_id: String,
    pub status: SlotStatus,
    pub leader_commitment: String,
    pub slot_start_ms: u64,
    pub slot_end_ms: u64,
    pub microbatch_ids: Vec<String>,
    pub microbatch_root: String,
    pub encrypted_order_root: String,
    pub fence_root: String,
    pub qos_class: QosClass,
    pub capacity_items: u32,
    pub capacity_bytes: u64,
    pub used_items: u32,
    pub used_bytes: u64,
    pub preconfirmation_deadline_ms: u64,
}

impl SequencingSlot {
    pub fn new(
        slot_index: u64,
        lane_id: impl Into<String>,
        leader_commitment: impl Into<String>,
        qos_class: QosClass,
        config: &Config,
    ) -> Result<Self> {
        let lane_id = lane_id.into();
        let leader_commitment = leader_commitment.into();
        ensure_non_empty(&lane_id, "lane_id")?;
        ensure_non_empty(&leader_commitment, "leader_commitment")?;
        let slot_start_ms = slot_index.saturating_mul(config.slot_width_ms);
        let slot_end_ms = slot_start_ms.saturating_add(config.slot_width_ms);
        let slot_id = deterministic_id(
            "sequencing-slot-id",
            &[
                HashPart::Int(slot_index as i128),
                HashPart::Str(&lane_id),
                HashPart::Str(&leader_commitment),
            ],
        );
        Ok(Self {
            slot_id,
            slot_index,
            lane_id,
            status: SlotStatus::Open,
            leader_commitment,
            slot_start_ms,
            slot_end_ms,
            microbatch_ids: Vec::new(),
            microbatch_root: empty_root("slot_microbatches"),
            encrypted_order_root: deterministic_id(
                "slot-encrypted-order-root",
                &[HashPart::Int(slot_index as i128)],
            ),
            fence_root: empty_root("slot_fences"),
            qos_class,
            capacity_items: config.microbatch_max_items,
            capacity_bytes: config.microbatch_max_bytes,
            used_items: 0,
            used_bytes: 0,
            preconfirmation_deadline_ms: slot_start_ms
                .saturating_add(qos_class.latency_budget_ms(config)),
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "slot_id": self.slot_id,
            "slot_index": self.slot_index,
            "lane_id": self.lane_id,
            "status": self.status,
            "leader_commitment": self.leader_commitment,
            "slot_start_ms": self.slot_start_ms,
            "slot_end_ms": self.slot_end_ms,
            "microbatch_ids": self.microbatch_ids,
            "microbatch_root": self.microbatch_root,
            "encrypted_order_root": self.encrypted_order_root,
            "fence_root": self.fence_root,
            "qos_class": self.qos_class,
            "capacity_items": self.capacity_items,
            "capacity_bytes": self.capacity_bytes,
            "used_items": self.used_items,
            "used_bytes": self.used_bytes,
            "preconfirmation_deadline_ms": self.preconfirmation_deadline_ms,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqCommittee {
    pub committee_id: String,
    pub committee_index: u64,
    pub status: CommitteeStatus,
    pub epoch: u64,
    pub lane_id: String,
    pub member_root: String,
    pub aggregate_pq_public_key_root: String,
    pub stake_weight: u64,
    pub quorum_weight: u64,
    pub supermajority_weight: u64,
    pub bond_micro_units: u64,
    pub assigned_microbatch_ids: BTreeSet<String>,
}

impl PqCommittee {
    pub fn new(
        committee_index: u64,
        epoch: u64,
        lane_id: impl Into<String>,
        member_root: impl Into<String>,
        aggregate_pq_public_key_root: impl Into<String>,
        stake_weight: u64,
        config: &Config,
    ) -> Result<Self> {
        let lane_id = lane_id.into();
        let member_root = member_root.into();
        let aggregate_pq_public_key_root = aggregate_pq_public_key_root.into();
        ensure_non_empty(&lane_id, "lane_id")?;
        ensure_non_empty(&member_root, "member_root")?;
        ensure_non_empty(
            &aggregate_pq_public_key_root,
            "aggregate_pq_public_key_root",
        )?;
        if stake_weight == 0 {
            return Err("committee stake weight must be positive".to_string());
        }
        let committee_id = deterministic_id(
            "committee-id",
            &[
                HashPart::Int(committee_index as i128),
                HashPart::Int(epoch as i128),
                HashPart::Str(&lane_id),
                HashPart::Str(&member_root),
            ],
        );
        Ok(Self {
            committee_id,
            committee_index,
            status: CommitteeStatus::Registered,
            epoch,
            lane_id,
            member_root,
            aggregate_pq_public_key_root,
            stake_weight,
            quorum_weight: bps_amount(stake_weight, config.quorum_weight_bps),
            supermajority_weight: bps_amount(stake_weight, config.supermajority_weight_bps),
            bond_micro_units: config.min_committee_bond_micro_units,
            assigned_microbatch_ids: BTreeSet::new(),
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "committee_id": self.committee_id,
            "committee_index": self.committee_index,
            "status": self.status,
            "epoch": self.epoch,
            "lane_id": self.lane_id,
            "member_root": self.member_root,
            "aggregate_pq_public_key_root": self.aggregate_pq_public_key_root,
            "stake_weight": self.stake_weight,
            "quorum_weight": self.quorum_weight,
            "supermajority_weight": self.supermajority_weight,
            "bond_micro_units": self.bond_micro_units,
            "assigned_microbatch_ids": self.assigned_microbatch_ids,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqAttestation {
    pub attestation_id: String,
    pub attestation_index: u64,
    pub committee_id: String,
    pub microbatch_id: String,
    pub slot_id: String,
    pub signer_commitment: String,
    pub signer_weight: u64,
    pub verdict: AttestationVerdict,
    pub pq_signature_commitment: String,
    pub transcript_root: String,
    pub latency_ms: u64,
    pub attested_slot: u64,
}

impl PqAttestation {
    pub fn new(
        attestation_index: u64,
        committee_id: impl Into<String>,
        microbatch_id: impl Into<String>,
        slot_id: impl Into<String>,
        signer_commitment: impl Into<String>,
        signer_weight: u64,
        verdict: AttestationVerdict,
        latency_ms: u64,
        attested_slot: u64,
    ) -> Result<Self> {
        let committee_id = committee_id.into();
        let microbatch_id = microbatch_id.into();
        let slot_id = slot_id.into();
        let signer_commitment = signer_commitment.into();
        ensure_non_empty(&committee_id, "committee_id")?;
        ensure_non_empty(&microbatch_id, "microbatch_id")?;
        ensure_non_empty(&slot_id, "slot_id")?;
        ensure_non_empty(&signer_commitment, "signer_commitment")?;
        if signer_weight == 0 {
            return Err("attestation signer weight must be positive".to_string());
        }
        let attestation_id = deterministic_id(
            "attestation-id",
            &[
                HashPart::Int(attestation_index as i128),
                HashPart::Str(&committee_id),
                HashPart::Str(&microbatch_id),
                HashPart::Str(&signer_commitment),
                HashPart::Str(verdict.as_str()),
            ],
        );
        Ok(Self {
            attestation_id: attestation_id.clone(),
            attestation_index,
            committee_id,
            microbatch_id,
            slot_id,
            signer_commitment,
            signer_weight,
            verdict,
            pq_signature_commitment: deterministic_id(
                "pq-attestation-signature",
                &[HashPart::Str(&attestation_id)],
            ),
            transcript_root: deterministic_id(
                "pq-attestation-transcript-root",
                &[HashPart::Str(&attestation_id)],
            ),
            latency_ms,
            attested_slot,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "attestation_index": self.attestation_index,
            "committee_id": self.committee_id,
            "microbatch_id": self.microbatch_id,
            "slot_id": self.slot_id,
            "signer_commitment": self.signer_commitment,
            "signer_weight": self.signer_weight,
            "verdict": self.verdict,
            "pq_signature_commitment": self.pq_signature_commitment,
            "transcript_root": self.transcript_root,
            "latency_ms": self.latency_ms,
            "attested_slot": self.attested_slot,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LatencyQosSample {
    pub sample_id: String,
    pub sample_index: u64,
    pub lane_id: String,
    pub microbatch_id: String,
    pub slot_id: String,
    pub qos_class: QosClass,
    pub ingress_ms: u64,
    pub preconfirmed_ms: u64,
    pub latency_ms: u64,
    pub soft_breached: bool,
    pub hard_breached: bool,
    pub eligible_rebate_bps: u64,
}

impl LatencyQosSample {
    pub fn new(
        sample_index: u64,
        lane_id: impl Into<String>,
        microbatch_id: impl Into<String>,
        slot_id: impl Into<String>,
        qos_class: QosClass,
        ingress_ms: u64,
        preconfirmed_ms: u64,
        config: &Config,
    ) -> Result<Self> {
        let lane_id = lane_id.into();
        let microbatch_id = microbatch_id.into();
        let slot_id = slot_id.into();
        ensure_non_empty(&lane_id, "lane_id")?;
        ensure_non_empty(&microbatch_id, "microbatch_id")?;
        ensure_non_empty(&slot_id, "slot_id")?;
        if preconfirmed_ms < ingress_ms {
            return Err("QoS preconfirmation timestamp precedes ingress".to_string());
        }
        let latency_ms = preconfirmed_ms.saturating_sub(ingress_ms);
        let sample_id = deterministic_id(
            "qos-sample-id",
            &[
                HashPart::Int(sample_index as i128),
                HashPart::Str(&lane_id),
                HashPart::Str(&microbatch_id),
                HashPart::Str(&slot_id),
            ],
        );
        Ok(Self {
            sample_id,
            sample_index,
            lane_id,
            microbatch_id,
            slot_id,
            qos_class,
            ingress_ms,
            preconfirmed_ms,
            latency_ms,
            soft_breached: latency_ms > config.soft_latency_ms,
            hard_breached: latency_ms > config.hard_latency_ms,
            eligible_rebate_bps: if config.enable_qos_rebates
                && latency_ms <= config.soft_latency_ms
            {
                config.qos_rebate_bps
            } else {
                0
            },
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "sample_id": self.sample_id,
            "sample_index": self.sample_index,
            "lane_id": self.lane_id,
            "microbatch_id": self.microbatch_id,
            "slot_id": self.slot_id,
            "qos_class": self.qos_class,
            "ingress_ms": self.ingress_ms,
            "preconfirmed_ms": self.preconfirmed_ms,
            "latency_ms": self.latency_ms,
            "soft_breached": self.soft_breached,
            "hard_breached": self.hard_breached,
            "eligible_rebate_bps": self.eligible_rebate_bps,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CancellationNullifierFence {
    pub fence_id: String,
    pub fence_index: u64,
    pub kind: FenceKind,
    pub lane_id: String,
    pub microbatch_id: String,
    pub nullifier_commitment: String,
    pub cancellation_commitment: String,
    pub fence_root: String,
    pub created_slot: u64,
    pub expiry_slot: u64,
    pub consumed: bool,
}

impl CancellationNullifierFence {
    pub fn new(
        fence_index: u64,
        kind: FenceKind,
        lane_id: impl Into<String>,
        microbatch_id: impl Into<String>,
        nullifier_commitment: impl Into<String>,
        cancellation_commitment: impl Into<String>,
        created_slot: u64,
        config: &Config,
    ) -> Result<Self> {
        let lane_id = lane_id.into();
        let microbatch_id = microbatch_id.into();
        let nullifier_commitment = nullifier_commitment.into();
        let cancellation_commitment = cancellation_commitment.into();
        ensure_non_empty(&lane_id, "lane_id")?;
        ensure_non_empty(&microbatch_id, "microbatch_id")?;
        ensure_non_empty(&nullifier_commitment, "nullifier_commitment")?;
        ensure_non_empty(&cancellation_commitment, "cancellation_commitment")?;
        let fence_id = deterministic_id(
            "fence-id",
            &[
                HashPart::Int(fence_index as i128),
                HashPart::Str(kind.as_str()),
                HashPart::Str(&lane_id),
                HashPart::Str(&microbatch_id),
                HashPart::Str(&nullifier_commitment),
            ],
        );
        Ok(Self {
            fence_id: fence_id.clone(),
            fence_index,
            kind,
            lane_id,
            microbatch_id,
            nullifier_commitment,
            cancellation_commitment,
            fence_root: deterministic_id("fence-root", &[HashPart::Str(&fence_id)]),
            created_slot,
            expiry_slot: created_slot.saturating_add(config.cancellation_ttl_slots),
            consumed: false,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "fence_id": self.fence_id,
            "fence_index": self.fence_index,
            "kind": self.kind,
            "lane_id": self.lane_id,
            "microbatch_id": self.microbatch_id,
            "nullifier_commitment": self.nullifier_commitment,
            "cancellation_commitment": self.cancellation_commitment,
            "fence_root": self.fence_root,
            "created_slot": self.created_slot,
            "expiry_slot": self.expiry_slot,
            "consumed": self.consumed,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RecursiveProofHint {
    pub hint_id: String,
    pub hint_index: u64,
    pub kind: ProofHintKind,
    pub microbatch_id: String,
    pub slot_id: String,
    pub circuit_commitment: String,
    pub witness_root: String,
    pub recursive_parent_root: String,
    pub expected_proof_weight: u64,
    pub proof_market_rebate_bps: u64,
    pub created_slot: u64,
    pub expiry_slot: u64,
}

impl RecursiveProofHint {
    pub fn new(
        hint_index: u64,
        kind: ProofHintKind,
        microbatch_id: impl Into<String>,
        slot_id: impl Into<String>,
        circuit_commitment: impl Into<String>,
        witness_root: impl Into<String>,
        expected_proof_weight: u64,
        created_slot: u64,
        config: &Config,
    ) -> Result<Self> {
        let microbatch_id = microbatch_id.into();
        let slot_id = slot_id.into();
        let circuit_commitment = circuit_commitment.into();
        let witness_root = witness_root.into();
        ensure_non_empty(&microbatch_id, "microbatch_id")?;
        ensure_non_empty(&slot_id, "slot_id")?;
        ensure_non_empty(&circuit_commitment, "circuit_commitment")?;
        ensure_non_empty(&witness_root, "witness_root")?;
        if expected_proof_weight == 0 {
            return Err("recursive proof hint weight must be positive".to_string());
        }
        let hint_id = deterministic_id(
            "proof-hint-id",
            &[
                HashPart::Int(hint_index as i128),
                HashPart::Str(kind.as_str()),
                HashPart::Str(&microbatch_id),
                HashPart::Str(&slot_id),
            ],
        );
        Ok(Self {
            hint_id: hint_id.clone(),
            hint_index,
            kind,
            microbatch_id,
            slot_id,
            circuit_commitment,
            witness_root,
            recursive_parent_root: deterministic_id(
                "recursive-parent-root",
                &[HashPart::Str(&hint_id)],
            ),
            expected_proof_weight,
            proof_market_rebate_bps: config.target_rebate_bps,
            created_slot,
            expiry_slot: created_slot.saturating_add(config.proof_hint_ttl_slots),
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "hint_id": self.hint_id,
            "hint_index": self.hint_index,
            "kind": self.kind,
            "microbatch_id": self.microbatch_id,
            "slot_id": self.slot_id,
            "circuit_commitment": self.circuit_commitment,
            "witness_root": self.witness_root,
            "recursive_parent_root": self.recursive_parent_root,
            "expected_proof_weight": self.expected_proof_weight,
            "proof_market_rebate_bps": self.proof_market_rebate_bps,
            "created_slot": self.created_slot,
            "expiry_slot": self.expiry_slot,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FeeRebate {
    pub rebate_id: String,
    pub rebate_index: u64,
    pub microbatch_id: String,
    pub beneficiary_commitment: String,
    pub asset_id: String,
    pub amount_micro_units: u64,
    pub rebate_bps: u64,
    pub status: RebateStatus,
    pub reason_root: String,
    pub created_slot: u64,
    pub expiry_slot: u64,
}

impl FeeRebate {
    pub fn new(
        rebate_index: u64,
        microbatch_id: impl Into<String>,
        beneficiary_commitment: impl Into<String>,
        amount_micro_units: u64,
        rebate_bps: u64,
        created_slot: u64,
        config: &Config,
    ) -> Result<Self> {
        let microbatch_id = microbatch_id.into();
        let beneficiary_commitment = beneficiary_commitment.into();
        ensure_non_empty(&microbatch_id, "microbatch_id")?;
        ensure_non_empty(&beneficiary_commitment, "beneficiary_commitment")?;
        ensure_bps(rebate_bps, "rebate_bps")?;
        if rebate_bps > config.max_rebate_bps {
            return Err("fee rebate exceeds configured cap".to_string());
        }
        let rebate_id = deterministic_id(
            "fee-rebate-id",
            &[
                HashPart::Int(rebate_index as i128),
                HashPart::Str(&microbatch_id),
                HashPart::Str(&beneficiary_commitment),
            ],
        );
        Ok(Self {
            rebate_id: rebate_id.clone(),
            rebate_index,
            microbatch_id,
            beneficiary_commitment,
            asset_id: config.rebate_asset_id.clone(),
            amount_micro_units,
            rebate_bps,
            status: RebateStatus::Accruing,
            reason_root: deterministic_id("fee-rebate-reason-root", &[HashPart::Str(&rebate_id)]),
            created_slot,
            expiry_slot: created_slot.saturating_add(config.rebate_ttl_slots),
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "rebate_id": self.rebate_id,
            "rebate_index": self.rebate_index,
            "microbatch_id": self.microbatch_id,
            "beneficiary_commitment": self.beneficiary_commitment,
            "asset_id": self.asset_id,
            "amount_micro_units": self.amount_micro_units,
            "rebate_bps": self.rebate_bps,
            "status": self.status,
            "reason_root": self.reason_root,
            "created_slot": self.created_slot,
            "expiry_slot": self.expiry_slot,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MakerReservation {
    pub reservation_id: String,
    pub reservation_index: u64,
    pub maker_commitment: String,
    pub lane_id: String,
    pub microbatch_id: Option<String>,
    pub quote_commitment: String,
    pub reserved_liquidity_commitment: String,
    pub min_fill_commitment: String,
    pub status: ReservationStatus,
    pub maker_bond_micro_units: u64,
    pub rebate_bps: u64,
    pub created_slot: u64,
    pub expiry_slot: u64,
}

impl MakerReservation {
    pub fn new(
        reservation_index: u64,
        maker_commitment: impl Into<String>,
        lane_id: impl Into<String>,
        quote_commitment: impl Into<String>,
        reserved_liquidity_commitment: impl Into<String>,
        created_slot: u64,
        config: &Config,
    ) -> Result<Self> {
        let maker_commitment = maker_commitment.into();
        let lane_id = lane_id.into();
        let quote_commitment = quote_commitment.into();
        let reserved_liquidity_commitment = reserved_liquidity_commitment.into();
        ensure_non_empty(&maker_commitment, "maker_commitment")?;
        ensure_non_empty(&lane_id, "lane_id")?;
        ensure_non_empty(&quote_commitment, "quote_commitment")?;
        ensure_non_empty(
            &reserved_liquidity_commitment,
            "reserved_liquidity_commitment",
        )?;
        let reservation_id = deterministic_id(
            "maker-reservation-id",
            &[
                HashPart::Int(reservation_index as i128),
                HashPart::Str(&maker_commitment),
                HashPart::Str(&lane_id),
                HashPart::Str(&quote_commitment),
            ],
        );
        Ok(Self {
            reservation_id: reservation_id.clone(),
            reservation_index,
            maker_commitment,
            lane_id,
            microbatch_id: None,
            quote_commitment,
            reserved_liquidity_commitment,
            min_fill_commitment: deterministic_id(
                "maker-reservation-min-fill",
                &[HashPart::Str(&reservation_id)],
            ),
            status: ReservationStatus::Open,
            maker_bond_micro_units: config.min_maker_bond_micro_units,
            rebate_bps: config.maker_rebate_bps,
            created_slot,
            expiry_slot: created_slot.saturating_add(config.reservation_ttl_slots),
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "reservation_id": self.reservation_id,
            "reservation_index": self.reservation_index,
            "maker_commitment": self.maker_commitment,
            "lane_id": self.lane_id,
            "microbatch_id": self.microbatch_id,
            "quote_commitment": self.quote_commitment,
            "reserved_liquidity_commitment": self.reserved_liquidity_commitment,
            "min_fill_commitment": self.min_fill_commitment,
            "status": self.status,
            "maker_bond_micro_units": self.maker_bond_micro_units,
            "rebate_bps": self.rebate_bps,
            "created_slot": self.created_slot,
            "expiry_slot": self.expiry_slot,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct VerifierReceipt {
    pub receipt_id: String,
    pub receipt_index: u64,
    pub microbatch_id: String,
    pub slot_id: String,
    pub verifier_commitment: String,
    pub status: ReceiptStatus,
    pub preconfirmation_root: String,
    pub attestation_root: String,
    pub recursive_proof_root: String,
    pub state_diff_root: String,
    pub public_output_root: String,
    pub verified_slot: u64,
    pub expiry_slot: u64,
}

impl VerifierReceipt {
    pub fn new(
        receipt_index: u64,
        microbatch_id: impl Into<String>,
        slot_id: impl Into<String>,
        verifier_commitment: impl Into<String>,
        attestation_root: impl Into<String>,
        recursive_proof_root: impl Into<String>,
        verified_slot: u64,
        config: &Config,
    ) -> Result<Self> {
        let microbatch_id = microbatch_id.into();
        let slot_id = slot_id.into();
        let verifier_commitment = verifier_commitment.into();
        let attestation_root = attestation_root.into();
        let recursive_proof_root = recursive_proof_root.into();
        ensure_non_empty(&microbatch_id, "microbatch_id")?;
        ensure_non_empty(&slot_id, "slot_id")?;
        ensure_non_empty(&verifier_commitment, "verifier_commitment")?;
        ensure_non_empty(&attestation_root, "attestation_root")?;
        ensure_non_empty(&recursive_proof_root, "recursive_proof_root")?;
        let receipt_id = deterministic_id(
            "verifier-receipt-id",
            &[
                HashPart::Int(receipt_index as i128),
                HashPart::Str(&microbatch_id),
                HashPart::Str(&slot_id),
                HashPart::Str(&verifier_commitment),
            ],
        );
        Ok(Self {
            receipt_id: receipt_id.clone(),
            receipt_index,
            microbatch_id,
            slot_id,
            verifier_commitment,
            status: ReceiptStatus::Published,
            preconfirmation_root: deterministic_id(
                "receipt-preconfirmation-root",
                &[HashPart::Str(&receipt_id)],
            ),
            attestation_root,
            recursive_proof_root,
            state_diff_root: deterministic_id(
                "receipt-state-diff-root",
                &[HashPart::Str(&receipt_id)],
            ),
            public_output_root: deterministic_id(
                "receipt-public-output-root",
                &[HashPart::Str(&receipt_id)],
            ),
            verified_slot,
            expiry_slot: verified_slot.saturating_add(config.receipt_ttl_slots),
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "receipt_index": self.receipt_index,
            "microbatch_id": self.microbatch_id,
            "slot_id": self.slot_id,
            "verifier_commitment": self.verifier_commitment,
            "status": self.status,
            "preconfirmation_root": self.preconfirmation_root,
            "attestation_root": self.attestation_root,
            "recursive_proof_root": self.recursive_proof_root,
            "state_diff_root": self.state_diff_root,
            "public_output_root": self.public_output_root,
            "verified_slot": self.verified_slot,
            "expiry_slot": self.expiry_slot,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SlashingEvidence {
    pub evidence_id: String,
    pub evidence_index: u64,
    pub reason: SlashingReason,
    pub accused_commitment: String,
    pub lane_id: Option<String>,
    pub microbatch_id: Option<String>,
    pub slot_id: Option<String>,
    pub committee_id: Option<String>,
    pub evidence_root: String,
    pub conflicting_transcript_root: String,
    pub slash_amount_micro_units: u64,
    pub opened_slot: u64,
    pub resolved: bool,
}

impl SlashingEvidence {
    pub fn new(
        evidence_index: u64,
        reason: SlashingReason,
        accused_commitment: impl Into<String>,
        evidence_root: impl Into<String>,
        conflicting_transcript_root: impl Into<String>,
        slash_base_micro_units: u64,
        opened_slot: u64,
        config: &Config,
    ) -> Result<Self> {
        let accused_commitment = accused_commitment.into();
        let evidence_root = evidence_root.into();
        let conflicting_transcript_root = conflicting_transcript_root.into();
        ensure_non_empty(&accused_commitment, "accused_commitment")?;
        ensure_non_empty(&evidence_root, "evidence_root")?;
        ensure_non_empty(&conflicting_transcript_root, "conflicting_transcript_root")?;
        let evidence_id = deterministic_id(
            "slashing-evidence-id",
            &[
                HashPart::Int(evidence_index as i128),
                HashPart::Str(reason.as_str()),
                HashPart::Str(&accused_commitment),
                HashPart::Str(&evidence_root),
            ],
        );
        Ok(Self {
            evidence_id,
            evidence_index,
            reason,
            accused_commitment,
            lane_id: None,
            microbatch_id: None,
            slot_id: None,
            committee_id: None,
            evidence_root,
            conflicting_transcript_root,
            slash_amount_micro_units: bps_amount(slash_base_micro_units, config.slash_bps),
            opened_slot,
            resolved: false,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "evidence_id": self.evidence_id,
            "evidence_index": self.evidence_index,
            "reason": self.reason,
            "accused_commitment": self.accused_commitment,
            "lane_id": self.lane_id,
            "microbatch_id": self.microbatch_id,
            "slot_id": self.slot_id,
            "committee_id": self.committee_id,
            "evidence_root": self.evidence_root,
            "conflicting_transcript_root": self.conflicting_transcript_root,
            "slash_amount_micro_units": self.slash_amount_micro_units,
            "opened_slot": self.opened_slot,
            "resolved": self.resolved,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RuntimeEvent {
    pub event_id: String,
    pub event_index: u64,
    pub kind: String,
    pub subject_id: String,
    pub slot: u64,
    pub record_root: String,
}

impl RuntimeEvent {
    pub fn new(
        event_index: u64,
        kind: impl Into<String>,
        subject_id: impl Into<String>,
        slot: u64,
        record: &Value,
    ) -> Result<Self> {
        let kind = kind.into();
        let subject_id = subject_id.into();
        ensure_non_empty(&kind, "event kind")?;
        ensure_non_empty(&subject_id, "event subject")?;
        let record_root = value_root("runtime-event-record", record);
        let event_id = deterministic_id(
            "runtime-event-id",
            &[
                HashPart::Int(event_index as i128),
                HashPart::Str(&kind),
                HashPart::Str(&subject_id),
                HashPart::Str(&record_root),
            ],
        );
        Ok(Self {
            event_id,
            event_index,
            kind,
            subject_id,
            slot,
            record_root,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "event_id": self.event_id,
            "event_index": self.event_index,
            "kind": self.kind,
            "subject_id": self.subject_id,
            "slot": self.slot,
            "record_root": self.record_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub lanes: BTreeMap<String, EncryptedMicrobatchLane>,
    pub microbatches: BTreeMap<String, ConfidentialMicrobatch>,
    pub sequencing_slots: BTreeMap<String, SequencingSlot>,
    pub committees: BTreeMap<String, PqCommittee>,
    pub attestations: BTreeMap<String, PqAttestation>,
    pub qos_samples: BTreeMap<String, LatencyQosSample>,
    pub cancellation_nullifier_fences: BTreeMap<String, CancellationNullifierFence>,
    pub recursive_proof_hints: BTreeMap<String, RecursiveProofHint>,
    pub fee_rebates: BTreeMap<String, FeeRebate>,
    pub maker_reservations: BTreeMap<String, MakerReservation>,
    pub verifier_receipts: BTreeMap<String, VerifierReceipt>,
    pub slashing_evidence: BTreeMap<String, SlashingEvidence>,
    pub events: BTreeMap<String, RuntimeEvent>,
}

impl State {
    pub fn devnet() -> Self {
        let config = Config::devnet();
        let counters = Counters::devnet();
        let roots = Roots::empty(&config, &counters);
        let mut state = Self {
            config,
            counters,
            roots,
            lanes: BTreeMap::new(),
            microbatches: BTreeMap::new(),
            sequencing_slots: BTreeMap::new(),
            committees: BTreeMap::new(),
            attestations: BTreeMap::new(),
            qos_samples: BTreeMap::new(),
            cancellation_nullifier_fences: BTreeMap::new(),
            recursive_proof_hints: BTreeMap::new(),
            fee_rebates: BTreeMap::new(),
            maker_reservations: BTreeMap::new(),
            verifier_receipts: BTreeMap::new(),
            slashing_evidence: BTreeMap::new(),
            events: BTreeMap::new(),
        };
        state.seed_devnet_records();
        state.refresh_roots();
        state
    }

    pub fn state_root(&self) -> String {
        state_root_from_public_record(&self.public_record())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "hash_suite": HASH_SUITE,
            "pq_attestation_suite": PQ_ATTESTATION_SUITE,
            "encrypted_lane_suite": ENCRYPTED_LANE_SUITE,
            "sequencing_slot_suite": SEQUENCING_SLOT_SUITE,
            "nullifier_fence_suite": NULLIFIER_FENCE_SUITE,
            "recursive_proof_hint_suite": RECURSIVE_PROOF_HINT_SUITE,
            "fee_rebate_suite": FEE_REBATE_SUITE,
            "maker_reservation_suite": MAKER_RESERVATION_SUITE,
            "verifier_receipt_suite": VERIFIER_RECEIPT_SUITE,
            "slashing_evidence_suite": SLASHING_EVIDENCE_SUITE,
            "chain_id": CHAIN_ID,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
        })
    }

    pub fn validate(&self) -> Result<()> {
        self.config.validate()?;
        ensure_capacity(self.lanes.len(), self.config.max_lanes, "lanes")?;
        ensure_capacity(
            self.microbatches.len(),
            self.config.max_microbatches,
            "microbatches",
        )?;
        ensure_capacity(
            self.sequencing_slots.len(),
            self.config.max_sequencing_slots,
            "sequencing_slots",
        )?;
        ensure_capacity(
            self.committees.len(),
            self.config.max_committees,
            "committees",
        )?;
        ensure_capacity(
            self.attestations.len(),
            self.config.max_attestations,
            "attestations",
        )?;
        ensure_capacity(
            self.qos_samples.len(),
            self.config.max_qos_samples,
            "qos_samples",
        )?;
        ensure_capacity(
            self.cancellation_nullifier_fences.len(),
            self.config.max_nullifier_fences,
            "cancellation_nullifier_fences",
        )?;
        ensure_capacity(
            self.recursive_proof_hints.len(),
            self.config.max_recursive_proof_hints,
            "recursive_proof_hints",
        )?;
        ensure_capacity(
            self.fee_rebates.len(),
            self.config.max_fee_rebates,
            "fee_rebates",
        )?;
        ensure_capacity(
            self.maker_reservations.len(),
            self.config.max_maker_reservations,
            "maker_reservations",
        )?;
        ensure_capacity(
            self.verifier_receipts.len(),
            self.config.max_verifier_receipts,
            "verifier_receipts",
        )?;
        ensure_capacity(
            self.slashing_evidence.len(),
            self.config.max_slashing_evidence,
            "slashing_evidence",
        )?;
        ensure_capacity(self.events.len(), self.config.max_events, "events")?;
        Ok(())
    }

    pub fn register_lane(
        &mut self,
        kind: LaneKind,
        owner_commitment: impl Into<String>,
        lane_public_key_commitment: impl Into<String>,
        threshold_key_commitment: impl Into<String>,
    ) -> Result<String> {
        self.ensure_can_insert(self.lanes.len(), self.config.max_lanes, "lanes")?;
        let lane = EncryptedMicrobatchLane::new(
            self.counters.next_lane_index,
            kind,
            owner_commitment,
            lane_public_key_commitment,
            threshold_key_commitment,
            self.counters.epoch,
            &self.config,
        )?;
        let lane_id = lane.lane_id.clone();
        self.counters.next_lane_index = self.counters.next_lane_index.saturating_add(1);
        self.lanes.insert(lane_id.clone(), lane.clone());
        self.push_event("lane_registered", &lane_id, &lane.public_record())?;
        self.refresh_roots();
        Ok(lane_id)
    }

    pub fn open_lane(&mut self, lane_id: &str, slot: u64) -> Result<()> {
        let record = {
            let lane = self
                .lanes
                .get_mut(lane_id)
                .ok_or_else(|| format!("unknown lane: {lane_id}"))?;
            if matches!(lane.status, LaneStatus::Slashed | LaneStatus::Retired) {
                return Err("lane cannot be opened from terminal status".to_string());
            }
            lane.status = LaneStatus::Open;
            lane.updated_slot = slot;
            lane.public_record()
        };
        self.push_event("lane_opened", lane_id, &record)?;
        self.refresh_roots();
        Ok(())
    }

    pub fn enqueue_microbatch(
        &mut self,
        lane_id: &str,
        qos_class: QosClass,
        encrypted_payload_commitment: impl Into<String>,
        ciphertext_root: impl Into<String>,
        item_commitment_root: impl Into<String>,
        item_count: u32,
        byte_size: u64,
        ingress_slot: u64,
    ) -> Result<String> {
        self.ensure_can_insert(
            self.microbatches.len(),
            self.config.max_microbatches,
            "microbatches",
        )?;
        {
            let lane = self
                .lanes
                .get(lane_id)
                .ok_or_else(|| format!("unknown lane: {lane_id}"))?;
            if !lane.status.accepts_microbatches() {
                return Err("lane is not accepting microbatches".to_string());
            }
            if lane.inflight_microbatches >= lane.max_inflight_microbatches as u64 {
                return Err("lane inflight microbatch limit reached".to_string());
            }
        }
        let microbatch = ConfidentialMicrobatch::new(
            self.counters.next_microbatch_index,
            lane_id,
            qos_class,
            encrypted_payload_commitment,
            ciphertext_root,
            item_commitment_root,
            item_count,
            byte_size,
            ingress_slot,
            &self.config,
        )?;
        let microbatch_id = microbatch.microbatch_id.clone();
        self.counters.next_microbatch_index = self.counters.next_microbatch_index.saturating_add(1);
        self.microbatches
            .insert(microbatch_id.clone(), microbatch.clone());
        if let Some(lane) = self.lanes.get_mut(lane_id) {
            lane.total_encrypted_microbatches = lane.total_encrypted_microbatches.saturating_add(1);
            lane.inflight_microbatches = lane.inflight_microbatches.saturating_add(1);
            lane.updated_slot = ingress_slot;
        }
        self.push_event(
            "microbatch_enqueued",
            &microbatch_id,
            &microbatch.public_record(),
        )?;
        self.refresh_roots();
        Ok(microbatch_id)
    }

    pub fn create_slot(
        &mut self,
        lane_id: &str,
        leader_commitment: impl Into<String>,
        qos_class: QosClass,
    ) -> Result<String> {
        self.ensure_can_insert(
            self.sequencing_slots.len(),
            self.config.max_sequencing_slots,
            "sequencing_slots",
        )?;
        if !self.lanes.contains_key(lane_id) {
            return Err(format!("unknown lane: {lane_id}"));
        }
        let slot = SequencingSlot::new(
            self.counters.next_slot_index,
            lane_id,
            leader_commitment,
            qos_class,
            &self.config,
        )?;
        let slot_id = slot.slot_id.clone();
        self.counters.next_slot_index = self.counters.next_slot_index.saturating_add(1);
        self.sequencing_slots.insert(slot_id.clone(), slot.clone());
        self.push_event("slot_created", &slot_id, &slot.public_record())?;
        self.refresh_roots();
        Ok(slot_id)
    }

    pub fn assign_microbatch_to_slot(&mut self, microbatch_id: &str, slot_id: &str) -> Result<()> {
        let (item_count, byte_size, lane_id, microbatch_record) = {
            let microbatch = self
                .microbatches
                .get_mut(microbatch_id)
                .ok_or_else(|| format!("unknown microbatch: {microbatch_id}"))?;
            if !matches!(
                microbatch.status,
                MicrobatchStatus::Encrypted | MicrobatchStatus::Fenced
            ) {
                return Err(
                    "microbatch cannot be assigned to a slot from current status".to_string(),
                );
            }
            microbatch.slot_id = Some(slot_id.to_string());
            microbatch.status = MicrobatchStatus::SlotAssigned;
            (
                microbatch.item_count,
                microbatch.byte_size,
                microbatch.lane_id.clone(),
                microbatch.public_record(),
            )
        };
        let slot_record = {
            let slot = self
                .sequencing_slots
                .get_mut(slot_id)
                .ok_or_else(|| format!("unknown sequencing slot: {slot_id}"))?;
            if slot.lane_id != lane_id {
                return Err("microbatch lane does not match sequencing slot lane".to_string());
            }
            if !slot.status.accepts_batch() {
                return Err("sequencing slot is not accepting microbatches".to_string());
            }
            if slot.used_items.saturating_add(item_count) > slot.capacity_items {
                return Err("sequencing slot item capacity exceeded".to_string());
            }
            if slot.used_bytes.saturating_add(byte_size) > slot.capacity_bytes {
                return Err("sequencing slot byte capacity exceeded".to_string());
            }
            slot.status = SlotStatus::Filling;
            slot.used_items = slot.used_items.saturating_add(item_count);
            slot.used_bytes = slot.used_bytes.saturating_add(byte_size);
            if !slot.microbatch_ids.iter().any(|id| id == microbatch_id) {
                slot.microbatch_ids.push(microbatch_id.to_string());
            }
            slot.microbatch_root = merkle_string_root("slot_microbatch_ids", &slot.microbatch_ids);
            slot.public_record()
        };
        self.push_event(
            "microbatch_slot_assigned",
            microbatch_id,
            &microbatch_record,
        )?;
        self.push_event("slot_filled", slot_id, &slot_record)?;
        self.refresh_roots();
        Ok(())
    }

    pub fn register_committee(
        &mut self,
        lane_id: &str,
        member_root: impl Into<String>,
        aggregate_pq_public_key_root: impl Into<String>,
        stake_weight: u64,
    ) -> Result<String> {
        self.ensure_can_insert(
            self.committees.len(),
            self.config.max_committees,
            "committees",
        )?;
        if !self.lanes.contains_key(lane_id) {
            return Err(format!("unknown lane: {lane_id}"));
        }
        let committee = PqCommittee::new(
            self.counters.next_committee_index,
            self.counters.epoch,
            lane_id,
            member_root,
            aggregate_pq_public_key_root,
            stake_weight,
            &self.config,
        )?;
        let committee_id = committee.committee_id.clone();
        self.counters.next_committee_index = self.counters.next_committee_index.saturating_add(1);
        self.committees
            .insert(committee_id.clone(), committee.clone());
        self.push_event(
            "committee_registered",
            &committee_id,
            &committee.public_record(),
        )?;
        self.refresh_roots();
        Ok(committee_id)
    }

    pub fn assign_committee_to_microbatch(
        &mut self,
        microbatch_id: &str,
        committee_id: &str,
    ) -> Result<()> {
        let lane_id = self
            .microbatches
            .get(microbatch_id)
            .ok_or_else(|| format!("unknown microbatch: {microbatch_id}"))?
            .lane_id
            .clone();
        {
            let committee = self
                .committees
                .get(committee_id)
                .ok_or_else(|| format!("unknown committee: {committee_id}"))?;
            if committee.lane_id != lane_id {
                return Err("committee lane does not match microbatch lane".to_string());
            }
            if !committee.status.can_attest() {
                return Err("committee cannot attest in current status".to_string());
            }
        }
        let microbatch_record = {
            let microbatch = self
                .microbatches
                .get_mut(microbatch_id)
                .ok_or_else(|| format!("unknown microbatch: {microbatch_id}"))?;
            microbatch.committee_id = Some(committee_id.to_string());
            microbatch.status = MicrobatchStatus::CommitteeAssigned;
            microbatch.public_record()
        };
        let committee_record = {
            let committee = self
                .committees
                .get_mut(committee_id)
                .ok_or_else(|| format!("unknown committee: {committee_id}"))?;
            committee.status = CommitteeStatus::Assigned;
            committee
                .assigned_microbatch_ids
                .insert(microbatch_id.to_string());
            committee.public_record()
        };
        self.push_event(
            "microbatch_committee_assigned",
            microbatch_id,
            &microbatch_record,
        )?;
        self.push_event(
            "committee_microbatch_assigned",
            committee_id,
            &committee_record,
        )?;
        self.refresh_roots();
        Ok(())
    }

    pub fn add_attestation(
        &mut self,
        committee_id: &str,
        microbatch_id: &str,
        signer_commitment: impl Into<String>,
        signer_weight: u64,
        verdict: AttestationVerdict,
        latency_ms: u64,
        attested_slot: u64,
    ) -> Result<String> {
        self.ensure_can_insert(
            self.attestations.len(),
            self.config.max_attestations,
            "attestations",
        )?;
        let slot_id = self
            .microbatches
            .get(microbatch_id)
            .ok_or_else(|| format!("unknown microbatch: {microbatch_id}"))?
            .slot_id
            .clone()
            .ok_or_else(|| "microbatch has no sequencing slot".to_string())?;
        let committee = self
            .committees
            .get(committee_id)
            .ok_or_else(|| format!("unknown committee: {committee_id}"))?;
        if !committee.assigned_microbatch_ids.contains(microbatch_id) {
            return Err("committee is not assigned to microbatch".to_string());
        }
        let attestation = PqAttestation::new(
            self.counters.next_attestation_index,
            committee_id,
            microbatch_id,
            &slot_id,
            signer_commitment,
            signer_weight,
            verdict,
            latency_ms,
            attested_slot,
        )?;
        let attestation_id = attestation.attestation_id.clone();
        self.counters.next_attestation_index =
            self.counters.next_attestation_index.saturating_add(1);
        self.attestations
            .insert(attestation_id.clone(), attestation.clone());
        self.recompute_committee_status(committee_id)?;
        if verdict.contributes_to_quorum() {
            if let Some(microbatch) = self.microbatches.get_mut(microbatch_id) {
                microbatch.status = MicrobatchStatus::Attesting;
            }
        }
        self.push_event(
            "pq_attestation_recorded",
            &attestation_id,
            &attestation.public_record(),
        )?;
        self.refresh_roots();
        Ok(attestation_id)
    }

    pub fn preconfirm_microbatch(
        &mut self,
        microbatch_id: &str,
        preconfirmed_slot: u64,
    ) -> Result<()> {
        let (lane_id, slot_id, microbatch_record) = {
            let microbatch = self
                .microbatches
                .get_mut(microbatch_id)
                .ok_or_else(|| format!("unknown microbatch: {microbatch_id}"))?;
            if !microbatch.status.live() {
                return Err("microbatch cannot be preconfirmed from terminal status".to_string());
            }
            let slot_id = microbatch
                .slot_id
                .clone()
                .ok_or_else(|| "microbatch has no sequencing slot".to_string())?;
            microbatch.status = MicrobatchStatus::Preconfirmed;
            microbatch.preconfirmed_slot = Some(preconfirmed_slot);
            (
                microbatch.lane_id.clone(),
                slot_id,
                microbatch.public_record(),
            )
        };
        if let Some(slot) = self.sequencing_slots.get_mut(&slot_id) {
            slot.status = SlotStatus::Preconfirmed;
        }
        if let Some(lane) = self.lanes.get_mut(&lane_id) {
            lane.total_preconfirmed_microbatches =
                lane.total_preconfirmed_microbatches.saturating_add(1);
            lane.updated_slot = preconfirmed_slot;
        }
        self.push_event("microbatch_preconfirmed", microbatch_id, &microbatch_record)?;
        self.refresh_roots();
        Ok(())
    }

    pub fn add_qos_sample(
        &mut self,
        lane_id: &str,
        microbatch_id: &str,
        slot_id: &str,
        qos_class: QosClass,
        ingress_ms: u64,
        preconfirmed_ms: u64,
    ) -> Result<String> {
        self.ensure_can_insert(
            self.qos_samples.len(),
            self.config.max_qos_samples,
            "qos_samples",
        )?;
        let sample = LatencyQosSample::new(
            self.counters.next_qos_sample_index,
            lane_id,
            microbatch_id,
            slot_id,
            qos_class,
            ingress_ms,
            preconfirmed_ms,
            &self.config,
        )?;
        let sample_id = sample.sample_id.clone();
        self.counters.next_qos_sample_index = self.counters.next_qos_sample_index.saturating_add(1);
        self.qos_samples.insert(sample_id.clone(), sample.clone());
        self.recompute_lane_qos(lane_id);
        self.push_event("qos_sample_recorded", &sample_id, &sample.public_record())?;
        self.refresh_roots();
        Ok(sample_id)
    }

    pub fn add_fence(
        &mut self,
        kind: FenceKind,
        lane_id: &str,
        microbatch_id: &str,
        nullifier_commitment: impl Into<String>,
        cancellation_commitment: impl Into<String>,
        created_slot: u64,
    ) -> Result<String> {
        self.ensure_can_insert(
            self.cancellation_nullifier_fences.len(),
            self.config.max_nullifier_fences,
            "cancellation_nullifier_fences",
        )?;
        let fence = CancellationNullifierFence::new(
            self.counters.next_fence_index,
            kind,
            lane_id,
            microbatch_id,
            nullifier_commitment,
            cancellation_commitment,
            created_slot,
            &self.config,
        )?;
        let fence_id = fence.fence_id.clone();
        self.counters.next_fence_index = self.counters.next_fence_index.saturating_add(1);
        self.cancellation_nullifier_fences
            .insert(fence_id.clone(), fence.clone());
        if let Some(microbatch) = self.microbatches.get_mut(microbatch_id) {
            if matches!(microbatch.status, MicrobatchStatus::Encrypted) {
                microbatch.status = MicrobatchStatus::Fenced;
            }
        }
        self.push_event("fence_recorded", &fence_id, &fence.public_record())?;
        self.refresh_roots();
        Ok(fence_id)
    }

    pub fn add_recursive_proof_hint(
        &mut self,
        kind: ProofHintKind,
        microbatch_id: &str,
        slot_id: &str,
        circuit_commitment: impl Into<String>,
        witness_root: impl Into<String>,
        expected_proof_weight: u64,
        created_slot: u64,
    ) -> Result<String> {
        self.ensure_can_insert(
            self.recursive_proof_hints.len(),
            self.config.max_recursive_proof_hints,
            "recursive_proof_hints",
        )?;
        let hint = RecursiveProofHint::new(
            self.counters.next_proof_hint_index,
            kind,
            microbatch_id,
            slot_id,
            circuit_commitment,
            witness_root,
            expected_proof_weight,
            created_slot,
            &self.config,
        )?;
        let hint_id = hint.hint_id.clone();
        self.counters.next_proof_hint_index = self.counters.next_proof_hint_index.saturating_add(1);
        self.recursive_proof_hints
            .insert(hint_id.clone(), hint.clone());
        self.push_event(
            "recursive_proof_hint_added",
            &hint_id,
            &hint.public_record(),
        )?;
        self.refresh_roots();
        Ok(hint_id)
    }

    pub fn add_fee_rebate(
        &mut self,
        microbatch_id: &str,
        beneficiary_commitment: impl Into<String>,
        amount_micro_units: u64,
        rebate_bps: u64,
        created_slot: u64,
    ) -> Result<String> {
        self.ensure_can_insert(
            self.fee_rebates.len(),
            self.config.max_fee_rebates,
            "fee_rebates",
        )?;
        let rebate = FeeRebate::new(
            self.counters.next_rebate_index,
            microbatch_id,
            beneficiary_commitment,
            amount_micro_units,
            rebate_bps,
            created_slot,
            &self.config,
        )?;
        let rebate_id = rebate.rebate_id.clone();
        self.counters.next_rebate_index = self.counters.next_rebate_index.saturating_add(1);
        self.fee_rebates.insert(rebate_id.clone(), rebate.clone());
        self.push_event("fee_rebate_added", &rebate_id, &rebate.public_record())?;
        self.refresh_roots();
        Ok(rebate_id)
    }

    pub fn add_maker_reservation(
        &mut self,
        maker_commitment: impl Into<String>,
        lane_id: &str,
        quote_commitment: impl Into<String>,
        reserved_liquidity_commitment: impl Into<String>,
        created_slot: u64,
    ) -> Result<String> {
        self.ensure_can_insert(
            self.maker_reservations.len(),
            self.config.max_maker_reservations,
            "maker_reservations",
        )?;
        if !self.config.enable_maker_reservations {
            return Err("maker reservations are disabled".to_string());
        }
        if !self.lanes.contains_key(lane_id) {
            return Err(format!("unknown lane: {lane_id}"));
        }
        let reservation = MakerReservation::new(
            self.counters.next_reservation_index,
            maker_commitment,
            lane_id,
            quote_commitment,
            reserved_liquidity_commitment,
            created_slot,
            &self.config,
        )?;
        let reservation_id = reservation.reservation_id.clone();
        self.counters.next_reservation_index =
            self.counters.next_reservation_index.saturating_add(1);
        self.maker_reservations
            .insert(reservation_id.clone(), reservation.clone());
        self.push_event(
            "maker_reservation_added",
            &reservation_id,
            &reservation.public_record(),
        )?;
        self.refresh_roots();
        Ok(reservation_id)
    }

    pub fn bind_maker_reservation(
        &mut self,
        reservation_id: &str,
        microbatch_id: &str,
    ) -> Result<()> {
        let reservation_record = {
            let reservation = self
                .maker_reservations
                .get_mut(reservation_id)
                .ok_or_else(|| format!("unknown maker reservation: {reservation_id}"))?;
            if !matches!(reservation.status, ReservationStatus::Open) {
                return Err("maker reservation is not open".to_string());
            }
            reservation.microbatch_id = Some(microbatch_id.to_string());
            reservation.status = ReservationStatus::Bound;
            reservation.public_record()
        };
        {
            let microbatch = self
                .microbatches
                .get_mut(microbatch_id)
                .ok_or_else(|| format!("unknown microbatch: {microbatch_id}"))?;
            microbatch.maker_reservation_id = Some(reservation_id.to_string());
        }
        self.push_event(
            "maker_reservation_bound",
            reservation_id,
            &reservation_record,
        )?;
        self.refresh_roots();
        Ok(())
    }

    pub fn add_verifier_receipt(
        &mut self,
        microbatch_id: &str,
        verifier_commitment: impl Into<String>,
        recursive_proof_root: impl Into<String>,
        verified_slot: u64,
    ) -> Result<String> {
        self.ensure_can_insert(
            self.verifier_receipts.len(),
            self.config.max_verifier_receipts,
            "verifier_receipts",
        )?;
        let slot_id = self
            .microbatches
            .get(microbatch_id)
            .ok_or_else(|| format!("unknown microbatch: {microbatch_id}"))?
            .slot_id
            .clone()
            .ok_or_else(|| "microbatch has no sequencing slot".to_string())?;
        let attestation_root = self.attestation_root_for_microbatch(microbatch_id);
        let receipt = VerifierReceipt::new(
            self.counters.next_receipt_index,
            microbatch_id,
            &slot_id,
            verifier_commitment,
            attestation_root,
            recursive_proof_root,
            verified_slot,
            &self.config,
        )?;
        let receipt_id = receipt.receipt_id.clone();
        self.counters.next_receipt_index = self.counters.next_receipt_index.saturating_add(1);
        self.verifier_receipts
            .insert(receipt_id.clone(), receipt.clone());
        if let Some(microbatch) = self.microbatches.get_mut(microbatch_id) {
            microbatch.status = MicrobatchStatus::Receipted;
            microbatch.receipt_id = Some(receipt_id.clone());
        }
        if let Some(slot) = self.sequencing_slots.get_mut(&slot_id) {
            slot.status = SlotStatus::Receipted;
        }
        self.push_event(
            "verifier_receipt_added",
            &receipt_id,
            &receipt.public_record(),
        )?;
        self.refresh_roots();
        Ok(receipt_id)
    }

    pub fn add_slashing_evidence(
        &mut self,
        reason: SlashingReason,
        accused_commitment: impl Into<String>,
        evidence_root: impl Into<String>,
        conflicting_transcript_root: impl Into<String>,
        slash_base_micro_units: u64,
        opened_slot: u64,
    ) -> Result<String> {
        self.ensure_can_insert(
            self.slashing_evidence.len(),
            self.config.max_slashing_evidence,
            "slashing_evidence",
        )?;
        let evidence = SlashingEvidence::new(
            self.counters.next_slashing_index,
            reason,
            accused_commitment,
            evidence_root,
            conflicting_transcript_root,
            slash_base_micro_units,
            opened_slot,
            &self.config,
        )?;
        let evidence_id = evidence.evidence_id.clone();
        self.counters.next_slashing_index = self.counters.next_slashing_index.saturating_add(1);
        self.slashing_evidence
            .insert(evidence_id.clone(), evidence.clone());
        self.push_event(
            "slashing_evidence_added",
            &evidence_id,
            &evidence.public_record(),
        )?;
        self.refresh_roots();
        Ok(evidence_id)
    }

    pub fn cancel_microbatch(&mut self, microbatch_id: &str, cancellation_slot: u64) -> Result<()> {
        let (lane_id, record) = {
            let microbatch = self
                .microbatches
                .get_mut(microbatch_id)
                .ok_or_else(|| format!("unknown microbatch: {microbatch_id}"))?;
            if !microbatch.status.live() {
                return Err("microbatch cannot be cancelled from terminal status".to_string());
            }
            microbatch.status = MicrobatchStatus::Cancelled;
            (microbatch.lane_id.clone(), microbatch.public_record())
        };
        if let Some(lane) = self.lanes.get_mut(&lane_id) {
            lane.total_cancelled_microbatches = lane.total_cancelled_microbatches.saturating_add(1);
            lane.inflight_microbatches = lane.inflight_microbatches.saturating_sub(1);
            lane.updated_slot = cancellation_slot;
        }
        self.push_event("microbatch_cancelled", microbatch_id, &record)?;
        self.refresh_roots();
        Ok(())
    }

    pub fn settle_microbatch(&mut self, microbatch_id: &str, settled_slot: u64) -> Result<()> {
        let (lane_id, record) = {
            let microbatch = self
                .microbatches
                .get_mut(microbatch_id)
                .ok_or_else(|| format!("unknown microbatch: {microbatch_id}"))?;
            if !matches!(
                microbatch.status,
                MicrobatchStatus::Preconfirmed | MicrobatchStatus::Receipted
            ) {
                return Err(
                    "microbatch must be preconfirmed or receipted before settlement".to_string(),
                );
            }
            microbatch.status = MicrobatchStatus::Settled;
            (microbatch.lane_id.clone(), microbatch.public_record())
        };
        if let Some(lane) = self.lanes.get_mut(&lane_id) {
            lane.inflight_microbatches = lane.inflight_microbatches.saturating_sub(1);
            lane.updated_slot = settled_slot;
        }
        self.push_event("microbatch_settled", microbatch_id, &record)?;
        self.refresh_roots();
        Ok(())
    }

    pub fn refresh_roots(&mut self) {
        self.roots = Roots {
            config_root: value_root("config", &self.config.public_record()),
            counters_root: value_root("counters", &self.counters.public_record()),
            lanes_root: map_root("lanes", &self.lanes, EncryptedMicrobatchLane::public_record),
            microbatches_root: map_root(
                "microbatches",
                &self.microbatches,
                ConfidentialMicrobatch::public_record,
            ),
            sequencing_slots_root: map_root(
                "sequencing_slots",
                &self.sequencing_slots,
                SequencingSlot::public_record,
            ),
            committees_root: map_root("committees", &self.committees, PqCommittee::public_record),
            attestations_root: map_root(
                "attestations",
                &self.attestations,
                PqAttestation::public_record,
            ),
            qos_samples_root: map_root(
                "qos_samples",
                &self.qos_samples,
                LatencyQosSample::public_record,
            ),
            cancellation_nullifier_fences_root: map_root(
                "cancellation_nullifier_fences",
                &self.cancellation_nullifier_fences,
                CancellationNullifierFence::public_record,
            ),
            recursive_proof_hints_root: map_root(
                "recursive_proof_hints",
                &self.recursive_proof_hints,
                RecursiveProofHint::public_record,
            ),
            fee_rebates_root: map_root("fee_rebates", &self.fee_rebates, FeeRebate::public_record),
            maker_reservations_root: map_root(
                "maker_reservations",
                &self.maker_reservations,
                MakerReservation::public_record,
            ),
            verifier_receipts_root: map_root(
                "verifier_receipts",
                &self.verifier_receipts,
                VerifierReceipt::public_record,
            ),
            slashing_evidence_root: map_root(
                "slashing_evidence",
                &self.slashing_evidence,
                SlashingEvidence::public_record,
            ),
            events_root: map_root("events", &self.events, RuntimeEvent::public_record),
        };
    }

    fn seed_devnet_records(&mut self) {
        let lane_id = match self.register_lane(
            LaneKind::Swap,
            "devnet-sequencer-owner-commitment",
            "devnet-lane-pq-public-key-commitment",
            "devnet-threshold-key-commitment",
        ) {
            Ok(lane_id) => lane_id,
            Err(_) => return,
        };
        let _ = self.open_lane(&lane_id, self.counters.epoch);
        let slot_id = match self.create_slot(
            &lane_id,
            "devnet-fast-sequencer-leader-commitment",
            QosClass::Fast,
        ) {
            Ok(slot_id) => slot_id,
            Err(_) => return,
        };
        let committee_id = match self.register_committee(
            &lane_id,
            "devnet-pq-committee-member-root",
            "devnet-pq-aggregate-public-key-root",
            10_000,
        ) {
            Ok(committee_id) => committee_id,
            Err(_) => return,
        };
        let microbatch_id = match self.enqueue_microbatch(
            &lane_id,
            QosClass::Fast,
            "devnet-encrypted-payload-commitment",
            "devnet-ciphertext-root",
            "devnet-item-commitment-root",
            64,
            65_536,
            self.counters.epoch,
        ) {
            Ok(microbatch_id) => microbatch_id,
            Err(_) => return,
        };
        let _ = self.add_maker_reservation(
            "devnet-maker-commitment",
            &lane_id,
            "devnet-maker-quote-commitment",
            "devnet-reserved-liquidity-commitment",
            self.counters.epoch,
        );
        let _ = self.add_fence(
            FenceKind::Nullifier,
            &lane_id,
            &microbatch_id,
            "devnet-nullifier-commitment",
            "devnet-cancellation-commitment",
            self.counters.epoch,
        );
        let _ = self.assign_microbatch_to_slot(&microbatch_id, &slot_id);
        let _ = self.assign_committee_to_microbatch(&microbatch_id, &committee_id);
        let _ = self.add_attestation(
            &committee_id,
            &microbatch_id,
            "devnet-pq-attestor-0",
            6_700,
            AttestationVerdict::Include,
            92,
            self.counters.epoch,
        );
        let _ = self.preconfirm_microbatch(&microbatch_id, self.counters.epoch);
        let _ = self.add_qos_sample(&lane_id, &microbatch_id, &slot_id, QosClass::Fast, 0, 92);
        let _ = self.add_recursive_proof_hint(
            ProofHintKind::RecursiveAggregation,
            &microbatch_id,
            &slot_id,
            "devnet-recursive-circuit-commitment",
            "devnet-recursive-witness-root",
            4_096,
            self.counters.epoch,
        );
        let target_rebate_bps = self.config.target_rebate_bps;
        let epoch = self.counters.epoch;
        let _ = self.add_fee_rebate(
            &microbatch_id,
            "devnet-user-rebate-beneficiary",
            320,
            target_rebate_bps,
            epoch,
        );
        let _ = self.add_verifier_receipt(
            &microbatch_id,
            "devnet-verifier-commitment",
            "devnet-recursive-proof-root",
            self.counters.epoch,
        );
    }

    fn ensure_can_insert(&self, len: usize, cap: usize, label: &str) -> Result<()> {
        if len >= cap {
            Err(format!(
                "microbatch preconfirmation {label} capacity reached"
            ))
        } else {
            Ok(())
        }
    }

    fn recompute_committee_status(&mut self, committee_id: &str) -> Result<()> {
        let (quorum_weight, supermajority_weight) = {
            let committee = self
                .committees
                .get(committee_id)
                .ok_or_else(|| format!("unknown committee: {committee_id}"))?;
            (committee.quorum_weight, committee.supermajority_weight)
        };
        let included_weight = self
            .attestations
            .values()
            .filter(|attestation| {
                attestation.committee_id == committee_id
                    && attestation.verdict.contributes_to_quorum()
            })
            .map(|attestation| attestation.signer_weight)
            .fold(0_u64, u64::saturating_add);
        let status = if included_weight >= supermajority_weight {
            CommitteeStatus::SupermajorityReached
        } else if included_weight >= quorum_weight {
            CommitteeStatus::QuorumReached
        } else {
            CommitteeStatus::Attesting
        };
        if let Some(committee) = self.committees.get_mut(committee_id) {
            committee.status = status;
        }
        Ok(())
    }

    fn recompute_lane_qos(&mut self, lane_id: &str) {
        let mut total = 0_u64;
        let mut count = 0_u64;
        for sample in self
            .qos_samples
            .values()
            .filter(|sample| sample.lane_id == lane_id)
        {
            count = count.saturating_add(1);
            let score = if sample.hard_breached {
                0
            } else if sample.soft_breached {
                MAX_BPS / 2
            } else {
                MAX_BPS
            };
            total = total.saturating_add(score);
        }
        if let Some(lane) = self.lanes.get_mut(lane_id) {
            if count > 0 {
                lane.qos_score_bps = total / count;
            }
        }
    }

    fn attestation_root_for_microbatch(&self, microbatch_id: &str) -> String {
        let leaves = self
            .attestations
            .values()
            .filter(|attestation| attestation.microbatch_id == microbatch_id)
            .map(PqAttestation::public_record)
            .collect::<Vec<_>>();
        merkle_root("microbatch_attestations", &leaves)
    }

    fn push_event(&mut self, kind: &str, subject_id: &str, record: &Value) -> Result<()> {
        self.ensure_can_insert(self.events.len(), self.config.max_events, "events")?;
        let event = RuntimeEvent::new(
            self.counters.next_event_index,
            kind,
            subject_id,
            self.counters.epoch,
            record,
        )?;
        self.counters.next_event_index = self.counters.next_event_index.saturating_add(1);
        self.events.insert(event.event_id.clone(), event);
        Ok(())
    }
}

pub fn devnet_state_root() -> String {
    State::devnet().state_root()
}

pub fn devnet_public_record() -> Value {
    State::devnet().public_record()
}

pub fn state_root_from_public_record(record: &Value) -> String {
    domain_hash(
        "private-l2-fast-pq-confidential-microbatch-preconfirmation-state-root",
        &[HashPart::Str(CHAIN_ID), HashPart::Json(record)],
        32,
    )
}

fn ensure_non_empty(value: &str, label: &str) -> Result<()> {
    if value.trim().is_empty() {
        Err(format!(
            "microbatch preconfirmation {label} must be non-empty"
        ))
    } else {
        Ok(())
    }
}

fn ensure_eq(left: &str, right: &str, label: &str) -> Result<()> {
    if left == right {
        Ok(())
    } else {
        Err(format!("microbatch preconfirmation {label} mismatch"))
    }
}

fn ensure_bps(value: u64, label: &str) -> Result<()> {
    if value <= MAX_BPS {
        Ok(())
    } else {
        Err(format!(
            "microbatch preconfirmation {label} exceeds BPS range"
        ))
    }
}

fn ensure_capacity(len: usize, cap: usize, label: &str) -> Result<()> {
    if len <= cap {
        Ok(())
    } else {
        Err(format!(
            "microbatch preconfirmation {label} length exceeds configured capacity"
        ))
    }
}

fn bps_amount(amount: u64, bps: u64) -> u64 {
    amount.saturating_mul(bps) / MAX_BPS
}

fn deterministic_id(domain: &str, parts: &[HashPart<'_>]) -> String {
    let mut full_parts = Vec::with_capacity(parts.len().saturating_add(1));
    full_parts.push(HashPart::Str(CHAIN_ID));
    for part in parts {
        match part {
            HashPart::Bytes(value) => full_parts.push(HashPart::Bytes(value)),
            HashPart::Str(value) => full_parts.push(HashPart::Str(value)),
            HashPart::U64(value) => full_parts.push(HashPart::U64(*value)),
            HashPart::Int(value) => full_parts.push(HashPart::Int(*value)),
            HashPart::Json(value) => full_parts.push(HashPart::Json(value)),
        }
    }
    domain_hash(
        &format!("private-l2-fast-pq-confidential-microbatch-preconfirmation:{domain}"),
        &full_parts,
        32,
    )
}

fn value_root(domain: &str, value: &Value) -> String {
    domain_hash(
        &format!("private-l2-fast-pq-confidential-microbatch-preconfirmation:{domain}"),
        &[HashPart::Str(CHAIN_ID), HashPart::Json(value)],
        32,
    )
}

fn empty_root(domain: &str) -> String {
    merkle_root(
        &format!("private-l2-fast-pq-confidential-microbatch-preconfirmation:{domain}"),
        &[],
    )
}

fn map_root<T, F>(domain: &str, map: &BTreeMap<String, T>, record_fn: F) -> String
where
    F: Fn(&T) -> Value,
{
    let leaves = map.values().map(record_fn).collect::<Vec<_>>();
    merkle_root(
        &format!("private-l2-fast-pq-confidential-microbatch-preconfirmation:{domain}"),
        &leaves,
    )
}

fn merkle_string_root(domain: &str, values: &[String]) -> String {
    let leaves = values
        .iter()
        .map(|value| json!({ "value": value }))
        .collect::<Vec<_>>();
    merkle_root(
        &format!("private-l2-fast-pq-confidential-microbatch-preconfirmation:{domain}"),
        &leaves,
    )
}
