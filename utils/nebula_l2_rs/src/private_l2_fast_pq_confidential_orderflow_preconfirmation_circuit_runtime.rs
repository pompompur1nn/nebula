use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2FastPqConfidentialOrderflowPreconfirmationCircuitRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PROTOCOL_VERSION: &str =
    "nebula-private-l2-fast-pq-confidential-orderflow-preconfirmation-circuit-runtime-v1";
pub const PRIVATE_L2_FAST_PQ_CONFIDENTIAL_ORDERFLOW_PRECONFIRMATION_CIRCUIT_PROTOCOL: &str =
    PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_ATTESTATION_SUITE: &str = "ML-DSA-87+SLH-DSA-SHAKE-256f-committee-attestation-v1";
pub const PQ_ENVELOPE_SUITE: &str = "ML-KEM-1024-threshold-orderflow-envelope-v1";
pub const PRECONFIRMATION_PROOF_SUITE: &str =
    "zk-fast-confidential-orderflow-preconfirmation-proof-v1";
pub const RECURSIVE_RECEIPT_SUITE: &str = "nova-pq-private-orderflow-recursive-receipt-v1";
pub const NULLIFIER_FENCE_SUITE: &str = "monero-l2-private-orderflow-nullifier-fence-v1";
pub const MEV_CHALLENGE_SUITE: &str = "confidential-orderflow-mev-challenge-evidence-v1";
pub const SPONSOR_REBATE_SUITE: &str = "low-fee-private-orderflow-sponsor-rebate-v1";
pub const DEFAULT_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEVNET_L2_HEIGHT: u64 = 2_140_000;
pub const DEVNET_MONERO_HEIGHT: u64 = 3_310_000;
pub const DEVNET_EPOCH: u64 = 4_096;
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 16_384;
pub const DEFAULT_TARGET_PRIVACY_SET_SIZE: u64 = 131_072;
pub const DEFAULT_TARGET_PRECONF_MS: u64 = 180;
pub const DEFAULT_MAX_PRECONF_MS: u64 = 650;
pub const DEFAULT_SLOT_WIDTH_MS: u64 = 80;
pub const DEFAULT_ENVELOPE_TTL_SLOTS: u64 = 24;
pub const DEFAULT_PROOF_TTL_SLOTS: u64 = 32;
pub const DEFAULT_CHALLENGE_WINDOW_SLOTS: u64 = 96;
pub const DEFAULT_QUORUM_WEIGHT_BPS: u64 = 6_700;
pub const DEFAULT_SUPERMAJORITY_WEIGHT_BPS: u64 = 8_000;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 16;
pub const DEFAULT_TARGET_REBATE_BPS: u64 = 7;
pub const DEFAULT_MAX_REBATE_BPS: u64 = 24;
pub const DEFAULT_BASE_REBATE_MICRO_UNITS: u64 = 250;
pub const DEFAULT_MIN_SPONSOR_BOND_MICRO_UNITS: u64 = 2_000_000;
pub const DEFAULT_MIN_COMMITTEE_BOND_MICRO_UNITS: u64 = 25_000_000;
pub const DEFAULT_SLASH_BPS: u64 = 1_250;
pub const DEFAULT_MAX_LANES: usize = 4_096;
pub const DEFAULT_MAX_ACTIVE_SLOTS: usize = 65_536;
pub const DEFAULT_MAX_ENVELOPES: usize = 1_048_576;
pub const DEFAULT_MAX_ATTESTATIONS: usize = 2_097_152;
pub const DEFAULT_MAX_PROOFS: usize = 524_288;
pub const DEFAULT_MAX_REBATES: usize = 524_288;
pub const DEFAULT_MAX_NULLIFIERS: usize = 2_097_152;
pub const DEFAULT_MAX_CHALLENGES: usize = 262_144;
pub const DEFAULT_MAX_RECEIPTS: usize = 524_288;
pub const DEFAULT_MAX_PUBLIC_RECORDS: usize = 1_048_576;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OrderflowLaneKind {
    MoneroSwap,
    ConfidentialToken,
    DefiIntent,
    SmartContractCall,
    PerpetualMargin,
    LendingLiquidation,
    BridgeExit,
    OracleUpdate,
    EmergencyUnwind,
}

impl OrderflowLaneKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MoneroSwap => "monero_swap",
            Self::ConfidentialToken => "confidential_token",
            Self::DefiIntent => "defi_intent",
            Self::SmartContractCall => "smart_contract_call",
            Self::PerpetualMargin => "perpetual_margin",
            Self::LendingLiquidation => "lending_liquidation",
            Self::BridgeExit => "bridge_exit",
            Self::OracleUpdate => "oracle_update",
            Self::EmergencyUnwind => "emergency_unwind",
        }
    }

    pub fn default_priority(self) -> u64 {
        match self {
            Self::EmergencyUnwind => 10_000,
            Self::BridgeExit => 9_600,
            Self::SmartContractCall => 9_200,
            Self::DefiIntent => 9_000,
            Self::MoneroSwap => 8_800,
            Self::PerpetualMargin => 8_500,
            Self::LendingLiquidation => 8_400,
            Self::OracleUpdate => 7_900,
            Self::ConfidentialToken => 7_600,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LaneStatus {
    Open,
    Congested,
    Draining,
    Suspended,
    Slashed,
    Retired,
}

impl LaneStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Congested => "congested",
            Self::Draining => "draining",
            Self::Suspended => "suspended",
            Self::Slashed => "slashed",
            Self::Retired => "retired",
        }
    }

    pub fn accepts_envelopes(self) -> bool {
        matches!(self, Self::Open | Self::Congested)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EnvelopeStatus {
    Submitted,
    Fenced,
    SlotAssigned,
    Attested,
    Preconfirmed,
    Receipted,
    Challenged,
    Slashed,
    Expired,
}

impl EnvelopeStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Fenced => "fenced",
            Self::SlotAssigned => "slot_assigned",
            Self::Attested => "attested",
            Self::Preconfirmed => "preconfirmed",
            Self::Receipted => "receipted",
            Self::Challenged => "challenged",
            Self::Slashed => "slashed",
            Self::Expired => "expired",
        }
    }

    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Submitted
                | Self::Fenced
                | Self::SlotAssigned
                | Self::Attested
                | Self::Preconfirmed
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SlotStatus {
    Open,
    Attesting,
    QuorumReached,
    Sealed,
    Receipted,
    Challenged,
    Slashed,
    Expired,
}

impl SlotStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Attesting => "attesting",
            Self::QuorumReached => "quorum_reached",
            Self::Sealed => "sealed",
            Self::Receipted => "receipted",
            Self::Challenged => "challenged",
            Self::Slashed => "slashed",
            Self::Expired => "expired",
        }
    }

    pub fn accepts_attestation(self) -> bool {
        matches!(self, Self::Open | Self::Attesting | Self::QuorumReached)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationVerdict {
    Include,
    Hold,
    Reject,
}

impl AttestationVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Include => "include",
            Self::Hold => "hold",
            Self::Reject => "reject",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofStatus {
    Draft,
    Sealed,
    Receipted,
    Challenged,
    Slashed,
    Expired,
}

impl ProofStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Sealed => "sealed",
            Self::Receipted => "receipted",
            Self::Challenged => "challenged",
            Self::Slashed => "slashed",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RebateStatus {
    Reserved,
    Earned,
    Released,
    Cancelled,
    Slashed,
}

impl RebateStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Earned => "earned",
            Self::Released => "released",
            Self::Cancelled => "cancelled",
            Self::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeStatus {
    Filed,
    Accepted,
    Rejected,
    Slashed,
    Expired,
}

impl ChallengeStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Filed => "filed",
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
            Self::Slashed => "slashed",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptStatus {
    Published,
    RecursiveAggregated,
    Finalized,
    Challenged,
    Slashed,
}

impl ReceiptStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Published => "published",
            Self::RecursiveAggregated => "recursive_aggregated",
            Self::Finalized => "finalized",
            Self::Challenged => "challenged",
            Self::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub max_lanes: usize,
    pub max_active_slots: usize,
    pub max_envelopes: usize,
    pub max_attestations: usize,
    pub max_proofs: usize,
    pub max_rebates: usize,
    pub max_nullifiers: usize,
    pub max_challenges: usize,
    pub max_receipts: usize,
    pub max_public_records: usize,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub target_preconfirmation_ms: u64,
    pub max_preconfirmation_ms: u64,
    pub slot_width_ms: u64,
    pub envelope_ttl_slots: u64,
    pub proof_ttl_slots: u64,
    pub challenge_window_slots: u64,
    pub quorum_weight_bps: u64,
    pub supermajority_weight_bps: u64,
    pub max_user_fee_bps: u64,
    pub target_rebate_bps: u64,
    pub max_rebate_bps: u64,
    pub base_rebate_micro_units: u64,
    pub min_sponsor_bond_micro_units: u64,
    pub min_committee_bond_micro_units: u64,
    pub slash_bps: u64,
    pub require_nullifier_fence: bool,
    pub require_recursive_receipt: bool,
    pub require_pq_attestation: bool,
    pub fee_asset_id: String,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            max_lanes: DEFAULT_MAX_LANES,
            max_active_slots: DEFAULT_MAX_ACTIVE_SLOTS,
            max_envelopes: DEFAULT_MAX_ENVELOPES,
            max_attestations: DEFAULT_MAX_ATTESTATIONS,
            max_proofs: DEFAULT_MAX_PROOFS,
            max_rebates: DEFAULT_MAX_REBATES,
            max_nullifiers: DEFAULT_MAX_NULLIFIERS,
            max_challenges: DEFAULT_MAX_CHALLENGES,
            max_receipts: DEFAULT_MAX_RECEIPTS,
            max_public_records: DEFAULT_MAX_PUBLIC_RECORDS,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            target_preconfirmation_ms: DEFAULT_TARGET_PRECONF_MS,
            max_preconfirmation_ms: DEFAULT_MAX_PRECONF_MS,
            slot_width_ms: DEFAULT_SLOT_WIDTH_MS,
            envelope_ttl_slots: DEFAULT_ENVELOPE_TTL_SLOTS,
            proof_ttl_slots: DEFAULT_PROOF_TTL_SLOTS,
            challenge_window_slots: DEFAULT_CHALLENGE_WINDOW_SLOTS,
            quorum_weight_bps: DEFAULT_QUORUM_WEIGHT_BPS,
            supermajority_weight_bps: DEFAULT_SUPERMAJORITY_WEIGHT_BPS,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            target_rebate_bps: DEFAULT_TARGET_REBATE_BPS,
            max_rebate_bps: DEFAULT_MAX_REBATE_BPS,
            base_rebate_micro_units: DEFAULT_BASE_REBATE_MICRO_UNITS,
            min_sponsor_bond_micro_units: DEFAULT_MIN_SPONSOR_BOND_MICRO_UNITS,
            min_committee_bond_micro_units: DEFAULT_MIN_COMMITTEE_BOND_MICRO_UNITS,
            slash_bps: DEFAULT_SLASH_BPS,
            require_nullifier_fence: true,
            require_recursive_receipt: true,
            require_pq_attestation: true,
            fee_asset_id: DEFAULT_FEE_ASSET_ID.to_string(),
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.max_lanes == 0
            || self.max_active_slots == 0
            || self.max_envelopes == 0
            || self.max_attestations == 0
            || self.max_proofs == 0
            || self.max_rebates == 0
            || self.max_nullifiers == 0
            || self.max_challenges == 0
            || self.max_receipts == 0
            || self.max_public_records == 0
        {
            return Err("confidential orderflow capacities must be positive".to_string());
        }
        if self.min_pq_security_bits < 128 {
            return Err("confidential orderflow PQ security floor is too low".to_string());
        }
        if self.min_privacy_set_size == 0
            || self.target_privacy_set_size < self.min_privacy_set_size
        {
            return Err("confidential orderflow privacy set policy is invalid".to_string());
        }
        if self.slot_width_ms == 0
            || self.target_preconfirmation_ms == 0
            || self.max_preconfirmation_ms < self.target_preconfirmation_ms
        {
            return Err("confidential orderflow latency policy is invalid".to_string());
        }
        if self.envelope_ttl_slots == 0
            || self.proof_ttl_slots == 0
            || self.challenge_window_slots == 0
        {
            return Err("confidential orderflow TTL windows must be positive".to_string());
        }
        if self.quorum_weight_bps == 0
            || self.supermajority_weight_bps < self.quorum_weight_bps
            || self.supermajority_weight_bps > MAX_BPS
        {
            return Err("confidential orderflow quorum policy is invalid".to_string());
        }
        if self.max_user_fee_bps > MAX_BPS
            || self.target_rebate_bps > self.max_rebate_bps
            || self.max_rebate_bps > MAX_BPS
            || self.slash_bps > MAX_BPS
        {
            return Err("confidential orderflow fee or slashing BPS is invalid".to_string());
        }
        if self.fee_asset_id.trim().is_empty() {
            return Err("confidential orderflow fee asset id is required".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "max_lanes": self.max_lanes,
            "max_active_slots": self.max_active_slots,
            "max_envelopes": self.max_envelopes,
            "max_attestations": self.max_attestations,
            "max_proofs": self.max_proofs,
            "max_rebates": self.max_rebates,
            "max_nullifiers": self.max_nullifiers,
            "max_challenges": self.max_challenges,
            "max_receipts": self.max_receipts,
            "max_public_records": self.max_public_records,
            "min_pq_security_bits": self.min_pq_security_bits,
            "min_privacy_set_size": self.min_privacy_set_size,
            "target_privacy_set_size": self.target_privacy_set_size,
            "target_preconfirmation_ms": self.target_preconfirmation_ms,
            "max_preconfirmation_ms": self.max_preconfirmation_ms,
            "slot_width_ms": self.slot_width_ms,
            "envelope_ttl_slots": self.envelope_ttl_slots,
            "proof_ttl_slots": self.proof_ttl_slots,
            "challenge_window_slots": self.challenge_window_slots,
            "quorum_weight_bps": self.quorum_weight_bps,
            "supermajority_weight_bps": self.supermajority_weight_bps,
            "max_user_fee_bps": self.max_user_fee_bps,
            "target_rebate_bps": self.target_rebate_bps,
            "max_rebate_bps": self.max_rebate_bps,
            "base_rebate_micro_units": self.base_rebate_micro_units,
            "min_sponsor_bond_micro_units": self.min_sponsor_bond_micro_units,
            "min_committee_bond_micro_units": self.min_committee_bond_micro_units,
            "slash_bps": self.slash_bps,
            "require_nullifier_fence": self.require_nullifier_fence,
            "require_recursive_receipt": self.require_recursive_receipt,
            "require_pq_attestation": self.require_pq_attestation,
            "fee_asset_id": self.fee_asset_id,
        })
    }

    pub fn state_root(&self) -> String {
        root_from_record("config", &self.public_record())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub lanes_opened: u64,
    pub slots_opened: u64,
    pub envelopes_submitted: u64,
    pub nullifier_fences_registered: u64,
    pub attestations_recorded: u64,
    pub preconfirmations_sealed: u64,
    pub rebates_reserved: u64,
    pub rebates_released: u64,
    pub receipts_published: u64,
    pub recursive_receipts_published: u64,
    pub challenges_filed: u64,
    pub challenges_accepted: u64,
    pub challenges_rejected: u64,
    pub slashes_executed: u64,
    pub expirations: u64,
    pub public_records_emitted: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "lanes_opened": self.lanes_opened,
            "slots_opened": self.slots_opened,
            "envelopes_submitted": self.envelopes_submitted,
            "nullifier_fences_registered": self.nullifier_fences_registered,
            "attestations_recorded": self.attestations_recorded,
            "preconfirmations_sealed": self.preconfirmations_sealed,
            "rebates_reserved": self.rebates_reserved,
            "rebates_released": self.rebates_released,
            "receipts_published": self.receipts_published,
            "recursive_receipts_published": self.recursive_receipts_published,
            "challenges_filed": self.challenges_filed,
            "challenges_accepted": self.challenges_accepted,
            "challenges_rejected": self.challenges_rejected,
            "slashes_executed": self.slashes_executed,
            "expirations": self.expirations,
            "public_records_emitted": self.public_records_emitted,
        })
    }

    pub fn state_root(&self) -> String {
        root_from_record("counters", &self.public_record())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub lane_root: String,
    pub slot_root: String,
    pub envelope_root: String,
    pub attestation_root: String,
    pub proof_root: String,
    pub rebate_root: String,
    pub nullifier_root: String,
    pub challenge_root: String,
    pub receipt_root: String,
    pub public_record_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "lane_root": self.lane_root,
            "slot_root": self.slot_root,
            "envelope_root": self.envelope_root,
            "attestation_root": self.attestation_root,
            "proof_root": self.proof_root,
            "rebate_root": self.rebate_root,
            "nullifier_root": self.nullifier_root,
            "challenge_root": self.challenge_root,
            "receipt_root": self.receipt_root,
            "public_record_root": self.public_record_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LanePolicy {
    pub max_envelopes_per_slot: usize,
    pub min_privacy_set_size: u64,
    pub target_latency_ms: u64,
    pub max_latency_ms: u64,
    pub max_user_fee_bps: u64,
    pub priority_weight: u64,
    pub require_sponsor: bool,
    pub allow_contract_calls: bool,
    pub allow_recursive_receipts: bool,
}

impl LanePolicy {
    pub fn for_kind(kind: OrderflowLaneKind, config: &Config) -> Self {
        Self {
            max_envelopes_per_slot: match kind {
                OrderflowLaneKind::EmergencyUnwind => 512,
                OrderflowLaneKind::OracleUpdate => 1_024,
                OrderflowLaneKind::SmartContractCall => 2_048,
                _ => 4_096,
            },
            min_privacy_set_size: config.min_privacy_set_size.max(
                if matches!(kind, OrderflowLaneKind::MoneroSwap) {
                    32_768
                } else {
                    config.min_privacy_set_size
                },
            ),
            target_latency_ms: config.target_preconfirmation_ms,
            max_latency_ms: config.max_preconfirmation_ms,
            max_user_fee_bps: config.max_user_fee_bps,
            priority_weight: kind.default_priority(),
            require_sponsor: !matches!(kind, OrderflowLaneKind::OracleUpdate),
            allow_contract_calls: matches!(
                kind,
                OrderflowLaneKind::SmartContractCall
                    | OrderflowLaneKind::DefiIntent
                    | OrderflowLaneKind::PerpetualMargin
                    | OrderflowLaneKind::LendingLiquidation
            ),
            allow_recursive_receipts: true,
        }
    }

    pub fn validate(&self, config: &Config) -> Result<()> {
        if self.max_envelopes_per_slot == 0 {
            return Err("lane policy requires positive slot capacity".to_string());
        }
        if self.min_privacy_set_size < config.min_privacy_set_size {
            return Err("lane policy privacy set is below runtime minimum".to_string());
        }
        if self.target_latency_ms == 0 || self.max_latency_ms < self.target_latency_ms {
            return Err("lane policy latency bounds are invalid".to_string());
        }
        if self.max_user_fee_bps > config.max_user_fee_bps {
            return Err("lane policy fee cap exceeds runtime cap".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "max_envelopes_per_slot": self.max_envelopes_per_slot,
            "min_privacy_set_size": self.min_privacy_set_size,
            "target_latency_ms": self.target_latency_ms,
            "max_latency_ms": self.max_latency_ms,
            "max_user_fee_bps": self.max_user_fee_bps,
            "priority_weight": self.priority_weight,
            "require_sponsor": self.require_sponsor,
            "allow_contract_calls": self.allow_contract_calls,
            "allow_recursive_receipts": self.allow_recursive_receipts,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OrderflowLane {
    pub lane_id: String,
    pub kind: OrderflowLaneKind,
    pub status: LaneStatus,
    pub operator_commitment: String,
    pub committee_id: String,
    pub policy: LanePolicy,
    pub opened_height: u64,
    pub opened_slot: u64,
    pub last_slot: u64,
    pub total_envelopes: u64,
    pub live_envelopes: u64,
    pub sealed_preconfirmations: u64,
    pub slashed_bond_micro_units: u64,
}

impl OrderflowLane {
    pub fn public_record(&self) -> Value {
        json!({
            "lane_id": self.lane_id,
            "kind": self.kind.as_str(),
            "status": self.status.as_str(),
            "operator_commitment": self.operator_commitment,
            "committee_id": self.committee_id,
            "policy": self.policy.public_record(),
            "opened_height": self.opened_height,
            "opened_slot": self.opened_slot,
            "last_slot": self.last_slot,
            "total_envelopes": self.total_envelopes,
            "live_envelopes": self.live_envelopes,
            "sealed_preconfirmations": self.sealed_preconfirmations,
            "slashed_bond_micro_units": self.slashed_bond_micro_units,
        })
    }

    pub fn state_root(&self) -> String {
        root_from_record("lane", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LatencySlot {
    pub slot_id: String,
    pub lane_id: String,
    pub status: SlotStatus,
    pub slot_index: u64,
    pub opens_at_ms: u64,
    pub closes_at_ms: u64,
    pub envelope_ids: Vec<String>,
    pub attestation_ids: Vec<String>,
    pub proof_id: Option<String>,
    pub target_root: String,
    pub observed_latency_ms: u64,
    pub include_weight_bps: u64,
    pub reject_weight_bps: u64,
}

impl LatencySlot {
    pub fn public_record(&self) -> Value {
        json!({
            "slot_id": self.slot_id,
            "lane_id": self.lane_id,
            "status": self.status.as_str(),
            "slot_index": self.slot_index,
            "opens_at_ms": self.opens_at_ms,
            "closes_at_ms": self.closes_at_ms,
            "envelope_ids": self.envelope_ids,
            "attestation_ids": self.attestation_ids,
            "proof_id": self.proof_id,
            "target_root": self.target_root,
            "observed_latency_ms": self.observed_latency_ms,
            "include_weight_bps": self.include_weight_bps,
            "reject_weight_bps": self.reject_weight_bps,
        })
    }

    pub fn state_root(&self) -> String {
        root_from_record("slot", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivateOrderflowEnvelope {
    pub envelope_id: String,
    pub lane_id: String,
    pub status: EnvelopeStatus,
    pub owner_commitment: String,
    pub encrypted_payload_commitment: String,
    pub payload_ciphertext_root: String,
    pub contract_call_root: String,
    pub fee_asset_id: String,
    pub max_fee_bps: u64,
    pub sponsor_id: Option<String>,
    pub nullifier: String,
    pub replay_fence: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub submitted_height: u64,
    pub submitted_slot: u64,
    pub expires_slot: u64,
    pub assigned_slot_id: Option<String>,
    pub preconfirmation_id: Option<String>,
    pub receipt_id: Option<String>,
}

impl PrivateOrderflowEnvelope {
    pub fn public_record(&self) -> Value {
        json!({
            "envelope_id": self.envelope_id,
            "lane_id": self.lane_id,
            "status": self.status.as_str(),
            "owner_commitment": self.owner_commitment,
            "encrypted_payload_commitment": self.encrypted_payload_commitment,
            "payload_ciphertext_root": self.payload_ciphertext_root,
            "contract_call_root": self.contract_call_root,
            "fee_asset_id": self.fee_asset_id,
            "max_fee_bps": self.max_fee_bps,
            "sponsor_id": self.sponsor_id,
            "nullifier": self.nullifier,
            "replay_fence": self.replay_fence,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "submitted_height": self.submitted_height,
            "submitted_slot": self.submitted_slot,
            "expires_slot": self.expires_slot,
            "assigned_slot_id": self.assigned_slot_id,
            "preconfirmation_id": self.preconfirmation_id,
            "receipt_id": self.receipt_id,
        })
    }

    pub fn state_root(&self) -> String {
        root_from_record("envelope", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NullifierFence {
    pub nullifier: String,
    pub fence_id: String,
    pub envelope_id: String,
    pub lane_id: String,
    pub replay_fence: String,
    pub registered_slot: u64,
    pub expires_slot: u64,
    pub consumed: bool,
}

impl NullifierFence {
    pub fn public_record(&self) -> Value {
        json!({
            "nullifier": self.nullifier,
            "fence_id": self.fence_id,
            "envelope_id": self.envelope_id,
            "lane_id": self.lane_id,
            "replay_fence": self.replay_fence,
            "registered_slot": self.registered_slot,
            "expires_slot": self.expires_slot,
            "consumed": self.consumed,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqCommitteeAttestation {
    pub attestation_id: String,
    pub slot_id: String,
    pub envelope_ids: Vec<String>,
    pub committee_id: String,
    pub signer_commitment: String,
    pub verdict: AttestationVerdict,
    pub weight_bps: u64,
    pub pq_signature_root: String,
    pub transcript_root: String,
    pub latency_ms: u64,
    pub attested_height: u64,
    pub attested_slot: u64,
}

impl PqCommitteeAttestation {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "slot_id": self.slot_id,
            "envelope_ids": self.envelope_ids,
            "committee_id": self.committee_id,
            "signer_commitment": self.signer_commitment,
            "verdict": self.verdict.as_str(),
            "weight_bps": self.weight_bps,
            "pq_signature_root": self.pq_signature_root,
            "transcript_root": self.transcript_root,
            "latency_ms": self.latency_ms,
            "attested_height": self.attested_height,
            "attested_slot": self.attested_slot,
        })
    }

    pub fn state_root(&self) -> String {
        root_from_record("attestation", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PreconfirmationProof {
    pub proof_id: String,
    pub slot_id: String,
    pub lane_id: String,
    pub envelope_ids: Vec<String>,
    pub attestation_root: String,
    pub nullifier_root: String,
    pub encrypted_orderflow_root: String,
    pub state_transition_root: String,
    pub proof_commitment: String,
    pub circuit_id: String,
    pub status: ProofStatus,
    pub sealed_height: u64,
    pub sealed_slot: u64,
    pub expires_slot: u64,
}

impl PreconfirmationProof {
    pub fn public_record(&self) -> Value {
        json!({
            "proof_id": self.proof_id,
            "slot_id": self.slot_id,
            "lane_id": self.lane_id,
            "envelope_ids": self.envelope_ids,
            "attestation_root": self.attestation_root,
            "nullifier_root": self.nullifier_root,
            "encrypted_orderflow_root": self.encrypted_orderflow_root,
            "state_transition_root": self.state_transition_root,
            "proof_commitment": self.proof_commitment,
            "circuit_id": self.circuit_id,
            "status": self.status.as_str(),
            "sealed_height": self.sealed_height,
            "sealed_slot": self.sealed_slot,
            "expires_slot": self.expires_slot,
        })
    }

    pub fn state_root(&self) -> String {
        root_from_record("proof", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SponsorRebate {
    pub rebate_id: String,
    pub envelope_id: String,
    pub sponsor_id: String,
    pub beneficiary_commitment: String,
    pub fee_asset_id: String,
    pub reserved_micro_units: u64,
    pub earned_micro_units: u64,
    pub rebate_bps: u64,
    pub status: RebateStatus,
    pub reserved_slot: u64,
    pub released_slot: Option<u64>,
}

impl SponsorRebate {
    pub fn public_record(&self) -> Value {
        json!({
            "rebate_id": self.rebate_id,
            "envelope_id": self.envelope_id,
            "sponsor_id": self.sponsor_id,
            "beneficiary_commitment": self.beneficiary_commitment,
            "fee_asset_id": self.fee_asset_id,
            "reserved_micro_units": self.reserved_micro_units,
            "earned_micro_units": self.earned_micro_units,
            "rebate_bps": self.rebate_bps,
            "status": self.status.as_str(),
            "reserved_slot": self.reserved_slot,
            "released_slot": self.released_slot,
        })
    }

    pub fn state_root(&self) -> String {
        root_from_record("rebate", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RecursiveReceipt {
    pub receipt_id: String,
    pub proof_id: String,
    pub slot_id: String,
    pub lane_id: String,
    pub envelope_ids: Vec<String>,
    pub recursive_receipt_root: String,
    pub public_input_root: String,
    pub settlement_manifest_root: String,
    pub prior_receipt_root: String,
    pub status: ReceiptStatus,
    pub published_height: u64,
    pub published_slot: u64,
    pub finalized_slot: Option<u64>,
}

impl RecursiveReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "proof_id": self.proof_id,
            "slot_id": self.slot_id,
            "lane_id": self.lane_id,
            "envelope_ids": self.envelope_ids,
            "recursive_receipt_root": self.recursive_receipt_root,
            "public_input_root": self.public_input_root,
            "settlement_manifest_root": self.settlement_manifest_root,
            "prior_receipt_root": self.prior_receipt_root,
            "status": self.status.as_str(),
            "published_height": self.published_height,
            "published_slot": self.published_slot,
            "finalized_slot": self.finalized_slot,
        })
    }

    pub fn state_root(&self) -> String {
        root_from_record("receipt", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MevChallengeEvidence {
    pub challenge_id: String,
    pub target_proof_id: String,
    pub slot_id: String,
    pub challenger_commitment: String,
    pub evidence_root: String,
    pub omitted_envelope_root: String,
    pub ordering_witness_root: String,
    pub duplicate_nullifier: Option<String>,
    pub status: ChallengeStatus,
    pub filed_height: u64,
    pub filed_slot: u64,
    pub resolution_slot: Option<u64>,
    pub slash_micro_units: u64,
}

impl MevChallengeEvidence {
    pub fn public_record(&self) -> Value {
        json!({
            "challenge_id": self.challenge_id,
            "target_proof_id": self.target_proof_id,
            "slot_id": self.slot_id,
            "challenger_commitment": self.challenger_commitment,
            "evidence_root": self.evidence_root,
            "omitted_envelope_root": self.omitted_envelope_root,
            "ordering_witness_root": self.ordering_witness_root,
            "duplicate_nullifier": self.duplicate_nullifier,
            "status": self.status.as_str(),
            "filed_height": self.filed_height,
            "filed_slot": self.filed_slot,
            "resolution_slot": self.resolution_slot,
            "slash_micro_units": self.slash_micro_units,
        })
    }

    pub fn state_root(&self) -> String {
        root_from_record("challenge", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublicRecord {
    pub record_id: String,
    pub record_kind: String,
    pub height: u64,
    pub slot: u64,
    pub state_root: String,
    pub payload: Value,
}

impl PublicRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "record_id": self.record_id,
            "record_kind": self.record_kind,
            "height": self.height,
            "slot": self.slot,
            "state_root": self.state_root,
            "payload": self.payload,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub current_height: u64,
    pub current_slot: u64,
    pub monero_anchor_height: u64,
    pub lanes: BTreeMap<String, OrderflowLane>,
    pub slots: BTreeMap<String, LatencySlot>,
    pub envelopes: BTreeMap<String, PrivateOrderflowEnvelope>,
    pub attestations: BTreeMap<String, PqCommitteeAttestation>,
    pub proofs: BTreeMap<String, PreconfirmationProof>,
    pub rebates: BTreeMap<String, SponsorRebate>,
    pub nullifier_fences: BTreeMap<String, NullifierFence>,
    pub challenges: BTreeMap<String, MevChallengeEvidence>,
    pub receipts: BTreeMap<String, RecursiveReceipt>,
    pub public_records: BTreeMap<String, PublicRecord>,
    pub slashed_committees: BTreeSet<String>,
}

impl State {
    pub fn new(
        config: Config,
        current_height: u64,
        current_slot: u64,
        monero_anchor_height: u64,
    ) -> Result<Self> {
        config.validate()?;
        let mut state = Self {
            config,
            counters: Counters::default(),
            roots: Roots::default(),
            current_height,
            current_slot,
            monero_anchor_height,
            lanes: BTreeMap::new(),
            slots: BTreeMap::new(),
            envelopes: BTreeMap::new(),
            attestations: BTreeMap::new(),
            proofs: BTreeMap::new(),
            rebates: BTreeMap::new(),
            nullifier_fences: BTreeMap::new(),
            challenges: BTreeMap::new(),
            receipts: BTreeMap::new(),
            public_records: BTreeMap::new(),
            slashed_committees: BTreeSet::new(),
        };
        state.refresh_roots();
        Ok(state)
    }

    pub fn devnet() -> Result<Self> {
        let mut state = Self::new(
            Config::devnet(),
            DEVNET_L2_HEIGHT,
            DEVNET_EPOCH,
            DEVNET_MONERO_HEIGHT,
        )?;
        let lane_id = state.open_lane(
            OrderflowLaneKind::DefiIntent,
            "devnet-fast-orderflow-operator",
            "devnet-pq-preconfirmation-committee",
            None,
        )?;
        state.open_latency_slot(&lane_id, DEVNET_EPOCH, DEVNET_EPOCH * DEFAULT_SLOT_WIDTH_MS)?;
        Ok(state)
    }

    pub fn advance_clock(
        &mut self,
        height: u64,
        slot: u64,
        monero_anchor_height: u64,
    ) -> Result<()> {
        if height < self.current_height || slot < self.current_slot {
            return Err("confidential orderflow clock cannot move backwards".to_string());
        }
        self.current_height = height;
        self.current_slot = slot;
        self.monero_anchor_height = monero_anchor_height;
        self.expire_stale_items();
        self.refresh_roots();
        Ok(())
    }

    pub fn open_lane(
        &mut self,
        kind: OrderflowLaneKind,
        operator_commitment: &str,
        committee_id: &str,
        policy: Option<LanePolicy>,
    ) -> Result<String> {
        if self.lanes.len() >= self.config.max_lanes {
            return Err("confidential orderflow lane capacity reached".to_string());
        }
        require_nonempty("operator commitment", operator_commitment)?;
        require_nonempty("committee id", committee_id)?;
        if self.slashed_committees.contains(committee_id) {
            return Err("slashed committee cannot open a new orderflow lane".to_string());
        }
        let policy = policy.unwrap_or_else(|| LanePolicy::for_kind(kind, &self.config));
        policy.validate(&self.config)?;
        let lane_id = lane_id(
            kind,
            operator_commitment,
            committee_id,
            self.current_height,
            self.current_slot,
            self.counters.lanes_opened,
        );
        if self.lanes.contains_key(&lane_id) {
            return Err("confidential orderflow lane id collision".to_string());
        }
        let lane = OrderflowLane {
            lane_id: lane_id.clone(),
            kind,
            status: LaneStatus::Open,
            operator_commitment: operator_commitment.to_string(),
            committee_id: committee_id.to_string(),
            policy,
            opened_height: self.current_height,
            opened_slot: self.current_slot,
            last_slot: self.current_slot,
            total_envelopes: 0,
            live_envelopes: 0,
            sealed_preconfirmations: 0,
            slashed_bond_micro_units: 0,
        };
        self.lanes.insert(lane_id.clone(), lane);
        self.counters.lanes_opened += 1;
        self.emit_public_record("lane_opened", json!({ "lane_id": lane_id }))?;
        self.refresh_roots();
        Ok(lane_id)
    }

    pub fn open_latency_slot(
        &mut self,
        lane_id: &str,
        slot_index: u64,
        opens_at_ms: u64,
    ) -> Result<String> {
        if self.slots.len() >= self.config.max_active_slots {
            return Err("confidential orderflow active slot capacity reached".to_string());
        }
        let lane = self
            .lanes
            .get_mut(lane_id)
            .ok_or_else(|| "confidential orderflow lane not found".to_string())?;
        if !lane.status.accepts_envelopes() {
            return Err("confidential orderflow lane is not accepting slots".to_string());
        }
        if slot_index < lane.last_slot {
            return Err("confidential orderflow slot index is stale".to_string());
        }
        let slot_id = latency_slot_id(lane_id, slot_index, opens_at_ms, self.counters.slots_opened);
        if self.slots.contains_key(&slot_id) {
            return Err("confidential orderflow slot id collision".to_string());
        }
        lane.last_slot = slot_index;
        let slot = LatencySlot {
            slot_id: slot_id.clone(),
            lane_id: lane_id.to_string(),
            status: SlotStatus::Open,
            slot_index,
            opens_at_ms,
            closes_at_ms: opens_at_ms + lane.policy.max_latency_ms,
            envelope_ids: Vec::new(),
            attestation_ids: Vec::new(),
            proof_id: None,
            target_root: empty_root("slot-target"),
            observed_latency_ms: 0,
            include_weight_bps: 0,
            reject_weight_bps: 0,
        };
        self.slots.insert(slot_id.clone(), slot);
        self.counters.slots_opened += 1;
        self.emit_public_record(
            "latency_slot_opened",
            json!({ "slot_id": slot_id, "lane_id": lane_id }),
        )?;
        self.refresh_roots();
        Ok(slot_id)
    }

    pub fn submit_envelope(&mut self, request: SubmitEnvelope) -> Result<String> {
        if self.envelopes.len() >= self.config.max_envelopes {
            return Err("confidential orderflow envelope capacity reached".to_string());
        }
        request.validate(&self.config)?;
        let lane = self
            .lanes
            .get_mut(&request.lane_id)
            .ok_or_else(|| "confidential orderflow lane not found".to_string())?;
        if !lane.status.accepts_envelopes() {
            return Err("confidential orderflow lane is closed to envelopes".to_string());
        }
        if request.privacy_set_size < lane.policy.min_privacy_set_size {
            return Err("confidential orderflow envelope privacy set below lane floor".to_string());
        }
        if request.max_fee_bps > lane.policy.max_user_fee_bps {
            return Err("confidential orderflow envelope fee exceeds lane cap".to_string());
        }
        if lane.policy.require_sponsor && request.sponsor_id.is_none() {
            return Err("confidential orderflow envelope requires a sponsor".to_string());
        }
        if self.nullifier_fences.contains_key(&request.nullifier) {
            return Err("confidential orderflow nullifier already fenced".to_string());
        }
        let envelope_id = envelope_id(
            &request,
            self.current_height,
            self.current_slot,
            self.counters.envelopes_submitted,
        );
        let fence_id = nullifier_fence_id(&request.nullifier, &request.replay_fence, &envelope_id);
        let fence = NullifierFence {
            nullifier: request.nullifier.clone(),
            fence_id,
            envelope_id: envelope_id.clone(),
            lane_id: request.lane_id.clone(),
            replay_fence: request.replay_fence.clone(),
            registered_slot: self.current_slot,
            expires_slot: self.current_slot + self.config.envelope_ttl_slots,
            consumed: false,
        };
        let envelope = PrivateOrderflowEnvelope {
            envelope_id: envelope_id.clone(),
            lane_id: request.lane_id.clone(),
            status: EnvelopeStatus::Fenced,
            owner_commitment: request.owner_commitment,
            encrypted_payload_commitment: request.encrypted_payload_commitment,
            payload_ciphertext_root: request.payload_ciphertext_root,
            contract_call_root: request.contract_call_root,
            fee_asset_id: request.fee_asset_id,
            max_fee_bps: request.max_fee_bps,
            sponsor_id: request.sponsor_id,
            nullifier: request.nullifier.clone(),
            replay_fence: request.replay_fence,
            privacy_set_size: request.privacy_set_size,
            pq_security_bits: request.pq_security_bits,
            submitted_height: self.current_height,
            submitted_slot: self.current_slot,
            expires_slot: self.current_slot + self.config.envelope_ttl_slots,
            assigned_slot_id: None,
            preconfirmation_id: None,
            receipt_id: None,
        };
        lane.total_envelopes += 1;
        lane.live_envelopes += 1;
        self.nullifier_fences.insert(request.nullifier, fence);
        self.envelopes.insert(envelope_id.clone(), envelope);
        self.counters.envelopes_submitted += 1;
        self.counters.nullifier_fences_registered += 1;
        self.emit_public_record("envelope_submitted", json!({ "envelope_id": envelope_id }))?;
        self.refresh_roots();
        Ok(envelope_id)
    }

    pub fn assign_envelope_to_slot(&mut self, envelope_id: &str, slot_id: &str) -> Result<()> {
        let slot = self
            .slots
            .get_mut(slot_id)
            .ok_or_else(|| "confidential orderflow slot not found".to_string())?;
        if !slot.status.accepts_attestation() {
            return Err("confidential orderflow slot cannot accept envelopes".to_string());
        }
        let lane = self
            .lanes
            .get(&slot.lane_id)
            .ok_or_else(|| "confidential orderflow lane not found".to_string())?;
        if slot.envelope_ids.len() >= lane.policy.max_envelopes_per_slot {
            return Err("confidential orderflow slot envelope capacity reached".to_string());
        }
        let envelope = self
            .envelopes
            .get_mut(envelope_id)
            .ok_or_else(|| "confidential orderflow envelope not found".to_string())?;
        if envelope.lane_id != slot.lane_id {
            return Err("confidential orderflow envelope and slot lane mismatch".to_string());
        }
        if !envelope.status.live() || envelope.expires_slot < self.current_slot {
            return Err("confidential orderflow envelope is not assignable".to_string());
        }
        if !slot.envelope_ids.iter().any(|id| id == envelope_id) {
            slot.envelope_ids.push(envelope_id.to_string());
        }
        envelope.status = EnvelopeStatus::SlotAssigned;
        envelope.assigned_slot_id = Some(slot_id.to_string());
        slot.target_root = merkle_root(
            "private-l2-fast-pq-confidential-orderflow-slot-target",
            &slot
                .envelope_ids
                .iter()
                .map(|id| json!(id))
                .collect::<Vec<_>>(),
        );
        self.emit_public_record(
            "envelope_assigned",
            json!({ "envelope_id": envelope_id, "slot_id": slot_id }),
        )?;
        self.refresh_roots();
        Ok(())
    }

    pub fn attest_slot(&mut self, request: AttestSlot) -> Result<String> {
        if self.attestations.len() >= self.config.max_attestations {
            return Err("confidential orderflow attestation capacity reached".to_string());
        }
        request.validate(&self.config)?;
        let slot = self
            .slots
            .get_mut(&request.slot_id)
            .ok_or_else(|| "confidential orderflow slot not found".to_string())?;
        if !slot.status.accepts_attestation() {
            return Err("confidential orderflow slot no longer accepts attestations".to_string());
        }
        let lane = self
            .lanes
            .get(&slot.lane_id)
            .ok_or_else(|| "confidential orderflow lane not found".to_string())?;
        if lane.committee_id != request.committee_id {
            return Err("confidential orderflow attestation committee mismatch".to_string());
        }
        for envelope_id in &request.envelope_ids {
            if !slot.envelope_ids.iter().any(|id| id == envelope_id) {
                return Err(
                    "confidential orderflow attestation references envelope outside slot"
                        .to_string(),
                );
            }
        }
        let attestation_id = attestation_id(
            &request,
            self.current_height,
            self.current_slot,
            self.counters.attestations_recorded,
        );
        let attestation = PqCommitteeAttestation {
            attestation_id: attestation_id.clone(),
            slot_id: request.slot_id.clone(),
            envelope_ids: request.envelope_ids,
            committee_id: request.committee_id,
            signer_commitment: request.signer_commitment,
            verdict: request.verdict,
            weight_bps: request.weight_bps,
            pq_signature_root: request.pq_signature_root,
            transcript_root: request.transcript_root,
            latency_ms: request.latency_ms,
            attested_height: self.current_height,
            attested_slot: self.current_slot,
        };
        match attestation.verdict {
            AttestationVerdict::Include => {
                slot.include_weight_bps = slot
                    .include_weight_bps
                    .saturating_add(attestation.weight_bps)
                    .min(MAX_BPS);
            }
            AttestationVerdict::Reject => {
                slot.reject_weight_bps = slot
                    .reject_weight_bps
                    .saturating_add(attestation.weight_bps)
                    .min(MAX_BPS);
            }
            AttestationVerdict::Hold => {}
        }
        slot.observed_latency_ms = slot.observed_latency_ms.max(attestation.latency_ms);
        slot.attestation_ids.push(attestation_id.clone());
        slot.status = if slot.include_weight_bps >= self.config.quorum_weight_bps {
            SlotStatus::QuorumReached
        } else {
            SlotStatus::Attesting
        };
        for envelope_id in &slot.envelope_ids {
            if let Some(envelope) = self.envelopes.get_mut(envelope_id) {
                if matches!(envelope.status, EnvelopeStatus::SlotAssigned) {
                    envelope.status = EnvelopeStatus::Attested;
                }
            }
        }
        self.attestations
            .insert(attestation_id.clone(), attestation);
        self.counters.attestations_recorded += 1;
        self.emit_public_record(
            "slot_attested",
            json!({ "attestation_id": attestation_id, "slot_id": request.slot_id }),
        )?;
        self.refresh_roots();
        Ok(attestation_id)
    }

    pub fn seal_preconfirmation(
        &mut self,
        slot_id: &str,
        proof_commitment: &str,
        circuit_id: &str,
        state_transition_root: &str,
    ) -> Result<String> {
        if self.proofs.len() >= self.config.max_proofs {
            return Err("confidential orderflow proof capacity reached".to_string());
        }
        require_nonempty("proof commitment", proof_commitment)?;
        require_nonempty("circuit id", circuit_id)?;
        require_nonempty("state transition root", state_transition_root)?;
        let slot = self
            .slots
            .get_mut(slot_id)
            .ok_or_else(|| "confidential orderflow slot not found".to_string())?;
        if slot.include_weight_bps < self.config.quorum_weight_bps {
            return Err("confidential orderflow slot lacks preconfirmation quorum".to_string());
        }
        if slot.reject_weight_bps >= self.config.quorum_weight_bps {
            return Err("confidential orderflow slot has rejection quorum".to_string());
        }
        let lane_id = slot.lane_id.clone();
        let envelope_ids = slot.envelope_ids.clone();
        let attestation_leaves = slot
            .attestation_ids
            .iter()
            .filter_map(|id| self.attestations.get(id))
            .map(|a| a.public_record())
            .collect::<Vec<_>>();
        let nullifier_leaves = envelope_ids
            .iter()
            .filter_map(|id| self.envelopes.get(id))
            .filter_map(|e| self.nullifier_fences.get(&e.nullifier))
            .map(|f| f.public_record())
            .collect::<Vec<_>>();
        let encrypted_leaves = envelope_ids
            .iter()
            .filter_map(|id| self.envelopes.get(id))
            .map(|e| {
                json!({
                    "envelope_id": e.envelope_id,
                    "encrypted_payload_commitment": e.encrypted_payload_commitment,
                    "payload_ciphertext_root": e.payload_ciphertext_root,
                    "contract_call_root": e.contract_call_root,
                })
            })
            .collect::<Vec<_>>();
        let proof_id = preconfirmation_proof_id(
            slot_id,
            proof_commitment,
            circuit_id,
            self.current_height,
            self.current_slot,
        );
        let proof = PreconfirmationProof {
            proof_id: proof_id.clone(),
            slot_id: slot_id.to_string(),
            lane_id: lane_id.clone(),
            envelope_ids: envelope_ids.clone(),
            attestation_root: merkle_root(
                "private-l2-fast-pq-confidential-orderflow-attestation-set",
                &attestation_leaves,
            ),
            nullifier_root: merkle_root(
                "private-l2-fast-pq-confidential-orderflow-nullifier-set",
                &nullifier_leaves,
            ),
            encrypted_orderflow_root: merkle_root(
                "private-l2-fast-pq-confidential-orderflow-encrypted-set",
                &encrypted_leaves,
            ),
            state_transition_root: state_transition_root.to_string(),
            proof_commitment: proof_commitment.to_string(),
            circuit_id: circuit_id.to_string(),
            status: ProofStatus::Sealed,
            sealed_height: self.current_height,
            sealed_slot: self.current_slot,
            expires_slot: self.current_slot + self.config.proof_ttl_slots,
        };
        slot.proof_id = Some(proof_id.clone());
        slot.status = SlotStatus::Sealed;
        for envelope_id in &envelope_ids {
            if let Some(envelope) = self.envelopes.get_mut(envelope_id) {
                envelope.status = EnvelopeStatus::Preconfirmed;
                envelope.preconfirmation_id = Some(proof_id.clone());
            }
        }
        if let Some(lane) = self.lanes.get_mut(&lane_id) {
            lane.sealed_preconfirmations += 1;
        }
        self.proofs.insert(proof_id.clone(), proof);
        self.counters.preconfirmations_sealed += 1;
        self.emit_public_record(
            "preconfirmation_sealed",
            json!({ "proof_id": proof_id, "slot_id": slot_id }),
        )?;
        self.refresh_roots();
        Ok(proof_id)
    }

    pub fn reserve_sponsor_rebate(
        &mut self,
        envelope_id: &str,
        sponsor_id: &str,
        beneficiary_commitment: &str,
        reserved_micro_units: u64,
        rebate_bps: u64,
    ) -> Result<String> {
        if self.rebates.len() >= self.config.max_rebates {
            return Err("confidential orderflow rebate capacity reached".to_string());
        }
        require_nonempty("sponsor id", sponsor_id)?;
        require_nonempty("beneficiary commitment", beneficiary_commitment)?;
        if reserved_micro_units == 0 || rebate_bps == 0 || rebate_bps > self.config.max_rebate_bps {
            return Err("confidential orderflow rebate quote is invalid".to_string());
        }
        let envelope = self
            .envelopes
            .get(envelope_id)
            .ok_or_else(|| "confidential orderflow envelope not found".to_string())?;
        if let Some(expected_sponsor) = &envelope.sponsor_id {
            if expected_sponsor != sponsor_id {
                return Err("confidential orderflow sponsor mismatch".to_string());
            }
        }
        let rebate_id = sponsor_rebate_id(
            envelope_id,
            sponsor_id,
            beneficiary_commitment,
            self.current_slot,
        );
        let rebate = SponsorRebate {
            rebate_id: rebate_id.clone(),
            envelope_id: envelope_id.to_string(),
            sponsor_id: sponsor_id.to_string(),
            beneficiary_commitment: beneficiary_commitment.to_string(),
            fee_asset_id: envelope.fee_asset_id.clone(),
            reserved_micro_units,
            earned_micro_units: 0,
            rebate_bps,
            status: RebateStatus::Reserved,
            reserved_slot: self.current_slot,
            released_slot: None,
        };
        self.rebates.insert(rebate_id.clone(), rebate);
        self.counters.rebates_reserved += 1;
        self.emit_public_record(
            "sponsor_rebate_reserved",
            json!({ "rebate_id": rebate_id, "envelope_id": envelope_id }),
        )?;
        self.refresh_roots();
        Ok(rebate_id)
    }

    pub fn publish_receipt(
        &mut self,
        proof_id: &str,
        recursive_receipt_root: &str,
        public_input_root: &str,
        settlement_manifest_root: &str,
        prior_receipt_root: Option<&str>,
    ) -> Result<String> {
        if self.receipts.len() >= self.config.max_receipts {
            return Err("confidential orderflow receipt capacity reached".to_string());
        }
        require_nonempty("recursive receipt root", recursive_receipt_root)?;
        require_nonempty("public input root", public_input_root)?;
        require_nonempty("settlement manifest root", settlement_manifest_root)?;
        let proof = self
            .proofs
            .get_mut(proof_id)
            .ok_or_else(|| "confidential orderflow proof not found".to_string())?;
        if !matches!(proof.status, ProofStatus::Sealed) {
            return Err("confidential orderflow proof is not receiptable".to_string());
        }
        if proof.expires_slot < self.current_slot {
            proof.status = ProofStatus::Expired;
            return Err("confidential orderflow proof expired before receipt".to_string());
        }
        let receipt_id = recursive_receipt_id(
            proof_id,
            recursive_receipt_root,
            public_input_root,
            self.current_height,
            self.current_slot,
        );
        let receipt = RecursiveReceipt {
            receipt_id: receipt_id.clone(),
            proof_id: proof_id.to_string(),
            slot_id: proof.slot_id.clone(),
            lane_id: proof.lane_id.clone(),
            envelope_ids: proof.envelope_ids.clone(),
            recursive_receipt_root: recursive_receipt_root.to_string(),
            public_input_root: public_input_root.to_string(),
            settlement_manifest_root: settlement_manifest_root.to_string(),
            prior_receipt_root: prior_receipt_root.unwrap_or("").to_string(),
            status: ReceiptStatus::Published,
            published_height: self.current_height,
            published_slot: self.current_slot,
            finalized_slot: None,
        };
        proof.status = ProofStatus::Receipted;
        if let Some(slot) = self.slots.get_mut(&proof.slot_id) {
            slot.status = SlotStatus::Receipted;
        }
        for envelope_id in &proof.envelope_ids {
            if let Some(envelope) = self.envelopes.get_mut(envelope_id) {
                envelope.status = EnvelopeStatus::Receipted;
                envelope.receipt_id = Some(receipt_id.clone());
                if let Some(fence) = self.nullifier_fences.get_mut(&envelope.nullifier) {
                    fence.consumed = true;
                }
            }
        }
        self.receipts.insert(receipt_id.clone(), receipt);
        self.counters.receipts_published += 1;
        self.counters.recursive_receipts_published += 1;
        self.release_rebates_for_proof(proof_id)?;
        self.emit_public_record(
            "recursive_receipt_published",
            json!({ "receipt_id": receipt_id, "proof_id": proof_id }),
        )?;
        self.refresh_roots();
        Ok(receipt_id)
    }

    pub fn challenge_preconfirmation(&mut self, request: ChallengeRequest) -> Result<String> {
        if self.challenges.len() >= self.config.max_challenges {
            return Err("confidential orderflow challenge capacity reached".to_string());
        }
        request.validate()?;
        let proof = self
            .proofs
            .get(&request.target_proof_id)
            .ok_or_else(|| "confidential orderflow challenged proof not found".to_string())?;
        if self.current_slot > proof.sealed_slot + self.config.challenge_window_slots {
            return Err("confidential orderflow challenge window is closed".to_string());
        }
        let challenge_id = mev_challenge_id(
            &request,
            self.current_height,
            self.current_slot,
            self.counters.challenges_filed,
        );
        let challenge = MevChallengeEvidence {
            challenge_id: challenge_id.clone(),
            target_proof_id: request.target_proof_id,
            slot_id: proof.slot_id.clone(),
            challenger_commitment: request.challenger_commitment,
            evidence_root: request.evidence_root,
            omitted_envelope_root: request.omitted_envelope_root,
            ordering_witness_root: request.ordering_witness_root,
            duplicate_nullifier: request.duplicate_nullifier,
            status: ChallengeStatus::Filed,
            filed_height: self.current_height,
            filed_slot: self.current_slot,
            resolution_slot: None,
            slash_micro_units: request.claimed_slash_micro_units,
        };
        self.challenges.insert(challenge_id.clone(), challenge);
        self.counters.challenges_filed += 1;
        self.emit_public_record(
            "mev_challenge_filed",
            json!({ "challenge_id": challenge_id }),
        )?;
        self.refresh_roots();
        Ok(challenge_id)
    }

    pub fn resolve_challenge(&mut self, challenge_id: &str, accept: bool) -> Result<()> {
        let (proof_id, slot_id, slash_micro_units) = {
            let challenge = self
                .challenges
                .get_mut(challenge_id)
                .ok_or_else(|| "confidential orderflow challenge not found".to_string())?;
            if !matches!(challenge.status, ChallengeStatus::Filed) {
                return Err("confidential orderflow challenge already resolved".to_string());
            }
            challenge.status = if accept {
                ChallengeStatus::Accepted
            } else {
                ChallengeStatus::Rejected
            };
            challenge.resolution_slot = Some(self.current_slot);
            (
                challenge.target_proof_id.clone(),
                challenge.slot_id.clone(),
                challenge.slash_micro_units,
            )
        };
        if accept {
            self.slash_preconfirmation(&proof_id, &slot_id, slash_micro_units)?;
            self.counters.challenges_accepted += 1;
        } else {
            self.counters.challenges_rejected += 1;
        }
        self.emit_public_record(
            "mev_challenge_resolved",
            json!({ "challenge_id": challenge_id, "accepted": accept }),
        )?;
        self.refresh_roots();
        Ok(())
    }

    pub fn slash_preconfirmation(
        &mut self,
        proof_id: &str,
        slot_id: &str,
        slash_micro_units: u64,
    ) -> Result<()> {
        let proof = self
            .proofs
            .get_mut(proof_id)
            .ok_or_else(|| "confidential orderflow proof not found".to_string())?;
        proof.status = ProofStatus::Slashed;
        let lane_id = proof.lane_id.clone();
        for envelope_id in &proof.envelope_ids {
            if let Some(envelope) = self.envelopes.get_mut(envelope_id) {
                envelope.status = EnvelopeStatus::Slashed;
            }
        }
        if let Some(slot) = self.slots.get_mut(slot_id) {
            slot.status = SlotStatus::Slashed;
        }
        if let Some(lane) = self.lanes.get_mut(&lane_id) {
            lane.status = LaneStatus::Slashed;
            lane.slashed_bond_micro_units = lane
                .slashed_bond_micro_units
                .saturating_add(slash_micro_units);
            self.slashed_committees.insert(lane.committee_id.clone());
        }
        for rebate in self.rebates.values_mut() {
            if proof
                .envelope_ids
                .iter()
                .any(|id| id == &rebate.envelope_id)
            {
                rebate.status = RebateStatus::Slashed;
            }
        }
        for receipt in self.receipts.values_mut() {
            if receipt.proof_id == proof_id {
                receipt.status = ReceiptStatus::Slashed;
            }
        }
        self.counters.slashes_executed += 1;
        self.refresh_roots();
        Ok(())
    }

    pub fn finalize_receipt(&mut self, receipt_id: &str) -> Result<()> {
        let receipt = self
            .receipts
            .get_mut(receipt_id)
            .ok_or_else(|| "confidential orderflow receipt not found".to_string())?;
        if !matches!(
            receipt.status,
            ReceiptStatus::Published | ReceiptStatus::RecursiveAggregated
        ) {
            return Err("confidential orderflow receipt cannot be finalized".to_string());
        }
        receipt.status = ReceiptStatus::Finalized;
        receipt.finalized_slot = Some(self.current_slot);
        self.emit_public_record("receipt_finalized", json!({ "receipt_id": receipt_id }))?;
        self.refresh_roots();
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "chain_id": CHAIN_ID,
            "hash_suite": HASH_SUITE,
            "pq_attestation_suite": PQ_ATTESTATION_SUITE,
            "pq_envelope_suite": PQ_ENVELOPE_SUITE,
            "preconfirmation_proof_suite": PRECONFIRMATION_PROOF_SUITE,
            "recursive_receipt_suite": RECURSIVE_RECEIPT_SUITE,
            "nullifier_fence_suite": NULLIFIER_FENCE_SUITE,
            "mev_challenge_suite": MEV_CHALLENGE_SUITE,
            "sponsor_rebate_suite": SPONSOR_REBATE_SUITE,
            "current_height": self.current_height,
            "current_slot": self.current_slot,
            "monero_anchor_height": self.monero_anchor_height,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "private-l2-fast-pq-confidential-orderflow-preconfirmation-circuit-state-root",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::U64(SCHEMA_VERSION),
                HashPart::U64(self.current_height),
                HashPart::U64(self.current_slot),
                HashPart::Str(&self.config.state_root()),
                HashPart::Str(&self.counters.state_root()),
                HashPart::Str(&self.roots.lane_root),
                HashPart::Str(&self.roots.slot_root),
                HashPart::Str(&self.roots.envelope_root),
                HashPart::Str(&self.roots.attestation_root),
                HashPart::Str(&self.roots.proof_root),
                HashPart::Str(&self.roots.rebate_root),
                HashPart::Str(&self.roots.nullifier_root),
                HashPart::Str(&self.roots.challenge_root),
                HashPart::Str(&self.roots.receipt_root),
                HashPart::Str(&self.roots.public_record_root),
            ],
            32,
        )
    }

    pub fn refresh_roots(&mut self) {
        self.roots.lane_root = merkle_root(
            "private-l2-fast-pq-confidential-orderflow-lanes",
            &self
                .lanes
                .values()
                .map(|v| v.public_record())
                .collect::<Vec<_>>(),
        );
        self.roots.slot_root = merkle_root(
            "private-l2-fast-pq-confidential-orderflow-slots",
            &self
                .slots
                .values()
                .map(|v| v.public_record())
                .collect::<Vec<_>>(),
        );
        self.roots.envelope_root = merkle_root(
            "private-l2-fast-pq-confidential-orderflow-envelopes",
            &self
                .envelopes
                .values()
                .map(|v| v.public_record())
                .collect::<Vec<_>>(),
        );
        self.roots.attestation_root = merkle_root(
            "private-l2-fast-pq-confidential-orderflow-attestations",
            &self
                .attestations
                .values()
                .map(|v| v.public_record())
                .collect::<Vec<_>>(),
        );
        self.roots.proof_root = merkle_root(
            "private-l2-fast-pq-confidential-orderflow-proofs",
            &self
                .proofs
                .values()
                .map(|v| v.public_record())
                .collect::<Vec<_>>(),
        );
        self.roots.rebate_root = merkle_root(
            "private-l2-fast-pq-confidential-orderflow-rebates",
            &self
                .rebates
                .values()
                .map(|v| v.public_record())
                .collect::<Vec<_>>(),
        );
        self.roots.nullifier_root = merkle_root(
            "private-l2-fast-pq-confidential-orderflow-nullifiers",
            &self
                .nullifier_fences
                .values()
                .map(|v| v.public_record())
                .collect::<Vec<_>>(),
        );
        self.roots.challenge_root = merkle_root(
            "private-l2-fast-pq-confidential-orderflow-challenges",
            &self
                .challenges
                .values()
                .map(|v| v.public_record())
                .collect::<Vec<_>>(),
        );
        self.roots.receipt_root = merkle_root(
            "private-l2-fast-pq-confidential-orderflow-receipts",
            &self
                .receipts
                .values()
                .map(|v| v.public_record())
                .collect::<Vec<_>>(),
        );
        self.roots.public_record_root = merkle_root(
            "private-l2-fast-pq-confidential-orderflow-public-records",
            &self
                .public_records
                .values()
                .map(|v| v.public_record())
                .collect::<Vec<_>>(),
        );
        self.roots.state_root = self.state_root();
    }

    fn release_rebates_for_proof(&mut self, proof_id: &str) -> Result<()> {
        let proof = self
            .proofs
            .get(proof_id)
            .ok_or_else(|| "confidential orderflow proof not found".to_string())?;
        for rebate in self.rebates.values_mut() {
            if proof
                .envelope_ids
                .iter()
                .any(|id| id == &rebate.envelope_id)
                && matches!(rebate.status, RebateStatus::Reserved)
            {
                rebate.status = RebateStatus::Released;
                rebate.earned_micro_units = rebate
                    .reserved_micro_units
                    .saturating_mul(rebate.rebate_bps)
                    / MAX_BPS;
                rebate.released_slot = Some(self.current_slot);
                self.counters.rebates_released += 1;
            }
        }
        Ok(())
    }

    fn expire_stale_items(&mut self) {
        for envelope in self.envelopes.values_mut() {
            if envelope.status.live() && envelope.expires_slot < self.current_slot {
                envelope.status = EnvelopeStatus::Expired;
                self.counters.expirations += 1;
            }
        }
        for slot in self.slots.values_mut() {
            if matches!(slot.status, SlotStatus::Open | SlotStatus::Attesting)
                && slot.slot_index + self.config.envelope_ttl_slots < self.current_slot
            {
                slot.status = SlotStatus::Expired;
                self.counters.expirations += 1;
            }
        }
        for proof in self.proofs.values_mut() {
            if matches!(proof.status, ProofStatus::Draft | ProofStatus::Sealed)
                && proof.expires_slot < self.current_slot
            {
                proof.status = ProofStatus::Expired;
                self.counters.expirations += 1;
            }
        }
        for challenge in self.challenges.values_mut() {
            if matches!(challenge.status, ChallengeStatus::Filed)
                && challenge.filed_slot + self.config.challenge_window_slots < self.current_slot
            {
                challenge.status = ChallengeStatus::Expired;
                self.counters.expirations += 1;
            }
        }
    }

    fn emit_public_record(&mut self, record_kind: &str, payload: Value) -> Result<String> {
        if self.public_records.len() >= self.config.max_public_records {
            return Err("confidential orderflow public record capacity reached".to_string());
        }
        let state_root = self.state_root();
        let record_id = public_record_id(
            record_kind,
            self.current_height,
            self.current_slot,
            &state_root,
            &payload,
        );
        let record = PublicRecord {
            record_id: record_id.clone(),
            record_kind: record_kind.to_string(),
            height: self.current_height,
            slot: self.current_slot,
            state_root,
            payload,
        };
        self.public_records.insert(record_id.clone(), record);
        self.counters.public_records_emitted += 1;
        Ok(record_id)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SubmitEnvelope {
    pub lane_id: String,
    pub owner_commitment: String,
    pub encrypted_payload_commitment: String,
    pub payload_ciphertext_root: String,
    pub contract_call_root: String,
    pub fee_asset_id: String,
    pub max_fee_bps: u64,
    pub sponsor_id: Option<String>,
    pub nullifier: String,
    pub replay_fence: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
}

impl SubmitEnvelope {
    pub fn validate(&self, config: &Config) -> Result<()> {
        require_nonempty("lane id", &self.lane_id)?;
        require_nonempty("owner commitment", &self.owner_commitment)?;
        require_nonempty(
            "encrypted payload commitment",
            &self.encrypted_payload_commitment,
        )?;
        require_nonempty("payload ciphertext root", &self.payload_ciphertext_root)?;
        require_nonempty("contract call root", &self.contract_call_root)?;
        require_nonempty("fee asset id", &self.fee_asset_id)?;
        require_nonempty("nullifier", &self.nullifier)?;
        require_nonempty("replay fence", &self.replay_fence)?;
        if self.max_fee_bps > config.max_user_fee_bps {
            return Err("confidential orderflow envelope fee exceeds runtime cap".to_string());
        }
        if self.privacy_set_size < config.min_privacy_set_size {
            return Err("confidential orderflow envelope privacy set too small".to_string());
        }
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err("confidential orderflow envelope PQ security too low".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AttestSlot {
    pub slot_id: String,
    pub envelope_ids: Vec<String>,
    pub committee_id: String,
    pub signer_commitment: String,
    pub verdict: AttestationVerdict,
    pub weight_bps: u64,
    pub pq_signature_root: String,
    pub transcript_root: String,
    pub latency_ms: u64,
}

impl AttestSlot {
    pub fn validate(&self, config: &Config) -> Result<()> {
        require_nonempty("slot id", &self.slot_id)?;
        require_nonempty("committee id", &self.committee_id)?;
        require_nonempty("signer commitment", &self.signer_commitment)?;
        require_nonempty("PQ signature root", &self.pq_signature_root)?;
        require_nonempty("transcript root", &self.transcript_root)?;
        if self.envelope_ids.is_empty() {
            return Err("confidential orderflow attestation requires envelopes".to_string());
        }
        if self.weight_bps == 0 || self.weight_bps > MAX_BPS {
            return Err("confidential orderflow attestation weight is invalid".to_string());
        }
        if self.latency_ms > config.max_preconfirmation_ms {
            return Err("confidential orderflow attestation latency exceeds maximum".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ChallengeRequest {
    pub target_proof_id: String,
    pub challenger_commitment: String,
    pub evidence_root: String,
    pub omitted_envelope_root: String,
    pub ordering_witness_root: String,
    pub duplicate_nullifier: Option<String>,
    pub claimed_slash_micro_units: u64,
}

impl ChallengeRequest {
    pub fn validate(&self) -> Result<()> {
        require_nonempty("target proof id", &self.target_proof_id)?;
        require_nonempty("challenger commitment", &self.challenger_commitment)?;
        require_nonempty("evidence root", &self.evidence_root)?;
        require_nonempty("omitted envelope root", &self.omitted_envelope_root)?;
        require_nonempty("ordering witness root", &self.ordering_witness_root)?;
        if self.claimed_slash_micro_units == 0 {
            return Err(
                "confidential orderflow challenge slash amount must be positive".to_string(),
            );
        }
        Ok(())
    }
}

pub fn lane_id(
    kind: OrderflowLaneKind,
    operator_commitment: &str,
    committee_id: &str,
    height: u64,
    slot: u64,
    nonce: u64,
) -> String {
    domain_hash(
        "private-l2-fast-pq-confidential-orderflow-lane-id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(kind.as_str()),
            HashPart::Str(operator_commitment),
            HashPart::Str(committee_id),
            HashPart::U64(height),
            HashPart::U64(slot),
            HashPart::U64(nonce),
        ],
        32,
    )
}

pub fn latency_slot_id(lane_id: &str, slot_index: u64, opens_at_ms: u64, nonce: u64) -> String {
    domain_hash(
        "private-l2-fast-pq-confidential-orderflow-latency-slot-id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(lane_id),
            HashPart::U64(slot_index),
            HashPart::U64(opens_at_ms),
            HashPart::U64(nonce),
        ],
        32,
    )
}

pub fn envelope_id(request: &SubmitEnvelope, height: u64, slot: u64, nonce: u64) -> String {
    domain_hash(
        "private-l2-fast-pq-confidential-orderflow-envelope-id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(&request.lane_id),
            HashPart::Str(&request.owner_commitment),
            HashPart::Str(&request.encrypted_payload_commitment),
            HashPart::Str(&request.payload_ciphertext_root),
            HashPart::Str(&request.nullifier),
            HashPart::Str(&request.replay_fence),
            HashPart::U64(height),
            HashPart::U64(slot),
            HashPart::U64(nonce),
        ],
        32,
    )
}

pub fn nullifier_fence_id(nullifier: &str, replay_fence: &str, envelope_id: &str) -> String {
    domain_hash(
        "private-l2-fast-pq-confidential-orderflow-nullifier-fence-id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(NULLIFIER_FENCE_SUITE),
            HashPart::Str(nullifier),
            HashPart::Str(replay_fence),
            HashPart::Str(envelope_id),
        ],
        32,
    )
}

pub fn attestation_id(request: &AttestSlot, height: u64, slot: u64, nonce: u64) -> String {
    let envelope_root = merkle_root(
        "private-l2-fast-pq-confidential-orderflow-attestation-envelope-ids",
        &request
            .envelope_ids
            .iter()
            .map(|id| json!(id))
            .collect::<Vec<_>>(),
    );
    domain_hash(
        "private-l2-fast-pq-confidential-orderflow-attestation-id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PQ_ATTESTATION_SUITE),
            HashPart::Str(&request.slot_id),
            HashPart::Str(&envelope_root),
            HashPart::Str(&request.committee_id),
            HashPart::Str(&request.signer_commitment),
            HashPart::Str(request.verdict.as_str()),
            HashPart::U64(request.weight_bps),
            HashPart::U64(height),
            HashPart::U64(slot),
            HashPart::U64(nonce),
        ],
        32,
    )
}

pub fn preconfirmation_proof_id(
    slot_id: &str,
    proof_commitment: &str,
    circuit_id: &str,
    height: u64,
    slot: u64,
) -> String {
    domain_hash(
        "private-l2-fast-pq-confidential-orderflow-preconfirmation-proof-id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PRECONFIRMATION_PROOF_SUITE),
            HashPart::Str(slot_id),
            HashPart::Str(proof_commitment),
            HashPart::Str(circuit_id),
            HashPart::U64(height),
            HashPart::U64(slot),
        ],
        32,
    )
}

pub fn sponsor_rebate_id(
    envelope_id: &str,
    sponsor_id: &str,
    beneficiary_commitment: &str,
    slot: u64,
) -> String {
    domain_hash(
        "private-l2-fast-pq-confidential-orderflow-sponsor-rebate-id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(SPONSOR_REBATE_SUITE),
            HashPart::Str(envelope_id),
            HashPart::Str(sponsor_id),
            HashPart::Str(beneficiary_commitment),
            HashPart::U64(slot),
        ],
        32,
    )
}

pub fn recursive_receipt_id(
    proof_id: &str,
    recursive_receipt_root: &str,
    public_input_root: &str,
    height: u64,
    slot: u64,
) -> String {
    domain_hash(
        "private-l2-fast-pq-confidential-orderflow-recursive-receipt-id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(RECURSIVE_RECEIPT_SUITE),
            HashPart::Str(proof_id),
            HashPart::Str(recursive_receipt_root),
            HashPart::Str(public_input_root),
            HashPart::U64(height),
            HashPart::U64(slot),
        ],
        32,
    )
}

pub fn mev_challenge_id(request: &ChallengeRequest, height: u64, slot: u64, nonce: u64) -> String {
    domain_hash(
        "private-l2-fast-pq-confidential-orderflow-mev-challenge-id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(MEV_CHALLENGE_SUITE),
            HashPart::Str(&request.target_proof_id),
            HashPart::Str(&request.challenger_commitment),
            HashPart::Str(&request.evidence_root),
            HashPart::Str(&request.omitted_envelope_root),
            HashPart::Str(&request.ordering_witness_root),
            HashPart::Str(request.duplicate_nullifier.as_deref().unwrap_or("")),
            HashPart::U64(height),
            HashPart::U64(slot),
            HashPart::U64(nonce),
        ],
        32,
    )
}

pub fn public_record_id(
    record_kind: &str,
    height: u64,
    slot: u64,
    state_root: &str,
    payload: &Value,
) -> String {
    domain_hash(
        "private-l2-fast-pq-confidential-orderflow-public-record-id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(record_kind),
            HashPart::U64(height),
            HashPart::U64(slot),
            HashPart::Str(state_root),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub fn root_from_record(domain: &str, record: &Value) -> String {
    domain_hash(
        "private-l2-fast-pq-confidential-orderflow-record-root",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(domain),
            HashPart::Json(record),
        ],
        32,
    )
}

pub fn state_root_from_record(record: &Value) -> String {
    root_from_record("external-state-record", record)
}

pub fn empty_root(label: &str) -> String {
    merkle_root(
        &format!("private-l2-fast-pq-confidential-orderflow-{label}"),
        &[],
    )
}

pub fn devnet() -> Result<State> {
    State::devnet()
}

fn require_nonempty(label: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        Err(format!("confidential orderflow {label} is required"))
    } else {
        Ok(())
    }
}
