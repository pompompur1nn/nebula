use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2FastPqConfidentialStateWitnessPrefetchRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_FAST_PQ_CONFIDENTIAL_STATE_WITNESS_PREFETCH_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-fast-pq-confidential-state-witness-prefetch-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_FAST_PQ_CONFIDENTIAL_STATE_WITNESS_PREFETCH_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_ATTESTATION_SUITE: &str = "ML-DSA-87+SLH-DSA-SHAKE-256f-state-witness-prefetch-v1";
pub const PQ_ENVELOPE_SUITE: &str = "ML-KEM-1024-threshold-confidential-state-hint-envelope-v1";
pub const PREFETCH_PROOF_SUITE: &str = "nova-pq-confidential-state-witness-prefetch-proof-v1";
pub const PRIVACY_FENCE_SUITE: &str = "monero-l2-nullifier-viewtag-contract-state-fence-v1";
pub const LOW_FEE_REBATE_SUITE: &str = "low-fee-private-state-witness-prefetch-rebate-v1";
pub const BANDWIDTH_AUCTION_SUITE: &str = "sealed-bandwidth-auction-confidential-prefetch-v1";
pub const DEVNET_L2_HEIGHT: u64 = 2_260_000;
pub const DEVNET_MONERO_HEIGHT: u64 = 3_420_000;
pub const DEVNET_EPOCH: u64 = 8_192;
pub const DEFAULT_FEE_ASSET_ID: &str = "piconero-devnet";
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_TARGET_PRIVACY_SET_SIZE: u64 = 524_288;
pub const DEFAULT_TARGET_PREFETCH_MS: u64 = 90;
pub const DEFAULT_MAX_PREFETCH_MS: u64 = 350;
pub const DEFAULT_SLOT_WIDTH_MS: u64 = 50;
pub const DEFAULT_RESERVATION_TTL_SLOTS: u64 = 32;
pub const DEFAULT_ATTESTATION_TTL_SLOTS: u64 = 48;
pub const DEFAULT_PROOF_CACHE_TTL_SLOTS: u64 = 96;
pub const DEFAULT_CHALLENGE_WINDOW_SLOTS: u64 = 128;
pub const DEFAULT_QUORUM_WEIGHT_BPS: u64 = 6_700;
pub const DEFAULT_SUPERMAJORITY_WEIGHT_BPS: u64 = 8_000;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 12;
pub const DEFAULT_TARGET_REBATE_BPS: u64 = 6;
pub const DEFAULT_MAX_REBATE_BPS: u64 = 20;
pub const DEFAULT_MIN_LANE_BOND_MICRO_UNITS: u64 = 25_000_000;
pub const DEFAULT_MIN_AUCTION_BOND_MICRO_UNITS: u64 = 1_000_000;
pub const DEFAULT_SLASH_BPS: u64 = 1_500;
pub const DEFAULT_MAX_STATE_HINTS: usize = 1_048_576;
pub const DEFAULT_MAX_ATTESTATIONS: usize = 2_097_152;
pub const DEFAULT_MAX_RESERVATIONS: usize = 1_048_576;
pub const DEFAULT_MAX_CACHE_LANES: usize = 16_384;
pub const DEFAULT_MAX_BANDWIDTH_AUCTIONS: usize = 262_144;
pub const DEFAULT_MAX_SCHEDULER_RECEIPTS: usize = 1_048_576;
pub const DEFAULT_MAX_PROOF_CACHE_HINTS: usize = 524_288;
pub const DEFAULT_MAX_LOW_FEE_REBATES: usize = 1_048_576;
pub const DEFAULT_MAX_PRIVACY_FENCES: usize = 1_048_576;
pub const DEFAULT_MAX_SLASHING_EVIDENCE: usize = 262_144;
pub const DEFAULT_MAX_PUBLIC_RECORDS: usize = 2_097_152;
pub const DEFAULT_MAX_ENCRYPTED_CONTRACT_STATE_HINTS: usize = DEFAULT_MAX_STATE_HINTS;
pub const DEFAULT_MAX_PQ_WITNESS_ATTESTATIONS: usize = DEFAULT_MAX_ATTESTATIONS;
pub const DEFAULT_MAX_PREFETCH_RESERVATIONS: usize = DEFAULT_MAX_RESERVATIONS;

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
pub enum ReservationStatus {
    Requested,
    Reserved,
    Prefetching,
    Warmed,
    Consumed,
    Expired,
    Slashed,
}

impl ReservationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Requested => "requested",
            Self::Reserved => "reserved",
            Self::Prefetching => "prefetching",
            Self::Warmed => "warmed",
            Self::Consumed => "consumed",
            Self::Expired => "expired",
            Self::Slashed => "slashed",
        }
    }

    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Requested | Self::Reserved | Self::Prefetching | Self::Warmed
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LaneStatus {
    Open,
    Congested,
    Draining,
    Suspended,
    Retired,
}

impl LaneStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Congested => "congested",
            Self::Draining => "draining",
            Self::Suspended => "suspended",
            Self::Retired => "retired",
        }
    }

    pub fn accepts_reservations(self) -> bool {
        matches!(self, Self::Open | Self::Congested)
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
pub enum PrivacyFenceKind {
    NullifierSet,
    ViewTagCohort,
    ContractKeyEpoch,
    CrossContractCall,
    SolverIntent,
    BridgeExit,
}

impl PrivacyFenceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NullifierSet => "nullifier_set",
            Self::ViewTagCohort => "view_tag_cohort",
            Self::ContractKeyEpoch => "contract_key_epoch",
            Self::CrossContractCall => "cross_contract_call",
            Self::SolverIntent => "solver_intent",
            Self::BridgeExit => "bridge_exit",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SlashingKind {
    WithheldWitness,
    InvalidPqSignature,
    BadPrefetchRoot,
    PrivacyFenceLeak,
    BandwidthOverclaim,
    SchedulerEquivocation,
}

impl SlashingKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WithheldWitness => "withheld_witness",
            Self::InvalidPqSignature => "invalid_pq_signature",
            Self::BadPrefetchRoot => "bad_prefetch_root",
            Self::PrivacyFenceLeak => "privacy_fence_leak",
            Self::BandwidthOverclaim => "bandwidth_overclaim",
            Self::SchedulerEquivocation => "scheduler_equivocation",
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct EncryptedContractStateHint {
    pub contract_id: String,
    pub encrypted_state_hint_root: String,
    pub contract_state_commitment: String,
    pub read_set_root: String,
    pub write_set_root: String,
    pub view_tag_root: String,
    pub privacy_budget_bps: u64,
    pub created_at_height: u64,
    pub expires_at_height: u64,
    pub sequence: u64,
}

impl EncryptedContractStateHint {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "encrypted_contract_state_hint",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "contract_id": self.contract_id,
            "encrypted_state_hint_root": self.encrypted_state_hint_root,
            "contract_state_commitment": self.contract_state_commitment,
            "read_set_root": self.read_set_root,
            "write_set_root": self.write_set_root,
            "view_tag_root": self.view_tag_root,
            "privacy_budget_bps": self.privacy_budget_bps,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
            "sequence": self.sequence,
        })
    }

    pub fn record_root(&self) -> String {
        runtime_payload_root("ENCRYPTED-CONTRACT-STATE-HINT", &self.public_record())
    }

    pub fn stable_id(&self) -> String {
        encrypted_contract_state_hint_id(&self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct PqWitnessAttestation {
    pub witness_id: String,
    pub witness_root: String,
    pub pq_public_key_root: String,
    pub pq_signature_root: String,
    pub attester_weight_bps: u64,
    pub verdict: AttestationVerdict,
    pub created_at_height: u64,
    pub expires_at_height: u64,
    pub sequence: u64,
}

impl PqWitnessAttestation {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_witness_attestation",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "witness_id": self.witness_id,
            "witness_root": self.witness_root,
            "pq_public_key_root": self.pq_public_key_root,
            "pq_signature_root": self.pq_signature_root,
            "attester_weight_bps": self.attester_weight_bps,
            "verdict": self.verdict,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
            "sequence": self.sequence,
        })
    }

    pub fn record_root(&self) -> String {
        runtime_payload_root("PQ-WITNESS-ATTESTATION", &self.public_record())
    }

    pub fn stable_id(&self) -> String {
        pq_witness_attestation_id(&self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct PrefetchReservation {
    pub reservation_id: String,
    pub lane_id: String,
    pub contract_id: String,
    pub state_hint_id: String,
    pub reserved_bytes: u64,
    pub max_fee_micro_units: u64,
    pub status: ReservationStatus,
    pub created_at_height: u64,
    pub expires_at_height: u64,
    pub sequence: u64,
}

impl PrefetchReservation {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "prefetch_reservation",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "reservation_id": self.reservation_id,
            "lane_id": self.lane_id,
            "contract_id": self.contract_id,
            "state_hint_id": self.state_hint_id,
            "reserved_bytes": self.reserved_bytes,
            "max_fee_micro_units": self.max_fee_micro_units,
            "status": self.status,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
            "sequence": self.sequence,
        })
    }

    pub fn record_root(&self) -> String {
        runtime_payload_root("PREFETCH-RESERVATION", &self.public_record())
    }

    pub fn stable_id(&self) -> String {
        prefetch_reservation_id(&self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct CacheLane {
    pub lane_id: String,
    pub operator_id: String,
    pub lane_status: LaneStatus,
    pub bandwidth_bytes_per_slot: u64,
    pub witness_cache_bytes: u64,
    pub pq_security_bits: u16,
    pub privacy_set_size: u64,
    pub created_at_height: u64,
    pub expires_at_height: u64,
    pub sequence: u64,
}

impl CacheLane {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "cache_lane",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "lane_id": self.lane_id,
            "operator_id": self.operator_id,
            "lane_status": self.lane_status,
            "bandwidth_bytes_per_slot": self.bandwidth_bytes_per_slot,
            "witness_cache_bytes": self.witness_cache_bytes,
            "pq_security_bits": self.pq_security_bits,
            "privacy_set_size": self.privacy_set_size,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
            "sequence": self.sequence,
        })
    }

    pub fn record_root(&self) -> String {
        runtime_payload_root("CACHE-LANE", &self.public_record())
    }

    pub fn stable_id(&self) -> String {
        cache_lane_id(&self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct BandwidthAuction {
    pub auction_id: String,
    pub lane_id: String,
    pub sealed_bid_root: String,
    pub clearing_price_micro_units: u64,
    pub allocated_bytes: u64,
    pub rebate_pool_micro_units: u64,
    pub winner_root: String,
    pub created_at_height: u64,
    pub expires_at_height: u64,
    pub sequence: u64,
}

impl BandwidthAuction {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "bandwidth_auction",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "auction_id": self.auction_id,
            "lane_id": self.lane_id,
            "sealed_bid_root": self.sealed_bid_root,
            "clearing_price_micro_units": self.clearing_price_micro_units,
            "allocated_bytes": self.allocated_bytes,
            "rebate_pool_micro_units": self.rebate_pool_micro_units,
            "winner_root": self.winner_root,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
            "sequence": self.sequence,
        })
    }

    pub fn record_root(&self) -> String {
        runtime_payload_root("BANDWIDTH-AUCTION", &self.public_record())
    }

    pub fn stable_id(&self) -> String {
        bandwidth_auction_id(&self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct SchedulerReceipt {
    pub receipt_id: String,
    pub lane_id: String,
    pub reservation_id: String,
    pub execution_root: String,
    pub prefetch_root: String,
    pub gas_saved_micro_units: u64,
    pub latency_ms: u64,
    pub created_at_height: u64,
    pub expires_at_height: u64,
    pub sequence: u64,
}

impl SchedulerReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "scheduler_receipt",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "receipt_id": self.receipt_id,
            "lane_id": self.lane_id,
            "reservation_id": self.reservation_id,
            "execution_root": self.execution_root,
            "prefetch_root": self.prefetch_root,
            "gas_saved_micro_units": self.gas_saved_micro_units,
            "latency_ms": self.latency_ms,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
            "sequence": self.sequence,
        })
    }

    pub fn record_root(&self) -> String {
        runtime_payload_root("SCHEDULER-RECEIPT", &self.public_record())
    }

    pub fn stable_id(&self) -> String {
        scheduler_receipt_id(&self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct ProofCacheHint {
    pub proof_hint_id: String,
    pub circuit_id: String,
    pub verifying_key_root: String,
    pub recursive_proof_hint_root: String,
    pub expected_hit_rate_bps: u64,
    pub proof_bytes: u64,
    pub ttl_slots: u64,
    pub created_at_height: u64,
    pub expires_at_height: u64,
    pub sequence: u64,
}

impl ProofCacheHint {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "proof_cache_hint",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "proof_hint_id": self.proof_hint_id,
            "circuit_id": self.circuit_id,
            "verifying_key_root": self.verifying_key_root,
            "recursive_proof_hint_root": self.recursive_proof_hint_root,
            "expected_hit_rate_bps": self.expected_hit_rate_bps,
            "proof_bytes": self.proof_bytes,
            "ttl_slots": self.ttl_slots,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
            "sequence": self.sequence,
        })
    }

    pub fn record_root(&self) -> String {
        runtime_payload_root("PROOF-CACHE-HINT", &self.public_record())
    }

    pub fn stable_id(&self) -> String {
        proof_cache_hint_id(&self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct LowFeeRebate {
    pub rebate_id: String,
    pub account_commitment: String,
    pub reservation_id: String,
    pub fee_asset_id: String,
    pub gross_fee_micro_units: u64,
    pub rebate_micro_units: u64,
    pub sponsor_pool_id: String,
    pub created_at_height: u64,
    pub expires_at_height: u64,
    pub sequence: u64,
}

impl LowFeeRebate {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "low_fee_rebate",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "rebate_id": self.rebate_id,
            "account_commitment": self.account_commitment,
            "reservation_id": self.reservation_id,
            "fee_asset_id": self.fee_asset_id,
            "gross_fee_micro_units": self.gross_fee_micro_units,
            "rebate_micro_units": self.rebate_micro_units,
            "sponsor_pool_id": self.sponsor_pool_id,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
            "sequence": self.sequence,
        })
    }

    pub fn record_root(&self) -> String {
        runtime_payload_root("LOW-FEE-REBATE", &self.public_record())
    }

    pub fn stable_id(&self) -> String {
        low_fee_rebate_id(&self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct PrivacyFence {
    pub fence_id: String,
    pub fence_kind: PrivacyFenceKind,
    pub scope_root: String,
    pub nullifier_root: String,
    pub min_privacy_set_size: u64,
    pub release_height: u64,
    pub sealed: bool,
    pub created_at_height: u64,
    pub expires_at_height: u64,
    pub sequence: u64,
}

impl PrivacyFence {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "privacy_fence",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "fence_id": self.fence_id,
            "fence_kind": self.fence_kind,
            "scope_root": self.scope_root,
            "nullifier_root": self.nullifier_root,
            "min_privacy_set_size": self.min_privacy_set_size,
            "release_height": self.release_height,
            "sealed": self.sealed,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
            "sequence": self.sequence,
        })
    }

    pub fn record_root(&self) -> String {
        runtime_payload_root("PRIVACY-FENCE", &self.public_record())
    }

    pub fn stable_id(&self) -> String {
        privacy_fence_id(&self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct SlashingEvidence {
    pub evidence_id: String,
    pub offender_id: String,
    pub slashing_kind: SlashingKind,
    pub evidence_root: String,
    pub challenger_id: String,
    pub slash_bps: u64,
    pub resolved: bool,
    pub created_at_height: u64,
    pub expires_at_height: u64,
    pub sequence: u64,
}

impl SlashingEvidence {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "slashing_evidence",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "evidence_id": self.evidence_id,
            "offender_id": self.offender_id,
            "slashing_kind": self.slashing_kind,
            "evidence_root": self.evidence_root,
            "challenger_id": self.challenger_id,
            "slash_bps": self.slash_bps,
            "resolved": self.resolved,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
            "sequence": self.sequence,
        })
    }

    pub fn record_root(&self) -> String {
        runtime_payload_root("SLASHING-EVIDENCE", &self.public_record())
    }

    pub fn stable_id(&self) -> String {
        slashing_evidence_id(&self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct Config {
    pub mode: RuntimeMode,
    pub schema_version: u64,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub target_prefetch_ms: u64,
    pub max_prefetch_ms: u64,
    pub slot_width_ms: u64,
    pub reservation_ttl_slots: u64,
    pub attestation_ttl_slots: u64,
    pub proof_cache_ttl_slots: u64,
    pub challenge_window_slots: u64,
    pub quorum_weight_bps: u64,
    pub supermajority_weight_bps: u64,
    pub max_user_fee_bps: u64,
    pub target_rebate_bps: u64,
    pub max_rebate_bps: u64,
    pub min_lane_bond_micro_units: u64,
    pub min_auction_bond_micro_units: u64,
    pub slash_bps: u64,
    pub fee_asset_id: String,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            mode: RuntimeMode::Devnet,
            schema_version: SCHEMA_VERSION,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            target_prefetch_ms: DEFAULT_TARGET_PREFETCH_MS,
            max_prefetch_ms: DEFAULT_MAX_PREFETCH_MS,
            slot_width_ms: DEFAULT_SLOT_WIDTH_MS,
            reservation_ttl_slots: DEFAULT_RESERVATION_TTL_SLOTS,
            attestation_ttl_slots: DEFAULT_ATTESTATION_TTL_SLOTS,
            proof_cache_ttl_slots: DEFAULT_PROOF_CACHE_TTL_SLOTS,
            challenge_window_slots: DEFAULT_CHALLENGE_WINDOW_SLOTS,
            quorum_weight_bps: DEFAULT_QUORUM_WEIGHT_BPS,
            supermajority_weight_bps: DEFAULT_SUPERMAJORITY_WEIGHT_BPS,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            target_rebate_bps: DEFAULT_TARGET_REBATE_BPS,
            max_rebate_bps: DEFAULT_MAX_REBATE_BPS,
            min_lane_bond_micro_units: DEFAULT_MIN_LANE_BOND_MICRO_UNITS,
            min_auction_bond_micro_units: DEFAULT_MIN_AUCTION_BOND_MICRO_UNITS,
            slash_bps: DEFAULT_SLASH_BPS,
            fee_asset_id: DEFAULT_FEE_ASSET_ID.to_string(),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_fast_pq_confidential_state_witness_prefetch_config",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "mode": self.mode.as_str(),
            "schema_version": self.schema_version,
            "min_pq_security_bits": self.min_pq_security_bits,
            "min_privacy_set_size": self.min_privacy_set_size,
            "target_privacy_set_size": self.target_privacy_set_size,
            "target_prefetch_ms": self.target_prefetch_ms,
            "max_prefetch_ms": self.max_prefetch_ms,
            "slot_width_ms": self.slot_width_ms,
            "reservation_ttl_slots": self.reservation_ttl_slots,
            "attestation_ttl_slots": self.attestation_ttl_slots,
            "proof_cache_ttl_slots": self.proof_cache_ttl_slots,
            "challenge_window_slots": self.challenge_window_slots,
            "quorum_weight_bps": self.quorum_weight_bps,
            "supermajority_weight_bps": self.supermajority_weight_bps,
            "max_user_fee_bps": self.max_user_fee_bps,
            "target_rebate_bps": self.target_rebate_bps,
            "max_rebate_bps": self.max_rebate_bps,
            "min_lane_bond_micro_units": self.min_lane_bond_micro_units,
            "min_auction_bond_micro_units": self.min_auction_bond_micro_units,
            "slash_bps": self.slash_bps,
            "fee_asset_id": self.fee_asset_id,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct Counters {
    pub encrypted_contract_state_hints: u64,
    pub pq_witness_attestations: u64,
    pub prefetch_reservations: u64,
    pub cache_lanes: u64,
    pub bandwidth_auctions: u64,
    pub scheduler_receipts: u64,
    pub proof_cache_hints: u64,
    pub low_fee_rebates: u64,
    pub privacy_fences: u64,
    pub slashing_evidence: u64,
    pub public_records: u64,
    pub total_reserved_bytes: u64,
    pub total_warmed_bytes: u64,
    pub total_rebate_micro_units: u64,
    pub total_slashed_micro_units: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_fast_pq_confidential_state_witness_prefetch_counters",
            "encrypted_contract_state_hints": self.encrypted_contract_state_hints,
            "pq_witness_attestations": self.pq_witness_attestations,
            "prefetch_reservations": self.prefetch_reservations,
            "cache_lanes": self.cache_lanes,
            "bandwidth_auctions": self.bandwidth_auctions,
            "scheduler_receipts": self.scheduler_receipts,
            "proof_cache_hints": self.proof_cache_hints,
            "low_fee_rebates": self.low_fee_rebates,
            "privacy_fences": self.privacy_fences,
            "slashing_evidence": self.slashing_evidence,
            "public_records": self.public_records,
            "total_reserved_bytes": self.total_reserved_bytes,
            "total_warmed_bytes": self.total_warmed_bytes,
            "total_rebate_micro_units": self.total_rebate_micro_units,
            "total_slashed_micro_units": self.total_slashed_micro_units,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct Roots {
    pub encrypted_contract_state_hints_root: String,
    pub pq_witness_attestations_root: String,
    pub prefetch_reservations_root: String,
    pub cache_lanes_root: String,
    pub bandwidth_auctions_root: String,
    pub scheduler_receipts_root: String,
    pub proof_cache_hints_root: String,
    pub low_fee_rebates_root: String,
    pub privacy_fences_root: String,
    pub slashing_evidence_root: String,
    pub public_record_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_fast_pq_confidential_state_witness_prefetch_roots",
            "encrypted_contract_state_hints_root": self.encrypted_contract_state_hints_root,
            "pq_witness_attestations_root": self.pq_witness_attestations_root,
            "prefetch_reservations_root": self.prefetch_reservations_root,
            "cache_lanes_root": self.cache_lanes_root,
            "bandwidth_auctions_root": self.bandwidth_auctions_root,
            "scheduler_receipts_root": self.scheduler_receipts_root,
            "proof_cache_hints_root": self.proof_cache_hints_root,
            "low_fee_rebates_root": self.low_fee_rebates_root,
            "privacy_fences_root": self.privacy_fences_root,
            "slashing_evidence_root": self.slashing_evidence_root,
            "public_record_root": self.public_record_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct State {
    pub config: Config,
    pub l2_height: u64,
    pub monero_height: u64,
    pub epoch: u64,
    pub encrypted_contract_state_hints: BTreeMap<String, EncryptedContractStateHint>,
    pub pq_witness_attestations: BTreeMap<String, PqWitnessAttestation>,
    pub prefetch_reservations: BTreeMap<String, PrefetchReservation>,
    pub cache_lanes: BTreeMap<String, CacheLane>,
    pub bandwidth_auctions: BTreeMap<String, BandwidthAuction>,
    pub scheduler_receipts: BTreeMap<String, SchedulerReceipt>,
    pub proof_cache_hints: BTreeMap<String, ProofCacheHint>,
    pub low_fee_rebates: BTreeMap<String, LowFeeRebate>,
    pub privacy_fences: BTreeMap<String, PrivacyFence>,
    pub slashing_evidence: BTreeMap<String, SlashingEvidence>,
    pub public_records: BTreeMap<String, Value>,
    pub consumed_nullifiers: BTreeSet<String>,
}

impl State {
    pub fn devnet() -> Self {
        let mut state = Self {
            config: Config::devnet(),
            l2_height: DEVNET_L2_HEIGHT,
            monero_height: DEVNET_MONERO_HEIGHT,
            epoch: DEVNET_EPOCH,
            encrypted_contract_state_hints: BTreeMap::new(),
            pq_witness_attestations: BTreeMap::new(),
            prefetch_reservations: BTreeMap::new(),
            cache_lanes: BTreeMap::new(),
            bandwidth_auctions: BTreeMap::new(),
            scheduler_receipts: BTreeMap::new(),
            proof_cache_hints: BTreeMap::new(),
            low_fee_rebates: BTreeMap::new(),
            privacy_fences: BTreeMap::new(),
            slashing_evidence: BTreeMap::new(),
            public_records: BTreeMap::new(),
            consumed_nullifiers: BTreeSet::new(),
        };
        state.seed_devnet_records();
        state
    }

    pub fn counters(&self) -> Counters {
        Counters {
            encrypted_contract_state_hints: self.encrypted_contract_state_hints.len() as u64,
            pq_witness_attestations: self.pq_witness_attestations.len() as u64,
            prefetch_reservations: self.prefetch_reservations.len() as u64,
            cache_lanes: self.cache_lanes.len() as u64,
            bandwidth_auctions: self.bandwidth_auctions.len() as u64,
            scheduler_receipts: self.scheduler_receipts.len() as u64,
            proof_cache_hints: self.proof_cache_hints.len() as u64,
            low_fee_rebates: self.low_fee_rebates.len() as u64,
            privacy_fences: self.privacy_fences.len() as u64,
            slashing_evidence: self.slashing_evidence.len() as u64,
            public_records: self.public_records.len() as u64,
            total_reserved_bytes: self
                .prefetch_reservations
                .values()
                .map(|r| r.reserved_bytes)
                .sum(),
            total_warmed_bytes: self
                .scheduler_receipts
                .values()
                .map(|r| r.gas_saved_micro_units.saturating_add(r.latency_ms))
                .sum(),
            total_rebate_micro_units: self
                .low_fee_rebates
                .values()
                .map(|r| r.rebate_micro_units)
                .sum(),
            total_slashed_micro_units: self.slashing_evidence.values().map(|e| e.slash_bps).sum(),
        }
    }

    pub fn roots(&self) -> Roots {
        Roots {
            encrypted_contract_state_hints_root: values_root(
                "ENCRYPTED-CONTRACT-STATE-HINT-SET",
                &self.encrypted_contract_state_hints,
            ),
            pq_witness_attestations_root: values_root(
                "PQ-WITNESS-ATTESTATION-SET",
                &self.pq_witness_attestations,
            ),
            prefetch_reservations_root: values_root(
                "PREFETCH-RESERVATION-SET",
                &self.prefetch_reservations,
            ),
            cache_lanes_root: values_root("CACHE-LANE-SET", &self.cache_lanes),
            bandwidth_auctions_root: values_root("BANDWIDTH-AUCTION-SET", &self.bandwidth_auctions),
            scheduler_receipts_root: values_root("SCHEDULER-RECEIPT-SET", &self.scheduler_receipts),
            proof_cache_hints_root: values_root("PROOF-CACHE-HINT-SET", &self.proof_cache_hints),
            low_fee_rebates_root: values_root("LOW-FEE-REBATE-SET", &self.low_fee_rebates),
            privacy_fences_root: values_root("PRIVACY-FENCE-SET", &self.privacy_fences),
            slashing_evidence_root: values_root("SLASHING-EVIDENCE-SET", &self.slashing_evidence),
            public_record_root: value_map_root(
                "STATE-WITNESS-PREFETCH-PUBLIC-RECORD",
                &self.public_records,
            ),
        }
    }

    pub fn public_record_without_state_root(&self) -> Value {
        json!({
            "kind": "private_l2_fast_pq_confidential_state_witness_prefetch_state",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "l2_height": self.l2_height,
            "monero_height": self.monero_height,
            "epoch": self.epoch,
            "config": self.config.public_record(),
            "roots": self.roots().public_record(),
            "counters": self.counters().public_record(),
            "consumed_nullifier_root": string_set_root("STATE-WITNESS-PREFETCH-CONSUMED-NULLIFIER", &self.consumed_nullifiers),
        })
    }

    pub fn state_root(&self) -> String {
        state_root_from_public_record(&self.public_record_without_state_root())
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        if let Value::Object(ref mut object) = record {
            object.insert("state_root".to_string(), Value::String(self.state_root()));
        }
        record
    }

    pub fn insert_encrypted_contract_state_hint(
        &mut self,
        mut record: EncryptedContractStateHint,
    ) -> Result<String> {
        if self.encrypted_contract_state_hints.len() >= DEFAULT_MAX_ENCRYPTED_CONTRACT_STATE_HINTS {
            return Err(format!("encrypted_contract_state_hint capacity exceeded"));
        }
        if record.contract_id.is_empty() {
            record.contract_id = encrypted_contract_state_hint_id(&record.public_record());
        }
        let id = record.contract_id.clone();
        self.record_public(
            format!("encrypted_contract_state_hint:{id}"),
            record.public_record(),
        )?;
        self.encrypted_contract_state_hints
            .insert(id.clone(), record);
        Ok(id)
    }

    pub fn get_encrypted_contract_state_hint(
        &self,
        id: &str,
    ) -> Option<&EncryptedContractStateHint> {
        self.encrypted_contract_state_hints.get(id)
    }

    pub fn insert_pq_witness_attestation(
        &mut self,
        mut record: PqWitnessAttestation,
    ) -> Result<String> {
        if self.pq_witness_attestations.len() >= DEFAULT_MAX_PQ_WITNESS_ATTESTATIONS {
            return Err(format!("pq_witness_attestation capacity exceeded"));
        }
        if record.witness_id.is_empty() {
            record.witness_id = pq_witness_attestation_id(&record.public_record());
        }
        let id = record.witness_id.clone();
        self.record_public(
            format!("pq_witness_attestation:{id}"),
            record.public_record(),
        )?;
        self.pq_witness_attestations.insert(id.clone(), record);
        Ok(id)
    }

    pub fn get_pq_witness_attestation(&self, id: &str) -> Option<&PqWitnessAttestation> {
        self.pq_witness_attestations.get(id)
    }

    pub fn insert_prefetch_reservation(
        &mut self,
        mut record: PrefetchReservation,
    ) -> Result<String> {
        if self.prefetch_reservations.len() >= DEFAULT_MAX_PREFETCH_RESERVATIONS {
            return Err(format!("prefetch_reservation capacity exceeded"));
        }
        if record.reservation_id.is_empty() {
            record.reservation_id = prefetch_reservation_id(&record.public_record());
        }
        let id = record.reservation_id.clone();
        self.record_public(format!("prefetch_reservation:{id}"), record.public_record())?;
        self.prefetch_reservations.insert(id.clone(), record);
        Ok(id)
    }

    pub fn get_prefetch_reservation(&self, id: &str) -> Option<&PrefetchReservation> {
        self.prefetch_reservations.get(id)
    }

    pub fn insert_cache_lane(&mut self, mut record: CacheLane) -> Result<String> {
        if self.cache_lanes.len() >= DEFAULT_MAX_CACHE_LANES {
            return Err(format!("cache_lane capacity exceeded"));
        }
        if record.lane_id.is_empty() {
            record.lane_id = cache_lane_id(&record.public_record());
        }
        let id = record.lane_id.clone();
        self.record_public(format!("cache_lane:{id}"), record.public_record())?;
        self.cache_lanes.insert(id.clone(), record);
        Ok(id)
    }

    pub fn get_cache_lane(&self, id: &str) -> Option<&CacheLane> {
        self.cache_lanes.get(id)
    }

    pub fn insert_bandwidth_auction(&mut self, mut record: BandwidthAuction) -> Result<String> {
        if self.bandwidth_auctions.len() >= DEFAULT_MAX_BANDWIDTH_AUCTIONS {
            return Err(format!("bandwidth_auction capacity exceeded"));
        }
        if record.auction_id.is_empty() {
            record.auction_id = bandwidth_auction_id(&record.public_record());
        }
        let id = record.auction_id.clone();
        self.record_public(format!("bandwidth_auction:{id}"), record.public_record())?;
        self.bandwidth_auctions.insert(id.clone(), record);
        Ok(id)
    }

    pub fn get_bandwidth_auction(&self, id: &str) -> Option<&BandwidthAuction> {
        self.bandwidth_auctions.get(id)
    }

    pub fn insert_scheduler_receipt(&mut self, mut record: SchedulerReceipt) -> Result<String> {
        if self.scheduler_receipts.len() >= DEFAULT_MAX_SCHEDULER_RECEIPTS {
            return Err(format!("scheduler_receipt capacity exceeded"));
        }
        if record.receipt_id.is_empty() {
            record.receipt_id = scheduler_receipt_id(&record.public_record());
        }
        let id = record.receipt_id.clone();
        self.record_public(format!("scheduler_receipt:{id}"), record.public_record())?;
        self.scheduler_receipts.insert(id.clone(), record);
        Ok(id)
    }

    pub fn get_scheduler_receipt(&self, id: &str) -> Option<&SchedulerReceipt> {
        self.scheduler_receipts.get(id)
    }

    pub fn insert_proof_cache_hint(&mut self, mut record: ProofCacheHint) -> Result<String> {
        if self.proof_cache_hints.len() >= DEFAULT_MAX_PROOF_CACHE_HINTS {
            return Err(format!("proof_cache_hint capacity exceeded"));
        }
        if record.proof_hint_id.is_empty() {
            record.proof_hint_id = proof_cache_hint_id(&record.public_record());
        }
        let id = record.proof_hint_id.clone();
        self.record_public(format!("proof_cache_hint:{id}"), record.public_record())?;
        self.proof_cache_hints.insert(id.clone(), record);
        Ok(id)
    }

    pub fn get_proof_cache_hint(&self, id: &str) -> Option<&ProofCacheHint> {
        self.proof_cache_hints.get(id)
    }

    pub fn insert_low_fee_rebate(&mut self, mut record: LowFeeRebate) -> Result<String> {
        if self.low_fee_rebates.len() >= DEFAULT_MAX_LOW_FEE_REBATES {
            return Err(format!("low_fee_rebate capacity exceeded"));
        }
        if record.rebate_id.is_empty() {
            record.rebate_id = low_fee_rebate_id(&record.public_record());
        }
        let id = record.rebate_id.clone();
        self.record_public(format!("low_fee_rebate:{id}"), record.public_record())?;
        self.low_fee_rebates.insert(id.clone(), record);
        Ok(id)
    }

    pub fn get_low_fee_rebate(&self, id: &str) -> Option<&LowFeeRebate> {
        self.low_fee_rebates.get(id)
    }

    pub fn insert_privacy_fence(&mut self, mut record: PrivacyFence) -> Result<String> {
        if self.privacy_fences.len() >= DEFAULT_MAX_PRIVACY_FENCES {
            return Err(format!("privacy_fence capacity exceeded"));
        }
        if record.fence_id.is_empty() {
            record.fence_id = privacy_fence_id(&record.public_record());
        }
        let id = record.fence_id.clone();
        self.record_public(format!("privacy_fence:{id}"), record.public_record())?;
        self.privacy_fences.insert(id.clone(), record);
        Ok(id)
    }

    pub fn get_privacy_fence(&self, id: &str) -> Option<&PrivacyFence> {
        self.privacy_fences.get(id)
    }

    pub fn insert_slashing_evidence(&mut self, mut record: SlashingEvidence) -> Result<String> {
        if self.slashing_evidence.len() >= DEFAULT_MAX_SLASHING_EVIDENCE {
            return Err(format!("slashing_evidence capacity exceeded"));
        }
        if record.evidence_id.is_empty() {
            record.evidence_id = slashing_evidence_id(&record.public_record());
        }
        let id = record.evidence_id.clone();
        self.record_public(format!("slashing_evidence:{id}"), record.public_record())?;
        self.slashing_evidence.insert(id.clone(), record);
        Ok(id)
    }

    pub fn get_slashing_evidence(&self, id: &str) -> Option<&SlashingEvidence> {
        self.slashing_evidence.get(id)
    }

    fn seed_devnet_records(&mut self) {
        let lane = CacheLane {
            lane_id: runtime_id("DEVNET-CACHE-LANE", &[HashPart::Str("lane-a")]),
            operator_id: "devnet-prefetch-operator-a".to_string(),
            lane_status: LaneStatus::Open,
            bandwidth_bytes_per_slot: 16_777_216,
            witness_cache_bytes: 1_073_741_824,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            created_at_height: self.l2_height,
            expires_at_height: self.l2_height + 10_000,
            sequence: 0,
        };
        let lane_id = lane.lane_id.clone();
        let _ = self.insert_cache_lane(lane);

        let hint = EncryptedContractStateHint {
            contract_id: runtime_id("DEVNET-CONTRACT", &[HashPart::Str("confidential-swap")]),
            encrypted_state_hint_root: runtime_id("DEVNET-HINT", &[HashPart::Str("hint")]),
            contract_state_commitment: runtime_id("DEVNET-STATE", &[HashPart::Str("state")]),
            read_set_root: runtime_id("DEVNET-READ-SET", &[HashPart::Str("read")]),
            write_set_root: runtime_id("DEVNET-WRITE-SET", &[HashPart::Str("write")]),
            view_tag_root: runtime_id("DEVNET-VIEW-TAG", &[HashPart::Str("view")]),
            privacy_budget_bps: 250,
            created_at_height: self.l2_height,
            expires_at_height: self.l2_height + self.config.reservation_ttl_slots,
            sequence: 1,
        };
        let contract_id = hint.contract_id.clone();
        let _ = self.insert_encrypted_contract_state_hint(hint);

        let reservation = PrefetchReservation {
            reservation_id: runtime_id("DEVNET-RESERVATION", &[HashPart::Str(&contract_id)]),
            lane_id: lane_id.clone(),
            contract_id: contract_id.clone(),
            state_hint_id: contract_id.clone(),
            reserved_bytes: 4_194_304,
            max_fee_micro_units: 700,
            status: ReservationStatus::Reserved,
            created_at_height: self.l2_height,
            expires_at_height: self.l2_height + self.config.reservation_ttl_slots,
            sequence: 2,
        };
        let reservation_id = reservation.reservation_id.clone();
        let _ = self.insert_prefetch_reservation(reservation);

        let attestation = PqWitnessAttestation {
            witness_id: runtime_id("DEVNET-WITNESS", &[HashPart::Str(&reservation_id)]),
            witness_root: runtime_id("DEVNET-WITNESS-ROOT", &[HashPart::Str(&reservation_id)]),
            pq_public_key_root: runtime_id("DEVNET-PQ-PK", &[HashPart::Str("committee-a")]),
            pq_signature_root: runtime_id("DEVNET-PQ-SIG", &[HashPart::Str("committee-a")]),
            attester_weight_bps: DEFAULT_QUORUM_WEIGHT_BPS,
            verdict: AttestationVerdict::Include,
            created_at_height: self.l2_height,
            expires_at_height: self.l2_height + self.config.attestation_ttl_slots,
            sequence: 3,
        };
        let _ = self.insert_pq_witness_attestation(attestation);

        let auction = BandwidthAuction {
            auction_id: runtime_id("DEVNET-AUCTION", &[HashPart::Str(&lane_id)]),
            lane_id: lane_id.clone(),
            sealed_bid_root: runtime_id("DEVNET-SEALED-BID", &[HashPart::Str(&lane_id)]),
            clearing_price_micro_units: 4,
            allocated_bytes: 8_388_608,
            rebate_pool_micro_units: 2_000,
            winner_root: runtime_id("DEVNET-WINNER", &[HashPart::Str(&lane_id)]),
            created_at_height: self.l2_height,
            expires_at_height: self.l2_height + 64,
            sequence: 4,
        };
        let _ = self.insert_bandwidth_auction(auction);

        let receipt = SchedulerReceipt {
            receipt_id: runtime_id("DEVNET-RECEIPT", &[HashPart::Str(&reservation_id)]),
            lane_id: lane_id.clone(),
            reservation_id: reservation_id.clone(),
            execution_root: runtime_id("DEVNET-EXECUTION", &[HashPart::Str(&reservation_id)]),
            prefetch_root: runtime_id("DEVNET-PREFETCH", &[HashPart::Str(&reservation_id)]),
            gas_saved_micro_units: 1_900,
            latency_ms: DEFAULT_TARGET_PREFETCH_MS,
            created_at_height: self.l2_height,
            expires_at_height: self.l2_height + 256,
            sequence: 5,
        };
        let _ = self.insert_scheduler_receipt(receipt);

        let proof_hint = ProofCacheHint {
            proof_hint_id: runtime_id("DEVNET-PROOF-HINT", &[HashPart::Str(&contract_id)]),
            circuit_id: "confidential-contract-call-vm".to_string(),
            verifying_key_root: runtime_id("DEVNET-VK", &[HashPart::Str("vm")]),
            recursive_proof_hint_root: runtime_id("DEVNET-RECURSIVE-HINT", &[HashPart::Str("vm")]),
            expected_hit_rate_bps: 7_500,
            proof_bytes: 196_608,
            ttl_slots: DEFAULT_PROOF_CACHE_TTL_SLOTS,
            created_at_height: self.l2_height,
            expires_at_height: self.l2_height + DEFAULT_PROOF_CACHE_TTL_SLOTS,
            sequence: 6,
        };
        let _ = self.insert_proof_cache_hint(proof_hint);

        let rebate = LowFeeRebate {
            rebate_id: runtime_id("DEVNET-REBATE", &[HashPart::Str(&reservation_id)]),
            account_commitment: runtime_id("DEVNET-ACCOUNT", &[HashPart::Str("alice")]),
            reservation_id: reservation_id.clone(),
            fee_asset_id: self.config.fee_asset_id.clone(),
            gross_fee_micro_units: 700,
            rebate_micro_units: 420,
            sponsor_pool_id: "devnet-sponsor-pool-a".to_string(),
            created_at_height: self.l2_height,
            expires_at_height: self.l2_height + 512,
            sequence: 7,
        };
        let _ = self.insert_low_fee_rebate(rebate);

        let fence = PrivacyFence {
            fence_id: runtime_id("DEVNET-FENCE", &[HashPart::Str(&contract_id)]),
            fence_kind: PrivacyFenceKind::ContractKeyEpoch,
            scope_root: runtime_id("DEVNET-FENCE-SCOPE", &[HashPart::Str(&contract_id)]),
            nullifier_root: runtime_id("DEVNET-NULLIFIER", &[HashPart::Str("nf")]),
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            release_height: self.l2_height + 720,
            sealed: true,
            created_at_height: self.l2_height,
            expires_at_height: self.l2_height + 720,
            sequence: 8,
        };
        let _ = self.insert_privacy_fence(fence);
    }

    fn record_public(&mut self, label: String, payload: Value) -> Result<String> {
        if self.public_records.len() >= DEFAULT_MAX_PUBLIC_RECORDS {
            return Err("public record capacity exceeded".to_string());
        }
        let record_id = public_record_id(&label, self.public_records.len() as u64, &payload);
        self.public_records.insert(record_id.clone(), payload);
        Ok(record_id)
    }
}

pub fn devnet_state_root() -> String {
    State::devnet().state_root()
}

pub fn devnet_public_record() -> Value {
    State::devnet().public_record()
}

pub fn state_root_from_public_record(record: &Value) -> String {
    runtime_payload_root("STATE-WITNESS-PREFETCH-STATE", record)
}

pub fn public_record_id(label: &str, sequence: u64, payload: &Value) -> String {
    domain_hash(
        "STATE-WITNESS-PREFETCH-PUBLIC-RECORD-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
            HashPart::U64(sequence),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub fn runtime_payload_root(domain: &str, payload: &Value) -> String {
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

pub fn runtime_id(domain: &str, parts: &[HashPart<'_>]) -> String {
    let mut owned = Vec::with_capacity(parts.len() + 2);
    owned.push(HashPart::Str(CHAIN_ID));
    owned.push(HashPart::Str(PROTOCOL_VERSION));
    owned.extend(parts.iter().map(clone_hash_part));
    domain_hash(domain, &owned, 32)
}

fn clone_hash_part<'a>(part: &HashPart<'a>) -> HashPart<'a> {
    match part {
        HashPart::Bytes(value) => HashPart::Bytes(*value),
        HashPart::Str(value) => HashPart::Str(*value),
        HashPart::U64(value) => HashPart::U64(*value),
        HashPart::Int(value) => HashPart::Int(*value),
        HashPart::Json(value) => HashPart::Json(*value),
    }
}

fn value_map_root<T: PublicRecord>(domain: &str, values: &BTreeMap<String, T>) -> String {
    let leaves = values
        .iter()
        .map(|(id, value)| json!({ "id": id, "record": value.public_record() }))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn values_root<T: PublicRecord>(domain: &str, values: &BTreeMap<String, T>) -> String {
    value_map_root(domain, values)
}

fn string_set_root(domain: &str, values: &BTreeSet<String>) -> String {
    let leaves = values.iter().map(|value| json!(value)).collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

pub trait PublicRecord {
    fn public_record(&self) -> Value;
}

impl PublicRecord for EncryptedContractStateHint {
    fn public_record(&self) -> Value {
        EncryptedContractStateHint::public_record(self)
    }
}
impl PublicRecord for PqWitnessAttestation {
    fn public_record(&self) -> Value {
        PqWitnessAttestation::public_record(self)
    }
}
impl PublicRecord for PrefetchReservation {
    fn public_record(&self) -> Value {
        PrefetchReservation::public_record(self)
    }
}
impl PublicRecord for CacheLane {
    fn public_record(&self) -> Value {
        CacheLane::public_record(self)
    }
}
impl PublicRecord for BandwidthAuction {
    fn public_record(&self) -> Value {
        BandwidthAuction::public_record(self)
    }
}
impl PublicRecord for SchedulerReceipt {
    fn public_record(&self) -> Value {
        SchedulerReceipt::public_record(self)
    }
}
impl PublicRecord for ProofCacheHint {
    fn public_record(&self) -> Value {
        ProofCacheHint::public_record(self)
    }
}
impl PublicRecord for LowFeeRebate {
    fn public_record(&self) -> Value {
        LowFeeRebate::public_record(self)
    }
}
impl PublicRecord for PrivacyFence {
    fn public_record(&self) -> Value {
        PrivacyFence::public_record(self)
    }
}
impl PublicRecord for SlashingEvidence {
    fn public_record(&self) -> Value {
        SlashingEvidence::public_record(self)
    }
}

impl PublicRecord for Value {
    fn public_record(&self) -> Value {
        self.clone()
    }
}

pub fn encrypted_contract_state_hint_id(record: &Value) -> String {
    runtime_payload_root("ENCRYPTED-CONTRACT-STATE-HINT-ID", record)
}
pub fn pq_witness_attestation_id(record: &Value) -> String {
    runtime_payload_root("PQ-WITNESS-ATTESTATION-ID", record)
}
pub fn prefetch_reservation_id(record: &Value) -> String {
    runtime_payload_root("PREFETCH-RESERVATION-ID", record)
}
pub fn cache_lane_id(record: &Value) -> String {
    runtime_payload_root("CACHE-LANE-ID", record)
}
pub fn bandwidth_auction_id(record: &Value) -> String {
    runtime_payload_root("BANDWIDTH-AUCTION-ID", record)
}
pub fn scheduler_receipt_id(record: &Value) -> String {
    runtime_payload_root("SCHEDULER-RECEIPT-ID", record)
}
pub fn proof_cache_hint_id(record: &Value) -> String {
    runtime_payload_root("PROOF-CACHE-HINT-ID", record)
}
pub fn low_fee_rebate_id(record: &Value) -> String {
    runtime_payload_root("LOW-FEE-REBATE-ID", record)
}
pub fn privacy_fence_id(record: &Value) -> String {
    runtime_payload_root("PRIVACY-FENCE-ID", record)
}
pub fn slashing_evidence_id(record: &Value) -> String {
    runtime_payload_root("SLASHING-EVIDENCE-ID", record)
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame0 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame0 {
    pub fn for_quantum_resistant_attestation(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "quantum_resistant_attestation".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame1 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame1 {
    pub fn for_fast_prefetch_path(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "fast_prefetch_path".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame2 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame2 {
    pub fn for_low_fee_rebate_path(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "low_fee_rebate_path".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame3 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame3 {
    pub fn for_privacy_preserving_fence(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "privacy_preserving_fence".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame4 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame4 {
    pub fn for_smart_contract_execution_cache(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "smart_contract_execution_cache".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame5 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame5 {
    pub fn for_monero_viewtag_alignment(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "monero_viewtag_alignment".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame6 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame6 {
    pub fn for_bandwidth_market_clearing(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "bandwidth_market_clearing".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame7 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame7 {
    pub fn for_scheduler_receipt_finality(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "scheduler_receipt_finality".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame8 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame8 {
    pub fn for_slashing_evidence_path(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "slashing_evidence_path".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame9 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame9 {
    pub fn for_proof_cache_hotset(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "proof_cache_hotset".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame10 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame10 {
    pub fn for_quantum_resistant_attestation(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "quantum_resistant_attestation".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame11 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame11 {
    pub fn for_fast_prefetch_path(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "fast_prefetch_path".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame12 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame12 {
    pub fn for_low_fee_rebate_path(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "low_fee_rebate_path".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame13 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame13 {
    pub fn for_privacy_preserving_fence(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "privacy_preserving_fence".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame14 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame14 {
    pub fn for_smart_contract_execution_cache(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "smart_contract_execution_cache".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame15 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame15 {
    pub fn for_monero_viewtag_alignment(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "monero_viewtag_alignment".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame16 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame16 {
    pub fn for_bandwidth_market_clearing(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "bandwidth_market_clearing".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame17 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame17 {
    pub fn for_scheduler_receipt_finality(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "scheduler_receipt_finality".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame18 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame18 {
    pub fn for_slashing_evidence_path(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "slashing_evidence_path".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame19 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame19 {
    pub fn for_proof_cache_hotset(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "proof_cache_hotset".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame20 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame20 {
    pub fn for_quantum_resistant_attestation(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "quantum_resistant_attestation".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame21 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame21 {
    pub fn for_fast_prefetch_path(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "fast_prefetch_path".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame22 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame22 {
    pub fn for_low_fee_rebate_path(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "low_fee_rebate_path".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame23 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame23 {
    pub fn for_privacy_preserving_fence(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "privacy_preserving_fence".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame24 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame24 {
    pub fn for_smart_contract_execution_cache(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "smart_contract_execution_cache".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame25 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame25 {
    pub fn for_monero_viewtag_alignment(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "monero_viewtag_alignment".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame26 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame26 {
    pub fn for_bandwidth_market_clearing(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "bandwidth_market_clearing".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame27 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame27 {
    pub fn for_scheduler_receipt_finality(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "scheduler_receipt_finality".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame28 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame28 {
    pub fn for_slashing_evidence_path(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "slashing_evidence_path".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame29 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame29 {
    pub fn for_proof_cache_hotset(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "proof_cache_hotset".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame30 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame30 {
    pub fn for_quantum_resistant_attestation(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "quantum_resistant_attestation".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame31 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame31 {
    pub fn for_fast_prefetch_path(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "fast_prefetch_path".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame32 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame32 {
    pub fn for_low_fee_rebate_path(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "low_fee_rebate_path".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame33 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame33 {
    pub fn for_privacy_preserving_fence(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "privacy_preserving_fence".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame34 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame34 {
    pub fn for_smart_contract_execution_cache(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "smart_contract_execution_cache".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame35 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame35 {
    pub fn for_monero_viewtag_alignment(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "monero_viewtag_alignment".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame36 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame36 {
    pub fn for_bandwidth_market_clearing(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "bandwidth_market_clearing".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame37 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame37 {
    pub fn for_scheduler_receipt_finality(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "scheduler_receipt_finality".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame38 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame38 {
    pub fn for_slashing_evidence_path(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "slashing_evidence_path".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame39 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame39 {
    pub fn for_proof_cache_hotset(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "proof_cache_hotset".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame40 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame40 {
    pub fn for_quantum_resistant_attestation(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "quantum_resistant_attestation".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame41 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame41 {
    pub fn for_fast_prefetch_path(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "fast_prefetch_path".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame42 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame42 {
    pub fn for_low_fee_rebate_path(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "low_fee_rebate_path".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame43 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame43 {
    pub fn for_privacy_preserving_fence(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "privacy_preserving_fence".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame44 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame44 {
    pub fn for_smart_contract_execution_cache(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "smart_contract_execution_cache".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame45 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame45 {
    pub fn for_monero_viewtag_alignment(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "monero_viewtag_alignment".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame46 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame46 {
    pub fn for_bandwidth_market_clearing(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "bandwidth_market_clearing".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame47 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame47 {
    pub fn for_scheduler_receipt_finality(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "scheduler_receipt_finality".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame48 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame48 {
    pub fn for_slashing_evidence_path(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "slashing_evidence_path".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame49 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame49 {
    pub fn for_proof_cache_hotset(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "proof_cache_hotset".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame50 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame50 {
    pub fn for_quantum_resistant_attestation(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "quantum_resistant_attestation".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame51 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame51 {
    pub fn for_fast_prefetch_path(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "fast_prefetch_path".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame52 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame52 {
    pub fn for_low_fee_rebate_path(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "low_fee_rebate_path".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame53 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame53 {
    pub fn for_privacy_preserving_fence(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "privacy_preserving_fence".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame54 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame54 {
    pub fn for_smart_contract_execution_cache(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "smart_contract_execution_cache".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame55 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame55 {
    pub fn for_monero_viewtag_alignment(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "monero_viewtag_alignment".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame56 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame56 {
    pub fn for_bandwidth_market_clearing(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "bandwidth_market_clearing".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame57 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame57 {
    pub fn for_scheduler_receipt_finality(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "scheduler_receipt_finality".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame58 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame58 {
    pub fn for_slashing_evidence_path(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "slashing_evidence_path".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame59 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame59 {
    pub fn for_proof_cache_hotset(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "proof_cache_hotset".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame60 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame60 {
    pub fn for_quantum_resistant_attestation(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "quantum_resistant_attestation".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame61 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame61 {
    pub fn for_fast_prefetch_path(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "fast_prefetch_path".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame62 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame62 {
    pub fn for_low_fee_rebate_path(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "low_fee_rebate_path".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame63 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame63 {
    pub fn for_privacy_preserving_fence(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "privacy_preserving_fence".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame64 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame64 {
    pub fn for_smart_contract_execution_cache(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "smart_contract_execution_cache".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame65 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame65 {
    pub fn for_monero_viewtag_alignment(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "monero_viewtag_alignment".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame66 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame66 {
    pub fn for_bandwidth_market_clearing(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "bandwidth_market_clearing".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame67 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame67 {
    pub fn for_scheduler_receipt_finality(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "scheduler_receipt_finality".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame68 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame68 {
    pub fn for_slashing_evidence_path(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "slashing_evidence_path".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame69 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame69 {
    pub fn for_proof_cache_hotset(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "proof_cache_hotset".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame70 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame70 {
    pub fn for_quantum_resistant_attestation(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "quantum_resistant_attestation".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame71 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame71 {
    pub fn for_fast_prefetch_path(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "fast_prefetch_path".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame72 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame72 {
    pub fn for_low_fee_rebate_path(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "low_fee_rebate_path".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame73 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame73 {
    pub fn for_privacy_preserving_fence(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "privacy_preserving_fence".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame74 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame74 {
    pub fn for_smart_contract_execution_cache(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "smart_contract_execution_cache".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame75 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame75 {
    pub fn for_monero_viewtag_alignment(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "monero_viewtag_alignment".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame76 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame76 {
    pub fn for_bandwidth_market_clearing(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "bandwidth_market_clearing".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame77 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame77 {
    pub fn for_scheduler_receipt_finality(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "scheduler_receipt_finality".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame78 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame78 {
    pub fn for_slashing_evidence_path(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "slashing_evidence_path".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame79 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame79 {
    pub fn for_proof_cache_hotset(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "proof_cache_hotset".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame80 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame80 {
    pub fn for_quantum_resistant_attestation(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "quantum_resistant_attestation".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame81 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame81 {
    pub fn for_fast_prefetch_path(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "fast_prefetch_path".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame82 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame82 {
    pub fn for_low_fee_rebate_path(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "low_fee_rebate_path".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame83 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame83 {
    pub fn for_privacy_preserving_fence(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "privacy_preserving_fence".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame84 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame84 {
    pub fn for_smart_contract_execution_cache(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "smart_contract_execution_cache".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame85 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame85 {
    pub fn for_monero_viewtag_alignment(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "monero_viewtag_alignment".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame86 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame86 {
    pub fn for_bandwidth_market_clearing(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "bandwidth_market_clearing".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame87 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame87 {
    pub fn for_scheduler_receipt_finality(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "scheduler_receipt_finality".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame88 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame88 {
    pub fn for_slashing_evidence_path(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "slashing_evidence_path".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame89 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame89 {
    pub fn for_proof_cache_hotset(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "proof_cache_hotset".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame90 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame90 {
    pub fn for_quantum_resistant_attestation(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "quantum_resistant_attestation".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame91 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame91 {
    pub fn for_fast_prefetch_path(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "fast_prefetch_path".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame92 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame92 {
    pub fn for_low_fee_rebate_path(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "low_fee_rebate_path".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame93 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame93 {
    pub fn for_privacy_preserving_fence(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "privacy_preserving_fence".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame94 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame94 {
    pub fn for_smart_contract_execution_cache(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "smart_contract_execution_cache".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame95 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame95 {
    pub fn for_monero_viewtag_alignment(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "monero_viewtag_alignment".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame96 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame96 {
    pub fn for_bandwidth_market_clearing(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "bandwidth_market_clearing".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame97 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame97 {
    pub fn for_scheduler_receipt_finality(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "scheduler_receipt_finality".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame98 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame98 {
    pub fn for_slashing_evidence_path(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "slashing_evidence_path".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame99 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame99 {
    pub fn for_proof_cache_hotset(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "proof_cache_hotset".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame100 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame100 {
    pub fn for_quantum_resistant_attestation(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "quantum_resistant_attestation".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame101 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame101 {
    pub fn for_fast_prefetch_path(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "fast_prefetch_path".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame102 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame102 {
    pub fn for_low_fee_rebate_path(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "low_fee_rebate_path".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame103 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame103 {
    pub fn for_privacy_preserving_fence(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "privacy_preserving_fence".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame104 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame104 {
    pub fn for_smart_contract_execution_cache(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "smart_contract_execution_cache".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame105 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame105 {
    pub fn for_monero_viewtag_alignment(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "monero_viewtag_alignment".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame106 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame106 {
    pub fn for_bandwidth_market_clearing(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "bandwidth_market_clearing".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame107 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame107 {
    pub fn for_scheduler_receipt_finality(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "scheduler_receipt_finality".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame108 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame108 {
    pub fn for_slashing_evidence_path(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "slashing_evidence_path".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame109 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame109 {
    pub fn for_proof_cache_hotset(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "proof_cache_hotset".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame110 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame110 {
    pub fn for_quantum_resistant_attestation(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "quantum_resistant_attestation".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame111 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame111 {
    pub fn for_fast_prefetch_path(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "fast_prefetch_path".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame112 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame112 {
    pub fn for_low_fee_rebate_path(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "low_fee_rebate_path".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame113 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame113 {
    pub fn for_privacy_preserving_fence(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "privacy_preserving_fence".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame114 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame114 {
    pub fn for_smart_contract_execution_cache(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "smart_contract_execution_cache".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame115 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame115 {
    pub fn for_monero_viewtag_alignment(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "monero_viewtag_alignment".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame116 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame116 {
    pub fn for_bandwidth_market_clearing(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "bandwidth_market_clearing".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame117 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame117 {
    pub fn for_scheduler_receipt_finality(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "scheduler_receipt_finality".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame118 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame118 {
    pub fn for_slashing_evidence_path(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "slashing_evidence_path".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame119 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame119 {
    pub fn for_proof_cache_hotset(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "proof_cache_hotset".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame120 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame120 {
    pub fn for_quantum_resistant_attestation(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "quantum_resistant_attestation".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame121 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame121 {
    pub fn for_fast_prefetch_path(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "fast_prefetch_path".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame122 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame122 {
    pub fn for_low_fee_rebate_path(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "low_fee_rebate_path".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame123 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame123 {
    pub fn for_privacy_preserving_fence(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "privacy_preserving_fence".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame124 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame124 {
    pub fn for_smart_contract_execution_cache(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "smart_contract_execution_cache".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame125 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame125 {
    pub fn for_monero_viewtag_alignment(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "monero_viewtag_alignment".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame126 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame126 {
    pub fn for_bandwidth_market_clearing(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "bandwidth_market_clearing".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame127 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame127 {
    pub fn for_scheduler_receipt_finality(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "scheduler_receipt_finality".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame128 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame128 {
    pub fn for_slashing_evidence_path(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "slashing_evidence_path".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame129 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame129 {
    pub fn for_proof_cache_hotset(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "proof_cache_hotset".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame130 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame130 {
    pub fn for_quantum_resistant_attestation(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "quantum_resistant_attestation".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame131 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame131 {
    pub fn for_fast_prefetch_path(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "fast_prefetch_path".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame132 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame132 {
    pub fn for_low_fee_rebate_path(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "low_fee_rebate_path".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame133 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame133 {
    pub fn for_privacy_preserving_fence(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "privacy_preserving_fence".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame134 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame134 {
    pub fn for_smart_contract_execution_cache(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "smart_contract_execution_cache".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame135 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame135 {
    pub fn for_monero_viewtag_alignment(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "monero_viewtag_alignment".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame136 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame136 {
    pub fn for_bandwidth_market_clearing(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "bandwidth_market_clearing".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame137 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame137 {
    pub fn for_scheduler_receipt_finality(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "scheduler_receipt_finality".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame138 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame138 {
    pub fn for_slashing_evidence_path(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "slashing_evidence_path".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame139 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame139 {
    pub fn for_proof_cache_hotset(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "proof_cache_hotset".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame140 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame140 {
    pub fn for_quantum_resistant_attestation(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "quantum_resistant_attestation".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame141 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame141 {
    pub fn for_fast_prefetch_path(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "fast_prefetch_path".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame142 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame142 {
    pub fn for_low_fee_rebate_path(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "low_fee_rebate_path".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame143 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame143 {
    pub fn for_privacy_preserving_fence(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "privacy_preserving_fence".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame144 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame144 {
    pub fn for_smart_contract_execution_cache(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "smart_contract_execution_cache".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame145 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame145 {
    pub fn for_monero_viewtag_alignment(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "monero_viewtag_alignment".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame146 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame146 {
    pub fn for_bandwidth_market_clearing(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "bandwidth_market_clearing".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame147 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame147 {
    pub fn for_scheduler_receipt_finality(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "scheduler_receipt_finality".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame148 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame148 {
    pub fn for_slashing_evidence_path(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "slashing_evidence_path".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame149 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame149 {
    pub fn for_proof_cache_hotset(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "proof_cache_hotset".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame150 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame150 {
    pub fn for_quantum_resistant_attestation(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "quantum_resistant_attestation".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame151 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame151 {
    pub fn for_fast_prefetch_path(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "fast_prefetch_path".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame152 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame152 {
    pub fn for_low_fee_rebate_path(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "low_fee_rebate_path".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame153 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame153 {
    pub fn for_privacy_preserving_fence(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "privacy_preserving_fence".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame154 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame154 {
    pub fn for_smart_contract_execution_cache(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "smart_contract_execution_cache".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame155 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame155 {
    pub fn for_monero_viewtag_alignment(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "monero_viewtag_alignment".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame156 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame156 {
    pub fn for_bandwidth_market_clearing(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "bandwidth_market_clearing".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame157 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame157 {
    pub fn for_scheduler_receipt_finality(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "scheduler_receipt_finality".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame158 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame158 {
    pub fn for_slashing_evidence_path(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "slashing_evidence_path".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame159 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame159 {
    pub fn for_proof_cache_hotset(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "proof_cache_hotset".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame160 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame160 {
    pub fn for_quantum_resistant_attestation(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "quantum_resistant_attestation".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame161 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame161 {
    pub fn for_fast_prefetch_path(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "fast_prefetch_path".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame162 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame162 {
    pub fn for_low_fee_rebate_path(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "low_fee_rebate_path".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame163 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame163 {
    pub fn for_privacy_preserving_fence(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "privacy_preserving_fence".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame164 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame164 {
    pub fn for_smart_contract_execution_cache(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "smart_contract_execution_cache".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame165 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame165 {
    pub fn for_monero_viewtag_alignment(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "monero_viewtag_alignment".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame166 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame166 {
    pub fn for_bandwidth_market_clearing(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "bandwidth_market_clearing".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame167 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame167 {
    pub fn for_scheduler_receipt_finality(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "scheduler_receipt_finality".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame168 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame168 {
    pub fn for_slashing_evidence_path(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "slashing_evidence_path".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame169 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame169 {
    pub fn for_proof_cache_hotset(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "proof_cache_hotset".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame170 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame170 {
    pub fn for_quantum_resistant_attestation(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "quantum_resistant_attestation".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame171 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame171 {
    pub fn for_fast_prefetch_path(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "fast_prefetch_path".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame172 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame172 {
    pub fn for_low_fee_rebate_path(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "low_fee_rebate_path".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame173 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame173 {
    pub fn for_privacy_preserving_fence(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "privacy_preserving_fence".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame174 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame174 {
    pub fn for_smart_contract_execution_cache(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "smart_contract_execution_cache".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame175 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame175 {
    pub fn for_monero_viewtag_alignment(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "monero_viewtag_alignment".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame176 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame176 {
    pub fn for_bandwidth_market_clearing(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "bandwidth_market_clearing".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame177 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame177 {
    pub fn for_scheduler_receipt_finality(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "scheduler_receipt_finality".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame178 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame178 {
    pub fn for_slashing_evidence_path(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "slashing_evidence_path".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame179 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeTelemetryFrame179 {
    pub fn for_proof_cache_hotset(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "proof_cache_hotset".to_string();
        let frame_id = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-WITNESS-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}
