use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2FastPqConfidentialProofPrefetchPipelineRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_FAST_PQ_CONFIDENTIAL_PROOF_PREFETCH_PIPELINE_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-fast-pq-confidential-proof-prefetch-pipeline-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_FAST_PQ_CONFIDENTIAL_PROOF_PREFETCH_PIPELINE_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_ATTESTATION_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-proof-prefetch-pipeline-v1";
pub const RECURSIVE_PREFETCH_SUITE: &str =
    "nova-pq-confidential-recursive-proof-prefetch-window-v1";
pub const WITNESS_RESERVATION_SUITE: &str =
    "ml-kem-sealed-confidential-witness-reservation-root-v1";
pub const VERIFIER_CACHE_LANE_SUITE: &str = "pq-confidential-verifier-cache-lane-prewarm-root-v1";
pub const METADATA_REDACTION_SUITE: &str =
    "monero-l2-viewtag-nullifier-metadata-redaction-policy-v1";
pub const STALE_PROOF_QUARANTINE_SUITE: &str =
    "confidential-proof-prefetch-stale-proof-quarantine-v1";
pub const FEE_PRIORITY_SUITE: &str = "fee-aware-private-proof-prefetch-priority-v1";
pub const DEFAULT_L2_NETWORK: &str = "nebula-devnet";
pub const DEFAULT_MONERO_NETWORK: &str = "monero-devnet";
pub const DEFAULT_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEVNET_L2_HEIGHT: u64 = 2_720_000;
pub const DEVNET_MONERO_HEIGHT: u64 = 3_560_000;
pub const DEVNET_EPOCH: u64 = 16_384;
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 262_144;
pub const DEFAULT_TARGET_PRIVACY_SET_SIZE: u64 = 1_048_576;
pub const DEFAULT_SLOT_WIDTH_MS: u64 = 40;
pub const DEFAULT_TARGET_PREFETCH_MS: u64 = 75;
pub const DEFAULT_MAX_PREFETCH_MS: u64 = 300;
pub const DEFAULT_WINDOW_TTL_SLOTS: u64 = 24;
pub const DEFAULT_RESERVATION_TTL_SLOTS: u64 = 32;
pub const DEFAULT_CACHE_LANE_TTL_SLOTS: u64 = 96;
pub const DEFAULT_QUARANTINE_TTL_SLOTS: u64 = 512;
pub const DEFAULT_PUBLIC_RECORD_TTL_SLOTS: u64 = 1_024;
pub const DEFAULT_CHALLENGE_WINDOW_SLOTS: u64 = 128;
pub const DEFAULT_QUORUM_WEIGHT_BPS: u64 = 6_700;
pub const DEFAULT_SUPERMAJORITY_WEIGHT_BPS: u64 = 8_000;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 14;
pub const DEFAULT_TARGET_REBATE_BPS: u64 = 7;
pub const DEFAULT_MAX_REBATE_BPS: u64 = 24;
pub const DEFAULT_MIN_RESERVATION_BOND_MICRO_UNITS: u64 = 1_500_000;
pub const DEFAULT_MIN_LANE_BOND_MICRO_UNITS: u64 = 25_000_000;
pub const DEFAULT_SLASH_BPS: u64 = 1_400;
pub const DEFAULT_MAX_WITNESS_RESERVATIONS: usize = 2_097_152;
pub const DEFAULT_MAX_PREFETCH_WINDOWS: usize = 1_048_576;
pub const DEFAULT_MAX_VERIFIER_CACHE_LANES: usize = 262_144;
pub const DEFAULT_MAX_PRIORITY_TICKETS: usize = 2_097_152;
pub const DEFAULT_MAX_METADATA_REDACTIONS: usize = 4_194_304;
pub const DEFAULT_MAX_STALE_QUARANTINES: usize = 1_048_576;
pub const DEFAULT_MAX_PUBLIC_RECORDS: usize = 4_194_304;
pub const DEFAULT_MAX_ROOT_HISTORY: usize = 262_144;

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
pub enum ProofKind {
    MoneroExit,
    ConfidentialTransfer,
    ContractExecution,
    RecursiveAggregation,
    DefiSettlement,
    OracleAttestation,
    BridgeSettlement,
    EmergencyEscape,
    LowFeeBulk,
}

impl ProofKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MoneroExit => "monero_exit",
            Self::ConfidentialTransfer => "confidential_transfer",
            Self::ContractExecution => "contract_execution",
            Self::RecursiveAggregation => "recursive_aggregation",
            Self::DefiSettlement => "defi_settlement",
            Self::OracleAttestation => "oracle_attestation",
            Self::BridgeSettlement => "bridge_settlement",
            Self::EmergencyEscape => "emergency_escape",
            Self::LowFeeBulk => "low_fee_bulk",
        }
    }

    pub fn base_priority(self) -> u64 {
        match self {
            Self::EmergencyEscape => 10_000,
            Self::BridgeSettlement => 9_700,
            Self::DefiSettlement => 9_500,
            Self::ContractExecution => 9_200,
            Self::MoneroExit => 9_000,
            Self::RecursiveAggregation => 8_800,
            Self::OracleAttestation => 8_100,
            Self::ConfidentialTransfer => 7_800,
            Self::LowFeeBulk => 5_600,
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

status_enum!(WitnessReservationStatus {
    Requested => "requested",
    Reserved => "reserved",
    Prefetching => "prefetching",
    Warmed => "warmed",
    Bound => "bound",
    Consumed => "consumed",
    Released => "released",
    Expired => "expired",
    Slashed => "slashed",
});
status_enum!(PrefetchWindowStatus {
    Open => "open",
    Filling => "filling",
    RecursiveReady => "recursive_ready",
    Sealed => "sealed",
    Published => "published",
    Expired => "expired",
    Quarantined => "quarantined",
});
status_enum!(VerifierCacheLaneStatus {
    Open => "open",
    Warming => "warming",
    Hot => "hot",
    Saturated => "saturated",
    Draining => "draining",
    Suspended => "suspended",
    Retired => "retired",
});
status_enum!(PriorityTicketStatus {
    Queued => "queued",
    Promoted => "promoted",
    Assigned => "assigned",
    Rebated => "rebated",
    Settled => "settled",
    Expired => "expired",
    Challenged => "challenged",
});
status_enum!(RedactionStatus {
    Draft => "draft",
    Applied => "applied",
    Audited => "audited",
    Frozen => "frozen",
    Revoked => "revoked",
});
status_enum!(QuarantineStatus {
    Filed => "filed",
    Isolated => "isolated",
    RecheckScheduled => "recheck_scheduled",
    Recovered => "recovered",
    Slashed => "slashed",
    Released => "released",
    Expired => "expired",
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
    pub hash_suite: String,
    pub pq_attestation_suite: String,
    pub recursive_prefetch_suite: String,
    pub witness_reservation_suite: String,
    pub verifier_cache_lane_suite: String,
    pub metadata_redaction_suite: String,
    pub stale_proof_quarantine_suite: String,
    pub fee_priority_suite: String,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub slot_width_ms: u64,
    pub target_prefetch_ms: u64,
    pub max_prefetch_ms: u64,
    pub window_ttl_slots: u64,
    pub reservation_ttl_slots: u64,
    pub cache_lane_ttl_slots: u64,
    pub quarantine_ttl_slots: u64,
    pub public_record_ttl_slots: u64,
    pub challenge_window_slots: u64,
    pub quorum_weight_bps: u64,
    pub supermajority_weight_bps: u64,
    pub max_user_fee_bps: u64,
    pub target_rebate_bps: u64,
    pub max_rebate_bps: u64,
    pub min_reservation_bond_micro_units: u64,
    pub min_lane_bond_micro_units: u64,
    pub slash_bps: u64,
    pub max_witness_reservations: usize,
    pub max_prefetch_windows: usize,
    pub max_verifier_cache_lanes: usize,
    pub max_priority_tickets: usize,
    pub max_metadata_redactions: usize,
    pub max_stale_quarantines: usize,
    pub max_public_records: usize,
    pub max_root_history: usize,
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
            hash_suite: HASH_SUITE.to_string(),
            pq_attestation_suite: PQ_ATTESTATION_SUITE.to_string(),
            recursive_prefetch_suite: RECURSIVE_PREFETCH_SUITE.to_string(),
            witness_reservation_suite: WITNESS_RESERVATION_SUITE.to_string(),
            verifier_cache_lane_suite: VERIFIER_CACHE_LANE_SUITE.to_string(),
            metadata_redaction_suite: METADATA_REDACTION_SUITE.to_string(),
            stale_proof_quarantine_suite: STALE_PROOF_QUARANTINE_SUITE.to_string(),
            fee_priority_suite: FEE_PRIORITY_SUITE.to_string(),
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            slot_width_ms: DEFAULT_SLOT_WIDTH_MS,
            target_prefetch_ms: DEFAULT_TARGET_PREFETCH_MS,
            max_prefetch_ms: DEFAULT_MAX_PREFETCH_MS,
            window_ttl_slots: DEFAULT_WINDOW_TTL_SLOTS,
            reservation_ttl_slots: DEFAULT_RESERVATION_TTL_SLOTS,
            cache_lane_ttl_slots: DEFAULT_CACHE_LANE_TTL_SLOTS,
            quarantine_ttl_slots: DEFAULT_QUARANTINE_TTL_SLOTS,
            public_record_ttl_slots: DEFAULT_PUBLIC_RECORD_TTL_SLOTS,
            challenge_window_slots: DEFAULT_CHALLENGE_WINDOW_SLOTS,
            quorum_weight_bps: DEFAULT_QUORUM_WEIGHT_BPS,
            supermajority_weight_bps: DEFAULT_SUPERMAJORITY_WEIGHT_BPS,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            target_rebate_bps: DEFAULT_TARGET_REBATE_BPS,
            max_rebate_bps: DEFAULT_MAX_REBATE_BPS,
            min_reservation_bond_micro_units: DEFAULT_MIN_RESERVATION_BOND_MICRO_UNITS,
            min_lane_bond_micro_units: DEFAULT_MIN_LANE_BOND_MICRO_UNITS,
            slash_bps: DEFAULT_SLASH_BPS,
            max_witness_reservations: DEFAULT_MAX_WITNESS_RESERVATIONS,
            max_prefetch_windows: DEFAULT_MAX_PREFETCH_WINDOWS,
            max_verifier_cache_lanes: DEFAULT_MAX_VERIFIER_CACHE_LANES,
            max_priority_tickets: DEFAULT_MAX_PRIORITY_TICKETS,
            max_metadata_redactions: DEFAULT_MAX_METADATA_REDACTIONS,
            max_stale_quarantines: DEFAULT_MAX_STALE_QUARANTINES,
            max_public_records: DEFAULT_MAX_PUBLIC_RECORDS,
            max_root_history: DEFAULT_MAX_ROOT_HISTORY,
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.protocol_version != PROTOCOL_VERSION {
            return Err(format!(
                "unsupported protocol version: {}",
                self.protocol_version
            ));
        }
        if self.schema_version != SCHEMA_VERSION {
            return Err(format!(
                "unsupported schema version: {}",
                self.schema_version
            ));
        }
        if self.min_pq_security_bits < 256 {
            return Err("pq security floor must be at least 256 bits".to_string());
        }
        if self.min_privacy_set_size < 65_536 {
            return Err("privacy set size below confidential L2 floor".to_string());
        }
        if self.target_privacy_set_size < self.min_privacy_set_size {
            return Err("target privacy set size below minimum".to_string());
        }
        if self.slot_width_ms == 0 || self.target_prefetch_ms == 0 {
            return Err("prefetch timing values must be non-zero".to_string());
        }
        if self.target_prefetch_ms > self.max_prefetch_ms {
            return Err("target prefetch latency exceeds maximum".to_string());
        }
        for value in [
            self.quorum_weight_bps,
            self.supermajority_weight_bps,
            self.max_user_fee_bps,
            self.target_rebate_bps,
            self.max_rebate_bps,
            self.slash_bps,
        ] {
            if value > MAX_BPS {
                return Err("basis point value exceeds MAX_BPS".to_string());
            }
        }
        if self.supermajority_weight_bps < self.quorum_weight_bps {
            return Err("supermajority weight below quorum".to_string());
        }
        if self.target_rebate_bps > self.max_rebate_bps {
            return Err("target rebate exceeds maximum rebate".to_string());
        }
        Ok(())
    }

    pub fn record(&self) -> Value {
        json!(self)
    }

    pub fn root(&self) -> String {
        merkle_root(
            "PRIVATE-L2-FAST-PQ-CONFIDENTIAL-PROOF-PREFETCH-CONFIG",
            &[self.record()],
        )
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub next_sequence: u64,
    pub witness_reservations: u64,
    pub prefetch_windows: u64,
    pub verifier_cache_lanes: u64,
    pub priority_tickets: u64,
    pub metadata_redactions: u64,
    pub stale_quarantines: u64,
    pub public_records: u64,
    pub root_publications: u64,
    pub reservations_consumed: u64,
    pub reservations_expired: u64,
    pub windows_sealed: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub fee_promotions: u64,
    pub redactions_applied: u64,
    pub proofs_quarantined: u64,
}

impl Counters {
    pub fn next_id(&mut self, prefix: &str) -> String {
        self.next_sequence += 1;
        format!("{prefix}-{:016}", self.next_sequence)
    }

    pub fn record(&self) -> Value {
        json!(self)
    }

    pub fn root(&self) -> String {
        merkle_root(
            "PRIVATE-L2-FAST-PQ-CONFIDENTIAL-PROOF-PREFETCH-COUNTERS",
            &[self.record()],
        )
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub counters_root: String,
    pub witness_reservation_root: String,
    pub prefetch_window_root: String,
    pub verifier_cache_lane_root: String,
    pub priority_ticket_root: String,
    pub metadata_redaction_root: String,
    pub stale_quarantine_root: String,
    pub public_record_root: String,
    pub deterministic_state_root: String,
}

impl Roots {
    pub fn record(&self) -> Value {
        json!(self)
    }

    pub fn root(&self) -> String {
        merkle_root(
            "PRIVATE-L2-FAST-PQ-CONFIDENTIAL-PROOF-PREFETCH-ROOTS",
            &[self.record()],
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WitnessReservation {
    pub reservation_id: String,
    pub proof_id: String,
    pub proof_kind: ProofKind,
    pub requester_commitment: String,
    pub witness_commitment_root: String,
    pub encrypted_witness_hint_root: String,
    pub nullifier_set_root: String,
    pub view_tag_root: String,
    pub lane_id: String,
    pub window_id: String,
    pub status: WitnessReservationStatus,
    pub reserved_units: u64,
    pub consumed_units: u64,
    pub fee_bid_micro_units: u64,
    pub rebate_bps: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub created_slot: u64,
    pub expires_slot: u64,
    pub sequence: u64,
}

impl WitnessReservation {
    pub fn live(&self) -> bool {
        matches!(
            self.status,
            WitnessReservationStatus::Requested
                | WitnessReservationStatus::Reserved
                | WitnessReservationStatus::Prefetching
                | WitnessReservationStatus::Warmed
                | WitnessReservationStatus::Bound
        )
    }

    pub fn remaining_units(&self) -> u64 {
        self.reserved_units.saturating_sub(self.consumed_units)
    }

    pub fn record(&self) -> Value {
        json!(self)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "reservation_id": self.reservation_id,
            "proof_id": self.proof_id,
            "proof_kind": self.proof_kind.as_str(),
            "lane_id": self.lane_id,
            "window_id": self.window_id,
            "status": self.status.as_str(),
            "reserved_units": self.reserved_units,
            "consumed_units": self.consumed_units,
            "fee_bid_micro_units": self.fee_bid_micro_units,
            "rebate_bps": self.rebate_bps,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "created_slot": self.created_slot,
            "expires_slot": self.expires_slot,
            "requester_commitment": redacted_commitment(&self.requester_commitment),
            "witness_commitment_root": self.witness_commitment_root,
            "encrypted_witness_hint_root": self.encrypted_witness_hint_root,
            "nullifier_set_root": self.nullifier_set_root,
            "view_tag_root": self.view_tag_root,
            "sequence": self.sequence,
        })
    }

    pub fn root(&self) -> String {
        merkle_root(
            "PRIVATE-L2-FAST-PQ-CONFIDENTIAL-PROOF-PREFETCH-WITNESS-RESERVATION",
            &[self.record()],
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RecursivePrefetchWindow {
    pub window_id: String,
    pub lane_id: String,
    pub parent_window_id: Option<String>,
    pub recursive_depth: u8,
    pub start_slot: u64,
    pub end_slot: u64,
    pub status: PrefetchWindowStatus,
    pub proof_kind: ProofKind,
    pub reservation_ids: BTreeSet<String>,
    pub aggregate_proof_root: String,
    pub recursive_receipt_root: String,
    pub witness_batch_root: String,
    pub privacy_fence_root: String,
    pub target_prefetch_ms: u64,
    pub measured_prefetch_ms: u64,
    pub fee_weight: u64,
    pub sequence: u64,
}

impl RecursivePrefetchWindow {
    pub fn accepts_reservation(&self, slot: u64) -> bool {
        matches!(
            self.status,
            PrefetchWindowStatus::Open | PrefetchWindowStatus::Filling
        ) && slot >= self.start_slot
            && slot <= self.end_slot
    }

    pub fn record(&self) -> Value {
        json!(self)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "window_id": self.window_id,
            "lane_id": self.lane_id,
            "parent_window_id": self.parent_window_id,
            "recursive_depth": self.recursive_depth,
            "start_slot": self.start_slot,
            "end_slot": self.end_slot,
            "status": self.status.as_str(),
            "proof_kind": self.proof_kind.as_str(),
            "reservation_count": self.reservation_ids.len(),
            "aggregate_proof_root": self.aggregate_proof_root,
            "recursive_receipt_root": self.recursive_receipt_root,
            "witness_batch_root": self.witness_batch_root,
            "privacy_fence_root": self.privacy_fence_root,
            "target_prefetch_ms": self.target_prefetch_ms,
            "measured_prefetch_ms": self.measured_prefetch_ms,
            "fee_weight": self.fee_weight,
            "sequence": self.sequence,
        })
    }

    pub fn root(&self) -> String {
        merkle_root(
            "PRIVATE-L2-FAST-PQ-CONFIDENTIAL-PROOF-PREFETCH-RECURSIVE-WINDOW",
            &[self.record()],
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct VerifierCacheLane {
    pub lane_id: String,
    pub operator_commitment: String,
    pub circuit_family: String,
    pub verifier_key_root: String,
    pub cache_commitment_root: String,
    pub hot_proof_root: String,
    pub status: VerifierCacheLaneStatus,
    pub capacity_units: u64,
    pub reserved_units: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub fee_floor_micro_units: u64,
    pub lane_bond_micro_units: u64,
    pub pq_security_bits: u16,
    pub privacy_set_size: u64,
    pub opened_slot: u64,
    pub expires_slot: u64,
    pub sequence: u64,
}

impl VerifierCacheLane {
    pub fn accepts_prefetch(&self) -> bool {
        matches!(
            self.status,
            VerifierCacheLaneStatus::Open
                | VerifierCacheLaneStatus::Warming
                | VerifierCacheLaneStatus::Hot
                | VerifierCacheLaneStatus::Saturated
        ) && self.available_units() > 0
    }

    pub fn available_units(&self) -> u64 {
        self.capacity_units.saturating_sub(self.reserved_units)
    }

    pub fn hit_rate_bps(&self) -> u64 {
        let total = self.cache_hits + self.cache_misses;
        if total == 0 {
            return 0;
        }
        self.cache_hits.saturating_mul(MAX_BPS) / total
    }

    pub fn record(&self) -> Value {
        json!(self)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "lane_id": self.lane_id,
            "operator_commitment": redacted_commitment(&self.operator_commitment),
            "circuit_family": self.circuit_family,
            "verifier_key_root": self.verifier_key_root,
            "cache_commitment_root": self.cache_commitment_root,
            "hot_proof_root": self.hot_proof_root,
            "status": self.status.as_str(),
            "capacity_units": self.capacity_units,
            "reserved_units": self.reserved_units,
            "available_units": self.available_units(),
            "cache_hits": self.cache_hits,
            "cache_misses": self.cache_misses,
            "hit_rate_bps": self.hit_rate_bps(),
            "fee_floor_micro_units": self.fee_floor_micro_units,
            "lane_bond_micro_units": self.lane_bond_micro_units,
            "pq_security_bits": self.pq_security_bits,
            "privacy_set_size": self.privacy_set_size,
            "opened_slot": self.opened_slot,
            "expires_slot": self.expires_slot,
            "sequence": self.sequence,
        })
    }

    pub fn root(&self) -> String {
        merkle_root(
            "PRIVATE-L2-FAST-PQ-CONFIDENTIAL-PROOF-PREFETCH-VERIFIER-CACHE-LANE",
            &[self.record()],
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FeePriorityTicket {
    pub ticket_id: String,
    pub reservation_id: String,
    pub proof_id: String,
    pub proof_kind: ProofKind,
    pub lane_id: String,
    pub status: PriorityTicketStatus,
    pub fee_bid_micro_units: u64,
    pub max_fee_bps: u64,
    pub rebate_bps: u64,
    pub urgency_weight: u64,
    pub privacy_weight: u64,
    pub deterministic_priority: u64,
    pub created_slot: u64,
    pub expires_slot: u64,
    pub sequence: u64,
}

impl FeePriorityTicket {
    pub fn score(&self) -> u64 {
        self.deterministic_priority
            .saturating_add(self.fee_bid_micro_units / 1_000)
            .saturating_add(self.urgency_weight)
            .saturating_add(self.privacy_weight)
            .saturating_sub(self.rebate_bps)
    }

    pub fn record(&self) -> Value {
        json!(self)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "ticket_id": self.ticket_id,
            "reservation_id": self.reservation_id,
            "proof_id": self.proof_id,
            "proof_kind": self.proof_kind.as_str(),
            "lane_id": self.lane_id,
            "status": self.status.as_str(),
            "fee_bid_micro_units": self.fee_bid_micro_units,
            "max_fee_bps": self.max_fee_bps,
            "rebate_bps": self.rebate_bps,
            "urgency_weight": self.urgency_weight,
            "privacy_weight": self.privacy_weight,
            "deterministic_priority": self.deterministic_priority,
            "score": self.score(),
            "created_slot": self.created_slot,
            "expires_slot": self.expires_slot,
            "sequence": self.sequence,
        })
    }

    pub fn root(&self) -> String {
        merkle_root(
            "PRIVATE-L2-FAST-PQ-CONFIDENTIAL-PROOF-PREFETCH-FEE-PRIORITY-TICKET",
            &[self.record()],
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MetadataRedaction {
    pub redaction_id: String,
    pub proof_id: String,
    pub policy_root: String,
    pub raw_metadata_root: String,
    pub redacted_metadata_root: String,
    pub nullifier_set_root: String,
    pub view_tag_cohort_root: String,
    pub status: RedactionStatus,
    pub fields_redacted: BTreeSet<String>,
    pub privacy_set_size: u64,
    pub auditor_commitment: String,
    pub applied_slot: u64,
    pub sequence: u64,
}

impl MetadataRedaction {
    pub fn record(&self) -> Value {
        json!(self)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "redaction_id": self.redaction_id,
            "proof_id": self.proof_id,
            "policy_root": self.policy_root,
            "redacted_metadata_root": self.redacted_metadata_root,
            "nullifier_set_root": self.nullifier_set_root,
            "view_tag_cohort_root": self.view_tag_cohort_root,
            "status": self.status.as_str(),
            "fields_redacted": self.fields_redacted,
            "privacy_set_size": self.privacy_set_size,
            "auditor_commitment": redacted_commitment(&self.auditor_commitment),
            "applied_slot": self.applied_slot,
            "sequence": self.sequence,
        })
    }

    pub fn root(&self) -> String {
        merkle_root(
            "PRIVATE-L2-FAST-PQ-CONFIDENTIAL-PROOF-PREFETCH-METADATA-REDACTION",
            &[self.record()],
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct StaleProofQuarantine {
    pub quarantine_id: String,
    pub proof_id: String,
    pub reservation_id: String,
    pub lane_id: String,
    pub stale_proof_root: String,
    pub expected_proof_root: String,
    pub evidence_root: String,
    pub status: QuarantineStatus,
    pub stale_slot: u64,
    pub detected_slot: u64,
    pub release_slot: u64,
    pub slashing_bps: u64,
    pub challenger_commitment: String,
    pub sequence: u64,
}

impl StaleProofQuarantine {
    pub fn record(&self) -> Value {
        json!(self)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "quarantine_id": self.quarantine_id,
            "proof_id": self.proof_id,
            "reservation_id": self.reservation_id,
            "lane_id": self.lane_id,
            "stale_proof_root": self.stale_proof_root,
            "expected_proof_root": self.expected_proof_root,
            "evidence_root": self.evidence_root,
            "status": self.status.as_str(),
            "stale_slot": self.stale_slot,
            "detected_slot": self.detected_slot,
            "release_slot": self.release_slot,
            "slashing_bps": self.slashing_bps,
            "challenger_commitment": redacted_commitment(&self.challenger_commitment),
            "sequence": self.sequence,
        })
    }

    pub fn root(&self) -> String {
        merkle_root(
            "PRIVATE-L2-FAST-PQ-CONFIDENTIAL-PROOF-PREFETCH-STALE-QUARANTINE",
            &[self.record()],
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublicRecord {
    pub record_id: String,
    pub category: String,
    pub subject_id: String,
    pub redacted_payload_root: String,
    pub public_payload: Value,
    pub created_slot: u64,
    pub expires_slot: u64,
    pub sequence: u64,
}

impl PublicRecord {
    pub fn record(&self) -> Value {
        json!(self)
    }

    pub fn root(&self) -> String {
        merkle_root(
            "PRIVATE-L2-FAST-PQ-CONFIDENTIAL-PROOF-PREFETCH-PUBLIC-RECORD",
            &[self.record()],
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub current_l2_height: u64,
    pub current_monero_height: u64,
    pub current_epoch: u64,
    pub current_slot: u64,
    pub witness_reservations: BTreeMap<String, WitnessReservation>,
    pub prefetch_windows: BTreeMap<String, RecursivePrefetchWindow>,
    pub verifier_cache_lanes: BTreeMap<String, VerifierCacheLane>,
    pub priority_tickets: BTreeMap<String, FeePriorityTicket>,
    pub metadata_redactions: BTreeMap<String, MetadataRedaction>,
    pub stale_quarantines: BTreeMap<String, StaleProofQuarantine>,
    pub public_records: BTreeMap<String, PublicRecord>,
    pub root_history: BTreeMap<u64, Roots>,
}

impl State {
    pub fn new(config: Config) -> Result<Self> {
        config.validate()?;
        let mut state = Self {
            config,
            counters: Counters::default(),
            roots: Roots::default(),
            current_l2_height: DEVNET_L2_HEIGHT,
            current_monero_height: DEVNET_MONERO_HEIGHT,
            current_epoch: DEVNET_EPOCH,
            current_slot: DEVNET_EPOCH.saturating_mul(32),
            witness_reservations: BTreeMap::new(),
            prefetch_windows: BTreeMap::new(),
            verifier_cache_lanes: BTreeMap::new(),
            priority_tickets: BTreeMap::new(),
            metadata_redactions: BTreeMap::new(),
            stale_quarantines: BTreeMap::new(),
            public_records: BTreeMap::new(),
            root_history: BTreeMap::new(),
        };
        state.recompute_roots();
        Ok(state)
    }

    pub fn devnet() -> Self {
        Self::new(Config::devnet()).expect("devnet config is valid")
    }

    pub fn advance_to_slot(&mut self, slot: u64) -> Result<()> {
        if slot < self.current_slot {
            return Err("cannot rewind proof prefetch runtime slot".to_string());
        }
        self.current_slot = slot;
        self.current_epoch = slot / 32;
        self.expire_stale_entries();
        self.recompute_roots();
        Ok(())
    }

    pub fn open_verifier_cache_lane(
        &mut self,
        operator_commitment: impl Into<String>,
        circuit_family: impl Into<String>,
        capacity_units: u64,
        fee_floor_micro_units: u64,
        lane_bond_micro_units: u64,
    ) -> Result<String> {
        if self.verifier_cache_lanes.len() >= self.config.max_verifier_cache_lanes {
            return Err("verifier cache lane capacity exhausted".to_string());
        }
        if capacity_units == 0 {
            return Err("verifier cache lane capacity must be non-zero".to_string());
        }
        if lane_bond_micro_units < self.config.min_lane_bond_micro_units {
            return Err("verifier cache lane bond below configured minimum".to_string());
        }

        let lane_id = self.counters.next_id("vcl");
        let sequence = self.counters.next_sequence;
        let circuit_family = circuit_family.into();
        let operator_commitment = operator_commitment.into();
        let verifier_key_root = deterministic_leaf(
            "VERIFIER-KEY",
            &[&lane_id, &operator_commitment, &circuit_family],
        );
        let cache_commitment_root = deterministic_leaf(
            "CACHE-COMMITMENT",
            &[
                &lane_id,
                &verifier_key_root,
                self.config.hash_suite.as_str(),
            ],
        );
        let hot_proof_root = merkle_root(
            "PRIVATE-L2-FAST-PQ-CONFIDENTIAL-PROOF-PREFETCH-HOT-PROOF-EMPTY",
            &[],
        );

        let lane = VerifierCacheLane {
            lane_id: lane_id.clone(),
            operator_commitment,
            circuit_family,
            verifier_key_root,
            cache_commitment_root,
            hot_proof_root,
            status: VerifierCacheLaneStatus::Open,
            capacity_units,
            reserved_units: 0,
            cache_hits: 0,
            cache_misses: 0,
            fee_floor_micro_units,
            lane_bond_micro_units,
            pq_security_bits: self.config.min_pq_security_bits,
            privacy_set_size: self.config.target_privacy_set_size,
            opened_slot: self.current_slot,
            expires_slot: self
                .current_slot
                .saturating_add(self.config.cache_lane_ttl_slots),
            sequence,
        };
        self.verifier_cache_lanes.insert(lane_id.clone(), lane);
        self.counters.verifier_cache_lanes += 1;
        self.emit_public_record("verifier_cache_lane", &lane_id)?;
        self.recompute_roots();
        Ok(lane_id)
    }

    pub fn open_prefetch_window(
        &mut self,
        lane_id: impl Into<String>,
        proof_kind: ProofKind,
        parent_window_id: Option<String>,
        recursive_depth: u8,
        fee_weight: u64,
    ) -> Result<String> {
        if self.prefetch_windows.len() >= self.config.max_prefetch_windows {
            return Err("prefetch window capacity exhausted".to_string());
        }
        let lane_id = lane_id.into();
        let lane = self
            .verifier_cache_lanes
            .get(&lane_id)
            .ok_or_else(|| format!("unknown verifier cache lane: {lane_id}"))?;
        if !lane.accepts_prefetch() {
            return Err("verifier cache lane does not accept prefetch work".to_string());
        }
        if let Some(parent) = parent_window_id.as_ref() {
            if !self.prefetch_windows.contains_key(parent) {
                return Err(format!("unknown parent prefetch window: {parent}"));
            }
        }

        let window_id = self.counters.next_id("rpw");
        let sequence = self.counters.next_sequence;
        let end_slot = self
            .current_slot
            .saturating_add(self.config.window_ttl_slots);
        let aggregate_proof_root =
            deterministic_leaf("AGGREGATE-PROOF", &[&window_id, proof_kind.as_str()]);
        let recursive_receipt_root = deterministic_leaf(
            "RECURSIVE-RECEIPT",
            &[&window_id, recursive_depth.to_string().as_str()],
        );
        let witness_batch_root = merkle_root(
            "PRIVATE-L2-FAST-PQ-CONFIDENTIAL-PROOF-PREFETCH-WITNESS-BATCH-EMPTY",
            &[],
        );
        let privacy_fence_root = deterministic_leaf(
            "PRIVACY-FENCE",
            &[&window_id, self.config.chain_id.as_str()],
        );

        let window = RecursivePrefetchWindow {
            window_id: window_id.clone(),
            lane_id,
            parent_window_id,
            recursive_depth,
            start_slot: self.current_slot,
            end_slot,
            status: PrefetchWindowStatus::Open,
            proof_kind,
            reservation_ids: BTreeSet::new(),
            aggregate_proof_root,
            recursive_receipt_root,
            witness_batch_root,
            privacy_fence_root,
            target_prefetch_ms: self.config.target_prefetch_ms,
            measured_prefetch_ms: 0,
            fee_weight,
            sequence,
        };
        self.prefetch_windows.insert(window_id.clone(), window);
        self.counters.prefetch_windows += 1;
        self.emit_public_record("prefetch_window", &window_id)?;
        self.recompute_roots();
        Ok(window_id)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn reserve_witness(
        &mut self,
        proof_id: impl Into<String>,
        proof_kind: ProofKind,
        requester_commitment: impl Into<String>,
        lane_id: impl Into<String>,
        window_id: impl Into<String>,
        reserved_units: u64,
        fee_bid_micro_units: u64,
    ) -> Result<String> {
        if self.witness_reservations.len() >= self.config.max_witness_reservations {
            return Err("witness reservation capacity exhausted".to_string());
        }
        if reserved_units == 0 {
            return Err("witness reservation units must be non-zero".to_string());
        }
        let proof_id = proof_id.into();
        let requester_commitment = requester_commitment.into();
        let lane_id = lane_id.into();
        let window_id = window_id.into();
        let lane = self
            .verifier_cache_lanes
            .get_mut(&lane_id)
            .ok_or_else(|| format!("unknown verifier cache lane: {lane_id}"))?;
        if !lane.accepts_prefetch() {
            return Err("verifier cache lane does not accept reservations".to_string());
        }
        if lane.available_units() < reserved_units {
            return Err("verifier cache lane does not have enough available units".to_string());
        }
        let window = self
            .prefetch_windows
            .get_mut(&window_id)
            .ok_or_else(|| format!("unknown prefetch window: {window_id}"))?;
        if !window.accepts_reservation(self.current_slot) {
            return Err("prefetch window does not accept reservations".to_string());
        }
        if window.proof_kind != proof_kind {
            return Err("proof kind does not match prefetch window".to_string());
        }

        let reservation_id = self.counters.next_id("wrs");
        let sequence = self.counters.next_sequence;
        let witness_commitment_root =
            deterministic_leaf("WITNESS-COMMITMENT", &[&reservation_id, &proof_id]);
        let encrypted_witness_hint_root = deterministic_leaf(
            "ENCRYPTED-WITNESS-HINT",
            &[&reservation_id, &requester_commitment],
        );
        let nullifier_set_root = deterministic_leaf(
            "NULLIFIER-SET",
            &[&proof_id, self.config.monero_network.as_str()],
        );
        let view_tag_root = deterministic_leaf("VIEW-TAG", &[&proof_id, &reservation_id]);
        let rebate_bps = self
            .config
            .target_rebate_bps
            .min(self.config.max_rebate_bps)
            .min(self.config.max_user_fee_bps);
        let reservation = WitnessReservation {
            reservation_id: reservation_id.clone(),
            proof_id: proof_id.clone(),
            proof_kind,
            requester_commitment,
            witness_commitment_root,
            encrypted_witness_hint_root,
            nullifier_set_root,
            view_tag_root,
            lane_id: lane_id.clone(),
            window_id: window_id.clone(),
            status: WitnessReservationStatus::Reserved,
            reserved_units,
            consumed_units: 0,
            fee_bid_micro_units,
            rebate_bps,
            privacy_set_size: self.config.target_privacy_set_size,
            pq_security_bits: self.config.min_pq_security_bits,
            created_slot: self.current_slot,
            expires_slot: self
                .current_slot
                .saturating_add(self.config.reservation_ttl_slots),
            sequence,
        };
        lane.reserved_units = lane.reserved_units.saturating_add(reserved_units);
        window.reservation_ids.insert(reservation_id.clone());
        window.status = PrefetchWindowStatus::Filling;
        self.witness_reservations
            .insert(reservation_id.clone(), reservation);
        self.counters.witness_reservations += 1;
        self.issue_priority_ticket(&reservation_id, fee_bid_micro_units)?;
        self.emit_public_record("witness_reservation", &reservation_id)?;
        self.recompute_roots();
        Ok(reservation_id)
    }

    pub fn issue_priority_ticket(
        &mut self,
        reservation_id: impl Into<String>,
        fee_bid_micro_units: u64,
    ) -> Result<String> {
        if self.priority_tickets.len() >= self.config.max_priority_tickets {
            return Err("priority ticket capacity exhausted".to_string());
        }
        let reservation_id = reservation_id.into();
        let reservation = self
            .witness_reservations
            .get(&reservation_id)
            .ok_or_else(|| format!("unknown witness reservation: {reservation_id}"))?;
        let ticket_id = self.counters.next_id("fpt");
        let sequence = self.counters.next_sequence;
        let deterministic_priority = deterministic_priority(
            reservation.proof_kind,
            fee_bid_micro_units,
            reservation.privacy_set_size,
            reservation.created_slot,
            sequence,
        );
        let ticket = FeePriorityTicket {
            ticket_id: ticket_id.clone(),
            reservation_id: reservation_id.clone(),
            proof_id: reservation.proof_id.clone(),
            proof_kind: reservation.proof_kind,
            lane_id: reservation.lane_id.clone(),
            status: PriorityTicketStatus::Queued,
            fee_bid_micro_units,
            max_fee_bps: self.config.max_user_fee_bps,
            rebate_bps: reservation.rebate_bps,
            urgency_weight: reservation.proof_kind.base_priority(),
            privacy_weight: reservation.privacy_set_size / 1_024,
            deterministic_priority,
            created_slot: self.current_slot,
            expires_slot: reservation.expires_slot,
            sequence,
        };
        self.priority_tickets.insert(ticket_id.clone(), ticket);
        self.counters.priority_tickets += 1;
        Ok(ticket_id)
    }

    pub fn promote_fee_aware_tickets(&mut self, limit: usize) -> Vec<String> {
        let mut candidates = self
            .priority_tickets
            .iter()
            .filter(|(_, ticket)| ticket.status == PriorityTicketStatus::Queued)
            .map(|(id, ticket)| (id.clone(), ticket.score(), ticket.sequence))
            .collect::<Vec<_>>();
        candidates.sort_by(|left, right| {
            right
                .1
                .cmp(&left.1)
                .then_with(|| left.2.cmp(&right.2))
                .then_with(|| left.0.cmp(&right.0))
        });
        let promoted = candidates
            .into_iter()
            .take(limit)
            .map(|(id, _, _)| id)
            .collect::<Vec<_>>();
        for ticket_id in &promoted {
            if let Some(ticket) = self.priority_tickets.get_mut(ticket_id) {
                ticket.status = PriorityTicketStatus::Promoted;
                self.counters.fee_promotions += 1;
            }
        }
        self.recompute_roots();
        promoted
    }

    pub fn consume_reservation(
        &mut self,
        reservation_id: impl Into<String>,
        units: u64,
    ) -> Result<()> {
        if units == 0 {
            return Err("consumed units must be non-zero".to_string());
        }
        let reservation_id = reservation_id.into();
        let reservation = self
            .witness_reservations
            .get_mut(&reservation_id)
            .ok_or_else(|| format!("unknown witness reservation: {reservation_id}"))?;
        if !reservation.live() {
            return Err("witness reservation is not live".to_string());
        }
        if units > reservation.remaining_units() {
            return Err("consume exceeds reserved witness units".to_string());
        }
        reservation.consumed_units = reservation.consumed_units.saturating_add(units);
        reservation.status = if reservation.remaining_units() == 0 {
            WitnessReservationStatus::Consumed
        } else {
            WitnessReservationStatus::Bound
        };
        if let Some(lane) = self.verifier_cache_lanes.get_mut(&reservation.lane_id) {
            lane.reserved_units = lane.reserved_units.saturating_sub(units);
            lane.cache_hits = lane.cache_hits.saturating_add(1);
        }
        self.counters.reservations_consumed += 1;
        self.counters.cache_hits += 1;
        self.emit_public_record("reservation_consumed", &reservation_id)?;
        self.recompute_roots();
        Ok(())
    }

    pub fn apply_metadata_redaction(
        &mut self,
        proof_id: impl Into<String>,
        raw_metadata_root: impl Into<String>,
        fields_redacted: BTreeSet<String>,
        auditor_commitment: impl Into<String>,
    ) -> Result<String> {
        if self.metadata_redactions.len() >= self.config.max_metadata_redactions {
            return Err("metadata redaction capacity exhausted".to_string());
        }
        if fields_redacted.is_empty() {
            return Err("metadata redaction must redact at least one field".to_string());
        }
        let proof_id = proof_id.into();
        let raw_metadata_root = raw_metadata_root.into();
        let auditor_commitment = auditor_commitment.into();
        let redaction_id = self.counters.next_id("mrd");
        let sequence = self.counters.next_sequence;
        let policy_root = deterministic_leaf(
            "METADATA-REDACTION-POLICY",
            &[&redaction_id, self.config.metadata_redaction_suite.as_str()],
        );
        let redacted_metadata_root =
            deterministic_leaf("REDACTED-METADATA", &[&raw_metadata_root, &policy_root]);
        let nullifier_set_root = deterministic_leaf("REDACTION-NULLIFIER-SET", &[&proof_id]);
        let view_tag_cohort_root = deterministic_leaf("REDACTION-VIEW-TAG", &[&proof_id]);
        let redaction = MetadataRedaction {
            redaction_id: redaction_id.clone(),
            proof_id: proof_id.clone(),
            policy_root,
            raw_metadata_root,
            redacted_metadata_root,
            nullifier_set_root,
            view_tag_cohort_root,
            status: RedactionStatus::Applied,
            fields_redacted,
            privacy_set_size: self.config.target_privacy_set_size,
            auditor_commitment,
            applied_slot: self.current_slot,
            sequence,
        };
        self.metadata_redactions
            .insert(redaction_id.clone(), redaction);
        self.counters.metadata_redactions += 1;
        self.counters.redactions_applied += 1;
        self.emit_public_record("metadata_redaction", &redaction_id)?;
        self.recompute_roots();
        Ok(redaction_id)
    }

    pub fn quarantine_stale_proof(
        &mut self,
        proof_id: impl Into<String>,
        reservation_id: impl Into<String>,
        stale_proof_root: impl Into<String>,
        expected_proof_root: impl Into<String>,
        challenger_commitment: impl Into<String>,
    ) -> Result<String> {
        if self.stale_quarantines.len() >= self.config.max_stale_quarantines {
            return Err("stale proof quarantine capacity exhausted".to_string());
        }
        let proof_id = proof_id.into();
        let reservation_id = reservation_id.into();
        let stale_proof_root = stale_proof_root.into();
        let expected_proof_root = expected_proof_root.into();
        let challenger_commitment = challenger_commitment.into();
        let reservation = self
            .witness_reservations
            .get(&reservation_id)
            .ok_or_else(|| format!("unknown witness reservation: {reservation_id}"))?;
        let quarantine_id = self.counters.next_id("spq");
        let sequence = self.counters.next_sequence;
        let evidence_root = deterministic_leaf(
            "STALE-PROOF-EVIDENCE",
            &[&quarantine_id, &stale_proof_root, &expected_proof_root],
        );
        let quarantine = StaleProofQuarantine {
            quarantine_id: quarantine_id.clone(),
            proof_id,
            reservation_id: reservation_id.clone(),
            lane_id: reservation.lane_id.clone(),
            stale_proof_root,
            expected_proof_root,
            evidence_root,
            status: QuarantineStatus::Isolated,
            stale_slot: reservation.expires_slot,
            detected_slot: self.current_slot,
            release_slot: self
                .current_slot
                .saturating_add(self.config.quarantine_ttl_slots),
            slashing_bps: self.config.slash_bps,
            challenger_commitment,
            sequence,
        };
        self.stale_quarantines
            .insert(quarantine_id.clone(), quarantine);
        if let Some(reservation) = self.witness_reservations.get_mut(&reservation_id) {
            reservation.status = WitnessReservationStatus::Slashed;
        }
        self.counters.stale_quarantines += 1;
        self.counters.proofs_quarantined += 1;
        self.emit_public_record("stale_proof_quarantine", &quarantine_id)?;
        self.recompute_roots();
        Ok(quarantine_id)
    }

    pub fn seal_window(
        &mut self,
        window_id: impl Into<String>,
        measured_prefetch_ms: u64,
    ) -> Result<()> {
        let window_id = window_id.into();
        let window = self
            .prefetch_windows
            .get_mut(&window_id)
            .ok_or_else(|| format!("unknown prefetch window: {window_id}"))?;
        if !matches!(
            window.status,
            PrefetchWindowStatus::Open
                | PrefetchWindowStatus::Filling
                | PrefetchWindowStatus::RecursiveReady
        ) {
            return Err("prefetch window cannot be sealed from current status".to_string());
        }
        let leaves = window
            .reservation_ids
            .iter()
            .filter_map(|id| self.witness_reservations.get(id))
            .map(WitnessReservation::public_record)
            .collect::<Vec<_>>();
        window.witness_batch_root = merkle_root(
            "PRIVATE-L2-FAST-PQ-CONFIDENTIAL-PROOF-PREFETCH-SEALED-WITNESS-BATCH",
            &leaves,
        );
        window.aggregate_proof_root = deterministic_leaf(
            "SEALED-AGGREGATE-PROOF",
            &[&window.window_id, &window.witness_batch_root],
        );
        window.recursive_receipt_root = deterministic_leaf(
            "SEALED-RECURSIVE-RECEIPT",
            &[&window.window_id, &window.aggregate_proof_root],
        );
        window.measured_prefetch_ms = measured_prefetch_ms;
        window.status = PrefetchWindowStatus::Sealed;
        self.counters.windows_sealed += 1;
        self.emit_public_record("prefetch_window_sealed", &window_id)?;
        self.recompute_roots();
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        let records = self
            .public_records
            .values()
            .map(PublicRecord::record)
            .collect::<Vec<_>>();
        json!({
            "protocol_version": self.config.protocol_version,
            "schema_version": self.config.schema_version,
            "chain_id": self.config.chain_id,
            "l2_network": self.config.l2_network,
            "monero_network": self.config.monero_network,
            "mode": self.config.mode.as_str(),
            "current_l2_height": self.current_l2_height,
            "current_monero_height": self.current_monero_height,
            "current_epoch": self.current_epoch,
            "current_slot": self.current_slot,
            "counters": self.counters,
            "roots": self.roots,
            "public_records": records,
        })
    }

    pub fn state_root(&self) -> String {
        merkle_root(
            "PRIVATE-L2-FAST-PQ-CONFIDENTIAL-PROOF-PREFETCH-STATE",
            &[
                self.config.record(),
                self.counters.record(),
                self.roots.record(),
                json!(self.current_l2_height),
                json!(self.current_monero_height),
                json!(self.current_epoch),
                json!(self.current_slot),
            ],
        )
    }

    pub fn recompute_roots(&mut self) {
        let witness_reservations = self
            .witness_reservations
            .values()
            .map(WitnessReservation::record)
            .collect::<Vec<_>>();
        let prefetch_windows = self
            .prefetch_windows
            .values()
            .map(RecursivePrefetchWindow::record)
            .collect::<Vec<_>>();
        let verifier_cache_lanes = self
            .verifier_cache_lanes
            .values()
            .map(VerifierCacheLane::record)
            .collect::<Vec<_>>();
        let priority_tickets = self
            .priority_tickets
            .values()
            .map(FeePriorityTicket::record)
            .collect::<Vec<_>>();
        let metadata_redactions = self
            .metadata_redactions
            .values()
            .map(MetadataRedaction::record)
            .collect::<Vec<_>>();
        let stale_quarantines = self
            .stale_quarantines
            .values()
            .map(StaleProofQuarantine::record)
            .collect::<Vec<_>>();
        let public_records = self
            .public_records
            .values()
            .map(PublicRecord::record)
            .collect::<Vec<_>>();
        let config_root = self.config.root();
        let counters_root = self.counters.root();
        let witness_reservation_root = merkle_root(
            "PRIVATE-L2-FAST-PQ-CONFIDENTIAL-PROOF-PREFETCH-WITNESS-RESERVATIONS",
            &witness_reservations,
        );
        let prefetch_window_root = merkle_root(
            "PRIVATE-L2-FAST-PQ-CONFIDENTIAL-PROOF-PREFETCH-WINDOWS",
            &prefetch_windows,
        );
        let verifier_cache_lane_root = merkle_root(
            "PRIVATE-L2-FAST-PQ-CONFIDENTIAL-PROOF-PREFETCH-VERIFIER-CACHE-LANES",
            &verifier_cache_lanes,
        );
        let priority_ticket_root = merkle_root(
            "PRIVATE-L2-FAST-PQ-CONFIDENTIAL-PROOF-PREFETCH-PRIORITY-TICKETS",
            &priority_tickets,
        );
        let metadata_redaction_root = merkle_root(
            "PRIVATE-L2-FAST-PQ-CONFIDENTIAL-PROOF-PREFETCH-METADATA-REDACTIONS",
            &metadata_redactions,
        );
        let stale_quarantine_root = merkle_root(
            "PRIVATE-L2-FAST-PQ-CONFIDENTIAL-PROOF-PREFETCH-STALE-QUARANTINES",
            &stale_quarantines,
        );
        let public_record_root = merkle_root(
            "PRIVATE-L2-FAST-PQ-CONFIDENTIAL-PROOF-PREFETCH-PUBLIC-RECORDS",
            &public_records,
        );
        let deterministic_state_root = merkle_root(
            "PRIVATE-L2-FAST-PQ-CONFIDENTIAL-PROOF-PREFETCH-DETERMINISTIC-ROOT",
            &[
                json!(config_root),
                json!(counters_root),
                json!(witness_reservation_root),
                json!(prefetch_window_root),
                json!(verifier_cache_lane_root),
                json!(priority_ticket_root),
                json!(metadata_redaction_root),
                json!(stale_quarantine_root),
                json!(public_record_root),
            ],
        );
        self.roots = Roots {
            config_root,
            counters_root,
            witness_reservation_root,
            prefetch_window_root,
            verifier_cache_lane_root,
            priority_ticket_root,
            metadata_redaction_root,
            stale_quarantine_root,
            public_record_root,
            deterministic_state_root,
        };
        self.root_history
            .insert(self.current_slot, self.roots.clone());
        while self.root_history.len() > self.config.max_root_history {
            if let Some(first) = self.root_history.keys().next().copied() {
                self.root_history.remove(&first);
            } else {
                break;
            }
        }
    }

    fn expire_stale_entries(&mut self) {
        for reservation in self.witness_reservations.values_mut() {
            if reservation.live() && reservation.expires_slot < self.current_slot {
                reservation.status = WitnessReservationStatus::Expired;
                self.counters.reservations_expired += 1;
            }
        }
        for window in self.prefetch_windows.values_mut() {
            if matches!(
                window.status,
                PrefetchWindowStatus::Open
                    | PrefetchWindowStatus::Filling
                    | PrefetchWindowStatus::RecursiveReady
            ) && window.end_slot < self.current_slot
            {
                window.status = PrefetchWindowStatus::Expired;
            }
        }
        for lane in self.verifier_cache_lanes.values_mut() {
            if matches!(
                lane.status,
                VerifierCacheLaneStatus::Open
                    | VerifierCacheLaneStatus::Warming
                    | VerifierCacheLaneStatus::Hot
                    | VerifierCacheLaneStatus::Saturated
                    | VerifierCacheLaneStatus::Draining
            ) && lane.expires_slot < self.current_slot
            {
                lane.status = VerifierCacheLaneStatus::Retired;
            }
        }
        for ticket in self.priority_tickets.values_mut() {
            if matches!(
                ticket.status,
                PriorityTicketStatus::Queued
                    | PriorityTicketStatus::Promoted
                    | PriorityTicketStatus::Assigned
            ) && ticket.expires_slot < self.current_slot
            {
                ticket.status = PriorityTicketStatus::Expired;
            }
        }
        for quarantine in self.stale_quarantines.values_mut() {
            if matches!(
                quarantine.status,
                QuarantineStatus::Filed
                    | QuarantineStatus::Isolated
                    | QuarantineStatus::RecheckScheduled
            ) && quarantine.release_slot < self.current_slot
            {
                quarantine.status = QuarantineStatus::Expired;
            }
        }
    }

    fn emit_public_record(&mut self, category: &str, subject_id: &str) -> Result<String> {
        if self.public_records.len() >= self.config.max_public_records {
            return Err("public record capacity exhausted".to_string());
        }
        let public_payload = self
            .public_payload_for(category, subject_id)
            .ok_or_else(|| format!("cannot build public payload for {category}:{subject_id}"))?;
        let redacted_payload_root = merkle_root(
            "PRIVATE-L2-FAST-PQ-CONFIDENTIAL-PROOF-PREFETCH-REDACTED-PUBLIC-PAYLOAD",
            &[public_payload.clone()],
        );
        let record_id = self.counters.next_id("prc");
        let sequence = self.counters.next_sequence;
        let record = PublicRecord {
            record_id: record_id.clone(),
            category: category.to_string(),
            subject_id: subject_id.to_string(),
            redacted_payload_root,
            public_payload,
            created_slot: self.current_slot,
            expires_slot: self
                .current_slot
                .saturating_add(self.config.public_record_ttl_slots),
            sequence,
        };
        self.public_records.insert(record_id.clone(), record);
        self.counters.public_records += 1;
        Ok(record_id)
    }

    fn public_payload_for(&self, category: &str, subject_id: &str) -> Option<Value> {
        match category {
            "witness_reservation" | "reservation_consumed" => self
                .witness_reservations
                .get(subject_id)
                .map(WitnessReservation::public_record),
            "prefetch_window" | "prefetch_window_sealed" => self
                .prefetch_windows
                .get(subject_id)
                .map(RecursivePrefetchWindow::public_record),
            "verifier_cache_lane" => self
                .verifier_cache_lanes
                .get(subject_id)
                .map(VerifierCacheLane::public_record),
            "metadata_redaction" => self
                .metadata_redactions
                .get(subject_id)
                .map(MetadataRedaction::public_record),
            "stale_proof_quarantine" => self
                .stale_quarantines
                .get(subject_id)
                .map(StaleProofQuarantine::public_record),
            _ => None,
        }
    }
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn demo() -> State {
    let mut state = State::devnet();
    let lane_a = state
        .open_verifier_cache_lane(
            "operator_commitment:devnet-alpha",
            "monero-exit-recursive",
            96,
            1_200,
            DEFAULT_MIN_LANE_BOND_MICRO_UNITS,
        )
        .expect("demo lane opens");
    let lane_b = state
        .open_verifier_cache_lane(
            "operator_commitment:devnet-beta",
            "confidential-contract-execution",
            128,
            1_500,
            DEFAULT_MIN_LANE_BOND_MICRO_UNITS.saturating_mul(2),
        )
        .expect("demo lane opens");
    let window_a = state
        .open_prefetch_window(lane_a.clone(), ProofKind::MoneroExit, None, 0, 9_000)
        .expect("demo window opens");
    let window_b = state
        .open_prefetch_window(
            lane_b.clone(),
            ProofKind::ContractExecution,
            Some(window_a.clone()),
            1,
            9_300,
        )
        .expect("demo window opens");
    let reservation_a = state
        .reserve_witness(
            "proof:monero-exit:0001",
            ProofKind::MoneroExit,
            "requester_commitment:wallet-alpha",
            lane_a,
            window_a.clone(),
            12,
            18_000,
        )
        .expect("demo reservation succeeds");
    let reservation_b = state
        .reserve_witness(
            "proof:contract-call:0002",
            ProofKind::ContractExecution,
            "requester_commitment:contract-caller-beta",
            lane_b,
            window_b.clone(),
            18,
            24_000,
        )
        .expect("demo reservation succeeds");
    state.promote_fee_aware_tickets(8);
    state
        .consume_reservation(reservation_a.clone(), 12)
        .expect("demo reservation consumes");
    let mut redacted_fields = BTreeSet::new();
    redacted_fields.insert("sender_view_tag".to_string());
    redacted_fields.insert("receiver_subaddress_hint".to_string());
    redacted_fields.insert("fee_change_output_hint".to_string());
    state
        .apply_metadata_redaction(
            "proof:contract-call:0002",
            "raw_metadata_root:contract-call-0002",
            redacted_fields,
            "auditor_commitment:privacy-committee-1",
        )
        .expect("demo redaction applies");
    state
        .quarantine_stale_proof(
            "proof:contract-call:0002",
            reservation_b,
            "stale_proof_root:contract-call-0002-old",
            "expected_proof_root:contract-call-0002-current",
            "challenger_commitment:watchtower-7",
        )
        .expect("demo quarantine applies");
    state
        .seal_window(window_a, DEFAULT_TARGET_PREFETCH_MS)
        .expect("demo window seals");
    state
        .seal_window(window_b, DEFAULT_TARGET_PREFETCH_MS.saturating_add(12))
        .expect("demo window seals");
    state.recompute_roots();
    state
}

pub fn public_record(state: &State) -> Value {
    state.public_record()
}

pub fn state_root(state: &State) -> String {
    state.roots.deterministic_state_root.clone()
}

fn deterministic_leaf(domain: &str, parts: &[&str]) -> String {
    let mut hash_parts = Vec::with_capacity(parts.len());
    for part in parts {
        hash_parts.push(HashPart::Str(part));
    }
    domain_hash(
        &format!("PRIVATE-L2-FAST-PQ-CONFIDENTIAL-PROOF-PREFETCH-{domain}"),
        &hash_parts,
        32,
    )
}

fn deterministic_priority(
    proof_kind: ProofKind,
    fee_bid_micro_units: u64,
    privacy_set_size: u64,
    slot: u64,
    sequence: u64,
) -> u64 {
    let digest = domain_hash(
        "PRIVATE-L2-FAST-PQ-CONFIDENTIAL-PROOF-PREFETCH-DETERMINISTIC-PRIORITY",
        &[
            HashPart::Str(proof_kind.as_str()),
            HashPart::U64(fee_bid_micro_units),
            HashPart::U64(privacy_set_size),
            HashPart::U64(slot),
            HashPart::U64(sequence),
        ],
        8,
    );
    u64::from_str_radix(&digest[..16], 16)
        .unwrap_or(0)
        .saturating_add(proof_kind.base_priority())
}

fn redacted_commitment(commitment: &str) -> String {
    if commitment.is_empty() {
        return "redacted:empty".to_string();
    }
    let digest = domain_hash(
        "PRIVATE-L2-FAST-PQ-CONFIDENTIAL-PROOF-PREFETCH-REDACTED-COMMITMENT",
        &[HashPart::Str(commitment)],
        16,
    );
    format!("redacted:{digest}")
}
