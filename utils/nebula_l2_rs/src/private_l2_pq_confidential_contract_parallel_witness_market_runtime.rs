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
    "nebula-private-l2-pq-confidential-contract-parallel-witness-market-runtime-v1";
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_KEM_SUITE: &str = "ML-KEM-1024-witness-bundle-sealed-box-v1";
pub const PQ_SIGNATURE_SUITE: &str = "ML-DSA-87+SLH-DSA-SHAKE-256f-parallel-witness-market-v1";
pub const WITNESS_ENCRYPTION_SCHEME: &str = "parallel-private-contract-witness-bundle-v1";
pub const ATTESTATION_SCHEME: &str = "pq-low-latency-witness-prover-attestation-v1";
pub const SLASHING_SCHEME: &str = "pq-witness-market-slashing-bond-v1";
pub const SPONSOR_RESERVATION_SCHEME: &str = "private-contract-call-sponsor-reservation-v1";
pub const BATCH_RECEIPT_SCHEME: &str = "parallel-witness-batch-receipt-v1";
pub const FEE_REBATE_SCHEME: &str = "low-fee-parallel-witness-rebate-v1";
pub const PRIVACY_FENCE_SCHEME: &str = "private-contract-nullifier-fence-v1";
pub const DEVNET_L2_NETWORK: &str = "nebula-devnet";
pub const DEVNET_CONTRACT_NETWORK: &str = "nebula-private-contract-devnet";
pub const DEVNET_HEIGHT: u64 = 1_744_000;
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_BATCH_PRIVACY_SET_SIZE: u64 = 524_288;
pub const DEFAULT_TARGET_LATENCY_MS: u64 = 420;
pub const DEFAULT_HARD_LATENCY_MS: u64 = 1_500;
pub const DEFAULT_ASSIGNMENT_TTL_BLOCKS: u64 = 12;
pub const DEFAULT_RESERVATION_TTL_BLOCKS: u64 = 48;
pub const DEFAULT_BUNDLE_TTL_BLOCKS: u64 = 96;
pub const DEFAULT_ATTESTATION_TTL_BLOCKS: u64 = 720;
pub const DEFAULT_BATCH_WINDOW_BLOCKS: u64 = 4;
pub const DEFAULT_REBATE_TTL_BLOCKS: u64 = 1_440;
pub const DEFAULT_MAX_CALL_FEE_BPS: u64 = 18;
pub const DEFAULT_TARGET_REBATE_BPS: u64 = 12;
pub const DEFAULT_SPONSOR_COVER_BPS: u64 = 8_500;
pub const DEFAULT_QUORUM_BPS: u64 = 6_700;
pub const DEFAULT_STRONG_QUORUM_BPS: u64 = 8_000;
pub const DEFAULT_MIN_WITNESS_BOND_MICRO_UNITS: u64 = 2_000_000;
pub const DEFAULT_MIN_PROVER_BOND_MICRO_UNITS: u64 = 5_000_000;
pub const MAX_PROVIDERS: usize = 1_048_576;
pub const MAX_CALLS: usize = 4_194_304;
pub const MAX_ASSIGNMENTS: usize = 8_388_608;
pub const MAX_BUNDLES: usize = 8_388_608;
pub const MAX_ATTESTATIONS: usize = 8_388_608;
pub const MAX_BONDS: usize = 2_097_152;
pub const MAX_RESERVATIONS: usize = 4_194_304;
pub const MAX_BATCH_RECEIPTS: usize = 2_097_152;
pub const MAX_REBATES: usize = 4_194_304;
pub const MAX_FENCES: usize = 8_388_608;
pub const MAX_EVENTS: usize = 8_388_608;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderKind {
    Witness,
    Prover,
    Hybrid,
    Aggregator,
    Watcher,
}

impl ProviderKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Witness => "witness",
            Self::Prover => "prover",
            Self::Hybrid => "hybrid",
            Self::Aggregator => "aggregator",
            Self::Watcher => "watcher",
        }
    }

    pub fn can_witness(self) -> bool {
        matches!(self, Self::Witness | Self::Hybrid)
    }

    pub fn can_prove(self) -> bool {
        matches!(self, Self::Prover | Self::Hybrid | Self::Aggregator)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ContractCallKind {
    PrivateStateRead,
    PrivateStateWrite,
    ConfidentialTransfer,
    ConfidentialSwap,
    CrossContractCall,
    BridgeExit,
    OracleUpdate,
    RecursiveProof,
    EmergencyCall,
}

impl ContractCallKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrivateStateRead => "private_state_read",
            Self::PrivateStateWrite => "private_state_write",
            Self::ConfidentialTransfer => "confidential_transfer",
            Self::ConfidentialSwap => "confidential_swap",
            Self::CrossContractCall => "cross_contract_call",
            Self::BridgeExit => "bridge_exit",
            Self::OracleUpdate => "oracle_update",
            Self::RecursiveProof => "recursive_proof",
            Self::EmergencyCall => "emergency_call",
        }
    }

    pub fn base_priority(self) -> u64 {
        match self {
            Self::EmergencyCall => 1_000,
            Self::BridgeExit => 920,
            Self::ConfidentialSwap => 860,
            Self::CrossContractCall => 820,
            Self::PrivateStateWrite => 780,
            Self::ConfidentialTransfer => 720,
            Self::RecursiveProof => 660,
            Self::OracleUpdate => 600,
            Self::PrivateStateRead => 540,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderStatus {
    Pending,
    Active,
    Hot,
    Throttled,
    Jailed,
    Exiting,
    Slashed,
}

impl ProviderStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Active => "active",
            Self::Hot => "hot",
            Self::Throttled => "throttled",
            Self::Jailed => "jailed",
            Self::Exiting => "exiting",
            Self::Slashed => "slashed",
        }
    }

    pub fn accepts_assignments(self) -> bool {
        matches!(self, Self::Active | Self::Hot | Self::Throttled)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CallStatus {
    Queued,
    Reserved,
    Assigned,
    Witnessed,
    Proving,
    Proved,
    Batched,
    Settled,
    Expired,
    Rejected,
    Slashed,
}

impl CallStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Reserved => "reserved",
            Self::Assigned => "assigned",
            Self::Witnessed => "witnessed",
            Self::Proving => "proving",
            Self::Proved => "proved",
            Self::Batched => "batched",
            Self::Settled => "settled",
            Self::Expired => "expired",
            Self::Rejected => "rejected",
            Self::Slashed => "slashed",
        }
    }

    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Queued
                | Self::Reserved
                | Self::Assigned
                | Self::Witnessed
                | Self::Proving
                | Self::Proved
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AssignmentStatus {
    Offered,
    Accepted,
    BundleCommitted,
    Attested,
    Proving,
    Complete,
    TimedOut,
    Disputed,
    Slashed,
}
impl AssignmentStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Offered => "offered",
            Self::Accepted => "accepted",
            Self::BundleCommitted => "bundle_committed",
            Self::Attested => "attested",
            Self::Proving => "proving",
            Self::Complete => "complete",
            Self::TimedOut => "timed_out",
            Self::Disputed => "disputed",
            Self::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BundleStatus {
    Sealed,
    Routed,
    OpenedByProver,
    ProofLinked,
    Expired,
    Quarantined,
}
impl BundleStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sealed => "sealed",
            Self::Routed => "routed",
            Self::OpenedByProver => "opened_by_prover",
            Self::ProofLinked => "proof_linked",
            Self::Expired => "expired",
            Self::Quarantined => "quarantined",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationStatus {
    Submitted,
    Accepted,
    WeakQuorum,
    StrongQuorum,
    Rejected,
    Superseded,
}
impl AttestationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Accepted => "accepted",
            Self::WeakQuorum => "weak_quorum",
            Self::StrongQuorum => "strong_quorum",
            Self::Rejected => "rejected",
            Self::Superseded => "superseded",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BondStatus {
    Locked,
    CoolingDown,
    Released,
    Jailed,
    Slashed,
}
impl BondStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Locked => "locked",
            Self::CoolingDown => "cooling_down",
            Self::Released => "released",
            Self::Jailed => "jailed",
            Self::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReservationStatus {
    Reserved,
    PartiallyConsumed,
    Consumed,
    RebateQueued,
    Refunded,
    Expired,
    Slashed,
}
impl ReservationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::PartiallyConsumed => "partially_consumed",
            Self::Consumed => "consumed",
            Self::RebateQueued => "rebate_queued",
            Self::Refunded => "refunded",
            Self::Expired => "expired",
            Self::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchStatus {
    Proposed,
    Filling,
    QuorumAttested,
    Settled,
    Disputed,
    Cancelled,
}
impl BatchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::Filling => "filling",
            Self::QuorumAttested => "quorum_attested",
            Self::Settled => "settled",
            Self::Disputed => "disputed",
            Self::Cancelled => "cancelled",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RebateStatus {
    Queued,
    Claimable,
    Claimed,
    Expired,
    Slashed,
}
impl RebateStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Claimable => "claimable",
            Self::Claimed => "claimed",
            Self::Expired => "expired",
            Self::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FenceStatus {
    Open,
    Spent,
    Tombstoned,
    Quarantined,
}
impl FenceStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Spent => "spent",
            Self::Tombstoned => "tombstoned",
            Self::Quarantined => "quarantined",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    ProviderRegistered,
    CallQueued,
    SponsorReserved,
    AssignmentAccepted,
    WitnessBundleSealed,
    PqAttestationAccepted,
    BatchReceiptPublished,
    FeeRebateQueued,
    BondSlashed,
    PrivacyFenceInserted,
    RuntimeRootPublished,
}
impl EventKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ProviderRegistered => "provider_registered",
            Self::CallQueued => "call_queued",
            Self::SponsorReserved => "sponsor_reserved",
            Self::AssignmentAccepted => "assignment_accepted",
            Self::WitnessBundleSealed => "witness_bundle_sealed",
            Self::PqAttestationAccepted => "pq_attestation_accepted",
            Self::BatchReceiptPublished => "batch_receipt_published",
            Self::FeeRebateQueued => "fee_rebate_queued",
            Self::BondSlashed => "bond_slashed",
            Self::PrivacyFenceInserted => "privacy_fence_inserted",
            Self::RuntimeRootPublished => "runtime_root_published",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub protocol_version: String,
    pub schema_version: u64,
    pub chain_id: String,
    pub l2_network: String,
    pub contract_network: String,
    pub hash_suite: String,
    pub pq_kem_suite: String,
    pub pq_signature_suite: String,
    pub witness_encryption_scheme: String,
    pub attestation_scheme: String,
    pub slashing_scheme: String,
    pub sponsor_reservation_scheme: String,
    pub batch_receipt_scheme: String,
    pub fee_rebate_scheme: String,
    pub privacy_fence_scheme: String,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub batch_privacy_set_size: u64,
    pub target_latency_ms: u64,
    pub hard_latency_ms: u64,
    pub assignment_ttl_blocks: u64,
    pub reservation_ttl_blocks: u64,
    pub bundle_ttl_blocks: u64,
    pub attestation_ttl_blocks: u64,
    pub batch_window_blocks: u64,
    pub rebate_ttl_blocks: u64,
    pub max_call_fee_bps: u64,
    pub target_rebate_bps: u64,
    pub sponsor_cover_bps: u64,
    pub quorum_bps: u64,
    pub strong_quorum_bps: u64,
    pub min_witness_bond_micro_units: u64,
    pub min_prover_bond_micro_units: u64,
    pub max_providers: usize,
    pub max_calls: usize,
    pub max_assignments: usize,
    pub max_bundles: usize,
    pub max_attestations: usize,
    pub max_bonds: usize,
    pub max_reservations: usize,
    pub max_batch_receipts: usize,
    pub max_rebates: usize,
    pub max_fences: usize,
    pub max_events: usize,
    pub devnet_height: u64,
}
impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            chain_id: CHAIN_ID.to_string(),
            l2_network: DEVNET_L2_NETWORK.to_string(),
            contract_network: DEVNET_CONTRACT_NETWORK.to_string(),
            hash_suite: HASH_SUITE.to_string(),
            pq_kem_suite: PQ_KEM_SUITE.to_string(),
            pq_signature_suite: PQ_SIGNATURE_SUITE.to_string(),
            witness_encryption_scheme: WITNESS_ENCRYPTION_SCHEME.to_string(),
            attestation_scheme: ATTESTATION_SCHEME.to_string(),
            slashing_scheme: SLASHING_SCHEME.to_string(),
            sponsor_reservation_scheme: SPONSOR_RESERVATION_SCHEME.to_string(),
            batch_receipt_scheme: BATCH_RECEIPT_SCHEME.to_string(),
            fee_rebate_scheme: FEE_REBATE_SCHEME.to_string(),
            privacy_fence_scheme: PRIVACY_FENCE_SCHEME.to_string(),
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            batch_privacy_set_size: DEFAULT_BATCH_PRIVACY_SET_SIZE,
            target_latency_ms: DEFAULT_TARGET_LATENCY_MS,
            hard_latency_ms: DEFAULT_HARD_LATENCY_MS,
            assignment_ttl_blocks: DEFAULT_ASSIGNMENT_TTL_BLOCKS,
            reservation_ttl_blocks: DEFAULT_RESERVATION_TTL_BLOCKS,
            bundle_ttl_blocks: DEFAULT_BUNDLE_TTL_BLOCKS,
            attestation_ttl_blocks: DEFAULT_ATTESTATION_TTL_BLOCKS,
            batch_window_blocks: DEFAULT_BATCH_WINDOW_BLOCKS,
            rebate_ttl_blocks: DEFAULT_REBATE_TTL_BLOCKS,
            max_call_fee_bps: DEFAULT_MAX_CALL_FEE_BPS,
            target_rebate_bps: DEFAULT_TARGET_REBATE_BPS,
            sponsor_cover_bps: DEFAULT_SPONSOR_COVER_BPS,
            quorum_bps: DEFAULT_QUORUM_BPS,
            strong_quorum_bps: DEFAULT_STRONG_QUORUM_BPS,
            min_witness_bond_micro_units: DEFAULT_MIN_WITNESS_BOND_MICRO_UNITS,
            min_prover_bond_micro_units: DEFAULT_MIN_PROVER_BOND_MICRO_UNITS,
            max_providers: MAX_PROVIDERS,
            max_calls: MAX_CALLS,
            max_assignments: MAX_ASSIGNMENTS,
            max_bundles: MAX_BUNDLES,
            max_attestations: MAX_ATTESTATIONS,
            max_bonds: MAX_BONDS,
            max_reservations: MAX_RESERVATIONS,
            max_batch_receipts: MAX_BATCH_RECEIPTS,
            max_rebates: MAX_REBATES,
            max_fences: MAX_FENCES,
            max_events: MAX_EVENTS,
            devnet_height: DEVNET_HEIGHT,
        }
    }
    pub fn validate(&self) -> Result<()> {
        require_eq(
            "config.protocol_version",
            &self.protocol_version,
            PROTOCOL_VERSION,
        )?;
        require_eq("config.chain_id", &self.chain_id, CHAIN_ID)?;
        require_bps("config.max_call_fee_bps", self.max_call_fee_bps)?;
        require_bps("config.target_rebate_bps", self.target_rebate_bps)?;
        require_bps("config.sponsor_cover_bps", self.sponsor_cover_bps)?;
        require_bps("config.quorum_bps", self.quorum_bps)?;
        require_bps("config.strong_quorum_bps", self.strong_quorum_bps)?;
        if self.quorum_bps > self.strong_quorum_bps {
            return Err("config.quorum_bps cannot exceed strong_quorum_bps".to_string());
        }
        if self.target_latency_ms == 0 || self.target_latency_ms > self.hard_latency_ms {
            return Err("config latency window is invalid".to_string());
        }
        if self.min_pq_security_bits < 192 {
            return Err("config.min_pq_security_bits must be at least 192".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub providers: u64,
    pub calls: u64,
    pub assignments: u64,
    pub bundles: u64,
    pub attestations: u64,
    pub bonds: u64,
    pub reservations: u64,
    pub batch_receipts: u64,
    pub rebates: u64,
    pub fences: u64,
    pub events: u64,
    pub slashes: u64,
    pub settled_calls: u64,
    pub rebated_micro_units: u64,
    pub sponsored_micro_units: u64,
}
impl Counters {
    pub fn public_record(&self) -> Value {
        json!({ "providers": self.providers, "calls": self.calls, "assignments": self.assignments, "bundles": self.bundles, "attestations": self.attestations, "bonds": self.bonds, "reservations": self.reservations, "batch_receipts": self.batch_receipts, "rebates": self.rebates, "fences": self.fences, "events": self.events, "slashes": self.slashes, "settled_calls": self.settled_calls, "rebated_micro_units": self.rebated_micro_units, "sponsored_micro_units": self.sponsored_micro_units })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub provider_root: String,
    pub call_root: String,
    pub assignment_root: String,
    pub bundle_root: String,
    pub attestation_root: String,
    pub bond_root: String,
    pub reservation_root: String,
    pub batch_receipt_root: String,
    pub rebate_root: String,
    pub fence_root: String,
    pub event_root: String,
    pub nullifier_root: String,
    pub sponsor_root: String,
    pub state_root: String,
}
impl Roots {
    pub fn public_record(&self) -> Value {
        json!({ "provider_root": self.provider_root, "call_root": self.call_root, "assignment_root": self.assignment_root, "bundle_root": self.bundle_root, "attestation_root": self.attestation_root, "bond_root": self.bond_root, "reservation_root": self.reservation_root, "batch_receipt_root": self.batch_receipt_root, "rebate_root": self.rebate_root, "fence_root": self.fence_root, "event_root": self.event_root, "nullifier_root": self.nullifier_root, "sponsor_root": self.sponsor_root, "state_root": self.state_root })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProviderRecord {
    pub provider_id: String,
    pub provider_kind: ProviderKind,
    pub status: ProviderStatus,
    pub operator_commitment: String,
    pub pq_identity_root: String,
    pub kem_public_key_root: String,
    pub signature_public_key_root: String,
    pub capability_root: String,
    pub region_commitment: String,
    pub max_parallel_calls: u64,
    pub target_latency_ms: u64,
    pub hard_latency_ms: u64,
    pub fee_bps: u64,
    pub bond_id: String,
    pub registered_at_height: u64,
    pub last_heartbeat_height: u64,
    pub expires_at_height: u64,
}
impl ProviderRecord {
    pub fn validate(&self, config: &Config) -> Result<()> {
        require_id("provider.provider_id", &self.provider_id)?;
        require_root("provider.pq_identity_root", &self.pq_identity_root)?;
        require_root("provider.kem_public_key_root", &self.kem_public_key_root)?;
        require_root(
            "provider.signature_public_key_root",
            &self.signature_public_key_root,
        )?;
        require_root("provider.capability_root", &self.capability_root)?;
        require_nonzero("provider.max_parallel_calls", self.max_parallel_calls)?;
        require_bps("provider.fee_bps", self.fee_bps)?;
        if self.fee_bps > config.max_call_fee_bps {
            return Err("provider fee exceeds config.max_call_fee_bps".to_string());
        }
        if self.target_latency_ms == 0
            || self.target_latency_ms > self.hard_latency_ms
            || self.hard_latency_ms > config.hard_latency_ms
        {
            return Err("provider latency bounds are invalid".to_string());
        }
        Ok(())
    }
    pub fn public_record(&self) -> Value {
        json!({ "chain_id": CHAIN_ID, "protocol_version": PROTOCOL_VERSION, "provider_id": self.provider_id, "provider_kind": self.provider_kind.as_str(), "status": self.status.as_str(), "operator_commitment": self.operator_commitment, "pq_identity_root": self.pq_identity_root, "kem_public_key_root": self.kem_public_key_root, "signature_public_key_root": self.signature_public_key_root, "capability_root": self.capability_root, "region_commitment": self.region_commitment, "max_parallel_calls": self.max_parallel_calls, "target_latency_ms": self.target_latency_ms, "hard_latency_ms": self.hard_latency_ms, "fee_bps": self.fee_bps, "bond_id": self.bond_id, "registered_at_height": self.registered_at_height, "last_heartbeat_height": self.last_heartbeat_height, "expires_at_height": self.expires_at_height })
    }
    pub fn record_root(&self) -> String {
        record_root("PQ-WITNESS-MARKET-PROVIDER", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ContractCallRequest {
    pub caller_commitment: String,
    pub contract_id: String,
    pub call_kind: ContractCallKind,
    pub encrypted_call_root: String,
    pub public_input_root: String,
    pub private_input_commitment_root: String,
    pub state_read_set_root: String,
    pub state_write_set_commitment_root: String,
    pub max_fee_micro_units: u64,
    pub max_witness_count: u64,
    pub max_prover_count: u64,
    pub latency_deadline_ms: u64,
    pub privacy_set_size: u64,
    pub sponsor_commitment: String,
    pub nullifier_hash: String,
    pub requested_at_height: u64,
    pub deadline_height: u64,
}
impl ContractCallRequest {
    pub fn validate(&self, config: &Config) -> Result<()> {
        require_id("call.contract_id", &self.contract_id)?;
        require_root("call.encrypted_call_root", &self.encrypted_call_root)?;
        require_root("call.public_input_root", &self.public_input_root)?;
        require_root(
            "call.private_input_commitment_root",
            &self.private_input_commitment_root,
        )?;
        require_root("call.state_read_set_root", &self.state_read_set_root)?;
        require_root(
            "call.state_write_set_commitment_root",
            &self.state_write_set_commitment_root,
        )?;
        require_nonzero("call.max_fee_micro_units", self.max_fee_micro_units)?;
        require_nonzero("call.max_witness_count", self.max_witness_count)?;
        require_nonzero("call.max_prover_count", self.max_prover_count)?;
        if self.latency_deadline_ms == 0 || self.latency_deadline_ms > config.hard_latency_ms {
            return Err("call.latency_deadline_ms exceeds hard latency".to_string());
        }
        if self.privacy_set_size < config.min_privacy_set_size {
            return Err("call privacy set is too small".to_string());
        }
        require_nullifier("call.nullifier_hash", &self.nullifier_hash)?;
        if self.deadline_height <= self.requested_at_height {
            return Err("call.deadline_height must be after requested_at_height".to_string());
        }
        Ok(())
    }
    pub fn call_id(&self) -> String {
        call_id(self)
    }
    pub fn public_record(&self) -> Value {
        json!({ "chain_id": CHAIN_ID, "protocol_version": PROTOCOL_VERSION, "caller_commitment": self.caller_commitment, "contract_id": self.contract_id, "call_kind": self.call_kind.as_str(), "encrypted_call_root": self.encrypted_call_root, "public_input_root": self.public_input_root, "private_input_commitment_root": self.private_input_commitment_root, "state_read_set_root": self.state_read_set_root, "state_write_set_commitment_root": self.state_write_set_commitment_root, "max_fee_micro_units": self.max_fee_micro_units, "max_witness_count": self.max_witness_count, "max_prover_count": self.max_prover_count, "latency_deadline_ms": self.latency_deadline_ms, "privacy_set_size": self.privacy_set_size, "sponsor_commitment": self.sponsor_commitment, "nullifier_hash": self.nullifier_hash, "requested_at_height": self.requested_at_height, "deadline_height": self.deadline_height })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ContractCallRecord {
    pub call_id: String,
    pub status: CallStatus,
    pub request: ContractCallRequest,
    pub priority_score: u64,
    pub reservation_id: String,
    pub assignment_root: String,
    pub bundle_root: String,
    pub attestation_root: String,
    pub batch_id: String,
    pub settled_at_height: u64,
}
impl ContractCallRecord {
    pub fn from_request(request: ContractCallRequest, config: &Config) -> Result<Self> {
        request.validate(config)?;
        let call_id = request.call_id();
        let priority_score = request.call_kind.base_priority()
            + (config
                .hard_latency_ms
                .saturating_sub(request.latency_deadline_ms));
        Ok(Self {
            call_id,
            status: CallStatus::Queued,
            request,
            priority_score,
            reservation_id: String::new(),
            assignment_root: empty_root("PQ-WITNESS-MARKET-CALL-ASSIGNMENTS"),
            bundle_root: empty_root("PQ-WITNESS-MARKET-CALL-BUNDLES"),
            attestation_root: empty_root("PQ-WITNESS-MARKET-CALL-ATTESTATIONS"),
            batch_id: String::new(),
            settled_at_height: 0,
        })
    }
    pub fn validate(&self, config: &Config) -> Result<()> {
        require_id("call.call_id", &self.call_id)?;
        self.request.validate(config)?;
        require_root("call.assignment_root", &self.assignment_root)?;
        require_root("call.bundle_root", &self.bundle_root)?;
        require_root("call.attestation_root", &self.attestation_root)?;
        Ok(())
    }
    pub fn public_record(&self) -> Value {
        json!({ "chain_id": CHAIN_ID, "protocol_version": PROTOCOL_VERSION, "call_id": self.call_id, "status": self.status.as_str(), "request": self.request.public_record(), "priority_score": self.priority_score, "reservation_id": self.reservation_id, "assignment_root": self.assignment_root, "bundle_root": self.bundle_root, "attestation_root": self.attestation_root, "batch_id": self.batch_id, "settled_at_height": self.settled_at_height })
    }
    pub fn record_root(&self) -> String {
        record_root("PQ-WITNESS-MARKET-CALL", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AssignmentRecord {
    pub assignment_id: String,
    pub call_id: String,
    pub provider_id: String,
    pub provider_kind: ProviderKind,
    pub status: AssignmentStatus,
    pub lane_index: u64,
    pub witness_share_index: u64,
    pub encrypted_route_root: String,
    pub expected_bundle_root: String,
    pub max_fee_micro_units: u64,
    pub accepted_at_height: u64,
    pub deadline_height: u64,
    pub latency_budget_ms: u64,
}
impl AssignmentRecord {
    pub fn validate(&self, config: &Config) -> Result<()> {
        require_id("assignment.assignment_id", &self.assignment_id)?;
        require_id("assignment.call_id", &self.call_id)?;
        require_id("assignment.provider_id", &self.provider_id)?;
        require_root(
            "assignment.encrypted_route_root",
            &self.encrypted_route_root,
        )?;
        require_root(
            "assignment.expected_bundle_root",
            &self.expected_bundle_root,
        )?;
        require_nonzero("assignment.max_fee_micro_units", self.max_fee_micro_units)?;
        if self.deadline_height <= self.accepted_at_height {
            return Err("assignment deadline must be after acceptance".to_string());
        }
        if self.latency_budget_ms == 0 || self.latency_budget_ms > config.hard_latency_ms {
            return Err("assignment latency budget is invalid".to_string());
        }
        Ok(())
    }
    pub fn public_record(&self) -> Value {
        json!({ "chain_id": CHAIN_ID, "protocol_version": PROTOCOL_VERSION, "assignment_id": self.assignment_id, "call_id": self.call_id, "provider_id": self.provider_id, "provider_kind": self.provider_kind.as_str(), "status": self.status.as_str(), "lane_index": self.lane_index, "witness_share_index": self.witness_share_index, "encrypted_route_root": self.encrypted_route_root, "expected_bundle_root": self.expected_bundle_root, "max_fee_micro_units": self.max_fee_micro_units, "accepted_at_height": self.accepted_at_height, "deadline_height": self.deadline_height, "latency_budget_ms": self.latency_budget_ms })
    }
    pub fn record_root(&self) -> String {
        record_root("PQ-WITNESS-MARKET-ASSIGNMENT", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WitnessBundleRecord {
    pub bundle_id: String,
    pub assignment_id: String,
    pub call_id: String,
    pub witness_provider_id: String,
    pub prover_provider_id: String,
    pub status: BundleStatus,
    pub encrypted_bundle_root: String,
    pub bundle_ciphertext_root: String,
    pub ephemeral_kem_root: String,
    pub witness_commitment_root: String,
    pub state_delta_commitment_root: String,
    pub privacy_fence_root: String,
    pub nullifier_root: String,
    pub opened_by_prover_at_height: u64,
    pub sealed_at_height: u64,
    pub expires_at_height: u64,
    pub byte_size: u64,
}
impl WitnessBundleRecord {
    pub fn validate(&self) -> Result<()> {
        require_id("bundle.bundle_id", &self.bundle_id)?;
        require_id("bundle.assignment_id", &self.assignment_id)?;
        require_id("bundle.call_id", &self.call_id)?;
        require_root("bundle.encrypted_bundle_root", &self.encrypted_bundle_root)?;
        require_root(
            "bundle.bundle_ciphertext_root",
            &self.bundle_ciphertext_root,
        )?;
        require_root("bundle.ephemeral_kem_root", &self.ephemeral_kem_root)?;
        require_root(
            "bundle.witness_commitment_root",
            &self.witness_commitment_root,
        )?;
        require_root(
            "bundle.state_delta_commitment_root",
            &self.state_delta_commitment_root,
        )?;
        require_root("bundle.privacy_fence_root", &self.privacy_fence_root)?;
        require_root("bundle.nullifier_root", &self.nullifier_root)?;
        require_nonzero("bundle.byte_size", self.byte_size)?;
        if self.expires_at_height <= self.sealed_at_height {
            return Err("bundle expires before it can be used".to_string());
        }
        Ok(())
    }
    pub fn public_record(&self) -> Value {
        json!({ "chain_id": CHAIN_ID, "protocol_version": PROTOCOL_VERSION, "bundle_id": self.bundle_id, "assignment_id": self.assignment_id, "call_id": self.call_id, "witness_provider_id": self.witness_provider_id, "prover_provider_id": self.prover_provider_id, "status": self.status.as_str(), "encrypted_bundle_root": self.encrypted_bundle_root, "bundle_ciphertext_root": self.bundle_ciphertext_root, "ephemeral_kem_root": self.ephemeral_kem_root, "witness_commitment_root": self.witness_commitment_root, "state_delta_commitment_root": self.state_delta_commitment_root, "privacy_fence_root": self.privacy_fence_root, "nullifier_root": self.nullifier_root, "opened_by_prover_at_height": self.opened_by_prover_at_height, "sealed_at_height": self.sealed_at_height, "expires_at_height": self.expires_at_height, "byte_size": self.byte_size })
    }
    pub fn record_root(&self) -> String {
        record_root("PQ-WITNESS-MARKET-BUNDLE", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqAttestationRecord {
    pub attestation_id: String,
    pub assignment_id: String,
    pub call_id: String,
    pub provider_id: String,
    pub status: AttestationStatus,
    pub attestation_root: String,
    pub transcript_root: String,
    pub latency_observation_ms: u64,
    pub pq_security_bits: u16,
    pub committee_weight_bps: u64,
    pub signed_at_height: u64,
    pub expires_at_height: u64,
}
impl PqAttestationRecord {
    pub fn validate(&self, config: &Config) -> Result<()> {
        require_id("attestation.attestation_id", &self.attestation_id)?;
        require_id("attestation.assignment_id", &self.assignment_id)?;
        require_id("attestation.call_id", &self.call_id)?;
        require_id("attestation.provider_id", &self.provider_id)?;
        require_root("attestation.attestation_root", &self.attestation_root)?;
        require_root("attestation.transcript_root", &self.transcript_root)?;
        if self.latency_observation_ms > config.hard_latency_ms {
            return Err("attestation latency exceeds hard latency".to_string());
        }
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err("attestation pq security is too weak".to_string());
        }
        require_bps(
            "attestation.committee_weight_bps",
            self.committee_weight_bps,
        )?;
        if self.expires_at_height <= self.signed_at_height {
            return Err("attestation expires before signed height".to_string());
        }
        Ok(())
    }
    pub fn public_record(&self) -> Value {
        json!({ "chain_id": CHAIN_ID, "protocol_version": PROTOCOL_VERSION, "attestation_id": self.attestation_id, "assignment_id": self.assignment_id, "call_id": self.call_id, "provider_id": self.provider_id, "status": self.status.as_str(), "attestation_root": self.attestation_root, "transcript_root": self.transcript_root, "latency_observation_ms": self.latency_observation_ms, "pq_security_bits": self.pq_security_bits, "committee_weight_bps": self.committee_weight_bps, "signed_at_height": self.signed_at_height, "expires_at_height": self.expires_at_height })
    }
    pub fn record_root(&self) -> String {
        record_root("PQ-WITNESS-MARKET-ATTESTATION", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SlashingBondRecord {
    pub bond_id: String,
    pub provider_id: String,
    pub provider_kind: ProviderKind,
    pub status: BondStatus,
    pub asset_id: String,
    pub locked_micro_units: u64,
    pub slashable_micro_units: u64,
    pub evidence_root: String,
    pub opened_at_height: u64,
    pub unlock_height: u64,
    pub slashed_at_height: u64,
}
impl SlashingBondRecord {
    pub fn validate(&self, config: &Config) -> Result<()> {
        require_id("bond.bond_id", &self.bond_id)?;
        require_id("bond.provider_id", &self.provider_id)?;
        require_nonzero("bond.locked_micro_units", self.locked_micro_units)?;
        if self.slashable_micro_units > self.locked_micro_units {
            return Err("bond slashable amount exceeds locked amount".to_string());
        }
        let min_bond = if self.provider_kind.can_prove() {
            config.min_prover_bond_micro_units
        } else {
            config.min_witness_bond_micro_units
        };
        if self.locked_micro_units < min_bond {
            return Err("bond locked amount is below role minimum".to_string());
        }
        require_root("bond.evidence_root", &self.evidence_root)?;
        Ok(())
    }
    pub fn public_record(&self) -> Value {
        json!({ "chain_id": CHAIN_ID, "protocol_version": PROTOCOL_VERSION, "bond_id": self.bond_id, "provider_id": self.provider_id, "provider_kind": self.provider_kind.as_str(), "status": self.status.as_str(), "asset_id": self.asset_id, "locked_micro_units": self.locked_micro_units, "slashable_micro_units": self.slashable_micro_units, "evidence_root": self.evidence_root, "opened_at_height": self.opened_at_height, "unlock_height": self.unlock_height, "slashed_at_height": self.slashed_at_height })
    }
    pub fn record_root(&self) -> String {
        record_root("PQ-WITNESS-MARKET-BOND", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SponsorReservationRecord {
    pub reservation_id: String,
    pub call_id: String,
    pub sponsor_commitment: String,
    pub status: ReservationStatus,
    pub fee_asset_id: String,
    pub reserved_micro_units: u64,
    pub consumed_micro_units: u64,
    pub cover_bps: u64,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
}
impl SponsorReservationRecord {
    pub fn validate(&self, config: &Config) -> Result<()> {
        require_id("reservation.reservation_id", &self.reservation_id)?;
        require_id("reservation.call_id", &self.call_id)?;
        require_nonzero(
            "reservation.reserved_micro_units",
            self.reserved_micro_units,
        )?;
        if self.consumed_micro_units > self.reserved_micro_units {
            return Err("reservation consumed amount exceeds reserved amount".to_string());
        }
        require_bps("reservation.cover_bps", self.cover_bps)?;
        if self.cover_bps > config.sponsor_cover_bps {
            return Err("reservation cover exceeds sponsor cover limit".to_string());
        }
        if self.expires_at_height <= self.opened_at_height {
            return Err("reservation expiry is invalid".to_string());
        }
        Ok(())
    }
    pub fn public_record(&self) -> Value {
        json!({ "chain_id": CHAIN_ID, "protocol_version": PROTOCOL_VERSION, "reservation_id": self.reservation_id, "call_id": self.call_id, "sponsor_commitment": self.sponsor_commitment, "status": self.status.as_str(), "fee_asset_id": self.fee_asset_id, "reserved_micro_units": self.reserved_micro_units, "consumed_micro_units": self.consumed_micro_units, "cover_bps": self.cover_bps, "opened_at_height": self.opened_at_height, "expires_at_height": self.expires_at_height })
    }
    pub fn record_root(&self) -> String {
        record_root("PQ-WITNESS-MARKET-RESERVATION", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BatchReceiptRecord {
    pub batch_id: String,
    pub status: BatchStatus,
    pub call_root: String,
    pub assignment_root: String,
    pub bundle_root: String,
    pub attestation_root: String,
    pub proof_receipt_root: String,
    pub fee_root: String,
    pub privacy_fence_root: String,
    pub call_count: u64,
    pub privacy_set_size: u64,
    pub aggregate_latency_ms: u64,
    pub proposed_at_height: u64,
    pub settled_at_height: u64,
}
impl BatchReceiptRecord {
    pub fn validate(&self, config: &Config) -> Result<()> {
        require_id("batch.batch_id", &self.batch_id)?;
        require_root("batch.call_root", &self.call_root)?;
        require_root("batch.assignment_root", &self.assignment_root)?;
        require_root("batch.bundle_root", &self.bundle_root)?;
        require_root("batch.attestation_root", &self.attestation_root)?;
        require_root("batch.proof_receipt_root", &self.proof_receipt_root)?;
        require_root("batch.fee_root", &self.fee_root)?;
        require_root("batch.privacy_fence_root", &self.privacy_fence_root)?;
        require_nonzero("batch.call_count", self.call_count)?;
        if self.privacy_set_size < config.batch_privacy_set_size {
            return Err("batch privacy set is too small".to_string());
        }
        Ok(())
    }
    pub fn public_record(&self) -> Value {
        json!({ "chain_id": CHAIN_ID, "protocol_version": PROTOCOL_VERSION, "batch_id": self.batch_id, "status": self.status.as_str(), "call_root": self.call_root, "assignment_root": self.assignment_root, "bundle_root": self.bundle_root, "attestation_root": self.attestation_root, "proof_receipt_root": self.proof_receipt_root, "fee_root": self.fee_root, "privacy_fence_root": self.privacy_fence_root, "call_count": self.call_count, "privacy_set_size": self.privacy_set_size, "aggregate_latency_ms": self.aggregate_latency_ms, "proposed_at_height": self.proposed_at_height, "settled_at_height": self.settled_at_height })
    }
    pub fn record_root(&self) -> String {
        record_root("PQ-WITNESS-MARKET-BATCH", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FeeRebateRecord {
    pub rebate_id: String,
    pub call_id: String,
    pub reservation_id: String,
    pub sponsor_commitment: String,
    pub status: RebateStatus,
    pub fee_asset_id: String,
    pub eligible_micro_units: u64,
    pub rebate_micro_units: u64,
    pub reason_root: String,
    pub queued_at_height: u64,
    pub claimable_at_height: u64,
    pub expires_at_height: u64,
}
impl FeeRebateRecord {
    pub fn validate(&self) -> Result<()> {
        require_id("rebate.rebate_id", &self.rebate_id)?;
        require_id("rebate.call_id", &self.call_id)?;
        require_nonzero("rebate.eligible_micro_units", self.eligible_micro_units)?;
        if self.rebate_micro_units > self.eligible_micro_units {
            return Err("rebate exceeds eligible fee".to_string());
        }
        require_root("rebate.reason_root", &self.reason_root)?;
        if self.expires_at_height <= self.queued_at_height
            || self.claimable_at_height < self.queued_at_height
        {
            return Err("rebate timing is invalid".to_string());
        }
        Ok(())
    }
    pub fn public_record(&self) -> Value {
        json!({ "chain_id": CHAIN_ID, "protocol_version": PROTOCOL_VERSION, "rebate_id": self.rebate_id, "call_id": self.call_id, "reservation_id": self.reservation_id, "sponsor_commitment": self.sponsor_commitment, "status": self.status.as_str(), "fee_asset_id": self.fee_asset_id, "eligible_micro_units": self.eligible_micro_units, "rebate_micro_units": self.rebate_micro_units, "reason_root": self.reason_root, "queued_at_height": self.queued_at_height, "claimable_at_height": self.claimable_at_height, "expires_at_height": self.expires_at_height })
    }
    pub fn record_root(&self) -> String {
        record_root("PQ-WITNESS-MARKET-REBATE", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivacyFenceRecord {
    pub fence_id: String,
    pub call_id: String,
    pub status: FenceStatus,
    pub nullifier_hash: String,
    pub nullifier_set_root: String,
    pub scope_root: String,
    pub inserted_at_height: u64,
    pub expires_at_height: u64,
}
impl PrivacyFenceRecord {
    pub fn validate(&self) -> Result<()> {
        require_id("fence.fence_id", &self.fence_id)?;
        require_id("fence.call_id", &self.call_id)?;
        require_nullifier("fence.nullifier_hash", &self.nullifier_hash)?;
        require_root("fence.nullifier_set_root", &self.nullifier_set_root)?;
        require_root("fence.scope_root", &self.scope_root)?;
        if self.expires_at_height <= self.inserted_at_height {
            return Err("fence expires before insertion".to_string());
        }
        Ok(())
    }
    pub fn public_record(&self) -> Value {
        json!({ "chain_id": CHAIN_ID, "protocol_version": PROTOCOL_VERSION, "fence_id": self.fence_id, "call_id": self.call_id, "status": self.status.as_str(), "nullifier_hash": self.nullifier_hash, "nullifier_set_root": self.nullifier_set_root, "scope_root": self.scope_root, "inserted_at_height": self.inserted_at_height, "expires_at_height": self.expires_at_height })
    }
    pub fn record_root(&self) -> String {
        record_root("PQ-WITNESS-MARKET-FENCE", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EventRecord {
    pub event_id: String,
    pub kind: EventKind,
    pub subject_id: String,
    pub subject_root: String,
    pub payload_root: String,
    pub emitted_at_height: u64,
    pub sequence: u64,
}
impl EventRecord {
    pub fn validate(&self) -> Result<()> {
        require_id("event.event_id", &self.event_id)?;
        require_id("event.subject_id", &self.subject_id)?;
        require_root("event.subject_root", &self.subject_root)?;
        require_root("event.payload_root", &self.payload_root)?;
        Ok(())
    }
    pub fn public_record(&self) -> Value {
        json!({ "chain_id": CHAIN_ID, "protocol_version": PROTOCOL_VERSION, "event_id": self.event_id, "kind": self.kind.as_str(), "subject_id": self.subject_id, "subject_root": self.subject_root, "payload_root": self.payload_root, "emitted_at_height": self.emitted_at_height, "sequence": self.sequence })
    }
    pub fn record_root(&self) -> String {
        record_root("PQ-WITNESS-MARKET-EVENT", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub providers: BTreeMap<String, ProviderRecord>,
    pub calls: BTreeMap<String, ContractCallRecord>,
    pub assignments: BTreeMap<String, AssignmentRecord>,
    pub bundles: BTreeMap<String, WitnessBundleRecord>,
    pub attestations: BTreeMap<String, PqAttestationRecord>,
    pub bonds: BTreeMap<String, SlashingBondRecord>,
    pub reservations: BTreeMap<String, SponsorReservationRecord>,
    pub batch_receipts: BTreeMap<String, BatchReceiptRecord>,
    pub rebates: BTreeMap<String, FeeRebateRecord>,
    pub fences: BTreeMap<String, PrivacyFenceRecord>,
    pub events: Vec<EventRecord>,
    pub spent_nullifiers: BTreeSet<String>,
}
impl State {
    pub fn devnet() -> Self {
        let config = Config::devnet();
        let mut state = Self::empty(config);
        let witness_bond_id = bond_id(
            "devnet-witness-alpha",
            ProviderKind::Witness,
            9_000_000,
            DEVNET_HEIGHT,
        );
        let prover_bond_id = bond_id(
            "devnet-prover-alpha",
            ProviderKind::Prover,
            16_000_000,
            DEVNET_HEIGHT,
        );
        let witness = ProviderRecord {
            provider_id: provider_id("devnet-witness-alpha", ProviderKind::Witness, DEVNET_HEIGHT),
            provider_kind: ProviderKind::Witness,
            status: ProviderStatus::Hot,
            operator_commitment: string_commitment("PQ-WITNESS-OPERATOR", "devnet-witness-alpha"),
            pq_identity_root: string_commitment("PQ-WITNESS-IDENTITY", "devnet-witness-alpha"),
            kem_public_key_root: string_commitment("PQ-WITNESS-KEM", "devnet-witness-alpha"),
            signature_public_key_root: string_commitment("PQ-WITNESS-SIG", "devnet-witness-alpha"),
            capability_root: string_commitment(
                "PQ-WITNESS-CAPABILITY",
                "fast-private-contract-witness",
            ),
            region_commitment: string_commitment("PQ-WITNESS-REGION", "us-east-low-latency"),
            max_parallel_calls: 384,
            target_latency_ms: 260,
            hard_latency_ms: 900,
            fee_bps: 6,
            bond_id: witness_bond_id.clone(),
            registered_at_height: DEVNET_HEIGHT - 360,
            last_heartbeat_height: DEVNET_HEIGHT,
            expires_at_height: DEVNET_HEIGHT + 86_400,
        };
        let prover = ProviderRecord {
            provider_id: provider_id("devnet-prover-alpha", ProviderKind::Prover, DEVNET_HEIGHT),
            provider_kind: ProviderKind::Prover,
            status: ProviderStatus::Hot,
            operator_commitment: string_commitment("PQ-WITNESS-OPERATOR", "devnet-prover-alpha"),
            pq_identity_root: string_commitment("PQ-WITNESS-IDENTITY", "devnet-prover-alpha"),
            kem_public_key_root: string_commitment("PQ-WITNESS-KEM", "devnet-prover-alpha"),
            signature_public_key_root: string_commitment("PQ-WITNESS-SIG", "devnet-prover-alpha"),
            capability_root: string_commitment(
                "PQ-WITNESS-CAPABILITY",
                "recursive-private-contract-prover",
            ),
            region_commitment: string_commitment("PQ-WITNESS-REGION", "us-east-low-latency"),
            max_parallel_calls: 128,
            target_latency_ms: 480,
            hard_latency_ms: 1_200,
            fee_bps: 9,
            bond_id: prover_bond_id.clone(),
            registered_at_height: DEVNET_HEIGHT - 320,
            last_heartbeat_height: DEVNET_HEIGHT,
            expires_at_height: DEVNET_HEIGHT + 86_400,
        };
        let witness_bond = SlashingBondRecord {
            bond_id: witness_bond_id,
            provider_id: witness.provider_id.clone(),
            provider_kind: ProviderKind::Witness,
            status: BondStatus::Locked,
            asset_id: "NEBULA".to_string(),
            locked_micro_units: 9_000_000,
            slashable_micro_units: 7_500_000,
            evidence_root: empty_root("PQ-WITNESS-MARKET-BOND-EVIDENCE"),
            opened_at_height: DEVNET_HEIGHT - 360,
            unlock_height: DEVNET_HEIGHT + 172_800,
            slashed_at_height: 0,
        };
        let prover_bond = SlashingBondRecord {
            bond_id: prover_bond_id,
            provider_id: prover.provider_id.clone(),
            provider_kind: ProviderKind::Prover,
            status: BondStatus::Locked,
            asset_id: "NEBULA".to_string(),
            locked_micro_units: 16_000_000,
            slashable_micro_units: 14_000_000,
            evidence_root: empty_root("PQ-WITNESS-MARKET-BOND-EVIDENCE"),
            opened_at_height: DEVNET_HEIGHT - 320,
            unlock_height: DEVNET_HEIGHT + 172_800,
            slashed_at_height: 0,
        };
        let request = ContractCallRequest {
            caller_commitment: string_commitment("PQ-WITNESS-CALLER", "devnet-caller-alpha"),
            contract_id: string_commitment("PQ-WITNESS-CONTRACT", "private-limit-order-vault"),
            call_kind: ContractCallKind::CrossContractCall,
            encrypted_call_root: string_commitment(
                "PQ-WITNESS-ENCRYPTED-CALL",
                "devnet-call-alpha",
            ),
            public_input_root: string_commitment("PQ-WITNESS-PUBLIC-INPUT", "devnet-call-alpha"),
            private_input_commitment_root: string_commitment(
                "PQ-WITNESS-PRIVATE-INPUT",
                "devnet-call-alpha",
            ),
            state_read_set_root: string_commitment("PQ-WITNESS-READ-SET", "devnet-call-alpha"),
            state_write_set_commitment_root: string_commitment(
                "PQ-WITNESS-WRITE-SET",
                "devnet-call-alpha",
            ),
            max_fee_micro_units: 84_000,
            max_witness_count: 3,
            max_prover_count: 2,
            latency_deadline_ms: 700,
            privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE * 2,
            sponsor_commitment: string_commitment("PQ-WITNESS-SPONSOR", "devnet-sponsor-alpha"),
            nullifier_hash: string_commitment("PQ-WITNESS-NULLIFIER", "devnet-call-alpha"),
            requested_at_height: DEVNET_HEIGHT,
            deadline_height: DEVNET_HEIGHT + 24,
        };
        let mut call =
            ContractCallRecord::from_request(request, &state.config).expect("devnet call is valid");
        let reservation = SponsorReservationRecord {
            reservation_id: reservation_id(&call.call_id, "devnet-sponsor-alpha", DEVNET_HEIGHT),
            call_id: call.call_id.clone(),
            sponsor_commitment: string_commitment("PQ-WITNESS-SPONSOR", "devnet-sponsor-alpha"),
            status: ReservationStatus::Reserved,
            fee_asset_id: "NEBULA".to_string(),
            reserved_micro_units: 84_000,
            consumed_micro_units: 0,
            cover_bps: DEFAULT_SPONSOR_COVER_BPS,
            opened_at_height: DEVNET_HEIGHT,
            expires_at_height: DEVNET_HEIGHT + DEFAULT_RESERVATION_TTL_BLOCKS,
        };
        call.status = CallStatus::Reserved;
        call.reservation_id = reservation.reservation_id.clone();
        state
            .providers
            .insert(witness.provider_id.clone(), witness.clone());
        state
            .providers
            .insert(prover.provider_id.clone(), prover.clone());
        state
            .bonds
            .insert(witness_bond.bond_id.clone(), witness_bond);
        state.bonds.insert(prover_bond.bond_id.clone(), prover_bond);
        state
            .reservations
            .insert(reservation.reservation_id.clone(), reservation.clone());
        state.calls.insert(call.call_id.clone(), call.clone());
        state.push_event(
            EventKind::ProviderRegistered,
            &witness.provider_id,
            &witness.record_root(),
            DEVNET_HEIGHT,
        );
        state.push_event(
            EventKind::ProviderRegistered,
            &prover.provider_id,
            &prover.record_root(),
            DEVNET_HEIGHT,
        );
        state.push_event(
            EventKind::CallQueued,
            &call.call_id,
            &call.record_root(),
            DEVNET_HEIGHT,
        );
        state.push_event(
            EventKind::SponsorReserved,
            &reservation.reservation_id,
            &reservation.record_root(),
            DEVNET_HEIGHT,
        );
        state.refresh_roots();
        state
    }
    pub fn empty(config: Config) -> Self {
        Self {
            config,
            counters: Counters::default(),
            roots: Roots::default(),
            providers: BTreeMap::new(),
            calls: BTreeMap::new(),
            assignments: BTreeMap::new(),
            bundles: BTreeMap::new(),
            attestations: BTreeMap::new(),
            bonds: BTreeMap::new(),
            reservations: BTreeMap::new(),
            batch_receipts: BTreeMap::new(),
            rebates: BTreeMap::new(),
            fences: BTreeMap::new(),
            events: Vec::new(),
            spent_nullifiers: BTreeSet::new(),
        }
    }
    pub fn validate(&self) -> Result<()> {
        self.config.validate()?;
        require_len("providers", self.providers.len(), self.config.max_providers)?;
        require_len("calls", self.calls.len(), self.config.max_calls)?;
        require_len(
            "assignments",
            self.assignments.len(),
            self.config.max_assignments,
        )?;
        require_len("bundles", self.bundles.len(), self.config.max_bundles)?;
        require_len(
            "attestations",
            self.attestations.len(),
            self.config.max_attestations,
        )?;
        require_len("bonds", self.bonds.len(), self.config.max_bonds)?;
        require_len(
            "reservations",
            self.reservations.len(),
            self.config.max_reservations,
        )?;
        require_len(
            "batch_receipts",
            self.batch_receipts.len(),
            self.config.max_batch_receipts,
        )?;
        require_len("rebates", self.rebates.len(), self.config.max_rebates)?;
        require_len("fences", self.fences.len(), self.config.max_fences)?;
        require_len("events", self.events.len(), self.config.max_events)?;
        for record in self.providers.values() {
            record.validate(&self.config)?;
        }
        for record in self.calls.values() {
            record.validate(&self.config)?;
        }
        for record in self.assignments.values() {
            record.validate(&self.config)?;
        }
        for record in self.bundles.values() {
            record.validate()?;
        }
        for record in self.attestations.values() {
            record.validate(&self.config)?;
        }
        for record in self.bonds.values() {
            record.validate(&self.config)?;
        }
        for record in self.reservations.values() {
            record.validate(&self.config)?;
        }
        for record in self.batch_receipts.values() {
            record.validate(&self.config)?;
        }
        for record in self.rebates.values() {
            record.validate()?;
        }
        for record in self.fences.values() {
            record.validate()?;
        }
        for record in &self.events {
            record.validate()?;
        }
        Ok(())
    }
    pub fn refresh_roots(&mut self) {
        self.counters = Counters {
            providers: self.providers.len() as u64,
            calls: self.calls.len() as u64,
            assignments: self.assignments.len() as u64,
            bundles: self.bundles.len() as u64,
            attestations: self.attestations.len() as u64,
            bonds: self.bonds.len() as u64,
            reservations: self.reservations.len() as u64,
            batch_receipts: self.batch_receipts.len() as u64,
            rebates: self.rebates.len() as u64,
            fences: self.fences.len() as u64,
            events: self.events.len() as u64,
            slashes: self
                .bonds
                .values()
                .filter(|b| b.status == BondStatus::Slashed)
                .count() as u64,
            settled_calls: self
                .calls
                .values()
                .filter(|c| c.status == CallStatus::Settled)
                .count() as u64,
            rebated_micro_units: self.rebates.values().map(|r| r.rebate_micro_units).sum(),
            sponsored_micro_units: self
                .reservations
                .values()
                .map(|r| r.reserved_micro_units)
                .sum(),
        };
        let provider_root = map_root(
            "PQ-WITNESS-MARKET-PROVIDERS",
            &self.providers,
            ProviderRecord::public_record,
        );
        let call_root = map_root(
            "PQ-WITNESS-MARKET-CALLS",
            &self.calls,
            ContractCallRecord::public_record,
        );
        let assignment_root = map_root(
            "PQ-WITNESS-MARKET-ASSIGNMENTS",
            &self.assignments,
            AssignmentRecord::public_record,
        );
        let bundle_root = map_root(
            "PQ-WITNESS-MARKET-BUNDLES",
            &self.bundles,
            WitnessBundleRecord::public_record,
        );
        let attestation_root = map_root(
            "PQ-WITNESS-MARKET-ATTESTATIONS",
            &self.attestations,
            PqAttestationRecord::public_record,
        );
        let bond_root = map_root(
            "PQ-WITNESS-MARKET-BONDS",
            &self.bonds,
            SlashingBondRecord::public_record,
        );
        let reservation_root = map_root(
            "PQ-WITNESS-MARKET-RESERVATIONS",
            &self.reservations,
            SponsorReservationRecord::public_record,
        );
        let batch_receipt_root = map_root(
            "PQ-WITNESS-MARKET-BATCH-RECEIPTS",
            &self.batch_receipts,
            BatchReceiptRecord::public_record,
        );
        let rebate_root = map_root(
            "PQ-WITNESS-MARKET-REBATES",
            &self.rebates,
            FeeRebateRecord::public_record,
        );
        let fence_root = map_root(
            "PQ-WITNESS-MARKET-FENCES",
            &self.fences,
            PrivacyFenceRecord::public_record,
        );
        let event_records: Vec<Value> =
            self.events.iter().map(EventRecord::public_record).collect();
        let event_root = merkle_root("PQ-WITNESS-MARKET-EVENTS", &event_records);
        let nullifier_records: Vec<Value> = self
            .spent_nullifiers
            .iter()
            .map(|n| json!({ "nullifier_hash": n }))
            .collect();
        let nullifier_root = merkle_root("PQ-WITNESS-MARKET-NULLIFIERS", &nullifier_records);
        let sponsor_records: Vec<Value> = self.reservations.values().map(|r| json!({ "reservation_id": r.reservation_id, "sponsor_commitment": r.sponsor_commitment, "reserved_micro_units": r.reserved_micro_units, "status": r.status.as_str() })).collect();
        let sponsor_root = merkle_root("PQ-WITNESS-MARKET-SPONSORS", &sponsor_records);
        let mut roots = Roots {
            provider_root,
            call_root,
            assignment_root,
            bundle_root,
            attestation_root,
            bond_root,
            reservation_root,
            batch_receipt_root,
            rebate_root,
            fence_root,
            event_root,
            nullifier_root,
            sponsor_root,
            state_root: String::new(),
        };
        roots.state_root = self.compute_state_root_with(&roots);
        self.roots = roots;
    }
    pub fn state_root(&self) -> String {
        self.compute_state_root_with(&self.roots)
    }
    fn compute_state_root_with(&self, roots: &Roots) -> String {
        domain_hash(
            "PQ-WITNESS-MARKET-STATE",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Json(&self.config_public_record()),
                HashPart::Json(&self.counters.public_record()),
                HashPart::Json(&roots.public_record()),
            ],
            32,
        )
    }
    pub fn public_record(&self) -> Value {
        json!({ "chain_id": CHAIN_ID, "protocol_version": PROTOCOL_VERSION, "schema_version": SCHEMA_VERSION, "config": self.config_public_record(), "counters": self.counters.public_record(), "roots": self.roots.public_record(), "state_root": self.state_root() })
    }
    fn config_public_record(&self) -> Value {
        json!({ "protocol_version": self.config.protocol_version, "schema_version": self.config.schema_version, "chain_id": self.config.chain_id, "l2_network": self.config.l2_network, "contract_network": self.config.contract_network, "hash_suite": self.config.hash_suite, "pq_kem_suite": self.config.pq_kem_suite, "pq_signature_suite": self.config.pq_signature_suite, "witness_encryption_scheme": self.config.witness_encryption_scheme, "attestation_scheme": self.config.attestation_scheme, "slashing_scheme": self.config.slashing_scheme, "sponsor_reservation_scheme": self.config.sponsor_reservation_scheme, "batch_receipt_scheme": self.config.batch_receipt_scheme, "fee_rebate_scheme": self.config.fee_rebate_scheme, "privacy_fence_scheme": self.config.privacy_fence_scheme, "min_pq_security_bits": self.config.min_pq_security_bits, "min_privacy_set_size": self.config.min_privacy_set_size, "batch_privacy_set_size": self.config.batch_privacy_set_size, "target_latency_ms": self.config.target_latency_ms, "hard_latency_ms": self.config.hard_latency_ms, "assignment_ttl_blocks": self.config.assignment_ttl_blocks, "reservation_ttl_blocks": self.config.reservation_ttl_blocks, "bundle_ttl_blocks": self.config.bundle_ttl_blocks, "attestation_ttl_blocks": self.config.attestation_ttl_blocks, "batch_window_blocks": self.config.batch_window_blocks, "rebate_ttl_blocks": self.config.rebate_ttl_blocks, "max_call_fee_bps": self.config.max_call_fee_bps, "target_rebate_bps": self.config.target_rebate_bps, "sponsor_cover_bps": self.config.sponsor_cover_bps, "quorum_bps": self.config.quorum_bps, "strong_quorum_bps": self.config.strong_quorum_bps, "devnet_height": self.config.devnet_height })
    }
    fn push_event(&mut self, kind: EventKind, subject_id: &str, subject_root: &str, height: u64) {
        let sequence = self.events.len() as u64;
        let payload_root = event_payload_root(kind, subject_id, subject_root, height, sequence);
        let event_id = event_id(kind, subject_id, subject_root, height, sequence);
        self.events.push(EventRecord {
            event_id,
            kind,
            subject_id: subject_id.to_string(),
            subject_root: subject_root.to_string(),
            payload_root,
            emitted_at_height: height,
            sequence,
        });
    }
}

pub fn provider_id(label: &str, provider_kind: ProviderKind, height: u64) -> String {
    domain_hash(
        "PQ-WITNESS-MARKET-PROVIDER-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Str(provider_kind.as_str()),
            HashPart::Int(height as i128),
        ],
        32,
    )
}
pub fn call_id(request: &ContractCallRequest) -> String {
    domain_hash(
        "PQ-WITNESS-MARKET-CALL-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.caller_commitment),
            HashPart::Str(&request.contract_id),
            HashPart::Str(request.call_kind.as_str()),
            HashPart::Str(&request.encrypted_call_root),
            HashPart::Str(&request.nullifier_hash),
            HashPart::Int(request.requested_at_height as i128),
        ],
        32,
    )
}
pub fn assignment_id(call_id: &str, provider_id: &str, lane_index: u64, height: u64) -> String {
    domain_hash(
        "PQ-WITNESS-MARKET-ASSIGNMENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(call_id),
            HashPart::Str(provider_id),
            HashPart::Int(lane_index as i128),
            HashPart::Int(height as i128),
        ],
        32,
    )
}
pub fn bundle_id(
    assignment_id: &str,
    encrypted_bundle_root: &str,
    sealed_at_height: u64,
) -> String {
    domain_hash(
        "PQ-WITNESS-MARKET-BUNDLE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(assignment_id),
            HashPart::Str(encrypted_bundle_root),
            HashPart::Int(sealed_at_height as i128),
        ],
        32,
    )
}
pub fn attestation_id(
    assignment_id: &str,
    provider_id: &str,
    transcript_root: &str,
    signed_at_height: u64,
) -> String {
    domain_hash(
        "PQ-WITNESS-MARKET-ATTESTATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(assignment_id),
            HashPart::Str(provider_id),
            HashPart::Str(transcript_root),
            HashPart::Int(signed_at_height as i128),
        ],
        32,
    )
}
pub fn bond_id(
    provider_label: &str,
    provider_kind: ProviderKind,
    locked_micro_units: u64,
    opened_at_height: u64,
) -> String {
    domain_hash(
        "PQ-WITNESS-MARKET-BOND-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(provider_label),
            HashPart::Str(provider_kind.as_str()),
            HashPart::Int(locked_micro_units as i128),
            HashPart::Int(opened_at_height as i128),
        ],
        32,
    )
}
pub fn reservation_id(call_id: &str, sponsor_label: &str, opened_at_height: u64) -> String {
    domain_hash(
        "PQ-WITNESS-MARKET-RESERVATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(call_id),
            HashPart::Str(sponsor_label),
            HashPart::Int(opened_at_height as i128),
        ],
        32,
    )
}
pub fn batch_id(call_root: &str, proposed_at_height: u64, sequence: u64) -> String {
    domain_hash(
        "PQ-WITNESS-MARKET-BATCH-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(call_root),
            HashPart::Int(proposed_at_height as i128),
            HashPart::Int(sequence as i128),
        ],
        32,
    )
}
pub fn rebate_id(call_id: &str, reservation_id: &str, queued_at_height: u64) -> String {
    domain_hash(
        "PQ-WITNESS-MARKET-REBATE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(call_id),
            HashPart::Str(reservation_id),
            HashPart::Int(queued_at_height as i128),
        ],
        32,
    )
}
pub fn fence_id(call_id: &str, nullifier_hash: &str, inserted_at_height: u64) -> String {
    domain_hash(
        "PQ-WITNESS-MARKET-FENCE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(call_id),
            HashPart::Str(nullifier_hash),
            HashPart::Int(inserted_at_height as i128),
        ],
        32,
    )
}
pub fn event_id(
    kind: EventKind,
    subject_id: &str,
    subject_root: &str,
    height: u64,
    sequence: u64,
) -> String {
    domain_hash(
        "PQ-WITNESS-MARKET-EVENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(kind.as_str()),
            HashPart::Str(subject_id),
            HashPart::Str(subject_root),
            HashPart::Int(height as i128),
            HashPart::Int(sequence as i128),
        ],
        32,
    )
}
fn event_payload_root(
    kind: EventKind,
    subject_id: &str,
    subject_root: &str,
    height: u64,
    sequence: u64,
) -> String {
    domain_hash(
        "PQ-WITNESS-MARKET-EVENT-PAYLOAD",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(kind.as_str()),
            HashPart::Str(subject_id),
            HashPart::Str(subject_root),
            HashPart::Int(height as i128),
            HashPart::Int(sequence as i128),
        ],
        32,
    )
}
fn record_root(domain: &str, record: &Value) -> String {
    domain_hash(
        domain,
        &[HashPart::Str(CHAIN_ID), HashPart::Json(record)],
        32,
    )
}
fn empty_root(domain: &str) -> String {
    merkle_root(domain, &[])
}
fn string_commitment(domain: &str, value: &str) -> String {
    domain_hash(domain, &[HashPart::Str(CHAIN_ID), HashPart::Str(value)], 32)
}
fn map_root<T, F>(domain: &str, records: &BTreeMap<String, T>, public_record: F) -> String
where
    F: Fn(&T) -> Value,
{
    let leaves: Vec<Value> = records.values().map(public_record).collect();
    merkle_root(domain, &leaves)
}
fn require_eq(name: &str, actual: &str, expected: &str) -> Result<()> {
    if actual == expected {
        Ok(())
    } else {
        Err(format!("{name} must equal {expected}"))
    }
}
fn require_id(name: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        Err(format!("{name} must not be empty"))
    } else {
        Ok(())
    }
}
fn require_root(name: &str, value: &str) -> Result<()> {
    if value.len() < 32 {
        Err(format!("{name} must be a domain-separated commitment root"))
    } else {
        Ok(())
    }
}
fn require_nullifier(name: &str, value: &str) -> Result<()> {
    require_root(name, value)
}
fn require_nonzero(name: &str, value: u64) -> Result<()> {
    if value == 0 {
        Err(format!("{name} must be non-zero"))
    } else {
        Ok(())
    }
}
fn require_bps(name: &str, value: u64) -> Result<()> {
    if value > MAX_BPS {
        Err(format!("{name} exceeds {MAX_BPS} bps"))
    } else {
        Ok(())
    }
}
fn require_len(name: &str, actual: usize, max: usize) -> Result<()> {
    if actual > max {
        Err(format!("{name} length {actual} exceeds max {max}"))
    } else {
        Ok(())
    }
}

pub fn validate_parallel_lane_001(
    latency_ms: u64,
    fee_bps: u64,
    privacy_set_size: u64,
    config: &Config,
) -> Result<()> {
    if latency_ms == 0 || latency_ms > config.hard_latency_ms {
        return Err("parallel lane 001 latency is outside configured bounds".to_string());
    }
    if fee_bps > config.max_call_fee_bps {
        return Err("parallel lane 001 fee exceeds configured cap".to_string());
    }
    if privacy_set_size < config.min_privacy_set_size {
        return Err(
            "parallel lane 001 privacy set is below the quantum-safe anonymity floor".to_string(),
        );
    }
    Ok(())
}

pub fn validate_parallel_lane_002(
    latency_ms: u64,
    fee_bps: u64,
    privacy_set_size: u64,
    config: &Config,
) -> Result<()> {
    if latency_ms == 0 || latency_ms > config.hard_latency_ms {
        return Err("parallel lane 002 latency is outside configured bounds".to_string());
    }
    if fee_bps > config.max_call_fee_bps {
        return Err("parallel lane 002 fee exceeds configured cap".to_string());
    }
    if privacy_set_size < config.min_privacy_set_size {
        return Err(
            "parallel lane 002 privacy set is below the quantum-safe anonymity floor".to_string(),
        );
    }
    Ok(())
}

pub fn validate_parallel_lane_003(
    latency_ms: u64,
    fee_bps: u64,
    privacy_set_size: u64,
    config: &Config,
) -> Result<()> {
    if latency_ms == 0 || latency_ms > config.hard_latency_ms {
        return Err("parallel lane 003 latency is outside configured bounds".to_string());
    }
    if fee_bps > config.max_call_fee_bps {
        return Err("parallel lane 003 fee exceeds configured cap".to_string());
    }
    if privacy_set_size < config.min_privacy_set_size {
        return Err(
            "parallel lane 003 privacy set is below the quantum-safe anonymity floor".to_string(),
        );
    }
    Ok(())
}

pub fn validate_parallel_lane_004(
    latency_ms: u64,
    fee_bps: u64,
    privacy_set_size: u64,
    config: &Config,
) -> Result<()> {
    if latency_ms == 0 || latency_ms > config.hard_latency_ms {
        return Err("parallel lane 004 latency is outside configured bounds".to_string());
    }
    if fee_bps > config.max_call_fee_bps {
        return Err("parallel lane 004 fee exceeds configured cap".to_string());
    }
    if privacy_set_size < config.min_privacy_set_size {
        return Err(
            "parallel lane 004 privacy set is below the quantum-safe anonymity floor".to_string(),
        );
    }
    Ok(())
}

pub fn validate_parallel_lane_005(
    latency_ms: u64,
    fee_bps: u64,
    privacy_set_size: u64,
    config: &Config,
) -> Result<()> {
    if latency_ms == 0 || latency_ms > config.hard_latency_ms {
        return Err("parallel lane 005 latency is outside configured bounds".to_string());
    }
    if fee_bps > config.max_call_fee_bps {
        return Err("parallel lane 005 fee exceeds configured cap".to_string());
    }
    if privacy_set_size < config.min_privacy_set_size {
        return Err(
            "parallel lane 005 privacy set is below the quantum-safe anonymity floor".to_string(),
        );
    }
    Ok(())
}

pub fn validate_parallel_lane_006(
    latency_ms: u64,
    fee_bps: u64,
    privacy_set_size: u64,
    config: &Config,
) -> Result<()> {
    if latency_ms == 0 || latency_ms > config.hard_latency_ms {
        return Err("parallel lane 006 latency is outside configured bounds".to_string());
    }
    if fee_bps > config.max_call_fee_bps {
        return Err("parallel lane 006 fee exceeds configured cap".to_string());
    }
    if privacy_set_size < config.min_privacy_set_size {
        return Err(
            "parallel lane 006 privacy set is below the quantum-safe anonymity floor".to_string(),
        );
    }
    Ok(())
}

pub fn validate_parallel_lane_007(
    latency_ms: u64,
    fee_bps: u64,
    privacy_set_size: u64,
    config: &Config,
) -> Result<()> {
    if latency_ms == 0 || latency_ms > config.hard_latency_ms {
        return Err("parallel lane 007 latency is outside configured bounds".to_string());
    }
    if fee_bps > config.max_call_fee_bps {
        return Err("parallel lane 007 fee exceeds configured cap".to_string());
    }
    if privacy_set_size < config.min_privacy_set_size {
        return Err(
            "parallel lane 007 privacy set is below the quantum-safe anonymity floor".to_string(),
        );
    }
    Ok(())
}

pub fn validate_parallel_lane_008(
    latency_ms: u64,
    fee_bps: u64,
    privacy_set_size: u64,
    config: &Config,
) -> Result<()> {
    if latency_ms == 0 || latency_ms > config.hard_latency_ms {
        return Err("parallel lane 008 latency is outside configured bounds".to_string());
    }
    if fee_bps > config.max_call_fee_bps {
        return Err("parallel lane 008 fee exceeds configured cap".to_string());
    }
    if privacy_set_size < config.min_privacy_set_size {
        return Err(
            "parallel lane 008 privacy set is below the quantum-safe anonymity floor".to_string(),
        );
    }
    Ok(())
}

pub fn validate_parallel_lane_009(
    latency_ms: u64,
    fee_bps: u64,
    privacy_set_size: u64,
    config: &Config,
) -> Result<()> {
    if latency_ms == 0 || latency_ms > config.hard_latency_ms {
        return Err("parallel lane 009 latency is outside configured bounds".to_string());
    }
    if fee_bps > config.max_call_fee_bps {
        return Err("parallel lane 009 fee exceeds configured cap".to_string());
    }
    if privacy_set_size < config.min_privacy_set_size {
        return Err(
            "parallel lane 009 privacy set is below the quantum-safe anonymity floor".to_string(),
        );
    }
    Ok(())
}

pub fn validate_parallel_lane_010(
    latency_ms: u64,
    fee_bps: u64,
    privacy_set_size: u64,
    config: &Config,
) -> Result<()> {
    if latency_ms == 0 || latency_ms > config.hard_latency_ms {
        return Err("parallel lane 010 latency is outside configured bounds".to_string());
    }
    if fee_bps > config.max_call_fee_bps {
        return Err("parallel lane 010 fee exceeds configured cap".to_string());
    }
    if privacy_set_size < config.min_privacy_set_size {
        return Err(
            "parallel lane 010 privacy set is below the quantum-safe anonymity floor".to_string(),
        );
    }
    Ok(())
}

pub fn validate_parallel_lane_011(
    latency_ms: u64,
    fee_bps: u64,
    privacy_set_size: u64,
    config: &Config,
) -> Result<()> {
    if latency_ms == 0 || latency_ms > config.hard_latency_ms {
        return Err("parallel lane 011 latency is outside configured bounds".to_string());
    }
    if fee_bps > config.max_call_fee_bps {
        return Err("parallel lane 011 fee exceeds configured cap".to_string());
    }
    if privacy_set_size < config.min_privacy_set_size {
        return Err(
            "parallel lane 011 privacy set is below the quantum-safe anonymity floor".to_string(),
        );
    }
    Ok(())
}

pub fn validate_parallel_lane_012(
    latency_ms: u64,
    fee_bps: u64,
    privacy_set_size: u64,
    config: &Config,
) -> Result<()> {
    if latency_ms == 0 || latency_ms > config.hard_latency_ms {
        return Err("parallel lane 012 latency is outside configured bounds".to_string());
    }
    if fee_bps > config.max_call_fee_bps {
        return Err("parallel lane 012 fee exceeds configured cap".to_string());
    }
    if privacy_set_size < config.min_privacy_set_size {
        return Err(
            "parallel lane 012 privacy set is below the quantum-safe anonymity floor".to_string(),
        );
    }
    Ok(())
}

pub fn validate_parallel_lane_013(
    latency_ms: u64,
    fee_bps: u64,
    privacy_set_size: u64,
    config: &Config,
) -> Result<()> {
    if latency_ms == 0 || latency_ms > config.hard_latency_ms {
        return Err("parallel lane 013 latency is outside configured bounds".to_string());
    }
    if fee_bps > config.max_call_fee_bps {
        return Err("parallel lane 013 fee exceeds configured cap".to_string());
    }
    if privacy_set_size < config.min_privacy_set_size {
        return Err(
            "parallel lane 013 privacy set is below the quantum-safe anonymity floor".to_string(),
        );
    }
    Ok(())
}

pub fn validate_parallel_lane_014(
    latency_ms: u64,
    fee_bps: u64,
    privacy_set_size: u64,
    config: &Config,
) -> Result<()> {
    if latency_ms == 0 || latency_ms > config.hard_latency_ms {
        return Err("parallel lane 014 latency is outside configured bounds".to_string());
    }
    if fee_bps > config.max_call_fee_bps {
        return Err("parallel lane 014 fee exceeds configured cap".to_string());
    }
    if privacy_set_size < config.min_privacy_set_size {
        return Err(
            "parallel lane 014 privacy set is below the quantum-safe anonymity floor".to_string(),
        );
    }
    Ok(())
}

pub fn validate_parallel_lane_015(
    latency_ms: u64,
    fee_bps: u64,
    privacy_set_size: u64,
    config: &Config,
) -> Result<()> {
    if latency_ms == 0 || latency_ms > config.hard_latency_ms {
        return Err("parallel lane 015 latency is outside configured bounds".to_string());
    }
    if fee_bps > config.max_call_fee_bps {
        return Err("parallel lane 015 fee exceeds configured cap".to_string());
    }
    if privacy_set_size < config.min_privacy_set_size {
        return Err(
            "parallel lane 015 privacy set is below the quantum-safe anonymity floor".to_string(),
        );
    }
    Ok(())
}

pub fn validate_parallel_lane_016(
    latency_ms: u64,
    fee_bps: u64,
    privacy_set_size: u64,
    config: &Config,
) -> Result<()> {
    if latency_ms == 0 || latency_ms > config.hard_latency_ms {
        return Err("parallel lane 016 latency is outside configured bounds".to_string());
    }
    if fee_bps > config.max_call_fee_bps {
        return Err("parallel lane 016 fee exceeds configured cap".to_string());
    }
    if privacy_set_size < config.min_privacy_set_size {
        return Err(
            "parallel lane 016 privacy set is below the quantum-safe anonymity floor".to_string(),
        );
    }
    Ok(())
}

pub fn validate_parallel_lane_017(
    latency_ms: u64,
    fee_bps: u64,
    privacy_set_size: u64,
    config: &Config,
) -> Result<()> {
    if latency_ms == 0 || latency_ms > config.hard_latency_ms {
        return Err("parallel lane 017 latency is outside configured bounds".to_string());
    }
    if fee_bps > config.max_call_fee_bps {
        return Err("parallel lane 017 fee exceeds configured cap".to_string());
    }
    if privacy_set_size < config.min_privacy_set_size {
        return Err(
            "parallel lane 017 privacy set is below the quantum-safe anonymity floor".to_string(),
        );
    }
    Ok(())
}

pub fn validate_parallel_lane_018(
    latency_ms: u64,
    fee_bps: u64,
    privacy_set_size: u64,
    config: &Config,
) -> Result<()> {
    if latency_ms == 0 || latency_ms > config.hard_latency_ms {
        return Err("parallel lane 018 latency is outside configured bounds".to_string());
    }
    if fee_bps > config.max_call_fee_bps {
        return Err("parallel lane 018 fee exceeds configured cap".to_string());
    }
    if privacy_set_size < config.min_privacy_set_size {
        return Err(
            "parallel lane 018 privacy set is below the quantum-safe anonymity floor".to_string(),
        );
    }
    Ok(())
}

pub fn validate_parallel_lane_019(
    latency_ms: u64,
    fee_bps: u64,
    privacy_set_size: u64,
    config: &Config,
) -> Result<()> {
    if latency_ms == 0 || latency_ms > config.hard_latency_ms {
        return Err("parallel lane 019 latency is outside configured bounds".to_string());
    }
    if fee_bps > config.max_call_fee_bps {
        return Err("parallel lane 019 fee exceeds configured cap".to_string());
    }
    if privacy_set_size < config.min_privacy_set_size {
        return Err(
            "parallel lane 019 privacy set is below the quantum-safe anonymity floor".to_string(),
        );
    }
    Ok(())
}

pub fn validate_parallel_lane_020(
    latency_ms: u64,
    fee_bps: u64,
    privacy_set_size: u64,
    config: &Config,
) -> Result<()> {
    if latency_ms == 0 || latency_ms > config.hard_latency_ms {
        return Err("parallel lane 020 latency is outside configured bounds".to_string());
    }
    if fee_bps > config.max_call_fee_bps {
        return Err("parallel lane 020 fee exceeds configured cap".to_string());
    }
    if privacy_set_size < config.min_privacy_set_size {
        return Err(
            "parallel lane 020 privacy set is below the quantum-safe anonymity floor".to_string(),
        );
    }
    Ok(())
}

pub fn validate_parallel_lane_021(
    latency_ms: u64,
    fee_bps: u64,
    privacy_set_size: u64,
    config: &Config,
) -> Result<()> {
    if latency_ms == 0 || latency_ms > config.hard_latency_ms {
        return Err("parallel lane 021 latency is outside configured bounds".to_string());
    }
    if fee_bps > config.max_call_fee_bps {
        return Err("parallel lane 021 fee exceeds configured cap".to_string());
    }
    if privacy_set_size < config.min_privacy_set_size {
        return Err(
            "parallel lane 021 privacy set is below the quantum-safe anonymity floor".to_string(),
        );
    }
    Ok(())
}

pub fn validate_parallel_lane_022(
    latency_ms: u64,
    fee_bps: u64,
    privacy_set_size: u64,
    config: &Config,
) -> Result<()> {
    if latency_ms == 0 || latency_ms > config.hard_latency_ms {
        return Err("parallel lane 022 latency is outside configured bounds".to_string());
    }
    if fee_bps > config.max_call_fee_bps {
        return Err("parallel lane 022 fee exceeds configured cap".to_string());
    }
    if privacy_set_size < config.min_privacy_set_size {
        return Err(
            "parallel lane 022 privacy set is below the quantum-safe anonymity floor".to_string(),
        );
    }
    Ok(())
}

pub fn validate_parallel_lane_023(
    latency_ms: u64,
    fee_bps: u64,
    privacy_set_size: u64,
    config: &Config,
) -> Result<()> {
    if latency_ms == 0 || latency_ms > config.hard_latency_ms {
        return Err("parallel lane 023 latency is outside configured bounds".to_string());
    }
    if fee_bps > config.max_call_fee_bps {
        return Err("parallel lane 023 fee exceeds configured cap".to_string());
    }
    if privacy_set_size < config.min_privacy_set_size {
        return Err(
            "parallel lane 023 privacy set is below the quantum-safe anonymity floor".to_string(),
        );
    }
    Ok(())
}

pub fn validate_parallel_lane_024(
    latency_ms: u64,
    fee_bps: u64,
    privacy_set_size: u64,
    config: &Config,
) -> Result<()> {
    if latency_ms == 0 || latency_ms > config.hard_latency_ms {
        return Err("parallel lane 024 latency is outside configured bounds".to_string());
    }
    if fee_bps > config.max_call_fee_bps {
        return Err("parallel lane 024 fee exceeds configured cap".to_string());
    }
    if privacy_set_size < config.min_privacy_set_size {
        return Err(
            "parallel lane 024 privacy set is below the quantum-safe anonymity floor".to_string(),
        );
    }
    Ok(())
}

pub fn validate_parallel_lane_025(
    latency_ms: u64,
    fee_bps: u64,
    privacy_set_size: u64,
    config: &Config,
) -> Result<()> {
    if latency_ms == 0 || latency_ms > config.hard_latency_ms {
        return Err("parallel lane 025 latency is outside configured bounds".to_string());
    }
    if fee_bps > config.max_call_fee_bps {
        return Err("parallel lane 025 fee exceeds configured cap".to_string());
    }
    if privacy_set_size < config.min_privacy_set_size {
        return Err(
            "parallel lane 025 privacy set is below the quantum-safe anonymity floor".to_string(),
        );
    }
    Ok(())
}

pub fn validate_parallel_lane_026(
    latency_ms: u64,
    fee_bps: u64,
    privacy_set_size: u64,
    config: &Config,
) -> Result<()> {
    if latency_ms == 0 || latency_ms > config.hard_latency_ms {
        return Err("parallel lane 026 latency is outside configured bounds".to_string());
    }
    if fee_bps > config.max_call_fee_bps {
        return Err("parallel lane 026 fee exceeds configured cap".to_string());
    }
    if privacy_set_size < config.min_privacy_set_size {
        return Err(
            "parallel lane 026 privacy set is below the quantum-safe anonymity floor".to_string(),
        );
    }
    Ok(())
}

pub fn validate_parallel_lane_027(
    latency_ms: u64,
    fee_bps: u64,
    privacy_set_size: u64,
    config: &Config,
) -> Result<()> {
    if latency_ms == 0 || latency_ms > config.hard_latency_ms {
        return Err("parallel lane 027 latency is outside configured bounds".to_string());
    }
    if fee_bps > config.max_call_fee_bps {
        return Err("parallel lane 027 fee exceeds configured cap".to_string());
    }
    if privacy_set_size < config.min_privacy_set_size {
        return Err(
            "parallel lane 027 privacy set is below the quantum-safe anonymity floor".to_string(),
        );
    }
    Ok(())
}

pub fn validate_parallel_lane_028(
    latency_ms: u64,
    fee_bps: u64,
    privacy_set_size: u64,
    config: &Config,
) -> Result<()> {
    if latency_ms == 0 || latency_ms > config.hard_latency_ms {
        return Err("parallel lane 028 latency is outside configured bounds".to_string());
    }
    if fee_bps > config.max_call_fee_bps {
        return Err("parallel lane 028 fee exceeds configured cap".to_string());
    }
    if privacy_set_size < config.min_privacy_set_size {
        return Err(
            "parallel lane 028 privacy set is below the quantum-safe anonymity floor".to_string(),
        );
    }
    Ok(())
}

pub fn validate_parallel_lane_029(
    latency_ms: u64,
    fee_bps: u64,
    privacy_set_size: u64,
    config: &Config,
) -> Result<()> {
    if latency_ms == 0 || latency_ms > config.hard_latency_ms {
        return Err("parallel lane 029 latency is outside configured bounds".to_string());
    }
    if fee_bps > config.max_call_fee_bps {
        return Err("parallel lane 029 fee exceeds configured cap".to_string());
    }
    if privacy_set_size < config.min_privacy_set_size {
        return Err(
            "parallel lane 029 privacy set is below the quantum-safe anonymity floor".to_string(),
        );
    }
    Ok(())
}

pub fn validate_parallel_lane_030(
    latency_ms: u64,
    fee_bps: u64,
    privacy_set_size: u64,
    config: &Config,
) -> Result<()> {
    if latency_ms == 0 || latency_ms > config.hard_latency_ms {
        return Err("parallel lane 030 latency is outside configured bounds".to_string());
    }
    if fee_bps > config.max_call_fee_bps {
        return Err("parallel lane 030 fee exceeds configured cap".to_string());
    }
    if privacy_set_size < config.min_privacy_set_size {
        return Err(
            "parallel lane 030 privacy set is below the quantum-safe anonymity floor".to_string(),
        );
    }
    Ok(())
}

pub fn validate_parallel_lane_031(
    latency_ms: u64,
    fee_bps: u64,
    privacy_set_size: u64,
    config: &Config,
) -> Result<()> {
    if latency_ms == 0 || latency_ms > config.hard_latency_ms {
        return Err("parallel lane 031 latency is outside configured bounds".to_string());
    }
    if fee_bps > config.max_call_fee_bps {
        return Err("parallel lane 031 fee exceeds configured cap".to_string());
    }
    if privacy_set_size < config.min_privacy_set_size {
        return Err(
            "parallel lane 031 privacy set is below the quantum-safe anonymity floor".to_string(),
        );
    }
    Ok(())
}

pub fn validate_parallel_lane_032(
    latency_ms: u64,
    fee_bps: u64,
    privacy_set_size: u64,
    config: &Config,
) -> Result<()> {
    if latency_ms == 0 || latency_ms > config.hard_latency_ms {
        return Err("parallel lane 032 latency is outside configured bounds".to_string());
    }
    if fee_bps > config.max_call_fee_bps {
        return Err("parallel lane 032 fee exceeds configured cap".to_string());
    }
    if privacy_set_size < config.min_privacy_set_size {
        return Err(
            "parallel lane 032 privacy set is below the quantum-safe anonymity floor".to_string(),
        );
    }
    Ok(())
}

pub fn validate_parallel_lane_033(
    latency_ms: u64,
    fee_bps: u64,
    privacy_set_size: u64,
    config: &Config,
) -> Result<()> {
    if latency_ms == 0 || latency_ms > config.hard_latency_ms {
        return Err("parallel lane 033 latency is outside configured bounds".to_string());
    }
    if fee_bps > config.max_call_fee_bps {
        return Err("parallel lane 033 fee exceeds configured cap".to_string());
    }
    if privacy_set_size < config.min_privacy_set_size {
        return Err(
            "parallel lane 033 privacy set is below the quantum-safe anonymity floor".to_string(),
        );
    }
    Ok(())
}

pub fn validate_parallel_lane_034(
    latency_ms: u64,
    fee_bps: u64,
    privacy_set_size: u64,
    config: &Config,
) -> Result<()> {
    if latency_ms == 0 || latency_ms > config.hard_latency_ms {
        return Err("parallel lane 034 latency is outside configured bounds".to_string());
    }
    if fee_bps > config.max_call_fee_bps {
        return Err("parallel lane 034 fee exceeds configured cap".to_string());
    }
    if privacy_set_size < config.min_privacy_set_size {
        return Err(
            "parallel lane 034 privacy set is below the quantum-safe anonymity floor".to_string(),
        );
    }
    Ok(())
}

pub fn validate_parallel_lane_035(
    latency_ms: u64,
    fee_bps: u64,
    privacy_set_size: u64,
    config: &Config,
) -> Result<()> {
    if latency_ms == 0 || latency_ms > config.hard_latency_ms {
        return Err("parallel lane 035 latency is outside configured bounds".to_string());
    }
    if fee_bps > config.max_call_fee_bps {
        return Err("parallel lane 035 fee exceeds configured cap".to_string());
    }
    if privacy_set_size < config.min_privacy_set_size {
        return Err(
            "parallel lane 035 privacy set is below the quantum-safe anonymity floor".to_string(),
        );
    }
    Ok(())
}

pub fn validate_parallel_lane_036(
    latency_ms: u64,
    fee_bps: u64,
    privacy_set_size: u64,
    config: &Config,
) -> Result<()> {
    if latency_ms == 0 || latency_ms > config.hard_latency_ms {
        return Err("parallel lane 036 latency is outside configured bounds".to_string());
    }
    if fee_bps > config.max_call_fee_bps {
        return Err("parallel lane 036 fee exceeds configured cap".to_string());
    }
    if privacy_set_size < config.min_privacy_set_size {
        return Err(
            "parallel lane 036 privacy set is below the quantum-safe anonymity floor".to_string(),
        );
    }
    Ok(())
}

pub fn validate_parallel_lane_037(
    latency_ms: u64,
    fee_bps: u64,
    privacy_set_size: u64,
    config: &Config,
) -> Result<()> {
    if latency_ms == 0 || latency_ms > config.hard_latency_ms {
        return Err("parallel lane 037 latency is outside configured bounds".to_string());
    }
    if fee_bps > config.max_call_fee_bps {
        return Err("parallel lane 037 fee exceeds configured cap".to_string());
    }
    if privacy_set_size < config.min_privacy_set_size {
        return Err(
            "parallel lane 037 privacy set is below the quantum-safe anonymity floor".to_string(),
        );
    }
    Ok(())
}

pub fn validate_parallel_lane_038(
    latency_ms: u64,
    fee_bps: u64,
    privacy_set_size: u64,
    config: &Config,
) -> Result<()> {
    if latency_ms == 0 || latency_ms > config.hard_latency_ms {
        return Err("parallel lane 038 latency is outside configured bounds".to_string());
    }
    if fee_bps > config.max_call_fee_bps {
        return Err("parallel lane 038 fee exceeds configured cap".to_string());
    }
    if privacy_set_size < config.min_privacy_set_size {
        return Err(
            "parallel lane 038 privacy set is below the quantum-safe anonymity floor".to_string(),
        );
    }
    Ok(())
}

pub fn validate_parallel_lane_039(
    latency_ms: u64,
    fee_bps: u64,
    privacy_set_size: u64,
    config: &Config,
) -> Result<()> {
    if latency_ms == 0 || latency_ms > config.hard_latency_ms {
        return Err("parallel lane 039 latency is outside configured bounds".to_string());
    }
    if fee_bps > config.max_call_fee_bps {
        return Err("parallel lane 039 fee exceeds configured cap".to_string());
    }
    if privacy_set_size < config.min_privacy_set_size {
        return Err(
            "parallel lane 039 privacy set is below the quantum-safe anonymity floor".to_string(),
        );
    }
    Ok(())
}
