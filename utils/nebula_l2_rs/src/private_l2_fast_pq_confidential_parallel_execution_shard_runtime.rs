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
    "nebula-private-l2-fast-pq-confidential-parallel-execution-shard-runtime-v1";
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_SUITE: &str = "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f";
pub const ENCRYPTION_SCHEME: &str = "pq-sealed-confidential-work-packet-v1";
pub const SCHEDULER_ATTESTATION_SCHEME: &str = "pq-parallel-shard-scheduler-attestation-v1";
pub const STATE_LOCK_SCHEME: &str = "shard-local-confidential-state-lock-v1";
pub const HANDOFF_SCHEME: &str = "cross-shard-confidential-handoff-commitment-v1";
pub const SPECULATIVE_RECEIPT_SCHEME: &str = "speculative-confidential-receipt-root-v1";
pub const PRECONFIRMATION_SCHEME: &str = "fast-pq-private-shard-preconfirmation-v1";
pub const NULLIFIER_FENCE_SCHEME: &str = "anti-conflict-nullifier-fence-v1";
pub const ROLLBACK_EVIDENCE_SCHEME: &str = "parallel-shard-rollback-reorg-evidence-v1";
pub const SLASHING_SCHEME: &str = "parallel-shard-scheduler-slashing-v1";
pub const DEVNET_SHARD_COUNT: u64 = 8;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 131_072;
pub const DEFAULT_MAX_PARALLEL_GROUPS: u64 = 64;
pub const DEFAULT_MAX_LOCKS_PER_PACKET: usize = 32;
pub const DEFAULT_PACKET_TTL_SLOTS: u64 = 12;
pub const DEFAULT_PRECONFIRMATION_TTL_SLOTS: u64 = 8;
pub const DEFAULT_HANDOFF_TTL_SLOTS: u64 = 16;
pub const DEFAULT_BASE_FEE_MICRO_XMR: u64 = 2_000;
pub const DEFAULT_LOW_FEE_CAP_BPS: u64 = 18;
pub const DEFAULT_SLASH_BPS: u64 = 1_250;
pub const MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PacketKind {
    Transfer,
    TokenMint,
    TokenBurn,
    ContractCall,
    DefiSwap,
    DefiLend,
    OracleUpdate,
    Governance,
    BridgeHandoff,
}

impl PacketKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Transfer => "transfer",
            Self::TokenMint => "token_mint",
            Self::TokenBurn => "token_burn",
            Self::ContractCall => "contract_call",
            Self::DefiSwap => "defi_swap",
            Self::DefiLend => "defi_lend",
            Self::OracleUpdate => "oracle_update",
            Self::Governance => "governance",
            Self::BridgeHandoff => "bridge_handoff",
        }
    }

    pub fn priority_weight(self) -> u64 {
        match self {
            Self::OracleUpdate => 1_000,
            Self::BridgeHandoff => 950,
            Self::DefiSwap => 900,
            Self::DefiLend => 860,
            Self::ContractCall => 820,
            Self::Transfer => 780,
            Self::TokenMint => 720,
            Self::TokenBurn => 720,
            Self::Governance => 640,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PacketStatus {
    Submitted,
    Fenced,
    Scheduled,
    Locked,
    ExecutedSpeculative,
    Preconfirmed,
    HandedOff,
    Settled,
    RolledBack,
    Slashed,
    Expired,
}

impl PacketStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Fenced => "fenced",
            Self::Scheduled => "scheduled",
            Self::Locked => "locked",
            Self::ExecutedSpeculative => "executed_speculative",
            Self::Preconfirmed => "preconfirmed",
            Self::HandedOff => "handed_off",
            Self::Settled => "settled",
            Self::RolledBack => "rolled_back",
            Self::Slashed => "slashed",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LockMode {
    Read,
    Write,
    Nullifier,
    Mint,
    Burn,
    ContractCall,
    HandoffOut,
    HandoffIn,
}

impl LockMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
            Self::Nullifier => "nullifier",
            Self::Mint => "mint",
            Self::Burn => "burn",
            Self::ContractCall => "contract_call",
            Self::HandoffOut => "handoff_out",
            Self::HandoffIn => "handoff_in",
        }
    }

    pub fn conflicts_with(self, other: Self) -> bool {
        !matches!((self, other), (Self::Read, Self::Read))
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FeeLaneKind {
    UltraLow,
    Standard,
    DefiPriority,
    ContractPriority,
    HandoffPriority,
    Emergency,
}

impl FeeLaneKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::UltraLow => "ultra_low",
            Self::Standard => "standard",
            Self::DefiPriority => "defi_priority",
            Self::ContractPriority => "contract_priority",
            Self::HandoffPriority => "handoff_priority",
            Self::Emergency => "emergency",
        }
    }

    pub fn multiplier_bps(self) -> u64 {
        match self {
            Self::UltraLow => 3_500,
            Self::Standard => 10_000,
            Self::DefiPriority => 12_000,
            Self::ContractPriority => 11_000,
            Self::HandoffPriority => 9_000,
            Self::Emergency => 16_000,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationStatus {
    Proposed,
    Accepted,
    Superseded,
    Challenged,
    Slashed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HandoffStatus {
    Prepared,
    Exported,
    Imported,
    Acknowledged,
    Expired,
    Disputed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    ConflictingLock,
    DuplicateNullifier,
    BadReceiptRoot,
    InvalidHandoff,
    SchedulerEquivocation,
    Reorg,
    LatePreconfirmation,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub protocol_version: String,
    pub chain_id: String,
    pub shard_count: u64,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub max_parallel_groups: u64,
    pub max_locks_per_packet: usize,
    pub packet_ttl_slots: u64,
    pub preconfirmation_ttl_slots: u64,
    pub handoff_ttl_slots: u64,
    pub base_fee_micro_xmr: u64,
    pub low_fee_cap_bps: u64,
    pub slash_bps: u64,
    pub deterministic_ordering: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            chain_id: CHAIN_ID.to_string(),
            shard_count: DEVNET_SHARD_COUNT,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            max_parallel_groups: DEFAULT_MAX_PARALLEL_GROUPS,
            max_locks_per_packet: DEFAULT_MAX_LOCKS_PER_PACKET,
            packet_ttl_slots: DEFAULT_PACKET_TTL_SLOTS,
            preconfirmation_ttl_slots: DEFAULT_PRECONFIRMATION_TTL_SLOTS,
            handoff_ttl_slots: DEFAULT_HANDOFF_TTL_SLOTS,
            base_fee_micro_xmr: DEFAULT_BASE_FEE_MICRO_XMR,
            low_fee_cap_bps: DEFAULT_LOW_FEE_CAP_BPS,
            slash_bps: DEFAULT_SLASH_BPS,
            deterministic_ordering: true,
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.protocol_version != PROTOCOL_VERSION {
            return Err("unsupported protocol version".to_string());
        }
        if self.chain_id != CHAIN_ID {
            return Err("chain id mismatch".to_string());
        }
        if self.shard_count == 0 {
            return Err("shard count must be nonzero".to_string());
        }
        if self.min_pq_security_bits < DEFAULT_MIN_PQ_SECURITY_BITS {
            return Err("pq security floor is too low".to_string());
        }
        if self.low_fee_cap_bps > MAX_BPS || self.slash_bps > MAX_BPS {
            return Err("basis points exceed maximum".to_string());
        }
        if self.max_locks_per_packet == 0 {
            return Err("lock limit must be nonzero".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub current_slot: u64,
    pub next_nonce: u64,
    pub packets_submitted: u64,
    pub packets_scheduled: u64,
    pub packets_preconfirmed: u64,
    pub packets_settled: u64,
    pub handoffs_created: u64,
    pub handoffs_imported: u64,
    pub locks_acquired: u64,
    pub fences_installed: u64,
    pub rollbacks_recorded: u64,
    pub slashes_recorded: u64,
    pub total_fees_micro_xmr: u128,
    pub total_slash_micro_xmr: u128,
}

impl Counters {
    pub fn devnet() -> Self {
        Self {
            current_slot: 1,
            next_nonce: 1,
            packets_submitted: 0,
            packets_scheduled: 0,
            packets_preconfirmed: 0,
            packets_settled: 0,
            handoffs_created: 0,
            handoffs_imported: 0,
            locks_acquired: 0,
            fences_installed: 0,
            rollbacks_recorded: 0,
            slashes_recorded: 0,
            total_fees_micro_xmr: 0,
            total_slash_micro_xmr: 0,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "current_slot": self.current_slot,
            "next_nonce": self.next_nonce,
            "packets_submitted": self.packets_submitted,
            "packets_scheduled": self.packets_scheduled,
            "packets_preconfirmed": self.packets_preconfirmed,
            "packets_settled": self.packets_settled,
            "handoffs_created": self.handoffs_created,
            "handoffs_imported": self.handoffs_imported,
            "locks_acquired": self.locks_acquired,
            "fences_installed": self.fences_installed,
            "rollbacks_recorded": self.rollbacks_recorded,
            "slashes_recorded": self.slashes_recorded,
            "total_fees_micro_xmr": self.total_fees_micro_xmr.to_string(),
            "total_slash_micro_xmr": self.total_slash_micro_xmr.to_string(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub shard_root: String,
    pub packet_root: String,
    pub scheduler_attestation_root: String,
    pub state_lock_root: String,
    pub handoff_root: String,
    pub speculative_receipt_root: String,
    pub preconfirmation_root: String,
    pub fee_lane_root: String,
    pub witness_locality_root: String,
    pub nullifier_fence_root: String,
    pub rollback_evidence_root: String,
    pub slashing_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn empty() -> Self {
        let mut roots = Self {
            shard_root: merkle_root("P2PES-SHARD", &[]),
            packet_root: merkle_root("P2PES-PACKET", &[]),
            scheduler_attestation_root: merkle_root("P2PES-SCHEDULER-ATTESTATION", &[]),
            state_lock_root: merkle_root("P2PES-STATE-LOCK", &[]),
            handoff_root: merkle_root("P2PES-HANDOFF", &[]),
            speculative_receipt_root: merkle_root("P2PES-SPECULATIVE-RECEIPT", &[]),
            preconfirmation_root: merkle_root("P2PES-PRECONFIRMATION", &[]),
            fee_lane_root: merkle_root("P2PES-FEE-LANE", &[]),
            witness_locality_root: merkle_root("P2PES-WITNESS-LOCALITY", &[]),
            nullifier_fence_root: merkle_root("P2PES-NULLIFIER-FENCE", &[]),
            rollback_evidence_root: merkle_root("P2PES-ROLLBACK-EVIDENCE", &[]),
            slashing_root: merkle_root("P2PES-SLASHING", &[]),
            state_root: String::new(),
        };
        roots.state_root = root_from_value("P2PES-ROOTS", &roots.public_record_without_state());
        roots
    }

    pub fn public_record_without_state(&self) -> Value {
        json!({
            "shard_root": self.shard_root,
            "packet_root": self.packet_root,
            "scheduler_attestation_root": self.scheduler_attestation_root,
            "state_lock_root": self.state_lock_root,
            "handoff_root": self.handoff_root,
            "speculative_receipt_root": self.speculative_receipt_root,
            "preconfirmation_root": self.preconfirmation_root,
            "fee_lane_root": self.fee_lane_root,
            "witness_locality_root": self.witness_locality_root,
            "nullifier_fence_root": self.nullifier_fence_root,
            "rollback_evidence_root": self.rollback_evidence_root,
            "slashing_root": self.slashing_root,
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state();
        if let Value::Object(values) = &mut record {
            values.insert(
                "state_root".to_string(),
                Value::String(self.state_root.clone()),
            );
        }
        record
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivateExecutionShard {
    pub shard_id: String,
    pub shard_index: u64,
    pub operator_commitment: String,
    pub pq_scheduler_key_commitment: String,
    pub encrypted_state_root: String,
    pub local_lock_root: String,
    pub current_receipt_root: String,
    pub active_parallel_groups: BTreeSet<u64>,
    pub accepted_fee_lanes: BTreeSet<FeeLaneKind>,
    pub capacity_units: u64,
    pub load_units: u64,
}

impl PrivateExecutionShard {
    pub fn devnet(index: u64) -> Self {
        let shard_id = shard_id(index);
        let active_parallel_groups = (0..4).map(|offset| index * 4 + offset).collect();
        let accepted_fee_lanes = [
            FeeLaneKind::UltraLow,
            FeeLaneKind::Standard,
            FeeLaneKind::DefiPriority,
            FeeLaneKind::ContractPriority,
            FeeLaneKind::HandoffPriority,
        ]
        .into_iter()
        .collect();
        Self {
            operator_commitment: deterministic_id("P2PES-OPERATOR", &[&shard_id]),
            pq_scheduler_key_commitment: deterministic_id("P2PES-SCHEDULER-KEY", &[&shard_id]),
            encrypted_state_root: deterministic_id("P2PES-ENCRYPTED-STATE", &[&shard_id]),
            local_lock_root: merkle_root("P2PES-SHARD-LOCK", &[]),
            current_receipt_root: merkle_root("P2PES-SHARD-RECEIPT", &[]),
            shard_id,
            shard_index: index,
            active_parallel_groups,
            accepted_fee_lanes,
            capacity_units: 1_000_000,
            load_units: 0,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "accepted_fee_lanes": fee_lane_set_record(&self.accepted_fee_lanes),
            "active_parallel_groups": u64_set_record(&self.active_parallel_groups),
            "capacity_units": self.capacity_units,
            "current_receipt_root": self.current_receipt_root,
            "encrypted_state_root": self.encrypted_state_root,
            "load_units": self.load_units,
            "local_lock_root": self.local_lock_root,
            "operator_commitment": self.operator_commitment,
            "pq_scheduler_key_commitment": self.pq_scheduler_key_commitment,
            "shard_id": self.shard_id,
            "shard_index": self.shard_index,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EncryptedWorkPacket {
    pub packet_id: String,
    pub shard_id: String,
    pub packet_kind: PacketKind,
    pub status: PacketStatus,
    pub fee_lane: FeeLaneKind,
    pub sender_commitment: String,
    pub contract_commitment: String,
    pub ciphertext_commitment: String,
    pub ciphertext_bytes: u64,
    pub access_list_commitment: String,
    pub witness_hint_id: String,
    pub nullifier_commitments: BTreeSet<String>,
    pub read_keys: BTreeSet<String>,
    pub write_keys: BTreeSet<String>,
    pub dependency_packet_ids: BTreeSet<String>,
    pub max_fee_micro_xmr: u64,
    pub gas_limit: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub submitted_slot: u64,
    pub expiry_slot: u64,
    pub deterministic_nonce: u64,
}

impl EncryptedWorkPacket {
    pub fn public_record(&self) -> Value {
        json!({
            "access_list_commitment": self.access_list_commitment,
            "ciphertext_bytes": self.ciphertext_bytes,
            "ciphertext_commitment": self.ciphertext_commitment,
            "contract_commitment": self.contract_commitment,
            "dependency_packet_ids": string_set_record(&self.dependency_packet_ids),
            "deterministic_nonce": self.deterministic_nonce,
            "expiry_slot": self.expiry_slot,
            "fee_lane": self.fee_lane.as_str(),
            "gas_limit": self.gas_limit,
            "max_fee_micro_xmr": self.max_fee_micro_xmr,
            "nullifier_commitments": string_set_record(&self.nullifier_commitments),
            "packet_id": self.packet_id,
            "packet_kind": self.packet_kind.as_str(),
            "pq_security_bits": self.pq_security_bits,
            "privacy_set_size": self.privacy_set_size,
            "read_keys": string_set_record(&self.read_keys),
            "sender_commitment": self.sender_commitment,
            "shard_id": self.shard_id,
            "status": self.status.as_str(),
            "submitted_slot": self.submitted_slot,
            "witness_hint_id": self.witness_hint_id,
            "write_keys": string_set_record(&self.write_keys),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SchedulerAttestation {
    pub attestation_id: String,
    pub shard_id: String,
    pub scheduler_commitment: String,
    pub packet_ids: BTreeSet<String>,
    pub parallel_group: u64,
    pub fee_lane: FeeLaneKind,
    pub read_set_root: String,
    pub write_set_root: String,
    pub nullifier_root: String,
    pub witness_locality_root: String,
    pub pq_signature_commitment: String,
    pub status: AttestationStatus,
    pub slot: u64,
}

impl SchedulerAttestation {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "fee_lane": self.fee_lane.as_str(),
            "nullifier_root": self.nullifier_root,
            "packet_ids": string_set_record(&self.packet_ids),
            "parallel_group": self.parallel_group,
            "pq_signature_commitment": self.pq_signature_commitment,
            "read_set_root": self.read_set_root,
            "scheduler_commitment": self.scheduler_commitment,
            "shard_id": self.shard_id,
            "slot": self.slot,
            "status": format!("{:?}", self.status).to_lowercase(),
            "witness_locality_root": self.witness_locality_root,
            "write_set_root": self.write_set_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ShardStateLock {
    pub lock_id: String,
    pub shard_id: String,
    pub packet_id: String,
    pub state_key_commitment: String,
    pub mode: LockMode,
    pub parallel_group: u64,
    pub acquired_slot: u64,
    pub release_slot: u64,
    pub fence_id: String,
}

impl ShardStateLock {
    pub fn public_record(&self) -> Value {
        json!({
            "acquired_slot": self.acquired_slot,
            "fence_id": self.fence_id,
            "lock_id": self.lock_id,
            "mode": self.mode.as_str(),
            "packet_id": self.packet_id,
            "parallel_group": self.parallel_group,
            "release_slot": self.release_slot,
            "shard_id": self.shard_id,
            "state_key_commitment": self.state_key_commitment,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CrossShardHandoffCommitment {
    pub handoff_id: String,
    pub source_shard_id: String,
    pub target_shard_id: String,
    pub packet_id: String,
    pub encrypted_payload_commitment: String,
    pub source_receipt_root: String,
    pub target_import_root: String,
    pub nullifier_fence_root: String,
    pub status: HandoffStatus,
    pub created_slot: u64,
    pub expiry_slot: u64,
}

impl CrossShardHandoffCommitment {
    pub fn public_record(&self) -> Value {
        json!({
            "created_slot": self.created_slot,
            "encrypted_payload_commitment": self.encrypted_payload_commitment,
            "expiry_slot": self.expiry_slot,
            "handoff_id": self.handoff_id,
            "nullifier_fence_root": self.nullifier_fence_root,
            "packet_id": self.packet_id,
            "source_receipt_root": self.source_receipt_root,
            "source_shard_id": self.source_shard_id,
            "status": format!("{:?}", self.status).to_lowercase(),
            "target_import_root": self.target_import_root,
            "target_shard_id": self.target_shard_id,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SpeculativeReceipt {
    pub receipt_id: String,
    pub packet_id: String,
    pub shard_id: String,
    pub attestation_id: String,
    pub result_commitment: String,
    pub state_diff_commitment: String,
    pub local_receipt_root: String,
    pub fee_charged_micro_xmr: u64,
    pub compute_units: u64,
    pub emitted_event_root: String,
    pub slot: u64,
}

impl SpeculativeReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "compute_units": self.compute_units,
            "emitted_event_root": self.emitted_event_root,
            "fee_charged_micro_xmr": self.fee_charged_micro_xmr,
            "local_receipt_root": self.local_receipt_root,
            "packet_id": self.packet_id,
            "receipt_id": self.receipt_id,
            "result_commitment": self.result_commitment,
            "shard_id": self.shard_id,
            "slot": self.slot,
            "state_diff_commitment": self.state_diff_commitment,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PreconfirmationCheckpoint {
    pub checkpoint_id: String,
    pub shard_id: String,
    pub packet_ids: BTreeSet<String>,
    pub receipt_root: String,
    pub lock_root: String,
    pub handoff_root: String,
    pub scheduler_attestation_root: String,
    pub sequencer_commitment: String,
    pub pq_signature_commitment: String,
    pub slot: u64,
    pub expiry_slot: u64,
}

impl PreconfirmationCheckpoint {
    pub fn public_record(&self) -> Value {
        json!({
            "checkpoint_id": self.checkpoint_id,
            "expiry_slot": self.expiry_slot,
            "handoff_root": self.handoff_root,
            "lock_root": self.lock_root,
            "packet_ids": string_set_record(&self.packet_ids),
            "pq_signature_commitment": self.pq_signature_commitment,
            "receipt_root": self.receipt_root,
            "scheduler_attestation_root": self.scheduler_attestation_root,
            "sequencer_commitment": self.sequencer_commitment,
            "shard_id": self.shard_id,
            "slot": self.slot,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FeeLane {
    pub lane_id: String,
    pub kind: FeeLaneKind,
    pub base_fee_micro_xmr: u64,
    pub multiplier_bps: u64,
    pub target_latency_slots: u64,
    pub pending_packet_ids: BTreeSet<String>,
    pub collected_fee_micro_xmr: u128,
}

impl FeeLane {
    pub fn devnet(kind: FeeLaneKind, base_fee_micro_xmr: u64) -> Self {
        Self {
            lane_id: deterministic_id("P2PES-FEE-LANE-ID", &[kind.as_str()]),
            kind,
            base_fee_micro_xmr,
            multiplier_bps: kind.multiplier_bps(),
            target_latency_slots: match kind {
                FeeLaneKind::Emergency => 1,
                FeeLaneKind::DefiPriority | FeeLaneKind::ContractPriority => 2,
                FeeLaneKind::HandoffPriority => 3,
                FeeLaneKind::Standard => 4,
                FeeLaneKind::UltraLow => 8,
            },
            pending_packet_ids: BTreeSet::new(),
            collected_fee_micro_xmr: 0,
        }
    }

    pub fn quote_fee(&self, gas_limit: u64) -> u64 {
        let units = gas_limit.max(1).div_ceil(1_000);
        self.base_fee_micro_xmr
            .saturating_mul(units)
            .saturating_mul(self.multiplier_bps)
            / MAX_BPS
    }

    pub fn public_record(&self) -> Value {
        json!({
            "base_fee_micro_xmr": self.base_fee_micro_xmr,
            "collected_fee_micro_xmr": self.collected_fee_micro_xmr.to_string(),
            "kind": self.kind.as_str(),
            "lane_id": self.lane_id,
            "multiplier_bps": self.multiplier_bps,
            "pending_packet_ids": string_set_record(&self.pending_packet_ids),
            "target_latency_slots": self.target_latency_slots,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WitnessLocalityHint {
    pub hint_id: String,
    pub shard_id: String,
    pub packet_id: String,
    pub witness_region_commitment: String,
    pub encrypted_witness_root: String,
    pub locality_score: u64,
    pub cache_key_commitments: BTreeSet<String>,
}

impl WitnessLocalityHint {
    pub fn public_record(&self) -> Value {
        json!({
            "cache_key_commitments": string_set_record(&self.cache_key_commitments),
            "encrypted_witness_root": self.encrypted_witness_root,
            "hint_id": self.hint_id,
            "locality_score": self.locality_score,
            "packet_id": self.packet_id,
            "shard_id": self.shard_id,
            "witness_region_commitment": self.witness_region_commitment,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NullifierFence {
    pub fence_id: String,
    pub shard_id: String,
    pub packet_id: String,
    pub nullifier_commitment: String,
    pub conflict_domain: String,
    pub installed_slot: u64,
    pub expiry_slot: u64,
}

impl NullifierFence {
    pub fn public_record(&self) -> Value {
        json!({
            "conflict_domain": self.conflict_domain,
            "expiry_slot": self.expiry_slot,
            "fence_id": self.fence_id,
            "installed_slot": self.installed_slot,
            "nullifier_commitment": self.nullifier_commitment,
            "packet_id": self.packet_id,
            "shard_id": self.shard_id,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RollbackReorgEvidence {
    pub evidence_id: String,
    pub kind: EvidenceKind,
    pub shard_id: String,
    pub packet_id: String,
    pub bad_root: String,
    pub expected_root: String,
    pub conflicting_record_ids: BTreeSet<String>,
    pub challenger_commitment: String,
    pub slot: u64,
}

impl RollbackReorgEvidence {
    pub fn public_record(&self) -> Value {
        json!({
            "bad_root": self.bad_root,
            "challenger_commitment": self.challenger_commitment,
            "conflicting_record_ids": string_set_record(&self.conflicting_record_ids),
            "evidence_id": self.evidence_id,
            "expected_root": self.expected_root,
            "kind": format!("{:?}", self.kind).to_lowercase(),
            "packet_id": self.packet_id,
            "shard_id": self.shard_id,
            "slot": self.slot,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SlashingRecord {
    pub slashing_id: String,
    pub evidence_id: String,
    pub shard_id: String,
    pub offender_commitment: String,
    pub reason: EvidenceKind,
    pub slash_micro_xmr: u64,
    pub redistribution_root: String,
    pub slot: u64,
}

impl SlashingRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "evidence_id": self.evidence_id,
            "offender_commitment": self.offender_commitment,
            "reason": format!("{:?}", self.reason).to_lowercase(),
            "redistribution_root": self.redistribution_root,
            "shard_id": self.shard_id,
            "slash_micro_xmr": self.slash_micro_xmr,
            "slashing_id": self.slashing_id,
            "slot": self.slot,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub shards: BTreeMap<String, PrivateExecutionShard>,
    pub packets: BTreeMap<String, EncryptedWorkPacket>,
    pub scheduler_attestations: BTreeMap<String, SchedulerAttestation>,
    pub state_locks: BTreeMap<String, ShardStateLock>,
    pub handoffs: BTreeMap<String, CrossShardHandoffCommitment>,
    pub speculative_receipts: BTreeMap<String, SpeculativeReceipt>,
    pub preconfirmations: BTreeMap<String, PreconfirmationCheckpoint>,
    pub fee_lanes: BTreeMap<String, FeeLane>,
    pub witness_hints: BTreeMap<String, WitnessLocalityHint>,
    pub nullifier_fences: BTreeMap<String, NullifierFence>,
    pub rollback_evidence: BTreeMap<String, RollbackReorgEvidence>,
    pub slashing_records: BTreeMap<String, SlashingRecord>,
}

impl State {
    pub fn devnet() -> Self {
        let config = Config::devnet();
        let counters = Counters::devnet();
        let mut shards = BTreeMap::new();
        for index in 0..config.shard_count {
            let shard = PrivateExecutionShard::devnet(index);
            shards.insert(shard.shard_id.clone(), shard);
        }
        let mut fee_lanes = BTreeMap::new();
        for kind in [
            FeeLaneKind::UltraLow,
            FeeLaneKind::Standard,
            FeeLaneKind::DefiPriority,
            FeeLaneKind::ContractPriority,
            FeeLaneKind::HandoffPriority,
            FeeLaneKind::Emergency,
        ] {
            let lane = FeeLane::devnet(kind, config.base_fee_micro_xmr);
            fee_lanes.insert(lane.lane_id.clone(), lane);
        }
        let mut state = Self {
            config,
            counters,
            roots: Roots::empty(),
            shards,
            packets: BTreeMap::new(),
            scheduler_attestations: BTreeMap::new(),
            state_locks: BTreeMap::new(),
            handoffs: BTreeMap::new(),
            speculative_receipts: BTreeMap::new(),
            preconfirmations: BTreeMap::new(),
            fee_lanes,
            witness_hints: BTreeMap::new(),
            nullifier_fences: BTreeMap::new(),
            rollback_evidence: BTreeMap::new(),
            slashing_records: BTreeMap::new(),
        };
        state.refresh_roots();
        state
    }

    pub fn validate_config(&self) -> Result<()> {
        self.config.validate()
    }

    pub fn state_root(&self) -> String {
        root_from_value("P2PES-STATE", &self.public_record_without_state_root())
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        if let Value::Object(values) = &mut record {
            values.insert("state_root".to_string(), Value::String(self.state_root()));
        }
        record
    }

    fn public_record_without_state_root(&self) -> Value {
        json!({
            "config": {
                "base_fee_micro_xmr": self.config.base_fee_micro_xmr,
                "chain_id": self.config.chain_id,
                "deterministic_ordering": self.config.deterministic_ordering,
                "handoff_ttl_slots": self.config.handoff_ttl_slots,
                "low_fee_cap_bps": self.config.low_fee_cap_bps,
                "max_locks_per_packet": self.config.max_locks_per_packet,
                "max_parallel_groups": self.config.max_parallel_groups,
                "min_pq_security_bits": self.config.min_pq_security_bits,
                "min_privacy_set_size": self.config.min_privacy_set_size,
                "packet_ttl_slots": self.config.packet_ttl_slots,
                "preconfirmation_ttl_slots": self.config.preconfirmation_ttl_slots,
                "protocol_version": self.config.protocol_version,
                "shard_count": self.config.shard_count,
                "slash_bps": self.config.slash_bps,
            },
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record_without_state(),
        })
    }

    pub fn submit_packet(
        &mut self,
        shard_id: &str,
        packet_kind: PacketKind,
        fee_lane: FeeLaneKind,
        sender_commitment: &str,
        contract_commitment: &str,
        ciphertext_commitment: &str,
        gas_limit: u64,
        max_fee_micro_xmr: u64,
        read_keys: BTreeSet<String>,
        write_keys: BTreeSet<String>,
        nullifier_commitments: BTreeSet<String>,
    ) -> Result<String> {
        self.validate_config()?;
        if !self.shards.contains_key(shard_id) {
            return Err("unknown shard".to_string());
        }
        if read_keys.len() + write_keys.len() + nullifier_commitments.len()
            > self.config.max_locks_per_packet
        {
            return Err("packet lock footprint exceeds configured maximum".to_string());
        }
        if gas_limit == 0 {
            return Err("gas limit must be nonzero".to_string());
        }
        let fee_quote = self.quote_fee(fee_lane, gas_limit)?;
        if max_fee_micro_xmr < fee_quote {
            return Err("max fee is below deterministic lane quote".to_string());
        }
        let nonce = self.take_nonce();
        let packet_id = work_packet_id(
            shard_id,
            sender_commitment,
            contract_commitment,
            ciphertext_commitment,
            nonce,
        );
        let witness_hint_id = deterministic_id("P2PES-WITNESS-HINT-ID", &[&packet_id]);
        let packet = EncryptedWorkPacket {
            packet_id: packet_id.clone(),
            shard_id: shard_id.to_string(),
            packet_kind,
            status: PacketStatus::Submitted,
            fee_lane,
            sender_commitment: sender_commitment.to_string(),
            contract_commitment: contract_commitment.to_string(),
            ciphertext_commitment: ciphertext_commitment.to_string(),
            ciphertext_bytes: 4096 + gas_limit.div_ceil(64),
            access_list_commitment: access_list_commitment(&read_keys, &write_keys),
            witness_hint_id: witness_hint_id.clone(),
            nullifier_commitments,
            read_keys,
            write_keys,
            dependency_packet_ids: BTreeSet::new(),
            max_fee_micro_xmr,
            gas_limit,
            privacy_set_size: self.config.min_privacy_set_size,
            pq_security_bits: self.config.min_pq_security_bits,
            submitted_slot: self.counters.current_slot,
            expiry_slot: self.counters.current_slot + self.config.packet_ttl_slots,
            deterministic_nonce: nonce,
        };
        let hint = WitnessLocalityHint {
            hint_id: witness_hint_id,
            shard_id: shard_id.to_string(),
            packet_id: packet_id.clone(),
            witness_region_commitment: deterministic_id("P2PES-WITNESS-REGION", &[shard_id]),
            encrypted_witness_root: encrypted_witness_root_for_packet(&packet),
            locality_score: locality_score(shard_id, &packet_id),
            cache_key_commitments: packet
                .read_keys
                .iter()
                .chain(packet.write_keys.iter())
                .map(|key| deterministic_id("P2PES-WITNESS-CACHE-KEY", &[key]))
                .collect(),
        };
        self.packets.insert(packet_id.clone(), packet);
        self.witness_hints.insert(hint.hint_id.clone(), hint);
        if let Some(lane) = self
            .fee_lanes
            .get_mut(&deterministic_id("P2PES-FEE-LANE-ID", &[fee_lane.as_str()]))
        {
            lane.pending_packet_ids.insert(packet_id.clone());
        }
        self.counters.packets_submitted += 1;
        self.refresh_roots();
        Ok(packet_id)
    }

    pub fn install_nullifier_fences(&mut self, packet_id: &str) -> Result<Vec<String>> {
        let packet = self.packet(packet_id)?.clone();
        if packet.status != PacketStatus::Submitted {
            return Err("packet is not in submitted state".to_string());
        }
        let mut fence_ids = Vec::new();
        for nullifier in &packet.nullifier_commitments {
            let conflict_domain = deterministic_id("P2PES-CONFLICT-DOMAIN", &[&packet.shard_id]);
            let fence_id = nullifier_fence_id(&packet.shard_id, packet_id, nullifier);
            if self.nullifier_fences.contains_key(&fence_id) {
                return Err("duplicate nullifier fence".to_string());
            }
            let fence = NullifierFence {
                fence_id: fence_id.clone(),
                shard_id: packet.shard_id.clone(),
                packet_id: packet_id.to_string(),
                nullifier_commitment: nullifier.clone(),
                conflict_domain,
                installed_slot: self.counters.current_slot,
                expiry_slot: packet.expiry_slot,
            };
            self.nullifier_fences.insert(fence_id.clone(), fence);
            fence_ids.push(fence_id);
            self.counters.fences_installed += 1;
        }
        if let Some(packet) = self.packets.get_mut(packet_id) {
            packet.status = PacketStatus::Fenced;
        }
        self.refresh_roots();
        Ok(fence_ids)
    }

    pub fn schedule_parallel_group(
        &mut self,
        shard_id: &str,
        scheduler_commitment: &str,
        packet_ids: BTreeSet<String>,
        parallel_group: u64,
    ) -> Result<String> {
        if packet_ids.is_empty() {
            return Err("packet set is empty".to_string());
        }
        let shard = self
            .shards
            .get(shard_id)
            .ok_or_else(|| "unknown shard".to_string())?;
        if !shard.active_parallel_groups.contains(&parallel_group) {
            return Err("parallel group is not active on shard".to_string());
        }
        let mut read_keys = BTreeSet::new();
        let mut write_keys = BTreeSet::new();
        let mut nullifiers = BTreeSet::new();
        let mut fee_lane = FeeLaneKind::UltraLow;
        for packet_id in &packet_ids {
            let packet = self.packet(packet_id)?;
            if packet.shard_id != shard_id {
                return Err("packet belongs to a different shard".to_string());
            }
            if !matches!(
                packet.status,
                PacketStatus::Submitted | PacketStatus::Fenced
            ) {
                return Err("packet is not schedulable".to_string());
            }
            fee_lane = packet.fee_lane;
            for key in &packet.read_keys {
                read_keys.insert(key.clone());
            }
            for key in &packet.write_keys {
                if read_keys.contains(key) {
                    return Err("read/write conflict inside scheduled group".to_string());
                }
                if !write_keys.insert(key.clone()) {
                    return Err("duplicate write key inside scheduled group".to_string());
                }
            }
            for nullifier in &packet.nullifier_commitments {
                if !nullifiers.insert(nullifier.clone()) {
                    return Err("duplicate nullifier inside scheduled group".to_string());
                }
            }
        }
        let read_set_root = string_set_root("P2PES-READ-SET", &read_keys);
        let write_set_root = string_set_root("P2PES-WRITE-SET", &write_keys);
        let nullifier_root = string_set_root("P2PES-NULLIFIER-SET", &nullifiers);
        let witness_locality_root = merkle_root(
            "P2PES-SCHEDULE-WITNESS-HINT",
            &packet_ids
                .iter()
                .filter_map(|id| self.packets.get(id))
                .filter_map(|packet| self.witness_hints.get(&packet.witness_hint_id))
                .map(WitnessLocalityHint::public_record)
                .collect::<Vec<_>>(),
        );
        let attestation_id = scheduler_attestation_id(
            shard_id,
            scheduler_commitment,
            &packet_ids,
            parallel_group,
            self.counters.current_slot,
        );
        let pq_signature_commitment = deterministic_id(
            "P2PES-SCHEDULER-PQ-SIGNATURE",
            &[&attestation_id, scheduler_commitment],
        );
        let attestation = SchedulerAttestation {
            attestation_id: attestation_id.clone(),
            shard_id: shard_id.to_string(),
            scheduler_commitment: scheduler_commitment.to_string(),
            packet_ids: packet_ids.clone(),
            parallel_group,
            fee_lane,
            read_set_root,
            write_set_root,
            nullifier_root,
            witness_locality_root,
            pq_signature_commitment,
            status: AttestationStatus::Accepted,
            slot: self.counters.current_slot,
        };
        for packet_id in packet_ids {
            if let Some(packet) = self.packets.get_mut(&packet_id) {
                packet.status = PacketStatus::Scheduled;
            }
        }
        self.scheduler_attestations
            .insert(attestation_id.clone(), attestation);
        self.counters.packets_scheduled += 1;
        self.refresh_roots();
        Ok(attestation_id)
    }

    pub fn acquire_locks(&mut self, attestation_id: &str) -> Result<Vec<String>> {
        let attestation = self.attestation(attestation_id)?.clone();
        if attestation.status != AttestationStatus::Accepted {
            return Err("attestation is not accepted".to_string());
        }
        let mut new_locks = Vec::new();
        for packet_id in &attestation.packet_ids {
            let packet = self.packet(packet_id)?.clone();
            for key in &packet.read_keys {
                let lock_id = state_lock_id(&packet.shard_id, packet_id, key, LockMode::Read);
                self.assert_lock_available(&packet.shard_id, key, LockMode::Read, &lock_id)?;
                self.state_locks.insert(
                    lock_id.clone(),
                    ShardStateLock {
                        lock_id: lock_id.clone(),
                        shard_id: packet.shard_id.clone(),
                        packet_id: packet_id.clone(),
                        state_key_commitment: key.clone(),
                        mode: LockMode::Read,
                        parallel_group: attestation.parallel_group,
                        acquired_slot: self.counters.current_slot,
                        release_slot: self.counters.current_slot + self.config.packet_ttl_slots,
                        fence_id: deterministic_id("P2PES-READ-FENCE", &[packet_id, key]),
                    },
                );
                new_locks.push(lock_id);
            }
            for key in &packet.write_keys {
                let lock_id = state_lock_id(&packet.shard_id, packet_id, key, LockMode::Write);
                self.assert_lock_available(&packet.shard_id, key, LockMode::Write, &lock_id)?;
                self.state_locks.insert(
                    lock_id.clone(),
                    ShardStateLock {
                        lock_id: lock_id.clone(),
                        shard_id: packet.shard_id.clone(),
                        packet_id: packet_id.clone(),
                        state_key_commitment: key.clone(),
                        mode: LockMode::Write,
                        parallel_group: attestation.parallel_group,
                        acquired_slot: self.counters.current_slot,
                        release_slot: self.counters.current_slot + self.config.packet_ttl_slots,
                        fence_id: deterministic_id("P2PES-WRITE-FENCE", &[packet_id, key]),
                    },
                );
                new_locks.push(lock_id);
            }
            if let Some(packet) = self.packets.get_mut(packet_id) {
                packet.status = PacketStatus::Locked;
            }
        }
        self.counters.locks_acquired += new_locks.len() as u64;
        self.refresh_roots();
        Ok(new_locks)
    }

    pub fn execute_speculative(
        &mut self,
        packet_id: &str,
        attestation_id: &str,
        result_commitment: &str,
        state_diff_commitment: &str,
        compute_units: u64,
    ) -> Result<String> {
        let packet = self.packet(packet_id)?.clone();
        if packet.status != PacketStatus::Locked {
            return Err("packet is not locked for execution".to_string());
        }
        let attestation = self.attestation(attestation_id)?;
        if !attestation.packet_ids.contains(packet_id) {
            return Err("attestation does not cover packet".to_string());
        }
        let fee = self.quote_fee(packet.fee_lane, packet.gas_limit)?;
        if fee > packet.max_fee_micro_xmr {
            return Err("quoted fee exceeds packet maximum".to_string());
        }
        let receipt_id = speculative_receipt_id(packet_id, attestation_id, result_commitment);
        let emitted_event_root =
            deterministic_id("P2PES-EVENT-ROOT", &[packet_id, result_commitment]);
        let local_receipt_root = root_from_value(
            "P2PES-LOCAL-RECEIPT",
            &json!({
                "attestation_id": attestation_id,
                "compute_units": compute_units,
                "emitted_event_root": emitted_event_root,
                "packet_id": packet_id,
                "result_commitment": result_commitment,
                "state_diff_commitment": state_diff_commitment,
            }),
        );
        let receipt = SpeculativeReceipt {
            receipt_id: receipt_id.clone(),
            packet_id: packet_id.to_string(),
            shard_id: packet.shard_id.clone(),
            attestation_id: attestation_id.to_string(),
            result_commitment: result_commitment.to_string(),
            state_diff_commitment: state_diff_commitment.to_string(),
            local_receipt_root: local_receipt_root.clone(),
            fee_charged_micro_xmr: fee,
            compute_units,
            emitted_event_root,
            slot: self.counters.current_slot,
        };
        self.speculative_receipts
            .insert(receipt_id.clone(), receipt);
        if let Some(packet) = self.packets.get_mut(packet_id) {
            packet.status = PacketStatus::ExecutedSpeculative;
        }
        if let Some(shard) = self.shards.get_mut(&packet.shard_id) {
            shard.load_units = shard.load_units.saturating_add(compute_units);
            shard.current_receipt_root = local_receipt_root;
        }
        let lane_id = deterministic_id("P2PES-FEE-LANE-ID", &[packet.fee_lane.as_str()]);
        if let Some(lane) = self.fee_lanes.get_mut(&lane_id) {
            lane.pending_packet_ids.remove(packet_id);
            lane.collected_fee_micro_xmr = lane.collected_fee_micro_xmr.saturating_add(fee as u128);
        }
        self.counters.total_fees_micro_xmr = self
            .counters
            .total_fees_micro_xmr
            .saturating_add(fee as u128);
        self.refresh_roots();
        Ok(receipt_id)
    }

    pub fn create_preconfirmation(
        &mut self,
        shard_id: &str,
        sequencer_commitment: &str,
        packet_ids: BTreeSet<String>,
    ) -> Result<String> {
        if packet_ids.is_empty() {
            return Err("preconfirmation packet set is empty".to_string());
        }
        for packet_id in &packet_ids {
            let packet = self.packet(packet_id)?;
            if packet.shard_id != shard_id {
                return Err("preconfirmation crosses shard boundary".to_string());
            }
            if packet.status != PacketStatus::ExecutedSpeculative {
                return Err("packet lacks speculative receipt".to_string());
            }
        }
        let receipt_records = self
            .speculative_receipts
            .values()
            .filter(|receipt| packet_ids.contains(&receipt.packet_id))
            .map(SpeculativeReceipt::public_record)
            .collect::<Vec<_>>();
        let lock_records = self
            .state_locks
            .values()
            .filter(|lock| packet_ids.contains(&lock.packet_id))
            .map(ShardStateLock::public_record)
            .collect::<Vec<_>>();
        let checkpoint_id = preconfirmation_id(
            shard_id,
            sequencer_commitment,
            &packet_ids,
            self.counters.current_slot,
        );
        let receipt_root = merkle_root("P2PES-PRECONF-RECEIPT", &receipt_records);
        let lock_root = merkle_root("P2PES-PRECONF-LOCK", &lock_records);
        let handoff_root = self.roots.handoff_root.clone();
        let scheduler_attestation_root = self.roots.scheduler_attestation_root.clone();
        let checkpoint = PreconfirmationCheckpoint {
            checkpoint_id: checkpoint_id.clone(),
            shard_id: shard_id.to_string(),
            packet_ids: packet_ids.clone(),
            receipt_root,
            lock_root,
            handoff_root,
            scheduler_attestation_root,
            sequencer_commitment: sequencer_commitment.to_string(),
            pq_signature_commitment: deterministic_id(
                "P2PES-PRECONF-PQ-SIGNATURE",
                &[&checkpoint_id, sequencer_commitment],
            ),
            slot: self.counters.current_slot,
            expiry_slot: self.counters.current_slot + self.config.preconfirmation_ttl_slots,
        };
        for packet_id in packet_ids {
            if let Some(packet) = self.packets.get_mut(&packet_id) {
                packet.status = PacketStatus::Preconfirmed;
            }
        }
        self.preconfirmations
            .insert(checkpoint_id.clone(), checkpoint);
        self.counters.packets_preconfirmed += 1;
        self.refresh_roots();
        Ok(checkpoint_id)
    }

    pub fn create_handoff(
        &mut self,
        packet_id: &str,
        target_shard_id: &str,
        encrypted_payload_commitment: &str,
    ) -> Result<String> {
        let packet = self.packet(packet_id)?.clone();
        if !self.shards.contains_key(target_shard_id) {
            return Err("target shard is unknown".to_string());
        }
        if packet.shard_id == target_shard_id {
            return Err("handoff target must differ from source shard".to_string());
        }
        if !matches!(
            packet.status,
            PacketStatus::Preconfirmed | PacketStatus::ExecutedSpeculative
        ) {
            return Err("packet is not ready for handoff".to_string());
        }
        let nullifier_records = self
            .nullifier_fences
            .values()
            .filter(|fence| fence.packet_id == packet_id)
            .map(NullifierFence::public_record)
            .collect::<Vec<_>>();
        let handoff_id = cross_shard_handoff_id(
            &packet.shard_id,
            target_shard_id,
            packet_id,
            encrypted_payload_commitment,
        );
        let handoff = CrossShardHandoffCommitment {
            handoff_id: handoff_id.clone(),
            source_shard_id: packet.shard_id.clone(),
            target_shard_id: target_shard_id.to_string(),
            packet_id: packet_id.to_string(),
            encrypted_payload_commitment: encrypted_payload_commitment.to_string(),
            source_receipt_root: self.roots.speculative_receipt_root.clone(),
            target_import_root: deterministic_id(
                "P2PES-TARGET-IMPORT-ROOT",
                &[target_shard_id, packet_id],
            ),
            nullifier_fence_root: merkle_root("P2PES-HANDOFF-NULLIFIER", &nullifier_records),
            status: HandoffStatus::Prepared,
            created_slot: self.counters.current_slot,
            expiry_slot: self.counters.current_slot + self.config.handoff_ttl_slots,
        };
        self.handoffs.insert(handoff_id.clone(), handoff);
        if let Some(packet) = self.packets.get_mut(packet_id) {
            packet.status = PacketStatus::HandedOff;
        }
        self.counters.handoffs_created += 1;
        self.refresh_roots();
        Ok(handoff_id)
    }

    pub fn import_handoff(&mut self, handoff_id: &str) -> Result<()> {
        let handoff = self
            .handoffs
            .get_mut(handoff_id)
            .ok_or_else(|| "handoff not found".to_string())?;
        if handoff.expiry_slot < self.counters.current_slot {
            handoff.status = HandoffStatus::Expired;
            self.refresh_roots();
            return Err("handoff expired".to_string());
        }
        if handoff.status != HandoffStatus::Prepared && handoff.status != HandoffStatus::Exported {
            return Err("handoff is not importable".to_string());
        }
        handoff.status = HandoffStatus::Imported;
        self.counters.handoffs_imported += 1;
        self.refresh_roots();
        Ok(())
    }

    pub fn settle_packet(&mut self, packet_id: &str) -> Result<()> {
        let packet = self.packet(packet_id)?.clone();
        if !matches!(
            packet.status,
            PacketStatus::Preconfirmed | PacketStatus::HandedOff
        ) {
            return Err("packet is not settleable".to_string());
        }
        if let Some(packet) = self.packets.get_mut(packet_id) {
            packet.status = PacketStatus::Settled;
        }
        self.release_packet_locks(packet_id);
        self.counters.packets_settled += 1;
        self.refresh_roots();
        Ok(())
    }

    pub fn record_rollback_evidence(
        &mut self,
        kind: EvidenceKind,
        shard_id: &str,
        packet_id: &str,
        bad_root: &str,
        expected_root: &str,
        conflicting_record_ids: BTreeSet<String>,
        challenger_commitment: &str,
    ) -> Result<String> {
        if !self.shards.contains_key(shard_id) {
            return Err("unknown shard".to_string());
        }
        if !self.packets.contains_key(packet_id) {
            return Err("unknown packet".to_string());
        }
        let evidence_id = rollback_evidence_id(
            shard_id,
            packet_id,
            bad_root,
            expected_root,
            self.counters.current_slot,
        );
        let evidence = RollbackReorgEvidence {
            evidence_id: evidence_id.clone(),
            kind,
            shard_id: shard_id.to_string(),
            packet_id: packet_id.to_string(),
            bad_root: bad_root.to_string(),
            expected_root: expected_root.to_string(),
            conflicting_record_ids,
            challenger_commitment: challenger_commitment.to_string(),
            slot: self.counters.current_slot,
        };
        self.rollback_evidence.insert(evidence_id.clone(), evidence);
        if let Some(packet) = self.packets.get_mut(packet_id) {
            packet.status = PacketStatus::RolledBack;
        }
        self.release_packet_locks(packet_id);
        self.counters.rollbacks_recorded += 1;
        self.refresh_roots();
        Ok(evidence_id)
    }

    pub fn slash_scheduler(
        &mut self,
        evidence_id: &str,
        offender_commitment: &str,
    ) -> Result<String> {
        let evidence = self
            .rollback_evidence
            .get(evidence_id)
            .ok_or_else(|| "evidence not found".to_string())?
            .clone();
        let base = self.config.base_fee_micro_xmr.saturating_mul(1_000);
        let slash_micro_xmr = base.saturating_mul(self.config.slash_bps) / MAX_BPS;
        let redistribution_root = deterministic_id(
            "P2PES-SLASH-REDISTRIBUTION",
            &[evidence_id, offender_commitment],
        );
        let slashing_id = slashing_id(
            evidence_id,
            &evidence.shard_id,
            offender_commitment,
            self.counters.current_slot,
        );
        let record = SlashingRecord {
            slashing_id: slashing_id.clone(),
            evidence_id: evidence_id.to_string(),
            shard_id: evidence.shard_id.clone(),
            offender_commitment: offender_commitment.to_string(),
            reason: evidence.kind,
            slash_micro_xmr,
            redistribution_root,
            slot: self.counters.current_slot,
        };
        self.slashing_records.insert(slashing_id.clone(), record);
        self.counters.slashes_recorded += 1;
        self.counters.total_slash_micro_xmr = self
            .counters
            .total_slash_micro_xmr
            .saturating_add(slash_micro_xmr as u128);
        for attestation in self.scheduler_attestations.values_mut() {
            if attestation.scheduler_commitment == offender_commitment {
                attestation.status = AttestationStatus::Slashed;
            }
        }
        self.refresh_roots();
        Ok(slashing_id)
    }

    pub fn advance_slot(&mut self, slots: u64) -> Result<()> {
        if slots == 0 {
            return Err("slot advance must be nonzero".to_string());
        }
        self.counters.current_slot = self.counters.current_slot.saturating_add(slots);
        let current = self.counters.current_slot;
        let expired_packets = self
            .packets
            .iter()
            .filter(|(_, packet)| {
                packet.expiry_slot < current && packet.status != PacketStatus::Settled
            })
            .map(|(id, _)| id.clone())
            .collect::<Vec<_>>();
        for packet_id in expired_packets {
            if let Some(packet) = self.packets.get_mut(&packet_id) {
                packet.status = PacketStatus::Expired;
            }
            self.release_packet_locks(&packet_id);
        }
        for handoff in self.handoffs.values_mut() {
            if handoff.expiry_slot < current
                && !matches!(
                    handoff.status,
                    HandoffStatus::Imported | HandoffStatus::Acknowledged
                )
            {
                handoff.status = HandoffStatus::Expired;
            }
        }
        self.refresh_roots();
        Ok(())
    }

    pub fn quote_fee(&self, lane: FeeLaneKind, gas_limit: u64) -> Result<u64> {
        let lane_id = deterministic_id("P2PES-FEE-LANE-ID", &[lane.as_str()]);
        self.fee_lanes
            .get(&lane_id)
            .map(|lane| lane.quote_fee(gas_limit))
            .ok_or_else(|| "fee lane not found".to_string())
    }

    pub fn refresh_roots(&mut self) {
        self.roots = Roots {
            shard_root: merkle_record_root(
                "P2PES-SHARD",
                self.shards
                    .values()
                    .map(PrivateExecutionShard::public_record),
            ),
            packet_root: merkle_record_root(
                "P2PES-PACKET",
                self.packets
                    .values()
                    .map(EncryptedWorkPacket::public_record),
            ),
            scheduler_attestation_root: merkle_record_root(
                "P2PES-SCHEDULER-ATTESTATION",
                self.scheduler_attestations
                    .values()
                    .map(SchedulerAttestation::public_record),
            ),
            state_lock_root: merkle_record_root(
                "P2PES-STATE-LOCK",
                self.state_locks.values().map(ShardStateLock::public_record),
            ),
            handoff_root: merkle_record_root(
                "P2PES-HANDOFF",
                self.handoffs
                    .values()
                    .map(CrossShardHandoffCommitment::public_record),
            ),
            speculative_receipt_root: merkle_record_root(
                "P2PES-SPECULATIVE-RECEIPT",
                self.speculative_receipts
                    .values()
                    .map(SpeculativeReceipt::public_record),
            ),
            preconfirmation_root: merkle_record_root(
                "P2PES-PRECONFIRMATION",
                self.preconfirmations
                    .values()
                    .map(PreconfirmationCheckpoint::public_record),
            ),
            fee_lane_root: merkle_record_root(
                "P2PES-FEE-LANE",
                self.fee_lanes.values().map(FeeLane::public_record),
            ),
            witness_locality_root: merkle_record_root(
                "P2PES-WITNESS-LOCALITY",
                self.witness_hints
                    .values()
                    .map(WitnessLocalityHint::public_record),
            ),
            nullifier_fence_root: merkle_record_root(
                "P2PES-NULLIFIER-FENCE",
                self.nullifier_fences
                    .values()
                    .map(NullifierFence::public_record),
            ),
            rollback_evidence_root: merkle_record_root(
                "P2PES-ROLLBACK-EVIDENCE",
                self.rollback_evidence
                    .values()
                    .map(RollbackReorgEvidence::public_record),
            ),
            slashing_root: merkle_record_root(
                "P2PES-SLASHING",
                self.slashing_records
                    .values()
                    .map(SlashingRecord::public_record),
            ),
            state_root: String::new(),
        };
        self.roots.state_root = self.state_root();
    }

    fn packet(&self, packet_id: &str) -> Result<&EncryptedWorkPacket> {
        self.packets
            .get(packet_id)
            .ok_or_else(|| "packet not found".to_string())
    }

    fn attestation(&self, attestation_id: &str) -> Result<&SchedulerAttestation> {
        self.scheduler_attestations
            .get(attestation_id)
            .ok_or_else(|| "attestation not found".to_string())
    }

    fn assert_lock_available(
        &self,
        shard_id: &str,
        state_key_commitment: &str,
        mode: LockMode,
        candidate_lock_id: &str,
    ) -> Result<()> {
        for lock in self.state_locks.values() {
            if lock.lock_id != candidate_lock_id
                && lock.shard_id == shard_id
                && lock.state_key_commitment == state_key_commitment
                && lock.release_slot >= self.counters.current_slot
                && lock.mode.conflicts_with(mode)
            {
                return Err("state lock conflict".to_string());
            }
        }
        Ok(())
    }

    fn release_packet_locks(&mut self, packet_id: &str) {
        let current = self.counters.current_slot;
        for lock in self.state_locks.values_mut() {
            if lock.packet_id == packet_id {
                lock.release_slot = current;
            }
        }
    }

    fn take_nonce(&mut self) -> u64 {
        let nonce = self.counters.next_nonce;
        self.counters.next_nonce = self.counters.next_nonce.saturating_add(1);
        nonce
    }
}

pub fn deterministic_id(domain: &str, parts: &[&str]) -> String {
    let hash_parts = parts
        .iter()
        .map(|part| HashPart::Str(part))
        .collect::<Vec<_>>();
    domain_hash(domain, &hash_parts, 32)
}

pub fn root_from_value(domain: &str, value: &Value) -> String {
    domain_hash(domain, &[HashPart::Json(value)], 32)
}

pub fn merkle_record_root<I>(domain: &str, records: I) -> String
where
    I: IntoIterator<Item = Value>,
{
    let leaves = records.into_iter().collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

pub fn string_set_root(domain: &str, values: &BTreeSet<String>) -> String {
    merkle_root(domain, &string_set_record(values))
}

pub fn shard_id(index: u64) -> String {
    domain_hash(
        "P2PES-SHARD-ID",
        &[HashPart::Str(CHAIN_ID), HashPart::U64(index)],
        32,
    )
}

pub fn work_packet_id(
    shard_id: &str,
    sender_commitment: &str,
    contract_commitment: &str,
    ciphertext_commitment: &str,
    nonce: u64,
) -> String {
    domain_hash(
        "P2PES-WORK-PACKET-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(shard_id),
            HashPart::Str(sender_commitment),
            HashPart::Str(contract_commitment),
            HashPart::Str(ciphertext_commitment),
            HashPart::U64(nonce),
        ],
        32,
    )
}

pub fn scheduler_attestation_id(
    shard_id: &str,
    scheduler_commitment: &str,
    packet_ids: &BTreeSet<String>,
    parallel_group: u64,
    slot: u64,
) -> String {
    let packet_root = string_set_root("P2PES-SCHEDULE-PACKET-ID", packet_ids);
    domain_hash(
        "P2PES-SCHEDULER-ATTESTATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(shard_id),
            HashPart::Str(scheduler_commitment),
            HashPart::Str(&packet_root),
            HashPart::U64(parallel_group),
            HashPart::U64(slot),
        ],
        32,
    )
}

pub fn state_lock_id(
    shard_id: &str,
    packet_id: &str,
    state_key_commitment: &str,
    mode: LockMode,
) -> String {
    domain_hash(
        "P2PES-STATE-LOCK-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(shard_id),
            HashPart::Str(packet_id),
            HashPart::Str(state_key_commitment),
            HashPart::Str(mode.as_str()),
        ],
        32,
    )
}

pub fn nullifier_fence_id(shard_id: &str, packet_id: &str, nullifier: &str) -> String {
    domain_hash(
        "P2PES-NULLIFIER-FENCE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(shard_id),
            HashPart::Str(packet_id),
            HashPart::Str(nullifier),
        ],
        32,
    )
}

pub fn cross_shard_handoff_id(
    source_shard_id: &str,
    target_shard_id: &str,
    packet_id: &str,
    encrypted_payload_commitment: &str,
) -> String {
    domain_hash(
        "P2PES-CROSS-SHARD-HANDOFF-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(source_shard_id),
            HashPart::Str(target_shard_id),
            HashPart::Str(packet_id),
            HashPart::Str(encrypted_payload_commitment),
        ],
        32,
    )
}

pub fn speculative_receipt_id(
    packet_id: &str,
    attestation_id: &str,
    result_commitment: &str,
) -> String {
    domain_hash(
        "P2PES-SPECULATIVE-RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(packet_id),
            HashPart::Str(attestation_id),
            HashPart::Str(result_commitment),
        ],
        32,
    )
}

pub fn preconfirmation_id(
    shard_id: &str,
    sequencer_commitment: &str,
    packet_ids: &BTreeSet<String>,
    slot: u64,
) -> String {
    let packet_root = string_set_root("P2PES-PRECONF-PACKET-ID", packet_ids);
    domain_hash(
        "P2PES-PRECONFIRMATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(shard_id),
            HashPart::Str(sequencer_commitment),
            HashPart::Str(&packet_root),
            HashPart::U64(slot),
        ],
        32,
    )
}

pub fn rollback_evidence_id(
    shard_id: &str,
    packet_id: &str,
    bad_root: &str,
    expected_root: &str,
    slot: u64,
) -> String {
    domain_hash(
        "P2PES-ROLLBACK-EVIDENCE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(shard_id),
            HashPart::Str(packet_id),
            HashPart::Str(bad_root),
            HashPart::Str(expected_root),
            HashPart::U64(slot),
        ],
        32,
    )
}

pub fn slashing_id(
    evidence_id: &str,
    shard_id: &str,
    offender_commitment: &str,
    slot: u64,
) -> String {
    domain_hash(
        "P2PES-SLASHING-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(evidence_id),
            HashPart::Str(shard_id),
            HashPart::Str(offender_commitment),
            HashPart::U64(slot),
        ],
        32,
    )
}

pub fn access_list_commitment(
    read_keys: &BTreeSet<String>,
    write_keys: &BTreeSet<String>,
) -> String {
    let record = json!({
        "read_keys": string_set_record(read_keys),
        "write_keys": string_set_record(write_keys),
    });
    root_from_value("P2PES-ACCESS-LIST", &record)
}

pub fn encrypted_witness_root_for_packet(packet: &EncryptedWorkPacket) -> String {
    root_from_value(
        "P2PES-ENCRYPTED-WITNESS",
        &json!({
            "packet_id": packet.packet_id,
            "shard_id": packet.shard_id,
            "witness_hint_id": packet.witness_hint_id,
        }),
    )
}

pub fn locality_score(shard_id: &str, packet_id: &str) -> u64 {
    let hash = domain_hash(
        "P2PES-WITNESS-LOCALITY-SCORE",
        &[HashPart::Str(shard_id), HashPart::Str(packet_id)],
        8,
    );
    u64::from_str_radix(&hash[..8], 16).unwrap_or(0) % 1_000
}

pub fn string_set_record(values: &BTreeSet<String>) -> Vec<Value> {
    values
        .iter()
        .map(|value| Value::String(value.clone()))
        .collect()
}

pub fn u64_set_record(values: &BTreeSet<u64>) -> Vec<Value> {
    values.iter().map(|value| json!(value)).collect()
}

pub fn fee_lane_set_record(values: &BTreeSet<FeeLaneKind>) -> Vec<Value> {
    values.iter().map(|value| json!(value.as_str())).collect()
}
