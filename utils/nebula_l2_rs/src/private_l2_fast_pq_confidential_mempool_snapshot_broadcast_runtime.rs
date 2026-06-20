use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2FastPqConfidentialMempoolSnapshotBroadcastRuntimeResult<T> =
    std::result::Result<T, String>;
pub type Runtime = State;

pub const PRIVATE_L2_FAST_PQ_CONFIDENTIAL_MEMPOOL_SNAPSHOT_BROADCAST_RUNTIME_PROTOCOL_VERSION:
    &str = "private-l2-fast-pq-confidential-mempool-snapshot-broadcast-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_FAST_PQ_CONFIDENTIAL_MEMPOOL_SNAPSHOT_BROADCAST_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_SIGNER_SUITE: &str = "ML-DSA-87+SLH-DSA-SHAKE-256f-snapshot-attestation-v1";
pub const SNAPSHOT_SEALING_SUITE: &str = "ML-KEM-1024+XWing-confidential-mempool-snapshot-v1";
pub const DELTA_FEED_SUITE: &str = "low-latency-confidential-mempool-delta-feed-v1";
pub const RELAY_CREDIT_SCHEME: &str = "fee-capped-confidential-relay-credit-v1";
pub const EQUIVOCATION_QUARANTINE_SCHEME: &str = "pq-signed-mempool-equivocation-quarantine-v1";
pub const PUBLIC_RECORD_SCHEME: &str = "roots-only-confidential-mempool-broadcast-record-v1";
pub const DEVNET_L2_NETWORK: &str = "nebula-private-l2-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_HEIGHT: u64 = 3_244_800;
pub const DEVNET_EPOCH: u64 = 7_012;
pub const DEFAULT_SLOT_MS: u64 = 250;
pub const DEFAULT_SLOT_WINDOW: u64 = 32;
pub const DEFAULT_DELTA_WINDOW_MS: u64 = 75;
pub const DEFAULT_SNAPSHOT_TTL_SLOTS: u64 = 96;
pub const DEFAULT_DELTA_TTL_SLOTS: u64 = 24;
pub const DEFAULT_ATTESTATION_TTL_SLOTS: u64 = 64;
pub const DEFAULT_QUARANTINE_TTL_SLOTS: u64 = 720;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_TARGET_PRIVACY_SET_SIZE: u64 = 524_288;
pub const DEFAULT_COMMITTEE_SIZE: u16 = 9;
pub const DEFAULT_QUORUM: u16 = 6;
pub const DEFAULT_BACKUP_QUORUM: u16 = 4;
pub const DEFAULT_MAX_FEE_CAP_BPS: u64 = 12;
pub const DEFAULT_RELAY_CREDIT_CAP_PICONERO: u128 = 2_500_000_000;
pub const DEFAULT_SLOT_CREDIT_PICONERO: u128 = 50_000_000;
pub const DEFAULT_DELTA_CREDIT_PICONERO: u128 = 8_000_000;
pub const DEFAULT_MAX_SNAPSHOT_BYTES: u64 = 8_388_608;
pub const DEFAULT_MAX_DELTA_BYTES: u64 = 262_144;
pub const DEFAULT_MAX_DECRYPTION_SHARES: u16 = 7;
pub const DEFAULT_EQUIVOCATION_STRIKE_LIMIT: u16 = 2;
pub const MAX_BPS: u64 = 10_000;
pub const MAX_SNAPSHOTS: usize = 8_388_608;
pub const MAX_SLOTS: usize = 4_194_304;
pub const MAX_ATTESTATIONS: usize = 16_777_216;
pub const MAX_DELTAS: usize = 33_554_432;
pub const MAX_RELAY_CREDITS: usize = 8_388_608;
pub const MAX_QUARANTINES: usize = 2_097_152;
pub const MAX_PUBLIC_EVENTS: usize = 33_554_432;

macro_rules! ensure {
    ($condition:expr, $($arg:tt)+) => {
        if !$condition {
            return Err(format!($($arg)+));
        }
    };
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotClass {
    FullEncrypted,
    RollingWindow,
    PriorityOnly,
    ExitOnly,
    LiquidationOnly,
    ProofOnly,
    Recovery,
}

impl SnapshotClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FullEncrypted => "full_encrypted",
            Self::RollingWindow => "rolling_window",
            Self::PriorityOnly => "priority_only",
            Self::ExitOnly => "exit_only",
            Self::LiquidationOnly => "liquidation_only",
            Self::ProofOnly => "proof_only",
            Self::Recovery => "recovery",
        }
    }

    pub fn priority_weight(self) -> u64 {
        match self {
            Self::LiquidationOnly => 10_000,
            Self::ExitOnly => 9_000,
            Self::PriorityOnly => 8_000,
            Self::Recovery => 7_500,
            Self::FullEncrypted => 6_500,
            Self::RollingWindow => 5_500,
            Self::ProofOnly => 4_500,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotStatus {
    Draft,
    Sealed,
    Broadcast,
    Attesting,
    QuorumCertified,
    DeltaLinked,
    Expired,
    Quarantined,
}

impl SnapshotStatus {
    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Sealed | Self::Broadcast | Self::Attesting | Self::QuorumCertified
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SlotStatus {
    Reserved,
    Open,
    Filled,
    Certified,
    Missed,
    Reassigned,
    Quarantined,
}

impl SlotStatus {
    pub fn accepts_snapshot(self) -> bool {
        matches!(self, Self::Reserved | Self::Open | Self::Reassigned)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationStatus {
    Observed,
    Signed,
    Counted,
    Superseded,
    Disputed,
    Expired,
    Slashed,
}

impl AttestationStatus {
    pub fn counts_for_quorum(self) -> bool {
        matches!(self, Self::Signed | Self::Counted)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DeltaStatus {
    Proposed,
    Published,
    Acked,
    Folded,
    Dropped,
    Expired,
    Quarantined,
}

impl DeltaStatus {
    pub fn visible(self) -> bool {
        matches!(self, Self::Published | Self::Acked | Self::Folded)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RelayCreditStatus {
    Minted,
    Reserved,
    Spent,
    Refunded,
    Capped,
    Expired,
    Slashed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QuarantineStatus {
    Open,
    EvidenceLinked,
    CommitteeConfirmed,
    RelayMuted,
    Released,
    Slashed,
    Expired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FeedLane {
    WalletSync,
    BridgeExit,
    SwapIntent,
    Liquidation,
    ProofAggregation,
    ContractCall,
    Recovery,
}

impl FeedLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WalletSync => "wallet_sync",
            Self::BridgeExit => "bridge_exit",
            Self::SwapIntent => "swap_intent",
            Self::Liquidation => "liquidation",
            Self::ProofAggregation => "proof_aggregation",
            Self::ContractCall => "contract_call",
            Self::Recovery => "recovery",
        }
    }

    pub fn latency_budget_ms(self) -> u64 {
        match self {
            Self::Liquidation => 50,
            Self::BridgeExit => 65,
            Self::Recovery => 70,
            Self::SwapIntent => 75,
            Self::ContractCall => 90,
            Self::WalletSync => 125,
            Self::ProofAggregation => 160,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PublicEventKind {
    SnapshotSealed,
    SlotAssigned,
    AttestationCounted,
    DeltaPublished,
    RelayCreditSpent,
    EquivocationQuarantined,
    RootRotated,
}

impl PublicEventKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SnapshotSealed => "snapshot_sealed",
            Self::SlotAssigned => "slot_assigned",
            Self::AttestationCounted => "attestation_counted",
            Self::DeltaPublished => "delta_published",
            Self::RelayCreditSpent => "relay_credit_spent",
            Self::EquivocationQuarantined => "equivocation_quarantined",
            Self::RootRotated => "root_rotated",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: u64,
    pub schema_version: u64,
    pub slot_ms: u64,
    pub slot_window: u64,
    pub delta_window_ms: u64,
    pub snapshot_ttl_slots: u64,
    pub delta_ttl_slots: u64,
    pub attestation_ttl_slots: u64,
    pub quarantine_ttl_slots: u64,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub committee_size: u16,
    pub quorum: u16,
    pub backup_quorum: u16,
    pub max_fee_cap_bps: u64,
    pub relay_credit_cap_piconero: u128,
    pub slot_credit_piconero: u128,
    pub delta_credit_piconero: u128,
    pub max_snapshot_bytes: u64,
    pub max_delta_bytes: u64,
    pub max_decryption_shares: u16,
    pub equivocation_strike_limit: u16,
    pub hash_suite: String,
    pub pq_signer_suite: String,
    pub snapshot_sealing_suite: String,
    pub delta_feed_suite: String,
    pub relay_credit_scheme: String,
    pub equivocation_quarantine_scheme: String,
    pub public_record_scheme: String,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID,
            schema_version: SCHEMA_VERSION,
            slot_ms: DEFAULT_SLOT_MS,
            slot_window: DEFAULT_SLOT_WINDOW,
            delta_window_ms: DEFAULT_DELTA_WINDOW_MS,
            snapshot_ttl_slots: DEFAULT_SNAPSHOT_TTL_SLOTS,
            delta_ttl_slots: DEFAULT_DELTA_TTL_SLOTS,
            attestation_ttl_slots: DEFAULT_ATTESTATION_TTL_SLOTS,
            quarantine_ttl_slots: DEFAULT_QUARANTINE_TTL_SLOTS,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            committee_size: DEFAULT_COMMITTEE_SIZE,
            quorum: DEFAULT_QUORUM,
            backup_quorum: DEFAULT_BACKUP_QUORUM,
            max_fee_cap_bps: DEFAULT_MAX_FEE_CAP_BPS,
            relay_credit_cap_piconero: DEFAULT_RELAY_CREDIT_CAP_PICONERO,
            slot_credit_piconero: DEFAULT_SLOT_CREDIT_PICONERO,
            delta_credit_piconero: DEFAULT_DELTA_CREDIT_PICONERO,
            max_snapshot_bytes: DEFAULT_MAX_SNAPSHOT_BYTES,
            max_delta_bytes: DEFAULT_MAX_DELTA_BYTES,
            max_decryption_shares: DEFAULT_MAX_DECRYPTION_SHARES,
            equivocation_strike_limit: DEFAULT_EQUIVOCATION_STRIKE_LIMIT,
            hash_suite: HASH_SUITE.to_owned(),
            pq_signer_suite: PQ_SIGNER_SUITE.to_owned(),
            snapshot_sealing_suite: SNAPSHOT_SEALING_SUITE.to_owned(),
            delta_feed_suite: DELTA_FEED_SUITE.to_owned(),
            relay_credit_scheme: RELAY_CREDIT_SCHEME.to_owned(),
            equivocation_quarantine_scheme: EQUIVOCATION_QUARANTINE_SCHEME.to_owned(),
            public_record_scheme: PUBLIC_RECORD_SCHEME.to_owned(),
        }
    }

    pub fn validate(&self) -> PrivateL2FastPqConfidentialMempoolSnapshotBroadcastRuntimeResult<()> {
        ensure!(self.chain_id == CHAIN_ID, "unexpected chain id");
        ensure!(self.slot_ms > 0, "slot duration must be non-zero");
        ensure!(self.slot_window > 0, "slot window must be non-zero");
        ensure!(self.delta_window_ms > 0, "delta window must be non-zero");
        ensure!(
            self.snapshot_ttl_slots >= self.slot_window,
            "snapshot ttl too short"
        );
        ensure!(
            self.attestation_ttl_slots >= self.slot_window,
            "attestation ttl too short"
        );
        ensure!(self.committee_size > 0, "committee must be non-empty");
        ensure!(self.quorum > 0, "quorum must be non-zero");
        ensure!(
            self.quorum <= self.committee_size,
            "quorum exceeds committee size"
        );
        ensure!(
            self.backup_quorum <= self.quorum,
            "backup quorum exceeds primary quorum"
        );
        ensure!(
            self.max_fee_cap_bps <= MAX_BPS,
            "relay fee cap exceeds bps denominator"
        );
        ensure!(
            self.min_pq_security_bits >= DEFAULT_MIN_PQ_SECURITY_BITS,
            "pq security bits too low"
        );
        ensure!(
            self.target_privacy_set_size >= self.min_privacy_set_size,
            "target privacy set smaller than minimum"
        );
        ensure!(
            self.max_decryption_shares <= self.committee_size,
            "decryption shares exceed committee size"
        );
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "schema_version": self.schema_version,
            "slot_ms": self.slot_ms,
            "slot_window": self.slot_window,
            "delta_window_ms": self.delta_window_ms,
            "snapshot_ttl_slots": self.snapshot_ttl_slots,
            "delta_ttl_slots": self.delta_ttl_slots,
            "attestation_ttl_slots": self.attestation_ttl_slots,
            "quarantine_ttl_slots": self.quarantine_ttl_slots,
            "min_pq_security_bits": self.min_pq_security_bits,
            "min_privacy_set_size": self.min_privacy_set_size,
            "target_privacy_set_size": self.target_privacy_set_size,
            "committee_size": self.committee_size,
            "quorum": self.quorum,
            "backup_quorum": self.backup_quorum,
            "max_fee_cap_bps": self.max_fee_cap_bps,
            "relay_credit_cap_piconero": self.relay_credit_cap_piconero.to_string(),
            "slot_credit_piconero": self.slot_credit_piconero.to_string(),
            "delta_credit_piconero": self.delta_credit_piconero.to_string(),
            "max_snapshot_bytes": self.max_snapshot_bytes,
            "max_delta_bytes": self.max_delta_bytes,
            "max_decryption_shares": self.max_decryption_shares,
            "equivocation_strike_limit": self.equivocation_strike_limit,
            "hash_suite": self.hash_suite,
            "pq_signer_suite": self.pq_signer_suite,
            "snapshot_sealing_suite": self.snapshot_sealing_suite,
            "delta_feed_suite": self.delta_feed_suite,
            "relay_credit_scheme": self.relay_credit_scheme,
            "equivocation_quarantine_scheme": self.equivocation_quarantine_scheme,
            "public_record_scheme": self.public_record_scheme
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub snapshots: u64,
    pub slots: u64,
    pub attestations: u64,
    pub deltas: u64,
    pub relay_credits: u64,
    pub quarantines: u64,
    pub public_events: u64,
    pub sealed_snapshot_bytes: u64,
    pub delta_bytes: u64,
    pub total_attestation_weight: u64,
    pub spent_relay_credit_piconero: u128,
    pub refunded_relay_credit_piconero: u128,
    pub equivocation_strikes: u64,
    pub certified_slots: u64,
    pub missed_slots: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "snapshots": self.snapshots,
            "slots": self.slots,
            "attestations": self.attestations,
            "deltas": self.deltas,
            "relay_credits": self.relay_credits,
            "quarantines": self.quarantines,
            "public_events": self.public_events,
            "sealed_snapshot_bytes": self.sealed_snapshot_bytes,
            "delta_bytes": self.delta_bytes,
            "total_attestation_weight": self.total_attestation_weight,
            "spent_relay_credit_piconero": self.spent_relay_credit_piconero.to_string(),
            "refunded_relay_credit_piconero": self.refunded_relay_credit_piconero.to_string(),
            "equivocation_strikes": self.equivocation_strikes,
            "certified_slots": self.certified_slots,
            "missed_slots": self.missed_slots
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub snapshots_root: String,
    pub slots_root: String,
    pub attestations_root: String,
    pub deltas_root: String,
    pub relay_credits_root: String,
    pub quarantines_root: String,
    pub public_events_root: String,
    pub signer_index_root: String,
    pub spent_nullifiers_root: String,
    pub counters_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "snapshots_root": self.snapshots_root,
            "slots_root": self.slots_root,
            "attestations_root": self.attestations_root,
            "deltas_root": self.deltas_root,
            "relay_credits_root": self.relay_credits_root,
            "quarantines_root": self.quarantines_root,
            "public_events_root": self.public_events_root,
            "signer_index_root": self.signer_index_root,
            "spent_nullifiers_root": self.spent_nullifiers_root,
            "counters_root": self.counters_root,
            "state_root": self.state_root
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EncryptedSnapshot {
    pub snapshot_id: String,
    pub slot_id: String,
    pub producer_id: String,
    pub class: SnapshotClass,
    pub status: SnapshotStatus,
    pub height: u64,
    pub slot: u64,
    pub encrypted_payload_root: String,
    pub ciphertext_commitment: String,
    pub transaction_commitment_root: String,
    pub nullifier_root: String,
    pub fee_commitment_root: String,
    pub privacy_set_size: u64,
    pub encrypted_bytes: u64,
    pub priority_score: u64,
    pub decryption_share_root: String,
    pub previous_snapshot_root: String,
    pub snapshot_root: String,
}

impl EncryptedSnapshot {
    pub fn public_record(&self) -> Value {
        json!({
            "snapshot_id": self.snapshot_id,
            "slot_id": self.slot_id,
            "producer_id": self.producer_id,
            "class": self.class.as_str(),
            "status": self.status,
            "height": self.height,
            "slot": self.slot,
            "encrypted_payload_root": self.encrypted_payload_root,
            "ciphertext_commitment": self.ciphertext_commitment,
            "transaction_commitment_root": self.transaction_commitment_root,
            "nullifier_root": self.nullifier_root,
            "fee_commitment_root": self.fee_commitment_root,
            "privacy_set_size": self.privacy_set_size,
            "encrypted_bytes": self.encrypted_bytes,
            "priority_score": self.priority_score,
            "decryption_share_root": self.decryption_share_root,
            "previous_snapshot_root": self.previous_snapshot_root,
            "snapshot_root": self.snapshot_root
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BroadcastSlot {
    pub slot_id: String,
    pub committee_id: String,
    pub leader_id: String,
    pub backup_leader_id: String,
    pub status: SlotStatus,
    pub height: u64,
    pub slot: u64,
    pub slot_deadline_ms: u64,
    pub assigned_snapshot_id: String,
    pub committee_root: String,
    pub lane_mix_root: String,
    pub credit_budget_piconero: u128,
    pub slot_root: String,
}

impl BroadcastSlot {
    pub fn public_record(&self) -> Value {
        json!({
            "slot_id": self.slot_id,
            "committee_id": self.committee_id,
            "leader_id": self.leader_id,
            "backup_leader_id": self.backup_leader_id,
            "status": self.status,
            "height": self.height,
            "slot": self.slot,
            "slot_deadline_ms": self.slot_deadline_ms,
            "assigned_snapshot_id": self.assigned_snapshot_id,
            "committee_root": self.committee_root,
            "lane_mix_root": self.lane_mix_root,
            "credit_budget_piconero": self.credit_budget_piconero.to_string(),
            "slot_root": self.slot_root
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqSignerAttestation {
    pub attestation_id: String,
    pub snapshot_id: String,
    pub slot_id: String,
    pub signer_id: String,
    pub status: AttestationStatus,
    pub slot: u64,
    pub signature_root: String,
    pub transcript_root: String,
    pub observed_snapshot_root: String,
    pub observed_delta_root: String,
    pub signer_weight: u64,
    pub latency_ms: u64,
    pub attestation_root: String,
}

impl PqSignerAttestation {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "snapshot_id": self.snapshot_id,
            "slot_id": self.slot_id,
            "signer_id": self.signer_id,
            "status": self.status,
            "slot": self.slot,
            "signature_root": self.signature_root,
            "transcript_root": self.transcript_root,
            "observed_snapshot_root": self.observed_snapshot_root,
            "observed_delta_root": self.observed_delta_root,
            "signer_weight": self.signer_weight,
            "latency_ms": self.latency_ms,
            "attestation_root": self.attestation_root
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DeltaFeed {
    pub delta_id: String,
    pub snapshot_id: String,
    pub slot_id: String,
    pub lane: FeedLane,
    pub status: DeltaStatus,
    pub publisher_id: String,
    pub sequence: u64,
    pub slot: u64,
    pub delta_commitment_root: String,
    pub erased_payload_root: String,
    pub fee_delta_root: String,
    pub nullifier_delta_root: String,
    pub delta_bytes: u64,
    pub latency_ms: u64,
    pub delta_root: String,
}

impl DeltaFeed {
    pub fn public_record(&self) -> Value {
        json!({
            "delta_id": self.delta_id,
            "snapshot_id": self.snapshot_id,
            "slot_id": self.slot_id,
            "lane": self.lane.as_str(),
            "status": self.status,
            "publisher_id": self.publisher_id,
            "sequence": self.sequence,
            "slot": self.slot,
            "delta_commitment_root": self.delta_commitment_root,
            "erased_payload_root": self.erased_payload_root,
            "fee_delta_root": self.fee_delta_root,
            "nullifier_delta_root": self.nullifier_delta_root,
            "delta_bytes": self.delta_bytes,
            "latency_ms": self.latency_ms,
            "delta_root": self.delta_root
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RelayCredit {
    pub credit_id: String,
    pub owner_id: String,
    pub slot_id: String,
    pub snapshot_id: String,
    pub status: RelayCreditStatus,
    pub fee_cap_bps: u64,
    pub minted_piconero: u128,
    pub spent_piconero: u128,
    pub refund_piconero: u128,
    pub credit_nullifier: String,
    pub settlement_root: String,
    pub credit_root: String,
}

impl RelayCredit {
    pub fn public_record(&self) -> Value {
        json!({
            "credit_id": self.credit_id,
            "owner_id": self.owner_id,
            "slot_id": self.slot_id,
            "snapshot_id": self.snapshot_id,
            "status": self.status,
            "fee_cap_bps": self.fee_cap_bps,
            "minted_piconero": self.minted_piconero.to_string(),
            "spent_piconero": self.spent_piconero.to_string(),
            "refund_piconero": self.refund_piconero.to_string(),
            "credit_nullifier": self.credit_nullifier,
            "settlement_root": self.settlement_root,
            "credit_root": self.credit_root
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EquivocationQuarantine {
    pub quarantine_id: String,
    pub offender_id: String,
    pub snapshot_a: String,
    pub snapshot_b: String,
    pub status: QuarantineStatus,
    pub slot: u64,
    pub evidence_root: String,
    pub committee_vote_root: String,
    pub muted_until_slot: u64,
    pub strike_count: u16,
    pub quarantine_root: String,
}

impl EquivocationQuarantine {
    pub fn public_record(&self) -> Value {
        json!({
            "quarantine_id": self.quarantine_id,
            "offender_id": self.offender_id,
            "snapshot_a": self.snapshot_a,
            "snapshot_b": self.snapshot_b,
            "status": self.status,
            "slot": self.slot,
            "evidence_root": self.evidence_root,
            "committee_vote_root": self.committee_vote_root,
            "muted_until_slot": self.muted_until_slot,
            "strike_count": self.strike_count,
            "quarantine_root": self.quarantine_root
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublicEvent {
    pub event_id: String,
    pub kind: PublicEventKind,
    pub slot: u64,
    pub subject_id: String,
    pub record_root: String,
    pub event_root: String,
}

impl PublicEvent {
    pub fn public_record(&self) -> Value {
        json!({
            "event_id": self.event_id,
            "kind": self.kind.as_str(),
            "slot": self.slot,
            "subject_id": self.subject_id,
            "record_root": self.record_root,
            "event_root": self.event_root
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub network: String,
    pub monero_network: String,
    pub height: u64,
    pub epoch: u64,
    pub current_slot: u64,
    pub snapshots: BTreeMap<String, EncryptedSnapshot>,
    pub slots: BTreeMap<String, BroadcastSlot>,
    pub attestations: BTreeMap<String, PqSignerAttestation>,
    pub deltas: BTreeMap<String, DeltaFeed>,
    pub relay_credits: BTreeMap<String, RelayCredit>,
    pub quarantines: BTreeMap<String, EquivocationQuarantine>,
    pub public_events: BTreeMap<String, PublicEvent>,
    pub signer_index: BTreeMap<String, String>,
    pub spent_nullifiers: BTreeSet<String>,
}

impl State {
    pub fn new(
        config: Config,
        network: &str,
        monero_network: &str,
        height: u64,
        epoch: u64,
    ) -> Self {
        Self {
            config,
            counters: Counters::default(),
            network: network.to_owned(),
            monero_network: monero_network.to_owned(),
            height,
            epoch,
            current_slot: 0,
            snapshots: BTreeMap::new(),
            slots: BTreeMap::new(),
            attestations: BTreeMap::new(),
            deltas: BTreeMap::new(),
            relay_credits: BTreeMap::new(),
            quarantines: BTreeMap::new(),
            public_events: BTreeMap::new(),
            signer_index: BTreeMap::new(),
            spent_nullifiers: BTreeSet::new(),
        }
    }

    pub fn devnet() -> Self {
        let mut state = Self::new(
            Config::devnet(),
            DEVNET_L2_NETWORK,
            DEVNET_MONERO_NETWORK,
            DEVNET_HEIGHT,
            DEVNET_EPOCH,
        );
        state.current_slot = 18;
        state
            .reserve_slot(
                "slot-devnet-00018",
                "committee-devnet-fast-pq-a",
                "signer-devnet-01",
                "signer-devnet-02",
                devnet_root("committee", "fast-pq-a"),
                devnet_root("lane-mix", "wallet-bridge-swap"),
            )
            .expect("devnet slot is valid");
        state
            .seal_snapshot(
                "snapshot-devnet-00018",
                "slot-devnet-00018",
                "signer-devnet-01",
                SnapshotClass::FullEncrypted,
                devnet_root("encrypted-payload", "snapshot-00018"),
                devnet_root("ciphertext", "snapshot-00018"),
                devnet_root("tx-commitments", "snapshot-00018"),
                devnet_root("nullifiers", "snapshot-00018"),
                devnet_root("fee-commitments", "snapshot-00018"),
                131_072,
                1_572_864,
            )
            .expect("devnet snapshot is valid");
        state
            .publish_delta(
                "delta-devnet-00018-0001",
                "snapshot-devnet-00018",
                "slot-devnet-00018",
                FeedLane::BridgeExit,
                "signer-devnet-03",
                1,
                devnet_root("delta-commitment", "bridge-exit-1"),
                devnet_root("erased-delta", "bridge-exit-1"),
                devnet_root("fee-delta", "bridge-exit-1"),
                devnet_root("nullifier-delta", "bridge-exit-1"),
                65_536,
                42,
            )
            .expect("devnet delta is valid");
        state
            .count_attestation(
                "attestation-devnet-00018-01",
                "snapshot-devnet-00018",
                "slot-devnet-00018",
                "signer-devnet-01",
                devnet_root("signature", "attestation-01"),
                devnet_root("transcript", "attestation-01"),
                devnet_root("delta-observed", "attestation-01"),
                1,
                38,
            )
            .expect("devnet attestation is valid");
        state
            .mint_relay_credit(
                "credit-devnet-00018-01",
                "relay-devnet-01",
                "slot-devnet-00018",
                "snapshot-devnet-00018",
                DEFAULT_MAX_FEE_CAP_BPS,
                DEFAULT_SLOT_CREDIT_PICONERO,
                devnet_root("credit-nullifier", "00018-01"),
                devnet_root("credit-settlement", "00018-01"),
            )
            .expect("devnet relay credit is valid");
        state
    }

    pub fn demo() -> Self {
        let mut state = Self::devnet();
        state.current_slot = 19;
        state
            .reserve_slot(
                "slot-demo-00019",
                "committee-devnet-fast-pq-b",
                "signer-devnet-04",
                "signer-devnet-05",
                devnet_root("committee", "fast-pq-b"),
                devnet_root("lane-mix", "liquidation-proof-recovery"),
            )
            .expect("demo slot is valid");
        state
            .seal_snapshot(
                "snapshot-demo-00019",
                "slot-demo-00019",
                "signer-devnet-04",
                SnapshotClass::LiquidationOnly,
                devnet_root("encrypted-payload", "snapshot-00019"),
                devnet_root("ciphertext", "snapshot-00019"),
                devnet_root("tx-commitments", "snapshot-00019"),
                devnet_root("nullifiers", "snapshot-00019"),
                devnet_root("fee-commitments", "snapshot-00019"),
                262_144,
                2_097_152,
            )
            .expect("demo snapshot is valid");
        state
            .count_attestation(
                "attestation-demo-00019-04",
                "snapshot-demo-00019",
                "slot-demo-00019",
                "signer-devnet-04",
                devnet_root("signature", "attestation-04"),
                devnet_root("transcript", "attestation-04"),
                devnet_root("delta-observed", "attestation-04"),
                2,
                31,
            )
            .expect("demo attestation is valid");
        state
            .quarantine_equivocation(
                "quarantine-demo-signer-07",
                "signer-devnet-07",
                "snapshot-devnet-00018",
                "snapshot-demo-00019",
                devnet_root("equivocation-evidence", "signer-07"),
                devnet_root("committee-vote", "signer-07"),
                1,
            )
            .expect("demo quarantine is valid");
        state
    }

    pub fn validate(&self) -> PrivateL2FastPqConfidentialMempoolSnapshotBroadcastRuntimeResult<()> {
        self.config.validate()?;
        ensure!(
            self.counters.snapshots as usize == self.snapshots.len(),
            "snapshot counter mismatch"
        );
        ensure!(
            self.counters.slots as usize == self.slots.len(),
            "slot counter mismatch"
        );
        ensure!(
            self.counters.attestations as usize == self.attestations.len(),
            "attestation counter mismatch"
        );
        ensure!(
            self.counters.deltas as usize == self.deltas.len(),
            "delta counter mismatch"
        );
        ensure!(
            self.counters.relay_credits as usize == self.relay_credits.len(),
            "relay credit counter mismatch"
        );
        ensure!(
            self.counters.quarantines as usize == self.quarantines.len(),
            "quarantine counter mismatch"
        );
        Ok(())
    }

    pub fn reserve_slot(
        &mut self,
        slot_id: impl Into<String>,
        committee_id: impl Into<String>,
        leader_id: impl Into<String>,
        backup_leader_id: impl Into<String>,
        committee_root: impl Into<String>,
        lane_mix_root: impl Into<String>,
    ) -> PrivateL2FastPqConfidentialMempoolSnapshotBroadcastRuntimeResult<String> {
        ensure!(self.slots.len() < MAX_SLOTS, "slot capacity exhausted");
        let slot_id = slot_id.into();
        ensure!(!self.slots.contains_key(&slot_id), "slot already exists");
        let slot_number = self.current_slot;
        let mut slot = BroadcastSlot {
            slot_id: slot_id.clone(),
            committee_id: committee_id.into(),
            leader_id: leader_id.into(),
            backup_leader_id: backup_leader_id.into(),
            status: SlotStatus::Reserved,
            height: self.height,
            slot: slot_number,
            slot_deadline_ms: self.config.slot_ms.saturating_mul(slot_number + 1),
            assigned_snapshot_id: String::new(),
            committee_root: committee_root.into(),
            lane_mix_root: lane_mix_root.into(),
            credit_budget_piconero: self.config.slot_credit_piconero,
            slot_root: String::new(),
        };
        slot.slot_root = record_root("SLOT", &slot.public_record());
        self.counters.slots = self.counters.slots.saturating_add(1);
        self.signer_index
            .insert(slot.leader_id.clone(), slot.slot_id.clone());
        self.slots.insert(slot_id.clone(), slot);
        self.append_event(PublicEventKind::SlotAssigned, slot_id.clone(), slot_id)?;
        Ok(self.state_root())
    }

    pub fn seal_snapshot(
        &mut self,
        snapshot_id: impl Into<String>,
        slot_id: impl Into<String>,
        producer_id: impl Into<String>,
        class: SnapshotClass,
        encrypted_payload_root: impl Into<String>,
        ciphertext_commitment: impl Into<String>,
        transaction_commitment_root: impl Into<String>,
        nullifier_root: impl Into<String>,
        fee_commitment_root: impl Into<String>,
        privacy_set_size: u64,
        encrypted_bytes: u64,
    ) -> PrivateL2FastPqConfidentialMempoolSnapshotBroadcastRuntimeResult<String> {
        ensure!(
            self.snapshots.len() < MAX_SNAPSHOTS,
            "snapshot capacity exhausted"
        );
        let snapshot_id = snapshot_id.into();
        let slot_id = slot_id.into();
        ensure!(
            !self.snapshots.contains_key(&snapshot_id),
            "snapshot already exists"
        );
        ensure!(
            privacy_set_size >= self.config.min_privacy_set_size,
            "privacy set too small"
        );
        ensure!(
            encrypted_bytes <= self.config.max_snapshot_bytes,
            "encrypted snapshot too large"
        );
        let slot = self
            .slots
            .get_mut(&slot_id)
            .ok_or_else(|| format!("unknown slot {slot_id}"))?;
        ensure!(
            slot.status.accepts_snapshot(),
            "slot cannot accept snapshot"
        );
        slot.status = SlotStatus::Filled;
        slot.assigned_snapshot_id = snapshot_id.clone();
        slot.slot_root = record_root("SLOT", &slot.public_record());
        let previous_snapshot_root = self
            .snapshots
            .values()
            .next_back()
            .map(|snapshot| snapshot.snapshot_root.clone())
            .unwrap_or_else(|| devnet_root("genesis-snapshot", "empty"));
        let priority_score = class
            .priority_weight()
            .saturating_add(privacy_set_size / 1024)
            .saturating_sub(encrypted_bytes / 65_536);
        let mut snapshot = EncryptedSnapshot {
            snapshot_id: snapshot_id.clone(),
            slot_id: slot_id.clone(),
            producer_id: producer_id.into(),
            class,
            status: SnapshotStatus::Sealed,
            height: self.height,
            slot: self.current_slot,
            encrypted_payload_root: encrypted_payload_root.into(),
            ciphertext_commitment: ciphertext_commitment.into(),
            transaction_commitment_root: transaction_commitment_root.into(),
            nullifier_root: nullifier_root.into(),
            fee_commitment_root: fee_commitment_root.into(),
            privacy_set_size,
            encrypted_bytes,
            priority_score,
            decryption_share_root: devnet_root("decryption-shares", &snapshot_id),
            previous_snapshot_root,
            snapshot_root: String::new(),
        };
        snapshot.snapshot_root = record_root("SNAPSHOT", &snapshot.public_record());
        self.counters.snapshots = self.counters.snapshots.saturating_add(1);
        self.counters.sealed_snapshot_bytes = self
            .counters
            .sealed_snapshot_bytes
            .saturating_add(encrypted_bytes);
        self.snapshots.insert(snapshot_id.clone(), snapshot);
        self.append_event(
            PublicEventKind::SnapshotSealed,
            snapshot_id.clone(),
            snapshot_id,
        )?;
        Ok(self.state_root())
    }

    pub fn count_attestation(
        &mut self,
        attestation_id: impl Into<String>,
        snapshot_id: impl Into<String>,
        slot_id: impl Into<String>,
        signer_id: impl Into<String>,
        signature_root: impl Into<String>,
        transcript_root: impl Into<String>,
        observed_delta_root: impl Into<String>,
        signer_weight: u64,
        latency_ms: u64,
    ) -> PrivateL2FastPqConfidentialMempoolSnapshotBroadcastRuntimeResult<String> {
        ensure!(
            self.attestations.len() < MAX_ATTESTATIONS,
            "attestation capacity exhausted"
        );
        let attestation_id = attestation_id.into();
        let snapshot_id = snapshot_id.into();
        let slot_id = slot_id.into();
        let signer_id = signer_id.into();
        ensure!(
            !self.attestations.contains_key(&attestation_id),
            "attestation already exists"
        );
        let snapshot_root = self
            .snapshots
            .get(&snapshot_id)
            .ok_or_else(|| format!("unknown snapshot {snapshot_id}"))?
            .snapshot_root
            .clone();
        ensure!(self.slots.contains_key(&slot_id), "unknown slot");
        let mut attestation = PqSignerAttestation {
            attestation_id: attestation_id.clone(),
            snapshot_id: snapshot_id.clone(),
            slot_id: slot_id.clone(),
            signer_id: signer_id.clone(),
            status: AttestationStatus::Counted,
            slot: self.current_slot,
            signature_root: signature_root.into(),
            transcript_root: transcript_root.into(),
            observed_snapshot_root: snapshot_root,
            observed_delta_root: observed_delta_root.into(),
            signer_weight,
            latency_ms,
            attestation_root: String::new(),
        };
        attestation.attestation_root = record_root("ATTESTATION", &attestation.public_record());
        self.counters.attestations = self.counters.attestations.saturating_add(1);
        self.counters.total_attestation_weight = self
            .counters
            .total_attestation_weight
            .saturating_add(signer_weight);
        self.signer_index.insert(signer_id, attestation_id.clone());
        self.attestations
            .insert(attestation_id.clone(), attestation);
        self.refresh_certification(&snapshot_id, &slot_id);
        self.append_event(
            PublicEventKind::AttestationCounted,
            attestation_id.clone(),
            attestation_id,
        )?;
        Ok(self.state_root())
    }

    pub fn publish_delta(
        &mut self,
        delta_id: impl Into<String>,
        snapshot_id: impl Into<String>,
        slot_id: impl Into<String>,
        lane: FeedLane,
        publisher_id: impl Into<String>,
        sequence: u64,
        delta_commitment_root: impl Into<String>,
        erased_payload_root: impl Into<String>,
        fee_delta_root: impl Into<String>,
        nullifier_delta_root: impl Into<String>,
        delta_bytes: u64,
        latency_ms: u64,
    ) -> PrivateL2FastPqConfidentialMempoolSnapshotBroadcastRuntimeResult<String> {
        ensure!(self.deltas.len() < MAX_DELTAS, "delta capacity exhausted");
        let delta_id = delta_id.into();
        let snapshot_id = snapshot_id.into();
        let slot_id = slot_id.into();
        ensure!(!self.deltas.contains_key(&delta_id), "delta already exists");
        ensure!(
            self.snapshots.contains_key(&snapshot_id),
            "unknown snapshot"
        );
        ensure!(self.slots.contains_key(&slot_id), "unknown slot");
        ensure!(
            delta_bytes <= self.config.max_delta_bytes,
            "delta payload too large"
        );
        ensure!(
            latency_ms <= lane.latency_budget_ms().saturating_mul(4),
            "delta exceeds extended latency budget"
        );
        let mut delta = DeltaFeed {
            delta_id: delta_id.clone(),
            snapshot_id: snapshot_id.clone(),
            slot_id,
            lane,
            status: DeltaStatus::Published,
            publisher_id: publisher_id.into(),
            sequence,
            slot: self.current_slot,
            delta_commitment_root: delta_commitment_root.into(),
            erased_payload_root: erased_payload_root.into(),
            fee_delta_root: fee_delta_root.into(),
            nullifier_delta_root: nullifier_delta_root.into(),
            delta_bytes,
            latency_ms,
            delta_root: String::new(),
        };
        delta.delta_root = record_root("DELTA", &delta.public_record());
        if let Some(snapshot) = self.snapshots.get_mut(&snapshot_id) {
            snapshot.status = SnapshotStatus::DeltaLinked;
            snapshot.snapshot_root = record_root("SNAPSHOT", &snapshot.public_record());
        }
        self.counters.deltas = self.counters.deltas.saturating_add(1);
        self.counters.delta_bytes = self.counters.delta_bytes.saturating_add(delta_bytes);
        self.deltas.insert(delta_id.clone(), delta);
        self.append_event(PublicEventKind::DeltaPublished, delta_id.clone(), delta_id)?;
        Ok(self.state_root())
    }

    pub fn mint_relay_credit(
        &mut self,
        credit_id: impl Into<String>,
        owner_id: impl Into<String>,
        slot_id: impl Into<String>,
        snapshot_id: impl Into<String>,
        fee_cap_bps: u64,
        minted_piconero: u128,
        credit_nullifier: impl Into<String>,
        settlement_root: impl Into<String>,
    ) -> PrivateL2FastPqConfidentialMempoolSnapshotBroadcastRuntimeResult<String> {
        ensure!(
            self.relay_credits.len() < MAX_RELAY_CREDITS,
            "relay credit capacity exhausted"
        );
        let credit_id = credit_id.into();
        let slot_id = slot_id.into();
        let snapshot_id = snapshot_id.into();
        let credit_nullifier = credit_nullifier.into();
        ensure!(
            !self.relay_credits.contains_key(&credit_id),
            "relay credit already exists"
        );
        ensure!(
            !self.spent_nullifiers.contains(&credit_nullifier),
            "credit nullifier already spent"
        );
        ensure!(self.slots.contains_key(&slot_id), "unknown slot");
        ensure!(
            self.snapshots.contains_key(&snapshot_id),
            "unknown snapshot"
        );
        ensure!(
            fee_cap_bps <= self.config.max_fee_cap_bps,
            "fee cap exceeds runtime maximum"
        );
        ensure!(
            minted_piconero <= self.config.relay_credit_cap_piconero,
            "relay credit exceeds cap"
        );
        let mut credit = RelayCredit {
            credit_id: credit_id.clone(),
            owner_id: owner_id.into(),
            slot_id,
            snapshot_id,
            status: RelayCreditStatus::Minted,
            fee_cap_bps,
            minted_piconero,
            spent_piconero: 0,
            refund_piconero: 0,
            credit_nullifier,
            settlement_root: settlement_root.into(),
            credit_root: String::new(),
        };
        credit.credit_root = record_root("RELAY-CREDIT", &credit.public_record());
        self.counters.relay_credits = self.counters.relay_credits.saturating_add(1);
        self.relay_credits.insert(credit_id, credit);
        Ok(self.state_root())
    }

    pub fn spend_relay_credit(
        &mut self,
        credit_id: &str,
        spent_piconero: u128,
    ) -> PrivateL2FastPqConfidentialMempoolSnapshotBroadcastRuntimeResult<String> {
        let credit = self
            .relay_credits
            .get_mut(credit_id)
            .ok_or_else(|| format!("unknown relay credit {credit_id}"))?;
        ensure!(
            matches!(
                credit.status,
                RelayCreditStatus::Minted | RelayCreditStatus::Reserved
            ),
            "relay credit cannot be spent"
        );
        ensure!(
            spent_piconero <= credit.minted_piconero,
            "spend exceeds minted credit"
        );
        credit.spent_piconero = spent_piconero;
        credit.refund_piconero = credit.minted_piconero.saturating_sub(spent_piconero);
        credit.status = if spent_piconero == credit.minted_piconero {
            RelayCreditStatus::Spent
        } else {
            RelayCreditStatus::Refunded
        };
        credit.credit_root = record_root("RELAY-CREDIT", &credit.public_record());
        self.spent_nullifiers
            .insert(credit.credit_nullifier.clone());
        self.counters.spent_relay_credit_piconero = self
            .counters
            .spent_relay_credit_piconero
            .saturating_add(spent_piconero);
        self.counters.refunded_relay_credit_piconero = self
            .counters
            .refunded_relay_credit_piconero
            .saturating_add(credit.refund_piconero);
        self.append_event(
            PublicEventKind::RelayCreditSpent,
            credit_id.to_owned(),
            credit_id.to_owned(),
        )?;
        Ok(self.state_root())
    }

    pub fn quarantine_equivocation(
        &mut self,
        quarantine_id: impl Into<String>,
        offender_id: impl Into<String>,
        snapshot_a: impl Into<String>,
        snapshot_b: impl Into<String>,
        evidence_root: impl Into<String>,
        committee_vote_root: impl Into<String>,
        strike_count: u16,
    ) -> PrivateL2FastPqConfidentialMempoolSnapshotBroadcastRuntimeResult<String> {
        ensure!(
            self.quarantines.len() < MAX_QUARANTINES,
            "quarantine capacity exhausted"
        );
        let quarantine_id = quarantine_id.into();
        let offender_id = offender_id.into();
        let snapshot_a = snapshot_a.into();
        let snapshot_b = snapshot_b.into();
        ensure!(
            !self.quarantines.contains_key(&quarantine_id),
            "quarantine already exists"
        );
        ensure!(
            snapshot_a != snapshot_b,
            "equivocation snapshots must differ"
        );
        ensure!(
            self.snapshots.contains_key(&snapshot_a),
            "unknown snapshot a"
        );
        ensure!(
            self.snapshots.contains_key(&snapshot_b),
            "unknown snapshot b"
        );
        let muted_until_slot = self
            .current_slot
            .saturating_add(self.config.quarantine_ttl_slots);
        let mut quarantine = EquivocationQuarantine {
            quarantine_id: quarantine_id.clone(),
            offender_id: offender_id.clone(),
            snapshot_a: snapshot_a.clone(),
            snapshot_b: snapshot_b.clone(),
            status: QuarantineStatus::EvidenceLinked,
            slot: self.current_slot,
            evidence_root: evidence_root.into(),
            committee_vote_root: committee_vote_root.into(),
            muted_until_slot,
            strike_count,
            quarantine_root: String::new(),
        };
        quarantine.quarantine_root = record_root("QUARANTINE", &quarantine.public_record());
        if let Some(snapshot) = self.snapshots.get_mut(&snapshot_a) {
            snapshot.status = SnapshotStatus::Quarantined;
            snapshot.snapshot_root = record_root("SNAPSHOT", &snapshot.public_record());
        }
        if let Some(snapshot) = self.snapshots.get_mut(&snapshot_b) {
            snapshot.status = SnapshotStatus::Quarantined;
            snapshot.snapshot_root = record_root("SNAPSHOT", &snapshot.public_record());
        }
        self.counters.quarantines = self.counters.quarantines.saturating_add(1);
        self.counters.equivocation_strikes = self
            .counters
            .equivocation_strikes
            .saturating_add(strike_count as u64);
        self.signer_index.insert(offender_id, quarantine_id.clone());
        self.quarantines.insert(quarantine_id.clone(), quarantine);
        self.append_event(
            PublicEventKind::EquivocationQuarantined,
            quarantine_id.clone(),
            quarantine_id,
        )?;
        Ok(self.state_root())
    }

    pub fn advance_slot(&mut self, slots: u64) -> String {
        self.current_slot = self.current_slot.saturating_add(slots);
        self.height = self
            .height
            .saturating_add(slots / self.config.slot_window.max(1));
        self.expire_old_records();
        self.state_root()
    }

    pub fn roots(&self) -> Roots {
        let config_root = record_root("CONFIG", &self.config.public_record());
        let snapshots_root = map_root(
            "SNAPSHOTS",
            self.snapshots
                .values()
                .map(|record| record.public_record())
                .collect(),
        );
        let slots_root = map_root(
            "SLOTS",
            self.slots
                .values()
                .map(|record| record.public_record())
                .collect(),
        );
        let attestations_root = map_root(
            "ATTESTATIONS",
            self.attestations
                .values()
                .map(|record| record.public_record())
                .collect(),
        );
        let deltas_root = map_root(
            "DELTAS",
            self.deltas
                .values()
                .map(|record| record.public_record())
                .collect(),
        );
        let relay_credits_root = map_root(
            "RELAY-CREDITS",
            self.relay_credits
                .values()
                .map(|record| record.public_record())
                .collect(),
        );
        let quarantines_root = map_root(
            "QUARANTINES",
            self.quarantines
                .values()
                .map(|record| record.public_record())
                .collect(),
        );
        let public_events_root = map_root(
            "PUBLIC-EVENTS",
            self.public_events
                .values()
                .map(|record| record.public_record())
                .collect(),
        );
        let signer_index_root = map_root(
            "SIGNER-INDEX",
            self.signer_index
                .iter()
                .map(|(signer, subject)| json!({"signer": signer, "subject": subject}))
                .collect(),
        );
        let spent_nullifiers_root = map_root(
            "SPENT-NULLIFIERS",
            self.spent_nullifiers
                .iter()
                .map(|nullifier| json!({"nullifier": nullifier}))
                .collect(),
        );
        let counters_root = record_root("COUNTERS", &self.counters.public_record());
        let state_root = record_root(
            "STATE-WITHOUT-SELF-ROOT",
            &json!({
                "config_root": config_root,
                "snapshots_root": snapshots_root,
                "slots_root": slots_root,
                "attestations_root": attestations_root,
                "deltas_root": deltas_root,
                "relay_credits_root": relay_credits_root,
                "quarantines_root": quarantines_root,
                "public_events_root": public_events_root,
                "signer_index_root": signer_index_root,
                "spent_nullifiers_root": spent_nullifiers_root,
                "counters_root": counters_root,
                "network": self.network,
                "monero_network": self.monero_network,
                "height": self.height,
                "epoch": self.epoch,
                "current_slot": self.current_slot
            }),
        );
        Roots {
            config_root,
            snapshots_root,
            slots_root,
            attestations_root,
            deltas_root,
            relay_credits_root,
            quarantines_root,
            public_events_root,
            signer_index_root,
            spent_nullifiers_root,
            counters_root,
            state_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "module_protocol_version": PRIVATE_L2_FAST_PQ_CONFIDENTIAL_MEMPOOL_SNAPSHOT_BROADCAST_RUNTIME_PROTOCOL_VERSION,
            "network": self.network,
            "monero_network": self.monero_network,
            "height": self.height,
            "epoch": self.epoch,
            "current_slot": self.current_slot,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": self.roots().public_record(),
            "state_root": self.state_root()
        })
    }

    pub fn state_root(&self) -> String {
        self.roots().state_root
    }

    fn append_event(
        &mut self,
        kind: PublicEventKind,
        subject_id: String,
        record_subject_id: String,
    ) -> PrivateL2FastPqConfidentialMempoolSnapshotBroadcastRuntimeResult<()> {
        ensure!(
            self.public_events.len() < MAX_PUBLIC_EVENTS,
            "public event capacity exhausted"
        );
        let record_root_value = self.subject_root(&record_subject_id);
        let event_id = format!(
            "event-{}-{:016}",
            kind.as_str(),
            self.counters.public_events.saturating_add(1)
        );
        let mut event = PublicEvent {
            event_id: event_id.clone(),
            kind,
            slot: self.current_slot,
            subject_id,
            record_root: record_root_value,
            event_root: String::new(),
        };
        event.event_root = record_root("PUBLIC-EVENT", &event.public_record());
        self.counters.public_events = self.counters.public_events.saturating_add(1);
        self.public_events.insert(event_id, event);
        Ok(())
    }

    fn subject_root(&self, subject_id: &str) -> String {
        if let Some(record) = self.snapshots.get(subject_id) {
            return record.snapshot_root.clone();
        }
        if let Some(record) = self.slots.get(subject_id) {
            return record.slot_root.clone();
        }
        if let Some(record) = self.attestations.get(subject_id) {
            return record.attestation_root.clone();
        }
        if let Some(record) = self.deltas.get(subject_id) {
            return record.delta_root.clone();
        }
        if let Some(record) = self.relay_credits.get(subject_id) {
            return record.credit_root.clone();
        }
        if let Some(record) = self.quarantines.get(subject_id) {
            return record.quarantine_root.clone();
        }
        record_root("UNKNOWN-SUBJECT", &json!({"subject_id": subject_id}))
    }

    fn refresh_certification(&mut self, snapshot_id: &str, slot_id: &str) {
        let weight: u64 = self
            .attestations
            .values()
            .filter(|attestation| {
                attestation.snapshot_id == snapshot_id
                    && attestation.status.counts_for_quorum()
                    && attestation.slot_id == slot_id
            })
            .map(|attestation| attestation.signer_weight)
            .sum();
        if weight >= self.config.quorum as u64 {
            if let Some(snapshot) = self.snapshots.get_mut(snapshot_id) {
                snapshot.status = SnapshotStatus::QuorumCertified;
                snapshot.snapshot_root = record_root("SNAPSHOT", &snapshot.public_record());
            }
            if let Some(slot) = self.slots.get_mut(slot_id) {
                if slot.status != SlotStatus::Certified {
                    self.counters.certified_slots = self.counters.certified_slots.saturating_add(1);
                }
                slot.status = SlotStatus::Certified;
                slot.slot_root = record_root("SLOT", &slot.public_record());
            }
        }
    }

    fn expire_old_records(&mut self) {
        let current_slot = self.current_slot;
        let snapshot_ttl = self.config.snapshot_ttl_slots;
        for snapshot in self.snapshots.values_mut() {
            if snapshot.status.live() && current_slot.saturating_sub(snapshot.slot) > snapshot_ttl {
                snapshot.status = SnapshotStatus::Expired;
                snapshot.snapshot_root = record_root("SNAPSHOT", &snapshot.public_record());
            }
        }
        let delta_ttl = self.config.delta_ttl_slots;
        for delta in self.deltas.values_mut() {
            if delta.status.visible() && current_slot.saturating_sub(delta.slot) > delta_ttl {
                delta.status = DeltaStatus::Expired;
                delta.delta_root = record_root("DELTA", &delta.public_record());
            }
        }
        let attestation_ttl = self.config.attestation_ttl_slots;
        for attestation in self.attestations.values_mut() {
            if attestation.status.counts_for_quorum()
                && current_slot.saturating_sub(attestation.slot) > attestation_ttl
            {
                attestation.status = AttestationStatus::Expired;
                attestation.attestation_root =
                    record_root("ATTESTATION", &attestation.public_record());
            }
        }
        for slot in self.slots.values_mut() {
            if matches!(slot.status, SlotStatus::Reserved | SlotStatus::Open)
                && current_slot.saturating_sub(slot.slot) > self.config.slot_window
            {
                slot.status = SlotStatus::Missed;
                slot.slot_root = record_root("SLOT", &slot.public_record());
                self.counters.missed_slots = self.counters.missed_slots.saturating_add(1);
            }
        }
    }
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn demo() -> State {
    State::demo()
}

pub fn public_record(state: &State) -> Value {
    state.public_record()
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}

pub fn record_root(domain: &str, record: &Value) -> String {
    domain_hash(
        &format!(
            "PRIVATE-L2-FAST-PQ-CONFIDENTIAL-MEMPOOL-SNAPSHOT-BROADCAST-{}",
            domain
        ),
        &[HashPart::Str(PROTOCOL_VERSION), HashPart::Json(record)],
        32,
    )
}

pub fn state_root_from_public_record(record: &Value) -> String {
    record_root("PUBLIC-RECORD", record)
}

fn map_root(domain: &str, records: Vec<Value>) -> String {
    let leaves: Vec<Value> = records
        .iter()
        .map(|record| Value::String(record_root(domain, record)))
        .collect();
    merkle_root(
        &format!(
            "PRIVATE-L2-FAST-PQ-CONFIDENTIAL-MEMPOOL-SNAPSHOT-BROADCAST-{}",
            domain
        ),
        &leaves,
    )
}

fn devnet_root(kind: &str, label: &str) -> String {
    domain_hash(
        "PRIVATE-L2-FAST-PQ-CONFIDENTIAL-MEMPOOL-SNAPSHOT-BROADCAST-DEVNET",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(kind),
            HashPart::Str(label),
        ],
        32,
    )
}
