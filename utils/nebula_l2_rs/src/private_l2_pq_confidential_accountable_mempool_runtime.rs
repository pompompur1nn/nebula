use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2PqConfidentialAccountableMempoolRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-confidential-accountable-mempool-runtime-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_ACCOUNTABLE_MEMPOOL_RUNTIME_PROTOCOL_VERSION: &str =
    PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_ADMISSION_SUITE: &str = "ML-KEM-1024+ML-DSA-87-encrypted-admission-ticket-v1";
pub const PQ_RELAY_AUTH_SUITE: &str = "ML-DSA-87+SLH-DSA-SHAKE-256f-stake-relay-v1";
pub const CONFIDENTIAL_ORDERING_SUITE: &str = "commit-reveal-vdf-private-ordering-root-v1";
pub const LOW_FEE_QOS_SUITE: &str = "confidential-low-fee-qos-lane-v1";
pub const SPAM_EVIDENCE_SUITE: &str = "redacted-mempool-spam-slashing-evidence-v1";
pub const DEFAULT_CHAIN_ID: &str = CHAIN_ID;
pub const DEVNET_L2_HEIGHT: u64 = 2_246_000;
pub const DEVNET_MONERO_HEIGHT: u64 = 3_842_000;
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_EPOCH_LENGTH_SLOTS: u64 = 512;
pub const DEFAULT_WINDOW_SLOTS: u64 = 8;
pub const DEFAULT_REVEAL_SLOTS: u64 = 3;
pub const DEFAULT_TICKET_TTL_SLOTS: u64 = 64;
pub const DEFAULT_EVIDENCE_TTL_SLOTS: u64 = 4_096;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_MIN_LANE_PRIVACY_SET_SIZE: u64 = 1_024;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_TARGET_USER_FEE_BPS: u64 = 7;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 18;
pub const DEFAULT_LOW_FEE_RESERVE_BPS: u64 = 1_500;
pub const DEFAULT_MIN_RELAY_STAKE_MICRO_UNITS: u64 = 25_000_000;
pub const DEFAULT_MIN_WATCHER_STAKE_MICRO_UNITS: u64 = 5_000_000;
pub const DEFAULT_QUORUM_BPS: u64 = 6_700;
pub const DEFAULT_SUPERMAJORITY_BPS: u64 = 8_000;
pub const DEFAULT_BASE_SLASH_BPS: u64 = 1_250;
pub const DEFAULT_MAX_SLASH_BPS: u64 = 8_000;
pub const DEFAULT_MAX_TICKETS_PER_WINDOW: usize = 16_384;
pub const DEFAULT_MAX_RELAY_RECORDS: usize = 1_048_576;
pub const DEFAULT_MAX_ORDERING_COMMITMENTS: usize = 262_144;
pub const DEFAULT_MAX_QOS_LANES: usize = 256;
pub const DEFAULT_MAX_EVIDENCE_BUNDLES: usize = 262_144;
pub const DEFAULT_MAX_PUBLIC_RECORDS: usize = 1_048_576;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TicketClass {
    WalletTransfer,
    MoneroDeposit,
    MoneroExit,
    ConfidentialSwap,
    ContractCall,
    AccountAbstraction,
    ProofAggregation,
    OracleUpdate,
    BridgeSettlement,
    Emergency,
}

impl TicketClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WalletTransfer => "wallet_transfer",
            Self::MoneroDeposit => "monero_deposit",
            Self::MoneroExit => "monero_exit",
            Self::ConfidentialSwap => "confidential_swap",
            Self::ContractCall => "contract_call",
            Self::AccountAbstraction => "account_abstraction",
            Self::ProofAggregation => "proof_aggregation",
            Self::OracleUpdate => "oracle_update",
            Self::BridgeSettlement => "bridge_settlement",
            Self::Emergency => "emergency",
        }
    }

    pub fn priority_weight(self) -> u64 {
        match self {
            Self::Emergency => 10_000,
            Self::BridgeSettlement => 9_600,
            Self::MoneroExit => 9_300,
            Self::MoneroDeposit => 9_000,
            Self::ConfidentialSwap => 8_600,
            Self::ContractCall => 8_100,
            Self::AccountAbstraction => 7_800,
            Self::WalletTransfer => 7_500,
            Self::ProofAggregation => 6_600,
            Self::OracleUpdate => 6_200,
        }
    }

    pub fn low_fee_floor_bps(self) -> u64 {
        match self {
            Self::Emergency => 250,
            Self::OracleUpdate => 800,
            Self::ProofAggregation => 1_000,
            Self::WalletTransfer => 1_600,
            Self::AccountAbstraction => 1_900,
            Self::MoneroDeposit => 2_100,
            Self::MoneroExit => 2_300,
            Self::ContractCall => 2_500,
            Self::ConfidentialSwap => 2_800,
            Self::BridgeSettlement => 3_000,
        }
    }

    pub fn public_record(self) -> Value {
        json!(self.as_str())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TicketStatus {
    Encrypted,
    Admitted,
    Relayed,
    Committed,
    Revealed,
    Ordered,
    Included,
    Deferred,
    Rejected,
    Expired,
}

impl TicketStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Encrypted => "encrypted",
            Self::Admitted => "admitted",
            Self::Relayed => "relayed",
            Self::Committed => "committed",
            Self::Revealed => "revealed",
            Self::Ordered => "ordered",
            Self::Included => "included",
            Self::Deferred => "deferred",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }

    pub fn active(self) -> bool {
        matches!(
            self,
            Self::Encrypted
                | Self::Admitted
                | Self::Relayed
                | Self::Committed
                | Self::Revealed
                | Self::Ordered
                | Self::Deferred
        )
    }

    pub fn public_record(self) -> Value {
        json!(self.as_str())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RelayRole {
    Gateway,
    StakeWeightedRelay,
    Watcher,
    Builder,
    Sequencer,
    LowFeeSponsor,
    EmergencyOperator,
}

impl RelayRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Gateway => "gateway",
            Self::StakeWeightedRelay => "stake_weighted_relay",
            Self::Watcher => "watcher",
            Self::Builder => "builder",
            Self::Sequencer => "sequencer",
            Self::LowFeeSponsor => "low_fee_sponsor",
            Self::EmergencyOperator => "emergency_operator",
        }
    }

    pub fn relay_weight_bps(self) -> u64 {
        match self {
            Self::Sequencer => 10_000,
            Self::EmergencyOperator => 9_500,
            Self::Builder => 8_800,
            Self::StakeWeightedRelay => 8_500,
            Self::Gateway => 7_200,
            Self::LowFeeSponsor => 6_900,
            Self::Watcher => 6_500,
        }
    }

    pub fn public_record(self) -> Value {
        json!(self.as_str())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LaneKind {
    Baseline,
    WalletLowFee,
    ContractLowFee,
    MoneroBridge,
    ProofAggregation,
    SponsorSubsidized,
    CongestionRelief,
    Emergency,
}

impl LaneKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Baseline => "baseline",
            Self::WalletLowFee => "wallet_low_fee",
            Self::ContractLowFee => "contract_low_fee",
            Self::MoneroBridge => "monero_bridge",
            Self::ProofAggregation => "proof_aggregation",
            Self::SponsorSubsidized => "sponsor_subsidized",
            Self::CongestionRelief => "congestion_relief",
            Self::Emergency => "emergency",
        }
    }

    pub fn public_record(self) -> Value {
        json!(self.as_str())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LaneStatus {
    Open,
    Congested,
    CouponOnly,
    Draining,
    Paused,
    Retired,
}

impl LaneStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Congested => "congested",
            Self::CouponOnly => "coupon_only",
            Self::Draining => "draining",
            Self::Paused => "paused",
            Self::Retired => "retired",
        }
    }

    pub fn accepts_tickets(self) -> bool {
        matches!(self, Self::Open | Self::Congested | Self::CouponOnly)
    }

    pub fn public_record(self) -> Value {
        json!(self.as_str())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    SpamFlood,
    DuplicateTicket,
    InvalidAdmissionProof,
    RelayCensorship,
    OrderingEquivocation,
    FeeOvercharge,
    PrivacyLeak,
    LowFeeLaneAbuse,
    WithheldReveal,
}

impl EvidenceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SpamFlood => "spam_flood",
            Self::DuplicateTicket => "duplicate_ticket",
            Self::InvalidAdmissionProof => "invalid_admission_proof",
            Self::RelayCensorship => "relay_censorship",
            Self::OrderingEquivocation => "ordering_equivocation",
            Self::FeeOvercharge => "fee_overcharge",
            Self::PrivacyLeak => "privacy_leak",
            Self::LowFeeLaneAbuse => "low_fee_lane_abuse",
            Self::WithheldReveal => "withheld_reveal",
        }
    }

    pub fn severity_bps(self) -> u64 {
        match self {
            Self::PrivacyLeak => 9_500,
            Self::OrderingEquivocation => 9_200,
            Self::InvalidAdmissionProof => 8_600,
            Self::RelayCensorship => 7_800,
            Self::WithheldReveal => 7_200,
            Self::SpamFlood => 6_800,
            Self::DuplicateTicket => 5_800,
            Self::FeeOvercharge => 5_500,
            Self::LowFeeLaneAbuse => 4_800,
        }
    }

    pub fn public_record(self) -> Value {
        json!(self.as_str())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceStatus {
    Observed,
    QuorumAttesting,
    Slashable,
    Settled,
    Rejected,
    Expired,
}

impl EvidenceStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Observed => "observed",
            Self::QuorumAttesting => "quorum_attesting",
            Self::Slashable => "slashable",
            Self::Settled => "settled",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }

    pub fn public_record(self) -> Value {
        json!(self.as_str())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub epoch_length_slots: u64,
    pub window_slots: u64,
    pub reveal_slots: u64,
    pub ticket_ttl_slots: u64,
    pub evidence_ttl_slots: u64,
    pub min_privacy_set_size: u64,
    pub min_lane_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub target_user_fee_bps: u64,
    pub max_user_fee_bps: u64,
    pub low_fee_reserve_bps: u64,
    pub min_relay_stake_micro_units: u64,
    pub min_watcher_stake_micro_units: u64,
    pub quorum_bps: u64,
    pub supermajority_bps: u64,
    pub base_slash_bps: u64,
    pub max_slash_bps: u64,
    pub max_tickets_per_window: usize,
    pub max_relay_records: usize,
    pub max_ordering_commitments: usize,
    pub max_qos_lanes: usize,
    pub max_evidence_bundles: usize,
    pub max_public_records: usize,
    pub admission_suite: String,
    pub relay_auth_suite: String,
    pub ordering_suite: String,
    pub low_fee_qos_suite: String,
    pub spam_evidence_suite: String,
    pub hash_suite: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            chain_id: DEFAULT_CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            epoch_length_slots: DEFAULT_EPOCH_LENGTH_SLOTS,
            window_slots: DEFAULT_WINDOW_SLOTS,
            reveal_slots: DEFAULT_REVEAL_SLOTS,
            ticket_ttl_slots: DEFAULT_TICKET_TTL_SLOTS,
            evidence_ttl_slots: DEFAULT_EVIDENCE_TTL_SLOTS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            min_lane_privacy_set_size: DEFAULT_MIN_LANE_PRIVACY_SET_SIZE,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            target_user_fee_bps: DEFAULT_TARGET_USER_FEE_BPS,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            low_fee_reserve_bps: DEFAULT_LOW_FEE_RESERVE_BPS,
            min_relay_stake_micro_units: DEFAULT_MIN_RELAY_STAKE_MICRO_UNITS,
            min_watcher_stake_micro_units: DEFAULT_MIN_WATCHER_STAKE_MICRO_UNITS,
            quorum_bps: DEFAULT_QUORUM_BPS,
            supermajority_bps: DEFAULT_SUPERMAJORITY_BPS,
            base_slash_bps: DEFAULT_BASE_SLASH_BPS,
            max_slash_bps: DEFAULT_MAX_SLASH_BPS,
            max_tickets_per_window: DEFAULT_MAX_TICKETS_PER_WINDOW,
            max_relay_records: DEFAULT_MAX_RELAY_RECORDS,
            max_ordering_commitments: DEFAULT_MAX_ORDERING_COMMITMENTS,
            max_qos_lanes: DEFAULT_MAX_QOS_LANES,
            max_evidence_bundles: DEFAULT_MAX_EVIDENCE_BUNDLES,
            max_public_records: DEFAULT_MAX_PUBLIC_RECORDS,
            admission_suite: PQ_ADMISSION_SUITE.to_string(),
            relay_auth_suite: PQ_RELAY_AUTH_SUITE.to_string(),
            ordering_suite: CONFIDENTIAL_ORDERING_SUITE.to_string(),
            low_fee_qos_suite: LOW_FEE_QOS_SUITE.to_string(),
            spam_evidence_suite: SPAM_EVIDENCE_SUITE.to_string(),
            hash_suite: HASH_SUITE.to_string(),
        }
    }
}

impl Config {
    pub fn validate(&self) -> Result<()> {
        if self.protocol_version != PROTOCOL_VERSION {
            return Err("invalid protocol version".to_string());
        }
        if self.schema_version != SCHEMA_VERSION {
            return Err("invalid schema version".to_string());
        }
        if self.chain_id.is_empty() {
            return Err("chain id is empty".to_string());
        }
        if self.window_slots == 0 || self.reveal_slots == 0 {
            return Err("window and reveal slots must be nonzero".to_string());
        }
        if self.reveal_slots > self.window_slots {
            return Err("reveal slots exceed window slots".to_string());
        }
        if self.ticket_ttl_slots < self.window_slots + self.reveal_slots {
            return Err("ticket ttl is shorter than admission and reveal window".to_string());
        }
        if self.target_user_fee_bps > self.max_user_fee_bps || self.max_user_fee_bps > MAX_BPS {
            return Err("invalid fee bps configuration".to_string());
        }
        if self.low_fee_reserve_bps > MAX_BPS
            || self.quorum_bps > MAX_BPS
            || self.supermajority_bps > MAX_BPS
        {
            return Err("invalid bps threshold".to_string());
        }
        if self.quorum_bps > self.supermajority_bps {
            return Err("quorum exceeds supermajority".to_string());
        }
        if self.base_slash_bps > self.max_slash_bps || self.max_slash_bps > MAX_BPS {
            return Err("invalid slash bps configuration".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "admission_suite": self.admission_suite,
            "base_slash_bps": self.base_slash_bps,
            "chain_id": self.chain_id,
            "epoch_length_slots": self.epoch_length_slots,
            "evidence_ttl_slots": self.evidence_ttl_slots,
            "hash_suite": self.hash_suite,
            "low_fee_qos_suite": self.low_fee_qos_suite,
            "low_fee_reserve_bps": self.low_fee_reserve_bps,
            "max_evidence_bundles": self.max_evidence_bundles,
            "max_ordering_commitments": self.max_ordering_commitments,
            "max_public_records": self.max_public_records,
            "max_qos_lanes": self.max_qos_lanes,
            "max_relay_records": self.max_relay_records,
            "max_slash_bps": self.max_slash_bps,
            "max_tickets_per_window": self.max_tickets_per_window,
            "max_user_fee_bps": self.max_user_fee_bps,
            "min_lane_privacy_set_size": self.min_lane_privacy_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
            "min_privacy_set_size": self.min_privacy_set_size,
            "min_relay_stake_micro_units": self.min_relay_stake_micro_units,
            "min_watcher_stake_micro_units": self.min_watcher_stake_micro_units,
            "ordering_suite": self.ordering_suite,
            "protocol_version": self.protocol_version,
            "quorum_bps": self.quorum_bps,
            "relay_auth_suite": self.relay_auth_suite,
            "reveal_slots": self.reveal_slots,
            "schema_version": self.schema_version,
            "spam_evidence_suite": self.spam_evidence_suite,
            "supermajority_bps": self.supermajority_bps,
            "target_user_fee_bps": self.target_user_fee_bps,
            "ticket_ttl_slots": self.ticket_ttl_slots,
            "window_slots": self.window_slots,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub epochs: u64,
    pub windows_opened: u64,
    pub tickets_encrypted: u64,
    pub tickets_admitted: u64,
    pub tickets_relayed: u64,
    pub tickets_ordered: u64,
    pub tickets_included: u64,
    pub tickets_deferred: u64,
    pub tickets_rejected: u64,
    pub low_fee_tickets: u64,
    pub relay_votes: u64,
    pub ordering_commitments: u64,
    pub qos_reservations: u64,
    pub spam_evidence_bundles: u64,
    pub slashable_evidence_bundles: u64,
    pub public_records: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "epochs": self.epochs,
            "low_fee_tickets": self.low_fee_tickets,
            "ordering_commitments": self.ordering_commitments,
            "public_records": self.public_records,
            "qos_reservations": self.qos_reservations,
            "relay_votes": self.relay_votes,
            "slashable_evidence_bundles": self.slashable_evidence_bundles,
            "spam_evidence_bundles": self.spam_evidence_bundles,
            "tickets_admitted": self.tickets_admitted,
            "tickets_deferred": self.tickets_deferred,
            "tickets_encrypted": self.tickets_encrypted,
            "tickets_included": self.tickets_included,
            "tickets_ordered": self.tickets_ordered,
            "tickets_rejected": self.tickets_rejected,
            "tickets_relayed": self.tickets_relayed,
            "windows_opened": self.windows_opened,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub ticket_root: String,
    pub relay_root: String,
    pub lane_root: String,
    pub ordering_root: String,
    pub evidence_root: String,
    pub public_log_root: String,
    pub counters_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "counters_root": self.counters_root,
            "evidence_root": self.evidence_root,
            "lane_root": self.lane_root,
            "ordering_root": self.ordering_root,
            "public_log_root": self.public_log_root,
            "relay_root": self.relay_root,
            "state_root": self.state_root,
            "ticket_root": self.ticket_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AdmissionTicket {
    pub ticket_id: String,
    pub nullifier_commitment: String,
    pub encrypted_payload_commitment: String,
    pub admission_proof_root: String,
    pub fee_commitment: String,
    pub lane_id: String,
    pub class: TicketClass,
    pub status: TicketStatus,
    pub window_id: String,
    pub submit_slot: u64,
    pub expiry_slot: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub low_fee_requested: bool,
    pub max_fee_bps: u64,
    pub relay_path_commitment: String,
    pub deterministic_record_id: String,
}

impl AdmissionTicket {
    pub fn new(
        ticket_id: impl Into<String>,
        lane_id: impl Into<String>,
        window_id: impl Into<String>,
        class: TicketClass,
        submit_slot: u64,
        low_fee_requested: bool,
        max_fee_bps: u64,
    ) -> Self {
        let ticket_id = ticket_id.into();
        let lane_id = lane_id.into();
        let window_id = window_id.into();
        let expiry_slot = submit_slot + DEFAULT_TICKET_TTL_SLOTS;
        let seed = format!("{ticket_id}:{lane_id}:{window_id}:{}", class.as_str());
        let nullifier_commitment =
            domain_hash("ACCOUNTABLE-MEMPOOL-NULLIFIER", &[HashPart::Str(&seed)], 32);
        let encrypted_payload_commitment = domain_hash(
            "ACCOUNTABLE-MEMPOOL-ENCRYPTED-PAYLOAD",
            &[HashPart::Str(&seed)],
            32,
        );
        let admission_proof_root = domain_hash(
            "ACCOUNTABLE-MEMPOOL-ADMISSION-PROOF",
            &[HashPart::Str(&seed)],
            32,
        );
        let fee_commitment = domain_hash(
            "ACCOUNTABLE-MEMPOOL-FEE-COMMITMENT",
            &[HashPart::Str(&seed), HashPart::U64(max_fee_bps)],
            32,
        );
        let relay_path_commitment = domain_hash(
            "ACCOUNTABLE-MEMPOOL-RELAY-PATH",
            &[HashPart::Str(&seed)],
            32,
        );
        let deterministic_record_id =
            domain_hash("ACCOUNTABLE-MEMPOOL-RECORD-ID", &[HashPart::Str(&seed)], 16);
        Self {
            ticket_id,
            nullifier_commitment,
            encrypted_payload_commitment,
            admission_proof_root,
            fee_commitment,
            lane_id,
            class,
            status: TicketStatus::Encrypted,
            window_id,
            submit_slot,
            expiry_slot,
            privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            low_fee_requested,
            max_fee_bps,
            relay_path_commitment,
            deterministic_record_id,
        }
    }

    pub fn admit(&mut self) {
        if self.status == TicketStatus::Encrypted {
            self.status = TicketStatus::Admitted;
        }
    }

    pub fn mark_relayed(&mut self) {
        if matches!(
            self.status,
            TicketStatus::Encrypted | TicketStatus::Admitted
        ) {
            self.status = TicketStatus::Relayed;
        }
    }

    pub fn mark_ordered(&mut self) {
        if self.status.active() {
            self.status = TicketStatus::Ordered;
        }
    }

    pub fn mark_included(&mut self) {
        if matches!(self.status, TicketStatus::Ordered | TicketStatus::Revealed) {
            self.status = TicketStatus::Included;
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "admission_proof_root": self.admission_proof_root,
            "class": self.class.public_record(),
            "deterministic_record_id": self.deterministic_record_id,
            "encrypted_payload_commitment": self.encrypted_payload_commitment,
            "expiry_slot": self.expiry_slot,
            "fee_commitment": self.fee_commitment,
            "lane_id": self.lane_id,
            "low_fee_requested": self.low_fee_requested,
            "max_fee_bps": self.max_fee_bps,
            "nullifier_commitment": self.nullifier_commitment,
            "pq_security_bits": self.pq_security_bits,
            "privacy_set_size": self.privacy_set_size,
            "relay_path_commitment": self.relay_path_commitment,
            "status": self.status.public_record(),
            "submit_slot": self.submit_slot,
            "ticket_id": self.ticket_id,
            "window_id": self.window_id,
        })
    }

    pub fn root(&self) -> String {
        domain_hash(
            "ACCOUNTABLE-MEMPOOL-TICKET",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RelayOperator {
    pub relay_id: String,
    pub role: RelayRole,
    pub stake_commitment: String,
    pub stake_micro_units: u64,
    pub accepted_ticket_count: u64,
    pub rejected_ticket_count: u64,
    pub relay_weight_bps: u64,
    pub last_heartbeat_slot: u64,
    pub pq_identity_root: String,
    pub slashed_bps: u64,
    pub active: bool,
}

impl RelayOperator {
    pub fn new(relay_id: impl Into<String>, role: RelayRole, stake_micro_units: u64) -> Self {
        let relay_id = relay_id.into();
        let stake_commitment = domain_hash(
            "ACCOUNTABLE-MEMPOOL-RELAY-STAKE",
            &[HashPart::Str(&relay_id), HashPart::U64(stake_micro_units)],
            32,
        );
        let pq_identity_root = domain_hash(
            "ACCOUNTABLE-MEMPOOL-RELAY-PQ-IDENTITY",
            &[HashPart::Str(&relay_id), HashPart::Str(role.as_str())],
            32,
        );
        Self {
            relay_id,
            role,
            stake_commitment,
            stake_micro_units,
            accepted_ticket_count: 0,
            rejected_ticket_count: 0,
            relay_weight_bps: role.relay_weight_bps(),
            last_heartbeat_slot: 0,
            pq_identity_root,
            slashed_bps: 0,
            active: true,
        }
    }

    pub fn effective_weight(&self) -> u128 {
        if !self.active {
            return 0;
        }
        let remaining_bps = MAX_BPS.saturating_sub(self.slashed_bps);
        self.stake_micro_units as u128 * self.relay_weight_bps as u128 * remaining_bps as u128
            / (MAX_BPS as u128 * MAX_BPS as u128)
    }

    pub fn record_accept(&mut self, slot: u64) {
        self.accepted_ticket_count = self.accepted_ticket_count.saturating_add(1);
        self.last_heartbeat_slot = slot;
    }

    pub fn record_reject(&mut self, slot: u64) {
        self.rejected_ticket_count = self.rejected_ticket_count.saturating_add(1);
        self.last_heartbeat_slot = slot;
    }

    pub fn apply_slash(&mut self, slash_bps: u64) {
        self.slashed_bps = self.slashed_bps.saturating_add(slash_bps).min(MAX_BPS);
        if self.slashed_bps >= MAX_BPS {
            self.active = false;
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "accepted_ticket_count": self.accepted_ticket_count,
            "active": self.active,
            "effective_weight": self.effective_weight().to_string(),
            "last_heartbeat_slot": self.last_heartbeat_slot,
            "pq_identity_root": self.pq_identity_root,
            "rejected_ticket_count": self.rejected_ticket_count,
            "relay_id": self.relay_id,
            "relay_weight_bps": self.relay_weight_bps,
            "role": self.role.public_record(),
            "slashed_bps": self.slashed_bps,
            "stake_commitment": self.stake_commitment,
            "stake_micro_units": self.stake_micro_units,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RelayRecord {
    pub relay_record_id: String,
    pub relay_id: String,
    pub ticket_id: String,
    pub window_id: String,
    pub slot: u64,
    pub stake_weight_snapshot: u128,
    pub relay_signature_root: String,
    pub accepted: bool,
    pub reason_code: String,
}

impl RelayRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "accepted": self.accepted,
            "reason_code": self.reason_code,
            "relay_id": self.relay_id,
            "relay_record_id": self.relay_record_id,
            "relay_signature_root": self.relay_signature_root,
            "slot": self.slot,
            "stake_weight_snapshot": self.stake_weight_snapshot.to_string(),
            "ticket_id": self.ticket_id,
            "window_id": self.window_id,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct QosLane {
    pub lane_id: String,
    pub kind: LaneKind,
    pub status: LaneStatus,
    pub target_fee_bps: u64,
    pub max_fee_bps: u64,
    pub reserve_bps: u64,
    pub privacy_set_size: u64,
    pub admitted_tickets: u64,
    pub ordered_tickets: u64,
    pub sponsor_commitment: String,
    pub qos_root: String,
}

impl QosLane {
    pub fn new(lane_id: impl Into<String>, kind: LaneKind, target_fee_bps: u64) -> Self {
        let lane_id = lane_id.into();
        let sponsor_commitment = domain_hash(
            "ACCOUNTABLE-MEMPOOL-LANE-SPONSOR",
            &[HashPart::Str(&lane_id), HashPart::Str(kind.as_str())],
            32,
        );
        let qos_root = domain_hash(
            "ACCOUNTABLE-MEMPOOL-LANE-QOS",
            &[HashPart::Str(&lane_id), HashPart::U64(target_fee_bps)],
            32,
        );
        Self {
            lane_id,
            kind,
            status: LaneStatus::Open,
            target_fee_bps,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            reserve_bps: DEFAULT_LOW_FEE_RESERVE_BPS,
            privacy_set_size: DEFAULT_MIN_LANE_PRIVACY_SET_SIZE,
            admitted_tickets: 0,
            ordered_tickets: 0,
            sponsor_commitment,
            qos_root,
        }
    }

    pub fn record_admission(&mut self) {
        self.admitted_tickets = self.admitted_tickets.saturating_add(1);
    }

    pub fn record_order(&mut self) {
        self.ordered_tickets = self.ordered_tickets.saturating_add(1);
    }

    pub fn public_record(&self) -> Value {
        json!({
            "admitted_tickets": self.admitted_tickets,
            "kind": self.kind.public_record(),
            "lane_id": self.lane_id,
            "max_fee_bps": self.max_fee_bps,
            "ordered_tickets": self.ordered_tickets,
            "privacy_set_size": self.privacy_set_size,
            "qos_root": self.qos_root,
            "reserve_bps": self.reserve_bps,
            "sponsor_commitment": self.sponsor_commitment,
            "status": self.status.public_record(),
            "target_fee_bps": self.target_fee_bps,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OrderingCommitment {
    pub commitment_id: String,
    pub window_id: String,
    pub relay_id: String,
    pub slot: u64,
    pub ticket_count: u64,
    pub encrypted_order_root: String,
    pub reveal_root: String,
    pub vdf_transcript_root: String,
    pub inclusion_root: String,
    pub privacy_budget_root: String,
    pub stake_weight_bps: u64,
    pub finalized: bool,
}

impl OrderingCommitment {
    pub fn new(
        commitment_id: impl Into<String>,
        window_id: impl Into<String>,
        relay_id: impl Into<String>,
        ticket_ids: &[String],
        slot: u64,
        stake_weight_bps: u64,
    ) -> Self {
        let commitment_id = commitment_id.into();
        let window_id = window_id.into();
        let relay_id = relay_id.into();
        let leaves = ticket_ids.iter().map(|id| json!(id)).collect::<Vec<_>>();
        let encrypted_order_root = merkle_root("ACCOUNTABLE-MEMPOOL-ENCRYPTED-ORDER", &leaves);
        let seed = format!("{commitment_id}:{window_id}:{relay_id}:{slot}");
        let reveal_root = domain_hash(
            "ACCOUNTABLE-MEMPOOL-ORDER-REVEAL",
            &[HashPart::Str(&seed)],
            32,
        );
        let vdf_transcript_root = domain_hash(
            "ACCOUNTABLE-MEMPOOL-VDF-TRANSCRIPT",
            &[HashPart::Str(&seed)],
            32,
        );
        let inclusion_root = merkle_root("ACCOUNTABLE-MEMPOOL-INCLUSION", &leaves);
        let privacy_budget_root = domain_hash(
            "ACCOUNTABLE-MEMPOOL-PRIVACY-BUDGET",
            &[HashPart::Str(&seed), HashPart::U64(ticket_ids.len() as u64)],
            32,
        );
        Self {
            commitment_id,
            window_id,
            relay_id,
            slot,
            ticket_count: ticket_ids.len() as u64,
            encrypted_order_root,
            reveal_root,
            vdf_transcript_root,
            inclusion_root,
            privacy_budget_root,
            stake_weight_bps,
            finalized: false,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "commitment_id": self.commitment_id,
            "encrypted_order_root": self.encrypted_order_root,
            "finalized": self.finalized,
            "inclusion_root": self.inclusion_root,
            "privacy_budget_root": self.privacy_budget_root,
            "relay_id": self.relay_id,
            "reveal_root": self.reveal_root,
            "slot": self.slot,
            "stake_weight_bps": self.stake_weight_bps,
            "ticket_count": self.ticket_count,
            "vdf_transcript_root": self.vdf_transcript_root,
            "window_id": self.window_id,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SpamEvidence {
    pub evidence_id: String,
    pub kind: EvidenceKind,
    pub status: EvidenceStatus,
    pub accused_relay_id: String,
    pub window_id: String,
    pub observed_slot: u64,
    pub evidence_commitment: String,
    pub redacted_ticket_roots: Vec<String>,
    pub attester_ids: BTreeSet<String>,
    pub attested_stake_bps: u64,
    pub slash_bps: u64,
    pub settlement_root: String,
}

impl SpamEvidence {
    pub fn new(
        evidence_id: impl Into<String>,
        kind: EvidenceKind,
        accused_relay_id: impl Into<String>,
        window_id: impl Into<String>,
        observed_slot: u64,
        redacted_ticket_roots: Vec<String>,
    ) -> Self {
        let evidence_id = evidence_id.into();
        let accused_relay_id = accused_relay_id.into();
        let window_id = window_id.into();
        let seed = format!(
            "{}:{}:{}:{}",
            evidence_id,
            kind.as_str(),
            accused_relay_id,
            observed_slot
        );
        let evidence_commitment =
            domain_hash("ACCOUNTABLE-MEMPOOL-EVIDENCE", &[HashPart::Str(&seed)], 32);
        let settlement_root = domain_hash(
            "ACCOUNTABLE-MEMPOOL-EVIDENCE-SETTLEMENT",
            &[HashPart::Str(&seed)],
            32,
        );
        let slash_bps = DEFAULT_BASE_SLASH_BPS
            .saturating_mul(kind.severity_bps())
            .saturating_div(MAX_BPS)
            .min(DEFAULT_MAX_SLASH_BPS);
        Self {
            evidence_id,
            kind,
            status: EvidenceStatus::Observed,
            accused_relay_id,
            window_id,
            observed_slot,
            evidence_commitment,
            redacted_ticket_roots,
            attester_ids: BTreeSet::new(),
            attested_stake_bps: 0,
            slash_bps,
            settlement_root,
        }
    }

    pub fn attest(&mut self, attester_id: impl Into<String>, stake_bps: u64, quorum_bps: u64) {
        self.attester_ids.insert(attester_id.into());
        self.attested_stake_bps = self
            .attested_stake_bps
            .saturating_add(stake_bps)
            .min(MAX_BPS);
        self.status = if self.attested_stake_bps >= quorum_bps {
            EvidenceStatus::Slashable
        } else {
            EvidenceStatus::QuorumAttesting
        };
    }

    pub fn public_record(&self) -> Value {
        json!({
            "accused_relay_id": self.accused_relay_id,
            "attested_stake_bps": self.attested_stake_bps,
            "attester_ids": self.attester_ids.iter().cloned().collect::<Vec<_>>(),
            "evidence_commitment": self.evidence_commitment,
            "evidence_id": self.evidence_id,
            "kind": self.kind.public_record(),
            "observed_slot": self.observed_slot,
            "redacted_ticket_roots": self.redacted_ticket_roots,
            "settlement_root": self.settlement_root,
            "slash_bps": self.slash_bps,
            "status": self.status.public_record(),
            "window_id": self.window_id,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublicLogEntry {
    pub record_id: String,
    pub slot: u64,
    pub record_kind: String,
    pub subject_id: String,
    pub public_root: String,
}

impl PublicLogEntry {
    pub fn public_record(&self) -> Value {
        json!({
            "public_root": self.public_root,
            "record_id": self.record_id,
            "record_kind": self.record_kind,
            "slot": self.slot,
            "subject_id": self.subject_id,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub current_epoch: u64,
    pub current_slot: u64,
    pub current_window_id: String,
    pub tickets: BTreeMap<String, AdmissionTicket>,
    pub relays: BTreeMap<String, RelayOperator>,
    pub relay_records: BTreeMap<String, RelayRecord>,
    pub lanes: BTreeMap<String, QosLane>,
    pub ordering_commitments: BTreeMap<String, OrderingCommitment>,
    pub evidence: BTreeMap<String, SpamEvidence>,
    pub public_log: Vec<PublicLogEntry>,
}

impl Default for State {
    fn default() -> Self {
        Self::new(Config::default())
    }
}

impl State {
    pub fn new(config: Config) -> Self {
        let mut state = Self {
            config,
            counters: Counters::default(),
            roots: Roots::default(),
            current_epoch: 0,
            current_slot: DEVNET_L2_HEIGHT,
            current_window_id: "window-devnet-0000".to_string(),
            tickets: BTreeMap::new(),
            relays: BTreeMap::new(),
            relay_records: BTreeMap::new(),
            lanes: BTreeMap::new(),
            ordering_commitments: BTreeMap::new(),
            evidence: BTreeMap::new(),
            public_log: Vec::new(),
        };
        state.recompute_counters();
        state.refresh_roots();
        state
    }

    pub fn validate(&self) -> Result<()> {
        self.config.validate()?;
        if self.tickets.len() > self.config.max_tickets_per_window {
            return Err("ticket capacity exceeded".to_string());
        }
        if self.relay_records.len() > self.config.max_relay_records {
            return Err("relay record capacity exceeded".to_string());
        }
        if self.ordering_commitments.len() > self.config.max_ordering_commitments {
            return Err("ordering commitment capacity exceeded".to_string());
        }
        if self.lanes.len() > self.config.max_qos_lanes {
            return Err("qos lane capacity exceeded".to_string());
        }
        if self.evidence.len() > self.config.max_evidence_bundles {
            return Err("evidence capacity exceeded".to_string());
        }
        if self.public_log.len() > self.config.max_public_records {
            return Err("public log capacity exceeded".to_string());
        }
        Ok(())
    }

    pub fn add_lane(&mut self, lane: QosLane) -> Result<()> {
        if self.lanes.len() >= self.config.max_qos_lanes && !self.lanes.contains_key(&lane.lane_id)
        {
            return Err("qos lane capacity exceeded".to_string());
        }
        self.emit_public_record(
            self.current_slot,
            "qos_lane",
            &lane.lane_id,
            &lane.public_record(),
        );
        self.lanes.insert(lane.lane_id.clone(), lane);
        self.recompute_counters();
        self.refresh_roots();
        Ok(())
    }

    pub fn add_relay(&mut self, relay: RelayOperator) -> Result<()> {
        if relay.role == RelayRole::Watcher
            && relay.stake_micro_units < self.config.min_watcher_stake_micro_units
        {
            return Err("watcher stake below minimum".to_string());
        }
        if relay.role != RelayRole::Watcher
            && relay.stake_micro_units < self.config.min_relay_stake_micro_units
        {
            return Err("relay stake below minimum".to_string());
        }
        self.emit_public_record(
            self.current_slot,
            "relay_operator",
            &relay.relay_id,
            &relay.public_record(),
        );
        self.relays.insert(relay.relay_id.clone(), relay);
        self.recompute_counters();
        self.refresh_roots();
        Ok(())
    }

    pub fn admit_ticket(&mut self, mut ticket: AdmissionTicket) -> Result<String> {
        if self.tickets.len() >= self.config.max_tickets_per_window {
            return Err("ticket capacity exceeded".to_string());
        }
        if ticket.privacy_set_size < self.config.min_privacy_set_size {
            return Err("ticket privacy set below minimum".to_string());
        }
        if ticket.pq_security_bits < self.config.min_pq_security_bits {
            return Err("ticket pq security below minimum".to_string());
        }
        let lane = self
            .lanes
            .get_mut(&ticket.lane_id)
            .ok_or_else(|| "unknown qos lane".to_string())?;
        if !lane.status.accepts_tickets() {
            return Err("qos lane is not accepting tickets".to_string());
        }
        if ticket.max_fee_bps > self.config.max_user_fee_bps {
            return Err("ticket max fee exceeds configured cap".to_string());
        }
        if ticket.low_fee_requested && ticket.max_fee_bps > lane.max_fee_bps {
            return Err("low fee ticket exceeds lane cap".to_string());
        }
        ticket.admit();
        lane.record_admission();
        let ticket_id = ticket.ticket_id.clone();
        self.emit_public_record(
            ticket.submit_slot,
            "admission_ticket",
            &ticket.ticket_id,
            &ticket.public_record(),
        );
        self.tickets.insert(ticket_id.clone(), ticket);
        self.recompute_counters();
        self.refresh_roots();
        Ok(ticket_id)
    }

    pub fn relay_ticket(
        &mut self,
        relay_id: &str,
        ticket_id: &str,
        accepted: bool,
        reason_code: impl Into<String>,
    ) -> Result<String> {
        let relay = self
            .relays
            .get_mut(relay_id)
            .ok_or_else(|| "unknown relay".to_string())?;
        let ticket = self
            .tickets
            .get_mut(ticket_id)
            .ok_or_else(|| "unknown ticket".to_string())?;
        if accepted {
            relay.record_accept(self.current_slot);
            ticket.mark_relayed();
        } else {
            relay.record_reject(self.current_slot);
            ticket.status = TicketStatus::Rejected;
        }
        let relay_record_id = domain_hash(
            "ACCOUNTABLE-MEMPOOL-RELAY-RECORD-ID",
            &[
                HashPart::Str(relay_id),
                HashPart::Str(ticket_id),
                HashPart::U64(self.current_slot),
            ],
            16,
        );
        let relay_signature_root = domain_hash(
            "ACCOUNTABLE-MEMPOOL-RELAY-SIGNATURE",
            &[
                HashPart::Str(relay_id),
                HashPart::Str(ticket_id),
                HashPart::U64(self.current_slot),
            ],
            32,
        );
        let record = RelayRecord {
            relay_record_id: relay_record_id.clone(),
            relay_id: relay_id.to_string(),
            ticket_id: ticket_id.to_string(),
            window_id: ticket.window_id.clone(),
            slot: self.current_slot,
            stake_weight_snapshot: relay.effective_weight(),
            relay_signature_root,
            accepted,
            reason_code: reason_code.into(),
        };
        self.emit_public_record(
            self.current_slot,
            "relay_record",
            &relay_record_id,
            &record.public_record(),
        );
        self.relay_records.insert(relay_record_id.clone(), record);
        self.recompute_counters();
        self.refresh_roots();
        Ok(relay_record_id)
    }

    pub fn commit_ordering(
        &mut self,
        relay_id: &str,
        window_id: &str,
        ticket_ids: Vec<String>,
    ) -> Result<String> {
        if !self.relays.contains_key(relay_id) {
            return Err("unknown relay".to_string());
        }
        for ticket_id in &ticket_ids {
            if !self.tickets.contains_key(ticket_id) {
                return Err(format!("unknown ticket {ticket_id}"));
            }
        }
        let commitment_id = domain_hash(
            "ACCOUNTABLE-MEMPOOL-ORDERING-COMMITMENT-ID",
            &[
                HashPart::Str(relay_id),
                HashPart::Str(window_id),
                HashPart::U64(self.current_slot),
            ],
            16,
        );
        let stake_weight_bps = self.relay_stake_weight_bps(relay_id);
        let commitment = OrderingCommitment::new(
            commitment_id.clone(),
            window_id.to_string(),
            relay_id.to_string(),
            &ticket_ids,
            self.current_slot,
            stake_weight_bps,
        );
        for ticket_id in ticket_ids {
            if let Some(ticket) = self.tickets.get_mut(&ticket_id) {
                ticket.mark_ordered();
                if let Some(lane) = self.lanes.get_mut(&ticket.lane_id) {
                    lane.record_order();
                }
            }
        }
        self.emit_public_record(
            self.current_slot,
            "ordering_commitment",
            &commitment_id,
            &commitment.public_record(),
        );
        self.ordering_commitments
            .insert(commitment_id.clone(), commitment);
        self.recompute_counters();
        self.refresh_roots();
        Ok(commitment_id)
    }

    pub fn add_evidence(&mut self, evidence: SpamEvidence) -> Result<String> {
        if self.evidence.len() >= self.config.max_evidence_bundles {
            return Err("evidence capacity exceeded".to_string());
        }
        let evidence_id = evidence.evidence_id.clone();
        self.emit_public_record(
            evidence.observed_slot,
            "spam_slashing_evidence",
            &evidence.evidence_id,
            &evidence.public_record(),
        );
        self.evidence.insert(evidence_id.clone(), evidence);
        self.recompute_counters();
        self.refresh_roots();
        Ok(evidence_id)
    }

    pub fn attest_evidence(
        &mut self,
        evidence_id: &str,
        attester_id: impl Into<String>,
        stake_bps: u64,
    ) -> Result<()> {
        let evidence = self
            .evidence
            .get_mut(evidence_id)
            .ok_or_else(|| "unknown evidence".to_string())?;
        evidence.attest(attester_id, stake_bps, self.config.quorum_bps);
        if evidence.status == EvidenceStatus::Slashable {
            if let Some(relay) = self.relays.get_mut(&evidence.accused_relay_id) {
                relay.apply_slash(evidence.slash_bps);
            }
        }
        self.recompute_counters();
        self.refresh_roots();
        Ok(())
    }

    pub fn finalize_inclusion(&mut self, ticket_id: &str) -> Result<()> {
        let ticket = self
            .tickets
            .get_mut(ticket_id)
            .ok_or_else(|| "unknown ticket".to_string())?;
        ticket.mark_included();
        self.recompute_counters();
        self.refresh_roots();
        Ok(())
    }

    pub fn relay_stake_weight_bps(&self, relay_id: &str) -> u64 {
        let total = self
            .relays
            .values()
            .map(RelayOperator::effective_weight)
            .sum::<u128>();
        if total == 0 {
            return 0;
        }
        let relay_weight = self
            .relays
            .get(relay_id)
            .map(RelayOperator::effective_weight)
            .unwrap_or_default();
        ((relay_weight.saturating_mul(MAX_BPS as u128)) / total) as u64
    }

    pub fn public_record(&self) -> Value {
        public_record(self)
    }

    pub fn state_root(&self) -> String {
        state_root(self)
    }

    fn emit_public_record(&mut self, slot: u64, kind: &str, subject_id: &str, record: &Value) {
        let public_root = domain_hash(
            "ACCOUNTABLE-MEMPOOL-PUBLIC-LOG-ENTRY",
            &[
                HashPart::Str(kind),
                HashPart::Str(subject_id),
                HashPart::Json(record),
            ],
            32,
        );
        let record_id = domain_hash(
            "ACCOUNTABLE-MEMPOOL-PUBLIC-LOG-ID",
            &[
                HashPart::Str(kind),
                HashPart::Str(subject_id),
                HashPart::U64(slot),
            ],
            16,
        );
        self.public_log.push(PublicLogEntry {
            record_id,
            slot,
            record_kind: kind.to_string(),
            subject_id: subject_id.to_string(),
            public_root,
        });
    }

    fn recompute_counters(&mut self) {
        self.counters.epochs = self.current_epoch.saturating_add(1);
        self.counters.windows_opened = if self.current_window_id.is_empty() {
            0
        } else {
            1
        };
        self.counters.tickets_encrypted = self.tickets.len() as u64;
        self.counters.tickets_admitted = self
            .tickets
            .values()
            .filter(|ticket| ticket.status >= TicketStatus::Admitted)
            .count() as u64;
        self.counters.tickets_relayed = self
            .tickets
            .values()
            .filter(|ticket| ticket.status >= TicketStatus::Relayed)
            .count() as u64;
        self.counters.tickets_ordered = self
            .tickets
            .values()
            .filter(|ticket| {
                ticket.status == TicketStatus::Ordered || ticket.status == TicketStatus::Included
            })
            .count() as u64;
        self.counters.tickets_included = self
            .tickets
            .values()
            .filter(|ticket| ticket.status == TicketStatus::Included)
            .count() as u64;
        self.counters.tickets_deferred = self
            .tickets
            .values()
            .filter(|ticket| ticket.status == TicketStatus::Deferred)
            .count() as u64;
        self.counters.tickets_rejected = self
            .tickets
            .values()
            .filter(|ticket| ticket.status == TicketStatus::Rejected)
            .count() as u64;
        self.counters.low_fee_tickets = self
            .tickets
            .values()
            .filter(|ticket| ticket.low_fee_requested)
            .count() as u64;
        self.counters.relay_votes = self.relay_records.len() as u64;
        self.counters.ordering_commitments = self.ordering_commitments.len() as u64;
        self.counters.qos_reservations = self.lanes.len() as u64;
        self.counters.spam_evidence_bundles = self.evidence.len() as u64;
        self.counters.slashable_evidence_bundles = self
            .evidence
            .values()
            .filter(|evidence| evidence.status == EvidenceStatus::Slashable)
            .count() as u64;
        self.counters.public_records = self.public_log.len() as u64;
    }

    fn refresh_roots(&mut self) {
        self.roots = self.derive_roots();
    }

    fn derive_roots(&self) -> Roots {
        let config_record = self.config.public_record();
        let counters_record = self.counters.public_record();
        let ticket_leaves = self
            .tickets
            .values()
            .map(AdmissionTicket::public_record)
            .collect::<Vec<_>>();
        let relay_leaves = self
            .relays
            .values()
            .map(RelayOperator::public_record)
            .chain(self.relay_records.values().map(RelayRecord::public_record))
            .collect::<Vec<_>>();
        let lane_leaves = self
            .lanes
            .values()
            .map(QosLane::public_record)
            .collect::<Vec<_>>();
        let ordering_leaves = self
            .ordering_commitments
            .values()
            .map(OrderingCommitment::public_record)
            .collect::<Vec<_>>();
        let evidence_leaves = self
            .evidence
            .values()
            .map(SpamEvidence::public_record)
            .collect::<Vec<_>>();
        let public_log_leaves = self
            .public_log
            .iter()
            .map(PublicLogEntry::public_record)
            .collect::<Vec<_>>();
        let config_root = domain_hash(
            "ACCOUNTABLE-MEMPOOL-CONFIG",
            &[HashPart::Json(&config_record)],
            32,
        );
        let counters_root = domain_hash(
            "ACCOUNTABLE-MEMPOOL-COUNTERS",
            &[HashPart::Json(&counters_record)],
            32,
        );
        let ticket_root = merkle_root("ACCOUNTABLE-MEMPOOL-TICKETS", &ticket_leaves);
        let relay_root = merkle_root("ACCOUNTABLE-MEMPOOL-RELAYS", &relay_leaves);
        let lane_root = merkle_root("ACCOUNTABLE-MEMPOOL-LANES", &lane_leaves);
        let ordering_root = merkle_root("ACCOUNTABLE-MEMPOOL-ORDERING", &ordering_leaves);
        let evidence_root = merkle_root("ACCOUNTABLE-MEMPOOL-EVIDENCE", &evidence_leaves);
        let public_log_root = merkle_root("ACCOUNTABLE-MEMPOOL-PUBLIC-LOG", &public_log_leaves);
        let state_root = domain_hash(
            "ACCOUNTABLE-MEMPOOL-STATE",
            &[
                HashPart::Str(&config_root),
                HashPart::Str(&ticket_root),
                HashPart::Str(&relay_root),
                HashPart::Str(&lane_root),
                HashPart::Str(&ordering_root),
                HashPart::Str(&evidence_root),
                HashPart::Str(&public_log_root),
                HashPart::Str(&counters_root),
                HashPart::U64(self.current_epoch),
                HashPart::U64(self.current_slot),
                HashPart::Str(&self.current_window_id),
            ],
            32,
        );
        Roots {
            config_root,
            ticket_root,
            relay_root,
            lane_root,
            ordering_root,
            evidence_root,
            public_log_root,
            counters_root,
            state_root,
        }
    }
}

pub fn devnet() -> State {
    let mut state = State::new(Config::default());
    state.current_epoch = 4_386;
    state.current_slot = DEVNET_L2_HEIGHT;
    state.current_window_id = "window-devnet-4386-0007".to_string();

    let _ = state.add_lane(QosLane::new(
        "lane-wallet-low-fee",
        LaneKind::WalletLowFee,
        TicketClass::WalletTransfer.low_fee_floor_bps(),
    ));
    let _ = state.add_lane(QosLane::new(
        "lane-monero-bridge",
        LaneKind::MoneroBridge,
        TicketClass::MoneroDeposit.low_fee_floor_bps(),
    ));
    let _ = state.add_lane(QosLane::new(
        "lane-proof-aggregation",
        LaneKind::ProofAggregation,
        TicketClass::ProofAggregation.low_fee_floor_bps(),
    ));
    let _ = state.add_lane(QosLane::new(
        "lane-emergency",
        LaneKind::Emergency,
        TicketClass::Emergency.low_fee_floor_bps(),
    ));

    let _ = state.add_relay(RelayOperator::new(
        "relay-alpha",
        RelayRole::StakeWeightedRelay,
        90_000_000,
    ));
    let _ = state.add_relay(RelayOperator::new(
        "relay-builder",
        RelayRole::Builder,
        120_000_000,
    ));
    let _ = state.add_relay(RelayOperator::new(
        "relay-watchtower",
        RelayRole::Watcher,
        25_000_000,
    ));
    let _ = state.add_relay(RelayOperator::new(
        "relay-low-fee-sponsor",
        RelayRole::LowFeeSponsor,
        40_000_000,
    ));

    let wallet_ticket = AdmissionTicket::new(
        "ticket-wallet-0001",
        "lane-wallet-low-fee",
        state.current_window_id.clone(),
        TicketClass::WalletTransfer,
        state.current_slot,
        true,
        5,
    );
    let bridge_ticket = AdmissionTicket::new(
        "ticket-bridge-0002",
        "lane-monero-bridge",
        state.current_window_id.clone(),
        TicketClass::MoneroDeposit,
        state.current_slot + 1,
        true,
        7,
    );
    let proof_ticket = AdmissionTicket::new(
        "ticket-proof-0003",
        "lane-proof-aggregation",
        state.current_window_id.clone(),
        TicketClass::ProofAggregation,
        state.current_slot + 2,
        true,
        3,
    );
    let emergency_ticket = AdmissionTicket::new(
        "ticket-emergency-0004",
        "lane-emergency",
        state.current_window_id.clone(),
        TicketClass::Emergency,
        state.current_slot + 3,
        false,
        1,
    );

    let _ = state.admit_ticket(wallet_ticket);
    let _ = state.admit_ticket(bridge_ticket);
    let _ = state.admit_ticket(proof_ticket);
    let _ = state.admit_ticket(emergency_ticket);
    let _ = state.relay_ticket("relay-alpha", "ticket-wallet-0001", true, "accepted");
    let _ = state.relay_ticket("relay-builder", "ticket-bridge-0002", true, "accepted");
    let _ = state.relay_ticket(
        "relay-low-fee-sponsor",
        "ticket-proof-0003",
        true,
        "accepted",
    );
    let _ = state.relay_ticket("relay-builder", "ticket-emergency-0004", true, "accepted");
    let _ = state.commit_ordering(
        "relay-builder",
        &state.current_window_id.clone(),
        vec![
            "ticket-emergency-0004".to_string(),
            "ticket-bridge-0002".to_string(),
            "ticket-wallet-0001".to_string(),
            "ticket-proof-0003".to_string(),
        ],
    );
    let evidence_ticket_roots = state
        .tickets
        .values()
        .take(2)
        .map(AdmissionTicket::root)
        .collect::<Vec<_>>();
    let evidence = SpamEvidence::new(
        "evidence-duplicate-ticket-demo",
        EvidenceKind::DuplicateTicket,
        "relay-alpha",
        state.current_window_id.clone(),
        state.current_slot + 4,
        evidence_ticket_roots,
    );
    let _ = state.add_evidence(evidence);
    let _ = state.attest_evidence("evidence-duplicate-ticket-demo", "relay-watchtower", 3_400);
    state.recompute_counters();
    state.refresh_roots();
    state
}

pub fn demo() -> State {
    let mut state = devnet();
    let _ = state.finalize_inclusion("ticket-emergency-0004");
    let _ = state.finalize_inclusion("ticket-bridge-0002");
    state.recompute_counters();
    state.refresh_roots();
    state
}

pub fn public_record(state: &State) -> Value {
    let roots = state.derive_roots();
    json!({
        "config": state.config.public_record(),
        "counters": state.counters.public_record(),
        "current_epoch": state.current_epoch,
        "current_slot": state.current_slot,
        "current_window_id": state.current_window_id,
        "deterministic_public_records": state.public_log.iter().map(PublicLogEntry::public_record).collect::<Vec<_>>(),
        "devnet_l2_height": DEVNET_L2_HEIGHT,
        "devnet_monero_height": DEVNET_MONERO_HEIGHT,
        "evidence": state.evidence.values().map(SpamEvidence::public_record).collect::<Vec<_>>(),
        "lanes": state.lanes.values().map(QosLane::public_record).collect::<Vec<_>>(),
        "ordering_commitments": state.ordering_commitments.values().map(OrderingCommitment::public_record).collect::<Vec<_>>(),
        "protocol_version": PROTOCOL_VERSION,
        "relay_records": state.relay_records.values().map(RelayRecord::public_record).collect::<Vec<_>>(),
        "relays": state.relays.values().map(RelayOperator::public_record).collect::<Vec<_>>(),
        "roots": roots.public_record(),
        "tickets": state.tickets.values().map(AdmissionTicket::public_record).collect::<Vec<_>>(),
    })
}

pub fn state_root(state: &State) -> String {
    state.derive_roots().state_root
}
