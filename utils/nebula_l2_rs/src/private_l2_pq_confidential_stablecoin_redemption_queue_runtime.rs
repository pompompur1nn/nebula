use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2PqConfidentialStablecoinRedemptionQueueRuntimeResult<T> = Result<T, String>;
pub type Runtime = State;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_STABLECOIN_REDEMPTION_QUEUE_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-confidential-stablecoin-redemption-queue-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_STABLECOIN_REDEMPTION_QUEUE_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_CUSTODIAN_ATTESTATION_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-custodian-redemption-v1";
pub const SHIELDED_TICKET_SUITE: &str =
    "ringct-shielded-redemption-ticket-nullifier-amount-commitment-v1";
pub const RESERVE_LANE_SUITE: &str = "confidential-stablecoin-redemption-reserve-lane-root-v1";
pub const BATCHING_SUITE: &str = "private-l2-pq-confidential-stablecoin-redemption-batch-root-v1";
pub const FEE_CAP_SUITE: &str = "withdrawal-fee-cap-redacted-policy-root-v1";
pub const PRIVACY_REDACTION_SUITE: &str =
    "selective-disclosure-redaction-budget-accounting-root-v1";
pub const BACKPRESSURE_SUITE: &str = "redemption-queue-backpressure-quarantine-accounting-root-v1";
pub const PUBLIC_RECORD_SUITE: &str =
    "roots-only-pq-confidential-stablecoin-redemption-queue-public-record-v1";
pub const DEVNET_L2_NETWORK: &str = "nebula-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_STABLE_ASSET_ID: &str = "asset:private-dusd";
pub const DEVNET_RESERVE_ASSET_ID: &str = "asset:wxmr";
pub const DEVNET_FEE_ASSET_ID: &str = "asset:piconero";
pub const DEVNET_QUEUE_ID: &str = "private-l2-pq-confidential-stablecoin-redemption-queue-devnet";
pub const DEVNET_HEIGHT: u64 = 2_460_000;
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_TARGET_BATCH_SIZE: usize = 512;
pub const DEFAULT_MAX_BATCH_SIZE: usize = 4_096;
pub const DEFAULT_MAX_TICKET_AGE_BLOCKS: u64 = 720;
pub const DEFAULT_MAX_ATTESTATION_AGE_BLOCKS: u64 = 180;
pub const DEFAULT_REDEMPTION_TTL_BLOCKS: u64 = 1_440;
pub const DEFAULT_MAX_WITHDRAWAL_FEE_BPS: u64 = 12;
pub const DEFAULT_MAX_EXPEDITE_FEE_BPS: u64 = 8;
pub const DEFAULT_MIN_RESERVE_COVERAGE_BPS: u64 = 10_100;
pub const DEFAULT_QUARANTINE_RELEASE_DELAY_BLOCKS: u64 = 360;
pub const DEFAULT_BACKPRESSURE_SOFT_LIMIT: usize = 32_768;
pub const DEFAULT_BACKPRESSURE_HARD_LIMIT: usize = 65_536;
pub const DEFAULT_PRIVACY_REDACTION_BUDGET: u64 = 24;
pub const DEFAULT_CUSTODIAN_QUORUM: u16 = 4;
pub const DEFAULT_MAX_PUBLIC_RECORDS: usize = 4_194_304;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RedemptionLaneKind {
    Standard,
    Expedited,
    Institutional,
    Emergency,
    Quarantine,
}

impl RedemptionLaneKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Standard => "standard",
            Self::Expedited => "expedited",
            Self::Institutional => "institutional",
            Self::Emergency => "emergency",
            Self::Quarantine => "quarantine",
        }
    }

    pub fn may_expedite(self) -> bool {
        matches!(
            self,
            Self::Expedited | Self::Institutional | Self::Emergency
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TicketStatus {
    Shielded,
    Admitted,
    LaneReserved,
    Attested,
    Batched,
    Settled,
    Quarantined,
    Rejected,
    Expired,
}

impl TicketStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Shielded => "shielded",
            Self::Admitted => "admitted",
            Self::LaneReserved => "lane_reserved",
            Self::Attested => "attested",
            Self::Batched => "batched",
            Self::Settled => "settled",
            Self::Quarantined => "quarantined",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }

    pub fn queue_live(self) -> bool {
        matches!(
            self,
            Self::Shielded | Self::Admitted | Self::LaneReserved | Self::Attested
        )
    }

    pub fn batchable(self) -> bool {
        matches!(self, Self::LaneReserved | Self::Attested)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReserveLaneStatus {
    Open,
    Throttled,
    Depleted,
    Rebalancing,
    Paused,
}

impl ReserveLaneStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Throttled => "throttled",
            Self::Depleted => "depleted",
            Self::Rebalancing => "rebalancing",
            Self::Paused => "paused",
        }
    }

    pub fn accepts(self) -> bool {
        matches!(self, Self::Open | Self::Throttled | Self::Rebalancing)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationVerdict {
    Covered,
    CoveredWithHaircut,
    HoldForReserve,
    HoldForRisk,
    Reject,
}

impl AttestationVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Covered => "covered",
            Self::CoveredWithHaircut => "covered_with_haircut",
            Self::HoldForReserve => "hold_for_reserve",
            Self::HoldForRisk => "hold_for_risk",
            Self::Reject => "reject",
        }
    }

    pub fn permits_release(self) -> bool {
        matches!(self, Self::Covered | Self::CoveredWithHaircut)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchStatus {
    Open,
    Ready,
    Submitted,
    Settled,
    Disputed,
    Expired,
}

impl BatchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Ready => "ready",
            Self::Submitted => "submitted",
            Self::Settled => "settled",
            Self::Disputed => "disputed",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QuarantineReason {
    NullifierReplay,
    FeeCapExceeded,
    ReserveCoverageLow,
    AttestationMissing,
    PrivacyBudgetExceeded,
    BackpressureHardLimit,
    OperatorChallenge,
}

impl QuarantineReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NullifierReplay => "nullifier_replay",
            Self::FeeCapExceeded => "fee_cap_exceeded",
            Self::ReserveCoverageLow => "reserve_coverage_low",
            Self::AttestationMissing => "attestation_missing",
            Self::PrivacyBudgetExceeded => "privacy_budget_exceeded",
            Self::BackpressureHardLimit => "backpressure_hard_limit",
            Self::OperatorChallenge => "operator_challenge",
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub l2_network: String,
    pub monero_network: String,
    pub queue_id: String,
    pub stable_asset_id: String,
    pub reserve_asset_id: String,
    pub fee_asset_id: String,
    pub hash_suite: String,
    pub pq_custodian_attestation_suite: String,
    pub shielded_ticket_suite: String,
    pub reserve_lane_suite: String,
    pub batching_suite: String,
    pub fee_cap_suite: String,
    pub privacy_redaction_suite: String,
    pub backpressure_suite: String,
    pub min_pq_security_bits: u16,
    pub custodian_quorum: u16,
    pub min_privacy_set_size: u64,
    pub target_batch_size: usize,
    pub max_batch_size: usize,
    pub max_ticket_age_blocks: u64,
    pub max_attestation_age_blocks: u64,
    pub redemption_ttl_blocks: u64,
    pub max_withdrawal_fee_bps: u64,
    pub max_expedite_fee_bps: u64,
    pub min_reserve_coverage_bps: u64,
    pub quarantine_release_delay_blocks: u64,
    pub backpressure_soft_limit: usize,
    pub backpressure_hard_limit: usize,
    pub privacy_redaction_budget: u64,
    pub max_public_records: usize,
    pub deterministic_public_records: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            l2_network: DEVNET_L2_NETWORK.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            queue_id: DEVNET_QUEUE_ID.to_string(),
            stable_asset_id: DEVNET_STABLE_ASSET_ID.to_string(),
            reserve_asset_id: DEVNET_RESERVE_ASSET_ID.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            hash_suite: HASH_SUITE.to_string(),
            pq_custodian_attestation_suite: PQ_CUSTODIAN_ATTESTATION_SUITE.to_string(),
            shielded_ticket_suite: SHIELDED_TICKET_SUITE.to_string(),
            reserve_lane_suite: RESERVE_LANE_SUITE.to_string(),
            batching_suite: BATCHING_SUITE.to_string(),
            fee_cap_suite: FEE_CAP_SUITE.to_string(),
            privacy_redaction_suite: PRIVACY_REDACTION_SUITE.to_string(),
            backpressure_suite: BACKPRESSURE_SUITE.to_string(),
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            custodian_quorum: DEFAULT_CUSTODIAN_QUORUM,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_batch_size: DEFAULT_TARGET_BATCH_SIZE,
            max_batch_size: DEFAULT_MAX_BATCH_SIZE,
            max_ticket_age_blocks: DEFAULT_MAX_TICKET_AGE_BLOCKS,
            max_attestation_age_blocks: DEFAULT_MAX_ATTESTATION_AGE_BLOCKS,
            redemption_ttl_blocks: DEFAULT_REDEMPTION_TTL_BLOCKS,
            max_withdrawal_fee_bps: DEFAULT_MAX_WITHDRAWAL_FEE_BPS,
            max_expedite_fee_bps: DEFAULT_MAX_EXPEDITE_FEE_BPS,
            min_reserve_coverage_bps: DEFAULT_MIN_RESERVE_COVERAGE_BPS,
            quarantine_release_delay_blocks: DEFAULT_QUARANTINE_RELEASE_DELAY_BLOCKS,
            backpressure_soft_limit: DEFAULT_BACKPRESSURE_SOFT_LIMIT,
            backpressure_hard_limit: DEFAULT_BACKPRESSURE_HARD_LIMIT,
            privacy_redaction_budget: DEFAULT_PRIVACY_REDACTION_BUDGET,
            max_public_records: DEFAULT_MAX_PUBLIC_RECORDS,
            deterministic_public_records: true,
        }
    }
}

impl Config {
    pub fn devnet() -> Self {
        Self::default()
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "l2_network": self.l2_network,
            "monero_network": self.monero_network,
            "queue_id": self.queue_id,
            "stable_asset_id": self.stable_asset_id,
            "reserve_asset_id": self.reserve_asset_id,
            "fee_asset_id": self.fee_asset_id,
            "hash_suite": self.hash_suite,
            "pq_custodian_attestation_suite": self.pq_custodian_attestation_suite,
            "shielded_ticket_suite": self.shielded_ticket_suite,
            "reserve_lane_suite": self.reserve_lane_suite,
            "batching_suite": self.batching_suite,
            "fee_cap_suite": self.fee_cap_suite,
            "privacy_redaction_suite": self.privacy_redaction_suite,
            "backpressure_suite": self.backpressure_suite,
            "min_pq_security_bits": self.min_pq_security_bits,
            "custodian_quorum": self.custodian_quorum,
            "min_privacy_set_size": self.min_privacy_set_size,
            "target_batch_size": self.target_batch_size,
            "max_batch_size": self.max_batch_size,
            "max_ticket_age_blocks": self.max_ticket_age_blocks,
            "max_attestation_age_blocks": self.max_attestation_age_blocks,
            "redemption_ttl_blocks": self.redemption_ttl_blocks,
            "max_withdrawal_fee_bps": self.max_withdrawal_fee_bps,
            "max_expedite_fee_bps": self.max_expedite_fee_bps,
            "min_reserve_coverage_bps": self.min_reserve_coverage_bps,
            "quarantine_release_delay_blocks": self.quarantine_release_delay_blocks,
            "backpressure_soft_limit": self.backpressure_soft_limit,
            "backpressure_hard_limit": self.backpressure_hard_limit,
            "privacy_redaction_budget": self.privacy_redaction_budget,
            "max_public_records": self.max_public_records,
            "deterministic_public_records": self.deterministic_public_records,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq, Serialize)]
pub struct Counters {
    pub ticket_counter: u64,
    pub admitted_ticket_counter: u64,
    pub reserve_lane_counter: u64,
    pub lane_assignment_counter: u64,
    pub custodian_attestation_counter: u64,
    pub batch_counter: u64,
    pub settlement_counter: u64,
    pub fee_cap_counter: u64,
    pub redaction_counter: u64,
    pub quarantine_counter: u64,
    pub released_quarantine_counter: u64,
    pub backpressure_event_counter: u64,
    pub consumed_nullifier_counter: u64,
    pub public_record_counter: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "ticket_counter": self.ticket_counter,
            "admitted_ticket_counter": self.admitted_ticket_counter,
            "reserve_lane_counter": self.reserve_lane_counter,
            "lane_assignment_counter": self.lane_assignment_counter,
            "custodian_attestation_counter": self.custodian_attestation_counter,
            "batch_counter": self.batch_counter,
            "settlement_counter": self.settlement_counter,
            "fee_cap_counter": self.fee_cap_counter,
            "redaction_counter": self.redaction_counter,
            "quarantine_counter": self.quarantine_counter,
            "released_quarantine_counter": self.released_quarantine_counter,
            "backpressure_event_counter": self.backpressure_event_counter,
            "consumed_nullifier_counter": self.consumed_nullifier_counter,
            "public_record_counter": self.public_record_counter,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub counters_root: String,
    pub shielded_ticket_root: String,
    pub admitted_queue_root: String,
    pub reserve_lane_root: String,
    pub lane_assignment_root: String,
    pub custodian_attestation_root: String,
    pub batch_root: String,
    pub settlement_root: String,
    pub fee_cap_root: String,
    pub privacy_redaction_budget_root: String,
    pub backpressure_root: String,
    pub quarantine_root: String,
    pub consumed_nullifier_root: String,
    pub deterministic_public_record_root: String,
    pub public_record_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "counters_root": self.counters_root,
            "shielded_ticket_root": self.shielded_ticket_root,
            "admitted_queue_root": self.admitted_queue_root,
            "reserve_lane_root": self.reserve_lane_root,
            "lane_assignment_root": self.lane_assignment_root,
            "custodian_attestation_root": self.custodian_attestation_root,
            "batch_root": self.batch_root,
            "settlement_root": self.settlement_root,
            "fee_cap_root": self.fee_cap_root,
            "privacy_redaction_budget_root": self.privacy_redaction_budget_root,
            "backpressure_root": self.backpressure_root,
            "quarantine_root": self.quarantine_root,
            "consumed_nullifier_root": self.consumed_nullifier_root,
            "deterministic_public_record_root": self.deterministic_public_record_root,
            "public_record_root": self.public_record_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct ShieldedRedemptionTicketRequest {
    pub redeemer_commitment: String,
    pub stable_burn_root: String,
    pub reserve_destination_root: String,
    pub amount_commitment_root: String,
    pub redemption_nullifier: String,
    pub requested_lane: RedemptionLaneKind,
    pub max_withdrawal_fee_bps: u64,
    pub max_expedite_fee_bps: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub submitted_at_height: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct ShieldedRedemptionTicket {
    pub ticket_id: String,
    pub redeemer_commitment: String,
    pub stable_burn_root: String,
    pub reserve_destination_root: String,
    pub amount_commitment_root: String,
    pub redemption_nullifier_hash: String,
    pub requested_lane: RedemptionLaneKind,
    pub assigned_lane_id: Option<String>,
    pub status: TicketStatus,
    pub max_withdrawal_fee_bps: u64,
    pub max_expedite_fee_bps: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub submitted_at_height: u64,
    pub expires_at_height: u64,
    pub attestation_ids: Vec<String>,
    pub batch_id: Option<String>,
    pub quarantine_id: Option<String>,
}

impl ShieldedRedemptionTicket {
    pub fn public_record(&self) -> Value {
        json!({
            "ticket_id": self.ticket_id,
            "redeemer_commitment": self.redeemer_commitment,
            "stable_burn_root": self.stable_burn_root,
            "reserve_destination_root": self.reserve_destination_root,
            "amount_commitment_root": self.amount_commitment_root,
            "redemption_nullifier_hash": self.redemption_nullifier_hash,
            "requested_lane": self.requested_lane.as_str(),
            "assigned_lane_id": self.assigned_lane_id,
            "status": self.status.as_str(),
            "max_withdrawal_fee_bps": self.max_withdrawal_fee_bps,
            "max_expedite_fee_bps": self.max_expedite_fee_bps,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "submitted_at_height": self.submitted_at_height,
            "expires_at_height": self.expires_at_height,
            "attestation_ids": self.attestation_ids,
            "batch_id": self.batch_id,
            "quarantine_id": self.quarantine_id,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct ReserveLaneRequest {
    pub lane_kind: RedemptionLaneKind,
    pub lane_operator_commitment: String,
    pub reserve_commitment_root: String,
    pub withdrawal_policy_root: String,
    pub capacity_commitment_root: String,
    pub coverage_bps: u64,
    pub fee_cap_bps: u64,
    pub opened_at_height: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct ReserveLane {
    pub lane_id: String,
    pub lane_kind: RedemptionLaneKind,
    pub lane_operator_commitment: String,
    pub reserve_commitment_root: String,
    pub withdrawal_policy_root: String,
    pub capacity_commitment_root: String,
    pub coverage_bps: u64,
    pub fee_cap_bps: u64,
    pub status: ReserveLaneStatus,
    pub opened_at_height: u64,
    pub assigned_tickets: u64,
    pub batched_tickets: u64,
}

impl ReserveLane {
    pub fn public_record(&self) -> Value {
        json!({
            "lane_id": self.lane_id,
            "lane_kind": self.lane_kind.as_str(),
            "lane_operator_commitment": self.lane_operator_commitment,
            "reserve_commitment_root": self.reserve_commitment_root,
            "withdrawal_policy_root": self.withdrawal_policy_root,
            "capacity_commitment_root": self.capacity_commitment_root,
            "coverage_bps": self.coverage_bps,
            "fee_cap_bps": self.fee_cap_bps,
            "status": self.status.as_str(),
            "opened_at_height": self.opened_at_height,
            "assigned_tickets": self.assigned_tickets,
            "batched_tickets": self.batched_tickets,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct CustodianAttestationRequest {
    pub ticket_id: String,
    pub lane_id: String,
    pub custodian_commitment: String,
    pub reserve_proof_root: String,
    pub pq_attestation_root: String,
    pub coverage_bps: u64,
    pub verdict: AttestationVerdict,
    pub attestation_nullifier: String,
    pub attested_at_height: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct CustodianAttestation {
    pub attestation_id: String,
    pub ticket_id: String,
    pub lane_id: String,
    pub custodian_commitment: String,
    pub reserve_proof_root: String,
    pub pq_attestation_root: String,
    pub coverage_bps: u64,
    pub verdict: AttestationVerdict,
    pub attestation_nullifier_hash: String,
    pub attested_at_height: u64,
    pub expires_at_height: u64,
}

impl CustodianAttestation {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "ticket_id": self.ticket_id,
            "lane_id": self.lane_id,
            "custodian_commitment": self.custodian_commitment,
            "reserve_proof_root": self.reserve_proof_root,
            "pq_attestation_root": self.pq_attestation_root,
            "coverage_bps": self.coverage_bps,
            "verdict": self.verdict.as_str(),
            "attestation_nullifier_hash": self.attestation_nullifier_hash,
            "attested_at_height": self.attested_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RedemptionBatchRequest {
    pub ticket_ids: Vec<String>,
    pub lane_ids: Vec<String>,
    pub reserve_delta_root: String,
    pub burn_aggregation_root: String,
    pub withdrawal_output_root: String,
    pub recursive_proof_root: String,
    pub fee_cap_root: String,
    pub privacy_budget_root: String,
    pub built_at_height: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RedemptionBatch {
    pub batch_id: String,
    pub ticket_ids: Vec<String>,
    pub lane_ids: Vec<String>,
    pub reserve_delta_root: String,
    pub burn_aggregation_root: String,
    pub withdrawal_output_root: String,
    pub recursive_proof_root: String,
    pub fee_cap_root: String,
    pub privacy_budget_root: String,
    pub status: BatchStatus,
    pub built_at_height: u64,
    pub submitted_at_height: Option<u64>,
    pub settled_at_height: Option<u64>,
}

impl RedemptionBatch {
    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "ticket_ids": self.ticket_ids,
            "lane_ids": self.lane_ids,
            "reserve_delta_root": self.reserve_delta_root,
            "burn_aggregation_root": self.burn_aggregation_root,
            "withdrawal_output_root": self.withdrawal_output_root,
            "recursive_proof_root": self.recursive_proof_root,
            "fee_cap_root": self.fee_cap_root,
            "privacy_budget_root": self.privacy_budget_root,
            "status": self.status.as_str(),
            "built_at_height": self.built_at_height,
            "submitted_at_height": self.submitted_at_height,
            "settled_at_height": self.settled_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct SettlementReceipt {
    pub receipt_id: String,
    pub batch_id: String,
    pub withdrawal_tx_root: String,
    pub reserve_root_after: String,
    pub queue_root_after: String,
    pub custodian_signature_root: String,
    pub settled_at_height: u64,
}

impl SettlementReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "batch_id": self.batch_id,
            "withdrawal_tx_root": self.withdrawal_tx_root,
            "reserve_root_after": self.reserve_root_after,
            "queue_root_after": self.queue_root_after,
            "custodian_signature_root": self.custodian_signature_root,
            "settled_at_height": self.settled_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct FeeCapSnapshot {
    pub cap_id: String,
    pub lane_id: String,
    pub withdrawal_fee_cap_bps: u64,
    pub expedite_fee_cap_bps: u64,
    pub fee_policy_root: String,
    pub effective_at_height: u64,
}

impl FeeCapSnapshot {
    pub fn public_record(&self) -> Value {
        json!({
            "cap_id": self.cap_id,
            "lane_id": self.lane_id,
            "withdrawal_fee_cap_bps": self.withdrawal_fee_cap_bps,
            "expedite_fee_cap_bps": self.expedite_fee_cap_bps,
            "fee_policy_root": self.fee_policy_root,
            "effective_at_height": self.effective_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct PrivacyRedactionBudget {
    pub budget_id: String,
    pub subject_root: String,
    pub redaction_policy_root: String,
    pub initial_budget: u64,
    pub consumed_budget: u64,
    pub remaining_budget: u64,
    pub epoch: u64,
}

impl PrivacyRedactionBudget {
    pub fn public_record(&self) -> Value {
        json!({
            "budget_id": self.budget_id,
            "subject_root": self.subject_root,
            "redaction_policy_root": self.redaction_policy_root,
            "initial_budget": self.initial_budget,
            "consumed_budget": self.consumed_budget,
            "remaining_budget": self.remaining_budget,
            "epoch": self.epoch,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct QuarantineEntry {
    pub quarantine_id: String,
    pub ticket_id: String,
    pub reason: QuarantineReason,
    pub evidence_root: String,
    pub entered_at_height: u64,
    pub release_after_height: u64,
    pub released: bool,
}

impl QuarantineEntry {
    pub fn public_record(&self) -> Value {
        json!({
            "quarantine_id": self.quarantine_id,
            "ticket_id": self.ticket_id,
            "reason": self.reason.as_str(),
            "evidence_root": self.evidence_root,
            "entered_at_height": self.entered_at_height,
            "release_after_height": self.release_after_height,
            "released": self.released,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq, Serialize)]
pub struct BackpressureAccounting {
    pub live_queue_depth: u64,
    pub soft_limit_events: u64,
    pub hard_limit_events: u64,
    pub quarantined_tickets: u64,
    pub throttled_lanes: u64,
    pub rejected_tickets: u64,
    pub last_event_height: u64,
    pub pressure_root: String,
}

impl BackpressureAccounting {
    pub fn public_record(&self) -> Value {
        json!({
            "live_queue_depth": self.live_queue_depth,
            "soft_limit_events": self.soft_limit_events,
            "hard_limit_events": self.hard_limit_events,
            "quarantined_tickets": self.quarantined_tickets,
            "throttled_lanes": self.throttled_lanes,
            "rejected_tickets": self.rejected_tickets,
            "last_event_height": self.last_event_height,
            "pressure_root": self.pressure_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub current_height: u64,
    pub shielded_tickets: BTreeMap<String, ShieldedRedemptionTicket>,
    pub admitted_queue: BTreeSet<String>,
    pub reserve_lanes: BTreeMap<String, ReserveLane>,
    pub lane_assignments: BTreeMap<String, String>,
    pub custodian_attestations: BTreeMap<String, CustodianAttestation>,
    pub batches: BTreeMap<String, RedemptionBatch>,
    pub settlement_receipts: BTreeMap<String, SettlementReceipt>,
    pub fee_caps: BTreeMap<String, FeeCapSnapshot>,
    pub privacy_redaction_budgets: BTreeMap<String, PrivacyRedactionBudget>,
    pub quarantine_entries: BTreeMap<String, QuarantineEntry>,
    pub consumed_nullifiers: BTreeSet<String>,
    pub deterministic_public_records: Vec<Value>,
    pub backpressure: BackpressureAccounting,
}

impl Default for State {
    fn default() -> Self {
        Self::devnet()
    }
}

impl State {
    pub fn new(config: Config, current_height: u64) -> Self {
        Self {
            config,
            counters: Counters::default(),
            current_height,
            shielded_tickets: BTreeMap::new(),
            admitted_queue: BTreeSet::new(),
            reserve_lanes: BTreeMap::new(),
            lane_assignments: BTreeMap::new(),
            custodian_attestations: BTreeMap::new(),
            batches: BTreeMap::new(),
            settlement_receipts: BTreeMap::new(),
            fee_caps: BTreeMap::new(),
            privacy_redaction_budgets: BTreeMap::new(),
            quarantine_entries: BTreeMap::new(),
            consumed_nullifiers: BTreeSet::new(),
            deterministic_public_records: Vec::new(),
            backpressure: BackpressureAccounting::default(),
        }
    }

    pub fn devnet() -> Self {
        Self::new(Config::devnet(), DEVNET_HEIGHT)
    }

    pub fn demo() -> Self {
        let mut state = Self::devnet();
        let lane_id = state
            .open_reserve_lane(ReserveLaneRequest {
                lane_kind: RedemptionLaneKind::Standard,
                lane_operator_commitment: demo_hash("lane-operator-0"),
                reserve_commitment_root: demo_hash("reserve-commitment-0"),
                withdrawal_policy_root: demo_hash("withdrawal-policy-0"),
                capacity_commitment_root: demo_hash("capacity-commitment-0"),
                coverage_bps: 10_250,
                fee_cap_bps: 10,
                opened_at_height: DEVNET_HEIGHT,
            })
            .expect("demo reserve lane should open");
        let ticket_id = state
            .submit_ticket(ShieldedRedemptionTicketRequest {
                redeemer_commitment: demo_hash("redeemer-0"),
                stable_burn_root: demo_hash("stable-burn-0"),
                reserve_destination_root: demo_hash("reserve-destination-0"),
                amount_commitment_root: demo_hash("amount-commitment-0"),
                redemption_nullifier: demo_hash("redemption-nullifier-0"),
                requested_lane: RedemptionLaneKind::Standard,
                max_withdrawal_fee_bps: 10,
                max_expedite_fee_bps: 0,
                privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
                pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
                submitted_at_height: DEVNET_HEIGHT + 1,
            })
            .expect("demo ticket should submit");
        state
            .assign_lane(&ticket_id, &lane_id, DEVNET_HEIGHT + 2)
            .expect("demo lane assignment should work");
        state
            .publish_custodian_attestation(CustodianAttestationRequest {
                ticket_id: ticket_id.clone(),
                lane_id: lane_id.clone(),
                custodian_commitment: demo_hash("custodian-0"),
                reserve_proof_root: demo_hash("reserve-proof-0"),
                pq_attestation_root: demo_hash("pq-attestation-0"),
                coverage_bps: 10_250,
                verdict: AttestationVerdict::Covered,
                attestation_nullifier: demo_hash("attestation-nullifier-0"),
                attested_at_height: DEVNET_HEIGHT + 3,
            })
            .expect("demo attestation should publish");
        let cap_id = state
            .record_fee_cap(
                &lane_id,
                10,
                0,
                demo_hash("fee-policy-0"),
                DEVNET_HEIGHT + 3,
            )
            .expect("demo fee cap should record");
        let budget_id = state
            .open_privacy_redaction_budget(
                demo_hash("subject-0"),
                demo_hash("redaction-policy-0"),
                DEFAULT_PRIVACY_REDACTION_BUDGET,
                1,
            )
            .expect("demo redaction budget should open");
        let batch_id = state
            .build_batch(RedemptionBatchRequest {
                ticket_ids: vec![ticket_id],
                lane_ids: vec![lane_id],
                reserve_delta_root: demo_hash("reserve-delta-0"),
                burn_aggregation_root: demo_hash("burn-aggregation-0"),
                withdrawal_output_root: demo_hash("withdrawal-output-0"),
                recursive_proof_root: demo_hash("recursive-proof-0"),
                fee_cap_root: cap_id,
                privacy_budget_root: budget_id,
                built_at_height: DEVNET_HEIGHT + 4,
            })
            .expect("demo batch should build");
        state
            .settle_batch(
                &batch_id,
                demo_hash("withdrawal-tx-0"),
                demo_hash("reserve-after-0"),
                demo_hash("queue-after-0"),
                demo_hash("custodian-sig-0"),
                DEVNET_HEIGHT + 8,
            )
            .expect("demo batch should settle");
        state
    }

    pub fn submit_ticket(
        &mut self,
        request: ShieldedRedemptionTicketRequest,
    ) -> PrivateL2PqConfidentialStablecoinRedemptionQueueRuntimeResult<String> {
        self.validate_ticket_request(&request)?;
        self.consume_nullifier(&request.redemption_nullifier)?;
        self.apply_backpressure(request.submitted_at_height)?;
        let ticket_id = shielded_ticket_id(&request, self.counters.ticket_counter);
        let ticket = ShieldedRedemptionTicket {
            ticket_id: ticket_id.clone(),
            redeemer_commitment: request.redeemer_commitment,
            stable_burn_root: request.stable_burn_root,
            reserve_destination_root: request.reserve_destination_root,
            amount_commitment_root: request.amount_commitment_root,
            redemption_nullifier_hash: payload_id(
                "REDEMPTION-NULLIFIER-HASH",
                &[HashPart::Str(&request.redemption_nullifier)],
            ),
            requested_lane: request.requested_lane,
            assigned_lane_id: None,
            status: TicketStatus::Admitted,
            max_withdrawal_fee_bps: request.max_withdrawal_fee_bps,
            max_expedite_fee_bps: request.max_expedite_fee_bps,
            privacy_set_size: request.privacy_set_size,
            pq_security_bits: request.pq_security_bits,
            submitted_at_height: request.submitted_at_height,
            expires_at_height: request
                .submitted_at_height
                .saturating_add(self.config.redemption_ttl_blocks),
            attestation_ids: Vec::new(),
            batch_id: None,
            quarantine_id: None,
        };
        self.admitted_queue.insert(ticket_id.clone());
        self.shielded_tickets.insert(ticket_id.clone(), ticket);
        self.counters.ticket_counter = self.counters.ticket_counter.saturating_add(1);
        self.counters.admitted_ticket_counter =
            self.counters.admitted_ticket_counter.saturating_add(1);
        self.backpressure.live_queue_depth = self.live_queue_depth();
        self.push_public_record("ticket_admitted", &ticket_id);
        Ok(ticket_id)
    }

    pub fn open_reserve_lane(
        &mut self,
        request: ReserveLaneRequest,
    ) -> PrivateL2PqConfidentialStablecoinRedemptionQueueRuntimeResult<String> {
        require_non_empty(
            "lane_operator_commitment",
            &request.lane_operator_commitment,
        )?;
        require_non_empty("reserve_commitment_root", &request.reserve_commitment_root)?;
        require_non_empty("withdrawal_policy_root", &request.withdrawal_policy_root)?;
        require_non_empty(
            "capacity_commitment_root",
            &request.capacity_commitment_root,
        )?;
        if request.coverage_bps < self.config.min_reserve_coverage_bps {
            return Err("reserve lane coverage below configured minimum".to_string());
        }
        if request.fee_cap_bps > self.config.max_withdrawal_fee_bps {
            return Err("reserve lane fee cap exceeds configured withdrawal cap".to_string());
        }
        let lane_id = reserve_lane_id(&request, self.counters.reserve_lane_counter);
        let lane = ReserveLane {
            lane_id: lane_id.clone(),
            lane_kind: request.lane_kind,
            lane_operator_commitment: request.lane_operator_commitment,
            reserve_commitment_root: request.reserve_commitment_root,
            withdrawal_policy_root: request.withdrawal_policy_root,
            capacity_commitment_root: request.capacity_commitment_root,
            coverage_bps: request.coverage_bps,
            fee_cap_bps: request.fee_cap_bps,
            status: ReserveLaneStatus::Open,
            opened_at_height: request.opened_at_height,
            assigned_tickets: 0,
            batched_tickets: 0,
        };
        self.reserve_lanes.insert(lane_id.clone(), lane);
        self.counters.reserve_lane_counter = self.counters.reserve_lane_counter.saturating_add(1);
        self.push_public_record("reserve_lane_opened", &lane_id);
        Ok(lane_id)
    }

    pub fn assign_lane(
        &mut self,
        ticket_id: &str,
        lane_id: &str,
        assigned_at_height: u64,
    ) -> PrivateL2PqConfidentialStablecoinRedemptionQueueRuntimeResult<()> {
        let ticket = self
            .shielded_tickets
            .get(ticket_id)
            .ok_or_else(|| "shielded redemption ticket not found".to_string())?;
        if !ticket.status.queue_live() {
            return Err("ticket is not live in redemption queue".to_string());
        }
        if ticket.expires_at_height <= assigned_at_height {
            return Err("ticket expired before reserve lane assignment".to_string());
        }
        let lane = self
            .reserve_lanes
            .get(lane_id)
            .ok_or_else(|| "reserve lane not found".to_string())?;
        if !lane.status.accepts() {
            return Err("reserve lane is not accepting assignments".to_string());
        }
        if lane.lane_kind != ticket.requested_lane
            && lane.lane_kind != RedemptionLaneKind::Emergency
        {
            return Err("reserve lane kind does not match requested ticket lane".to_string());
        }
        if ticket.max_withdrawal_fee_bps > lane.fee_cap_bps {
            return Err("ticket withdrawal fee cap is below lane fee requirement".to_string());
        }
        let ticket = self
            .shielded_tickets
            .get_mut(ticket_id)
            .ok_or_else(|| "shielded redemption ticket not found".to_string())?;
        ticket.assigned_lane_id = Some(lane_id.to_string());
        ticket.status = TicketStatus::LaneReserved;
        self.admitted_queue.remove(ticket_id);
        self.lane_assignments
            .insert(ticket_id.to_string(), lane_id.to_string());
        let lane = self
            .reserve_lanes
            .get_mut(lane_id)
            .ok_or_else(|| "reserve lane not found".to_string())?;
        lane.assigned_tickets = lane.assigned_tickets.saturating_add(1);
        self.counters.lane_assignment_counter =
            self.counters.lane_assignment_counter.saturating_add(1);
        self.backpressure.live_queue_depth = self.live_queue_depth();
        self.push_public_record("reserve_lane_assigned", ticket_id);
        Ok(())
    }

    pub fn publish_custodian_attestation(
        &mut self,
        request: CustodianAttestationRequest,
    ) -> PrivateL2PqConfidentialStablecoinRedemptionQueueRuntimeResult<String> {
        require_non_empty("custodian_commitment", &request.custodian_commitment)?;
        require_non_empty("reserve_proof_root", &request.reserve_proof_root)?;
        require_non_empty("pq_attestation_root", &request.pq_attestation_root)?;
        self.consume_nullifier(&request.attestation_nullifier)?;
        let ticket = self
            .shielded_tickets
            .get(&request.ticket_id)
            .ok_or_else(|| "attested ticket not found".to_string())?;
        if ticket.assigned_lane_id.as_deref() != Some(request.lane_id.as_str()) {
            return Err("custodian attestation lane does not match ticket assignment".to_string());
        }
        if request.coverage_bps < self.config.min_reserve_coverage_bps {
            return self.quarantine_ticket(
                &request.ticket_id,
                QuarantineReason::ReserveCoverageLow,
                request.reserve_proof_root,
                request.attested_at_height,
            );
        }
        if !request.verdict.permits_release() {
            return self.quarantine_ticket(
                &request.ticket_id,
                QuarantineReason::AttestationMissing,
                request.pq_attestation_root,
                request.attested_at_height,
            );
        }
        let attestation_id =
            custodian_attestation_id(&request, self.counters.custodian_attestation_counter);
        let attestation = CustodianAttestation {
            attestation_id: attestation_id.clone(),
            ticket_id: request.ticket_id.clone(),
            lane_id: request.lane_id,
            custodian_commitment: request.custodian_commitment,
            reserve_proof_root: request.reserve_proof_root,
            pq_attestation_root: request.pq_attestation_root,
            coverage_bps: request.coverage_bps,
            verdict: request.verdict,
            attestation_nullifier_hash: payload_id(
                "CUSTODIAN-ATTESTATION-NULLIFIER-HASH",
                &[HashPart::Str(&request.attestation_nullifier)],
            ),
            attested_at_height: request.attested_at_height,
            expires_at_height: request
                .attested_at_height
                .saturating_add(self.config.max_attestation_age_blocks),
        };
        self.custodian_attestations
            .insert(attestation_id.clone(), attestation);
        let ticket = self
            .shielded_tickets
            .get_mut(&request.ticket_id)
            .ok_or_else(|| "attested ticket not found".to_string())?;
        ticket.attestation_ids.push(attestation_id.clone());
        ticket.status = TicketStatus::Attested;
        self.counters.custodian_attestation_counter = self
            .counters
            .custodian_attestation_counter
            .saturating_add(1);
        self.push_public_record("custodian_attestation_published", &attestation_id);
        Ok(attestation_id)
    }

    pub fn record_fee_cap(
        &mut self,
        lane_id: &str,
        withdrawal_fee_cap_bps: u64,
        expedite_fee_cap_bps: u64,
        fee_policy_root: String,
        effective_at_height: u64,
    ) -> PrivateL2PqConfidentialStablecoinRedemptionQueueRuntimeResult<String> {
        require_non_empty("fee_policy_root", &fee_policy_root)?;
        if !self.reserve_lanes.contains_key(lane_id) {
            return Err("fee cap lane not found".to_string());
        }
        if withdrawal_fee_cap_bps > self.config.max_withdrawal_fee_bps {
            return Err("withdrawal fee cap exceeds configured maximum".to_string());
        }
        if expedite_fee_cap_bps > self.config.max_expedite_fee_bps {
            return Err("expedite fee cap exceeds configured maximum".to_string());
        }
        let cap_id = payload_id(
            "FEE-CAP-SNAPSHOT-ID",
            &[
                HashPart::Str(lane_id),
                HashPart::U64(withdrawal_fee_cap_bps),
                HashPart::U64(expedite_fee_cap_bps),
                HashPart::Str(&fee_policy_root),
                HashPart::U64(self.counters.fee_cap_counter),
            ],
        );
        let cap = FeeCapSnapshot {
            cap_id: cap_id.clone(),
            lane_id: lane_id.to_string(),
            withdrawal_fee_cap_bps,
            expedite_fee_cap_bps,
            fee_policy_root,
            effective_at_height,
        };
        self.fee_caps.insert(cap_id.clone(), cap);
        self.counters.fee_cap_counter = self.counters.fee_cap_counter.saturating_add(1);
        self.push_public_record("fee_cap_recorded", &cap_id);
        Ok(cap_id)
    }

    pub fn open_privacy_redaction_budget(
        &mut self,
        subject_root: String,
        redaction_policy_root: String,
        initial_budget: u64,
        epoch: u64,
    ) -> PrivateL2PqConfidentialStablecoinRedemptionQueueRuntimeResult<String> {
        require_non_empty("subject_root", &subject_root)?;
        require_non_empty("redaction_policy_root", &redaction_policy_root)?;
        if initial_budget > self.config.privacy_redaction_budget {
            return Err("redaction budget exceeds configured privacy budget".to_string());
        }
        let budget_id = payload_id(
            "PRIVACY-REDACTION-BUDGET-ID",
            &[
                HashPart::Str(&subject_root),
                HashPart::Str(&redaction_policy_root),
                HashPart::U64(initial_budget),
                HashPart::U64(epoch),
                HashPart::U64(self.counters.redaction_counter),
            ],
        );
        let budget = PrivacyRedactionBudget {
            budget_id: budget_id.clone(),
            subject_root,
            redaction_policy_root,
            initial_budget,
            consumed_budget: 0,
            remaining_budget: initial_budget,
            epoch,
        };
        self.privacy_redaction_budgets
            .insert(budget_id.clone(), budget);
        self.counters.redaction_counter = self.counters.redaction_counter.saturating_add(1);
        self.push_public_record("privacy_redaction_budget_opened", &budget_id);
        Ok(budget_id)
    }

    pub fn consume_redaction_budget(
        &mut self,
        budget_id: &str,
        units: u64,
    ) -> PrivateL2PqConfidentialStablecoinRedemptionQueueRuntimeResult<()> {
        let budget = self
            .privacy_redaction_budgets
            .get_mut(budget_id)
            .ok_or_else(|| "privacy redaction budget not found".to_string())?;
        if units > budget.remaining_budget {
            return Err("privacy redaction budget exhausted".to_string());
        }
        budget.consumed_budget = budget.consumed_budget.saturating_add(units);
        budget.remaining_budget = budget.remaining_budget.saturating_sub(units);
        self.push_public_record("privacy_redaction_budget_consumed", budget_id);
        Ok(())
    }

    pub fn build_batch(
        &mut self,
        request: RedemptionBatchRequest,
    ) -> PrivateL2PqConfidentialStablecoinRedemptionQueueRuntimeResult<String> {
        if request.ticket_ids.is_empty() {
            return Err("redemption batch cannot be empty".to_string());
        }
        if request.ticket_ids.len() > self.config.max_batch_size {
            return Err("redemption batch exceeds configured maximum size".to_string());
        }
        if request.lane_ids.is_empty() {
            return Err("redemption batch requires at least one reserve lane".to_string());
        }
        require_non_empty("reserve_delta_root", &request.reserve_delta_root)?;
        require_non_empty("burn_aggregation_root", &request.burn_aggregation_root)?;
        require_non_empty("withdrawal_output_root", &request.withdrawal_output_root)?;
        require_non_empty("recursive_proof_root", &request.recursive_proof_root)?;
        require_non_empty("fee_cap_root", &request.fee_cap_root)?;
        require_non_empty("privacy_budget_root", &request.privacy_budget_root)?;
        for ticket_id in &request.ticket_ids {
            let ticket = self
                .shielded_tickets
                .get(ticket_id)
                .ok_or_else(|| "batch ticket not found".to_string())?;
            validate_ticket_for_batch(ticket, request.built_at_height)?;
            if ticket.attestation_ids.len() < usize::from(self.config.custodian_quorum) {
                return Err("ticket lacks custodian attestation quorum".to_string());
            }
        }
        for lane_id in &request.lane_ids {
            if !self.reserve_lanes.contains_key(lane_id) {
                return Err("batch reserve lane not found".to_string());
            }
        }
        let batch_id = redemption_batch_id(&request, self.counters.batch_counter);
        let batch = RedemptionBatch {
            batch_id: batch_id.clone(),
            ticket_ids: request.ticket_ids.clone(),
            lane_ids: request.lane_ids.clone(),
            reserve_delta_root: request.reserve_delta_root,
            burn_aggregation_root: request.burn_aggregation_root,
            withdrawal_output_root: request.withdrawal_output_root,
            recursive_proof_root: request.recursive_proof_root,
            fee_cap_root: request.fee_cap_root,
            privacy_budget_root: request.privacy_budget_root,
            status: BatchStatus::Ready,
            built_at_height: request.built_at_height,
            submitted_at_height: None,
            settled_at_height: None,
        };
        for ticket_id in &request.ticket_ids {
            let ticket = self
                .shielded_tickets
                .get_mut(ticket_id)
                .ok_or_else(|| "batch ticket not found".to_string())?;
            ticket.status = TicketStatus::Batched;
            ticket.batch_id = Some(batch_id.clone());
        }
        for lane_id in &request.lane_ids {
            if let Some(lane) = self.reserve_lanes.get_mut(lane_id) {
                lane.batched_tickets = lane.batched_tickets.saturating_add(1);
            }
        }
        self.batches.insert(batch_id.clone(), batch);
        self.counters.batch_counter = self.counters.batch_counter.saturating_add(1);
        self.push_public_record("redemption_batch_built", &batch_id);
        Ok(batch_id)
    }

    pub fn settle_batch(
        &mut self,
        batch_id: &str,
        withdrawal_tx_root: String,
        reserve_root_after: String,
        queue_root_after: String,
        custodian_signature_root: String,
        settled_at_height: u64,
    ) -> PrivateL2PqConfidentialStablecoinRedemptionQueueRuntimeResult<String> {
        require_non_empty("withdrawal_tx_root", &withdrawal_tx_root)?;
        require_non_empty("reserve_root_after", &reserve_root_after)?;
        require_non_empty("queue_root_after", &queue_root_after)?;
        require_non_empty("custodian_signature_root", &custodian_signature_root)?;
        let batch = self
            .batches
            .get_mut(batch_id)
            .ok_or_else(|| "redemption batch not found".to_string())?;
        if batch.status != BatchStatus::Ready && batch.status != BatchStatus::Submitted {
            return Err("redemption batch is not settlement ready".to_string());
        }
        batch.status = BatchStatus::Settled;
        batch.settled_at_height = Some(settled_at_height);
        let ticket_ids = batch.ticket_ids.clone();
        let receipt_id = payload_id(
            "REDEMPTION-SETTLEMENT-RECEIPT-ID",
            &[
                HashPart::Str(batch_id),
                HashPart::Str(&withdrawal_tx_root),
                HashPart::Str(&reserve_root_after),
                HashPart::Str(&queue_root_after),
                HashPart::U64(self.counters.settlement_counter),
            ],
        );
        for ticket_id in ticket_ids {
            if let Some(ticket) = self.shielded_tickets.get_mut(&ticket_id) {
                ticket.status = TicketStatus::Settled;
            }
        }
        let receipt = SettlementReceipt {
            receipt_id: receipt_id.clone(),
            batch_id: batch_id.to_string(),
            withdrawal_tx_root,
            reserve_root_after,
            queue_root_after,
            custodian_signature_root,
            settled_at_height,
        };
        self.settlement_receipts.insert(receipt_id.clone(), receipt);
        self.counters.settlement_counter = self.counters.settlement_counter.saturating_add(1);
        self.backpressure.live_queue_depth = self.live_queue_depth();
        self.push_public_record("redemption_batch_settled", batch_id);
        Ok(receipt_id)
    }

    pub fn quarantine_ticket(
        &mut self,
        ticket_id: &str,
        reason: QuarantineReason,
        evidence_root: String,
        entered_at_height: u64,
    ) -> PrivateL2PqConfidentialStablecoinRedemptionQueueRuntimeResult<String> {
        require_non_empty("evidence_root", &evidence_root)?;
        if !self.shielded_tickets.contains_key(ticket_id) {
            return Err("quarantine ticket not found".to_string());
        }
        let quarantine_id = payload_id(
            "REDEMPTION-QUARANTINE-ID",
            &[
                HashPart::Str(ticket_id),
                HashPart::Str(reason.as_str()),
                HashPart::Str(&evidence_root),
                HashPart::U64(self.counters.quarantine_counter),
            ],
        );
        let entry = QuarantineEntry {
            quarantine_id: quarantine_id.clone(),
            ticket_id: ticket_id.to_string(),
            reason,
            evidence_root,
            entered_at_height,
            release_after_height: entered_at_height
                .saturating_add(self.config.quarantine_release_delay_blocks),
            released: false,
        };
        self.quarantine_entries.insert(quarantine_id.clone(), entry);
        let ticket = self
            .shielded_tickets
            .get_mut(ticket_id)
            .ok_or_else(|| "quarantine ticket not found".to_string())?;
        ticket.status = TicketStatus::Quarantined;
        ticket.quarantine_id = Some(quarantine_id.clone());
        self.admitted_queue.remove(ticket_id);
        self.counters.quarantine_counter = self.counters.quarantine_counter.saturating_add(1);
        self.backpressure.quarantined_tickets =
            self.backpressure.quarantined_tickets.saturating_add(1);
        self.backpressure.live_queue_depth = self.live_queue_depth();
        self.push_public_record("ticket_quarantined", &quarantine_id);
        Ok(quarantine_id)
    }

    pub fn release_quarantine(
        &mut self,
        quarantine_id: &str,
        released_at_height: u64,
    ) -> PrivateL2PqConfidentialStablecoinRedemptionQueueRuntimeResult<()> {
        let entry = self
            .quarantine_entries
            .get_mut(quarantine_id)
            .ok_or_else(|| "quarantine entry not found".to_string())?;
        if entry.released {
            return Err("quarantine entry already released".to_string());
        }
        if released_at_height < entry.release_after_height {
            return Err("quarantine release delay has not elapsed".to_string());
        }
        entry.released = true;
        if let Some(ticket) = self.shielded_tickets.get_mut(&entry.ticket_id) {
            ticket.status = TicketStatus::Admitted;
            ticket.quarantine_id = None;
            self.admitted_queue.insert(entry.ticket_id.clone());
        }
        self.counters.released_quarantine_counter =
            self.counters.released_quarantine_counter.saturating_add(1);
        self.backpressure.live_queue_depth = self.live_queue_depth();
        self.push_public_record("ticket_quarantine_released", quarantine_id);
        Ok(())
    }

    pub fn roots(&self) -> Roots {
        let config_root = root_from_record("CONFIG-ROOT", &self.config.public_record());
        let counters_root = root_from_record("COUNTERS-ROOT", &self.counters.public_record());
        let shielded_ticket_root = collection_root(
            "SHIELDED-TICKET-ROOT",
            self.shielded_tickets.values().map(|v| v.public_record()),
        );
        let admitted_queue_root = collection_root(
            "ADMITTED-QUEUE-ROOT",
            self.admitted_queue
                .iter()
                .map(|ticket_id| json!({"ticket_id": ticket_id})),
        );
        let reserve_lane_root = collection_root(
            "RESERVE-LANE-ROOT",
            self.reserve_lanes.values().map(|v| v.public_record()),
        );
        let lane_assignment_root = collection_root(
            "LANE-ASSIGNMENT-ROOT",
            self.lane_assignments
                .iter()
                .map(|(ticket_id, lane_id)| json!({"ticket_id": ticket_id, "lane_id": lane_id})),
        );
        let custodian_attestation_root = collection_root(
            "CUSTODIAN-ATTESTATION-ROOT",
            self.custodian_attestations
                .values()
                .map(|v| v.public_record()),
        );
        let batch_root = collection_root(
            "BATCH-ROOT",
            self.batches.values().map(|v| v.public_record()),
        );
        let settlement_root = collection_root(
            "SETTLEMENT-ROOT",
            self.settlement_receipts.values().map(|v| v.public_record()),
        );
        let fee_cap_root = collection_root(
            "FEE-CAP-ROOT",
            self.fee_caps.values().map(|v| v.public_record()),
        );
        let privacy_redaction_budget_root = collection_root(
            "PRIVACY-REDACTION-BUDGET-ROOT",
            self.privacy_redaction_budgets
                .values()
                .map(|v| v.public_record()),
        );
        let backpressure_root =
            root_from_record("BACKPRESSURE-ROOT", &self.backpressure.public_record());
        let quarantine_root = collection_root(
            "QUARANTINE-ROOT",
            self.quarantine_entries.values().map(|v| v.public_record()),
        );
        let consumed_nullifier_root = collection_root(
            "CONSUMED-NULLIFIER-ROOT",
            self.consumed_nullifiers
                .iter()
                .map(|nullifier| json!({"nullifier_hash": nullifier})),
        );
        let deterministic_public_record_root = collection_root(
            "DETERMINISTIC-PUBLIC-RECORD-ROOT",
            self.deterministic_public_records.iter().cloned(),
        );
        let public_record_root = root_from_record(
            "PUBLIC-RECORD-ROOT",
            &json!({
                "suite": PUBLIC_RECORD_SUITE,
                "height": self.current_height,
                "config_root": config_root,
                "counters_root": counters_root,
                "shielded_ticket_root": shielded_ticket_root,
                "admitted_queue_root": admitted_queue_root,
                "reserve_lane_root": reserve_lane_root,
                "lane_assignment_root": lane_assignment_root,
                "custodian_attestation_root": custodian_attestation_root,
                "batch_root": batch_root,
                "settlement_root": settlement_root,
                "fee_cap_root": fee_cap_root,
                "privacy_redaction_budget_root": privacy_redaction_budget_root,
                "backpressure_root": backpressure_root,
                "quarantine_root": quarantine_root,
                "consumed_nullifier_root": consumed_nullifier_root,
                "deterministic_public_record_root": deterministic_public_record_root,
            }),
        );
        let state_root = root_from_record(
            "STATE-ROOT",
            &json!({
                "protocol_version": self.config.protocol_version,
                "height": self.current_height,
                "public_record_root": public_record_root,
                "ticket_counter": self.counters.ticket_counter,
                "batch_counter": self.counters.batch_counter,
                "settlement_counter": self.counters.settlement_counter,
            }),
        );
        Roots {
            config_root,
            counters_root,
            shielded_ticket_root,
            admitted_queue_root,
            reserve_lane_root,
            lane_assignment_root,
            custodian_attestation_root,
            batch_root,
            settlement_root,
            fee_cap_root,
            privacy_redaction_budget_root,
            backpressure_root,
            quarantine_root,
            consumed_nullifier_root,
            deterministic_public_record_root,
            public_record_root,
            state_root,
        }
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        json!({
            "protocol_version": self.config.protocol_version,
            "schema_version": self.config.schema_version,
            "chain_id": self.config.chain_id,
            "queue_id": self.config.queue_id,
            "l2_network": self.config.l2_network,
            "monero_network": self.config.monero_network,
            "height": self.current_height,
            "stable_asset_id": self.config.stable_asset_id,
            "reserve_asset_id": self.config.reserve_asset_id,
            "fee_asset_id": self.config.fee_asset_id,
            "counters": self.counters.public_record(),
            "backpressure": self.backpressure.public_record(),
            "roots": roots.public_record(),
        })
    }

    pub fn state_root(&self) -> String {
        self.roots().state_root
    }

    fn validate_ticket_request(
        &self,
        request: &ShieldedRedemptionTicketRequest,
    ) -> PrivateL2PqConfidentialStablecoinRedemptionQueueRuntimeResult<()> {
        require_non_empty("redeemer_commitment", &request.redeemer_commitment)?;
        require_non_empty("stable_burn_root", &request.stable_burn_root)?;
        require_non_empty(
            "reserve_destination_root",
            &request.reserve_destination_root,
        )?;
        require_non_empty("amount_commitment_root", &request.amount_commitment_root)?;
        require_non_empty("redemption_nullifier", &request.redemption_nullifier)?;
        if request.privacy_set_size < self.config.min_privacy_set_size {
            return Err("shielded redemption privacy set below configured threshold".to_string());
        }
        if request.pq_security_bits < self.config.min_pq_security_bits {
            return Err("PQ redemption authorization below configured security bits".to_string());
        }
        if request.max_withdrawal_fee_bps > self.config.max_withdrawal_fee_bps {
            return Err("withdrawal fee cap exceeds configured maximum".to_string());
        }
        if request.max_expedite_fee_bps > self.config.max_expedite_fee_bps {
            return Err("expedite fee cap exceeds configured maximum".to_string());
        }
        if !request.requested_lane.may_expedite() && request.max_expedite_fee_bps > 0 {
            return Err("non-expedited lane cannot carry expedite fee budget".to_string());
        }
        Ok(())
    }

    fn apply_backpressure(
        &mut self,
        event_height: u64,
    ) -> PrivateL2PqConfidentialStablecoinRedemptionQueueRuntimeResult<()> {
        let live_depth = self.live_queue_depth();
        self.backpressure.live_queue_depth = live_depth;
        if live_depth as usize >= self.config.backpressure_hard_limit {
            self.backpressure.hard_limit_events =
                self.backpressure.hard_limit_events.saturating_add(1);
            self.backpressure.last_event_height = event_height;
            self.counters.backpressure_event_counter =
                self.counters.backpressure_event_counter.saturating_add(1);
            return Err("redemption queue hard backpressure limit reached".to_string());
        }
        if live_depth as usize >= self.config.backpressure_soft_limit {
            self.backpressure.soft_limit_events =
                self.backpressure.soft_limit_events.saturating_add(1);
            self.backpressure.last_event_height = event_height;
            self.counters.backpressure_event_counter =
                self.counters.backpressure_event_counter.saturating_add(1);
        }
        self.backpressure.pressure_root = root_from_record(
            "BACKPRESSURE-PRESSURE-ROOT",
            &json!({
                "live_queue_depth": self.backpressure.live_queue_depth,
                "soft_limit_events": self.backpressure.soft_limit_events,
                "hard_limit_events": self.backpressure.hard_limit_events,
                "last_event_height": self.backpressure.last_event_height,
            }),
        );
        Ok(())
    }

    fn live_queue_depth(&self) -> u64 {
        self.shielded_tickets
            .values()
            .filter(|ticket| ticket.status.queue_live())
            .count() as u64
    }

    fn consume_nullifier(
        &mut self,
        nullifier: &str,
    ) -> PrivateL2PqConfidentialStablecoinRedemptionQueueRuntimeResult<()> {
        let nullifier_hash = payload_id("NULLIFIER-ID", &[HashPart::Str(nullifier)]);
        if !self.consumed_nullifiers.insert(nullifier_hash) {
            return Err("confidential redemption nullifier replay detected".to_string());
        }
        self.counters.consumed_nullifier_counter =
            self.counters.consumed_nullifier_counter.saturating_add(1);
        Ok(())
    }

    fn push_public_record(&mut self, event_kind: &str, object_id: &str) {
        if self.deterministic_public_records.len() >= self.config.max_public_records {
            return;
        }
        let record = json!({
            "event_index": self.counters.public_record_counter,
            "event_kind": event_kind,
            "object_id": object_id,
            "height": self.current_height,
            "state_root_before_record": self.state_root(),
        });
        self.deterministic_public_records.push(record);
        self.counters.public_record_counter = self.counters.public_record_counter.saturating_add(1);
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

pub fn shielded_ticket_id(request: &ShieldedRedemptionTicketRequest, counter: u64) -> String {
    root_from_record(
        "SHIELDED-REDEMPTION-TICKET-ID",
        &json!({
            "counter": counter,
            "redeemer_commitment": request.redeemer_commitment,
            "stable_burn_root": request.stable_burn_root,
            "reserve_destination_root": request.reserve_destination_root,
            "amount_commitment_root": request.amount_commitment_root,
            "redemption_nullifier": request.redemption_nullifier,
            "requested_lane": request.requested_lane.as_str(),
            "submitted_at_height": request.submitted_at_height,
        }),
    )
}

pub fn reserve_lane_id(request: &ReserveLaneRequest, counter: u64) -> String {
    root_from_record(
        "RESERVE-LANE-ID",
        &json!({
            "counter": counter,
            "lane_kind": request.lane_kind.as_str(),
            "lane_operator_commitment": request.lane_operator_commitment,
            "reserve_commitment_root": request.reserve_commitment_root,
            "withdrawal_policy_root": request.withdrawal_policy_root,
            "capacity_commitment_root": request.capacity_commitment_root,
            "opened_at_height": request.opened_at_height,
        }),
    )
}

pub fn custodian_attestation_id(request: &CustodianAttestationRequest, counter: u64) -> String {
    root_from_record(
        "CUSTODIAN-ATTESTATION-ID",
        &json!({
            "counter": counter,
            "ticket_id": request.ticket_id,
            "lane_id": request.lane_id,
            "custodian_commitment": request.custodian_commitment,
            "reserve_proof_root": request.reserve_proof_root,
            "pq_attestation_root": request.pq_attestation_root,
            "coverage_bps": request.coverage_bps,
            "verdict": request.verdict.as_str(),
            "attestation_nullifier": request.attestation_nullifier,
            "attested_at_height": request.attested_at_height,
        }),
    )
}

pub fn redemption_batch_id(request: &RedemptionBatchRequest, counter: u64) -> String {
    root_from_record(
        "REDEMPTION-BATCH-ID",
        &json!({
            "counter": counter,
            "ticket_ids": request.ticket_ids,
            "lane_ids": request.lane_ids,
            "reserve_delta_root": request.reserve_delta_root,
            "burn_aggregation_root": request.burn_aggregation_root,
            "withdrawal_output_root": request.withdrawal_output_root,
            "recursive_proof_root": request.recursive_proof_root,
            "fee_cap_root": request.fee_cap_root,
            "privacy_budget_root": request.privacy_budget_root,
            "built_at_height": request.built_at_height,
        }),
    )
}

pub fn root_from_record(domain: &str, record: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Json(record),
        ],
        32,
    )
}

pub fn payload_id(domain: &str, parts: &[HashPart<'_>]) -> String {
    domain_hash(
        &format!("{}:{}:{}", PROTOCOL_VERSION, CHAIN_ID, domain),
        parts,
        32,
    )
}

pub fn collection_root<I>(domain: &str, records: I) -> String
where
    I: IntoIterator<Item = Value>,
{
    let leaves: Vec<String> = records
        .into_iter()
        .map(|record| root_from_record(domain, &record))
        .collect();
    merkle_root(domain, &leaves)
}

pub fn validate_ticket_for_batch(
    ticket: &ShieldedRedemptionTicket,
    built_at_height: u64,
) -> PrivateL2PqConfidentialStablecoinRedemptionQueueRuntimeResult<()> {
    if !ticket.status.batchable() {
        return Err("shielded redemption ticket is not batchable".to_string());
    }
    if ticket.expires_at_height <= built_at_height {
        return Err("shielded redemption ticket expired before batch".to_string());
    }
    if ticket.assigned_lane_id.is_none() {
        return Err("shielded redemption ticket has no reserve lane".to_string());
    }
    Ok(())
}

pub fn require_non_empty(
    label: &str,
    value: &str,
) -> PrivateL2PqConfidentialStablecoinRedemptionQueueRuntimeResult<()> {
    if value.trim().is_empty() {
        return Err(format!("{label} cannot be empty"));
    }
    Ok(())
}

pub fn demo_hash(label: &str) -> String {
    payload_id("DEMO-HASH", &[HashPart::Str(label)])
}

pub fn invariant_anchor_001(state: &State) -> Value {
    json!({"invariant":"anchor_001","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_002(state: &State) -> Value {
    json!({"invariant":"anchor_002","shielded_ticket_root":state.roots().shielded_ticket_root,"reserve_lane_root":state.roots().reserve_lane_root,"batch_root":state.roots().batch_root})
}

pub fn invariant_anchor_003(state: &State) -> Value {
    json!({"invariant":"anchor_003","custodian_attestation_root":state.roots().custodian_attestation_root,"quarantine_root":state.roots().quarantine_root,"backpressure_root":state.roots().backpressure_root})
}
