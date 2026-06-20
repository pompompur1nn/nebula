use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2PqContractExecutionSlaRuntimeResult<T> = Result<T>;

pub const PRIVATE_L2_PQ_CONTRACT_EXECUTION_SLA_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-contract-execution-sla-runtime-v1";
pub const PRIVATE_L2_PQ_CONTRACT_EXECUTION_SLA_RUNTIME_SCHEMA_VERSION: u64 = 1;
pub const PRIVATE_L2_PQ_CONTRACT_EXECUTION_SLA_RUNTIME_HASH_SUITE: &str =
    "SHAKE256-domain-separated-canonical-json";
pub const PRIVATE_L2_PQ_CONTRACT_EXECUTION_SLA_RUNTIME_TICKET_SCHEME: &str =
    "ml-kem-1024-encrypted-contract-execution-ticket-v1";
pub const PRIVATE_L2_PQ_CONTRACT_EXECUTION_SLA_RUNTIME_PRECONF_SCHEME: &str =
    "ml-dsa-87-threshold-preconfirmation-root-v1";
pub const PRIVATE_L2_PQ_CONTRACT_EXECUTION_SLA_RUNTIME_PROOF_WINDOW_SCHEME: &str =
    "recursive-zk-proof-window-root-v1";
pub const PRIVATE_L2_PQ_CONTRACT_EXECUTION_SLA_RUNTIME_SPONSOR_SCHEME: &str =
    "low-fee-sponsored-execution-reservation-v1";
pub const PRIVATE_L2_PQ_CONTRACT_EXECUTION_SLA_RUNTIME_RECEIPT_SCHEME: &str =
    "private-execution-sla-settlement-receipt-v1";
pub const PRIVATE_L2_PQ_CONTRACT_EXECUTION_SLA_RUNTIME_DEVNET_HEIGHT: u64 = 512_800;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_EXECUTION_PRIVACY_SET_SIZE: u64 = 512;
pub const DEFAULT_MIN_BATCH_PRIVACY_SET_SIZE: u64 = 1_024;
pub const DEFAULT_TICKET_TTL_BLOCKS: u64 = 32;
pub const DEFAULT_PRECONF_DEADLINE_BLOCKS: u64 = 2;
pub const DEFAULT_EXECUTION_DEADLINE_BLOCKS: u64 = 8;
pub const DEFAULT_PROOF_DEADLINE_BLOCKS: u64 = 18;
pub const DEFAULT_RESERVATION_TTL_BLOCKS: u64 = 48;
pub const DEFAULT_REBATE_TTL_BLOCKS: u64 = 720;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 16;
pub const DEFAULT_TARGET_REBATE_BPS: u64 = 5;
pub const DEFAULT_MAX_REBATE_BPS: u64 = 20;
pub const DEFAULT_OPERATOR_BOND_MICRO_UNITS: u64 = 25_000_000;
pub const DEFAULT_SPONSOR_BUDGET_MICRO_UNITS: u64 = 220_000_000;
pub const DEFAULT_MAX_TICKETS: usize = 1_048_576;
pub const DEFAULT_MAX_BATCH_TICKETS: usize = 2_048;
pub const DEFAULT_MAX_PROOF_WINDOWS: usize = 65_536;
pub const DEFAULT_MAX_PRECONFIRMATIONS: usize = 262_144;
pub const MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SlaLaneKind {
    SpotSwap,
    LendingAction,
    VaultRebalance,
    PerpetualsMargin,
    TokenLaunch,
    GovernanceExecution,
    MoneroBridgeExit,
    EmergencyCircuitBreaker,
}

impl SlaLaneKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SpotSwap => "spot_swap",
            Self::LendingAction => "lending_action",
            Self::VaultRebalance => "vault_rebalance",
            Self::PerpetualsMargin => "perpetuals_margin",
            Self::TokenLaunch => "token_launch",
            Self::GovernanceExecution => "governance_execution",
            Self::MoneroBridgeExit => "monero_bridge_exit",
            Self::EmergencyCircuitBreaker => "emergency_circuit_breaker",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FeeClass {
    Sponsored,
    UserPaid,
    RebateEligible,
    ProtocolFunded,
    EmergencySubsidized,
}

impl FeeClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sponsored => "sponsored",
            Self::UserPaid => "user_paid",
            Self::RebateEligible => "rebate_eligible",
            Self::ProtocolFunded => "protocol_funded",
            Self::EmergencySubsidized => "emergency_subsidized",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SlaProfileStatus {
    Draft,
    Active,
    Paused,
    Retired,
    EmergencyOnly,
}

impl SlaProfileStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Active => "active",
            Self::Paused => "paused",
            Self::Retired => "retired",
            Self::EmergencyOnly => "emergency_only",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TicketStatus {
    Queued,
    Preconfirmed,
    Executing,
    Proving,
    Settled,
    Expired,
    Quarantined,
    Slashed,
}

impl TicketStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Preconfirmed => "preconfirmed",
            Self::Executing => "executing",
            Self::Proving => "proving",
            Self::Settled => "settled",
            Self::Expired => "expired",
            Self::Quarantined => "quarantined",
            Self::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PreconfirmationStatus {
    Pending,
    Signed,
    Aggregated,
    Disputed,
    Expired,
}

impl PreconfirmationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Signed => "signed",
            Self::Aggregated => "aggregated",
            Self::Disputed => "disputed",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofWindowStatus {
    Open,
    Filled,
    Aggregating,
    Settled,
    Late,
    Failed,
}

impl ProofWindowStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Filled => "filled",
            Self::Aggregating => "aggregating",
            Self::Settled => "settled",
            Self::Late => "late",
            Self::Failed => "failed",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReservationStatus {
    Reserved,
    Bound,
    Consumed,
    Released,
    Expired,
}

impl ReservationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Bound => "bound",
            Self::Consumed => "consumed",
            Self::Released => "released",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptKind {
    Preconfirmation,
    Execution,
    Proof,
    Rebate,
    Slash,
    Quarantine,
}

impl ReceiptKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Preconfirmation => "preconfirmation",
            Self::Execution => "execution",
            Self::Proof => "proof",
            Self::Rebate => "rebate",
            Self::Slash => "slash",
            Self::Quarantine => "quarantine",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PenaltyStatus {
    Pending,
    Assessed,
    BondDebited,
    Appealed,
    Reversed,
    Settled,
}

impl PenaltyStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Assessed => "assessed",
            Self::BondDebited => "bond_debited",
            Self::Appealed => "appealed",
            Self::Reversed => "reversed",
            Self::Settled => "settled",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RebateStatus {
    Accruing,
    Claimable,
    Claimed,
    Expired,
    DonatedToSponsorPool,
}

impl RebateStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Accruing => "accruing",
            Self::Claimable => "claimable",
            Self::Claimed => "claimed",
            Self::Expired => "expired",
            Self::DonatedToSponsorPool => "donated_to_sponsor_pool",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivacyFenceStatus {
    Open,
    Reserved,
    Spent,
    Expired,
    Quarantined,
}

impl PrivacyFenceStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Reserved => "reserved",
            Self::Spent => "spent",
            Self::Expired => "expired",
            Self::Quarantined => "quarantined",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WitnessStatus {
    Pending,
    Accepted,
    Rejected,
    Superseded,
}

impl WitnessStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
            Self::Superseded => "superseded",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchStatus {
    Building,
    Sealed,
    Proving,
    Settled,
    PartialFailure,
    ReorgHold,
}

impl BatchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Building => "building",
            Self::Sealed => "sealed",
            Self::Proving => "proving",
            Self::Settled => "settled",
            Self::PartialFailure => "partial_failure",
            Self::ReorgHold => "reorg_hold",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    pub min_pq_security_bits: u16,
    pub min_execution_privacy_set_size: u64,
    pub min_batch_privacy_set_size: u64,
    pub ticket_ttl_blocks: u64,
    pub preconfirmation_deadline_blocks: u64,
    pub execution_deadline_blocks: u64,
    pub proof_deadline_blocks: u64,
    pub reservation_ttl_blocks: u64,
    pub rebate_ttl_blocks: u64,
    pub max_user_fee_bps: u64,
    pub target_rebate_bps: u64,
    pub max_rebate_bps: u64,
    pub operator_bond_micro_units: u64,
    pub sponsor_budget_micro_units: u64,
    pub max_tickets: usize,
    pub max_batch_tickets: usize,
    pub max_proof_windows: usize,
    pub max_preconfirmations: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_execution_privacy_set_size: DEFAULT_MIN_EXECUTION_PRIVACY_SET_SIZE,
            min_batch_privacy_set_size: DEFAULT_MIN_BATCH_PRIVACY_SET_SIZE,
            ticket_ttl_blocks: DEFAULT_TICKET_TTL_BLOCKS,
            preconfirmation_deadline_blocks: DEFAULT_PRECONF_DEADLINE_BLOCKS,
            execution_deadline_blocks: DEFAULT_EXECUTION_DEADLINE_BLOCKS,
            proof_deadline_blocks: DEFAULT_PROOF_DEADLINE_BLOCKS,
            reservation_ttl_blocks: DEFAULT_RESERVATION_TTL_BLOCKS,
            rebate_ttl_blocks: DEFAULT_REBATE_TTL_BLOCKS,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            target_rebate_bps: DEFAULT_TARGET_REBATE_BPS,
            max_rebate_bps: DEFAULT_MAX_REBATE_BPS,
            operator_bond_micro_units: DEFAULT_OPERATOR_BOND_MICRO_UNITS,
            sponsor_budget_micro_units: DEFAULT_SPONSOR_BUDGET_MICRO_UNITS,
            max_tickets: DEFAULT_MAX_TICKETS,
            max_batch_tickets: DEFAULT_MAX_BATCH_TICKETS,
            max_proof_windows: DEFAULT_MAX_PROOF_WINDOWS,
            max_preconfirmations: DEFAULT_MAX_PRECONFIRMATIONS,
        }
    }
}

impl Config {
    pub fn validate(&self) -> Result<()> {
        if self.min_pq_security_bits < 192 {
            return Err("minimum PQ security must be at least 192 bits".to_string());
        }
        if self.min_execution_privacy_set_size < 2 {
            return Err("execution privacy set must contain at least two members".to_string());
        }
        if self.min_batch_privacy_set_size < self.min_execution_privacy_set_size {
            return Err("batch privacy set must cover execution privacy set".to_string());
        }
        if self.ticket_ttl_blocks == 0
            || self.preconfirmation_deadline_blocks == 0
            || self.execution_deadline_blocks == 0
            || self.proof_deadline_blocks == 0
            || self.reservation_ttl_blocks == 0
        {
            return Err("SLA windows must be non-zero".to_string());
        }
        if self.max_user_fee_bps > MAX_BPS
            || self.target_rebate_bps > MAX_BPS
            || self.max_rebate_bps > MAX_BPS
        {
            return Err("fee bps values must fit within MAX_BPS".to_string());
        }
        if self.target_rebate_bps > self.max_rebate_bps {
            return Err("target rebate cannot exceed max rebate".to_string());
        }
        if self.operator_bond_micro_units == 0 || self.sponsor_budget_micro_units == 0 {
            return Err("bond and sponsor budget must be non-zero".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "min_pq_security_bits": self.min_pq_security_bits,
            "min_execution_privacy_set_size": self.min_execution_privacy_set_size,
            "min_batch_privacy_set_size": self.min_batch_privacy_set_size,
            "ticket_ttl_blocks": self.ticket_ttl_blocks,
            "preconfirmation_deadline_blocks": self.preconfirmation_deadline_blocks,
            "execution_deadline_blocks": self.execution_deadline_blocks,
            "proof_deadline_blocks": self.proof_deadline_blocks,
            "reservation_ttl_blocks": self.reservation_ttl_blocks,
            "rebate_ttl_blocks": self.rebate_ttl_blocks,
            "max_user_fee_bps": self.max_user_fee_bps,
            "target_rebate_bps": self.target_rebate_bps,
            "max_rebate_bps": self.max_rebate_bps,
            "operator_bond_micro_units": self.operator_bond_micro_units,
            "sponsor_budget_micro_units": self.sponsor_budget_micro_units,
            "max_tickets": self.max_tickets,
            "max_batch_tickets": self.max_batch_tickets,
            "max_proof_windows": self.max_proof_windows,
            "max_preconfirmations": self.max_preconfirmations,
        })
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Counters {
    pub profiles: u64,
    pub tickets: u64,
    pub preconfirmations: u64,
    pub proof_windows: u64,
    pub reservations: u64,
    pub receipts: u64,
    pub penalties: u64,
    pub rebates: u64,
    pub fences: u64,
    pub witness_attestations: u64,
    pub batches: u64,
    pub spent_nullifiers: u64,
    pub events: u64,
    pub settled_tickets: u64,
    pub late_tickets: u64,
    pub slashed_tickets: u64,
    pub sponsored_fee_micro_units: u64,
    pub user_fee_micro_units: u64,
    pub rebate_micro_units: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "profiles": self.profiles,
            "tickets": self.tickets,
            "preconfirmations": self.preconfirmations,
            "proof_windows": self.proof_windows,
            "reservations": self.reservations,
            "receipts": self.receipts,
            "penalties": self.penalties,
            "rebates": self.rebates,
            "fences": self.fences,
            "witness_attestations": self.witness_attestations,
            "batches": self.batches,
            "spent_nullifiers": self.spent_nullifiers,
            "events": self.events,
            "settled_tickets": self.settled_tickets,
            "late_tickets": self.late_tickets,
            "slashed_tickets": self.slashed_tickets,
            "sponsored_fee_micro_units": self.sponsored_fee_micro_units,
            "user_fee_micro_units": self.user_fee_micro_units,
            "rebate_micro_units": self.rebate_micro_units,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Roots {
    pub profile_root: String,
    pub ticket_root: String,
    pub preconfirmation_root: String,
    pub proof_window_root: String,
    pub reservation_root: String,
    pub receipt_root: String,
    pub penalty_root: String,
    pub rebate_root: String,
    pub fence_root: String,
    pub witness_root: String,
    pub batch_root: String,
    pub nullifier_root: String,
    pub event_root: String,
}

impl Default for Roots {
    fn default() -> Self {
        Self {
            profile_root: merkle_root("PRIVATE-L2-PQ-SLA-PROFILE-EMPTY", &[]),
            ticket_root: merkle_root("PRIVATE-L2-PQ-SLA-TICKET-EMPTY", &[]),
            preconfirmation_root: merkle_root("PRIVATE-L2-PQ-SLA-PRECONFIRMATION-EMPTY", &[]),
            proof_window_root: merkle_root("PRIVATE-L2-PQ-SLA-PROOF-WINDOW-EMPTY", &[]),
            reservation_root: merkle_root("PRIVATE-L2-PQ-SLA-RESERVATION-EMPTY", &[]),
            receipt_root: merkle_root("PRIVATE-L2-PQ-SLA-RECEIPT-EMPTY", &[]),
            penalty_root: merkle_root("PRIVATE-L2-PQ-SLA-PENALTY-EMPTY", &[]),
            rebate_root: merkle_root("PRIVATE-L2-PQ-SLA-REBATE-EMPTY", &[]),
            fence_root: merkle_root("PRIVATE-L2-PQ-SLA-FENCE-EMPTY", &[]),
            witness_root: merkle_root("PRIVATE-L2-PQ-SLA-WITNESS-EMPTY", &[]),
            batch_root: merkle_root("PRIVATE-L2-PQ-SLA-BATCH-EMPTY", &[]),
            nullifier_root: merkle_root("PRIVATE-L2-PQ-SLA-NULLIFIER-EMPTY", &[]),
            event_root: merkle_root("PRIVATE-L2-PQ-SLA-EVENT-EMPTY", &[]),
        }
    }
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "profile_root": self.profile_root,
            "ticket_root": self.ticket_root,
            "preconfirmation_root": self.preconfirmation_root,
            "proof_window_root": self.proof_window_root,
            "reservation_root": self.reservation_root,
            "receipt_root": self.receipt_root,
            "penalty_root": self.penalty_root,
            "rebate_root": self.rebate_root,
            "fence_root": self.fence_root,
            "witness_root": self.witness_root,
            "batch_root": self.batch_root,
            "nullifier_root": self.nullifier_root,
            "event_root": self.event_root,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SlaProfile {
    pub profile_id: String,
    pub lane_kind: SlaLaneKind,
    pub status: SlaProfileStatus,
    pub label_hash: String,
    pub contract_scope_root: String,
    pub operator_set_root: String,
    pub prover_set_root: String,
    pub sponsor_pool_root: String,
    pub min_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub max_user_fee_bps: u64,
    pub target_rebate_bps: u64,
    pub preconfirmation_deadline_blocks: u64,
    pub execution_deadline_blocks: u64,
    pub proof_deadline_blocks: u64,
    pub created_at_height: u64,
    pub expires_at_height: Option<u64>,
}

impl SlaProfile {
    pub fn validate(&self, config: &Config) -> Result<()> {
        if self.profile_id.is_empty() {
            return Err("SLA profile id is empty".to_string());
        }
        if self.min_privacy_set_size < config.min_execution_privacy_set_size {
            return Err("SLA profile privacy set is below runtime minimum".to_string());
        }
        if self.min_pq_security_bits < config.min_pq_security_bits {
            return Err("SLA profile PQ security is below runtime minimum".to_string());
        }
        if self.max_user_fee_bps > config.max_user_fee_bps {
            return Err("SLA profile max fee exceeds runtime cap".to_string());
        }
        if self.target_rebate_bps > config.max_rebate_bps {
            return Err("SLA profile rebate exceeds runtime cap".to_string());
        }
        if self.preconfirmation_deadline_blocks == 0
            || self.execution_deadline_blocks == 0
            || self.proof_deadline_blocks == 0
        {
            return Err("SLA profile deadlines must be non-zero".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "profile_id": self.profile_id,
            "lane_kind": self.lane_kind,
            "status": self.status,
            "label_hash": self.label_hash,
            "contract_scope_root": self.contract_scope_root,
            "operator_set_root": self.operator_set_root,
            "prover_set_root": self.prover_set_root,
            "sponsor_pool_root": self.sponsor_pool_root,
            "min_privacy_set_size": self.min_privacy_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
            "max_user_fee_bps": self.max_user_fee_bps,
            "target_rebate_bps": self.target_rebate_bps,
            "preconfirmation_deadline_blocks": self.preconfirmation_deadline_blocks,
            "execution_deadline_blocks": self.execution_deadline_blocks,
            "proof_deadline_blocks": self.proof_deadline_blocks,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExecutionTicket {
    pub ticket_id: String,
    pub profile_id: String,
    pub lane_kind: SlaLaneKind,
    pub fee_class: FeeClass,
    pub status: TicketStatus,
    pub caller_commitment: String,
    pub contract_commitment: String,
    pub method_selector_hash: String,
    pub encrypted_call_root: String,
    pub call_value_commitment: String,
    pub asset_root: String,
    pub dependency_root: String,
    pub privacy_fence_id: String,
    pub nullifier: String,
    pub sponsor_reservation_id: Option<String>,
    pub max_fee_micro_units: u64,
    pub priority_fee_micro_units: u64,
    pub requested_at_height: u64,
    pub preconfirmation_deadline_height: u64,
    pub execution_deadline_height: u64,
    pub proof_deadline_height: u64,
    pub expires_at_height: u64,
}

impl ExecutionTicket {
    pub fn validate(&self, config: &Config, profile: &SlaProfile) -> Result<()> {
        if self.ticket_id.is_empty()
            || self.profile_id.is_empty()
            || self.contract_commitment.is_empty()
            || self.nullifier.is_empty()
        {
            return Err("execution ticket is missing required roots".to_string());
        }
        if self.profile_id != profile.profile_id {
            return Err("ticket profile mismatch".to_string());
        }
        if self.max_fee_micro_units == 0 {
            return Err("ticket max fee must be non-zero".to_string());
        }
        if self.priority_fee_micro_units > self.max_fee_micro_units {
            return Err("ticket priority fee exceeds max fee".to_string());
        }
        if self.preconfirmation_deadline_height <= self.requested_at_height {
            return Err("preconfirmation deadline must be after request height".to_string());
        }
        if self.execution_deadline_height <= self.preconfirmation_deadline_height {
            return Err("execution deadline must be after preconfirmation deadline".to_string());
        }
        if self.proof_deadline_height <= self.execution_deadline_height {
            return Err("proof deadline must be after execution deadline".to_string());
        }
        if self.expires_at_height <= self.requested_at_height {
            return Err("ticket expiry must be after request height".to_string());
        }
        if self.expires_at_height > self.requested_at_height + config.ticket_ttl_blocks * 4 {
            return Err("ticket expiry exceeds bounded TTL envelope".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "ticket_id": self.ticket_id,
            "profile_id": self.profile_id,
            "lane_kind": self.lane_kind,
            "fee_class": self.fee_class,
            "status": self.status,
            "caller_commitment": self.caller_commitment,
            "contract_commitment": self.contract_commitment,
            "method_selector_hash": self.method_selector_hash,
            "encrypted_call_root": self.encrypted_call_root,
            "call_value_commitment": self.call_value_commitment,
            "asset_root": self.asset_root,
            "dependency_root": self.dependency_root,
            "privacy_fence_id": self.privacy_fence_id,
            "nullifier": self.nullifier,
            "sponsor_reservation_id": self.sponsor_reservation_id,
            "max_fee_micro_units": self.max_fee_micro_units,
            "priority_fee_micro_units": self.priority_fee_micro_units,
            "requested_at_height": self.requested_at_height,
            "preconfirmation_deadline_height": self.preconfirmation_deadline_height,
            "execution_deadline_height": self.execution_deadline_height,
            "proof_deadline_height": self.proof_deadline_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PqPreconfirmation {
    pub preconfirmation_id: String,
    pub ticket_id: String,
    pub profile_id: String,
    pub status: PreconfirmationStatus,
    pub operator_commitment: String,
    pub committee_epoch: u64,
    pub signature_root: String,
    pub transcript_root: String,
    pub promised_execution_height: u64,
    pub issued_at_height: u64,
    pub expires_at_height: u64,
    pub pq_security_bits: u16,
    pub threshold: u16,
    pub signer_count: u16,
}

impl PqPreconfirmation {
    pub fn validate(&self, config: &Config) -> Result<()> {
        if self.preconfirmation_id.is_empty()
            || self.ticket_id.is_empty()
            || self.signature_root.is_empty()
        {
            return Err("preconfirmation missing required roots".to_string());
        }
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err("preconfirmation PQ security below minimum".to_string());
        }
        if self.threshold == 0 || self.signer_count == 0 || self.threshold > self.signer_count {
            return Err("invalid preconfirmation threshold".to_string());
        }
        if self.expires_at_height <= self.issued_at_height {
            return Err("preconfirmation expiry must be after issue height".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "preconfirmation_id": self.preconfirmation_id,
            "ticket_id": self.ticket_id,
            "profile_id": self.profile_id,
            "status": self.status,
            "operator_commitment": self.operator_commitment,
            "committee_epoch": self.committee_epoch,
            "signature_root": self.signature_root,
            "transcript_root": self.transcript_root,
            "promised_execution_height": self.promised_execution_height,
            "issued_at_height": self.issued_at_height,
            "expires_at_height": self.expires_at_height,
            "pq_security_bits": self.pq_security_bits,
            "threshold": self.threshold,
            "signer_count": self.signer_count,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProofWindow {
    pub window_id: String,
    pub profile_id: String,
    pub status: ProofWindowStatus,
    pub ticket_root: String,
    pub preconfirmation_root: String,
    pub witness_root: String,
    pub prover_commitment: String,
    pub recursive_proof_root: Option<String>,
    pub opened_at_height: u64,
    pub closes_at_height: u64,
    pub max_tickets: usize,
    pub ticket_count: u64,
    pub aggregated_count: u64,
    pub late_count: u64,
}

impl ProofWindow {
    pub fn validate(&self, config: &Config) -> Result<()> {
        if self.window_id.is_empty() || self.profile_id.is_empty() {
            return Err("proof window missing required id".to_string());
        }
        if self.closes_at_height <= self.opened_at_height {
            return Err("proof window close height must be after open height".to_string());
        }
        if self.max_tickets == 0 || self.max_tickets > config.max_batch_tickets {
            return Err("proof window max ticket count is invalid".to_string());
        }
        if self.ticket_count > self.max_tickets as u64 {
            return Err("proof window ticket count exceeds cap".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "window_id": self.window_id,
            "profile_id": self.profile_id,
            "status": self.status,
            "ticket_root": self.ticket_root,
            "preconfirmation_root": self.preconfirmation_root,
            "witness_root": self.witness_root,
            "prover_commitment": self.prover_commitment,
            "recursive_proof_root": self.recursive_proof_root,
            "opened_at_height": self.opened_at_height,
            "closes_at_height": self.closes_at_height,
            "max_tickets": self.max_tickets,
            "ticket_count": self.ticket_count,
            "aggregated_count": self.aggregated_count,
            "late_count": self.late_count,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FeeSponsorReservation {
    pub reservation_id: String,
    pub sponsor_commitment: String,
    pub ticket_id: Option<String>,
    pub profile_id: String,
    pub status: ReservationStatus,
    pub reserved_fee_micro_units: u64,
    pub max_fee_bps: u64,
    pub rebate_bps: u64,
    pub privacy_set_size: u64,
    pub created_at_height: u64,
    pub expires_at_height: u64,
}

impl FeeSponsorReservation {
    pub fn validate(&self, config: &Config) -> Result<()> {
        if self.reservation_id.is_empty() || self.sponsor_commitment.is_empty() {
            return Err("fee sponsor reservation missing required roots".to_string());
        }
        if self.reserved_fee_micro_units == 0 {
            return Err("fee sponsor reservation must reserve non-zero fee".to_string());
        }
        if self.max_fee_bps > config.max_user_fee_bps || self.rebate_bps > config.max_rebate_bps {
            return Err("fee sponsor reservation exceeds fee caps".to_string());
        }
        if self.privacy_set_size < config.min_execution_privacy_set_size {
            return Err("fee sponsor reservation privacy set too small".to_string());
        }
        if self.expires_at_height <= self.created_at_height {
            return Err("reservation expiry must be after creation height".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "reservation_id": self.reservation_id,
            "sponsor_commitment": self.sponsor_commitment,
            "ticket_id": self.ticket_id,
            "profile_id": self.profile_id,
            "status": self.status,
            "reserved_fee_micro_units": self.reserved_fee_micro_units,
            "max_fee_bps": self.max_fee_bps,
            "rebate_bps": self.rebate_bps,
            "privacy_set_size": self.privacy_set_size,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WitnessAttestation {
    pub attestation_id: String,
    pub ticket_id: String,
    pub profile_id: String,
    pub status: WitnessStatus,
    pub witness_commitment: String,
    pub transcript_root: String,
    pub observed_state_root: String,
    pub latency_ms: u64,
    pub fee_observed_micro_units: u64,
    pub issued_at_height: u64,
}

impl WitnessAttestation {
    pub fn validate(&self) -> Result<()> {
        if self.attestation_id.is_empty()
            || self.ticket_id.is_empty()
            || self.transcript_root.is_empty()
        {
            return Err("witness attestation missing required roots".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "ticket_id": self.ticket_id,
            "profile_id": self.profile_id,
            "status": self.status,
            "witness_commitment": self.witness_commitment,
            "transcript_root": self.transcript_root,
            "observed_state_root": self.observed_state_root,
            "latency_ms": self.latency_ms,
            "fee_observed_micro_units": self.fee_observed_micro_units,
            "issued_at_height": self.issued_at_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SettlementBatch {
    pub batch_id: String,
    pub profile_id: String,
    pub window_id: String,
    pub status: BatchStatus,
    pub ticket_root: String,
    pub receipt_root: String,
    pub penalty_root: String,
    pub rebate_root: String,
    pub post_state_root: String,
    pub proof_root: String,
    pub batch_size: u64,
    pub settled_count: u64,
    pub failed_count: u64,
    pub total_fee_micro_units: u64,
    pub total_rebate_micro_units: u64,
    pub sealed_at_height: u64,
    pub settled_at_height: Option<u64>,
}

impl SettlementBatch {
    pub fn validate(&self, config: &Config) -> Result<()> {
        if self.batch_id.is_empty() || self.profile_id.is_empty() || self.window_id.is_empty() {
            return Err("settlement batch missing required ids".to_string());
        }
        if self.batch_size == 0 || self.batch_size > config.max_batch_tickets as u64 {
            return Err("settlement batch size invalid".to_string());
        }
        if self.settled_count + self.failed_count > self.batch_size {
            return Err("settlement batch counts exceed batch size".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "profile_id": self.profile_id,
            "window_id": self.window_id,
            "status": self.status,
            "ticket_root": self.ticket_root,
            "receipt_root": self.receipt_root,
            "penalty_root": self.penalty_root,
            "rebate_root": self.rebate_root,
            "post_state_root": self.post_state_root,
            "proof_root": self.proof_root,
            "batch_size": self.batch_size,
            "settled_count": self.settled_count,
            "failed_count": self.failed_count,
            "total_fee_micro_units": self.total_fee_micro_units,
            "total_rebate_micro_units": self.total_rebate_micro_units,
            "sealed_at_height": self.sealed_at_height,
            "settled_at_height": self.settled_at_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SettlementReceipt {
    pub receipt_id: String,
    pub ticket_id: String,
    pub batch_id: String,
    pub profile_id: String,
    pub kind: ReceiptKind,
    pub status: TicketStatus,
    pub execution_root: String,
    pub fee_paid_micro_units: u64,
    pub sponsor_paid_micro_units: u64,
    pub rebate_id: Option<String>,
    pub penalty_id: Option<String>,
    pub settled_at_height: u64,
}

impl SettlementReceipt {
    pub fn validate(&self) -> Result<()> {
        if self.receipt_id.is_empty()
            || self.ticket_id.is_empty()
            || self.batch_id.is_empty()
            || self.execution_root.is_empty()
        {
            return Err("settlement receipt missing required roots".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "ticket_id": self.ticket_id,
            "batch_id": self.batch_id,
            "profile_id": self.profile_id,
            "kind": self.kind,
            "status": self.status,
            "execution_root": self.execution_root,
            "fee_paid_micro_units": self.fee_paid_micro_units,
            "sponsor_paid_micro_units": self.sponsor_paid_micro_units,
            "rebate_id": self.rebate_id,
            "penalty_id": self.penalty_id,
            "settled_at_height": self.settled_at_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SlaPenalty {
    pub penalty_id: String,
    pub ticket_id: String,
    pub profile_id: String,
    pub operator_commitment: String,
    pub status: PenaltyStatus,
    pub reason_hash: String,
    pub assessed_micro_units: u64,
    pub bond_debit_micro_units: u64,
    pub evidence_root: String,
    pub assessed_at_height: u64,
}

impl SlaPenalty {
    pub fn validate(&self) -> Result<()> {
        if self.penalty_id.is_empty() || self.ticket_id.is_empty() || self.evidence_root.is_empty()
        {
            return Err("SLA penalty missing required roots".to_string());
        }
        if self.assessed_micro_units == 0 {
            return Err("SLA penalty must assess non-zero amount".to_string());
        }
        if self.bond_debit_micro_units > self.assessed_micro_units {
            return Err("SLA penalty bond debit exceeds assessment".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "penalty_id": self.penalty_id,
            "ticket_id": self.ticket_id,
            "profile_id": self.profile_id,
            "operator_commitment": self.operator_commitment,
            "status": self.status,
            "reason_hash": self.reason_hash,
            "assessed_micro_units": self.assessed_micro_units,
            "bond_debit_micro_units": self.bond_debit_micro_units,
            "evidence_root": self.evidence_root,
            "assessed_at_height": self.assessed_at_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FeeRebate {
    pub rebate_id: String,
    pub receipt_id: String,
    pub beneficiary_commitment: String,
    pub status: RebateStatus,
    pub amount_micro_units: u64,
    pub claim_nullifier: String,
    pub privacy_set_size: u64,
    pub created_at_height: u64,
    pub expires_at_height: u64,
}

impl FeeRebate {
    pub fn validate(&self, config: &Config) -> Result<()> {
        if self.rebate_id.is_empty()
            || self.receipt_id.is_empty()
            || self.claim_nullifier.is_empty()
        {
            return Err("fee rebate missing required roots".to_string());
        }
        if self.amount_micro_units == 0 {
            return Err("fee rebate amount must be non-zero".to_string());
        }
        if self.privacy_set_size < config.min_execution_privacy_set_size {
            return Err("fee rebate privacy set too small".to_string());
        }
        if self.expires_at_height <= self.created_at_height {
            return Err("fee rebate expiry must be after creation height".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "rebate_id": self.rebate_id,
            "receipt_id": self.receipt_id,
            "beneficiary_commitment": self.beneficiary_commitment,
            "status": self.status,
            "amount_micro_units": self.amount_micro_units,
            "claim_nullifier": self.claim_nullifier,
            "privacy_set_size": self.privacy_set_size,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrivacyFence {
    pub fence_id: String,
    pub ticket_id: Option<String>,
    pub profile_id: String,
    pub status: PrivacyFenceStatus,
    pub nullifier: String,
    pub ring_root: String,
    pub view_tag_root: String,
    pub fence_root: String,
    pub privacy_set_size: u64,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
}

impl PrivacyFence {
    pub fn validate(&self, config: &Config) -> Result<()> {
        if self.fence_id.is_empty() || self.nullifier.is_empty() || self.fence_root.is_empty() {
            return Err("privacy fence missing required roots".to_string());
        }
        if self.privacy_set_size < config.min_execution_privacy_set_size {
            return Err("privacy fence set size too small".to_string());
        }
        if self.expires_at_height <= self.opened_at_height {
            return Err("privacy fence expiry must be after open height".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "fence_id": self.fence_id,
            "ticket_id": self.ticket_id,
            "profile_id": self.profile_id,
            "status": self.status,
            "nullifier": self.nullifier,
            "ring_root": self.ring_root,
            "view_tag_root": self.view_tag_root,
            "fence_root": self.fence_root,
            "privacy_set_size": self.privacy_set_size,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RuntimeEvent {
    pub event_id: String,
    pub event_kind: String,
    pub subject_id: String,
    pub profile_id: Option<String>,
    pub payload_root: String,
    pub emitted_at_height: u64,
}

impl RuntimeEvent {
    pub fn public_record(&self) -> Value {
        json!({
            "event_id": self.event_id,
            "event_kind": self.event_kind,
            "subject_id": self.subject_id,
            "profile_id": self.profile_id,
            "payload_root": self.payload_root,
            "emitted_at_height": self.emitted_at_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub current_height: u64,
    pub profiles: BTreeMap<String, SlaProfile>,
    pub tickets: BTreeMap<String, ExecutionTicket>,
    pub preconfirmations: BTreeMap<String, PqPreconfirmation>,
    pub proof_windows: BTreeMap<String, ProofWindow>,
    pub reservations: BTreeMap<String, FeeSponsorReservation>,
    pub receipts: BTreeMap<String, SettlementReceipt>,
    pub penalties: BTreeMap<String, SlaPenalty>,
    pub rebates: BTreeMap<String, FeeRebate>,
    pub privacy_fences: BTreeMap<String, PrivacyFence>,
    pub witness_attestations: BTreeMap<String, WitnessAttestation>,
    pub batches: BTreeMap<String, SettlementBatch>,
    pub spent_nullifiers: BTreeSet<String>,
    pub events: Vec<RuntimeEvent>,
}

impl Default for State {
    fn default() -> Self {
        Self {
            config: Config::default(),
            counters: Counters::default(),
            roots: Roots::default(),
            current_height: 0,
            profiles: BTreeMap::new(),
            tickets: BTreeMap::new(),
            preconfirmations: BTreeMap::new(),
            proof_windows: BTreeMap::new(),
            reservations: BTreeMap::new(),
            receipts: BTreeMap::new(),
            penalties: BTreeMap::new(),
            rebates: BTreeMap::new(),
            privacy_fences: BTreeMap::new(),
            witness_attestations: BTreeMap::new(),
            batches: BTreeMap::new(),
            spent_nullifiers: BTreeSet::new(),
            events: Vec::new(),
        }
    }
}

impl State {
    pub fn new(config: Config, current_height: u64) -> Result<Self> {
        config.validate()?;
        let mut state = Self {
            config,
            current_height,
            ..Self::default()
        };
        state.recompute_counters();
        state.recompute_roots();
        Ok(state)
    }

    pub fn devnet() -> Self {
        let mut state = Self {
            current_height: PRIVATE_L2_PQ_CONTRACT_EXECUTION_SLA_RUNTIME_DEVNET_HEIGHT,
            ..Self::default()
        };
        let height = state.current_height;
        let profile_id_value = sla_profile_id(SlaLaneKind::SpotSwap, "devnet-private-dex-fast", 1);
        let bridge_profile_id =
            sla_profile_id(SlaLaneKind::MoneroBridgeExit, "devnet-monero-exit-fast", 1);

        let fast_profile = SlaProfile {
            profile_id: profile_id_value.clone(),
            lane_kind: SlaLaneKind::SpotSwap,
            status: SlaProfileStatus::Active,
            label_hash: label_hash("devnet private dex fast execution"),
            contract_scope_root: payload_root(
                "PRIVATE-L2-PQ-SLA-CONTRACT-SCOPE",
                &json!([
                    "private-stable-swap",
                    "darkpool-cross-margin",
                    "confidential-token-vault"
                ]),
            ),
            operator_set_root: payload_root(
                "PRIVATE-L2-PQ-SLA-OPERATOR-SET",
                &json!(["operator-pq-a", "operator-pq-b", "operator-pq-c"]),
            ),
            prover_set_root: payload_root(
                "PRIVATE-L2-PQ-SLA-PROVER-SET",
                &json!(["recursive-prover-a", "recursive-prover-b"]),
            ),
            sponsor_pool_root: payload_root(
                "PRIVATE-L2-PQ-SLA-SPONSOR-POOL",
                &json!(["fee-sponsor-a", "fee-sponsor-b"]),
            ),
            min_privacy_set_size: state.config.min_execution_privacy_set_size,
            min_pq_security_bits: state.config.min_pq_security_bits,
            max_user_fee_bps: state.config.max_user_fee_bps,
            target_rebate_bps: state.config.target_rebate_bps,
            preconfirmation_deadline_blocks: state.config.preconfirmation_deadline_blocks,
            execution_deadline_blocks: state.config.execution_deadline_blocks,
            proof_deadline_blocks: state.config.proof_deadline_blocks,
            created_at_height: height - 4_096,
            expires_at_height: None,
        };
        let bridge_profile = SlaProfile {
            profile_id: bridge_profile_id.clone(),
            lane_kind: SlaLaneKind::MoneroBridgeExit,
            status: SlaProfileStatus::Active,
            label_hash: label_hash("devnet monero bridge exit fast execution"),
            contract_scope_root: payload_root(
                "PRIVATE-L2-PQ-SLA-CONTRACT-SCOPE",
                &json!([
                    "monero-exit-router",
                    "reserve-attestation",
                    "private-fee-sponsor"
                ]),
            ),
            operator_set_root: payload_root(
                "PRIVATE-L2-PQ-SLA-OPERATOR-SET",
                &json!(["bridge-relay-pq-a", "bridge-relay-pq-b", "watcher-pq-a"]),
            ),
            prover_set_root: payload_root(
                "PRIVATE-L2-PQ-SLA-PROVER-SET",
                &json!(["monero-exit-prover-a", "monero-exit-prover-b"]),
            ),
            sponsor_pool_root: payload_root(
                "PRIVATE-L2-PQ-SLA-SPONSOR-POOL",
                &json!(["bridge-fee-sponsor-a", "bridge-fee-sponsor-b"]),
            ),
            min_privacy_set_size: state.config.min_batch_privacy_set_size,
            min_pq_security_bits: state.config.min_pq_security_bits,
            max_user_fee_bps: 10,
            target_rebate_bps: state.config.target_rebate_bps,
            preconfirmation_deadline_blocks: state.config.preconfirmation_deadline_blocks + 1,
            execution_deadline_blocks: state.config.execution_deadline_blocks,
            proof_deadline_blocks: state.config.proof_deadline_blocks + 4,
            created_at_height: height - 3_840,
            expires_at_height: None,
        };
        state
            .register_profile(fast_profile)
            .expect("devnet fast SLA profile");
        state
            .register_profile(bridge_profile)
            .expect("devnet bridge SLA profile");

        let ticket_nullifier = nullifier(&profile_id_value, "devnet-ticket-alice-0001");
        let fence_id_value = privacy_fence_id(&profile_id_value, &ticket_nullifier);
        let ticket_id_value = execution_ticket_id(&profile_id_value, &ticket_nullifier, height - 9);
        let reservation_id_value = sponsor_reservation_id(
            "sponsor-a",
            &profile_id_value,
            &ticket_id_value,
            height - 10,
        );
        let ticket = ExecutionTicket {
            ticket_id: ticket_id_value.clone(),
            profile_id: profile_id_value.clone(),
            lane_kind: SlaLaneKind::SpotSwap,
            fee_class: FeeClass::Sponsored,
            status: TicketStatus::Settled,
            caller_commitment: commitment("caller", "devnet-alice"),
            contract_commitment: commitment("contract", "private-stable-swap"),
            method_selector_hash: selector_hash("swap_exact_private_input"),
            encrypted_call_root: payload_root(
                "PRIVATE-L2-PQ-SLA-ENCRYPTED-CALL",
                &json!({"path": "wxmr/private-usd", "amount": "hidden", "suite": "ml-kem-1024"}),
            ),
            call_value_commitment: commitment("value", "hidden"),
            asset_root: payload_root(
                "PRIVATE-L2-PQ-SLA-ASSET-ROOT",
                &json!(["wxmr", "private-usd"]),
            ),
            dependency_root: root_from_values(
                "PRIVATE-L2-PQ-SLA-DEPENDENCIES",
                &[
                    "policy-engine-ok",
                    "verifier-cache-warm",
                    "fee-sponsor-bound",
                ],
            ),
            privacy_fence_id: fence_id_value.clone(),
            nullifier: ticket_nullifier.clone(),
            sponsor_reservation_id: Some(reservation_id_value.clone()),
            max_fee_micro_units: 5_000_000,
            priority_fee_micro_units: 150_000,
            requested_at_height: height - 9,
            preconfirmation_deadline_height: height - 7,
            execution_deadline_height: height - 3,
            proof_deadline_height: height + 6,
            expires_at_height: height + state.config.ticket_ttl_blocks,
        };
        state.submit_ticket(ticket).expect("devnet ticket");

        let bridge_nullifier = nullifier(&bridge_profile_id, "devnet-bridge-ticket-bob-0001");
        let bridge_fence_id = privacy_fence_id(&bridge_profile_id, &bridge_nullifier);
        let bridge_ticket_id =
            execution_ticket_id(&bridge_profile_id, &bridge_nullifier, height - 6);
        let bridge_reservation_id = sponsor_reservation_id(
            "bridge-sponsor-a",
            &bridge_profile_id,
            &bridge_ticket_id,
            height - 7,
        );
        let bridge_ticket = ExecutionTicket {
            ticket_id: bridge_ticket_id.clone(),
            profile_id: bridge_profile_id.clone(),
            lane_kind: SlaLaneKind::MoneroBridgeExit,
            fee_class: FeeClass::RebateEligible,
            status: TicketStatus::Preconfirmed,
            caller_commitment: commitment("caller", "devnet-bob"),
            contract_commitment: commitment("contract", "monero-private-exit-router"),
            method_selector_hash: selector_hash("prove_private_exit"),
            encrypted_call_root: payload_root(
                "PRIVATE-L2-PQ-SLA-ENCRYPTED-CALL",
                &json!({"exit_note": "encrypted", "subaddress": "hidden", "view_tag": "hidden"}),
            ),
            call_value_commitment: commitment("value", "exit-hidden"),
            asset_root: payload_root("PRIVATE-L2-PQ-SLA-ASSET-ROOT", &json!(["xmr", "wxmr"])),
            dependency_root: root_from_values(
                "PRIVATE-L2-PQ-SLA-DEPENDENCIES",
                &[
                    "reserve-attested",
                    "header-finality-ok",
                    "watcher-quorum-ok",
                ],
            ),
            privacy_fence_id: bridge_fence_id.clone(),
            nullifier: bridge_nullifier.clone(),
            sponsor_reservation_id: Some(bridge_reservation_id.clone()),
            max_fee_micro_units: 8_000_000,
            priority_fee_micro_units: 240_000,
            requested_at_height: height - 6,
            preconfirmation_deadline_height: height - 3,
            execution_deadline_height: height + 2,
            proof_deadline_height: height + 18,
            expires_at_height: height + state.config.ticket_ttl_blocks,
        };
        state
            .submit_ticket(bridge_ticket)
            .expect("devnet bridge ticket");

        state
            .reserve_fee(FeeSponsorReservation {
                reservation_id: reservation_id_value.clone(),
                sponsor_commitment: commitment("sponsor", "fee-sponsor-a"),
                ticket_id: Some(ticket_id_value.clone()),
                profile_id: profile_id_value.clone(),
                status: ReservationStatus::Consumed,
                reserved_fee_micro_units: 5_000_000,
                max_fee_bps: 12,
                rebate_bps: state.config.target_rebate_bps,
                privacy_set_size: state.config.min_execution_privacy_set_size,
                created_at_height: height - 10,
                expires_at_height: height + state.config.reservation_ttl_blocks,
            })
            .expect("devnet sponsor reservation");
        state
            .reserve_fee(FeeSponsorReservation {
                reservation_id: bridge_reservation_id.clone(),
                sponsor_commitment: commitment("sponsor", "bridge-fee-sponsor-a"),
                ticket_id: Some(bridge_ticket_id.clone()),
                profile_id: bridge_profile_id.clone(),
                status: ReservationStatus::Bound,
                reserved_fee_micro_units: 8_000_000,
                max_fee_bps: 10,
                rebate_bps: state.config.target_rebate_bps,
                privacy_set_size: state.config.min_batch_privacy_set_size,
                created_at_height: height - 7,
                expires_at_height: height + state.config.reservation_ttl_blocks,
            })
            .expect("devnet bridge sponsor reservation");

        state
            .open_privacy_fence(PrivacyFence {
                fence_id: fence_id_value.clone(),
                ticket_id: Some(ticket_id_value.clone()),
                profile_id: profile_id_value.clone(),
                status: PrivacyFenceStatus::Spent,
                nullifier: ticket_nullifier.clone(),
                ring_root: payload_root(
                    "PRIVATE-L2-PQ-SLA-RING-ROOT",
                    &json!(["dex-ring-root-0001", "dex-ring-root-0002"]),
                ),
                view_tag_root: payload_root(
                    "PRIVATE-L2-PQ-SLA-VIEW-TAG-ROOT",
                    &json!(["viewtag-dex-0001"]),
                ),
                fence_root: payload_root(
                    "PRIVATE-L2-PQ-SLA-FENCE-ROOT",
                    &json!({"ticket": ticket_id_value, "nullifier": ticket_nullifier}),
                ),
                privacy_set_size: state.config.min_execution_privacy_set_size,
                opened_at_height: height - 9,
                expires_at_height: height + state.config.ticket_ttl_blocks,
            })
            .expect("devnet privacy fence");
        state
            .open_privacy_fence(PrivacyFence {
                fence_id: bridge_fence_id.clone(),
                ticket_id: Some(bridge_ticket_id.clone()),
                profile_id: bridge_profile_id.clone(),
                status: PrivacyFenceStatus::Reserved,
                nullifier: bridge_nullifier.clone(),
                ring_root: payload_root(
                    "PRIVATE-L2-PQ-SLA-RING-ROOT",
                    &json!(["monero-ring-root-0001", "monero-ring-root-0002"]),
                ),
                view_tag_root: payload_root(
                    "PRIVATE-L2-PQ-SLA-VIEW-TAG-ROOT",
                    &json!(["viewtag-bridge-0001"]),
                ),
                fence_root: payload_root(
                    "PRIVATE-L2-PQ-SLA-FENCE-ROOT",
                    &json!({"ticket": bridge_ticket_id, "nullifier": bridge_nullifier}),
                ),
                privacy_set_size: state.config.min_batch_privacy_set_size,
                opened_at_height: height - 6,
                expires_at_height: height + state.config.ticket_ttl_blocks,
            })
            .expect("devnet bridge privacy fence");
        state
            .spend_nullifier(&ticket_nullifier)
            .expect("devnet spent ticket nullifier");

        let preconfirmation_id_value = preconfirmation_id(&ticket_id_value, "operator-pq-a", 1);
        state
            .record_preconfirmation(PqPreconfirmation {
                preconfirmation_id: preconfirmation_id_value.clone(),
                ticket_id: ticket_id_value.clone(),
                profile_id: profile_id_value.clone(),
                status: PreconfirmationStatus::Aggregated,
                operator_commitment: commitment("operator", "operator-pq-a"),
                committee_epoch: 1,
                signature_root: payload_root(
                    "PRIVATE-L2-PQ-SLA-PRECONF-SIGNATURE",
                    &json!(["ml-dsa-87-sig-a", "ml-dsa-87-sig-b"]),
                ),
                transcript_root: payload_root(
                    "PRIVATE-L2-PQ-SLA-PRECONF-TRANSCRIPT",
                    &json!({"ticket": ticket_id_value, "fiat_shamir": "shake256"}),
                ),
                promised_execution_height: height - 3,
                issued_at_height: height - 8,
                expires_at_height: height + state.config.preconfirmation_deadline_blocks,
                pq_security_bits: state.config.min_pq_security_bits,
                threshold: 2,
                signer_count: 3,
            })
            .expect("devnet preconfirmation");

        state
            .record_preconfirmation(PqPreconfirmation {
                preconfirmation_id: preconfirmation_id(&bridge_ticket_id, "bridge-relay-pq-a", 1),
                ticket_id: bridge_ticket_id.clone(),
                profile_id: bridge_profile_id.clone(),
                status: PreconfirmationStatus::Signed,
                operator_commitment: commitment("operator", "bridge-relay-pq-a"),
                committee_epoch: 1,
                signature_root: payload_root(
                    "PRIVATE-L2-PQ-SLA-PRECONF-SIGNATURE",
                    &json!(["bridge-ml-dsa-87-sig-a", "bridge-ml-dsa-87-sig-b"]),
                ),
                transcript_root: payload_root(
                    "PRIVATE-L2-PQ-SLA-PRECONF-TRANSCRIPT",
                    &json!({"ticket": bridge_ticket_id, "fiat_shamir": "shake256"}),
                ),
                promised_execution_height: height + 1,
                issued_at_height: height - 5,
                expires_at_height: height + state.config.preconfirmation_deadline_blocks,
                pq_security_bits: state.config.min_pq_security_bits,
                threshold: 2,
                signer_count: 3,
            })
            .expect("devnet bridge preconfirmation");

        let window_id_value = proof_window_id(&profile_id_value, height / 16, 0);
        state
            .open_proof_window(ProofWindow {
                window_id: window_id_value.clone(),
                profile_id: profile_id_value.clone(),
                status: ProofWindowStatus::Settled,
                ticket_root: map_root(
                    "PRIVATE-L2-PQ-SLA-WINDOW-TICKETS",
                    &state.tickets,
                    |ticket| ticket.public_record(),
                ),
                preconfirmation_root: map_root(
                    "PRIVATE-L2-PQ-SLA-WINDOW-PRECONFIRMATIONS",
                    &state.preconfirmations,
                    |preconfirmation| preconfirmation.public_record(),
                ),
                witness_root: merkle_root("PRIVATE-L2-PQ-SLA-WINDOW-WITNESS-EMPTY", &[]),
                prover_commitment: commitment("prover", "recursive-prover-a"),
                recursive_proof_root: Some(payload_root(
                    "PRIVATE-L2-PQ-SLA-RECURSIVE-PROOF",
                    &json!({"proof": "devnet-recursive-proof-root"}),
                )),
                opened_at_height: height - 8,
                closes_at_height: height + state.config.proof_deadline_blocks,
                max_tickets: state.config.max_batch_tickets,
                ticket_count: 2,
                aggregated_count: 1,
                late_count: 0,
            })
            .expect("devnet proof window");

        state
            .record_witness_attestation(WitnessAttestation {
                attestation_id: witness_attestation_id(&ticket_id_value, "watcher-a", height - 2),
                ticket_id: ticket_id_value.clone(),
                profile_id: profile_id_value.clone(),
                status: WitnessStatus::Accepted,
                witness_commitment: commitment("watcher", "watcher-a"),
                transcript_root: payload_root(
                    "PRIVATE-L2-PQ-SLA-WITNESS-TRANSCRIPT",
                    &json!({"latency_ms": 180, "fee": 4_800_000_u64}),
                ),
                observed_state_root: payload_root(
                    "PRIVATE-L2-PQ-SLA-WITNESS-STATE",
                    &json!({"post_state": "hidden-success"}),
                ),
                latency_ms: 180,
                fee_observed_micro_units: 4_800_000,
                issued_at_height: height - 2,
            })
            .expect("devnet witness");

        let batch_id_value = batch_id(&profile_id_value, &window_id_value, height, 0);
        let receipt_id_value = settlement_receipt_id(&batch_id_value, &ticket_id_value);
        let rebate_id_value = rebate_id(&receipt_id_value, "devnet-alice");
        state
            .issue_receipt(SettlementReceipt {
                receipt_id: receipt_id_value.clone(),
                ticket_id: ticket_id_value.clone(),
                batch_id: batch_id_value.clone(),
                profile_id: profile_id_value.clone(),
                kind: ReceiptKind::Execution,
                status: TicketStatus::Settled,
                execution_root: payload_root(
                    "PRIVATE-L2-PQ-SLA-EXECUTION-ROOT",
                    &json!({"contract": "private-stable-swap", "result": "hidden-success"}),
                ),
                fee_paid_micro_units: 4_800_000,
                sponsor_paid_micro_units: 4_650_000,
                rebate_id: Some(rebate_id_value.clone()),
                penalty_id: None,
                settled_at_height: height,
            })
            .expect("devnet receipt");
        state
            .issue_rebate(FeeRebate {
                rebate_id: rebate_id_value,
                receipt_id: receipt_id_value.clone(),
                beneficiary_commitment: commitment("beneficiary", "devnet-alice"),
                status: RebateStatus::Claimable,
                amount_micro_units: 240_000,
                claim_nullifier: nullifier("rebate", "devnet-alice-sla-0001"),
                privacy_set_size: state.config.min_execution_privacy_set_size,
                created_at_height: height,
                expires_at_height: height + state.config.rebate_ttl_blocks,
            })
            .expect("devnet rebate");

        let late_penalty_id = penalty_id(&bridge_ticket_id, "late-proof-window");
        state
            .apply_penalty(SlaPenalty {
                penalty_id: late_penalty_id,
                ticket_id: bridge_ticket_id.clone(),
                profile_id: bridge_profile_id.clone(),
                operator_commitment: commitment("operator", "bridge-relay-pq-a"),
                status: PenaltyStatus::Pending,
                reason_hash: label_hash("bridge proof window not yet filled"),
                assessed_micro_units: 500_000,
                bond_debit_micro_units: 0,
                evidence_root: payload_root(
                    "PRIVATE-L2-PQ-SLA-PENALTY-EVIDENCE",
                    &json!({"ticket": bridge_ticket_id, "status": "preconfirmed"}),
                ),
                assessed_at_height: height,
            })
            .expect("devnet pending penalty");

        state
            .settle_batch(SettlementBatch {
                batch_id: batch_id_value.clone(),
                profile_id: profile_id_value.clone(),
                window_id: window_id_value,
                status: BatchStatus::Settled,
                ticket_root: map_root("PRIVATE-L2-PQ-SLA-BATCH-TICKET", &state.tickets, |ticket| {
                    ticket.public_record()
                }),
                receipt_root: map_root(
                    "PRIVATE-L2-PQ-SLA-BATCH-RECEIPT",
                    &state.receipts,
                    |receipt| receipt.public_record(),
                ),
                penalty_root: map_root(
                    "PRIVATE-L2-PQ-SLA-BATCH-PENALTY",
                    &state.penalties,
                    |penalty| penalty.public_record(),
                ),
                rebate_root: map_root("PRIVATE-L2-PQ-SLA-BATCH-REBATE", &state.rebates, |rebate| {
                    rebate.public_record()
                }),
                post_state_root: payload_root(
                    "PRIVATE-L2-PQ-SLA-BATCH-POST-STATE",
                    &json!({"state": "hidden", "receipts": 1}),
                ),
                proof_root: payload_root(
                    "PRIVATE-L2-PQ-SLA-BATCH-PROOF",
                    &json!({"recursive": true, "pq_transcript": "shake256"}),
                ),
                batch_size: 2,
                settled_count: 1,
                failed_count: 0,
                total_fee_micro_units: 4_800_000,
                total_rebate_micro_units: 240_000,
                sealed_at_height: height - 1,
                settled_at_height: Some(height),
            })
            .expect("devnet settlement batch");

        state.emit_event(
            "profile_activated",
            &profile_id_value,
            Some(profile_id_value.clone()),
            &json!({"lane": SlaLaneKind::SpotSwap.as_str()}),
            height - 4_096,
        );
        state.emit_event(
            "ticket_settled",
            &ticket_id_value,
            Some(profile_id_value),
            &json!({"batch_id": batch_id_value, "fee_micro_units": 4_800_000_u64}),
            height,
        );
        state.emit_event(
            "bridge_ticket_preconfirmed",
            &bridge_profile_id,
            Some(bridge_profile_id.clone()),
            &json!({"status": "waiting_for_exit_proof"}),
            height,
        );
        state.recompute_counters();
        state.recompute_roots();
        state
    }

    pub fn register_profile(&mut self, profile: SlaProfile) -> Result<()> {
        profile.validate(&self.config)?;
        self.profiles.insert(profile.profile_id.clone(), profile);
        self.recompute_counters();
        self.recompute_roots();
        Ok(())
    }

    pub fn submit_ticket(&mut self, ticket: ExecutionTicket) -> Result<()> {
        if self.tickets.len() >= self.config.max_tickets {
            return Err("execution ticket capacity exceeded".to_string());
        }
        let profile = self
            .profiles
            .get(&ticket.profile_id)
            .ok_or_else(|| format!("unknown SLA profile: {}", ticket.profile_id))?;
        ticket.validate(&self.config, profile)?;
        if self.spent_nullifiers.contains(&ticket.nullifier) {
            return Err("ticket nullifier already spent".to_string());
        }
        self.tickets.insert(ticket.ticket_id.clone(), ticket);
        self.recompute_counters();
        self.recompute_roots();
        Ok(())
    }

    pub fn reserve_fee(&mut self, reservation: FeeSponsorReservation) -> Result<()> {
        reservation.validate(&self.config)?;
        if !self.profiles.contains_key(&reservation.profile_id) {
            return Err("reservation references unknown SLA profile".to_string());
        }
        self.reservations
            .insert(reservation.reservation_id.clone(), reservation);
        self.recompute_counters();
        self.recompute_roots();
        Ok(())
    }

    pub fn record_preconfirmation(&mut self, preconfirmation: PqPreconfirmation) -> Result<()> {
        if self.preconfirmations.len() >= self.config.max_preconfirmations {
            return Err("preconfirmation capacity exceeded".to_string());
        }
        preconfirmation.validate(&self.config)?;
        if !self.tickets.contains_key(&preconfirmation.ticket_id) {
            return Err("preconfirmation references unknown ticket".to_string());
        }
        self.preconfirmations
            .insert(preconfirmation.preconfirmation_id.clone(), preconfirmation);
        self.recompute_counters();
        self.recompute_roots();
        Ok(())
    }

    pub fn open_proof_window(&mut self, window: ProofWindow) -> Result<()> {
        if self.proof_windows.len() >= self.config.max_proof_windows {
            return Err("proof window capacity exceeded".to_string());
        }
        window.validate(&self.config)?;
        if !self.profiles.contains_key(&window.profile_id) {
            return Err("proof window references unknown SLA profile".to_string());
        }
        self.proof_windows.insert(window.window_id.clone(), window);
        self.recompute_counters();
        self.recompute_roots();
        Ok(())
    }

    pub fn record_witness_attestation(&mut self, attestation: WitnessAttestation) -> Result<()> {
        attestation.validate()?;
        if !self.tickets.contains_key(&attestation.ticket_id) {
            return Err("witness attestation references unknown ticket".to_string());
        }
        self.witness_attestations
            .insert(attestation.attestation_id.clone(), attestation);
        self.recompute_counters();
        self.recompute_roots();
        Ok(())
    }

    pub fn settle_batch(&mut self, batch: SettlementBatch) -> Result<()> {
        batch.validate(&self.config)?;
        if !self.profiles.contains_key(&batch.profile_id) {
            return Err("batch references unknown SLA profile".to_string());
        }
        if !self.proof_windows.contains_key(&batch.window_id) {
            return Err("batch references unknown proof window".to_string());
        }
        self.batches.insert(batch.batch_id.clone(), batch);
        self.recompute_counters();
        self.recompute_roots();
        Ok(())
    }

    pub fn issue_receipt(&mut self, receipt: SettlementReceipt) -> Result<()> {
        receipt.validate()?;
        if !self.tickets.contains_key(&receipt.ticket_id) {
            return Err("receipt references unknown ticket".to_string());
        }
        self.receipts.insert(receipt.receipt_id.clone(), receipt);
        self.recompute_counters();
        self.recompute_roots();
        Ok(())
    }

    pub fn apply_penalty(&mut self, penalty: SlaPenalty) -> Result<()> {
        penalty.validate()?;
        if !self.tickets.contains_key(&penalty.ticket_id) {
            return Err("penalty references unknown ticket".to_string());
        }
        self.penalties.insert(penalty.penalty_id.clone(), penalty);
        self.recompute_counters();
        self.recompute_roots();
        Ok(())
    }

    pub fn issue_rebate(&mut self, rebate: FeeRebate) -> Result<()> {
        rebate.validate(&self.config)?;
        if !self.receipts.contains_key(&rebate.receipt_id) {
            return Err("rebate references unknown receipt".to_string());
        }
        self.rebates.insert(rebate.rebate_id.clone(), rebate);
        self.recompute_counters();
        self.recompute_roots();
        Ok(())
    }

    pub fn open_privacy_fence(&mut self, fence: PrivacyFence) -> Result<()> {
        fence.validate(&self.config)?;
        self.privacy_fences.insert(fence.fence_id.clone(), fence);
        self.recompute_counters();
        self.recompute_roots();
        Ok(())
    }

    pub fn spend_nullifier(&mut self, nullifier_value: &str) -> Result<()> {
        if !self.spent_nullifiers.insert(nullifier_value.to_string()) {
            return Err("nullifier already spent".to_string());
        }
        self.recompute_counters();
        self.recompute_roots();
        Ok(())
    }

    pub fn emit_event(
        &mut self,
        event_kind: &str,
        subject_id: &str,
        profile_id: Option<String>,
        payload: &Value,
        emitted_at_height: u64,
    ) {
        self.events.push(RuntimeEvent {
            event_id: runtime_event_id(event_kind, subject_id, emitted_at_height),
            event_kind: event_kind.to_string(),
            subject_id: subject_id.to_string(),
            profile_id,
            payload_root: payload_root("PRIVATE-L2-PQ-SLA-EVENT-PAYLOAD", payload),
            emitted_at_height,
        });
        self.recompute_counters();
        self.recompute_roots();
    }

    pub fn recompute_counters(&mut self) {
        self.counters = Counters {
            profiles: self.profiles.len() as u64,
            tickets: self.tickets.len() as u64,
            preconfirmations: self.preconfirmations.len() as u64,
            proof_windows: self.proof_windows.len() as u64,
            reservations: self.reservations.len() as u64,
            receipts: self.receipts.len() as u64,
            penalties: self.penalties.len() as u64,
            rebates: self.rebates.len() as u64,
            fences: self.privacy_fences.len() as u64,
            witness_attestations: self.witness_attestations.len() as u64,
            batches: self.batches.len() as u64,
            spent_nullifiers: self.spent_nullifiers.len() as u64,
            events: self.events.len() as u64,
            settled_tickets: self
                .tickets
                .values()
                .filter(|ticket| ticket.status == TicketStatus::Settled)
                .count() as u64,
            late_tickets: self
                .proof_windows
                .values()
                .map(|window| window.late_count)
                .sum(),
            slashed_tickets: self
                .tickets
                .values()
                .filter(|ticket| ticket.status == TicketStatus::Slashed)
                .count() as u64,
            sponsored_fee_micro_units: self
                .receipts
                .values()
                .map(|receipt| receipt.sponsor_paid_micro_units)
                .sum(),
            user_fee_micro_units: self
                .receipts
                .values()
                .map(|receipt| receipt.fee_paid_micro_units)
                .sum(),
            rebate_micro_units: self
                .rebates
                .values()
                .map(|rebate| rebate.amount_micro_units)
                .sum(),
        };
    }

    pub fn recompute_roots(&mut self) {
        self.roots = Roots {
            profile_root: map_root("PRIVATE-L2-PQ-SLA-PROFILES", &self.profiles, |profile| {
                profile.public_record()
            }),
            ticket_root: map_root("PRIVATE-L2-PQ-SLA-TICKETS", &self.tickets, |ticket| {
                ticket.public_record()
            }),
            preconfirmation_root: map_root(
                "PRIVATE-L2-PQ-SLA-PRECONFIRMATIONS",
                &self.preconfirmations,
                |preconfirmation| preconfirmation.public_record(),
            ),
            proof_window_root: map_root(
                "PRIVATE-L2-PQ-SLA-PROOF-WINDOWS",
                &self.proof_windows,
                |window| window.public_record(),
            ),
            reservation_root: map_root(
                "PRIVATE-L2-PQ-SLA-RESERVATIONS",
                &self.reservations,
                |reservation| reservation.public_record(),
            ),
            receipt_root: map_root("PRIVATE-L2-PQ-SLA-RECEIPTS", &self.receipts, |receipt| {
                receipt.public_record()
            }),
            penalty_root: map_root("PRIVATE-L2-PQ-SLA-PENALTIES", &self.penalties, |penalty| {
                penalty.public_record()
            }),
            rebate_root: map_root("PRIVATE-L2-PQ-SLA-REBATES", &self.rebates, |rebate| {
                rebate.public_record()
            }),
            fence_root: map_root("PRIVATE-L2-PQ-SLA-FENCES", &self.privacy_fences, |fence| {
                fence.public_record()
            }),
            witness_root: map_root(
                "PRIVATE-L2-PQ-SLA-WITNESSES",
                &self.witness_attestations,
                |attestation| attestation.public_record(),
            ),
            batch_root: map_root("PRIVATE-L2-PQ-SLA-BATCHES", &self.batches, |batch| {
                batch.public_record()
            }),
            nullifier_root: set_root("PRIVATE-L2-PQ-SLA-SPENT-NULLIFIERS", &self.spent_nullifiers),
            event_root: vec_root(
                "PRIVATE-L2-PQ-SLA-EVENTS",
                &self
                    .events
                    .iter()
                    .map(RuntimeEvent::public_record)
                    .collect::<Vec<_>>(),
            ),
        };
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": PRIVATE_L2_PQ_CONTRACT_EXECUTION_SLA_RUNTIME_PROTOCOL_VERSION,
            "schema_version": PRIVATE_L2_PQ_CONTRACT_EXECUTION_SLA_RUNTIME_SCHEMA_VERSION,
            "hash_suite": PRIVATE_L2_PQ_CONTRACT_EXECUTION_SLA_RUNTIME_HASH_SUITE,
            "ticket_scheme": PRIVATE_L2_PQ_CONTRACT_EXECUTION_SLA_RUNTIME_TICKET_SCHEME,
            "preconfirmation_scheme": PRIVATE_L2_PQ_CONTRACT_EXECUTION_SLA_RUNTIME_PRECONF_SCHEME,
            "proof_window_scheme": PRIVATE_L2_PQ_CONTRACT_EXECUTION_SLA_RUNTIME_PROOF_WINDOW_SCHEME,
            "sponsor_scheme": PRIVATE_L2_PQ_CONTRACT_EXECUTION_SLA_RUNTIME_SPONSOR_SCHEME,
            "receipt_scheme": PRIVATE_L2_PQ_CONTRACT_EXECUTION_SLA_RUNTIME_RECEIPT_SCHEME,
            "chain_id": CHAIN_ID,
            "current_height": self.current_height,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
        })
    }

    pub fn state_root(&self) -> String {
        state_root_from_record(&self.public_record())
    }
}

pub type Runtime = State;

pub fn devnet() -> State {
    State::devnet()
}

pub fn private_l2_pq_contract_execution_sla_runtime_public_record(state: &State) -> Value {
    state.public_record()
}

pub fn private_l2_pq_contract_execution_sla_runtime_state_root(state: &State) -> String {
    state.state_root()
}

pub fn sla_profile_id(kind: SlaLaneKind, label: &str, epoch: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-SLA-PROFILE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(kind.as_str()),
            HashPart::Str(label),
            HashPart::U64(epoch),
        ],
        32,
    )
}

pub fn execution_ticket_id(profile_id: &str, nullifier_value: &str, height: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-SLA-TICKET-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(profile_id),
            HashPart::Str(nullifier_value),
            HashPart::U64(height),
        ],
        32,
    )
}

pub fn preconfirmation_id(ticket_id: &str, operator_label: &str, epoch: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-SLA-PRECONFIRMATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(ticket_id),
            HashPart::Str(operator_label),
            HashPart::U64(epoch),
        ],
        32,
    )
}

pub fn proof_window_id(profile_id: &str, bucket: u64, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-SLA-PROOF-WINDOW-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(profile_id),
            HashPart::U64(bucket),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn sponsor_reservation_id(
    sponsor_label: &str,
    profile_id: &str,
    ticket_id: &str,
    height: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-SLA-SPONSOR-RESERVATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(sponsor_label),
            HashPart::Str(profile_id),
            HashPart::Str(ticket_id),
            HashPart::U64(height),
        ],
        32,
    )
}

pub fn settlement_receipt_id(batch_id: &str, ticket_id: &str) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-SLA-SETTLEMENT-RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(batch_id),
            HashPart::Str(ticket_id),
        ],
        32,
    )
}

pub fn penalty_id(ticket_id: &str, reason_label: &str) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-SLA-PENALTY-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(ticket_id),
            HashPart::Str(reason_label),
        ],
        32,
    )
}

pub fn rebate_id(receipt_id: &str, beneficiary_label: &str) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-SLA-REBATE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(receipt_id),
            HashPart::Str(beneficiary_label),
        ],
        32,
    )
}

pub fn privacy_fence_id(profile_id: &str, nullifier_value: &str) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-SLA-PRIVACY-FENCE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(profile_id),
            HashPart::Str(nullifier_value),
        ],
        32,
    )
}

pub fn witness_attestation_id(ticket_id: &str, witness_label: &str, height: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-SLA-WITNESS-ATTESTATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(ticket_id),
            HashPart::Str(witness_label),
            HashPart::U64(height),
        ],
        32,
    )
}

pub fn batch_id(profile_id: &str, window_id: &str, height: u64, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-SLA-BATCH-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(profile_id),
            HashPart::Str(window_id),
            HashPart::U64(height),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn runtime_event_id(event_kind: &str, subject_id: &str, height: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-SLA-EVENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(event_kind),
            HashPart::Str(subject_id),
            HashPart::U64(height),
        ],
        32,
    )
}

pub fn nullifier(scope_id: &str, secret_label: &str) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-SLA-NULLIFIER",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(scope_id),
            HashPart::Str(secret_label),
        ],
        32,
    )
}

pub fn commitment(domain: &str, label: &str) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-SLA-COMMITMENT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(domain),
            HashPart::Str(label),
        ],
        32,
    )
}

pub fn label_hash(label: &str) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-SLA-LABEL",
        &[HashPart::Str(CHAIN_ID), HashPart::Str(label)],
        32,
    )
}

pub fn selector_hash(selector: &str) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-SLA-METHOD-SELECTOR",
        &[HashPart::Str(CHAIN_ID), HashPart::Str(selector)],
        4,
    )
}

pub fn payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[HashPart::Str(CHAIN_ID), HashPart::Json(payload)],
        32,
    )
}

pub fn root_from_record(domain: &str, record: &Value) -> String {
    domain_hash(
        domain,
        &[HashPart::Str(CHAIN_ID), HashPart::Json(record)],
        32,
    )
}

pub fn public_record_root(record: &Value) -> String {
    root_from_record("PRIVATE-L2-PQ-SLA-PUBLIC-RECORD", record)
}

pub fn state_root_from_record(record: &Value) -> String {
    root_from_record("PRIVATE-L2-PQ-SLA-STATE", record)
}

pub fn root_from_values(domain: &str, values: &[&str]) -> String {
    let leaves = values
        .iter()
        .map(|value| {
            json!(domain_hash(
                domain,
                &[HashPart::Str(CHAIN_ID), HashPart::Str(value)],
                32
            ))
        })
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn map_root<T, F>(domain: &str, map: &BTreeMap<String, T>, project: F) -> String
where
    F: Fn(&T) -> Value,
{
    let leaves = map
        .iter()
        .map(|(id, value)| {
            json!(root_from_record(
                domain,
                &json!({"id": id, "record": project(value)})
            ))
        })
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn set_root(domain: &str, set: &BTreeSet<String>) -> String {
    let leaves = set
        .iter()
        .map(|value| {
            json!(domain_hash(
                domain,
                &[HashPart::Str(CHAIN_ID), HashPart::Str(value)],
                32
            ))
        })
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn vec_root(domain: &str, values: &[Value]) -> String {
    let leaves = values
        .iter()
        .map(|value| json!(root_from_record(domain, value)))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}
