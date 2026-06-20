use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2PqConfidentialOptionsExerciseSettlementRuntimeResult<T> = Result<T, String>;
pub type Runtime = State;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_OPTIONS_EXERCISE_SETTLEMENT_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-confidential-options-exercise-settlement-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_OPTIONS_EXERCISE_SETTLEMENT_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_AUTH_SUITE: &str = "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f";
pub const TICKET_SUITE: &str = "sealed-confidential-options-exercise-ticket-root-v1";
pub const MARGIN_LOCK_SUITE: &str = "confidential-options-exercise-margin-lock-root-v1";
pub const ORACLE_ATTESTATION_SUITE: &str =
    "pq-confidential-options-exercise-oracle-attestation-root-v1";
pub const KEEPER_ATTESTATION_SUITE: &str =
    "pq-confidential-options-exercise-keeper-attestation-root-v1";
pub const BATCH_SETTLEMENT_SUITE: &str =
    "low-fee-confidential-options-exercise-batch-settlement-root-v1";
pub const REBATE_SUITE: &str = "low-fee-confidential-options-exercise-rebate-root-v1";
pub const REDACTION_SUITE: &str = "privacy-redaction-budget-root-v1";
pub const QUARANTINE_SUITE: &str = "confidential-options-exercise-failure-quarantine-root-v1";
pub const PUBLIC_RECORD_SUITE: &str =
    "roots-only-confidential-options-exercise-settlement-public-record-v1";
pub const DEVNET_L2_HEIGHT: u64 = 2_144_000;
pub const DEVNET_MONERO_HEIGHT: u64 = 3_740_000;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_BATCH_PRIVACY_SET_SIZE: u64 = 262_144;
pub const DEFAULT_MAX_EXERCISE_BATCH_ITEMS: usize = 4_096;
pub const DEFAULT_MAX_REDACTION_UNITS_PER_EPOCH: u64 = 25_000;
pub const DEFAULT_LOW_FEE_TARGET_BPS: u64 = 9;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 18;
pub const DEFAULT_ORACLE_QUORUM: u16 = 3;
pub const DEFAULT_KEEPER_QUORUM: u16 = 2;
pub const DEFAULT_ATTESTATION_TTL_BLOCKS: u64 = 18;
pub const DEFAULT_SETTLEMENT_TTL_BLOCKS: u64 = 12;
pub const DEFAULT_MARGIN_LOCK_TTL_BLOCKS: u64 = 48;
pub const DEFAULT_QUARANTINE_TTL_BLOCKS: u64 = 144;
pub const DEFAULT_REBATE_POOL_MICRO_UNITS: u64 = 8_000_000_000;
pub const DEFAULT_MIN_MARGIN_RATIO_BPS: u64 = 12_500;
pub const DEFAULT_MAX_ORACLE_DEVIATION_BPS: u64 = 250;
pub const DEFAULT_SETTLEMENT_PRICE_SCALE: u64 = 1_000_000;
pub const MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OptionKind {
    Call,
    Put,
    BinaryCall,
    BinaryPut,
    BarrierCall,
    BarrierPut,
}

impl OptionKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Call => "call",
            Self::Put => "put",
            Self::BinaryCall => "binary_call",
            Self::BinaryPut => "binary_put",
            Self::BarrierCall => "barrier_call",
            Self::BarrierPut => "barrier_put",
        }
    }

    pub fn is_call(self) -> bool {
        matches!(self, Self::Call | Self::BinaryCall | Self::BarrierCall)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TicketStatus {
    Sealed,
    MarginLocked,
    OracleAttested,
    KeeperAttested,
    BatchQueued,
    Settled,
    RebateIssued,
    Quarantined,
    Expired,
    Rejected,
}

impl TicketStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sealed => "sealed",
            Self::MarginLocked => "margin_locked",
            Self::OracleAttested => "oracle_attested",
            Self::KeeperAttested => "keeper_attested",
            Self::BatchQueued => "batch_queued",
            Self::Settled => "settled",
            Self::RebateIssued => "rebate_issued",
            Self::Quarantined => "quarantined",
            Self::Expired => "expired",
            Self::Rejected => "rejected",
        }
    }

    pub fn accepts_attestation(self) -> bool {
        matches!(
            self,
            Self::Sealed | Self::MarginLocked | Self::OracleAttested | Self::KeeperAttested
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MarginLockStatus {
    Reserved,
    PartiallyReleased,
    Released,
    Slashed,
    Expired,
}

impl MarginLockStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::PartiallyReleased => "partially_released",
            Self::Released => "released",
            Self::Slashed => "slashed",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationRole {
    Oracle,
    Keeper,
}

impl AttestationRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Oracle => "oracle",
            Self::Keeper => "keeper",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationVerdict {
    Accept,
    Reject,
    NeedsReview,
}

impl AttestationVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Accept => "accept",
            Self::Reject => "reject",
            Self::NeedsReview => "needs_review",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementStatus {
    Open,
    Ready,
    Settling,
    Settled,
    PartiallySettled,
    Quarantined,
    Rejected,
}

impl SettlementStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Ready => "ready",
            Self::Settling => "settling",
            Self::Settled => "settled",
            Self::PartiallySettled => "partially_settled",
            Self::Quarantined => "quarantined",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QuarantineReason {
    MissingMargin,
    OracleDisagreement,
    KeeperDisagreement,
    ExpiredTicket,
    RedactionBudgetExceeded,
    DuplicateNullifier,
    SettlementInvariantFailed,
    FeeLimitExceeded,
}

impl QuarantineReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MissingMargin => "missing_margin",
            Self::OracleDisagreement => "oracle_disagreement",
            Self::KeeperDisagreement => "keeper_disagreement",
            Self::ExpiredTicket => "expired_ticket",
            Self::RedactionBudgetExceeded => "redaction_budget_exceeded",
            Self::DuplicateNullifier => "duplicate_nullifier",
            Self::SettlementInvariantFailed => "settlement_invariant_failed",
            Self::FeeLimitExceeded => "fee_limit_exceeded",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub protocol_version: String,
    pub schema_version: u64,
    pub chain_id: String,
    pub l2_height: u64,
    pub monero_height: u64,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub batch_privacy_set_size: u64,
    pub max_exercise_batch_items: usize,
    pub max_redaction_units_per_epoch: u64,
    pub low_fee_target_bps: u64,
    pub max_user_fee_bps: u64,
    pub oracle_quorum: u16,
    pub keeper_quorum: u16,
    pub attestation_ttl_blocks: u64,
    pub settlement_ttl_blocks: u64,
    pub margin_lock_ttl_blocks: u64,
    pub quarantine_ttl_blocks: u64,
    pub rebate_pool_micro_units: u64,
    pub min_margin_ratio_bps: u64,
    pub max_oracle_deviation_bps: u64,
    pub settlement_price_scale: u64,
    pub default_fee_asset_id: String,
    pub default_collateral_asset_id: String,
    pub replay_domain: String,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            chain_id: CHAIN_ID.to_string(),
            l2_height: DEVNET_L2_HEIGHT,
            monero_height: DEVNET_MONERO_HEIGHT,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            batch_privacy_set_size: DEFAULT_BATCH_PRIVACY_SET_SIZE,
            max_exercise_batch_items: DEFAULT_MAX_EXERCISE_BATCH_ITEMS,
            max_redaction_units_per_epoch: DEFAULT_MAX_REDACTION_UNITS_PER_EPOCH,
            low_fee_target_bps: DEFAULT_LOW_FEE_TARGET_BPS,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            oracle_quorum: DEFAULT_ORACLE_QUORUM,
            keeper_quorum: DEFAULT_KEEPER_QUORUM,
            attestation_ttl_blocks: DEFAULT_ATTESTATION_TTL_BLOCKS,
            settlement_ttl_blocks: DEFAULT_SETTLEMENT_TTL_BLOCKS,
            margin_lock_ttl_blocks: DEFAULT_MARGIN_LOCK_TTL_BLOCKS,
            quarantine_ttl_blocks: DEFAULT_QUARANTINE_TTL_BLOCKS,
            rebate_pool_micro_units: DEFAULT_REBATE_POOL_MICRO_UNITS,
            min_margin_ratio_bps: DEFAULT_MIN_MARGIN_RATIO_BPS,
            max_oracle_deviation_bps: DEFAULT_MAX_ORACLE_DEVIATION_BPS,
            settlement_price_scale: DEFAULT_SETTLEMENT_PRICE_SCALE,
            default_fee_asset_id: "piconero-devnet".to_string(),
            default_collateral_asset_id: "private-dusd-devnet".to_string(),
            replay_domain: "nebula-private-l2-pq-confidential-options-exercise-devnet".to_string(),
        }
    }

    pub fn validate(&self) -> PrivateL2PqConfidentialOptionsExerciseSettlementRuntimeResult<()> {
        if self.protocol_version != PROTOCOL_VERSION {
            return Err("invalid protocol version".to_string());
        }
        if self.schema_version != SCHEMA_VERSION {
            return Err("invalid schema version".to_string());
        }
        if self.min_pq_security_bits < DEFAULT_MIN_PQ_SECURITY_BITS {
            return Err("pq security bits below generated floor".to_string());
        }
        if self.min_privacy_set_size == 0 || self.batch_privacy_set_size < self.min_privacy_set_size
        {
            return Err("invalid privacy set size".to_string());
        }
        if self.max_exercise_batch_items == 0 {
            return Err("batch item limit must be positive".to_string());
        }
        if self.low_fee_target_bps > self.max_user_fee_bps || self.max_user_fee_bps > MAX_BPS {
            return Err("invalid fee bps envelope".to_string());
        }
        if self.oracle_quorum == 0 || self.keeper_quorum == 0 {
            return Err("attestation quorum must be positive".to_string());
        }
        if self.min_margin_ratio_bps < MAX_BPS {
            return Err("margin ratio must cover notional".to_string());
        }
        if self.settlement_price_scale == 0 {
            return Err("settlement price scale must be positive".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub sealed_tickets: u64,
    pub margin_locks: u64,
    pub oracle_attestations: u64,
    pub keeper_attestations: u64,
    pub batch_settlements: u64,
    pub settled_tickets: u64,
    pub rebate_coupons: u64,
    pub redaction_spends: u64,
    pub quarantine_cases: u64,
    pub deterministic_records: u64,
    pub rejected_requests: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "sealed_tickets": self.sealed_tickets,
            "margin_locks": self.margin_locks,
            "oracle_attestations": self.oracle_attestations,
            "keeper_attestations": self.keeper_attestations,
            "batch_settlements": self.batch_settlements,
            "settled_tickets": self.settled_tickets,
            "rebate_coupons": self.rebate_coupons,
            "redaction_spends": self.redaction_spends,
            "quarantine_cases": self.quarantine_cases,
            "deterministic_records": self.deterministic_records,
            "rejected_requests": self.rejected_requests,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub tickets_root: String,
    pub margin_locks_root: String,
    pub oracle_attestations_root: String,
    pub keeper_attestations_root: String,
    pub batch_settlements_root: String,
    pub rebates_root: String,
    pub redaction_budgets_root: String,
    pub quarantine_root: String,
    pub nullifier_root: String,
    pub public_records_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "tickets_root": self.tickets_root,
            "margin_locks_root": self.margin_locks_root,
            "oracle_attestations_root": self.oracle_attestations_root,
            "keeper_attestations_root": self.keeper_attestations_root,
            "batch_settlements_root": self.batch_settlements_root,
            "rebates_root": self.rebates_root,
            "redaction_budgets_root": self.redaction_budgets_root,
            "quarantine_root": self.quarantine_root,
            "nullifier_root": self.nullifier_root,
            "public_records_root": self.public_records_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SealedExerciseTicket {
    pub ticket_id: String,
    pub vault_id: String,
    pub option_note_id: String,
    pub owner_commitment: String,
    pub counterparty_commitment: String,
    pub nullifier: String,
    pub option_kind: OptionKind,
    pub quantity: u64,
    pub strike_price: u64,
    pub expiry_l2_height: u64,
    pub encrypted_exercise_payload_root: String,
    pub sealed_ticket_root: String,
    pub pq_authorization_root: String,
    pub privacy_set_size: u64,
    pub requested_fee_bps: u64,
    pub redaction_units_reserved: u64,
    pub status: TicketStatus,
}

impl SealedExerciseTicket {
    pub fn public_record(&self) -> Value {
        json!({
            "ticket_id": self.ticket_id,
            "vault_id": self.vault_id,
            "option_note_id": self.option_note_id,
            "owner_commitment": self.owner_commitment,
            "counterparty_commitment": self.counterparty_commitment,
            "nullifier": self.nullifier,
            "option_kind": self.option_kind.as_str(),
            "quantity": self.quantity,
            "strike_price": self.strike_price,
            "expiry_l2_height": self.expiry_l2_height,
            "encrypted_exercise_payload_root": self.encrypted_exercise_payload_root,
            "sealed_ticket_root": self.sealed_ticket_root,
            "pq_authorization_root": self.pq_authorization_root,
            "privacy_set_size": self.privacy_set_size,
            "requested_fee_bps": self.requested_fee_bps,
            "redaction_units_reserved": self.redaction_units_reserved,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MarginLock {
    pub lock_id: String,
    pub ticket_id: String,
    pub account_commitment: String,
    pub collateral_asset_id: String,
    pub notional_micro_units: u64,
    pub locked_micro_units: u64,
    pub required_margin_bps: u64,
    pub locked_at_l2_height: u64,
    pub expires_at_l2_height: u64,
    pub lock_proof_root: String,
    pub release_commitment_root: String,
    pub status: MarginLockStatus,
}

impl MarginLock {
    pub fn public_record(&self) -> Value {
        json!({
            "lock_id": self.lock_id,
            "ticket_id": self.ticket_id,
            "account_commitment": self.account_commitment,
            "collateral_asset_id": self.collateral_asset_id,
            "notional_micro_units": self.notional_micro_units,
            "locked_micro_units": self.locked_micro_units,
            "required_margin_bps": self.required_margin_bps,
            "locked_at_l2_height": self.locked_at_l2_height,
            "expires_at_l2_height": self.expires_at_l2_height,
            "lock_proof_root": self.lock_proof_root,
            "release_commitment_root": self.release_commitment_root,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqAttestation {
    pub attestation_id: String,
    pub ticket_id: String,
    pub role: AttestationRole,
    pub attestor_commitment: String,
    pub price_micro_units: u64,
    pub volatility_bps: u64,
    pub l2_height: u64,
    pub expires_at_l2_height: u64,
    pub pq_signature_root: String,
    pub transcript_root: String,
    pub verdict: AttestationVerdict,
}

impl PqAttestation {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "ticket_id": self.ticket_id,
            "role": self.role.as_str(),
            "attestor_commitment": self.attestor_commitment,
            "price_micro_units": self.price_micro_units,
            "volatility_bps": self.volatility_bps,
            "l2_height": self.l2_height,
            "expires_at_l2_height": self.expires_at_l2_height,
            "pq_signature_root": self.pq_signature_root,
            "transcript_root": self.transcript_root,
            "verdict": self.verdict.as_str(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BatchExerciseSettlement {
    pub batch_id: String,
    pub ticket_ids: Vec<String>,
    pub keeper_committee_root: String,
    pub oracle_price_root: String,
    pub settlement_proof_root: String,
    pub gross_payout_micro_units: u64,
    pub fee_micro_units: u64,
    pub rebate_micro_units: u64,
    pub redaction_units_spent: u64,
    pub opened_at_l2_height: u64,
    pub settled_at_l2_height: u64,
    pub status: SettlementStatus,
}

impl BatchExerciseSettlement {
    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "ticket_ids": self.ticket_ids,
            "keeper_committee_root": self.keeper_committee_root,
            "oracle_price_root": self.oracle_price_root,
            "settlement_proof_root": self.settlement_proof_root,
            "gross_payout_micro_units": self.gross_payout_micro_units,
            "fee_micro_units": self.fee_micro_units,
            "rebate_micro_units": self.rebate_micro_units,
            "redaction_units_spent": self.redaction_units_spent,
            "opened_at_l2_height": self.opened_at_l2_height,
            "settled_at_l2_height": self.settled_at_l2_height,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LowFeeRebate {
    pub rebate_id: String,
    pub ticket_id: String,
    pub batch_id: String,
    pub recipient_commitment: String,
    pub fee_asset_id: String,
    pub charged_fee_bps: u64,
    pub target_fee_bps: u64,
    pub rebate_micro_units: u64,
    pub coupon_root: String,
    pub claimed: bool,
}

impl LowFeeRebate {
    pub fn public_record(&self) -> Value {
        json!({
            "rebate_id": self.rebate_id,
            "ticket_id": self.ticket_id,
            "batch_id": self.batch_id,
            "recipient_commitment": self.recipient_commitment,
            "fee_asset_id": self.fee_asset_id,
            "charged_fee_bps": self.charged_fee_bps,
            "target_fee_bps": self.target_fee_bps,
            "rebate_micro_units": self.rebate_micro_units,
            "coupon_root": self.coupon_root,
            "claimed": self.claimed,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivacyRedactionBudget {
    pub epoch: u64,
    pub budget_id: String,
    pub consumer_commitment: String,
    pub max_units: u64,
    pub reserved_units: u64,
    pub spent_units: u64,
    pub redacted_fields_root: String,
}

impl PrivacyRedactionBudget {
    pub fn available_units(&self) -> u64 {
        self.max_units
            .saturating_sub(self.reserved_units + self.spent_units)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "epoch": self.epoch,
            "budget_id": self.budget_id,
            "consumer_commitment": self.consumer_commitment,
            "max_units": self.max_units,
            "reserved_units": self.reserved_units,
            "spent_units": self.spent_units,
            "redacted_fields_root": self.redacted_fields_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FailureQuarantine {
    pub quarantine_id: String,
    pub ticket_id: String,
    pub batch_id: Option<String>,
    pub reason: QuarantineReason,
    pub evidence_root: String,
    pub opened_at_l2_height: u64,
    pub release_at_l2_height: u64,
    pub review_committee_root: String,
    pub resolved: bool,
}

impl FailureQuarantine {
    pub fn public_record(&self) -> Value {
        json!({
            "quarantine_id": self.quarantine_id,
            "ticket_id": self.ticket_id,
            "batch_id": self.batch_id,
            "reason": self.reason.as_str(),
            "evidence_root": self.evidence_root,
            "opened_at_l2_height": self.opened_at_l2_height,
            "release_at_l2_height": self.release_at_l2_height,
            "review_committee_root": self.review_committee_root,
            "resolved": self.resolved,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DeterministicPublicRecord {
    pub record_id: String,
    pub subject_id: String,
    pub record_kind: String,
    pub public_payload: Value,
    pub payload_root: String,
    pub emitted_at_l2_height: u64,
}

impl DeterministicPublicRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "record_id": self.record_id,
            "subject_id": self.subject_id,
            "record_kind": self.record_kind,
            "public_payload": self.public_payload,
            "payload_root": self.payload_root,
            "emitted_at_l2_height": self.emitted_at_l2_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SealedExerciseTicketRequest {
    pub vault_id: String,
    pub option_note_id: String,
    pub owner_commitment: String,
    pub counterparty_commitment: String,
    pub nullifier: String,
    pub option_kind: OptionKind,
    pub quantity: u64,
    pub strike_price: u64,
    pub expiry_l2_height: u64,
    pub encrypted_exercise_payload_root: String,
    pub pq_authorization_root: String,
    pub privacy_set_size: u64,
    pub requested_fee_bps: u64,
    pub redaction_units_reserved: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MarginLockRequest {
    pub ticket_id: String,
    pub account_commitment: String,
    pub collateral_asset_id: String,
    pub mark_price_micro_units: u64,
    pub locked_micro_units: u64,
    pub lock_proof_root: String,
    pub release_commitment_root: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqAttestationRequest {
    pub ticket_id: String,
    pub role: AttestationRole,
    pub attestor_commitment: String,
    pub price_micro_units: u64,
    pub volatility_bps: u64,
    pub pq_signature_root: String,
    pub transcript_root: String,
    pub verdict: AttestationVerdict,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BatchSettlementRequest {
    pub ticket_ids: Vec<String>,
    pub keeper_committee_root: String,
    pub oracle_price_root: String,
    pub settlement_proof_root: String,
    pub redaction_units_spent: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub tickets: BTreeMap<String, SealedExerciseTicket>,
    pub margin_locks: BTreeMap<String, MarginLock>,
    pub oracle_attestations: BTreeMap<String, PqAttestation>,
    pub keeper_attestations: BTreeMap<String, PqAttestation>,
    pub batches: BTreeMap<String, BatchExerciseSettlement>,
    pub rebates: BTreeMap<String, LowFeeRebate>,
    pub redaction_budgets: BTreeMap<String, PrivacyRedactionBudget>,
    pub quarantines: BTreeMap<String, FailureQuarantine>,
    pub public_records: BTreeMap<String, DeterministicPublicRecord>,
    pub consumed_nullifiers: BTreeSet<String>,
}

impl State {
    pub fn new(
        config: Config,
    ) -> PrivateL2PqConfidentialOptionsExerciseSettlementRuntimeResult<Self> {
        config.validate()?;
        let mut state = Self {
            config,
            counters: Counters::default(),
            roots: Roots::default(),
            tickets: BTreeMap::new(),
            margin_locks: BTreeMap::new(),
            oracle_attestations: BTreeMap::new(),
            keeper_attestations: BTreeMap::new(),
            batches: BTreeMap::new(),
            rebates: BTreeMap::new(),
            redaction_budgets: BTreeMap::new(),
            quarantines: BTreeMap::new(),
            public_records: BTreeMap::new(),
            consumed_nullifiers: BTreeSet::new(),
        };
        state.recompute_roots();
        Ok(state)
    }

    pub fn devnet() -> Self {
        Self::new(Config::devnet()).expect("valid devnet exercise settlement runtime")
    }

    pub fn seed_redaction_budget(
        &mut self,
        epoch: u64,
        consumer_commitment: impl Into<String>,
        max_units: u64,
    ) -> String {
        let consumer_commitment = consumer_commitment.into();
        let budget_id = deterministic_id(
            "budget",
            &[
                HashPart::U64(epoch),
                HashPart::Str(&consumer_commitment),
                HashPart::U64(max_units),
            ],
        );
        let redacted_fields_root = domain_hash(
            REDACTION_SUITE,
            &[
                HashPart::Str("seed"),
                HashPart::U64(epoch),
                HashPart::Str(&consumer_commitment),
            ],
            32,
        );
        let budget = PrivacyRedactionBudget {
            epoch,
            budget_id: budget_id.clone(),
            consumer_commitment,
            max_units,
            reserved_units: 0,
            spent_units: 0,
            redacted_fields_root,
        };
        self.redaction_budgets.insert(budget_id.clone(), budget);
        self.recompute_roots();
        budget_id
    }

    pub fn seal_exercise_ticket(
        &mut self,
        request: SealedExerciseTicketRequest,
    ) -> PrivateL2PqConfidentialOptionsExerciseSettlementRuntimeResult<String> {
        if request.quantity == 0 {
            self.counters.rejected_requests += 1;
            return Err("exercise quantity must be positive".to_string());
        }
        if request.privacy_set_size < self.config.min_privacy_set_size {
            self.counters.rejected_requests += 1;
            return Err("privacy set below runtime floor".to_string());
        }
        if request.requested_fee_bps > self.config.max_user_fee_bps {
            self.counters.rejected_requests += 1;
            return Err("requested fee exceeds user fee cap".to_string());
        }
        if request.expiry_l2_height < self.config.l2_height {
            self.counters.rejected_requests += 1;
            return Err("exercise ticket already expired".to_string());
        }
        if self.consumed_nullifiers.contains(&request.nullifier) {
            self.counters.rejected_requests += 1;
            let ticket_id = deterministic_id("duplicate", &[HashPart::Str(&request.nullifier)]);
            self.quarantine_ticket(
                ticket_id,
                None,
                QuarantineReason::DuplicateNullifier,
                request.nullifier,
            );
            return Err("duplicate exercise nullifier".to_string());
        }

        let ticket_id = deterministic_id(
            "ticket",
            &[
                HashPart::Str(&request.vault_id),
                HashPart::Str(&request.option_note_id),
                HashPart::Str(&request.owner_commitment),
                HashPart::Str(&request.nullifier),
            ],
        );
        let sealed_ticket_root = domain_hash(
            TICKET_SUITE,
            &[
                HashPart::Str(&ticket_id),
                HashPart::Str(&request.encrypted_exercise_payload_root),
                HashPart::Str(&request.pq_authorization_root),
            ],
            32,
        );
        let ticket = SealedExerciseTicket {
            ticket_id: ticket_id.clone(),
            vault_id: request.vault_id,
            option_note_id: request.option_note_id,
            owner_commitment: request.owner_commitment,
            counterparty_commitment: request.counterparty_commitment,
            nullifier: request.nullifier.clone(),
            option_kind: request.option_kind,
            quantity: request.quantity,
            strike_price: request.strike_price,
            expiry_l2_height: request.expiry_l2_height,
            encrypted_exercise_payload_root: request.encrypted_exercise_payload_root,
            sealed_ticket_root,
            pq_authorization_root: request.pq_authorization_root,
            privacy_set_size: request.privacy_set_size,
            requested_fee_bps: request.requested_fee_bps,
            redaction_units_reserved: request.redaction_units_reserved,
            status: TicketStatus::Sealed,
        };
        self.consumed_nullifiers.insert(request.nullifier);
        self.tickets.insert(ticket_id.clone(), ticket);
        self.counters.sealed_tickets += 1;
        self.emit_record(&ticket_id, "sealed_exercise_ticket");
        self.recompute_roots();
        Ok(ticket_id)
    }

    pub fn lock_margin(
        &mut self,
        request: MarginLockRequest,
    ) -> PrivateL2PqConfidentialOptionsExerciseSettlementRuntimeResult<String> {
        let ticket = self
            .tickets
            .get(&request.ticket_id)
            .ok_or_else(|| "unknown ticket".to_string())?
            .clone();
        if ticket.status == TicketStatus::Quarantined {
            self.counters.rejected_requests += 1;
            return Err("ticket is quarantined".to_string());
        }
        let notional = option_intrinsic_value(&ticket, request.mark_price_micro_units)
            .saturating_mul(ticket.quantity);
        let required = notional
            .saturating_mul(self.config.min_margin_ratio_bps)
            .saturating_add(MAX_BPS - 1)
            / MAX_BPS;
        if request.locked_micro_units < required {
            self.counters.rejected_requests += 1;
            self.quarantine_ticket(
                ticket.ticket_id,
                None,
                QuarantineReason::MissingMargin,
                request.lock_proof_root,
            );
            return Err("insufficient confidential margin lock".to_string());
        }
        let lock_id = deterministic_id(
            "margin-lock",
            &[
                HashPart::Str(&request.ticket_id),
                HashPart::Str(&request.account_commitment),
                HashPart::U64(request.locked_micro_units),
            ],
        );
        let lock = MarginLock {
            lock_id: lock_id.clone(),
            ticket_id: request.ticket_id.clone(),
            account_commitment: request.account_commitment,
            collateral_asset_id: request.collateral_asset_id,
            notional_micro_units: notional,
            locked_micro_units: request.locked_micro_units,
            required_margin_bps: self.config.min_margin_ratio_bps,
            locked_at_l2_height: self.config.l2_height,
            expires_at_l2_height: self.config.l2_height + self.config.margin_lock_ttl_blocks,
            lock_proof_root: request.lock_proof_root,
            release_commitment_root: request.release_commitment_root,
            status: MarginLockStatus::Reserved,
        };
        self.margin_locks.insert(lock_id.clone(), lock);
        if let Some(ticket) = self.tickets.get_mut(&request.ticket_id) {
            ticket.status = TicketStatus::MarginLocked;
        }
        self.counters.margin_locks += 1;
        self.emit_record(&request.ticket_id, "margin_lock");
        self.recompute_roots();
        Ok(lock_id)
    }

    pub fn attest(
        &mut self,
        request: PqAttestationRequest,
    ) -> PrivateL2PqConfidentialOptionsExerciseSettlementRuntimeResult<String> {
        let status = self
            .tickets
            .get(&request.ticket_id)
            .ok_or_else(|| "unknown ticket".to_string())?
            .status;
        if !status.accepts_attestation() {
            self.counters.rejected_requests += 1;
            return Err("ticket does not accept attestations".to_string());
        }
        let attestation_id = deterministic_id(
            request.role.as_str(),
            &[
                HashPart::Str(&request.ticket_id),
                HashPart::Str(&request.attestor_commitment),
                HashPart::Str(&request.pq_signature_root),
            ],
        );
        let attestation = PqAttestation {
            attestation_id: attestation_id.clone(),
            ticket_id: request.ticket_id.clone(),
            role: request.role,
            attestor_commitment: request.attestor_commitment,
            price_micro_units: request.price_micro_units,
            volatility_bps: request.volatility_bps,
            l2_height: self.config.l2_height,
            expires_at_l2_height: self.config.l2_height + self.config.attestation_ttl_blocks,
            pq_signature_root: request.pq_signature_root,
            transcript_root: request.transcript_root,
            verdict: request.verdict,
        };
        match request.role {
            AttestationRole::Oracle => {
                self.oracle_attestations
                    .insert(attestation_id.clone(), attestation);
                self.counters.oracle_attestations += 1;
            }
            AttestationRole::Keeper => {
                self.keeper_attestations
                    .insert(attestation_id.clone(), attestation);
                self.counters.keeper_attestations += 1;
            }
        }
        self.refresh_ticket_attestation_status(&request.ticket_id);
        self.emit_record(&request.ticket_id, request.role.as_str());
        self.recompute_roots();
        Ok(attestation_id)
    }

    pub fn settle_batch(
        &mut self,
        request: BatchSettlementRequest,
    ) -> PrivateL2PqConfidentialOptionsExerciseSettlementRuntimeResult<String> {
        if request.ticket_ids.is_empty() {
            self.counters.rejected_requests += 1;
            return Err("batch must include tickets".to_string());
        }
        if request.ticket_ids.len() > self.config.max_exercise_batch_items {
            self.counters.rejected_requests += 1;
            return Err("batch exceeds configured item limit".to_string());
        }
        let mut seen = BTreeSet::new();
        let mut gross_payout = 0_u64;
        let mut total_fee = 0_u64;
        let mut total_rebate = 0_u64;
        let mut settled_ids = Vec::with_capacity(request.ticket_ids.len());

        for ticket_id in &request.ticket_ids {
            if !seen.insert(ticket_id.clone()) {
                self.counters.rejected_requests += 1;
                return Err("duplicate ticket in batch".to_string());
            }
            let ticket = self
                .tickets
                .get(ticket_id)
                .ok_or_else(|| format!("unknown ticket {ticket_id}"))?
                .clone();
            self.ensure_ticket_batch_ready(&ticket)?;
            let mark_price = self.consensus_oracle_price(ticket_id)?;
            let payout =
                option_intrinsic_value(&ticket, mark_price).saturating_mul(ticket.quantity);
            let fee = payout.saturating_mul(ticket.requested_fee_bps) / MAX_BPS;
            let rebate = if ticket.requested_fee_bps > self.config.low_fee_target_bps {
                payout.saturating_mul(ticket.requested_fee_bps - self.config.low_fee_target_bps)
                    / MAX_BPS
            } else {
                0
            };
            gross_payout = gross_payout.saturating_add(payout);
            total_fee = total_fee.saturating_add(fee);
            total_rebate = total_rebate.saturating_add(rebate);
            settled_ids.push(ticket_id.clone());
        }

        self.spend_redaction_units(request.redaction_units_spent)?;
        let batch_id = deterministic_id(
            "exercise-batch",
            &[
                HashPart::Str(&request.keeper_committee_root),
                HashPart::Str(&request.oracle_price_root),
                HashPart::Str(&request.settlement_proof_root),
                HashPart::U64(self.counters.batch_settlements + 1),
            ],
        );
        let batch = BatchExerciseSettlement {
            batch_id: batch_id.clone(),
            ticket_ids: settled_ids.clone(),
            keeper_committee_root: request.keeper_committee_root,
            oracle_price_root: request.oracle_price_root,
            settlement_proof_root: request.settlement_proof_root,
            gross_payout_micro_units: gross_payout,
            fee_micro_units: total_fee,
            rebate_micro_units: total_rebate.min(self.config.rebate_pool_micro_units),
            redaction_units_spent: request.redaction_units_spent,
            opened_at_l2_height: self.config.l2_height,
            settled_at_l2_height: self.config.l2_height + self.config.settlement_ttl_blocks,
            status: SettlementStatus::Settled,
        };
        self.batches.insert(batch_id.clone(), batch);
        self.counters.batch_settlements += 1;

        for ticket_id in settled_ids {
            if let Some(ticket) = self.tickets.get_mut(&ticket_id) {
                ticket.status = TicketStatus::Settled;
                self.counters.settled_tickets += 1;
            }
            self.release_margin_for_ticket(&ticket_id);
            self.issue_rebate_for_ticket(&batch_id, &ticket_id);
            self.emit_record(&ticket_id, "exercise_settled");
        }
        self.emit_record(&batch_id, "batch_exercise_settlement");
        self.recompute_roots();
        Ok(batch_id)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.config.protocol_version,
            "schema_version": self.config.schema_version,
            "chain_id": self.config.chain_id,
            "l2_height": self.config.l2_height,
            "monero_height": self.config.monero_height,
            "hash_suite": HASH_SUITE,
            "pq_auth_suite": PQ_AUTH_SUITE,
            "min_pq_security_bits": self.config.min_pq_security_bits,
            "min_privacy_set_size": self.config.min_privacy_set_size,
            "batch_privacy_set_size": self.config.batch_privacy_set_size,
            "max_exercise_batch_items": self.config.max_exercise_batch_items,
            "low_fee_target_bps": self.config.low_fee_target_bps,
            "max_user_fee_bps": self.config.max_user_fee_bps,
            "oracle_quorum": self.config.oracle_quorum,
            "keeper_quorum": self.config.keeper_quorum,
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
        })
    }

    pub fn state_root(&self) -> String {
        self.roots.state_root.clone()
    }

    fn ensure_ticket_batch_ready(
        &mut self,
        ticket: &SealedExerciseTicket,
    ) -> PrivateL2PqConfidentialOptionsExerciseSettlementRuntimeResult<()> {
        if ticket.expiry_l2_height < self.config.l2_height {
            self.quarantine_ticket(
                ticket.ticket_id.clone(),
                None,
                QuarantineReason::ExpiredTicket,
                ticket.sealed_ticket_root.clone(),
            );
            return Err("ticket expired before settlement".to_string());
        }
        if ticket.status != TicketStatus::OracleAttested
            && ticket.status != TicketStatus::KeeperAttested
            && ticket.status != TicketStatus::BatchQueued
        {
            self.quarantine_ticket(
                ticket.ticket_id.clone(),
                None,
                QuarantineReason::SettlementInvariantFailed,
                ticket.sealed_ticket_root.clone(),
            );
            return Err("ticket lacks ready status".to_string());
        }
        if accepted_attestations(
            &self.oracle_attestations,
            &ticket.ticket_id,
            self.config.l2_height,
        ) < self.config.oracle_quorum as usize
        {
            self.quarantine_ticket(
                ticket.ticket_id.clone(),
                None,
                QuarantineReason::OracleDisagreement,
                ticket.sealed_ticket_root.clone(),
            );
            return Err("oracle quorum missing".to_string());
        }
        if accepted_attestations(
            &self.keeper_attestations,
            &ticket.ticket_id,
            self.config.l2_height,
        ) < self.config.keeper_quorum as usize
        {
            self.quarantine_ticket(
                ticket.ticket_id.clone(),
                None,
                QuarantineReason::KeeperDisagreement,
                ticket.sealed_ticket_root.clone(),
            );
            return Err("keeper quorum missing".to_string());
        }
        Ok(())
    }

    fn consensus_oracle_price(
        &self,
        ticket_id: &str,
    ) -> PrivateL2PqConfidentialOptionsExerciseSettlementRuntimeResult<u64> {
        let prices = self
            .oracle_attestations
            .values()
            .filter(|attestation| {
                attestation.ticket_id == ticket_id
                    && attestation.verdict == AttestationVerdict::Accept
                    && attestation.expires_at_l2_height >= self.config.l2_height
            })
            .map(|attestation| attestation.price_micro_units)
            .collect::<Vec<_>>();
        if prices.is_empty() {
            return Err("missing oracle price".to_string());
        }
        let min = prices.iter().copied().min().unwrap_or(0);
        let max = prices.iter().copied().max().unwrap_or(0);
        if min > 0
            && max.saturating_sub(min).saturating_mul(MAX_BPS) / min
                > self.config.max_oracle_deviation_bps
        {
            return Err("oracle price deviation exceeds cap".to_string());
        }
        Ok(prices.iter().sum::<u64>() / prices.len() as u64)
    }

    fn refresh_ticket_attestation_status(&mut self, ticket_id: &str) {
        let oracle_count =
            accepted_attestations(&self.oracle_attestations, ticket_id, self.config.l2_height);
        let keeper_count =
            accepted_attestations(&self.keeper_attestations, ticket_id, self.config.l2_height);
        if let Some(ticket) = self.tickets.get_mut(ticket_id) {
            if oracle_count >= self.config.oracle_quorum as usize
                && keeper_count >= self.config.keeper_quorum as usize
            {
                ticket.status = TicketStatus::BatchQueued;
            } else if oracle_count >= self.config.oracle_quorum as usize {
                ticket.status = TicketStatus::OracleAttested;
            } else if keeper_count >= self.config.keeper_quorum as usize {
                ticket.status = TicketStatus::KeeperAttested;
            }
        }
    }

    fn spend_redaction_units(
        &mut self,
        units: u64,
    ) -> PrivateL2PqConfidentialOptionsExerciseSettlementRuntimeResult<()> {
        let total_available = self
            .redaction_budgets
            .values()
            .map(PrivacyRedactionBudget::available_units)
            .sum::<u64>();
        if units > total_available {
            self.counters.rejected_requests += 1;
            return Err("redaction budget exceeded".to_string());
        }
        let mut remaining = units;
        for budget in self.redaction_budgets.values_mut() {
            if remaining == 0 {
                break;
            }
            let spend = remaining.min(budget.available_units());
            budget.spent_units += spend;
            remaining -= spend;
        }
        self.counters.redaction_spends += 1;
        Ok(())
    }

    fn release_margin_for_ticket(&mut self, ticket_id: &str) {
        for lock in self.margin_locks.values_mut() {
            if lock.ticket_id == ticket_id && lock.status == MarginLockStatus::Reserved {
                lock.status = MarginLockStatus::Released;
            }
        }
    }

    fn issue_rebate_for_ticket(&mut self, batch_id: &str, ticket_id: &str) {
        let Some(ticket) = self.tickets.get(ticket_id).cloned() else {
            return;
        };
        if ticket.requested_fee_bps <= self.config.low_fee_target_bps {
            return;
        }
        let rebate_id = deterministic_id(
            "rebate",
            &[
                HashPart::Str(batch_id),
                HashPart::Str(ticket_id),
                HashPart::Str(&ticket.owner_commitment),
            ],
        );
        let coupon_root = domain_hash(
            REBATE_SUITE,
            &[
                HashPart::Str(&rebate_id),
                HashPart::Str(&ticket.owner_commitment),
                HashPart::U64(ticket.requested_fee_bps),
            ],
            32,
        );
        let rebate = LowFeeRebate {
            rebate_id: rebate_id.clone(),
            ticket_id: ticket_id.to_string(),
            batch_id: batch_id.to_string(),
            recipient_commitment: ticket.owner_commitment,
            fee_asset_id: self.config.default_fee_asset_id.clone(),
            charged_fee_bps: ticket.requested_fee_bps,
            target_fee_bps: self.config.low_fee_target_bps,
            rebate_micro_units: ticket
                .quantity
                .saturating_mul(ticket.requested_fee_bps - self.config.low_fee_target_bps),
            coupon_root,
            claimed: false,
        };
        self.rebates.insert(rebate_id, rebate);
        self.counters.rebate_coupons += 1;
        if let Some(ticket) = self.tickets.get_mut(ticket_id) {
            ticket.status = TicketStatus::RebateIssued;
        }
    }

    fn quarantine_ticket(
        &mut self,
        ticket_id: String,
        batch_id: Option<String>,
        reason: QuarantineReason,
        evidence_root: String,
    ) {
        let quarantine_id = deterministic_id(
            "quarantine",
            &[
                HashPart::Str(&ticket_id),
                HashPart::Str(reason.as_str()),
                HashPart::Str(&evidence_root),
            ],
        );
        let review_committee_root = domain_hash(
            QUARANTINE_SUITE,
            &[
                HashPart::Str("review-committee"),
                HashPart::Str(&ticket_id),
                HashPart::U64(self.config.l2_height),
            ],
            32,
        );
        let quarantine = FailureQuarantine {
            quarantine_id: quarantine_id.clone(),
            ticket_id: ticket_id.clone(),
            batch_id,
            reason,
            evidence_root,
            opened_at_l2_height: self.config.l2_height,
            release_at_l2_height: self.config.l2_height + self.config.quarantine_ttl_blocks,
            review_committee_root,
            resolved: false,
        };
        self.quarantines.insert(quarantine_id, quarantine);
        self.counters.quarantine_cases += 1;
        if let Some(ticket) = self.tickets.get_mut(&ticket_id) {
            ticket.status = TicketStatus::Quarantined;
        }
        self.recompute_roots();
    }

    fn emit_record(&mut self, subject_id: &str, record_kind: &str) {
        let public_payload = match record_kind {
            "sealed_exercise_ticket" | "margin_lock" | "oracle" | "keeper" | "exercise_settled" => {
                self.tickets
                    .get(subject_id)
                    .map(SealedExerciseTicket::public_record)
                    .unwrap_or_else(|| json!({ "subject_id": subject_id }))
            }
            "batch_exercise_settlement" => self
                .batches
                .get(subject_id)
                .map(BatchExerciseSettlement::public_record)
                .unwrap_or_else(|| json!({ "subject_id": subject_id })),
            _ => json!({ "subject_id": subject_id }),
        };
        let payload_root = domain_hash(
            PUBLIC_RECORD_SUITE,
            &[HashPart::Str(record_kind), HashPart::Json(&public_payload)],
            32,
        );
        let record_id = deterministic_id(
            "record",
            &[
                HashPart::Str(subject_id),
                HashPart::Str(record_kind),
                HashPart::Str(&payload_root),
            ],
        );
        let record = DeterministicPublicRecord {
            record_id: record_id.clone(),
            subject_id: subject_id.to_string(),
            record_kind: record_kind.to_string(),
            public_payload,
            payload_root,
            emitted_at_l2_height: self.config.l2_height,
        };
        self.public_records.insert(record_id, record);
        self.counters.deterministic_records += 1;
    }

    fn recompute_roots(&mut self) {
        self.roots.tickets_root = merkle_root(
            TICKET_SUITE,
            &self
                .tickets
                .values()
                .map(SealedExerciseTicket::public_record)
                .collect::<Vec<_>>(),
        );
        self.roots.margin_locks_root = merkle_root(
            MARGIN_LOCK_SUITE,
            &self
                .margin_locks
                .values()
                .map(MarginLock::public_record)
                .collect::<Vec<_>>(),
        );
        self.roots.oracle_attestations_root = merkle_root(
            ORACLE_ATTESTATION_SUITE,
            &self
                .oracle_attestations
                .values()
                .map(PqAttestation::public_record)
                .collect::<Vec<_>>(),
        );
        self.roots.keeper_attestations_root = merkle_root(
            KEEPER_ATTESTATION_SUITE,
            &self
                .keeper_attestations
                .values()
                .map(PqAttestation::public_record)
                .collect::<Vec<_>>(),
        );
        self.roots.batch_settlements_root = merkle_root(
            BATCH_SETTLEMENT_SUITE,
            &self
                .batches
                .values()
                .map(BatchExerciseSettlement::public_record)
                .collect::<Vec<_>>(),
        );
        self.roots.rebates_root = merkle_root(
            REBATE_SUITE,
            &self
                .rebates
                .values()
                .map(LowFeeRebate::public_record)
                .collect::<Vec<_>>(),
        );
        self.roots.redaction_budgets_root = merkle_root(
            REDACTION_SUITE,
            &self
                .redaction_budgets
                .values()
                .map(PrivacyRedactionBudget::public_record)
                .collect::<Vec<_>>(),
        );
        self.roots.quarantine_root = merkle_root(
            QUARANTINE_SUITE,
            &self
                .quarantines
                .values()
                .map(FailureQuarantine::public_record)
                .collect::<Vec<_>>(),
        );
        self.roots.nullifier_root = merkle_root(
            "confidential-options-exercise-nullifier-set-v1",
            &self
                .consumed_nullifiers
                .iter()
                .map(|nullifier| json!({ "nullifier": nullifier }))
                .collect::<Vec<_>>(),
        );
        self.roots.public_records_root = merkle_root(
            PUBLIC_RECORD_SUITE,
            &self
                .public_records
                .values()
                .map(DeterministicPublicRecord::public_record)
                .collect::<Vec<_>>(),
        );
        self.roots.state_root = domain_hash(
            "nebula-private-l2-pq-confidential-options-exercise-settlement-state-root-v1",
            &[
                HashPart::Str(&self.config.protocol_version),
                HashPart::U64(self.config.schema_version),
                HashPart::Str(&self.config.chain_id),
                HashPart::U64(self.config.l2_height),
                HashPart::Str(&self.roots.tickets_root),
                HashPart::Str(&self.roots.margin_locks_root),
                HashPart::Str(&self.roots.oracle_attestations_root),
                HashPart::Str(&self.roots.keeper_attestations_root),
                HashPart::Str(&self.roots.batch_settlements_root),
                HashPart::Str(&self.roots.rebates_root),
                HashPart::Str(&self.roots.redaction_budgets_root),
                HashPart::Str(&self.roots.quarantine_root),
                HashPart::Str(&self.roots.nullifier_root),
                HashPart::Str(&self.roots.public_records_root),
            ],
            32,
        );
    }
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn demo() -> State {
    let mut state = State::devnet();
    state.seed_redaction_budget(
        42,
        "redaction-consumer:options-exercise-settlement:devnet",
        DEFAULT_MAX_REDACTION_UNITS_PER_EPOCH,
    );
    let ticket_id = state
        .seal_exercise_ticket(SealedExerciseTicketRequest {
            vault_id: "vault:covered-call:devnet:0001".to_string(),
            option_note_id: "option-note:sealed:devnet:0001".to_string(),
            owner_commitment: "owner-commitment:9f5c-devnet".to_string(),
            counterparty_commitment: "counterparty-commitment:4c31-devnet".to_string(),
            nullifier: "exercise-nullifier:devnet:0001".to_string(),
            option_kind: OptionKind::Call,
            quantity: 10,
            strike_price: 150_000_000,
            expiry_l2_height: DEVNET_L2_HEIGHT + 72,
            encrypted_exercise_payload_root: "enc-exercise-payload-root:devnet:0001".to_string(),
            pq_authorization_root: "pq-auth-root:ml-dsa-87:devnet:0001".to_string(),
            privacy_set_size: DEFAULT_BATCH_PRIVACY_SET_SIZE,
            requested_fee_bps: 14,
            redaction_units_reserved: 96,
        })
        .expect("demo ticket");
    state
        .lock_margin(MarginLockRequest {
            ticket_id: ticket_id.clone(),
            account_commitment: "owner-commitment:9f5c-devnet".to_string(),
            collateral_asset_id: state.config.default_collateral_asset_id.clone(),
            mark_price_micro_units: 188_000_000,
            locked_micro_units: 500_000_000,
            lock_proof_root: "margin-lock-proof-root:devnet:0001".to_string(),
            release_commitment_root: "margin-release-commitment-root:devnet:0001".to_string(),
        })
        .expect("demo margin lock");
    for index in 0..DEFAULT_ORACLE_QUORUM {
        state
            .attest(PqAttestationRequest {
                ticket_id: ticket_id.clone(),
                role: AttestationRole::Oracle,
                attestor_commitment: format!("oracle-attestor:devnet:{index:04}"),
                price_micro_units: 188_000_000 + u64::from(index) * 20_000,
                volatility_bps: 4_200,
                pq_signature_root: format!("oracle-pq-signature-root:devnet:{index:04}"),
                transcript_root: format!("oracle-transcript-root:devnet:{index:04}"),
                verdict: AttestationVerdict::Accept,
            })
            .expect("demo oracle attestation");
    }
    for index in 0..DEFAULT_KEEPER_QUORUM {
        state
            .attest(PqAttestationRequest {
                ticket_id: ticket_id.clone(),
                role: AttestationRole::Keeper,
                attestor_commitment: format!("keeper-attestor:devnet:{index:04}"),
                price_micro_units: 188_010_000,
                volatility_bps: 4_150,
                pq_signature_root: format!("keeper-pq-signature-root:devnet:{index:04}"),
                transcript_root: format!("keeper-transcript-root:devnet:{index:04}"),
                verdict: AttestationVerdict::Accept,
            })
            .expect("demo keeper attestation");
    }
    state
        .settle_batch(BatchSettlementRequest {
            ticket_ids: vec![ticket_id],
            keeper_committee_root: "keeper-committee-root:devnet:exercise:0001".to_string(),
            oracle_price_root: "oracle-price-root:devnet:exercise:0001".to_string(),
            settlement_proof_root: "settlement-proof-root:devnet:exercise:0001".to_string(),
            redaction_units_spent: 128,
        })
        .expect("demo exercise batch settlement");
    state
}

pub fn public_record(state: &State) -> Value {
    state.public_record()
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}

fn accepted_attestations(
    attestations: &BTreeMap<String, PqAttestation>,
    ticket_id: &str,
    l2_height: u64,
) -> usize {
    attestations
        .values()
        .filter(|attestation| {
            attestation.ticket_id == ticket_id
                && attestation.verdict == AttestationVerdict::Accept
                && attestation.expires_at_l2_height >= l2_height
        })
        .count()
}

fn option_intrinsic_value(ticket: &SealedExerciseTicket, mark_price_micro_units: u64) -> u64 {
    match ticket.option_kind {
        OptionKind::Call | OptionKind::BarrierCall => {
            mark_price_micro_units.saturating_sub(ticket.strike_price)
        }
        OptionKind::Put | OptionKind::BarrierPut => {
            ticket.strike_price.saturating_sub(mark_price_micro_units)
        }
        OptionKind::BinaryCall => {
            if mark_price_micro_units > ticket.strike_price {
                ticket.strike_price / 10
            } else {
                0
            }
        }
        OptionKind::BinaryPut => {
            if mark_price_micro_units < ticket.strike_price {
                ticket.strike_price / 10
            } else {
                0
            }
        }
    }
}

fn deterministic_id(domain: &str, parts: &[HashPart<'_>]) -> String {
    format!("{domain}:{}", domain_hash(domain, parts, 16))
}
