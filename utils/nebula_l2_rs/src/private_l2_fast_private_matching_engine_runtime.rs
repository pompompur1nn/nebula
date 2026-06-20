use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2FastPrivateMatchingEngineRuntimeResult<T> = Result<T, String>;

pub const PRIVATE_L2_FAST_PRIVATE_MATCHING_ENGINE_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-fast-private-matching-engine-runtime-v1";
pub const PRIVATE_L2_FAST_PRIVATE_MATCHING_ENGINE_RUNTIME_SCHEMA_VERSION: u64 = 1;
pub const PRIVATE_L2_FAST_PRIVATE_MATCHING_ENGINE_RUNTIME_HASH_SUITE: &str =
    "SHAKE256-domain-separated-canonical-json";
pub const PRIVATE_L2_FAST_PRIVATE_MATCHING_ENGINE_RUNTIME_SEALED_INTENT_SCHEME: &str =
    "ml-kem-1024+zk-sealed-fast-private-defi-intent-v1";
pub const PRIVATE_L2_FAST_PRIVATE_MATCHING_ENGINE_RUNTIME_MATCHING_ROUND_SCHEME: &str =
    "fast-private-defi-solver-matching-round-v1";
pub const PRIVATE_L2_FAST_PRIVATE_MATCHING_ENGINE_RUNTIME_PQ_SOLVER_ATTESTATION_SCHEME: &str =
    "ml-dsa-87+slh-dsa-shake-256s-fast-solver-attestation-v1";
pub const PRIVATE_L2_FAST_PRIVATE_MATCHING_ENGINE_RUNTIME_REBATE_RESERVATION_SCHEME: &str =
    "roots-only-low-fee-fast-matching-rebate-reservation-v1";
pub const PRIVATE_L2_FAST_PRIVATE_MATCHING_ENGINE_RUNTIME_SETTLEMENT_RECEIPT_SCHEME: &str =
    "zk-pq-fast-private-matching-batch-settlement-receipt-v1";
pub const PRIVATE_L2_FAST_PRIVATE_MATCHING_ENGINE_RUNTIME_DEVNET_HEIGHT: u64 = 512_000;
pub const PRIVATE_L2_FAST_PRIVATE_MATCHING_ENGINE_RUNTIME_DEFAULT_MATCHING_WINDOW_BLOCKS: u64 = 3;
pub const PRIVATE_L2_FAST_PRIVATE_MATCHING_ENGINE_RUNTIME_DEFAULT_INTENT_TTL_BLOCKS: u64 = 18;
pub const PRIVATE_L2_FAST_PRIVATE_MATCHING_ENGINE_RUNTIME_DEFAULT_SETTLEMENT_TTL_BLOCKS: u64 = 10;
pub const PRIVATE_L2_FAST_PRIVATE_MATCHING_ENGINE_RUNTIME_DEFAULT_MAX_INTENTS: usize = 4096;
pub const PRIVATE_L2_FAST_PRIVATE_MATCHING_ENGINE_RUNTIME_DEFAULT_MAX_ROUNDS: usize = 1024;
pub const PRIVATE_L2_FAST_PRIVATE_MATCHING_ENGINE_RUNTIME_DEFAULT_MAX_ATTESTATIONS: usize = 4096;
pub const PRIVATE_L2_FAST_PRIVATE_MATCHING_ENGINE_RUNTIME_DEFAULT_MAX_RESERVATIONS: usize = 4096;
pub const PRIVATE_L2_FAST_PRIVATE_MATCHING_ENGINE_RUNTIME_DEFAULT_MAX_BATCHES: usize = 1024;
pub const PRIVATE_L2_FAST_PRIVATE_MATCHING_ENGINE_RUNTIME_DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 192;
pub const PRIVATE_L2_FAST_PRIVATE_MATCHING_ENGINE_RUNTIME_DEFAULT_BATCH_PRIVACY_SET_SIZE: u64 = 512;
pub const PRIVATE_L2_FAST_PRIVATE_MATCHING_ENGINE_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const PRIVATE_L2_FAST_PRIVATE_MATCHING_ENGINE_RUNTIME_DEFAULT_MAX_USER_FEE_BPS: u64 = 18;
pub const PRIVATE_L2_FAST_PRIVATE_MATCHING_ENGINE_RUNTIME_DEFAULT_MAX_SOLVER_FEE_BPS: u64 = 24;
pub const PRIVATE_L2_FAST_PRIVATE_MATCHING_ENGINE_RUNTIME_DEFAULT_MIN_REBATE_BPS: u64 = 3;
pub const PRIVATE_L2_FAST_PRIVATE_MATCHING_ENGINE_RUNTIME_DEFAULT_MAX_REBATE_BPS: u64 = 15;
pub const PRIVATE_L2_FAST_PRIVATE_MATCHING_ENGINE_RUNTIME_DEFAULT_REBATE_BUDGET_MICRO_UNITS: u64 =
    100_000_000;
pub const PRIVATE_L2_FAST_PRIVATE_MATCHING_ENGINE_RUNTIME_MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FastPrivateIntentKind {
    SwapExactIn,
    SwapExactOut,
    LimitSwap,
    LendingBorrow,
    LendingRepay,
    LendingRefinance,
    PerpOpen,
    PerpClose,
    PerpReduce,
    CrossMarginRebalance,
}

impl FastPrivateIntentKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SwapExactIn => "swap_exact_in",
            Self::SwapExactOut => "swap_exact_out",
            Self::LimitSwap => "limit_swap",
            Self::LendingBorrow => "lending_borrow",
            Self::LendingRepay => "lending_repay",
            Self::LendingRefinance => "lending_refinance",
            Self::PerpOpen => "perp_open",
            Self::PerpClose => "perp_close",
            Self::PerpReduce => "perp_reduce",
            Self::CrossMarginRebalance => "cross_margin_rebalance",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MatchingLane {
    Swap,
    Lending,
    Perp,
    CrossMargin,
    InternalNetting,
}

impl MatchingLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Swap => "swap",
            Self::Lending => "lending",
            Self::Perp => "perp",
            Self::CrossMargin => "cross_margin",
            Self::InternalNetting => "internal_netting",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentStatus {
    Submitted,
    Attested,
    RebateReserved,
    Matched,
    Settled,
    Rejected,
    Expired,
}

impl IntentStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Attested => "attested",
            Self::RebateReserved => "rebate_reserved",
            Self::Matched => "matched",
            Self::Settled => "settled",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }

    pub fn matchable(self) -> bool {
        matches!(
            self,
            Self::Submitted | Self::Attested | Self::RebateReserved
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SolverAttestationStatus {
    Recorded,
    Selected,
    Settled,
    Rejected,
    Expired,
}

impl SolverAttestationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Recorded => "recorded",
            Self::Selected => "selected",
            Self::Settled => "settled",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RebateReservationStatus {
    Reserved,
    Consumed,
    Released,
    Expired,
}

impl RebateReservationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Consumed => "consumed",
            Self::Released => "released",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MatchingRoundStatus {
    Built,
    SettlementReady,
    Settled,
    Disputed,
    Expired,
}

impl MatchingRoundStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Built => "built",
            Self::SettlementReady => "settlement_ready",
            Self::Settled => "settled",
            Self::Disputed => "disputed",
            Self::Expired => "expired",
        }
    }

    pub fn can_settle(self) -> bool {
        matches!(self, Self::SettlementReady)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptStatus {
    Published,
    Finalized,
    Disputed,
}

impl ReceiptStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Published => "published",
            Self::Finalized => "finalized",
            Self::Disputed => "disputed",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub protocol_version: String,
    pub schema_version: u64,
    pub chain_id: String,
    pub hash_suite: String,
    pub sealed_intent_scheme: String,
    pub matching_round_scheme: String,
    pub pq_solver_attestation_scheme: String,
    pub rebate_reservation_scheme: String,
    pub settlement_receipt_scheme: String,
    pub matching_window_blocks: u64,
    pub intent_ttl_blocks: u64,
    pub settlement_ttl_blocks: u64,
    pub max_intents: usize,
    pub max_rounds: usize,
    pub max_attestations: usize,
    pub max_reservations: usize,
    pub max_batches: usize,
    pub min_privacy_set_size: u64,
    pub batch_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub max_user_fee_bps: u64,
    pub max_solver_fee_bps: u64,
    pub min_rebate_bps: u64,
    pub max_rebate_bps: u64,
    pub rebate_budget_micro_units: u64,
    pub require_private_intents: bool,
    pub require_pq_solver_attestations: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version: PRIVATE_L2_FAST_PRIVATE_MATCHING_ENGINE_RUNTIME_PROTOCOL_VERSION
                .to_string(),
            schema_version: PRIVATE_L2_FAST_PRIVATE_MATCHING_ENGINE_RUNTIME_SCHEMA_VERSION,
            chain_id: CHAIN_ID.to_string(),
            hash_suite: PRIVATE_L2_FAST_PRIVATE_MATCHING_ENGINE_RUNTIME_HASH_SUITE.to_string(),
            sealed_intent_scheme:
                PRIVATE_L2_FAST_PRIVATE_MATCHING_ENGINE_RUNTIME_SEALED_INTENT_SCHEME.to_string(),
            matching_round_scheme:
                PRIVATE_L2_FAST_PRIVATE_MATCHING_ENGINE_RUNTIME_MATCHING_ROUND_SCHEME.to_string(),
            pq_solver_attestation_scheme:
                PRIVATE_L2_FAST_PRIVATE_MATCHING_ENGINE_RUNTIME_PQ_SOLVER_ATTESTATION_SCHEME
                    .to_string(),
            rebate_reservation_scheme:
                PRIVATE_L2_FAST_PRIVATE_MATCHING_ENGINE_RUNTIME_REBATE_RESERVATION_SCHEME
                    .to_string(),
            settlement_receipt_scheme:
                PRIVATE_L2_FAST_PRIVATE_MATCHING_ENGINE_RUNTIME_SETTLEMENT_RECEIPT_SCHEME
                    .to_string(),
            matching_window_blocks:
                PRIVATE_L2_FAST_PRIVATE_MATCHING_ENGINE_RUNTIME_DEFAULT_MATCHING_WINDOW_BLOCKS,
            intent_ttl_blocks:
                PRIVATE_L2_FAST_PRIVATE_MATCHING_ENGINE_RUNTIME_DEFAULT_INTENT_TTL_BLOCKS,
            settlement_ttl_blocks:
                PRIVATE_L2_FAST_PRIVATE_MATCHING_ENGINE_RUNTIME_DEFAULT_SETTLEMENT_TTL_BLOCKS,
            max_intents: PRIVATE_L2_FAST_PRIVATE_MATCHING_ENGINE_RUNTIME_DEFAULT_MAX_INTENTS,
            max_rounds: PRIVATE_L2_FAST_PRIVATE_MATCHING_ENGINE_RUNTIME_DEFAULT_MAX_ROUNDS,
            max_attestations:
                PRIVATE_L2_FAST_PRIVATE_MATCHING_ENGINE_RUNTIME_DEFAULT_MAX_ATTESTATIONS,
            max_reservations:
                PRIVATE_L2_FAST_PRIVATE_MATCHING_ENGINE_RUNTIME_DEFAULT_MAX_RESERVATIONS,
            max_batches: PRIVATE_L2_FAST_PRIVATE_MATCHING_ENGINE_RUNTIME_DEFAULT_MAX_BATCHES,
            min_privacy_set_size:
                PRIVATE_L2_FAST_PRIVATE_MATCHING_ENGINE_RUNTIME_DEFAULT_MIN_PRIVACY_SET_SIZE,
            batch_privacy_set_size:
                PRIVATE_L2_FAST_PRIVATE_MATCHING_ENGINE_RUNTIME_DEFAULT_BATCH_PRIVACY_SET_SIZE,
            min_pq_security_bits:
                PRIVATE_L2_FAST_PRIVATE_MATCHING_ENGINE_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS,
            max_user_fee_bps:
                PRIVATE_L2_FAST_PRIVATE_MATCHING_ENGINE_RUNTIME_DEFAULT_MAX_USER_FEE_BPS,
            max_solver_fee_bps:
                PRIVATE_L2_FAST_PRIVATE_MATCHING_ENGINE_RUNTIME_DEFAULT_MAX_SOLVER_FEE_BPS,
            min_rebate_bps: PRIVATE_L2_FAST_PRIVATE_MATCHING_ENGINE_RUNTIME_DEFAULT_MIN_REBATE_BPS,
            max_rebate_bps: PRIVATE_L2_FAST_PRIVATE_MATCHING_ENGINE_RUNTIME_DEFAULT_MAX_REBATE_BPS,
            rebate_budget_micro_units:
                PRIVATE_L2_FAST_PRIVATE_MATCHING_ENGINE_RUNTIME_DEFAULT_REBATE_BUDGET_MICRO_UNITS,
            require_private_intents: true,
            require_pq_solver_attestations: true,
        }
    }

    pub fn validate(&self) -> PrivateL2FastPrivateMatchingEngineRuntimeResult<()> {
        ensure_eq(
            &self.chain_id,
            CHAIN_ID,
            "fast private matching engine chain id",
        )?;
        ensure_eq(
            &self.protocol_version,
            PRIVATE_L2_FAST_PRIVATE_MATCHING_ENGINE_RUNTIME_PROTOCOL_VERSION,
            "fast private matching engine protocol version",
        )?;
        if self.schema_version != PRIVATE_L2_FAST_PRIVATE_MATCHING_ENGINE_RUNTIME_SCHEMA_VERSION {
            return Err("fast private matching engine schema version mismatch".to_string());
        }
        if self.matching_window_blocks == 0
            || self.intent_ttl_blocks == 0
            || self.settlement_ttl_blocks == 0
            || self.max_intents == 0
            || self.max_rounds == 0
            || self.max_attestations == 0
            || self.max_reservations == 0
            || self.max_batches == 0
        {
            return Err(
                "fast private matching engine windows and capacities must be positive".to_string(),
            );
        }
        if self.min_privacy_set_size == 0 || self.batch_privacy_set_size < self.min_privacy_set_size
        {
            return Err(
                "fast private matching batch privacy set must cover intent privacy set".to_string(),
            );
        }
        if self.min_pq_security_bits < 192 {
            return Err("fast private matching PQ security bits below minimum".to_string());
        }
        if self.max_user_fee_bps > PRIVATE_L2_FAST_PRIVATE_MATCHING_ENGINE_RUNTIME_MAX_BPS
            || self.max_solver_fee_bps > PRIVATE_L2_FAST_PRIVATE_MATCHING_ENGINE_RUNTIME_MAX_BPS
            || self.min_rebate_bps > self.max_rebate_bps
            || self.max_rebate_bps > self.max_user_fee_bps
        {
            return Err(
                "fast private matching fee/rebate bps configuration is invalid".to_string(),
            );
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_fast_private_matching_engine_config",
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "chain_id": self.chain_id,
            "hash_suite": self.hash_suite,
            "sealed_intent_scheme": self.sealed_intent_scheme,
            "matching_round_scheme": self.matching_round_scheme,
            "pq_solver_attestation_scheme": self.pq_solver_attestation_scheme,
            "rebate_reservation_scheme": self.rebate_reservation_scheme,
            "settlement_receipt_scheme": self.settlement_receipt_scheme,
            "matching_window_blocks": self.matching_window_blocks,
            "intent_ttl_blocks": self.intent_ttl_blocks,
            "settlement_ttl_blocks": self.settlement_ttl_blocks,
            "max_intents": self.max_intents,
            "max_rounds": self.max_rounds,
            "max_attestations": self.max_attestations,
            "max_reservations": self.max_reservations,
            "max_batches": self.max_batches,
            "min_privacy_set_size": self.min_privacy_set_size,
            "batch_privacy_set_size": self.batch_privacy_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
            "max_user_fee_bps": self.max_user_fee_bps,
            "max_solver_fee_bps": self.max_solver_fee_bps,
            "min_rebate_bps": self.min_rebate_bps,
            "max_rebate_bps": self.max_rebate_bps,
            "rebate_budget_micro_units": self.rebate_budget_micro_units,
            "require_private_intents": self.require_private_intents,
            "require_pq_solver_attestations": self.require_pq_solver_attestations,
        })
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    pub next_intent_nonce: u64,
    pub next_attestation_nonce: u64,
    pub next_reservation_nonce: u64,
    pub next_round_nonce: u64,
    pub next_receipt_nonce: u64,
    pub sealed_intents_submitted: u64,
    pub solver_attestations_recorded: u64,
    pub rebate_reservations_recorded: u64,
    pub matching_rounds_built: u64,
    pub settlement_receipts_published: u64,
    pub intents_settled: u64,
    pub rebates_reserved_micro_units: u64,
    pub rebates_consumed_micro_units: u64,
    pub solver_fees_micro_units: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_fast_private_matching_engine_counters",
            "next_intent_nonce": self.next_intent_nonce,
            "next_attestation_nonce": self.next_attestation_nonce,
            "next_reservation_nonce": self.next_reservation_nonce,
            "next_round_nonce": self.next_round_nonce,
            "next_receipt_nonce": self.next_receipt_nonce,
            "sealed_intents_submitted": self.sealed_intents_submitted,
            "solver_attestations_recorded": self.solver_attestations_recorded,
            "rebate_reservations_recorded": self.rebate_reservations_recorded,
            "matching_rounds_built": self.matching_rounds_built,
            "settlement_receipts_published": self.settlement_receipts_published,
            "intents_settled": self.intents_settled,
            "rebates_reserved_micro_units": self.rebates_reserved_micro_units,
            "rebates_consumed_micro_units": self.rebates_consumed_micro_units,
            "solver_fees_micro_units": self.solver_fees_micro_units,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubmitSealedIntentRequest {
    pub intent_kind: FastPrivateIntentKind,
    pub lane: MatchingLane,
    pub account_commitment: String,
    pub sealed_intent_root: String,
    pub encrypted_payload_root: String,
    pub asset_pair_root: String,
    pub amount_commitment_root: String,
    pub limit_or_margin_commitment_root: String,
    pub nullifier_root: String,
    pub refund_commitment_root: String,
    pub max_user_fee_bps: u64,
    pub requested_rebate_bps: u64,
    pub estimated_value_micro_units: u64,
    pub privacy_set_size: u64,
    pub pq_authorization_root: String,
    pub pq_security_bits: u16,
    pub submitted_at_height: u64,
    pub expires_at_height: u64,
}

impl SubmitSealedIntentRequest {
    pub fn validate(&self, config: &Config) -> PrivateL2FastPrivateMatchingEngineRuntimeResult<()> {
        require_root("account commitment", &self.account_commitment)?;
        require_root("sealed intent root", &self.sealed_intent_root)?;
        require_root("encrypted payload root", &self.encrypted_payload_root)?;
        require_root("asset pair root", &self.asset_pair_root)?;
        require_root("amount commitment root", &self.amount_commitment_root)?;
        require_root(
            "limit or margin commitment root",
            &self.limit_or_margin_commitment_root,
        )?;
        require_root("nullifier root", &self.nullifier_root)?;
        require_root("refund commitment root", &self.refund_commitment_root)?;
        require_root("PQ authorization root", &self.pq_authorization_root)?;
        if self.max_user_fee_bps > config.max_user_fee_bps {
            return Err("sealed intent max user fee exceeds runtime cap".to_string());
        }
        if self.requested_rebate_bps < config.min_rebate_bps
            || self.requested_rebate_bps > config.max_rebate_bps
        {
            return Err("sealed intent requested rebate outside configured bounds".to_string());
        }
        if self.privacy_set_size < config.min_privacy_set_size {
            return Err("sealed intent privacy set below runtime minimum".to_string());
        }
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err("sealed intent PQ authorization security bits below minimum".to_string());
        }
        if self.expires_at_height <= self.submitted_at_height
            || self.expires_at_height
                > self
                    .submitted_at_height
                    .saturating_add(config.intent_ttl_blocks)
        {
            return Err("sealed intent expiry outside runtime ttl window".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "intent_kind": self.intent_kind.as_str(),
            "lane": self.lane.as_str(),
            "account_commitment": self.account_commitment,
            "sealed_intent_root": self.sealed_intent_root,
            "encrypted_payload_root": self.encrypted_payload_root,
            "asset_pair_root": self.asset_pair_root,
            "amount_commitment_root": self.amount_commitment_root,
            "limit_or_margin_commitment_root": self.limit_or_margin_commitment_root,
            "nullifier_root": self.nullifier_root,
            "refund_commitment_root": self.refund_commitment_root,
            "max_user_fee_bps": self.max_user_fee_bps,
            "requested_rebate_bps": self.requested_rebate_bps,
            "estimated_value_micro_units": self.estimated_value_micro_units,
            "privacy_set_size": self.privacy_set_size,
            "pq_authorization_root": self.pq_authorization_root,
            "pq_security_bits": self.pq_security_bits,
            "submitted_at_height": self.submitted_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordSolverAttestationRequest {
    pub solver_id: String,
    pub intent_ids: Vec<String>,
    pub route_commitment_root: String,
    pub matching_claim_root: String,
    pub expected_surplus_micro_units: u64,
    pub solver_fee_bps: u64,
    pub pq_attestation_root: String,
    pub pq_security_bits: u16,
    pub attested_at_height: u64,
    pub expires_at_height: u64,
}

impl RecordSolverAttestationRequest {
    pub fn validate(&self, config: &Config) -> PrivateL2FastPrivateMatchingEngineRuntimeResult<()> {
        require_non_empty("solver id", &self.solver_id)?;
        require_root("route commitment root", &self.route_commitment_root)?;
        require_root("matching claim root", &self.matching_claim_root)?;
        require_root("PQ attestation root", &self.pq_attestation_root)?;
        if self.intent_ids.is_empty() {
            return Err("solver attestation must reference at least one intent".to_string());
        }
        if self.solver_fee_bps > config.max_solver_fee_bps {
            return Err("solver attestation fee exceeds runtime cap".to_string());
        }
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err("solver attestation PQ security bits below minimum".to_string());
        }
        if self.expires_at_height <= self.attested_at_height {
            return Err("solver attestation expiry must be after attestation height".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "solver_id": self.solver_id,
            "intent_ids": self.intent_ids,
            "route_commitment_root": self.route_commitment_root,
            "matching_claim_root": self.matching_claim_root,
            "expected_surplus_micro_units": self.expected_surplus_micro_units,
            "solver_fee_bps": self.solver_fee_bps,
            "pq_attestation_root": self.pq_attestation_root,
            "pq_security_bits": self.pq_security_bits,
            "attested_at_height": self.attested_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReserveLowFeeRebateRequest {
    pub sponsor_commitment: String,
    pub intent_ids: Vec<String>,
    pub budget_root: String,
    pub rebate_commitment_root: String,
    pub reserved_micro_units: u64,
    pub rebate_bps: u64,
    pub pq_reservation_root: String,
    pub reserved_at_height: u64,
    pub expires_at_height: u64,
}

impl ReserveLowFeeRebateRequest {
    pub fn validate(&self, config: &Config) -> PrivateL2FastPrivateMatchingEngineRuntimeResult<()> {
        require_root("sponsor commitment", &self.sponsor_commitment)?;
        require_root("budget root", &self.budget_root)?;
        require_root("rebate commitment root", &self.rebate_commitment_root)?;
        require_root("PQ reservation root", &self.pq_reservation_root)?;
        if self.intent_ids.is_empty() {
            return Err("rebate reservation must reference at least one intent".to_string());
        }
        if self.reserved_micro_units == 0 {
            return Err("rebate reservation amount must be positive".to_string());
        }
        if self.rebate_bps < config.min_rebate_bps || self.rebate_bps > config.max_rebate_bps {
            return Err("rebate reservation bps outside configured bounds".to_string());
        }
        if self.expires_at_height <= self.reserved_at_height {
            return Err("rebate reservation expiry must be after reservation height".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "sponsor_commitment": self.sponsor_commitment,
            "intent_ids": self.intent_ids,
            "budget_root": self.budget_root,
            "rebate_commitment_root": self.rebate_commitment_root,
            "reserved_micro_units": self.reserved_micro_units,
            "rebate_bps": self.rebate_bps,
            "pq_reservation_root": self.pq_reservation_root,
            "reserved_at_height": self.reserved_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BuildMatchingRoundRequest {
    pub round_label: String,
    pub lane: MatchingLane,
    pub intent_ids: Vec<String>,
    pub solver_attestation_ids: Vec<String>,
    pub rebate_reservation_ids: Vec<String>,
    pub aggregate_intent_root: String,
    pub aggregate_solver_attestation_root: String,
    pub aggregate_rebate_reservation_root: String,
    pub clearing_price_root: String,
    pub output_commitment_root: String,
    pub solver_payment_root: String,
    pub rebate_distribution_root: String,
    pub batch_witness_root: String,
    pub selected_solver_fee_bps: u64,
    pub privacy_set_size: u64,
    pub built_at_height: u64,
}

impl BuildMatchingRoundRequest {
    pub fn validate(&self, config: &Config) -> PrivateL2FastPrivateMatchingEngineRuntimeResult<()> {
        require_non_empty("round label", &self.round_label)?;
        require_root("aggregate intent root", &self.aggregate_intent_root)?;
        require_root(
            "aggregate solver attestation root",
            &self.aggregate_solver_attestation_root,
        )?;
        require_root(
            "aggregate rebate reservation root",
            &self.aggregate_rebate_reservation_root,
        )?;
        require_root("clearing price root", &self.clearing_price_root)?;
        require_root("output commitment root", &self.output_commitment_root)?;
        require_root("solver payment root", &self.solver_payment_root)?;
        require_root("rebate distribution root", &self.rebate_distribution_root)?;
        require_root("batch witness root", &self.batch_witness_root)?;
        if self.intent_ids.is_empty() {
            return Err("matching round must include at least one intent".to_string());
        }
        if self.intent_ids.len() > config.max_intents {
            return Err("matching round exceeds max intents".to_string());
        }
        if self.solver_attestation_ids.is_empty() {
            return Err("matching round must include at least one solver attestation".to_string());
        }
        if self.selected_solver_fee_bps > config.max_solver_fee_bps {
            return Err("matching round selected solver fee exceeds runtime cap".to_string());
        }
        if self.privacy_set_size < config.batch_privacy_set_size {
            return Err("matching round privacy set below batch target".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "round_label": self.round_label,
            "lane": self.lane.as_str(),
            "intent_ids": self.intent_ids,
            "solver_attestation_ids": self.solver_attestation_ids,
            "rebate_reservation_ids": self.rebate_reservation_ids,
            "aggregate_intent_root": self.aggregate_intent_root,
            "aggregate_solver_attestation_root": self.aggregate_solver_attestation_root,
            "aggregate_rebate_reservation_root": self.aggregate_rebate_reservation_root,
            "clearing_price_root": self.clearing_price_root,
            "output_commitment_root": self.output_commitment_root,
            "solver_payment_root": self.solver_payment_root,
            "rebate_distribution_root": self.rebate_distribution_root,
            "batch_witness_root": self.batch_witness_root,
            "selected_solver_fee_bps": self.selected_solver_fee_bps,
            "privacy_set_size": self.privacy_set_size,
            "built_at_height": self.built_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettleMatchingBatchRequest {
    pub matching_round_id: String,
    pub settlement_tx_root: String,
    pub settlement_proof_root: String,
    pub spent_nullifier_root: String,
    pub output_commitment_root: String,
    pub solver_payment_root: String,
    pub rebate_distribution_root: String,
    pub state_transition_root: String,
    pub runtime_state_root_after: String,
    pub settled_at_height: u64,
    pub finalized_at_height: Option<u64>,
}

impl SettleMatchingBatchRequest {
    pub fn validate(&self) -> PrivateL2FastPrivateMatchingEngineRuntimeResult<()> {
        require_non_empty("matching round id", &self.matching_round_id)?;
        require_root("settlement tx root", &self.settlement_tx_root)?;
        require_root("settlement proof root", &self.settlement_proof_root)?;
        require_root("spent nullifier root", &self.spent_nullifier_root)?;
        require_root("output commitment root", &self.output_commitment_root)?;
        require_root("solver payment root", &self.solver_payment_root)?;
        require_root("rebate distribution root", &self.rebate_distribution_root)?;
        require_root("state transition root", &self.state_transition_root)?;
        require_root("runtime state root after", &self.runtime_state_root_after)?;
        if let Some(finalized_at_height) = self.finalized_at_height {
            if finalized_at_height < self.settled_at_height {
                return Err("finalization height must not precede settlement height".to_string());
            }
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "matching_round_id": self.matching_round_id,
            "settlement_tx_root": self.settlement_tx_root,
            "settlement_proof_root": self.settlement_proof_root,
            "spent_nullifier_root": self.spent_nullifier_root,
            "output_commitment_root": self.output_commitment_root,
            "solver_payment_root": self.solver_payment_root,
            "rebate_distribution_root": self.rebate_distribution_root,
            "state_transition_root": self.state_transition_root,
            "runtime_state_root_after": self.runtime_state_root_after,
            "settled_at_height": self.settled_at_height,
            "finalized_at_height": self.finalized_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedIntentRecord {
    pub intent_id: String,
    pub request: SubmitSealedIntentRequest,
    pub status: IntentStatus,
    pub solver_attestation_id: Option<String>,
    pub rebate_reservation_id: Option<String>,
    pub matching_round_id: Option<String>,
}

impl SealedIntentRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_fast_private_matching_engine_sealed_intent",
            "intent_id": self.intent_id,
            "request": self.request.public_record(),
            "status": self.status.as_str(),
            "solver_attestation_id": self.solver_attestation_id,
            "rebate_reservation_id": self.rebate_reservation_id,
            "matching_round_id": self.matching_round_id,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SolverAttestationRecord {
    pub attestation_id: String,
    pub request: RecordSolverAttestationRequest,
    pub score: u128,
    pub status: SolverAttestationStatus,
}

impl SolverAttestationRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_fast_private_matching_engine_solver_attestation",
            "attestation_id": self.attestation_id,
            "request": self.request.public_record(),
            "score": self.score.to_string(),
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeRebateReservationRecord {
    pub reservation_id: String,
    pub request: ReserveLowFeeRebateRequest,
    pub status: RebateReservationStatus,
}

impl LowFeeRebateReservationRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_fast_private_matching_engine_low_fee_rebate_reservation",
            "reservation_id": self.reservation_id,
            "request": self.request.public_record(),
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MatchingRoundRecord {
    pub matching_round_id: String,
    pub request: BuildMatchingRoundRequest,
    pub selected_solver_attestation_id: String,
    pub settlement_deadline_height: u64,
    pub status: MatchingRoundStatus,
    pub settlement_receipt_id: Option<String>,
}

impl MatchingRoundRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_fast_private_matching_engine_matching_round",
            "matching_round_id": self.matching_round_id,
            "request": self.request.public_record(),
            "selected_solver_attestation_id": self.selected_solver_attestation_id,
            "settlement_deadline_height": self.settlement_deadline_height,
            "status": self.status.as_str(),
            "settlement_receipt_id": self.settlement_receipt_id,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MatchingBatchSettlementReceipt {
    pub receipt_id: String,
    pub matching_round_id: String,
    pub status: ReceiptStatus,
    pub settlement_tx_root: String,
    pub settlement_proof_root: String,
    pub spent_nullifier_root: String,
    pub output_commitment_root: String,
    pub solver_payment_root: String,
    pub rebate_distribution_root: String,
    pub state_transition_root: String,
    pub state_root_before: String,
    pub state_root_after: String,
    pub runtime_state_root_after: String,
    pub settled_at_height: u64,
    pub finalized_at_height: Option<u64>,
}

impl MatchingBatchSettlementReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_fast_private_matching_engine_settlement_receipt",
            "receipt_id": self.receipt_id,
            "matching_round_id": self.matching_round_id,
            "status": self.status.as_str(),
            "settlement_tx_root": self.settlement_tx_root,
            "settlement_proof_root": self.settlement_proof_root,
            "spent_nullifier_root": self.spent_nullifier_root,
            "output_commitment_root": self.output_commitment_root,
            "solver_payment_root": self.solver_payment_root,
            "rebate_distribution_root": self.rebate_distribution_root,
            "state_transition_root": self.state_transition_root,
            "state_root_before": self.state_root_before,
            "state_root_after": self.state_root_after,
            "runtime_state_root_after": self.runtime_state_root_after,
            "settled_at_height": self.settled_at_height,
            "finalized_at_height": self.finalized_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roots {
    pub config_root: String,
    pub sealed_intent_root: String,
    pub solver_attestation_root: String,
    pub rebate_reservation_root: String,
    pub matching_round_root: String,
    pub settlement_receipt_root: String,
    pub consumed_nullifier_root: String,
    pub public_record_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "sealed_intent_root": self.sealed_intent_root,
            "solver_attestation_root": self.solver_attestation_root,
            "rebate_reservation_root": self.rebate_reservation_root,
            "matching_round_root": self.matching_round_root,
            "settlement_receipt_root": self.settlement_receipt_root,
            "consumed_nullifier_root": self.consumed_nullifier_root,
            "public_record_root": self.public_record_root,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrivateL2FastPrivateMatchingEngineRuntime {
    pub config: Config,
    pub counters: Counters,
    pub current_height: u64,
    pub runtime_root: String,
    pub rebate_budget_remaining_micro_units: u64,
    pub sealed_intents: BTreeMap<String, SealedIntentRecord>,
    pub solver_attestations: BTreeMap<String, SolverAttestationRecord>,
    pub rebate_reservations: BTreeMap<String, LowFeeRebateReservationRecord>,
    pub matching_rounds: BTreeMap<String, MatchingRoundRecord>,
    pub settlement_receipts: BTreeMap<String, MatchingBatchSettlementReceipt>,
    pub consumed_nullifier_roots: BTreeSet<String>,
    pub public_records: BTreeMap<String, Value>,
}

impl PrivateL2FastPrivateMatchingEngineRuntime {
    pub fn devnet() -> PrivateL2FastPrivateMatchingEngineRuntimeResult<Self> {
        Self::new(Config::devnet())
    }

    pub fn new(config: Config) -> PrivateL2FastPrivateMatchingEngineRuntimeResult<Self> {
        config.validate()?;
        let runtime_root = private_l2_fast_private_matching_engine_payload_root(
            "PRIVATE-L2-FAST-PRIVATE-MATCHING-ENGINE-DEVNET-RUNTIME",
            &config.public_record(),
        );
        let rebate_budget_remaining_micro_units = config.rebate_budget_micro_units;
        Ok(Self {
            config,
            counters: Counters::default(),
            current_height: PRIVATE_L2_FAST_PRIVATE_MATCHING_ENGINE_RUNTIME_DEVNET_HEIGHT,
            runtime_root,
            rebate_budget_remaining_micro_units,
            sealed_intents: BTreeMap::new(),
            solver_attestations: BTreeMap::new(),
            rebate_reservations: BTreeMap::new(),
            matching_rounds: BTreeMap::new(),
            settlement_receipts: BTreeMap::new(),
            consumed_nullifier_roots: BTreeSet::new(),
            public_records: BTreeMap::new(),
        })
    }

    pub fn submit_sealed_intent(
        &mut self,
        request: SubmitSealedIntentRequest,
    ) -> PrivateL2FastPrivateMatchingEngineRuntimeResult<SealedIntentRecord> {
        self.config.validate()?;
        request.validate(&self.config)?;
        if self.sealed_intents.len() >= self.config.max_intents {
            return Err("sealed intent store is full".to_string());
        }
        if self
            .consumed_nullifier_roots
            .contains(&request.nullifier_root)
        {
            return Err("sealed intent nullifier root already consumed".to_string());
        }
        let intent_id = sealed_intent_id(&request, self.counters.next_intent_nonce);
        if self.sealed_intents.contains_key(&intent_id) {
            return Err("sealed intent already submitted".to_string());
        }
        let record = SealedIntentRecord {
            intent_id: intent_id.clone(),
            request,
            status: IntentStatus::Submitted,
            solver_attestation_id: None,
            rebate_reservation_id: None,
            matching_round_id: None,
        };
        self.current_height = self.current_height.max(record.request.submitted_at_height);
        self.counters.next_intent_nonce = self.counters.next_intent_nonce.saturating_add(1);
        self.counters.sealed_intents_submitted =
            self.counters.sealed_intents_submitted.saturating_add(1);
        self.sealed_intents
            .insert(intent_id.clone(), record.clone());
        self.publish_public_record("sealed_intent", &intent_id, record.public_record());
        Ok(record)
    }

    pub fn record_solver_attestation(
        &mut self,
        request: RecordSolverAttestationRequest,
    ) -> PrivateL2FastPrivateMatchingEngineRuntimeResult<SolverAttestationRecord> {
        self.config.validate()?;
        request.validate(&self.config)?;
        if self.solver_attestations.len() >= self.config.max_attestations {
            return Err("solver attestation store is full".to_string());
        }
        let mut unique_intents = BTreeSet::new();
        for intent_id in &request.intent_ids {
            if !unique_intents.insert(intent_id.clone()) {
                return Err("solver attestation contains duplicate intent id".to_string());
            }
            let intent = self.sealed_intents.get(intent_id).ok_or_else(|| {
                format!("solver attestation references unknown intent: {intent_id}")
            })?;
            if !intent.status.matchable() {
                return Err(format!("intent is not matchable: {intent_id}"));
            }
            if request.attested_at_height > intent.request.expires_at_height {
                return Err(format!(
                    "intent expired before solver attestation: {intent_id}"
                ));
            }
        }
        let score = solver_attestation_score(&request);
        let attestation_id =
            solver_attestation_id(&request, score, self.counters.next_attestation_nonce);
        for intent_id in &request.intent_ids {
            if let Some(intent) = self.sealed_intents.get_mut(intent_id) {
                intent.status = IntentStatus::Attested;
                intent.solver_attestation_id = Some(attestation_id.clone());
            }
        }
        let record = SolverAttestationRecord {
            attestation_id: attestation_id.clone(),
            request,
            score,
            status: SolverAttestationStatus::Recorded,
        };
        self.current_height = self.current_height.max(record.request.attested_at_height);
        self.counters.next_attestation_nonce =
            self.counters.next_attestation_nonce.saturating_add(1);
        self.counters.solver_attestations_recorded =
            self.counters.solver_attestations_recorded.saturating_add(1);
        self.solver_attestations
            .insert(attestation_id.clone(), record.clone());
        self.refresh_intent_records(&record.request.intent_ids);
        self.publish_public_record(
            "solver_attestation",
            &attestation_id,
            record.public_record(),
        );
        Ok(record)
    }

    pub fn reserve_low_fee_rebate(
        &mut self,
        request: ReserveLowFeeRebateRequest,
    ) -> PrivateL2FastPrivateMatchingEngineRuntimeResult<LowFeeRebateReservationRecord> {
        self.config.validate()?;
        request.validate(&self.config)?;
        if self.rebate_reservations.len() >= self.config.max_reservations {
            return Err("rebate reservation store is full".to_string());
        }
        if request.reserved_micro_units > self.rebate_budget_remaining_micro_units {
            return Err("rebate reservation exceeds remaining budget".to_string());
        }
        let mut unique_intents = BTreeSet::new();
        for intent_id in &request.intent_ids {
            if !unique_intents.insert(intent_id.clone()) {
                return Err("rebate reservation contains duplicate intent id".to_string());
            }
            let intent = self.sealed_intents.get(intent_id).ok_or_else(|| {
                format!("rebate reservation references unknown intent: {intent_id}")
            })?;
            if !intent.status.matchable() {
                return Err(format!("intent is not rebate-reservable: {intent_id}"));
            }
            if request.reserved_at_height > intent.request.expires_at_height {
                return Err(format!(
                    "intent expired before rebate reservation: {intent_id}"
                ));
            }
        }
        let reservation_id = low_fee_rebate_reservation_id(
            &request,
            self.counters.next_reservation_nonce,
            self.rebate_budget_remaining_micro_units,
        );
        for intent_id in &request.intent_ids {
            if let Some(intent) = self.sealed_intents.get_mut(intent_id) {
                intent.status = IntentStatus::RebateReserved;
                intent.rebate_reservation_id = Some(reservation_id.clone());
            }
        }
        self.rebate_budget_remaining_micro_units = self
            .rebate_budget_remaining_micro_units
            .saturating_sub(request.reserved_micro_units);
        let record = LowFeeRebateReservationRecord {
            reservation_id: reservation_id.clone(),
            request,
            status: RebateReservationStatus::Reserved,
        };
        self.current_height = self.current_height.max(record.request.reserved_at_height);
        self.counters.next_reservation_nonce =
            self.counters.next_reservation_nonce.saturating_add(1);
        self.counters.rebate_reservations_recorded =
            self.counters.rebate_reservations_recorded.saturating_add(1);
        self.counters.rebates_reserved_micro_units = self
            .counters
            .rebates_reserved_micro_units
            .saturating_add(record.request.reserved_micro_units);
        self.rebate_reservations
            .insert(reservation_id.clone(), record.clone());
        self.refresh_intent_records(&record.request.intent_ids);
        self.publish_public_record(
            "low_fee_rebate_reservation",
            &reservation_id,
            record.public_record(),
        );
        Ok(record)
    }

    pub fn build_matching_round(
        &mut self,
        request: BuildMatchingRoundRequest,
    ) -> PrivateL2FastPrivateMatchingEngineRuntimeResult<MatchingRoundRecord> {
        self.config.validate()?;
        request.validate(&self.config)?;
        if self.matching_rounds.len() >= self.config.max_rounds
            || self.matching_rounds.len() >= self.config.max_batches
        {
            return Err("matching round store is full".to_string());
        }
        let mut unique_intents = BTreeSet::new();
        for intent_id in &request.intent_ids {
            if !unique_intents.insert(intent_id.clone()) {
                return Err("matching round contains duplicate intent id".to_string());
            }
            let intent = self
                .sealed_intents
                .get(intent_id)
                .ok_or_else(|| format!("matching round references unknown intent: {intent_id}"))?;
            if !intent.status.matchable() {
                return Err(format!("intent is not matchable: {intent_id}"));
            }
            if request.built_at_height > intent.request.expires_at_height {
                return Err(format!("intent expired before matching round: {intent_id}"));
            }
            if intent.request.lane != request.lane {
                return Err(format!(
                    "intent lane mismatch for matching round: {intent_id}"
                ));
            }
        }
        let mut selected_attestation: Option<SolverAttestationRecord> = None;
        for attestation_id in &request.solver_attestation_ids {
            let attestation = self
                .solver_attestations
                .get(attestation_id)
                .ok_or_else(|| {
                    format!(
                        "matching round references unknown solver attestation: {attestation_id}"
                    )
                })?;
            if !matches!(attestation.status, SolverAttestationStatus::Recorded) {
                return Err(format!(
                    "solver attestation is not selectable: {attestation_id}"
                ));
            }
            if !covers_all(&attestation.request.intent_ids, &request.intent_ids) {
                return Err(format!(
                    "solver attestation does not cover matching round intents: {attestation_id}"
                ));
            }
            if request.built_at_height > attestation.request.expires_at_height {
                return Err(format!(
                    "solver attestation expired before matching round: {attestation_id}"
                ));
            }
            if selected_attestation
                .as_ref()
                .map(|selected| attestation.score > selected.score)
                .unwrap_or(true)
            {
                selected_attestation = Some(attestation.clone());
            }
        }
        for reservation_id in &request.rebate_reservation_ids {
            let reservation = self
                .rebate_reservations
                .get(reservation_id)
                .ok_or_else(|| {
                    format!(
                        "matching round references unknown rebate reservation: {reservation_id}"
                    )
                })?;
            if !matches!(reservation.status, RebateReservationStatus::Reserved) {
                return Err(format!(
                    "rebate reservation is not active: {reservation_id}"
                ));
            }
            if !covers_all(&reservation.request.intent_ids, &request.intent_ids) {
                return Err(format!(
                    "rebate reservation does not cover matching round intents: {reservation_id}"
                ));
            }
            if request.built_at_height > reservation.request.expires_at_height {
                return Err(format!(
                    "rebate reservation expired before matching round: {reservation_id}"
                ));
            }
        }
        let selected_attestation = selected_attestation
            .ok_or_else(|| "matching round has no selectable solver attestation".to_string())?;
        let matching_round_id = matching_round_id(
            &request,
            &selected_attestation.attestation_id,
            self.counters.next_round_nonce,
        );
        for intent_id in &request.intent_ids {
            if let Some(intent) = self.sealed_intents.get_mut(intent_id) {
                intent.status = IntentStatus::Matched;
                intent.matching_round_id = Some(matching_round_id.clone());
            }
        }
        for attestation_id in &request.solver_attestation_ids {
            if let Some(attestation) = self.solver_attestations.get_mut(attestation_id) {
                attestation.status = if *attestation_id == selected_attestation.attestation_id {
                    SolverAttestationStatus::Selected
                } else {
                    SolverAttestationStatus::Rejected
                };
            }
        }
        let settlement_deadline_height = request
            .built_at_height
            .saturating_add(self.config.settlement_ttl_blocks);
        let record = MatchingRoundRecord {
            matching_round_id: matching_round_id.clone(),
            request,
            selected_solver_attestation_id: selected_attestation.attestation_id,
            settlement_deadline_height,
            status: MatchingRoundStatus::SettlementReady,
            settlement_receipt_id: None,
        };
        self.current_height = self.current_height.max(record.request.built_at_height);
        self.counters.next_round_nonce = self.counters.next_round_nonce.saturating_add(1);
        self.counters.matching_rounds_built = self.counters.matching_rounds_built.saturating_add(1);
        self.counters.solver_fees_micro_units = self
            .counters
            .solver_fees_micro_units
            .saturating_add(solver_fee_micro_units(&record));
        self.matching_rounds
            .insert(matching_round_id.clone(), record.clone());
        self.refresh_intent_records(&record.request.intent_ids);
        self.refresh_attestation_records(&record.request.solver_attestation_ids);
        self.publish_public_record("matching_round", &matching_round_id, record.public_record());
        Ok(record)
    }

    pub fn settle_matching_batch(
        &mut self,
        request: SettleMatchingBatchRequest,
    ) -> PrivateL2FastPrivateMatchingEngineRuntimeResult<MatchingBatchSettlementReceipt> {
        self.config.validate()?;
        request.validate()?;
        let state_root_before = self.state_root();
        let round = self
            .matching_rounds
            .get(&request.matching_round_id)
            .cloned()
            .ok_or_else(|| "settlement references unknown matching round".to_string())?;
        if !round.status.can_settle() {
            return Err("matching round is not settlement ready".to_string());
        }
        if request.settled_at_height > round.settlement_deadline_height {
            return Err("matching round settlement deadline elapsed".to_string());
        }
        if request.output_commitment_root != round.request.output_commitment_root
            || request.solver_payment_root != round.request.solver_payment_root
            || request.rebate_distribution_root != round.request.rebate_distribution_root
        {
            return Err("settlement roots do not match matching round commitments".to_string());
        }
        let receipt_id = matching_batch_settlement_receipt_id(
            &request,
            self.counters.next_receipt_nonce,
            &state_root_before,
        );
        for intent_id in &round.request.intent_ids {
            if let Some(intent) = self.sealed_intents.get_mut(intent_id) {
                intent.status = IntentStatus::Settled;
                self.consumed_nullifier_roots
                    .insert(intent.request.nullifier_root.clone());
            }
        }
        if let Some(attestation) = self
            .solver_attestations
            .get_mut(&round.selected_solver_attestation_id)
        {
            attestation.status = SolverAttestationStatus::Settled;
        }
        for reservation_id in &round.request.rebate_reservation_ids {
            if let Some(reservation) = self.rebate_reservations.get_mut(reservation_id) {
                reservation.status = RebateReservationStatus::Consumed;
                self.counters.rebates_consumed_micro_units = self
                    .counters
                    .rebates_consumed_micro_units
                    .saturating_add(reservation.request.reserved_micro_units);
            }
        }
        if let Some(stored_round) = self.matching_rounds.get_mut(&request.matching_round_id) {
            stored_round.status = MatchingRoundStatus::Settled;
            stored_round.settlement_receipt_id = Some(receipt_id.clone());
        }
        self.runtime_root = request.runtime_state_root_after.clone();
        self.current_height = self.current_height.max(request.settled_at_height);
        self.counters.next_receipt_nonce = self.counters.next_receipt_nonce.saturating_add(1);
        self.counters.settlement_receipts_published = self
            .counters
            .settlement_receipts_published
            .saturating_add(1);
        self.counters.intents_settled = self
            .counters
            .intents_settled
            .saturating_add(round.request.intent_ids.len() as u64);
        let state_root_after = self.state_root();
        let record = MatchingBatchSettlementReceipt {
            receipt_id: receipt_id.clone(),
            matching_round_id: request.matching_round_id,
            status: if request.finalized_at_height.is_some() {
                ReceiptStatus::Finalized
            } else {
                ReceiptStatus::Published
            },
            settlement_tx_root: request.settlement_tx_root,
            settlement_proof_root: request.settlement_proof_root,
            spent_nullifier_root: request.spent_nullifier_root,
            output_commitment_root: request.output_commitment_root,
            solver_payment_root: request.solver_payment_root,
            rebate_distribution_root: request.rebate_distribution_root,
            state_transition_root: request.state_transition_root,
            state_root_before,
            state_root_after,
            runtime_state_root_after: request.runtime_state_root_after,
            settled_at_height: request.settled_at_height,
            finalized_at_height: request.finalized_at_height,
        };
        self.settlement_receipts
            .insert(receipt_id.clone(), record.clone());
        self.refresh_intent_records(&round.request.intent_ids);
        self.refresh_attestation_records(&round.request.solver_attestation_ids);
        self.refresh_reservation_records(&round.request.rebate_reservation_ids);
        self.publish_public_record("settlement_receipt", &receipt_id, record.public_record());
        Ok(record)
    }

    pub fn roots(&self) -> Roots {
        Roots {
            config_root: private_l2_fast_private_matching_engine_payload_root(
                "PRIVATE-L2-FAST-PRIVATE-MATCHING-ENGINE-CONFIG",
                &self.config.public_record(),
            ),
            sealed_intent_root: private_l2_fast_private_matching_engine_merkle_root(
                "PRIVATE-L2-FAST-PRIVATE-MATCHING-ENGINE-SEALED-INTENT",
                self.sealed_intents
                    .values()
                    .map(SealedIntentRecord::public_record)
                    .collect(),
            ),
            solver_attestation_root: private_l2_fast_private_matching_engine_merkle_root(
                "PRIVATE-L2-FAST-PRIVATE-MATCHING-ENGINE-SOLVER-ATTESTATION",
                self.solver_attestations
                    .values()
                    .map(SolverAttestationRecord::public_record)
                    .collect(),
            ),
            rebate_reservation_root: private_l2_fast_private_matching_engine_merkle_root(
                "PRIVATE-L2-FAST-PRIVATE-MATCHING-ENGINE-REBATE-RESERVATION",
                self.rebate_reservations
                    .values()
                    .map(LowFeeRebateReservationRecord::public_record)
                    .collect(),
            ),
            matching_round_root: private_l2_fast_private_matching_engine_merkle_root(
                "PRIVATE-L2-FAST-PRIVATE-MATCHING-ENGINE-MATCHING-ROUND",
                self.matching_rounds
                    .values()
                    .map(MatchingRoundRecord::public_record)
                    .collect(),
            ),
            settlement_receipt_root: private_l2_fast_private_matching_engine_merkle_root(
                "PRIVATE-L2-FAST-PRIVATE-MATCHING-ENGINE-SETTLEMENT-RECEIPT",
                self.settlement_receipts
                    .values()
                    .map(MatchingBatchSettlementReceipt::public_record)
                    .collect(),
            ),
            consumed_nullifier_root: private_l2_fast_private_matching_engine_merkle_root(
                "PRIVATE-L2-FAST-PRIVATE-MATCHING-ENGINE-CONSUMED-NULLIFIER",
                self.consumed_nullifier_roots
                    .iter()
                    .map(|root| json!({ "nullifier_root": root }))
                    .collect(),
            ),
            public_record_root: private_l2_fast_private_matching_engine_merkle_root(
                "PRIVATE-L2-FAST-PRIVATE-MATCHING-ENGINE-PUBLIC-RECORD",
                self.public_records.values().cloned().collect(),
            ),
        }
    }

    pub fn public_record_without_state_root(&self) -> Value {
        json!({
            "kind": "private_l2_fast_private_matching_engine_runtime",
            "protocol_version": PRIVATE_L2_FAST_PRIVATE_MATCHING_ENGINE_RUNTIME_PROTOCOL_VERSION,
            "schema_version": PRIVATE_L2_FAST_PRIVATE_MATCHING_ENGINE_RUNTIME_SCHEMA_VERSION,
            "chain_id": CHAIN_ID,
            "hash_suite": PRIVATE_L2_FAST_PRIVATE_MATCHING_ENGINE_RUNTIME_HASH_SUITE,
            "sealed_intent_scheme": PRIVATE_L2_FAST_PRIVATE_MATCHING_ENGINE_RUNTIME_SEALED_INTENT_SCHEME,
            "matching_round_scheme": PRIVATE_L2_FAST_PRIVATE_MATCHING_ENGINE_RUNTIME_MATCHING_ROUND_SCHEME,
            "pq_solver_attestation_scheme": PRIVATE_L2_FAST_PRIVATE_MATCHING_ENGINE_RUNTIME_PQ_SOLVER_ATTESTATION_SCHEME,
            "rebate_reservation_scheme": PRIVATE_L2_FAST_PRIVATE_MATCHING_ENGINE_RUNTIME_REBATE_RESERVATION_SCHEME,
            "settlement_receipt_scheme": PRIVATE_L2_FAST_PRIVATE_MATCHING_ENGINE_RUNTIME_SETTLEMENT_RECEIPT_SCHEME,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "current_height": self.current_height,
            "runtime_root": self.runtime_root,
            "rebate_budget_remaining_micro_units": self.rebate_budget_remaining_micro_units,
            "roots": self.roots().public_record(),
        })
    }

    pub fn public_record(&self) -> Value {
        let record = self.public_record_without_state_root();
        json!({
            "state_root": private_l2_fast_private_matching_engine_state_root_from_record(&record),
            "record": record,
        })
    }

    pub fn state_root(&self) -> String {
        private_l2_fast_private_matching_engine_state_root_from_record(
            &self.public_record_without_state_root(),
        )
    }

    fn publish_public_record(&mut self, record_kind: &str, subject_id: &str, payload: Value) {
        let record_id = public_record_id(record_kind, subject_id, &payload);
        self.public_records.insert(
            record_id,
            roots_only_payload(record_kind, subject_id, &payload),
        );
    }

    fn refresh_intent_records(&mut self, intent_ids: &[String]) {
        let updates = intent_ids
            .iter()
            .filter_map(|intent_id| {
                self.sealed_intents
                    .get(intent_id)
                    .map(|intent| (intent.intent_id.clone(), intent.public_record()))
            })
            .collect::<Vec<_>>();
        for (intent_id, record) in updates {
            self.publish_public_record("sealed_intent", &intent_id, record);
        }
    }

    fn refresh_attestation_records(&mut self, attestation_ids: &[String]) {
        let updates = attestation_ids
            .iter()
            .filter_map(|attestation_id| {
                self.solver_attestations
                    .get(attestation_id)
                    .map(|attestation| {
                        (
                            attestation.attestation_id.clone(),
                            attestation.public_record(),
                        )
                    })
            })
            .collect::<Vec<_>>();
        for (attestation_id, record) in updates {
            self.publish_public_record("solver_attestation", &attestation_id, record);
        }
    }

    fn refresh_reservation_records(&mut self, reservation_ids: &[String]) {
        let updates = reservation_ids
            .iter()
            .filter_map(|reservation_id| {
                self.rebate_reservations
                    .get(reservation_id)
                    .map(|reservation| {
                        (
                            reservation.reservation_id.clone(),
                            reservation.public_record(),
                        )
                    })
            })
            .collect::<Vec<_>>();
        for (reservation_id, record) in updates {
            self.publish_public_record("low_fee_rebate_reservation", &reservation_id, record);
        }
    }
}

pub fn private_l2_fast_private_matching_engine_payload_root(
    domain: &str,
    payload: &Value,
) -> String {
    domain_hash(
        domain,
        &[HashPart::Str(CHAIN_ID), HashPart::Json(payload)],
        32,
    )
}

pub fn private_l2_fast_private_matching_engine_state_root_from_record(record: &Value) -> String {
    private_l2_fast_private_matching_engine_payload_root(
        "PRIVATE-L2-FAST-PRIVATE-MATCHING-ENGINE-STATE",
        record,
    )
}

pub fn private_l2_fast_private_matching_engine_merkle_root(
    domain: &str,
    leaves: Vec<Value>,
) -> String {
    merkle_root(domain, &leaves)
}

pub fn sealed_intent_id(request: &SubmitSealedIntentRequest, nonce: u64) -> String {
    domain_hash(
        "PRIVATE-L2-FAST-PRIVATE-MATCHING-ENGINE-SEALED-INTENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(nonce as i128),
            HashPart::Str(request.intent_kind.as_str()),
            HashPart::Str(request.lane.as_str()),
            HashPart::Str(&request.account_commitment),
            HashPart::Str(&request.sealed_intent_root),
            HashPart::Str(&request.nullifier_root),
        ],
        32,
    )
}

pub fn solver_attestation_id(
    request: &RecordSolverAttestationRequest,
    score: u128,
    nonce: u64,
) -> String {
    let intent_root = private_l2_fast_private_matching_engine_merkle_root(
        "PRIVATE-L2-FAST-PRIVATE-MATCHING-ENGINE-SOLVER-ATTESTATION-ID-INTENT",
        request.intent_ids.iter().map(|id| json!(id)).collect(),
    );
    domain_hash(
        "PRIVATE-L2-FAST-PRIVATE-MATCHING-ENGINE-SOLVER-ATTESTATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(nonce as i128),
            HashPart::Str(&request.solver_id),
            HashPart::Str(&intent_root),
            HashPart::Str(&request.route_commitment_root),
            HashPart::Str(&request.pq_attestation_root),
            HashPart::Int(score as i128),
        ],
        32,
    )
}

pub fn low_fee_rebate_reservation_id(
    request: &ReserveLowFeeRebateRequest,
    nonce: u64,
    remaining_budget_micro_units: u64,
) -> String {
    let intent_root = private_l2_fast_private_matching_engine_merkle_root(
        "PRIVATE-L2-FAST-PRIVATE-MATCHING-ENGINE-REBATE-RESERVATION-ID-INTENT",
        request.intent_ids.iter().map(|id| json!(id)).collect(),
    );
    domain_hash(
        "PRIVATE-L2-FAST-PRIVATE-MATCHING-ENGINE-REBATE-RESERVATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(nonce as i128),
            HashPart::Str(&request.sponsor_commitment),
            HashPart::Str(&intent_root),
            HashPart::Str(&request.rebate_commitment_root),
            HashPart::Int(request.reserved_micro_units as i128),
            HashPart::Int(remaining_budget_micro_units as i128),
        ],
        32,
    )
}

pub fn matching_round_id(
    request: &BuildMatchingRoundRequest,
    selected_solver_attestation_id: &str,
    nonce: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-FAST-PRIVATE-MATCHING-ENGINE-MATCHING-ROUND-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(nonce as i128),
            HashPart::Str(&request.round_label),
            HashPart::Str(request.lane.as_str()),
            HashPart::Str(&request.aggregate_intent_root),
            HashPart::Str(&request.aggregate_solver_attestation_root),
            HashPart::Str(selected_solver_attestation_id),
            HashPart::Str(&request.clearing_price_root),
            HashPart::Int(request.built_at_height as i128),
        ],
        32,
    )
}

pub fn matching_batch_settlement_receipt_id(
    request: &SettleMatchingBatchRequest,
    nonce: u64,
    state_root_before: &str,
) -> String {
    domain_hash(
        "PRIVATE-L2-FAST-PRIVATE-MATCHING-ENGINE-SETTLEMENT-RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(nonce as i128),
            HashPart::Str(&request.matching_round_id),
            HashPart::Str(&request.settlement_tx_root),
            HashPart::Str(&request.settlement_proof_root),
            HashPart::Str(state_root_before),
            HashPart::Int(request.settled_at_height as i128),
        ],
        32,
    )
}

fn solver_attestation_score(request: &RecordSolverAttestationRequest) -> u128 {
    let surplus = request.expected_surplus_micro_units as u128;
    let solver_fee_penalty = request.solver_fee_bps as u128 * 1_000_000;
    surplus
        .saturating_mul(1_000_000)
        .saturating_sub(solver_fee_penalty)
}

fn solver_fee_micro_units(record: &MatchingRoundRecord) -> u64 {
    record
        .request
        .intent_ids
        .len()
        .saturating_mul(record.request.selected_solver_fee_bps as usize) as u64
}

fn covers_all(haystack: &[String], needles: &[String]) -> bool {
    let haystack = haystack.iter().collect::<BTreeSet<_>>();
    needles.iter().all(|needle| haystack.contains(needle))
}

fn public_record_id(record_kind: &str, subject_id: &str, payload: &Value) -> String {
    domain_hash(
        "PRIVATE-L2-FAST-PRIVATE-MATCHING-ENGINE-PUBLIC-RECORD-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(record_kind),
            HashPart::Str(subject_id),
            HashPart::Json(payload),
        ],
        32,
    )
}

fn roots_only_payload(record_kind: &str, subject_id: &str, payload: &Value) -> Value {
    json!({
        "kind": "private_l2_fast_private_matching_engine_roots_only_payload",
        "chain_id": CHAIN_ID,
        "record_kind": record_kind,
        "subject_id": subject_id,
        "payload_root": private_l2_fast_private_matching_engine_payload_root(
            "PRIVATE-L2-FAST-PRIVATE-MATCHING-ENGINE-ROOTS-ONLY-PAYLOAD",
            payload,
        ),
    })
}

fn require_non_empty(
    label: &str,
    value: &str,
) -> PrivateL2FastPrivateMatchingEngineRuntimeResult<()> {
    if value.is_empty() {
        return Err(format!("{label} cannot be empty"));
    }
    Ok(())
}

fn require_root(label: &str, value: &str) -> PrivateL2FastPrivateMatchingEngineRuntimeResult<()> {
    if value.len() < 32 || !value.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return Err(format!(
            "{label} must be a hex commitment/root of at least 32 chars"
        ));
    }
    Ok(())
}

fn ensure_eq(
    actual: &str,
    expected: &str,
    label: &str,
) -> PrivateL2FastPrivateMatchingEngineRuntimeResult<()> {
    if actual != expected {
        return Err(format!(
            "{label} mismatch: expected {expected}, got {actual}"
        ));
    }
    Ok(())
}
