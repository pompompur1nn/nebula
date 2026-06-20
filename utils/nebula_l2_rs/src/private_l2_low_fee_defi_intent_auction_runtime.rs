use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2LowFeeDefiIntentAuctionRuntimeResult<T> = Result<T, String>;

pub const PRIVATE_L2_LOW_FEE_DEFI_INTENT_AUCTION_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-low-fee-defi-intent-auction-runtime-v1";
pub const PRIVATE_L2_LOW_FEE_DEFI_INTENT_AUCTION_RUNTIME_SCHEMA_VERSION: u64 = 1;
pub const PRIVATE_L2_LOW_FEE_DEFI_INTENT_AUCTION_RUNTIME_HASH_SUITE: &str =
    "SHAKE256-domain-separated-canonical-json";
pub const PRIVATE_L2_LOW_FEE_DEFI_INTENT_AUCTION_RUNTIME_SEALED_INTENT_SCHEME: &str =
    "ml-kem-1024+zk-sealed-private-defi-intent-v1";
pub const PRIVATE_L2_LOW_FEE_DEFI_INTENT_AUCTION_RUNTIME_SOLVER_COMMITMENT_SCHEME: &str =
    "commit-reveal-private-defi-solver-route-v1";
pub const PRIVATE_L2_LOW_FEE_DEFI_INTENT_AUCTION_RUNTIME_CLEARING_SCHEME: &str =
    "batched-private-defi-intent-clearing-v1";
pub const PRIVATE_L2_LOW_FEE_DEFI_INTENT_AUCTION_RUNTIME_FEE_RESERVATION_SCHEME: &str =
    "roots-only-low-fee-rebate-sponsor-reservation-v1";
pub const PRIVATE_L2_LOW_FEE_DEFI_INTENT_AUCTION_RUNTIME_PQ_SOLVER_ATTESTATION_SCHEME: &str =
    "ml-dsa-87+slh-dsa-shake-256s-solver-attestation-v1";
pub const PRIVATE_L2_LOW_FEE_DEFI_INTENT_AUCTION_RUNTIME_SETTLEMENT_RECEIPT_SCHEME: &str =
    "zk-pq-private-defi-intent-settlement-receipt-v1";
pub const PRIVATE_L2_LOW_FEE_DEFI_INTENT_AUCTION_RUNTIME_DEVNET_HEIGHT: u64 = 411_000;
pub const PRIVATE_L2_LOW_FEE_DEFI_INTENT_AUCTION_RUNTIME_DEFAULT_AUCTION_WINDOW_BLOCKS: u64 = 5;
pub const PRIVATE_L2_LOW_FEE_DEFI_INTENT_AUCTION_RUNTIME_DEFAULT_INTENT_TTL_BLOCKS: u64 = 28;
pub const PRIVATE_L2_LOW_FEE_DEFI_INTENT_AUCTION_RUNTIME_DEFAULT_SETTLEMENT_TTL_BLOCKS: u64 = 14;
pub const PRIVATE_L2_LOW_FEE_DEFI_INTENT_AUCTION_RUNTIME_DEFAULT_MAX_INTENTS_PER_BATCH: usize =
    1_024;
pub const PRIVATE_L2_LOW_FEE_DEFI_INTENT_AUCTION_RUNTIME_DEFAULT_MAX_SOLVER_COMMITMENTS: usize =
    192;
pub const PRIVATE_L2_LOW_FEE_DEFI_INTENT_AUCTION_RUNTIME_DEFAULT_MAX_RESERVATIONS: usize = 1_024;
pub const PRIVATE_L2_LOW_FEE_DEFI_INTENT_AUCTION_RUNTIME_DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 128;
pub const PRIVATE_L2_LOW_FEE_DEFI_INTENT_AUCTION_RUNTIME_DEFAULT_BATCH_PRIVACY_SET_SIZE: u64 = 384;
pub const PRIVATE_L2_LOW_FEE_DEFI_INTENT_AUCTION_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const PRIVATE_L2_LOW_FEE_DEFI_INTENT_AUCTION_RUNTIME_DEFAULT_MAX_USER_FEE_BPS: u64 = 22;
pub const PRIVATE_L2_LOW_FEE_DEFI_INTENT_AUCTION_RUNTIME_DEFAULT_MAX_SOLVER_FEE_BPS: u64 = 26;
pub const PRIVATE_L2_LOW_FEE_DEFI_INTENT_AUCTION_RUNTIME_DEFAULT_MIN_REBATE_BPS: u64 = 4;
pub const PRIVATE_L2_LOW_FEE_DEFI_INTENT_AUCTION_RUNTIME_DEFAULT_MAX_REBATE_BPS: u64 = 18;
pub const PRIVATE_L2_LOW_FEE_DEFI_INTENT_AUCTION_RUNTIME_DEFAULT_SPONSOR_BUDGET_MICRO_UNITS: u64 =
    125_000_000;
pub const PRIVATE_L2_LOW_FEE_DEFI_INTENT_AUCTION_RUNTIME_MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DefiIntentKind {
    SwapExactIn,
    SwapExactOut,
    LimitSwap,
    DarkpoolCross,
    VaultDeposit,
    VaultWithdraw,
    LendingBorrow,
    LendingRepay,
    PerpOpen,
    PerpClose,
    CrossMarginRebalance,
    LiquidityProvision,
}

impl DefiIntentKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SwapExactIn => "swap_exact_in",
            Self::SwapExactOut => "swap_exact_out",
            Self::LimitSwap => "limit_swap",
            Self::DarkpoolCross => "darkpool_cross",
            Self::VaultDeposit => "vault_deposit",
            Self::VaultWithdraw => "vault_withdraw",
            Self::LendingBorrow => "lending_borrow",
            Self::LendingRepay => "lending_repay",
            Self::PerpOpen => "perp_open",
            Self::PerpClose => "perp_close",
            Self::CrossMarginRebalance => "cross_margin_rebalance",
            Self::LiquidityProvision => "liquidity_provision",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DefiVenue {
    PrivateAmm,
    Darkpool,
    IntentRfQ,
    LendingPool,
    Perps,
    Vault,
    InternalNetting,
}

impl DefiVenue {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrivateAmm => "private_amm",
            Self::Darkpool => "darkpool",
            Self::IntentRfQ => "intent_rfq",
            Self::LendingPool => "lending_pool",
            Self::Perps => "perps",
            Self::Vault => "vault",
            Self::InternalNetting => "internal_netting",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentStatus {
    Submitted,
    SolverCommitted,
    Reserved,
    Batched,
    Settled,
    Rejected,
    Expired,
}

impl IntentStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::SolverCommitted => "solver_committed",
            Self::Reserved => "reserved",
            Self::Batched => "batched",
            Self::Settled => "settled",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }

    pub fn batchable(self) -> bool {
        matches!(
            self,
            Self::Submitted | Self::SolverCommitted | Self::Reserved
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SolverCommitmentStatus {
    Committed,
    Selected,
    Settled,
    Rejected,
    Expired,
}

impl SolverCommitmentStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Committed => "committed",
            Self::Selected => "selected",
            Self::Settled => "settled",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReservationStatus {
    Reserved,
    Consumed,
    Released,
    Expired,
}

impl ReservationStatus {
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
pub enum ClearingStatus {
    Built,
    SettlementReady,
    Settled,
    Disputed,
    Expired,
}

impl ClearingStatus {
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
    pub solver_commitment_scheme: String,
    pub clearing_scheme: String,
    pub fee_reservation_scheme: String,
    pub pq_solver_attestation_scheme: String,
    pub settlement_receipt_scheme: String,
    pub auction_window_blocks: u64,
    pub intent_ttl_blocks: u64,
    pub settlement_ttl_blocks: u64,
    pub max_intents_per_batch: usize,
    pub max_solver_commitments: usize,
    pub max_reservations: usize,
    pub min_privacy_set_size: u64,
    pub batch_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub max_user_fee_bps: u64,
    pub max_solver_fee_bps: u64,
    pub min_rebate_bps: u64,
    pub max_rebate_bps: u64,
    pub sponsor_budget_micro_units: u64,
    pub require_pq_solver_attestations: bool,
    pub require_private_intents: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version: PRIVATE_L2_LOW_FEE_DEFI_INTENT_AUCTION_RUNTIME_PROTOCOL_VERSION
                .to_string(),
            schema_version: PRIVATE_L2_LOW_FEE_DEFI_INTENT_AUCTION_RUNTIME_SCHEMA_VERSION,
            chain_id: CHAIN_ID.to_string(),
            hash_suite: PRIVATE_L2_LOW_FEE_DEFI_INTENT_AUCTION_RUNTIME_HASH_SUITE.to_string(),
            sealed_intent_scheme:
                PRIVATE_L2_LOW_FEE_DEFI_INTENT_AUCTION_RUNTIME_SEALED_INTENT_SCHEME.to_string(),
            solver_commitment_scheme:
                PRIVATE_L2_LOW_FEE_DEFI_INTENT_AUCTION_RUNTIME_SOLVER_COMMITMENT_SCHEME.to_string(),
            clearing_scheme: PRIVATE_L2_LOW_FEE_DEFI_INTENT_AUCTION_RUNTIME_CLEARING_SCHEME
                .to_string(),
            fee_reservation_scheme:
                PRIVATE_L2_LOW_FEE_DEFI_INTENT_AUCTION_RUNTIME_FEE_RESERVATION_SCHEME.to_string(),
            pq_solver_attestation_scheme:
                PRIVATE_L2_LOW_FEE_DEFI_INTENT_AUCTION_RUNTIME_PQ_SOLVER_ATTESTATION_SCHEME
                    .to_string(),
            settlement_receipt_scheme:
                PRIVATE_L2_LOW_FEE_DEFI_INTENT_AUCTION_RUNTIME_SETTLEMENT_RECEIPT_SCHEME.to_string(),
            auction_window_blocks:
                PRIVATE_L2_LOW_FEE_DEFI_INTENT_AUCTION_RUNTIME_DEFAULT_AUCTION_WINDOW_BLOCKS,
            intent_ttl_blocks:
                PRIVATE_L2_LOW_FEE_DEFI_INTENT_AUCTION_RUNTIME_DEFAULT_INTENT_TTL_BLOCKS,
            settlement_ttl_blocks:
                PRIVATE_L2_LOW_FEE_DEFI_INTENT_AUCTION_RUNTIME_DEFAULT_SETTLEMENT_TTL_BLOCKS,
            max_intents_per_batch:
                PRIVATE_L2_LOW_FEE_DEFI_INTENT_AUCTION_RUNTIME_DEFAULT_MAX_INTENTS_PER_BATCH,
            max_solver_commitments:
                PRIVATE_L2_LOW_FEE_DEFI_INTENT_AUCTION_RUNTIME_DEFAULT_MAX_SOLVER_COMMITMENTS,
            max_reservations:
                PRIVATE_L2_LOW_FEE_DEFI_INTENT_AUCTION_RUNTIME_DEFAULT_MAX_RESERVATIONS,
            min_privacy_set_size:
                PRIVATE_L2_LOW_FEE_DEFI_INTENT_AUCTION_RUNTIME_DEFAULT_MIN_PRIVACY_SET_SIZE,
            batch_privacy_set_size:
                PRIVATE_L2_LOW_FEE_DEFI_INTENT_AUCTION_RUNTIME_DEFAULT_BATCH_PRIVACY_SET_SIZE,
            min_pq_security_bits:
                PRIVATE_L2_LOW_FEE_DEFI_INTENT_AUCTION_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS,
            max_user_fee_bps:
                PRIVATE_L2_LOW_FEE_DEFI_INTENT_AUCTION_RUNTIME_DEFAULT_MAX_USER_FEE_BPS,
            max_solver_fee_bps:
                PRIVATE_L2_LOW_FEE_DEFI_INTENT_AUCTION_RUNTIME_DEFAULT_MAX_SOLVER_FEE_BPS,
            min_rebate_bps: PRIVATE_L2_LOW_FEE_DEFI_INTENT_AUCTION_RUNTIME_DEFAULT_MIN_REBATE_BPS,
            max_rebate_bps: PRIVATE_L2_LOW_FEE_DEFI_INTENT_AUCTION_RUNTIME_DEFAULT_MAX_REBATE_BPS,
            sponsor_budget_micro_units:
                PRIVATE_L2_LOW_FEE_DEFI_INTENT_AUCTION_RUNTIME_DEFAULT_SPONSOR_BUDGET_MICRO_UNITS,
            require_pq_solver_attestations: true,
            require_private_intents: true,
        }
    }

    pub fn validate(&self) -> PrivateL2LowFeeDefiIntentAuctionRuntimeResult<()> {
        ensure_eq(&self.chain_id, CHAIN_ID, "low-fee DeFi auction chain id")?;
        ensure_eq(
            &self.protocol_version,
            PRIVATE_L2_LOW_FEE_DEFI_INTENT_AUCTION_RUNTIME_PROTOCOL_VERSION,
            "low-fee DeFi auction protocol version",
        )?;
        if self.schema_version != PRIVATE_L2_LOW_FEE_DEFI_INTENT_AUCTION_RUNTIME_SCHEMA_VERSION {
            return Err("low-fee DeFi auction schema version mismatch".to_string());
        }
        if self.auction_window_blocks == 0
            || self.intent_ttl_blocks == 0
            || self.settlement_ttl_blocks == 0
            || self.max_intents_per_batch == 0
            || self.max_solver_commitments == 0
            || self.max_reservations == 0
        {
            return Err("low-fee DeFi auction windows and capacities must be positive".to_string());
        }
        if self.min_privacy_set_size == 0 || self.batch_privacy_set_size < self.min_privacy_set_size
        {
            return Err("batch privacy set must cover private intent privacy set".to_string());
        }
        if self.min_pq_security_bits < 192 {
            return Err("solver PQ attestation security bits below minimum".to_string());
        }
        if self.max_user_fee_bps > PRIVATE_L2_LOW_FEE_DEFI_INTENT_AUCTION_RUNTIME_MAX_BPS
            || self.max_solver_fee_bps > PRIVATE_L2_LOW_FEE_DEFI_INTENT_AUCTION_RUNTIME_MAX_BPS
            || self.min_rebate_bps > self.max_rebate_bps
            || self.max_rebate_bps > self.max_user_fee_bps
        {
            return Err("low-fee DeFi auction bps configuration is invalid".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_low_fee_defi_intent_auction_config",
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "chain_id": self.chain_id,
            "hash_suite": self.hash_suite,
            "sealed_intent_scheme": self.sealed_intent_scheme,
            "solver_commitment_scheme": self.solver_commitment_scheme,
            "clearing_scheme": self.clearing_scheme,
            "fee_reservation_scheme": self.fee_reservation_scheme,
            "pq_solver_attestation_scheme": self.pq_solver_attestation_scheme,
            "settlement_receipt_scheme": self.settlement_receipt_scheme,
            "auction_window_blocks": self.auction_window_blocks,
            "intent_ttl_blocks": self.intent_ttl_blocks,
            "settlement_ttl_blocks": self.settlement_ttl_blocks,
            "max_intents_per_batch": self.max_intents_per_batch,
            "max_solver_commitments": self.max_solver_commitments,
            "max_reservations": self.max_reservations,
            "min_privacy_set_size": self.min_privacy_set_size,
            "batch_privacy_set_size": self.batch_privacy_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
            "max_user_fee_bps": self.max_user_fee_bps,
            "max_solver_fee_bps": self.max_solver_fee_bps,
            "min_rebate_bps": self.min_rebate_bps,
            "max_rebate_bps": self.max_rebate_bps,
            "sponsor_budget_micro_units": self.sponsor_budget_micro_units,
            "require_pq_solver_attestations": self.require_pq_solver_attestations,
            "require_private_intents": self.require_private_intents,
        })
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    pub next_intent_nonce: u64,
    pub next_solver_commitment_nonce: u64,
    pub next_reservation_nonce: u64,
    pub next_clearing_nonce: u64,
    pub next_receipt_nonce: u64,
    pub private_intents_submitted: u64,
    pub solver_commitments_recorded: u64,
    pub fee_reservations_recorded: u64,
    pub clearing_batches_built: u64,
    pub settlement_receipts_published: u64,
    pub intents_settled: u64,
    pub rebates_reserved_micro_units: u64,
    pub rebates_consumed_micro_units: u64,
    pub solver_fees_micro_units: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_low_fee_defi_intent_auction_counters",
            "next_intent_nonce": self.next_intent_nonce,
            "next_solver_commitment_nonce": self.next_solver_commitment_nonce,
            "next_reservation_nonce": self.next_reservation_nonce,
            "next_clearing_nonce": self.next_clearing_nonce,
            "next_receipt_nonce": self.next_receipt_nonce,
            "private_intents_submitted": self.private_intents_submitted,
            "solver_commitments_recorded": self.solver_commitments_recorded,
            "fee_reservations_recorded": self.fee_reservations_recorded,
            "clearing_batches_built": self.clearing_batches_built,
            "settlement_receipts_published": self.settlement_receipts_published,
            "intents_settled": self.intents_settled,
            "rebates_reserved_micro_units": self.rebates_reserved_micro_units,
            "rebates_consumed_micro_units": self.rebates_consumed_micro_units,
            "solver_fees_micro_units": self.solver_fees_micro_units,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubmitPrivateIntentRequest {
    pub intent_kind: DefiIntentKind,
    pub venue: DefiVenue,
    pub account_commitment: String,
    pub sealed_intent_root: String,
    pub encrypted_payload_root: String,
    pub asset_pair_root: String,
    pub amount_commitment_root: String,
    pub price_limit_commitment_root: String,
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

impl SubmitPrivateIntentRequest {
    pub fn validate(&self, config: &Config) -> PrivateL2LowFeeDefiIntentAuctionRuntimeResult<()> {
        require_root("account commitment", &self.account_commitment)?;
        require_root("sealed intent root", &self.sealed_intent_root)?;
        require_root("encrypted payload root", &self.encrypted_payload_root)?;
        require_root("asset pair root", &self.asset_pair_root)?;
        require_root("amount commitment root", &self.amount_commitment_root)?;
        require_root(
            "price limit commitment root",
            &self.price_limit_commitment_root,
        )?;
        require_root("nullifier root", &self.nullifier_root)?;
        require_root("refund commitment root", &self.refund_commitment_root)?;
        require_root("PQ authorization root", &self.pq_authorization_root)?;
        if self.max_user_fee_bps > config.max_user_fee_bps {
            return Err("private intent fee cap exceeds low-fee runtime maximum".to_string());
        }
        if self.requested_rebate_bps < config.min_rebate_bps
            || self.requested_rebate_bps > config.max_rebate_bps
        {
            return Err("private intent requested rebate is outside configured bounds".to_string());
        }
        if self.privacy_set_size < config.min_privacy_set_size {
            return Err("private intent privacy set is below runtime minimum".to_string());
        }
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err("private intent PQ authorization security bits below minimum".to_string());
        }
        if self.expires_at_height <= self.submitted_at_height
            || self.expires_at_height
                > self
                    .submitted_at_height
                    .saturating_add(config.intent_ttl_blocks)
        {
            return Err("private intent expiry must be live and within TTL".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SolverCommitmentRequest {
    pub intent_ids: Vec<String>,
    pub solver_id: String,
    pub route_commitment_root: String,
    pub clearing_price_root: String,
    pub solver_fee_bps: u64,
    pub expected_surplus_micro_units: u64,
    pub pq_attestation_root: String,
    pub pq_security_bits: u16,
    pub bond_commitment_root: String,
    pub committed_at_height: u64,
    pub expires_at_height: u64,
}

impl SolverCommitmentRequest {
    pub fn validate(&self, config: &Config) -> PrivateL2LowFeeDefiIntentAuctionRuntimeResult<()> {
        if self.intent_ids.is_empty() {
            return Err("solver commitment must target at least one private intent".to_string());
        }
        require_non_empty("solver id", &self.solver_id)?;
        require_root("route commitment root", &self.route_commitment_root)?;
        require_root("clearing price root", &self.clearing_price_root)?;
        require_root("PQ solver attestation root", &self.pq_attestation_root)?;
        require_root("solver bond commitment root", &self.bond_commitment_root)?;
        if self.solver_fee_bps > config.max_solver_fee_bps {
            return Err("solver commitment fee exceeds runtime cap".to_string());
        }
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err("solver PQ attestation security bits below minimum".to_string());
        }
        if self.expires_at_height <= self.committed_at_height {
            return Err("solver commitment expiry must be after commitment height".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReserveFeeSponsorRequest {
    pub intent_ids: Vec<String>,
    pub sponsor_commitment: String,
    pub budget_root: String,
    pub rebate_commitment_root: String,
    pub reserved_rebate_bps: u64,
    pub reserved_micro_units: u64,
    pub pq_reservation_root: String,
    pub reserved_at_height: u64,
    pub expires_at_height: u64,
}

impl ReserveFeeSponsorRequest {
    pub fn validate(&self, config: &Config) -> PrivateL2LowFeeDefiIntentAuctionRuntimeResult<()> {
        if self.intent_ids.is_empty() {
            return Err("fee sponsor reservation must target at least one intent".to_string());
        }
        require_root("sponsor commitment", &self.sponsor_commitment)?;
        require_root("sponsor budget root", &self.budget_root)?;
        require_root("rebate commitment root", &self.rebate_commitment_root)?;
        require_root("PQ reservation root", &self.pq_reservation_root)?;
        if self.reserved_rebate_bps < config.min_rebate_bps
            || self.reserved_rebate_bps > config.max_rebate_bps
        {
            return Err("reserved rebate bps outside runtime bounds".to_string());
        }
        if self.reserved_micro_units == 0 {
            return Err("reserved sponsor amount must be positive".to_string());
        }
        if self.expires_at_height <= self.reserved_at_height {
            return Err(
                "fee sponsor reservation expiry must be after reservation height".to_string(),
            );
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BuildClearingBatchRequest {
    pub batch_label: String,
    pub intent_ids: Vec<String>,
    pub solver_commitment_ids: Vec<String>,
    pub reservation_ids: Vec<String>,
    pub aggregate_intent_root: String,
    pub aggregate_solver_commitment_root: String,
    pub aggregate_rebate_reservation_root: String,
    pub aggregate_pq_attestation_root: String,
    pub clearing_price_root: String,
    pub output_commitment_root: String,
    pub solver_payment_root: String,
    pub rebate_distribution_root: String,
    pub recursive_proof_root: String,
    pub max_user_fee_bps: u64,
    pub selected_solver_fee_bps: u64,
    pub selected_rebate_bps: u64,
    pub privacy_set_size: u64,
    pub built_at_height: u64,
}

impl BuildClearingBatchRequest {
    pub fn validate(&self, config: &Config) -> PrivateL2LowFeeDefiIntentAuctionRuntimeResult<()> {
        if self.intent_ids.is_empty() {
            return Err("clearing batch must include at least one private intent".to_string());
        }
        if self.intent_ids.len() > config.max_intents_per_batch {
            return Err("clearing batch exceeds max intent count".to_string());
        }
        if self.solver_commitment_ids.is_empty() {
            return Err("clearing batch requires at least one solver commitment".to_string());
        }
        if self.solver_commitment_ids.len() > config.max_solver_commitments {
            return Err("clearing batch exceeds max solver commitment count".to_string());
        }
        require_non_empty("batch label", &self.batch_label)?;
        require_root("aggregate intent root", &self.aggregate_intent_root)?;
        require_root(
            "aggregate solver commitment root",
            &self.aggregate_solver_commitment_root,
        )?;
        require_root(
            "aggregate rebate reservation root",
            &self.aggregate_rebate_reservation_root,
        )?;
        require_root(
            "aggregate PQ attestation root",
            &self.aggregate_pq_attestation_root,
        )?;
        require_root("clearing price root", &self.clearing_price_root)?;
        require_root("output commitment root", &self.output_commitment_root)?;
        require_root("solver payment root", &self.solver_payment_root)?;
        require_root("rebate distribution root", &self.rebate_distribution_root)?;
        require_root("recursive proof root", &self.recursive_proof_root)?;
        if self.max_user_fee_bps > config.max_user_fee_bps
            || self.selected_solver_fee_bps > config.max_solver_fee_bps
            || self.selected_rebate_bps < config.min_rebate_bps
            || self.selected_rebate_bps > config.max_rebate_bps
        {
            return Err("clearing batch fee or rebate bps outside runtime bounds".to_string());
        }
        if self.privacy_set_size < config.batch_privacy_set_size {
            return Err("clearing batch privacy set below runtime batch target".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettleClearingBatchRequest {
    pub clearing_batch_id: String,
    pub settlement_tx_root: String,
    pub settlement_proof_root: String,
    pub spent_nullifier_root: String,
    pub output_commitment_root: String,
    pub solver_payment_root: String,
    pub rebate_distribution_root: String,
    pub runtime_state_root_after: String,
    pub settled_at_height: u64,
    pub finalized_at_height: Option<u64>,
}

impl SettleClearingBatchRequest {
    pub fn validate(&self) -> PrivateL2LowFeeDefiIntentAuctionRuntimeResult<()> {
        require_root("clearing batch id", &self.clearing_batch_id)?;
        require_root("settlement tx root", &self.settlement_tx_root)?;
        require_root("settlement proof root", &self.settlement_proof_root)?;
        require_root("spent nullifier root", &self.spent_nullifier_root)?;
        require_root("output commitment root", &self.output_commitment_root)?;
        require_root("solver payment root", &self.solver_payment_root)?;
        require_root("rebate distribution root", &self.rebate_distribution_root)?;
        require_root("runtime state root after", &self.runtime_state_root_after)?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateIntentRecord {
    pub intent_id: String,
    pub request: SubmitPrivateIntentRequest,
    pub status: IntentStatus,
    pub solver_commitment_id: Option<String>,
    pub fee_reservation_id: Option<String>,
    pub clearing_batch_id: Option<String>,
}

impl PrivateIntentRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_low_fee_defi_intent",
            "intent_id": self.intent_id,
            "status": self.status.as_str(),
            "request": self.request,
            "solver_commitment_id": self.solver_commitment_id,
            "fee_reservation_id": self.fee_reservation_id,
            "clearing_batch_id": self.clearing_batch_id,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SolverCommitmentRecord {
    pub commitment_id: String,
    pub request: SolverCommitmentRequest,
    pub score: u128,
    pub status: SolverCommitmentStatus,
}

impl SolverCommitmentRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_low_fee_defi_solver_commitment",
            "commitment_id": self.commitment_id,
            "request": self.request,
            "score": self.score.to_string(),
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeeSponsorReservationRecord {
    pub reservation_id: String,
    pub request: ReserveFeeSponsorRequest,
    pub status: ReservationStatus,
}

impl FeeSponsorReservationRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_low_fee_defi_fee_sponsor_reservation",
            "reservation_id": self.reservation_id,
            "request": self.request,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClearingBatchRecord {
    pub clearing_batch_id: String,
    pub request: BuildClearingBatchRequest,
    pub selected_solver_commitment_id: String,
    pub settlement_deadline_height: u64,
    pub status: ClearingStatus,
    pub settlement_receipt_id: Option<String>,
}

impl ClearingBatchRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_low_fee_defi_clearing_batch",
            "clearing_batch_id": self.clearing_batch_id,
            "request": self.request,
            "selected_solver_commitment_id": self.selected_solver_commitment_id,
            "settlement_deadline_height": self.settlement_deadline_height,
            "status": self.status.as_str(),
            "settlement_receipt_id": self.settlement_receipt_id,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementReceiptRecord {
    pub receipt_id: String,
    pub clearing_batch_id: String,
    pub status: ReceiptStatus,
    pub settlement_tx_root: String,
    pub settlement_proof_root: String,
    pub spent_nullifier_root: String,
    pub output_commitment_root: String,
    pub solver_payment_root: String,
    pub rebate_distribution_root: String,
    pub state_root_before: String,
    pub state_root_after: String,
    pub runtime_state_root_after: String,
    pub settled_at_height: u64,
    pub finalized_at_height: Option<u64>,
}

impl SettlementReceiptRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_low_fee_defi_settlement_receipt",
            "receipt_id": self.receipt_id,
            "clearing_batch_id": self.clearing_batch_id,
            "status": self.status.as_str(),
            "settlement_tx_root": self.settlement_tx_root,
            "settlement_proof_root": self.settlement_proof_root,
            "spent_nullifier_root": self.spent_nullifier_root,
            "output_commitment_root": self.output_commitment_root,
            "solver_payment_root": self.solver_payment_root,
            "rebate_distribution_root": self.rebate_distribution_root,
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
    pub private_intent_root: String,
    pub solver_commitment_root: String,
    pub fee_reservation_root: String,
    pub clearing_batch_root: String,
    pub settlement_receipt_root: String,
    pub consumed_nullifier_root: String,
    pub public_record_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "private_intent_root": self.private_intent_root,
            "solver_commitment_root": self.solver_commitment_root,
            "fee_reservation_root": self.fee_reservation_root,
            "clearing_batch_root": self.clearing_batch_root,
            "settlement_receipt_root": self.settlement_receipt_root,
            "consumed_nullifier_root": self.consumed_nullifier_root,
            "public_record_root": self.public_record_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateL2LowFeeDefiIntentAuctionRuntime {
    pub config: Config,
    pub counters: Counters,
    pub current_height: u64,
    pub sponsor_budget_remaining_micro_units: u64,
    pub runtime_root: String,
    pub private_intents: BTreeMap<String, PrivateIntentRecord>,
    pub solver_commitments: BTreeMap<String, SolverCommitmentRecord>,
    pub fee_reservations: BTreeMap<String, FeeSponsorReservationRecord>,
    pub clearing_batches: BTreeMap<String, ClearingBatchRecord>,
    pub settlement_receipts: BTreeMap<String, SettlementReceiptRecord>,
    pub consumed_nullifier_roots: BTreeSet<String>,
    pub public_records: BTreeMap<String, Value>,
}

impl PrivateL2LowFeeDefiIntentAuctionRuntime {
    pub fn devnet() -> PrivateL2LowFeeDefiIntentAuctionRuntimeResult<Self> {
        let config = Config::devnet();
        config.validate()?;
        let mut runtime = Self {
            sponsor_budget_remaining_micro_units: config.sponsor_budget_micro_units,
            config,
            counters: Counters::default(),
            current_height: PRIVATE_L2_LOW_FEE_DEFI_INTENT_AUCTION_RUNTIME_DEVNET_HEIGHT,
            runtime_root: private_l2_low_fee_defi_intent_auction_payload_root(
                "PRIVATE-L2-LOW-FEE-DEFI-INTENT-AUCTION-DEVNET-RUNTIME",
                &json!({ "chain_id": CHAIN_ID }),
            ),
            private_intents: BTreeMap::new(),
            solver_commitments: BTreeMap::new(),
            fee_reservations: BTreeMap::new(),
            clearing_batches: BTreeMap::new(),
            settlement_receipts: BTreeMap::new(),
            consumed_nullifier_roots: BTreeSet::new(),
            public_records: BTreeMap::new(),
        };
        runtime.publish_public_record("config", "devnet", runtime.config.public_record());
        Ok(runtime)
    }

    pub fn submit_private_intent(
        &mut self,
        request: SubmitPrivateIntentRequest,
    ) -> PrivateL2LowFeeDefiIntentAuctionRuntimeResult<PrivateIntentRecord> {
        self.config.validate()?;
        request.validate(&self.config)?;
        if self.private_intents.len() >= self.config.max_intents_per_batch {
            return Err("private intent devnet queue is full".to_string());
        }
        if request.submitted_at_height < self.current_height {
            return Err("private intent cannot be submitted before runtime height".to_string());
        }
        if !self
            .consumed_nullifier_roots
            .insert(request.nullifier_root.clone())
        {
            return Err("private intent nullifier root already seen".to_string());
        }
        let intent_id = private_intent_id(&request, self.counters.next_intent_nonce);
        let record = PrivateIntentRecord {
            intent_id: intent_id.clone(),
            request,
            status: IntentStatus::Submitted,
            solver_commitment_id: None,
            fee_reservation_id: None,
            clearing_batch_id: None,
        };
        self.current_height = self.current_height.max(record.request.submitted_at_height);
        self.counters.next_intent_nonce = self.counters.next_intent_nonce.saturating_add(1);
        self.counters.private_intents_submitted =
            self.counters.private_intents_submitted.saturating_add(1);
        self.private_intents
            .insert(intent_id.clone(), record.clone());
        self.publish_public_record("private_intent", &intent_id, record.public_record());
        Ok(record)
    }

    pub fn record_solver_commitment(
        &mut self,
        request: SolverCommitmentRequest,
    ) -> PrivateL2LowFeeDefiIntentAuctionRuntimeResult<SolverCommitmentRecord> {
        self.config.validate()?;
        request.validate(&self.config)?;
        if self.solver_commitments.len() >= self.config.max_solver_commitments {
            return Err("solver commitment store is full".to_string());
        }
        let unique_intents = request.intent_ids.iter().collect::<BTreeSet<_>>();
        if unique_intents.len() != request.intent_ids.len() {
            return Err("solver commitment contains duplicate private intent ids".to_string());
        }
        for intent_id in &request.intent_ids {
            let intent = self.private_intents.get(intent_id).ok_or_else(|| {
                format!("solver commitment references unknown intent {intent_id}")
            })?;
            if !intent.status.batchable() {
                return Err(format!(
                    "private intent is not solver-committable: {intent_id}"
                ));
            }
            if intent.request.expires_at_height <= request.committed_at_height {
                return Err(format!(
                    "private intent expired before solver commit: {intent_id}"
                ));
            }
        }
        let score = solver_score(&request);
        let commitment_id =
            solver_commitment_id(&request, score, self.counters.next_solver_commitment_nonce);
        for intent_id in &request.intent_ids {
            if let Some(intent) = self.private_intents.get_mut(intent_id) {
                intent.status = IntentStatus::SolverCommitted;
                intent.solver_commitment_id = Some(commitment_id.clone());
            }
        }
        let record = SolverCommitmentRecord {
            commitment_id: commitment_id.clone(),
            request,
            score,
            status: SolverCommitmentStatus::Committed,
        };
        self.current_height = self.current_height.max(record.request.committed_at_height);
        self.counters.next_solver_commitment_nonce =
            self.counters.next_solver_commitment_nonce.saturating_add(1);
        self.counters.solver_commitments_recorded =
            self.counters.solver_commitments_recorded.saturating_add(1);
        self.solver_commitments
            .insert(commitment_id.clone(), record.clone());
        self.refresh_intent_records(&record.request.intent_ids);
        self.publish_public_record("solver_commitment", &commitment_id, record.public_record());
        Ok(record)
    }

    pub fn reserve_fee_sponsor(
        &mut self,
        request: ReserveFeeSponsorRequest,
    ) -> PrivateL2LowFeeDefiIntentAuctionRuntimeResult<FeeSponsorReservationRecord> {
        self.config.validate()?;
        request.validate(&self.config)?;
        if self.fee_reservations.len() >= self.config.max_reservations {
            return Err("fee sponsor reservation store is full".to_string());
        }
        if request.reserved_micro_units > self.sponsor_budget_remaining_micro_units {
            return Err("fee sponsor reservation exceeds remaining devnet budget".to_string());
        }
        let unique_intents = request.intent_ids.iter().collect::<BTreeSet<_>>();
        if unique_intents.len() != request.intent_ids.len() {
            return Err(
                "fee sponsor reservation contains duplicate private intent ids".to_string(),
            );
        }
        for intent_id in &request.intent_ids {
            let intent = self
                .private_intents
                .get(intent_id)
                .ok_or_else(|| format!("fee sponsor references unknown intent {intent_id}"))?;
            if !intent.status.batchable() {
                return Err(format!("private intent is not fee-reservable: {intent_id}"));
            }
            if request.reserved_rebate_bps < intent.request.requested_rebate_bps {
                return Err(format!(
                    "fee sponsor rebate is below intent request: {intent_id}"
                ));
            }
        }
        let reservation_id = fee_sponsor_reservation_id(
            &request,
            self.counters.next_reservation_nonce,
            self.sponsor_budget_remaining_micro_units,
        );
        for intent_id in &request.intent_ids {
            if let Some(intent) = self.private_intents.get_mut(intent_id) {
                intent.status = IntentStatus::Reserved;
                intent.fee_reservation_id = Some(reservation_id.clone());
            }
        }
        self.sponsor_budget_remaining_micro_units = self
            .sponsor_budget_remaining_micro_units
            .saturating_sub(request.reserved_micro_units);
        self.counters.next_reservation_nonce =
            self.counters.next_reservation_nonce.saturating_add(1);
        self.counters.fee_reservations_recorded =
            self.counters.fee_reservations_recorded.saturating_add(1);
        self.counters.rebates_reserved_micro_units = self
            .counters
            .rebates_reserved_micro_units
            .saturating_add(request.reserved_micro_units);
        let record = FeeSponsorReservationRecord {
            reservation_id: reservation_id.clone(),
            request,
            status: ReservationStatus::Reserved,
        };
        self.current_height = self.current_height.max(record.request.reserved_at_height);
        self.fee_reservations
            .insert(reservation_id.clone(), record.clone());
        self.refresh_intent_records(&record.request.intent_ids);
        self.publish_public_record(
            "fee_sponsor_reservation",
            &reservation_id,
            record.public_record(),
        );
        Ok(record)
    }

    pub fn build_clearing_batch(
        &mut self,
        request: BuildClearingBatchRequest,
    ) -> PrivateL2LowFeeDefiIntentAuctionRuntimeResult<ClearingBatchRecord> {
        self.config.validate()?;
        request.validate(&self.config)?;
        let unique_intents = request.intent_ids.iter().collect::<BTreeSet<_>>();
        if unique_intents.len() != request.intent_ids.len() {
            return Err("clearing batch contains duplicate private intent ids".to_string());
        }
        for intent_id in &request.intent_ids {
            let intent = self
                .private_intents
                .get(intent_id)
                .ok_or_else(|| format!("clearing batch references unknown intent {intent_id}"))?;
            if !intent.status.batchable() {
                return Err(format!("private intent is not batchable: {intent_id}"));
            }
            if intent.request.expires_at_height <= request.built_at_height {
                return Err(format!(
                    "private intent expired before clearing: {intent_id}"
                ));
            }
            if intent.request.max_user_fee_bps < request.max_user_fee_bps {
                return Err(format!("clearing fee exceeds intent cap: {intent_id}"));
            }
            if intent.request.requested_rebate_bps > request.selected_rebate_bps {
                return Err(format!(
                    "clearing rebate is below intent request: {intent_id}"
                ));
            }
        }
        let mut selected_solver = None;
        for commitment_id in &request.solver_commitment_ids {
            let commitment = self
                .solver_commitments
                .get(commitment_id)
                .ok_or_else(|| format!("clearing references unknown solver {commitment_id}"))?;
            if commitment.status != SolverCommitmentStatus::Committed {
                return Err(format!(
                    "solver commitment is not committed: {commitment_id}"
                ));
            }
            if commitment.request.expires_at_height <= request.built_at_height {
                return Err(format!(
                    "solver commitment expired before clearing: {commitment_id}"
                ));
            }
            if !covers_all(&commitment.request.intent_ids, &request.intent_ids) {
                return Err(format!(
                    "solver commitment does not cover all clearing intents: {commitment_id}"
                ));
            }
            selected_solver = match selected_solver {
                Some((_, best_score)) if best_score >= commitment.score => selected_solver,
                _ => Some((commitment_id.clone(), commitment.score)),
            };
        }
        for reservation_id in &request.reservation_ids {
            let reservation = self.fee_reservations.get(reservation_id).ok_or_else(|| {
                format!("clearing references unknown reservation {reservation_id}")
            })?;
            if reservation.status != ReservationStatus::Reserved {
                return Err(format!("fee reservation is not reserved: {reservation_id}"));
            }
            if reservation.request.expires_at_height <= request.built_at_height {
                return Err(format!(
                    "fee reservation expired before clearing: {reservation_id}"
                ));
            }
        }
        let selected_solver_commitment_id = selected_solver
            .map(|(commitment_id, _)| commitment_id)
            .ok_or_else(|| "clearing batch requires a selected solver".to_string())?;
        let clearing_batch_id = clearing_batch_id(
            &request,
            &selected_solver_commitment_id,
            self.counters.next_clearing_nonce,
        );
        for intent_id in &request.intent_ids {
            if let Some(intent) = self.private_intents.get_mut(intent_id) {
                intent.status = IntentStatus::Batched;
                intent.clearing_batch_id = Some(clearing_batch_id.clone());
            }
        }
        for commitment_id in &request.solver_commitment_ids {
            if let Some(commitment) = self.solver_commitments.get_mut(commitment_id) {
                commitment.status = if *commitment_id == selected_solver_commitment_id {
                    SolverCommitmentStatus::Selected
                } else {
                    SolverCommitmentStatus::Rejected
                };
            }
        }
        let settlement_deadline_height = request
            .built_at_height
            .saturating_add(self.config.settlement_ttl_blocks);
        let record = ClearingBatchRecord {
            clearing_batch_id: clearing_batch_id.clone(),
            request,
            selected_solver_commitment_id,
            settlement_deadline_height,
            status: ClearingStatus::SettlementReady,
            settlement_receipt_id: None,
        };
        self.current_height = self.current_height.max(record.request.built_at_height);
        self.counters.next_clearing_nonce = self.counters.next_clearing_nonce.saturating_add(1);
        self.counters.clearing_batches_built =
            self.counters.clearing_batches_built.saturating_add(1);
        self.counters.solver_fees_micro_units = self
            .counters
            .solver_fees_micro_units
            .saturating_add(solver_fee_micro_units(&record));
        self.clearing_batches
            .insert(clearing_batch_id.clone(), record.clone());
        self.refresh_intent_records(&record.request.intent_ids);
        self.refresh_solver_records(&record.request.solver_commitment_ids);
        self.publish_public_record("clearing_batch", &clearing_batch_id, record.public_record());
        Ok(record)
    }

    pub fn settle_clearing_batch(
        &mut self,
        request: SettleClearingBatchRequest,
    ) -> PrivateL2LowFeeDefiIntentAuctionRuntimeResult<SettlementReceiptRecord> {
        self.config.validate()?;
        request.validate()?;
        let state_root_before = self.state_root();
        let batch = self
            .clearing_batches
            .get(&request.clearing_batch_id)
            .cloned()
            .ok_or_else(|| "settlement references unknown clearing batch".to_string())?;
        if !batch.status.can_settle() {
            return Err("clearing batch is not settlement ready".to_string());
        }
        if request.settled_at_height > batch.settlement_deadline_height {
            return Err("clearing batch settlement deadline elapsed".to_string());
        }
        if request.output_commitment_root != batch.request.output_commitment_root
            || request.solver_payment_root != batch.request.solver_payment_root
            || request.rebate_distribution_root != batch.request.rebate_distribution_root
        {
            return Err("settlement roots do not match clearing batch commitments".to_string());
        }
        let receipt_id = settlement_receipt_id(
            &request,
            self.counters.next_receipt_nonce,
            &state_root_before,
        );
        for intent_id in &batch.request.intent_ids {
            if let Some(intent) = self.private_intents.get_mut(intent_id) {
                intent.status = IntentStatus::Settled;
            }
        }
        if let Some(commitment) = self
            .solver_commitments
            .get_mut(&batch.selected_solver_commitment_id)
        {
            commitment.status = SolverCommitmentStatus::Settled;
        }
        for reservation_id in &batch.request.reservation_ids {
            if let Some(reservation) = self.fee_reservations.get_mut(reservation_id) {
                reservation.status = ReservationStatus::Consumed;
                self.counters.rebates_consumed_micro_units = self
                    .counters
                    .rebates_consumed_micro_units
                    .saturating_add(reservation.request.reserved_micro_units);
            }
        }
        if let Some(stored_batch) = self.clearing_batches.get_mut(&request.clearing_batch_id) {
            stored_batch.status = ClearingStatus::Settled;
            stored_batch.settlement_receipt_id = Some(receipt_id.clone());
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
            .saturating_add(batch.request.intent_ids.len() as u64);
        let state_root_after = self.state_root();
        let record = SettlementReceiptRecord {
            receipt_id: receipt_id.clone(),
            clearing_batch_id: request.clearing_batch_id,
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
            state_root_before,
            state_root_after,
            runtime_state_root_after: request.runtime_state_root_after,
            settled_at_height: request.settled_at_height,
            finalized_at_height: request.finalized_at_height,
        };
        self.settlement_receipts
            .insert(receipt_id.clone(), record.clone());
        self.refresh_intent_records(&batch.request.intent_ids);
        self.refresh_solver_records(&batch.request.solver_commitment_ids);
        self.refresh_reservation_records(&batch.request.reservation_ids);
        self.publish_public_record("settlement_receipt", &receipt_id, record.public_record());
        Ok(record)
    }

    pub fn roots(&self) -> Roots {
        Roots {
            config_root: private_l2_low_fee_defi_intent_auction_payload_root(
                "PRIVATE-L2-LOW-FEE-DEFI-INTENT-AUCTION-CONFIG",
                &self.config.public_record(),
            ),
            private_intent_root: private_l2_low_fee_defi_intent_auction_merkle_root(
                "PRIVATE-L2-LOW-FEE-DEFI-INTENT-AUCTION-PRIVATE-INTENT",
                self.private_intents
                    .values()
                    .map(PrivateIntentRecord::public_record)
                    .collect(),
            ),
            solver_commitment_root: private_l2_low_fee_defi_intent_auction_merkle_root(
                "PRIVATE-L2-LOW-FEE-DEFI-INTENT-AUCTION-SOLVER-COMMITMENT",
                self.solver_commitments
                    .values()
                    .map(SolverCommitmentRecord::public_record)
                    .collect(),
            ),
            fee_reservation_root: private_l2_low_fee_defi_intent_auction_merkle_root(
                "PRIVATE-L2-LOW-FEE-DEFI-INTENT-AUCTION-FEE-RESERVATION",
                self.fee_reservations
                    .values()
                    .map(FeeSponsorReservationRecord::public_record)
                    .collect(),
            ),
            clearing_batch_root: private_l2_low_fee_defi_intent_auction_merkle_root(
                "PRIVATE-L2-LOW-FEE-DEFI-INTENT-AUCTION-CLEARING-BATCH",
                self.clearing_batches
                    .values()
                    .map(ClearingBatchRecord::public_record)
                    .collect(),
            ),
            settlement_receipt_root: private_l2_low_fee_defi_intent_auction_merkle_root(
                "PRIVATE-L2-LOW-FEE-DEFI-INTENT-AUCTION-SETTLEMENT-RECEIPT",
                self.settlement_receipts
                    .values()
                    .map(SettlementReceiptRecord::public_record)
                    .collect(),
            ),
            consumed_nullifier_root: private_l2_low_fee_defi_intent_auction_merkle_root(
                "PRIVATE-L2-LOW-FEE-DEFI-INTENT-AUCTION-CONSUMED-NULLIFIER",
                self.consumed_nullifier_roots
                    .iter()
                    .map(|root| json!({ "nullifier_root": root }))
                    .collect(),
            ),
            public_record_root: private_l2_low_fee_defi_intent_auction_merkle_root(
                "PRIVATE-L2-LOW-FEE-DEFI-INTENT-AUCTION-PUBLIC-RECORD",
                self.public_records.values().cloned().collect(),
            ),
        }
    }

    pub fn public_record_without_state_root(&self) -> Value {
        json!({
            "kind": "private_l2_low_fee_defi_intent_auction_runtime",
            "protocol_version": PRIVATE_L2_LOW_FEE_DEFI_INTENT_AUCTION_RUNTIME_PROTOCOL_VERSION,
            "schema_version": PRIVATE_L2_LOW_FEE_DEFI_INTENT_AUCTION_RUNTIME_SCHEMA_VERSION,
            "chain_id": CHAIN_ID,
            "hash_suite": PRIVATE_L2_LOW_FEE_DEFI_INTENT_AUCTION_RUNTIME_HASH_SUITE,
            "sealed_intent_scheme": PRIVATE_L2_LOW_FEE_DEFI_INTENT_AUCTION_RUNTIME_SEALED_INTENT_SCHEME,
            "solver_commitment_scheme": PRIVATE_L2_LOW_FEE_DEFI_INTENT_AUCTION_RUNTIME_SOLVER_COMMITMENT_SCHEME,
            "clearing_scheme": PRIVATE_L2_LOW_FEE_DEFI_INTENT_AUCTION_RUNTIME_CLEARING_SCHEME,
            "fee_reservation_scheme": PRIVATE_L2_LOW_FEE_DEFI_INTENT_AUCTION_RUNTIME_FEE_RESERVATION_SCHEME,
            "pq_solver_attestation_scheme": PRIVATE_L2_LOW_FEE_DEFI_INTENT_AUCTION_RUNTIME_PQ_SOLVER_ATTESTATION_SCHEME,
            "settlement_receipt_scheme": PRIVATE_L2_LOW_FEE_DEFI_INTENT_AUCTION_RUNTIME_SETTLEMENT_RECEIPT_SCHEME,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "current_height": self.current_height,
            "runtime_root": self.runtime_root,
            "sponsor_budget_remaining_micro_units": self.sponsor_budget_remaining_micro_units,
            "roots": self.roots().public_record(),
        })
    }

    pub fn public_record(&self) -> Value {
        let record = self.public_record_without_state_root();
        json!({
            "state_root": private_l2_low_fee_defi_intent_auction_state_root_from_record(&record),
            "record": record,
        })
    }

    pub fn state_root(&self) -> String {
        private_l2_low_fee_defi_intent_auction_state_root_from_record(
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
                self.private_intents
                    .get(intent_id)
                    .map(|intent| (intent.intent_id.clone(), intent.public_record()))
            })
            .collect::<Vec<_>>();
        for (intent_id, record) in updates {
            self.publish_public_record("private_intent", &intent_id, record);
        }
    }

    fn refresh_solver_records(&mut self, commitment_ids: &[String]) {
        let updates = commitment_ids
            .iter()
            .filter_map(|commitment_id| {
                self.solver_commitments
                    .get(commitment_id)
                    .map(|commitment| {
                        (commitment.commitment_id.clone(), commitment.public_record())
                    })
            })
            .collect::<Vec<_>>();
        for (commitment_id, record) in updates {
            self.publish_public_record("solver_commitment", &commitment_id, record);
        }
    }

    fn refresh_reservation_records(&mut self, reservation_ids: &[String]) {
        let updates = reservation_ids
            .iter()
            .filter_map(|reservation_id| {
                self.fee_reservations
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
            self.publish_public_record("fee_sponsor_reservation", &reservation_id, record);
        }
    }
}

pub fn private_l2_low_fee_defi_intent_auction_payload_root(
    domain: &str,
    payload: &Value,
) -> String {
    domain_hash(
        domain,
        &[HashPart::Str(CHAIN_ID), HashPart::Json(payload)],
        32,
    )
}

pub fn private_l2_low_fee_defi_intent_auction_state_root_from_record(record: &Value) -> String {
    private_l2_low_fee_defi_intent_auction_payload_root(
        "PRIVATE-L2-LOW-FEE-DEFI-INTENT-AUCTION-STATE",
        record,
    )
}

pub fn private_l2_low_fee_defi_intent_auction_merkle_root(
    domain: &str,
    leaves: Vec<Value>,
) -> String {
    merkle_root(domain, &leaves)
}

pub fn private_intent_id(request: &SubmitPrivateIntentRequest, nonce: u64) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-DEFI-INTENT-AUCTION-PRIVATE-INTENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(nonce as i128),
            HashPart::Str(request.intent_kind.as_str()),
            HashPart::Str(request.venue.as_str()),
            HashPart::Str(&request.account_commitment),
            HashPart::Str(&request.sealed_intent_root),
            HashPart::Str(&request.nullifier_root),
        ],
        32,
    )
}

pub fn solver_commitment_id(request: &SolverCommitmentRequest, score: u128, nonce: u64) -> String {
    let intent_root = private_l2_low_fee_defi_intent_auction_merkle_root(
        "PRIVATE-L2-LOW-FEE-DEFI-INTENT-AUCTION-SOLVER-ID-INTENT",
        request.intent_ids.iter().map(|id| json!(id)).collect(),
    );
    domain_hash(
        "PRIVATE-L2-LOW-FEE-DEFI-INTENT-AUCTION-SOLVER-COMMITMENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(nonce as i128),
            HashPart::Str(&request.solver_id),
            HashPart::Str(&intent_root),
            HashPart::Str(&request.route_commitment_root),
            HashPart::Int(score as i128),
        ],
        32,
    )
}

pub fn fee_sponsor_reservation_id(
    request: &ReserveFeeSponsorRequest,
    nonce: u64,
    remaining_budget_micro_units: u64,
) -> String {
    let intent_root = private_l2_low_fee_defi_intent_auction_merkle_root(
        "PRIVATE-L2-LOW-FEE-DEFI-INTENT-AUCTION-RESERVATION-ID-INTENT",
        request.intent_ids.iter().map(|id| json!(id)).collect(),
    );
    domain_hash(
        "PRIVATE-L2-LOW-FEE-DEFI-INTENT-AUCTION-FEE-SPONSOR-RESERVATION-ID",
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

pub fn clearing_batch_id(
    request: &BuildClearingBatchRequest,
    selected_solver_commitment_id: &str,
    nonce: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-DEFI-INTENT-AUCTION-CLEARING-BATCH-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(nonce as i128),
            HashPart::Str(&request.batch_label),
            HashPart::Str(&request.aggregate_intent_root),
            HashPart::Str(&request.aggregate_solver_commitment_root),
            HashPart::Str(selected_solver_commitment_id),
            HashPart::Str(&request.clearing_price_root),
            HashPart::Int(request.built_at_height as i128),
        ],
        32,
    )
}

pub fn settlement_receipt_id(
    request: &SettleClearingBatchRequest,
    nonce: u64,
    state_root_before: &str,
) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-DEFI-INTENT-AUCTION-SETTLEMENT-RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(nonce as i128),
            HashPart::Str(&request.clearing_batch_id),
            HashPart::Str(&request.settlement_tx_root),
            HashPart::Str(&request.settlement_proof_root),
            HashPart::Str(state_root_before),
            HashPart::Int(request.settled_at_height as i128),
        ],
        32,
    )
}

fn solver_score(request: &SolverCommitmentRequest) -> u128 {
    let surplus = request.expected_surplus_micro_units as u128;
    let solver_fee_penalty = request.solver_fee_bps as u128 * 1_000_000;
    surplus
        .saturating_mul(1_000_000)
        .saturating_sub(solver_fee_penalty)
}

fn solver_fee_micro_units(record: &ClearingBatchRecord) -> u64 {
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
        "PRIVATE-L2-LOW-FEE-DEFI-INTENT-AUCTION-PUBLIC-RECORD-ID",
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
        "kind": "private_l2_low_fee_defi_intent_auction_roots_only_payload",
        "chain_id": CHAIN_ID,
        "record_kind": record_kind,
        "subject_id": subject_id,
        "payload_root": private_l2_low_fee_defi_intent_auction_payload_root(
            "PRIVATE-L2-LOW-FEE-DEFI-INTENT-AUCTION-ROOTS-ONLY-PAYLOAD",
            payload,
        ),
    })
}

fn require_non_empty(
    label: &str,
    value: &str,
) -> PrivateL2LowFeeDefiIntentAuctionRuntimeResult<()> {
    if value.is_empty() {
        return Err(format!("{label} cannot be empty"));
    }
    Ok(())
}

fn require_root(label: &str, value: &str) -> PrivateL2LowFeeDefiIntentAuctionRuntimeResult<()> {
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
) -> PrivateL2LowFeeDefiIntentAuctionRuntimeResult<()> {
    if actual != expected {
        return Err(format!(
            "{label} mismatch: expected {expected}, got {actual}"
        ));
    }
    Ok(())
}
