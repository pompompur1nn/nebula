use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2PqConfidentialFheOrderMatchingRuntimeResult<T> = Result<T, String>;
pub type Runtime = State;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_FHE_ORDER_MATCHING_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-confidential-fhe-order-matching-runtime-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_FHE_ORDER_MATCHING_RUNTIME_SCHEMA_VERSION: u64 = 1;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_FHE_ORDER_MATCHING_RUNTIME_HASH_SUITE: &str =
    "SHAKE256-domain-separated-canonical-json";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_FHE_ORDER_MATCHING_RUNTIME_SEALED_ORDER_SUITE: &str =
    "ml-kem-1024+threshold-fhe-sealed-order-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_FHE_ORDER_MATCHING_RUNTIME_PRICE_BUCKET_SUITE: &str =
    "bfv-ckks-hybrid-encrypted-price-bucket-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_FHE_ORDER_MATCHING_RUNTIME_SOLVER_ATTESTATION_SUITE: &str =
    "ml-dsa-87+slh-dsa-shake-256f-fhe-solver-attestation-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_FHE_ORDER_MATCHING_RUNTIME_BATCH_MATCHING_SUITE: &str =
    "confidential-fhe-crossing-batch-matching-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_FHE_ORDER_MATCHING_RUNTIME_REBATE_SUITE: &str =
    "low-fee-settlement-rebate-accounting-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_FHE_ORDER_MATCHING_RUNTIME_REDACTION_SUITE: &str =
    "privacy-redaction-budget-ledger-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_FHE_ORDER_MATCHING_RUNTIME_QUARANTINE_SUITE: &str =
    "failure-quarantine-accounting-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_FHE_ORDER_MATCHING_RUNTIME_DEVNET_HEIGHT: u64 = 1_224_000;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_FHE_ORDER_MATCHING_RUNTIME_MAX_BPS: u64 = 10_000;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_FHE_ORDER_MATCHING_RUNTIME_DEFAULT_MIN_PRIVACY_SET: u64 =
    1_024;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_FHE_ORDER_MATCHING_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS: u16 =
    256;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_FHE_ORDER_MATCHING_RUNTIME_DEFAULT_MAX_USER_FEE_BPS: u64 = 18;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_FHE_ORDER_MATCHING_RUNTIME_DEFAULT_REBATE_BPS: u64 = 7_500;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_FHE_ORDER_MATCHING_RUNTIME_DEFAULT_ORDER_TTL_BLOCKS: u64 = 64;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_FHE_ORDER_MATCHING_RUNTIME_DEFAULT_BATCH_TTL_BLOCKS: u64 = 18;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_FHE_ORDER_MATCHING_RUNTIME_DEFAULT_MAX_BUCKETS: usize = 4_096;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_FHE_ORDER_MATCHING_RUNTIME_DEFAULT_MAX_ORDERS: usize = 524_288;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_FHE_ORDER_MATCHING_RUNTIME_DEFAULT_MAX_BATCHES: usize = 65_536;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_FHE_ORDER_MATCHING_RUNTIME_DEFAULT_MAX_REDACTIONS: usize =
    262_144;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_FHE_ORDER_MATCHING_RUNTIME_DEFAULT_MAX_QUARANTINES: usize =
    65_536;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OrderSide {
    Bid,
    Ask,
}

impl OrderSide {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Bid => "bid",
            Self::Ask => "ask",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OrderKind {
    Limit,
    PeggedMidpoint,
    FillOrKill,
    ImmediateOrCancel,
    HiddenReserve,
    MoneroExit,
}

impl OrderKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Limit => "limit",
            Self::PeggedMidpoint => "pegged_midpoint",
            Self::FillOrKill => "fill_or_kill",
            Self::ImmediateOrCancel => "immediate_or_cancel",
            Self::HiddenReserve => "hidden_reserve",
            Self::MoneroExit => "monero_exit",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OrderStatus {
    Sealed,
    Admitted,
    Bucketed,
    Matching,
    PartiallyFilled,
    Filled,
    Settled,
    Cancelled,
    Expired,
    Rejected,
    Quarantined,
}

impl OrderStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sealed => "sealed",
            Self::Admitted => "admitted",
            Self::Bucketed => "bucketed",
            Self::Matching => "matching",
            Self::PartiallyFilled => "partially_filled",
            Self::Filled => "filled",
            Self::Settled => "settled",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
            Self::Rejected => "rejected",
            Self::Quarantined => "quarantined",
        }
    }

    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Sealed | Self::Admitted | Self::Bucketed | Self::Matching | Self::PartiallyFilled
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BucketStatus {
    Open,
    Sealed,
    Solving,
    Matched,
    Settling,
    Settled,
    Stale,
    Quarantined,
}

impl BucketStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Sealed => "sealed",
            Self::Solving => "solving",
            Self::Matched => "matched",
            Self::Settling => "settling",
            Self::Settled => "settled",
            Self::Stale => "stale",
            Self::Quarantined => "quarantined",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SolverStatus {
    Registered,
    Attested,
    Active,
    RateLimited,
    Slashed,
    Quarantined,
    Retired,
}

impl SolverStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Registered => "registered",
            Self::Attested => "attested",
            Self::Active => "active",
            Self::RateLimited => "rate_limited",
            Self::Slashed => "slashed",
            Self::Quarantined => "quarantined",
            Self::Retired => "retired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchStatus {
    Proposed,
    Solving,
    Attested,
    Matched,
    SettlementReady,
    Settled,
    Rebated,
    Failed,
    Quarantined,
}

impl BatchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::Solving => "solving",
            Self::Attested => "attested",
            Self::Matched => "matched",
            Self::SettlementReady => "settlement_ready",
            Self::Settled => "settled",
            Self::Rebated => "rebated",
            Self::Failed => "failed",
            Self::Quarantined => "quarantined",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QuarantineReason {
    InvalidCiphertext,
    MissingPqAttestation,
    FheCircuitMismatch,
    RedactionBudgetExceeded,
    SolverEquivocation,
    SettlementRootMismatch,
    FeeCapExceeded,
    PrivacySetTooSmall,
}

impl QuarantineReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidCiphertext => "invalid_ciphertext",
            Self::MissingPqAttestation => "missing_pq_attestation",
            Self::FheCircuitMismatch => "fhe_circuit_mismatch",
            Self::RedactionBudgetExceeded => "redaction_budget_exceeded",
            Self::SolverEquivocation => "solver_equivocation",
            Self::SettlementRootMismatch => "settlement_root_mismatch",
            Self::FeeCapExceeded => "fee_cap_exceeded",
            Self::PrivacySetTooSmall => "privacy_set_too_small",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub runtime_id: String,
    pub chain_id: String,
    pub operator_commitment: String,
    pub settlement_asset: String,
    pub quote_asset: String,
    pub sealed_order_suite: String,
    pub price_bucket_suite: String,
    pub solver_attestation_suite: String,
    pub batch_matching_suite: String,
    pub rebate_suite: String,
    pub redaction_suite: String,
    pub quarantine_suite: String,
    pub min_privacy_set: u64,
    pub min_pq_security_bits: u16,
    pub max_user_fee_bps: u64,
    pub settlement_rebate_bps: u64,
    pub order_ttl_blocks: u64,
    pub batch_ttl_blocks: u64,
    pub max_buckets: usize,
    pub max_orders: usize,
    pub max_batches: usize,
    pub max_redactions: usize,
    pub max_quarantines: usize,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            runtime_id: "devnet-private-l2-pq-confidential-fhe-order-matching-runtime".to_string(),
            chain_id: CHAIN_ID.to_string(),
            operator_commitment: "devnet-fhe-matching-operator-committee-root".to_string(),
            settlement_asset: "pXMR".to_string(),
            quote_asset: "pUSD".to_string(),
            sealed_order_suite:
                PRIVATE_L2_PQ_CONFIDENTIAL_FHE_ORDER_MATCHING_RUNTIME_SEALED_ORDER_SUITE.to_string(),
            price_bucket_suite:
                PRIVATE_L2_PQ_CONFIDENTIAL_FHE_ORDER_MATCHING_RUNTIME_PRICE_BUCKET_SUITE.to_string(),
            solver_attestation_suite:
                PRIVATE_L2_PQ_CONFIDENTIAL_FHE_ORDER_MATCHING_RUNTIME_SOLVER_ATTESTATION_SUITE
                    .to_string(),
            batch_matching_suite:
                PRIVATE_L2_PQ_CONFIDENTIAL_FHE_ORDER_MATCHING_RUNTIME_BATCH_MATCHING_SUITE
                    .to_string(),
            rebate_suite: PRIVATE_L2_PQ_CONFIDENTIAL_FHE_ORDER_MATCHING_RUNTIME_REBATE_SUITE
                .to_string(),
            redaction_suite: PRIVATE_L2_PQ_CONFIDENTIAL_FHE_ORDER_MATCHING_RUNTIME_REDACTION_SUITE
                .to_string(),
            quarantine_suite:
                PRIVATE_L2_PQ_CONFIDENTIAL_FHE_ORDER_MATCHING_RUNTIME_QUARANTINE_SUITE.to_string(),
            min_privacy_set:
                PRIVATE_L2_PQ_CONFIDENTIAL_FHE_ORDER_MATCHING_RUNTIME_DEFAULT_MIN_PRIVACY_SET,
            min_pq_security_bits:
                PRIVATE_L2_PQ_CONFIDENTIAL_FHE_ORDER_MATCHING_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS,
            max_user_fee_bps:
                PRIVATE_L2_PQ_CONFIDENTIAL_FHE_ORDER_MATCHING_RUNTIME_DEFAULT_MAX_USER_FEE_BPS,
            settlement_rebate_bps:
                PRIVATE_L2_PQ_CONFIDENTIAL_FHE_ORDER_MATCHING_RUNTIME_DEFAULT_REBATE_BPS,
            order_ttl_blocks:
                PRIVATE_L2_PQ_CONFIDENTIAL_FHE_ORDER_MATCHING_RUNTIME_DEFAULT_ORDER_TTL_BLOCKS,
            batch_ttl_blocks:
                PRIVATE_L2_PQ_CONFIDENTIAL_FHE_ORDER_MATCHING_RUNTIME_DEFAULT_BATCH_TTL_BLOCKS,
            max_buckets: PRIVATE_L2_PQ_CONFIDENTIAL_FHE_ORDER_MATCHING_RUNTIME_DEFAULT_MAX_BUCKETS,
            max_orders: PRIVATE_L2_PQ_CONFIDENTIAL_FHE_ORDER_MATCHING_RUNTIME_DEFAULT_MAX_ORDERS,
            max_batches: PRIVATE_L2_PQ_CONFIDENTIAL_FHE_ORDER_MATCHING_RUNTIME_DEFAULT_MAX_BATCHES,
            max_redactions:
                PRIVATE_L2_PQ_CONFIDENTIAL_FHE_ORDER_MATCHING_RUNTIME_DEFAULT_MAX_REDACTIONS,
            max_quarantines:
                PRIVATE_L2_PQ_CONFIDENTIAL_FHE_ORDER_MATCHING_RUNTIME_DEFAULT_MAX_QUARANTINES,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_pq_confidential_fhe_order_matching_config",
            "runtime_id": self.runtime_id,
            "chain_id": self.chain_id,
            "operator_commitment": self.operator_commitment,
            "settlement_asset": self.settlement_asset,
            "quote_asset": self.quote_asset,
            "sealed_order_suite": self.sealed_order_suite,
            "price_bucket_suite": self.price_bucket_suite,
            "solver_attestation_suite": self.solver_attestation_suite,
            "batch_matching_suite": self.batch_matching_suite,
            "rebate_suite": self.rebate_suite,
            "redaction_suite": self.redaction_suite,
            "quarantine_suite": self.quarantine_suite,
            "min_privacy_set": self.min_privacy_set,
            "min_pq_security_bits": self.min_pq_security_bits,
            "max_user_fee_bps": self.max_user_fee_bps,
            "settlement_rebate_bps": self.settlement_rebate_bps,
            "order_ttl_blocks": self.order_ttl_blocks,
            "batch_ttl_blocks": self.batch_ttl_blocks,
            "max_buckets": self.max_buckets,
            "max_orders": self.max_orders,
            "max_batches": self.max_batches,
            "max_redactions": self.max_redactions,
            "max_quarantines": self.max_quarantines,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub sealed_orders: u64,
    pub admitted_orders: u64,
    pub bucketed_orders: u64,
    pub matched_orders: u64,
    pub settled_orders: u64,
    pub rejected_orders: u64,
    pub quarantined_orders: u64,
    pub encrypted_price_buckets: u64,
    pub active_solvers: u64,
    pub solver_attestations: u64,
    pub match_batches: u64,
    pub successful_batches: u64,
    pub failed_batches: u64,
    pub settlement_rebates: u64,
    pub redaction_budgets: u64,
    pub redaction_events: u64,
    pub quarantine_events: u64,
    pub fee_micro_units_charged: u64,
    pub rebate_micro_units_paid: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_pq_confidential_fhe_order_matching_counters",
            "sealed_orders": self.sealed_orders,
            "admitted_orders": self.admitted_orders,
            "bucketed_orders": self.bucketed_orders,
            "matched_orders": self.matched_orders,
            "settled_orders": self.settled_orders,
            "rejected_orders": self.rejected_orders,
            "quarantined_orders": self.quarantined_orders,
            "encrypted_price_buckets": self.encrypted_price_buckets,
            "active_solvers": self.active_solvers,
            "solver_attestations": self.solver_attestations,
            "match_batches": self.match_batches,
            "successful_batches": self.successful_batches,
            "failed_batches": self.failed_batches,
            "settlement_rebates": self.settlement_rebates,
            "redaction_budgets": self.redaction_budgets,
            "redaction_events": self.redaction_events,
            "quarantine_events": self.quarantine_events,
            "fee_micro_units_charged": self.fee_micro_units_charged,
            "rebate_micro_units_paid": self.rebate_micro_units_paid,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub sealed_order_root: String,
    pub price_bucket_root: String,
    pub solver_root: String,
    pub solver_attestation_root: String,
    pub match_batch_root: String,
    pub settlement_rebate_root: String,
    pub redaction_budget_root: String,
    pub quarantine_root: String,
    pub failure_accounting_root: String,
    pub deterministic_record_root: String,
    pub counter_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_pq_confidential_fhe_order_matching_roots",
            "config_root": self.config_root,
            "sealed_order_root": self.sealed_order_root,
            "price_bucket_root": self.price_bucket_root,
            "solver_root": self.solver_root,
            "solver_attestation_root": self.solver_attestation_root,
            "match_batch_root": self.match_batch_root,
            "settlement_rebate_root": self.settlement_rebate_root,
            "redaction_budget_root": self.redaction_budget_root,
            "quarantine_root": self.quarantine_root,
            "failure_accounting_root": self.failure_accounting_root,
            "deterministic_record_root": self.deterministic_record_root,
            "counter_root": self.counter_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SealedOrder {
    pub order_id: String,
    pub account_commitment: String,
    pub side: OrderSide,
    pub order_kind: OrderKind,
    pub status: OrderStatus,
    pub sealed_payload_root: String,
    pub encrypted_price_root: String,
    pub encrypted_amount_root: String,
    pub bucket_hint_root: String,
    pub nullifier_hash: String,
    pub pq_authorization_root: String,
    pub redaction_budget_id: String,
    pub opened_height: u64,
    pub expires_height: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub max_fee_bps: u64,
}

impl SealedOrder {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        account_commitment: &str,
        side: OrderSide,
        order_kind: OrderKind,
        height: u64,
        ttl_blocks: u64,
        sealed_payload: &Value,
        encrypted_price: &Value,
        encrypted_amount: &Value,
        bucket_hint: &Value,
        pq_authorization: &Value,
        privacy_set_size: u64,
        pq_security_bits: u16,
        max_fee_bps: u64,
    ) -> Self {
        let sealed_payload_root = runtime_payload_root("SEALED-ORDER-PAYLOAD", sealed_payload);
        let encrypted_price_root = runtime_payload_root("SEALED-ORDER-PRICE", encrypted_price);
        let encrypted_amount_root = runtime_payload_root("SEALED-ORDER-AMOUNT", encrypted_amount);
        let bucket_hint_root = runtime_payload_root("SEALED-ORDER-BUCKET-HINT", bucket_hint);
        let pq_authorization_root =
            runtime_payload_root("SEALED-ORDER-PQ-AUTHORIZATION", pq_authorization);
        let nullifier_hash = runtime_string_root(
            "SEALED-ORDER-NULLIFIER",
            &format!("{account_commitment}:{sealed_payload_root}:{height}"),
        );
        let redaction_budget_id = runtime_string_root(
            "SEALED-ORDER-REDACTION-BUDGET",
            &format!("{account_commitment}:{bucket_hint_root}"),
        );
        let expires_height = height.saturating_add(ttl_blocks);
        let order_id = sealed_order_id(
            account_commitment,
            side,
            order_kind,
            height,
            expires_height,
            &sealed_payload_root,
            &encrypted_price_root,
            &encrypted_amount_root,
            &bucket_hint_root,
            &nullifier_hash,
            &pq_authorization_root,
        );
        Self {
            order_id,
            account_commitment: account_commitment.to_string(),
            side,
            order_kind,
            status: OrderStatus::Sealed,
            sealed_payload_root,
            encrypted_price_root,
            encrypted_amount_root,
            bucket_hint_root,
            nullifier_hash,
            pq_authorization_root,
            redaction_budget_id,
            opened_height: height,
            expires_height,
            privacy_set_size,
            pq_security_bits,
            max_fee_bps,
        }
    }

    pub fn admit(&mut self) {
        if self.status == OrderStatus::Sealed {
            self.status = OrderStatus::Admitted;
        }
    }

    pub fn bucket(&mut self) {
        if matches!(self.status, OrderStatus::Sealed | OrderStatus::Admitted) {
            self.status = OrderStatus::Bucketed;
        }
    }

    pub fn matched(&mut self, partial: bool) {
        self.status = if partial {
            OrderStatus::PartiallyFilled
        } else {
            OrderStatus::Filled
        };
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "sealed_order",
            "order_id": self.order_id,
            "account_commitment": self.account_commitment,
            "side": self.side.as_str(),
            "order_kind": self.order_kind.as_str(),
            "status": self.status.as_str(),
            "sealed_payload_root": self.sealed_payload_root,
            "encrypted_price_root": self.encrypted_price_root,
            "encrypted_amount_root": self.encrypted_amount_root,
            "bucket_hint_root": self.bucket_hint_root,
            "nullifier_hash": self.nullifier_hash,
            "pq_authorization_root": self.pq_authorization_root,
            "redaction_budget_id": self.redaction_budget_id,
            "opened_height": self.opened_height,
            "expires_height": self.expires_height,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "max_fee_bps": self.max_fee_bps,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EncryptedPriceBucket {
    pub bucket_id: String,
    pub market_id: String,
    pub side: OrderSide,
    pub status: BucketStatus,
    pub encrypted_price_band_root: String,
    pub encrypted_liquidity_root: String,
    pub order_root: String,
    pub nullifier_root: String,
    pub bucket_commitment_root: String,
    pub order_ids: BTreeSet<String>,
    pub opened_height: u64,
    pub sealed_height: u64,
    pub privacy_set_size: u64,
}

impl EncryptedPriceBucket {
    pub fn new(
        market_id: &str,
        side: OrderSide,
        height: u64,
        encrypted_price_band: &Value,
        encrypted_liquidity: &Value,
        privacy_set_size: u64,
    ) -> Self {
        let encrypted_price_band_root =
            runtime_payload_root("PRICE-BUCKET-PRICE-BAND", encrypted_price_band);
        let encrypted_liquidity_root =
            runtime_payload_root("PRICE-BUCKET-LIQUIDITY", encrypted_liquidity);
        let bucket_commitment_root = runtime_string_root(
            "PRICE-BUCKET-COMMITMENT",
            &format!("{market_id}:{}:{encrypted_price_band_root}", side.as_str()),
        );
        let bucket_id = price_bucket_id(
            market_id,
            side,
            height,
            &encrypted_price_band_root,
            &encrypted_liquidity_root,
            &bucket_commitment_root,
        );
        Self {
            bucket_id,
            market_id: market_id.to_string(),
            side,
            status: BucketStatus::Open,
            encrypted_price_band_root,
            encrypted_liquidity_root,
            order_root: merkle_root("PRIVATE-L2-PQ-FHE-PRICE-BUCKET-ORDERS", &[]),
            nullifier_root: merkle_root("PRIVATE-L2-PQ-FHE-PRICE-BUCKET-NULLIFIERS", &[]),
            bucket_commitment_root,
            order_ids: BTreeSet::new(),
            opened_height: height,
            sealed_height: height,
            privacy_set_size,
        }
    }

    pub fn add_order(&mut self, order: &SealedOrder) {
        self.order_ids.insert(order.order_id.clone());
        let order_records = self
            .order_ids
            .iter()
            .map(|order_id| json!({ "order_id": order_id }))
            .collect::<Vec<_>>();
        self.order_root = merkle_root("PRIVATE-L2-PQ-FHE-PRICE-BUCKET-ORDER-IDS", &order_records);
        let nullifier_records = self
            .order_ids
            .iter()
            .map(|order_id| json!(runtime_string_root("BUCKET-ORDER-NULLIFIER", order_id)))
            .collect::<Vec<_>>();
        self.nullifier_root = merkle_root(
            "PRIVATE-L2-PQ-FHE-PRICE-BUCKET-NULLIFIER-IDS",
            &nullifier_records,
        );
    }

    pub fn seal(&mut self, height: u64) {
        self.status = BucketStatus::Sealed;
        self.sealed_height = height;
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "encrypted_price_bucket",
            "bucket_id": self.bucket_id,
            "market_id": self.market_id,
            "side": self.side.as_str(),
            "status": self.status.as_str(),
            "encrypted_price_band_root": self.encrypted_price_band_root,
            "encrypted_liquidity_root": self.encrypted_liquidity_root,
            "order_root": self.order_root,
            "nullifier_root": self.nullifier_root,
            "bucket_commitment_root": self.bucket_commitment_root,
            "order_ids": self.order_ids.iter().cloned().collect::<Vec<_>>(),
            "opened_height": self.opened_height,
            "sealed_height": self.sealed_height,
            "privacy_set_size": self.privacy_set_size,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqSolver {
    pub solver_id: String,
    pub operator_commitment: String,
    pub status: SolverStatus,
    pub fhe_key_root: String,
    pub pq_identity_root: String,
    pub stake_root: String,
    pub registered_height: u64,
    pub solved_batches: u64,
    pub failed_batches: u64,
    pub rolling_success_bps: u64,
}

impl PqSolver {
    pub fn new(
        operator_commitment: &str,
        height: u64,
        fhe_key: &Value,
        pq_identity: &Value,
        stake: &Value,
    ) -> Self {
        let fhe_key_root = runtime_payload_root("SOLVER-FHE-KEY", fhe_key);
        let pq_identity_root = runtime_payload_root("SOLVER-PQ-IDENTITY", pq_identity);
        let stake_root = runtime_payload_root("SOLVER-STAKE", stake);
        let solver_id = solver_id(
            operator_commitment,
            height,
            &fhe_key_root,
            &pq_identity_root,
            &stake_root,
        );
        Self {
            solver_id,
            operator_commitment: operator_commitment.to_string(),
            status: SolverStatus::Registered,
            fhe_key_root,
            pq_identity_root,
            stake_root,
            registered_height: height,
            solved_batches: 0,
            failed_batches: 0,
            rolling_success_bps: 10_000,
        }
    }

    pub fn activate(&mut self) {
        self.status = SolverStatus::Active;
    }

    pub fn record_batch(&mut self, success: bool) {
        if success {
            self.solved_batches = self.solved_batches.saturating_add(1);
        } else {
            self.failed_batches = self.failed_batches.saturating_add(1);
        }
        let total = self
            .solved_batches
            .saturating_add(self.failed_batches)
            .max(1);
        self.rolling_success_bps = self
            .solved_batches
            .saturating_mul(10_000)
            .saturating_div(total);
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_solver",
            "solver_id": self.solver_id,
            "operator_commitment": self.operator_commitment,
            "status": self.status.as_str(),
            "fhe_key_root": self.fhe_key_root,
            "pq_identity_root": self.pq_identity_root,
            "stake_root": self.stake_root,
            "registered_height": self.registered_height,
            "solved_batches": self.solved_batches,
            "failed_batches": self.failed_batches,
            "rolling_success_bps": self.rolling_success_bps,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SolverAttestation {
    pub attestation_id: String,
    pub solver_id: String,
    pub batch_id: String,
    pub status: SolverStatus,
    pub circuit_root: String,
    pub transcript_root: String,
    pub pq_signature_root: String,
    pub verification_key_root: String,
    pub attested_height: u64,
    pub pq_security_bits: u16,
}

impl SolverAttestation {
    pub fn new(
        solver_id: &str,
        batch_id: &str,
        height: u64,
        circuit: &Value,
        transcript: &Value,
        pq_signature: &Value,
        verification_key: &Value,
        pq_security_bits: u16,
    ) -> Self {
        let circuit_root = runtime_payload_root("SOLVER-ATTESTATION-CIRCUIT", circuit);
        let transcript_root = runtime_payload_root("SOLVER-ATTESTATION-TRANSCRIPT", transcript);
        let pq_signature_root =
            runtime_payload_root("SOLVER-ATTESTATION-PQ-SIGNATURE", pq_signature);
        let verification_key_root =
            runtime_payload_root("SOLVER-ATTESTATION-VERIFICATION-KEY", verification_key);
        let attestation_id = solver_attestation_id(
            solver_id,
            batch_id,
            height,
            &circuit_root,
            &transcript_root,
            &pq_signature_root,
            &verification_key_root,
        );
        Self {
            attestation_id,
            solver_id: solver_id.to_string(),
            batch_id: batch_id.to_string(),
            status: SolverStatus::Attested,
            circuit_root,
            transcript_root,
            pq_signature_root,
            verification_key_root,
            attested_height: height,
            pq_security_bits,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "solver_attestation",
            "attestation_id": self.attestation_id,
            "solver_id": self.solver_id,
            "batch_id": self.batch_id,
            "status": self.status.as_str(),
            "circuit_root": self.circuit_root,
            "transcript_root": self.transcript_root,
            "pq_signature_root": self.pq_signature_root,
            "verification_key_root": self.verification_key_root,
            "attested_height": self.attested_height,
            "pq_security_bits": self.pq_security_bits,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MatchBatch {
    pub batch_id: String,
    pub market_id: String,
    pub solver_id: String,
    pub status: BatchStatus,
    pub bid_bucket_ids: BTreeSet<String>,
    pub ask_bucket_ids: BTreeSet<String>,
    pub sealed_order_root: String,
    pub crossing_result_root: String,
    pub encrypted_fill_root: String,
    pub settlement_intent_root: String,
    pub fee_accounting_root: String,
    pub redaction_root: String,
    pub opened_height: u64,
    pub expires_height: u64,
    pub matched_order_count: u64,
    pub fee_micro_units: u64,
    pub rebate_micro_units: u64,
}

impl MatchBatch {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        market_id: &str,
        solver_id: &str,
        height: u64,
        ttl_blocks: u64,
        bid_bucket_ids: BTreeSet<String>,
        ask_bucket_ids: BTreeSet<String>,
        crossing_result: &Value,
        encrypted_fill: &Value,
        settlement_intent: &Value,
        fee_accounting: &Value,
        redaction: &Value,
    ) -> Self {
        let bucket_records = bid_bucket_ids
            .iter()
            .chain(ask_bucket_ids.iter())
            .map(|bucket_id| json!({ "bucket_id": bucket_id }))
            .collect::<Vec<_>>();
        let sealed_order_root = merkle_root("PRIVATE-L2-PQ-FHE-BATCH-BUCKETS", &bucket_records);
        let crossing_result_root = runtime_payload_root("MATCH-BATCH-CROSSING", crossing_result);
        let encrypted_fill_root =
            runtime_payload_root("MATCH-BATCH-ENCRYPTED-FILL", encrypted_fill);
        let settlement_intent_root =
            runtime_payload_root("MATCH-BATCH-SETTLEMENT-INTENT", settlement_intent);
        let fee_accounting_root =
            runtime_payload_root("MATCH-BATCH-FEE-ACCOUNTING", fee_accounting);
        let redaction_root = runtime_payload_root("MATCH-BATCH-REDACTION", redaction);
        let expires_height = height.saturating_add(ttl_blocks);
        let fee_micro_units = fee_accounting
            .get("fee_micro_units")
            .and_then(Value::as_u64)
            .unwrap_or_default();
        let rebate_micro_units = fee_accounting
            .get("rebate_micro_units")
            .and_then(Value::as_u64)
            .unwrap_or_default();
        let matched_order_count = crossing_result
            .get("matched_order_count")
            .and_then(Value::as_u64)
            .unwrap_or_default();
        let batch_id = match_batch_id(
            market_id,
            solver_id,
            height,
            expires_height,
            &sealed_order_root,
            &crossing_result_root,
            &encrypted_fill_root,
            &settlement_intent_root,
        );
        Self {
            batch_id,
            market_id: market_id.to_string(),
            solver_id: solver_id.to_string(),
            status: BatchStatus::Proposed,
            bid_bucket_ids,
            ask_bucket_ids,
            sealed_order_root,
            crossing_result_root,
            encrypted_fill_root,
            settlement_intent_root,
            fee_accounting_root,
            redaction_root,
            opened_height: height,
            expires_height,
            matched_order_count,
            fee_micro_units,
            rebate_micro_units,
        }
    }

    pub fn attest(&mut self) {
        self.status = BatchStatus::Attested;
    }

    pub fn settle(&mut self) {
        self.status = BatchStatus::Settled;
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "match_batch",
            "batch_id": self.batch_id,
            "market_id": self.market_id,
            "solver_id": self.solver_id,
            "status": self.status.as_str(),
            "bid_bucket_ids": self.bid_bucket_ids.iter().cloned().collect::<Vec<_>>(),
            "ask_bucket_ids": self.ask_bucket_ids.iter().cloned().collect::<Vec<_>>(),
            "sealed_order_root": self.sealed_order_root,
            "crossing_result_root": self.crossing_result_root,
            "encrypted_fill_root": self.encrypted_fill_root,
            "settlement_intent_root": self.settlement_intent_root,
            "fee_accounting_root": self.fee_accounting_root,
            "redaction_root": self.redaction_root,
            "opened_height": self.opened_height,
            "expires_height": self.expires_height,
            "matched_order_count": self.matched_order_count,
            "fee_micro_units": self.fee_micro_units,
            "rebate_micro_units": self.rebate_micro_units,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SettlementRebate {
    pub rebate_id: String,
    pub batch_id: String,
    pub account_commitment: String,
    pub status: BatchStatus,
    pub fee_root: String,
    pub rebate_note_root: String,
    pub settlement_receipt_root: String,
    pub height: u64,
    pub fee_micro_units: u64,
    pub rebate_micro_units: u64,
}

impl SettlementRebate {
    pub fn new(
        batch_id: &str,
        account_commitment: &str,
        height: u64,
        fee: &Value,
        rebate_note: &Value,
        settlement_receipt: &Value,
    ) -> Self {
        let fee_root = runtime_payload_root("SETTLEMENT-REBATE-FEE", fee);
        let rebate_note_root = runtime_payload_root("SETTLEMENT-REBATE-NOTE", rebate_note);
        let settlement_receipt_root =
            runtime_payload_root("SETTLEMENT-REBATE-RECEIPT", settlement_receipt);
        let fee_micro_units = fee
            .get("fee_micro_units")
            .and_then(Value::as_u64)
            .unwrap_or_default();
        let rebate_micro_units = rebate_note
            .get("rebate_micro_units")
            .and_then(Value::as_u64)
            .unwrap_or_default();
        let rebate_id = settlement_rebate_id(
            batch_id,
            account_commitment,
            height,
            &fee_root,
            &rebate_note_root,
            &settlement_receipt_root,
        );
        Self {
            rebate_id,
            batch_id: batch_id.to_string(),
            account_commitment: account_commitment.to_string(),
            status: BatchStatus::Rebated,
            fee_root,
            rebate_note_root,
            settlement_receipt_root,
            height,
            fee_micro_units,
            rebate_micro_units,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "settlement_rebate",
            "rebate_id": self.rebate_id,
            "batch_id": self.batch_id,
            "account_commitment": self.account_commitment,
            "status": self.status.as_str(),
            "fee_root": self.fee_root,
            "rebate_note_root": self.rebate_note_root,
            "settlement_receipt_root": self.settlement_receipt_root,
            "height": self.height,
            "fee_micro_units": self.fee_micro_units,
            "rebate_micro_units": self.rebate_micro_units,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RedactionBudget {
    pub budget_id: String,
    pub account_commitment: String,
    pub market_id: String,
    pub scope_root: String,
    pub status: OrderStatus,
    pub opened_height: u64,
    pub expires_height: u64,
    pub max_redactions: u64,
    pub used_redactions: u64,
    pub remaining_redactions: u64,
}

impl RedactionBudget {
    pub fn new(
        account_commitment: &str,
        market_id: &str,
        height: u64,
        ttl_blocks: u64,
        max_redactions: u64,
        scope: &Value,
    ) -> Self {
        let scope_root = runtime_payload_root("REDACTION-BUDGET-SCOPE", scope);
        let expires_height = height.saturating_add(ttl_blocks);
        let budget_id = redaction_budget_id(
            account_commitment,
            market_id,
            height,
            expires_height,
            max_redactions,
            &scope_root,
        );
        Self {
            budget_id,
            account_commitment: account_commitment.to_string(),
            market_id: market_id.to_string(),
            scope_root,
            status: OrderStatus::Admitted,
            opened_height: height,
            expires_height,
            max_redactions,
            used_redactions: 0,
            remaining_redactions: max_redactions,
        }
    }

    pub fn consume(
        &mut self,
        units: u64,
    ) -> PrivateL2PqConfidentialFheOrderMatchingRuntimeResult<()> {
        if units > self.remaining_redactions {
            self.status = OrderStatus::Quarantined;
            return Err("private l2 pq fhe redaction budget exceeded".to_string());
        }
        self.used_redactions = self.used_redactions.saturating_add(units);
        self.remaining_redactions = self.remaining_redactions.saturating_sub(units);
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "redaction_budget",
            "budget_id": self.budget_id,
            "account_commitment": self.account_commitment,
            "market_id": self.market_id,
            "scope_root": self.scope_root,
            "status": self.status.as_str(),
            "opened_height": self.opened_height,
            "expires_height": self.expires_height,
            "max_redactions": self.max_redactions,
            "used_redactions": self.used_redactions,
            "remaining_redactions": self.remaining_redactions,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct QuarantineAccount {
    pub quarantine_id: String,
    pub subject_id: String,
    pub subject_kind: String,
    pub reason: QuarantineReason,
    pub evidence_root: String,
    pub failure_accounting_root: String,
    pub opened_height: u64,
    pub released_height: u64,
    pub slashed_micro_units: u64,
}

impl QuarantineAccount {
    pub fn new(
        subject_id: &str,
        subject_kind: &str,
        reason: QuarantineReason,
        height: u64,
        evidence: &Value,
        failure_accounting: &Value,
    ) -> Self {
        let evidence_root = runtime_payload_root("QUARANTINE-EVIDENCE", evidence);
        let failure_accounting_root =
            runtime_payload_root("QUARANTINE-FAILURE-ACCOUNTING", failure_accounting);
        let slashed_micro_units = failure_accounting
            .get("slashed_micro_units")
            .and_then(Value::as_u64)
            .unwrap_or_default();
        let quarantine_id = quarantine_id(
            subject_id,
            subject_kind,
            reason,
            height,
            &evidence_root,
            &failure_accounting_root,
        );
        Self {
            quarantine_id,
            subject_id: subject_id.to_string(),
            subject_kind: subject_kind.to_string(),
            reason,
            evidence_root,
            failure_accounting_root,
            opened_height: height,
            released_height: 0,
            slashed_micro_units,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "quarantine_account",
            "quarantine_id": self.quarantine_id,
            "subject_id": self.subject_id,
            "subject_kind": self.subject_kind,
            "reason": self.reason.as_str(),
            "evidence_root": self.evidence_root,
            "failure_accounting_root": self.failure_accounting_root,
            "opened_height": self.opened_height,
            "released_height": self.released_height,
            "slashed_micro_units": self.slashed_micro_units,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub height: u64,
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub sealed_orders: BTreeMap<String, SealedOrder>,
    pub price_buckets: BTreeMap<String, EncryptedPriceBucket>,
    pub solvers: BTreeMap<String, PqSolver>,
    pub solver_attestations: BTreeMap<String, SolverAttestation>,
    pub match_batches: BTreeMap<String, MatchBatch>,
    pub settlement_rebates: BTreeMap<String, SettlementRebate>,
    pub redaction_budgets: BTreeMap<String, RedactionBudget>,
    pub quarantines: BTreeMap<String, QuarantineAccount>,
    pub state_root: String,
}

impl State {
    pub fn new(height: u64, config: Config) -> Self {
        let mut state = Self {
            height,
            config,
            counters: Counters::default(),
            roots: Roots::default(),
            sealed_orders: BTreeMap::new(),
            price_buckets: BTreeMap::new(),
            solvers: BTreeMap::new(),
            solver_attestations: BTreeMap::new(),
            match_batches: BTreeMap::new(),
            settlement_rebates: BTreeMap::new(),
            redaction_budgets: BTreeMap::new(),
            quarantines: BTreeMap::new(),
            state_root: String::new(),
        };
        state.recompute();
        state
    }

    pub fn devnet() -> Self {
        let mut state = Self::new(
            PRIVATE_L2_PQ_CONFIDENTIAL_FHE_ORDER_MATCHING_RUNTIME_DEVNET_HEIGHT,
            Config::devnet(),
        );
        state.seed_devnet();
        state.recompute();
        state
    }

    pub fn demo() -> Self {
        let mut state = Self::devnet();
        let mut extra_bid = state.devnet_order(
            "demo-account-bidder-charlie",
            OrderSide::Bid,
            OrderKind::HiddenReserve,
            7,
            1_280,
            12,
        );
        extra_bid.admit();
        state.add_order(extra_bid).ok();
        let mut extra_ask = state.devnet_order(
            "demo-account-maker-delta",
            OrderSide::Ask,
            OrderKind::PeggedMidpoint,
            8,
            1_344,
            12,
        );
        extra_ask.admit();
        state.add_order(extra_ask).ok();
        state.recompute();
        state
    }

    pub fn add_order(
        &mut self,
        mut order: SealedOrder,
    ) -> PrivateL2PqConfidentialFheOrderMatchingRuntimeResult<()> {
        if self.sealed_orders.len() >= self.config.max_orders {
            self.counters.rejected_orders = self.counters.rejected_orders.saturating_add(1);
            return Err("private l2 pq fhe order capacity exceeded".to_string());
        }
        if order.max_fee_bps > self.config.max_user_fee_bps {
            self.counters.rejected_orders = self.counters.rejected_orders.saturating_add(1);
            return Err("private l2 pq fhe order exceeds fee cap".to_string());
        }
        if order.privacy_set_size < self.config.min_privacy_set {
            order.status = OrderStatus::Rejected;
            self.counters.rejected_orders = self.counters.rejected_orders.saturating_add(1);
            self.sealed_orders.insert(order.order_id.clone(), order);
            self.recompute();
            return Err("private l2 pq fhe order privacy set too small".to_string());
        }
        if order.pq_security_bits < self.config.min_pq_security_bits {
            order.status = OrderStatus::Rejected;
            self.counters.rejected_orders = self.counters.rejected_orders.saturating_add(1);
            self.sealed_orders.insert(order.order_id.clone(), order);
            self.recompute();
            return Err("private l2 pq fhe order pq security too small".to_string());
        }
        self.sealed_orders.insert(order.order_id.clone(), order);
        self.recompute();
        Ok(())
    }

    pub fn add_bucket(
        &mut self,
        bucket: EncryptedPriceBucket,
    ) -> PrivateL2PqConfidentialFheOrderMatchingRuntimeResult<()> {
        if self.price_buckets.len() >= self.config.max_buckets {
            return Err("private l2 pq fhe bucket capacity exceeded".to_string());
        }
        self.price_buckets.insert(bucket.bucket_id.clone(), bucket);
        self.recompute();
        Ok(())
    }

    pub fn add_solver(
        &mut self,
        solver: PqSolver,
    ) -> PrivateL2PqConfidentialFheOrderMatchingRuntimeResult<()> {
        self.solvers.insert(solver.solver_id.clone(), solver);
        self.recompute();
        Ok(())
    }

    pub fn add_batch(
        &mut self,
        batch: MatchBatch,
    ) -> PrivateL2PqConfidentialFheOrderMatchingRuntimeResult<()> {
        if self.match_batches.len() >= self.config.max_batches {
            return Err("private l2 pq fhe batch capacity exceeded".to_string());
        }
        self.match_batches.insert(batch.batch_id.clone(), batch);
        self.recompute();
        Ok(())
    }

    pub fn add_attestation(
        &mut self,
        attestation: SolverAttestation,
    ) -> PrivateL2PqConfidentialFheOrderMatchingRuntimeResult<()> {
        if attestation.pq_security_bits < self.config.min_pq_security_bits {
            return Err("private l2 pq fhe solver attestation pq security too small".to_string());
        }
        self.solver_attestations
            .insert(attestation.attestation_id.clone(), attestation);
        self.recompute();
        Ok(())
    }

    pub fn add_rebate(
        &mut self,
        rebate: SettlementRebate,
    ) -> PrivateL2PqConfidentialFheOrderMatchingRuntimeResult<()> {
        self.settlement_rebates
            .insert(rebate.rebate_id.clone(), rebate);
        self.recompute();
        Ok(())
    }

    pub fn add_redaction_budget(
        &mut self,
        budget: RedactionBudget,
    ) -> PrivateL2PqConfidentialFheOrderMatchingRuntimeResult<()> {
        if self.redaction_budgets.len() >= self.config.max_redactions {
            return Err("private l2 pq fhe redaction budget capacity exceeded".to_string());
        }
        self.redaction_budgets
            .insert(budget.budget_id.clone(), budget);
        self.recompute();
        Ok(())
    }

    pub fn add_quarantine(
        &mut self,
        quarantine: QuarantineAccount,
    ) -> PrivateL2PqConfidentialFheOrderMatchingRuntimeResult<()> {
        if self.quarantines.len() >= self.config.max_quarantines {
            return Err("private l2 pq fhe quarantine capacity exceeded".to_string());
        }
        self.quarantines
            .insert(quarantine.quarantine_id.clone(), quarantine);
        self.recompute();
        Ok(())
    }

    pub fn recompute(&mut self) {
        self.counters = self.derive_counters();
        let sealed_order_records = values_to_records(&self.sealed_orders);
        let price_bucket_records = values_to_records(&self.price_buckets);
        let solver_records = values_to_records(&self.solvers);
        let attestation_records = values_to_records(&self.solver_attestations);
        let batch_records = values_to_records(&self.match_batches);
        let rebate_records = values_to_records(&self.settlement_rebates);
        let redaction_records = values_to_records(&self.redaction_budgets);
        let quarantine_records = values_to_records(&self.quarantines);
        let failure_records = self
            .quarantines
            .values()
            .map(|entry| {
                json!({
                    "quarantine_id": entry.quarantine_id,
                    "reason": entry.reason.as_str(),
                    "failure_accounting_root": entry.failure_accounting_root,
                    "slashed_micro_units": entry.slashed_micro_units,
                })
            })
            .collect::<Vec<_>>();
        self.roots = Roots {
            config_root: runtime_payload_root("CONFIG", &self.config.public_record()),
            sealed_order_root: merkle_root(
                "PRIVATE-L2-PQ-FHE-ORDER-MATCHING-SEALED-ORDERS",
                &sealed_order_records,
            ),
            price_bucket_root: merkle_root(
                "PRIVATE-L2-PQ-FHE-ORDER-MATCHING-PRICE-BUCKETS",
                &price_bucket_records,
            ),
            solver_root: merkle_root("PRIVATE-L2-PQ-FHE-ORDER-MATCHING-SOLVERS", &solver_records),
            solver_attestation_root: merkle_root(
                "PRIVATE-L2-PQ-FHE-ORDER-MATCHING-SOLVER-ATTESTATIONS",
                &attestation_records,
            ),
            match_batch_root: merkle_root(
                "PRIVATE-L2-PQ-FHE-ORDER-MATCHING-BATCHES",
                &batch_records,
            ),
            settlement_rebate_root: merkle_root(
                "PRIVATE-L2-PQ-FHE-ORDER-MATCHING-REBATES",
                &rebate_records,
            ),
            redaction_budget_root: merkle_root(
                "PRIVATE-L2-PQ-FHE-ORDER-MATCHING-REDACTIONS",
                &redaction_records,
            ),
            quarantine_root: merkle_root(
                "PRIVATE-L2-PQ-FHE-ORDER-MATCHING-QUARANTINES",
                &quarantine_records,
            ),
            failure_accounting_root: merkle_root(
                "PRIVATE-L2-PQ-FHE-ORDER-MATCHING-FAILURES",
                &failure_records,
            ),
            deterministic_record_root: runtime_payload_root(
                "DETERMINISTIC-PUBLIC-RECORD",
                &self.public_record_without_root(),
            ),
            counter_root: runtime_payload_root("COUNTERS", &self.counters.public_record()),
        };
        self.state_root = runtime_payload_root("STATE", &self.public_record_without_root());
    }

    pub fn state_root(&self) -> String {
        self.state_root.clone()
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "private_l2_pq_confidential_fhe_order_matching_state",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_L2_PQ_CONFIDENTIAL_FHE_ORDER_MATCHING_RUNTIME_PROTOCOL_VERSION,
            "schema_version": PRIVATE_L2_PQ_CONFIDENTIAL_FHE_ORDER_MATCHING_RUNTIME_SCHEMA_VERSION,
            "hash_suite": PRIVATE_L2_PQ_CONFIDENTIAL_FHE_ORDER_MATCHING_RUNTIME_HASH_SUITE,
            "height": self.height,
            "config": self.config.public_record(),
            "roots": self.roots.public_record(),
            "counters": self.counters.public_record(),
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_root();
        if let Some(object) = record.as_object_mut() {
            object.insert("state_root".to_string(), json!(self.state_root));
            object.insert(
                "sealed_orders".to_string(),
                json!(self
                    .sealed_orders
                    .values()
                    .map(SealedOrder::public_record)
                    .collect::<Vec<_>>()),
            );
            object.insert(
                "price_buckets".to_string(),
                json!(self
                    .price_buckets
                    .values()
                    .map(EncryptedPriceBucket::public_record)
                    .collect::<Vec<_>>()),
            );
            object.insert(
                "solvers".to_string(),
                json!(self
                    .solvers
                    .values()
                    .map(PqSolver::public_record)
                    .collect::<Vec<_>>()),
            );
            object.insert(
                "solver_attestations".to_string(),
                json!(self
                    .solver_attestations
                    .values()
                    .map(SolverAttestation::public_record)
                    .collect::<Vec<_>>()),
            );
            object.insert(
                "match_batches".to_string(),
                json!(self
                    .match_batches
                    .values()
                    .map(MatchBatch::public_record)
                    .collect::<Vec<_>>()),
            );
            object.insert(
                "settlement_rebates".to_string(),
                json!(self
                    .settlement_rebates
                    .values()
                    .map(SettlementRebate::public_record)
                    .collect::<Vec<_>>()),
            );
            object.insert(
                "redaction_budgets".to_string(),
                json!(self
                    .redaction_budgets
                    .values()
                    .map(RedactionBudget::public_record)
                    .collect::<Vec<_>>()),
            );
            object.insert(
                "quarantines".to_string(),
                json!(self
                    .quarantines
                    .values()
                    .map(QuarantineAccount::public_record)
                    .collect::<Vec<_>>()),
            );
        }
        record
    }

    fn derive_counters(&self) -> Counters {
        let sealed_orders = self.sealed_orders.len() as u64;
        let admitted_orders = self
            .sealed_orders
            .values()
            .filter(|order| matches!(order.status, OrderStatus::Admitted | OrderStatus::Bucketed))
            .count() as u64;
        let bucketed_orders = self
            .sealed_orders
            .values()
            .filter(|order| order.status == OrderStatus::Bucketed)
            .count() as u64;
        let matched_orders = self
            .sealed_orders
            .values()
            .filter(|order| {
                matches!(
                    order.status,
                    OrderStatus::PartiallyFilled | OrderStatus::Filled
                )
            })
            .count() as u64;
        let settled_orders = self
            .sealed_orders
            .values()
            .filter(|order| order.status == OrderStatus::Settled)
            .count() as u64;
        let rejected_orders = self
            .sealed_orders
            .values()
            .filter(|order| order.status == OrderStatus::Rejected)
            .count() as u64;
        let quarantined_orders = self
            .sealed_orders
            .values()
            .filter(|order| order.status == OrderStatus::Quarantined)
            .count() as u64;
        let active_solvers = self
            .solvers
            .values()
            .filter(|solver| solver.status == SolverStatus::Active)
            .count() as u64;
        let successful_batches = self
            .match_batches
            .values()
            .filter(|batch| matches!(batch.status, BatchStatus::Settled | BatchStatus::Rebated))
            .count() as u64;
        let failed_batches = self
            .match_batches
            .values()
            .filter(|batch| matches!(batch.status, BatchStatus::Failed | BatchStatus::Quarantined))
            .count() as u64;
        Counters {
            sealed_orders,
            admitted_orders,
            bucketed_orders,
            matched_orders,
            settled_orders,
            rejected_orders,
            quarantined_orders,
            encrypted_price_buckets: self.price_buckets.len() as u64,
            active_solvers,
            solver_attestations: self.solver_attestations.len() as u64,
            match_batches: self.match_batches.len() as u64,
            successful_batches,
            failed_batches,
            settlement_rebates: self.settlement_rebates.len() as u64,
            redaction_budgets: self.redaction_budgets.len() as u64,
            redaction_events: self
                .redaction_budgets
                .values()
                .map(|budget| budget.used_redactions)
                .sum(),
            quarantine_events: self.quarantines.len() as u64,
            fee_micro_units_charged: self
                .match_batches
                .values()
                .map(|batch| batch.fee_micro_units)
                .sum(),
            rebate_micro_units_paid: self
                .settlement_rebates
                .values()
                .map(|rebate| rebate.rebate_micro_units)
                .sum(),
        }
    }

    fn seed_devnet(&mut self) {
        let height = self.height;
        let mut bid_order = self.devnet_order(
            "devnet-account-bidder-alpha",
            OrderSide::Bid,
            OrderKind::Limit,
            1,
            2_048,
            10,
        );
        bid_order.admit();
        bid_order.bucket();
        let mut ask_order = self.devnet_order(
            "devnet-account-maker-bravo",
            OrderSide::Ask,
            OrderKind::Limit,
            2,
            2_112,
            10,
        );
        ask_order.admit();
        ask_order.bucket();

        let mut bid_bucket = EncryptedPriceBucket::new(
            "XMR-USD-private-devnet",
            OrderSide::Bid,
            height,
            &json!({"band": "encrypted-bid-band-240-245", "scheme": "fhe"}),
            &json!({"liquidity": "encrypted-bid-liquidity", "scale": 64}),
            4_096,
        );
        bid_bucket.add_order(&bid_order);
        bid_bucket.seal(height.saturating_add(1));

        let mut ask_bucket = EncryptedPriceBucket::new(
            "XMR-USD-private-devnet",
            OrderSide::Ask,
            height,
            &json!({"band": "encrypted-ask-band-240-245", "scheme": "fhe"}),
            &json!({"liquidity": "encrypted-ask-liquidity", "scale": 64}),
            4_096,
        );
        ask_bucket.add_order(&ask_order);
        ask_bucket.seal(height.saturating_add(1));

        let mut solver = PqSolver::new(
            "devnet-fhe-solver-alpha",
            height,
            &json!({"evaluation_key": "devnet-fhe-eval-key-root"}),
            &json!({"ml_dsa": "devnet-ml-dsa-root", "slh_dsa": "devnet-slh-dsa-root"}),
            &json!({"bond": "devnet-solver-bond-root", "amount": 500_000u64}),
        );
        solver.activate();

        let mut bid_ids = BTreeSet::new();
        bid_ids.insert(bid_bucket.bucket_id.clone());
        let mut ask_ids = BTreeSet::new();
        ask_ids.insert(ask_bucket.bucket_id.clone());
        let mut batch = MatchBatch::new(
            "XMR-USD-private-devnet",
            &solver.solver_id,
            height.saturating_add(2),
            self.config.batch_ttl_blocks,
            bid_ids,
            ask_ids,
            &json!({"matched_order_count": 2u64, "clearing_price": "encrypted-midpoint"}),
            &json!({"fill_vector": "encrypted-fill-vector-root"}),
            &json!({"settlement": "devnet-confidential-settlement-intent"}),
            &json!({"fee_micro_units": 240u64, "rebate_micro_units": 180u64}),
            &json!({"redacted_fields": ["price", "amount"], "budget_units": 2u64}),
        );
        batch.attest();
        batch.settle();

        let attestation = SolverAttestation::new(
            &solver.solver_id,
            &batch.batch_id,
            height.saturating_add(3),
            &json!({"circuit": "fhe-private-crossing-v1", "gate_count": 1_048_576u64}),
            &json!({"transcript": "devnet-fhe-solver-transcript-root"}),
            &json!({"ml_dsa_signature": "devnet-solver-ml-dsa-signature-root"}),
            &json!({"vk": "devnet-fhe-crossing-verification-key-root"}),
            self.config.min_pq_security_bits,
        );

        let rebate = SettlementRebate::new(
            &batch.batch_id,
            "devnet-account-bidder-alpha",
            height.saturating_add(4),
            &json!({"fee_micro_units": 240u64}),
            &json!({"rebate_micro_units": 180u64, "note": "encrypted-low-fee-rebate-note"}),
            &json!({"receipt": "devnet-settlement-receipt-root"}),
        );

        let mut budget = RedactionBudget::new(
            "devnet-account-bidder-alpha",
            "XMR-USD-private-devnet",
            height,
            self.config.order_ttl_blocks,
            8,
            &json!({"scope": "sealed-order-public-record-redactions"}),
        );
        budget.consume(2).ok();

        let quarantine = QuarantineAccount::new(
            "devnet-rejected-order-sentinel",
            "sealed_order",
            QuarantineReason::InvalidCiphertext,
            height.saturating_add(5),
            &json!({"ciphertext": "malformed-devnet-ciphertext-root"}),
            &json!({"slashed_micro_units": 50u64, "failure": "ciphertext-decode"}),
        );

        self.sealed_orders
            .insert(bid_order.order_id.clone(), bid_order);
        self.sealed_orders
            .insert(ask_order.order_id.clone(), ask_order);
        self.price_buckets
            .insert(bid_bucket.bucket_id.clone(), bid_bucket);
        self.price_buckets
            .insert(ask_bucket.bucket_id.clone(), ask_bucket);
        self.solvers.insert(solver.solver_id.clone(), solver);
        self.match_batches.insert(batch.batch_id.clone(), batch);
        self.solver_attestations
            .insert(attestation.attestation_id.clone(), attestation);
        self.settlement_rebates
            .insert(rebate.rebate_id.clone(), rebate);
        self.redaction_budgets
            .insert(budget.budget_id.clone(), budget);
        self.quarantines
            .insert(quarantine.quarantine_id.clone(), quarantine);
    }

    fn devnet_order(
        &self,
        account_commitment: &str,
        side: OrderSide,
        order_kind: OrderKind,
        nonce: u64,
        privacy_set_size: u64,
        max_fee_bps: u64,
    ) -> SealedOrder {
        SealedOrder::new(
            account_commitment,
            side,
            order_kind,
            self.height.saturating_add(nonce),
            self.config.order_ttl_blocks,
            &json!({"sealed_order": format!("devnet-sealed-order-{nonce}")}),
            &json!({"encrypted_price": format!("devnet-encrypted-price-{nonce}")}),
            &json!({"encrypted_amount": format!("devnet-encrypted-amount-{nonce}")}),
            &json!({"bucket_hint": format!("devnet-bucket-hint-{nonce}")}),
            &json!({"pq_authorization": format!("devnet-pq-authorization-{nonce}")}),
            privacy_set_size,
            self.config.min_pq_security_bits,
            max_fee_bps,
        )
    }
}

pub trait PublicRecord {
    fn public_record(&self) -> Value;
}

impl PublicRecord for SealedOrder {
    fn public_record(&self) -> Value {
        SealedOrder::public_record(self)
    }
}

impl PublicRecord for EncryptedPriceBucket {
    fn public_record(&self) -> Value {
        EncryptedPriceBucket::public_record(self)
    }
}

impl PublicRecord for PqSolver {
    fn public_record(&self) -> Value {
        PqSolver::public_record(self)
    }
}

impl PublicRecord for SolverAttestation {
    fn public_record(&self) -> Value {
        SolverAttestation::public_record(self)
    }
}

impl PublicRecord for MatchBatch {
    fn public_record(&self) -> Value {
        MatchBatch::public_record(self)
    }
}

impl PublicRecord for SettlementRebate {
    fn public_record(&self) -> Value {
        SettlementRebate::public_record(self)
    }
}

impl PublicRecord for RedactionBudget {
    fn public_record(&self) -> Value {
        RedactionBudget::public_record(self)
    }
}

impl PublicRecord for QuarantineAccount {
    fn public_record(&self) -> Value {
        QuarantineAccount::public_record(self)
    }
}

fn values_to_records<T: PublicRecord>(values: &BTreeMap<String, T>) -> Vec<Value> {
    values
        .iter()
        .map(|(id, value)| json!({ "id": id, "record": value.public_record() }))
        .collect()
}

pub fn runtime_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        &format!("PRIVATE-L2-PQ-CONFIDENTIAL-FHE-ORDER-MATCHING-{domain}"),
        &[HashPart::Json(payload)],
        32,
    )
}

pub fn runtime_string_root(domain: &str, value: &str) -> String {
    domain_hash(
        &format!("PRIVATE-L2-PQ-CONFIDENTIAL-FHE-ORDER-MATCHING-{domain}"),
        &[HashPart::Str(value)],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn sealed_order_id(
    account_commitment: &str,
    side: OrderSide,
    order_kind: OrderKind,
    opened_height: u64,
    expires_height: u64,
    sealed_payload_root: &str,
    encrypted_price_root: &str,
    encrypted_amount_root: &str,
    bucket_hint_root: &str,
    nullifier_hash: &str,
    pq_authorization_root: &str,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-FHE-ORDER-MATCHING-SEALED-ORDER-ID",
        &[
            HashPart::Str(account_commitment),
            HashPart::Str(side.as_str()),
            HashPart::Str(order_kind.as_str()),
            HashPart::Int(opened_height as i128),
            HashPart::Int(expires_height as i128),
            HashPart::Str(sealed_payload_root),
            HashPart::Str(encrypted_price_root),
            HashPart::Str(encrypted_amount_root),
            HashPart::Str(bucket_hint_root),
            HashPart::Str(nullifier_hash),
            HashPart::Str(pq_authorization_root),
        ],
        32,
    )
}

pub fn price_bucket_id(
    market_id: &str,
    side: OrderSide,
    opened_height: u64,
    encrypted_price_band_root: &str,
    encrypted_liquidity_root: &str,
    bucket_commitment_root: &str,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-FHE-ORDER-MATCHING-PRICE-BUCKET-ID",
        &[
            HashPart::Str(market_id),
            HashPart::Str(side.as_str()),
            HashPart::Int(opened_height as i128),
            HashPart::Str(encrypted_price_band_root),
            HashPart::Str(encrypted_liquidity_root),
            HashPart::Str(bucket_commitment_root),
        ],
        32,
    )
}

pub fn solver_id(
    operator_commitment: &str,
    registered_height: u64,
    fhe_key_root: &str,
    pq_identity_root: &str,
    stake_root: &str,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-FHE-ORDER-MATCHING-SOLVER-ID",
        &[
            HashPart::Str(operator_commitment),
            HashPart::Int(registered_height as i128),
            HashPart::Str(fhe_key_root),
            HashPart::Str(pq_identity_root),
            HashPart::Str(stake_root),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn solver_attestation_id(
    solver_id: &str,
    batch_id: &str,
    attested_height: u64,
    circuit_root: &str,
    transcript_root: &str,
    pq_signature_root: &str,
    verification_key_root: &str,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-FHE-ORDER-MATCHING-SOLVER-ATTESTATION-ID",
        &[
            HashPart::Str(solver_id),
            HashPart::Str(batch_id),
            HashPart::Int(attested_height as i128),
            HashPart::Str(circuit_root),
            HashPart::Str(transcript_root),
            HashPart::Str(pq_signature_root),
            HashPart::Str(verification_key_root),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn match_batch_id(
    market_id: &str,
    solver_id: &str,
    opened_height: u64,
    expires_height: u64,
    sealed_order_root: &str,
    crossing_result_root: &str,
    encrypted_fill_root: &str,
    settlement_intent_root: &str,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-FHE-ORDER-MATCHING-BATCH-ID",
        &[
            HashPart::Str(market_id),
            HashPart::Str(solver_id),
            HashPart::Int(opened_height as i128),
            HashPart::Int(expires_height as i128),
            HashPart::Str(sealed_order_root),
            HashPart::Str(crossing_result_root),
            HashPart::Str(encrypted_fill_root),
            HashPart::Str(settlement_intent_root),
        ],
        32,
    )
}

pub fn settlement_rebate_id(
    batch_id: &str,
    account_commitment: &str,
    height: u64,
    fee_root: &str,
    rebate_note_root: &str,
    settlement_receipt_root: &str,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-FHE-ORDER-MATCHING-SETTLEMENT-REBATE-ID",
        &[
            HashPart::Str(batch_id),
            HashPart::Str(account_commitment),
            HashPart::Int(height as i128),
            HashPart::Str(fee_root),
            HashPart::Str(rebate_note_root),
            HashPart::Str(settlement_receipt_root),
        ],
        32,
    )
}

pub fn redaction_budget_id(
    account_commitment: &str,
    market_id: &str,
    opened_height: u64,
    expires_height: u64,
    max_redactions: u64,
    scope_root: &str,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-FHE-ORDER-MATCHING-REDACTION-BUDGET-ID",
        &[
            HashPart::Str(account_commitment),
            HashPart::Str(market_id),
            HashPart::Int(opened_height as i128),
            HashPart::Int(expires_height as i128),
            HashPart::Int(max_redactions as i128),
            HashPart::Str(scope_root),
        ],
        32,
    )
}

pub fn quarantine_id(
    subject_id: &str,
    subject_kind: &str,
    reason: QuarantineReason,
    opened_height: u64,
    evidence_root: &str,
    failure_accounting_root: &str,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-FHE-ORDER-MATCHING-QUARANTINE-ID",
        &[
            HashPart::Str(subject_id),
            HashPart::Str(subject_kind),
            HashPart::Str(reason.as_str()),
            HashPart::Int(opened_height as i128),
            HashPart::Str(evidence_root),
            HashPart::Str(failure_accounting_root),
        ],
        32,
    )
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn demo() -> State {
    State::demo()
}

pub fn public_record(state: &State) -> serde_json::Value {
    state.public_record()
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}
