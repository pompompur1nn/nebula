use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2PqConfidentialContractComposableLimitOrderBookRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-confidential-contract-composable-limit-order-book-runtime-v1";
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const SEALED_ORDER_SUITE: &str = "ML-KEM-1024+zk-sealed-contract-limit-order-v1";
pub const CONTRACT_CALLBACK_SUITE: &str = "pq-signed-confidential-contract-callback-v1";
pub const SOLVER_ATTESTATION_SUITE: &str =
    "ML-DSA-87+SLH-DSA-SHAKE-256f-batch-matching-solver-attestation-v1";
pub const BATCH_MATCHING_SUITE: &str = "mev-safe-confidential-composable-clob-batch-v1";
pub const PUBLIC_RECORD_SUITE: &str = "roots-only-confidential-clob-public-record-v1";
pub const DEVNET_L2_HEIGHT: u64 = 1_284_000;
pub const DEVNET_MONERO_HEIGHT: u64 = 3_590_000;
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 16_384;
pub const DEFAULT_BATCH_PRIVACY_SET_SIZE: u64 = 131_072;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_ORDER_TTL_BLOCKS: u64 = 64;
pub const DEFAULT_CALLBACK_TTL_BLOCKS: u64 = 16;
pub const DEFAULT_BATCH_TTL_BLOCKS: u64 = 12;
pub const DEFAULT_MAX_TAKER_FEE_BPS: u64 = 18;
pub const DEFAULT_MAX_MAKER_FEE_BPS: u64 = 8;
pub const DEFAULT_TARGET_REBATE_BPS: u64 = 5;
pub const DEFAULT_REDACTION_BUDGET_UNITS: u64 = 1_000_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PairKind {
    Spot,
    Stable,
    Perpetual,
    Options,
    Rwa,
    VaultShare,
    BridgeAsset,
}

impl PairKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Spot => "spot",
            Self::Stable => "stable",
            Self::Perpetual => "perpetual",
            Self::Options => "options",
            Self::Rwa => "rwa",
            Self::VaultShare => "vault_share",
            Self::BridgeAsset => "bridge_asset",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PairStatus {
    Registered,
    Active,
    Paused,
    SettlementOnly,
    Retired,
}

impl PairStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Registered => "registered",
            Self::Active => "active",
            Self::Paused => "paused",
            Self::SettlementOnly => "settlement_only",
            Self::Retired => "retired",
        }
    }

    pub fn accepts_orders(self) -> bool {
        matches!(self, Self::Registered | Self::Active)
    }
}

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
pub enum TimeInForce {
    ImmediateOrCancel,
    FillOrKill,
    GoodTilHeight,
    PostOnly,
    MakerPeg,
}

impl TimeInForce {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ImmediateOrCancel => "immediate_or_cancel",
            Self::FillOrKill => "fill_or_kill",
            Self::GoodTilHeight => "good_til_height",
            Self::PostOnly => "post_only",
            Self::MakerPeg => "maker_peg",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OrderStatus {
    Sealed,
    Admitted,
    CallbackChecked,
    SolverQueued,
    BatchLocked,
    PartiallyFilled,
    Filled,
    Cancelled,
    Expired,
    Rejected,
}

impl OrderStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sealed => "sealed",
            Self::Admitted => "admitted",
            Self::CallbackChecked => "callback_checked",
            Self::SolverQueued => "solver_queued",
            Self::BatchLocked => "batch_locked",
            Self::PartiallyFilled => "partially_filled",
            Self::Filled => "filled",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
            Self::Rejected => "rejected",
        }
    }

    pub fn matchable(self) -> bool {
        matches!(
            self,
            Self::Sealed | Self::Admitted | Self::CallbackChecked | Self::SolverQueued
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CallbackKind {
    BeforePlace,
    BeforeMatch,
    AfterFill,
    AfterCancel,
    RebateClaim,
    RiskHook,
}

impl CallbackKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BeforePlace => "before_place",
            Self::BeforeMatch => "before_match",
            Self::AfterFill => "after_fill",
            Self::AfterCancel => "after_cancel",
            Self::RebateClaim => "rebate_claim",
            Self::RiskHook => "risk_hook",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CallbackStatus {
    Scheduled,
    Proved,
    Consumed,
    TimedOut,
    Rejected,
}

impl CallbackStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Scheduled => "scheduled",
            Self::Proved => "proved",
            Self::Consumed => "consumed",
            Self::TimedOut => "timed_out",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SolverStatus {
    Registered,
    Active,
    RateLimited,
    Quarantined,
    Slashed,
    Retired,
}

impl SolverStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Registered => "registered",
            Self::Active => "active",
            Self::RateLimited => "rate_limited",
            Self::Quarantined => "quarantined",
            Self::Slashed => "slashed",
            Self::Retired => "retired",
        }
    }

    pub fn can_solve(self) -> bool {
        matches!(self, Self::Registered | Self::Active | Self::RateLimited)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchStatus {
    Built,
    SolverAttested,
    MevLocked,
    SettlementReady,
    Settled,
    Disputed,
    Expired,
}

impl BatchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Built => "built",
            Self::SolverAttested => "solver_attested",
            Self::MevLocked => "mev_locked",
            Self::SettlementReady => "settlement_ready",
            Self::Settled => "settled",
            Self::Disputed => "disputed",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PublicRecordKind {
    TokenPair,
    SealedOrder,
    ContractCallback,
    SolverAttestation,
    MatchingBatch,
    MevSafeFill,
    FeeRebate,
    PrivacyRedaction,
}

impl PublicRecordKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::TokenPair => "token_pair",
            Self::SealedOrder => "sealed_order",
            Self::ContractCallback => "contract_callback",
            Self::SolverAttestation => "solver_attestation",
            Self::MatchingBatch => "matching_batch",
            Self::MevSafeFill => "mev_safe_fill",
            Self::FeeRebate => "fee_rebate",
            Self::PrivacyRedaction => "privacy_redaction",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub monero_network: String,
    pub l2_network: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub sealed_order_suite: String,
    pub callback_suite: String,
    pub solver_attestation_suite: String,
    pub batch_matching_suite: String,
    pub settlement_asset_id: String,
    pub fee_asset_id: String,
    pub min_privacy_set_size: u64,
    pub batch_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub max_taker_fee_bps: u64,
    pub max_maker_fee_bps: u64,
    pub target_rebate_bps: u64,
    pub order_ttl_blocks: u64,
    pub callback_ttl_blocks: u64,
    pub batch_ttl_blocks: u64,
    pub redaction_budget_units: u64,
    pub quantum_resistance_required: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            monero_network: "monero-devnet".to_string(),
            l2_network: "nebula-devnet".to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            sealed_order_suite: SEALED_ORDER_SUITE.to_string(),
            callback_suite: CONTRACT_CALLBACK_SUITE.to_string(),
            solver_attestation_suite: SOLVER_ATTESTATION_SUITE.to_string(),
            batch_matching_suite: BATCH_MATCHING_SUITE.to_string(),
            settlement_asset_id: "asset:private-dusd".to_string(),
            fee_asset_id: "asset:piconero".to_string(),
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            batch_privacy_set_size: DEFAULT_BATCH_PRIVACY_SET_SIZE,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            max_taker_fee_bps: DEFAULT_MAX_TAKER_FEE_BPS,
            max_maker_fee_bps: DEFAULT_MAX_MAKER_FEE_BPS,
            target_rebate_bps: DEFAULT_TARGET_REBATE_BPS,
            order_ttl_blocks: DEFAULT_ORDER_TTL_BLOCKS,
            callback_ttl_blocks: DEFAULT_CALLBACK_TTL_BLOCKS,
            batch_ttl_blocks: DEFAULT_BATCH_TTL_BLOCKS,
            redaction_budget_units: DEFAULT_REDACTION_BUDGET_UNITS,
            quantum_resistance_required: true,
        }
    }
}

impl Config {
    pub fn validate(&self) -> Result<()> {
        require(self.chain_id == CHAIN_ID, "chain id mismatch")?;
        require(
            self.protocol_version == PROTOCOL_VERSION,
            "protocol version mismatch",
        )?;
        require(
            self.schema_version == SCHEMA_VERSION,
            "schema version mismatch",
        )?;
        require_bps("max taker fee bps", self.max_taker_fee_bps)?;
        require_bps("max maker fee bps", self.max_maker_fee_bps)?;
        require_bps("target rebate bps", self.target_rebate_bps)?;
        require(
            self.batch_privacy_set_size >= self.min_privacy_set_size,
            "batch privacy set must cover minimum privacy set",
        )?;
        require(
            self.min_pq_security_bits >= DEFAULT_MIN_PQ_SECURITY_BITS,
            "pq security bits below policy",
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_pq_confidential_contract_composable_clob_config",
            "chain_id": self.chain_id,
            "monero_network": self.monero_network,
            "l2_network": self.l2_network,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "sealed_order_suite": self.sealed_order_suite,
            "callback_suite": self.callback_suite,
            "solver_attestation_suite": self.solver_attestation_suite,
            "batch_matching_suite": self.batch_matching_suite,
            "settlement_asset_id": self.settlement_asset_id,
            "fee_asset_id": self.fee_asset_id,
            "privacy": {
                "min_privacy_set_size": self.min_privacy_set_size,
                "batch_privacy_set_size": self.batch_privacy_set_size,
                "redaction_budget_units": self.redaction_budget_units,
            },
            "fees": {
                "max_taker_fee_bps": self.max_taker_fee_bps,
                "max_maker_fee_bps": self.max_maker_fee_bps,
                "target_rebate_bps": self.target_rebate_bps,
            },
            "ttl_blocks": {
                "order": self.order_ttl_blocks,
                "callback": self.callback_ttl_blocks,
                "batch": self.batch_ttl_blocks,
            },
            "min_pq_security_bits": self.min_pq_security_bits,
            "quantum_resistance_required": self.quantum_resistance_required,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub token_pairs: u64,
    pub sealed_orders: u64,
    pub callbacks: u64,
    pub solver_attestations: u64,
    pub matching_batches: u64,
    pub mev_safe_fills: u64,
    pub fee_rebates: u64,
    pub privacy_redactions: u64,
    pub public_records: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_pq_confidential_contract_composable_clob_counters",
            "token_pairs": self.token_pairs,
            "sealed_orders": self.sealed_orders,
            "callbacks": self.callbacks,
            "solver_attestations": self.solver_attestations,
            "matching_batches": self.matching_batches,
            "mev_safe_fills": self.mev_safe_fills,
            "fee_rebates": self.fee_rebates,
            "privacy_redactions": self.privacy_redactions,
            "public_records": self.public_records,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TokenPairRegistry {
    pub pair_id: String,
    pub base_asset_id: String,
    pub quote_asset_id: String,
    pub pair_kind: PairKind,
    pub status: PairStatus,
    pub tick_size_commitment: String,
    pub min_lot_commitment: String,
    pub fee_vault_commitment: String,
    pub callback_contracts: BTreeSet<String>,
    pub registered_at_height: u64,
}

impl TokenPairRegistry {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_pq_confidential_contract_composable_clob_pair",
            "pair_id": self.pair_id,
            "base_asset_id": self.base_asset_id,
            "quote_asset_id": self.quote_asset_id,
            "pair_kind": self.pair_kind.as_str(),
            "status": self.status.as_str(),
            "tick_size_commitment": self.tick_size_commitment,
            "min_lot_commitment": self.min_lot_commitment,
            "fee_vault_commitment": self.fee_vault_commitment,
            "callback_contracts": self.callback_contracts,
            "registered_at_height": self.registered_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SealedOrderCommitment {
    pub order_id: String,
    pub pair_id: String,
    pub owner_commitment: String,
    pub side: OrderSide,
    pub time_in_force: TimeInForce,
    pub status: OrderStatus,
    pub sealed_terms_root: String,
    pub price_commitment: String,
    pub quantity_commitment: String,
    pub callback_policy_root: String,
    pub nullifier_root: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub admitted_at_height: u64,
    pub expires_at_height: u64,
}

impl SealedOrderCommitment {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_pq_confidential_contract_composable_clob_sealed_order",
            "order_id": self.order_id,
            "pair_id": self.pair_id,
            "owner_commitment": self.owner_commitment,
            "side": self.side.as_str(),
            "time_in_force": self.time_in_force.as_str(),
            "status": self.status.as_str(),
            "sealed_terms_root": self.sealed_terms_root,
            "price_commitment": self.price_commitment,
            "quantity_commitment": self.quantity_commitment,
            "callback_policy_root": self.callback_policy_root,
            "nullifier_root": self.nullifier_root,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "admitted_at_height": self.admitted_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ContractCallback {
    pub callback_id: String,
    pub order_id: String,
    pub pair_id: String,
    pub contract_id: String,
    pub callback_kind: CallbackKind,
    pub status: CallbackStatus,
    pub call_data_root: String,
    pub output_root: String,
    pub gas_note_commitment: String,
    pub proof_root: String,
    pub scheduled_at_height: u64,
    pub deadline_height: u64,
}

impl ContractCallback {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_pq_confidential_contract_composable_clob_callback",
            "callback_id": self.callback_id,
            "order_id": self.order_id,
            "pair_id": self.pair_id,
            "contract_id": self.contract_id,
            "callback_kind": self.callback_kind.as_str(),
            "status": self.status.as_str(),
            "call_data_root": self.call_data_root,
            "output_root": self.output_root,
            "gas_note_commitment": self.gas_note_commitment,
            "proof_root": self.proof_root,
            "scheduled_at_height": self.scheduled_at_height,
            "deadline_height": self.deadline_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqSolverAttestation {
    pub attestation_id: String,
    pub solver_commitment: String,
    pub batch_id: String,
    pub pair_id: String,
    pub solver_public_key_root: String,
    pub matched_order_root: String,
    pub clearing_price_commitment: String,
    pub surplus_commitment: String,
    pub fairness_proof_root: String,
    pub pq_signature_root: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub attested_at_height: u64,
}

impl PqSolverAttestation {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_pq_confidential_contract_composable_clob_solver_attestation",
            "attestation_id": self.attestation_id,
            "solver_commitment": self.solver_commitment,
            "batch_id": self.batch_id,
            "pair_id": self.pair_id,
            "solver_public_key_root": self.solver_public_key_root,
            "matched_order_root": self.matched_order_root,
            "clearing_price_commitment": self.clearing_price_commitment,
            "surplus_commitment": self.surplus_commitment,
            "fairness_proof_root": self.fairness_proof_root,
            "pq_signature_root": self.pq_signature_root,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "attested_at_height": self.attested_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MatchingBatch {
    pub batch_id: String,
    pub pair_id: String,
    pub status: BatchStatus,
    pub bid_order_root: String,
    pub ask_order_root: String,
    pub callback_root: String,
    pub solver_attestation_root: String,
    pub mev_lock_root: String,
    pub settlement_root: String,
    pub fill_count: u64,
    pub opened_at_height: u64,
    pub settlement_deadline_height: u64,
}

impl MatchingBatch {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_pq_confidential_contract_composable_clob_matching_batch",
            "batch_id": self.batch_id,
            "pair_id": self.pair_id,
            "status": self.status.as_str(),
            "bid_order_root": self.bid_order_root,
            "ask_order_root": self.ask_order_root,
            "callback_root": self.callback_root,
            "solver_attestation_root": self.solver_attestation_root,
            "mev_lock_root": self.mev_lock_root,
            "settlement_root": self.settlement_root,
            "fill_count": self.fill_count,
            "opened_at_height": self.opened_at_height,
            "settlement_deadline_height": self.settlement_deadline_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MevSafeFill {
    pub fill_id: String,
    pub batch_id: String,
    pub maker_order_id: String,
    pub taker_order_id: String,
    pub pair_id: String,
    pub fill_commitment: String,
    pub price_commitment: String,
    pub quantity_commitment: String,
    pub sequencing_proof_root: String,
    pub anti_sandwich_root: String,
    pub finalized_at_height: u64,
}

impl MevSafeFill {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_pq_confidential_contract_composable_clob_mev_safe_fill",
            "fill_id": self.fill_id,
            "batch_id": self.batch_id,
            "maker_order_id": self.maker_order_id,
            "taker_order_id": self.taker_order_id,
            "pair_id": self.pair_id,
            "fill_commitment": self.fill_commitment,
            "price_commitment": self.price_commitment,
            "quantity_commitment": self.quantity_commitment,
            "sequencing_proof_root": self.sequencing_proof_root,
            "anti_sandwich_root": self.anti_sandwich_root,
            "finalized_at_height": self.finalized_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FeeRebate {
    pub rebate_id: String,
    pub batch_id: String,
    pub recipient_commitment: String,
    pub rebate_note_commitment: String,
    pub rebate_bps: u64,
    pub reason_root: String,
    pub issued_at_height: u64,
}

impl FeeRebate {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_pq_confidential_contract_composable_clob_fee_rebate",
            "rebate_id": self.rebate_id,
            "batch_id": self.batch_id,
            "recipient_commitment": self.recipient_commitment,
            "rebate_note_commitment": self.rebate_note_commitment,
            "rebate_bps": self.rebate_bps,
            "reason_root": self.reason_root,
            "issued_at_height": self.issued_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivacyRedactionBudget {
    pub budget_id: String,
    pub subject_root: String,
    pub scope: String,
    pub units_granted: u64,
    pub units_spent: u64,
    pub min_public_delay_blocks: u64,
    pub expires_at_height: u64,
}

impl PrivacyRedactionBudget {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_pq_confidential_contract_composable_clob_privacy_redaction_budget",
            "budget_id": self.budget_id,
            "subject_root": self.subject_root,
            "scope": self.scope,
            "units_granted": self.units_granted,
            "units_spent": self.units_spent,
            "units_remaining": self.units_granted.saturating_sub(self.units_spent),
            "min_public_delay_blocks": self.min_public_delay_blocks,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublicRecord {
    pub record_id: String,
    pub record_kind: PublicRecordKind,
    pub subject_id: String,
    pub payload_root: String,
    pub state_root: String,
    pub height: u64,
}

impl PublicRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_pq_confidential_contract_composable_clob_public_record",
            "record_id": self.record_id,
            "record_kind": self.record_kind.as_str(),
            "subject_id": self.subject_id,
            "payload_root": self.payload_root,
            "state_root": self.state_root,
            "height": self.height,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub pair_root: String,
    pub sealed_order_root: String,
    pub callback_root: String,
    pub solver_attestation_root: String,
    pub matching_batch_root: String,
    pub mev_safe_fill_root: String,
    pub fee_rebate_root: String,
    pub privacy_redaction_root: String,
    pub public_record_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_pq_confidential_contract_composable_clob_roots",
            "config_root": self.config_root,
            "pair_root": self.pair_root,
            "sealed_order_root": self.sealed_order_root,
            "callback_root": self.callback_root,
            "solver_attestation_root": self.solver_attestation_root,
            "matching_batch_root": self.matching_batch_root,
            "mev_safe_fill_root": self.mev_safe_fill_root,
            "fee_rebate_root": self.fee_rebate_root,
            "privacy_redaction_root": self.privacy_redaction_root,
            "public_record_root": self.public_record_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub current_l2_height: u64,
    pub current_monero_height: u64,
    pub token_pairs: BTreeMap<String, TokenPairRegistry>,
    pub sealed_orders: BTreeMap<String, SealedOrderCommitment>,
    pub callbacks: BTreeMap<String, ContractCallback>,
    pub solver_attestations: BTreeMap<String, PqSolverAttestation>,
    pub matching_batches: BTreeMap<String, MatchingBatch>,
    pub mev_safe_fills: BTreeMap<String, MevSafeFill>,
    pub fee_rebates: BTreeMap<String, FeeRebate>,
    pub privacy_redactions: BTreeMap<String, PrivacyRedactionBudget>,
    pub public_records: BTreeMap<String, PublicRecord>,
    pub roots: Roots,
}

impl Default for State {
    fn default() -> Self {
        let mut state = Self {
            config: Config::default(),
            counters: Counters::default(),
            current_l2_height: DEVNET_L2_HEIGHT,
            current_monero_height: DEVNET_MONERO_HEIGHT,
            token_pairs: BTreeMap::new(),
            sealed_orders: BTreeMap::new(),
            callbacks: BTreeMap::new(),
            solver_attestations: BTreeMap::new(),
            matching_batches: BTreeMap::new(),
            mev_safe_fills: BTreeMap::new(),
            fee_rebates: BTreeMap::new(),
            privacy_redactions: BTreeMap::new(),
            public_records: BTreeMap::new(),
            roots: Roots::default(),
        };
        state.refresh_roots();
        state
    }
}

impl State {
    pub fn new(config: Config, current_l2_height: u64, current_monero_height: u64) -> Result<Self> {
        config.validate()?;
        let mut state = Self {
            config,
            current_l2_height,
            current_monero_height,
            ..Self::default()
        };
        state.refresh_roots();
        Ok(state)
    }

    pub fn devnet() -> Self {
        let mut state = Self::new(Config::default(), DEVNET_L2_HEIGHT, DEVNET_MONERO_HEIGHT)
            .expect("valid devnet config");
        let wxmr_dusd = state.insert_pair("wxmr", "private-dusd", PairKind::Spot);
        let vault_dusd =
            state.insert_pair("vault-share-alpha", "private-dusd", PairKind::VaultShare);
        let bid = state.insert_order(
            &wxmr_dusd,
            "maker-alpha",
            OrderSide::Bid,
            TimeInForce::PostOnly,
        );
        let ask = state.insert_order(
            &wxmr_dusd,
            "taker-beta",
            OrderSide::Ask,
            TimeInForce::GoodTilHeight,
        );
        let callback = state.insert_callback(
            &bid,
            &wxmr_dusd,
            "contract:vault-rebate",
            CallbackKind::BeforeMatch,
        );
        let batch = state.insert_batch(&wxmr_dusd, &[bid.clone()], &[ask.clone()], &[callback]);
        state.insert_attestation(&batch, &wxmr_dusd, "solver-alpha");
        state.insert_fill(&batch, &bid, &ask, &wxmr_dusd);
        state.insert_rebate(&batch, "maker-alpha", state.config.target_rebate_bps);
        state.insert_redaction("devnet-clob-epoch", "sealed_order_terms", 250_000);
        state.insert_pair_public_records();
        state.insert_pair("wxmr", "vault-share-alpha", PairKind::BridgeAsset);
        state.insert_order(
            &vault_dusd,
            "strategy-gamma",
            OrderSide::Bid,
            TimeInForce::MakerPeg,
        );
        state.refresh_roots();
        state
    }

    pub fn demo() -> Self {
        Self::devnet()
    }

    pub fn public_record_without_roots(&self) -> Value {
        json!({
            "kind": "private_l2_pq_confidential_contract_composable_limit_order_book_state",
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "chain_id": CHAIN_ID,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "current_l2_height": self.current_l2_height,
            "current_monero_height": self.current_monero_height,
            "token_pairs": records_from_map(&self.token_pairs),
            "sealed_orders": records_from_map(&self.sealed_orders),
            "callbacks": records_from_map(&self.callbacks),
            "solver_attestations": records_from_map(&self.solver_attestations),
            "matching_batches": records_from_map(&self.matching_batches),
            "mev_safe_fills": records_from_map(&self.mev_safe_fills),
            "fee_rebates": records_from_map(&self.fee_rebates),
            "privacy_redactions": records_from_map(&self.privacy_redactions),
            "public_records": records_from_map(&self.public_records),
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_roots();
        if let Value::Object(values) = &mut record {
            values.insert("roots".to_string(), self.roots.public_record());
        }
        record
    }

    pub fn state_root(&self) -> String {
        state_root_from_record(&self.public_record_without_roots())
    }

    pub fn operator_summary(&self) -> Value {
        json!({
            "kind": "private_l2_pq_confidential_contract_composable_clob_operator_summary",
            "protocol_version": PROTOCOL_VERSION,
            "current_l2_height": self.current_l2_height,
            "current_monero_height": self.current_monero_height,
            "active_pairs": self.token_pairs.values().filter(|pair| pair.status.accepts_orders()).count(),
            "matchable_orders": self.sealed_orders.values().filter(|order| order.status.matchable()).count(),
            "open_batches": self.matching_batches.values().filter(|batch| !matches!(batch.status, BatchStatus::Settled | BatchStatus::Expired)).count(),
            "callback_queue": self.callbacks.values().filter(|callback| matches!(callback.status, CallbackStatus::Scheduled | CallbackStatus::Proved)).count(),
            "redaction_units_remaining": self.privacy_redactions.values().map(|budget| budget.units_granted.saturating_sub(budget.units_spent)).sum::<u64>(),
            "roots": self.roots.public_record(),
        })
    }

    pub fn refresh_counters(&mut self) {
        self.counters.token_pairs = self.token_pairs.len() as u64;
        self.counters.sealed_orders = self.sealed_orders.len() as u64;
        self.counters.callbacks = self.callbacks.len() as u64;
        self.counters.solver_attestations = self.solver_attestations.len() as u64;
        self.counters.matching_batches = self.matching_batches.len() as u64;
        self.counters.mev_safe_fills = self.mev_safe_fills.len() as u64;
        self.counters.fee_rebates = self.fee_rebates.len() as u64;
        self.counters.privacy_redactions = self.privacy_redactions.len() as u64;
        self.counters.public_records = self.public_records.len() as u64;
    }

    pub fn refresh_roots(&mut self) {
        self.refresh_counters();
        self.roots = Roots {
            config_root: payload_root("CONFIG", &self.config.public_record()),
            pair_root: map_root("PAIR", records_from_map(&self.token_pairs)),
            sealed_order_root: map_root("SEALED-ORDER", records_from_map(&self.sealed_orders)),
            callback_root: map_root("CALLBACK", records_from_map(&self.callbacks)),
            solver_attestation_root: map_root(
                "SOLVER-ATTESTATION",
                records_from_map(&self.solver_attestations),
            ),
            matching_batch_root: map_root(
                "MATCHING-BATCH",
                records_from_map(&self.matching_batches),
            ),
            mev_safe_fill_root: map_root("MEV-SAFE-FILL", records_from_map(&self.mev_safe_fills)),
            fee_rebate_root: map_root("FEE-REBATE", records_from_map(&self.fee_rebates)),
            privacy_redaction_root: map_root(
                "PRIVACY-REDACTION",
                records_from_map(&self.privacy_redactions),
            ),
            public_record_root: map_root("PUBLIC-RECORDS", records_from_map(&self.public_records)),
            state_root: String::new(),
        };
        self.roots.state_root = self.state_root();
    }

    fn insert_pair(&mut self, base: &str, quote: &str, pair_kind: PairKind) -> String {
        let pair_id = deterministic_id("pair", &[base, quote, pair_kind.as_str()]);
        let mut callbacks = BTreeSet::new();
        callbacks.insert(format!("contract:{base}-{quote}-risk-hook"));
        let pair = TokenPairRegistry {
            pair_id: pair_id.clone(),
            base_asset_id: format!("asset:{base}"),
            quote_asset_id: format!("asset:{quote}"),
            pair_kind,
            status: PairStatus::Active,
            tick_size_commitment: deterministic_root("TICK", &pair_id),
            min_lot_commitment: deterministic_root("LOT", &pair_id),
            fee_vault_commitment: deterministic_root("FEE-VAULT", &pair_id),
            callback_contracts: callbacks,
            registered_at_height: self.current_l2_height,
        };
        self.token_pairs.insert(pair_id.clone(), pair);
        pair_id
    }

    fn insert_order(
        &mut self,
        pair_id: &str,
        owner: &str,
        side: OrderSide,
        time_in_force: TimeInForce,
    ) -> String {
        let order_id = deterministic_id("order", &[pair_id, owner, side.as_str()]);
        let order = SealedOrderCommitment {
            order_id: order_id.clone(),
            pair_id: pair_id.to_string(),
            owner_commitment: deterministic_root("OWNER", owner),
            side,
            time_in_force,
            status: OrderStatus::CallbackChecked,
            sealed_terms_root: deterministic_root("SEALED-TERMS", &order_id),
            price_commitment: deterministic_root("PRICE", &order_id),
            quantity_commitment: deterministic_root("QTY", &order_id),
            callback_policy_root: deterministic_root("CALLBACK-POLICY", &order_id),
            nullifier_root: deterministic_root("ORDER-NULLIFIER", &order_id),
            privacy_set_size: self.config.min_privacy_set_size,
            pq_security_bits: self.config.min_pq_security_bits,
            admitted_at_height: self.current_l2_height,
            expires_at_height: self.current_l2_height + self.config.order_ttl_blocks,
        };
        self.sealed_orders.insert(order_id.clone(), order);
        order_id
    }

    fn insert_callback(
        &mut self,
        order_id: &str,
        pair_id: &str,
        contract_id: &str,
        callback_kind: CallbackKind,
    ) -> String {
        let callback_id =
            deterministic_id("callback", &[order_id, contract_id, callback_kind.as_str()]);
        let callback = ContractCallback {
            callback_id: callback_id.clone(),
            order_id: order_id.to_string(),
            pair_id: pair_id.to_string(),
            contract_id: contract_id.to_string(),
            callback_kind,
            status: CallbackStatus::Proved,
            call_data_root: deterministic_root("CALL-DATA", &callback_id),
            output_root: deterministic_root("CALLBACK-OUTPUT", &callback_id),
            gas_note_commitment: deterministic_root("CALLBACK-GAS", &callback_id),
            proof_root: deterministic_root("CALLBACK-PROOF", &callback_id),
            scheduled_at_height: self.current_l2_height,
            deadline_height: self.current_l2_height + self.config.callback_ttl_blocks,
        };
        self.callbacks.insert(callback_id.clone(), callback);
        callback_id
    }

    fn insert_batch(
        &mut self,
        pair_id: &str,
        bids: &[String],
        asks: &[String],
        callbacks: &[String],
    ) -> String {
        let batch_id = deterministic_id(
            "batch",
            &[pair_id, &bids.len().to_string(), &asks.len().to_string()],
        );
        let batch = MatchingBatch {
            batch_id: batch_id.clone(),
            pair_id: pair_id.to_string(),
            status: BatchStatus::MevLocked,
            bid_order_root: list_root("BID-ORDERS", bids),
            ask_order_root: list_root("ASK-ORDERS", asks),
            callback_root: list_root("BATCH-CALLBACKS", callbacks),
            solver_attestation_root: deterministic_root("PENDING-SOLVER-ATTESTATION", &batch_id),
            mev_lock_root: deterministic_root("MEV-LOCK", &batch_id),
            settlement_root: deterministic_root("SETTLEMENT", &batch_id),
            fill_count: 1,
            opened_at_height: self.current_l2_height,
            settlement_deadline_height: self.current_l2_height + self.config.batch_ttl_blocks,
        };
        self.matching_batches.insert(batch_id.clone(), batch);
        batch_id
    }

    fn insert_attestation(&mut self, batch_id: &str, pair_id: &str, solver: &str) -> String {
        let attestation_id = deterministic_id("attestation", &[batch_id, solver]);
        let attestation = PqSolverAttestation {
            attestation_id: attestation_id.clone(),
            solver_commitment: deterministic_root("SOLVER", solver),
            batch_id: batch_id.to_string(),
            pair_id: pair_id.to_string(),
            solver_public_key_root: deterministic_root("SOLVER-PQ-PK", solver),
            matched_order_root: deterministic_root("MATCHED-ORDERS", batch_id),
            clearing_price_commitment: deterministic_root("CLEARING-PRICE", batch_id),
            surplus_commitment: deterministic_root("SURPLUS", batch_id),
            fairness_proof_root: deterministic_root("FAIRNESS", batch_id),
            pq_signature_root: deterministic_root("PQ-SIG", &attestation_id),
            privacy_set_size: self.config.batch_privacy_set_size,
            pq_security_bits: self.config.min_pq_security_bits,
            attested_at_height: self.current_l2_height,
        };
        self.solver_attestations
            .insert(attestation_id.clone(), attestation);
        attestation_id
    }

    fn insert_fill(&mut self, batch_id: &str, maker: &str, taker: &str, pair_id: &str) -> String {
        let fill_id = deterministic_id("fill", &[batch_id, maker, taker]);
        let fill = MevSafeFill {
            fill_id: fill_id.clone(),
            batch_id: batch_id.to_string(),
            maker_order_id: maker.to_string(),
            taker_order_id: taker.to_string(),
            pair_id: pair_id.to_string(),
            fill_commitment: deterministic_root("FILL", &fill_id),
            price_commitment: deterministic_root("FILL-PRICE", &fill_id),
            quantity_commitment: deterministic_root("FILL-QTY", &fill_id),
            sequencing_proof_root: deterministic_root("SEQUENCE", &fill_id),
            anti_sandwich_root: deterministic_root("ANTI-SANDWICH", &fill_id),
            finalized_at_height: self.current_l2_height + 1,
        };
        self.mev_safe_fills.insert(fill_id.clone(), fill);
        fill_id
    }

    fn insert_rebate(&mut self, batch_id: &str, recipient: &str, rebate_bps: u64) -> String {
        let rebate_id = deterministic_id("rebate", &[batch_id, recipient]);
        let rebate = FeeRebate {
            rebate_id: rebate_id.clone(),
            batch_id: batch_id.to_string(),
            recipient_commitment: deterministic_root("REBATE-RECIPIENT", recipient),
            rebate_note_commitment: deterministic_root("REBATE-NOTE", &rebate_id),
            rebate_bps,
            reason_root: deterministic_root("REBATE-REASON", "maker-surplus-share"),
            issued_at_height: self.current_l2_height + 1,
        };
        self.fee_rebates.insert(rebate_id.clone(), rebate);
        rebate_id
    }

    fn insert_redaction(&mut self, subject: &str, scope: &str, units: u64) -> String {
        let budget_id = deterministic_id("redaction", &[subject, scope]);
        let budget = PrivacyRedactionBudget {
            budget_id: budget_id.clone(),
            subject_root: deterministic_root("REDACTION-SUBJECT", subject),
            scope: scope.to_string(),
            units_granted: units,
            units_spent: units / 5,
            min_public_delay_blocks: 12,
            expires_at_height: self.current_l2_height + 720,
        };
        self.privacy_redactions.insert(budget_id.clone(), budget);
        budget_id
    }

    fn insert_pair_public_records(&mut self) {
        self.refresh_roots();
        for (pair_id, pair) in &self.token_pairs {
            let payload = pair.public_record();
            let payload_root = public_record_root(&payload);
            let record_id = public_record_id(PublicRecordKind::TokenPair, pair_id, &payload_root);
            self.public_records.insert(
                record_id.clone(),
                PublicRecord {
                    record_id,
                    record_kind: PublicRecordKind::TokenPair,
                    subject_id: pair_id.clone(),
                    payload_root,
                    state_root: self.roots.state_root.clone(),
                    height: self.current_l2_height,
                },
            );
        }
    }
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn demo() -> State {
    State::demo()
}

pub fn payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        &format!("PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-COMPOSABLE-CLOB-{domain}"),
        &[HashPart::Str(CHAIN_ID), HashPart::Json(payload)],
        32,
    )
}

pub fn public_record_root(record: &Value) -> String {
    payload_root("PUBLIC-RECORD", record)
}

pub fn state_root_from_record(record: &Value) -> String {
    payload_root("STATE", record)
}

pub fn map_root(domain: &str, leaves: Vec<Value>) -> String {
    merkle_root(
        &format!("PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-COMPOSABLE-CLOB-{domain}"),
        &leaves,
    )
}

pub fn deterministic_root(domain: &str, seed: &str) -> String {
    domain_hash(
        &format!("PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-COMPOSABLE-CLOB-{domain}"),
        &[HashPart::Str(CHAIN_ID), HashPart::Str(seed)],
        32,
    )
}

pub fn deterministic_id(prefix: &str, parts: &[&str]) -> String {
    let joined = parts.join(":");
    format!("{prefix}:{}", deterministic_root("ID", &joined))
}

pub fn list_root(domain: &str, values: &[String]) -> String {
    let leaves = values
        .iter()
        .map(|value| json!({ "value": value }))
        .collect::<Vec<_>>();
    map_root(domain, leaves)
}

pub fn public_record_id(
    record_kind: PublicRecordKind,
    subject_id: &str,
    payload_root: &str,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-COMPOSABLE-CLOB-PUBLIC-RECORD-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(record_kind.as_str()),
            HashPart::Str(subject_id),
            HashPart::Str(payload_root),
        ],
        32,
    )
}

pub trait PublicRecordView {
    fn public_record(&self) -> Value;
}

impl PublicRecordView for TokenPairRegistry {
    fn public_record(&self) -> Value {
        TokenPairRegistry::public_record(self)
    }
}

impl PublicRecordView for SealedOrderCommitment {
    fn public_record(&self) -> Value {
        SealedOrderCommitment::public_record(self)
    }
}

impl PublicRecordView for ContractCallback {
    fn public_record(&self) -> Value {
        ContractCallback::public_record(self)
    }
}

impl PublicRecordView for PqSolverAttestation {
    fn public_record(&self) -> Value {
        PqSolverAttestation::public_record(self)
    }
}

impl PublicRecordView for MatchingBatch {
    fn public_record(&self) -> Value {
        MatchingBatch::public_record(self)
    }
}

impl PublicRecordView for MevSafeFill {
    fn public_record(&self) -> Value {
        MevSafeFill::public_record(self)
    }
}

impl PublicRecordView for FeeRebate {
    fn public_record(&self) -> Value {
        FeeRebate::public_record(self)
    }
}

impl PublicRecordView for PrivacyRedactionBudget {
    fn public_record(&self) -> Value {
        PrivacyRedactionBudget::public_record(self)
    }
}

impl PublicRecordView for PublicRecord {
    fn public_record(&self) -> Value {
        PublicRecord::public_record(self)
    }
}

pub fn records_from_map<T: PublicRecordView>(map: &BTreeMap<String, T>) -> Vec<Value> {
    map.values().map(PublicRecordView::public_record).collect()
}

fn require(condition: bool, message: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(message.to_string())
    }
}

fn require_bps(label: &str, value: u64) -> Result<()> {
    require(value <= MAX_BPS, &format!("{label} exceeds 10000 bps"))
}
