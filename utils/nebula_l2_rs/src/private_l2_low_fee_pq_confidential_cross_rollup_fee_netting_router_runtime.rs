use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

pub type PrivateL2LowFeePqConfidentialCrossRollupFeeNettingRouterRuntimeResult<T> =
    std::result::Result<T, String>;
pub type Runtime = State;

pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_CROSS_ROLLUP_FEE_NETTING_ROUTER_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-private-l2-low-fee-pq-confidential-cross-rollup-fee-netting-router-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_CROSS_ROLLUP_FEE_NETTING_ROUTER_RUNTIME_PROTOCOL_VERSION;
pub const HASH_SUITE: &str = "stable-fnv1a-128-domain-separated-json";
pub const PQ_SUITE: &str = "ml-kem-1024+ml-dsa-87+slh-dsa-shake-256f";
pub const CONFIDENTIAL_FEE_SUITE: &str = "pedersen-compatible-fee-commitments-v1";
pub const ROUTE_COMMITMENT_SUITE: &str = "cross-rollup-route-commitment-roots-v1";
pub const QUOTE_ATTESTATION_SUITE: &str = "pq-signed-fee-quote-attestation-v1";
pub const VOUCHER_SUITE: &str = "confidential-cross-rollup-fee-voucher-v1";
pub const PUBLIC_RECORD_SUITE: &str = "roots-only-redacted-public-record-v1";
pub const DEVNET_CHAIN_ID: &str = "nebula-private-l2-devnet";
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MAX_ROUTE_HOPS: usize = 8;
pub const DEFAULT_MAX_INTENTS_PER_EPOCH: usize = 4_096;
pub const DEFAULT_MAX_QUOTES_PER_INTENT: usize = 24;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 256;
pub const DEFAULT_MAX_PUBLIC_EVENTS: usize = 65_536;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub hash_suite: String,
    pub pq_suite: String,
    pub confidential_fee_suite: String,
    pub route_commitment_suite: String,
    pub quote_attestation_suite: String,
    pub voucher_suite: String,
    pub public_record_suite: String,
    pub current_l2_height: u64,
    pub current_monero_height: u64,
    pub epoch: u64,
    pub epoch_length_blocks: u64,
    pub settlement_delay_blocks: u64,
    pub quote_ttl_blocks: u64,
    pub voucher_ttl_blocks: u64,
    pub redemption_grace_blocks: u64,
    pub challenge_window_blocks: u64,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub min_lane_liquidity_piconero: u64,
    pub min_sponsor_bond_piconero: u64,
    pub max_user_fee_bps: u64,
    pub max_router_fee_bps: u64,
    pub max_sponsor_discount_bps: u64,
    pub min_netting_savings_bps: u64,
    pub max_da_cost_piconero: u64,
    pub max_proof_cost_piconero: u64,
    pub max_total_cost_piconero: u64,
    pub default_redaction_budget_units: u64,
    pub max_redaction_budget_units: u64,
    pub max_route_hops: usize,
    pub max_intents_per_epoch: usize,
    pub max_quotes_per_intent: usize,
    pub max_public_events: usize,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: DEVNET_CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            hash_suite: HASH_SUITE.to_string(),
            pq_suite: PQ_SUITE.to_string(),
            confidential_fee_suite: CONFIDENTIAL_FEE_SUITE.to_string(),
            route_commitment_suite: ROUTE_COMMITMENT_SUITE.to_string(),
            quote_attestation_suite: QUOTE_ATTESTATION_SUITE.to_string(),
            voucher_suite: VOUCHER_SUITE.to_string(),
            public_record_suite: PUBLIC_RECORD_SUITE.to_string(),
            current_l2_height: 1_880_240,
            current_monero_height: 3_624_800,
            epoch: 42,
            epoch_length_blocks: 24,
            settlement_delay_blocks: 6,
            quote_ttl_blocks: 12,
            voucher_ttl_blocks: 96,
            redemption_grace_blocks: 144,
            challenge_window_blocks: 48,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            min_lane_liquidity_piconero: 12_000_000_000,
            min_sponsor_bond_piconero: 5_000_000_000,
            max_user_fee_bps: 22,
            max_router_fee_bps: 28,
            max_sponsor_discount_bps: 2_000,
            min_netting_savings_bps: 350,
            max_da_cost_piconero: 120_000,
            max_proof_cost_piconero: 280_000,
            max_total_cost_piconero: 480_000,
            default_redaction_budget_units: 64,
            max_redaction_budget_units: 256,
            max_route_hops: DEFAULT_MAX_ROUTE_HOPS,
            max_intents_per_epoch: DEFAULT_MAX_INTENTS_PER_EPOCH,
            max_quotes_per_intent: DEFAULT_MAX_QUOTES_PER_INTENT,
            max_public_events: DEFAULT_MAX_PUBLIC_EVENTS,
        }
    }

    pub fn validate(
        &self,
    ) -> PrivateL2LowFeePqConfidentialCrossRollupFeeNettingRouterRuntimeResult<()> {
        require_non_empty("chain_id", &self.chain_id)?;
        require_non_empty("protocol_version", &self.protocol_version)?;
        require_non_empty("hash_suite", &self.hash_suite)?;
        require_non_empty("pq_suite", &self.pq_suite)?;
        require_non_empty("confidential_fee_suite", &self.confidential_fee_suite)?;
        require_non_empty("route_commitment_suite", &self.route_commitment_suite)?;
        require_non_empty("quote_attestation_suite", &self.quote_attestation_suite)?;
        require_non_empty("voucher_suite", &self.voucher_suite)?;
        if self.protocol_version != PROTOCOL_VERSION {
            return Err("protocol version mismatch".to_string());
        }
        if self.min_pq_security_bits < DEFAULT_MIN_PQ_SECURITY_BITS {
            return Err("post-quantum security floor too low".to_string());
        }
        if self.max_user_fee_bps > MAX_BPS
            || self.max_router_fee_bps > MAX_BPS
            || self.max_sponsor_discount_bps > MAX_BPS
            || self.min_netting_savings_bps > MAX_BPS
        {
            return Err("basis points out of range".to_string());
        }
        if self.epoch_length_blocks == 0
            || self.settlement_delay_blocks == 0
            || self.quote_ttl_blocks == 0
            || self.voucher_ttl_blocks == 0
            || self.challenge_window_blocks == 0
            || self.max_route_hops == 0
            || self.max_intents_per_epoch == 0
            || self.max_quotes_per_intent == 0
        {
            return Err("config windows and limits must be nonzero".to_string());
        }
        if self.max_total_cost_piconero
            < self
                .max_da_cost_piconero
                .saturating_add(self.max_proof_cost_piconero)
        {
            return Err("total cost cap must cover DA plus proof caps".to_string());
        }
        if self.default_redaction_budget_units > self.max_redaction_budget_units {
            return Err("default redaction budget exceeds max".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "hash_suite": self.hash_suite,
            "pq_suite": self.pq_suite,
            "confidential_fee_suite": self.confidential_fee_suite,
            "route_commitment_suite": self.route_commitment_suite,
            "quote_attestation_suite": self.quote_attestation_suite,
            "voucher_suite": self.voucher_suite,
            "public_record_suite": self.public_record_suite,
            "current_l2_height": self.current_l2_height,
            "current_monero_height": self.current_monero_height,
            "epoch": self.epoch,
            "epoch_length_blocks": self.epoch_length_blocks,
            "settlement_delay_blocks": self.settlement_delay_blocks,
            "quote_ttl_blocks": self.quote_ttl_blocks,
            "voucher_ttl_blocks": self.voucher_ttl_blocks,
            "redemption_grace_blocks": self.redemption_grace_blocks,
            "challenge_window_blocks": self.challenge_window_blocks,
            "min_pq_security_bits": self.min_pq_security_bits,
            "min_privacy_set_size": self.min_privacy_set_size,
            "min_lane_liquidity_piconero": self.min_lane_liquidity_piconero,
            "min_sponsor_bond_piconero": self.min_sponsor_bond_piconero,
            "max_user_fee_bps": self.max_user_fee_bps,
            "max_router_fee_bps": self.max_router_fee_bps,
            "max_sponsor_discount_bps": self.max_sponsor_discount_bps,
            "min_netting_savings_bps": self.min_netting_savings_bps,
            "max_da_cost_piconero": self.max_da_cost_piconero,
            "max_proof_cost_piconero": self.max_proof_cost_piconero,
            "max_total_cost_piconero": self.max_total_cost_piconero,
            "default_redaction_budget_units": self.default_redaction_budget_units,
            "max_redaction_budget_units": self.max_redaction_budget_units,
            "max_route_hops": self.max_route_hops,
            "max_intents_per_epoch": self.max_intents_per_epoch,
            "max_quotes_per_intent": self.max_quotes_per_intent,
            "max_public_events": self.max_public_events
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    pub next_lane: u64,
    pub next_route: u64,
    pub next_sponsor_pool: u64,
    pub next_epoch: u64,
    pub next_quote: u64,
    pub next_voucher: u64,
    pub next_redemption: u64,
    pub next_cost_cap: u64,
    pub next_privacy_budget: u64,
    pub next_receipt: u64,
    pub events: u64,
}

impl Counters {
    pub fn devnet() -> Self {
        Self {
            next_lane: 1,
            next_route: 1,
            next_sponsor_pool: 1,
            next_epoch: 43,
            next_quote: 1,
            next_voucher: 1,
            next_redemption: 1,
            next_cost_cap: 1,
            next_privacy_budget: 1,
            next_receipt: 1,
            events: 0,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "next_lane": self.next_lane,
            "next_route": self.next_route,
            "next_sponsor_pool": self.next_sponsor_pool,
            "next_epoch": self.next_epoch,
            "next_quote": self.next_quote,
            "next_voucher": self.next_voucher,
            "next_redemption": self.next_redemption,
            "next_cost_cap": self.next_cost_cap,
            "next_privacy_budget": self.next_privacy_budget,
            "next_receipt": self.next_receipt,
            "events": self.events
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roots {
    pub config_root: String,
    pub counters_root: String,
    pub lane_root: String,
    pub route_root: String,
    pub sponsor_pool_root: String,
    pub epoch_root: String,
    pub quote_root: String,
    pub voucher_root: String,
    pub redemption_root: String,
    pub cost_cap_root: String,
    pub privacy_budget_root: String,
    pub nullifier_root: String,
    pub receipt_root: String,
    pub event_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "counters_root": self.counters_root,
            "lane_root": self.lane_root,
            "route_root": self.route_root,
            "sponsor_pool_root": self.sponsor_pool_root,
            "epoch_root": self.epoch_root,
            "quote_root": self.quote_root,
            "voucher_root": self.voucher_root,
            "redemption_root": self.redemption_root,
            "cost_cap_root": self.cost_cap_root,
            "privacy_budget_root": self.privacy_budget_root,
            "nullifier_root": self.nullifier_root,
            "receipt_root": self.receipt_root,
            "event_root": self.event_root,
            "state_root": self.state_root
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LaneKind {
    UserFeeIntent,
    SponsoredWallet,
    ContractPaymaster,
    DefiBatch,
    TokenTransfer,
    MoneroExit,
    OracleUpdate,
    ProofDaAmortization,
}

impl LaneKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::UserFeeIntent => "user_fee_intent",
            Self::SponsoredWallet => "sponsored_wallet",
            Self::ContractPaymaster => "contract_paymaster",
            Self::DefiBatch => "defi_batch",
            Self::TokenTransfer => "token_transfer",
            Self::MoneroExit => "monero_exit",
            Self::OracleUpdate => "oracle_update",
            Self::ProofDaAmortization => "proof_da_amortization",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LaneStatus {
    Open,
    Throttled,
    Netting,
    Settling,
    Paused,
    Drained,
}

impl LaneStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Throttled => "throttled",
            Self::Netting => "netting",
            Self::Settling => "settling",
            Self::Paused => "paused",
            Self::Drained => "drained",
        }
    }

    pub fn accepts_intents(self) -> bool {
        matches!(self, Self::Open | Self::Throttled | Self::Netting)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteStatus {
    Proposed,
    Committed,
    Attested,
    Nettable,
    Settled,
    Expired,
    Challenged,
}

impl RouteStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::Committed => "committed",
            Self::Attested => "attested",
            Self::Nettable => "nettable",
            Self::Settled => "settled",
            Self::Expired => "expired",
            Self::Challenged => "challenged",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EpochStatus {
    Collecting,
    QuoteLocked,
    Netted,
    VoucherIssued,
    Settling,
    Finalized,
    Challenged,
}

impl EpochStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Collecting => "collecting",
            Self::QuoteLocked => "quote_locked",
            Self::Netted => "netted",
            Self::VoucherIssued => "voucher_issued",
            Self::Settling => "settling",
            Self::Finalized => "finalized",
            Self::Challenged => "challenged",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VoucherStatus {
    Issued,
    PartiallyRedeemed,
    Redeemed,
    Expired,
    Revoked,
}

impl VoucherStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Issued => "issued",
            Self::PartiallyRedeemed => "partially_redeemed",
            Self::Redeemed => "redeemed",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeeIntentLane {
    pub lane_id: String,
    pub kind: LaneKind,
    pub status: LaneStatus,
    pub source_rollup: String,
    pub destination_rollups: BTreeSet<String>,
    pub token: String,
    pub confidential_balance_commitment: String,
    pub pending_fee_commitment: String,
    pub min_privacy_set_size: u64,
    pub max_user_fee_bps: u64,
    pub sponsor_pool_id: Option<String>,
    pub active_epoch_id: String,
    pub admitted_intents: u64,
    pub netted_intents: u64,
    pub rejected_intents: u64,
    pub created_at_height: u64,
    pub updated_at_height: u64,
    pub lane_root: String,
}

impl FeeIntentLane {
    pub fn public_record(&self) -> Value {
        json!({
            "lane_id": self.lane_id,
            "kind": self.kind.as_str(),
            "status": self.status.as_str(),
            "source_rollup": self.source_rollup,
            "destination_rollups": self.destination_rollups,
            "token": self.token,
            "confidential_balance_commitment": self.confidential_balance_commitment,
            "pending_fee_commitment": self.pending_fee_commitment,
            "min_privacy_set_size": self.min_privacy_set_size,
            "max_user_fee_bps": self.max_user_fee_bps,
            "sponsor_pool_id": self.sponsor_pool_id,
            "active_epoch_id": self.active_epoch_id,
            "admitted_intents": self.admitted_intents,
            "netted_intents": self.netted_intents,
            "rejected_intents": self.rejected_intents,
            "created_at_height": self.created_at_height,
            "updated_at_height": self.updated_at_height,
            "lane_root": self.lane_root
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteHop {
    pub rollup_id: String,
    pub bridge_adapter: String,
    pub fee_asset: String,
    pub fee_commitment: String,
    pub da_cost_cap_piconero: u64,
    pub proof_cost_cap_piconero: u64,
    pub expected_latency_ms: u64,
    pub hop_commitment: String,
}

impl RouteHop {
    pub fn public_record(&self) -> Value {
        json!({
            "rollup_id": self.rollup_id,
            "bridge_adapter": self.bridge_adapter,
            "fee_asset": self.fee_asset,
            "fee_commitment": self.fee_commitment,
            "da_cost_cap_piconero": self.da_cost_cap_piconero,
            "proof_cost_cap_piconero": self.proof_cost_cap_piconero,
            "expected_latency_ms": self.expected_latency_ms,
            "hop_commitment": self.hop_commitment
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RollupRouteCommitment {
    pub route_id: String,
    pub lane_id: String,
    pub epoch_id: String,
    pub status: RouteStatus,
    pub source_rollup: String,
    pub destination_rollup: String,
    pub hops: Vec<RouteHop>,
    pub aggregate_fee_commitment: String,
    pub route_witness_root: String,
    pub nullifier_set_root: String,
    pub pq_commitment_key: String,
    pub route_commitment: String,
    pub quote_ids: BTreeSet<String>,
    pub created_at_height: u64,
    pub expires_at_height: u64,
}

impl RollupRouteCommitment {
    pub fn public_record(&self) -> Value {
        let hops: Vec<Value> = self.hops.iter().map(RouteHop::public_record).collect();
        json!({
            "route_id": self.route_id,
            "lane_id": self.lane_id,
            "epoch_id": self.epoch_id,
            "status": self.status.as_str(),
            "source_rollup": self.source_rollup,
            "destination_rollup": self.destination_rollup,
            "hops": hops,
            "aggregate_fee_commitment": self.aggregate_fee_commitment,
            "route_witness_root": self.route_witness_root,
            "nullifier_set_root": self.nullifier_set_root,
            "pq_commitment_key": self.pq_commitment_key,
            "route_commitment": self.route_commitment,
            "quote_ids": self.quote_ids,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SponsorPool {
    pub pool_id: String,
    pub sponsor_id: String,
    pub status: LaneStatus,
    pub covered_rollups: BTreeSet<String>,
    pub covered_tokens: BTreeSet<String>,
    pub bonded_piconero: u64,
    pub available_credit_piconero: u64,
    pub reserved_credit_piconero: u64,
    pub max_discount_bps: u64,
    pub max_epoch_spend_piconero: u64,
    pub current_epoch_spend_piconero: u64,
    pub pq_public_key: String,
    pub sponsor_policy_root: String,
    pub withdrawal_delay_blocks: u64,
}

impl SponsorPool {
    pub fn public_record(&self) -> Value {
        json!({
            "pool_id": self.pool_id,
            "sponsor_id": self.sponsor_id,
            "status": self.status.as_str(),
            "covered_rollups": self.covered_rollups,
            "covered_tokens": self.covered_tokens,
            "bonded_piconero": self.bonded_piconero,
            "available_credit_piconero": self.available_credit_piconero,
            "reserved_credit_piconero": self.reserved_credit_piconero,
            "max_discount_bps": self.max_discount_bps,
            "max_epoch_spend_piconero": self.max_epoch_spend_piconero,
            "current_epoch_spend_piconero": self.current_epoch_spend_piconero,
            "pq_public_key": self.pq_public_key,
            "sponsor_policy_root": self.sponsor_policy_root,
            "withdrawal_delay_blocks": self.withdrawal_delay_blocks
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DaProofCostCap {
    pub cap_id: String,
    pub rollup_id: String,
    pub epoch_id: String,
    pub da_cost_cap_piconero: u64,
    pub proof_cost_cap_piconero: u64,
    pub total_cost_cap_piconero: u64,
    pub amortization_floor_intents: u64,
    pub measured_da_bytes: u64,
    pub measured_proof_weight: u64,
    pub oracle_attestation_root: String,
    pub enforced: bool,
}

impl DaProofCostCap {
    pub fn public_record(&self) -> Value {
        json!({
            "cap_id": self.cap_id,
            "rollup_id": self.rollup_id,
            "epoch_id": self.epoch_id,
            "da_cost_cap_piconero": self.da_cost_cap_piconero,
            "proof_cost_cap_piconero": self.proof_cost_cap_piconero,
            "total_cost_cap_piconero": self.total_cost_cap_piconero,
            "amortization_floor_intents": self.amortization_floor_intents,
            "measured_da_bytes": self.measured_da_bytes,
            "measured_proof_weight": self.measured_proof_weight,
            "oracle_attestation_root": self.oracle_attestation_root,
            "enforced": self.enforced
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivacyRedactionBudget {
    pub budget_id: String,
    pub lane_id: String,
    pub epoch_id: String,
    pub subject_root: String,
    pub budget_units: u64,
    pub spent_units: u64,
    pub redacted_fields: BTreeSet<String>,
    pub disclosure_policy_root: String,
    pub view_key_guard_root: String,
    pub expires_at_height: u64,
}

impl PrivacyRedactionBudget {
    pub fn public_record(&self) -> Value {
        json!({
            "budget_id": self.budget_id,
            "lane_id": self.lane_id,
            "epoch_id": self.epoch_id,
            "subject_root": self.subject_root,
            "budget_units": self.budget_units,
            "spent_units": self.spent_units,
            "redacted_fields": self.redacted_fields,
            "disclosure_policy_root": self.disclosure_policy_root,
            "view_key_guard_root": self.view_key_guard_root,
            "expires_at_height": self.expires_at_height
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NettingEpoch {
    pub epoch_id: String,
    pub status: EpochStatus,
    pub opens_at_height: u64,
    pub closes_at_height: u64,
    pub settles_after_height: u64,
    pub lane_ids: BTreeSet<String>,
    pub route_ids: BTreeSet<String>,
    pub quote_ids: BTreeSet<String>,
    pub voucher_ids: BTreeSet<String>,
    pub total_gross_fee_commitment: String,
    pub total_netted_fee_commitment: String,
    pub sponsor_credit_commitment: String,
    pub da_cost_commitment: String,
    pub proof_cost_commitment: String,
    pub netting_savings_bps: u64,
    pub participant_count: u64,
    pub privacy_set_size: u64,
    pub epoch_root: String,
}

impl NettingEpoch {
    pub fn public_record(&self) -> Value {
        json!({
            "epoch_id": self.epoch_id,
            "status": self.status.as_str(),
            "opens_at_height": self.opens_at_height,
            "closes_at_height": self.closes_at_height,
            "settles_after_height": self.settles_after_height,
            "lane_ids": self.lane_ids,
            "route_ids": self.route_ids,
            "quote_ids": self.quote_ids,
            "voucher_ids": self.voucher_ids,
            "total_gross_fee_commitment": self.total_gross_fee_commitment,
            "total_netted_fee_commitment": self.total_netted_fee_commitment,
            "sponsor_credit_commitment": self.sponsor_credit_commitment,
            "da_cost_commitment": self.da_cost_commitment,
            "proof_cost_commitment": self.proof_cost_commitment,
            "netting_savings_bps": self.netting_savings_bps,
            "participant_count": self.participant_count,
            "privacy_set_size": self.privacy_set_size,
            "epoch_root": self.epoch_root
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuoteAttestation {
    pub quote_id: String,
    pub route_id: String,
    pub epoch_id: String,
    pub attestor_id: String,
    pub pq_signature: String,
    pub quoted_fee_commitment: String,
    pub max_fee_piconero: u64,
    pub sponsor_discount_bps: u64,
    pub da_cost_piconero: u64,
    pub proof_cost_piconero: u64,
    pub valid_from_height: u64,
    pub valid_until_height: u64,
    pub attestation_root: String,
    pub selected: bool,
}

impl QuoteAttestation {
    pub fn public_record(&self) -> Value {
        json!({
            "quote_id": self.quote_id,
            "route_id": self.route_id,
            "epoch_id": self.epoch_id,
            "attestor_id": self.attestor_id,
            "pq_signature": self.pq_signature,
            "quoted_fee_commitment": self.quoted_fee_commitment,
            "max_fee_piconero": self.max_fee_piconero,
            "sponsor_discount_bps": self.sponsor_discount_bps,
            "da_cost_piconero": self.da_cost_piconero,
            "proof_cost_piconero": self.proof_cost_piconero,
            "valid_from_height": self.valid_from_height,
            "valid_until_height": self.valid_until_height,
            "attestation_root": self.attestation_root,
            "selected": self.selected
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeeVoucher {
    pub voucher_id: String,
    pub epoch_id: String,
    pub lane_id: String,
    pub route_id: String,
    pub quote_id: String,
    pub sponsor_pool_id: Option<String>,
    pub status: VoucherStatus,
    pub beneficiary_commitment: String,
    pub fee_credit_commitment: String,
    pub redeemed_credit_commitment: String,
    pub nullifier: String,
    pub redemption_ids: BTreeSet<String>,
    pub issued_at_height: u64,
    pub expires_at_height: u64,
    pub voucher_root: String,
}

impl FeeVoucher {
    pub fn public_record(&self) -> Value {
        json!({
            "voucher_id": self.voucher_id,
            "epoch_id": self.epoch_id,
            "lane_id": self.lane_id,
            "route_id": self.route_id,
            "quote_id": self.quote_id,
            "sponsor_pool_id": self.sponsor_pool_id,
            "status": self.status.as_str(),
            "beneficiary_commitment": self.beneficiary_commitment,
            "fee_credit_commitment": self.fee_credit_commitment,
            "redeemed_credit_commitment": self.redeemed_credit_commitment,
            "nullifier": self.nullifier,
            "redemption_ids": self.redemption_ids,
            "issued_at_height": self.issued_at_height,
            "expires_at_height": self.expires_at_height,
            "voucher_root": self.voucher_root
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RedemptionReceipt {
    pub redemption_id: String,
    pub voucher_id: String,
    pub epoch_id: String,
    pub redeeming_rollup: String,
    pub settlement_tx_root: String,
    pub redeemed_fee_commitment: String,
    pub residual_fee_commitment: String,
    pub proof_root: String,
    pub pq_signature: String,
    pub redeemed_at_height: u64,
    pub finality_height: u64,
}

impl RedemptionReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "redemption_id": self.redemption_id,
            "voucher_id": self.voucher_id,
            "epoch_id": self.epoch_id,
            "redeeming_rollup": self.redeeming_rollup,
            "settlement_tx_root": self.settlement_tx_root,
            "redeemed_fee_commitment": self.redeemed_fee_commitment,
            "residual_fee_commitment": self.residual_fee_commitment,
            "proof_root": self.proof_root,
            "pq_signature": self.pq_signature,
            "redeemed_at_height": self.redeemed_at_height,
            "finality_height": self.finality_height
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicEvent {
    pub event_id: String,
    pub height: u64,
    pub epoch_id: String,
    pub kind: String,
    pub subject_id: String,
    pub public_root: String,
}

impl PublicEvent {
    pub fn public_record(&self) -> Value {
        json!({
            "event_id": self.event_id,
            "height": self.height,
            "epoch_id": self.epoch_id,
            "kind": self.kind,
            "subject_id": self.subject_id,
            "public_root": self.public_root
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub lanes: BTreeMap<String, FeeIntentLane>,
    pub routes: BTreeMap<String, RollupRouteCommitment>,
    pub sponsor_pools: BTreeMap<String, SponsorPool>,
    pub epochs: BTreeMap<String, NettingEpoch>,
    pub quote_attestations: BTreeMap<String, QuoteAttestation>,
    pub vouchers: BTreeMap<String, FeeVoucher>,
    pub redemptions: BTreeMap<String, RedemptionReceipt>,
    pub cost_caps: BTreeMap<String, DaProofCostCap>,
    pub privacy_budgets: BTreeMap<String, PrivacyRedactionBudget>,
    pub nullifiers: BTreeSet<String>,
    pub public_events: Vec<PublicEvent>,
}

impl State {
    pub fn recompute_roots(&mut self) {
        self.roots = compute_roots(self);
    }

    pub fn public_record(&self) -> Value {
        public_record(self)
    }

    pub fn state_root(&self) -> String {
        state_root(self)
    }

    pub fn validate(
        &self,
    ) -> PrivateL2LowFeePqConfidentialCrossRollupFeeNettingRouterRuntimeResult<()> {
        self.config.validate()?;
        if self.public_events.len() > self.config.max_public_events {
            return Err("public event limit exceeded".to_string());
        }
        for lane in self.lanes.values() {
            require_non_empty("lane_id", &lane.lane_id)?;
            require_non_empty("source_rollup", &lane.source_rollup)?;
            if lane.min_privacy_set_size < self.config.min_privacy_set_size {
                return Err(format!(
                    "lane {} privacy set below config floor",
                    lane.lane_id
                ));
            }
            if lane.max_user_fee_bps > self.config.max_user_fee_bps {
                return Err(format!("lane {} fee cap exceeds config", lane.lane_id));
            }
        }
        for route in self.routes.values() {
            if route.hops.is_empty() || route.hops.len() > self.config.max_route_hops {
                return Err(format!("route {} hop count out of range", route.route_id));
            }
            if !self.lanes.contains_key(&route.lane_id) {
                return Err(format!("route {} references unknown lane", route.route_id));
            }
        }
        for quote in self.quote_attestations.values() {
            if !self.routes.contains_key(&quote.route_id) {
                return Err(format!("quote {} references unknown route", quote.quote_id));
            }
            if quote.da_cost_piconero > self.config.max_da_cost_piconero
                || quote.proof_cost_piconero > self.config.max_proof_cost_piconero
                || quote
                    .da_cost_piconero
                    .saturating_add(quote.proof_cost_piconero)
                    > self.config.max_total_cost_piconero
            {
                return Err(format!("quote {} exceeds cost caps", quote.quote_id));
            }
        }
        for voucher in self.vouchers.values() {
            if !self.nullifiers.contains(&voucher.nullifier) {
                return Err(format!(
                    "voucher {} missing nullifier fence",
                    voucher.voucher_id
                ));
            }
        }
        Ok(())
    }
}

pub fn devnet() -> State {
    let config = Config::devnet();
    let counters = Counters::devnet();
    let epoch_id = stable_id("epoch", config.epoch);
    let lane_id = stable_id("lane", 1);
    let route_id = stable_id("route", 1);
    let quote_id = stable_id("quote", 1);
    let voucher_id = stable_id("voucher", 1);
    let redemption_id = stable_id("redemption", 1);
    let sponsor_pool_id = stable_id("sponsor_pool", 1);
    let cap_id = stable_id("cost_cap", 1);
    let budget_id = stable_id("redaction_budget", 1);
    let source_rollup = "monero-l2-fast-confidential-rollup".to_string();
    let destination_rollup = "nebula-defi-contract-rollup".to_string();
    let mut destination_rollups = BTreeSet::new();
    destination_rollups.insert(destination_rollup.clone());
    destination_rollups.insert("nebula-token-rollup".to_string());
    let mut covered_rollups = destination_rollups.clone();
    covered_rollups.insert(source_rollup.clone());
    let mut covered_tokens = BTreeSet::new();
    covered_tokens.insert("pXMR".to_string());
    covered_tokens.insert("dUSD".to_string());
    let lane_root = stable_hash("lane", &[&lane_id, &epoch_id, &source_rollup]);
    let lane = FeeIntentLane {
        lane_id: lane_id.clone(),
        kind: LaneKind::DefiBatch,
        status: LaneStatus::Netting,
        source_rollup: source_rollup.clone(),
        destination_rollups,
        token: "pXMR".to_string(),
        confidential_balance_commitment: stable_hash(
            "balance_commitment",
            &[&lane_id, "92000000000"],
        ),
        pending_fee_commitment: stable_hash("pending_fee_commitment", &[&lane_id, "360000"]),
        min_privacy_set_size: 512,
        max_user_fee_bps: 18,
        sponsor_pool_id: Some(sponsor_pool_id.clone()),
        active_epoch_id: epoch_id.clone(),
        admitted_intents: 384,
        netted_intents: 352,
        rejected_intents: 3,
        created_at_height: config.current_l2_height - 18,
        updated_at_height: config.current_l2_height,
        lane_root,
    };
    let hop_a = RouteHop {
        rollup_id: source_rollup.clone(),
        bridge_adapter: "monero-viewtag-batched-adapter".to_string(),
        fee_asset: "pXMR".to_string(),
        fee_commitment: stable_hash("hop_fee", &[&route_id, "0"]),
        da_cost_cap_piconero: 48_000,
        proof_cost_cap_piconero: 90_000,
        expected_latency_ms: 420,
        hop_commitment: stable_hash("hop", &[&route_id, &source_rollup]),
    };
    let hop_b = RouteHop {
        rollup_id: destination_rollup.clone(),
        bridge_adapter: "confidential-contract-call-adapter".to_string(),
        fee_asset: "dUSD".to_string(),
        fee_commitment: stable_hash("hop_fee", &[&route_id, "1"]),
        da_cost_cap_piconero: 42_000,
        proof_cost_cap_piconero: 120_000,
        expected_latency_ms: 680,
        hop_commitment: stable_hash("hop", &[&route_id, &destination_rollup]),
    };
    let mut quote_ids = BTreeSet::new();
    quote_ids.insert(quote_id.clone());
    let route = RollupRouteCommitment {
        route_id: route_id.clone(),
        lane_id: lane_id.clone(),
        epoch_id: epoch_id.clone(),
        status: RouteStatus::Nettable,
        source_rollup: source_rollup.clone(),
        destination_rollup: destination_rollup.clone(),
        hops: vec![hop_a, hop_b],
        aggregate_fee_commitment: stable_hash("aggregate_fee", &[&route_id]),
        route_witness_root: stable_hash("route_witness", &[&route_id]),
        nullifier_set_root: stable_hash("route_nullifiers", &[&route_id]),
        pq_commitment_key: stable_hash("pq_route_key", &[&route_id]),
        route_commitment: stable_hash("route_commitment", &[&route_id, &lane_id]),
        quote_ids,
        created_at_height: config.current_l2_height - 8,
        expires_at_height: config.current_l2_height + config.quote_ttl_blocks,
    };
    let sponsor_pool = SponsorPool {
        pool_id: sponsor_pool_id.clone(),
        sponsor_id: "devnet-wallet-sponsor-alpha".to_string(),
        status: LaneStatus::Open,
        covered_rollups,
        covered_tokens,
        bonded_piconero: 9_000_000_000,
        available_credit_piconero: 2_400_000_000,
        reserved_credit_piconero: 180_000_000,
        max_discount_bps: 1_250,
        max_epoch_spend_piconero: 450_000_000,
        current_epoch_spend_piconero: 72_000_000,
        pq_public_key: stable_hash("sponsor_pq_key", &[&sponsor_pool_id]),
        sponsor_policy_root: stable_hash("sponsor_policy", &[&sponsor_pool_id]),
        withdrawal_delay_blocks: 144,
    };
    let quote = QuoteAttestation {
        quote_id: quote_id.clone(),
        route_id: route_id.clone(),
        epoch_id: epoch_id.clone(),
        attestor_id: "pq-fee-oracle-committee-0".to_string(),
        pq_signature: stable_hash("quote_signature", &[&quote_id, &route_id]),
        quoted_fee_commitment: stable_hash("quote_fee", &[&quote_id]),
        max_fee_piconero: 212_000,
        sponsor_discount_bps: 850,
        da_cost_piconero: 90_000,
        proof_cost_piconero: 210_000,
        valid_from_height: config.current_l2_height - 2,
        valid_until_height: config.current_l2_height + config.quote_ttl_blocks,
        attestation_root: stable_hash("quote_attestation", &[&quote_id]),
        selected: true,
    };
    let mut lane_ids = BTreeSet::new();
    lane_ids.insert(lane_id.clone());
    let mut route_ids = BTreeSet::new();
    route_ids.insert(route_id.clone());
    let mut epoch_quote_ids = BTreeSet::new();
    epoch_quote_ids.insert(quote_id.clone());
    let mut voucher_ids = BTreeSet::new();
    voucher_ids.insert(voucher_id.clone());
    let epoch = NettingEpoch {
        epoch_id: epoch_id.clone(),
        status: EpochStatus::VoucherIssued,
        opens_at_height: config.current_l2_height - config.epoch_length_blocks,
        closes_at_height: config.current_l2_height,
        settles_after_height: config.current_l2_height + config.settlement_delay_blocks,
        lane_ids,
        route_ids,
        quote_ids: epoch_quote_ids,
        voucher_ids,
        total_gross_fee_commitment: stable_hash("gross_fee", &[&epoch_id]),
        total_netted_fee_commitment: stable_hash("netted_fee", &[&epoch_id]),
        sponsor_credit_commitment: stable_hash("sponsor_credit", &[&epoch_id]),
        da_cost_commitment: stable_hash("da_cost", &[&epoch_id]),
        proof_cost_commitment: stable_hash("proof_cost", &[&epoch_id]),
        netting_savings_bps: 2_140,
        participant_count: 352,
        privacy_set_size: 1_024,
        epoch_root: stable_hash("epoch_root", &[&epoch_id]),
    };
    let nullifier = stable_hash("voucher_nullifier", &[&voucher_id]);
    let mut redemption_ids = BTreeSet::new();
    redemption_ids.insert(redemption_id.clone());
    let voucher = FeeVoucher {
        voucher_id: voucher_id.clone(),
        epoch_id: epoch_id.clone(),
        lane_id: lane_id.clone(),
        route_id: route_id.clone(),
        quote_id: quote_id.clone(),
        sponsor_pool_id: Some(sponsor_pool_id.clone()),
        status: VoucherStatus::PartiallyRedeemed,
        beneficiary_commitment: stable_hash("beneficiary", &[&voucher_id]),
        fee_credit_commitment: stable_hash("fee_credit", &[&voucher_id]),
        redeemed_credit_commitment: stable_hash("redeemed_credit", &[&voucher_id]),
        nullifier: nullifier.clone(),
        redemption_ids,
        issued_at_height: config.current_l2_height,
        expires_at_height: config.current_l2_height + config.voucher_ttl_blocks,
        voucher_root: stable_hash("voucher_root", &[&voucher_id]),
    };
    let redemption = RedemptionReceipt {
        redemption_id: redemption_id.clone(),
        voucher_id: voucher_id.clone(),
        epoch_id: epoch_id.clone(),
        redeeming_rollup: destination_rollup.clone(),
        settlement_tx_root: stable_hash("settlement_tx", &[&redemption_id]),
        redeemed_fee_commitment: stable_hash("redeemed_fee", &[&redemption_id]),
        residual_fee_commitment: stable_hash("residual_fee", &[&redemption_id]),
        proof_root: stable_hash("redemption_proof", &[&redemption_id]),
        pq_signature: stable_hash("redemption_signature", &[&redemption_id]),
        redeemed_at_height: config.current_l2_height + 2,
        finality_height: config.current_l2_height + 12,
    };
    let cost_cap = DaProofCostCap {
        cap_id: cap_id.clone(),
        rollup_id: destination_rollup,
        epoch_id: epoch_id.clone(),
        da_cost_cap_piconero: config.max_da_cost_piconero,
        proof_cost_cap_piconero: config.max_proof_cost_piconero,
        total_cost_cap_piconero: config.max_total_cost_piconero,
        amortization_floor_intents: 128,
        measured_da_bytes: 98_304,
        measured_proof_weight: 44_032,
        oracle_attestation_root: stable_hash("cost_oracle", &[&cap_id]),
        enforced: true,
    };
    let mut redacted_fields = BTreeSet::new();
    redacted_fields.insert("beneficiary_commitment_opening".to_string());
    redacted_fields.insert("per_intent_fee_amounts".to_string());
    redacted_fields.insert("route_linkage_witness".to_string());
    let budget = PrivacyRedactionBudget {
        budget_id: budget_id.clone(),
        lane_id: lane_id.clone(),
        epoch_id: epoch_id.clone(),
        subject_root: stable_hash("redaction_subject", &[&budget_id]),
        budget_units: config.default_redaction_budget_units,
        spent_units: 19,
        redacted_fields,
        disclosure_policy_root: stable_hash("disclosure_policy", &[&budget_id]),
        view_key_guard_root: stable_hash("view_key_guard", &[&budget_id]),
        expires_at_height: config.current_l2_height + config.redemption_grace_blocks,
    };
    let mut lanes = BTreeMap::new();
    lanes.insert(lane_id.clone(), lane);
    let mut routes = BTreeMap::new();
    routes.insert(route_id.clone(), route);
    let mut sponsor_pools = BTreeMap::new();
    sponsor_pools.insert(sponsor_pool_id, sponsor_pool);
    let mut epochs = BTreeMap::new();
    epochs.insert(epoch_id.clone(), epoch);
    let mut quote_attestations = BTreeMap::new();
    quote_attestations.insert(quote_id.clone(), quote);
    let mut vouchers = BTreeMap::new();
    vouchers.insert(voucher_id.clone(), voucher);
    let mut redemptions = BTreeMap::new();
    redemptions.insert(redemption_id.clone(), redemption);
    let mut cost_caps = BTreeMap::new();
    cost_caps.insert(cap_id, cost_cap);
    let mut privacy_budgets = BTreeMap::new();
    privacy_budgets.insert(budget_id, budget);
    let mut nullifiers = BTreeSet::new();
    nullifiers.insert(nullifier);
    let public_events = vec![
        event(&config, &epoch_id, "lane_opened", &lane_id),
        event(&config, &epoch_id, "route_committed", &route_id),
        event(&config, &epoch_id, "quote_selected", &quote_id),
        event(&config, &epoch_id, "voucher_issued", &voucher_id),
        event(&config, &epoch_id, "voucher_redeemed", &redemption_id),
    ];
    let roots = Roots {
        config_root: String::new(),
        counters_root: String::new(),
        lane_root: String::new(),
        route_root: String::new(),
        sponsor_pool_root: String::new(),
        epoch_root: String::new(),
        quote_root: String::new(),
        voucher_root: String::new(),
        redemption_root: String::new(),
        cost_cap_root: String::new(),
        privacy_budget_root: String::new(),
        nullifier_root: String::new(),
        receipt_root: String::new(),
        event_root: String::new(),
        state_root: String::new(),
    };
    let mut state = State {
        config,
        counters,
        roots,
        lanes,
        routes,
        sponsor_pools,
        epochs,
        quote_attestations,
        vouchers,
        redemptions,
        cost_caps,
        privacy_budgets,
        nullifiers,
        public_events,
    };
    state.recompute_roots();
    state
}

pub fn demo() -> State {
    let mut state = devnet();
    let second_lane_id = stable_id("lane", 2);
    let epoch_id = stable_id("epoch", state.config.epoch);
    let mut destinations = BTreeSet::new();
    destinations.insert("nebula-oracle-rollup".to_string());
    destinations.insert("nebula-token-rollup".to_string());
    let lane = FeeIntentLane {
        lane_id: second_lane_id.clone(),
        kind: LaneKind::OracleUpdate,
        status: LaneStatus::Open,
        source_rollup: "nebula-defi-contract-rollup".to_string(),
        destination_rollups: destinations,
        token: "dUSD".to_string(),
        confidential_balance_commitment: stable_hash(
            "balance_commitment",
            &[&second_lane_id, "3600000000"],
        ),
        pending_fee_commitment: stable_hash("pending_fee_commitment", &[&second_lane_id, "84000"]),
        min_privacy_set_size: 512,
        max_user_fee_bps: 12,
        sponsor_pool_id: None,
        active_epoch_id: epoch_id.clone(),
        admitted_intents: 96,
        netted_intents: 88,
        rejected_intents: 1,
        created_at_height: state.config.current_l2_height - 6,
        updated_at_height: state.config.current_l2_height,
        lane_root: stable_hash("lane", &[&second_lane_id, &epoch_id]),
    };
    if let Some(epoch) = state.epochs.get_mut(&epoch_id) {
        epoch.lane_ids.insert(second_lane_id.clone());
        epoch.participant_count = epoch.participant_count.saturating_add(88);
        epoch.privacy_set_size = epoch.privacy_set_size.saturating_add(256);
        epoch.netting_savings_bps = epoch.netting_savings_bps.saturating_add(110);
        epoch.epoch_root = stable_hash("epoch_root_demo", &[&epoch_id, &second_lane_id]);
    }
    state.lanes.insert(second_lane_id.clone(), lane);
    state.public_events.push(event(
        &state.config,
        &epoch_id,
        "demo_oracle_lane_opened",
        &second_lane_id,
    ));
    state.counters.next_lane = 3;
    state.counters.events = state.public_events.len() as u64;
    state.recompute_roots();
    state
}

pub fn public_record(state: &State) -> Value {
    let lanes: Vec<Value> = state
        .lanes
        .values()
        .map(FeeIntentLane::public_record)
        .collect();
    let routes: Vec<Value> = state
        .routes
        .values()
        .map(RollupRouteCommitment::public_record)
        .collect();
    let sponsor_pools: Vec<Value> = state
        .sponsor_pools
        .values()
        .map(SponsorPool::public_record)
        .collect();
    let epochs: Vec<Value> = state
        .epochs
        .values()
        .map(NettingEpoch::public_record)
        .collect();
    let quote_attestations: Vec<Value> = state
        .quote_attestations
        .values()
        .map(QuoteAttestation::public_record)
        .collect();
    let vouchers: Vec<Value> = state
        .vouchers
        .values()
        .map(FeeVoucher::public_record)
        .collect();
    let redemptions: Vec<Value> = state
        .redemptions
        .values()
        .map(RedemptionReceipt::public_record)
        .collect();
    let cost_caps: Vec<Value> = state
        .cost_caps
        .values()
        .map(DaProofCostCap::public_record)
        .collect();
    let privacy_budgets: Vec<Value> = state
        .privacy_budgets
        .values()
        .map(PrivacyRedactionBudget::public_record)
        .collect();
    let public_events: Vec<Value> = state
        .public_events
        .iter()
        .map(PublicEvent::public_record)
        .collect();
    json!({
        "config": state.config.public_record(),
        "counters": state.counters.public_record(),
        "roots": state.roots.public_record(),
        "lanes": lanes,
        "routes": routes,
        "sponsor_pools": sponsor_pools,
        "epochs": epochs,
        "quote_attestations": quote_attestations,
        "vouchers": vouchers,
        "redemptions": redemptions,
        "cost_caps": cost_caps,
        "privacy_budgets": privacy_budgets,
        "nullifier_root": set_root("nullifiers", &state.nullifiers),
        "public_events": public_events
    })
}

pub fn state_root(state: &State) -> String {
    compute_roots(state).state_root
}

fn compute_roots(state: &State) -> Roots {
    let config_root = value_root("config", &state.config.public_record());
    let counters_root = value_root("counters", &state.counters.public_record());
    let lane_root = map_root("lanes", &state.lanes, FeeIntentLane::public_record);
    let route_root = map_root(
        "routes",
        &state.routes,
        RollupRouteCommitment::public_record,
    );
    let sponsor_pool_root = map_root(
        "sponsor_pools",
        &state.sponsor_pools,
        SponsorPool::public_record,
    );
    let epoch_root = map_root("epochs", &state.epochs, NettingEpoch::public_record);
    let quote_root = map_root(
        "quote_attestations",
        &state.quote_attestations,
        QuoteAttestation::public_record,
    );
    let voucher_root = map_root("vouchers", &state.vouchers, FeeVoucher::public_record);
    let redemption_root = map_root(
        "redemptions",
        &state.redemptions,
        RedemptionReceipt::public_record,
    );
    let cost_cap_root = map_root("cost_caps", &state.cost_caps, DaProofCostCap::public_record);
    let privacy_budget_root = map_root(
        "privacy_budgets",
        &state.privacy_budgets,
        PrivacyRedactionBudget::public_record,
    );
    let nullifier_root = set_root("nullifiers", &state.nullifiers);
    let receipt_root = stable_hash("receipts", &[&voucher_root, &redemption_root]);
    let event_values: Vec<Value> = state
        .public_events
        .iter()
        .map(PublicEvent::public_record)
        .collect();
    let event_root = list_root("events", &event_values);
    let state_root = stable_hash(
        "state",
        &[
            &config_root,
            &counters_root,
            &lane_root,
            &route_root,
            &sponsor_pool_root,
            &epoch_root,
            &quote_root,
            &voucher_root,
            &redemption_root,
            &cost_cap_root,
            &privacy_budget_root,
            &nullifier_root,
            &receipt_root,
            &event_root,
        ],
    );
    Roots {
        config_root,
        counters_root,
        lane_root,
        route_root,
        sponsor_pool_root,
        epoch_root,
        quote_root,
        voucher_root,
        redemption_root,
        cost_cap_root,
        privacy_budget_root,
        nullifier_root,
        receipt_root,
        event_root,
        state_root,
    }
}

fn event(config: &Config, epoch_id: &str, kind: &str, subject_id: &str) -> PublicEvent {
    let event_id = stable_hash("event_id", &[epoch_id, kind, subject_id]);
    PublicEvent {
        event_id,
        height: config.current_l2_height,
        epoch_id: epoch_id.to_string(),
        kind: kind.to_string(),
        subject_id: subject_id.to_string(),
        public_root: stable_hash("event_root", &[epoch_id, kind, subject_id]),
    }
}

fn require_non_empty(
    field: &str,
    value: &str,
) -> PrivateL2LowFeePqConfidentialCrossRollupFeeNettingRouterRuntimeResult<()> {
    if value.trim().is_empty() {
        Err(format!("{field} must not be empty"))
    } else {
        Ok(())
    }
}

fn stable_id(prefix: &str, number: u64) -> String {
    format!(
        "{prefix}-{:016x}",
        stable_u128(prefix, &[&number.to_string()])
    )
}

fn value_root(domain: &str, value: &Value) -> String {
    stable_hash(domain, &[&canonical_json(value)])
}

fn map_root<T, F>(domain: &str, map: &BTreeMap<String, T>, record: F) -> String
where
    F: Fn(&T) -> Value,
{
    let leaves: Vec<String> = map
        .iter()
        .map(|(key, value)| stable_hash(domain, &[key, &canonical_json(&record(value))]))
        .collect();
    list_hash(domain, &leaves)
}

fn set_root(domain: &str, set: &BTreeSet<String>) -> String {
    let leaves: Vec<String> = set
        .iter()
        .map(|item| stable_hash(domain, &[item]))
        .collect();
    list_hash(domain, &leaves)
}

fn list_root(domain: &str, values: &[Value]) -> String {
    let leaves: Vec<String> = values
        .iter()
        .map(|value| stable_hash(domain, &[&canonical_json(value)]))
        .collect();
    list_hash(domain, &leaves)
}

fn list_hash(domain: &str, leaves: &[String]) -> String {
    if leaves.is_empty() {
        stable_hash(domain, &["empty"])
    } else {
        let refs: Vec<&str> = leaves.iter().map(String::as_str).collect();
        stable_hash(domain, &refs)
    }
}

fn stable_hash(domain: &str, parts: &[&str]) -> String {
    format!("{:032x}", stable_u128(domain, parts))
}

fn stable_u128(domain: &str, parts: &[&str]) -> u128 {
    let mut lo: u64 = 0xcbf2_9ce4_8422_2325;
    let mut hi: u64 = 0x8422_2325_cbf2_9ce4;
    fn feed(state: &mut u64, byte: u8) {
        *state ^= byte as u64;
        *state = state.wrapping_mul(0x0000_0100_0000_01b3);
    }
    for byte in domain.as_bytes() {
        feed(&mut lo, *byte);
        feed(&mut hi, byte.rotate_left(1));
    }
    feed(&mut lo, 0xff);
    feed(&mut hi, 0x7f);
    for part in parts {
        for byte in part.as_bytes() {
            feed(&mut lo, *byte);
            feed(&mut hi, byte.rotate_right(1));
        }
        feed(&mut lo, 0x1f);
        feed(&mut hi, 0xf1);
    }
    ((hi as u128) << 64) | lo as u128
}

fn canonical_json(value: &Value) -> String {
    match value {
        Value::Null => "null".to_string(),
        Value::Bool(v) => v.to_string(),
        Value::Number(v) => v.to_string(),
        Value::String(v) => format!("{v:?}"),
        Value::Array(values) => {
            let inner: Vec<String> = values.iter().map(canonical_json).collect();
            format!("[{}]", inner.join(","))
        }
        Value::Object(map) => {
            let inner: Vec<String> = map
                .iter()
                .map(|(key, value)| format!("{key:?}:{}", canonical_json(value)))
                .collect();
            format!("{{{}}}", inner.join(","))
        }
    }
}
