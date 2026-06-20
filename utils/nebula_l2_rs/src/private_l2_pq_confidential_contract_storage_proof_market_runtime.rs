use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2PqConfidentialContractStorageProofMarketRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_STORAGE_PROOF_MARKET_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-confidential-contract-storage-proof-market-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_STORAGE_PROOF_MARKET_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_ATTESTATION_SUITE: &str = "ML-DSA-87+SLH-DSA-SHAKE-256f-storage-proof-v1";
pub const STORAGE_COMMITMENT_SUITE: &str = "confidential-contract-storage-commitment-root-v1";
pub const PROOF_MARKET_SUITE: &str = "private-storage-proof-orderbook-v1";
pub const LOW_FEE_REBATE_SUITE: &str = "low-fee-storage-proof-rebate-coupon-v1";
pub const PRIVACY_REDACTION_SUITE: &str = "storage-proof-operator-redaction-root-v1";
pub const DEVNET_L2_HEIGHT: u64 = 4_440_000;
pub const DEVNET_EPOCH: u64 = 19_204;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 12;
pub const DEFAULT_PROOF_TTL_BLOCKS: u64 = 64;
pub const DEFAULT_ORDER_TTL_BLOCKS: u64 = 24;
pub const DEFAULT_PROVIDER_BOND_MICRO_UNITS: u64 = 40_000_000;
pub const DEFAULT_REBATE_BPS: u64 = 6;
pub const DEFAULT_BATCH_DISCOUNT_BPS: u64 = 1_250;
pub const DEFAULT_SLASH_BPS: u64 = 850;
pub const MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StorageProofKind {
    SlotInclusion,
    SlotNonInclusion,
    RangeInclusion,
    ContractCodeHash,
    EventAccumulator,
    CrossContractRead,
    BridgeReserveView,
}

impl StorageProofKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SlotInclusion => "slot_inclusion",
            Self::SlotNonInclusion => "slot_non_inclusion",
            Self::RangeInclusion => "range_inclusion",
            Self::ContractCodeHash => "contract_code_hash",
            Self::EventAccumulator => "event_accumulator",
            Self::CrossContractRead => "cross_contract_read",
            Self::BridgeReserveView => "bridge_reserve_view",
        }
    }

    pub fn default_weight(self) -> u64 {
        match self {
            Self::SlotInclusion => 1_000,
            Self::SlotNonInclusion => 1_120,
            Self::RangeInclusion => 1_450,
            Self::ContractCodeHash => 900,
            Self::EventAccumulator => 1_250,
            Self::CrossContractRead => 1_650,
            Self::BridgeReserveView => 1_800,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofOrderStatus {
    Open,
    Matched,
    Settled,
    Expired,
    Slashed,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub max_user_fee_bps: u64,
    pub provider_bond_micro_units: u64,
    pub proof_ttl_blocks: u64,
    pub order_ttl_blocks: u64,
    pub rebate_bps: u64,
    pub batch_discount_bps: u64,
    pub slash_bps: u64,
    pub hash_suite: String,
    pub pq_attestation_suite: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            provider_bond_micro_units: DEFAULT_PROVIDER_BOND_MICRO_UNITS,
            proof_ttl_blocks: DEFAULT_PROOF_TTL_BLOCKS,
            order_ttl_blocks: DEFAULT_ORDER_TTL_BLOCKS,
            rebate_bps: DEFAULT_REBATE_BPS,
            batch_discount_bps: DEFAULT_BATCH_DISCOUNT_BPS,
            slash_bps: DEFAULT_SLASH_BPS,
            hash_suite: HASH_SUITE.to_string(),
            pq_attestation_suite: PQ_ATTESTATION_SUITE.to_string(),
        }
    }
}

impl Config {
    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "min_pq_security_bits": self.min_pq_security_bits,
            "min_privacy_set_size": self.min_privacy_set_size,
            "max_user_fee_bps": self.max_user_fee_bps,
            "provider_bond_micro_units": self.provider_bond_micro_units,
            "proof_ttl_blocks": self.proof_ttl_blocks,
            "order_ttl_blocks": self.order_ttl_blocks,
            "rebate_bps": self.rebate_bps,
            "batch_discount_bps": self.batch_discount_bps,
            "slash_bps": self.slash_bps,
            "hash_suite": self.hash_suite,
            "pq_attestation_suite": self.pq_attestation_suite,
        })
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Counters {
    pub providers: u64,
    pub storage_commitments: u64,
    pub proof_orders: u64,
    pub proof_bids: u64,
    pub settlements: u64,
    pub rebate_coupons: u64,
    pub redaction_budgets: u64,
    pub slashed_orders: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "providers": self.providers,
            "storage_commitments": self.storage_commitments,
            "proof_orders": self.proof_orders,
            "proof_bids": self.proof_bids,
            "settlements": self.settlements,
            "rebate_coupons": self.rebate_coupons,
            "redaction_budgets": self.redaction_budgets,
            "slashed_orders": self.slashed_orders,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Roots {
    pub config_root: String,
    pub counters_root: String,
    pub provider_root: String,
    pub commitment_root: String,
    pub order_root: String,
    pub bid_root: String,
    pub settlement_root: String,
    pub rebate_root: String,
    pub redaction_root: String,
    pub public_summary_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn empty(config: &Config, counters: &Counters) -> Self {
        let empty = |label: &str| deterministic_root("empty", label);
        let mut roots = Self {
            config_root: record_root("config", &config.public_record()),
            counters_root: record_root("counters", &counters.public_record()),
            provider_root: empty("providers"),
            commitment_root: empty("commitments"),
            order_root: empty("orders"),
            bid_root: empty("bids"),
            settlement_root: empty("settlements"),
            rebate_root: empty("rebates"),
            redaction_root: empty("redactions"),
            public_summary_root: empty("public_summaries"),
            state_root: String::new(),
        };
        roots.state_root = record_root("roots", &roots.public_record_without_state_root());
        roots
    }

    fn public_record_without_state_root(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "counters_root": self.counters_root,
            "provider_root": self.provider_root,
            "commitment_root": self.commitment_root,
            "order_root": self.order_root,
            "bid_root": self.bid_root,
            "settlement_root": self.settlement_root,
            "rebate_root": self.rebate_root,
            "redaction_root": self.redaction_root,
            "public_summary_root": self.public_summary_root,
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        record["state_root"] = json!(self.state_root.clone());
        record
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProviderRegistrationRequest {
    pub operator_label: String,
    pub pq_signer_root: String,
    pub supported_kinds: Vec<StorageProofKind>,
    pub max_parallel_orders: u64,
    pub bond_micro_units: u64,
    pub fee_floor_micro_units: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
}

impl ProviderRegistrationRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "operator_label": self.operator_label,
            "pq_signer_root": self.pq_signer_root,
            "supported_kinds": self.supported_kinds.iter().map(|kind| kind.as_str()).collect::<Vec<_>>(),
            "max_parallel_orders": self.max_parallel_orders,
            "bond_micro_units": self.bond_micro_units,
            "fee_floor_micro_units": self.fee_floor_micro_units,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProviderRecord {
    pub provider_id: String,
    pub request: ProviderRegistrationRequest,
    pub available_capacity: u64,
    pub reputation_score_bps: u64,
    pub slashed_micro_units: u64,
    pub registered_at_height: u64,
    pub provider_root: String,
}

impl ProviderRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "provider_id": self.provider_id,
            "request": self.request.public_record(),
            "available_capacity": self.available_capacity,
            "reputation_score_bps": self.reputation_score_bps,
            "slashed_micro_units": self.slashed_micro_units,
            "registered_at_height": self.registered_at_height,
            "provider_root": self.provider_root,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StorageCommitmentRequest {
    pub contract_id: String,
    pub storage_epoch: u64,
    pub confidential_slot_root: String,
    pub state_commitment_root: String,
    pub event_accumulator_root: String,
    pub bridge_context_root: String,
    pub privacy_redaction_budget: u64,
}

impl StorageCommitmentRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "contract_id": self.contract_id,
            "storage_epoch": self.storage_epoch,
            "confidential_slot_root": self.confidential_slot_root,
            "state_commitment_root": self.state_commitment_root,
            "event_accumulator_root": self.event_accumulator_root,
            "bridge_context_root": self.bridge_context_root,
            "privacy_redaction_budget": self.privacy_redaction_budget,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StorageCommitmentRecord {
    pub commitment_id: String,
    pub request: StorageCommitmentRequest,
    pub published_at_height: u64,
    pub expires_at_height: u64,
    pub commitment_root: String,
}

impl StorageCommitmentRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "commitment_id": self.commitment_id,
            "request": self.request.public_record(),
            "published_at_height": self.published_at_height,
            "expires_at_height": self.expires_at_height,
            "commitment_root": self.commitment_root,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProofOrderRequest {
    pub requester_commitment_root: String,
    pub contract_id: String,
    pub commitment_id: String,
    pub proof_kind: StorageProofKind,
    pub private_query_root: String,
    pub max_fee_micro_units: u64,
    pub max_user_fee_bps: u64,
    pub urgency_blocks: u64,
    pub pq_auth_root: String,
}

impl ProofOrderRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "requester_commitment_root": self.requester_commitment_root,
            "contract_id": self.contract_id,
            "commitment_id": self.commitment_id,
            "proof_kind": self.proof_kind.as_str(),
            "private_query_root": self.private_query_root,
            "max_fee_micro_units": self.max_fee_micro_units,
            "max_user_fee_bps": self.max_user_fee_bps,
            "urgency_blocks": self.urgency_blocks,
            "pq_auth_root": self.pq_auth_root,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProofOrderRecord {
    pub order_id: String,
    pub request: ProofOrderRequest,
    pub status: ProofOrderStatus,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub matched_bid_id: Option<String>,
    pub clearing_fee_micro_units: Option<u64>,
    pub order_root: String,
}

impl ProofOrderRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "order_id": self.order_id,
            "request": self.request.public_record(),
            "status": self.status,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "matched_bid_id": self.matched_bid_id,
            "clearing_fee_micro_units": self.clearing_fee_micro_units,
            "order_root": self.order_root,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProofBidRequest {
    pub order_id: String,
    pub provider_id: String,
    pub fee_micro_units: u64,
    pub proof_latency_blocks: u64,
    pub witness_availability_root: String,
    pub pq_attestation_root: String,
    pub low_fee_coupon_root: String,
}

impl ProofBidRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "order_id": self.order_id,
            "provider_id": self.provider_id,
            "fee_micro_units": self.fee_micro_units,
            "proof_latency_blocks": self.proof_latency_blocks,
            "witness_availability_root": self.witness_availability_root,
            "pq_attestation_root": self.pq_attestation_root,
            "low_fee_coupon_root": self.low_fee_coupon_root,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProofBidRecord {
    pub bid_id: String,
    pub request: ProofBidRequest,
    pub accepted: bool,
    pub bid_root: String,
}

impl ProofBidRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "bid_id": self.bid_id,
            "request": self.request.public_record(),
            "accepted": self.accepted,
            "bid_root": self.bid_root,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProofSettlementRecord {
    pub settlement_id: String,
    pub order_id: String,
    pub bid_id: String,
    pub provider_id: String,
    pub proof_transcript_root: String,
    pub pq_verification_root: String,
    pub redacted_receipt_root: String,
    pub fee_paid_micro_units: u64,
    pub rebate_micro_units: u64,
    pub settled_at_height: u64,
    pub settlement_root: String,
}

impl ProofSettlementRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "settlement_id": self.settlement_id,
            "order_id": self.order_id,
            "bid_id": self.bid_id,
            "provider_id": self.provider_id,
            "proof_transcript_root": self.proof_transcript_root,
            "pq_verification_root": self.pq_verification_root,
            "redacted_receipt_root": self.redacted_receipt_root,
            "fee_paid_micro_units": self.fee_paid_micro_units,
            "rebate_micro_units": self.rebate_micro_units,
            "settled_at_height": self.settled_at_height,
            "settlement_root": self.settlement_root,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RebateCouponRecord {
    pub coupon_id: String,
    pub order_id: String,
    pub provider_id: String,
    pub rebate_micro_units: u64,
    pub sponsor_pool_root: String,
    pub expires_at_height: u64,
    pub coupon_root: String,
}

impl RebateCouponRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "coupon_id": self.coupon_id,
            "order_id": self.order_id,
            "provider_id": self.provider_id,
            "rebate_micro_units": self.rebate_micro_units,
            "sponsor_pool_root": self.sponsor_pool_root,
            "expires_at_height": self.expires_at_height,
            "coupon_root": self.coupon_root,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RedactionBudgetRecord {
    pub redaction_id: String,
    pub order_id: String,
    pub disclosed_fields_root: String,
    pub privacy_set_size: u64,
    pub remaining_budget_units: u64,
    pub redaction_root: String,
}

impl RedactionBudgetRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "redaction_id": self.redaction_id,
            "order_id": self.order_id,
            "disclosed_fields_root": self.disclosed_fields_root,
            "privacy_set_size": self.privacy_set_size,
            "remaining_budget_units": self.remaining_budget_units,
            "redaction_root": self.redaction_root,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OperatorSummary {
    pub protocol_version: String,
    pub state_root: String,
    pub provider_count: u64,
    pub open_order_count: u64,
    pub settled_order_count: u64,
    pub average_fee_micro_units: u64,
    pub low_fee_rebate_bps: u64,
    pub min_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
}

impl OperatorSummary {
    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.protocol_version,
            "state_root": self.state_root,
            "provider_count": self.provider_count,
            "open_order_count": self.open_order_count,
            "settled_order_count": self.settled_order_count,
            "average_fee_micro_units": self.average_fee_micro_units,
            "low_fee_rebate_bps": self.low_fee_rebate_bps,
            "min_privacy_set_size": self.min_privacy_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub current_height: u64,
    pub current_epoch: u64,
    pub providers: BTreeMap<String, ProviderRecord>,
    pub commitments: BTreeMap<String, StorageCommitmentRecord>,
    pub orders: BTreeMap<String, ProofOrderRecord>,
    pub bids: BTreeMap<String, ProofBidRecord>,
    pub settlements: BTreeMap<String, ProofSettlementRecord>,
    pub rebates: BTreeMap<String, RebateCouponRecord>,
    pub redactions: BTreeMap<String, RedactionBudgetRecord>,
    pub public_summaries: BTreeMap<String, Value>,
}

impl Default for State {
    fn default() -> Self {
        Self::new(Config::default())
    }
}

impl State {
    pub fn new(config: Config) -> Self {
        let counters = Counters::default();
        let roots = Roots::empty(&config, &counters);
        Self {
            config,
            counters,
            roots,
            current_height: DEVNET_L2_HEIGHT,
            current_epoch: DEVNET_EPOCH,
            providers: BTreeMap::new(),
            commitments: BTreeMap::new(),
            orders: BTreeMap::new(),
            bids: BTreeMap::new(),
            settlements: BTreeMap::new(),
            rebates: BTreeMap::new(),
            redactions: BTreeMap::new(),
            public_summaries: BTreeMap::new(),
        }
    }

    pub fn register_provider(&mut self, request: ProviderRegistrationRequest) -> Result<String> {
        if request.pq_security_bits < self.config.min_pq_security_bits {
            return Err("provider pq security bits below runtime floor".to_string());
        }
        if request.privacy_set_size < self.config.min_privacy_set_size {
            return Err("provider privacy set below runtime floor".to_string());
        }
        if request.bond_micro_units < self.config.provider_bond_micro_units {
            return Err("provider bond below runtime floor".to_string());
        }
        let provider_id = id_from_record("provider", &request.public_record());
        let provider_root = record_root("provider", &request.public_record());
        let record = ProviderRecord {
            provider_id: provider_id.clone(),
            available_capacity: request.max_parallel_orders,
            request,
            reputation_score_bps: 9_600,
            slashed_micro_units: 0,
            registered_at_height: self.current_height,
            provider_root,
        };
        self.providers.insert(provider_id.clone(), record);
        self.counters.providers = self.providers.len() as u64;
        self.refresh_roots();
        Ok(provider_id)
    }

    pub fn publish_storage_commitment(
        &mut self,
        request: StorageCommitmentRequest,
    ) -> Result<String> {
        if request.privacy_redaction_budget == 0 {
            return Err("privacy redaction budget must be nonzero".to_string());
        }
        let commitment_id = id_from_record("commitment", &request.public_record());
        let commitment_root = record_root("commitment", &request.public_record());
        let record = StorageCommitmentRecord {
            commitment_id: commitment_id.clone(),
            request,
            published_at_height: self.current_height,
            expires_at_height: self.current_height + self.config.proof_ttl_blocks,
            commitment_root,
        };
        self.commitments.insert(commitment_id.clone(), record);
        self.counters.storage_commitments = self.commitments.len() as u64;
        self.refresh_roots();
        Ok(commitment_id)
    }

    pub fn open_proof_order(&mut self, request: ProofOrderRequest) -> Result<String> {
        if !self.commitments.contains_key(&request.commitment_id) {
            return Err("unknown storage commitment".to_string());
        }
        if request.max_user_fee_bps > self.config.max_user_fee_bps {
            return Err("order exceeds max user fee bps".to_string());
        }
        let order_id = id_from_record("proof_order", &request.public_record());
        let order_root = record_root("proof_order", &request.public_record());
        let record = ProofOrderRecord {
            order_id: order_id.clone(),
            request,
            status: ProofOrderStatus::Open,
            opened_at_height: self.current_height,
            expires_at_height: self.current_height + self.config.order_ttl_blocks,
            matched_bid_id: None,
            clearing_fee_micro_units: None,
            order_root,
        };
        self.orders.insert(order_id.clone(), record);
        self.counters.proof_orders = self.orders.len() as u64;
        self.refresh_roots();
        Ok(order_id)
    }

    pub fn submit_proof_bid(&mut self, request: ProofBidRequest) -> Result<String> {
        let order = self
            .orders
            .get(&request.order_id)
            .ok_or_else(|| "unknown proof order".to_string())?;
        if order.status != ProofOrderStatus::Open {
            return Err("proof order is not open".to_string());
        }
        let provider = self
            .providers
            .get(&request.provider_id)
            .ok_or_else(|| "unknown provider".to_string())?;
        if provider.available_capacity == 0 {
            return Err("provider has no available capacity".to_string());
        }
        if request.fee_micro_units > order.request.max_fee_micro_units {
            return Err("bid exceeds requester max fee".to_string());
        }
        let bid_id = id_from_record("proof_bid", &request.public_record());
        let bid_root = record_root("proof_bid", &request.public_record());
        let record = ProofBidRecord {
            bid_id: bid_id.clone(),
            request,
            accepted: false,
            bid_root,
        };
        self.bids.insert(bid_id.clone(), record);
        self.counters.proof_bids = self.bids.len() as u64;
        self.refresh_roots();
        Ok(bid_id)
    }

    pub fn accept_bid(&mut self, order_id: &str, bid_id: &str) -> Result<()> {
        let bid = self
            .bids
            .get_mut(bid_id)
            .ok_or_else(|| "unknown proof bid".to_string())?;
        if bid.request.order_id != order_id {
            return Err("bid does not target proof order".to_string());
        }
        bid.accepted = true;
        let provider_id = bid.request.provider_id.clone();
        let fee_micro_units = bid.request.fee_micro_units;
        let order = self
            .orders
            .get_mut(order_id)
            .ok_or_else(|| "unknown proof order".to_string())?;
        order.status = ProofOrderStatus::Matched;
        order.matched_bid_id = Some(bid_id.to_string());
        order.clearing_fee_micro_units = Some(fee_micro_units);
        if let Some(provider) = self.providers.get_mut(&provider_id) {
            provider.available_capacity = provider.available_capacity.saturating_sub(1);
        }
        self.refresh_roots();
        Ok(())
    }

    pub fn settle_proof(
        &mut self,
        order_id: &str,
        proof_transcript_root: String,
        pq_verification_root: String,
        redacted_receipt_root: String,
    ) -> Result<String> {
        let (bid_id, fee_paid) = {
            let order = self
                .orders
                .get_mut(order_id)
                .ok_or_else(|| "unknown proof order".to_string())?;
            if order.status != ProofOrderStatus::Matched {
                return Err("proof order is not matched".to_string());
            }
            let bid_id = order
                .matched_bid_id
                .clone()
                .ok_or_else(|| "matched order missing bid".to_string())?;
            let bid_fee = self
                .bids
                .get(&bid_id)
                .ok_or_else(|| "matched bid missing".to_string())?
                .request
                .fee_micro_units;
            let fee_paid = order.clearing_fee_micro_units.unwrap_or(bid_fee);
            order.status = ProofOrderStatus::Settled;
            (bid_id, fee_paid)
        };
        let provider_id = self
            .bids
            .get(&bid_id)
            .ok_or_else(|| "matched bid missing".to_string())?
            .request
            .provider_id
            .clone();
        let rebate = fee_paid.saturating_mul(self.config.rebate_bps) / MAX_BPS;
        let settlement_id = deterministic_id(
            "settlement",
            &[
                order_id,
                &bid_id,
                &proof_transcript_root,
                &pq_verification_root,
            ],
        );
        let mut record = ProofSettlementRecord {
            settlement_id: settlement_id.clone(),
            order_id: order_id.to_string(),
            bid_id: bid_id.clone(),
            provider_id: provider_id.clone(),
            proof_transcript_root,
            pq_verification_root,
            redacted_receipt_root,
            fee_paid_micro_units: fee_paid,
            rebate_micro_units: rebate,
            settled_at_height: self.current_height,
            settlement_root: String::new(),
        };
        record.settlement_root = record_root("settlement", &record.public_record());
        self.settlements.insert(settlement_id.clone(), record);
        self.counters.settlements = self.settlements.len() as u64;
        self.issue_rebate(order_id, &provider_id, rebate)?;
        self.refresh_roots();
        Ok(settlement_id)
    }

    pub fn issue_rebate(
        &mut self,
        order_id: &str,
        provider_id: &str,
        rebate_micro_units: u64,
    ) -> Result<String> {
        let coupon_id = deterministic_id(
            "rebate",
            &[order_id, provider_id, &rebate_micro_units.to_string()],
        );
        let sponsor_pool_root = deterministic_root("sponsor_pool", order_id);
        let mut record = RebateCouponRecord {
            coupon_id: coupon_id.clone(),
            order_id: order_id.to_string(),
            provider_id: provider_id.to_string(),
            rebate_micro_units,
            sponsor_pool_root,
            expires_at_height: self.current_height + self.config.proof_ttl_blocks,
            coupon_root: String::new(),
        };
        record.coupon_root = record_root("rebate", &record.public_record());
        self.rebates.insert(coupon_id.clone(), record);
        self.counters.rebate_coupons = self.rebates.len() as u64;
        self.refresh_roots();
        Ok(coupon_id)
    }

    pub fn record_redaction_budget(
        &mut self,
        order_id: &str,
        disclosed_fields_root: String,
        privacy_set_size: u64,
        remaining_budget_units: u64,
    ) -> Result<String> {
        if privacy_set_size < self.config.min_privacy_set_size {
            return Err("redaction privacy set below runtime floor".to_string());
        }
        let redaction_id = deterministic_id(
            "redaction",
            &[
                order_id,
                &disclosed_fields_root,
                &privacy_set_size.to_string(),
            ],
        );
        let mut record = RedactionBudgetRecord {
            redaction_id: redaction_id.clone(),
            order_id: order_id.to_string(),
            disclosed_fields_root,
            privacy_set_size,
            remaining_budget_units,
            redaction_root: String::new(),
        };
        record.redaction_root = record_root("redaction", &record.public_record());
        self.redactions.insert(redaction_id.clone(), record);
        self.counters.redaction_budgets = self.redactions.len() as u64;
        self.refresh_roots();
        Ok(redaction_id)
    }

    pub fn slash_order(&mut self, order_id: &str, reason_root: String) -> Result<String> {
        let order = self
            .orders
            .get_mut(order_id)
            .ok_or_else(|| "unknown proof order".to_string())?;
        order.status = ProofOrderStatus::Slashed;
        self.counters.slashed_orders = self.counters.slashed_orders.saturating_add(1);
        let summary_id = deterministic_id("slash", &[order_id, &reason_root]);
        self.public_summaries.insert(
            summary_id.clone(),
            json!({
                "kind": "storage_proof_slash",
                "order_id": order_id,
                "reason_root": reason_root,
                "height": self.current_height,
                "slash_bps": self.config.slash_bps,
            }),
        );
        self.refresh_roots();
        Ok(summary_id)
    }

    pub fn operator_summary(&self) -> OperatorSummary {
        self.operator_summary_with_state_root(self.state_root())
    }

    fn operator_summary_without_state_root(&self) -> OperatorSummary {
        self.operator_summary_with_state_root(String::new())
    }

    fn operator_summary_with_state_root(&self, state_root: String) -> OperatorSummary {
        let settled = self
            .orders
            .values()
            .filter(|order| order.status == ProofOrderStatus::Settled)
            .count() as u64;
        let open = self
            .orders
            .values()
            .filter(|order| order.status == ProofOrderStatus::Open)
            .count() as u64;
        let total_fee = self
            .settlements
            .values()
            .map(|settlement| settlement.fee_paid_micro_units)
            .sum::<u64>();
        let average_fee = if self.settlements.is_empty() {
            0
        } else {
            total_fee / self.settlements.len() as u64
        };
        OperatorSummary {
            protocol_version: PROTOCOL_VERSION.to_string(),
            state_root,
            provider_count: self.providers.len() as u64,
            open_order_count: open,
            settled_order_count: settled,
            average_fee_micro_units: average_fee,
            low_fee_rebate_bps: self.config.rebate_bps,
            min_privacy_set_size: self.config.min_privacy_set_size,
            min_pq_security_bits: self.config.min_pq_security_bits,
        }
    }

    pub fn refresh_roots(&mut self) {
        self.roots.config_root = record_root("config", &self.config.public_record());
        self.roots.counters_root = record_root("counters", &self.counters.public_record());
        self.roots.provider_root =
            map_root("providers", &self.providers, ProviderRecord::public_record);
        self.roots.commitment_root = map_root(
            "commitments",
            &self.commitments,
            StorageCommitmentRecord::public_record,
        );
        self.roots.order_root = map_root("orders", &self.orders, ProofOrderRecord::public_record);
        self.roots.bid_root = map_root("bids", &self.bids, ProofBidRecord::public_record);
        self.roots.settlement_root = map_root(
            "settlements",
            &self.settlements,
            ProofSettlementRecord::public_record,
        );
        self.roots.rebate_root =
            map_root("rebates", &self.rebates, RebateCouponRecord::public_record);
        self.roots.redaction_root = map_root(
            "redactions",
            &self.redactions,
            RedactionBudgetRecord::public_record,
        );
        self.roots.public_summary_root = value_map_root("public_summaries", &self.public_summaries);
        self.roots.state_root = self.state_root();
    }

    pub fn state_root(&self) -> String {
        state_root_from_record(&self.public_record_without_state_root())
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        record["state_root"] = json!(self.state_root());
        record
    }

    fn public_record_without_state_root(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "chain_id": self.config.chain_id,
            "current_height": self.current_height,
            "current_epoch": self.current_epoch,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record_without_state_root(),
            "operator_summary": self.operator_summary_without_state_root().public_record(),
        })
    }
}

pub fn devnet() -> State {
    let mut state = State::default();
    seed_devnet(&mut state);
    state
}

pub fn demo() -> State {
    devnet()
}

pub fn public_record(state: &State) -> Value {
    state.public_record()
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}

fn seed_devnet(state: &mut State) {
    let provider_id = state
        .register_provider(ProviderRegistrationRequest {
            operator_label: "devnet-storage-proof-provider-a".to_string(),
            pq_signer_root: deterministic_root("pq_signer", "provider-a"),
            supported_kinds: vec![
                StorageProofKind::SlotInclusion,
                StorageProofKind::CrossContractRead,
                StorageProofKind::BridgeReserveView,
            ],
            max_parallel_orders: 128,
            bond_micro_units: DEFAULT_PROVIDER_BOND_MICRO_UNITS * 2,
            fee_floor_micro_units: 600,
            privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE * 4,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        })
        .expect("devnet provider");

    let commitment_id = state
        .publish_storage_commitment(StorageCommitmentRequest {
            contract_id: "private-credit-vault-devnet".to_string(),
            storage_epoch: DEVNET_EPOCH,
            confidential_slot_root: deterministic_root("slot_root", "credit-vault"),
            state_commitment_root: deterministic_root("state_commitment", "credit-vault"),
            event_accumulator_root: deterministic_root("event_accumulator", "credit-vault"),
            bridge_context_root: deterministic_root("bridge_context", "monero-reserve-view"),
            privacy_redaction_budget: 12_000,
        })
        .expect("devnet commitment");

    let order_id = state
        .open_proof_order(ProofOrderRequest {
            requester_commitment_root: deterministic_root("requester", "wallet-a"),
            contract_id: "private-credit-vault-devnet".to_string(),
            commitment_id,
            proof_kind: StorageProofKind::CrossContractRead,
            private_query_root: deterministic_root("query", "margin-health-window"),
            max_fee_micro_units: 7_500,
            max_user_fee_bps: 8,
            urgency_blocks: 6,
            pq_auth_root: deterministic_root("pq_auth", "wallet-session-a"),
        })
        .expect("devnet order");

    let bid_id = state
        .submit_proof_bid(ProofBidRequest {
            order_id: order_id.clone(),
            provider_id: provider_id.clone(),
            fee_micro_units: 4_800,
            proof_latency_blocks: 3,
            witness_availability_root: deterministic_root("witness", "provider-a"),
            pq_attestation_root: deterministic_root("pq_attestation", "provider-a"),
            low_fee_coupon_root: deterministic_root("low_fee_coupon", "storage-proof"),
        })
        .expect("devnet bid");

    state.accept_bid(&order_id, &bid_id).expect("devnet accept");
    state
        .record_redaction_budget(
            &order_id,
            deterministic_root("disclosed_fields", "root-only"),
            DEFAULT_MIN_PRIVACY_SET_SIZE * 8,
            9_250,
        )
        .expect("devnet redaction");
    state
        .settle_proof(
            &order_id,
            deterministic_root("proof_transcript", "cross-contract-read"),
            deterministic_root("pq_verification", "storage-proof"),
            deterministic_root("redacted_receipt", "wallet-safe"),
        )
        .expect("devnet settlement");
    state.refresh_roots();
}

fn deterministic_id(domain: &str, parts: &[&str]) -> String {
    let hash_parts = parts
        .iter()
        .map(|part| HashPart::Str(part))
        .collect::<Vec<_>>();
    domain_hash(
        &format!("contract-storage-proof-market:{domain}:id"),
        &hash_parts,
        16,
    )
}

fn deterministic_root(domain: &str, label: &str) -> String {
    domain_hash(
        &format!("contract-storage-proof-market:{domain}:root"),
        &[HashPart::Str(label)],
        32,
    )
}

fn id_from_record(domain: &str, record: &Value) -> String {
    domain_hash(
        &format!("contract-storage-proof-market:{domain}:id"),
        &[HashPart::Json(record)],
        16,
    )
}

fn record_root(domain: &str, record: &Value) -> String {
    domain_hash(
        &format!("contract-storage-proof-market:{domain}:record"),
        &[HashPart::Json(record)],
        32,
    )
}

fn state_root_from_record(record: &Value) -> String {
    domain_hash(
        "contract-storage-proof-market:state-root",
        &[HashPart::Json(record)],
        32,
    )
}

fn map_root<T, F>(domain: &str, map: &BTreeMap<String, T>, public: F) -> String
where
    F: Fn(&T) -> Value,
{
    let leaves = map
        .iter()
        .map(|(key, value)| json!({"key": key, "record": public(value)}))
        .collect::<Vec<_>>();
    merkle_root(&format!("contract-storage-proof-market:{domain}"), &leaves)
}

fn value_map_root(domain: &str, map: &BTreeMap<String, Value>) -> String {
    let leaves = map
        .iter()
        .map(|(key, value)| json!({"key": key, "record": value}))
        .collect::<Vec<_>>();
    merkle_root(&format!("contract-storage-proof-market:{domain}"), &leaves)
}
