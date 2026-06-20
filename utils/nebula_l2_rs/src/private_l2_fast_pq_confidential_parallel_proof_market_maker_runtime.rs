use crate::hash::{domain_hash as raw_domain_hash, merkle_root as raw_merkle_root, HashPart};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2FastPqConfidentialParallelProofMarketMakerRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PROTOCOL_VERSION: &str =
    "nebula-private-l2-fast-pq-confidential-parallel-proof-market-maker-runtime-v1";
pub const SCHEMA_VERSION: u64 = 1;
pub const DEVNET_L2_NETWORK: &str = "nebula-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEVNET_CHAIN_ID: u64 = 20_260_617;
pub const DEVNET_HEIGHT: u64 = 2_760_000;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_AUTH_SUITE: &str = "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-proof-maker-v1";
pub const CONFIDENTIAL_QUOTE_SCHEME: &str = "sealed-gpu-prover-liquidity-quote-root-v1";
pub const RECURSIVE_INVENTORY_SCHEME: &str = "recursive-proof-inventory-commitment-root-v1";
pub const PRECONFIRMATION_SLA_SCHEME: &str = "fast-confidential-preconfirmation-sla-bucket-root-v1";
pub const FAIR_ROUTING_SCHEME: &str = "deterministic-fair-proof-routing-root-v1";
pub const BACKPRESSURE_SCHEME: &str = "proof-market-maker-backpressure-root-v1";
pub const FEE_CAP_SCHEME: &str = "confidential-proof-fee-cap-root-v1";
pub const SETTLEMENT_RECEIPT_SCHEME: &str = "low-latency-settlement-receipt-root-v1";
pub const PUBLIC_RECORD_SCHEME: &str = "public-proof-market-maker-record-root-v1";
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 262_144;
pub const DEFAULT_MAX_FEE_BPS: u64 = 18;
pub const DEFAULT_QUOTE_TTL_BLOCKS: u64 = 8;
pub const DEFAULT_RECEIPT_TTL_BLOCKS: u64 = 24;
pub const DEFAULT_SLA_TARGET_MS: u64 = 550;
pub const DEFAULT_HARD_SLA_MS: u64 = 2_000;
pub const DEFAULT_BACKPRESSURE_HIGH_WATERMARK_BPS: u64 = 8_200;
pub const DEFAULT_BACKPRESSURE_LOW_WATERMARK_BPS: u64 = 5_800;
pub const DEFAULT_MAX_QUOTES: usize = 262_144;
pub const DEFAULT_MAX_INVENTORY: usize = 131_072;
pub const DEFAULT_MAX_SLA_BUCKETS: usize = 64;
pub const DEFAULT_MAX_ROUTES: usize = 262_144;
pub const DEFAULT_MAX_RECEIPTS: usize = 262_144;
pub const DEFAULT_MAX_PUBLIC_EVENTS: usize = 262_144;
pub const MAX_BPS: u64 = 10_000;

const D_CONFIG: &str = "PL2-FAST-PQ-CONF-PARALLEL-PROOF-MM:CONFIG";
const D_COUNTERS: &str = "PL2-FAST-PQ-CONF-PARALLEL-PROOF-MM:COUNTERS";
const D_ROOTS: &str = "PL2-FAST-PQ-CONF-PARALLEL-PROOF-MM:ROOTS";
const D_QUOTES: &str = "PL2-FAST-PQ-CONF-PARALLEL-PROOF-MM:QUOTES";
const D_INVENTORY: &str = "PL2-FAST-PQ-CONF-PARALLEL-PROOF-MM:INVENTORY";
const D_SLA: &str = "PL2-FAST-PQ-CONF-PARALLEL-PROOF-MM:SLA";
const D_ROUTES: &str = "PL2-FAST-PQ-CONF-PARALLEL-PROOF-MM:ROUTES";
const D_BACKPRESSURE: &str = "PL2-FAST-PQ-CONF-PARALLEL-PROOF-MM:BACKPRESSURE";
const D_FEE_CAPS: &str = "PL2-FAST-PQ-CONF-PARALLEL-PROOF-MM:FEE-CAPS";
const D_RECEIPTS: &str = "PL2-FAST-PQ-CONF-PARALLEL-PROOF-MM:RECEIPTS";
const D_PUBLIC: &str = "PL2-FAST-PQ-CONF-PARALLEL-PROOF-MM:PUBLIC";
const D_STATE: &str = "PL2-FAST-PQ-CONF-PARALLEL-PROOF-MM:STATE";

trait LocalHashPart {
    fn to_hash_part(&self) -> HashPart<'_>;
}

impl LocalHashPart for &str {
    fn to_hash_part(&self) -> HashPart<'_> {
        HashPart::Str(*self)
    }
}

impl LocalHashPart for String {
    fn to_hash_part(&self) -> HashPart<'_> {
        HashPart::Str(self.as_str())
    }
}

impl LocalHashPart for &String {
    fn to_hash_part(&self) -> HashPart<'_> {
        HashPart::Str(self.as_str())
    }
}

impl<'a> LocalHashPart for HashPart<'a> {
    fn to_hash_part(&self) -> HashPart<'_> {
        match self {
            HashPart::Bytes(value) => HashPart::Bytes(value),
            HashPart::Str(value) => HashPart::Str(value),
            HashPart::U64(value) => HashPart::U64(*value),
            HashPart::Int(value) => HashPart::Int(*value),
            HashPart::Json(value) => HashPart::Json(value),
        }
    }
}

fn domain_hash<T: LocalHashPart>(domain: &str, parts: &[T]) -> String {
    let hash_parts = parts
        .iter()
        .map(LocalHashPart::to_hash_part)
        .collect::<Vec<_>>();
    raw_domain_hash(domain, &hash_parts, 32)
}

trait MerkleLeaf {
    fn to_merkle_leaf(&self) -> Value;
}

impl<'a> MerkleLeaf for HashPart<'a> {
    fn to_merkle_leaf(&self) -> Value {
        match self {
            HashPart::Bytes(value) => Value::String(hex::encode(value)),
            HashPart::Str(value) => Value::String((*value).to_string()),
            HashPart::U64(value) => json!(value),
            HashPart::Int(value) => json!(value),
            HashPart::Json(value) => (*value).clone(),
        }
    }
}

impl MerkleLeaf for String {
    fn to_merkle_leaf(&self) -> Value {
        Value::String(self.clone())
    }
}

impl MerkleLeaf for &String {
    fn to_merkle_leaf(&self) -> Value {
        Value::String((*self).clone())
    }
}

fn merkle_root<T: MerkleLeaf>(domain: &str, leaves: Vec<T>) -> String {
    let values = leaves
        .iter()
        .map(MerkleLeaf::to_merkle_leaf)
        .collect::<Vec<_>>();
    raw_merkle_root(domain, &values)
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AcceleratorKind {
    Gpu,
    Fpga,
    CpuVector,
    RecursiveAggregator,
    VerifierCache,
    Hybrid,
}
impl AcceleratorKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Gpu => "gpu",
            Self::Fpga => "fpga",
            Self::CpuVector => "cpu_vector",
            Self::RecursiveAggregator => "recursive_aggregator",
            Self::VerifierCache => "verifier_cache",
            Self::Hybrid => "hybrid",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofWorkloadKind {
    TransferBatch,
    ContractExecution,
    ConfidentialSwap,
    TokenNetting,
    MoneroExit,
    OracleAttestation,
    RecursiveWrap,
    SettlementCompress,
    EmergencyEscape,
    LowFeeBulk,
}
impl ProofWorkloadKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::TransferBatch => "transfer_batch",
            Self::ContractExecution => "contract_execution",
            Self::ConfidentialSwap => "confidential_swap",
            Self::TokenNetting => "token_netting",
            Self::MoneroExit => "monero_exit",
            Self::OracleAttestation => "oracle_attestation",
            Self::RecursiveWrap => "recursive_wrap",
            Self::SettlementCompress => "settlement_compress",
            Self::EmergencyEscape => "emergency_escape",
            Self::LowFeeBulk => "low_fee_bulk",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SlaClass {
    Instant,
    Fast,
    Standard,
    LowFee,
    Sponsored,
    Emergency,
}
impl SlaClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Instant => "instant",
            Self::Fast => "fast",
            Self::Standard => "standard",
            Self::LowFee => "low_fee",
            Self::Sponsored => "sponsored",
            Self::Emergency => "emergency",
        }
    }
    pub fn target_ms(self, config: &Config) -> u64 {
        match self {
            Self::Instant => config.sla_target_ms.saturating_div(2).max(1),
            Self::Fast => config.sla_target_ms,
            Self::Standard => config.sla_target_ms.saturating_mul(3),
            Self::LowFee => config.sla_target_ms.saturating_mul(8),
            Self::Sponsored => config.sla_target_ms.saturating_mul(5),
            Self::Emergency => config.sla_target_ms.saturating_div(3).max(1),
        }
    }
    pub fn fee_multiplier_bps(self) -> u64 {
        match self {
            Self::Instant => 1_450,
            Self::Fast => 1_150,
            Self::Standard => 1_000,
            Self::LowFee => 720,
            Self::Sponsored => 620,
            Self::Emergency => 1_900,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QuoteStatus {
    Open,
    Reserved,
    Filled,
    Expired,
    Throttled,
    Cancelled,
}
impl QuoteStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Reserved => "reserved",
            Self::Filled => "filled",
            Self::Expired => "expired",
            Self::Throttled => "throttled",
            Self::Cancelled => "cancelled",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptStatus {
    Accepted,
    Proving,
    Preconfirmed,
    Settled,
    Rebated,
    Slashed,
}
impl ReceiptStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Proving => "proving",
            Self::Preconfirmed => "preconfirmed",
            Self::Settled => "settled",
            Self::Rebated => "rebated",
            Self::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: u64,
    pub network: String,
    pub fee_asset_id: String,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub max_fee_bps: u64,
    pub quote_ttl_blocks: u64,
    pub receipt_ttl_blocks: u64,
    pub sla_target_ms: u64,
    pub hard_sla_ms: u64,
    pub backpressure_high_watermark_bps: u64,
    pub backpressure_low_watermark_bps: u64,
    pub max_quotes: usize,
    pub max_inventory: usize,
    pub max_sla_buckets: usize,
    pub max_routes: usize,
    pub max_receipts: usize,
    pub max_public_events: usize,
    pub enforce_fee_caps: bool,
    pub deterministic_fair_routing: bool,
    pub allow_low_fee_sponsored_lane: bool,
}
impl Default for Config {
    fn default() -> Self {
        Self {
            chain_id: DEVNET_CHAIN_ID,
            network: DEVNET_L2_NETWORK.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            max_fee_bps: DEFAULT_MAX_FEE_BPS,
            quote_ttl_blocks: DEFAULT_QUOTE_TTL_BLOCKS,
            receipt_ttl_blocks: DEFAULT_RECEIPT_TTL_BLOCKS,
            sla_target_ms: DEFAULT_SLA_TARGET_MS,
            hard_sla_ms: DEFAULT_HARD_SLA_MS,
            backpressure_high_watermark_bps: DEFAULT_BACKPRESSURE_HIGH_WATERMARK_BPS,
            backpressure_low_watermark_bps: DEFAULT_BACKPRESSURE_LOW_WATERMARK_BPS,
            max_quotes: DEFAULT_MAX_QUOTES,
            max_inventory: DEFAULT_MAX_INVENTORY,
            max_sla_buckets: DEFAULT_MAX_SLA_BUCKETS,
            max_routes: DEFAULT_MAX_ROUTES,
            max_receipts: DEFAULT_MAX_RECEIPTS,
            max_public_events: DEFAULT_MAX_PUBLIC_EVENTS,
            enforce_fee_caps: true,
            deterministic_fair_routing: true,
            allow_low_fee_sponsored_lane: true,
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub quote_requests: u64,
    pub quotes_recorded: u64,
    pub inventory_records: u64,
    pub sla_buckets_recorded: u64,
    pub route_decisions: u64,
    pub backpressure_updates: u64,
    pub fee_caps_recorded: u64,
    pub settlement_receipts: u64,
    pub public_events: u64,
    pub rejected_fee_caps: u64,
    pub rejected_security: u64,
    pub rejected_capacity: u64,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub counters_root: String,
    pub quotes_root: String,
    pub inventory_root: String,
    pub sla_root: String,
    pub route_root: String,
    pub backpressure_root: String,
    pub fee_cap_root: String,
    pub receipt_root: String,
    pub public_root: String,
    pub state_root: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiquidityQuoteRequest {
    pub request_id: String,
    pub intent_commitment: String,
    pub workload: ProofWorkloadKind,
    pub sla_class: SlaClass,
    pub max_fee_bps: u64,
    pub notional_piconero: u64,
    pub encrypted_witness_root: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub preferred_region_code: String,
    pub height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GpuProverLiquidityQuote {
    pub quote_id: String,
    pub request_id: String,
    pub maker_id: String,
    pub accelerator: AcceleratorKind,
    pub workload: ProofWorkloadKind,
    pub sla_class: SlaClass,
    pub capacity_units: u64,
    pub fee_bps: u64,
    pub estimated_latency_ms: u64,
    pub recursive_slots: u64,
    pub confidential_quote_root: String,
    pub expires_at_height: u64,
    pub status: QuoteStatus,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RecursiveProofInventoryRecord {
    pub inventory_id: String,
    pub maker_id: String,
    pub workload: ProofWorkloadKind,
    pub available_leaf_proofs: u64,
    pub available_recursive_wraps: u64,
    pub reserved_recursive_wraps: u64,
    pub verifier_cache_hits: u64,
    pub inventory_commitment: String,
    pub height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PreconfirmationSlaBucket {
    pub bucket_id: String,
    pub sla_class: SlaClass,
    pub target_ms: u64,
    pub hard_limit_ms: u64,
    pub reserved_capacity_units: u64,
    pub open_capacity_units: u64,
    pub fee_ceiling_bps: u64,
    pub breach_budget_bps: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FairRoutingDecisionRecord {
    pub route_id: String,
    pub request_id: String,
    pub quote_id: String,
    pub maker_id: String,
    pub sla_class: SlaClass,
    pub fairness_rank: u64,
    pub deterministic_weight: u64,
    pub fee_bps: u64,
    pub estimated_latency_ms: u64,
    pub route_commitment: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BackpressureRecord {
    pub record_id: String,
    pub maker_id: String,
    pub queue_depth_units: u64,
    pub capacity_units: u64,
    pub utilization_bps: u64,
    pub throttle_bps: u64,
    pub shed_low_fee: bool,
    pub reason: String,
    pub height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FeeCapRecord {
    pub cap_id: String,
    pub sla_class: SlaClass,
    pub workload: ProofWorkloadKind,
    pub max_fee_bps: u64,
    pub sponsor_cover_bps: u64,
    pub rebate_bps: u64,
    pub cap_commitment: String,
    pub height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SettlementReceiptRecord {
    pub receipt_id: String,
    pub request_id: String,
    pub route_id: String,
    pub maker_id: String,
    pub status: ReceiptStatus,
    pub fee_paid_piconero: u64,
    pub latency_ms: u64,
    pub settlement_height: u64,
    pub receipt_commitment: String,
    pub recursive_proof_root: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublicEventRecord {
    pub event_id: String,
    pub kind: String,
    pub subject_id: String,
    pub public_root: String,
    pub height: u64,
    pub note: String,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub quote_requests: BTreeMap<String, LiquidityQuoteRequest>,
    pub quotes: BTreeMap<String, GpuProverLiquidityQuote>,
    pub inventory: BTreeMap<String, RecursiveProofInventoryRecord>,
    pub sla_buckets: BTreeMap<String, PreconfirmationSlaBucket>,
    pub routes: BTreeMap<String, FairRoutingDecisionRecord>,
    pub backpressure: BTreeMap<String, BackpressureRecord>,
    pub fee_caps: BTreeMap<String, FeeCapRecord>,
    pub receipts: BTreeMap<String, SettlementReceiptRecord>,
    pub public_events: VecDeque<PublicEventRecord>,
    pub makers: BTreeSet<String>,
}
impl Default for State {
    fn default() -> Self {
        let mut state = Self {
            config: Config::default(),
            counters: Counters::default(),
            roots: Roots::default(),
            quote_requests: BTreeMap::new(),
            quotes: BTreeMap::new(),
            inventory: BTreeMap::new(),
            sla_buckets: BTreeMap::new(),
            routes: BTreeMap::new(),
            backpressure: BTreeMap::new(),
            fee_caps: BTreeMap::new(),
            receipts: BTreeMap::new(),
            public_events: VecDeque::new(),
            makers: BTreeSet::new(),
        };
        state.refresh_roots();
        state
    }
}
impl State {
    pub fn new(config: Config) -> Self {
        let mut state = Self {
            config,
            ..Self::default()
        };
        state.refresh_roots();
        state
    }
    pub fn record_quote_request(&mut self, request: LiquidityQuoteRequest) -> Result<()> {
        if request.pq_security_bits < self.config.min_pq_security_bits {
            self.counters.rejected_security = self.counters.rejected_security.saturating_add(1);
            self.refresh_roots();
            return Err("pq security bits below runtime minimum".to_string());
        }
        if request.privacy_set_size < self.config.min_privacy_set_size {
            self.counters.rejected_security = self.counters.rejected_security.saturating_add(1);
            self.refresh_roots();
            return Err("privacy set size below runtime minimum".to_string());
        }
        if self.quote_requests.len() >= self.config.max_quotes {
            self.counters.rejected_capacity = self.counters.rejected_capacity.saturating_add(1);
            self.refresh_roots();
            return Err("quote request capacity exhausted".to_string());
        }
        self.counters.quote_requests = self.counters.quote_requests.saturating_add(1);
        self.quote_requests
            .insert(request.request_id.clone(), request);
        self.refresh_roots();
        Ok(())
    }
    pub fn record_quote(&mut self, mut quote: GpuProverLiquidityQuote) -> Result<()> {
        if self.quotes.len() >= self.config.max_quotes {
            self.counters.rejected_capacity = self.counters.rejected_capacity.saturating_add(1);
            self.refresh_roots();
            return Err("quote capacity exhausted".to_string());
        }
        if self.config.enforce_fee_caps && quote.fee_bps > self.config.max_fee_bps {
            self.counters.rejected_fee_caps = self.counters.rejected_fee_caps.saturating_add(1);
            quote.status = QuoteStatus::Throttled;
        }
        self.makers.insert(quote.maker_id.clone());
        self.counters.quotes_recorded = self.counters.quotes_recorded.saturating_add(1);
        self.quotes.insert(quote.quote_id.clone(), quote);
        self.refresh_roots();
        Ok(())
    }
    pub fn record_inventory(&mut self, inventory: RecursiveProofInventoryRecord) -> Result<()> {
        if self.inventory.len() >= self.config.max_inventory {
            self.counters.rejected_capacity = self.counters.rejected_capacity.saturating_add(1);
            self.refresh_roots();
            return Err("inventory capacity exhausted".to_string());
        }
        self.makers.insert(inventory.maker_id.clone());
        self.counters.inventory_records = self.counters.inventory_records.saturating_add(1);
        self.inventory
            .insert(inventory.inventory_id.clone(), inventory);
        self.refresh_roots();
        Ok(())
    }
    pub fn record_sla_bucket(&mut self, bucket: PreconfirmationSlaBucket) -> Result<()> {
        if self.sla_buckets.len() >= self.config.max_sla_buckets {
            self.counters.rejected_capacity = self.counters.rejected_capacity.saturating_add(1);
            self.refresh_roots();
            return Err("sla bucket capacity exhausted".to_string());
        }
        self.counters.sla_buckets_recorded = self.counters.sla_buckets_recorded.saturating_add(1);
        self.sla_buckets.insert(bucket.bucket_id.clone(), bucket);
        self.refresh_roots();
        Ok(())
    }
    pub fn record_route(&mut self, route: FairRoutingDecisionRecord) -> Result<()> {
        if self.routes.len() >= self.config.max_routes {
            self.counters.rejected_capacity = self.counters.rejected_capacity.saturating_add(1);
            self.refresh_roots();
            return Err("route capacity exhausted".to_string());
        }
        self.makers.insert(route.maker_id.clone());
        self.counters.route_decisions = self.counters.route_decisions.saturating_add(1);
        self.routes.insert(route.route_id.clone(), route);
        self.refresh_roots();
        Ok(())
    }
    pub fn record_backpressure(&mut self, record: BackpressureRecord) -> Result<()> {
        self.makers.insert(record.maker_id.clone());
        self.counters.backpressure_updates = self.counters.backpressure_updates.saturating_add(1);
        self.backpressure.insert(record.record_id.clone(), record);
        self.refresh_roots();
        Ok(())
    }
    pub fn record_fee_cap(&mut self, cap: FeeCapRecord) -> Result<()> {
        if self.config.enforce_fee_caps && cap.max_fee_bps > self.config.max_fee_bps {
            self.counters.rejected_fee_caps = self.counters.rejected_fee_caps.saturating_add(1);
            self.refresh_roots();
            return Err("fee cap exceeds runtime maximum".to_string());
        }
        self.counters.fee_caps_recorded = self.counters.fee_caps_recorded.saturating_add(1);
        self.fee_caps.insert(cap.cap_id.clone(), cap);
        self.refresh_roots();
        Ok(())
    }
    pub fn record_settlement_receipt(&mut self, receipt: SettlementReceiptRecord) -> Result<()> {
        if self.receipts.len() >= self.config.max_receipts {
            self.counters.rejected_capacity = self.counters.rejected_capacity.saturating_add(1);
            self.refresh_roots();
            return Err("receipt capacity exhausted".to_string());
        }
        self.makers.insert(receipt.maker_id.clone());
        self.counters.settlement_receipts = self.counters.settlement_receipts.saturating_add(1);
        self.receipts.insert(receipt.receipt_id.clone(), receipt);
        self.refresh_roots();
        Ok(())
    }
    pub fn push_public_event(&mut self, event: PublicEventRecord) {
        while self.public_events.len() >= self.config.max_public_events {
            let _ = self.public_events.pop_front();
        }
        self.counters.public_events = self.counters.public_events.saturating_add(1);
        self.public_events.push_back(event);
        self.refresh_roots();
    }
    pub fn deterministic_route_for(&self, request_id: &str) -> Option<FairRoutingDecisionRecord> {
        let request = self.quote_requests.get(request_id)?;
        let mut candidates: Vec<&GpuProverLiquidityQuote> = self
            .quotes
            .values()
            .filter(|q| q.request_id == request_id)
            .filter(|q| q.status == QuoteStatus::Open || q.status == QuoteStatus::Reserved)
            .filter(|q| q.fee_bps <= request.max_fee_bps.min(self.config.max_fee_bps))
            .collect();
        candidates.sort_by(|l, r| {
            l.fee_bps
                .cmp(&r.fee_bps)
                .then(l.estimated_latency_ms.cmp(&r.estimated_latency_ms))
                .then(l.maker_id.cmp(&r.maker_id))
                .then(l.quote_id.cmp(&r.quote_id))
        });
        let quote = candidates.first()?;
        let rank = self.fairness_rank(&quote.maker_id, &quote.quote_id);
        Some(FairRoutingDecisionRecord {
            route_id: deterministic_id("route", &[request_id, &quote.quote_id, &rank.to_string()]),
            request_id: request_id.to_string(),
            quote_id: quote.quote_id.clone(),
            maker_id: quote.maker_id.clone(),
            sla_class: request.sla_class,
            fairness_rank: rank,
            deterministic_weight: deterministic_weight(
                &quote.maker_id,
                &quote.quote_id,
                request_id,
            ),
            fee_bps: quote.fee_bps,
            estimated_latency_ms: quote.estimated_latency_ms,
            route_commitment: domain_hash(
                D_ROUTES,
                &[request_id, &quote.quote_id, &quote.maker_id],
            ),
        })
    }
    pub fn apply_deterministic_route(
        &mut self,
        request_id: &str,
    ) -> Result<Option<FairRoutingDecisionRecord>> {
        let route = self.deterministic_route_for(request_id);
        if let Some(record) = route.clone() {
            self.record_route(record)?;
        }
        Ok(route)
    }
    pub fn backpressure_for(&self, maker_id: &str) -> Option<&BackpressureRecord> {
        self.backpressure
            .values()
            .rev()
            .find(|record| record.maker_id == maker_id)
    }
    pub fn effective_fee_cap_bps(&self, workload: ProofWorkloadKind, sla_class: SlaClass) -> u64 {
        {
            let cap = self
                .fee_caps
                .values()
                .filter(|cap| cap.workload == workload && cap.sla_class == sla_class)
                .map(|cap| cap.max_fee_bps)
                .min();
            match cap {
                Some(value) => value,
                None => self.config.max_fee_bps,
            }
        }
    }
    pub fn inventory_available_wraps(&self, maker_id: &str) -> u64 {
        self.inventory
            .values()
            .filter(|record| record.maker_id == maker_id)
            .map(|record| {
                record
                    .available_recursive_wraps
                    .saturating_sub(record.reserved_recursive_wraps)
            })
            .sum()
    }
    pub fn state_root(&self) -> String {
        self.roots.state_root.clone()
    }
    pub fn public_record(&self) -> Value {
        json!({ "protocol_version": PROTOCOL_VERSION, "schema_version": SCHEMA_VERSION, "chain_id": self.config.chain_id, "network": self.config.network, "fee_asset_id": self.config.fee_asset_id, "hash_suite": HASH_SUITE, "pq_auth_suite": PQ_AUTH_SUITE, "counts": { "quote_requests": self.quote_requests.len(), "quotes": self.quotes.len(), "inventory": self.inventory.len(), "sla_buckets": self.sla_buckets.len(), "routes": self.routes.len(), "backpressure": self.backpressure.len(), "fee_caps": self.fee_caps.len(), "receipts": self.receipts.len(), "makers": self.makers.len() }, "counters": self.counters, "roots": self.roots })
    }
    pub fn refresh_roots(&mut self) {
        self.roots.config_root = json_root(D_CONFIG, &self.config);
        self.roots.counters_root = json_root(D_COUNTERS, &self.counters);
        self.roots.quotes_root = map_root(D_QUOTES, &self.quotes);
        self.roots.inventory_root = map_root(D_INVENTORY, &self.inventory);
        self.roots.sla_root = map_root(D_SLA, &self.sla_buckets);
        self.roots.route_root = map_root(D_ROUTES, &self.routes);
        self.roots.backpressure_root = map_root(D_BACKPRESSURE, &self.backpressure);
        self.roots.fee_cap_root = map_root(D_FEE_CAPS, &self.fee_caps);
        self.roots.receipt_root = map_root(D_RECEIPTS, &self.receipts);
        self.roots.public_root = vecdeque_root(D_PUBLIC, &self.public_events);
        self.roots.state_root = domain_hash(
            D_STATE,
            &[
                &self.roots.config_root,
                &self.roots.counters_root,
                &self.roots.quotes_root,
                &self.roots.inventory_root,
                &self.roots.sla_root,
                &self.roots.route_root,
                &self.roots.backpressure_root,
                &self.roots.fee_cap_root,
                &self.roots.receipt_root,
                &self.roots.public_root,
            ],
        );
    }
    fn fairness_rank(&self, maker_id: &str, quote_id: &str) -> u64 {
        let maker_count = self.makers.len() as u64;
        let spread = maker_count.saturating_add(1).saturating_mul(1_000);
        deterministic_weight(maker_id, quote_id, &self.roots.inventory_root) % spread.max(1)
    }
}

pub fn devnet() -> State {
    let mut state = State::default();
    for bucket in default_sla_buckets(&state.config) {
        let _ = state.record_sla_bucket(bucket);
    }
    for cap in default_fee_caps(DEVNET_HEIGHT) {
        let _ = state.record_fee_cap(cap);
    }
    state
}
pub fn demo() -> State {
    let mut state = devnet();
    let request = LiquidityQuoteRequest {
        request_id: "demo-request-0001".to_string(),
        intent_commitment: domain_hash("demo-intent", &["swap", "xmr", "nebula"]),
        workload: ProofWorkloadKind::ConfidentialSwap,
        sla_class: SlaClass::Fast,
        max_fee_bps: 12,
        notional_piconero: 42_000_000,
        encrypted_witness_root: domain_hash("demo-witness", &["sealed"]),
        privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
        pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        preferred_region_code: "devnet-a".to_string(),
        height: DEVNET_HEIGHT,
    };
    let _ = state.record_quote_request(request);
    let quote = GpuProverLiquidityQuote {
        quote_id: "demo-quote-gpu-0001".to_string(),
        request_id: "demo-request-0001".to_string(),
        maker_id: "maker-gpu-alpha".to_string(),
        accelerator: AcceleratorKind::Gpu,
        workload: ProofWorkloadKind::ConfidentialSwap,
        sla_class: SlaClass::Fast,
        capacity_units: 64,
        fee_bps: 9,
        estimated_latency_ms: 420,
        recursive_slots: 12,
        confidential_quote_root: domain_hash("demo-quote", &["maker-gpu-alpha", "9"]),
        expires_at_height: DEVNET_HEIGHT.saturating_add(DEFAULT_QUOTE_TTL_BLOCKS),
        status: QuoteStatus::Open,
    };
    let _ = state.record_quote(quote);
    let inventory = RecursiveProofInventoryRecord {
        inventory_id: "demo-inventory-alpha".to_string(),
        maker_id: "maker-gpu-alpha".to_string(),
        workload: ProofWorkloadKind::ConfidentialSwap,
        available_leaf_proofs: 512,
        available_recursive_wraps: 48,
        reserved_recursive_wraps: 4,
        verifier_cache_hits: 128,
        inventory_commitment: domain_hash("demo-inventory", &["maker-gpu-alpha", "48"]),
        height: DEVNET_HEIGHT,
    };
    let _ = state.record_inventory(inventory);
    if let Ok(Some(route)) = state.apply_deterministic_route("demo-request-0001") {
        let receipt = SettlementReceiptRecord {
            receipt_id: "demo-receipt-0001".to_string(),
            request_id: route.request_id.clone(),
            route_id: route.route_id.clone(),
            maker_id: route.maker_id.clone(),
            status: ReceiptStatus::Preconfirmed,
            fee_paid_piconero: 3_780,
            latency_ms: route.estimated_latency_ms,
            settlement_height: DEVNET_HEIGHT.saturating_add(2),
            receipt_commitment: domain_hash("demo-receipt", &[&route.route_id, "preconfirmed"]),
            recursive_proof_root: domain_hash("demo-recursive-proof", &[&route.quote_id]),
        };
        let _ = state.record_settlement_receipt(receipt);
    }
    state.push_public_event(PublicEventRecord {
        event_id: "demo-public-event-0001".to_string(),
        kind: "market_maker_demo".to_string(),
        subject_id: "demo-request-0001".to_string(),
        public_root: state.state_root(),
        height: DEVNET_HEIGHT.saturating_add(2),
        note: "devnet deterministic proof market maker demo".to_string(),
    });
    state
}
pub fn public_record() -> Value {
    demo().public_record()
}
pub fn state_root() -> String {
    demo().state_root()
}
pub fn default_sla_buckets(config: &Config) -> Vec<PreconfirmationSlaBucket> {
    vec![
        make_sla_bucket("instant", SlaClass::Instant, config, 8, 2_000),
        make_sla_bucket("fast", SlaClass::Fast, config, 24, 1_200),
        make_sla_bucket("standard", SlaClass::Standard, config, 64, 800),
        make_sla_bucket("low-fee", SlaClass::LowFee, config, 128, 350),
        make_sla_bucket("sponsored", SlaClass::Sponsored, config, 80, 250),
        make_sla_bucket("emergency", SlaClass::Emergency, config, 12, 4_000),
    ]
}
pub fn default_fee_caps(height: u64) -> Vec<FeeCapRecord> {
    let workloads = [
        ProofWorkloadKind::TransferBatch,
        ProofWorkloadKind::ContractExecution,
        ProofWorkloadKind::ConfidentialSwap,
        ProofWorkloadKind::TokenNetting,
        ProofWorkloadKind::MoneroExit,
        ProofWorkloadKind::OracleAttestation,
        ProofWorkloadKind::RecursiveWrap,
        ProofWorkloadKind::SettlementCompress,
        ProofWorkloadKind::EmergencyEscape,
        ProofWorkloadKind::LowFeeBulk,
    ];
    let classes = [
        SlaClass::Instant,
        SlaClass::Fast,
        SlaClass::Standard,
        SlaClass::LowFee,
        SlaClass::Sponsored,
        SlaClass::Emergency,
    ];
    let mut caps = Vec::new();
    for workload in workloads {
        for sla_class in classes {
            let base: u64 = match workload {
                ProofWorkloadKind::EmergencyEscape => 18,
                ProofWorkloadKind::MoneroExit => 15,
                ProofWorkloadKind::ContractExecution => 14,
                ProofWorkloadKind::RecursiveWrap => 13,
                ProofWorkloadKind::SettlementCompress => 11,
                ProofWorkloadKind::ConfidentialSwap => 12,
                ProofWorkloadKind::TokenNetting => 10,
                ProofWorkloadKind::OracleAttestation => 9,
                ProofWorkloadKind::TransferBatch => 8,
                ProofWorkloadKind::LowFeeBulk => 6,
            };
            let cap = base
                .saturating_mul(sla_class.fee_multiplier_bps())
                .saturating_div(MAX_BPS);
            caps.push(FeeCapRecord {
                cap_id: deterministic_id("fee-cap", &[workload.as_str(), sla_class.as_str()]),
                sla_class,
                workload,
                max_fee_bps: cap.max(1).min(DEFAULT_MAX_FEE_BPS),
                sponsor_cover_bps: if sla_class == SlaClass::Sponsored {
                    9_500
                } else {
                    0
                },
                rebate_bps: if sla_class == SlaClass::LowFee {
                    120
                } else {
                    0
                },
                cap_commitment: domain_hash(
                    D_FEE_CAPS,
                    &[workload.as_str(), sla_class.as_str(), &height.to_string()],
                ),
                height,
            });
        }
    }
    caps
}
fn make_sla_bucket(
    label: &str,
    sla_class: SlaClass,
    config: &Config,
    open_capacity_units: u64,
    breach_budget_bps: u64,
) -> PreconfirmationSlaBucket {
    let target_ms = sla_class.target_ms(config);
    PreconfirmationSlaBucket {
        bucket_id: deterministic_id("sla", &[label, sla_class.as_str()]),
        sla_class,
        target_ms,
        hard_limit_ms: config.hard_sla_ms.max(target_ms),
        reserved_capacity_units: 0,
        open_capacity_units,
        fee_ceiling_bps: config.max_fee_bps,
        breach_budget_bps,
    }
}
fn json_root<T: Serialize>(domain: &str, value: &T) -> String {
    let encoded = match serde_json::to_string(value) {
        Ok(encoded) => encoded,
        Err(_) => "null".to_string(),
    };
    domain_hash(domain, &[&encoded])
}
fn map_root<T: Serialize>(domain: &str, values: &BTreeMap<String, T>) -> String {
    let leaves: Vec<String> = values
        .iter()
        .map(|(key, value)| {
            let encoded = match serde_json::to_string(value) {
                Ok(encoded) => encoded,
                Err(_) => "null".to_string(),
            };
            domain_hash(domain, &[key, &encoded])
        })
        .collect();
    merkle_root(domain, leaves)
}
fn vecdeque_root<T: Serialize>(domain: &str, values: &VecDeque<T>) -> String {
    let leaves: Vec<String> = values
        .iter()
        .enumerate()
        .map(|(index, value)| {
            let encoded = match serde_json::to_string(value) {
                Ok(encoded) => encoded,
                Err(_) => "null".to_string(),
            };
            domain_hash(domain, &[&index.to_string(), &encoded])
        })
        .collect();
    merkle_root(domain, leaves)
}
fn deterministic_id(prefix: &str, parts: &[&str]) -> String {
    let digest = domain_hash(prefix, parts);
    let suffix: String = digest.chars().take(24).collect();
    format!("{}-{}", prefix, suffix)
}
fn deterministic_weight(a: &str, b: &str, c: &str) -> u64 {
    let digest = domain_hash("proof-market-maker-weight", &[a, b, c]);
    digest.bytes().fold(0_u64, |acc, byte| {
        acc.wrapping_mul(131).wrapping_add(byte as u64)
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MarketMakerScenario {
    pub scenario_id: &'static str,
    pub maker_id: &'static str,
    pub workload: ProofWorkloadKind,
    pub sla_class: SlaClass,
    pub accelerator: AcceleratorKind,
    pub capacity_units: u64,
    pub fee_bps: u64,
    pub latency_ms: u64,
    pub recursive_slots: u64,
}

pub const DETERMINISTIC_SCENARIO_CATALOG: &[MarketMakerScenario] = &[
    MarketMakerScenario {
        scenario_id: "scenario-0001",
        maker_id: "maker-02",
        workload: ProofWorkloadKind::ContractExecution,
        sla_class: SlaClass::Fast,
        accelerator: AcceleratorKind::Fpga,
        capacity_units: 17,
        fee_bps: 5,
        latency_ms: 197,
        recursive_slots: 3,
    },
    MarketMakerScenario {
        scenario_id: "scenario-0002",
        maker_id: "maker-03",
        workload: ProofWorkloadKind::ConfidentialSwap,
        sla_class: SlaClass::Standard,
        accelerator: AcceleratorKind::CpuVector,
        capacity_units: 18,
        fee_bps: 6,
        latency_ms: 214,
        recursive_slots: 4,
    },
    MarketMakerScenario {
        scenario_id: "scenario-0003",
        maker_id: "maker-04",
        workload: ProofWorkloadKind::TokenNetting,
        sla_class: SlaClass::LowFee,
        accelerator: AcceleratorKind::RecursiveAggregator,
        capacity_units: 19,
        fee_bps: 7,
        latency_ms: 231,
        recursive_slots: 5,
    },
    MarketMakerScenario {
        scenario_id: "scenario-0004",
        maker_id: "maker-05",
        workload: ProofWorkloadKind::MoneroExit,
        sla_class: SlaClass::Sponsored,
        accelerator: AcceleratorKind::VerifierCache,
        capacity_units: 20,
        fee_bps: 8,
        latency_ms: 248,
        recursive_slots: 6,
    },
    MarketMakerScenario {
        scenario_id: "scenario-0005",
        maker_id: "maker-06",
        workload: ProofWorkloadKind::OracleAttestation,
        sla_class: SlaClass::Emergency,
        accelerator: AcceleratorKind::Hybrid,
        capacity_units: 21,
        fee_bps: 9,
        latency_ms: 265,
        recursive_slots: 7,
    },
    MarketMakerScenario {
        scenario_id: "scenario-0006",
        maker_id: "maker-07",
        workload: ProofWorkloadKind::RecursiveWrap,
        sla_class: SlaClass::Instant,
        accelerator: AcceleratorKind::Gpu,
        capacity_units: 22,
        fee_bps: 10,
        latency_ms: 282,
        recursive_slots: 8,
    },
    MarketMakerScenario {
        scenario_id: "scenario-0007",
        maker_id: "maker-08",
        workload: ProofWorkloadKind::SettlementCompress,
        sla_class: SlaClass::Fast,
        accelerator: AcceleratorKind::Fpga,
        capacity_units: 23,
        fee_bps: 11,
        latency_ms: 299,
        recursive_slots: 9,
    },
    MarketMakerScenario {
        scenario_id: "scenario-0008",
        maker_id: "maker-09",
        workload: ProofWorkloadKind::EmergencyEscape,
        sla_class: SlaClass::Standard,
        accelerator: AcceleratorKind::CpuVector,
        capacity_units: 24,
        fee_bps: 12,
        latency_ms: 316,
        recursive_slots: 10,
    },
    MarketMakerScenario {
        scenario_id: "scenario-0009",
        maker_id: "maker-10",
        workload: ProofWorkloadKind::LowFeeBulk,
        sla_class: SlaClass::LowFee,
        accelerator: AcceleratorKind::RecursiveAggregator,
        capacity_units: 25,
        fee_bps: 13,
        latency_ms: 333,
        recursive_slots: 11,
    },
    MarketMakerScenario {
        scenario_id: "scenario-0010",
        maker_id: "maker-11",
        workload: ProofWorkloadKind::TransferBatch,
        sla_class: SlaClass::Sponsored,
        accelerator: AcceleratorKind::VerifierCache,
        capacity_units: 26,
        fee_bps: 14,
        latency_ms: 350,
        recursive_slots: 12,
    },
    MarketMakerScenario {
        scenario_id: "scenario-0011",
        maker_id: "maker-12",
        workload: ProofWorkloadKind::ContractExecution,
        sla_class: SlaClass::Emergency,
        accelerator: AcceleratorKind::Hybrid,
        capacity_units: 27,
        fee_bps: 15,
        latency_ms: 367,
        recursive_slots: 13,
    },
    MarketMakerScenario {
        scenario_id: "scenario-0012",
        maker_id: "maker-13",
        workload: ProofWorkloadKind::ConfidentialSwap,
        sla_class: SlaClass::Instant,
        accelerator: AcceleratorKind::Gpu,
        capacity_units: 28,
        fee_bps: 16,
        latency_ms: 384,
        recursive_slots: 14,
    },
    MarketMakerScenario {
        scenario_id: "scenario-0013",
        maker_id: "maker-14",
        workload: ProofWorkloadKind::TokenNetting,
        sla_class: SlaClass::Fast,
        accelerator: AcceleratorKind::Fpga,
        capacity_units: 29,
        fee_bps: 17,
        latency_ms: 401,
        recursive_slots: 15,
    },
    MarketMakerScenario {
        scenario_id: "scenario-0014",
        maker_id: "maker-15",
        workload: ProofWorkloadKind::MoneroExit,
        sla_class: SlaClass::Standard,
        accelerator: AcceleratorKind::CpuVector,
        capacity_units: 30,
        fee_bps: 4,
        latency_ms: 418,
        recursive_slots: 16,
    },
    MarketMakerScenario {
        scenario_id: "scenario-0015",
        maker_id: "maker-16",
        workload: ProofWorkloadKind::OracleAttestation,
        sla_class: SlaClass::LowFee,
        accelerator: AcceleratorKind::RecursiveAggregator,
        capacity_units: 31,
        fee_bps: 5,
        latency_ms: 435,
        recursive_slots: 17,
    },
    MarketMakerScenario {
        scenario_id: "scenario-0016",
        maker_id: "maker-17",
        workload: ProofWorkloadKind::RecursiveWrap,
        sla_class: SlaClass::Sponsored,
        accelerator: AcceleratorKind::VerifierCache,
        capacity_units: 32,
        fee_bps: 6,
        latency_ms: 452,
        recursive_slots: 18,
    },
    MarketMakerScenario {
        scenario_id: "scenario-0017",
        maker_id: "maker-18",
        workload: ProofWorkloadKind::SettlementCompress,
        sla_class: SlaClass::Emergency,
        accelerator: AcceleratorKind::Hybrid,
        capacity_units: 33,
        fee_bps: 7,
        latency_ms: 469,
        recursive_slots: 19,
    },
    MarketMakerScenario {
        scenario_id: "scenario-0018",
        maker_id: "maker-19",
        workload: ProofWorkloadKind::EmergencyEscape,
        sla_class: SlaClass::Instant,
        accelerator: AcceleratorKind::Gpu,
        capacity_units: 34,
        fee_bps: 8,
        latency_ms: 486,
        recursive_slots: 20,
    },
    MarketMakerScenario {
        scenario_id: "scenario-0019",
        maker_id: "maker-20",
        workload: ProofWorkloadKind::LowFeeBulk,
        sla_class: SlaClass::Fast,
        accelerator: AcceleratorKind::Fpga,
        capacity_units: 35,
        fee_bps: 9,
        latency_ms: 503,
        recursive_slots: 21,
    },
    MarketMakerScenario {
        scenario_id: "scenario-0020",
        maker_id: "maker-21",
        workload: ProofWorkloadKind::TransferBatch,
        sla_class: SlaClass::Standard,
        accelerator: AcceleratorKind::CpuVector,
        capacity_units: 36,
        fee_bps: 10,
        latency_ms: 520,
        recursive_slots: 22,
    },
    MarketMakerScenario {
        scenario_id: "scenario-0021",
        maker_id: "maker-22",
        workload: ProofWorkloadKind::ContractExecution,
        sla_class: SlaClass::LowFee,
        accelerator: AcceleratorKind::RecursiveAggregator,
        capacity_units: 37,
        fee_bps: 11,
        latency_ms: 537,
        recursive_slots: 23,
    },
    MarketMakerScenario {
        scenario_id: "scenario-0022",
        maker_id: "maker-23",
        workload: ProofWorkloadKind::ConfidentialSwap,
        sla_class: SlaClass::Sponsored,
        accelerator: AcceleratorKind::VerifierCache,
        capacity_units: 38,
        fee_bps: 12,
        latency_ms: 554,
        recursive_slots: 24,
    },
    MarketMakerScenario {
        scenario_id: "scenario-0023",
        maker_id: "maker-24",
        workload: ProofWorkloadKind::TokenNetting,
        sla_class: SlaClass::Emergency,
        accelerator: AcceleratorKind::Hybrid,
        capacity_units: 39,
        fee_bps: 13,
        latency_ms: 571,
        recursive_slots: 25,
    },
    MarketMakerScenario {
        scenario_id: "scenario-0024",
        maker_id: "maker-01",
        workload: ProofWorkloadKind::MoneroExit,
        sla_class: SlaClass::Instant,
        accelerator: AcceleratorKind::Gpu,
        capacity_units: 40,
        fee_bps: 14,
        latency_ms: 588,
        recursive_slots: 26,
    },
    MarketMakerScenario {
        scenario_id: "scenario-0025",
        maker_id: "maker-02",
        workload: ProofWorkloadKind::OracleAttestation,
        sla_class: SlaClass::Fast,
        accelerator: AcceleratorKind::Fpga,
        capacity_units: 41,
        fee_bps: 15,
        latency_ms: 605,
        recursive_slots: 27,
    },
    MarketMakerScenario {
        scenario_id: "scenario-0026",
        maker_id: "maker-03",
        workload: ProofWorkloadKind::RecursiveWrap,
        sla_class: SlaClass::Standard,
        accelerator: AcceleratorKind::CpuVector,
        capacity_units: 42,
        fee_bps: 16,
        latency_ms: 622,
        recursive_slots: 28,
    },
    MarketMakerScenario {
        scenario_id: "scenario-0027",
        maker_id: "maker-04",
        workload: ProofWorkloadKind::SettlementCompress,
        sla_class: SlaClass::LowFee,
        accelerator: AcceleratorKind::RecursiveAggregator,
        capacity_units: 43,
        fee_bps: 17,
        latency_ms: 639,
        recursive_slots: 29,
    },
    MarketMakerScenario {
        scenario_id: "scenario-0028",
        maker_id: "maker-05",
        workload: ProofWorkloadKind::EmergencyEscape,
        sla_class: SlaClass::Sponsored,
        accelerator: AcceleratorKind::VerifierCache,
        capacity_units: 44,
        fee_bps: 4,
        latency_ms: 656,
        recursive_slots: 30,
    },
    MarketMakerScenario {
        scenario_id: "scenario-0029",
        maker_id: "maker-06",
        workload: ProofWorkloadKind::LowFeeBulk,
        sla_class: SlaClass::Emergency,
        accelerator: AcceleratorKind::Hybrid,
        capacity_units: 45,
        fee_bps: 5,
        latency_ms: 673,
        recursive_slots: 31,
    },
    MarketMakerScenario {
        scenario_id: "scenario-0030",
        maker_id: "maker-07",
        workload: ProofWorkloadKind::TransferBatch,
        sla_class: SlaClass::Instant,
        accelerator: AcceleratorKind::Gpu,
        capacity_units: 46,
        fee_bps: 6,
        latency_ms: 690,
        recursive_slots: 32,
    },
    MarketMakerScenario {
        scenario_id: "scenario-0031",
        maker_id: "maker-08",
        workload: ProofWorkloadKind::ContractExecution,
        sla_class: SlaClass::Fast,
        accelerator: AcceleratorKind::Fpga,
        capacity_units: 47,
        fee_bps: 7,
        latency_ms: 707,
        recursive_slots: 33,
    },
    MarketMakerScenario {
        scenario_id: "scenario-0032",
        maker_id: "maker-09",
        workload: ProofWorkloadKind::ConfidentialSwap,
        sla_class: SlaClass::Standard,
        accelerator: AcceleratorKind::CpuVector,
        capacity_units: 48,
        fee_bps: 8,
        latency_ms: 724,
        recursive_slots: 2,
    },
    MarketMakerScenario {
        scenario_id: "scenario-0033",
        maker_id: "maker-10",
        workload: ProofWorkloadKind::TokenNetting,
        sla_class: SlaClass::LowFee,
        accelerator: AcceleratorKind::RecursiveAggregator,
        capacity_units: 49,
        fee_bps: 9,
        latency_ms: 741,
        recursive_slots: 3,
    },
    MarketMakerScenario {
        scenario_id: "scenario-0034",
        maker_id: "maker-11",
        workload: ProofWorkloadKind::MoneroExit,
        sla_class: SlaClass::Sponsored,
        accelerator: AcceleratorKind::VerifierCache,
        capacity_units: 50,
        fee_bps: 10,
        latency_ms: 758,
        recursive_slots: 4,
    },
    MarketMakerScenario {
        scenario_id: "scenario-0035",
        maker_id: "maker-12",
        workload: ProofWorkloadKind::OracleAttestation,
        sla_class: SlaClass::Emergency,
        accelerator: AcceleratorKind::Hybrid,
        capacity_units: 51,
        fee_bps: 11,
        latency_ms: 775,
        recursive_slots: 5,
    },
    MarketMakerScenario {
        scenario_id: "scenario-0036",
        maker_id: "maker-13",
        workload: ProofWorkloadKind::RecursiveWrap,
        sla_class: SlaClass::Instant,
        accelerator: AcceleratorKind::Gpu,
        capacity_units: 52,
        fee_bps: 12,
        latency_ms: 792,
        recursive_slots: 6,
    },
    MarketMakerScenario {
        scenario_id: "scenario-0037",
        maker_id: "maker-14",
        workload: ProofWorkloadKind::SettlementCompress,
        sla_class: SlaClass::Fast,
        accelerator: AcceleratorKind::Fpga,
        capacity_units: 53,
        fee_bps: 13,
        latency_ms: 809,
        recursive_slots: 7,
    },
    MarketMakerScenario {
        scenario_id: "scenario-0038",
        maker_id: "maker-15",
        workload: ProofWorkloadKind::EmergencyEscape,
        sla_class: SlaClass::Standard,
        accelerator: AcceleratorKind::CpuVector,
        capacity_units: 54,
        fee_bps: 14,
        latency_ms: 826,
        recursive_slots: 8,
    },
    MarketMakerScenario {
        scenario_id: "scenario-0039",
        maker_id: "maker-16",
        workload: ProofWorkloadKind::LowFeeBulk,
        sla_class: SlaClass::LowFee,
        accelerator: AcceleratorKind::RecursiveAggregator,
        capacity_units: 55,
        fee_bps: 15,
        latency_ms: 843,
        recursive_slots: 9,
    },
    MarketMakerScenario {
        scenario_id: "scenario-0040",
        maker_id: "maker-17",
        workload: ProofWorkloadKind::TransferBatch,
        sla_class: SlaClass::Sponsored,
        accelerator: AcceleratorKind::VerifierCache,
        capacity_units: 56,
        fee_bps: 16,
        latency_ms: 860,
        recursive_slots: 10,
    },
    MarketMakerScenario {
        scenario_id: "scenario-0041",
        maker_id: "maker-18",
        workload: ProofWorkloadKind::ContractExecution,
        sla_class: SlaClass::Emergency,
        accelerator: AcceleratorKind::Hybrid,
        capacity_units: 57,
        fee_bps: 17,
        latency_ms: 877,
        recursive_slots: 11,
    },
    MarketMakerScenario {
        scenario_id: "scenario-0042",
        maker_id: "maker-19",
        workload: ProofWorkloadKind::ConfidentialSwap,
        sla_class: SlaClass::Instant,
        accelerator: AcceleratorKind::Gpu,
        capacity_units: 58,
        fee_bps: 4,
        latency_ms: 894,
        recursive_slots: 12,
    },
    MarketMakerScenario {
        scenario_id: "scenario-0043",
        maker_id: "maker-20",
        workload: ProofWorkloadKind::TokenNetting,
        sla_class: SlaClass::Fast,
        accelerator: AcceleratorKind::Fpga,
        capacity_units: 59,
        fee_bps: 5,
        latency_ms: 911,
        recursive_slots: 13,
    },
    MarketMakerScenario {
        scenario_id: "scenario-0044",
        maker_id: "maker-21",
        workload: ProofWorkloadKind::MoneroExit,
        sla_class: SlaClass::Standard,
        accelerator: AcceleratorKind::CpuVector,
        capacity_units: 60,
        fee_bps: 6,
        latency_ms: 928,
        recursive_slots: 14,
    },
    MarketMakerScenario {
        scenario_id: "scenario-0045",
        maker_id: "maker-22",
        workload: ProofWorkloadKind::OracleAttestation,
        sla_class: SlaClass::LowFee,
        accelerator: AcceleratorKind::RecursiveAggregator,
        capacity_units: 61,
        fee_bps: 7,
        latency_ms: 945,
        recursive_slots: 15,
    },
    MarketMakerScenario {
        scenario_id: "scenario-0046",
        maker_id: "maker-23",
        workload: ProofWorkloadKind::RecursiveWrap,
        sla_class: SlaClass::Sponsored,
        accelerator: AcceleratorKind::VerifierCache,
        capacity_units: 62,
        fee_bps: 8,
        latency_ms: 962,
        recursive_slots: 16,
    },
    MarketMakerScenario {
        scenario_id: "scenario-0047",
        maker_id: "maker-24",
        workload: ProofWorkloadKind::SettlementCompress,
        sla_class: SlaClass::Emergency,
        accelerator: AcceleratorKind::Hybrid,
        capacity_units: 63,
        fee_bps: 9,
        latency_ms: 979,
        recursive_slots: 17,
    },
    MarketMakerScenario {
        scenario_id: "scenario-0048",
        maker_id: "maker-01",
        workload: ProofWorkloadKind::EmergencyEscape,
        sla_class: SlaClass::Instant,
        accelerator: AcceleratorKind::Gpu,
        capacity_units: 64,
        fee_bps: 10,
        latency_ms: 996,
        recursive_slots: 18,
    },
    MarketMakerScenario {
        scenario_id: "scenario-0049",
        maker_id: "maker-02",
        workload: ProofWorkloadKind::LowFeeBulk,
        sla_class: SlaClass::Fast,
        accelerator: AcceleratorKind::Fpga,
        capacity_units: 65,
        fee_bps: 11,
        latency_ms: 1013,
        recursive_slots: 19,
    },
    MarketMakerScenario {
        scenario_id: "scenario-0050",
        maker_id: "maker-03",
        workload: ProofWorkloadKind::TransferBatch,
        sla_class: SlaClass::Standard,
        accelerator: AcceleratorKind::CpuVector,
        capacity_units: 66,
        fee_bps: 12,
        latency_ms: 1030,
        recursive_slots: 20,
    },
    MarketMakerScenario {
        scenario_id: "scenario-0051",
        maker_id: "maker-04",
        workload: ProofWorkloadKind::ContractExecution,
        sla_class: SlaClass::LowFee,
        accelerator: AcceleratorKind::RecursiveAggregator,
        capacity_units: 67,
        fee_bps: 13,
        latency_ms: 1047,
        recursive_slots: 21,
    },
    MarketMakerScenario {
        scenario_id: "scenario-0052",
        maker_id: "maker-05",
        workload: ProofWorkloadKind::ConfidentialSwap,
        sla_class: SlaClass::Sponsored,
        accelerator: AcceleratorKind::VerifierCache,
        capacity_units: 68,
        fee_bps: 14,
        latency_ms: 1064,
        recursive_slots: 22,
    },
    MarketMakerScenario {
        scenario_id: "scenario-0053",
        maker_id: "maker-06",
        workload: ProofWorkloadKind::TokenNetting,
        sla_class: SlaClass::Emergency,
        accelerator: AcceleratorKind::Hybrid,
        capacity_units: 69,
        fee_bps: 15,
        latency_ms: 1081,
        recursive_slots: 23,
    },
    MarketMakerScenario {
        scenario_id: "scenario-0054",
        maker_id: "maker-07",
        workload: ProofWorkloadKind::MoneroExit,
        sla_class: SlaClass::Instant,
        accelerator: AcceleratorKind::Gpu,
        capacity_units: 70,
        fee_bps: 16,
        latency_ms: 1098,
        recursive_slots: 24,
    },
    MarketMakerScenario {
        scenario_id: "scenario-0055",
        maker_id: "maker-08",
        workload: ProofWorkloadKind::OracleAttestation,
        sla_class: SlaClass::Fast,
        accelerator: AcceleratorKind::Fpga,
        capacity_units: 71,
        fee_bps: 17,
        latency_ms: 1115,
        recursive_slots: 25,
    },
    MarketMakerScenario {
        scenario_id: "scenario-0056",
        maker_id: "maker-09",
        workload: ProofWorkloadKind::RecursiveWrap,
        sla_class: SlaClass::Standard,
        accelerator: AcceleratorKind::CpuVector,
        capacity_units: 72,
        fee_bps: 4,
        latency_ms: 1132,
        recursive_slots: 26,
    },
    MarketMakerScenario {
        scenario_id: "scenario-0057",
        maker_id: "maker-10",
        workload: ProofWorkloadKind::SettlementCompress,
        sla_class: SlaClass::LowFee,
        accelerator: AcceleratorKind::RecursiveAggregator,
        capacity_units: 73,
        fee_bps: 5,
        latency_ms: 1149,
        recursive_slots: 27,
    },
    MarketMakerScenario {
        scenario_id: "scenario-0058",
        maker_id: "maker-11",
        workload: ProofWorkloadKind::EmergencyEscape,
        sla_class: SlaClass::Sponsored,
        accelerator: AcceleratorKind::VerifierCache,
        capacity_units: 74,
        fee_bps: 6,
        latency_ms: 1166,
        recursive_slots: 28,
    },
    MarketMakerScenario {
        scenario_id: "scenario-0059",
        maker_id: "maker-12",
        workload: ProofWorkloadKind::LowFeeBulk,
        sla_class: SlaClass::Emergency,
        accelerator: AcceleratorKind::Hybrid,
        capacity_units: 75,
        fee_bps: 7,
        latency_ms: 1183,
        recursive_slots: 29,
    },
    MarketMakerScenario {
        scenario_id: "scenario-0060",
        maker_id: "maker-13",
        workload: ProofWorkloadKind::TransferBatch,
        sla_class: SlaClass::Instant,
        accelerator: AcceleratorKind::Gpu,
        capacity_units: 76,
        fee_bps: 8,
        latency_ms: 1200,
        recursive_slots: 30,
    },
    MarketMakerScenario {
        scenario_id: "scenario-0061",
        maker_id: "maker-14",
        workload: ProofWorkloadKind::ContractExecution,
        sla_class: SlaClass::Fast,
        accelerator: AcceleratorKind::Fpga,
        capacity_units: 77,
        fee_bps: 9,
        latency_ms: 1217,
        recursive_slots: 31,
    },
    MarketMakerScenario {
        scenario_id: "scenario-0062",
        maker_id: "maker-15",
        workload: ProofWorkloadKind::ConfidentialSwap,
        sla_class: SlaClass::Standard,
        accelerator: AcceleratorKind::CpuVector,
        capacity_units: 78,
        fee_bps: 10,
        latency_ms: 1234,
        recursive_slots: 32,
    },
    MarketMakerScenario {
        scenario_id: "scenario-0063",
        maker_id: "maker-16",
        workload: ProofWorkloadKind::TokenNetting,
        sla_class: SlaClass::LowFee,
        accelerator: AcceleratorKind::RecursiveAggregator,
        capacity_units: 79,
        fee_bps: 11,
        latency_ms: 1251,
        recursive_slots: 33,
    },
    MarketMakerScenario {
        scenario_id: "scenario-0064",
        maker_id: "maker-17",
        workload: ProofWorkloadKind::MoneroExit,
        sla_class: SlaClass::Sponsored,
        accelerator: AcceleratorKind::VerifierCache,
        capacity_units: 80,
        fee_bps: 12,
        latency_ms: 1268,
        recursive_slots: 2,
    },
    MarketMakerScenario {
        scenario_id: "scenario-0065",
        maker_id: "maker-18",
        workload: ProofWorkloadKind::OracleAttestation,
        sla_class: SlaClass::Emergency,
        accelerator: AcceleratorKind::Hybrid,
        capacity_units: 81,
        fee_bps: 13,
        latency_ms: 1285,
        recursive_slots: 3,
    },
    MarketMakerScenario {
        scenario_id: "scenario-0066",
        maker_id: "maker-19",
        workload: ProofWorkloadKind::RecursiveWrap,
        sla_class: SlaClass::Instant,
        accelerator: AcceleratorKind::Gpu,
        capacity_units: 82,
        fee_bps: 14,
        latency_ms: 1302,
        recursive_slots: 4,
    },
    MarketMakerScenario {
        scenario_id: "scenario-0067",
        maker_id: "maker-20",
        workload: ProofWorkloadKind::SettlementCompress,
        sla_class: SlaClass::Fast,
        accelerator: AcceleratorKind::Fpga,
        capacity_units: 83,
        fee_bps: 15,
        latency_ms: 1319,
        recursive_slots: 5,
    },
    MarketMakerScenario {
        scenario_id: "scenario-0068",
        maker_id: "maker-21",
        workload: ProofWorkloadKind::EmergencyEscape,
        sla_class: SlaClass::Standard,
        accelerator: AcceleratorKind::CpuVector,
        capacity_units: 84,
        fee_bps: 16,
        latency_ms: 1336,
        recursive_slots: 6,
    },
    MarketMakerScenario {
        scenario_id: "scenario-0069",
        maker_id: "maker-22",
        workload: ProofWorkloadKind::LowFeeBulk,
        sla_class: SlaClass::LowFee,
        accelerator: AcceleratorKind::RecursiveAggregator,
        capacity_units: 85,
        fee_bps: 17,
        latency_ms: 1353,
        recursive_slots: 7,
    },
    MarketMakerScenario {
        scenario_id: "scenario-0070",
        maker_id: "maker-23",
        workload: ProofWorkloadKind::TransferBatch,
        sla_class: SlaClass::Sponsored,
        accelerator: AcceleratorKind::VerifierCache,
        capacity_units: 86,
        fee_bps: 4,
        latency_ms: 1370,
        recursive_slots: 8,
    },
    MarketMakerScenario {
        scenario_id: "scenario-0071",
        maker_id: "maker-24",
        workload: ProofWorkloadKind::ContractExecution,
        sla_class: SlaClass::Emergency,
        accelerator: AcceleratorKind::Hybrid,
        capacity_units: 87,
        fee_bps: 5,
        latency_ms: 1387,
        recursive_slots: 9,
    },
    MarketMakerScenario {
        scenario_id: "scenario-0072",
        maker_id: "maker-01",
        workload: ProofWorkloadKind::ConfidentialSwap,
        sla_class: SlaClass::Instant,
        accelerator: AcceleratorKind::Gpu,
        capacity_units: 88,
        fee_bps: 6,
        latency_ms: 1404,
        recursive_slots: 10,
    },
    MarketMakerScenario {
        scenario_id: "scenario-0073",
        maker_id: "maker-02",
        workload: ProofWorkloadKind::TokenNetting,
        sla_class: SlaClass::Fast,
        accelerator: AcceleratorKind::Fpga,
        capacity_units: 89,
        fee_bps: 7,
        latency_ms: 1421,
        recursive_slots: 11,
    },
    MarketMakerScenario {
        scenario_id: "scenario-0074",
        maker_id: "maker-03",
        workload: ProofWorkloadKind::MoneroExit,
        sla_class: SlaClass::Standard,
        accelerator: AcceleratorKind::CpuVector,
        capacity_units: 90,
        fee_bps: 8,
        latency_ms: 1438,
        recursive_slots: 12,
    },
    MarketMakerScenario {
        scenario_id: "scenario-0075",
        maker_id: "maker-04",
        workload: ProofWorkloadKind::OracleAttestation,
        sla_class: SlaClass::LowFee,
        accelerator: AcceleratorKind::RecursiveAggregator,
        capacity_units: 91,
        fee_bps: 9,
        latency_ms: 1455,
        recursive_slots: 13,
    },
    MarketMakerScenario {
        scenario_id: "scenario-0076",
        maker_id: "maker-05",
        workload: ProofWorkloadKind::RecursiveWrap,
        sla_class: SlaClass::Sponsored,
        accelerator: AcceleratorKind::VerifierCache,
        capacity_units: 92,
        fee_bps: 10,
        latency_ms: 1472,
        recursive_slots: 14,
    },
    MarketMakerScenario {
        scenario_id: "scenario-0077",
        maker_id: "maker-06",
        workload: ProofWorkloadKind::SettlementCompress,
        sla_class: SlaClass::Emergency,
        accelerator: AcceleratorKind::Hybrid,
        capacity_units: 93,
        fee_bps: 11,
        latency_ms: 1489,
        recursive_slots: 15,
    },
    MarketMakerScenario {
        scenario_id: "scenario-0078",
        maker_id: "maker-07",
        workload: ProofWorkloadKind::EmergencyEscape,
        sla_class: SlaClass::Instant,
        accelerator: AcceleratorKind::Gpu,
        capacity_units: 94,
        fee_bps: 12,
        latency_ms: 1506,
        recursive_slots: 16,
    },
    MarketMakerScenario {
        scenario_id: "scenario-0079",
        maker_id: "maker-08",
        workload: ProofWorkloadKind::LowFeeBulk,
        sla_class: SlaClass::Fast,
        accelerator: AcceleratorKind::Fpga,
        capacity_units: 95,
        fee_bps: 13,
        latency_ms: 1523,
        recursive_slots: 17,
    },
    MarketMakerScenario {
        scenario_id: "scenario-0080",
        maker_id: "maker-09",
        workload: ProofWorkloadKind::TransferBatch,
        sla_class: SlaClass::Standard,
        accelerator: AcceleratorKind::CpuVector,
        capacity_units: 96,
        fee_bps: 14,
        latency_ms: 1540,
        recursive_slots: 18,
    },
];
pub fn scenario_quote_request(
    scenario: &MarketMakerScenario,
    height: u64,
) -> LiquidityQuoteRequest {
    LiquidityQuoteRequest {
        request_id: deterministic_id(
            "request",
            &[scenario.scenario_id, scenario.workload.as_str()],
        ),
        intent_commitment: domain_hash(
            "scenario-intent",
            &[scenario.scenario_id, scenario.workload.as_str()],
        ),
        workload: scenario.workload,
        sla_class: scenario.sla_class,
        max_fee_bps: scenario.fee_bps.saturating_add(3).min(DEFAULT_MAX_FEE_BPS),
        notional_piconero: scenario.capacity_units.saturating_mul(1_000_000),
        encrypted_witness_root: domain_hash(
            "scenario-witness",
            &[scenario.scenario_id, scenario.maker_id],
        ),
        privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE.saturating_add(scenario.capacity_units),
        pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        preferred_region_code: "deterministic-devnet".to_string(),
        height,
    }
}
pub fn scenario_quote(
    scenario: &MarketMakerScenario,
    request_id: &str,
    height: u64,
) -> GpuProverLiquidityQuote {
    GpuProverLiquidityQuote {
        quote_id: deterministic_id(
            "quote",
            &[scenario.scenario_id, scenario.maker_id, request_id],
        ),
        request_id: request_id.to_string(),
        maker_id: scenario.maker_id.to_string(),
        accelerator: scenario.accelerator,
        workload: scenario.workload,
        sla_class: scenario.sla_class,
        capacity_units: scenario.capacity_units,
        fee_bps: scenario.fee_bps.min(DEFAULT_MAX_FEE_BPS),
        estimated_latency_ms: scenario.latency_ms,
        recursive_slots: scenario.recursive_slots,
        confidential_quote_root: domain_hash(
            "scenario-quote",
            &[scenario.scenario_id, scenario.maker_id],
        ),
        expires_at_height: height.saturating_add(DEFAULT_QUOTE_TTL_BLOCKS),
        status: QuoteStatus::Open,
    }
}
pub fn scenario_inventory(
    scenario: &MarketMakerScenario,
    height: u64,
) -> RecursiveProofInventoryRecord {
    RecursiveProofInventoryRecord {
        inventory_id: deterministic_id("inventory", &[scenario.scenario_id, scenario.maker_id]),
        maker_id: scenario.maker_id.to_string(),
        workload: scenario.workload,
        available_leaf_proofs: scenario.capacity_units.saturating_mul(8),
        available_recursive_wraps: scenario.recursive_slots.saturating_mul(2),
        reserved_recursive_wraps: scenario.recursive_slots.saturating_div(4),
        verifier_cache_hits: scenario.capacity_units.saturating_mul(3),
        inventory_commitment: domain_hash(
            "scenario-inventory",
            &[scenario.scenario_id, scenario.maker_id],
        ),
        height,
    }
}
pub fn seeded_demo_from_catalog(limit: usize) -> State {
    let mut state = devnet();
    for scenario in DETERMINISTIC_SCENARIO_CATALOG.iter().take(limit) {
        let request = scenario_quote_request(scenario, DEVNET_HEIGHT);
        let request_id = request.request_id.clone();
        let _ = state.record_quote_request(request);
        let _ = state.record_quote(scenario_quote(scenario, &request_id, DEVNET_HEIGHT));
        let _ = state.record_inventory(scenario_inventory(scenario, DEVNET_HEIGHT));
        let _ = state.apply_deterministic_route(&request_id);
    }
    state.push_public_event(PublicEventRecord {
        event_id: deterministic_id("public", &["seeded-demo", &limit.to_string()]),
        kind: "seeded_catalog".to_string(),
        subject_id: limit.to_string(),
        public_root: state.state_root(),
        height: DEVNET_HEIGHT,
        note: "deterministic catalog seeded with local data only".to_string(),
    });
    state
}

pub fn catalog_window_001_root() -> String {
    let start = 0usize;
    let leaves: Vec<String> = DETERMINISTIC_SCENARIO_CATALOG
        .iter()
        .skip(start)
        .take(6)
        .map(|scenario| {
            domain_hash(
                "catalog-window-001",
                &[
                    scenario.scenario_id,
                    scenario.maker_id,
                    scenario.workload.as_str(),
                    scenario.sla_class.as_str(),
                    scenario.accelerator.as_str(),
                ],
            )
        })
        .collect();
    merkle_root("catalog-window-001", leaves)
}

pub fn catalog_window_002_root() -> String {
    let start = 1usize;
    let leaves: Vec<String> = DETERMINISTIC_SCENARIO_CATALOG
        .iter()
        .skip(start)
        .take(6)
        .map(|scenario| {
            domain_hash(
                "catalog-window-002",
                &[
                    scenario.scenario_id,
                    scenario.maker_id,
                    scenario.workload.as_str(),
                    scenario.sla_class.as_str(),
                    scenario.accelerator.as_str(),
                ],
            )
        })
        .collect();
    merkle_root("catalog-window-002", leaves)
}

pub fn catalog_window_003_root() -> String {
    let start = 2usize;
    let leaves: Vec<String> = DETERMINISTIC_SCENARIO_CATALOG
        .iter()
        .skip(start)
        .take(6)
        .map(|scenario| {
            domain_hash(
                "catalog-window-003",
                &[
                    scenario.scenario_id,
                    scenario.maker_id,
                    scenario.workload.as_str(),
                    scenario.sla_class.as_str(),
                    scenario.accelerator.as_str(),
                ],
            )
        })
        .collect();
    merkle_root("catalog-window-003", leaves)
}

pub fn catalog_window_004_root() -> String {
    let start = 3usize;
    let leaves: Vec<String> = DETERMINISTIC_SCENARIO_CATALOG
        .iter()
        .skip(start)
        .take(6)
        .map(|scenario| {
            domain_hash(
                "catalog-window-004",
                &[
                    scenario.scenario_id,
                    scenario.maker_id,
                    scenario.workload.as_str(),
                    scenario.sla_class.as_str(),
                    scenario.accelerator.as_str(),
                ],
            )
        })
        .collect();
    merkle_root("catalog-window-004", leaves)
}

pub fn catalog_window_005_root() -> String {
    let start = 4usize;
    let leaves: Vec<String> = DETERMINISTIC_SCENARIO_CATALOG
        .iter()
        .skip(start)
        .take(6)
        .map(|scenario| {
            domain_hash(
                "catalog-window-005",
                &[
                    scenario.scenario_id,
                    scenario.maker_id,
                    scenario.workload.as_str(),
                    scenario.sla_class.as_str(),
                    scenario.accelerator.as_str(),
                ],
            )
        })
        .collect();
    merkle_root("catalog-window-005", leaves)
}

pub fn catalog_window_006_root() -> String {
    let start = 5usize;
    let leaves: Vec<String> = DETERMINISTIC_SCENARIO_CATALOG
        .iter()
        .skip(start)
        .take(6)
        .map(|scenario| {
            domain_hash(
                "catalog-window-006",
                &[
                    scenario.scenario_id,
                    scenario.maker_id,
                    scenario.workload.as_str(),
                    scenario.sla_class.as_str(),
                    scenario.accelerator.as_str(),
                ],
            )
        })
        .collect();
    merkle_root("catalog-window-006", leaves)
}

pub fn catalog_window_007_root() -> String {
    let start = 6usize;
    let leaves: Vec<String> = DETERMINISTIC_SCENARIO_CATALOG
        .iter()
        .skip(start)
        .take(6)
        .map(|scenario| {
            domain_hash(
                "catalog-window-007",
                &[
                    scenario.scenario_id,
                    scenario.maker_id,
                    scenario.workload.as_str(),
                    scenario.sla_class.as_str(),
                    scenario.accelerator.as_str(),
                ],
            )
        })
        .collect();
    merkle_root("catalog-window-007", leaves)
}

pub fn catalog_window_008_root() -> String {
    let start = 7usize;
    let leaves: Vec<String> = DETERMINISTIC_SCENARIO_CATALOG
        .iter()
        .skip(start)
        .take(6)
        .map(|scenario| {
            domain_hash(
                "catalog-window-008",
                &[
                    scenario.scenario_id,
                    scenario.maker_id,
                    scenario.workload.as_str(),
                    scenario.sla_class.as_str(),
                    scenario.accelerator.as_str(),
                ],
            )
        })
        .collect();
    merkle_root("catalog-window-008", leaves)
}

pub fn catalog_window_009_root() -> String {
    let start = 8usize;
    let leaves: Vec<String> = DETERMINISTIC_SCENARIO_CATALOG
        .iter()
        .skip(start)
        .take(6)
        .map(|scenario| {
            domain_hash(
                "catalog-window-009",
                &[
                    scenario.scenario_id,
                    scenario.maker_id,
                    scenario.workload.as_str(),
                    scenario.sla_class.as_str(),
                    scenario.accelerator.as_str(),
                ],
            )
        })
        .collect();
    merkle_root("catalog-window-009", leaves)
}

pub fn catalog_window_010_root() -> String {
    let start = 9usize;
    let leaves: Vec<String> = DETERMINISTIC_SCENARIO_CATALOG
        .iter()
        .skip(start)
        .take(6)
        .map(|scenario| {
            domain_hash(
                "catalog-window-010",
                &[
                    scenario.scenario_id,
                    scenario.maker_id,
                    scenario.workload.as_str(),
                    scenario.sla_class.as_str(),
                    scenario.accelerator.as_str(),
                ],
            )
        })
        .collect();
    merkle_root("catalog-window-010", leaves)
}

pub fn catalog_window_011_root() -> String {
    let start = 10usize;
    let leaves: Vec<String> = DETERMINISTIC_SCENARIO_CATALOG
        .iter()
        .skip(start)
        .take(6)
        .map(|scenario| {
            domain_hash(
                "catalog-window-011",
                &[
                    scenario.scenario_id,
                    scenario.maker_id,
                    scenario.workload.as_str(),
                    scenario.sla_class.as_str(),
                    scenario.accelerator.as_str(),
                ],
            )
        })
        .collect();
    merkle_root("catalog-window-011", leaves)
}

pub fn catalog_window_012_root() -> String {
    let start = 11usize;
    let leaves: Vec<String> = DETERMINISTIC_SCENARIO_CATALOG
        .iter()
        .skip(start)
        .take(6)
        .map(|scenario| {
            domain_hash(
                "catalog-window-012",
                &[
                    scenario.scenario_id,
                    scenario.maker_id,
                    scenario.workload.as_str(),
                    scenario.sla_class.as_str(),
                    scenario.accelerator.as_str(),
                ],
            )
        })
        .collect();
    merkle_root("catalog-window-012", leaves)
}

pub fn catalog_window_013_root() -> String {
    let start = 12usize;
    let leaves: Vec<String> = DETERMINISTIC_SCENARIO_CATALOG
        .iter()
        .skip(start)
        .take(6)
        .map(|scenario| {
            domain_hash(
                "catalog-window-013",
                &[
                    scenario.scenario_id,
                    scenario.maker_id,
                    scenario.workload.as_str(),
                    scenario.sla_class.as_str(),
                    scenario.accelerator.as_str(),
                ],
            )
        })
        .collect();
    merkle_root("catalog-window-013", leaves)
}

pub fn catalog_window_014_root() -> String {
    let start = 13usize;
    let leaves: Vec<String> = DETERMINISTIC_SCENARIO_CATALOG
        .iter()
        .skip(start)
        .take(6)
        .map(|scenario| {
            domain_hash(
                "catalog-window-014",
                &[
                    scenario.scenario_id,
                    scenario.maker_id,
                    scenario.workload.as_str(),
                    scenario.sla_class.as_str(),
                    scenario.accelerator.as_str(),
                ],
            )
        })
        .collect();
    merkle_root("catalog-window-014", leaves)
}

pub fn catalog_window_015_root() -> String {
    let start = 14usize;
    let leaves: Vec<String> = DETERMINISTIC_SCENARIO_CATALOG
        .iter()
        .skip(start)
        .take(6)
        .map(|scenario| {
            domain_hash(
                "catalog-window-015",
                &[
                    scenario.scenario_id,
                    scenario.maker_id,
                    scenario.workload.as_str(),
                    scenario.sla_class.as_str(),
                    scenario.accelerator.as_str(),
                ],
            )
        })
        .collect();
    merkle_root("catalog-window-015", leaves)
}

pub fn catalog_window_016_root() -> String {
    let start = 15usize;
    let leaves: Vec<String> = DETERMINISTIC_SCENARIO_CATALOG
        .iter()
        .skip(start)
        .take(6)
        .map(|scenario| {
            domain_hash(
                "catalog-window-016",
                &[
                    scenario.scenario_id,
                    scenario.maker_id,
                    scenario.workload.as_str(),
                    scenario.sla_class.as_str(),
                    scenario.accelerator.as_str(),
                ],
            )
        })
        .collect();
    merkle_root("catalog-window-016", leaves)
}

pub fn catalog_window_017_root() -> String {
    let start = 16usize;
    let leaves: Vec<String> = DETERMINISTIC_SCENARIO_CATALOG
        .iter()
        .skip(start)
        .take(6)
        .map(|scenario| {
            domain_hash(
                "catalog-window-017",
                &[
                    scenario.scenario_id,
                    scenario.maker_id,
                    scenario.workload.as_str(),
                    scenario.sla_class.as_str(),
                    scenario.accelerator.as_str(),
                ],
            )
        })
        .collect();
    merkle_root("catalog-window-017", leaves)
}

pub fn catalog_window_018_root() -> String {
    let start = 17usize;
    let leaves: Vec<String> = DETERMINISTIC_SCENARIO_CATALOG
        .iter()
        .skip(start)
        .take(6)
        .map(|scenario| {
            domain_hash(
                "catalog-window-018",
                &[
                    scenario.scenario_id,
                    scenario.maker_id,
                    scenario.workload.as_str(),
                    scenario.sla_class.as_str(),
                    scenario.accelerator.as_str(),
                ],
            )
        })
        .collect();
    merkle_root("catalog-window-018", leaves)
}

pub fn catalog_window_019_root() -> String {
    let start = 18usize;
    let leaves: Vec<String> = DETERMINISTIC_SCENARIO_CATALOG
        .iter()
        .skip(start)
        .take(6)
        .map(|scenario| {
            domain_hash(
                "catalog-window-019",
                &[
                    scenario.scenario_id,
                    scenario.maker_id,
                    scenario.workload.as_str(),
                    scenario.sla_class.as_str(),
                    scenario.accelerator.as_str(),
                ],
            )
        })
        .collect();
    merkle_root("catalog-window-019", leaves)
}

pub fn catalog_window_020_root() -> String {
    let start = 19usize;
    let leaves: Vec<String> = DETERMINISTIC_SCENARIO_CATALOG
        .iter()
        .skip(start)
        .take(6)
        .map(|scenario| {
            domain_hash(
                "catalog-window-020",
                &[
                    scenario.scenario_id,
                    scenario.maker_id,
                    scenario.workload.as_str(),
                    scenario.sla_class.as_str(),
                    scenario.accelerator.as_str(),
                ],
            )
        })
        .collect();
    merkle_root("catalog-window-020", leaves)
}

pub fn catalog_window_021_root() -> String {
    let start = 20usize;
    let leaves: Vec<String> = DETERMINISTIC_SCENARIO_CATALOG
        .iter()
        .skip(start)
        .take(6)
        .map(|scenario| {
            domain_hash(
                "catalog-window-021",
                &[
                    scenario.scenario_id,
                    scenario.maker_id,
                    scenario.workload.as_str(),
                    scenario.sla_class.as_str(),
                    scenario.accelerator.as_str(),
                ],
            )
        })
        .collect();
    merkle_root("catalog-window-021", leaves)
}

pub fn catalog_window_022_root() -> String {
    let start = 21usize;
    let leaves: Vec<String> = DETERMINISTIC_SCENARIO_CATALOG
        .iter()
        .skip(start)
        .take(6)
        .map(|scenario| {
            domain_hash(
                "catalog-window-022",
                &[
                    scenario.scenario_id,
                    scenario.maker_id,
                    scenario.workload.as_str(),
                    scenario.sla_class.as_str(),
                    scenario.accelerator.as_str(),
                ],
            )
        })
        .collect();
    merkle_root("catalog-window-022", leaves)
}

pub fn catalog_window_023_root() -> String {
    let start = 22usize;
    let leaves: Vec<String> = DETERMINISTIC_SCENARIO_CATALOG
        .iter()
        .skip(start)
        .take(6)
        .map(|scenario| {
            domain_hash(
                "catalog-window-023",
                &[
                    scenario.scenario_id,
                    scenario.maker_id,
                    scenario.workload.as_str(),
                    scenario.sla_class.as_str(),
                    scenario.accelerator.as_str(),
                ],
            )
        })
        .collect();
    merkle_root("catalog-window-023", leaves)
}

pub fn catalog_window_024_root() -> String {
    let start = 23usize;
    let leaves: Vec<String> = DETERMINISTIC_SCENARIO_CATALOG
        .iter()
        .skip(start)
        .take(6)
        .map(|scenario| {
            domain_hash(
                "catalog-window-024",
                &[
                    scenario.scenario_id,
                    scenario.maker_id,
                    scenario.workload.as_str(),
                    scenario.sla_class.as_str(),
                    scenario.accelerator.as_str(),
                ],
            )
        })
        .collect();
    merkle_root("catalog-window-024", leaves)
}

pub fn catalog_window_025_root() -> String {
    let start = 24usize;
    let leaves: Vec<String> = DETERMINISTIC_SCENARIO_CATALOG
        .iter()
        .skip(start)
        .take(6)
        .map(|scenario| {
            domain_hash(
                "catalog-window-025",
                &[
                    scenario.scenario_id,
                    scenario.maker_id,
                    scenario.workload.as_str(),
                    scenario.sla_class.as_str(),
                    scenario.accelerator.as_str(),
                ],
            )
        })
        .collect();
    merkle_root("catalog-window-025", leaves)
}

pub fn catalog_window_026_root() -> String {
    let start = 25usize;
    let leaves: Vec<String> = DETERMINISTIC_SCENARIO_CATALOG
        .iter()
        .skip(start)
        .take(6)
        .map(|scenario| {
            domain_hash(
                "catalog-window-026",
                &[
                    scenario.scenario_id,
                    scenario.maker_id,
                    scenario.workload.as_str(),
                    scenario.sla_class.as_str(),
                    scenario.accelerator.as_str(),
                ],
            )
        })
        .collect();
    merkle_root("catalog-window-026", leaves)
}

pub fn catalog_window_027_root() -> String {
    let start = 26usize;
    let leaves: Vec<String> = DETERMINISTIC_SCENARIO_CATALOG
        .iter()
        .skip(start)
        .take(6)
        .map(|scenario| {
            domain_hash(
                "catalog-window-027",
                &[
                    scenario.scenario_id,
                    scenario.maker_id,
                    scenario.workload.as_str(),
                    scenario.sla_class.as_str(),
                    scenario.accelerator.as_str(),
                ],
            )
        })
        .collect();
    merkle_root("catalog-window-027", leaves)
}

pub fn catalog_window_028_root() -> String {
    let start = 27usize;
    let leaves: Vec<String> = DETERMINISTIC_SCENARIO_CATALOG
        .iter()
        .skip(start)
        .take(6)
        .map(|scenario| {
            domain_hash(
                "catalog-window-028",
                &[
                    scenario.scenario_id,
                    scenario.maker_id,
                    scenario.workload.as_str(),
                    scenario.sla_class.as_str(),
                    scenario.accelerator.as_str(),
                ],
            )
        })
        .collect();
    merkle_root("catalog-window-028", leaves)
}

pub fn catalog_window_029_root() -> String {
    let start = 28usize;
    let leaves: Vec<String> = DETERMINISTIC_SCENARIO_CATALOG
        .iter()
        .skip(start)
        .take(6)
        .map(|scenario| {
            domain_hash(
                "catalog-window-029",
                &[
                    scenario.scenario_id,
                    scenario.maker_id,
                    scenario.workload.as_str(),
                    scenario.sla_class.as_str(),
                    scenario.accelerator.as_str(),
                ],
            )
        })
        .collect();
    merkle_root("catalog-window-029", leaves)
}

pub fn catalog_window_030_root() -> String {
    let start = 29usize;
    let leaves: Vec<String> = DETERMINISTIC_SCENARIO_CATALOG
        .iter()
        .skip(start)
        .take(6)
        .map(|scenario| {
            domain_hash(
                "catalog-window-030",
                &[
                    scenario.scenario_id,
                    scenario.maker_id,
                    scenario.workload.as_str(),
                    scenario.sla_class.as_str(),
                    scenario.accelerator.as_str(),
                ],
            )
        })
        .collect();
    merkle_root("catalog-window-030", leaves)
}

pub fn catalog_window_031_root() -> String {
    let start = 30usize;
    let leaves: Vec<String> = DETERMINISTIC_SCENARIO_CATALOG
        .iter()
        .skip(start)
        .take(6)
        .map(|scenario| {
            domain_hash(
                "catalog-window-031",
                &[
                    scenario.scenario_id,
                    scenario.maker_id,
                    scenario.workload.as_str(),
                    scenario.sla_class.as_str(),
                    scenario.accelerator.as_str(),
                ],
            )
        })
        .collect();
    merkle_root("catalog-window-031", leaves)
}

pub fn catalog_window_032_root() -> String {
    let start = 31usize;
    let leaves: Vec<String> = DETERMINISTIC_SCENARIO_CATALOG
        .iter()
        .skip(start)
        .take(6)
        .map(|scenario| {
            domain_hash(
                "catalog-window-032",
                &[
                    scenario.scenario_id,
                    scenario.maker_id,
                    scenario.workload.as_str(),
                    scenario.sla_class.as_str(),
                    scenario.accelerator.as_str(),
                ],
            )
        })
        .collect();
    merkle_root("catalog-window-032", leaves)
}

pub fn catalog_window_033_root() -> String {
    let start = 32usize;
    let leaves: Vec<String> = DETERMINISTIC_SCENARIO_CATALOG
        .iter()
        .skip(start)
        .take(6)
        .map(|scenario| {
            domain_hash(
                "catalog-window-033",
                &[
                    scenario.scenario_id,
                    scenario.maker_id,
                    scenario.workload.as_str(),
                    scenario.sla_class.as_str(),
                    scenario.accelerator.as_str(),
                ],
            )
        })
        .collect();
    merkle_root("catalog-window-033", leaves)
}

pub fn catalog_window_034_root() -> String {
    let start = 33usize;
    let leaves: Vec<String> = DETERMINISTIC_SCENARIO_CATALOG
        .iter()
        .skip(start)
        .take(6)
        .map(|scenario| {
            domain_hash(
                "catalog-window-034",
                &[
                    scenario.scenario_id,
                    scenario.maker_id,
                    scenario.workload.as_str(),
                    scenario.sla_class.as_str(),
                    scenario.accelerator.as_str(),
                ],
            )
        })
        .collect();
    merkle_root("catalog-window-034", leaves)
}

pub fn catalog_window_035_root() -> String {
    let start = 34usize;
    let leaves: Vec<String> = DETERMINISTIC_SCENARIO_CATALOG
        .iter()
        .skip(start)
        .take(6)
        .map(|scenario| {
            domain_hash(
                "catalog-window-035",
                &[
                    scenario.scenario_id,
                    scenario.maker_id,
                    scenario.workload.as_str(),
                    scenario.sla_class.as_str(),
                    scenario.accelerator.as_str(),
                ],
            )
        })
        .collect();
    merkle_root("catalog-window-035", leaves)
}
