use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::hash::{domain_hash, merkle_root, HashPart};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2FastPqConfidentialWitnessDerivativeLatencyMarginRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_FAST_PQ_CONFIDENTIAL_WITNESS_DERIVATIVE_LATENCY_MARGIN_RUNTIME_PROTOCOL_VERSION: &str = "nebula-private-l2-fast-pq-confidential-witness-derivative-latency-margin-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_FAST_PQ_CONFIDENTIAL_WITNESS_DERIVATIVE_LATENCY_MARGIN_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "shake256-domain-separated-canonical-json-v1";
pub const PQ_MARGIN_ATTESTATION_SUITE: &str =
    "ml-dsa-87+slh-dsa-shake-256f-latency-margin-attestation-root-v1";
pub const MARGINED_POSITION_SUITE: &str =
    "ml-kem-1024-sealed-defi-derivative-margined-position-root-v1";
pub const PRIVACY_BOUNDARY: &str =
    "roots_only_no_plaintext_witnesses_addresses_keys_margin_terms_or_positions";
pub const PUBLIC_RECORD_SUITE: &str =
    "roots-only-private-l2-fast-pq-confidential-derivative-latency-margin-record-v1";
pub const DEVNET_L2_NETWORK: &str = "nebula-private-l2-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEVNET_HEIGHT: u64 = 8_240_000;
pub const DEVNET_EPOCH: u64 = 51_200;
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 262_144;
pub const DEFAULT_TARGET_PRIVACY_SET_SIZE: u64 = 1_048_576;
pub const DEFAULT_MARGIN_CYCLE_MS: u64 = 25;
pub const DEFAULT_MAX_LATENCY_MS: u64 = 180;
pub const DEFAULT_SETTLEMENT_DELAY_SLOTS: u64 = 2;
pub const DEFAULT_LOW_FEE_CAP_BPS: u64 = 18;
pub const DEFAULT_MAKER_REBATE_BPS: u64 = 80;
pub const DEFAULT_TAKER_FEE_BPS: u64 = 120;
pub const DEFAULT_MARGIN_DISCOUNT_BPS: u64 = 620;
pub const DEFAULT_PRIVACY_DISCOUNT_BPS: u64 = 420;
pub const DEFAULT_MIN_QUORUM_BPS: u64 = 7_000;
pub const DEFAULT_MAX_POOLS: usize = 65_536;
pub const DEFAULT_MAX_ORDERS: usize = 1_048_576;
pub const DEFAULT_MAX_MARGIN_ROUNDS: usize = 524_288;
pub const DEFAULT_MAX_ATTESTATIONS: usize = 1_048_576;
pub const DEFAULT_MAX_RECEIPTS: usize = 2_097_152;

const D_CONFIG: &str = "PL2-FAST-PQ-CONF-WITNESS-DERIV-LAT-MARGIN:CONFIG";
const D_COUNTERS: &str = "PL2-FAST-PQ-CONF-WITNESS-DERIV-LAT-MARGIN:COUNTERS";
const D_ROOTS: &str = "PL2-FAST-PQ-CONF-WITNESS-DERIV-LAT-MARGIN:ROOTS";
const D_STATE: &str = "PL2-FAST-PQ-CONF-WITNESS-DERIV-LAT-MARGIN:STATE";
const D_POOLS: &str = "PL2-FAST-PQ-CONF-WITNESS-DERIV-LAT-MARGIN:POOLS";
const D_ORDERS: &str = "PL2-FAST-PQ-CONF-WITNESS-DERIV-LAT-MARGIN:ORDERS";
const D_ROUNDS: &str = "PL2-FAST-PQ-CONF-WITNESS-DERIV-LAT-MARGIN:ROUNDS";
const D_ATTESTATIONS: &str = "PL2-FAST-PQ-CONF-WITNESS-DERIV-LAT-MARGIN:ATTESTATIONS";
const D_RECEIPTS: &str = "PL2-FAST-PQ-CONF-WITNESS-DERIV-LAT-MARGIN:RECEIPTS";
const D_PUBLIC: &str = "PL2-FAST-PQ-CONF-WITNESS-DERIV-LAT-MARGIN:PUBLIC";
const D_DEVNET: &str = "PL2-FAST-PQ-CONF-WITNESS-DERIV-LAT-MARGIN:DEVNET";

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MarginMode {
    Continuous,
    BatchAuction,
    MakerCross,
    EmergencyDrain,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PoolStatus {
    Open,
    Hot,
    Congested,
    Draining,
    Paused,
    Sealed,
}

impl PoolStatus {
    pub fn accepts_orders(self) -> bool {
        matches!(self, Self::Open | Self::Hot | Self::Congested)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DerivativeClass {
    LatencyFuture,
    WitnessDelaySwap,
    FeeRebateForward,
    CongestionOption,
    ReliabilityVariance,
    LiquidationBackstop,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Side {
    PayLatency,
    ReceiveLatency,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OrderStatus {
    Open,
    Nettable,
    Margined,
    Settled,
    Expired,
    Rejected,
}

impl OrderStatus {
    pub fn live(self) -> bool {
        matches!(self, Self::Open | Self::Nettable | Self::Margined)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RoundStatus {
    Building,
    Attested,
    Settled,
    Disputed,
    Expired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationStatus {
    Pending,
    Accepted,
    QuorumSatisfied,
    Rejected,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct Config {
    pub protocol_version: String,
    pub schema_version: u64,
    pub l2_network: String,
    pub fee_asset_id: String,
    pub hash_suite: String,
    pub pq_margin_attestation_suite: String,
    pub margined_position_suite: String,
    pub roots_only_public_records: bool,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub margin_cycle_ms: u64,
    pub max_latency_ms: u64,
    pub settlement_delay_slots: u64,
    pub low_fee_cap_bps: u64,
    pub maker_rebate_bps: u64,
    pub taker_fee_bps: u64,
    pub margin_discount_bps: u64,
    pub privacy_discount_bps: u64,
    pub min_quorum_bps: u64,
    pub max_pools: usize,
    pub max_orders: usize,
    pub max_margin_rounds: usize,
    pub max_attestations: usize,
    pub max_receipts: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            l2_network: DEVNET_L2_NETWORK.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            hash_suite: HASH_SUITE.to_string(),
            pq_margin_attestation_suite: PQ_MARGIN_ATTESTATION_SUITE.to_string(),
            margined_position_suite: MARGINED_POSITION_SUITE.to_string(),
            roots_only_public_records: true,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            margin_cycle_ms: DEFAULT_MARGIN_CYCLE_MS,
            max_latency_ms: DEFAULT_MAX_LATENCY_MS,
            settlement_delay_slots: DEFAULT_SETTLEMENT_DELAY_SLOTS,
            low_fee_cap_bps: DEFAULT_LOW_FEE_CAP_BPS,
            maker_rebate_bps: DEFAULT_MAKER_REBATE_BPS,
            taker_fee_bps: DEFAULT_TAKER_FEE_BPS,
            margin_discount_bps: DEFAULT_MARGIN_DISCOUNT_BPS,
            privacy_discount_bps: DEFAULT_PRIVACY_DISCOUNT_BPS,
            min_quorum_bps: DEFAULT_MIN_QUORUM_BPS,
            max_pools: DEFAULT_MAX_POOLS,
            max_orders: DEFAULT_MAX_ORDERS,
            max_margin_rounds: DEFAULT_MAX_MARGIN_ROUNDS,
            max_attestations: DEFAULT_MAX_ATTESTATIONS,
            max_receipts: DEFAULT_MAX_RECEIPTS,
        }
    }
}

impl Config {
    pub fn validate(&self) -> Result<()> {
        ensure_non_empty("protocol_version", &self.protocol_version)?;
        ensure_bps("low_fee_cap_bps", self.low_fee_cap_bps)?;
        ensure_bps("maker_rebate_bps", self.maker_rebate_bps)?;
        ensure_bps("taker_fee_bps", self.taker_fee_bps)?;
        ensure_bps("margin_discount_bps", self.margin_discount_bps)?;
        ensure_bps("privacy_discount_bps", self.privacy_discount_bps)?;
        ensure_bps("min_quorum_bps", self.min_quorum_bps)?;
        if self.min_pq_security_bits < 192 {
            return Err("min_pq_security_bits below PQ safety floor".to_string());
        }
        if self.min_privacy_set_size == 0 || self.margin_cycle_ms == 0 {
            return Err("privacy set and margin cycle must be non-zero".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "l2_network": self.l2_network,
            "fee_asset_id": self.fee_asset_id,
            "hash_suite": self.hash_suite,
            "pq_margin_attestation_suite": self.pq_margin_attestation_suite,
            "margined_position_suite": self.margined_position_suite,
            "roots_only_public_records": self.roots_only_public_records,
            "min_pq_security_bits": self.min_pq_security_bits,
            "min_privacy_set_size": self.min_privacy_set_size,
            "target_privacy_set_size": self.target_privacy_set_size,
            "margin_cycle_ms": self.margin_cycle_ms,
            "max_latency_ms": self.max_latency_ms,
            "low_fee_cap_bps": self.low_fee_cap_bps,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq, Serialize)]
pub struct Counters {
    pub pools_registered: u64,
    pub orders_opened: u64,
    pub orders_Margined: u64,
    pub rounds_opened: u64,
    pub rounds_settled: u64,
    pub attestations_recorded: u64,
    pub replay_receipts_recorded: u64,
    pub duplicate_replay_receipts: u64,
    pub total_gross_notional_micros: u128,
    pub total_net_notional_micros: u128,
    pub total_fee_micros: u128,
    pub total_fee_savings_micros: u128,
    pub peak_open_interest_micros: u128,
    pub last_height: u64,
    pub last_epoch: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        serde_json::to_value(self).unwrap_or_else(|_| json!({"serialization":"failed"}))
    }
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub counters_root: String,
    pub pools_root: String,
    pub orders_root: String,
    pub Margin_rounds_root: String,
    pub pq_attestations_root: String,
    pub replay_receipts_root: String,
    pub public_record_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        serde_json::to_value(self).unwrap_or_else(|_| json!({"serialization":"failed"}))
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RegisterPoolInput {
    pub pool_id: String,
    pub derivative_class: DerivativeClass,
    pub Margin_mode: MarginMode,
    pub maker_commitment_root: String,
    pub margin_vault_root: String,
    pub encrypted_curve_root: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub max_latency_ms: u64,
    pub open_interest_limit_micros: u128,
    pub created_at_height: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct MarginPool {
    pub pool_id: String,
    pub derivative_class: DerivativeClass,
    pub Margin_mode: MarginMode,
    pub status: PoolStatus,
    pub maker_commitment_root: String,
    pub margin_vault_root: String,
    pub encrypted_curve_root: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub max_latency_ms: u64,
    pub open_interest_limit_micros: u128,
    pub open_interest_micros: u128,
    pub Margined_interest_micros: u128,
    pub order_count: u64,
    pub round_count: u64,
    pub created_at_height: u64,
    pub updated_at_height: u64,
}

impl MarginPool {
    pub fn from_input(input: RegisterPoolInput) -> Self {
        Self {
            pool_id: input.pool_id,
            derivative_class: input.derivative_class,
            Margin_mode: input.Margin_mode,
            status: PoolStatus::Open,
            maker_commitment_root: input.maker_commitment_root,
            margin_vault_root: input.margin_vault_root,
            encrypted_curve_root: input.encrypted_curve_root,
            privacy_set_size: input.privacy_set_size,
            pq_security_bits: input.pq_security_bits,
            max_latency_ms: input.max_latency_ms,
            open_interest_limit_micros: input.open_interest_limit_micros,
            open_interest_micros: 0,
            Margined_interest_micros: 0,
            order_count: 0,
            round_count: 0,
            created_at_height: input.created_at_height,
            updated_at_height: input.created_at_height,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "pool_id": self.pool_id,
            "derivative_class": self.derivative_class,
            "Margin_mode": self.Margin_mode,
            "status": self.status,
            "maker_commitment_root": self.maker_commitment_root,
            "margin_vault_root": self.margin_vault_root,
            "encrypted_curve_root": self.encrypted_curve_root,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "max_latency_ms": self.max_latency_ms,
            "open_interest_micros": self.open_interest_micros,
            "Margined_interest_micros": self.Margined_interest_micros,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct OpenOrderInput {
    pub order_id: String,
    pub pool_id: String,
    pub side: Side,
    pub trader_commitment_root: String,
    pub sealed_terms_root: String,
    pub nullifier_root: String,
    pub notional_micros: u64,
    pub max_fee_micros: u64,
    pub latency_bound_ms: u64,
    pub opened_slot: u64,
    pub expires_slot: u64,
    pub created_at_height: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct MarginOrder {
    pub order_id: String,
    pub pool_id: String,
    pub side: Side,
    pub status: OrderStatus,
    pub trader_commitment_root: String,
    pub sealed_terms_root: String,
    pub nullifier_root: String,
    pub notional_micros: u64,
    pub max_fee_micros: u64,
    pub latency_bound_ms: u64,
    pub opened_slot: u64,
    pub expires_slot: u64,
    pub created_at_height: u64,
    pub Margined_round_id: Option<String>,
}

impl MarginOrder {
    pub fn from_input(input: OpenOrderInput) -> Self {
        Self {
            order_id: input.order_id,
            pool_id: input.pool_id,
            side: input.side,
            status: OrderStatus::Open,
            trader_commitment_root: input.trader_commitment_root,
            sealed_terms_root: input.sealed_terms_root,
            nullifier_root: input.nullifier_root,
            notional_micros: input.notional_micros,
            max_fee_micros: input.max_fee_micros,
            latency_bound_ms: input.latency_bound_ms,
            opened_slot: input.opened_slot,
            expires_slot: input.expires_slot,
            created_at_height: input.created_at_height,
            Margined_round_id: None,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "order_id": self.order_id,
            "pool_id": self.pool_id,
            "side": self.side,
            "status": self.status,
            "trader_commitment_root": self.trader_commitment_root,
            "sealed_terms_root": self.sealed_terms_root,
            "nullifier_root": self.nullifier_root,
            "notional_micros": self.notional_micros,
            "latency_bound_ms": self.latency_bound_ms,
            "opened_slot": self.opened_slot,
            "expires_slot": self.expires_slot,
            "Margined_round_id": self.Margined_round_id,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RunMarginInput {
    pub round_id: String,
    pub pool_id: String,
    pub order_ids: Vec<String>,
    pub net_position_root: String,
    pub fee_commitment_root: String,
    pub observed_latency_ms: u64,
    pub slot: u64,
    pub height: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct MarginRound {
    pub round_id: String,
    pub pool_id: String,
    pub status: RoundStatus,
    pub order_ids_root: String,
    pub net_position_root: String,
    pub fee_commitment_root: String,
    pub gross_notional_micros: u128,
    pub net_notional_micros: u128,
    pub fee_micros: u64,
    pub fee_savings_micros: u64,
    pub observed_latency_ms: u64,
    pub slot: u64,
    pub height: u64,
    pub attestation_count: u64,
}

impl MarginRound {
    pub fn public_record(&self) -> Value {
        json!({
            "round_id": self.round_id,
            "pool_id": self.pool_id,
            "status": self.status,
            "order_ids_root": self.order_ids_root,
            "net_position_root": self.net_position_root,
            "fee_commitment_root": self.fee_commitment_root,
            "gross_notional_micros": self.gross_notional_micros,
            "net_notional_micros": self.net_notional_micros,
            "fee_micros": self.fee_micros,
            "fee_savings_micros": self.fee_savings_micros,
            "observed_latency_ms": self.observed_latency_ms,
            "slot": self.slot,
            "height": self.height,
            "attestation_count": self.attestation_count,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct PqMarginAttestationInput {
    pub attestation_id: String,
    pub round_id: String,
    pub committee_root: String,
    pub pq_signature_root: String,
    pub quorum_bps: u64,
    pub security_bits: u16,
    pub valid_until_height: u64,
    pub recorded_at_height: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct PqMarginAttestation {
    pub attestation_id: String,
    pub round_id: String,
    pub status: AttestationStatus,
    pub committee_root: String,
    pub pq_signature_root: String,
    pub quorum_bps: u64,
    pub security_bits: u16,
    pub valid_until_height: u64,
    pub recorded_at_height: u64,
}

impl PqMarginAttestation {
    pub fn public_record(&self) -> Value {
        serde_json::to_value(self).unwrap_or_else(|_| json!({"serialization":"failed"}))
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct ReplayReceiptInput {
    pub receipt_id: String,
    pub nullifier_root: String,
    pub bound_round_root: String,
    pub recorded_at_height: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct ReplayReceipt {
    pub receipt_id: String,
    pub nullifier_root: String,
    pub bound_round_root: String,
    pub duplicate: bool,
    pub recorded_at_height: u64,
}

impl ReplayReceipt {
    pub fn public_record(&self) -> Value {
        serde_json::to_value(self).unwrap_or_else(|_| json!({"serialization":"failed"}))
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct PublicRecord {
    pub protocol_version: String,
    pub scheme: String,
    pub privacy_boundary: String,
    pub height: u64,
    pub epoch: u64,
    pub config_root: String,
    pub counters_root: String,
    pub pools_root: String,
    pub orders_root: String,
    pub Margin_rounds_root: String,
    pub pq_attestations_root: String,
    pub replay_receipts_root: String,
    pub state_root: String,
}

impl PublicRecord {
    pub fn public_record(&self) -> Value {
        serde_json::to_value(self).unwrap_or_else(|_| json!({"serialization":"failed"}))
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub pools: BTreeMap<String, MarginPool>,
    pub orders: BTreeMap<String, MarginOrder>,
    pub Margin_rounds: BTreeMap<String, MarginRound>,
    pub pq_attestations: BTreeMap<String, PqMarginAttestation>,
    pub replay_receipts: BTreeMap<String, ReplayReceipt>,
    seen_nullifiers: BTreeSet<String>,
}

impl State {
    pub fn new(config: Config) -> Self {
        let mut state = Self {
            config,
            counters: Counters::default(),
            roots: Roots::default(),
            pools: BTreeMap::new(),
            orders: BTreeMap::new(),
            Margin_rounds: BTreeMap::new(),
            pq_attestations: BTreeMap::new(),
            replay_receipts: BTreeMap::new(),
            seen_nullifiers: BTreeSet::new(),
        };
        state.refresh_roots();
        state
    }

    pub fn register_pool(&mut self, input: RegisterPoolInput) -> Result<()> {
        self.config.validate()?;
        ensure_capacity(self.pools.len(), self.config.max_pools, "pools")?;
        ensure_unique(&self.pools, "pool", &input.pool_id)?;
        ensure_non_empty("maker_commitment_root", &input.maker_commitment_root)?;
        if input.privacy_set_size < self.config.min_privacy_set_size {
            return Err("pool privacy set below configured floor".to_string());
        }
        if input.pq_security_bits < self.config.min_pq_security_bits {
            return Err("pool PQ security below configured floor".to_string());
        }
        let pool = MarginPool::from_input(input);
        self.counters.pools_registered = self.counters.pools_registered.saturating_add(1);
        self.pools.insert(pool.pool_id.clone(), pool);
        self.refresh_roots();
        Ok(())
    }

    pub fn open_order(&mut self, input: OpenOrderInput) -> Result<()> {
        ensure_capacity(self.orders.len(), self.config.max_orders, "orders")?;
        ensure_unique(&self.orders, "order", &input.order_id)?;
        let pool = self
            .pools
            .get_mut(&input.pool_id)
            .ok_or_else(|| format!("pool `{}` not found", input.pool_id))?;
        if !pool.status.accepts_orders() {
            return Err("pool does not accept orders".to_string());
        }
        if input.expires_slot <= input.opened_slot {
            return Err("order expires before it opens".to_string());
        }
        if input.latency_bound_ms > pool.max_latency_ms {
            return Err("order latency bound exceeds pool maximum".to_string());
        }
        let next_interest = pool
            .open_interest_micros
            .saturating_add(u128::from(input.notional_micros));
        if next_interest > pool.open_interest_limit_micros {
            return Err("pool open interest limit exceeded".to_string());
        }
        let order = MarginOrder::from_input(input);
        pool.open_interest_micros = next_interest;
        pool.order_count = pool.order_count.saturating_add(1);
        pool.updated_at_height = order.created_at_height;
        self.counters.orders_opened = self.counters.orders_opened.saturating_add(1);
        self.counters.total_gross_notional_micros = self
            .counters
            .total_gross_notional_micros
            .saturating_add(u128::from(order.notional_micros));
        self.update_peak_open_interest();
        self.orders.insert(order.order_id.clone(), order);
        self.refresh_roots();
        Ok(())
    }

    pub fn run_Margin(&mut self, input: RunMarginInput) -> Result<()> {
        ensure_capacity(
            self.Margin_rounds.len(),
            self.config.max_margin_rounds,
            "Margin rounds",
        )?;
        ensure_unique(&self.Margin_rounds, "Margin round", &input.round_id)?;
        let pool = self
            .pools
            .get(&input.pool_id)
            .ok_or_else(|| format!("pool `{}` not found", input.pool_id))?
            .clone();
        if input.observed_latency_ms > pool.max_latency_ms {
            return Err("Margin round exceeds pool latency bound".to_string());
        }
        let mut pay_latency = 0_u128;
        let mut receive_latency = 0_u128;
        for order_id in &input.order_ids {
            let order = self
                .orders
                .get(order_id)
                .ok_or_else(|| format!("order `{order_id}` not found"))?;
            if order.pool_id != input.pool_id || !order.status.live() {
                return Err(format!("order `{order_id}` is not nettable"));
            }
            match order.side {
                Side::PayLatency => {
                    pay_latency = pay_latency.saturating_add(u128::from(order.notional_micros))
                }
                Side::ReceiveLatency => {
                    receive_latency =
                        receive_latency.saturating_add(u128::from(order.notional_micros))
                }
            }
        }
        let gross_notional_micros = pay_latency.saturating_add(receive_latency);
        let net_notional_micros = pay_latency.abs_diff(receive_latency);
        let crossed_notional_micros = gross_notional_micros.saturating_sub(net_notional_micros);
        let fee_micros = fee_for_net(gross_notional_micros, net_notional_micros, &self.config);
        let fee_savings_micros =
            fee_savings_for_cross(crossed_notional_micros, self.config.margin_discount_bps);
        let order_ids_root = merkle_string_root(D_ORDERS, &input.order_ids);
        for order_id in &input.order_ids {
            if let Some(order) = self.orders.get_mut(order_id) {
                order.status = OrderStatus::Margined;
                order.Margined_round_id = Some(input.round_id.clone());
            }
        }
        if let Some(pool_mut) = self.pools.get_mut(&input.pool_id) {
            pool_mut.Margined_interest_micros = pool_mut
                .Margined_interest_micros
                .saturating_add(net_notional_micros);
            pool_mut.round_count = pool_mut.round_count.saturating_add(1);
            pool_mut.updated_at_height = input.height;
        }
        let round = MarginRound {
            round_id: input.round_id,
            pool_id: input.pool_id,
            status: RoundStatus::Building,
            order_ids_root,
            net_position_root: input.net_position_root,
            fee_commitment_root: input.fee_commitment_root,
            gross_notional_micros,
            net_notional_micros,
            fee_micros,
            fee_savings_micros,
            observed_latency_ms: input.observed_latency_ms,
            slot: input.slot,
            height: input.height,
            attestation_count: 0,
        };
        self.counters.rounds_opened = self.counters.rounds_opened.saturating_add(1);
        self.counters.orders_Margined = self
            .counters
            .orders_Margined
            .saturating_add(input.order_ids.len() as u64);
        self.counters.total_net_notional_micros = self
            .counters
            .total_net_notional_micros
            .saturating_add(net_notional_micros);
        self.counters.total_fee_micros = self
            .counters
            .total_fee_micros
            .saturating_add(u128::from(fee_micros));
        self.counters.total_fee_savings_micros = self
            .counters
            .total_fee_savings_micros
            .saturating_add(u128::from(fee_savings_micros));
        self.Margin_rounds.insert(round.round_id.clone(), round);
        self.refresh_roots();
        Ok(())
    }

    pub fn attest_Margin(&mut self, input: PqMarginAttestationInput) -> Result<()> {
        ensure_capacity(
            self.pq_attestations.len(),
            self.config.max_attestations,
            "PQ attestations",
        )?;
        ensure_unique(&self.pq_attestations, "attestation", &input.attestation_id)?;
        let round = self
            .Margin_rounds
            .get_mut(&input.round_id)
            .ok_or_else(|| format!("round `{}` not found", input.round_id))?;
        ensure_bps("quorum_bps", input.quorum_bps)?;
        let status = if input.security_bits >= self.config.min_pq_security_bits
            && input.quorum_bps >= self.config.min_quorum_bps
        {
            AttestationStatus::QuorumSatisfied
        } else {
            AttestationStatus::Pending
        };
        if status == AttestationStatus::QuorumSatisfied {
            round.status = RoundStatus::Attested;
        }
        round.attestation_count = round.attestation_count.saturating_add(1);
        let attestation = PqMarginAttestation {
            attestation_id: input.attestation_id,
            round_id: input.round_id,
            status,
            committee_root: input.committee_root,
            pq_signature_root: input.pq_signature_root,
            quorum_bps: input.quorum_bps,
            security_bits: input.security_bits,
            valid_until_height: input.valid_until_height,
            recorded_at_height: input.recorded_at_height,
        };
        self.counters.attestations_recorded = self.counters.attestations_recorded.saturating_add(1);
        self.pq_attestations
            .insert(attestation.attestation_id.clone(), attestation);
        self.refresh_roots();
        Ok(())
    }

    pub fn record_replay_receipt(&mut self, input: ReplayReceiptInput) -> Result<()> {
        ensure_capacity(
            self.replay_receipts.len(),
            self.config.max_receipts,
            "replay receipts",
        )?;
        ensure_unique(&self.replay_receipts, "receipt", &input.receipt_id)?;
        let duplicate = !self.seen_nullifiers.insert(input.nullifier_root.clone());
        let receipt = ReplayReceipt {
            receipt_id: input.receipt_id,
            nullifier_root: input.nullifier_root,
            bound_round_root: input.bound_round_root,
            duplicate,
            recorded_at_height: input.recorded_at_height,
        };
        self.counters.replay_receipts_recorded =
            self.counters.replay_receipts_recorded.saturating_add(1);
        if duplicate {
            self.counters.duplicate_replay_receipts =
                self.counters.duplicate_replay_receipts.saturating_add(1);
        }
        self.replay_receipts
            .insert(receipt.receipt_id.clone(), receipt);
        self.refresh_roots();
        Ok(())
    }

    pub fn settle_round(&mut self, round_id: &str, height: u64, epoch: u64) -> Result<()> {
        let round = self
            .Margin_rounds
            .get_mut(round_id)
            .ok_or_else(|| format!("round `{round_id}` not found"))?;
        if round.status != RoundStatus::Attested {
            return Err("round must be PQ-attested before settlement".to_string());
        }
        round.status = RoundStatus::Settled;
        for order in self
            .orders
            .values_mut()
            .filter(|order| order.Margined_round_id.as_deref() == Some(round_id))
        {
            order.status = OrderStatus::Settled;
        }
        self.counters.rounds_settled = self.counters.rounds_settled.saturating_add(1);
        self.counters.last_height = height;
        self.counters.last_epoch = epoch;
        self.refresh_roots();
        Ok(())
    }

    pub fn refresh_roots(&mut self) {
        self.roots.config_root = canonical_root(D_CONFIG, &self.config.public_record());
        self.roots.counters_root = canonical_root(D_COUNTERS, &self.counters);
        self.roots.pools_root = map_root(D_POOLS, &self.pools);
        self.roots.orders_root = map_root(D_ORDERS, &self.orders);
        self.roots.Margin_rounds_root = map_root(D_ROUNDS, &self.Margin_rounds);
        self.roots.pq_attestations_root = map_root(D_ATTESTATIONS, &self.pq_attestations);
        self.roots.replay_receipts_root = map_root(D_RECEIPTS, &self.replay_receipts);
        let public_seed = self.roots_only_record();
        self.roots.public_record_root = canonical_root(D_PUBLIC, &public_seed);
        self.roots.state_root = domain_hash(
            D_STATE,
            &[
                HashPart::from(self.roots.config_root.as_str()),
                HashPart::from(self.roots.counters_root.as_str()),
                HashPart::from(self.roots.pools_root.as_str()),
                HashPart::from(self.roots.orders_root.as_str()),
                HashPart::from(self.roots.Margin_rounds_root.as_str()),
                HashPart::from(self.roots.pq_attestations_root.as_str()),
                HashPart::from(self.roots.replay_receipts_root.as_str()),
                HashPart::from(self.roots.public_record_root.as_str()),
            ],
        );
    }

    pub fn state_root(&self) -> String {
        self.roots.state_root.clone()
    }

    pub fn public_record(&mut self, height: u64, epoch: u64) -> Result<PublicRecord> {
        self.config.validate()?;
        self.counters.last_height = height;
        self.counters.last_epoch = epoch;
        self.refresh_roots();
        Ok(self.roots_only_record())
    }

    fn roots_only_record(&self) -> PublicRecord {
        PublicRecord {
            protocol_version: PROTOCOL_VERSION.to_string(),
            scheme: PUBLIC_RECORD_SUITE.to_string(),
            privacy_boundary: PRIVACY_BOUNDARY.to_string(),
            height: self.counters.last_height,
            epoch: self.counters.last_epoch,
            config_root: self.roots.config_root.clone(),
            counters_root: self.roots.counters_root.clone(),
            pools_root: self.roots.pools_root.clone(),
            orders_root: self.roots.orders_root.clone(),
            Margin_rounds_root: self.roots.Margin_rounds_root.clone(),
            pq_attestations_root: self.roots.pq_attestations_root.clone(),
            replay_receipts_root: self.roots.replay_receipts_root.clone(),
            state_root: self.roots.state_root.clone(),
        }
    }

    fn update_peak_open_interest(&mut self) {
        let open_interest = self
            .pools
            .values()
            .map(|pool| pool.open_interest_micros)
            .sum::<u128>();
        self.counters.peak_open_interest_micros =
            self.counters.peak_open_interest_micros.max(open_interest);
    }
}

pub fn devnet() -> State {
    let mut state = State::new(Config::default());
    let pool_id = "devnet-fast-pq-latency-margin-pool-0".to_string();
    state
        .register_pool(RegisterPoolInput {
            pool_id: pool_id.clone(),
            derivative_class: DerivativeClass::LatencyFuture,
            Margin_mode: MarginMode::Continuous,
            maker_commitment_root: devnet_commitment("maker", 0),
            margin_vault_root: devnet_commitment("margin-vault", 0),
            encrypted_curve_root: devnet_commitment("encrypted-curve", 0),
            privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            max_latency_ms: DEFAULT_MAX_LATENCY_MS,
            open_interest_limit_micros: 5_000_000_000,
            created_at_height: DEVNET_HEIGHT,
        })
        .expect("devnet pool must register");
    state
        .open_order(OpenOrderInput {
            order_id: "devnet-margin-order-pay-0".to_string(),
            pool_id: pool_id.clone(),
            side: Side::PayLatency,
            trader_commitment_root: devnet_commitment("pay-trader", 0),
            sealed_terms_root: devnet_commitment("pay-terms", 0),
            nullifier_root: devnet_commitment("pay-nullifier", 0),
            notional_micros: 80_000,
            max_fee_micros: 14,
            latency_bound_ms: 120,
            opened_slot: DEVNET_EPOCH,
            expires_slot: DEVNET_EPOCH + 64,
            created_at_height: DEVNET_HEIGHT + 1,
        })
        .expect("devnet pay order must open");
    state
        .open_order(OpenOrderInput {
            order_id: "devnet-margin-order-receive-0".to_string(),
            pool_id: pool_id.clone(),
            side: Side::ReceiveLatency,
            trader_commitment_root: devnet_commitment("receive-trader", 0),
            sealed_terms_root: devnet_commitment("receive-terms", 0),
            nullifier_root: devnet_commitment("receive-nullifier", 0),
            notional_micros: 72_000,
            max_fee_micros: 11,
            latency_bound_ms: 120,
            opened_slot: DEVNET_EPOCH,
            expires_slot: DEVNET_EPOCH + 64,
            created_at_height: DEVNET_HEIGHT + 1,
        })
        .expect("devnet receive order must open");
    state
        .run_Margin(RunMarginInput {
            round_id: "devnet-margin-round-0".to_string(),
            pool_id,
            order_ids: vec![
                "devnet-margin-order-pay-0".to_string(),
                "devnet-margin-order-receive-0".to_string(),
            ],
            net_position_root: devnet_commitment("net-position", 0),
            fee_commitment_root: devnet_commitment("fee", 0),
            observed_latency_ms: 24,
            slot: DEVNET_EPOCH + 1,
            height: DEVNET_HEIGHT + 2,
        })
        .expect("devnet round must net");
    state
        .attest_Margin(PqMarginAttestationInput {
            attestation_id: "devnet-margin-attestation-0".to_string(),
            round_id: "devnet-margin-round-0".to_string(),
            committee_root: devnet_commitment("committee", 0),
            pq_signature_root: devnet_commitment("pq-signature", 0),
            quorum_bps: DEFAULT_MIN_QUORUM_BPS,
            security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            valid_until_height: DEVNET_HEIGHT + 128,
            recorded_at_height: DEVNET_HEIGHT + 3,
        })
        .expect("devnet attestation must record");
    state
        .settle_round("devnet-margin-round-0", DEVNET_HEIGHT + 4, DEVNET_EPOCH + 2)
        .expect("devnet round must settle");
    state.refresh_roots();
    state
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}

pub fn public_record(state: &mut State, height: u64, epoch: u64) -> Result<PublicRecord> {
    state.public_record(height, epoch)
}

fn fee_for_net(gross: u128, net: u128, config: &Config) -> u64 {
    let fee_bps = config
        .taker_fee_bps
        .saturating_sub(config.margin_discount_bps.min(config.taker_fee_bps))
        .min(config.low_fee_cap_bps);
    gross
        .saturating_add(net)
        .saturating_mul(u128::from(fee_bps))
        .saturating_div(u128::from(MAX_BPS))
        .min(u128::from(u64::MAX)) as u64
}

fn fee_savings_for_cross(crossed: u128, discount_bps: u64) -> u64 {
    crossed
        .saturating_mul(u128::from(discount_bps.min(MAX_BPS)))
        .saturating_div(u128::from(MAX_BPS))
        .min(u128::from(u64::MAX)) as u64
}

fn ensure_non_empty(field: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        Err(format!("{field} must be non-empty"))
    } else {
        Ok(())
    }
}

fn ensure_bps(field: &str, value: u64) -> Result<()> {
    if value > MAX_BPS {
        Err(format!("{field} exceeds {MAX_BPS} bps"))
    } else {
        Ok(())
    }
}

fn ensure_capacity(len: usize, max: usize, label: &str) -> Result<()> {
    if len >= max {
        Err(format!("{label} capacity exhausted"))
    } else {
        Ok(())
    }
}

fn ensure_unique<T>(map: &BTreeMap<String, T>, label: &str, id: &str) -> Result<()> {
    if map.contains_key(id) {
        Err(format!("{label} `{id}` already exists"))
    } else {
        Ok(())
    }
}

fn canonical_root<T: Serialize>(domain: &'static str, value: &T) -> String {
    let encoded = serde_json::to_string(value).unwrap_or_else(|_| "null".to_string());
    domain_hash(domain, &[HashPart::from(encoded.as_str())])
}

fn map_root<T: Serialize>(domain: &'static str, map: &BTreeMap<String, T>) -> String {
    if map.is_empty() {
        return empty_root(domain);
    }
    let leaves = map
        .iter()
        .map(|(key, value)| {
            let encoded = serde_json::to_string(value).unwrap_or_else(|_| "null".to_string());
            domain_hash(
                domain,
                &[
                    HashPart::from(key.as_str()),
                    HashPart::from(encoded.as_str()),
                ],
            )
        })
        .collect::<Vec<_>>();
    merkle_root(
        domain,
        leaves.iter().map(|leaf| HashPart::from(leaf.as_str())),
    )
}

fn merkle_string_root(domain: &'static str, values: &[String]) -> String {
    if values.is_empty() {
        return empty_root(domain);
    }
    merkle_root(
        domain,
        values.iter().map(|value| HashPart::from(value.as_str())),
    )
}

fn empty_root(domain: &'static str) -> String {
    merkle_root(domain, std::iter::empty::<HashPart>())
}

fn devnet_commitment(label: &str, sequence: u64) -> String {
    domain_hash(
        D_DEVNET,
        &[
            HashPart::from(label),
            HashPart::from(DEVNET_L2_NETWORK),
            HashPart::from(DEVNET_HEIGHT),
            HashPart::from(DEVNET_EPOCH),
            HashPart::from(sequence),
        ],
    )
}
