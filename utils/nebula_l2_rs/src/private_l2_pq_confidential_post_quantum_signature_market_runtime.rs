use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2PqConfidentialPostQuantumSignatureMarketRuntimeResult<T> = Result<T, String>;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_POST_QUANTUM_SIGNATURE_MARKET_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-confidential-post-quantum-signature-market-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_POST_QUANTUM_SIGNATURE_MARKET_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_AUTH_SUITE: &str = "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-market-v1";
pub const THRESHOLD_COMMITMENT_SUITE: &str =
    "frost-like-pq-threshold-aggregation-commitment-root-v1";
pub const PRIVATE_REDACTION_SUITE: &str =
    "roots-only-confidential-signature-market-redaction-root-v1";
pub const LOW_FEE_COUPON_SUITE: &str = "batched-pq-verification-coupon-root-v1";
pub const DEVNET_HEIGHT: u64 = 1_184_000;
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PRIVACY_SET: u64 = 16_384;
pub const DEFAULT_QUOTE_TTL_BLOCKS: u64 = 24;
pub const DEFAULT_ORDER_TTL_BLOCKS: u64 = 36;
pub const DEFAULT_COUPON_TTL_BLOCKS: u64 = 720;
pub const DEFAULT_LOW_FEE_MICRONERO: u64 = 900;
pub const DEFAULT_MAX_FEE_MICRONERO: u64 = 25_000;
pub const DEFAULT_SLASH_BPS: u64 = 750;
pub const DEFAULT_QUARANTINE_BLOCKS: u64 = 2_880;
pub const DEFAULT_MAX_SIGNERS: usize = 524_288;
pub const DEFAULT_MAX_QUOTES: usize = 1_048_576;
pub const DEFAULT_MAX_ORDERS: usize = 1_048_576;
pub const DEFAULT_MAX_PUBLIC_RECORDS: usize = 2_097_152;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SignatureScheme {
    MlDsa87,
    SlhDsaShake256f,
    Falcon1024,
    HybridMigration,
}

impl SignatureScheme {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MlDsa87 => "ml_dsa_87",
            Self::SlhDsaShake256f => "slh_dsa_shake_256f",
            Self::Falcon1024 => "falcon_1024",
            Self::HybridMigration => "hybrid_migration",
        }
    }

    pub fn security_bits(self) -> u16 {
        match self {
            Self::MlDsa87 | Self::SlhDsaShake256f => 256,
            Self::Falcon1024 => 256,
            Self::HybridMigration => 192,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MarketLane {
    BridgeWatcher,
    ContractPrecompile,
    DefiSettlement,
    BatchVerification,
    EmergencyRotation,
}

impl MarketLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BridgeWatcher => "bridge_watcher",
            Self::ContractPrecompile => "contract_precompile",
            Self::DefiSettlement => "defi_settlement",
            Self::BatchVerification => "batch_verification",
            Self::EmergencyRotation => "emergency_rotation",
        }
    }

    pub fn priority_weight(self) -> u64 {
        match self {
            Self::EmergencyRotation => 1_000,
            Self::BridgeWatcher => 920,
            Self::ContractPrecompile => 860,
            Self::DefiSettlement => 780,
            Self::BatchVerification => 700,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QuoteStatus {
    Open,
    Matched,
    Aggregating,
    Fulfilled,
    Expired,
    Quarantined,
    Slashed,
}

impl QuoteStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Matched => "matched",
            Self::Aggregating => "aggregating",
            Self::Fulfilled => "fulfilled",
            Self::Expired => "expired",
            Self::Quarantined => "quarantined",
            Self::Slashed => "slashed",
        }
    }

    pub fn live(self) -> bool {
        matches!(self, Self::Open | Self::Matched | Self::Aggregating)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OrderStatus {
    Open,
    Matched,
    Reserved,
    Aggregated,
    Settled,
    Expired,
    Failed,
}

impl OrderStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Matched => "matched",
            Self::Reserved => "reserved",
            Self::Aggregated => "aggregated",
            Self::Settled => "settled",
            Self::Expired => "expired",
            Self::Failed => "failed",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub protocol_version: String,
    pub monero_network: String,
    pub l2_network: String,
    pub activation_height: u64,
    pub min_pq_security_bits: u16,
    pub min_privacy_set: u64,
    pub quote_ttl_blocks: u64,
    pub order_ttl_blocks: u64,
    pub coupon_ttl_blocks: u64,
    pub low_fee_micronero: u64,
    pub max_fee_micronero: u64,
    pub slash_bps: u64,
    pub quarantine_blocks: u64,
    pub max_signers: usize,
    pub max_quotes: usize,
    pub max_orders: usize,
    pub max_public_records: usize,
    pub allowed_schemes: BTreeSet<SignatureScheme>,
    pub quantum_resistance_first: bool,
    pub allow_contract_precompile_reservations: bool,
    pub allow_low_fee_coupons: bool,
    pub require_operator_safe_summaries: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            monero_network: "monero-devnet".to_string(),
            l2_network: "nebula-private-l2-devnet".to_string(),
            activation_height: DEVNET_HEIGHT,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set: DEFAULT_MIN_PRIVACY_SET,
            quote_ttl_blocks: DEFAULT_QUOTE_TTL_BLOCKS,
            order_ttl_blocks: DEFAULT_ORDER_TTL_BLOCKS,
            coupon_ttl_blocks: DEFAULT_COUPON_TTL_BLOCKS,
            low_fee_micronero: DEFAULT_LOW_FEE_MICRONERO,
            max_fee_micronero: DEFAULT_MAX_FEE_MICRONERO,
            slash_bps: DEFAULT_SLASH_BPS,
            quarantine_blocks: DEFAULT_QUARANTINE_BLOCKS,
            max_signers: DEFAULT_MAX_SIGNERS,
            max_quotes: DEFAULT_MAX_QUOTES,
            max_orders: DEFAULT_MAX_ORDERS,
            max_public_records: DEFAULT_MAX_PUBLIC_RECORDS,
            allowed_schemes: BTreeSet::from([
                SignatureScheme::MlDsa87,
                SignatureScheme::SlhDsaShake256f,
                SignatureScheme::Falcon1024,
            ]),
            quantum_resistance_first: true,
            allow_contract_precompile_reservations: true,
            allow_low_fee_coupons: true,
            require_operator_safe_summaries: true,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.protocol_version,
            "schema_version": SCHEMA_VERSION,
            "hash_suite": HASH_SUITE,
            "pq_auth_suite": PQ_AUTH_SUITE,
            "monero_network": self.monero_network,
            "l2_network": self.l2_network,
            "activation_height": self.activation_height,
            "min_pq_security_bits": self.min_pq_security_bits,
            "min_privacy_set": self.min_privacy_set,
            "quote_ttl_blocks": self.quote_ttl_blocks,
            "order_ttl_blocks": self.order_ttl_blocks,
            "coupon_ttl_blocks": self.coupon_ttl_blocks,
            "low_fee_micronero": self.low_fee_micronero,
            "max_fee_micronero": self.max_fee_micronero,
            "slash_bps": self.slash_bps,
            "quarantine_blocks": self.quarantine_blocks,
            "max_signers": self.max_signers,
            "max_quotes": self.max_quotes,
            "max_orders": self.max_orders,
            "max_public_records": self.max_public_records,
            "allowed_schemes": self.allowed_schemes.iter().map(|scheme| scheme.as_str()).collect::<Vec<_>>(),
            "quantum_resistance_first": self.quantum_resistance_first,
            "allow_contract_precompile_reservations": self.allow_contract_precompile_reservations,
            "allow_low_fee_coupons": self.allow_low_fee_coupons,
            "require_operator_safe_summaries": self.require_operator_safe_summaries,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Counters {
    pub signer_liquidity: u64,
    pub quotes: u64,
    pub orders: u64,
    pub matches: u64,
    pub threshold_commitments: u64,
    pub bridge_watcher_bids: u64,
    pub precompile_reservations: u64,
    pub low_fee_coupons: u64,
    pub slashing_events: u64,
    pub quarantines: u64,
    pub public_records: u64,
    pub total_capacity_units: u128,
    pub total_fee_micronero: u128,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub signer_root: String,
    pub quote_root: String,
    pub order_root: String,
    pub match_root: String,
    pub threshold_commitment_root: String,
    pub bridge_watcher_bid_root: String,
    pub precompile_reservation_root: String,
    pub low_fee_coupon_root: String,
    pub privacy_redaction_root: String,
    pub slashing_root: String,
    pub quarantine_root: String,
    pub public_record_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SignerLiquidityRequest {
    pub operator_commitment: String,
    pub signer_key_commitment: String,
    pub scheme: SignatureScheme,
    pub lanes: BTreeSet<MarketLane>,
    pub capacity_units: u64,
    pub min_fee_micronero: u64,
    pub bond_commitment: String,
    pub privacy_group_root: String,
    pub pq_attestation_root: String,
    pub nonce: String,
}

impl SignerLiquidityRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "operator_commitment": self.operator_commitment,
            "signer_key_commitment": self.signer_key_commitment,
            "scheme": self.scheme.as_str(),
            "lanes": self.lanes.iter().map(|lane| lane.as_str()).collect::<Vec<_>>(),
            "capacity_units": self.capacity_units,
            "min_fee_micronero": self.min_fee_micronero,
            "bond_commitment": self.bond_commitment,
            "privacy_group_root": self.privacy_group_root,
            "pq_attestation_root": self.pq_attestation_root,
            "nonce": self.nonce,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SignerLiquidityRecord {
    pub signer_id: String,
    pub request: SignerLiquidityRequest,
    pub remaining_units: u64,
    pub score: u64,
    pub quarantined_until_height: Option<u64>,
}

impl SignerLiquidityRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "signer_id": self.signer_id,
            "request": self.request.public_record(),
            "remaining_units": self.remaining_units,
            "score": self.score,
            "quarantined_until_height": self.quarantined_until_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SignatureQuoteRequest {
    pub requester_commitment: String,
    pub lane: MarketLane,
    pub scheme: SignatureScheme,
    pub message_root: String,
    pub max_fee_micronero: u64,
    pub min_signers: u16,
    pub expires_at_height: u64,
    pub privacy_redaction_root: String,
    pub nonce: String,
}

impl SignatureQuoteRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "requester_commitment": self.requester_commitment,
            "lane": self.lane.as_str(),
            "scheme": self.scheme.as_str(),
            "message_root": self.message_root,
            "max_fee_micronero": self.max_fee_micronero,
            "min_signers": self.min_signers,
            "expires_at_height": self.expires_at_height,
            "privacy_redaction_root": self.privacy_redaction_root,
            "nonce": self.nonce,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SignatureQuoteRecord {
    pub quote_id: String,
    pub request: SignatureQuoteRequest,
    pub status: QuoteStatus,
    pub matched_order_id: Option<String>,
}

impl SignatureQuoteRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "quote_id": self.quote_id,
            "request": self.request.public_record(),
            "status": self.status.as_str(),
            "matched_order_id": self.matched_order_id,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SignatureOrderRequest {
    pub quote_id: String,
    pub signer_ids: Vec<String>,
    pub aggregate_message_root: String,
    pub fee_bid_micronero: u64,
    pub settlement_contract: String,
    pub deadline_height: u64,
    pub nonce: String,
}

impl SignatureOrderRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "quote_id": self.quote_id,
            "signer_ids": self.signer_ids,
            "aggregate_message_root": self.aggregate_message_root,
            "fee_bid_micronero": self.fee_bid_micronero,
            "settlement_contract": self.settlement_contract,
            "deadline_height": self.deadline_height,
            "nonce": self.nonce,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SignatureOrderRecord {
    pub order_id: String,
    pub request: SignatureOrderRequest,
    pub status: OrderStatus,
    pub matched_fee_micronero: u64,
}

impl SignatureOrderRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "order_id": self.order_id,
            "request": self.request.public_record(),
            "status": self.status.as_str(),
            "matched_fee_micronero": self.matched_fee_micronero,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OrderMatchRecord {
    pub match_id: String,
    pub quote_id: String,
    pub order_id: String,
    pub signer_ids: Vec<String>,
    pub clearing_fee_micronero: u64,
    pub priority_score: u64,
}

impl OrderMatchRecord {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ThresholdAggregationCommitmentRecord {
    pub aggregation_id: String,
    pub order_id: String,
    pub participant_root: String,
    pub partial_signature_root: String,
    pub aggregate_signature_commitment: String,
    pub threshold: u16,
    pub scheme: SignatureScheme,
    pub privacy_redaction_root: String,
}

impl ThresholdAggregationCommitmentRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "aggregation_id": self.aggregation_id,
            "order_id": self.order_id,
            "participant_root": self.participant_root,
            "partial_signature_root": self.partial_signature_root,
            "aggregate_signature_commitment": self.aggregate_signature_commitment,
            "threshold": self.threshold,
            "scheme": self.scheme.as_str(),
            "privacy_redaction_root": self.privacy_redaction_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BridgeWatcherSignatureBidRecord {
    pub bid_id: String,
    pub watcher_commitment: String,
    pub bridge_event_root: String,
    pub scheme: SignatureScheme,
    pub fee_micronero: u64,
    pub response_height: u64,
    pub redaction_root: String,
}

impl BridgeWatcherSignatureBidRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "bid_id": self.bid_id,
            "watcher_commitment": self.watcher_commitment,
            "bridge_event_root": self.bridge_event_root,
            "scheme": self.scheme.as_str(),
            "fee_micronero": self.fee_micronero,
            "response_height": self.response_height,
            "redaction_root": self.redaction_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PrecompileReservationRecord {
    pub reservation_id: String,
    pub contract_commitment: String,
    pub call_root: String,
    pub lane: MarketLane,
    pub max_batch_size: u32,
    pub reserved_units: u64,
    pub fee_cap_micronero: u64,
    pub expires_at_height: u64,
}

impl PrecompileReservationRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "reservation_id": self.reservation_id,
            "contract_commitment": self.contract_commitment,
            "call_root": self.call_root,
            "lane": self.lane.as_str(),
            "max_batch_size": self.max_batch_size,
            "reserved_units": self.reserved_units,
            "fee_cap_micronero": self.fee_cap_micronero,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LowFeeBatchVerificationCouponRecord {
    pub coupon_id: String,
    pub sponsor_commitment: String,
    pub lane: MarketLane,
    pub coupon_units: u64,
    pub max_fee_micronero: u64,
    pub batch_root: String,
    pub expires_at_height: u64,
}

impl LowFeeBatchVerificationCouponRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "coupon_id": self.coupon_id,
            "sponsor_commitment": self.sponsor_commitment,
            "lane": self.lane.as_str(),
            "coupon_units": self.coupon_units,
            "max_fee_micronero": self.max_fee_micronero,
            "batch_root": self.batch_root,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PrivacyRedactionRecord {
    pub redaction_id: String,
    pub subject_kind: String,
    pub subject_id: String,
    pub disclosed_fields: BTreeSet<String>,
    pub sealed_payload_root: String,
}

impl PrivacyRedactionRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "redaction_id": self.redaction_id,
            "subject_kind": self.subject_kind,
            "subject_id": self.subject_id,
            "disclosed_fields": self.disclosed_fields,
            "sealed_payload_root": self.sealed_payload_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SlashingQuarantineRecord {
    pub action_id: String,
    pub signer_id: String,
    pub reason_code: String,
    pub evidence_root: String,
    pub slash_amount_commitment: String,
    pub quarantine_until_height: u64,
}

impl SlashingQuarantineRecord {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OperatorSafeSummary {
    pub state_root: String,
    pub live_signers: u64,
    pub live_quotes: u64,
    pub live_orders: u64,
    pub average_fee_band_micronero: String,
    pub pq_security_floor_bits: u16,
    pub public_record_root: String,
}

impl OperatorSafeSummary {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub signer_liquidity: BTreeMap<String, SignerLiquidityRecord>,
    pub quotes: BTreeMap<String, SignatureQuoteRecord>,
    pub orders: BTreeMap<String, SignatureOrderRecord>,
    pub matches: BTreeMap<String, OrderMatchRecord>,
    pub threshold_commitments: BTreeMap<String, ThresholdAggregationCommitmentRecord>,
    pub bridge_watcher_bids: BTreeMap<String, BridgeWatcherSignatureBidRecord>,
    pub precompile_reservations: BTreeMap<String, PrecompileReservationRecord>,
    pub low_fee_coupons: BTreeMap<String, LowFeeBatchVerificationCouponRecord>,
    pub privacy_redactions: BTreeMap<String, PrivacyRedactionRecord>,
    pub slashing_quarantines: BTreeMap<String, SlashingQuarantineRecord>,
    pub public_records: BTreeMap<String, Value>,
}

impl Default for State {
    fn default() -> Self {
        let mut state = Self {
            config: Config::devnet(),
            counters: Counters::default(),
            roots: Roots::default(),
            signer_liquidity: BTreeMap::new(),
            quotes: BTreeMap::new(),
            orders: BTreeMap::new(),
            matches: BTreeMap::new(),
            threshold_commitments: BTreeMap::new(),
            bridge_watcher_bids: BTreeMap::new(),
            precompile_reservations: BTreeMap::new(),
            low_fee_coupons: BTreeMap::new(),
            privacy_redactions: BTreeMap::new(),
            slashing_quarantines: BTreeMap::new(),
            public_records: BTreeMap::new(),
        };
        state.refresh_roots();
        state
    }
}

impl State {
    pub fn devnet() -> Self {
        devnet()
    }

    pub fn demo() -> Self {
        demo()
    }

    pub fn register_signer(
        &mut self,
        request: SignerLiquidityRequest,
    ) -> PrivateL2PqConfidentialPostQuantumSignatureMarketRuntimeResult<String> {
        require_scheme(&self.config, request.scheme)?;
        require(request.capacity_units > 0, "signer capacity is zero")?;
        require(
            self.signer_liquidity.len() < self.config.max_signers,
            "signer book capacity reached",
        )?;
        let signer_id = id_from_record("SIGNER-ID", &request.public_record());
        let record = SignerLiquidityRecord {
            signer_id: signer_id.clone(),
            remaining_units: request.capacity_units,
            score: request
                .capacity_units
                .saturating_mul(request.scheme.security_bits() as u64),
            quarantined_until_height: None,
            request,
        };
        self.record_public(format!("signer:{signer_id}"), record.public_record())?;
        self.signer_liquidity.insert(signer_id.clone(), record);
        self.refresh_roots();
        Ok(signer_id)
    }

    pub fn post_quote(
        &mut self,
        request: SignatureQuoteRequest,
    ) -> PrivateL2PqConfidentialPostQuantumSignatureMarketRuntimeResult<String> {
        require_scheme(&self.config, request.scheme)?;
        require(
            request.scheme.security_bits() >= self.config.min_pq_security_bits,
            "quote does not meet quantum resistance floor",
        )?;
        require(
            request.max_fee_micronero <= self.config.max_fee_micronero,
            "quote fee cap exceeds config max",
        )?;
        require(
            self.quotes.len() < self.config.max_quotes,
            "quote book capacity reached",
        )?;
        let quote_id = id_from_record("QUOTE-ID", &request.public_record());
        let record = SignatureQuoteRecord {
            quote_id: quote_id.clone(),
            request,
            status: QuoteStatus::Open,
            matched_order_id: None,
        };
        self.record_public(format!("quote:{quote_id}"), record.public_record())?;
        self.quotes.insert(quote_id.clone(), record);
        self.refresh_roots();
        Ok(quote_id)
    }

    pub fn place_order(
        &mut self,
        request: SignatureOrderRequest,
    ) -> PrivateL2PqConfidentialPostQuantumSignatureMarketRuntimeResult<String> {
        require(
            self.orders.len() < self.config.max_orders,
            "order book capacity reached",
        )?;
        let quote = self
            .quotes
            .get(&request.quote_id)
            .ok_or_else(|| "quote not found".to_string())?;
        require(quote.status == QuoteStatus::Open, "quote is not open")?;
        let quote_lane = quote.request.lane;
        let quote_scheme = quote.request.scheme;
        let quote_min_signers = quote.request.min_signers;
        let quote_max_fee_micronero = quote.request.max_fee_micronero;
        require(
            request.signer_ids.len() >= quote_min_signers as usize,
            "insufficient signer commitments",
        )?;
        require(
            request.fee_bid_micronero <= quote_max_fee_micronero,
            "order fee exceeds quote cap",
        )?;
        for signer_id in &request.signer_ids {
            let signer = self
                .signer_liquidity
                .get(signer_id)
                .ok_or_else(|| format!("signer not found: {signer_id}"))?;
            require(
                signer.request.scheme == quote_scheme,
                "signer scheme mismatch",
            )?;
            require(
                signer.request.lanes.contains(&quote_lane),
                "signer lane mismatch",
            )?;
            require(
                signer.quarantined_until_height.is_none(),
                "signer quarantined",
            )?;
        }
        let order_id = id_from_record("ORDER-ID", &request.public_record());
        let record = SignatureOrderRecord {
            order_id: order_id.clone(),
            matched_fee_micronero: request.fee_bid_micronero,
            request,
            status: OrderStatus::Matched,
        };
        if let Some(quote) = self.quotes.get_mut(&record.request.quote_id) {
            quote.status = QuoteStatus::Matched;
            quote.matched_order_id = Some(order_id.clone());
        }
        let match_id = id_from_record("MATCH-ID", &record.public_record());
        let match_record = OrderMatchRecord {
            match_id: match_id.clone(),
            quote_id: record.request.quote_id.clone(),
            order_id: order_id.clone(),
            signer_ids: record.request.signer_ids.clone(),
            clearing_fee_micronero: record.matched_fee_micronero,
            priority_score: quote_lane.priority_weight() + quote_scheme.security_bits() as u64,
        };
        self.record_public(format!("order:{order_id}"), record.public_record())?;
        self.record_public(format!("match:{match_id}"), match_record.public_record())?;
        self.orders.insert(order_id.clone(), record);
        self.matches.insert(match_id, match_record);
        self.refresh_roots();
        Ok(order_id)
    }

    pub fn commit_threshold_aggregation(
        &mut self,
        record: ThresholdAggregationCommitmentRecord,
    ) -> PrivateL2PqConfidentialPostQuantumSignatureMarketRuntimeResult<()> {
        require_scheme(&self.config, record.scheme)?;
        require(
            self.orders.contains_key(&record.order_id),
            "aggregation order not found",
        )?;
        self.record_public(
            format!("aggregation:{}", record.aggregation_id),
            record.public_record(),
        )?;
        self.threshold_commitments
            .insert(record.aggregation_id.clone(), record);
        self.refresh_roots();
        Ok(())
    }

    pub fn record_bridge_watcher_bid(
        &mut self,
        record: BridgeWatcherSignatureBidRecord,
    ) -> PrivateL2PqConfidentialPostQuantumSignatureMarketRuntimeResult<()> {
        require_scheme(&self.config, record.scheme)?;
        self.record_public(
            format!("bridge_bid:{}", record.bid_id),
            record.public_record(),
        )?;
        self.bridge_watcher_bids
            .insert(record.bid_id.clone(), record);
        self.refresh_roots();
        Ok(())
    }

    pub fn reserve_precompile(
        &mut self,
        record: PrecompileReservationRecord,
    ) -> PrivateL2PqConfidentialPostQuantumSignatureMarketRuntimeResult<()> {
        require(
            self.config.allow_contract_precompile_reservations,
            "precompile reservations disabled",
        )?;
        require(record.reserved_units > 0, "reserved units is zero")?;
        self.record_public(
            format!("precompile:{}", record.reservation_id),
            record.public_record(),
        )?;
        self.precompile_reservations
            .insert(record.reservation_id.clone(), record);
        self.refresh_roots();
        Ok(())
    }

    pub fn mint_low_fee_coupon(
        &mut self,
        record: LowFeeBatchVerificationCouponRecord,
    ) -> PrivateL2PqConfidentialPostQuantumSignatureMarketRuntimeResult<()> {
        require(
            self.config.allow_low_fee_coupons,
            "low fee coupons disabled",
        )?;
        require(
            record.max_fee_micronero <= self.config.low_fee_micronero,
            "coupon exceeds low fee cap",
        )?;
        self.record_public(
            format!("coupon:{}", record.coupon_id),
            record.public_record(),
        )?;
        self.low_fee_coupons
            .insert(record.coupon_id.clone(), record);
        self.refresh_roots();
        Ok(())
    }

    pub fn slash_and_quarantine(
        &mut self,
        record: SlashingQuarantineRecord,
    ) -> PrivateL2PqConfidentialPostQuantumSignatureMarketRuntimeResult<()> {
        let signer = self
            .signer_liquidity
            .get_mut(&record.signer_id)
            .ok_or_else(|| "signer not found for slashing".to_string())?;
        signer.quarantined_until_height = Some(record.quarantine_until_height);
        self.record_public(
            format!("slash:{}", record.action_id),
            record.public_record(),
        )?;
        self.slashing_quarantines
            .insert(record.action_id.clone(), record);
        self.refresh_roots();
        Ok(())
    }

    pub fn refresh_roots(&mut self) {
        self.counters = self.counters();
        self.roots = self.compute_roots();
    }

    pub fn roots(&self) -> Roots {
        self.compute_roots()
    }

    pub fn counters(&self) -> Counters {
        Counters {
            signer_liquidity: self.signer_liquidity.len() as u64,
            quotes: self.quotes.len() as u64,
            orders: self.orders.len() as u64,
            matches: self.matches.len() as u64,
            threshold_commitments: self.threshold_commitments.len() as u64,
            bridge_watcher_bids: self.bridge_watcher_bids.len() as u64,
            precompile_reservations: self.precompile_reservations.len() as u64,
            low_fee_coupons: self.low_fee_coupons.len() as u64,
            slashing_events: self.slashing_quarantines.len() as u64,
            quarantines: self
                .signer_liquidity
                .values()
                .filter(|signer| signer.quarantined_until_height.is_some())
                .count() as u64,
            public_records: self.public_records.len() as u64,
            total_capacity_units: self
                .signer_liquidity
                .values()
                .map(|signer| signer.request.capacity_units as u128)
                .sum(),
            total_fee_micronero: self
                .orders
                .values()
                .map(|order| order.matched_fee_micronero as u128)
                .sum::<u128>()
                + self
                    .bridge_watcher_bids
                    .values()
                    .map(|bid| bid.fee_micronero as u128)
                    .sum::<u128>(),
        }
    }

    pub fn public_record_without_state_root(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "config": self.config.public_record(),
            "counters": self.counters().public_record(),
            "roots": self.roots().public_record(),
            "operator_safe_summary": self.operator_safe_summary_without_state_root().public_record(),
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        record["state_root"] = Value::String(self.state_root());
        record
    }

    pub fn state_root(&self) -> String {
        state_root_from_record(&self.public_record_without_state_root())
    }

    pub fn operator_safe_summary(&self) -> OperatorSafeSummary {
        let mut summary = self.operator_safe_summary_without_state_root();
        summary.state_root = self.state_root();
        summary
    }

    fn operator_safe_summary_without_state_root(&self) -> OperatorSafeSummary {
        let counters = self.counters();
        OperatorSafeSummary {
            state_root: String::new(),
            live_signers: self
                .signer_liquidity
                .values()
                .filter(|signer| signer.quarantined_until_height.is_none())
                .count() as u64,
            live_quotes: self
                .quotes
                .values()
                .filter(|quote| quote.status.live())
                .count() as u64,
            live_orders: self
                .orders
                .values()
                .filter(|order| matches!(order.status, OrderStatus::Open | OrderStatus::Matched))
                .count() as u64,
            average_fee_band_micronero: fee_band(counters.total_fee_micronero, counters.orders),
            pq_security_floor_bits: self.config.min_pq_security_bits,
            public_record_root: self.roots.public_record_root.clone(),
        }
    }

    fn compute_roots(&self) -> Roots {
        Roots {
            config_root: record_root("CONFIG", &self.config.public_record()),
            signer_root: map_root("SIGNERS", &self.signer_liquidity, |record| {
                record.public_record()
            }),
            quote_root: map_root("QUOTES", &self.quotes, |record| record.public_record()),
            order_root: map_root("ORDERS", &self.orders, |record| record.public_record()),
            match_root: map_root("MATCHES", &self.matches, |record| record.public_record()),
            threshold_commitment_root: map_root(
                "THRESHOLD-COMMITMENTS",
                &self.threshold_commitments,
                |record| record.public_record(),
            ),
            bridge_watcher_bid_root: map_root(
                "BRIDGE-WATCHER-BIDS",
                &self.bridge_watcher_bids,
                |record| record.public_record(),
            ),
            precompile_reservation_root: map_root(
                "PRECOMPILE-RESERVATIONS",
                &self.precompile_reservations,
                |record| record.public_record(),
            ),
            low_fee_coupon_root: map_root("LOW-FEE-COUPONS", &self.low_fee_coupons, |record| {
                record.public_record()
            }),
            privacy_redaction_root: map_root(
                "PRIVACY-REDACTIONS",
                &self.privacy_redactions,
                |record| record.public_record(),
            ),
            slashing_root: map_root("SLASHING", &self.slashing_quarantines, |record| {
                record.public_record()
            }),
            quarantine_root: merkle_root(
                "PQ-SIGNATURE-MARKET-QUARANTINES",
                &self
                    .signer_liquidity
                    .values()
                    .filter_map(|signer| {
                        signer.quarantined_until_height.map(|until| {
                            json!({"signer_id": signer.signer_id, "quarantined_until_height": until})
                        })
                    })
                    .collect::<Vec<_>>(),
            ),
            public_record_root: map_value_root("PUBLIC-RECORDS", &self.public_records),
        }
    }

    fn record_public(
        &mut self,
        key: String,
        record: Value,
    ) -> PrivateL2PqConfidentialPostQuantumSignatureMarketRuntimeResult<()> {
        if !self.public_records.contains_key(&key) {
            require(
                self.public_records.len() < self.config.max_public_records,
                "public record capacity reached",
            )?;
        }
        self.public_records.insert(key, record);
        Ok(())
    }
}

pub type Runtime = State;

pub fn devnet() -> State {
    let mut state = State::default();

    let signer_a = state
        .register_signer(SignerLiquidityRequest {
            operator_commitment: sample_commitment("operator", 1),
            signer_key_commitment: sample_commitment("signer-key", 1),
            scheme: SignatureScheme::MlDsa87,
            lanes: BTreeSet::from([
                MarketLane::BridgeWatcher,
                MarketLane::ContractPrecompile,
                MarketLane::BatchVerification,
            ]),
            capacity_units: 50_000,
            min_fee_micronero: 700,
            bond_commitment: sample_commitment("bond", 1),
            privacy_group_root: sample_root("privacy-group", 1),
            pq_attestation_root: sample_root("pq-attestation", 1),
            nonce: "devnet-signer-1".to_string(),
        })
        .expect("devnet signer a");
    let signer_b = state
        .register_signer(SignerLiquidityRequest {
            operator_commitment: sample_commitment("operator", 2),
            signer_key_commitment: sample_commitment("signer-key", 2),
            scheme: SignatureScheme::MlDsa87,
            lanes: BTreeSet::from([MarketLane::BridgeWatcher, MarketLane::DefiSettlement]),
            capacity_units: 36_000,
            min_fee_micronero: 850,
            bond_commitment: sample_commitment("bond", 2),
            privacy_group_root: sample_root("privacy-group", 2),
            pq_attestation_root: sample_root("pq-attestation", 2),
            nonce: "devnet-signer-2".to_string(),
        })
        .expect("devnet signer b");
    let signer_c = state
        .register_signer(SignerLiquidityRequest {
            operator_commitment: sample_commitment("operator", 3),
            signer_key_commitment: sample_commitment("signer-key", 3),
            scheme: SignatureScheme::SlhDsaShake256f,
            lanes: BTreeSet::from([MarketLane::EmergencyRotation, MarketLane::BatchVerification]),
            capacity_units: 18_000,
            min_fee_micronero: 1_200,
            bond_commitment: sample_commitment("bond", 3),
            privacy_group_root: sample_root("privacy-group", 3),
            pq_attestation_root: sample_root("pq-attestation", 3),
            nonce: "devnet-signer-3".to_string(),
        })
        .expect("devnet signer c");

    let quote_id = state
        .post_quote(SignatureQuoteRequest {
            requester_commitment: sample_commitment("requester", 1),
            lane: MarketLane::BridgeWatcher,
            scheme: SignatureScheme::MlDsa87,
            message_root: sample_root("bridge-message", 1),
            max_fee_micronero: 2_400,
            min_signers: 2,
            expires_at_height: DEVNET_HEIGHT + DEFAULT_QUOTE_TTL_BLOCKS,
            privacy_redaction_root: sample_root("quote-redaction", 1),
            nonce: "devnet-quote-1".to_string(),
        })
        .expect("devnet quote");

    let order_id = state
        .place_order(SignatureOrderRequest {
            quote_id,
            signer_ids: vec![signer_a.clone(), signer_b.clone()],
            aggregate_message_root: sample_root("aggregate-message", 1),
            fee_bid_micronero: 1_800,
            settlement_contract: sample_commitment("settlement-contract", 1),
            deadline_height: DEVNET_HEIGHT + DEFAULT_ORDER_TTL_BLOCKS,
            nonce: "devnet-order-1".to_string(),
        })
        .expect("devnet order");

    state
        .commit_threshold_aggregation(ThresholdAggregationCommitmentRecord {
            aggregation_id: sample_id("aggregation", 1),
            order_id,
            participant_root: merkle_root(
                "DEVNET-PQ-SIGNATURE-PARTICIPANTS",
                &[json!(signer_a), json!(signer_b)],
            ),
            partial_signature_root: sample_root("partial-signatures", 1),
            aggregate_signature_commitment: sample_commitment("aggregate-signature", 1),
            threshold: 2,
            scheme: SignatureScheme::MlDsa87,
            privacy_redaction_root: sample_root("aggregation-redaction", 1),
        })
        .expect("devnet aggregation");

    state
        .record_bridge_watcher_bid(BridgeWatcherSignatureBidRecord {
            bid_id: sample_id("bridge-bid", 1),
            watcher_commitment: sample_commitment("watcher", 1),
            bridge_event_root: sample_root("bridge-event", 1),
            scheme: SignatureScheme::MlDsa87,
            fee_micronero: 1_100,
            response_height: DEVNET_HEIGHT + 2,
            redaction_root: sample_root("watcher-redaction", 1),
        })
        .expect("devnet watcher bid");

    state
        .reserve_precompile(PrecompileReservationRecord {
            reservation_id: sample_id("precompile", 1),
            contract_commitment: sample_commitment("contract", 1),
            call_root: sample_root("contract-call", 1),
            lane: MarketLane::ContractPrecompile,
            max_batch_size: 128,
            reserved_units: 4_096,
            fee_cap_micronero: 2_000,
            expires_at_height: DEVNET_HEIGHT + 18,
        })
        .expect("devnet precompile");

    state
        .mint_low_fee_coupon(LowFeeBatchVerificationCouponRecord {
            coupon_id: sample_id("coupon", 1),
            sponsor_commitment: sample_commitment("coupon-sponsor", 1),
            lane: MarketLane::BatchVerification,
            coupon_units: 16_384,
            max_fee_micronero: DEFAULT_LOW_FEE_MICRONERO,
            batch_root: sample_root("coupon-batch", 1),
            expires_at_height: DEVNET_HEIGHT + DEFAULT_COUPON_TTL_BLOCKS,
        })
        .expect("devnet coupon");

    state
        .slash_and_quarantine(SlashingQuarantineRecord {
            action_id: sample_id("slash", 1),
            signer_id: signer_c,
            reason_code: "missed-emergency-rotation-window".to_string(),
            evidence_root: sample_root("slash-evidence", 1),
            slash_amount_commitment: sample_commitment("slash-amount", 1),
            quarantine_until_height: DEVNET_HEIGHT + DEFAULT_QUARANTINE_BLOCKS,
        })
        .expect("devnet slash");

    state.refresh_roots();
    state
}

pub fn demo() -> State {
    devnet()
}

pub fn public_record(state: &State) -> Value {
    state.public_record()
}

pub fn private_l2_pq_confidential_post_quantum_signature_market_runtime_public_record(
    state: &State,
) -> Value {
    state.public_record()
}

pub fn refresh_roots(state: &mut State) {
    state.refresh_roots();
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}

fn require(
    condition: bool,
    message: &str,
) -> PrivateL2PqConfidentialPostQuantumSignatureMarketRuntimeResult<()> {
    if condition {
        Ok(())
    } else {
        Err(message.to_string())
    }
}

fn require_scheme(
    config: &Config,
    scheme: SignatureScheme,
) -> PrivateL2PqConfidentialPostQuantumSignatureMarketRuntimeResult<()> {
    require(
        config.allowed_schemes.contains(&scheme),
        "signature scheme is not enabled",
    )
}

fn state_root_from_record(record: &Value) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-SIGNATURE-MARKET-STATE-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Json(record),
        ],
        32,
    )
}

fn record_root(domain: &str, record: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Json(record),
        ],
        32,
    )
}

fn id_from_record(domain: &str, record: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Json(record),
        ],
        16,
    )
}

fn sample_id(label: &str, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-SIGNATURE-MARKET-SAMPLE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
            HashPart::U64(sequence),
        ],
        16,
    )
}

fn sample_root(label: &str, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-SIGNATURE-MARKET-SAMPLE-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
            HashPart::U64(sequence),
        ],
        32,
    )
}

fn sample_commitment(label: &str, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-SIGNATURE-MARKET-SAMPLE-COMMITMENT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
            HashPart::U64(sequence),
        ],
        32,
    )
}

fn map_root<T, F>(domain: &str, map: &BTreeMap<String, T>, public_record: F) -> String
where
    F: Fn(&T) -> Value,
{
    let records = map
        .iter()
        .map(|(key, value)| json!({ "key": key, "record": public_record(value) }))
        .collect::<Vec<_>>();
    merkle_root(domain, &records)
}

fn map_value_root(domain: &str, map: &BTreeMap<String, Value>) -> String {
    let records = map
        .iter()
        .map(|(key, value)| json!({ "key": key, "record": value }))
        .collect::<Vec<_>>();
    merkle_root(domain, &records)
}

fn fee_band(total_fee_micronero: u128, orders: u64) -> String {
    if orders == 0 {
        return "none".to_string();
    }
    let average = total_fee_micronero / orders as u128;
    if average <= DEFAULT_LOW_FEE_MICRONERO as u128 {
        "low".to_string()
    } else if average <= 5_000 {
        "standard".to_string()
    } else {
        "priority".to_string()
    }
}
