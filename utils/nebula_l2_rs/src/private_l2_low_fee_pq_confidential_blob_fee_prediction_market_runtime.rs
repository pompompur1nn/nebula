use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;

pub type Runtime = State;

pub const PROTOCOL_ID: &str =
    "nebula.private_l2.low_fee_pq.confidential_blob_fee_prediction_market";
pub const VERSION: u32 = 1;
pub const ROOT_DOMAIN: &str = "nebula-low-fee-pq-v1";
pub const RECEIPT_DOMAIN: &str = "confidential-settlement-receipt-v1";
pub const BASIS_POINTS: u64 = 10_000;
pub const MAX_FORECAST_HORIZON_SLOTS: u64 = 8_192;
pub const MAX_BID_AGE_SLOTS: u64 = 512;
pub const MAX_ROUTE_CAP_BPS: u64 = 9_500;
pub const MIN_ROUTE_CAP_BPS: u64 = 100;
pub const MAX_INSURANCE_PREPAYMENT: u64 = 10_000_000_000;
pub const MAX_REBATE_BPS: u64 = 8_000;
pub const MIN_CONFIDENCE_BPS: u64 = 1_000;
pub const MAX_CONFIDENCE_BPS: u64 = BASIS_POINTS;
pub const DEFAULT_BASE_FEE_WEI: u64 = 1_000_000_000;
pub const DEFAULT_BLOB_FEE_WEI: u64 = 2_000_000_000;
pub const DEFAULT_DA_FEE_WEI: u64 = 1_500_000_000;
pub const DEFAULT_PROOF_FEE_WEI: u64 = 350_000_000;
pub const DEFAULT_CALLDATA_FEE_WEI: u64 = 700_000_000;
pub const DEFAULT_SPONSOR_RESERVE: u64 = 25_000_000_000;
pub const DEFAULT_ROUTE_CAP_WEI: u64 = 6_000_000_000;
pub const DEFAULT_INSURANCE_POOL: u64 = 50_000_000_000;
pub const DEFAULT_REBATE_POOL: u64 = 15_000_000_000;
pub const DEFAULT_SETTLEMENT_LIMIT: u64 = 100_000_000_000;
pub const DEFAULT_VOLATILITY_BPS: u64 = 1_250;
pub const DEFAULT_SAFETY_MARGIN_BPS: u64 = 1_100;
pub const DEFAULT_HEDGE_RATIO_BPS: u64 = 6_000;
pub const DEFAULT_REBATE_RATIO_BPS: u64 = 2_500;
pub const DEFAULT_SPONSOR_DISCOUNT_BPS: u64 = 850;
pub const DEFAULT_INSURANCE_PREMIUM_BPS: u64 = 320;
pub const DEFAULT_RECEIPT_MASK: &str = "pq-mask-devnet";
pub const DEFAULT_OPERATOR: &str = "operator.devnet";
pub const DEFAULT_MARKET: &str = "blob-da-low-fee-market";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Config {
    pub protocol_id: String,
    pub version: u32,
    pub market_id: String,
    pub operator_id: String,
    pub base_fee_wei: u64,
    pub blob_fee_wei: u64,
    pub da_fee_wei: u64,
    pub proof_fee_wei: u64,
    pub calldata_fee_wei: u64,
    pub sponsor_reserve_wei: u64,
    pub insurance_pool_wei: u64,
    pub rebate_pool_wei: u64,
    pub settlement_limit_wei: u64,
    pub default_route_cap_wei: u64,
    pub volatility_bps: u64,
    pub safety_margin_bps: u64,
    pub hedge_ratio_bps: u64,
    pub rebate_ratio_bps: u64,
    pub sponsor_discount_bps: u64,
    pub insurance_premium_bps: u64,
    pub receipt_mask: String,
    pub max_forecast_horizon_slots: u64,
    pub max_bid_age_slots: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            protocol_id: PROTOCOL_ID.to_string(),
            version: VERSION,
            market_id: DEFAULT_MARKET.to_string(),
            operator_id: DEFAULT_OPERATOR.to_string(),
            base_fee_wei: DEFAULT_BASE_FEE_WEI,
            blob_fee_wei: DEFAULT_BLOB_FEE_WEI,
            da_fee_wei: DEFAULT_DA_FEE_WEI,
            proof_fee_wei: DEFAULT_PROOF_FEE_WEI,
            calldata_fee_wei: DEFAULT_CALLDATA_FEE_WEI,
            sponsor_reserve_wei: DEFAULT_SPONSOR_RESERVE,
            insurance_pool_wei: DEFAULT_INSURANCE_POOL,
            rebate_pool_wei: DEFAULT_REBATE_POOL,
            settlement_limit_wei: DEFAULT_SETTLEMENT_LIMIT,
            default_route_cap_wei: DEFAULT_ROUTE_CAP_WEI,
            volatility_bps: DEFAULT_VOLATILITY_BPS,
            safety_margin_bps: DEFAULT_SAFETY_MARGIN_BPS,
            hedge_ratio_bps: DEFAULT_HEDGE_RATIO_BPS,
            rebate_ratio_bps: DEFAULT_REBATE_RATIO_BPS,
            sponsor_discount_bps: DEFAULT_SPONSOR_DISCOUNT_BPS,
            insurance_premium_bps: DEFAULT_INSURANCE_PREMIUM_BPS,
            receipt_mask: DEFAULT_RECEIPT_MASK.to_string(),
            max_forecast_horizon_slots: MAX_FORECAST_HORIZON_SLOTS,
            max_bid_age_slots: MAX_BID_AGE_SLOTS,
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Counters {
    pub forecast_requests: u64,
    pub forecast_records: u64,
    pub sponsor_bid_requests: u64,
    pub sponsor_bid_records: u64,
    pub insurance_requests: u64,
    pub insurance_records: u64,
    pub rebate_requests: u64,
    pub rebate_records: u64,
    pub route_cap_requests: u64,
    pub route_cap_records: u64,
    pub settlement_requests: u64,
    pub settlement_records: u64,
    pub rejected_requests: u64,
    pub deterministic_revisions: u64,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Roots {
    pub config_root: String,
    pub forecast_root: String,
    pub sponsor_root: String,
    pub insurance_root: String,
    pub rebate_root: String,
    pub route_root: String,
    pub settlement_root: String,
    pub counter_root: String,
    pub state_root: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ForecastRequest {
    pub request_id: String,
    pub account_id: String,
    pub route_id: String,
    pub start_slot: u64,
    pub horizon_slots: u64,
    pub blob_units: u64,
    pub calldata_bytes: u64,
    pub proof_units: u64,
    pub da_units: u64,
    pub max_fee_wei: u64,
    pub confidence_bps: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ForecastRecord {
    pub forecast_id: String,
    pub request_id: String,
    pub route_id: String,
    pub predicted_blob_fee_wei: u64,
    pub predicted_calldata_fee_wei: u64,
    pub predicted_proof_fee_wei: u64,
    pub predicted_da_fee_wei: u64,
    pub predicted_total_fee_wei: u64,
    pub capped_total_fee_wei: u64,
    pub hedge_notional_wei: u64,
    pub confidence_bps: u64,
    pub root: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SponsorBidRequest {
    pub request_id: String,
    pub sponsor_id: String,
    pub account_id: String,
    pub route_id: String,
    pub forecast_id: String,
    pub bid_slot: u64,
    pub max_sponsored_fee_wei: u64,
    pub discount_bps: u64,
    pub confidentiality_level: u8,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SponsorBidRecord {
    pub bid_id: String,
    pub request_id: String,
    pub sponsor_id: String,
    pub accepted_fee_wei: u64,
    pub sponsored_fee_wei: u64,
    pub discounted_fee_wei: u64,
    pub reserve_after_wei: u64,
    pub expires_slot: u64,
    pub root: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct InsuranceRequest {
    pub request_id: String,
    pub account_id: String,
    pub forecast_id: String,
    pub coverage_limit_wei: u64,
    pub prepaid_amount_wei: u64,
    pub premium_bps: u64,
    pub coverage_slots: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct InsuranceRecord {
    pub policy_id: String,
    pub request_id: String,
    pub forecast_id: String,
    pub covered_fee_wei: u64,
    pub premium_wei: u64,
    pub prepaid_balance_wei: u64,
    pub pool_after_wei: u64,
    pub expires_slot: u64,
    pub root: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RebateRequest {
    pub request_id: String,
    pub account_id: String,
    pub route_id: String,
    pub forecast_id: String,
    pub calldata_bytes: u64,
    pub proof_units: u64,
    pub da_units: u64,
    pub requested_rebate_bps: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RebateRecord {
    pub rebate_id: String,
    pub request_id: String,
    pub calldata_rebate_wei: u64,
    pub proof_rebate_wei: u64,
    pub da_rebate_wei: u64,
    pub total_rebate_wei: u64,
    pub pool_after_wei: u64,
    pub root: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RouteCapRequest {
    pub request_id: String,
    pub route_id: String,
    pub account_id: String,
    pub forecast_id: String,
    pub requested_cap_wei: u64,
    pub cap_bps: u64,
    pub priority_lane: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RouteCapRecord {
    pub cap_id: String,
    pub request_id: String,
    pub route_id: String,
    pub effective_cap_wei: u64,
    pub overage_budget_wei: u64,
    pub priority_lane: bool,
    pub root: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SettlementRequest {
    pub request_id: String,
    pub account_id: String,
    pub route_id: String,
    pub forecast_id: String,
    pub bid_id: String,
    pub policy_id: String,
    pub rebate_id: String,
    pub cap_id: String,
    pub actual_blob_fee_wei: u64,
    pub actual_calldata_fee_wei: u64,
    pub actual_proof_fee_wei: u64,
    pub actual_da_fee_wei: u64,
    pub settlement_nonce: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SettlementRecord {
    pub receipt_id: String,
    pub request_id: String,
    pub account_commitment: String,
    pub route_id: String,
    pub actual_total_fee_wei: u64,
    pub forecast_total_fee_wei: u64,
    pub sponsor_paid_wei: u64,
    pub insurance_paid_wei: u64,
    pub rebate_paid_wei: u64,
    pub user_paid_wei: u64,
    pub route_cap_wei: u64,
    pub confidential_receipt: String,
    pub root: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub current_slot: u64,
    pub sponsor_reserve_wei: u64,
    pub insurance_pool_wei: u64,
    pub rebate_pool_wei: u64,
    pub forecasts: BTreeMap<String, ForecastRecord>,
    pub sponsor_bids: BTreeMap<String, SponsorBidRecord>,
    pub insurance_policies: BTreeMap<String, InsuranceRecord>,
    pub rebates: BTreeMap<String, RebateRecord>,
    pub route_caps: BTreeMap<String, RouteCapRecord>,
    pub settlements: BTreeMap<String, SettlementRecord>,
    pub rejected: Vec<String>,
}

impl Default for State {
    fn default() -> Self {
        Self::new(Config::default())
    }
}

impl State {
    pub fn new(config: Config) -> Self {
        let mut state = Self {
            current_slot: 0,
            sponsor_reserve_wei: config.sponsor_reserve_wei,
            insurance_pool_wei: config.insurance_pool_wei,
            rebate_pool_wei: config.rebate_pool_wei,
            config,
            counters: Counters::default(),
            roots: Roots::default(),
            forecasts: BTreeMap::new(),
            sponsor_bids: BTreeMap::new(),
            insurance_policies: BTreeMap::new(),
            rebates: BTreeMap::new(),
            route_caps: BTreeMap::new(),
            settlements: BTreeMap::new(),
            rejected: Vec::new(),
        };
        state.refresh_roots();
        state
    }

    pub fn devnet() -> Self {
        devnet()
    }

    pub fn demo() -> Self {
        demo()
    }

    pub fn request_forecast(&mut self, request: ForecastRequest) -> Option<ForecastRecord> {
        self.counters.forecast_requests = self.counters.forecast_requests.saturating_add(1);
        if !self.valid_forecast_request(&request) {
            self.reject(&request.request_id);
            return None;
        }
        let predicted_blob_fee_wei = scale_fee(
            self.config.blob_fee_wei,
            request.blob_units,
            request.horizon_slots,
            self.config.volatility_bps,
        );
        let predicted_calldata_fee_wei =
            linear_fee(self.config.calldata_fee_wei, request.calldata_bytes, 1024);
        let predicted_proof_fee_wei = linear_fee(self.config.proof_fee_wei, request.proof_units, 1);
        let predicted_da_fee_wei = linear_fee(self.config.da_fee_wei, request.da_units, 1);
        let predicted_total_fee_wei = predicted_blob_fee_wei
            .saturating_add(predicted_calldata_fee_wei)
            .saturating_add(predicted_proof_fee_wei)
            .saturating_add(predicted_da_fee_wei);
        let capped_total_fee_wei = min_u64(predicted_total_fee_wei, request.max_fee_wei);
        let hedge_notional_wei = bps(capped_total_fee_wei, self.config.hedge_ratio_bps);
        let forecast_id = deterministic_id(
            "forecast",
            &request.request_id,
            self.counters.forecast_records,
        );
        let root = digest_parts(&[
            ROOT_DOMAIN,
            "forecast",
            &forecast_id,
            &request.route_id,
            &predicted_total_fee_wei.to_string(),
            &capped_total_fee_wei.to_string(),
            &hedge_notional_wei.to_string(),
        ]);
        let record = ForecastRecord {
            forecast_id: forecast_id.clone(),
            request_id: request.request_id,
            route_id: request.route_id,
            predicted_blob_fee_wei,
            predicted_calldata_fee_wei,
            predicted_proof_fee_wei,
            predicted_da_fee_wei,
            predicted_total_fee_wei,
            capped_total_fee_wei,
            hedge_notional_wei,
            confidence_bps: clamp(
                request.confidence_bps,
                MIN_CONFIDENCE_BPS,
                MAX_CONFIDENCE_BPS,
            ),
            root,
        };
        self.forecasts.insert(forecast_id, record.clone());
        self.counters.forecast_records = self.counters.forecast_records.saturating_add(1);
        self.refresh_roots();
        Some(record)
    }

    pub fn record_sponsor_bid(&mut self, request: SponsorBidRequest) -> Option<SponsorBidRecord> {
        self.counters.sponsor_bid_requests = self.counters.sponsor_bid_requests.saturating_add(1);
        let forecast = match self.forecasts.get(&request.forecast_id) {
            Some(record) => record.clone(),
            None => {
                self.reject(&request.request_id);
                return None;
            }
        };
        if !self.valid_sponsor_bid_request(&request) {
            self.reject(&request.request_id);
            return None;
        }
        let accepted_fee_wei =
            min_u64(forecast.capped_total_fee_wei, request.max_sponsored_fee_wei);
        let discount_bps = clamp(request.discount_bps, 0, BASIS_POINTS);
        let discounted_fee_wei =
            accepted_fee_wei.saturating_sub(bps(accepted_fee_wei, discount_bps));
        let sponsored_fee_wei = min_u64(discounted_fee_wei, self.sponsor_reserve_wei);
        self.sponsor_reserve_wei = self.sponsor_reserve_wei.saturating_sub(sponsored_fee_wei);
        let bid_id = deterministic_id(
            "sponsor-bid",
            &request.request_id,
            self.counters.sponsor_bid_records,
        );
        let expires_slot = request
            .bid_slot
            .saturating_add(self.config.max_bid_age_slots);
        let root = digest_parts(&[
            ROOT_DOMAIN,
            "sponsor",
            &bid_id,
            &request.sponsor_id,
            &sponsored_fee_wei.to_string(),
            &self.sponsor_reserve_wei.to_string(),
        ]);
        let record = SponsorBidRecord {
            bid_id: bid_id.clone(),
            request_id: request.request_id,
            sponsor_id: request.sponsor_id,
            accepted_fee_wei,
            sponsored_fee_wei,
            discounted_fee_wei,
            reserve_after_wei: self.sponsor_reserve_wei,
            expires_slot,
            root,
        };
        self.sponsor_bids.insert(bid_id, record.clone());
        self.counters.sponsor_bid_records = self.counters.sponsor_bid_records.saturating_add(1);
        self.refresh_roots();
        Some(record)
    }

    pub fn record_insurance(&mut self, request: InsuranceRequest) -> Option<InsuranceRecord> {
        self.counters.insurance_requests = self.counters.insurance_requests.saturating_add(1);
        let forecast = match self.forecasts.get(&request.forecast_id) {
            Some(record) => record.clone(),
            None => {
                self.reject(&request.request_id);
                return None;
            }
        };
        if !self.valid_insurance_request(&request) {
            self.reject(&request.request_id);
            return None;
        }
        let covered_fee_wei = min_u64(request.coverage_limit_wei, forecast.capped_total_fee_wei);
        let premium_wei = bps(covered_fee_wei, clamp(request.premium_bps, 1, BASIS_POINTS));
        let prepaid_balance_wei = request.prepaid_amount_wei.saturating_sub(premium_wei);
        self.insurance_pool_wei = self.insurance_pool_wei.saturating_add(premium_wei);
        let policy_id = deterministic_id(
            "policy",
            &request.request_id,
            self.counters.insurance_records,
        );
        let expires_slot = self.current_slot.saturating_add(request.coverage_slots);
        let root = digest_parts(&[
            ROOT_DOMAIN,
            "insurance",
            &policy_id,
            &request.forecast_id,
            &covered_fee_wei.to_string(),
            &premium_wei.to_string(),
            &self.insurance_pool_wei.to_string(),
        ]);
        let record = InsuranceRecord {
            policy_id: policy_id.clone(),
            request_id: request.request_id,
            forecast_id: request.forecast_id,
            covered_fee_wei,
            premium_wei,
            prepaid_balance_wei,
            pool_after_wei: self.insurance_pool_wei,
            expires_slot,
            root,
        };
        self.insurance_policies.insert(policy_id, record.clone());
        self.counters.insurance_records = self.counters.insurance_records.saturating_add(1);
        self.refresh_roots();
        Some(record)
    }

    pub fn record_rebate(&mut self, request: RebateRequest) -> Option<RebateRecord> {
        self.counters.rebate_requests = self.counters.rebate_requests.saturating_add(1);
        if !self.forecasts.contains_key(&request.forecast_id)
            || !self.valid_rebate_request(&request)
        {
            self.reject(&request.request_id);
            return None;
        }
        let rebate_bps = clamp(request.requested_rebate_bps, 0, MAX_REBATE_BPS);
        let calldata_rebate_wei = bps(
            linear_fee(self.config.calldata_fee_wei, request.calldata_bytes, 1024),
            rebate_bps,
        );
        let proof_rebate_wei = bps(
            linear_fee(self.config.proof_fee_wei, request.proof_units, 1),
            rebate_bps,
        );
        let da_rebate_wei = bps(
            linear_fee(self.config.da_fee_wei, request.da_units, 1),
            rebate_bps,
        );
        let requested_total = calldata_rebate_wei
            .saturating_add(proof_rebate_wei)
            .saturating_add(da_rebate_wei);
        let total_rebate_wei = min_u64(requested_total, self.rebate_pool_wei);
        self.rebate_pool_wei = self.rebate_pool_wei.saturating_sub(total_rebate_wei);
        let rebate_id =
            deterministic_id("rebate", &request.request_id, self.counters.rebate_records);
        let root = digest_parts(&[
            ROOT_DOMAIN,
            "rebate",
            &rebate_id,
            &request.route_id,
            &total_rebate_wei.to_string(),
            &self.rebate_pool_wei.to_string(),
        ]);
        let record = RebateRecord {
            rebate_id: rebate_id.clone(),
            request_id: request.request_id,
            calldata_rebate_wei,
            proof_rebate_wei,
            da_rebate_wei,
            total_rebate_wei,
            pool_after_wei: self.rebate_pool_wei,
            root,
        };
        self.rebates.insert(rebate_id, record.clone());
        self.counters.rebate_records = self.counters.rebate_records.saturating_add(1);
        self.refresh_roots();
        Some(record)
    }

    pub fn record_route_cap(&mut self, request: RouteCapRequest) -> Option<RouteCapRecord> {
        self.counters.route_cap_requests = self.counters.route_cap_requests.saturating_add(1);
        let forecast = match self.forecasts.get(&request.forecast_id) {
            Some(record) => record.clone(),
            None => {
                self.reject(&request.request_id);
                return None;
            }
        };
        if !self.valid_route_cap_request(&request) {
            self.reject(&request.request_id);
            return None;
        }
        let capped_by_bps = bps(
            forecast.capped_total_fee_wei,
            clamp(request.cap_bps, MIN_ROUTE_CAP_BPS, MAX_ROUTE_CAP_BPS),
        );
        let capped_by_request =
            min_u64(request.requested_cap_wei, self.config.default_route_cap_wei);
        let effective_cap_wei = max_u64(capped_by_bps, capped_by_request);
        let overage_budget_wei = forecast
            .capped_total_fee_wei
            .saturating_sub(effective_cap_wei);
        let cap_id = deterministic_id(
            "route-cap",
            &request.request_id,
            self.counters.route_cap_records,
        );
        let root = digest_parts(&[
            ROOT_DOMAIN,
            "route-cap",
            &cap_id,
            &request.route_id,
            &effective_cap_wei.to_string(),
            &overage_budget_wei.to_string(),
        ]);
        let record = RouteCapRecord {
            cap_id: cap_id.clone(),
            request_id: request.request_id,
            route_id: request.route_id,
            effective_cap_wei,
            overage_budget_wei,
            priority_lane: request.priority_lane,
            root,
        };
        self.route_caps.insert(cap_id, record.clone());
        self.counters.route_cap_records = self.counters.route_cap_records.saturating_add(1);
        self.refresh_roots();
        Some(record)
    }

    pub fn record_settlement(&mut self, request: SettlementRequest) -> Option<SettlementRecord> {
        self.counters.settlement_requests = self.counters.settlement_requests.saturating_add(1);
        let forecast = match self.forecasts.get(&request.forecast_id) {
            Some(record) => record.clone(),
            None => {
                self.reject(&request.request_id);
                return None;
            }
        };
        let bid = match self.sponsor_bids.get(&request.bid_id) {
            Some(record) => record.clone(),
            None => {
                self.reject(&request.request_id);
                return None;
            }
        };
        let policy = match self.insurance_policies.get(&request.policy_id) {
            Some(record) => record.clone(),
            None => {
                self.reject(&request.request_id);
                return None;
            }
        };
        let rebate = match self.rebates.get(&request.rebate_id) {
            Some(record) => record.clone(),
            None => {
                self.reject(&request.request_id);
                return None;
            }
        };
        let cap = match self.route_caps.get(&request.cap_id) {
            Some(record) => record.clone(),
            None => {
                self.reject(&request.request_id);
                return None;
            }
        };
        let actual_total_fee_wei = request
            .actual_blob_fee_wei
            .saturating_add(request.actual_calldata_fee_wei)
            .saturating_add(request.actual_proof_fee_wei)
            .saturating_add(request.actual_da_fee_wei);
        if actual_total_fee_wei > self.config.settlement_limit_wei {
            self.reject(&request.request_id);
            return None;
        }
        let sponsor_paid_wei = min_u64(actual_total_fee_wei, bid.sponsored_fee_wei);
        let after_sponsor = actual_total_fee_wei.saturating_sub(sponsor_paid_wei);
        let over_forecast = actual_total_fee_wei.saturating_sub(forecast.capped_total_fee_wei);
        let insurance_paid_wei = min_u64(
            min_u64(over_forecast, policy.covered_fee_wei),
            self.insurance_pool_wei,
        );
        self.insurance_pool_wei = self.insurance_pool_wei.saturating_sub(insurance_paid_wei);
        let after_insurance = after_sponsor.saturating_sub(insurance_paid_wei);
        let rebate_paid_wei = min_u64(after_insurance, rebate.total_rebate_wei);
        let after_rebate = after_insurance.saturating_sub(rebate_paid_wei);
        let user_paid_wei = min_u64(after_rebate, cap.effective_cap_wei);
        let receipt_id = deterministic_id(
            "receipt",
            &request.request_id,
            self.counters.settlement_records,
        );
        let account_commitment = digest_parts(&[
            RECEIPT_DOMAIN,
            &self.config.receipt_mask,
            &request.account_id,
            &request.settlement_nonce.to_string(),
        ]);
        let confidential_receipt = digest_parts(&[
            RECEIPT_DOMAIN,
            &receipt_id,
            &account_commitment,
            &actual_total_fee_wei.to_string(),
            &sponsor_paid_wei.to_string(),
            &insurance_paid_wei.to_string(),
            &rebate_paid_wei.to_string(),
            &user_paid_wei.to_string(),
        ]);
        let root = digest_parts(&[
            ROOT_DOMAIN,
            "settlement",
            &receipt_id,
            &request.route_id,
            &confidential_receipt,
        ]);
        let record = SettlementRecord {
            receipt_id: receipt_id.clone(),
            request_id: request.request_id,
            account_commitment,
            route_id: request.route_id,
            actual_total_fee_wei,
            forecast_total_fee_wei: forecast.capped_total_fee_wei,
            sponsor_paid_wei,
            insurance_paid_wei,
            rebate_paid_wei,
            user_paid_wei,
            route_cap_wei: cap.effective_cap_wei,
            confidential_receipt,
            root,
        };
        self.settlements.insert(receipt_id, record.clone());
        self.counters.settlement_records = self.counters.settlement_records.saturating_add(1);
        self.refresh_roots();
        Some(record)
    }

    pub fn advance_slot(&mut self, slots: u64) {
        self.current_slot = self.current_slot.saturating_add(slots);
        self.counters.deterministic_revisions =
            self.counters.deterministic_revisions.saturating_add(1);
        self.refresh_roots();
    }

    pub fn public_record(&self) -> Value {
        public_record(self)
    }

    pub fn state_root(&self) -> String {
        self.roots.state_root.clone()
    }

    fn valid_forecast_request(&self, request: &ForecastRequest) -> bool {
        !request.request_id.is_empty()
            && !request.account_id.is_empty()
            && !request.route_id.is_empty()
            && request.horizon_slots > 0
            && request.horizon_slots <= self.config.max_forecast_horizon_slots
            && request.max_fee_wei > 0
            && request.confidence_bps >= MIN_CONFIDENCE_BPS
            && request.confidence_bps <= MAX_CONFIDENCE_BPS
    }

    fn valid_sponsor_bid_request(&self, request: &SponsorBidRequest) -> bool {
        !request.request_id.is_empty()
            && !request.sponsor_id.is_empty()
            && !request.account_id.is_empty()
            && !request.route_id.is_empty()
            && !request.forecast_id.is_empty()
            && request.max_sponsored_fee_wei > 0
            && request.discount_bps <= BASIS_POINTS
            && request.confidentiality_level <= 10
    }

    fn valid_insurance_request(&self, request: &InsuranceRequest) -> bool {
        !request.request_id.is_empty()
            && !request.account_id.is_empty()
            && !request.forecast_id.is_empty()
            && request.coverage_limit_wei > 0
            && request.prepaid_amount_wei <= MAX_INSURANCE_PREPAYMENT
            && request.premium_bps > 0
            && request.premium_bps <= BASIS_POINTS
            && request.coverage_slots > 0
    }

    fn valid_rebate_request(&self, request: &RebateRequest) -> bool {
        !request.request_id.is_empty()
            && !request.account_id.is_empty()
            && !request.route_id.is_empty()
            && !request.forecast_id.is_empty()
            && request.requested_rebate_bps <= MAX_REBATE_BPS
    }

    fn valid_route_cap_request(&self, request: &RouteCapRequest) -> bool {
        !request.request_id.is_empty()
            && !request.route_id.is_empty()
            && !request.account_id.is_empty()
            && !request.forecast_id.is_empty()
            && request.requested_cap_wei > 0
            && request.cap_bps >= MIN_ROUTE_CAP_BPS
            && request.cap_bps <= MAX_ROUTE_CAP_BPS
    }

    fn reject(&mut self, request_id: &str) {
        self.counters.rejected_requests = self.counters.rejected_requests.saturating_add(1);
        self.rejected.push(request_id.to_string());
        self.refresh_roots();
    }

    fn refresh_roots(&mut self) {
        self.roots.config_root = config_root(&self.config);
        self.roots.forecast_root = map_root("forecasts", &self.forecasts);
        self.roots.sponsor_root = map_root("sponsors", &self.sponsor_bids);
        self.roots.insurance_root = map_root("insurance", &self.insurance_policies);
        self.roots.rebate_root = map_root("rebates", &self.rebates);
        self.roots.route_root = map_root("routes", &self.route_caps);
        self.roots.settlement_root = map_root("settlements", &self.settlements);
        self.roots.counter_root = digest_parts(&[
            ROOT_DOMAIN,
            "counters",
            &self.counters.forecast_requests.to_string(),
            &self.counters.forecast_records.to_string(),
            &self.counters.sponsor_bid_requests.to_string(),
            &self.counters.sponsor_bid_records.to_string(),
            &self.counters.insurance_requests.to_string(),
            &self.counters.insurance_records.to_string(),
            &self.counters.rebate_requests.to_string(),
            &self.counters.rebate_records.to_string(),
            &self.counters.route_cap_requests.to_string(),
            &self.counters.route_cap_records.to_string(),
            &self.counters.settlement_requests.to_string(),
            &self.counters.settlement_records.to_string(),
            &self.counters.rejected_requests.to_string(),
            &self.counters.deterministic_revisions.to_string(),
        ]);
        self.roots.state_root = digest_parts(&[
            ROOT_DOMAIN,
            "state",
            &self.roots.config_root,
            &self.roots.forecast_root,
            &self.roots.sponsor_root,
            &self.roots.insurance_root,
            &self.roots.rebate_root,
            &self.roots.route_root,
            &self.roots.settlement_root,
            &self.roots.counter_root,
            &self.current_slot.to_string(),
            &self.sponsor_reserve_wei.to_string(),
            &self.insurance_pool_wei.to_string(),
            &self.rebate_pool_wei.to_string(),
        ]);
    }
}

pub fn devnet() -> State {
    State::new(Config::default())
}

pub fn demo() -> State {
    let mut state = devnet();
    let forecast = match state.request_forecast(ForecastRequest {
        request_id: "forecast.demo.0".to_string(),
        account_id: "account.demo.low-fee".to_string(),
        route_id: "route.blob-da.optimism".to_string(),
        start_slot: 1,
        horizon_slots: 64,
        blob_units: 2,
        calldata_bytes: 4096,
        proof_units: 1,
        da_units: 3,
        max_fee_wei: 9_500_000_000,
        confidence_bps: 8_700,
    }) {
        Some(record) => record,
        None => return state,
    };
    let bid = match state.record_sponsor_bid(SponsorBidRequest {
        request_id: "bid.demo.0".to_string(),
        sponsor_id: "sponsor.demo".to_string(),
        account_id: "account.demo.low-fee".to_string(),
        route_id: forecast.route_id.clone(),
        forecast_id: forecast.forecast_id.clone(),
        bid_slot: 2,
        max_sponsored_fee_wei: 5_000_000_000,
        discount_bps: state.config.sponsor_discount_bps,
        confidentiality_level: 7,
    }) {
        Some(record) => record,
        None => return state,
    };
    let policy = match state.record_insurance(InsuranceRequest {
        request_id: "policy.demo.0".to_string(),
        account_id: "account.demo.low-fee".to_string(),
        forecast_id: forecast.forecast_id.clone(),
        coverage_limit_wei: 3_000_000_000,
        prepaid_amount_wei: 600_000_000,
        premium_bps: state.config.insurance_premium_bps,
        coverage_slots: 256,
    }) {
        Some(record) => record,
        None => return state,
    };
    let rebate = match state.record_rebate(RebateRequest {
        request_id: "rebate.demo.0".to_string(),
        account_id: "account.demo.low-fee".to_string(),
        route_id: forecast.route_id.clone(),
        forecast_id: forecast.forecast_id.clone(),
        calldata_bytes: 4096,
        proof_units: 1,
        da_units: 3,
        requested_rebate_bps: state.config.rebate_ratio_bps,
    }) {
        Some(record) => record,
        None => return state,
    };
    let cap = match state.record_route_cap(RouteCapRequest {
        request_id: "cap.demo.0".to_string(),
        route_id: forecast.route_id.clone(),
        account_id: "account.demo.low-fee".to_string(),
        forecast_id: forecast.forecast_id.clone(),
        requested_cap_wei: 4_000_000_000,
        cap_bps: 7_500,
        priority_lane: true,
    }) {
        Some(record) => record,
        None => return state,
    };
    let _settlement = state.record_settlement(SettlementRequest {
        request_id: "settlement.demo.0".to_string(),
        account_id: "account.demo.low-fee".to_string(),
        route_id: forecast.route_id,
        forecast_id: forecast.forecast_id,
        bid_id: bid.bid_id,
        policy_id: policy.policy_id,
        rebate_id: rebate.rebate_id,
        cap_id: cap.cap_id,
        actual_blob_fee_wei: 2_600_000_000,
        actual_calldata_fee_wei: 800_000_000,
        actual_proof_fee_wei: 350_000_000,
        actual_da_fee_wei: 1_800_000_000,
        settlement_nonce: 42,
    });
    state
}

pub fn public_record(state: &State) -> Value {
    json!({
        "protocol_id": state.config.protocol_id,
        "version": state.config.version,
        "market_id": state.config.market_id,
        "operator_id": state.config.operator_id,
        "current_slot": state.current_slot,
        "liquidity": {
            "sponsor_reserve_wei": state.sponsor_reserve_wei,
            "insurance_pool_wei": state.insurance_pool_wei,
            "rebate_pool_wei": state.rebate_pool_wei
        },
        "counters": state.counters,
        "roots": state.roots,
        "forecast_count": state.forecasts.len(),
        "sponsor_bid_count": state.sponsor_bids.len(),
        "insurance_policy_count": state.insurance_policies.len(),
        "rebate_count": state.rebates.len(),
        "route_cap_count": state.route_caps.len(),
        "settlement_count": state.settlements.len(),
        "rejected_count": state.rejected.len()
    })
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}

fn config_root(config: &Config) -> String {
    digest_parts(&[
        ROOT_DOMAIN,
        "config",
        &config.protocol_id,
        &config.version.to_string(),
        &config.market_id,
        &config.operator_id,
        &config.base_fee_wei.to_string(),
        &config.blob_fee_wei.to_string(),
        &config.da_fee_wei.to_string(),
        &config.proof_fee_wei.to_string(),
        &config.calldata_fee_wei.to_string(),
        &config.sponsor_reserve_wei.to_string(),
        &config.insurance_pool_wei.to_string(),
        &config.rebate_pool_wei.to_string(),
        &config.settlement_limit_wei.to_string(),
        &config.default_route_cap_wei.to_string(),
        &config.volatility_bps.to_string(),
        &config.safety_margin_bps.to_string(),
        &config.hedge_ratio_bps.to_string(),
        &config.rebate_ratio_bps.to_string(),
        &config.sponsor_discount_bps.to_string(),
        &config.insurance_premium_bps.to_string(),
        &config.receipt_mask,
        &config.max_forecast_horizon_slots.to_string(),
        &config.max_bid_age_slots.to_string(),
    ])
}

fn map_root<T: Serialize>(label: &str, map: &BTreeMap<String, T>) -> String {
    let mut acc = digest_parts(&[ROOT_DOMAIN, label, &map.len().to_string()]);
    for (key, value) in map {
        let encoded = stable_json(value);
        acc = digest_parts(&[ROOT_DOMAIN, label, &acc, key, &encoded]);
    }
    acc
}

fn stable_json<T: Serialize>(value: &T) -> String {
    match serde_json::to_value(value) {
        Ok(json_value) => canonical_value(&json_value),
        Err(_err) => "serialization-error".to_string(),
    }
}

fn canonical_value(value: &Value) -> String {
    match value {
        Value::Null => "null".to_string(),
        Value::Bool(v) => {
            if *v {
                "true".to_string()
            } else {
                "false".to_string()
            }
        }
        Value::Number(v) => v.to_string(),
        Value::String(v) => format!("{:?}", v),
        Value::Array(values) => {
            let mut out = String::from("[");
            let mut first = true;
            for item in values {
                if !first {
                    out.push(',');
                }
                first = false;
                out.push_str(&canonical_value(item));
            }
            out.push(']');
            out
        }
        Value::Object(values) => {
            let mut out = String::from("{");
            let mut first = true;
            for (key, item) in values {
                if !first {
                    out.push(',');
                }
                first = false;
                out.push_str(&format!("{:?}", key));
                out.push(':');
                out.push_str(&canonical_value(item));
            }
            out.push('}');
            out
        }
    }
}

fn deterministic_id(kind: &str, request_id: &str, counter: u64) -> String {
    let digest = digest_parts(&[ROOT_DOMAIN, kind, request_id, &counter.to_string()]);
    format!("{}-{}", kind, &digest[0..24])
}

fn digest_parts(parts: &[&str]) -> String {
    let mut a: u64 = 0x243f_6a88_85a3_08d3;
    let mut b: u64 = 0x1319_8a2e_0370_7344;
    let mut c: u64 = 0xa409_3822_299f_31d0;
    let mut d: u64 = 0x082e_fa98_ec4e_6c89;
    for part in parts {
        for byte in part.as_bytes() {
            a = a.rotate_left(5) ^ u64::from(*byte);
            b = b.wrapping_add(a ^ 0x9e37_79b9_7f4a_7c15);
            c ^= b.rotate_left(17).wrapping_mul(0x1000_0000_01b3);
            d = d.wrapping_add(c ^ a.rotate_right(11));
        }
        a ^= 0xff;
        b = b.rotate_left(13);
        c = c.wrapping_add(0x517c_c1b7_2722_0a95);
        d ^= b.rotate_right(7);
    }
    format!("{:016x}{:016x}{:016x}{:016x}", a, b, c, d)
}

fn scale_fee(base_fee: u64, units: u64, horizon_slots: u64, volatility_bps: u64) -> u64 {
    let horizon_factor = BASIS_POINTS
        .saturating_add(min_u64(horizon_slots, MAX_FORECAST_HORIZON_SLOTS).saturating_mul(3));
    let volatility_factor = BASIS_POINTS.saturating_add(volatility_bps);
    let unit_fee = base_fee.saturating_mul(units);
    bps(bps(unit_fee, horizon_factor), volatility_factor)
}

fn linear_fee(base_fee: u64, units: u64, divisor: u64) -> u64 {
    let safe_divisor = max_u64(divisor, 1);
    let scaled_units = units.saturating_add(safe_divisor.saturating_sub(1)) / safe_divisor;
    base_fee.saturating_mul(max_u64(scaled_units, 1))
}

fn bps(amount: u64, points: u64) -> u64 {
    amount.saturating_mul(points) / BASIS_POINTS
}

fn clamp(value: u64, low: u64, high: u64) -> u64 {
    min_u64(max_u64(value, low), high)
}

fn min_u64(left: u64, right: u64) -> u64 {
    if left < right {
        left
    } else {
        right
    }
}

fn max_u64(left: u64, right: u64) -> u64 {
    if left > right {
        left
    } else {
        right
    }
}

pub const FEE_BUCKET_0000: u64 = 1_000_000_000;
pub const FEE_BUCKET_0001: u64 = 1_017_000_000;
pub const FEE_BUCKET_0002: u64 = 1_034_289_000;
pub const FEE_BUCKET_0003: u64 = 1_051_871_913;
pub const FEE_BUCKET_0004: u64 = 1_069_753_735;
pub const FEE_BUCKET_0005: u64 = 1_087_939_548;
pub const FEE_BUCKET_0006: u64 = 1_106_434_520;
pub const FEE_BUCKET_0007: u64 = 1_125_243_906;
pub const FEE_BUCKET_0008: u64 = 1_144_373_052;
pub const FEE_BUCKET_0009: u64 = 1_163_827_393;
pub const FEE_BUCKET_0010: u64 = 1_183_612_459;
pub const FEE_BUCKET_0011: u64 = 1_203_733_871;
pub const FEE_BUCKET_0012: u64 = 1_224_197_347;
pub const FEE_BUCKET_0013: u64 = 1_245_008_702;
pub const FEE_BUCKET_0014: u64 = 1_266_173_850;
pub const FEE_BUCKET_0015: u64 = 1_287_698_806;
pub const FEE_BUCKET_0016: u64 = 1_309_589_685;
pub const FEE_BUCKET_0017: u64 = 1_331_852_709;
pub const FEE_BUCKET_0018: u64 = 1_354_494_205;
pub const FEE_BUCKET_0019: u64 = 1_377_520_606;
pub const FEE_BUCKET_0020: u64 = 1_400_938_456;
pub const FEE_BUCKET_0021: u64 = 1_424_754_409;
pub const FEE_BUCKET_0022: u64 = 1_448_975_734;
pub const FEE_BUCKET_0023: u64 = 1_473_609_321;
pub const FEE_BUCKET_0024: u64 = 1_498_662_679;
pub const FEE_BUCKET_0025: u64 = 1_524_143_942;
pub const FEE_BUCKET_0026: u64 = 1_550_061_389;
pub const FEE_BUCKET_0027: u64 = 1_576_423_433;
pub const FEE_BUCKET_0028: u64 = 1_603_238_631;
pub const FEE_BUCKET_0029: u64 = 1_630_515_687;
pub const FEE_BUCKET_0030: u64 = 1_658_263_454;
pub const FEE_BUCKET_0031: u64 = 1_686_490_933;
pub const FEE_BUCKET_0032: u64 = 1_715_207_279;
pub const FEE_BUCKET_0033: u64 = 1_744_421_802;
pub const FEE_BUCKET_0034: u64 = 1_774_143_972;
pub const FEE_BUCKET_0035: u64 = 1_804_383_419;
pub const FEE_BUCKET_0036: u64 = 1_835_149_937;
pub const FEE_BUCKET_0037: u64 = 1_866_453_486;
pub const FEE_BUCKET_0038: u64 = 1_898_304_196;
pub const FEE_BUCKET_0039: u64 = 1_930_712_376;
pub const FEE_BUCKET_0040: u64 = 1_963_688_516;
pub const FEE_BUCKET_0041: u64 = 1_997_243_220;
pub const FEE_BUCKET_0042: u64 = 2_031_387_354;
pub const FEE_BUCKET_0043: u64 = 2_066_132_986;
pub const FEE_BUCKET_0044: u64 = 2_101_491_438;
pub const FEE_BUCKET_0045: u64 = 2_137_474_270;
pub const FEE_BUCKET_0046: u64 = 2_174_093_299;
pub const FEE_BUCKET_0047: u64 = 2_211_360_597;
pub const FEE_BUCKET_0048: u64 = 2_249_288_496;
pub const FEE_BUCKET_0049: u64 = 2_287_889_594;
pub const FEE_BUCKET_0050: u64 = 2_327_176_759;
pub const FEE_BUCKET_0051: u64 = 2_367_163_133;
pub const FEE_BUCKET_0052: u64 = 2_407_862_136;
pub const FEE_BUCKET_0053: u64 = 2_449_287_466;
pub const FEE_BUCKET_0054: u64 = 2_491_453_103;
pub const FEE_BUCKET_0055: u64 = 2_534_373_314;
pub const FEE_BUCKET_0056: u64 = 2_578_062_653;
pub const FEE_BUCKET_0057: u64 = 2_622_535_972;
pub const FEE_BUCKET_0058: u64 = 2_667_808_433;
pub const FEE_BUCKET_0059: u64 = 2_713_895_512;
pub const FEE_BUCKET_0060: u64 = 2_760_813_005;
pub const FEE_BUCKET_0061: u64 = 2_808_577_037;
pub const FEE_BUCKET_0062: u64 = 2_857_204_064;
pub const FEE_BUCKET_0063: u64 = 2_906_711_875;
pub const FEE_BUCKET_0064: u64 = 2_957_118_602;
pub const FEE_BUCKET_0065: u64 = 3_008_442_722;
pub const FEE_BUCKET_0066: u64 = 3_060_703_058;
pub const FEE_BUCKET_0067: u64 = 3_113_918_787;
pub const FEE_BUCKET_0068: u64 = 3_168_109_437;
pub const FEE_BUCKET_0069: u64 = 3_223_294_899;
pub const FEE_BUCKET_0070: u64 = 3_279_495_427;
pub const FEE_BUCKET_0071: u64 = 3_336_731_651;
pub const FEE_BUCKET_0072: u64 = 3_395_024_585;
pub const FEE_BUCKET_0073: u64 = 3_454_395_626;
pub const FEE_BUCKET_0074: u64 = 3_514_866_561;
pub const FEE_BUCKET_0075: u64 = 3_576_459_577;
pub const FEE_BUCKET_0076: u64 = 3_639_197_265;
pub const FEE_BUCKET_0077: u64 = 3_703_102_624;
pub const FEE_BUCKET_0078: u64 = 3_768_198_069;
pub const FEE_BUCKET_0079: u64 = 3_834_506_437;
pub const FEE_BUCKET_0080: u64 = 3_902_051_989;
pub const FEE_BUCKET_0081: u64 = 3_970_859_422;
pub const FEE_BUCKET_0082: u64 = 4_040_953_867;
pub const FEE_BUCKET_0083: u64 = 4_112_360_894;
pub const FEE_BUCKET_0084: u64 = 4_185_106_516;
pub const FEE_BUCKET_0085: u64 = 4_259_217_200;
pub const FEE_BUCKET_0086: u64 = 4_334_719_870;
pub const FEE_BUCKET_0087: u64 = 4_411_641_922;
pub const FEE_BUCKET_0088: u64 = 4_490_011_223;
pub const FEE_BUCKET_0089: u64 = 4_569_856_119;
pub const FEE_BUCKET_0090: u64 = 4_651_205_445;
pub const FEE_BUCKET_0091: u64 = 4_734_088_523;
pub const FEE_BUCKET_0092: u64 = 4_818_535_173;
pub const FEE_BUCKET_0093: u64 = 4_904_575_721;
pub const FEE_BUCKET_0094: u64 = 4_992_240_999;
pub const FEE_BUCKET_0095: u64 = 5_081_562_355;
pub const FEE_BUCKET_0096: u64 = 5_172_571_653;
pub const FEE_BUCKET_0097: u64 = 5_265_301_281;
pub const FEE_BUCKET_0098: u64 = 5_359_784_158;
pub const FEE_BUCKET_0099: u64 = 5_456_053_740;
pub const FEE_BUCKET_0100: u64 = 5_554_144_027;
pub const FEE_BUCKET_0101: u64 = 5_654_089_570;
pub const FEE_BUCKET_0102: u64 = 5_755_925_092;
pub const FEE_BUCKET_0103: u64 = 5_859_685_818;
pub const FEE_BUCKET_0104: u64 = 5_965_407_252;
pub const FEE_BUCKET_0105: u64 = 6_073_125_175;
pub const FEE_BUCKET_0106: u64 = 6_182_875_303;
pub const FEE_BUCKET_0107: u64 = 6_294_693_783;
pub const FEE_BUCKET_0108: u64 = 6_408_617_606;
pub const FEE_BUCKET_0109: u64 = 6_524_684_106;
pub const FEE_BUCKET_0110: u64 = 6_642_931_736;
pub const FEE_BUCKET_0111: u64 = 6_763_399_413;
pub const FEE_BUCKET_0112: u64 = 6_886_126_200;
pub const FEE_BUCKET_0113: u64 = 7_011_151_436;
pub const FEE_BUCKET_0114: u64 = 7_138_514_717;
pub const FEE_BUCKET_0115: u64 = 7_268_255_972;
pub const FEE_BUCKET_0116: u64 = 7_400_415_457;
pub const FEE_BUCKET_0117: u64 = 7_535_033_805;
pub const FEE_BUCKET_0118: u64 = 7_672_152_030;
pub const FEE_BUCKET_0119: u64 = 7_811_811_614;
pub const FEE_BUCKET_0120: u64 = 7_954_054_812;
pub const FEE_BUCKET_0121: u64 = 8_098_924_493;
pub const FEE_BUCKET_0122: u64 = 8_246_464_209;
pub const FEE_BUCKET_0123: u64 = 8_396_718_101;
pub const FEE_BUCKET_0124: u64 = 8_549_731_309;
pub const FEE_BUCKET_0125: u64 = 8_705_549_178;
pub const FEE_BUCKET_0126: u64 = 8_864_218_514;
pub const FEE_BUCKET_0127: u64 = 9_025_786_821;
pub const FEE_BUCKET_0128: u64 = 9_190_302_864;
pub const FEE_BUCKET_0129: u64 = 9_357_816_476;
pub const FEE_BUCKET_0130: u64 = 9_528_378_265;
pub const FEE_BUCKET_0131: u64 = 9_702_039_930;
pub const FEE_BUCKET_0132: u64 = 9_878_854_609;
pub const FEE_BUCKET_0133: u64 = 10_058_876_138;
pub const FEE_BUCKET_0134: u64 = 10_242_159_287;
pub const FEE_BUCKET_0135: u64 = 10_428_759_017;
pub const FEE_BUCKET_0136: u64 = 10_618_731_741;
pub const FEE_BUCKET_0137: u64 = 10_812_134_616;
pub const FEE_BUCKET_0138: u64 = 11_009_025_905;
pub const FEE_BUCKET_0139: u64 = 11_209_464_378;
pub const FEE_BUCKET_0140: u64 = 11_413_509_273;
pub const FEE_BUCKET_0141: u64 = 11_621_220_930;
pub const FEE_BUCKET_0142: u64 = 11_832_660_104;
pub const FEE_BUCKET_0143: u64 = 12_047_887_325;
pub const FEE_BUCKET_0144: u64 = 12_266_965_410;
pub const FEE_BUCKET_0145: u64 = 12_489_956_822;
pub const FEE_BUCKET_0146: u64 = 12_716_925_087;
pub const FEE_BUCKET_0147: u64 = 12_947_934_266;
pub const FEE_BUCKET_0148: u64 = 13_183_049_503;
pub const FEE_BUCKET_0149: u64 = 13_422_337_221;
pub const FEE_BUCKET_0150: u64 = 13_665_865_954;
pub const FEE_BUCKET_0151: u64 = 13_913_705_693;
pub const FEE_BUCKET_0152: u64 = 14_165_927_990;
pub const FEE_BUCKET_0153: u64 = 14_422_605_766;
pub const FEE_BUCKET_0154: u64 = 14_683_813_764;
pub const FEE_BUCKET_0155: u64 = 14_949_628_598;
pub const FEE_BUCKET_0156: u64 = 15_220_128_284;
pub const FEE_BUCKET_0157: u64 = 15_495_392_944;
pub const FEE_BUCKET_0158: u64 = 15_775_504_624;
pub const FEE_BUCKET_0159: u64 = 16_060_547_722;
pub const FEE_BUCKET_0160: u64 = 16_350_608_989;
pub const FEE_BUCKET_0161: u64 = 16_645_777_342;
pub const FEE_BUCKET_0162: u64 = 16_946_143_987;
pub const FEE_BUCKET_0163: u64 = 17_251_802_435;
pub const FEE_BUCKET_0164: u64 = 17_562_848_077;
pub const FEE_BUCKET_0165: u64 = 17_879_378_495;
pub const FEE_BUCKET_0166: u64 = 18_201_493_929;
pub const FEE_BUCKET_0167: u64 = 18_529_297_326;
pub const FEE_BUCKET_0168: u64 = 18_862_894_381;
pub const FEE_BUCKET_0169: u64 = 19_202_393_586;
pub const FEE_BUCKET_0170: u64 = 19_547_906_277;
pub const FEE_BUCKET_0171: u64 = 19_899_546_683;
pub const FEE_BUCKET_0172: u64 = 20_257_431_977;
pub const FEE_BUCKET_0173: u64 = 20_621_682_321;
pub const FEE_BUCKET_0174: u64 = 20_992_420_921;
pub const FEE_BUCKET_0175: u64 = 21_369_773_077;
pub const FEE_BUCKET_0176: u64 = 21_753_867_219;
pub const FEE_BUCKET_0177: u64 = 22_144_834_961;
pub const FEE_BUCKET_0178: u64 = 22_542_811_155;
pub const FEE_BUCKET_0179: u64 = 22_947_933_945;
pub const FEE_BUCKET_0180: u64 = 23_360_344_822;
pub const FEE_BUCKET_0181: u64 = 23_780_188_925;
pub const FEE_BUCKET_0182: u64 = 24_207_615_137;
pub const FEE_BUCKET_0183: u64 = 24_642_776_594;
pub const FEE_BUCKET_0184: u64 = 25_085_830_136;
pub const FEE_BUCKET_0185: u64 = 25_536_936_248;
pub const FEE_BUCKET_0186: u64 = 25_996_259_164;
pub const FEE_BUCKET_0187: u64 = 26_463_966_570;
pub const FEE_BUCKET_0188: u64 = 26_940_229_002;
pub const FEE_BUCKET_0189: u64 = 27_425_220_498;
pub const FEE_BUCKET_0190: u64 = 27_919_118_746;
pub const FEE_BUCKET_0191: u64 = 28_422_105_765;
pub const FEE_BUCKET_0192: u64 = 28_934_367_563;
pub const FEE_BUCKET_0193: u64 = 29_456_094_399;
pub const FEE_BUCKET_0194: u64 = 29_987_480_090;
pub const FEE_BUCKET_0195: u64 = 30_528_722_252;
pub const FEE_BUCKET_0196: u64 = 31_080_022_530;
pub const FEE_BUCKET_0197: u64 = 31_641_586_565;
pub const FEE_BUCKET_0198: u64 = 32_213_624_536;
pub const FEE_BUCKET_0199: u64 = 32_796_351_154;
pub const FEE_BUCKET_0200: u64 = 33_389_985_967;
pub const FEE_BUCKET_0201: u64 = 33_994_753_728;
pub const FEE_BUCKET_0202: u64 = 34_610_884_541;
pub const FEE_BUCKET_0203: u64 = 35_238_614_571;
pub const FEE_BUCKET_0204: u64 = 35_878_185_885;
pub const FEE_BUCKET_0205: u64 = 36_529_846_148;
pub const FEE_BUCKET_0206: u64 = 37_193_849_533;
pub const FEE_BUCKET_0207: u64 = 37_870_457_975;
pub const FEE_BUCKET_0208: u64 = 38_559_940_761;
pub const FEE_BUCKET_0209: u64 = 39_262_574_868;
pub const FEE_BUCKET_0210: u64 = 39_978_645_641;
pub const FEE_BUCKET_0211: u64 = 40_708_447_776;
pub const FEE_BUCKET_0212: u64 = 41_452_285_388;
pub const FEE_BUCKET_0213: u64 = 42_210_472_185;
pub const FEE_BUCKET_0214: u64 = 42_983_331_705;
pub const FEE_BUCKET_0215: u64 = 43_771_197_344;
pub const FEE_BUCKET_0216: u64 = 44_574_412_898;
pub const FEE_BUCKET_0217: u64 = 45_393_332_918;
pub const FEE_BUCKET_0218: u64 = 46_228_323_092;
pub const FEE_BUCKET_0219: u64 = 47_079_760_553;
pub const FEE_BUCKET_0220: u64 = 47_948_034_842;
pub const FEE_BUCKET_0221: u64 = 48_833_548_434;
pub const FEE_BUCKET_0222: u64 = 49_736_716_113;
pub const FEE_BUCKET_0223: u64 = 50_657_965_608;
pub const FEE_BUCKET_0224: u64 = 51_597_737_100;
pub const FEE_BUCKET_0225: u64 = 52_556_483_630;
pub const FEE_BUCKET_0226: u64 = 53_534_671_852;
pub const FEE_BUCKET_0227: u64 = 54_532_782_274;
pub const FEE_BUCKET_0228: u64 = 55_551_309_573;
pub const FEE_BUCKET_0229: u64 = 56_590_762_038;
pub const FEE_BUCKET_0230: u64 = 57_651_662_993;
pub const FEE_BUCKET_0231: u64 = 58_734_550_264;
pub const FEE_BUCKET_0232: u64 = 59_839_976_619;
pub const FEE_BUCKET_0233: u64 = 60_968_510_979;
pub const FEE_BUCKET_0234: u64 = 62_120_738_017;
pub const FEE_BUCKET_0235: u64 = 63_297_258_563;
pub const FEE_BUCKET_0236: u64 = 64_498_689_116;
pub const FEE_BUCKET_0237: u64 = 65_725_662_632;
pub const FEE_BUCKET_0238: u64 = 66_978_828_897;
pub const FEE_BUCKET_0239: u64 = 68_258_854_988;
pub const FEE_BUCKET_0240: u64 = 69_566_425_522;
pub const FEE_BUCKET_0241: u64 = 70_902_243_611;
pub const FEE_BUCKET_0242: u64 = 72_267_031_753;
pub const FEE_BUCKET_0243: u64 = 73_661_532_394;
pub const FEE_BUCKET_0244: u64 = 75_086_508_484;
pub const FEE_BUCKET_0245: u64 = 76_542_744_163;
pub const FEE_BUCKET_0246: u64 = 78_031_045_384;
pub const FEE_BUCKET_0247: u64 = 79_552_240_581;
pub const FEE_BUCKET_0248: u64 = 81_107_181_310;
pub const FEE_BUCKET_0249: u64 = 82_696_742901;
pub const FEE_BUCKET_0250: u64 = 84_321_825_212;
pub const FEE_BUCKET_0251: u64 = 85_983_353_487;
pub const FEE_BUCKET_0252: u64 = 87_682_279_509;
pub const FEE_BUCKET_0253: u64 = 89_419_582_764;
pub const FEE_BUCKET_0254: u64 = 91_196_271_632;
pub const FEE_BUCKET_0255: u64 = 93_013_384_553;
pub const FEE_BUCKET_0256: u64 = 94_871_991_203;
pub const FEE_BUCKET_0257: u64 = 96_773_193_675;
pub const FEE_BUCKET_0258: u64 = 98_718_127_652;
pub const FEE_BUCKET_0259: u64 = 100_707_963_592;
pub const FEE_BUCKET_0260: u64 = 102_743_907_921;
pub const FEE_BUCKET_0261: u64 = 104_827_203_221;
pub const FEE_BUCKET_0262: u64 = 106_959_129_430;
pub const FEE_BUCKET_0263: u64 = 109_140_004_036;
pub const FEE_BUCKET_0264: u64 = 111_371_182_276;
pub const FEE_BUCKET_0265: u64 = 113_654_057_341;
pub const FEE_BUCKET_0266: u64 = 115_990_060_587;
pub const FEE_BUCKET_0267: u64 = 118_380_661_737;
pub const FEE_BUCKET_0268: u64 = 120_827_369_074;
pub const FEE_BUCKET_0269: u64 = 123_331_729_642;
pub const FEE_BUCKET_0270: u64 = 125_895_329_446;
pub const FEE_BUCKET_0271: u64 = 128_519_793_674;
pub const FEE_BUCKET_0272: u64 = 131_206_787_935;
pub const FEE_BUCKET_0273: u64 = 133_958_019_532;
pub const FEE_BUCKET_0274: u64 = 136_775_238_759;
pub const FEE_BUCKET_0275: u64 = 139_660_240_191;
pub const FEE_BUCKET_0276: u64 = 142_614_863_018;
pub const FEE_BUCKET_0277: u64 = 145_641_991_394;
pub const FEE_BUCKET_0278: u64 = 148_743_555_790;
pub const FEE_BUCKET_0279: u64 = 151_921_533_386;
pub const FEE_BUCKET_0280: u64 = 155_177_948_526;
pub const FEE_BUCKET_0281: u64 = 158_514_873_192;
pub const FEE_BUCKET_0282: u64 = 161_934_427_517;
pub const FEE_BUCKET_0283: u64 = 165_438_780_301;
pub const FEE_BUCKET_0284: u64 = 169_030_149_531;
pub const FEE_BUCKET_0285: u64 = 172_710_803_920;
pub const FEE_BUCKET_0286: u64 = 176_483_064_453;
pub const FEE_BUCKET_0287: u64 = 180_349_306_973;
pub const FEE_BUCKET_0288: u64 = 184_311_963_796;
pub const FEE_BUCKET_0289: u64 = 188_373_526_332;
pub const FEE_BUCKET_0290: u64 = 192_536_547_718;
pub const FEE_BUCKET_0291: u64 = 196_803_645_484;
pub const FEE_BUCKET_0292: u64 = 201_177_504_234;
pub const FEE_BUCKET_0293: u64 = 205_660_879_355;
pub const FEE_BUCKET_0294: u64 = 210_256_599_760;
pub const FEE_BUCKET_0295: u64 = 214_967_570_650;
pub const FEE_BUCKET_0296: u64 = 219_796_776_330;
pub const FEE_BUCKET_0297: u64 = 224_747_283_395;
pub const FEE_BUCKET_0298: u64 = 229_822_243_105;
pub const FEE_BUCKET_0299: u64 = 235_024_894_021;
pub const FEE_BUCKET_0300: u64 = 240_358_565_986;
pub const FEE_BUCKET_0301: u64 = 245_826_683_351;
pub const FEE_BUCKET_0302: u64 = 251_432_768_529;
pub const FEE_BUCKET_0303: u64 = 257_180_445_859;
pub const FEE_BUCKET_0304: u64 = 263_073_445_815;
pub const FEE_BUCKET_0305: u64 = 269_115_609_642;
pub const FEE_BUCKET_0306: u64 = 275_310_893_263;
pub const FEE_BUCKET_0307: u64 = 281_663_370_546;
pub const FEE_BUCKET_0308: u64 = 288_177_236_916;
pub const FEE_BUCKET_0309: u64 = 294_856_812_181;
pub const FEE_BUCKET_0310: u64 = 301_706_543_542;
pub const FEE_BUCKET_0311: u64 = 308_731_008_836;
pub const FEE_BUCKET_0312: u64 = 315_934_919_011;
pub const FEE_BUCKET_0313: u64 = 323_323_121_776;
pub const FEE_BUCKET_0314: u64 = 330_900_605_468;
pub const FEE_BUCKET_0315: u64 = 338_672_503_079;
pub const FEE_BUCKET_0316: u64 = 346_644_096_477;
pub const FEE_BUCKET_0317: u64 = 354_820_819_797;
pub const FEE_BUCKET_0318: u64 = 363_208_263_001;
pub const FEE_BUCKET_0319: u64 = 371_812_175_651;
pub const FEE_BUCKET_0320: u64 = 380_638_470_900;
pub const FEE_BUCKET_0321: u64 = 389_693_229_721;
pub const FEE_BUCKET_0322: u64 = 398_982_704_468;
pub const FEE_BUCKET_0323: u64 = 408_513_323_719;
pub const FEE_BUCKET_0324: u64 = 418_291_697_440;
pub const FEE_BUCKET_0325: u64 = 428_324_621_495;
pub const FEE_BUCKET_0326: u64 = 438_619_082_635;
pub const FEE_BUCKET_0327: u64 = 449_182_263_025;
pub const FEE_BUCKET_0328: u64 = 460_021_545_337;
pub const FEE_BUCKET_0329: u64 = 471_144_517_225;
pub const FEE_BUCKET_0330: u64 = 482_558_975_339;
pub const FEE_BUCKET_0331: u64 = 494_272_929_686;
pub const FEE_BUCKET_0332: u64 = 506_294_608_983;
pub const FEE_BUCKET_0333: u64 = 518_632_465_631;
pub const FEE_BUCKET_0334: u64 = 531_295_179_336;
pub const FEE_BUCKET_0335: u64 = 544_291_661_452;
pub const FEE_BUCKET_0336: u64 = 557_631_058_047;
pub const FEE_BUCKET_0337: u64 = 571_322_754_692;
pub const FEE_BUCKET_0338: u64 = 585_376_379_987;
pub const FEE_BUCKET_0339: u64 = 599_801_810_883;
pub const FEE_BUCKET_0340: u64 = 614_609_177_809;
pub const FEE_BUCKET_0341: u64 = 629_808_869_719;
pub const FEE_BUCKET_0342: u64 = 645_411_539_054;
pub const FEE_BUCKET_0343: u64 = 661_428_106_590;
pub const FEE_BUCKET_0344: u64 = 677_869_766_072;
pub const FEE_BUCKET_0345: u64 = 694_748_990_687;
pub const FEE_BUCKET_0346: u64 = 712_078_539_546;
pub const FEE_BUCKET_0347: u64 = 729_871_464_140;
pub const FEE_BUCKET_0348: u64 = 748_141_115_793;
pub const FEE_BUCKET_0349: u64 = 766_901_151_106;
pub const FEE_BUCKET_0350: u64 = 786_165_538_434;
pub const FEE_BUCKET_0351: u64 = 805_948_563_588;
pub const FEE_BUCKET_0352: u64 = 826_264_837_010;
pub const FEE_BUCKET_0353: u64 = 847_129_300_389;
pub const FEE_BUCKET_0354: u64 = 868_557_233_759;
pub const FEE_BUCKET_0355: u64 = 890_564_262_080;
pub const FEE_BUCKET_0356: u64 = 913_166_362_533;
pub const FEE_BUCKET_0357: u64 = 936_379_870_491;
pub const FEE_BUCKET_0358: u64 = 960_221_486_389;
pub const FEE_BUCKET_0359: u64 = 984_708_282_455;
pub const FEE_BUCKET_0360: u64 = 1_009_857_710_373;
pub const FEE_BUCKET_0361: u64 = 1_035_687_562_892;
pub const FEE_BUCKET_0362: u64 = 1_062_216_096_461;
pub const FEE_BUCKET_0363: u64 = 1_089_462_998_333;
pub const FEE_BUCKET_0364: u64 = 1_117_448_430_320;
pub const FEE_BUCKET_0365: u64 = 1_146_193_092_801;
pub const FEE_BUCKET_0366: u64 = 1_175_718_207_915;
pub const FEE_BUCKET_0367: u64 = 1_206_045_588_982;
pub const FEE_BUCKET_0368: u64 = 1_237_197_696_480;
pub const FEE_BUCKET_0369: u64 = 1_269_197_695_521;
pub const FEE_BUCKET_0370: u64 = 1_302_069_504_735;
pub const FEE_BUCKET_0371: u64 = 1_335_837_849_718;
pub const FEE_BUCKET_0372: u64 = 1_370_528_314_036;
pub const FEE_BUCKET_0373: u64 = 1_406_167_390_760;
pub const FEE_BUCKET_0374: u64 = 1_442_782_539_335;
pub const FEE_BUCKET_0375: u64 = 1_480_402_238_068;
pub const FEE_BUCKET_0376: u64 = 1_519_055_042_977;
pub const FEE_BUCKET_0377: u64 = 1_558_770_654_200;
pub const FEE_BUCKET_0378: u64 = 1_599_579_984_833;
pub const FEE_BUCKET_0379: u64 = 1_641_515_235_555;
pub const FEE_BUCKET_0380: u64 = 1_684_609_962_560;
pub const FEE_BUCKET_0381: u64 = 1_728_899_150_382;
pub const FEE_BUCKET_0382: u64 = 1_774_419_286_790;
pub const FEE_BUCKET_0383: u64 = 1_821_208_432_788;
pub const FEE_BUCKET_0384: u64 = 1_869_306_295_699;
pub const FEE_BUCKET_0385: u64 = 1_918_754_302_360;
pub const FEE_BUCKET_0386: u64 = 1_969_595_674_453;
pub const FEE_BUCKET_0387: u64 = 2_021_875_507_984;
pub const FEE_BUCKET_0388: u64 = 2_075_640_854_952;
pub const FEE_BUCKET_0389: u64 = 2_130_940_809_169;
pub const FEE_BUCKET_0390: u64 = 2_187_826_602_213;
pub const FEE_BUCKET_0391: u64 = 2_246_351_692_641;
pub const FEE_BUCKET_0392: u64 = 2_306_571_866_630;
pub const FEE_BUCKET_0393: u64 = 2_368_545_346_361;
pub const FEE_BUCKET_0394: u64 = 2_432_332_906_421;
pub const FEE_BUCKET_0395: u64 = 2_497_998_991_830;
pub const FEE_BUCKET_0396: u64 = 2_565_610_847_284;
pub const FEE_BUCKET_0397: u64 = 2_635_238_641_684;
pub const FEE_BUCKET_0398: u64 = 2_706_955_608_678;
pub const FEE_BUCKET_0399: u64 = 2_780_838_194_026;
pub const FEE_BUCKET_0400: u64 = 2_856_966_204_580;
pub const FEE_BUCKET_0401: u64 = 2_935_422_966_628;
pub const FEE_BUCKET_0402: u64 = 3_016_295_486_239;
pub const FEE_BUCKET_0403: u64 = 3_099_674_623_935;
pub const FEE_BUCKET_0404: u64 = 3_185_655_270_657;
pub const FEE_BUCKET_0405: u64 = 3_274_336_536_043;
pub const FEE_BUCKET_0406: u64 = 3_365_821_942_066;
pub const FEE_BUCKET_0407: u64 = 3_460_219_631_174;
pub const FEE_BUCKET_0408: u64 = 3_557_642_591_063;
pub const FEE_BUCKET_0409: u64 = 3_658_208_882_044;
pub const FEE_BUCKET_0410: u64 = 3_762_041_863_001;
pub const FEE_BUCKET_0411: u64 = 3_869_270_422_971;
pub const FEE_BUCKET_0412: u64 = 3_980_029_237_791;
pub const FEE_BUCKET_0413: u64 = 4_094_459_030_069;
pub const FEE_BUCKET_0414: u64 = 4_212_706_843_430;
pub const FEE_BUCKET_0415: u64 = 4_334_926_334_657;
pub const FEE_BUCKET_0416: u64 = 4_461_277_092_776;
pub const FEE_BUCKET_0417: u64 = 4_591_925_979_353;
pub const FEE_BUCKET_0418: u64 = 4_727_046_491_002;
pub const FEE_BUCKET_0419: u64 = 4_866_819_131_349;
pub const FEE_BUCKET_0420: u64 = 5_011_431_789_257;
pub const FEE_BUCKET_0421: u64 = 5_161_080_139_674;
pub const FEE_BUCKET_0422: u64 = 5_315_967_052_048;
pub const FEE_BUCKET_0423: u64 = 5_476_302_017_932;
pub const FEE_BUCKET_0424: u64 = 5_642_301_581_472;
pub const FEE_BUCKET_0425: u64 = 5_814_189_780_584;
pub const FEE_BUCKET_0426: u64 = 5_992_198_599_079;
pub const FEE_BUCKET_0427: u64 = 6_176_568_458_495;
pub const FEE_BUCKET_0428: u64 = 6_367_548_734_765;
pub const FEE_BUCKET_0429: u64 = 6_565_398_280_358;
pub const FEE_BUCKET_0430: u64 = 6_770_386_958_125;
pub const FEE_BUCKET_0431: u64 = 6_982_796_211_413;
pub const FEE_BUCKET_0432: u64 = 7_202_919_668_732;
pub const FEE_BUCKET_0433: u64 = 7_431_063_807_892;
pub const FEE_BUCKET_0434: u64 = 7_667_548_658_713;
pub const FEE_BUCKET_0435: u64 = 7_912_708_524_530;
pub const FEE_BUCKET_0436: u64 = 8_166_892_724_905;
pub const FEE_BUCKET_0437: u64 = 8_430_466_363_700;
pub const FEE_BUCKET_0438: u64 = 8_703_811_118_659;
pub const FEE_BUCKET_0439: u64 = 8_987_326_059_068;
pub const FEE_BUCKET_0440: u64 = 9_281_428_485_521;
pub const FEE_BUCKET_0441: u64 = 9_586_554_808_343;
pub const FEE_BUCKET_0442: u64 = 9_903_161_448_219;
pub const FEE_BUCKET_0443: u64 = 10_231_725_748_265;
pub const FEE_BUCKET_0444: u64 = 10_572_746_905_924;
pub const FEE_BUCKET_0445: u64 = 10_926_746_913_834;
pub const FEE_BUCKET_0446: u64 = 11_294_271_502_030;
pub const FEE_BUCKET_0447: u64 = 11_675_891_085_021;
pub const FEE_BUCKET_0448: u64 = 12_072_201_713_967;
pub const FEE_BUCKET_0449: u64 = 12_483_826_048_487;
pub const FEE_BUCKET_0450: u64 = 12_911_414_343_065;
pub const FEE_BUCKET_0451: u64 = 13_355_645_448_134;
pub const FEE_BUCKET_0452: u64 = 13_817_228_824_355;
pub const FEE_BUCKET_0453: u64 = 14_296_905_573_354;
pub const FEE_BUCKET_0454: u64 = 14_795_449_485_915;
pub const FEE_BUCKET_0455: u64 = 15_313_669_106_492;
pub const FEE_BUCKET_0456: u64 = 15_852_409_812_046;
pub const FEE_BUCKET_0457: u64 = 16_412_555_905_311;
pub const FEE_BUCKET_0458: u64 = 16_995_032_741_833;
pub const FEE_BUCKET_0459: u64 = 17_600_809_874_375;
pub const FEE_BUCKET_0460: u64 = 18_230_902_225_138;
pub const FEE_BUCKET_0461: u64 = 18_886_371_293_163;
pub const FEE_BUCKET_0462: u64 = 19_568_326_400_229;
pub const FEE_BUCKET_0463: u64 = 20_277_926_952_654;
pub const FEE_BUCKET_0464: u64 = 21_016_384_732_954;
pub const FEE_BUCKET_0465: u64 = 21_784_965_221_620;
pub const FEE_BUCKET_0466: u64 = 22_585_988_934_140;
pub const FEE_BUCKET_0467: u64 = 23_421_833_790_501;
pub const FEE_BUCKET_0468: u64 = 24_294_936_512_096;
pub const FEE_BUCKET_0469: u64 = 25_207_794_046_979;
pub const FEE_BUCKET_0470: u64 = 26_163_965_027_510;
pub const FEE_BUCKET_0471: u64 = 27_167_071_246_684;
pub const FEE_BUCKET_0472: u64 = 28_220_800_151_491;
pub const FEE_BUCKET_0473: u64 = 29_328_907_374_198;
pub const FEE_BUCKET_0474: u64 = 30_495_220_357_833;
pub const FEE_BUCKET_0475: u64 = 31_723_641_114_122;
pub const FEE_BUCKET_0476: u64 = 33_018_149_119_390;
pub const FEE_BUCKET_0477: u64 = 34_382_805_353_027;
pub const FEE_BUCKET_0478: u64 = 35_821_756_486_990;
pub const FEE_BUCKET_0479: u64 = 37_339_238_227_412;
pub const FEE_BUCKET_0480: u64 = 38_939_580_784_316;
pub const FEE_BUCKET_0481: u64 = 40_627_214_525_393;
pub const FEE_BUCKET_0482: u64 = 42_406_675_834_329;
pub const FEE_BUCKET_0483: u64 = 44_282_613_130_690;
pub const FEE_BUCKET_0484: u64 = 46_259_793_089_385;
pub const FEE_BUCKET_0485: u64 = 48_343_107_035_904;
pub const FEE_BUCKET_0486: u64 = 50_537_576_479_514;
pub const FEE_BUCKET_0487: u64 = 52_848_358_859_667;
pub const FEE_BUCKET_0488: u64 = 55_280_754_555_282;
pub const FEE_BUCKET_0489: u64 = 57_840_214_171_576;
pub const FEE_BUCKET_0490: u64 = 60_532_346_115_018;
pub const FEE_BUCKET_0491: u64 = 63_362_925_469_539;
pub const FEE_BUCKET_0492: u64 = 66_337_901_171_636;
pub const FEE_BUCKET_0493: u64 = 69_463_403_451_524;
pub const FEE_BUCKET_0494: u64 = 72_745_752_520_735;
pub const FEE_BUCKET_0495: u64 = 76_191_467_523_679;
pub const FEE_BUCKET_0496: u64 = 79_807_275_776_747;
pub const FEE_BUCKET_0497: u64 = 83_600_123_375_426;
pub const FEE_BUCKET_0498: u64 = 87_577_185_113_528;
pub const FEE_BUCKET_0499: u64 = 91_745_876_842_650;
pub const FEE_BUCKET_0500: u64 = 96_113_865_407_183;
pub const FEE_BUCKET_0501: u64 = 100_689_080_165_103;
pub const FEE_BUCKET_0502: u64 = 105_479_725_139_472;
pub const FEE_BUCKET_0503: u64 = 110_494_291_989_649;
pub const FEE_BUCKET_0504: u64 = 115_741_574_922_554;
pub const FEE_BUCKET_0505: u64 = 121_230_687_501_834;
pub const FEE_BUCKET_0506: u64 = 126_971_079_465_414;
pub const FEE_BUCKET_0507: u64 = 132_972_554_521_932;
pub const FEE_BUCKET_0508: u64 = 139_245_287_204_804;
pub const FEE_BUCKET_0509: u64 = 145_799_840_782_021;
pub const FEE_BUCKET_0510: u64 = 152_647_184_317_448;
pub const FEE_BUCKET_0511: u64 = 159_798_712_835_864;
pub const FEE_BUCKET_0512: u64 = 167_266_267_595_932;
pub const FEE_BUCKET_0513: u64 = 175_062_157_473_063;
pub const FEE_BUCKET_0514: u64 = 183_199_181_424_581;
pub const FEE_BUCKET_0515: u64 = 191_690_650_063_181;
pub const FEE_BUCKET_0516: u64 = 200_550_408_320_388;
pub const FEE_BUCKET_0517: u64 = 209_792_859_259_353;
pub const FEE_BUCKET_0518: u64 = 219_432_989_095_561;
pub const FEE_BUCKET_0519: u64 = 229_486_393_432_382;
pub const FEE_BUCKET_0520: u64 = 239_969_303_704_193;
pub const FEE_BUCKET_0521: u64 = 250_898_615_867_851;
pub const FEE_BUCKET_0522: u64 = 262_291_915_270_579;
pub const FEE_BUCKET_0523: u64 = 274_167_505_753_948;
pub const FEE_BUCKET_0524: u64 = 286_544_446_075_216;
pub const FEE_BUCKET_0525: u64 = 299_442_588_695_581;
pub const FEE_BUCKET_0526: u64 = 312_882_618_927_405;
pub const FEE_BUCKET_0527: u64 = 326_886_094_587_034;
pub const FEE_BUCKET_0528: u64 = 341_475_488_287_531;
pub const FEE_BUCKET_0529: u64 = 356_674_230_430_332;
pub const FEE_BUCKET_0530: u64 = 372_506_754_198_029;
pub const FEE_BUCKET_0531: u64 = 389_998_544_697_396;
pub const FEE_BUCKET_0532: u64 = 409_176_193_176_294;
pub const FEE_BUCKET_0533: u64 = 430_067_447_336_889;
pub const FEE_BUCKET_0534: u64 = 452_701_271_825_649;
pub const FEE_BUCKET_0535: u64 = 477_107_905_922_534;
pub const FEE_BUCKET_0536: u64 = 503_318_926_826_013;
pub const FEE_BUCKET_0537: u64 = 531_367_313_392_056;
pub const FEE_BUCKET_0538: u64 = 561_287_518_819_158;
pub const FEE_BUCKET_0539: u64 = 593_115_543_524_913;
pub const FEE_BUCKET_0540: u64 = 626_889_008_553_827;
pub const FEE_BUCKET_0541: u64 = 662_647_229_203_242;
pub const FEE_BUCKET_0542: u64 = 700_431_293_170_934;
pub const FEE_BUCKET_0543: u64 = 740_284_151_305_501;
pub const FEE_BUCKET_0544: u64 = 782_250_707_905_412;
pub const FEE_BUCKET_0545: u64 = 826_377_916_677_419;
pub const FEE_BUCKET_0546: u64 = 872_714_886_136_088;
pub const FEE_BUCKET_0547: u64 = 921_313_002_732_578;
pub const FEE_BUCKET_0548: u64 = 972_226_049_995_436;
pub const FEE_BUCKET_0549: u64 = 1_025_510_332_986_080;
pub const FEE_BUCKET_0550: u64 = 1_081_224_815_146_844;
pub const FEE_BUCKET_0551: u64 = 1_139_431_270_319_339;
pub const FEE_BUCKET_0552: u64 = 1_200_194_433_610_878;
pub const FEE_BUCKET_0553: u64 = 1_263_582_161_487_438;
pub const FEE_BUCKET_0554: u64 = 1_329_665_594_532_124;
pub const FEE_BUCKET_0555: u64 = 1_398_519_324_839_271;
pub const FEE_BUCKET_0556: u64 = 1_470_221_547_157_674;
pub const FEE_BUCKET_0557: u64 = 1_544_854_227_987_623;
pub const FEE_BUCKET_0558: u64 = 1_622_503_284_575_911;
pub const FEE_BUCKET_0559: u64 = 1_703_258_794_906_203;
pub const FEE_BUCKET_0560: u64 = 1_787_214_202_727_608;
pub const FEE_BUCKET_0561: u64 = 1_874_467_535_564_977;
pub const FEE_BUCKET_0562: u64 = 1_965_120_623_026_592;
pub const FEE_BUCKET_0563: u64 = 2_059_279_324_836_926;
pub const FEE_BUCKET_0564: u64 = 2_157_053_788_638_313;
pub const FEE_BUCKET_0565: u64 = 2_258_558_723_298_137;
pub const FEE_BUCKET_0566: u64 = 2_363_913_686_366_684;
pub const FEE_BUCKET_0567: u64 = 2_473_243_388_852_584;
pub const FEE_BUCKET_0568: u64 = 2_586_677_999_895_078;
pub const FEE_BUCKET_0569: u64 = 2_704_353_467_642_350;
pub const FEE_BUCKET_0570: u64 = 2_826_411_864_053_689;
pub const FEE_BUCKET_0571: u64 = 2_952_999_748_931_464;
pub const FEE_BUCKET_0572: u64 = 3_084_268_531_662_778;
pub const FEE_BUCKET_0573: u64 = 3_220_374_843_706_310;
pub const FEE_BUCKET_0574: u64 = 3_361_480_922_183_637;
pub const FEE_BUCKET_0575: u64 = 3_507_754_998_384_111;
pub const FEE_BUCKET_0576: u64 = 3_659_371_690_356_421;
pub const FEE_BUCKET_0577: u64 = 3_816_512_399_559_170;
pub const FEE_BUCKET_0578: u64 = 3_979_365_705_610_196;
pub const FEE_BUCKET_0579: u64 = 4_148_127_760_978_156;
pub const FEE_BUCKET_0580: u64 = 4_323_002_698_688_848;
pub const FEE_BUCKET_0581: u64 = 4_504_202_044_130_559;
pub const FEE_BUCKET_0582: u64 = 4_691_945_155_565_995;
pub const FEE_BUCKET_0583: u64 = 4_886_459_693_866_456;
pub const FEE_BUCKET_0584: u64 = 5_087_982_151_968_420;
pub const FEE_BUCKET_0585: u64 = 5_296_758_420_158_802;
pub const FEE_BUCKET_0586: u64 = 5_513_044_375_091_501;
pub const FEE_BUCKET_0587: u64 = 5_737_106_514_353_741;
pub const FEE_BUCKET_0588: u64 = 5_969_222_610_170_467;
pub const FEE_BUCKET_0589: u64 = 6_209_681_385_131_527;
pub const FEE_BUCKET_0590: u64 = 6_458_782_211_112_841;
pub const FEE_BUCKET_0591: u64 = 6_716_835_817_576_603;
pub const FEE_BUCKET_0592: u64 = 6_984_164_022_333_574;
pub const FEE_BUCKET_0593: u64 = 7_261_099_490_273_231;
pub const FEE_BUCKET_0594: u64 = 7_547_985_515_772_278;
pub const FEE_BUCKET_0595: u64 = 7_845_175_815_405_607;
pub const FEE_BUCKET_0596: u64 = 8_153_034_346_785_220;
pub const FEE_BUCKET_0597: u64 = 8_471_935_142_566_064;
pub const FEE_BUCKET_0598: u64 = 8_802_262_143_411_687;
pub const FEE_BUCKET_0599: u64 = 9_144_409_050_888_070;
pub const FEE_BUCKET_0600: u64 = 9_498_779_178_346_604;
pub const FEE_BUCKET_0601: u64 = 9_865_785_304_381_076;
pub const FEE_BUCKET_0602: u64 = 10_245_849_530_224_804;
pub const FEE_BUCKET_0603: u64 = 10_639_403_150_141_573;
pub const FEE_BUCKET_0604: u64 = 11_046_886_521_931_125;
pub const FEE_BUCKET_0605: u64 = 11_468_749_946_487_952;
pub const FEE_BUCKET_0606: u64 = 11_905_453_545_408_247;
pub const FEE_BUCKET_0607: u64 = 12_357_467_136_655_188;
pub const FEE_BUCKET_0608: u64 = 12_825_270_112_365_898;
pub const FEE_BUCKET_0609: u64 = 13_309_351_325_975_416;
pub const FEE_BUCKET_0610: u64 = 13_810_209_979_682_942;
pub const FEE_BUCKET_0611: u64 = 14_328_355_507_646_967;
pub const FEE_BUCKET_0612: u64 = 14_864_307_464_937_221;
pub const FEE_BUCKET_0613: u64 = 15_418_595_424_232_077;
pub const FEE_BUCKET_0614: u64 = 15_991_758_879_601_363;
pub const FEE_BUCKET_0615: u64 = 16_584_347_158_722_197;
pub const FEE_BUCKET_0616: u64 = 17_196_919_325_221_053;
pub const FEE_BUCKET_0617: u64 = 17_830_044_078_542_293;
pub const FEE_BUCKET_0618: u64 = 18_484_299_657_875_274;
pub const FEE_BUCKET_0619: u64 = 19_160_273_733_008_030;
pub const FEE_BUCKET_0620: u64 = 19_858_563_318_119_406;
pub const FEE_BUCKET_0621: u64 = 20_579_774_680_525_436;
pub const FEE_BUCKET_0622: u64 = 21_324_523_257_348_617;
pub const FEE_BUCKET_0623: u64 = 22_093_433_560_137_325;
pub const FEE_BUCKET_0624: u64 = 22_887_139_099_313_155;
pub const FEE_BUCKET_0625: u64 = 23_706_282_314_472_847;
pub const FEE_BUCKET_0626: u64 = 24_551_514_506_440_675;
pub const FEE_BUCKET_0627: u64 = 25_423_495_773_302_168;
pub const FEE_BUCKET_0628: u64 = 26_322_895_938_585_160;
pub const FEE_BUCKET_0629: u64 = 27_250_395_479_743_246;
pub const FEE_BUCKET_0630: u64 = 28_206_686_456_398_636;
pub const FEE_BUCKET_0631: u64 = 29_192_473_433_997_407;
pub const FEE_BUCKET_0632: u64 = 30_208_474_410_375_365;
pub const FEE_BUCKET_0633: u64 = 31_255_421_740_838_099;
pub const FEE_BUCKET_0634: u64 = 32_334_062_067_765_138;
pub const FEE_BUCKET_0635: u64 = 33_445_156_251_661_500;
pub const FEE_BUCKET_0636: u64 = 34_589_479_301_857_773;
pub const FEE_BUCKET_0637: u64 = 35_767_820_307_445_831;
pub const FEE_BUCKET_0638: u64 = 36_981_982_368_530_003;
pub const FEE_BUCKET_0639: u64 = 38_233_782_539_996_630;
pub const FEE_BUCKET_0640: u64 = 39_525_052_791_827_592;
pub const FEE_BUCKET_0641: u64 = 40_857_640_961_115_603;
pub const FEE_BUCKET_0642: u64 = 42_233_411_713_488_859;
pub const FEE_BUCKET_0643: u64 = 43_654_247_514_043_933;
pub const FEE_BUCKET_0644: u64 = 45_122_049_596_912_750;
pub const FEE_BUCKET_0645: u64 = 46_638_739_936_398_267;
pub const FEE_BUCKET_0646: u64 = 48_206_262_226_288_841;
pub const FEE_BUCKET_0647: u64 = 49_826_582_864_445_995;
pub const FEE_BUCKET_0648: u64 = 51_501_692_945_141_577;
pub const FEE_BUCKET_0649: u64 = 53_233_609_260_776_248;
pub const FEE_BUCKET_0650: u64 = 55_024_375_307_808_325;
pub const FEE_BUCKET_0651: u64 = 56_876_062_302_047_694;
pub const FEE_BUCKET_0652: u64 = 58_790_770_206_143_503;
pub const FEE_BUCKET_0653: u64 = 60_770_628_788_858_117;
pub const FEE_BUCKET_0654: u64 = 62_817_798_713_840_426;
pub const FEE_BUCKET_0655: u64 = 64_934_472_640_341_221;
pub const FEE_BUCKET_0656: u64 = 67_122_876_354_792_825;
pub const FEE_BUCKET_0657: u64 = 69_385_270_940_352_238;
pub const FEE_BUCKET_0658: u64 = 71_723_954_962_016_096;
pub const FEE_BUCKET_0659: u64 = 74_141_266_674_035_411;
pub const FEE_BUCKET_0660: u64 = 76_639_586_245_663_793;
pub const FEE_BUCKET_0661: u64 = 79_221_337_015_201_560;
pub const FEE_BUCKET_0662: u64 = 81_889_987_760_862_660;
pub const FEE_BUCKET_0663: u64 = 84_648_053_007_246_731;
pub const FEE_BUCKET_0664: u64 = 87_498_094_367_329_112;
pub const FEE_BUCKET_0665: u64 = 90_442_721_961_550_084;
pub const FEE_BUCKET_0666: u64 = 93_484_596_885_658_739;
pub const FEE_BUCKET_0667: u64 = 96_626_433_735_570_322;
pub const FEE_BUCKET_0668: u64 = 99_871_003_193_268_686;
pub const FEE_BUCKET_0669: u64 = 103_221_134_667_513_572;
pub const FEE_BUCKET_0670: u64 = 106_679_718_982_336_337;
pub const FEE_BUCKET_0671: u64 = 110_249_711_119_606_356;
pub const FEE_BUCKET_0672: u64 = 113_934_132_028_464_221;
pub const FEE_BUCKET_0673: u64 = 117_736_070_506_137_292;
pub const FEE_BUCKET_0674: u64 = 121_658_684_153_426_759;
pub const FEE_BUCKET_0675: u64 = 125_705_201_415_883_935;
pub const FEE_BUCKET_0676: u64 = 129_878_923_785_008_851;
pub const FEE_BUCKET_0677: u64 = 134_183_228_178_459_999;
pub const FEE_BUCKET_0678: u64 = 138_621_570_558_241_820;
pub const FEE_BUCKET_0679: u64 = 143_197_489_700_428_799;
pub const FEE_BUCKET_0680: u64 = 147_914_610_214_177_094;
pub const FEE_BUCKET_0681: u64 = 152_776_645_814_631_988;
pub const FEE_BUCKET_0682: u64 = 157_787_402_765_769_688;
pub const FEE_BUCKET_0683: u64 = 162_950_784_455_072_690;
pub const FEE_BUCKET_0684: u64 = 168_270_795_100_808_130;
pub const FEE_BUCKET_0685: u64 = 173_751_543_643_490_758;
pub const FEE_BUCKET_0686: u64 = 179_397_246_828_382_810;
pub const FEE_BUCKET_0687: u64 = 185_212_232_463_000_563;
pub const FEE_BUCKET_0688: u64 = 191_200_943_842_871_834;
pub const FEE_BUCKET_0689: u64 = 197_367_945_376_637_594;
pub const FEE_BUCKET_0690: u64 = 203_717_928_430_164_372;
pub const FEE_BUCKET_0691: u64 = 210_255_718_356_813_880;
pub const FEE_BUCKET_0692: u64 = 216_986_280_653_692_147;
pub const FEE_BUCKET_0693: u64 = 223_914_728_251_997_540;
pub const FEE_BUCKET_0694: u64 = 231_046_329_908_281_207;
pub const FEE_BUCKET_0695: u64 = 238_386_518_735_569_980;
pub const FEE_BUCKET_0696: u64 = 245_940_899_909_974_929;
pub const FEE_BUCKET_0697: u64 = 253_715_260_083_692_983;
pub const FEE_BUCKET_0698: u64 = 261_715_575_848_485_750;
pub const FEE_BUCKET_0699: u64 = 269_948_023_198_596_973;
pub const FEE_BUCKET_0700: u64 = 278_418_987_979_071_089;
pub const FEE_BUCKET_0701: u64 = 287_135_076_333_372_049;
pub const FEE_BUCKET_0702: u64 = 296_103_126_157_086_374;
pub const FEE_BUCKET_0703: u64 = 305_330_218_548_826_887;
pub const FEE_BUCKET_0704: u64 = 314_823_690_278_584_260;
pub const FEE_BUCKET_0705: u64 = 324_591_146_261_118_124;
pub const FEE_BUCKET_0706: u64 = 334_640_473_039_607_305;
pub const FEE_BUCKET_0707: u64 = 344_979_852_283_482_186;
pub const FEE_BUCKET_0708: u64 = 355_617_773_307_104_737;
pub const FEE_BUCKET_0709: u64 = 366_563_047_597_280_895;
pub const FEE_BUCKET_0710: u64 = 377_824_822_358_477_773;
pub const FEE_BUCKET_0711: u64 = 389_412_597_120_723_662;
pub const FEE_BUCKET_0712: u64 = 401_336_241_388_989_154;
pub const FEE_BUCKET_0713: u64 = 413_606_013_362_785_990;
pub const FEE_BUCKET_0714: u64 = 426_232_581_755_064_180;
pub const FEE_BUCKET_0715: u64 = 439_226_046_696_646_204;
pub const FEE_BUCKET_0716: u64 = 452_596_960_721_125_510;
pub const FEE_BUCKET_0717: u64 = 466_356_350_818_359_463;
pub const FEE_BUCKET_0718: u64 = 480_515_742_588_991_762;
pub const FEE_BUCKET_0719: u64 = 495_087_184_355_006_586;
pub const FEE_BUCKET_0720: u64 = 510_083_272_239_480_705;
pub const FEE_BUCKET_0721: u64 = 525_517_178_470_126_998;
pub const FEE_BUCKET_0722: u64 = 541_402_681_817_710_237;
pub const FEE_BUCKET_0723: u64 = 557_754_199_795_894_430;
pub const FEE_BUCKET_0724: u64 = 574_586_823_495_424_633;
pub const FEE_BUCKET_0725: u64 = 591_916_344_135_849_872;
pub const FEE_BUCKET_0726: u64 = 609_759_282_361_757_892;
pub const FEE_BUCKET_0727: u64 = 628_132_918_391_104_459;
pub const FEE_BUCKET_0728: u64 = 647_055_322_187_448_613;
pub const FEE_BUCKET_0729: u64 = 666_545_384_616_706_553;
pub const FEE_BUCKET_0730: u64 = 686_622_848_573_352_010;
pub const FEE_BUCKET_0731: u64 = 707_308_339_039_311_993;
pub const FEE_BUCKET_0732: u64 = 728_623_397_018_988_673;
pub const FEE_BUCKET_0733: u64 = 750_590_511_373_929_671;
pub const FEE_BUCKET_0734: u64 = 773_233_152_567_075_979;
pub const FEE_BUCKET_0735: u64 = 796_575_809_333_855_416;
pub const FEE_BUCKET_0736: u64 = 820_644_026_363_730_387;
pub const FEE_BUCKET_0737: u64 = 845_464_437_971_130_051;
pub const FEE_BUCKET_0738: u64 = 871_064_811_806_334_262;
pub const FEE_BUCKET_0739: u64 = 897_474_093_618_892_879;
pub const FEE_BUCKET_0740: u64 = 924_722_455_925_643_633;
pub const FEE_BUCKET_0741: u64 = 952_841_349_633_379_122;
pub const FEE_BUCKET_0742: u64 = 981_863_558_521_379_492;
pub const FEE_BUCKET_0743: u64 = 1_011_823_246_351_522_230;
pub const FEE_BUCKET_0744: u64 = 1_042_756_202_546_927_104;
pub const FEE_BUCKET_0745: u64 = 1_074_699_700_646_458_872;
pub const FEE_BUCKET_0746: u64 = 1_107_692_659_632_322_602;
pub const FEE_BUCKET_0747: u64 = 1_141_775_714_150_272_466;
pub const FEE_BUCKET_0748: u64 = 1_176_991_294_701_788_875;
pub const FEE_BUCKET_0749: u64 = 1_213_383_717_701_920_146;
pub const FEE_BUCKET_0750: u64 = 1_250_999_277_451_522_329;
pub const FEE_BUCKET_0751: u64 = 1_289_886_348_026_322_881;
pub const FEE_BUCKET_0752: u64 = 1_330_095_487_979_080_667;
pub const FEE_BUCKET_0753: u64 = 1_371_679_553_298_725_166;
pub const FEE_BUCKET_0754: u64 = 1_414_693_816_564_520_827;
pub const FEE_BUCKET_0755: u64 = 1_459_196_091_371_105_403;
pub const FEE_BUCKET_0756: u64 = 1_505_246_872_114_587_401;
pub const FEE_BUCKET_0757: u64 = 1_552_909_483_147_216_928;
pub const FEE_BUCKET_0758: u64 = 1_602_250_233_561_719_615;
pub const FEE_BUCKET_0759: u64 = 1_653_338_576_238_188_876;
pub const FEE_BUCKET_0760: u64 = 1_706_247_274_471_161_745;
pub const FEE_BUCKET_0761: u64 = 1_761_052_578_837_370_312;
pub const FEE_BUCKET_0762: u64 = 1_817_834_409_068_232_602;
pub const FEE_BUCKET_0763: u64 = 1_876_676_557_374_092_492;
pub const FEE_BUCKET_0764: u64 = 1_937_667_890_107_856_300;
pub const FEE_BUCKET_0765: u64 = 2_000_901_563_666_347_582;
pub const FEE_BUCKET_0766: u64 = 2_066_475_254_654_017_162;
pub const FEE_BUCKET_0767: u64 = 2_134_491_404_197_135_456;
pub const FEE_BUCKET_0768: u64 = 2_205_057_475_401_503_238;
pub const FEE_BUCKET_0769: u64 = 2_278_286_237_973_322_919;
pub const FEE_BUCKET_0770: u64 = 2_354_295_072_009_072_657;
pub const FEE_BUCKET_0771: u64 = 2_433_206_318_002_368_163;
pub const FEE_BUCKET_0772: u64 = 2_515_147_662_180_287_190;
pub const FEE_BUCKET_0773: u64 = 2_600_252_528_227_901_981;
pub const FEE_BUCKET_0774: u64 = 2_688_660_484_604_776_697;
pub const FEE_BUCKET_0775: u64 = 2_780_517_677_243_058_173;
pub const FEE_BUCKET_0776: u64 = 2_875_977_265_589_519_709;
pub const FEE_BUCKET_0777: u64 = 2_975_199_873_843_276_707;
pub const FEE_BUCKET_0778: u64 = 3_078_353_063_989_994_504;
pub const FEE_BUCKET_0779: u64 = 3_185_611_823_044_329_960;
pub const FEE_BUCKET_0780: u64 = 3_297_158_052_036_528_099;
pub const FEE_BUCKET_0781: u64 = 3_413_180_050_794_093_793;
pub const FEE_BUCKET_0782: u64 = 3_533_872_022_606_498_948;
pub const FEE_BUCKET_0783: u64 = 3_659_435_595_687_001_755;
pub const FEE_BUCKET_0784: u64 = 3_790_079_347_182_756_815;
pub const FEE_BUCKET_0785: u64 = 3_926_019_356_941_261_116;
pub const FEE_BUCKET_0786: u64 = 4_067_479_745_506_638_487;
pub const FEE_BUCKET_0787: u64 = 4_214_692_240_558_049_789;
pub const FEE_BUCKET_0788: u64 = 4_367_896_780_654_690_766;
pub const FEE_BUCKET_0789: u64 = 4_527_342_127_665_896_162;
pub const FEE_BUCKET_0790: u64 = 4_693_286_505_472_355_607;
pub const FEE_BUCKET_0791: u64 = 4_865_998_275_132_097_963;
pub const FEE_BUCKET_0792: u64 = 5_045_756_648_351_465_332;
pub const FEE_BUCKET_0793: u64 = 5_232_852_464_195_132_636;
pub const FEE_BUCKET_0794: u64 = 5_427_588_039_236_336_160;
pub const FEE_BUCKET_0795: u64 = 5_630_277_080_410_755_210;
pub const FEE_BUCKET_0796: u64 = 5_841_244_646_777_078_041;
pub const FEE_BUCKET_0797: u64 = 6_060_827_153_157_847_752;
pub const FEE_BUCKET_0798: u64 = 6_289_372_393_464_512_385;
pub const FEE_BUCKET_0799: u64 = 6_527_239_595_737_409_343;
pub const FEE_BUCKET_0800: u64 = 6_774_799_500_683_671_360;
pub const FEE_BUCKET_0801: u64 = 7_032_434_486_538_216_905;
pub const FEE_BUCKET_0802: u64 = 7_300_538_710_927_776_236;
pub const FEE_BUCKET_0803: u64 = 7_579_518_272_975_992_530;
pub const FEE_BUCKET_0804: u64 = 7_869_791_382_645_657_721;
pub const FEE_BUCKET_0805: u64 = 8_171_788_550_443_529_202;
pub const FEE_BUCKET_0806: u64 = 8_485_952_778_346_086_708;
pub const FEE_BUCKET_0807: u64 = 8_812_740_766_290_470_936;
pub const FEE_BUCKET_0808: u64 = 9_152_623_112_551_980_060;
pub const FEE_BUCKET_0809: u64 = 9_506_084_535_877_033_815;
pub const FEE_BUCKET_0810: u64 = 9_873_624_102_328_017_501;
pub const FEE_BUCKET_0811: u64 = 10_255_755_466_814_118_096;
pub const FEE_BUCKET_0812: u64 = 10_653_007_111_621_544_176;
pub const FEE_BUCKET_0813: u64 = 11_065_922_603_975_565_950;
pub const FEE_BUCKET_0814: u64 = 11_495_061_854_638_357_537;
pub const FEE_BUCKET_0815: u64 = 11_941_002_398_681_213_916;
pub const FEE_BUCKET_0816: u64 = 12_404_340_688_445_421_426;
pub const FEE_BUCKET_0817: u64 = 12_885_692_411_592_267_297;
pub const FEE_BUCKET_0818: u64 = 13_385_693_824_886_071_099;
pub const FEE_BUCKET_0819: u64 = 13_905_002_097_072_980_637;
pub const FEE_BUCKET_0820: u64 = 14_444_296_685_738_247_890;
pub const FEE_BUCKET_0821: u64 = 15_004_279_739_536_509_350;
pub const FEE_BUCKET_0822: u64 = 15_585_676_507_053_117_846;
pub const FEE_BUCKET_0823: u64 = 16_189_235_768_147_693_912;
pub const FEE_BUCKET_0824: u64 = 16_815_730_291_546_401_122;
pub const FEE_BUCKET_0825: u64 = 17_465_957_326_661_665_437;
pub const FEE_BUCKET_0826: u64 = 18_140_739_110_705_912_322;
pub const FEE_BUCKET_0827: u64 = 18_000_000_000_000_000_000;
pub const FEE_BUCKET_0828: u64 = 18_001_000_000_000_000_000;
pub const FEE_BUCKET_0829: u64 = 18_002_000_000_000_000_000;
pub const FEE_BUCKET_0830: u64 = 18_003_000_000_000_000_000;
pub const FEE_BUCKET_0831: u64 = 18_004_000_000_000_000_000;
pub const FEE_BUCKET_0832: u64 = 18_005_000_000_000_000_000;
pub const FEE_BUCKET_0833: u64 = 18_006_000_000_000_000_000;
pub const FEE_BUCKET_0834: u64 = 18_007_000_000_000_000_000;
pub const FEE_BUCKET_0835: u64 = 18_008_000_000_000_000_000;
pub const FEE_BUCKET_0836: u64 = 18_009_000_000_000_000_000;
pub const FEE_BUCKET_0837: u64 = 18_010_000_000_000_000_000;
pub const FEE_BUCKET_0838: u64 = 18_011_000_000_000_000_000;
pub const FEE_BUCKET_0839: u64 = 18_012_000_000_000_000_000;
pub const FEE_BUCKET_0840: u64 = 18_013_000_000_000_000_000;
pub const FEE_BUCKET_0841: u64 = 18_014_000_000_000_000_000;
pub const FEE_BUCKET_0842: u64 = 18_015_000_000_000_000_000;
pub const FEE_BUCKET_0843: u64 = 18_016_000_000_000_000_000;
pub const FEE_BUCKET_0844: u64 = 18_017_000_000_000_000_000;
pub const FEE_BUCKET_0845: u64 = 18_018_000_000_000_000_000;
pub const FEE_BUCKET_0846: u64 = 18_019_000_000_000_000_000;
pub const FEE_BUCKET_0847: u64 = 18_020_000_000_000_000_000;
pub const FEE_BUCKET_0848: u64 = 18_021_000_000_000_000_000;
pub const FEE_BUCKET_0849: u64 = 18_022_000_000_000_000_000;
pub const FEE_BUCKET_0850: u64 = 18_023_000_000_000_000_000;
pub const FEE_BUCKET_0851: u64 = 18_024_000_000_000_000_000;
pub const FEE_BUCKET_0852: u64 = 18_025_000_000_000_000_000;
pub const FEE_BUCKET_0853: u64 = 18_026_000_000_000_000_000;
pub const FEE_BUCKET_0854: u64 = 18_027_000_000_000_000_000;
pub const FEE_BUCKET_0855: u64 = 18_028_000_000_000_000_000;
pub const FEE_BUCKET_0856: u64 = 18_029_000_000_000_000_000;
pub const FEE_BUCKET_0857: u64 = 18_030_000_000_000_000_000;
pub const FEE_BUCKET_0858: u64 = 18_031_000_000_000_000_000;
pub const FEE_BUCKET_0859: u64 = 18_032_000_000_000_000_000;
pub const FEE_BUCKET_0860: u64 = 18_033_000_000_000_000_000;
pub const FEE_BUCKET_0861: u64 = 18_034_000_000_000_000_000;
pub const FEE_BUCKET_0862: u64 = 18_035_000_000_000_000_000;
pub const FEE_BUCKET_0863: u64 = 18_036_000_000_000_000_000;
pub const FEE_BUCKET_0864: u64 = 18_037_000_000_000_000_000;
pub const FEE_BUCKET_0865: u64 = 18_038_000_000_000_000_000;
pub const FEE_BUCKET_0866: u64 = 18_039_000_000_000_000_000;
pub const FEE_BUCKET_0867: u64 = 18_040_000_000_000_000_000;
pub const FEE_BUCKET_0868: u64 = 18_041_000_000_000_000_000;
pub const FEE_BUCKET_0869: u64 = 18_042_000_000_000_000_000;
pub const FEE_BUCKET_0870: u64 = 18_043_000_000_000_000_000;
pub const FEE_BUCKET_0871: u64 = 18_044_000_000_000_000_000;
pub const FEE_BUCKET_0872: u64 = 18_045_000_000_000_000_000;
pub const FEE_BUCKET_0873: u64 = 18_046_000_000_000_000_000;
pub const FEE_BUCKET_0874: u64 = 18_047_000_000_000_000_000;
pub const FEE_BUCKET_0875: u64 = 18_048_000_000_000_000_000;
pub const FEE_BUCKET_0876: u64 = 18_049_000_000_000_000_000;
pub const FEE_BUCKET_0877: u64 = 18_050_000_000_000_000_000;
pub const FEE_BUCKET_0878: u64 = 18_051_000_000_000_000_000;
pub const FEE_BUCKET_0879: u64 = 18_052_000_000_000_000_000;
pub const FEE_BUCKET_0880: u64 = 18_053_000_000_000_000_000;
pub const FEE_BUCKET_0881: u64 = 18_054_000_000_000_000_000;
pub const FEE_BUCKET_0882: u64 = 18_055_000_000_000_000_000;
pub const FEE_BUCKET_0883: u64 = 18_056_000_000_000_000_000;
pub const FEE_BUCKET_0884: u64 = 18_057_000_000_000_000_000;
pub const FEE_BUCKET_0885: u64 = 18_058_000_000_000_000_000;
pub const FEE_BUCKET_0886: u64 = 18_059_000_000_000_000_000;
pub const FEE_BUCKET_0887: u64 = 18_060_000_000_000_000_000;
pub const FEE_BUCKET_0888: u64 = 18_061_000_000_000_000_000;
pub const FEE_BUCKET_0889: u64 = 18_062_000_000_000_000_000;
pub const FEE_BUCKET_0890: u64 = 18_063_000_000_000_000_000;
pub const FEE_BUCKET_0891: u64 = 18_064_000_000_000_000_000;
pub const FEE_BUCKET_0892: u64 = 18_065_000_000_000_000_000;
pub const FEE_BUCKET_0893: u64 = 18_066_000_000_000_000_000;
pub const FEE_BUCKET_0894: u64 = 18_067_000_000_000_000_000;
pub const FEE_BUCKET_0895: u64 = 18_068_000_000_000_000_000;
pub const FEE_BUCKET_0896: u64 = 18_069_000_000_000_000_000;
pub const FEE_BUCKET_0897: u64 = 18_070_000_000_000_000_000;
pub const FEE_BUCKET_0898: u64 = 18_071_000_000_000_000_000;
pub const FEE_BUCKET_0899: u64 = 18_072_000_000_000_000_000;
pub const FEE_BUCKET_0900: u64 = 18_073_000_000_000_000_000;
