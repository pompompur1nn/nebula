use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, json_size, merkle_root, HashPart},
    CHAIN_ID, DEVNET_AUTH_BYTES, DEVNET_PRIVACY_PROOF_BYTES, TARGET_BLOCK_MS,
};

pub const FEE_QUOTE_TARGET_TXS_PER_BLOCK: u64 = 64;
pub const FEE_QUOTE_CONGESTION_FREE_TXS: u64 = 8;
pub const FEE_QUOTE_FAST_MULTIPLIER_BPS: u64 = 12_500;
pub const DA_BATCH_NUMERATOR: u64 = 72;
pub const DA_BATCH_DENOMINATOR: u64 = 100;
pub const MIN_DA_BYTES_PER_TX: u64 = 96;
pub const DEFAULT_PACKING_MAX_TXS: u64 = 128;
pub const DEFAULT_PACKING_MAX_EXECUTION_FUEL: u64 = 8_000_000;
pub const DEFAULT_PACKING_MAX_PRIVACY_PROOFS: u64 = 256;
pub const DEFAULT_PACKING_MAX_CONTRACT_CALLS: u64 = 512;
pub const DEFAULT_PACKING_MAX_BATCHED_DA_BYTES: u64 = 768_000;
pub const DEFAULT_PACKING_MAX_PROOF_BYTES: u64 = 8_388_608;
pub const DEFAULT_PACKING_MAX_AUTHORIZATIONS: u64 = 512;
pub const DEFAULT_PACKING_LANE_RESERVE: u64 = 2;
pub const LOW_FEE_LANE_TYPE: &str = "low_fee";
pub const LOW_FEE_PRIVACY_TRANSFER_LANE_KEY: &str = "privacy_transfer";
pub const LOW_FEE_MONERO_BRIDGE_LANE_KEY: &str = "monero_bridge";
pub const LOW_FEE_SMALL_DEFI_CALL_LANE_KEY: &str = "small_defi_call";
pub const FEE_SMOOTHING_MAX_REBATE_BPS: u64 = 10_000;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct LowFeeLane {
    pub lane_type: String,
    pub lane_key: String,
}

impl LowFeeLane {
    pub fn new(lane_type: &str, lane_key: &str) -> Self {
        Self {
            lane_type: lane_type.to_string(),
            lane_key: lane_key.to_string(),
        }
    }

    pub fn privacy_transfers() -> Self {
        Self::new(LOW_FEE_LANE_TYPE, LOW_FEE_PRIVACY_TRANSFER_LANE_KEY)
    }

    pub fn monero_bridge_ops() -> Self {
        Self::new(LOW_FEE_LANE_TYPE, LOW_FEE_MONERO_BRIDGE_LANE_KEY)
    }

    pub fn small_defi_calls() -> Self {
        Self::new(LOW_FEE_LANE_TYPE, LOW_FEE_SMALL_DEFI_CALL_LANE_KEY)
    }

    pub fn lane_id(&self) -> String {
        low_fee_lane_id(&self.lane_type, &self.lane_key)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "lane_id": self.lane_id(),
            "lane_type": self.lane_type,
            "lane_key": self.lane_key,
        })
    }

    pub fn root(&self) -> String {
        domain_hash(
            "LOW-FEE-LANE-ROOT",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeeSmoothingLaneBudget {
    pub epoch: u64,
    pub lane_type: String,
    pub lane_key: String,
    pub budget_units: u64,
    pub spent_units: u64,
    pub reserved_units: u64,
    pub max_rebate_bps: u64,
    pub min_settled_fee_units: u64,
    pub settlement_root: String,
}

impl FeeSmoothingLaneBudget {
    pub fn new(
        epoch: u64,
        lane: LowFeeLane,
        budget_units: u64,
        max_rebate_bps: u64,
        min_settled_fee_units: u64,
        settlement_root: &str,
    ) -> Self {
        Self {
            epoch,
            lane_type: lane.lane_type,
            lane_key: lane.lane_key,
            budget_units,
            spent_units: 0,
            reserved_units: 0,
            max_rebate_bps: std::cmp::min(max_rebate_bps, FEE_SMOOTHING_MAX_REBATE_BPS),
            min_settled_fee_units,
            settlement_root: settlement_root.to_string(),
        }
    }

    pub fn privacy_transfers(
        epoch: u64,
        budget_units: u64,
        max_rebate_bps: u64,
        min_settled_fee_units: u64,
        settlement_root: &str,
    ) -> Self {
        Self::new(
            epoch,
            LowFeeLane::privacy_transfers(),
            budget_units,
            max_rebate_bps,
            min_settled_fee_units,
            settlement_root,
        )
    }

    pub fn monero_bridge_ops(
        epoch: u64,
        budget_units: u64,
        max_rebate_bps: u64,
        min_settled_fee_units: u64,
        settlement_root: &str,
    ) -> Self {
        Self::new(
            epoch,
            LowFeeLane::monero_bridge_ops(),
            budget_units,
            max_rebate_bps,
            min_settled_fee_units,
            settlement_root,
        )
    }

    pub fn small_defi_calls(
        epoch: u64,
        budget_units: u64,
        max_rebate_bps: u64,
        min_settled_fee_units: u64,
        settlement_root: &str,
    ) -> Self {
        Self::new(
            epoch,
            LowFeeLane::small_defi_calls(),
            budget_units,
            max_rebate_bps,
            min_settled_fee_units,
            settlement_root,
        )
    }

    pub fn lane_id(&self) -> String {
        low_fee_lane_id(&self.lane_type, &self.lane_key)
    }

    pub fn budget_id(&self) -> String {
        fee_smoothing_budget_id(self.epoch, &self.lane_type, &self.lane_key)
    }

    pub fn available_units(&self) -> u64 {
        self.budget_units
            .saturating_sub(self.spent_units)
            .saturating_sub(self.reserved_units)
    }

    pub fn bounded_rebate_units(&self, gross_fee_units: u64) -> u64 {
        let rebate_by_bps = fee_rebate_units(gross_fee_units, self.max_rebate_bps);
        let rebate_above_floor = gross_fee_units.saturating_sub(self.min_settled_fee_units);
        std::cmp::min(
            self.available_units(),
            std::cmp::min(rebate_by_bps, rebate_above_floor),
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "budget_id": self.budget_id(),
            "lane_id": self.lane_id(),
            "epoch": self.epoch,
            "lane_type": self.lane_type,
            "lane_key": self.lane_key,
            "budget_units": self.budget_units,
            "spent_units": self.spent_units,
            "reserved_units": self.reserved_units,
            "available_units": self.available_units(),
            "max_rebate_bps": self.max_rebate_bps,
            "min_settled_fee_units": self.min_settled_fee_units,
            "settlement_root": self.settlement_root,
        })
    }

    pub fn root(&self) -> String {
        domain_hash(
            "FEE-SMOOTHING-LANE-BUDGET-ROOT",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeeLaneRebate {
    pub epoch: u64,
    pub lane_type: String,
    pub lane_key: String,
    pub tx_id: String,
    pub fee_payer_commitment: String,
    pub fee_asset_id: String,
    pub gross_fee_units: u64,
    pub rebate_units: u64,
    pub settled_fee_units: u64,
    pub settlement_root: String,
}

impl FeeLaneRebate {
    pub fn new(
        epoch: u64,
        lane: LowFeeLane,
        tx_id: &str,
        fee_payer_commitment: &str,
        fee_asset_id: &str,
        gross_fee_units: u64,
        rebate_units: u64,
        settlement_root: &str,
    ) -> Self {
        let rebate_units = std::cmp::min(rebate_units, gross_fee_units);
        Self {
            epoch,
            lane_type: lane.lane_type,
            lane_key: lane.lane_key,
            tx_id: tx_id.to_string(),
            fee_payer_commitment: fee_payer_commitment.to_string(),
            fee_asset_id: fee_asset_id.to_string(),
            gross_fee_units,
            rebate_units,
            settled_fee_units: gross_fee_units.saturating_sub(rebate_units),
            settlement_root: settlement_root.to_string(),
        }
    }

    pub fn from_budget(
        budget: &FeeSmoothingLaneBudget,
        tx_id: &str,
        fee_payer_commitment: &str,
        fee_asset_id: &str,
        gross_fee_units: u64,
    ) -> Self {
        Self::new(
            budget.epoch,
            LowFeeLane::new(&budget.lane_type, &budget.lane_key),
            tx_id,
            fee_payer_commitment,
            fee_asset_id,
            gross_fee_units,
            budget.bounded_rebate_units(gross_fee_units),
            &budget.settlement_root,
        )
    }

    pub fn lane_id(&self) -> String {
        low_fee_lane_id(&self.lane_type, &self.lane_key)
    }

    pub fn rebate_id(&self) -> String {
        fee_lane_rebate_id(
            self.epoch,
            &self.lane_type,
            &self.lane_key,
            &self.tx_id,
            &self.fee_payer_commitment,
            &self.fee_asset_id,
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "rebate_id": self.rebate_id(),
            "lane_id": self.lane_id(),
            "epoch": self.epoch,
            "lane_type": self.lane_type,
            "lane_key": self.lane_key,
            "tx_id": self.tx_id,
            "fee_payer_commitment": self.fee_payer_commitment,
            "fee_asset_id": self.fee_asset_id,
            "gross_fee_units": self.gross_fee_units,
            "rebate_units": self.rebate_units,
            "settled_fee_units": self.settled_fee_units,
            "settlement_root": self.settlement_root,
        })
    }

    pub fn root(&self) -> String {
        domain_hash(
            "FEE-LANE-REBATE-ROOT",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeeLaneCredit {
    pub epoch: u64,
    pub lane_type: String,
    pub lane_key: String,
    pub credit_owner_commitment: String,
    pub fee_asset_id: String,
    pub credit_units: u64,
    pub spent_units: u64,
    pub expires_at_height: u64,
    pub source_rebate_id: String,
    pub settlement_root: String,
}

impl FeeLaneCredit {
    pub fn new(
        epoch: u64,
        lane: LowFeeLane,
        credit_owner_commitment: &str,
        fee_asset_id: &str,
        credit_units: u64,
        expires_at_height: u64,
        source_rebate_id: &str,
        settlement_root: &str,
    ) -> Self {
        Self {
            epoch,
            lane_type: lane.lane_type,
            lane_key: lane.lane_key,
            credit_owner_commitment: credit_owner_commitment.to_string(),
            fee_asset_id: fee_asset_id.to_string(),
            credit_units,
            spent_units: 0,
            expires_at_height,
            source_rebate_id: source_rebate_id.to_string(),
            settlement_root: settlement_root.to_string(),
        }
    }

    pub fn from_rebate(
        rebate: &FeeLaneRebate,
        credit_owner_commitment: &str,
        expires_at_height: u64,
    ) -> Self {
        Self::new(
            rebate.epoch,
            LowFeeLane::new(&rebate.lane_type, &rebate.lane_key),
            credit_owner_commitment,
            &rebate.fee_asset_id,
            rebate.rebate_units,
            expires_at_height,
            &rebate.rebate_id(),
            &rebate.settlement_root,
        )
    }

    pub fn lane_id(&self) -> String {
        low_fee_lane_id(&self.lane_type, &self.lane_key)
    }

    pub fn credit_id(&self) -> String {
        fee_lane_credit_id(
            self.epoch,
            &self.lane_type,
            &self.lane_key,
            &self.credit_owner_commitment,
            &self.fee_asset_id,
            &self.source_rebate_id,
            self.expires_at_height,
        )
    }

    pub fn available_units(&self) -> u64 {
        self.credit_units.saturating_sub(self.spent_units)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "credit_id": self.credit_id(),
            "lane_id": self.lane_id(),
            "epoch": self.epoch,
            "lane_type": self.lane_type,
            "lane_key": self.lane_key,
            "credit_owner_commitment": self.credit_owner_commitment,
            "fee_asset_id": self.fee_asset_id,
            "credit_units": self.credit_units,
            "spent_units": self.spent_units,
            "available_units": self.available_units(),
            "expires_at_height": self.expires_at_height,
            "source_rebate_id": self.source_rebate_id,
            "settlement_root": self.settlement_root,
        })
    }

    pub fn root(&self) -> String {
        domain_hash(
            "FEE-LANE-CREDIT-ROOT",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeeSmoothingState {
    pub epoch: u64,
    pub lane_budgets: Vec<FeeSmoothingLaneBudget>,
    pub rebates: Vec<FeeLaneRebate>,
    pub credits: Vec<FeeLaneCredit>,
    pub settlement_roots: Vec<String>,
}

impl FeeSmoothingState {
    pub fn empty(epoch: u64) -> Self {
        Self {
            epoch,
            lane_budgets: Vec::new(),
            rebates: Vec::new(),
            credits: Vec::new(),
            settlement_roots: Vec::new(),
        }
    }

    pub fn new(
        epoch: u64,
        lane_budgets: Vec<FeeSmoothingLaneBudget>,
        rebates: Vec<FeeLaneRebate>,
        credits: Vec<FeeLaneCredit>,
        settlement_roots: Vec<String>,
    ) -> Self {
        Self {
            epoch,
            lane_budgets,
            rebates,
            credits,
            settlement_roots,
        }
    }

    pub fn lane_budget(&self, lane_type: &str, lane_key: &str) -> Option<&FeeSmoothingLaneBudget> {
        self.lane_budgets
            .iter()
            .filter(|budget| budget.lane_type == lane_type && budget.lane_key == lane_key)
            .min_by_key(|budget| budget.budget_id())
    }

    pub fn available_budget_units(&self, lane_type: &str, lane_key: &str) -> u64 {
        self.lane_budgets
            .iter()
            .filter(|budget| budget.lane_type == lane_type && budget.lane_key == lane_key)
            .fold(0_u64, |total, budget| {
                total.saturating_add(budget.available_units())
            })
    }

    pub fn rebate_for_lane_fee(
        &self,
        lane_type: &str,
        lane_key: &str,
        gross_fee_units: u64,
    ) -> u64 {
        self.lane_budgets
            .iter()
            .filter(|budget| budget.lane_type == lane_type && budget.lane_key == lane_key)
            .map(|budget| budget.bounded_rebate_units(gross_fee_units))
            .max()
            .unwrap_or(0)
    }

    pub fn smoothed_fee_units(&self, lane_type: &str, lane_key: &str, gross_fee_units: u64) -> u64 {
        gross_fee_units.saturating_sub(self.rebate_for_lane_fee(
            lane_type,
            lane_key,
            gross_fee_units,
        ))
    }

    pub fn total_rebate_units(&self) -> u64 {
        self.rebates.iter().fold(0_u64, |total, rebate| {
            total.saturating_add(rebate.rebate_units)
        })
    }

    pub fn total_credit_units(&self) -> u64 {
        self.credits.iter().fold(0_u64, |total, credit| {
            total.saturating_add(credit.credit_units)
        })
    }

    pub fn budget_root(&self) -> String {
        merkle_root("FEE-SMOOTHING-BUDGET", &self.sorted_budget_records())
    }

    pub fn rebate_root(&self) -> String {
        merkle_root("FEE-SMOOTHING-REBATE", &self.sorted_rebate_records())
    }

    pub fn credit_root(&self) -> String {
        merkle_root("FEE-SMOOTHING-CREDIT", &self.sorted_credit_records())
    }

    pub fn settlement_root(&self) -> String {
        fee_smoothing_settlement_root(&self.canonical_settlement_roots())
    }

    pub fn state_root(&self) -> String {
        fee_smoothing_state_root_from_record(&self.public_record_without_root())
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_root();
        record
            .as_object_mut()
            .expect("fee smoothing state record object")
            .insert("state_root".to_string(), Value::String(self.state_root()));
        record
    }

    fn public_record_without_root(&self) -> Value {
        let settlement_roots = self.canonical_settlement_roots();
        json!({
            "epoch": self.epoch,
            "lane_budget_count": self.lane_budgets.len() as u64,
            "rebate_count": self.rebates.len() as u64,
            "credit_count": self.credits.len() as u64,
            "budget_root": self.budget_root(),
            "rebate_root": self.rebate_root(),
            "credit_root": self.credit_root(),
            "settlement_root": fee_smoothing_settlement_root(&settlement_roots),
            "settlement_roots": settlement_roots,
            "total_rebate_units": self.total_rebate_units(),
            "total_credit_units": self.total_credit_units(),
            "lane_budgets": self.sorted_budget_records(),
            "rebates": self.sorted_rebate_records(),
            "credits": self.sorted_credit_records(),
        })
    }

    fn sorted_budget_records(&self) -> Vec<Value> {
        let mut records = self
            .lane_budgets
            .iter()
            .map(|budget| (budget.budget_id(), budget.public_record()))
            .collect::<Vec<_>>();
        records.sort_by(|left, right| left.0.cmp(&right.0));
        records.into_iter().map(|(_, record)| record).collect()
    }

    fn sorted_rebate_records(&self) -> Vec<Value> {
        let mut records = self
            .rebates
            .iter()
            .map(|rebate| (rebate.rebate_id(), rebate.public_record()))
            .collect::<Vec<_>>();
        records.sort_by(|left, right| left.0.cmp(&right.0));
        records.into_iter().map(|(_, record)| record).collect()
    }

    fn sorted_credit_records(&self) -> Vec<Value> {
        let mut records = self
            .credits
            .iter()
            .map(|credit| (credit.credit_id(), credit.public_record()))
            .collect::<Vec<_>>();
        records.sort_by(|left, right| left.0.cmp(&right.0));
        records.into_iter().map(|(_, record)| record).collect()
    }

    fn canonical_settlement_roots(&self) -> Vec<String> {
        let mut roots = self
            .settlement_roots
            .iter()
            .filter(|root| !root.is_empty())
            .cloned()
            .collect::<BTreeSet<_>>();
        roots.extend(
            self.lane_budgets
                .iter()
                .map(|budget| budget.settlement_root.clone())
                .filter(|root| !root.is_empty()),
        );
        roots.extend(
            self.rebates
                .iter()
                .map(|rebate| rebate.settlement_root.clone())
                .filter(|root| !root.is_empty()),
        );
        roots.extend(
            self.credits
                .iter()
                .map(|credit| credit.settlement_root.clone())
                .filter(|root| !root.is_empty()),
        );
        roots.into_iter().collect()
    }
}

pub fn low_fee_lane_id(lane_type: &str, lane_key: &str) -> String {
    domain_hash(
        "LOW-FEE-LANE",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(lane_type),
            HashPart::Str(lane_key),
        ],
        32,
    )
}

pub fn fee_smoothing_budget_id(epoch: u64, lane_type: &str, lane_key: &str) -> String {
    domain_hash(
        "FEE-SMOOTHING-BUDGET",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(epoch as i128),
            HashPart::Str(lane_type),
            HashPart::Str(lane_key),
        ],
        32,
    )
}

pub fn fee_lane_rebate_id(
    epoch: u64,
    lane_type: &str,
    lane_key: &str,
    tx_id: &str,
    fee_payer_commitment: &str,
    fee_asset_id: &str,
) -> String {
    domain_hash(
        "FEE-LANE-REBATE",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(epoch as i128),
            HashPart::Str(lane_type),
            HashPart::Str(lane_key),
            HashPart::Str(tx_id),
            HashPart::Str(fee_payer_commitment),
            HashPart::Str(fee_asset_id),
        ],
        32,
    )
}

pub fn fee_lane_credit_id(
    epoch: u64,
    lane_type: &str,
    lane_key: &str,
    credit_owner_commitment: &str,
    fee_asset_id: &str,
    source_rebate_id: &str,
    expires_at_height: u64,
) -> String {
    domain_hash(
        "FEE-LANE-CREDIT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(epoch as i128),
            HashPart::Str(lane_type),
            HashPart::Str(lane_key),
            HashPart::Str(credit_owner_commitment),
            HashPart::Str(fee_asset_id),
            HashPart::Str(source_rebate_id),
            HashPart::Int(expires_at_height as i128),
        ],
        32,
    )
}

pub fn fee_rebate_units(gross_fee_units: u64, rebate_bps: u64) -> u64 {
    let bounded_bps = std::cmp::min(rebate_bps, FEE_SMOOTHING_MAX_REBATE_BPS);
    ((gross_fee_units as u128) * (bounded_bps as u128) / 10_000u128).min(u64::MAX as u128) as u64
}

pub fn fee_smoothing_settlement_root(settlement_roots: &[String]) -> String {
    let records = settlement_roots
        .iter()
        .filter(|root| !root.is_empty())
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .map(Value::String)
        .collect::<Vec<_>>();
    merkle_root("FEE-SMOOTHING-SETTLEMENT", &records)
}

pub fn fee_smoothing_state_root(state: &FeeSmoothingState) -> String {
    state.state_root()
}

pub fn fee_smoothing_state_root_from_record(record: &Value) -> String {
    domain_hash("FEE-SMOOTHING-STATE", &[HashPart::Json(record)], 32)
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeeMarketResource {
    pub public_record: Value,
    pub execution_fuel: u64,
    pub privacy_proof_count: u64,
    pub contract_call_count: u64,
    pub observed_fee_units: u64,
    pub estimated_proof_bytes: u64,
    pub authorization_count: u64,
    pub fee_asset_ids: Vec<String>,
    pub fee_lanes: Vec<(String, String)>,
}

impl FeeMarketResource {
    pub fn operation(kind: &str, observed_fee_units: u64, fee_asset_id: &str) -> Self {
        let mut fee_asset_ids = Vec::new();
        if !fee_asset_id.is_empty() {
            fee_asset_ids.push(fee_asset_id.to_string());
        }
        Self {
            public_record: json!({"kind": kind, "fee": observed_fee_units}),
            execution_fuel: 0,
            privacy_proof_count: 1,
            contract_call_count: 0,
            observed_fee_units,
            estimated_proof_bytes: DEVNET_PRIVACY_PROOF_BYTES,
            authorization_count: 1,
            fee_asset_ids,
            fee_lanes: vec![("operation".to_string(), kind.to_string())],
        }
    }

    pub fn proof_job(
        kind: &str,
        proof_system: &str,
        estimated_proof_bytes: u64,
        observed_fee_units: u64,
        fee_asset_id: &str,
    ) -> Self {
        let mut resource = Self::operation(kind, observed_fee_units, fee_asset_id);
        resource.privacy_proof_count = 1;
        resource.estimated_proof_bytes = estimated_proof_bytes;
        resource.fee_lanes = vec![
            ("proof_job_kind".to_string(), kind.to_string()),
            ("proof_system".to_string(), proof_system.to_string()),
        ];
        resource
    }

    pub fn with_low_fee_lane(mut self, lane: LowFeeLane) -> Self {
        let fee_lane = (lane.lane_type, lane.lane_key);
        if !self.fee_lanes.contains(&fee_lane) {
            self.fee_lanes.push(fee_lane);
        }
        self
    }

    pub fn with_privacy_transfer_low_fee_lane(self) -> Self {
        self.with_low_fee_lane(LowFeeLane::privacy_transfers())
    }

    pub fn with_monero_bridge_low_fee_lane(self) -> Self {
        self.with_low_fee_lane(LowFeeLane::monero_bridge_ops())
    }

    pub fn with_small_defi_low_fee_lane(self) -> Self {
        self.with_low_fee_lane(LowFeeLane::small_defi_calls())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalFeeMarketLane {
    pub lane_type: String,
    pub lane_key: String,
    pub tx_count: u64,
    pub execution_fuel: u64,
    pub uncompressed_da_bytes: u64,
    pub batched_da_bytes: u64,
    pub observed_fee_units: u64,
    pub privacy_proof_count: u64,
    pub contract_call_count: u64,
    pub fee_density_microunits: u64,
}

impl LocalFeeMarketLane {
    pub fn lane_id(&self) -> String {
        domain_hash(
            "LOCAL-FEE-MARKET-LANE",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&self.lane_type),
                HashPart::Str(&self.lane_key),
            ],
            32,
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "lane_id": self.lane_id(),
            "lane_type": self.lane_type,
            "lane_key": self.lane_key,
            "tx_count": self.tx_count,
            "execution_fuel": self.execution_fuel,
            "uncompressed_da_bytes": self.uncompressed_da_bytes,
            "batched_da_bytes": self.batched_da_bytes,
            "observed_fee_units": self.observed_fee_units,
            "privacy_proof_count": self.privacy_proof_count,
            "contract_call_count": self.contract_call_count,
            "fee_density_microunits": self.fee_density_microunits,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockExecutionProfile {
    pub target_block_ms: u64,
    pub tx_count: u64,
    pub privacy_proof_count: u64,
    pub contract_call_count: u64,
    pub execution_fuel: u64,
    pub uncompressed_da_bytes: u64,
    pub batched_da_bytes: u64,
    pub amortized_da_bytes_per_tx: u64,
    pub estimated_proof_bytes: u64,
    pub authorization_count: u64,
    pub estimated_authorization_bytes: u64,
    pub observed_fee_units: u64,
    pub fee_asset_count: u64,
    pub fee_density_microunits: u64,
    pub batch_discount_bps: u64,
    pub local_fee_market_root: String,
    pub local_fee_lane_count: u64,
    pub max_local_fee_density_microunits: u64,
}

impl BlockExecutionProfile {
    pub fn empty() -> Self {
        Self {
            target_block_ms: TARGET_BLOCK_MS,
            tx_count: 0,
            privacy_proof_count: 0,
            contract_call_count: 0,
            execution_fuel: 0,
            uncompressed_da_bytes: 0,
            batched_da_bytes: 0,
            amortized_da_bytes_per_tx: 0,
            estimated_proof_bytes: 0,
            authorization_count: 0,
            estimated_authorization_bytes: 0,
            observed_fee_units: 0,
            fee_asset_count: 0,
            fee_density_microunits: 0,
            batch_discount_bps: 0,
            local_fee_market_root: merkle_root("LOCAL-FEE-MARKET", &[]),
            local_fee_lane_count: 0,
            max_local_fee_density_microunits: 0,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "target_block_ms": self.target_block_ms,
            "tx_count": self.tx_count,
            "privacy_proof_count": self.privacy_proof_count,
            "contract_call_count": self.contract_call_count,
            "execution_fuel": self.execution_fuel,
            "uncompressed_da_bytes": self.uncompressed_da_bytes,
            "batched_da_bytes": self.batched_da_bytes,
            "amortized_da_bytes_per_tx": self.amortized_da_bytes_per_tx,
            "estimated_proof_bytes": self.estimated_proof_bytes,
            "authorization_count": self.authorization_count,
            "estimated_authorization_bytes": self.estimated_authorization_bytes,
            "observed_fee_units": self.observed_fee_units,
            "fee_asset_count": self.fee_asset_count,
            "fee_density_microunits": self.fee_density_microunits,
            "batch_discount_bps": self.batch_discount_bps,
            "local_fee_market_root": self.local_fee_market_root,
            "local_fee_lane_count": self.local_fee_lane_count,
            "max_local_fee_density_microunits": self.max_local_fee_density_microunits,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeeQuote {
    pub operation: String,
    pub pending_tx_count: u64,
    pub projected_tx_count: u64,
    pub candidate_profile: BlockExecutionProfile,
    pub pending_profile: BlockExecutionProfile,
    pub projected_profile: BlockExecutionProfile,
    pub marginal_uncompressed_da_bytes: i64,
    pub marginal_batched_da_bytes: i64,
    pub marginal_batch_savings_bps: u64,
    pub minimum_fee_units: u64,
    pub recommended_fee_units: u64,
    pub fast_fee_units: u64,
    pub congestion_multiplier_bps: u64,
    pub target_block_ms: u64,
    pub target_inclusion_blocks: u64,
    pub estimated_inclusion_ms: u64,
    pub quote_hash: String,
}

impl FeeQuote {
    pub fn public_record(&self) -> Value {
        json!({
            "operation": self.operation,
            "pending_tx_count": self.pending_tx_count,
            "projected_tx_count": self.projected_tx_count,
            "candidate_profile": self.candidate_profile.public_record(),
            "pending_profile": self.pending_profile.public_record(),
            "projected_profile": self.projected_profile.public_record(),
            "marginal_uncompressed_da_bytes": self.marginal_uncompressed_da_bytes,
            "marginal_batched_da_bytes": self.marginal_batched_da_bytes,
            "marginal_batch_savings_bps": self.marginal_batch_savings_bps,
            "minimum_fee_units": self.minimum_fee_units,
            "recommended_fee_units": self.recommended_fee_units,
            "fast_fee_units": self.fast_fee_units,
            "congestion_multiplier_bps": self.congestion_multiplier_bps,
            "target_block_ms": self.target_block_ms,
            "target_inclusion_blocks": self.target_inclusion_blocks,
            "estimated_inclusion_ms": self.estimated_inclusion_ms,
            "quote_hash": self.quote_hash,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockPackingPolicy {
    pub max_tx_count: u64,
    pub max_execution_fuel: u64,
    pub max_privacy_proof_count: u64,
    pub max_contract_call_count: u64,
    pub max_batched_da_bytes: u64,
    pub max_estimated_proof_bytes: u64,
    pub max_authorization_count: u64,
    pub min_fee_density_microunits: u64,
    pub lane_reserve_tx_count: u64,
}

impl Default for BlockPackingPolicy {
    fn default() -> Self {
        Self {
            max_tx_count: DEFAULT_PACKING_MAX_TXS,
            max_execution_fuel: DEFAULT_PACKING_MAX_EXECUTION_FUEL,
            max_privacy_proof_count: DEFAULT_PACKING_MAX_PRIVACY_PROOFS,
            max_contract_call_count: DEFAULT_PACKING_MAX_CONTRACT_CALLS,
            max_batched_da_bytes: DEFAULT_PACKING_MAX_BATCHED_DA_BYTES,
            max_estimated_proof_bytes: DEFAULT_PACKING_MAX_PROOF_BYTES,
            max_authorization_count: DEFAULT_PACKING_MAX_AUTHORIZATIONS,
            min_fee_density_microunits: 0,
            lane_reserve_tx_count: DEFAULT_PACKING_LANE_RESERVE,
        }
    }
}

impl BlockPackingPolicy {
    pub fn public_record(&self) -> Value {
        json!({
            "max_tx_count": self.max_tx_count,
            "max_execution_fuel": self.max_execution_fuel,
            "max_privacy_proof_count": self.max_privacy_proof_count,
            "max_contract_call_count": self.max_contract_call_count,
            "max_batched_da_bytes": self.max_batched_da_bytes,
            "max_estimated_proof_bytes": self.max_estimated_proof_bytes,
            "max_authorization_count": self.max_authorization_count,
            "min_fee_density_microunits": self.min_fee_density_microunits,
            "lane_reserve_tx_count": self.lane_reserve_tx_count,
        })
    }

    pub fn disabled_limits() -> Self {
        Self {
            max_tx_count: u64::MAX,
            max_execution_fuel: u64::MAX,
            max_privacy_proof_count: u64::MAX,
            max_contract_call_count: u64::MAX,
            max_batched_da_bytes: u64::MAX,
            max_estimated_proof_bytes: u64::MAX,
            max_authorization_count: u64::MAX,
            min_fee_density_microunits: 0,
            lane_reserve_tx_count: 0,
        }
    }

    pub fn accepts_profile(&self, profile: &BlockExecutionProfile) -> bool {
        profile.tx_count <= self.max_tx_count
            && profile.execution_fuel <= self.max_execution_fuel
            && profile.privacy_proof_count <= self.max_privacy_proof_count
            && profile.contract_call_count <= self.max_contract_call_count
            && profile.batched_da_bytes <= self.max_batched_da_bytes
            && profile.estimated_proof_bytes <= self.max_estimated_proof_bytes
            && profile.authorization_count <= self.max_authorization_count
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockPackingCandidate {
    pub pending_index: u64,
    pub tx_kind: String,
    pub primary_lane_type: String,
    pub primary_lane_key: String,
    pub uncompressed_da_bytes: u64,
    pub resource_weight_units: u64,
    pub observed_fee_units: u64,
    pub fee_density_microunits: u64,
    pub estimated_proof_bytes: u64,
    pub execution_fuel: u64,
    pub privacy_proof_count: u64,
    pub contract_call_count: u64,
    pub authorization_count: u64,
}

impl BlockPackingCandidate {
    pub fn lane_id(&self) -> String {
        domain_hash(
            "BLOCK-PACKING-LANE",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&self.primary_lane_type),
                HashPart::Str(&self.primary_lane_key),
            ],
            32,
        )
    }

    pub fn candidate_id(&self) -> String {
        domain_hash(
            "BLOCK-PACKING-CANDIDATE",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Int(self.pending_index as i128),
                HashPart::Str(&self.tx_kind),
                HashPart::Str(&self.primary_lane_type),
                HashPart::Str(&self.primary_lane_key),
                HashPart::Int(self.resource_weight_units as i128),
                HashPart::Int(self.observed_fee_units as i128),
            ],
            32,
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "candidate_id": self.candidate_id(),
            "pending_index": self.pending_index,
            "tx_kind": self.tx_kind,
            "primary_lane_type": self.primary_lane_type,
            "primary_lane_key": self.primary_lane_key,
            "lane_id": self.lane_id(),
            "uncompressed_da_bytes": self.uncompressed_da_bytes,
            "resource_weight_units": self.resource_weight_units,
            "observed_fee_units": self.observed_fee_units,
            "fee_density_microunits": self.fee_density_microunits,
            "estimated_proof_bytes": self.estimated_proof_bytes,
            "execution_fuel": self.execution_fuel,
            "privacy_proof_count": self.privacy_proof_count,
            "contract_call_count": self.contract_call_count,
            "authorization_count": self.authorization_count,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockPackingSelection {
    pub policy: BlockPackingPolicy,
    pub selected_indices: Vec<u64>,
    pub deferred_indices: Vec<u64>,
    pub selected_profile: BlockExecutionProfile,
    pub deferred_profile: BlockExecutionProfile,
    pub selected_candidates: Vec<BlockPackingCandidate>,
    pub deferred_candidates: Vec<BlockPackingCandidate>,
    pub fairness_pass_count: u64,
    pub density_pass_count: u64,
    pub rejected_low_density_count: u64,
}

impl BlockPackingSelection {
    pub fn packing_root(&self) -> String {
        domain_hash(
            "BLOCK-PACKING-SELECTION",
            &[HashPart::Json(&self.public_record_without_root())],
            32,
        )
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_root();
        record
            .as_object_mut()
            .expect("block packing record object")
            .insert(
                "packing_root".to_string(),
                Value::String(self.packing_root()),
            );
        record
    }

    fn public_record_without_root(&self) -> Value {
        json!({
            "policy": self.policy.public_record(),
            "selected_indices": self.selected_indices,
            "deferred_indices": self.deferred_indices,
            "selected_count": self.selected_indices.len() as u64,
            "deferred_count": self.deferred_indices.len() as u64,
            "selected_profile": self.selected_profile.public_record(),
            "deferred_profile": self.deferred_profile.public_record(),
            "selected_candidate_root": merkle_root(
                "BLOCK-PACKING-SELECTED-CANDIDATE",
                &self.selected_candidates.iter().map(BlockPackingCandidate::public_record).collect::<Vec<_>>(),
            ),
            "deferred_candidate_root": merkle_root(
                "BLOCK-PACKING-DEFERRED-CANDIDATE",
                &self.deferred_candidates.iter().map(BlockPackingCandidate::public_record).collect::<Vec<_>>(),
            ),
            "selected_candidates": self.selected_candidates.iter().map(BlockPackingCandidate::public_record).collect::<Vec<_>>(),
            "deferred_candidates": self.deferred_candidates.iter().map(BlockPackingCandidate::public_record).collect::<Vec<_>>(),
            "fairness_pass_count": self.fairness_pass_count,
            "density_pass_count": self.density_pass_count,
            "rejected_low_density_count": self.rejected_low_density_count,
        })
    }
}

#[derive(Default)]
struct LaneBucket {
    tx_count: u64,
    execution_fuel: u64,
    uncompressed_da_bytes: u64,
    observed_fee_units: u64,
    privacy_proof_count: u64,
    contract_call_count: u64,
}

pub fn batched_da_bytes(uncompressed_da_bytes: u64, tx_count: u64) -> u64 {
    if tx_count == 0 || uncompressed_da_bytes == 0 {
        return 0;
    }
    let batched_floor = tx_count * MIN_DA_BYTES_PER_TX;
    let batched = std::cmp::max(
        batched_floor,
        uncompressed_da_bytes * DA_BATCH_NUMERATOR / DA_BATCH_DENOMINATOR,
    );
    std::cmp::min(batched, uncompressed_da_bytes)
}

fn ceil_div(numerator: u64, denominator: u64) -> u64 {
    if denominator == 0 {
        0
    } else {
        numerator.div_ceil(denominator)
    }
}

fn fee_density_microunits(observed_fee_units: u64, resource_units: u64) -> u64 {
    if resource_units == 0 {
        return 0;
    }
    ((observed_fee_units as u128) * 1_000_000u128 / resource_units as u128).min(u64::MAX as u128)
        as u64
}

pub fn local_fee_markets_for_resources(resources: &[FeeMarketResource]) -> Vec<LocalFeeMarketLane> {
    let mut buckets: BTreeMap<(String, String), LaneBucket> = BTreeMap::new();
    for resource in resources {
        let mut lanes = resource
            .fee_lanes
            .iter()
            .cloned()
            .collect::<BTreeSet<(String, String)>>();
        if lanes.is_empty() {
            let kind = resource
                .public_record
                .get("kind")
                .and_then(Value::as_str)
                .unwrap_or("unknown")
                .to_string();
            lanes.insert(("operation".to_string(), kind));
        }
        let uncompressed_da_bytes = json_size(&resource.public_record) as u64;
        for lane in lanes {
            let bucket = buckets.entry(lane).or_default();
            bucket.tx_count += 1;
            bucket.execution_fuel += resource.execution_fuel;
            bucket.uncompressed_da_bytes += uncompressed_da_bytes;
            bucket.observed_fee_units += resource.observed_fee_units;
            bucket.privacy_proof_count += resource.privacy_proof_count;
            bucket.contract_call_count += resource.contract_call_count;
        }
    }

    buckets
        .into_iter()
        .map(|((lane_type, lane_key), bucket)| {
            let batched_da_bytes = batched_da_bytes(bucket.uncompressed_da_bytes, bucket.tx_count);
            let fee_density_microunits =
                fee_density_microunits(bucket.observed_fee_units, batched_da_bytes);
            LocalFeeMarketLane {
                lane_type,
                lane_key,
                tx_count: bucket.tx_count,
                execution_fuel: bucket.execution_fuel,
                uncompressed_da_bytes: bucket.uncompressed_da_bytes,
                batched_da_bytes,
                observed_fee_units: bucket.observed_fee_units,
                privacy_proof_count: bucket.privacy_proof_count,
                contract_call_count: bucket.contract_call_count,
                fee_density_microunits,
            }
        })
        .collect()
}

pub fn execution_profile_from_resources(resources: &[FeeMarketResource]) -> BlockExecutionProfile {
    if resources.is_empty() {
        return BlockExecutionProfile::empty();
    }
    let tx_count = resources.len() as u64;
    let local_fee_markets = local_fee_markets_for_resources(resources);
    let uncompressed_da_bytes = resources
        .iter()
        .map(|resource| json_size(&resource.public_record) as u64)
        .sum::<u64>();
    let batched_da_bytes = batched_da_bytes(uncompressed_da_bytes, tx_count);
    let observed_fee_units = resources
        .iter()
        .map(|resource| resource.observed_fee_units)
        .sum::<u64>();
    let fee_density_microunits = fee_density_microunits(observed_fee_units, batched_da_bytes);
    let batch_discount_bps = ((uncompressed_da_bytes - batched_da_bytes) * 10_000)
        .checked_div(uncompressed_da_bytes)
        .unwrap_or(0);
    let fee_asset_ids = resources
        .iter()
        .flat_map(|resource| resource.fee_asset_ids.iter().cloned())
        .collect::<BTreeSet<_>>();
    let lane_records = local_fee_markets
        .iter()
        .map(LocalFeeMarketLane::public_record)
        .collect::<Vec<_>>();
    BlockExecutionProfile {
        target_block_ms: TARGET_BLOCK_MS,
        tx_count,
        privacy_proof_count: resources
            .iter()
            .map(|resource| resource.privacy_proof_count)
            .sum(),
        contract_call_count: resources
            .iter()
            .map(|resource| resource.contract_call_count)
            .sum(),
        execution_fuel: resources
            .iter()
            .map(|resource| resource.execution_fuel)
            .sum(),
        uncompressed_da_bytes,
        batched_da_bytes,
        amortized_da_bytes_per_tx: ceil_div(batched_da_bytes, tx_count),
        estimated_proof_bytes: resources
            .iter()
            .map(|resource| resource.estimated_proof_bytes)
            .sum(),
        authorization_count: resources
            .iter()
            .map(|resource| resource.authorization_count)
            .sum(),
        estimated_authorization_bytes: resources
            .iter()
            .map(|resource| resource.authorization_count)
            .sum::<u64>()
            * DEVNET_AUTH_BYTES,
        observed_fee_units,
        fee_asset_count: fee_asset_ids.len() as u64,
        fee_density_microunits,
        batch_discount_bps,
        local_fee_market_root: merkle_root("LOCAL-FEE-MARKET", &lane_records),
        local_fee_lane_count: local_fee_markets.len() as u64,
        max_local_fee_density_microunits: local_fee_markets
            .iter()
            .map(|lane| lane.fee_density_microunits)
            .max()
            .unwrap_or(0),
    }
}

pub fn block_packing_candidates(resources: &[FeeMarketResource]) -> Vec<BlockPackingCandidate> {
    resources
        .iter()
        .enumerate()
        .map(|(index, resource)| block_packing_candidate(index as u64, resource))
        .collect()
}

pub fn block_packing_candidate(
    pending_index: u64,
    resource: &FeeMarketResource,
) -> BlockPackingCandidate {
    let (primary_lane_type, primary_lane_key) = primary_fee_lane(resource);
    let tx_kind = resource
        .public_record
        .get("kind")
        .and_then(Value::as_str)
        .unwrap_or("unknown")
        .to_string();
    let uncompressed_da_bytes = json_size(&resource.public_record) as u64;
    let resource_weight_units = block_packing_resource_weight(resource, uncompressed_da_bytes);
    let fee_density_microunits =
        fee_density_microunits(resource.observed_fee_units, resource_weight_units);
    BlockPackingCandidate {
        pending_index,
        tx_kind,
        primary_lane_type,
        primary_lane_key,
        uncompressed_da_bytes,
        resource_weight_units,
        observed_fee_units: resource.observed_fee_units,
        fee_density_microunits,
        estimated_proof_bytes: resource.estimated_proof_bytes,
        execution_fuel: resource.execution_fuel,
        privacy_proof_count: resource.privacy_proof_count,
        contract_call_count: resource.contract_call_count,
        authorization_count: resource.authorization_count,
    }
}

pub fn pack_fee_resources(
    resources: &[FeeMarketResource],
    policy: &BlockPackingPolicy,
) -> BlockPackingSelection {
    let candidates = block_packing_candidates(resources);
    let mut selected_indices = Vec::<usize>::new();
    let mut selected_set = BTreeSet::<usize>::new();
    let mut fairness_pass_count = 0;
    let mut density_pass_count = 0;
    let mut rejected_low_density_count = 0;
    let mut selected_resources = Vec::<FeeMarketResource>::new();

    let mut lanes = BTreeMap::<(String, String), Vec<usize>>::new();
    for candidate in &candidates {
        lanes
            .entry((
                candidate.primary_lane_type.clone(),
                candidate.primary_lane_key.clone(),
            ))
            .or_default()
            .push(candidate.pending_index as usize);
    }

    if policy.lane_reserve_tx_count > 0 {
        for lane_indices in lanes.values() {
            let mut admitted_from_lane = 0;
            for index in lane_indices {
                if admitted_from_lane >= policy.lane_reserve_tx_count {
                    break;
                }
                if selected_set.contains(index) {
                    continue;
                }
                if candidates[*index].fee_density_microunits < policy.min_fee_density_microunits {
                    rejected_low_density_count += 1;
                    continue;
                }
                if candidate_fits(&selected_resources, &resources[*index], policy) {
                    selected_resources.push(resources[*index].clone());
                    selected_indices.push(*index);
                    selected_set.insert(*index);
                    admitted_from_lane += 1;
                    fairness_pass_count += 1;
                }
            }
        }
    }

    let mut density_order = (0..resources.len()).collect::<Vec<_>>();
    density_order
        .sort_by(|left, right| compare_candidates(&candidates[*left], &candidates[*right]));
    for index in density_order {
        if selected_set.contains(&index) {
            continue;
        }
        if candidates[index].fee_density_microunits < policy.min_fee_density_microunits {
            rejected_low_density_count += 1;
            continue;
        }
        if candidate_fits(&selected_resources, &resources[index], policy) {
            selected_resources.push(resources[index].clone());
            selected_indices.push(index);
            selected_set.insert(index);
            density_pass_count += 1;
        }
    }

    let deferred_indices = (0..resources.len())
        .filter(|index| !selected_set.contains(index))
        .collect::<Vec<_>>();
    let deferred_resources = deferred_indices
        .iter()
        .map(|index| resources[*index].clone())
        .collect::<Vec<_>>();
    let selected_candidates = selected_indices
        .iter()
        .map(|index| candidates[*index].clone())
        .collect::<Vec<_>>();
    let deferred_candidates = deferred_indices
        .iter()
        .map(|index| candidates[*index].clone())
        .collect::<Vec<_>>();

    BlockPackingSelection {
        policy: policy.clone(),
        selected_indices: selected_indices
            .into_iter()
            .map(|index| index as u64)
            .collect(),
        deferred_indices: deferred_indices
            .into_iter()
            .map(|index| index as u64)
            .collect(),
        selected_profile: execution_profile_from_resources(&selected_resources),
        deferred_profile: execution_profile_from_resources(&deferred_resources),
        selected_candidates,
        deferred_candidates,
        fairness_pass_count,
        density_pass_count,
        rejected_low_density_count,
    }
}

pub fn block_packing_selection_from_indices(
    resources: &[FeeMarketResource],
    policy: &BlockPackingPolicy,
    selected_indices: &[usize],
    fairness_pass_count: u64,
    density_pass_count: u64,
    rejected_low_density_count: u64,
) -> BlockPackingSelection {
    let candidates = block_packing_candidates(resources);
    let selected_set = selected_indices.iter().copied().collect::<BTreeSet<_>>();
    let deferred_indices = (0..resources.len())
        .filter(|index| !selected_set.contains(index))
        .collect::<Vec<_>>();
    let selected_resources = selected_indices
        .iter()
        .map(|index| resources[*index].clone())
        .collect::<Vec<_>>();
    let deferred_resources = deferred_indices
        .iter()
        .map(|index| resources[*index].clone())
        .collect::<Vec<_>>();
    BlockPackingSelection {
        policy: policy.clone(),
        selected_indices: selected_indices.iter().map(|index| *index as u64).collect(),
        deferred_indices: deferred_indices.iter().map(|index| *index as u64).collect(),
        selected_profile: execution_profile_from_resources(&selected_resources),
        deferred_profile: execution_profile_from_resources(&deferred_resources),
        selected_candidates: selected_indices
            .iter()
            .map(|index| candidates[*index].clone())
            .collect(),
        deferred_candidates: deferred_indices
            .iter()
            .map(|index| candidates[*index].clone())
            .collect(),
        fairness_pass_count,
        density_pass_count,
        rejected_low_density_count,
    }
}

pub fn fee_quote(
    operation: &str,
    pending_resources: &[FeeMarketResource],
    candidate: FeeMarketResource,
) -> FeeQuote {
    let candidate_profile = execution_profile_from_resources(std::slice::from_ref(&candidate));
    let pending_profile = execution_profile_from_resources(pending_resources);
    let mut projected_resources = pending_resources.to_vec();
    projected_resources.push(candidate);
    let projected_profile = execution_profile_from_resources(&projected_resources);
    let marginal_batched_da_bytes =
        projected_profile.batched_da_bytes as i64 - pending_profile.batched_da_bytes as i64;
    let marginal_uncompressed_da_bytes = projected_profile.uncompressed_da_bytes as i64
        - pending_profile.uncompressed_da_bytes as i64;
    let marginal_batch_savings_bps = (std::cmp::max(
        0,
        candidate_profile.batched_da_bytes as i64 - marginal_batched_da_bytes,
    ) as u64
        * 10_000)
        .checked_div(candidate_profile.batched_da_bytes)
        .unwrap_or(0);
    let minimum_fee_units = std::cmp::max(1, candidate_profile.observed_fee_units);
    let over_free_txs = pending_profile
        .tx_count
        .saturating_sub(FEE_QUOTE_CONGESTION_FREE_TXS);
    let congestion_multiplier_bps =
        10_000 + over_free_txs * 10_000 / FEE_QUOTE_TARGET_TXS_PER_BLOCK;
    let recommended_fee_units = std::cmp::max(
        minimum_fee_units,
        minimum_fee_units * congestion_multiplier_bps / 10_000,
    );
    let fast_fee_units = std::cmp::max(
        recommended_fee_units,
        recommended_fee_units * FEE_QUOTE_FAST_MULTIPLIER_BPS / 10_000,
    );
    let target_inclusion_blocks = if pending_profile.tx_count < FEE_QUOTE_TARGET_TXS_PER_BLOCK {
        1
    } else {
        ceil_div(pending_profile.tx_count + 1, FEE_QUOTE_TARGET_TXS_PER_BLOCK)
    };
    let quote_payload = json!({
        "chain_id": CHAIN_ID,
        "operation": operation,
        "pending_tx_count": pending_profile.tx_count,
        "projected_tx_count": projected_profile.tx_count,
        "marginal_batched_da_bytes": marginal_batched_da_bytes,
        "minimum_fee_units": minimum_fee_units,
        "recommended_fee_units": recommended_fee_units,
        "fast_fee_units": fast_fee_units,
        "congestion_multiplier_bps": congestion_multiplier_bps,
        "target_inclusion_blocks": target_inclusion_blocks,
        "candidate_profile_root": domain_hash(
            "FEE-QUOTE-CANDIDATE-PROFILE",
            &[HashPart::Json(&candidate_profile.public_record())],
            32,
        ),
        "projected_profile_root": domain_hash(
            "FEE-QUOTE-PROJECTED-PROFILE",
            &[HashPart::Json(&projected_profile.public_record())],
            32,
        ),
    });
    let quote_hash = domain_hash("FEE-QUOTE", &[HashPart::Json(&quote_payload)], 32);
    FeeQuote {
        operation: operation.to_string(),
        pending_tx_count: pending_profile.tx_count,
        projected_tx_count: projected_profile.tx_count,
        candidate_profile,
        pending_profile,
        projected_profile,
        marginal_uncompressed_da_bytes,
        marginal_batched_da_bytes,
        marginal_batch_savings_bps,
        minimum_fee_units,
        recommended_fee_units,
        fast_fee_units,
        congestion_multiplier_bps,
        target_block_ms: TARGET_BLOCK_MS,
        target_inclusion_blocks,
        estimated_inclusion_ms: target_inclusion_blocks * TARGET_BLOCK_MS,
        quote_hash,
    }
}

fn primary_fee_lane(resource: &FeeMarketResource) -> (String, String) {
    resource
        .fee_lanes
        .iter()
        .find(|(lane_type, _)| lane_type == LOW_FEE_LANE_TYPE)
        .or_else(|| {
            resource
                .fee_lanes
                .iter()
                .find(|(lane_type, _)| lane_type == "operation")
        })
        .or_else(|| resource.fee_lanes.first())
        .cloned()
        .or_else(|| {
            resource
                .public_record
                .get("kind")
                .and_then(Value::as_str)
                .map(|kind| ("operation".to_string(), kind.to_string()))
        })
        .unwrap_or_else(|| ("operation".to_string(), "unknown".to_string()))
}

fn block_packing_resource_weight(resource: &FeeMarketResource, uncompressed_da_bytes: u64) -> u64 {
    let da_weight = std::cmp::max(1, uncompressed_da_bytes);
    let proof_weight = resource.estimated_proof_bytes;
    let auth_weight = resource.authorization_count * DEVNET_AUTH_BYTES;
    let call_weight = resource.contract_call_count * 256;
    da_weight + resource.execution_fuel + proof_weight + auth_weight + call_weight
}

fn candidate_fits(
    selected_resources: &[FeeMarketResource],
    candidate: &FeeMarketResource,
    policy: &BlockPackingPolicy,
) -> bool {
    let mut projected = selected_resources.to_vec();
    projected.push(candidate.clone());
    let profile = execution_profile_from_resources(&projected);
    profile_fits_policy(&profile, policy)
}

fn profile_fits_policy(profile: &BlockExecutionProfile, policy: &BlockPackingPolicy) -> bool {
    policy.accepts_profile(profile)
}

fn compare_candidates(
    left: &BlockPackingCandidate,
    right: &BlockPackingCandidate,
) -> std::cmp::Ordering {
    right
        .fee_density_microunits
        .cmp(&left.fee_density_microunits)
        .then_with(|| right.observed_fee_units.cmp(&left.observed_fee_units))
        .then_with(|| left.resource_weight_units.cmp(&right.resource_weight_units))
        .then_with(|| left.pending_index.cmp(&right.pending_index))
        .then_with(|| left.candidate_id().cmp(&right.candidate_id()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn transfer_resource(owner: &str, amount: u64, fee: u64, asset_id: &str) -> FeeMarketResource {
        FeeMarketResource {
            public_record: json!({
                "kind": "private_transfer",
                "amount_commitment": domain_hash("TEST-AMOUNT", &[HashPart::Str(owner), HashPart::Int(amount as i128)], 32),
                "fee": fee,
                "asset_id": asset_id,
            }),
            execution_fuel: 0,
            privacy_proof_count: 1,
            contract_call_count: 0,
            observed_fee_units: fee,
            estimated_proof_bytes: DEVNET_PRIVACY_PROOF_BYTES,
            authorization_count: 1,
            fee_asset_ids: vec![asset_id.to_string()],
            fee_lanes: vec![
                ("operation".to_string(), "private_transfer".to_string()),
                ("asset".to_string(), asset_id.to_string()),
            ],
        }
    }

    #[test]
    fn local_fee_profile_tracks_private_transfer_batching() {
        let asset_id = "wxmr-rust";
        let resources = vec![
            transfer_resource("alice", 100, 2, asset_id),
            transfer_resource("carol", 200, 3, asset_id),
        ];
        let lanes = local_fee_markets_for_resources(&resources);
        assert_eq!(lanes.len(), 2);
        assert_eq!(lanes[0].lane_type, "asset");
        assert_eq!(lanes[0].lane_key, asset_id);
        assert_eq!(lanes[0].tx_count, 2);
        assert_eq!(lanes[0].observed_fee_units, 5);
        assert_eq!(lanes[1].lane_type, "operation");
        assert_eq!(lanes[1].lane_key, "private_transfer");

        let profile = execution_profile_from_resources(&resources);
        assert_eq!(profile.tx_count, 2);
        assert_eq!(profile.privacy_proof_count, 2);
        assert_eq!(profile.authorization_count, 2);
        assert_eq!(profile.estimated_authorization_bytes, 2 * DEVNET_AUTH_BYTES);
        assert_eq!(profile.observed_fee_units, 5);
        assert_eq!(profile.fee_asset_count, 1);
        assert_eq!(profile.local_fee_lane_count, 2);
        assert!(profile.batched_da_bytes <= profile.uncompressed_da_bytes);
        assert_eq!(
            profile.amortized_da_bytes_per_tx,
            ceil_div(profile.batched_da_bytes, 2)
        );
        assert_eq!(profile.local_fee_market_root.len(), 64);
    }

    #[test]
    fn fee_quote_projects_marginal_batch_savings() {
        let asset_id = "wxmr-rust";
        let pending = vec![
            transfer_resource("alice", 100, 2, asset_id),
            transfer_resource("carol", 200, 3, asset_id),
        ];
        let candidate = FeeMarketResource {
            public_record: json!({
                "kind": "private_transfer_batch",
                "input_count": 2,
                "output_count": 3,
                "fee": 5,
                "asset_id": asset_id,
            }),
            execution_fuel: 0,
            privacy_proof_count: 1,
            contract_call_count: 0,
            observed_fee_units: 5,
            estimated_proof_bytes: DEVNET_PRIVACY_PROOF_BYTES + 512,
            authorization_count: 1,
            fee_asset_ids: vec![asset_id.to_string()],
            fee_lanes: vec![
                (
                    "operation".to_string(),
                    "private_transfer_batch".to_string(),
                ),
                ("asset".to_string(), asset_id.to_string()),
            ],
        };
        let quote = fee_quote("batch-transfer", &pending, candidate);
        assert_eq!(quote.operation, "batch-transfer");
        assert_eq!(quote.pending_tx_count, 2);
        assert_eq!(quote.projected_tx_count, 3);
        assert_eq!(quote.candidate_profile.privacy_proof_count, 1);
        assert_eq!(quote.minimum_fee_units, 5);
        assert!(quote.recommended_fee_units >= quote.minimum_fee_units);
        assert!(quote.fast_fee_units >= quote.recommended_fee_units);
        assert!(quote.marginal_batched_da_bytes <= quote.candidate_profile.batched_da_bytes as i64);
        assert_eq!(quote.target_inclusion_blocks, 1);
        assert_eq!(quote.estimated_inclusion_ms, TARGET_BLOCK_MS);
        assert_eq!(quote.quote_hash.len(), 64);
        let public_quote = quote.public_record();
        assert_eq!(public_quote["pending_tx_count"], json!(2));
        assert_eq!(public_quote["projected_tx_count"], json!(3));
    }
}
