use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type Runtime = State;

pub const PROTOCOL_VERSION: &str =
    "nebula-private-l2-low-fee-pq-confidential-fee-bridge-netting-v1";
pub const HASH_SUITE: &str = "shake256-domain-separated-canonical-json";
pub const PQ_SUITE: &str = "ml-kem-1024+ml-dsa-87+shake256-commitments";
pub const CONFIDENTIAL_FEE_SCHEME: &str = "pedersen-compatible-fee-commitment-v1";
pub const PICONERO_PER_XMR: u64 = 1_000_000_000_000;
pub const MAX_BPS: u64 = 10_000;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub hash_suite: String,
    pub pq_suite: String,
    pub confidential_fee_scheme: String,
    pub epoch: u64,
    pub netting_window_blocks: u64,
    pub rebate_window_blocks: u64,
    pub settlement_delay_blocks: u64,
    pub challenge_window_blocks: u64,
    pub min_payer_cohort_size: u64,
    pub min_sponsor_bond_piconero: u64,
    pub max_bridge_fee_bps: u64,
    pub target_fee_bps: u64,
    pub reserve_rebate_bps: u64,
    pub sponsor_discount_bps: u64,
    pub da_amortization_floor_piconero: u64,
    pub proof_amortization_floor_piconero: u64,
    pub max_batch_items: usize,
    pub max_public_events: usize,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            hash_suite: HASH_SUITE.to_string(),
            pq_suite: PQ_SUITE.to_string(),
            confidential_fee_scheme: CONFIDENTIAL_FEE_SCHEME.to_string(),
            epoch: 7,
            netting_window_blocks: 20,
            rebate_window_blocks: 120,
            settlement_delay_blocks: 8,
            challenge_window_blocks: 48,
            min_payer_cohort_size: 32,
            min_sponsor_bond_piconero: 2_500_000_000,
            max_bridge_fee_bps: 35,
            target_fee_bps: 8,
            reserve_rebate_bps: 6_000,
            sponsor_discount_bps: 1_500,
            da_amortization_floor_piconero: 15_000,
            proof_amortization_floor_piconero: 35_000,
            max_batch_items: 512,
            max_public_events: 65_536,
        }
    }

    pub fn validate(&self) -> Result<()> {
        require_non_empty("chain_id", &self.chain_id)?;
        require_non_empty("protocol_version", &self.protocol_version)?;
        require_non_empty("hash_suite", &self.hash_suite)?;
        require_non_empty("pq_suite", &self.pq_suite)?;
        require_non_empty("confidential_fee_scheme", &self.confidential_fee_scheme)?;
        if self.chain_id != CHAIN_ID {
            return Err("config chain id mismatch".to_string());
        }
        if self.protocol_version != PROTOCOL_VERSION {
            return Err("config protocol version mismatch".to_string());
        }
        if self.max_bridge_fee_bps > MAX_BPS
            || self.target_fee_bps > self.max_bridge_fee_bps
            || self.reserve_rebate_bps > MAX_BPS
            || self.sponsor_discount_bps > MAX_BPS
        {
            return Err("config basis points out of range".to_string());
        }
        if self.netting_window_blocks == 0
            || self.rebate_window_blocks == 0
            || self.settlement_delay_blocks == 0
            || self.challenge_window_blocks == 0
            || self.min_payer_cohort_size == 0
            || self.max_batch_items == 0
        {
            return Err("config windows and limits must be nonzero".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "hash_suite": self.hash_suite,
            "pq_suite": self.pq_suite,
            "confidential_fee_scheme": self.confidential_fee_scheme,
            "epoch": self.epoch,
            "netting_window_blocks": self.netting_window_blocks,
            "rebate_window_blocks": self.rebate_window_blocks,
            "settlement_delay_blocks": self.settlement_delay_blocks,
            "challenge_window_blocks": self.challenge_window_blocks,
            "min_payer_cohort_size": self.min_payer_cohort_size,
            "min_sponsor_bond_piconero": self.min_sponsor_bond_piconero,
            "max_bridge_fee_bps": self.max_bridge_fee_bps,
            "target_fee_bps": self.target_fee_bps,
            "reserve_rebate_bps": self.reserve_rebate_bps,
            "sponsor_discount_bps": self.sponsor_discount_bps,
            "da_amortization_floor_piconero": self.da_amortization_floor_piconero,
            "proof_amortization_floor_piconero": self.proof_amortization_floor_piconero,
            "max_batch_items": self.max_batch_items,
            "max_public_events": self.max_public_events
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    pub next_bridge_fee: u64,
    pub next_rebate: u64,
    pub next_sponsor_lane: u64,
    pub next_piconero_lane: u64,
    pub next_amortization_pool: u64,
    pub next_payer_cohort: u64,
    pub next_batch: u64,
    pub next_exit_coupon: u64,
    pub next_slashing_evidence: u64,
    pub events: u64,
}

impl Counters {
    pub fn devnet() -> Self {
        Self {
            next_bridge_fee: 1,
            next_rebate: 1,
            next_sponsor_lane: 1,
            next_piconero_lane: 1,
            next_amortization_pool: 1,
            next_payer_cohort: 1,
            next_batch: 1,
            next_exit_coupon: 1,
            next_slashing_evidence: 1,
            events: 0,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "next_bridge_fee": self.next_bridge_fee,
            "next_rebate": self.next_rebate,
            "next_sponsor_lane": self.next_sponsor_lane,
            "next_piconero_lane": self.next_piconero_lane,
            "next_amortization_pool": self.next_amortization_pool,
            "next_payer_cohort": self.next_payer_cohort,
            "next_batch": self.next_batch,
            "next_exit_coupon": self.next_exit_coupon,
            "next_slashing_evidence": self.next_slashing_evidence,
            "events": self.events
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roots {
    pub config_root: String,
    pub counters_root: String,
    pub bridge_fee_root: String,
    pub rebate_root: String,
    pub sponsor_lane_root: String,
    pub piconero_lane_root: String,
    pub amortization_pool_root: String,
    pub payer_cohort_root: String,
    pub batch_root: String,
    pub exit_coupon_root: String,
    pub nullifier_fence_root: String,
    pub slashing_evidence_root: String,
    pub event_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "counters_root": self.counters_root,
            "bridge_fee_root": self.bridge_fee_root,
            "rebate_root": self.rebate_root,
            "sponsor_lane_root": self.sponsor_lane_root,
            "piconero_lane_root": self.piconero_lane_root,
            "amortization_pool_root": self.amortization_pool_root,
            "payer_cohort_root": self.payer_cohort_root,
            "batch_root": self.batch_root,
            "exit_coupon_root": self.exit_coupon_root,
            "nullifier_fence_root": self.nullifier_fence_root,
            "slashing_evidence_root": self.slashing_evidence_root,
            "event_root": self.event_root,
            "state_root": self.state_root
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BridgeDirection {
    Inbound,
    Outbound,
    InternalRollup,
}

impl BridgeDirection {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Inbound => "inbound",
            Self::Outbound => "outbound",
            Self::InternalRollup => "internal_rollup",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LaneStatus {
    Open,
    Settling,
    Settled,
    Frozen,
}

impl LaneStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Settling => "settling",
            Self::Settled => "settled",
            Self::Frozen => "frozen",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CouponStatus {
    Open,
    Claimed,
    Expired,
    Slashed,
}

impl CouponStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Claimed => "claimed",
            Self::Expired => "expired",
            Self::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BridgeFeeCommitment {
    pub fee_id: String,
    pub bridge_id: String,
    pub token_id: String,
    pub direction: BridgeDirection,
    pub payer_cohort_id: String,
    pub sponsor_lane_id: Option<String>,
    pub amount_commitment: String,
    pub fee_piconero: u64,
    pub max_fee_piconero: u64,
    pub da_units: u64,
    pub proof_units: u64,
    pub nullifier: String,
    pub encrypted_payer_hint: String,
    pub pq_receipt_commitment: String,
    pub opened_at_height: u64,
    pub maturity_height: u64,
}

impl BridgeFeeCommitment {
    pub fn public_record(&self) -> Value {
        json!({
            "fee_id": self.fee_id,
            "bridge_id": self.bridge_id,
            "token_id": self.token_id,
            "direction": self.direction.as_str(),
            "payer_cohort_id": self.payer_cohort_id,
            "sponsor_lane_id": self.sponsor_lane_id,
            "amount_commitment": self.amount_commitment,
            "fee_piconero": self.fee_piconero,
            "max_fee_piconero": self.max_fee_piconero,
            "da_units": self.da_units,
            "proof_units": self.proof_units,
            "nullifier": self.nullifier,
            "encrypted_payer_hint": self.encrypted_payer_hint,
            "pq_receipt_commitment": self.pq_receipt_commitment,
            "opened_at_height": self.opened_at_height,
            "maturity_height": self.maturity_height
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MultiTokenRebate {
    pub rebate_id: String,
    pub token_id: String,
    pub payer_cohort_id: String,
    pub reserve_id: String,
    pub source_fee_ids: BTreeSet<String>,
    pub rebate_commitment: String,
    pub rebate_piconero: u64,
    pub reserve_debit_piconero: u64,
    pub claim_nullifier: String,
    pub expires_at_height: u64,
}

impl MultiTokenRebate {
    pub fn public_record(&self) -> Value {
        json!({
            "rebate_id": self.rebate_id,
            "token_id": self.token_id,
            "payer_cohort_id": self.payer_cohort_id,
            "reserve_id": self.reserve_id,
            "source_fee_ids": sorted_strings(&self.source_fee_ids),
            "rebate_commitment": self.rebate_commitment,
            "rebate_piconero": self.rebate_piconero,
            "reserve_debit_piconero": self.reserve_debit_piconero,
            "claim_nullifier": self.claim_nullifier,
            "expires_at_height": self.expires_at_height
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SponsorSettlementLane {
    pub lane_id: String,
    pub sponsor_commitment: String,
    pub settlement_asset_id: String,
    pub status: LaneStatus,
    pub bonded_piconero: u64,
    pub credit_limit_piconero: u64,
    pub used_credit_piconero: u64,
    pub settlement_manifest_root: String,
    pub route_commitment_root: String,
    pub opened_at_height: u64,
    pub settle_after_height: u64,
}

impl SponsorSettlementLane {
    pub fn available_credit(&self) -> u64 {
        self.credit_limit_piconero
            .saturating_sub(self.used_credit_piconero)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "lane_id": self.lane_id,
            "sponsor_commitment": self.sponsor_commitment,
            "settlement_asset_id": self.settlement_asset_id,
            "status": self.status.as_str(),
            "bonded_piconero": self.bonded_piconero,
            "credit_limit_piconero": self.credit_limit_piconero,
            "used_credit_piconero": self.used_credit_piconero,
            "available_credit_piconero": self.available_credit(),
            "settlement_manifest_root": self.settlement_manifest_root,
            "route_commitment_root": self.route_commitment_root,
            "opened_at_height": self.opened_at_height,
            "settle_after_height": self.settle_after_height
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PiconeroFeeLane {
    pub lane_id: String,
    pub token_id: String,
    pub fee_floor_piconero: u64,
    pub target_fee_piconero: u64,
    pub collected_piconero: u64,
    pub rebated_piconero: u64,
    pub netted_piconero: u64,
    pub payer_count: u64,
    pub last_height: u64,
}

impl PiconeroFeeLane {
    pub fn public_record(&self) -> Value {
        json!({
            "lane_id": self.lane_id,
            "token_id": self.token_id,
            "fee_floor_piconero": self.fee_floor_piconero,
            "target_fee_piconero": self.target_fee_piconero,
            "collected_piconero": self.collected_piconero,
            "rebated_piconero": self.rebated_piconero,
            "netted_piconero": self.netted_piconero,
            "payer_count": self.payer_count,
            "last_height": self.last_height
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AmortizationPool {
    pub pool_id: String,
    pub bridge_id: String,
    pub da_commitment_root: String,
    pub proof_commitment_root: String,
    pub da_units: u64,
    pub proof_units: u64,
    pub prepaid_piconero: u64,
    pub allocated_piconero: u64,
    pub participant_fee_ids: BTreeSet<String>,
}

impl AmortizationPool {
    pub fn public_record(&self) -> Value {
        json!({
            "pool_id": self.pool_id,
            "bridge_id": self.bridge_id,
            "da_commitment_root": self.da_commitment_root,
            "proof_commitment_root": self.proof_commitment_root,
            "da_units": self.da_units,
            "proof_units": self.proof_units,
            "prepaid_piconero": self.prepaid_piconero,
            "allocated_piconero": self.allocated_piconero,
            "participant_fee_ids": sorted_strings(&self.participant_fee_ids)
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PayerCohort {
    pub cohort_id: String,
    pub token_id: String,
    pub encrypted_cohort_root: String,
    pub payer_commitment_root: String,
    pub nullifier_root: String,
    pub min_size: u64,
    pub observed_size: u64,
    pub opened_at_height: u64,
}

impl PayerCohort {
    pub fn public_record(&self) -> Value {
        json!({
            "cohort_id": self.cohort_id,
            "token_id": self.token_id,
            "encrypted_cohort_root": self.encrypted_cohort_root,
            "payer_commitment_root": self.payer_commitment_root,
            "nullifier_root": self.nullifier_root,
            "min_size": self.min_size,
            "observed_size": self.observed_size,
            "opened_at_height": self.opened_at_height
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchNetting {
    pub batch_id: String,
    pub token_id: String,
    pub fee_ids: BTreeSet<String>,
    pub rebate_ids: BTreeSet<String>,
    pub sponsor_lane_ids: BTreeSet<String>,
    pub gross_fee_piconero: u64,
    pub rebate_piconero: u64,
    pub sponsor_credit_piconero: u64,
    pub net_settlement_piconero: u64,
    pub settlement_manifest_root: String,
    pub created_at_height: u64,
}

impl BatchNetting {
    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "token_id": self.token_id,
            "fee_ids": sorted_strings(&self.fee_ids),
            "rebate_ids": sorted_strings(&self.rebate_ids),
            "sponsor_lane_ids": sorted_strings(&self.sponsor_lane_ids),
            "gross_fee_piconero": self.gross_fee_piconero,
            "rebate_piconero": self.rebate_piconero,
            "sponsor_credit_piconero": self.sponsor_credit_piconero,
            "net_settlement_piconero": self.net_settlement_piconero,
            "settlement_manifest_root": self.settlement_manifest_root,
            "created_at_height": self.created_at_height
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BridgeExitCoupon {
    pub coupon_id: String,
    pub batch_id: String,
    pub recipient_commitment: String,
    pub token_id: String,
    pub value_commitment: String,
    pub exit_fee_piconero: u64,
    pub claim_nullifier: String,
    pub status: CouponStatus,
    pub expires_at_height: u64,
}

impl BridgeExitCoupon {
    pub fn public_record(&self) -> Value {
        json!({
            "coupon_id": self.coupon_id,
            "batch_id": self.batch_id,
            "recipient_commitment": self.recipient_commitment,
            "token_id": self.token_id,
            "value_commitment": self.value_commitment,
            "exit_fee_piconero": self.exit_fee_piconero,
            "claim_nullifier": self.claim_nullifier,
            "status": self.status.as_str(),
            "expires_at_height": self.expires_at_height
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NullifierFence {
    pub nullifier: String,
    pub first_seen_height: u64,
    pub source_id: String,
    pub domain: String,
}

impl NullifierFence {
    pub fn public_record(&self) -> Value {
        json!({
            "nullifier": self.nullifier,
            "first_seen_height": self.first_seen_height,
            "source_id": self.source_id,
            "domain": self.domain
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlashingEvidence {
    pub evidence_id: String,
    pub offender_commitment: String,
    pub abuse_kind: String,
    pub related_ids: BTreeSet<String>,
    pub evidence_root: String,
    pub slash_piconero: u64,
    pub opened_at_height: u64,
}

impl SlashingEvidence {
    pub fn public_record(&self) -> Value {
        json!({
            "evidence_id": self.evidence_id,
            "offender_commitment": self.offender_commitment,
            "abuse_kind": self.abuse_kind,
            "related_ids": sorted_strings(&self.related_ids),
            "evidence_root": self.evidence_root,
            "slash_piconero": self.slash_piconero,
            "opened_at_height": self.opened_at_height
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub height: u64,
    pub config: Config,
    pub counters: Counters,
    pub bridge_fees: BTreeMap<String, BridgeFeeCommitment>,
    pub rebates: BTreeMap<String, MultiTokenRebate>,
    pub sponsor_lanes: BTreeMap<String, SponsorSettlementLane>,
    pub piconero_lanes: BTreeMap<String, PiconeroFeeLane>,
    pub amortization_pools: BTreeMap<String, AmortizationPool>,
    pub payer_cohorts: BTreeMap<String, PayerCohort>,
    pub batches: BTreeMap<String, BatchNetting>,
    pub exit_coupons: BTreeMap<String, BridgeExitCoupon>,
    pub nullifier_fences: BTreeMap<String, NullifierFence>,
    pub slashing_evidence: BTreeMap<String, SlashingEvidence>,
    pub public_events: Vec<Value>,
}

impl State {
    pub fn devnet() -> Self {
        let mut state = Self {
            height: 1_777,
            config: Config::devnet(),
            counters: Counters::devnet(),
            bridge_fees: BTreeMap::new(),
            rebates: BTreeMap::new(),
            sponsor_lanes: BTreeMap::new(),
            piconero_lanes: BTreeMap::new(),
            amortization_pools: BTreeMap::new(),
            payer_cohorts: BTreeMap::new(),
            batches: BTreeMap::new(),
            exit_coupons: BTreeMap::new(),
            nullifier_fences: BTreeMap::new(),
            slashing_evidence: BTreeMap::new(),
            public_events: Vec::new(),
        };
        let cohort = state
            .open_payer_cohort(
                "dxmr",
                &deterministic_root("DEVNET-COHORT", "encrypted", state.height),
                &deterministic_root("DEVNET-COHORT", "payers", state.height),
                96,
            )
            .unwrap_or_else(|_| "cohort-devnet-unavailable".to_string());
        let sponsor = state
            .open_sponsor_lane(
                "sponsor:devnet:market-maker",
                "dxmr",
                5_000_000_000,
                50_000_000_000,
                &deterministic_root("DEVNET-SPONSOR", "manifest", state.height),
                &deterministic_root("DEVNET-SPONSOR", "routes", state.height),
            )
            .unwrap_or_else(|_| "sponsor-devnet-unavailable".to_string());
        let fee = state
            .commit_bridge_fee(BridgeFeeInput {
                bridge_id: "bridge:monero:devnet".to_string(),
                token_id: "dxmr".to_string(),
                direction: BridgeDirection::Outbound,
                payer_cohort_id: cohort.clone(),
                sponsor_lane_id: Some(sponsor),
                amount_commitment: deterministic_commitment("amount", "devnet", state.height),
                fee_piconero: 120_000,
                max_fee_piconero: 180_000,
                da_units: 2,
                proof_units: 1,
                nullifier: deterministic_nullifier("fee", "devnet", state.height),
                encrypted_payer_hint: deterministic_commitment(
                    "payer-hint",
                    "devnet",
                    state.height,
                ),
                pq_receipt_commitment: deterministic_commitment(
                    "pq-receipt",
                    "devnet",
                    state.height,
                ),
            })
            .unwrap_or_else(|_| "fee-devnet-unavailable".to_string());
        let mut fee_ids = BTreeSet::new();
        fee_ids.insert(fee);
        let _ = state.create_rebate(
            "dxmr",
            &cohort,
            "reserve:devnet:fee-stability",
            fee_ids,
            45_000,
            deterministic_nullifier("rebate", "devnet", state.height),
        );
        state
    }

    pub fn validate(&self) -> Result<()> {
        self.config.validate()?;
        for (id, fee) in &self.bridge_fees {
            require_equal("bridge fee key", id, &fee.fee_id)?;
            require_known("payer cohort", &fee.payer_cohort_id, &self.payer_cohorts)?;
            if let Some(lane_id) = &fee.sponsor_lane_id {
                require_known("sponsor lane", lane_id, &self.sponsor_lanes)?;
            }
        }
        for (id, rebate) in &self.rebates {
            require_equal("rebate key", id, &rebate.rebate_id)?;
            require_known("payer cohort", &rebate.payer_cohort_id, &self.payer_cohorts)?;
        }
        for (id, batch) in &self.batches {
            require_equal("batch key", id, &batch.batch_id)?;
            for fee_id in &batch.fee_ids {
                require_known("batch fee", fee_id, &self.bridge_fees)?;
            }
            for rebate_id in &batch.rebate_ids {
                require_known("batch rebate", rebate_id, &self.rebates)?;
            }
        }
        Ok(())
    }

    pub fn advance_height(&mut self, height: u64) -> Result<()> {
        if height < self.height {
            return Err("height cannot move backward".to_string());
        }
        self.height = height;
        self.push_event("height_advanced", json!({ "height": height }));
        Ok(())
    }

    pub fn open_payer_cohort(
        &mut self,
        token_id: &str,
        encrypted_cohort_root: &str,
        payer_commitment_root: &str,
        observed_size: u64,
    ) -> Result<String> {
        require_non_empty("token_id", token_id)?;
        require_non_empty("encrypted_cohort_root", encrypted_cohort_root)?;
        require_non_empty("payer_commitment_root", payer_commitment_root)?;
        if observed_size < self.config.min_payer_cohort_size {
            return Err("payer cohort is below privacy floor".to_string());
        }
        let sequence = take_counter(&mut self.counters.next_payer_cohort);
        let cohort_id = payer_cohort_id(token_id, encrypted_cohort_root, sequence);
        let nullifier_root = deterministic_root("PAYER-COHORT-NULLIFIERS", &cohort_id, self.height);
        self.payer_cohorts.insert(
            cohort_id.clone(),
            PayerCohort {
                cohort_id: cohort_id.clone(),
                token_id: token_id.to_string(),
                encrypted_cohort_root: encrypted_cohort_root.to_string(),
                payer_commitment_root: payer_commitment_root.to_string(),
                nullifier_root,
                min_size: self.config.min_payer_cohort_size,
                observed_size,
                opened_at_height: self.height,
            },
        );
        self.push_event("payer_cohort_opened", json!({ "cohort_id": cohort_id }));
        Ok(cohort_id)
    }

    pub fn open_sponsor_lane(
        &mut self,
        sponsor_commitment: &str,
        settlement_asset_id: &str,
        bonded_piconero: u64,
        credit_limit_piconero: u64,
        settlement_manifest_root: &str,
        route_commitment_root: &str,
    ) -> Result<String> {
        require_non_empty("sponsor_commitment", sponsor_commitment)?;
        require_non_empty("settlement_asset_id", settlement_asset_id)?;
        require_non_empty("settlement_manifest_root", settlement_manifest_root)?;
        require_non_empty("route_commitment_root", route_commitment_root)?;
        if bonded_piconero < self.config.min_sponsor_bond_piconero {
            return Err("sponsor bond below minimum".to_string());
        }
        if credit_limit_piconero == 0 {
            return Err("sponsor credit limit must be nonzero".to_string());
        }
        let sequence = take_counter(&mut self.counters.next_sponsor_lane);
        let lane_id = sponsor_lane_id(sponsor_commitment, settlement_asset_id, sequence);
        self.sponsor_lanes.insert(
            lane_id.clone(),
            SponsorSettlementLane {
                lane_id: lane_id.clone(),
                sponsor_commitment: sponsor_commitment.to_string(),
                settlement_asset_id: settlement_asset_id.to_string(),
                status: LaneStatus::Open,
                bonded_piconero,
                credit_limit_piconero,
                used_credit_piconero: 0,
                settlement_manifest_root: settlement_manifest_root.to_string(),
                route_commitment_root: route_commitment_root.to_string(),
                opened_at_height: self.height,
                settle_after_height: self.height + self.config.settlement_delay_blocks,
            },
        );
        self.push_event("sponsor_lane_opened", json!({ "lane_id": lane_id }));
        Ok(lane_id)
    }

    pub fn ensure_piconero_lane(
        &mut self,
        token_id: &str,
        fee_floor_piconero: u64,
        target_fee_piconero: u64,
    ) -> Result<String> {
        require_non_empty("token_id", token_id)?;
        if target_fee_piconero < fee_floor_piconero {
            return Err("target fee must be at least the fee floor".to_string());
        }
        let existing = self
            .piconero_lanes
            .values()
            .find(|lane| lane.token_id == token_id)
            .map(|lane| lane.lane_id.clone());
        if let Some(lane_id) = existing {
            return Ok(lane_id);
        }
        let sequence = take_counter(&mut self.counters.next_piconero_lane);
        let lane_id = piconero_lane_id(token_id, sequence);
        self.piconero_lanes.insert(
            lane_id.clone(),
            PiconeroFeeLane {
                lane_id: lane_id.clone(),
                token_id: token_id.to_string(),
                fee_floor_piconero,
                target_fee_piconero,
                collected_piconero: 0,
                rebated_piconero: 0,
                netted_piconero: 0,
                payer_count: 0,
                last_height: self.height,
            },
        );
        self.push_event("piconero_lane_opened", json!({ "lane_id": lane_id }));
        Ok(lane_id)
    }

    pub fn commit_bridge_fee(&mut self, input: BridgeFeeInput) -> Result<String> {
        input.validate()?;
        require_known("payer cohort", &input.payer_cohort_id, &self.payer_cohorts)?;
        self.insert_nullifier(&input.nullifier, "bridge_fee")?;
        if let Some(lane_id) = &input.sponsor_lane_id {
            let lane = self
                .sponsor_lanes
                .get_mut(lane_id)
                .ok_or_else(|| "unknown sponsor lane".to_string())?;
            if lane.status != LaneStatus::Open {
                return Err("sponsor lane is not open".to_string());
            }
            if lane.available_credit() < input.fee_piconero {
                return Err("sponsor lane lacks credit".to_string());
            }
            lane.used_credit_piconero =
                lane.used_credit_piconero.saturating_add(input.fee_piconero);
        }
        let lane_id = self.ensure_piconero_lane(
            &input.token_id,
            self.config.da_amortization_floor_piconero,
            input.fee_piconero,
        )?;
        if let Some(lane) = self.piconero_lanes.get_mut(&lane_id) {
            lane.collected_piconero = lane.collected_piconero.saturating_add(input.fee_piconero);
            lane.payer_count = lane.payer_count.saturating_add(1);
            lane.last_height = self.height;
        }
        let sequence = take_counter(&mut self.counters.next_bridge_fee);
        let fee_id = bridge_fee_id(
            &input.bridge_id,
            &input.token_id,
            &input.nullifier,
            sequence,
        );
        let record = BridgeFeeCommitment {
            fee_id: fee_id.clone(),
            bridge_id: input.bridge_id,
            token_id: input.token_id,
            direction: input.direction,
            payer_cohort_id: input.payer_cohort_id,
            sponsor_lane_id: input.sponsor_lane_id,
            amount_commitment: input.amount_commitment,
            fee_piconero: input.fee_piconero,
            max_fee_piconero: input.max_fee_piconero,
            da_units: input.da_units,
            proof_units: input.proof_units,
            nullifier: input.nullifier,
            encrypted_payer_hint: input.encrypted_payer_hint,
            pq_receipt_commitment: input.pq_receipt_commitment,
            opened_at_height: self.height,
            maturity_height: self.height + self.config.netting_window_blocks,
        };
        self.bridge_fees.insert(fee_id.clone(), record);
        self.push_event("bridge_fee_committed", json!({ "fee_id": fee_id }));
        Ok(fee_id)
    }

    pub fn create_amortization_pool(
        &mut self,
        bridge_id: &str,
        da_commitment_root: &str,
        proof_commitment_root: &str,
        da_units: u64,
        proof_units: u64,
        prepaid_piconero: u64,
        participant_fee_ids: BTreeSet<String>,
    ) -> Result<String> {
        require_non_empty("bridge_id", bridge_id)?;
        require_non_empty("da_commitment_root", da_commitment_root)?;
        require_non_empty("proof_commitment_root", proof_commitment_root)?;
        if participant_fee_ids.is_empty() || participant_fee_ids.len() > self.config.max_batch_items
        {
            return Err("participant fee ids out of range".to_string());
        }
        for fee_id in &participant_fee_ids {
            require_known("participant fee", fee_id, &self.bridge_fees)?;
        }
        let sequence = take_counter(&mut self.counters.next_amortization_pool);
        let pool_id = amortization_pool_id(bridge_id, da_commitment_root, sequence);
        let allocated_piconero = prepaid_piconero
            .saturating_add(da_units.saturating_mul(self.config.da_amortization_floor_piconero))
            .saturating_add(
                proof_units.saturating_mul(self.config.proof_amortization_floor_piconero),
            );
        self.amortization_pools.insert(
            pool_id.clone(),
            AmortizationPool {
                pool_id: pool_id.clone(),
                bridge_id: bridge_id.to_string(),
                da_commitment_root: da_commitment_root.to_string(),
                proof_commitment_root: proof_commitment_root.to_string(),
                da_units,
                proof_units,
                prepaid_piconero,
                allocated_piconero,
                participant_fee_ids,
            },
        );
        self.push_event("amortization_pool_created", json!({ "pool_id": pool_id }));
        Ok(pool_id)
    }

    pub fn create_rebate(
        &mut self,
        token_id: &str,
        payer_cohort_id: &str,
        reserve_id: &str,
        source_fee_ids: BTreeSet<String>,
        rebate_piconero: u64,
        claim_nullifier: String,
    ) -> Result<String> {
        require_non_empty("token_id", token_id)?;
        require_known("payer cohort", payer_cohort_id, &self.payer_cohorts)?;
        require_non_empty("reserve_id", reserve_id)?;
        if source_fee_ids.is_empty() {
            return Err("rebate needs source fees".to_string());
        }
        for fee_id in &source_fee_ids {
            require_known("source fee", fee_id, &self.bridge_fees)?;
        }
        self.insert_nullifier(&claim_nullifier, "rebate_claim")?;
        let sequence = take_counter(&mut self.counters.next_rebate);
        let rebate_id = rebate_id(token_id, payer_cohort_id, reserve_id, sequence);
        let rebate_commitment = deterministic_commitment("rebate", &rebate_id, self.height);
        let reserve_debit_piconero =
            rebate_piconero.saturating_mul(self.config.reserve_rebate_bps) / MAX_BPS;
        self.rebates.insert(
            rebate_id.clone(),
            MultiTokenRebate {
                rebate_id: rebate_id.clone(),
                token_id: token_id.to_string(),
                payer_cohort_id: payer_cohort_id.to_string(),
                reserve_id: reserve_id.to_string(),
                source_fee_ids,
                rebate_commitment,
                rebate_piconero,
                reserve_debit_piconero,
                claim_nullifier,
                expires_at_height: self.height + self.config.rebate_window_blocks,
            },
        );
        if let Some(lane) = self
            .piconero_lanes
            .values_mut()
            .find(|lane| lane.token_id == token_id)
        {
            lane.rebated_piconero = lane.rebated_piconero.saturating_add(rebate_piconero);
        }
        self.push_event("rebate_created", json!({ "rebate_id": rebate_id }));
        Ok(rebate_id)
    }

    pub fn create_batch_netting(
        &mut self,
        token_id: &str,
        fee_ids: BTreeSet<String>,
        rebate_ids: BTreeSet<String>,
    ) -> Result<String> {
        require_non_empty("token_id", token_id)?;
        if fee_ids.is_empty() || fee_ids.len() > self.config.max_batch_items {
            return Err("batch fee count out of range".to_string());
        }
        let mut gross_fee_piconero = 0_u64;
        let mut sponsor_credit_piconero = 0_u64;
        let mut sponsor_lane_ids = BTreeSet::new();
        for fee_id in &fee_ids {
            let fee = self
                .bridge_fees
                .get(fee_id)
                .ok_or_else(|| format!("unknown fee {fee_id}"))?;
            if fee.token_id != token_id {
                return Err("batch token mismatch".to_string());
            }
            gross_fee_piconero = gross_fee_piconero.saturating_add(fee.fee_piconero);
            if let Some(lane_id) = &fee.sponsor_lane_id {
                sponsor_lane_ids.insert(lane_id.clone());
                sponsor_credit_piconero = sponsor_credit_piconero.saturating_add(fee.fee_piconero);
            }
        }
        let mut rebate_piconero = 0_u64;
        for rebate_id in &rebate_ids {
            let rebate = self
                .rebates
                .get(rebate_id)
                .ok_or_else(|| format!("unknown rebate {rebate_id}"))?;
            if rebate.token_id != token_id {
                return Err("rebate token mismatch".to_string());
            }
            rebate_piconero = rebate_piconero.saturating_add(rebate.rebate_piconero);
        }
        let sequence = take_counter(&mut self.counters.next_batch);
        let batch_id = batch_id(token_id, &fee_ids, sequence);
        let net_settlement_piconero = gross_fee_piconero
            .saturating_sub(rebate_piconero)
            .saturating_sub(
                sponsor_credit_piconero.saturating_mul(self.config.sponsor_discount_bps) / MAX_BPS,
            );
        let settlement_manifest_root = settlement_manifest_root(
            &batch_id,
            token_id,
            gross_fee_piconero,
            rebate_piconero,
            sponsor_credit_piconero,
        );
        self.batches.insert(
            batch_id.clone(),
            BatchNetting {
                batch_id: batch_id.clone(),
                token_id: token_id.to_string(),
                fee_ids,
                rebate_ids,
                sponsor_lane_ids,
                gross_fee_piconero,
                rebate_piconero,
                sponsor_credit_piconero,
                net_settlement_piconero,
                settlement_manifest_root,
                created_at_height: self.height,
            },
        );
        if let Some(lane) = self
            .piconero_lanes
            .values_mut()
            .find(|lane| lane.token_id == token_id)
        {
            lane.netted_piconero = lane.netted_piconero.saturating_add(net_settlement_piconero);
        }
        self.push_event("batch_netted", json!({ "batch_id": batch_id }));
        Ok(batch_id)
    }

    pub fn issue_exit_coupon(
        &mut self,
        batch_id: &str,
        recipient_commitment: &str,
        token_id: &str,
        value_commitment: &str,
        exit_fee_piconero: u64,
        claim_nullifier: String,
    ) -> Result<String> {
        require_known("batch", batch_id, &self.batches)?;
        require_non_empty("recipient_commitment", recipient_commitment)?;
        require_non_empty("token_id", token_id)?;
        require_non_empty("value_commitment", value_commitment)?;
        self.insert_nullifier(&claim_nullifier, "exit_coupon")?;
        let sequence = take_counter(&mut self.counters.next_exit_coupon);
        let coupon_id = exit_coupon_id(batch_id, recipient_commitment, sequence);
        self.exit_coupons.insert(
            coupon_id.clone(),
            BridgeExitCoupon {
                coupon_id: coupon_id.clone(),
                batch_id: batch_id.to_string(),
                recipient_commitment: recipient_commitment.to_string(),
                token_id: token_id.to_string(),
                value_commitment: value_commitment.to_string(),
                exit_fee_piconero,
                claim_nullifier,
                status: CouponStatus::Open,
                expires_at_height: self.height + self.config.rebate_window_blocks,
            },
        );
        self.push_event("exit_coupon_issued", json!({ "coupon_id": coupon_id }));
        Ok(coupon_id)
    }

    pub fn claim_exit_coupon(&mut self, coupon_id: &str, claim_nullifier: &str) -> Result<()> {
        let coupon = self
            .exit_coupons
            .get_mut(coupon_id)
            .ok_or_else(|| "unknown coupon".to_string())?;
        if coupon.status != CouponStatus::Open {
            return Err("coupon is not open".to_string());
        }
        if coupon.claim_nullifier != claim_nullifier {
            return Err("coupon nullifier mismatch".to_string());
        }
        coupon.status = CouponStatus::Claimed;
        self.push_event("exit_coupon_claimed", json!({ "coupon_id": coupon_id }));
        Ok(())
    }

    pub fn record_slashing_evidence(
        &mut self,
        offender_commitment: &str,
        abuse_kind: &str,
        related_ids: BTreeSet<String>,
        evidence_root: &str,
        slash_piconero: u64,
    ) -> Result<String> {
        require_non_empty("offender_commitment", offender_commitment)?;
        require_non_empty("abuse_kind", abuse_kind)?;
        require_non_empty("evidence_root", evidence_root)?;
        if related_ids.is_empty() {
            return Err("slashing evidence needs related ids".to_string());
        }
        let sequence = take_counter(&mut self.counters.next_slashing_evidence);
        let evidence_id = slashing_evidence_id(offender_commitment, abuse_kind, sequence);
        self.slashing_evidence.insert(
            evidence_id.clone(),
            SlashingEvidence {
                evidence_id: evidence_id.clone(),
                offender_commitment: offender_commitment.to_string(),
                abuse_kind: abuse_kind.to_string(),
                related_ids,
                evidence_root: evidence_root.to_string(),
                slash_piconero,
                opened_at_height: self.height,
            },
        );
        for lane in self.sponsor_lanes.values_mut() {
            if lane.sponsor_commitment == offender_commitment {
                lane.status = LaneStatus::Frozen;
                lane.bonded_piconero = lane.bonded_piconero.saturating_sub(slash_piconero);
            }
        }
        self.push_event(
            "slashing_evidence_recorded",
            json!({ "evidence_id": evidence_id }),
        );
        Ok(evidence_id)
    }

    pub fn roots(&self) -> Roots {
        let config_root = record_hash("CONFIG", &self.config.public_record());
        let counters_root = record_hash("COUNTERS", &self.counters.public_record());
        let bridge_fee_root = map_root(
            "BRIDGE-FEES",
            self.bridge_fees
                .values()
                .map(BridgeFeeCommitment::public_record),
        );
        let rebate_root = map_root(
            "REBATES",
            self.rebates.values().map(MultiTokenRebate::public_record),
        );
        let sponsor_lane_root = map_root(
            "SPONSOR-LANES",
            self.sponsor_lanes
                .values()
                .map(SponsorSettlementLane::public_record),
        );
        let piconero_lane_root = map_root(
            "PICONERO-LANES",
            self.piconero_lanes
                .values()
                .map(PiconeroFeeLane::public_record),
        );
        let amortization_pool_root = map_root(
            "AMORTIZATION-POOLS",
            self.amortization_pools
                .values()
                .map(AmortizationPool::public_record),
        );
        let payer_cohort_root = map_root(
            "PAYER-COHORTS",
            self.payer_cohorts.values().map(PayerCohort::public_record),
        );
        let batch_root = map_root(
            "BATCHES",
            self.batches.values().map(BatchNetting::public_record),
        );
        let exit_coupon_root = map_root(
            "EXIT-COUPONS",
            self.exit_coupons
                .values()
                .map(BridgeExitCoupon::public_record),
        );
        let nullifier_fence_root = map_root(
            "NULLIFIER-FENCES",
            self.nullifier_fences
                .values()
                .map(NullifierFence::public_record),
        );
        let slashing_evidence_root = map_root(
            "SLASHING-EVIDENCE",
            self.slashing_evidence
                .values()
                .map(SlashingEvidence::public_record),
        );
        let event_root = merkle_root("PUBLIC-EVENTS", &self.public_events);
        let state_root = domain_hash(
            "PRIVATE-L2-FEE-NETTING-STATE",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Int(self.height as i128),
                HashPart::Str(&config_root),
                HashPart::Str(&counters_root),
                HashPart::Str(&bridge_fee_root),
                HashPart::Str(&rebate_root),
                HashPart::Str(&sponsor_lane_root),
                HashPart::Str(&piconero_lane_root),
                HashPart::Str(&amortization_pool_root),
                HashPart::Str(&payer_cohort_root),
                HashPart::Str(&batch_root),
                HashPart::Str(&exit_coupon_root),
                HashPart::Str(&nullifier_fence_root),
                HashPart::Str(&slashing_evidence_root),
                HashPart::Str(&event_root),
            ],
            32,
        );
        Roots {
            config_root,
            counters_root,
            bridge_fee_root,
            rebate_root,
            sponsor_lane_root,
            piconero_lane_root,
            amortization_pool_root,
            payer_cohort_root,
            batch_root,
            exit_coupon_root,
            nullifier_fence_root,
            slashing_evidence_root,
            event_root,
            state_root,
        }
    }

    pub fn state_root(&self) -> String {
        self.roots().state_root
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        json!({
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "height": self.height,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": roots.public_record(),
            "bridge_fees": values_record(self.bridge_fees.values().map(BridgeFeeCommitment::public_record)),
            "rebates": values_record(self.rebates.values().map(MultiTokenRebate::public_record)),
            "sponsor_lanes": values_record(self.sponsor_lanes.values().map(SponsorSettlementLane::public_record)),
            "piconero_lanes": values_record(self.piconero_lanes.values().map(PiconeroFeeLane::public_record)),
            "amortization_pools": values_record(self.amortization_pools.values().map(AmortizationPool::public_record)),
            "payer_cohorts": values_record(self.payer_cohorts.values().map(PayerCohort::public_record)),
            "batches": values_record(self.batches.values().map(BatchNetting::public_record)),
            "exit_coupons": values_record(self.exit_coupons.values().map(BridgeExitCoupon::public_record)),
            "nullifier_fences": values_record(self.nullifier_fences.values().map(NullifierFence::public_record)),
            "slashing_evidence": values_record(self.slashing_evidence.values().map(SlashingEvidence::public_record)),
            "public_events": self.public_events
        })
    }

    fn insert_nullifier(&mut self, nullifier: &str, domain: &str) -> Result<()> {
        require_non_empty("nullifier", nullifier)?;
        if self.nullifier_fences.contains_key(nullifier) {
            return Err("nullifier already fenced".to_string());
        }
        self.nullifier_fences.insert(
            nullifier.to_string(),
            NullifierFence {
                nullifier: nullifier.to_string(),
                first_seen_height: self.height,
                source_id: deterministic_id("NULLIFIER-SOURCE", &[nullifier, domain], self.height),
                domain: domain.to_string(),
            },
        );
        Ok(())
    }

    fn push_event(&mut self, kind: &str, payload: Value) {
        self.counters.events = self.counters.events.saturating_add(1);
        let event = json!({
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "height": self.height,
            "sequence": self.counters.events,
            "kind": kind,
            "payload": payload
        });
        self.public_events.push(event);
        if self.public_events.len() > self.config.max_public_events {
            let overflow = self.public_events.len() - self.config.max_public_events;
            self.public_events.drain(0..overflow);
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BridgeFeeInput {
    pub bridge_id: String,
    pub token_id: String,
    pub direction: BridgeDirection,
    pub payer_cohort_id: String,
    pub sponsor_lane_id: Option<String>,
    pub amount_commitment: String,
    pub fee_piconero: u64,
    pub max_fee_piconero: u64,
    pub da_units: u64,
    pub proof_units: u64,
    pub nullifier: String,
    pub encrypted_payer_hint: String,
    pub pq_receipt_commitment: String,
}

impl BridgeFeeInput {
    pub fn validate(&self) -> Result<()> {
        require_non_empty("bridge_id", &self.bridge_id)?;
        require_non_empty("token_id", &self.token_id)?;
        require_non_empty("payer_cohort_id", &self.payer_cohort_id)?;
        require_non_empty("amount_commitment", &self.amount_commitment)?;
        require_non_empty("nullifier", &self.nullifier)?;
        require_non_empty("encrypted_payer_hint", &self.encrypted_payer_hint)?;
        require_non_empty("pq_receipt_commitment", &self.pq_receipt_commitment)?;
        if self.fee_piconero == 0 || self.max_fee_piconero == 0 {
            return Err("fee amounts must be nonzero".to_string());
        }
        if self.fee_piconero > self.max_fee_piconero {
            return Err("fee exceeds max fee".to_string());
        }
        if self.da_units == 0 || self.proof_units == 0 {
            return Err("da and proof units must be nonzero".to_string());
        }
        Ok(())
    }
}

pub fn record_hash(domain: &str, record: &Value) -> String {
    domain_hash(
        &format!("PRIVATE-L2-FEE-NETTING-{domain}"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Json(record),
        ],
        32,
    )
}

pub fn map_root<I>(domain: &str, records: I) -> String
where
    I: IntoIterator<Item = Value>,
{
    let mut leaves = records.into_iter().collect::<Vec<_>>();
    leaves.sort_by_key(record_hash_sort_key);
    merkle_root(&format!("PRIVATE-L2-FEE-NETTING-{domain}"), &leaves)
}

pub fn values_record<I>(records: I) -> Value
where
    I: IntoIterator<Item = Value>,
{
    let mut values = records.into_iter().collect::<Vec<_>>();
    values.sort_by_key(record_hash_sort_key);
    Value::Array(values)
}

pub fn deterministic_id(domain: &str, parts: &[&str], sequence: u64) -> String {
    let mut hash_parts = Vec::with_capacity(parts.len() + 3);
    hash_parts.push(HashPart::Str(CHAIN_ID));
    hash_parts.push(HashPart::Str(PROTOCOL_VERSION));
    for part in parts {
        hash_parts.push(HashPart::Str(part));
    }
    hash_parts.push(HashPart::Int(sequence as i128));
    domain_hash(
        &format!("PRIVATE-L2-FEE-NETTING-{domain}-ID"),
        &hash_parts,
        16,
    )
}

pub fn deterministic_root(domain: &str, label: &str, height: u64) -> String {
    domain_hash(
        &format!("PRIVATE-L2-FEE-NETTING-{domain}-ROOT"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
            HashPart::Int(height as i128),
        ],
        32,
    )
}

pub fn deterministic_commitment(domain: &str, label: &str, height: u64) -> String {
    domain_hash(
        &format!("PRIVATE-L2-FEE-NETTING-{domain}-COMMITMENT"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
            HashPart::Int(height as i128),
        ],
        32,
    )
}

pub fn deterministic_nullifier(domain: &str, label: &str, height: u64) -> String {
    domain_hash(
        &format!("PRIVATE-L2-FEE-NETTING-{domain}-NULLIFIER"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
            HashPart::Int(height as i128),
        ],
        32,
    )
}

pub fn bridge_fee_id(bridge_id: &str, token_id: &str, nullifier: &str, sequence: u64) -> String {
    deterministic_id("BRIDGE-FEE", &[bridge_id, token_id, nullifier], sequence)
}

pub fn rebate_id(token_id: &str, payer_cohort_id: &str, reserve_id: &str, sequence: u64) -> String {
    deterministic_id("REBATE", &[token_id, payer_cohort_id, reserve_id], sequence)
}

pub fn sponsor_lane_id(
    sponsor_commitment: &str,
    settlement_asset_id: &str,
    sequence: u64,
) -> String {
    deterministic_id(
        "SPONSOR-LANE",
        &[sponsor_commitment, settlement_asset_id],
        sequence,
    )
}

pub fn piconero_lane_id(token_id: &str, sequence: u64) -> String {
    deterministic_id("PICONERO-LANE", &[token_id], sequence)
}

pub fn amortization_pool_id(bridge_id: &str, da_commitment_root: &str, sequence: u64) -> String {
    deterministic_id(
        "AMORTIZATION-POOL",
        &[bridge_id, da_commitment_root],
        sequence,
    )
}

pub fn payer_cohort_id(token_id: &str, encrypted_cohort_root: &str, sequence: u64) -> String {
    deterministic_id("PAYER-COHORT", &[token_id, encrypted_cohort_root], sequence)
}

pub fn batch_id(token_id: &str, fee_ids: &BTreeSet<String>, sequence: u64) -> String {
    let fee_root = merkle_root(
        "PRIVATE-L2-FEE-NETTING-BATCH-ID-FEES",
        &fee_ids.iter().map(|id| json!(id)).collect::<Vec<_>>(),
    );
    deterministic_id("BATCH", &[token_id, &fee_root], sequence)
}

pub fn exit_coupon_id(batch_id: &str, recipient_commitment: &str, sequence: u64) -> String {
    deterministic_id("EXIT-COUPON", &[batch_id, recipient_commitment], sequence)
}

pub fn slashing_evidence_id(offender_commitment: &str, abuse_kind: &str, sequence: u64) -> String {
    deterministic_id(
        "SLASHING-EVIDENCE",
        &[offender_commitment, abuse_kind],
        sequence,
    )
}

pub fn settlement_manifest_root(
    batch_id: &str,
    token_id: &str,
    gross_fee_piconero: u64,
    rebate_piconero: u64,
    sponsor_credit_piconero: u64,
) -> String {
    record_hash(
        "SETTLEMENT-MANIFEST",
        &json!({
            "batch_id": batch_id,
            "token_id": token_id,
            "gross_fee_piconero": gross_fee_piconero,
            "rebate_piconero": rebate_piconero,
            "sponsor_credit_piconero": sponsor_credit_piconero
        }),
    )
}

fn take_counter(counter: &mut u64) -> u64 {
    let current = *counter;
    *counter = counter.saturating_add(1);
    current
}

fn sorted_strings(values: &BTreeSet<String>) -> Vec<String> {
    values.iter().cloned().collect()
}

fn record_hash_sort_key(record: &Value) -> String {
    record_hash("SORT", record)
}

fn require_non_empty(name: &str, value: &str) -> Result<()> {
    if value.is_empty() {
        return Err(format!("{name} must not be empty"));
    }
    Ok(())
}

fn require_equal(name: &str, left: &str, right: &str) -> Result<()> {
    if left != right {
        return Err(format!("{name} mismatch"));
    }
    Ok(())
}

fn require_known<T>(name: &str, id: &str, map: &BTreeMap<String, T>) -> Result<()> {
    if !map.contains_key(id) {
        return Err(format!("unknown {name}"));
    }
    Ok(())
}
