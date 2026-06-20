use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2LowFeePqConfidentialProofBlobRebateOptimizerRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_PROOF_BLOB_REBATE_OPTIMIZER_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-low-fee-pq-confidential-proof-blob-rebate-optimizer-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_PROOF_BLOB_REBATE_OPTIMIZER_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const CONFIDENTIAL_REBATE_QUEUE_SUITE: &str = "ml-kem-1024-sealed-proof-blob-rebate-queue-v1";
pub const PQ_VERIFIER_ATTESTATION_SUITE: &str =
    "ml-dsa-87+slh-dsa-shake-256f-proof-blob-verifier-attestation-v1";
pub const AMORTIZATION_SUITE: &str = "low-fee-confidential-proof-blob-da-amortization-optimizer-v1";
pub const PRIVACY_BOUNDARY: &str =
    "roots_only_no_rebate_plaintexts_blob_payloads_view_keys_addresses_or_secret_keys";
pub const DEVNET_L2_HEIGHT: u64 = 4_560_000;
pub const DEVNET_EPOCH: u64 = 14_592;
pub const DEFAULT_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEFAULT_REBATE_ASSET_ID: &str = "proof-blob-rebate-credit-devnet";
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 131_072;
pub const DEFAULT_TARGET_PRIVACY_SET_SIZE: u64 = 1_048_576;
pub const DEFAULT_BASE_PROOF_FEE_MICRO_UNITS: u64 = 5_000;
pub const DEFAULT_BASE_BLOB_DA_FEE_MICRO_UNITS: u64 = 7_500;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 9;
pub const DEFAULT_TARGET_REBATE_BPS: u64 = 35;
pub const DEFAULT_MAX_REBATE_BPS: u64 = 80;
pub const DEFAULT_AMORTIZATION_WINDOW_SLOTS: u64 = 768;
pub const DEFAULT_QUEUE_TTL_SLOTS: u64 = 4_096;
pub const DEFAULT_ATTESTATION_TTL_SLOTS: u64 = 2_048;
pub const MAX_BPS: u64 = 10_000;

const D_STATE: &str = "PL2-LOW-FEE-PQ-CONF-PROOF-BLOB-REBATE-OPTIMIZER:STATE";
const D_CONFIG: &str = "PL2-LOW-FEE-PQ-CONF-PROOF-BLOB-REBATE-OPTIMIZER:CONFIG";
const D_COUNTERS: &str = "PL2-LOW-FEE-PQ-CONF-PROOF-BLOB-REBATE-OPTIMIZER:COUNTERS";
const D_ROOTS: &str = "PL2-LOW-FEE-PQ-CONF-PROOF-BLOB-REBATE-OPTIMIZER:ROOTS";
const D_QUEUES: &str = "PL2-LOW-FEE-PQ-CONF-PROOF-BLOB-REBATE-OPTIMIZER:QUEUES";
const D_ATTESTATIONS: &str = "PL2-LOW-FEE-PQ-CONF-PROOF-BLOB-REBATE-OPTIMIZER:ATTESTATIONS";
const D_BIDS: &str = "PL2-LOW-FEE-PQ-CONF-PROOF-BLOB-REBATE-OPTIMIZER:BIDS";
const D_PLANS: &str = "PL2-LOW-FEE-PQ-CONF-PROOF-BLOB-REBATE-OPTIMIZER:PLANS";
const D_SETTLEMENTS: &str = "PL2-LOW-FEE-PQ-CONF-PROOF-BLOB-REBATE-OPTIMIZER:SETTLEMENTS";
const D_NULLIFIERS: &str = "PL2-LOW-FEE-PQ-CONF-PROOF-BLOB-REBATE-OPTIMIZER:NULLIFIERS";
const D_EVENTS: &str = "PL2-LOW-FEE-PQ-CONF-PROOF-BLOB-REBATE-OPTIMIZER:EVENTS";

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OptimizerLane {
    MicroProof,
    StandardBlob,
    RecursiveBundle,
    DaHeavy,
    Emergency,
}

impl OptimizerLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MicroProof => "micro_proof",
            Self::StandardBlob => "standard_blob",
            Self::RecursiveBundle => "recursive_bundle",
            Self::DaHeavy => "da_heavy",
            Self::Emergency => "emergency",
        }
    }

    pub fn fee_multiplier_bps(self) -> u64 {
        match self {
            Self::MicroProof => 6_500,
            Self::StandardBlob => 10_000,
            Self::RecursiveBundle => 11_500,
            Self::DaHeavy => 14_500,
            Self::Emergency => 22_000,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QueueStatus {
    Open,
    Optimizing,
    Draining,
    Exhausted,
    Expired,
}

impl QueueStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Optimizing => "optimizing",
            Self::Draining => "draining",
            Self::Exhausted => "exhausted",
            Self::Expired => "expired",
        }
    }

    pub fn accepts_bids(self) -> bool {
        matches!(self, Self::Open | Self::Optimizing | Self::Draining)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub fee_asset_id: String,
    pub rebate_asset_id: String,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub base_proof_fee_micro_units: u64,
    pub base_blob_da_fee_micro_units: u64,
    pub max_user_fee_bps: u64,
    pub target_rebate_bps: u64,
    pub max_rebate_bps: u64,
    pub amortization_window_slots: u64,
    pub queue_ttl_slots: u64,
    pub attestation_ttl_slots: u64,
    pub devnet_l2_height: u64,
    pub devnet_epoch: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            fee_asset_id: DEFAULT_FEE_ASSET_ID.to_string(),
            rebate_asset_id: DEFAULT_REBATE_ASSET_ID.to_string(),
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            base_proof_fee_micro_units: DEFAULT_BASE_PROOF_FEE_MICRO_UNITS,
            base_blob_da_fee_micro_units: DEFAULT_BASE_BLOB_DA_FEE_MICRO_UNITS,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            target_rebate_bps: DEFAULT_TARGET_REBATE_BPS,
            max_rebate_bps: DEFAULT_MAX_REBATE_BPS,
            amortization_window_slots: DEFAULT_AMORTIZATION_WINDOW_SLOTS,
            queue_ttl_slots: DEFAULT_QUEUE_TTL_SLOTS,
            attestation_ttl_slots: DEFAULT_ATTESTATION_TTL_SLOTS,
            devnet_l2_height: DEVNET_L2_HEIGHT,
            devnet_epoch: DEVNET_EPOCH,
        }
    }
}

impl Config {
    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": SCHEMA_VERSION,
            "hash_suite": HASH_SUITE,
            "confidential_rebate_queue_suite": CONFIDENTIAL_REBATE_QUEUE_SUITE,
            "pq_verifier_attestation_suite": PQ_VERIFIER_ATTESTATION_SUITE,
            "amortization_suite": AMORTIZATION_SUITE,
            "privacy_boundary": PRIVACY_BOUNDARY,
            "fee_asset_id": self.fee_asset_id,
            "rebate_asset_id": self.rebate_asset_id,
            "min_pq_security_bits": self.min_pq_security_bits,
            "min_privacy_set_size": self.min_privacy_set_size,
            "target_privacy_set_size": self.target_privacy_set_size,
            "base_proof_fee_micro_units": self.base_proof_fee_micro_units,
            "base_blob_da_fee_micro_units": self.base_blob_da_fee_micro_units,
            "max_user_fee_bps": self.max_user_fee_bps,
            "target_rebate_bps": self.target_rebate_bps,
            "max_rebate_bps": self.max_rebate_bps,
            "amortization_window_slots": self.amortization_window_slots,
            "queue_ttl_slots": self.queue_ttl_slots,
            "attestation_ttl_slots": self.attestation_ttl_slots,
            "devnet_l2_height": self.devnet_l2_height,
            "devnet_epoch": self.devnet_epoch
        })
    }

    pub fn state_root(&self) -> String {
        record_root(D_CONFIG, &self.public_record())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub rebate_queues: u64,
    pub pq_verifier_attestations: u64,
    pub confidential_rebate_bids: u64,
    pub optimization_plans: u64,
    pub rebate_settlements: u64,
    pub nullifiers: u64,
    pub public_events: u64,
    pub queued_rebate_micro_units: u64,
    pub optimized_rebate_micro_units: u64,
    pub settled_rebate_micro_units: u64,
    pub amortized_proof_fee_micro_units: u64,
    pub amortized_blob_da_fee_micro_units: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn state_root(&self) -> String {
        record_root(D_COUNTERS, &self.public_record())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub counters_root: String,
    pub rebate_queue_root: String,
    pub pq_verifier_attestation_root: String,
    pub confidential_rebate_bid_root: String,
    pub optimization_plan_root: String,
    pub rebate_settlement_root: String,
    pub nullifier_root: String,
    pub public_events_root: String,
    pub deterministic_state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn state_root(&self) -> String {
        record_root(D_ROOTS, &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RebateQueue {
    pub queue_id: String,
    pub sponsor_commitment: String,
    pub lane: OptimizerLane,
    pub sealed_queue_root: String,
    pub available_rebate_micro_units: u64,
    pub privacy_set_size: u64,
    pub opened_slot: u64,
    pub expires_slot: u64,
    pub status: QueueStatus,
}

impl RebateQueue {
    pub fn public_record(&self) -> Value {
        json!({
            "queue_id": self.queue_id,
            "sponsor_commitment": redacted_commitment(&self.sponsor_commitment),
            "lane": self.lane.as_str(),
            "sealed_queue_root": self.sealed_queue_root,
            "available_rebate_micro_units": self.available_rebate_micro_units,
            "privacy_set_size": self.privacy_set_size,
            "opened_slot": self.opened_slot,
            "expires_slot": self.expires_slot,
            "status": self.status.as_str()
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqVerifierAttestation {
    pub attestation_id: String,
    pub queue_id: String,
    pub verifier_commitment: String,
    pub pq_key_commitment: String,
    pub attestation_root: String,
    pub signature_commitment: String,
    pub security_bits: u16,
    pub privacy_set_size: u64,
    pub valid_until_slot: u64,
}

impl PqVerifierAttestation {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "queue_id": self.queue_id,
            "verifier_commitment": redacted_commitment(&self.verifier_commitment),
            "pq_key_commitment": redacted_commitment(&self.pq_key_commitment),
            "attestation_root": self.attestation_root,
            "signature_commitment": redacted_commitment(&self.signature_commitment),
            "security_bits": self.security_bits,
            "privacy_set_size": self.privacy_set_size,
            "valid_until_slot": self.valid_until_slot
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ConfidentialRebateBid {
    pub bid_id: String,
    pub queue_id: String,
    pub attestation_id: String,
    pub sealed_bid_root: String,
    pub rebate_nullifier: String,
    pub requested_rebate_micro_units: u64,
    pub proof_work_units: u64,
    pub blob_bytes: u64,
    pub max_user_fee_micro_units: u64,
    pub slot: u64,
}

impl ConfidentialRebateBid {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OptimizationPlan {
    pub plan_id: String,
    pub bid_id: String,
    pub queue_id: String,
    pub amortized_proof_fee_micro_units: u64,
    pub amortized_blob_da_fee_micro_units: u64,
    pub gross_fee_micro_units: u64,
    pub user_fee_cap_micro_units: u64,
    pub optimized_rebate_micro_units: u64,
    pub amortization_window_slots: u64,
}

impl OptimizationPlan {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RebateSettlement {
    pub settlement_id: String,
    pub plan_id: String,
    pub queue_id: String,
    pub settlement_nullifier: String,
    pub paid_user_fee_micro_units: u64,
    pub settled_rebate_micro_units: u64,
    pub slot: u64,
}

impl RebateSettlement {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub rebate_queues: BTreeMap<String, RebateQueue>,
    pub pq_verifier_attestations: BTreeMap<String, PqVerifierAttestation>,
    pub confidential_rebate_bids: BTreeMap<String, ConfidentialRebateBid>,
    pub optimization_plans: BTreeMap<String, OptimizationPlan>,
    pub rebate_settlements: BTreeMap<String, RebateSettlement>,
    pub nullifiers: BTreeSet<String>,
    pub public_events: Vec<Value>,
}

impl Default for State {
    fn default() -> Self {
        let mut state = Self {
            config: Config::default(),
            counters: Counters::default(),
            roots: Roots::default(),
            rebate_queues: BTreeMap::new(),
            pq_verifier_attestations: BTreeMap::new(),
            confidential_rebate_bids: BTreeMap::new(),
            optimization_plans: BTreeMap::new(),
            rebate_settlements: BTreeMap::new(),
            nullifiers: BTreeSet::new(),
            public_events: Vec::new(),
        };
        state.recompute_roots();
        state
    }
}

impl State {
    pub fn devnet() -> Self {
        devnet()
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        set_json_field(&mut record, "state_root", json!(self.state_root()));
        record
    }

    pub fn state_root(&self) -> String {
        state_root_from_public_record(&self.public_record_without_state_root())
    }

    pub fn open_rebate_queue(
        &mut self,
        sponsor_commitment: impl Into<String>,
        lane: OptimizerLane,
        sealed_queue_root: impl Into<String>,
        rebate_micro_units: u64,
        privacy_set_size: u64,
        opened_slot: u64,
    ) -> Result<String> {
        if rebate_micro_units == 0 {
            return Err("rebate queue requires positive rebate liquidity".to_string());
        }
        if privacy_set_size < self.config.min_privacy_set_size {
            return Err("rebate queue privacy set below configured floor".to_string());
        }
        let sponsor_commitment = sponsor_commitment.into();
        let sealed_queue_root = sealed_queue_root.into();
        let queue_id = deterministic_id(
            "queue",
            &[
                &sponsor_commitment,
                lane.as_str(),
                &sealed_queue_root,
                &opened_slot.to_string(),
            ],
        );
        let queue = RebateQueue {
            queue_id: queue_id.clone(),
            sponsor_commitment,
            lane,
            sealed_queue_root,
            available_rebate_micro_units: rebate_micro_units,
            privacy_set_size,
            opened_slot,
            expires_slot: opened_slot.saturating_add(self.config.queue_ttl_slots),
            status: QueueStatus::Open,
        };
        self.rebate_queues.insert(queue_id.clone(), queue);
        self.counters.queued_rebate_micro_units = self
            .counters
            .queued_rebate_micro_units
            .saturating_add(rebate_micro_units);
        self.record_event("confidential_rebate_queue_opened", &queue_id);
        self.recompute_roots();
        Ok(queue_id)
    }

    pub fn record_pq_verifier_attestation(
        &mut self,
        queue_id: impl Into<String>,
        verifier_commitment: impl Into<String>,
        pq_key_commitment: impl Into<String>,
        signature_commitment: impl Into<String>,
        security_bits: u16,
        privacy_set_size: u64,
        slot: u64,
    ) -> Result<String> {
        let queue_id = queue_id.into();
        if !self.rebate_queues.contains_key(&queue_id) {
            return Err("unknown rebate queue for verifier attestation".to_string());
        }
        if security_bits < self.config.min_pq_security_bits {
            return Err("PQ verifier attestation below configured security floor".to_string());
        }
        if privacy_set_size < self.config.min_privacy_set_size {
            return Err("PQ verifier attestation privacy set below configured floor".to_string());
        }
        let verifier_commitment = verifier_commitment.into();
        let pq_key_commitment = pq_key_commitment.into();
        let signature_commitment = signature_commitment.into();
        let attestation_id = deterministic_id(
            "pq-verifier-attestation",
            &[
                &queue_id,
                &verifier_commitment,
                &pq_key_commitment,
                &slot.to_string(),
            ],
        );
        let attestation_root = deterministic_leaf(
            "pq-verifier-attestation-root",
            &[
                &attestation_id,
                &queue_id,
                &pq_key_commitment,
                &signature_commitment,
            ],
        );
        let attestation = PqVerifierAttestation {
            attestation_id: attestation_id.clone(),
            queue_id,
            verifier_commitment,
            pq_key_commitment,
            attestation_root,
            signature_commitment,
            security_bits,
            privacy_set_size,
            valid_until_slot: slot.saturating_add(self.config.attestation_ttl_slots),
        };
        self.pq_verifier_attestations
            .insert(attestation_id.clone(), attestation);
        self.record_event("pq_verifier_attestation_recorded", &attestation_id);
        self.recompute_roots();
        Ok(attestation_id)
    }

    pub fn enqueue_rebate_bid(
        &mut self,
        queue_id: impl Into<String>,
        attestation_id: impl Into<String>,
        sealed_bid_root: impl Into<String>,
        rebate_nullifier: impl Into<String>,
        requested_rebate_micro_units: u64,
        proof_work_units: u64,
        blob_bytes: u64,
        slot: u64,
    ) -> Result<String> {
        let queue_id = queue_id.into();
        let attestation_id = attestation_id.into();
        let rebate_nullifier = rebate_nullifier.into();
        ensure_nullifier_available(&self.nullifiers, &rebate_nullifier)?;
        let attestation = self
            .pq_verifier_attestations
            .get(&attestation_id)
            .ok_or_else(|| "unknown PQ verifier attestation".to_string())?;
        if attestation.queue_id != queue_id {
            return Err("PQ verifier attestation is not bound to rebate queue".to_string());
        }
        if slot > attestation.valid_until_slot {
            return Err("PQ verifier attestation has expired".to_string());
        }
        let queue = self
            .rebate_queues
            .get_mut(&queue_id)
            .ok_or_else(|| "unknown rebate queue".to_string())?;
        if !queue.status.accepts_bids() {
            return Err("rebate queue is not accepting bids".to_string());
        }
        if slot > queue.expires_slot {
            queue.status = QueueStatus::Expired;
            return Err("rebate queue has expired".to_string());
        }
        if requested_rebate_micro_units == 0
            || requested_rebate_micro_units > queue.available_rebate_micro_units
        {
            return Err("insufficient confidential rebate liquidity".to_string());
        }
        if proof_work_units == 0 || blob_bytes == 0 {
            return Err("optimizer bid requires proof work and blob bytes".to_string());
        }
        let sealed_bid_root = sealed_bid_root.into();
        let bid_id = deterministic_id(
            "rebate-bid",
            &[
                &queue_id,
                &attestation_id,
                &sealed_bid_root,
                &rebate_nullifier,
                &slot.to_string(),
            ],
        );
        let estimated_gross_fee =
            estimated_fee(&self.config, queue.lane, proof_work_units, blob_bytes);
        let max_user_fee_micro_units = estimated_gross_fee
            .saturating_mul(self.config.max_user_fee_bps)
            .saturating_div(MAX_BPS);
        queue.available_rebate_micro_units = queue
            .available_rebate_micro_units
            .saturating_sub(requested_rebate_micro_units);
        queue.status = if queue.available_rebate_micro_units == 0 {
            QueueStatus::Exhausted
        } else {
            QueueStatus::Optimizing
        };
        let bid = ConfidentialRebateBid {
            bid_id: bid_id.clone(),
            queue_id,
            attestation_id,
            sealed_bid_root,
            rebate_nullifier: rebate_nullifier.clone(),
            requested_rebate_micro_units,
            proof_work_units,
            blob_bytes,
            max_user_fee_micro_units,
            slot,
        };
        self.nullifiers.insert(rebate_nullifier);
        self.confidential_rebate_bids.insert(bid_id.clone(), bid);
        self.record_event("confidential_rebate_bid_enqueued", &bid_id);
        self.recompute_roots();
        Ok(bid_id)
    }

    pub fn optimize_rebate_plan(&mut self, bid_id: impl Into<String>) -> Result<String> {
        let bid_id = bid_id.into();
        let bid = self
            .confidential_rebate_bids
            .get(&bid_id)
            .ok_or_else(|| "unknown confidential rebate bid".to_string())?;
        let queue = self
            .rebate_queues
            .get(&bid.queue_id)
            .ok_or_else(|| "unknown rebate queue for optimization".to_string())?;
        let proof_fee = amortized_proof_fee(&self.config, queue.lane, bid.proof_work_units);
        let blob_da_fee = amortized_blob_da_fee(&self.config, queue.lane, bid.blob_bytes);
        let gross_fee = proof_fee.saturating_add(blob_da_fee);
        let target_rebate = gross_fee
            .saturating_mul(self.config.target_rebate_bps)
            .saturating_div(MAX_BPS);
        let max_rebate = gross_fee
            .saturating_mul(self.config.max_rebate_bps)
            .saturating_div(MAX_BPS);
        let optimized_rebate = bid
            .requested_rebate_micro_units
            .min(max_rebate)
            .max(target_rebate);
        let optimized_rebate = optimized_rebate.min(bid.requested_rebate_micro_units);
        let plan_id = deterministic_id(
            "optimization-plan",
            &[
                &bid_id,
                &gross_fee.to_string(),
                &optimized_rebate.to_string(),
            ],
        );
        let plan = OptimizationPlan {
            plan_id: plan_id.clone(),
            bid_id: bid_id.clone(),
            queue_id: bid.queue_id.clone(),
            amortized_proof_fee_micro_units: proof_fee,
            amortized_blob_da_fee_micro_units: blob_da_fee,
            gross_fee_micro_units: gross_fee,
            user_fee_cap_micro_units: bid.max_user_fee_micro_units,
            optimized_rebate_micro_units: optimized_rebate,
            amortization_window_slots: self.config.amortization_window_slots,
        };
        self.counters.optimized_rebate_micro_units = self
            .counters
            .optimized_rebate_micro_units
            .saturating_add(optimized_rebate);
        self.counters.amortized_proof_fee_micro_units = self
            .counters
            .amortized_proof_fee_micro_units
            .saturating_add(proof_fee);
        self.counters.amortized_blob_da_fee_micro_units = self
            .counters
            .amortized_blob_da_fee_micro_units
            .saturating_add(blob_da_fee);
        self.optimization_plans.insert(plan_id.clone(), plan);
        self.record_event("proof_blob_rebate_plan_optimized", &plan_id);
        self.recompute_roots();
        Ok(plan_id)
    }

    pub fn settle_rebate(
        &mut self,
        plan_id: impl Into<String>,
        settlement_nullifier: impl Into<String>,
        paid_user_fee_micro_units: u64,
        slot: u64,
    ) -> Result<String> {
        let plan_id = plan_id.into();
        let settlement_nullifier = settlement_nullifier.into();
        ensure_nullifier_available(&self.nullifiers, &settlement_nullifier)?;
        let plan = self
            .optimization_plans
            .get(&plan_id)
            .ok_or_else(|| "unknown optimization plan".to_string())?;
        if paid_user_fee_micro_units > plan.user_fee_cap_micro_units {
            return Err("paid user fee exceeds optimized low-fee cap".to_string());
        }
        let settlement_id = deterministic_id(
            "rebate-settlement",
            &[&plan_id, &settlement_nullifier, &slot.to_string()],
        );
        let settlement = RebateSettlement {
            settlement_id: settlement_id.clone(),
            plan_id,
            queue_id: plan.queue_id.clone(),
            settlement_nullifier: settlement_nullifier.clone(),
            paid_user_fee_micro_units,
            settled_rebate_micro_units: plan.optimized_rebate_micro_units,
            slot,
        };
        self.nullifiers.insert(settlement_nullifier);
        self.counters.settled_rebate_micro_units = self
            .counters
            .settled_rebate_micro_units
            .saturating_add(settlement.settled_rebate_micro_units);
        if let Some(queue) = self.rebate_queues.get_mut(&settlement.queue_id) {
            if queue.status == QueueStatus::Optimizing {
                queue.status = QueueStatus::Draining;
            }
        }
        self.rebate_settlements
            .insert(settlement_id.clone(), settlement);
        self.record_event("proof_blob_rebate_settled", &settlement_id);
        self.recompute_roots();
        Ok(settlement_id)
    }

    pub fn recompute_roots(&mut self) {
        self.counters.rebate_queues = self.rebate_queues.len() as u64;
        self.counters.pq_verifier_attestations = self.pq_verifier_attestations.len() as u64;
        self.counters.confidential_rebate_bids = self.confidential_rebate_bids.len() as u64;
        self.counters.optimization_plans = self.optimization_plans.len() as u64;
        self.counters.rebate_settlements = self.rebate_settlements.len() as u64;
        self.counters.nullifiers = self.nullifiers.len() as u64;
        self.counters.public_events = self.public_events.len() as u64;
        self.roots.config_root = self.config.state_root();
        self.roots.counters_root = self.counters.state_root();
        self.roots.rebate_queue_root =
            map_root(D_QUEUES, &self.rebate_queues, RebateQueue::public_record);
        self.roots.pq_verifier_attestation_root = map_root(
            D_ATTESTATIONS,
            &self.pq_verifier_attestations,
            PqVerifierAttestation::public_record,
        );
        self.roots.confidential_rebate_bid_root = map_root(
            D_BIDS,
            &self.confidential_rebate_bids,
            ConfidentialRebateBid::public_record,
        );
        self.roots.optimization_plan_root = map_root(
            D_PLANS,
            &self.optimization_plans,
            OptimizationPlan::public_record,
        );
        self.roots.rebate_settlement_root = map_root(
            D_SETTLEMENTS,
            &self.rebate_settlements,
            RebateSettlement::public_record,
        );
        self.roots.nullifier_root = set_root(D_NULLIFIERS, &self.nullifiers);
        self.roots.public_events_root = list_root(D_EVENTS, &self.public_events);
        self.roots.deterministic_state_root = self.state_root();
    }

    fn public_record_without_state_root(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
            "rebate_queues": public_map(&self.rebate_queues, RebateQueue::public_record),
            "pq_verifier_attestations": public_map(&self.pq_verifier_attestations, PqVerifierAttestation::public_record),
            "confidential_rebate_bids": public_map(&self.confidential_rebate_bids, ConfidentialRebateBid::public_record),
            "optimization_plans": public_map(&self.optimization_plans, OptimizationPlan::public_record),
            "rebate_settlements": public_map(&self.rebate_settlements, RebateSettlement::public_record),
            "nullifiers": self.nullifiers,
            "public_events": self.public_events,
            "privacy_boundary": PRIVACY_BOUNDARY
        })
    }

    fn record_event(&mut self, kind: &str, subject_id: &str) {
        self.public_events.push(json!({
            "kind": kind,
            "subject_id": subject_id,
            "event_index": self.public_events.len() as u64,
            "event_root": deterministic_leaf(kind, &[subject_id, &self.public_events.len().to_string()])
        }));
        self.counters.public_events = self.public_events.len() as u64;
    }
}

pub fn devnet() -> State {
    let mut state = State::default();
    let queue = state
        .open_rebate_queue(
            "sponsor_commitment:devnet-proof-blob-rebate-optimizer",
            OptimizerLane::StandardBlob,
            demo_root("sealed-rebate-queue"),
            25_000_000,
            DEFAULT_TARGET_PRIVACY_SET_SIZE,
            DEVNET_EPOCH,
        )
        .expect("devnet rebate queue opens");
    state
        .record_pq_verifier_attestation(
            queue,
            "verifier_commitment:devnet-proof-blob-verifier",
            "pq_key_commitment:devnet-verifier-ml-dsa-87",
            "pq_signature_commitment:devnet-proof-blob-verifier",
            DEFAULT_MIN_PQ_SECURITY_BITS,
            DEFAULT_TARGET_PRIVACY_SET_SIZE,
            DEVNET_EPOCH + 1,
        )
        .expect("devnet PQ verifier attestation records");
    state.recompute_roots();
    state
}

pub fn demo() -> State {
    let mut state = devnet();
    let queue_id = state
        .rebate_queues
        .keys()
        .next()
        .cloned()
        .expect("demo has rebate queue");
    let attestation_id = state
        .pq_verifier_attestations
        .keys()
        .next()
        .cloned()
        .expect("demo has PQ verifier attestation");
    let bid = state
        .enqueue_rebate_bid(
            queue_id,
            attestation_id,
            demo_root("sealed-bid"),
            "nullifier:devnet-proof-blob-rebate-bid",
            12_000,
            9,
            393_216,
            DEVNET_EPOCH + 4,
        )
        .expect("demo rebate bid enqueues");
    let plan = state
        .optimize_rebate_plan(bid)
        .expect("demo rebate plan optimizes");
    state
        .settle_rebate(
            plan,
            "nullifier:devnet-proof-blob-rebate-settlement",
            11,
            DEVNET_EPOCH + 6,
        )
        .expect("demo rebate settles");
    state.recompute_roots();
    state
}

pub fn public_record(state: &State) -> Value {
    state.public_record()
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}

fn public_map<T>(map: &BTreeMap<String, T>, public_record: fn(&T) -> Value) -> Vec<Value> {
    map.iter()
        .map(|(key, value)| json!({ "key": key, "record": public_record(value) }))
        .collect()
}

fn map_root<T>(domain: &str, map: &BTreeMap<String, T>, public_record: fn(&T) -> Value) -> String {
    let leaves: Vec<Value> = map
        .iter()
        .map(|(key, value)| {
            json!({
                "key": key,
                "record_root": record_root(domain, &json!({ "key": key, "record": public_record(value) }))
            })
        })
        .collect();
    merkle_root(domain, &leaves)
}

fn set_root(domain: &str, set: &BTreeSet<String>) -> String {
    let leaves: Vec<Value> = set.iter().map(|value| json!({ "value": value })).collect();
    merkle_root(domain, &leaves)
}

fn list_root(domain: &str, values: &[Value]) -> String {
    let leaves: Vec<Value> = values
        .iter()
        .enumerate()
        .map(|(index, value)| {
            json!({
                "index": index,
                "record_root": record_root(domain, &json!({ "index": index, "record": value }))
            })
        })
        .collect();
    merkle_root(domain, &leaves)
}

fn state_root_from_public_record(record: &Value) -> String {
    record_root(D_STATE, record)
}

fn record_root(domain: &str, record: &Value) -> String {
    domain_hash(domain, &[HashPart::Json(record)], 32)
}

fn deterministic_id(label: &str, parts: &[&str]) -> String {
    format!("{label}:{}", deterministic_leaf(label, parts))
}

fn deterministic_leaf(domain: &str, parts: &[&str]) -> String {
    let hash_parts = parts
        .iter()
        .map(|part| HashPart::Str(*part))
        .collect::<Vec<_>>();
    domain_hash(
        &format!("PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-PROOF-BLOB-REBATE-OPTIMIZER:{domain}"),
        &hash_parts,
        32,
    )
}

fn demo_root(label: &str) -> String {
    deterministic_leaf("demo-root", &[label])
}

fn estimated_fee(
    config: &Config,
    lane: OptimizerLane,
    proof_work_units: u64,
    blob_bytes: u64,
) -> u64 {
    amortized_proof_fee(config, lane, proof_work_units)
        .saturating_add(amortized_blob_da_fee(config, lane, blob_bytes))
}

fn amortized_proof_fee(config: &Config, lane: OptimizerLane, proof_work_units: u64) -> u64 {
    config
        .base_proof_fee_micro_units
        .saturating_mul(proof_work_units)
        .saturating_mul(lane.fee_multiplier_bps())
        .saturating_div(MAX_BPS)
}

fn amortized_blob_da_fee(config: &Config, lane: OptimizerLane, blob_bytes: u64) -> u64 {
    let blob_chunks = blob_bytes.saturating_add(131_071).saturating_div(131_072);
    config
        .base_blob_da_fee_micro_units
        .saturating_mul(blob_chunks)
        .saturating_mul(lane.fee_multiplier_bps())
        .saturating_div(MAX_BPS)
}

fn ensure_nullifier_available(nullifiers: &BTreeSet<String>, nullifier: &str) -> Result<()> {
    if nullifiers.contains(nullifier) {
        Err(format!("nullifier {nullifier} already consumed"))
    } else {
        Ok(())
    }
}

fn redacted_commitment(commitment: &str) -> String {
    if commitment.is_empty() {
        return "redacted:empty".to_string();
    }
    let digest = domain_hash(
        "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-PROOF-BLOB-REBATE-OPTIMIZER:REDACTED-COMMITMENT",
        &[HashPart::Str(commitment)],
        16,
    );
    format!("redacted:{digest}")
}

fn set_json_field(record: &mut Value, key: &str, value: Value) {
    if let Value::Object(object) = record {
        object.insert(key.to_string(), value);
    }
}
