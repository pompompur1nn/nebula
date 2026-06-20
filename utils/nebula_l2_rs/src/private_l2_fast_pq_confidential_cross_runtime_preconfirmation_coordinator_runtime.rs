use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type Runtime = State;

pub const PROTOCOL_VERSION: &str =
    "nebula-private-l2-fast-pq-confidential-cross-runtime-preconfirmation-coordinator-v1";

const D_STATE: &str = "PL2-PQ-XR-PRECONF-STATE";
const D_CONFIG: &str = "PL2-PQ-XR-PRECONF-CONFIG";
const D_COUNTERS: &str = "PL2-PQ-XR-PRECONF-COUNTERS";
const D_SHARDS: &str = "PL2-PQ-XR-PRECONF-SHARDS";
const D_LANES: &str = "PL2-PQ-XR-PRECONF-LANES";
const D_INTENTS: &str = "PL2-PQ-XR-PRECONF-INTENTS";
const D_RECEIPTS: &str = "PL2-PQ-XR-PRECONF-RECEIPTS";
const D_BRIDGES: &str = "PL2-PQ-XR-PRECONF-BRIDGES";
const D_PRECONF: &str = "PL2-PQ-XR-PRECONF-RECEIPTS-FAST";
const D_ATTEST: &str = "PL2-PQ-XR-PRECONF-ATTEST";
const D_HANDOFF: &str = "PL2-PQ-XR-PRECONF-HANDOFF";
const D_WITNESS: &str = "PL2-PQ-XR-PRECONF-WITNESS";
const D_PRIORITY: &str = "PL2-PQ-XR-PRECONF-LOW-FEE";
const D_ROLLBACK: &str = "PL2-PQ-XR-PRECONF-ROLLBACK";
const D_NULLIFIER: &str = "PL2-PQ-XR-PRECONF-NULLIFIER";
const D_SLASHING: &str = "PL2-PQ-XR-PRECONF-SLASHING";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub epoch: u64,
    pub max_shards: u64,
    pub max_intents_per_lane: u64,
    pub preconfirmation_target_ms: u64,
    pub settlement_finality_depth: u64,
    pub low_fee_floor_microunits: u64,
    pub low_fee_discount_bps: u64,
    pub nullifier_window_slots: u64,
    pub rollback_window_slots: u64,
    pub slashing_bond_microunits: u64,
    pub pq_signature_scheme: String,
    pub pq_kem_scheme: String,
    pub transcript_cipher: String,
    pub witness_zones: BTreeSet<String>,
    pub runtimes: BTreeSet<String>,
    pub assets: BTreeSet<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Counters {
    pub ticks: u64,
    pub epochs: u64,
    pub shards: u64,
    pub lanes: u64,
    pub intents: u64,
    pub scheduled: u64,
    pub receipts: u64,
    pub bridge_manifests: u64,
    pub settled_manifests: u64,
    pub preconfirmations: u64,
    pub attestations: u64,
    pub handoffs: u64,
    pub witness_hints: u64,
    pub low_fee_promotions: u64,
    pub rollback_evidence: u64,
    pub nullifier_fences: u64,
    pub slashing_evidence: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Roots {
    pub config_root: String,
    pub counters_root: String,
    pub shard_root: String,
    pub lane_root: String,
    pub intent_root: String,
    pub receipt_index_root: String,
    pub bridge_manifest_root: String,
    pub preconfirmation_root: String,
    pub scheduler_attestation_root: String,
    pub shard_handoff_root: String,
    pub witness_locality_root: String,
    pub low_fee_priority_root: String,
    pub rollback_evidence_root: String,
    pub nullifier_fence_root: String,
    pub slashing_evidence_root: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum ShardStatus {
    Active,
    Draining,
    Halted,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum LaneKind {
    Swap,
    Token,
    Contract,
    Bridge,
    Defi,
    Settlement,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum IntentStatus {
    Pending,
    Scheduled,
    Preconfirmed,
    Settled,
    Cancelled,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum BridgeStatus {
    Open,
    Preconfirmed,
    Settled,
    Disputed,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum EvidenceSeverity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum SlashingOffense {
    DoublePreconfirmation,
    InvalidAttestation,
    WithheldWitness,
    BridgeManifestFraud,
    NullifierFenceViolation,
    ReorgConcealment,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum AdjudicationState {
    Open,
    Accepted,
    Rejected,
    Paid,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ParallelExecutionShard {
    pub shard_id: String,
    pub runtime_id: String,
    pub execution_domain: String,
    pub lane_ids: BTreeSet<String>,
    pub operator_committee: BTreeSet<String>,
    pub slot: u64,
    pub state_commitment: String,
    pub last_preconfirmation_id: Option<String>,
    pub in_flight_intents: BTreeSet<String>,
    pub capacity_weight: u64,
    pub confidentiality_policy: String,
    pub pq_verifier_key_commitment: String,
    pub status: ShardStatus,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct IntentMempoolLane {
    pub lane_id: String,
    pub shard_id: String,
    pub kind: LaneKind,
    pub intent_ids: BTreeSet<String>,
    pub solver_commitments: BTreeSet<String>,
    pub low_fee_enabled: bool,
    pub min_fee_microunits: u64,
    pub max_batch_weight: u64,
    pub scheduled_batch_root: String,
    pub privacy_budget: u64,
    pub sequence: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct EncryptedIntent {
    pub intent_id: String,
    pub lane_id: String,
    pub owner_commitment: String,
    pub payload_commitment: String,
    pub fee_microunits: u64,
    pub gas_limit: u64,
    pub contract_id: Option<String>,
    pub assets: BTreeSet<String>,
    pub nullifiers: BTreeSet<String>,
    pub witness_zone_hint: Option<String>,
    pub sequence: u64,
    pub deadline_slot: u64,
    pub status: IntentStatus,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ContractReceiptIndex {
    pub index_id: String,
    pub contract_id: String,
    pub shard_id: String,
    pub receipt_ids: BTreeSet<String>,
    pub event_topics: BTreeMap<String, BTreeSet<String>>,
    pub state_diff_root: String,
    pub private_log_root: String,
    pub latest_slot: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ContractReceipt {
    pub receipt_id: String,
    pub intent_id: String,
    pub contract_id: String,
    pub shard_id: String,
    pub slot: u64,
    pub gas_used: u64,
    pub status_code: u16,
    pub encrypted_return_commitment: String,
    pub private_events: BTreeSet<String>,
    pub state_diff_commitment: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct BridgeSettlementManifest {
    pub manifest_id: String,
    pub source_runtime: String,
    pub target_runtime: String,
    pub bridge_id: String,
    pub asset_commitments: BTreeMap<String, u64>,
    pub encrypted_recipient_root: String,
    pub exit_batch_root: String,
    pub settlement_slot: u64,
    pub finality_depth: u64,
    pub status: BridgeStatus,
    pub receipt_ids: BTreeSet<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PreconfirmationReceipt {
    pub preconfirmation_id: String,
    pub shard_id: String,
    pub lane_id: String,
    pub slot: u64,
    pub intent_ids: BTreeSet<String>,
    pub receipt_ids: BTreeSet<String>,
    pub bridge_manifest_ids: BTreeSet<String>,
    pub scheduler_attestation_id: String,
    pub prior_state_commitment: String,
    pub post_state_commitment: String,
    pub fee_microunits: u64,
    pub latency_ms: u64,
    pub pq_signature_commitment: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct EncryptedSchedulerAttestation {
    pub attestation_id: String,
    pub scheduler_id: String,
    pub shard_id: String,
    pub lane_id: String,
    pub epoch: u64,
    pub slot: u64,
    pub encrypted_schedule_root: String,
    pub fairness_transcript_commitment: String,
    pub pq_signature_commitment: String,
    pub kem_ciphertext_commitment: String,
    pub admitted: u64,
    pub rejected: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShardHandoff {
    pub handoff_id: String,
    pub from_shard_id: String,
    pub to_shard_id: String,
    pub intent_ids: BTreeSet<String>,
    pub receipt_ids: BTreeSet<String>,
    pub witness_hint_ids: BTreeSet<String>,
    pub prior_owner_commitment: String,
    pub new_owner_commitment: String,
    pub slot: u64,
    pub encrypted_payload_root: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct WitnessLocalityHint {
    pub hint_id: String,
    pub intent_id: String,
    pub shard_id: String,
    pub zone_id: String,
    pub da_region: String,
    pub encrypted_witness_root: String,
    pub recursive_witness_commitment: String,
    pub access_cost_microunits: u64,
    pub expires_slot: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct LowFeePriorityLane {
    pub priority_id: String,
    pub lane_id: String,
    pub sponsor_commitment: String,
    pub fee_floor_microunits: u64,
    pub discount_bps: u64,
    pub eligible_intent_ids: BTreeSet<String>,
    pub cumulative_fee_saved_microunits: u64,
    pub max_latency_ms: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RollbackEvidence {
    pub evidence_id: String,
    pub shard_id: String,
    pub disputed_preconfirmation_id: String,
    pub canonical_state_root: String,
    pub observed_state_root: String,
    pub fork_slot: u64,
    pub witness_commitments: BTreeSet<String>,
    pub reporter_commitment: String,
    pub severity: EvidenceSeverity,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct NullifierFence {
    pub fence_id: String,
    pub shard_id: String,
    pub lane_id: String,
    pub nullifiers: BTreeSet<String>,
    pub start_slot: u64,
    pub end_slot: u64,
    pub reason: String,
    pub privacy_budget: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SlashingEvidence {
    pub slashing_id: String,
    pub operator_commitment: String,
    pub shard_id: String,
    pub offense: SlashingOffense,
    pub linked_evidence_ids: BTreeSet<String>,
    pub bond_at_risk_microunits: u64,
    pub reporter_commitment: String,
    pub adjudication_state: AdjudicationState,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub shards: BTreeMap<String, ParallelExecutionShard>,
    pub lanes: BTreeMap<String, IntentMempoolLane>,
    pub intents: BTreeMap<String, EncryptedIntent>,
    pub receipt_indexes: BTreeMap<String, ContractReceiptIndex>,
    pub receipts: BTreeMap<String, ContractReceipt>,
    pub bridge_manifests: BTreeMap<String, BridgeSettlementManifest>,
    pub preconfirmations: BTreeMap<String, PreconfirmationReceipt>,
    pub scheduler_attestations: BTreeMap<String, EncryptedSchedulerAttestation>,
    pub shard_handoffs: BTreeMap<String, ShardHandoff>,
    pub witness_hints: BTreeMap<String, WitnessLocalityHint>,
    pub low_fee_priority_lanes: BTreeMap<String, LowFeePriorityLane>,
    pub rollback_evidence: BTreeMap<String, RollbackEvidence>,
    pub nullifier_fences: BTreeMap<String, NullifierFence>,
    pub slashing_evidence: BTreeMap<String, SlashingEvidence>,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            epoch: 1,
            max_shards: 8,
            max_intents_per_lane: 256,
            preconfirmation_target_ms: 180,
            settlement_finality_depth: 24,
            low_fee_floor_microunits: 25,
            low_fee_discount_bps: 750,
            nullifier_window_slots: 512,
            rollback_window_slots: 96,
            slashing_bond_microunits: 5_000_000,
            pq_signature_scheme: "ml-dsa-87".to_string(),
            pq_kem_scheme: "ml-kem-1024".to_string(),
            transcript_cipher: "xchacha20poly1305-shake256".to_string(),
            witness_zones: set(["zone-a", "zone-b", "zone-c"]),
            runtimes: set(["nebula-private-l2", "monero-bridge", "evm-confidential"]),
            assets: set(["xmr", "pdin", "usdc.private", "wbtc.private"]),
        }
    }

    pub fn public_record(&self) -> Value {
        to_value(self)
    }

    pub fn root(&self) -> String {
        root_json(D_CONFIG, &self.public_record())
    }
}

impl Counters {
    pub fn new() -> Self {
        Self {
            ticks: 0,
            epochs: 0,
            shards: 0,
            lanes: 0,
            intents: 0,
            scheduled: 0,
            receipts: 0,
            bridge_manifests: 0,
            settled_manifests: 0,
            preconfirmations: 0,
            attestations: 0,
            handoffs: 0,
            witness_hints: 0,
            low_fee_promotions: 0,
            rollback_evidence: 0,
            nullifier_fences: 0,
            slashing_evidence: 0,
        }
    }

    pub fn public_record(&self) -> Value {
        to_value(self)
    }

    pub fn root(&self) -> String {
        root_json(D_COUNTERS, &self.public_record())
    }
}

impl Roots {
    pub fn from_state(s: &State) -> Self {
        Self {
            config_root: s.config.root(),
            counters_root: s.counters.root(),
            shard_root: map_root(D_SHARDS, &s.shards),
            lane_root: map_root(D_LANES, &s.lanes),
            intent_root: map_root(D_INTENTS, &s.intents),
            receipt_index_root: map_root(D_RECEIPTS, &s.receipt_indexes),
            bridge_manifest_root: map_root(D_BRIDGES, &s.bridge_manifests),
            preconfirmation_root: map_root(D_PRECONF, &s.preconfirmations),
            scheduler_attestation_root: map_root(D_ATTEST, &s.scheduler_attestations),
            shard_handoff_root: map_root(D_HANDOFF, &s.shard_handoffs),
            witness_locality_root: map_root(D_WITNESS, &s.witness_hints),
            low_fee_priority_root: map_root(D_PRIORITY, &s.low_fee_priority_lanes),
            rollback_evidence_root: map_root(D_ROLLBACK, &s.rollback_evidence),
            nullifier_fence_root: map_root(D_NULLIFIER, &s.nullifier_fences),
            slashing_evidence_root: map_root(D_SLASHING, &s.slashing_evidence),
        }
    }

    pub fn public_record(&self) -> Value {
        to_value(self)
    }

    pub fn root(&self) -> String {
        root_json(D_STATE, &self.public_record())
    }
}

impl State {
    pub fn devnet() -> Self {
        let mut s = Self {
            config: Config::devnet(),
            counters: Counters::new(),
            shards: BTreeMap::new(),
            lanes: BTreeMap::new(),
            intents: BTreeMap::new(),
            receipt_indexes: BTreeMap::new(),
            receipts: BTreeMap::new(),
            bridge_manifests: BTreeMap::new(),
            preconfirmations: BTreeMap::new(),
            scheduler_attestations: BTreeMap::new(),
            shard_handoffs: BTreeMap::new(),
            witness_hints: BTreeMap::new(),
            low_fee_priority_lanes: BTreeMap::new(),
            rollback_evidence: BTreeMap::new(),
            nullifier_fences: BTreeMap::new(),
            slashing_evidence: BTreeMap::new(),
        };
        s.seed_devnet();
        s
    }

    pub fn roots(&self) -> Roots {
        Roots::from_state(self)
    }

    pub fn state_root(&self) -> String {
        self.roots().root()
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "state_root": self.state_root(),
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": self.roots().public_record(),
            "shards": self.shards,
            "lanes": self.lanes,
            "intents": self.intents,
            "receipt_indexes": self.receipt_indexes,
            "receipts": self.receipts,
            "bridge_manifests": self.bridge_manifests,
            "preconfirmations": self.preconfirmations,
            "scheduler_attestations": self.scheduler_attestations,
            "shard_handoffs": self.shard_handoffs,
            "witness_hints": self.witness_hints,
            "low_fee_priority_lanes": self.low_fee_priority_lanes,
            "rollback_evidence": self.rollback_evidence,
            "nullifier_fences": self.nullifier_fences,
            "slashing_evidence": self.slashing_evidence
        })
    }

    pub fn register_shard(
        &mut self,
        runtime_id: &str,
        execution_domain: &str,
        operator_committee: BTreeSet<String>,
        capacity_weight: u64,
        pq_verifier_key_commitment: &str,
    ) -> Result<String> {
        self.ensure_runtime(runtime_id)?;
        non_empty("execution_domain", execution_domain)?;
        non_empty("pq_verifier_key_commitment", pq_verifier_key_commitment)?;
        if operator_committee.is_empty() {
            return Err("operator committee is empty".to_string());
        }
        if self.shards.len() as u64 >= self.config.max_shards {
            return Err("parallel shard limit reached".to_string());
        }
        let shard_id = shard_id(runtime_id, execution_domain, self.counters.shards + 1);
        self.shards.insert(
            shard_id.clone(),
            ParallelExecutionShard {
                shard_id: shard_id.clone(),
                runtime_id: runtime_id.to_string(),
                execution_domain: execution_domain.to_string(),
                lane_ids: BTreeSet::new(),
                operator_committee,
                slot: 0,
                state_commitment: commitment_id("initial-state", &shard_id, 0),
                last_preconfirmation_id: None,
                in_flight_intents: BTreeSet::new(),
                capacity_weight,
                confidentiality_policy: "pq-confidential-nullifier-fenced".to_string(),
                pq_verifier_key_commitment: pq_verifier_key_commitment.to_string(),
                status: ShardStatus::Active,
            },
        );
        self.counters.shards += 1;
        self.tick();
        Ok(shard_id)
    }

    pub fn register_lane(
        &mut self,
        shard_id: &str,
        kind: LaneKind,
        low_fee_enabled: bool,
        min_fee_microunits: u64,
        max_batch_weight: u64,
        privacy_budget: u64,
    ) -> Result<String> {
        let shard = self
            .shards
            .get_mut(shard_id)
            .ok_or_else(|| unknown("shard", shard_id))?;
        if shard.status != ShardStatus::Active {
            return Err("shard is not active".to_string());
        }
        let lane_id = lane_id(shard_id, &kind, self.counters.lanes + 1);
        shard.lane_ids.insert(lane_id.clone());
        self.lanes.insert(
            lane_id.clone(),
            IntentMempoolLane {
                lane_id: lane_id.clone(),
                shard_id: shard_id.to_string(),
                kind,
                intent_ids: BTreeSet::new(),
                solver_commitments: BTreeSet::new(),
                low_fee_enabled,
                min_fee_microunits,
                max_batch_weight,
                scheduled_batch_root: empty_root(D_LANES),
                privacy_budget,
                sequence: 0,
            },
        );
        self.counters.lanes += 1;
        self.tick();
        Ok(lane_id)
    }

    pub fn accept_intent(
        &mut self,
        lane_id: &str,
        owner_commitment: &str,
        payload_commitment: &str,
        fee_microunits: u64,
        gas_limit: u64,
        contract_id: Option<String>,
        assets: BTreeSet<String>,
        nullifiers: BTreeSet<String>,
        witness_zone_hint: Option<String>,
        deadline_slot: u64,
    ) -> Result<String> {
        non_empty("owner_commitment", owner_commitment)?;
        non_empty("payload_commitment", payload_commitment)?;
        self.ensure_nullifiers_free(&nullifiers)?;
        if let Some(zone) = witness_zone_hint.as_deref() {
            self.ensure_witness_zone(zone)?;
        }
        let lane = self
            .lanes
            .get_mut(lane_id)
            .ok_or_else(|| unknown("lane", lane_id))?;
        if lane.intent_ids.len() as u64 >= self.config.max_intents_per_lane {
            return Err("lane intent limit reached".to_string());
        }
        if fee_microunits < lane.min_fee_microunits {
            return Err("fee below lane minimum".to_string());
        }
        lane.sequence += 1;
        let intent_id = intent_id(lane_id, owner_commitment, lane.sequence);
        lane.intent_ids.insert(intent_id.clone());
        self.intents.insert(
            intent_id.clone(),
            EncryptedIntent {
                intent_id: intent_id.clone(),
                lane_id: lane_id.to_string(),
                owner_commitment: owner_commitment.to_string(),
                payload_commitment: payload_commitment.to_string(),
                fee_microunits,
                gas_limit,
                contract_id,
                assets,
                nullifiers,
                witness_zone_hint,
                sequence: lane.sequence,
                deadline_slot,
                status: IntentStatus::Pending,
            },
        );
        self.counters.intents += 1;
        self.tick();
        Ok(intent_id)
    }

    pub fn schedule_intents(
        &mut self,
        lane_id: &str,
        intent_ids: BTreeSet<String>,
        solver_commitment: &str,
    ) -> Result<String> {
        non_empty("solver_commitment", solver_commitment)?;
        if intent_ids.is_empty() {
            return Err("no intents supplied".to_string());
        }
        let shard_id = self
            .lanes
            .get(lane_id)
            .ok_or_else(|| unknown("lane", lane_id))?
            .shard_id
            .clone();
        for id in &intent_ids {
            let intent = self
                .intents
                .get_mut(id)
                .ok_or_else(|| unknown("intent", id))?;
            if intent.lane_id != lane_id || intent.status != IntentStatus::Pending {
                return Err(format!("intent {id} is not pending in lane {lane_id}"));
            }
            intent.status = IntentStatus::Scheduled;
        }
        let root = collection_root(
            D_INTENTS,
            intent_ids
                .iter()
                .filter_map(|id| self.intents.get(id))
                .map(to_value),
        );
        let lane = self
            .lanes
            .get_mut(lane_id)
            .ok_or_else(|| unknown("lane", lane_id))?;
        lane.solver_commitments
            .insert(solver_commitment.to_string());
        lane.scheduled_batch_root = root.clone();
        let shard = self
            .shards
            .get_mut(&shard_id)
            .ok_or_else(|| unknown("shard", &shard_id))?;
        shard.in_flight_intents.extend(intent_ids.iter().cloned());
        self.counters.scheduled += intent_ids.len() as u64;
        self.tick();
        Ok(root)
    }

    pub fn record_scheduler_attestation(
        &mut self,
        scheduler_id: &str,
        shard_id: &str,
        lane_id: &str,
        slot: u64,
        encrypted_schedule_root: &str,
        fairness_transcript_commitment: &str,
        pq_signature_commitment: &str,
        kem_ciphertext_commitment: &str,
        admitted: u64,
        rejected: u64,
    ) -> Result<String> {
        self.ensure_lane_on_shard(shard_id, lane_id)?;
        non_empty("scheduler_id", scheduler_id)?;
        non_empty("encrypted_schedule_root", encrypted_schedule_root)?;
        non_empty("pq_signature_commitment", pq_signature_commitment)?;
        let attestation_id = attestation_id(scheduler_id, shard_id, lane_id, slot);
        self.scheduler_attestations.insert(
            attestation_id.clone(),
            EncryptedSchedulerAttestation {
                attestation_id: attestation_id.clone(),
                scheduler_id: scheduler_id.to_string(),
                shard_id: shard_id.to_string(),
                lane_id: lane_id.to_string(),
                epoch: self.config.epoch,
                slot,
                encrypted_schedule_root: encrypted_schedule_root.to_string(),
                fairness_transcript_commitment: fairness_transcript_commitment.to_string(),
                pq_signature_commitment: pq_signature_commitment.to_string(),
                kem_ciphertext_commitment: kem_ciphertext_commitment.to_string(),
                admitted,
                rejected,
            },
        );
        self.counters.attestations += 1;
        self.tick();
        Ok(attestation_id)
    }

    pub fn index_contract_receipt(
        &mut self,
        intent_id: &str,
        contract_id: &str,
        shard_id: &str,
        slot: u64,
        gas_used: u64,
        status_code: u16,
        encrypted_return_commitment: &str,
        private_events: BTreeSet<String>,
        state_diff_commitment: &str,
    ) -> Result<String> {
        self.ensure_shard(shard_id)?;
        self.ensure_intent(intent_id)?;
        non_empty("contract_id", contract_id)?;
        non_empty("encrypted_return_commitment", encrypted_return_commitment)?;
        non_empty("state_diff_commitment", state_diff_commitment)?;
        let receipt_id = receipt_id(intent_id, contract_id, shard_id, slot);
        self.receipts.insert(
            receipt_id.clone(),
            ContractReceipt {
                receipt_id: receipt_id.clone(),
                intent_id: intent_id.to_string(),
                contract_id: contract_id.to_string(),
                shard_id: shard_id.to_string(),
                slot,
                gas_used,
                status_code,
                encrypted_return_commitment: encrypted_return_commitment.to_string(),
                private_events: private_events.clone(),
                state_diff_commitment: state_diff_commitment.to_string(),
            },
        );
        let index_id = receipt_index_id(contract_id, shard_id);
        let index = self
            .receipt_indexes
            .entry(index_id.clone())
            .or_insert_with(|| ContractReceiptIndex {
                index_id,
                contract_id: contract_id.to_string(),
                shard_id: shard_id.to_string(),
                receipt_ids: BTreeSet::new(),
                event_topics: BTreeMap::new(),
                state_diff_root: empty_root(D_RECEIPTS),
                private_log_root: empty_root(D_RECEIPTS),
                latest_slot: 0,
            });
        index.receipt_ids.insert(receipt_id.clone());
        index.latest_slot = index.latest_slot.max(slot);
        index
            .event_topics
            .entry("private-events".to_string())
            .or_insert_with(BTreeSet::new)
            .extend(private_events);
        let receipts = index
            .receipt_ids
            .iter()
            .filter_map(|id| self.receipts.get(id))
            .cloned()
            .collect::<Vec<_>>();
        index.state_diff_root = collection_root(
            D_RECEIPTS,
            receipts.iter().map(
                |r| json!({"receipt_id": r.receipt_id, "state_diff": r.state_diff_commitment}),
            ),
        );
        index.private_log_root = collection_root(
            D_RECEIPTS,
            receipts
                .iter()
                .map(|r| json!({"receipt_id": r.receipt_id, "events": r.private_events})),
        );
        self.counters.receipts += 1;
        self.tick();
        Ok(receipt_id)
    }

    pub fn open_bridge_manifest(
        &mut self,
        source_runtime: &str,
        target_runtime: &str,
        bridge_id: &str,
        asset_commitments: BTreeMap<String, u64>,
        encrypted_recipient_root: &str,
        exit_batch_root: &str,
        settlement_slot: u64,
    ) -> Result<String> {
        self.ensure_runtime(source_runtime)?;
        self.ensure_runtime(target_runtime)?;
        non_empty("bridge_id", bridge_id)?;
        if asset_commitments.is_empty() {
            return Err("bridge manifest has no assets".to_string());
        }
        let manifest_id =
            bridge_manifest_id(source_runtime, target_runtime, bridge_id, settlement_slot);
        self.bridge_manifests.insert(
            manifest_id.clone(),
            BridgeSettlementManifest {
                manifest_id: manifest_id.clone(),
                source_runtime: source_runtime.to_string(),
                target_runtime: target_runtime.to_string(),
                bridge_id: bridge_id.to_string(),
                asset_commitments,
                encrypted_recipient_root: encrypted_recipient_root.to_string(),
                exit_batch_root: exit_batch_root.to_string(),
                settlement_slot,
                finality_depth: self.config.settlement_finality_depth,
                status: BridgeStatus::Open,
                receipt_ids: BTreeSet::new(),
            },
        );
        self.counters.bridge_manifests += 1;
        self.tick();
        Ok(manifest_id)
    }

    pub fn issue_preconfirmation(
        &mut self,
        shard_id: &str,
        lane_id: &str,
        slot: u64,
        intent_ids: BTreeSet<String>,
        receipt_ids: BTreeSet<String>,
        bridge_manifest_ids: BTreeSet<String>,
        scheduler_attestation_id: &str,
        post_state_commitment: &str,
        fee_microunits: u64,
        latency_ms: u64,
        pq_signature_commitment: &str,
    ) -> Result<String> {
        self.ensure_lane_on_shard(shard_id, lane_id)?;
        if !self
            .scheduler_attestations
            .contains_key(scheduler_attestation_id)
        {
            return Err(unknown("scheduler attestation", scheduler_attestation_id));
        }
        non_empty("post_state_commitment", post_state_commitment)?;
        non_empty("pq_signature_commitment", pq_signature_commitment)?;
        for id in &intent_ids {
            let intent = self
                .intents
                .get_mut(id)
                .ok_or_else(|| unknown("intent", id))?;
            if intent.lane_id != lane_id || intent.status != IntentStatus::Scheduled {
                return Err(format!("intent {id} is not scheduled in lane {lane_id}"));
            }
            intent.status = IntentStatus::Preconfirmed;
        }
        for id in &receipt_ids {
            if !self.receipts.contains_key(id) {
                return Err(unknown("receipt", id));
            }
        }
        for id in &bridge_manifest_ids {
            let manifest = self
                .bridge_manifests
                .get_mut(id)
                .ok_or_else(|| unknown("bridge manifest", id))?;
            manifest.status = BridgeStatus::Preconfirmed;
            manifest.receipt_ids.extend(receipt_ids.iter().cloned());
        }
        let prior = self
            .shards
            .get(shard_id)
            .ok_or_else(|| unknown("shard", shard_id))?
            .state_commitment
            .clone();
        let preconfirmation_id = preconfirmation_id(shard_id, lane_id, slot, &intent_ids);
        self.preconfirmations.insert(
            preconfirmation_id.clone(),
            PreconfirmationReceipt {
                preconfirmation_id: preconfirmation_id.clone(),
                shard_id: shard_id.to_string(),
                lane_id: lane_id.to_string(),
                slot,
                intent_ids: intent_ids.clone(),
                receipt_ids,
                bridge_manifest_ids,
                scheduler_attestation_id: scheduler_attestation_id.to_string(),
                prior_state_commitment: prior,
                post_state_commitment: post_state_commitment.to_string(),
                fee_microunits,
                latency_ms,
                pq_signature_commitment: pq_signature_commitment.to_string(),
            },
        );
        let shard = self
            .shards
            .get_mut(shard_id)
            .ok_or_else(|| unknown("shard", shard_id))?;
        shard.slot = shard.slot.max(slot);
        shard.state_commitment = post_state_commitment.to_string();
        shard.last_preconfirmation_id = Some(preconfirmation_id.clone());
        for id in &intent_ids {
            shard.in_flight_intents.remove(id);
        }
        self.counters.preconfirmations += 1;
        self.tick();
        Ok(preconfirmation_id)
    }

    pub fn settle_bridge_manifest(&mut self, manifest_id: &str) -> Result<String> {
        let manifest = self
            .bridge_manifests
            .get_mut(manifest_id)
            .ok_or_else(|| unknown("bridge manifest", manifest_id))?;
        if manifest.status != BridgeStatus::Preconfirmed {
            return Err("bridge manifest is not preconfirmed".to_string());
        }
        manifest.status = BridgeStatus::Settled;
        self.counters.settled_manifests += 1;
        self.tick();
        Ok(root_json(D_BRIDGES, &to_value(manifest)))
    }

    pub fn record_shard_handoff(
        &mut self,
        from_shard_id: &str,
        to_shard_id: &str,
        intent_ids: BTreeSet<String>,
        receipt_ids: BTreeSet<String>,
        witness_hint_ids: BTreeSet<String>,
        prior_owner_commitment: &str,
        new_owner_commitment: &str,
        slot: u64,
        encrypted_payload_root: &str,
    ) -> Result<String> {
        self.ensure_shard(from_shard_id)?;
        self.ensure_shard(to_shard_id)?;
        for id in &intent_ids {
            self.ensure_intent(id)?;
        }
        let handoff_id = handoff_id(from_shard_id, to_shard_id, slot, &intent_ids);
        self.shard_handoffs.insert(
            handoff_id.clone(),
            ShardHandoff {
                handoff_id: handoff_id.clone(),
                from_shard_id: from_shard_id.to_string(),
                to_shard_id: to_shard_id.to_string(),
                intent_ids,
                receipt_ids,
                witness_hint_ids,
                prior_owner_commitment: prior_owner_commitment.to_string(),
                new_owner_commitment: new_owner_commitment.to_string(),
                slot,
                encrypted_payload_root: encrypted_payload_root.to_string(),
            },
        );
        self.counters.handoffs += 1;
        self.tick();
        Ok(handoff_id)
    }

    pub fn record_witness_locality_hint(
        &mut self,
        intent_id: &str,
        shard_id: &str,
        zone_id: &str,
        da_region: &str,
        encrypted_witness_root: &str,
        recursive_witness_commitment: &str,
        access_cost_microunits: u64,
        expires_slot: u64,
    ) -> Result<String> {
        self.ensure_intent(intent_id)?;
        self.ensure_shard(shard_id)?;
        self.ensure_witness_zone(zone_id)?;
        let hint_id = witness_hint_id(intent_id, shard_id, zone_id);
        self.witness_hints.insert(
            hint_id.clone(),
            WitnessLocalityHint {
                hint_id: hint_id.clone(),
                intent_id: intent_id.to_string(),
                shard_id: shard_id.to_string(),
                zone_id: zone_id.to_string(),
                da_region: da_region.to_string(),
                encrypted_witness_root: encrypted_witness_root.to_string(),
                recursive_witness_commitment: recursive_witness_commitment.to_string(),
                access_cost_microunits,
                expires_slot,
            },
        );
        self.counters.witness_hints += 1;
        self.tick();
        Ok(hint_id)
    }

    pub fn open_low_fee_priority_lane(
        &mut self,
        lane_id: &str,
        sponsor_commitment: &str,
        fee_floor_microunits: u64,
        discount_bps: u64,
        max_latency_ms: u64,
    ) -> Result<String> {
        let lane = self
            .lanes
            .get(lane_id)
            .ok_or_else(|| unknown("lane", lane_id))?;
        if !lane.low_fee_enabled {
            return Err("lane does not allow low-fee priority".to_string());
        }
        if discount_bps > 10_000 {
            return Err("discount exceeds 10000 bps".to_string());
        }
        let priority_id = priority_id(lane_id, sponsor_commitment);
        self.low_fee_priority_lanes.insert(
            priority_id.clone(),
            LowFeePriorityLane {
                priority_id: priority_id.clone(),
                lane_id: lane_id.to_string(),
                sponsor_commitment: sponsor_commitment.to_string(),
                fee_floor_microunits,
                discount_bps,
                eligible_intent_ids: BTreeSet::new(),
                cumulative_fee_saved_microunits: 0,
                max_latency_ms,
            },
        );
        self.counters.low_fee_promotions += 1;
        self.tick();
        Ok(priority_id)
    }

    pub fn promote_intent_low_fee(&mut self, priority_id: &str, intent_id: &str) -> Result<u64> {
        let intent = self
            .intents
            .get(intent_id)
            .ok_or_else(|| unknown("intent", intent_id))?;
        let lane = self
            .low_fee_priority_lanes
            .get_mut(priority_id)
            .ok_or_else(|| unknown("priority lane", priority_id))?;
        if intent.lane_id != lane.lane_id || intent.fee_microunits < lane.fee_floor_microunits {
            return Err("intent is not eligible for low-fee priority".to_string());
        }
        let saved = intent.fee_microunits.saturating_mul(lane.discount_bps) / 10_000;
        lane.eligible_intent_ids.insert(intent_id.to_string());
        lane.cumulative_fee_saved_microunits += saved;
        self.counters.low_fee_promotions += 1;
        self.tick();
        Ok(saved)
    }

    pub fn record_rollback_evidence(
        &mut self,
        shard_id: &str,
        disputed_preconfirmation_id: &str,
        canonical_state_root: &str,
        observed_state_root: &str,
        fork_slot: u64,
        witness_commitments: BTreeSet<String>,
        reporter_commitment: &str,
        severity: EvidenceSeverity,
    ) -> Result<String> {
        self.ensure_shard(shard_id)?;
        if !self
            .preconfirmations
            .contains_key(disputed_preconfirmation_id)
        {
            return Err(unknown("preconfirmation", disputed_preconfirmation_id));
        }
        if canonical_state_root == observed_state_root {
            return Err("rollback evidence roots are equal".to_string());
        }
        let evidence_id = rollback_evidence_id(shard_id, disputed_preconfirmation_id, fork_slot);
        self.rollback_evidence.insert(
            evidence_id.clone(),
            RollbackEvidence {
                evidence_id: evidence_id.clone(),
                shard_id: shard_id.to_string(),
                disputed_preconfirmation_id: disputed_preconfirmation_id.to_string(),
                canonical_state_root: canonical_state_root.to_string(),
                observed_state_root: observed_state_root.to_string(),
                fork_slot,
                witness_commitments,
                reporter_commitment: reporter_commitment.to_string(),
                severity,
            },
        );
        self.counters.rollback_evidence += 1;
        self.tick();
        Ok(evidence_id)
    }

    pub fn record_nullifier_fence(
        &mut self,
        shard_id: &str,
        lane_id: &str,
        nullifiers: BTreeSet<String>,
        start_slot: u64,
        end_slot: u64,
        reason: &str,
        privacy_budget: u64,
    ) -> Result<String> {
        self.ensure_lane_on_shard(shard_id, lane_id)?;
        if nullifiers.is_empty() || start_slot >= end_slot {
            return Err("invalid nullifier fence".to_string());
        }
        self.ensure_nullifiers_free(&nullifiers)?;
        let fence_id = nullifier_fence_id(shard_id, lane_id, start_slot, end_slot, &nullifiers);
        self.nullifier_fences.insert(
            fence_id.clone(),
            NullifierFence {
                fence_id: fence_id.clone(),
                shard_id: shard_id.to_string(),
                lane_id: lane_id.to_string(),
                nullifiers,
                start_slot,
                end_slot,
                reason: reason.to_string(),
                privacy_budget,
            },
        );
        self.counters.nullifier_fences += 1;
        self.tick();
        Ok(fence_id)
    }

    pub fn record_slashing_evidence(
        &mut self,
        operator_commitment: &str,
        shard_id: &str,
        offense: SlashingOffense,
        linked_evidence_ids: BTreeSet<String>,
        reporter_commitment: &str,
    ) -> Result<String> {
        self.ensure_shard(shard_id)?;
        if linked_evidence_ids.is_empty() {
            return Err("slashing evidence has no linked evidence".to_string());
        }
        let slashing_id = slashing_id(
            operator_commitment,
            shard_id,
            &offense,
            &linked_evidence_ids,
        );
        self.slashing_evidence.insert(
            slashing_id.clone(),
            SlashingEvidence {
                slashing_id: slashing_id.clone(),
                operator_commitment: operator_commitment.to_string(),
                shard_id: shard_id.to_string(),
                offense,
                linked_evidence_ids,
                bond_at_risk_microunits: self.config.slashing_bond_microunits,
                reporter_commitment: reporter_commitment.to_string(),
                adjudication_state: AdjudicationState::Open,
            },
        );
        self.counters.slashing_evidence += 1;
        self.tick();
        Ok(slashing_id)
    }

    pub fn advance_epoch(&mut self) -> Result<u64> {
        self.config.epoch += 1;
        self.counters.epochs += 1;
        self.tick();
        Ok(self.config.epoch)
    }

    fn seed_devnet(&mut self) {
        let shard_a = ParallelExecutionShard {
            shard_id: "shard-a".to_string(),
            runtime_id: "nebula-private-l2".to_string(),
            execution_domain: "contracts".to_string(),
            lane_ids: set(["lane-contract-fast"]),
            operator_committee: set(["operator-a", "operator-b", "operator-c"]),
            slot: 0,
            state_commitment: commitment_id("devnet-state", "shard-a", 0),
            last_preconfirmation_id: None,
            in_flight_intents: BTreeSet::new(),
            capacity_weight: 100,
            confidentiality_policy: "pq-confidential-nullifier-fenced".to_string(),
            pq_verifier_key_commitment: commitment_id("devnet-pq-vk", "shard-a", 0),
            status: ShardStatus::Active,
        };
        let shard_b = ParallelExecutionShard {
            shard_id: "shard-b".to_string(),
            runtime_id: "monero-bridge".to_string(),
            execution_domain: "bridge".to_string(),
            lane_ids: set(["lane-bridge-low-fee"]),
            operator_committee: set(["operator-a", "operator-b", "operator-c"]),
            slot: 0,
            state_commitment: commitment_id("devnet-state", "shard-b", 0),
            last_preconfirmation_id: None,
            in_flight_intents: BTreeSet::new(),
            capacity_weight: 100,
            confidentiality_policy: "pq-confidential-bridge".to_string(),
            pq_verifier_key_commitment: commitment_id("devnet-pq-vk", "shard-b", 0),
            status: ShardStatus::Active,
        };
        self.shards.insert(shard_a.shard_id.clone(), shard_a);
        self.shards.insert(shard_b.shard_id.clone(), shard_b);
        self.lanes.insert(
            "lane-contract-fast".to_string(),
            self.seed_lane("lane-contract-fast", "shard-a", LaneKind::Contract),
        );
        self.lanes.insert(
            "lane-bridge-low-fee".to_string(),
            self.seed_lane("lane-bridge-low-fee", "shard-b", LaneKind::Bridge),
        );
        self.counters.shards = 2;
        self.counters.lanes = 2;
    }

    fn seed_lane(&self, lane_id: &str, shard_id: &str, kind: LaneKind) -> IntentMempoolLane {
        IntentMempoolLane {
            lane_id: lane_id.to_string(),
            shard_id: shard_id.to_string(),
            kind,
            intent_ids: BTreeSet::new(),
            solver_commitments: BTreeSet::new(),
            low_fee_enabled: true,
            min_fee_microunits: self.config.low_fee_floor_microunits,
            max_batch_weight: 1_000_000,
            scheduled_batch_root: empty_root(D_LANES),
            privacy_budget: 10_000,
            sequence: 0,
        }
    }

    fn ensure_runtime(&self, runtime_id: &str) -> Result<()> {
        if self.config.runtimes.contains(runtime_id) {
            Ok(())
        } else {
            Err(format!("unsupported runtime {runtime_id}"))
        }
    }

    fn ensure_shard(&self, shard_id: &str) -> Result<()> {
        if self.shards.contains_key(shard_id) {
            Ok(())
        } else {
            Err(unknown("shard", shard_id))
        }
    }

    fn ensure_intent(&self, intent_id: &str) -> Result<()> {
        if self.intents.contains_key(intent_id) {
            Ok(())
        } else {
            Err(unknown("intent", intent_id))
        }
    }

    fn ensure_lane_on_shard(&self, shard_id: &str, lane_id: &str) -> Result<()> {
        let lane = self
            .lanes
            .get(lane_id)
            .ok_or_else(|| unknown("lane", lane_id))?;
        if lane.shard_id == shard_id {
            Ok(())
        } else {
            Err(format!("lane {lane_id} is not on shard {shard_id}"))
        }
    }

    fn ensure_witness_zone(&self, zone_id: &str) -> Result<()> {
        if self.config.witness_zones.contains(zone_id) {
            Ok(())
        } else {
            Err(format!("unsupported witness zone {zone_id}"))
        }
    }

    fn ensure_nullifiers_free(&self, nullifiers: &BTreeSet<String>) -> Result<()> {
        for fence in self.nullifier_fences.values() {
            for nullifier in nullifiers {
                if fence.nullifiers.contains(nullifier) {
                    return Err(format!("nullifier commitment {nullifier} is fenced"));
                }
            }
        }
        Ok(())
    }

    fn tick(&mut self) {
        self.counters.ticks += 1;
    }
}

pub fn root_json(domain: &str, value: &Value) -> String {
    domain_hash(
        domain,
        &[HashPart::Str(CHAIN_ID), HashPart::Json(value)],
        32,
    )
}

pub fn collection_root<I>(domain: &str, values: I) -> String
where
    I: IntoIterator<Item = Value>,
{
    merkle_root(domain, &values.into_iter().collect::<Vec<_>>())
}

pub fn shard_root(shards: &BTreeMap<String, ParallelExecutionShard>) -> String {
    map_root(D_SHARDS, shards)
}

pub fn intent_lane_root(lanes: &BTreeMap<String, IntentMempoolLane>) -> String {
    map_root(D_LANES, lanes)
}

pub fn preconfirmation_root(preconfirmations: &BTreeMap<String, PreconfirmationReceipt>) -> String {
    map_root(D_PRECONF, preconfirmations)
}

pub fn deterministic_id(domain: &str, parts: &[HashPart<'_>]) -> String {
    let mut encoded = Vec::with_capacity(parts.len() + 1);
    encoded.push(HashPart::Str(CHAIN_ID));
    for part in parts {
        encoded.push(copy_hash_part(part));
    }
    domain_hash(domain, &encoded, 20)
}

pub fn commitment_id(domain: &str, label: &str, sequence: u64) -> String {
    deterministic_id(domain, &[HashPart::Str(label), HashPart::U64(sequence)])
}

pub fn shard_id(runtime_id: &str, execution_domain: &str, sequence: u64) -> String {
    prefixed(
        "shard",
        D_SHARDS,
        &[
            HashPart::Str(runtime_id),
            HashPart::Str(execution_domain),
            HashPart::U64(sequence),
        ],
    )
}

pub fn lane_id(shard_id: &str, kind: &LaneKind, sequence: u64) -> String {
    prefixed(
        "lane",
        D_LANES,
        &[
            HashPart::Str(shard_id),
            HashPart::Str(lane_label(kind)),
            HashPart::U64(sequence),
        ],
    )
}

pub fn intent_id(lane_id: &str, owner_commitment: &str, sequence: u64) -> String {
    prefixed(
        "intent",
        D_INTENTS,
        &[
            HashPart::Str(lane_id),
            HashPart::Str(owner_commitment),
            HashPart::U64(sequence),
        ],
    )
}

pub fn receipt_id(intent_id: &str, contract_id: &str, shard_id: &str, slot: u64) -> String {
    prefixed(
        "receipt",
        D_RECEIPTS,
        &[
            HashPart::Str(intent_id),
            HashPart::Str(contract_id),
            HashPart::Str(shard_id),
            HashPart::U64(slot),
        ],
    )
}

pub fn receipt_index_id(contract_id: &str, shard_id: &str) -> String {
    prefixed(
        "receipt-index",
        D_RECEIPTS,
        &[HashPart::Str(contract_id), HashPart::Str(shard_id)],
    )
}

pub fn bridge_manifest_id(source: &str, target: &str, bridge_id: &str, slot: u64) -> String {
    prefixed(
        "bridge",
        D_BRIDGES,
        &[
            HashPart::Str(source),
            HashPart::Str(target),
            HashPart::Str(bridge_id),
            HashPart::U64(slot),
        ],
    )
}

pub fn attestation_id(scheduler_id: &str, shard_id: &str, lane_id: &str, slot: u64) -> String {
    prefixed(
        "attestation",
        D_ATTEST,
        &[
            HashPart::Str(scheduler_id),
            HashPart::Str(shard_id),
            HashPart::Str(lane_id),
            HashPart::U64(slot),
        ],
    )
}

pub fn preconfirmation_id(
    shard_id: &str,
    lane_id: &str,
    slot: u64,
    intents: &BTreeSet<String>,
) -> String {
    let root = string_set_root(D_PRECONF, intents);
    prefixed(
        "preconf",
        D_PRECONF,
        &[
            HashPart::Str(shard_id),
            HashPart::Str(lane_id),
            HashPart::U64(slot),
            HashPart::Str(&root),
        ],
    )
}

pub fn handoff_id(from: &str, to: &str, slot: u64, intents: &BTreeSet<String>) -> String {
    let root = string_set_root(D_HANDOFF, intents);
    prefixed(
        "handoff",
        D_HANDOFF,
        &[
            HashPart::Str(from),
            HashPart::Str(to),
            HashPart::U64(slot),
            HashPart::Str(&root),
        ],
    )
}

pub fn witness_hint_id(intent_id: &str, shard_id: &str, zone_id: &str) -> String {
    prefixed(
        "witness",
        D_WITNESS,
        &[
            HashPart::Str(intent_id),
            HashPart::Str(shard_id),
            HashPart::Str(zone_id),
        ],
    )
}

pub fn priority_id(lane_id: &str, sponsor: &str) -> String {
    prefixed(
        "priority",
        D_PRIORITY,
        &[HashPart::Str(lane_id), HashPart::Str(sponsor)],
    )
}

pub fn rollback_evidence_id(shard_id: &str, preconfirmation_id: &str, fork_slot: u64) -> String {
    prefixed(
        "rollback",
        D_ROLLBACK,
        &[
            HashPart::Str(shard_id),
            HashPart::Str(preconfirmation_id),
            HashPart::U64(fork_slot),
        ],
    )
}

pub fn nullifier_fence_id(
    shard_id: &str,
    lane_id: &str,
    start_slot: u64,
    end_slot: u64,
    nullifiers: &BTreeSet<String>,
) -> String {
    let root = string_set_root(D_NULLIFIER, nullifiers);
    prefixed(
        "nullifier-fence",
        D_NULLIFIER,
        &[
            HashPart::Str(shard_id),
            HashPart::Str(lane_id),
            HashPart::U64(start_slot),
            HashPart::U64(end_slot),
            HashPart::Str(&root),
        ],
    )
}

pub fn slashing_id(
    operator: &str,
    shard_id: &str,
    offense: &SlashingOffense,
    evidence: &BTreeSet<String>,
) -> String {
    let root = string_set_root(D_SLASHING, evidence);
    prefixed(
        "slash",
        D_SLASHING,
        &[
            HashPart::Str(operator),
            HashPart::Str(shard_id),
            HashPart::Str(offense_label(offense)),
            HashPart::Str(&root),
        ],
    )
}

fn map_root<T: Serialize>(domain: &str, values: &BTreeMap<String, T>) -> String {
    collection_root(domain, values.values().map(to_value))
}

fn empty_root(domain: &str) -> String {
    collection_root(domain, std::iter::empty::<Value>())
}

fn string_set_root(domain: &str, values: &BTreeSet<String>) -> String {
    collection_root(domain, values.iter().map(|v| json!(v)))
}

fn prefixed(prefix: &str, domain: &str, parts: &[HashPart<'_>]) -> String {
    format!("{prefix}-{}", deterministic_id(domain, parts))
}

fn copy_hash_part<'a>(part: &HashPart<'a>) -> HashPart<'a> {
    match part {
        HashPart::Bytes(v) => HashPart::Bytes(v),
        HashPart::Str(v) => HashPart::Str(v),
        HashPart::U64(v) => HashPart::U64(*v),
        HashPart::Int(v) => HashPart::Int(*v),
        HashPart::Json(v) => HashPart::Json(v),
    }
}

fn to_value<T: Serialize>(value: T) -> Value {
    match serde_json::to_value(value) {
        Ok(value) => value,
        Err(error) => json!({"serialization_error": error.to_string()}),
    }
}

fn set<const N: usize>(values: [&str; N]) -> BTreeSet<String> {
    values.into_iter().map(str::to_string).collect()
}

fn non_empty(name: &str, value: &str) -> Result<()> {
    if value.is_empty() {
        Err(format!("{name} is empty"))
    } else {
        Ok(())
    }
}

fn unknown(kind: &str, id: &str) -> String {
    format!("unknown {kind} {id}")
}

fn lane_label(kind: &LaneKind) -> &'static str {
    match kind {
        LaneKind::Swap => "swap",
        LaneKind::Token => "token",
        LaneKind::Contract => "contract",
        LaneKind::Bridge => "bridge",
        LaneKind::Defi => "defi",
        LaneKind::Settlement => "settlement",
    }
}

fn offense_label(offense: &SlashingOffense) -> &'static str {
    match offense {
        SlashingOffense::DoublePreconfirmation => "double-preconfirmation",
        SlashingOffense::InvalidAttestation => "invalid-attestation",
        SlashingOffense::WithheldWitness => "withheld-witness",
        SlashingOffense::BridgeManifestFraud => "bridge-manifest-fraud",
        SlashingOffense::NullifierFenceViolation => "nullifier-fence-violation",
        SlashingOffense::ReorgConcealment => "reorg-concealment",
    }
}
