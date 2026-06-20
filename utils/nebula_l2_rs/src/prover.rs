use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    blocks::{
        verify_validity_certificate, BlockPrivacyProofAggregate, BlockValidityCertificate, L2Block,
    },
    crypto_policy::{
        crypto_policy_root, public_key_for_label, sign_authorization_for_role,
        verify_authorization_for_role, Authorization, CryptoRole,
    },
    fees::{execution_profile_from_resources, FeeMarketResource},
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID, DEVNET_PRIVACY_PROOF_BYTES, TARGET_BLOCK_MS,
};

pub type ProverResult<T> = Result<T, String>;

pub const PROVER_DEFAULT_JOB_TTL_BLOCKS: u64 = 8;
pub const PROVER_MIN_STAKE_UNITS: u64 = 1_000;
pub const PROVER_BASE_PROOF_FEE_UNITS: u64 = 25;
pub const PROVER_PROOF_FEE_PER_ITEM_UNITS: u64 = 7;
pub const PROVER_PROOF_FEE_PER_KIB_UNITS: u64 = 2;
pub const PROVER_AGGREGATION_FEE_UNITS: u64 = 11;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProverNode {
    pub label: String,
    pub prover_id: String,
    pub prover_public_key: String,
    pub stake_units: u64,
    pub max_parallel_jobs: u64,
    pub base_fee_units: u64,
    pub supported_proof_systems: Vec<String>,
    pub status: String,
    pub registered_at_height: u64,
    pub last_seen_height: u64,
    pub completed_job_count: u64,
    pub failed_job_count: u64,
    pub slashed_units: u64,
}

impl ProverNode {
    pub fn new(label: &str, stake_units: u64, current_height: u64) -> ProverResult<Self> {
        if label.is_empty() {
            return Err("prover label is required".to_string());
        }
        if stake_units < PROVER_MIN_STAKE_UNITS {
            return Err("prover stake is below minimum".to_string());
        }
        let public_key = public_key_for_label(CryptoRole::ProverSignature, label);
        Ok(Self {
            label: label.to_string(),
            prover_id: prover_id(label),
            prover_public_key: public_key.public_key,
            stake_units,
            max_parallel_jobs: 4,
            base_fee_units: PROVER_BASE_PROOF_FEE_UNITS,
            supported_proof_systems: vec![
                "devnet-transparent-state-transition-proof".to_string(),
                "devnet-transparent-privacy-proof-aggregate".to_string(),
            ],
            status: "active".to_string(),
            registered_at_height: current_height,
            last_seen_height: current_height,
            completed_job_count: 0,
            failed_job_count: 0,
            slashed_units: 0,
        })
    }

    pub fn is_active(&self) -> bool {
        self.status == "active" && self.stake_units > self.slashed_units
    }

    pub fn supports(&self, proof_system: &str) -> bool {
        self.supported_proof_systems.is_empty()
            || self
                .supported_proof_systems
                .iter()
                .any(|supported| supported == proof_system)
    }

    pub fn available_stake_units(&self) -> u64 {
        self.stake_units.saturating_sub(self.slashed_units)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "prover_node",
            "chain_id": CHAIN_ID,
            "label": self.label,
            "prover_id": self.prover_id,
            "prover_public_key": self.prover_public_key,
            "stake_units": self.stake_units,
            "available_stake_units": self.available_stake_units(),
            "max_parallel_jobs": self.max_parallel_jobs,
            "base_fee_units": self.base_fee_units,
            "supported_proof_systems": self.supported_proof_systems,
            "status": self.status,
            "registered_at_height": self.registered_at_height,
            "last_seen_height": self.last_seen_height,
            "completed_job_count": self.completed_job_count,
            "failed_job_count": self.failed_job_count,
            "slashed_units": self.slashed_units,
            "crypto_policy_root": crypto_policy_root(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofJobRequest {
    pub block: L2Block,
    pub privacy_aggregate: BlockPrivacyProofAggregate,
    pub validity_certificate: BlockValidityCertificate,
    pub previous_state_root: String,
    pub reward_asset_id: String,
    pub max_fee_units: u64,
    pub priority_fee_units: u64,
    pub requester_label: String,
    pub opened_at_height: u64,
    pub deadline_height: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofJob {
    pub job_id: String,
    pub block_height: u64,
    pub block_hash: String,
    pub previous_state_root: String,
    pub state_root: String,
    pub tx_root: String,
    pub da_root: String,
    pub mempool_admission_root: String,
    pub privacy_aggregate_root: String,
    pub privacy_aggregate_proof_root: String,
    pub validity_certificate_root: String,
    pub public_input_hash: String,
    pub requested_proof_system: String,
    pub expected_proof_root: String,
    pub execution_profile_hash: String,
    pub estimated_proof_bytes: u64,
    pub privacy_proof_count: u64,
    pub execution_fuel: u64,
    pub reward_asset_id: String,
    pub max_fee_units: u64,
    pub priority_fee_units: u64,
    pub estimated_fee_units: u64,
    pub requester_label: String,
    pub opened_at_height: u64,
    pub deadline_height: u64,
    pub status: String,
    pub assigned_prover_id: Option<String>,
    pub assignment_id: Option<String>,
    pub receipt_id: Option<String>,
}

impl ProofJob {
    pub fn is_open(&self) -> bool {
        self.status == "open"
    }

    pub fn is_assigned(&self) -> bool {
        self.status == "assigned"
    }

    pub fn is_expired(&self, current_height: u64) -> bool {
        current_height > self.deadline_height && self.receipt_id.is_none()
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "proof_job",
            "chain_id": CHAIN_ID,
            "job_id": self.job_id,
            "block_height": self.block_height,
            "block_hash": self.block_hash,
            "previous_state_root": self.previous_state_root,
            "state_root": self.state_root,
            "tx_root": self.tx_root,
            "da_root": self.da_root,
            "mempool_admission_root": self.mempool_admission_root,
            "privacy_aggregate_root": self.privacy_aggregate_root,
            "privacy_aggregate_proof_root": self.privacy_aggregate_proof_root,
            "validity_certificate_root": self.validity_certificate_root,
            "public_input_hash": self.public_input_hash,
            "requested_proof_system": self.requested_proof_system,
            "expected_proof_root": self.expected_proof_root,
            "execution_profile_hash": self.execution_profile_hash,
            "estimated_proof_bytes": self.estimated_proof_bytes,
            "privacy_proof_count": self.privacy_proof_count,
            "execution_fuel": self.execution_fuel,
            "reward_asset_id": self.reward_asset_id,
            "max_fee_units": self.max_fee_units,
            "priority_fee_units": self.priority_fee_units,
            "estimated_fee_units": self.estimated_fee_units,
            "requester_label": self.requester_label,
            "opened_at_height": self.opened_at_height,
            "deadline_height": self.deadline_height,
            "status": self.status,
            "assigned_prover_id": self.assigned_prover_id,
            "assignment_id": self.assignment_id,
            "receipt_id": self.receipt_id,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProverAssignment {
    pub assignment_id: String,
    pub job_id: String,
    pub prover_id: String,
    pub prover_label: String,
    pub block_height: u64,
    pub assigned_at_height: u64,
    pub fee_quote_units: u64,
    pub capacity_root: String,
    pub prover_public_key: String,
    pub authorization: Authorization,
}

impl ProverAssignment {
    pub fn unsigned_record(&self) -> Value {
        json!({
            "kind": "prover_assignment",
            "chain_id": CHAIN_ID,
            "assignment_id": self.assignment_id,
            "job_id": self.job_id,
            "prover_id": self.prover_id,
            "prover_label": self.prover_label,
            "block_height": self.block_height,
            "assigned_at_height": self.assigned_at_height,
            "fee_quote_units": self.fee_quote_units,
            "capacity_root": self.capacity_root,
            "prover_public_key": self.prover_public_key,
            "crypto_policy_root": crypto_policy_root(),
        })
    }

    pub fn assignment_root(&self) -> String {
        domain_hash(
            "PROVER-ASSIGNMENT",
            &[HashPart::Json(&self.unsigned_record())],
            32,
        )
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.unsigned_record();
        let object = record
            .as_object_mut()
            .expect("prover assignment record object");
        object.insert(
            "assignment_root".to_string(),
            Value::String(self.assignment_root()),
        );
        object.insert(
            "auth_scheme".to_string(),
            Value::String(self.authorization.auth_scheme.clone()),
        );
        object.insert(
            "auth_public_key".to_string(),
            Value::String(self.authorization.auth_public_key.clone()),
        );
        object.insert(
            "auth_transcript_hash".to_string(),
            Value::String(self.authorization.auth_transcript_hash.clone()),
        );
        object.insert(
            "auth_signature".to_string(),
            Value::String(self.authorization.auth_signature.clone()),
        );
        record
    }

    pub fn verify_authorization(&self) -> bool {
        verify_authorization_for_role(
            CryptoRole::ProverSignature,
            &self.prover_public_key,
            "prover_assignment",
            &self.unsigned_record(),
            &self.authorization,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProverCompletionInput {
    pub job_id: String,
    pub block: L2Block,
    pub privacy_aggregate: BlockPrivacyProofAggregate,
    pub validity_certificate: BlockValidityCertificate,
    pub previous_state_root: String,
    pub prover_label: String,
    pub completed_at_height: u64,
    pub proof_time_ms: u64,
    pub fee_units: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProverReceipt {
    pub receipt_id: String,
    pub job_id: String,
    pub assignment_id: String,
    pub block_height: u64,
    pub block_hash: String,
    pub prover_id: String,
    pub prover_label: String,
    pub prover_public_key: String,
    pub validity_certificate_root: String,
    pub privacy_aggregate_root: String,
    pub public_input_hash: String,
    pub proof_system: String,
    pub proof_root: String,
    pub aggregate_proof_root: String,
    pub completed_at_height: u64,
    pub proof_time_ms: u64,
    pub fee_units: u64,
    pub reward_asset_id: String,
    pub authorization: Authorization,
}

impl ProverReceipt {
    pub fn unsigned_record(&self) -> Value {
        json!({
            "kind": "prover_receipt",
            "chain_id": CHAIN_ID,
            "receipt_id": self.receipt_id,
            "job_id": self.job_id,
            "assignment_id": self.assignment_id,
            "block_height": self.block_height,
            "block_hash": self.block_hash,
            "prover_id": self.prover_id,
            "prover_label": self.prover_label,
            "prover_public_key": self.prover_public_key,
            "validity_certificate_root": self.validity_certificate_root,
            "privacy_aggregate_root": self.privacy_aggregate_root,
            "public_input_hash": self.public_input_hash,
            "proof_system": self.proof_system,
            "proof_root": self.proof_root,
            "aggregate_proof_root": self.aggregate_proof_root,
            "completed_at_height": self.completed_at_height,
            "proof_time_ms": self.proof_time_ms,
            "fee_units": self.fee_units,
            "reward_asset_id": self.reward_asset_id,
            "crypto_policy_root": crypto_policy_root(),
        })
    }

    pub fn receipt_root(&self) -> String {
        domain_hash(
            "PROVER-RECEIPT",
            &[HashPart::Json(&self.unsigned_record())],
            32,
        )
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.unsigned_record();
        let object = record
            .as_object_mut()
            .expect("prover receipt record object");
        object.insert(
            "receipt_root".to_string(),
            Value::String(self.receipt_root()),
        );
        object.insert(
            "auth_scheme".to_string(),
            Value::String(self.authorization.auth_scheme.clone()),
        );
        object.insert(
            "auth_public_key".to_string(),
            Value::String(self.authorization.auth_public_key.clone()),
        );
        object.insert(
            "auth_transcript_hash".to_string(),
            Value::String(self.authorization.auth_transcript_hash.clone()),
        );
        object.insert(
            "auth_signature".to_string(),
            Value::String(self.authorization.auth_signature.clone()),
        );
        record
    }

    pub fn verify_authorization(&self) -> bool {
        verify_authorization_for_role(
            CryptoRole::ProverSignature,
            &self.prover_public_key,
            "prover_receipt",
            &self.unsigned_record(),
            &self.authorization,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProverAggregation {
    pub aggregation_id: String,
    pub receipt_ids: Vec<String>,
    pub block_heights: Vec<u64>,
    pub receipt_root: String,
    pub certificate_root: String,
    pub aggregate_proof_system: String,
    pub aggregate_proof_root: String,
    pub prover_set_root: String,
    pub aggregator_label: String,
    pub aggregator_public_key: String,
    pub fee_units: u64,
    pub authorization: Authorization,
}

impl ProverAggregation {
    pub fn unsigned_record(&self) -> Value {
        json!({
            "kind": "prover_aggregation",
            "chain_id": CHAIN_ID,
            "aggregation_id": self.aggregation_id,
            "receipt_ids": self.receipt_ids,
            "block_heights": self.block_heights,
            "receipt_root": self.receipt_root,
            "certificate_root": self.certificate_root,
            "aggregate_proof_system": self.aggregate_proof_system,
            "aggregate_proof_root": self.aggregate_proof_root,
            "prover_set_root": self.prover_set_root,
            "aggregator_label": self.aggregator_label,
            "aggregator_public_key": self.aggregator_public_key,
            "fee_units": self.fee_units,
            "crypto_policy_root": crypto_policy_root(),
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.unsigned_record();
        let object = record
            .as_object_mut()
            .expect("prover aggregation record object");
        object.insert(
            "aggregation_root".to_string(),
            Value::String(self.aggregation_root()),
        );
        object.insert(
            "auth_scheme".to_string(),
            Value::String(self.authorization.auth_scheme.clone()),
        );
        object.insert(
            "auth_public_key".to_string(),
            Value::String(self.authorization.auth_public_key.clone()),
        );
        object.insert(
            "auth_transcript_hash".to_string(),
            Value::String(self.authorization.auth_transcript_hash.clone()),
        );
        object.insert(
            "auth_signature".to_string(),
            Value::String(self.authorization.auth_signature.clone()),
        );
        record
    }

    pub fn aggregation_root(&self) -> String {
        domain_hash(
            "PROVER-AGGREGATION",
            &[HashPart::Json(&self.unsigned_record())],
            32,
        )
    }

    pub fn verify_authorization(&self) -> bool {
        verify_authorization_for_role(
            CryptoRole::ProverSignature,
            &self.aggregator_public_key,
            "prover_aggregation",
            &self.unsigned_record(),
            &self.authorization,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProverDispute {
    pub dispute_id: String,
    pub receipt_id: String,
    pub job_id: String,
    pub prover_id: String,
    pub challenge_kind: String,
    pub expected_root: String,
    pub observed_root: String,
    pub reporter_label: String,
    pub opened_at_height: u64,
    pub status: String,
    pub slash_units: u64,
    pub authorization: Authorization,
}

impl ProverDispute {
    pub fn unsigned_record(&self) -> Value {
        json!({
            "kind": "prover_dispute",
            "chain_id": CHAIN_ID,
            "dispute_id": self.dispute_id,
            "receipt_id": self.receipt_id,
            "job_id": self.job_id,
            "prover_id": self.prover_id,
            "challenge_kind": self.challenge_kind,
            "expected_root": self.expected_root,
            "observed_root": self.observed_root,
            "reporter_label": self.reporter_label,
            "opened_at_height": self.opened_at_height,
            "status": self.status,
            "slash_units": self.slash_units,
        })
    }

    pub fn dispute_root(&self) -> String {
        domain_hash(
            "PROVER-DISPUTE",
            &[HashPart::Json(&self.unsigned_record())],
            32,
        )
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.unsigned_record();
        let object = record
            .as_object_mut()
            .expect("prover dispute record object");
        object.insert(
            "dispute_root".to_string(),
            Value::String(self.dispute_root()),
        );
        object.insert(
            "auth_scheme".to_string(),
            Value::String(self.authorization.auth_scheme.clone()),
        );
        object.insert(
            "auth_public_key".to_string(),
            Value::String(self.authorization.auth_public_key.clone()),
        );
        object.insert(
            "auth_transcript_hash".to_string(),
            Value::String(self.authorization.auth_transcript_hash.clone()),
        );
        object.insert(
            "auth_signature".to_string(),
            Value::String(self.authorization.auth_signature.clone()),
        );
        record
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProverState {
    pub height: u64,
    pub provers: BTreeMap<String, ProverNode>,
    pub jobs: BTreeMap<String, ProofJob>,
    pub assignments: BTreeMap<String, ProverAssignment>,
    pub receipts: BTreeMap<String, ProverReceipt>,
    pub aggregations: BTreeMap<String, ProverAggregation>,
    pub disputes: BTreeMap<String, ProverDispute>,
}

impl ProverState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_height(&mut self, height: u64) {
        self.height = height;
    }

    pub fn register_prover(
        &mut self,
        label: &str,
        stake_units: u64,
        supported_proof_systems: Vec<String>,
    ) -> ProverResult<ProverNode> {
        let mut node = ProverNode::new(label, stake_units, self.height)?;
        if !supported_proof_systems.is_empty() {
            node.supported_proof_systems = supported_proof_systems;
        }
        self.provers.insert(node.prover_id.clone(), node.clone());
        Ok(node)
    }

    pub fn ensure_default_prover(&mut self, label: &str) -> ProverResult<ProverNode> {
        if let Some(node) = self.provers.values().find(|node| node.label == label) {
            return Ok(node.clone());
        }
        self.register_prover(label, PROVER_MIN_STAKE_UNITS * 10, Vec::new())
    }

    pub fn submit_block_job(&mut self, request: ProofJobRequest) -> ProverResult<ProofJob> {
        if !verify_validity_certificate(
            &request.block,
            &request.privacy_aggregate,
            &request.previous_state_root,
            &request.validity_certificate,
        ) {
            return Err("proof job validity certificate does not match block".to_string());
        }
        let opened_at_height = if request.opened_at_height == 0 {
            self.height
        } else {
            request.opened_at_height
        };
        let deadline_height = if request.deadline_height == 0 {
            opened_at_height + PROVER_DEFAULT_JOB_TTL_BLOCKS
        } else {
            request.deadline_height
        };
        if deadline_height < opened_at_height {
            return Err("proof job deadline is before open height".to_string());
        }
        let estimated_fee_units = estimated_prover_fee_units(
            request.block.header.execution_profile.estimated_proof_bytes,
            request.privacy_aggregate.privacy_proof_count,
            request.block.header.execution_profile.execution_fuel,
        )
        .saturating_add(request.priority_fee_units);
        if request.max_fee_units < estimated_fee_units {
            return Err("proof job max fee below estimated prover fee".to_string());
        }
        let block_height = request.block.header.height;
        let block_hash = request.block.header.block_hash();
        let state_root = request.block.header.state_root.clone();
        let tx_root = request.block.header.tx_root.clone();
        let da_root = request.block.header.da_root.clone();
        let mempool_admission_root = request.block.header.mempool_admission_root.clone();
        let execution_profile_record = request.block.header.execution_profile.public_record();
        let estimated_proof_bytes = request.block.header.execution_profile.estimated_proof_bytes;
        let execution_fuel = request.block.header.execution_profile.execution_fuel;
        let privacy_aggregate_root = request.privacy_aggregate.aggregate_root();
        let privacy_aggregate_proof_root = request.privacy_aggregate.aggregate_proof_root.clone();
        let privacy_proof_count = request.privacy_aggregate.privacy_proof_count;
        let validity_certificate_root = request.validity_certificate.certificate_root();
        let public_input_hash = request.validity_certificate.public_input_hash.clone();
        let requested_proof_system = request.validity_certificate.proof_system.clone();
        let expected_proof_root = request.validity_certificate.proof_root.clone();
        let job_id = proof_job_id(
            block_height,
            &block_hash,
            &validity_certificate_root,
            &privacy_aggregate_root,
            &request.requester_label,
        );
        let job = ProofJob {
            job_id: job_id.clone(),
            block_height,
            block_hash,
            previous_state_root: request.previous_state_root,
            state_root,
            tx_root,
            da_root,
            mempool_admission_root,
            privacy_aggregate_root,
            privacy_aggregate_proof_root,
            validity_certificate_root,
            public_input_hash,
            requested_proof_system,
            expected_proof_root,
            execution_profile_hash: domain_hash(
                "EXECUTION-PROFILE",
                &[HashPart::Json(&execution_profile_record)],
                32,
            ),
            estimated_proof_bytes,
            privacy_proof_count,
            execution_fuel,
            reward_asset_id: request.reward_asset_id,
            max_fee_units: request.max_fee_units,
            priority_fee_units: request.priority_fee_units,
            estimated_fee_units,
            requester_label: request.requester_label,
            opened_at_height,
            deadline_height,
            status: "open".to_string(),
            assigned_prover_id: None,
            assignment_id: None,
            receipt_id: None,
        };
        self.jobs.insert(job_id, job.clone());
        Ok(job)
    }

    pub fn assign_job(
        &mut self,
        job_id: &str,
        prover_label: &str,
    ) -> ProverResult<ProverAssignment> {
        let job = self
            .jobs
            .get(job_id)
            .cloned()
            .ok_or_else(|| "unknown proof job".to_string())?;
        if !job.is_open() {
            return Err("proof job is not open".to_string());
        }
        if job.is_expired(self.height) {
            return Err("proof job is expired".to_string());
        }
        let prover = self
            .provers
            .values()
            .find(|node| node.label == prover_label)
            .cloned()
            .ok_or_else(|| "unknown prover".to_string())?;
        if !prover.is_active() {
            return Err("prover is not active".to_string());
        }
        if !prover.supports(&job.requested_proof_system) {
            return Err("prover does not support requested proof system".to_string());
        }
        let active_jobs = self
            .jobs
            .values()
            .filter(|candidate| {
                candidate.status == "assigned"
                    && candidate
                        .assigned_prover_id
                        .as_ref()
                        .is_some_and(|assigned| assigned == &prover.prover_id)
            })
            .count() as u64;
        if active_jobs >= prover.max_parallel_jobs {
            return Err("prover has no available proof capacity".to_string());
        }
        let capacity_root = prover_capacity_root(&prover, active_jobs, &self.jobs);
        let assignment_id = prover_assignment_id(job_id, &prover.prover_id, self.height);
        let mut assignment = ProverAssignment {
            assignment_id: assignment_id.clone(),
            job_id: job_id.to_string(),
            prover_id: prover.prover_id.clone(),
            prover_label: prover.label.clone(),
            block_height: job.block_height,
            assigned_at_height: self.height,
            fee_quote_units: job
                .estimated_fee_units
                .saturating_add(prover.base_fee_units),
            capacity_root,
            prover_public_key: prover.prover_public_key.clone(),
            authorization: Authorization {
                signer_label: prover.label.clone(),
                auth_scheme: CryptoRole::ProverSignature.scheme().to_string(),
                auth_public_key: String::new(),
                auth_transcript_hash: String::new(),
                auth_signature: String::new(),
            },
        };
        assignment.authorization = sign_authorization_for_role(
            CryptoRole::ProverSignature,
            &prover.label,
            "prover_assignment",
            &assignment.unsigned_record(),
        );
        if !assignment.verify_authorization() {
            return Err("prover assignment authorization failed".to_string());
        }
        let job_mut = self
            .jobs
            .get_mut(job_id)
            .ok_or_else(|| "unknown proof job".to_string())?;
        job_mut.status = "assigned".to_string();
        job_mut.assigned_prover_id = Some(prover.prover_id.clone());
        job_mut.assignment_id = Some(assignment_id.clone());
        self.assignments
            .insert(assignment_id.clone(), assignment.clone());
        if let Some(node) = self.provers.get_mut(&prover.prover_id) {
            node.last_seen_height = self.height;
        }
        Ok(assignment)
    }

    pub fn complete_job(&mut self, input: ProverCompletionInput) -> ProverResult<ProverReceipt> {
        let job = self
            .jobs
            .get(&input.job_id)
            .cloned()
            .ok_or_else(|| "unknown proof job".to_string())?;
        if !job.is_assigned() {
            return Err("proof job is not assigned".to_string());
        }
        if !verify_validity_certificate(
            &input.block,
            &input.privacy_aggregate,
            &input.previous_state_root,
            &input.validity_certificate,
        ) {
            return Err("completed proof certificate does not match block".to_string());
        }
        let prover = self
            .provers
            .values()
            .find(|node| node.label == input.prover_label)
            .cloned()
            .ok_or_else(|| "unknown prover".to_string())?;
        if job.assigned_prover_id.as_deref() != Some(&prover.prover_id) {
            return Err("proof job assigned to a different prover".to_string());
        }
        let assignment_id = job
            .assignment_id
            .clone()
            .ok_or_else(|| "proof job has no assignment".to_string())?;
        let assignment = self
            .assignments
            .get(&assignment_id)
            .ok_or_else(|| "missing proof assignment".to_string())?;
        if !assignment.verify_authorization() {
            return Err("proof assignment authorization failed".to_string());
        }
        validate_completion_matches_job(&job, &input)?;
        if input.fee_units > job.max_fee_units {
            return Err("proof completion fee exceeds job max fee".to_string());
        }
        let receipt_id =
            prover_receipt_id(&job.job_id, &prover.prover_id, &job.expected_proof_root);
        let mut receipt = ProverReceipt {
            receipt_id: receipt_id.clone(),
            job_id: job.job_id.clone(),
            assignment_id,
            block_height: job.block_height,
            block_hash: job.block_hash.clone(),
            prover_id: prover.prover_id.clone(),
            prover_label: prover.label.clone(),
            prover_public_key: prover.prover_public_key.clone(),
            validity_certificate_root: job.validity_certificate_root.clone(),
            privacy_aggregate_root: job.privacy_aggregate_root.clone(),
            public_input_hash: job.public_input_hash.clone(),
            proof_system: job.requested_proof_system.clone(),
            proof_root: job.expected_proof_root.clone(),
            aggregate_proof_root: job.privacy_aggregate_proof_root.clone(),
            completed_at_height: input.completed_at_height,
            proof_time_ms: input.proof_time_ms,
            fee_units: input.fee_units,
            reward_asset_id: job.reward_asset_id.clone(),
            authorization: Authorization {
                signer_label: prover.label.clone(),
                auth_scheme: CryptoRole::ProverSignature.scheme().to_string(),
                auth_public_key: String::new(),
                auth_transcript_hash: String::new(),
                auth_signature: String::new(),
            },
        };
        receipt.authorization = sign_authorization_for_role(
            CryptoRole::ProverSignature,
            &prover.label,
            "prover_receipt",
            &receipt.unsigned_record(),
        );
        if !receipt.verify_authorization() {
            return Err("prover receipt authorization failed".to_string());
        }
        let job_mut = self
            .jobs
            .get_mut(&input.job_id)
            .ok_or_else(|| "unknown proof job".to_string())?;
        job_mut.status = "completed".to_string();
        job_mut.receipt_id = Some(receipt_id.clone());
        if let Some(node) = self.provers.get_mut(&prover.prover_id) {
            node.completed_job_count += 1;
            node.last_seen_height = input.completed_at_height;
        }
        self.receipts.insert(receipt_id, receipt.clone());
        Ok(receipt)
    }

    pub fn aggregate_receipts(
        &mut self,
        receipt_ids: &[String],
        aggregator_label: &str,
    ) -> ProverResult<ProverAggregation> {
        if receipt_ids.is_empty() {
            return Err("aggregation requires at least one receipt".to_string());
        }
        let mut unique = BTreeSet::new();
        let mut receipts = Vec::new();
        for receipt_id in receipt_ids {
            if !unique.insert(receipt_id.clone()) {
                return Err("duplicate receipt in prover aggregation".to_string());
            }
            receipts.push(
                self.receipts
                    .get(receipt_id)
                    .cloned()
                    .ok_or_else(|| "unknown prover receipt".to_string())?,
            );
        }
        receipts.sort_by_key(|receipt| (receipt.block_height, receipt.receipt_id.clone()));
        let receipt_records = receipts
            .iter()
            .map(ProverReceipt::public_record)
            .collect::<Vec<_>>();
        let receipt_root = merkle_root("PROVER-AGGREGATION-RECEIPT", &receipt_records);
        let certificate_records = receipts
            .iter()
            .map(|receipt| {
                json!({
                    "block_height": receipt.block_height,
                    "validity_certificate_root": receipt.validity_certificate_root,
                    "privacy_aggregate_root": receipt.privacy_aggregate_root,
                })
            })
            .collect::<Vec<_>>();
        let certificate_root = merkle_root("PROVER-AGGREGATION-CERTIFICATE", &certificate_records);
        let prover_records = receipts
            .iter()
            .map(|receipt| {
                json!({
                    "prover_id": receipt.prover_id,
                    "prover_public_key": receipt.prover_public_key,
                })
            })
            .collect::<Vec<_>>();
        let prover_set_root = merkle_root("PROVER-AGGREGATION-SET", &prover_records);
        let aggregate_proof_system = "devnet-recursive-prover-receipt-aggregation".to_string();
        let aggregate_proof_root = domain_hash(
            "PROVER-RECEIPT-AGGREGATE-PROOF",
            &[
                HashPart::Str(&receipt_root),
                HashPart::Str(&certificate_root),
                HashPart::Str(&prover_set_root),
                HashPart::Str(&aggregate_proof_system),
            ],
            32,
        );
        let aggregation_id = prover_aggregation_id(&receipt_root, &aggregate_proof_root);
        let aggregator_key = public_key_for_label(CryptoRole::ProverSignature, aggregator_label);
        let mut aggregation = ProverAggregation {
            aggregation_id: aggregation_id.clone(),
            receipt_ids: receipts
                .iter()
                .map(|receipt| receipt.receipt_id.clone())
                .collect(),
            block_heights: receipts
                .iter()
                .map(|receipt| receipt.block_height)
                .collect(),
            receipt_root,
            certificate_root,
            aggregate_proof_system,
            aggregate_proof_root,
            prover_set_root,
            aggregator_label: aggregator_label.to_string(),
            aggregator_public_key: aggregator_key.public_key,
            fee_units: PROVER_AGGREGATION_FEE_UNITS * receipts.len() as u64,
            authorization: Authorization {
                signer_label: aggregator_label.to_string(),
                auth_scheme: CryptoRole::ProverSignature.scheme().to_string(),
                auth_public_key: String::new(),
                auth_transcript_hash: String::new(),
                auth_signature: String::new(),
            },
        };
        aggregation.authorization = sign_authorization_for_role(
            CryptoRole::ProverSignature,
            aggregator_label,
            "prover_aggregation",
            &aggregation.unsigned_record(),
        );
        if !aggregation.verify_authorization() {
            return Err("prover aggregation authorization failed".to_string());
        }
        self.aggregations
            .insert(aggregation_id, aggregation.clone());
        Ok(aggregation)
    }

    pub fn open_dispute(
        &mut self,
        receipt_id: &str,
        challenge_kind: &str,
        observed_root: &str,
        reporter_label: &str,
    ) -> ProverResult<ProverDispute> {
        if challenge_kind.is_empty() {
            return Err("prover dispute challenge kind is required".to_string());
        }
        let receipt = self
            .receipts
            .get(receipt_id)
            .cloned()
            .ok_or_else(|| "unknown prover receipt".to_string())?;
        let expected_root = match challenge_kind {
            "proof-root-mismatch" => receipt.proof_root.clone(),
            "aggregate-root-mismatch" => receipt.aggregate_proof_root.clone(),
            "certificate-root-mismatch" => receipt.validity_certificate_root.clone(),
            _ => receipt.receipt_root(),
        };
        let status = if observed_root == expected_root {
            "rejected"
        } else {
            "open"
        }
        .to_string();
        let slash_units = if status == "open" {
            std::cmp::max(1, PROVER_MIN_STAKE_UNITS / 10)
        } else {
            0
        };
        let dispute_id = prover_dispute_id(receipt_id, challenge_kind, observed_root);
        let mut dispute = ProverDispute {
            dispute_id: dispute_id.clone(),
            receipt_id: receipt_id.to_string(),
            job_id: receipt.job_id.clone(),
            prover_id: receipt.prover_id.clone(),
            challenge_kind: challenge_kind.to_string(),
            expected_root,
            observed_root: observed_root.to_string(),
            reporter_label: reporter_label.to_string(),
            opened_at_height: self.height,
            status,
            slash_units,
            authorization: Authorization {
                signer_label: reporter_label.to_string(),
                auth_scheme: CryptoRole::AccountSignature.scheme().to_string(),
                auth_public_key: String::new(),
                auth_transcript_hash: String::new(),
                auth_signature: String::new(),
            },
        };
        dispute.authorization = sign_authorization_for_role(
            CryptoRole::AccountSignature,
            reporter_label,
            "prover_dispute",
            &dispute.unsigned_record(),
        );
        self.disputes.insert(dispute_id, dispute.clone());
        Ok(dispute)
    }

    pub fn settle_dispute(&mut self, dispute_id: &str) -> ProverResult<ProverDispute> {
        let dispute = self
            .disputes
            .get(dispute_id)
            .cloned()
            .ok_or_else(|| "unknown prover dispute".to_string())?;
        if dispute.status != "open" {
            return Ok(dispute);
        }
        let node = self
            .provers
            .get_mut(&dispute.prover_id)
            .ok_or_else(|| "unknown disputed prover".to_string())?;
        node.slashed_units = node.slashed_units.saturating_add(std::cmp::min(
            dispute.slash_units,
            node.available_stake_units(),
        ));
        node.failed_job_count += 1;
        if node.available_stake_units() == 0 {
            node.status = "slashed".to_string();
        }
        let dispute_mut = self
            .disputes
            .get_mut(dispute_id)
            .ok_or_else(|| "unknown prover dispute".to_string())?;
        dispute_mut.status = "settled".to_string();
        Ok(dispute_mut.clone())
    }

    pub fn prover_root(&self) -> String {
        merkle_root(
            "PROVER-NODE",
            &self
                .provers
                .values()
                .map(ProverNode::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn job_root(&self) -> String {
        merkle_root(
            "PROVER-JOB",
            &self
                .jobs
                .values()
                .map(ProofJob::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn assignment_root(&self) -> String {
        merkle_root(
            "PROVER-ASSIGNMENT",
            &self
                .assignments
                .values()
                .map(ProverAssignment::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn receipt_root(&self) -> String {
        merkle_root(
            "PROVER-RECEIPT",
            &self
                .receipts
                .values()
                .map(ProverReceipt::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn aggregation_root(&self) -> String {
        merkle_root(
            "PROVER-AGGREGATION",
            &self
                .aggregations
                .values()
                .map(ProverAggregation::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn dispute_root(&self) -> String {
        merkle_root(
            "PROVER-DISPUTE",
            &self
                .disputes
                .values()
                .map(ProverDispute::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "PROVER-STATE",
            &[
                HashPart::Str(&self.prover_root()),
                HashPart::Str(&self.job_root()),
                HashPart::Str(&self.assignment_root()),
                HashPart::Str(&self.receipt_root()),
                HashPart::Str(&self.aggregation_root()),
                HashPart::Str(&self.dispute_root()),
            ],
            32,
        )
    }

    pub fn pending_job_count(&self) -> u64 {
        self.jobs
            .values()
            .filter(|job| job.status == "open" || job.status == "assigned")
            .count() as u64
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "prover_state",
            "chain_id": CHAIN_ID,
            "height": self.height,
            "prover_root": self.prover_root(),
            "job_root": self.job_root(),
            "assignment_root": self.assignment_root(),
            "receipt_root": self.receipt_root(),
            "aggregation_root": self.aggregation_root(),
            "dispute_root": self.dispute_root(),
            "prover_state_root": self.state_root(),
            "prover_count": self.provers.len() as u64,
            "pending_job_count": self.pending_job_count(),
            "receipt_count": self.receipts.len() as u64,
            "aggregation_count": self.aggregations.len() as u64,
            "dispute_count": self.disputes.len() as u64,
        })
    }
}

pub fn prover_id(label: &str) -> String {
    domain_hash(
        "PROVER-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Str(&crypto_policy_root()),
        ],
        32,
    )
}

pub fn proof_job_id(
    block_height: u64,
    block_hash: &str,
    certificate_root: &str,
    privacy_aggregate_root: &str,
    requester_label: &str,
) -> String {
    domain_hash(
        "PROOF-JOB-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(block_height as i128),
            HashPart::Str(block_hash),
            HashPart::Str(certificate_root),
            HashPart::Str(privacy_aggregate_root),
            HashPart::Str(requester_label),
        ],
        32,
    )
}

pub fn prover_assignment_id(job_id: &str, prover_id: &str, assigned_at_height: u64) -> String {
    domain_hash(
        "PROVER-ASSIGNMENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(job_id),
            HashPart::Str(prover_id),
            HashPart::Int(assigned_at_height as i128),
        ],
        32,
    )
}

pub fn prover_receipt_id(job_id: &str, prover_id: &str, proof_root: &str) -> String {
    domain_hash(
        "PROVER-RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(job_id),
            HashPart::Str(prover_id),
            HashPart::Str(proof_root),
        ],
        32,
    )
}

pub fn prover_aggregation_id(receipt_root: &str, aggregate_proof_root: &str) -> String {
    domain_hash(
        "PROVER-AGGREGATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(receipt_root),
            HashPart::Str(aggregate_proof_root),
        ],
        32,
    )
}

pub fn prover_dispute_id(receipt_id: &str, challenge_kind: &str, observed_root: &str) -> String {
    domain_hash(
        "PROVER-DISPUTE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(receipt_id),
            HashPart::Str(challenge_kind),
            HashPart::Str(observed_root),
        ],
        32,
    )
}

pub fn estimated_prover_fee_units(
    estimated_proof_bytes: u64,
    privacy_proof_count: u64,
    execution_fuel: u64,
) -> u64 {
    let proof_kib = std::cmp::max(1, estimated_proof_bytes.div_ceil(1024));
    PROVER_BASE_PROOF_FEE_UNITS
        .saturating_add(privacy_proof_count.saturating_mul(PROVER_PROOF_FEE_PER_ITEM_UNITS))
        .saturating_add(proof_kib.saturating_mul(PROVER_PROOF_FEE_PER_KIB_UNITS))
        .saturating_add(execution_fuel.div_ceil(10_000))
}

pub fn fee_market_resource_for_proof_job(job: &ProofJob) -> FeeMarketResource {
    FeeMarketResource {
        public_record: job.public_record(),
        execution_fuel: 0,
        privacy_proof_count: job.privacy_proof_count,
        contract_call_count: 0,
        observed_fee_units: job.estimated_fee_units,
        estimated_proof_bytes: job.estimated_proof_bytes,
        authorization_count: 1,
        fee_asset_ids: if job.reward_asset_id.is_empty() {
            Vec::new()
        } else {
            vec![job.reward_asset_id.clone()]
        },
        fee_lanes: vec![
            (
                "proof_system".to_string(),
                job.requested_proof_system.clone(),
            ),
            ("proof_block".to_string(), job.block_height.to_string()),
        ],
    }
}

pub fn proof_market_snapshot(prover_state: &ProverState) -> Value {
    let resources = prover_state
        .jobs
        .values()
        .filter(|job| job.status == "open" || job.status == "assigned")
        .map(fee_market_resource_for_proof_job)
        .collect::<Vec<_>>();
    let profile = execution_profile_from_resources(&resources);
    json!({
        "kind": "proof_market_snapshot",
        "chain_id": CHAIN_ID,
        "height": prover_state.height,
        "pending_job_count": prover_state.pending_job_count(),
        "active_prover_count": prover_state.provers.values().filter(|node| node.is_active()).count() as u64,
        "proof_fee_profile": profile.public_record(),
        "prover_root": prover_state.prover_root(),
        "job_root": prover_state.job_root(),
        "receipt_root": prover_state.receipt_root(),
        "prover_state_root": prover_state.state_root(),
        "target_block_ms": TARGET_BLOCK_MS,
    })
}

fn prover_capacity_root(
    prover: &ProverNode,
    active_jobs: u64,
    jobs: &BTreeMap<String, ProofJob>,
) -> String {
    let assigned_roots = jobs
        .values()
        .filter(|job| {
            job.status == "assigned"
                && job
                    .assigned_prover_id
                    .as_ref()
                    .is_some_and(|assigned| assigned == &prover.prover_id)
        })
        .map(|job| {
            json!({
                "job_id": job.job_id,
                "block_height": job.block_height,
                "deadline_height": job.deadline_height,
                "estimated_proof_bytes": job.estimated_proof_bytes,
            })
        })
        .collect::<Vec<_>>();
    domain_hash(
        "PROVER-CAPACITY",
        &[
            HashPart::Str(&prover.prover_id),
            HashPart::Int(active_jobs as i128),
            HashPart::Int(prover.max_parallel_jobs as i128),
            HashPart::Json(&Value::Array(assigned_roots)),
        ],
        32,
    )
}

fn validate_completion_matches_job(
    job: &ProofJob,
    input: &ProverCompletionInput,
) -> ProverResult<()> {
    let aggregate_root = input.privacy_aggregate.aggregate_root();
    let certificate_root = input.validity_certificate.certificate_root();
    if input.block.header.height != job.block_height {
        return Err("completed proof block height mismatch".to_string());
    }
    if input.block.header.block_hash() != job.block_hash {
        return Err("completed proof block hash mismatch".to_string());
    }
    if input.previous_state_root != job.previous_state_root {
        return Err("completed proof previous state root mismatch".to_string());
    }
    if input.block.header.state_root != job.state_root {
        return Err("completed proof state root mismatch".to_string());
    }
    if input.block.header.tx_root != job.tx_root {
        return Err("completed proof tx root mismatch".to_string());
    }
    if input.block.header.da_root != job.da_root {
        return Err("completed proof DA root mismatch".to_string());
    }
    if aggregate_root != job.privacy_aggregate_root {
        return Err("completed proof privacy aggregate root mismatch".to_string());
    }
    if certificate_root != job.validity_certificate_root {
        return Err("completed proof certificate root mismatch".to_string());
    }
    if input.validity_certificate.public_input_hash != job.public_input_hash {
        return Err("completed proof public input hash mismatch".to_string());
    }
    if input.validity_certificate.proof_root != job.expected_proof_root {
        return Err("completed proof root mismatch".to_string());
    }
    if input.validity_certificate.proof_system != job.requested_proof_system {
        return Err("completed proof system mismatch".to_string());
    }
    Ok(())
}

pub fn devnet_proof_job_request(
    block: L2Block,
    privacy_aggregate: BlockPrivacyProofAggregate,
    validity_certificate: BlockValidityCertificate,
    previous_state_root: String,
    requester_label: &str,
    reward_asset_id: &str,
    opened_at_height: u64,
) -> ProofJobRequest {
    let estimated_fee_units = estimated_prover_fee_units(
        block
            .header
            .execution_profile
            .estimated_proof_bytes
            .max(DEVNET_PRIVACY_PROOF_BYTES),
        privacy_aggregate.privacy_proof_count,
        block.header.execution_profile.execution_fuel,
    );
    ProofJobRequest {
        block,
        privacy_aggregate,
        validity_certificate,
        previous_state_root,
        reward_asset_id: reward_asset_id.to_string(),
        max_fee_units: estimated_fee_units.saturating_mul(2),
        priority_fee_units: 0,
        requester_label: requester_label.to_string(),
        opened_at_height,
        deadline_height: opened_at_height + PROVER_DEFAULT_JOB_TTL_BLOCKS,
    }
}
