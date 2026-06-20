use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type ProverMarketResult<T> = Result<T, String>;

pub const PROVER_MARKET_PROTOCOL_VERSION: u64 = 1;
pub const PROVER_MARKET_DEFAULT_SLA_BLOCKS: u64 = 6;
pub const PROVER_MARKET_DEFAULT_BID_WINDOW_BLOCKS: u64 = 2;
pub const PROVER_MARKET_DEFAULT_BATCH_WINDOW_BLOCKS: u64 = 4;
pub const PROVER_MARKET_MIN_CAPACITY_STAKE_UNITS: u64 = 5_000;
pub const PROVER_MARKET_MIN_BID_COLLATERAL_BPS: u64 = 2_500;
pub const PROVER_MARKET_LATE_PENALTY_BPS: u64 = 1_500;
pub const PROVER_MARKET_FAULT_PENALTY_BPS: u64 = 10_000;
pub const PROVER_MARKET_VERIFIER_SAMPLE_COUNT: u64 = 7;
pub const PROVER_MARKET_MAX_SAMPLE_POPULATION: u64 = 4_096;
pub const PROVER_MARKET_PQ_SIGNATURE_SCHEME: &str = "ML-DSA-65";
pub const PROVER_MARKET_PQ_KEM_SCHEME: &str = "ML-KEM-768";
pub const PROVER_MARKET_STATE_PROOF_SYSTEM: &str = "nebula-devnet-pq-state-transition-v1";
pub const PROVER_MARKET_PRIVACY_PROOF_SYSTEM: &str = "nebula-devnet-pq-monero-privacy-v1";
pub const PROVER_MARKET_RECURSIVE_PROOF_SYSTEM: &str = "nebula-devnet-pq-recursive-batch-v1";

pub const PROVER_MARKET_STATUS_OPEN: &str = "open";
pub const PROVER_MARKET_STATUS_ASSIGNED: &str = "assigned";
pub const PROVER_MARKET_STATUS_FINALIZED: &str = "finalized";
pub const PROVER_MARKET_STATUS_CANCELLED: &str = "cancelled";
pub const PROVER_MARKET_STATUS_ACTIVE: &str = "active";
pub const PROVER_MARKET_STATUS_EXHAUSTED: &str = "exhausted";
pub const PROVER_MARKET_STATUS_ACCEPTED: &str = "accepted";
pub const PROVER_MARKET_STATUS_REJECTED: &str = "rejected";
pub const PROVER_MARKET_STATUS_FULFILLED: &str = "fulfilled";
pub const PROVER_MARKET_STATUS_APPLIED: &str = "applied";
pub const PROVER_MARKET_STATUS_SAMPLED: &str = "sampled";

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProverDeviceKind {
    Cpu,
    Gpu,
}

impl ProverDeviceKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Cpu => "cpu",
            Self::Gpu => "gpu",
        }
    }

    pub fn is_gpu(&self) -> bool {
        matches!(self, Self::Gpu)
    }

    pub fn capacity_weight(&self) -> u64 {
        match self {
            Self::Cpu => 1,
            Self::Gpu => 8,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProverMarketConfig {
    pub protocol_version: u64,
    pub default_bid_window_blocks: u64,
    pub default_sla_blocks: u64,
    pub default_batch_window_blocks: u64,
    pub min_capacity_stake_units: u64,
    pub min_bid_collateral_bps: u64,
    pub late_penalty_bps: u64,
    pub fault_penalty_bps: u64,
    pub verifier_sample_count: u64,
    pub max_sample_population: u64,
    pub pq_signature_scheme: String,
    pub pq_kem_scheme: String,
}

impl Default for ProverMarketConfig {
    fn default() -> Self {
        Self {
            protocol_version: PROVER_MARKET_PROTOCOL_VERSION,
            default_bid_window_blocks: PROVER_MARKET_DEFAULT_BID_WINDOW_BLOCKS,
            default_sla_blocks: PROVER_MARKET_DEFAULT_SLA_BLOCKS,
            default_batch_window_blocks: PROVER_MARKET_DEFAULT_BATCH_WINDOW_BLOCKS,
            min_capacity_stake_units: PROVER_MARKET_MIN_CAPACITY_STAKE_UNITS,
            min_bid_collateral_bps: PROVER_MARKET_MIN_BID_COLLATERAL_BPS,
            late_penalty_bps: PROVER_MARKET_LATE_PENALTY_BPS,
            fault_penalty_bps: PROVER_MARKET_FAULT_PENALTY_BPS,
            verifier_sample_count: PROVER_MARKET_VERIFIER_SAMPLE_COUNT,
            max_sample_population: PROVER_MARKET_MAX_SAMPLE_POPULATION,
            pq_signature_scheme: PROVER_MARKET_PQ_SIGNATURE_SCHEME.to_string(),
            pq_kem_scheme: PROVER_MARKET_PQ_KEM_SCHEME.to_string(),
        }
    }
}

impl ProverMarketConfig {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "prover_market_config",
            "chain_id": CHAIN_ID,
            "protocol_version": self.protocol_version,
            "default_bid_window_blocks": self.default_bid_window_blocks,
            "default_sla_blocks": self.default_sla_blocks,
            "default_batch_window_blocks": self.default_batch_window_blocks,
            "min_capacity_stake_units": self.min_capacity_stake_units,
            "min_bid_collateral_bps": self.min_bid_collateral_bps,
            "late_penalty_bps": self.late_penalty_bps,
            "fault_penalty_bps": self.fault_penalty_bps,
            "verifier_sample_count": self.verifier_sample_count,
            "max_sample_population": self.max_sample_population,
            "pq_signature_scheme": self.pq_signature_scheme,
            "pq_kem_scheme": self.pq_kem_scheme,
        })
    }

    pub fn config_root(&self) -> String {
        domain_hash(
            "PROVER-MARKET-CONFIG",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProverCapacityCommitment {
    pub commitment_id: String,
    pub prover_id: String,
    pub prover_label: String,
    pub device_kind: ProverDeviceKind,
    pub device_count: u64,
    pub parallel_slots: u64,
    pub proof_systems: Vec<String>,
    pub compute_units_per_block: u64,
    pub memory_mib: u64,
    pub max_queue_depth: u64,
    pub energy_watts: u64,
    pub stake_locked_units: u64,
    pub price_floor_units: u64,
    pub availability_start_height: u64,
    pub availability_end_height: u64,
    pub nonce: u64,
    pub status: String,
}

impl ProverCapacityCommitment {
    pub fn new(
        prover_label: &str,
        device_kind: ProverDeviceKind,
        device_count: u64,
        parallel_slots: u64,
        proof_systems: Vec<String>,
        compute_units_per_block: u64,
        stake_locked_units: u64,
        price_floor_units: u64,
        availability_start_height: u64,
        availability_end_height: u64,
        nonce: u64,
    ) -> ProverMarketResult<Self> {
        if prover_label.is_empty() {
            return Err("prover label is required".to_string());
        }
        if device_count == 0 {
            return Err("capacity commitment requires at least one device".to_string());
        }
        if parallel_slots == 0 {
            return Err("capacity commitment requires at least one parallel slot".to_string());
        }
        if compute_units_per_block == 0 {
            return Err("capacity commitment requires compute units".to_string());
        }
        if stake_locked_units < PROVER_MARKET_MIN_CAPACITY_STAKE_UNITS {
            return Err("capacity commitment stake is below market minimum".to_string());
        }
        if availability_end_height < availability_start_height {
            return Err("capacity commitment ends before it starts".to_string());
        }
        let prover_id = prover_market_prover_id(prover_label);
        let commitment_id = prover_capacity_commitment_id(
            &prover_id,
            device_kind.as_str(),
            availability_start_height,
            availability_end_height,
            nonce,
        );
        Ok(Self {
            commitment_id,
            prover_id,
            prover_label: prover_label.to_string(),
            device_kind,
            device_count,
            parallel_slots,
            proof_systems,
            compute_units_per_block,
            memory_mib: device_count.saturating_mul(16_384),
            max_queue_depth: parallel_slots.saturating_mul(2),
            energy_watts: device_count.saturating_mul(450),
            stake_locked_units,
            price_floor_units,
            availability_start_height,
            availability_end_height,
            nonce,
            status: PROVER_MARKET_STATUS_ACTIVE.to_string(),
        })
    }

    pub fn supports(&self, proof_system: &str) -> bool {
        self.proof_systems.is_empty()
            || self
                .proof_systems
                .iter()
                .any(|supported| supported == proof_system)
    }

    pub fn is_active_at(&self, height: u64) -> bool {
        self.status == PROVER_MARKET_STATUS_ACTIVE
            && height >= self.availability_start_height
            && height <= self.availability_end_height
    }

    pub fn effective_compute_units(&self) -> u64 {
        self.compute_units_per_block
            .saturating_mul(self.device_count)
            .saturating_mul(self.device_kind.capacity_weight())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "prover_capacity_commitment",
            "chain_id": CHAIN_ID,
            "commitment_id": self.commitment_id,
            "prover_id": self.prover_id,
            "prover_label": self.prover_label,
            "device_kind": self.device_kind.as_str(),
            "device_count": self.device_count,
            "parallel_slots": self.parallel_slots,
            "proof_systems": self.proof_systems,
            "compute_units_per_block": self.compute_units_per_block,
            "effective_compute_units": self.effective_compute_units(),
            "memory_mib": self.memory_mib,
            "max_queue_depth": self.max_queue_depth,
            "energy_watts": self.energy_watts,
            "stake_locked_units": self.stake_locked_units,
            "price_floor_units": self.price_floor_units,
            "availability_start_height": self.availability_start_height,
            "availability_end_height": self.availability_end_height,
            "nonce": self.nonce,
            "status": self.status,
            "pq_signature_scheme": PROVER_MARKET_PQ_SIGNATURE_SCHEME,
        })
    }

    pub fn commitment_root(&self) -> String {
        prover_capacity_commitment_root(self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofWorkloadProfile {
    pub workload_id: String,
    pub proof_system: String,
    pub circuit_family: String,
    pub public_input_root: String,
    pub witness_commitment: String,
    pub estimated_rows: u64,
    pub estimated_proof_bytes: u64,
    pub recursion_depth: u64,
    pub privacy_input_count: u64,
    pub state_transition_count: u64,
    pub requires_gpu: bool,
    pub requested_latency_blocks: u64,
}

impl ProofWorkloadProfile {
    pub fn new(
        proof_system: &str,
        circuit_family: &str,
        public_input_root: &str,
        witness_commitment: &str,
        estimated_rows: u64,
        estimated_proof_bytes: u64,
        recursion_depth: u64,
        privacy_input_count: u64,
        state_transition_count: u64,
        requires_gpu: bool,
        requested_latency_blocks: u64,
    ) -> ProverMarketResult<Self> {
        if proof_system.is_empty() {
            return Err("workload proof system is required".to_string());
        }
        if circuit_family.is_empty() {
            return Err("workload circuit family is required".to_string());
        }
        if public_input_root.is_empty() {
            return Err("workload public input root is required".to_string());
        }
        if witness_commitment.is_empty() {
            return Err("workload witness commitment is required".to_string());
        }
        let workload_id = proof_workload_id(
            proof_system,
            circuit_family,
            public_input_root,
            witness_commitment,
            recursion_depth,
        );
        Ok(Self {
            workload_id,
            proof_system: proof_system.to_string(),
            circuit_family: circuit_family.to_string(),
            public_input_root: public_input_root.to_string(),
            witness_commitment: witness_commitment.to_string(),
            estimated_rows,
            estimated_proof_bytes,
            recursion_depth,
            privacy_input_count,
            state_transition_count,
            requires_gpu,
            requested_latency_blocks,
        })
    }

    pub fn devnet_state_transition(
        block_height: u64,
        previous_state_root: &str,
        state_root: &str,
        tx_root: &str,
    ) -> Self {
        let public_input_root = domain_hash(
            "PROVER-MARKET-DEVNET-PUBLIC-INPUT",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Int(block_height as i128),
                HashPart::Str(previous_state_root),
                HashPart::Str(state_root),
                HashPart::Str(tx_root),
            ],
            32,
        );
        let witness_commitment = domain_hash(
            "PROVER-MARKET-DEVNET-WITNESS",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Int(block_height as i128),
                HashPart::Str(&public_input_root),
            ],
            32,
        );
        Self::new(
            PROVER_MARKET_STATE_PROOF_SYSTEM,
            "state_transition",
            &public_input_root,
            &witness_commitment,
            2_200_000 + block_height.saturating_mul(1_000),
            196_608,
            0,
            2,
            1,
            true,
            PROVER_MARKET_DEFAULT_SLA_BLOCKS,
        )
        .expect("devnet state transition workload")
    }

    pub fn compute_units(&self) -> u64 {
        let row_units = self.estimated_rows.div_ceil(1_024);
        let byte_units = self.estimated_proof_bytes.div_ceil(1_024);
        let privacy_units = self.privacy_input_count.saturating_mul(320);
        let transition_units = self.state_transition_count.saturating_mul(800);
        let recursion_units = self.recursion_depth.saturating_mul(1_200);
        row_units
            .saturating_add(byte_units)
            .saturating_add(privacy_units)
            .saturating_add(transition_units)
            .saturating_add(recursion_units)
            .max(1)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "proof_workload_profile",
            "chain_id": CHAIN_ID,
            "workload_id": self.workload_id,
            "proof_system": self.proof_system,
            "circuit_family": self.circuit_family,
            "public_input_root": self.public_input_root,
            "witness_commitment": self.witness_commitment,
            "estimated_rows": self.estimated_rows,
            "estimated_proof_bytes": self.estimated_proof_bytes,
            "recursion_depth": self.recursion_depth,
            "privacy_input_count": self.privacy_input_count,
            "state_transition_count": self.state_transition_count,
            "requires_gpu": self.requires_gpu,
            "requested_latency_blocks": self.requested_latency_blocks,
            "compute_units": self.compute_units(),
            "pq_kem_scheme": PROVER_MARKET_PQ_KEM_SCHEME,
        })
    }

    pub fn workload_root(&self) -> String {
        proof_workload_root(self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofJobAuction {
    pub auction_id: String,
    pub requester_label: String,
    pub job_kind: String,
    pub workload: ProofWorkloadProfile,
    pub reward_asset_id: String,
    pub max_fee_units: u64,
    pub reserve_fee_units: u64,
    pub priority_fee_units: u64,
    pub opened_at_height: u64,
    pub bid_deadline_height: u64,
    pub proof_deadline_height: u64,
    pub sponsorship_id: Option<String>,
    pub status: String,
    pub winning_bid_id: Option<String>,
    pub receipt_id: Option<String>,
    pub batch_id: Option<String>,
}

impl ProofJobAuction {
    pub fn new(
        requester_label: &str,
        job_kind: &str,
        workload: ProofWorkloadProfile,
        reward_asset_id: &str,
        max_fee_units: u64,
        reserve_fee_units: u64,
        priority_fee_units: u64,
        opened_at_height: u64,
        bid_window_blocks: u64,
        sla_blocks: u64,
        sponsorship_id: Option<String>,
    ) -> ProverMarketResult<Self> {
        if requester_label.is_empty() {
            return Err("auction requester is required".to_string());
        }
        if job_kind.is_empty() {
            return Err("auction job kind is required".to_string());
        }
        if reward_asset_id.is_empty() {
            return Err("auction reward asset id is required".to_string());
        }
        if max_fee_units == 0 {
            return Err("auction max fee must be nonzero".to_string());
        }
        if reserve_fee_units > max_fee_units {
            return Err("auction reserve fee exceeds max fee".to_string());
        }
        let bid_deadline_height = opened_at_height.saturating_add(bid_window_blocks.max(1));
        let proof_deadline_height =
            bid_deadline_height.saturating_add(sla_blocks.max(workload.requested_latency_blocks));
        let workload_root = workload.workload_root();
        let auction_id = proof_job_auction_id(
            requester_label,
            job_kind,
            &workload_root,
            opened_at_height,
            max_fee_units,
        );
        Ok(Self {
            auction_id,
            requester_label: requester_label.to_string(),
            job_kind: job_kind.to_string(),
            workload,
            reward_asset_id: reward_asset_id.to_string(),
            max_fee_units,
            reserve_fee_units,
            priority_fee_units,
            opened_at_height,
            bid_deadline_height,
            proof_deadline_height,
            sponsorship_id,
            status: PROVER_MARKET_STATUS_OPEN.to_string(),
            winning_bid_id: None,
            receipt_id: None,
            batch_id: None,
        })
    }

    pub fn accepts_bids_at(&self, height: u64) -> bool {
        self.status == PROVER_MARKET_STATUS_OPEN && height <= self.bid_deadline_height
    }

    pub fn proof_is_late(&self, completed_at_height: u64) -> bool {
        completed_at_height > self.proof_deadline_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "proof_job_auction",
            "chain_id": CHAIN_ID,
            "auction_id": self.auction_id,
            "requester_label": self.requester_label,
            "job_kind": self.job_kind,
            "workload": self.workload.public_record(),
            "workload_root": self.workload.workload_root(),
            "reward_asset_id": self.reward_asset_id,
            "max_fee_units": self.max_fee_units,
            "reserve_fee_units": self.reserve_fee_units,
            "priority_fee_units": self.priority_fee_units,
            "opened_at_height": self.opened_at_height,
            "bid_deadline_height": self.bid_deadline_height,
            "proof_deadline_height": self.proof_deadline_height,
            "sponsorship_id": self.sponsorship_id,
            "status": self.status,
            "winning_bid_id": self.winning_bid_id,
            "receipt_id": self.receipt_id,
            "batch_id": self.batch_id,
        })
    }

    pub fn auction_root(&self) -> String {
        proof_job_auction_root(self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProverBid {
    pub bid_id: String,
    pub auction_id: String,
    pub prover_id: String,
    pub prover_label: String,
    pub capacity_commitment_id: String,
    pub bid_fee_units: u64,
    pub promised_latency_blocks: u64,
    pub collateral_units: u64,
    pub device_kind: ProverDeviceKind,
    pub estimated_start_height: u64,
    pub score: u64,
    pub placed_at_height: u64,
    pub status: String,
}

impl ProverBid {
    pub fn new(
        auction: &ProofJobAuction,
        commitment: &ProverCapacityCommitment,
        bid_fee_units: u64,
        promised_latency_blocks: u64,
        collateral_units: u64,
        estimated_start_height: u64,
        placed_at_height: u64,
    ) -> ProverMarketResult<Self> {
        if bid_fee_units == 0 {
            return Err("bid fee must be nonzero".to_string());
        }
        if bid_fee_units > auction.max_fee_units {
            return Err("bid fee exceeds auction max fee".to_string());
        }
        if bid_fee_units < commitment.price_floor_units {
            return Err("bid fee is below capacity price floor".to_string());
        }
        if promised_latency_blocks == 0 {
            return Err("bid latency must be nonzero".to_string());
        }
        let required_collateral =
            required_bid_collateral_units(bid_fee_units, PROVER_MARKET_MIN_BID_COLLATERAL_BPS);
        if collateral_units < required_collateral {
            return Err("bid collateral is below market minimum".to_string());
        }
        let score = prover_bid_score(
            auction,
            commitment,
            bid_fee_units,
            promised_latency_blocks,
            collateral_units,
        );
        let bid_id = prover_bid_id(
            &auction.auction_id,
            &commitment.prover_id,
            &commitment.commitment_id,
            bid_fee_units,
            placed_at_height,
        );
        Ok(Self {
            bid_id,
            auction_id: auction.auction_id.clone(),
            prover_id: commitment.prover_id.clone(),
            prover_label: commitment.prover_label.clone(),
            capacity_commitment_id: commitment.commitment_id.clone(),
            bid_fee_units,
            promised_latency_blocks,
            collateral_units,
            device_kind: commitment.device_kind.clone(),
            estimated_start_height,
            score,
            placed_at_height,
            status: PROVER_MARKET_STATUS_OPEN.to_string(),
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "prover_bid",
            "chain_id": CHAIN_ID,
            "bid_id": self.bid_id,
            "auction_id": self.auction_id,
            "prover_id": self.prover_id,
            "prover_label": self.prover_label,
            "capacity_commitment_id": self.capacity_commitment_id,
            "bid_fee_units": self.bid_fee_units,
            "promised_latency_blocks": self.promised_latency_blocks,
            "collateral_units": self.collateral_units,
            "device_kind": self.device_kind.as_str(),
            "estimated_start_height": self.estimated_start_height,
            "score": self.score,
            "placed_at_height": self.placed_at_height,
            "status": self.status,
        })
    }

    pub fn bid_root(&self) -> String {
        prover_bid_root(self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofSponsorship {
    pub sponsorship_id: String,
    pub sponsor_label: String,
    pub lane_key: String,
    pub beneficiary_commitment: String,
    pub budget_units: u64,
    pub spent_units: u64,
    pub max_fee_per_job_units: u64,
    pub starts_at_height: u64,
    pub expires_at_height: u64,
    pub eligibility_root: String,
    pub status: String,
}

impl ProofSponsorship {
    pub fn new(
        sponsor_label: &str,
        lane_key: &str,
        beneficiary_commitment: &str,
        budget_units: u64,
        max_fee_per_job_units: u64,
        starts_at_height: u64,
        expires_at_height: u64,
        eligibility_records: &[Value],
    ) -> ProverMarketResult<Self> {
        if sponsor_label.is_empty() {
            return Err("sponsor label is required".to_string());
        }
        if lane_key.is_empty() {
            return Err("sponsorship lane key is required".to_string());
        }
        if beneficiary_commitment.is_empty() {
            return Err("sponsorship beneficiary commitment is required".to_string());
        }
        if budget_units == 0 {
            return Err("sponsorship budget must be nonzero".to_string());
        }
        if max_fee_per_job_units == 0 {
            return Err("sponsorship max fee per job must be nonzero".to_string());
        }
        if expires_at_height < starts_at_height {
            return Err("sponsorship expires before it starts".to_string());
        }
        let eligibility_root =
            merkle_root("PROVER-MARKET-SPONSOR-ELIGIBILITY", eligibility_records);
        let sponsorship_id = proof_sponsorship_id(
            sponsor_label,
            lane_key,
            beneficiary_commitment,
            starts_at_height,
            &eligibility_root,
        );
        Ok(Self {
            sponsorship_id,
            sponsor_label: sponsor_label.to_string(),
            lane_key: lane_key.to_string(),
            beneficiary_commitment: beneficiary_commitment.to_string(),
            budget_units,
            spent_units: 0,
            max_fee_per_job_units,
            starts_at_height,
            expires_at_height,
            eligibility_root,
            status: PROVER_MARKET_STATUS_ACTIVE.to_string(),
        })
    }

    pub fn available_budget_units(&self) -> u64 {
        self.budget_units.saturating_sub(self.spent_units)
    }

    pub fn is_active_at(&self, height: u64) -> bool {
        self.status == PROVER_MARKET_STATUS_ACTIVE
            && height >= self.starts_at_height
            && height <= self.expires_at_height
            && self.available_budget_units() > 0
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "proof_sponsorship",
            "chain_id": CHAIN_ID,
            "sponsorship_id": self.sponsorship_id,
            "sponsor_label": self.sponsor_label,
            "lane_key": self.lane_key,
            "beneficiary_commitment": self.beneficiary_commitment,
            "budget_units": self.budget_units,
            "spent_units": self.spent_units,
            "available_budget_units": self.available_budget_units(),
            "max_fee_per_job_units": self.max_fee_per_job_units,
            "starts_at_height": self.starts_at_height,
            "expires_at_height": self.expires_at_height,
            "eligibility_root": self.eligibility_root,
            "status": self.status,
        })
    }

    pub fn sponsorship_root(&self) -> String {
        proof_sponsorship_root(self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofReceipt {
    pub receipt_id: String,
    pub auction_id: String,
    pub bid_id: String,
    pub prover_id: String,
    pub prover_label: String,
    pub proof_system: String,
    pub proof_root: String,
    pub public_input_root: String,
    pub verification_key_root: String,
    pub proof_bytes: u64,
    pub completed_at_height: u64,
    pub latency_blocks: u64,
    pub fee_paid_units: u64,
    pub sponsored_units: u64,
    pub penalty_units: u64,
    pub recursive_parent_id: Option<String>,
    pub status: String,
}

impl ProofReceipt {
    pub fn new(
        auction: &ProofJobAuction,
        bid: &ProverBid,
        proof_root: &str,
        verification_key_root: &str,
        proof_bytes: u64,
        completed_at_height: u64,
        sponsored_units: u64,
        penalty_units: u64,
        recursive_parent_id: Option<String>,
    ) -> ProverMarketResult<Self> {
        if proof_root.is_empty() {
            return Err("proof receipt root is required".to_string());
        }
        if verification_key_root.is_empty() {
            return Err("proof receipt verification key root is required".to_string());
        }
        if proof_bytes == 0 {
            return Err("proof receipt bytes must be nonzero".to_string());
        }
        let latency_blocks = completed_at_height.saturating_sub(auction.opened_at_height);
        let receipt_id = proof_receipt_id(
            &auction.auction_id,
            &bid.bid_id,
            proof_root,
            completed_at_height,
        );
        Ok(Self {
            receipt_id,
            auction_id: auction.auction_id.clone(),
            bid_id: bid.bid_id.clone(),
            prover_id: bid.prover_id.clone(),
            prover_label: bid.prover_label.clone(),
            proof_system: auction.workload.proof_system.clone(),
            proof_root: proof_root.to_string(),
            public_input_root: auction.workload.public_input_root.clone(),
            verification_key_root: verification_key_root.to_string(),
            proof_bytes,
            completed_at_height,
            latency_blocks,
            fee_paid_units: bid.bid_fee_units,
            sponsored_units,
            penalty_units,
            recursive_parent_id,
            status: PROVER_MARKET_STATUS_FINALIZED.to_string(),
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "proof_receipt",
            "chain_id": CHAIN_ID,
            "receipt_id": self.receipt_id,
            "auction_id": self.auction_id,
            "bid_id": self.bid_id,
            "prover_id": self.prover_id,
            "prover_label": self.prover_label,
            "proof_system": self.proof_system,
            "proof_root": self.proof_root,
            "public_input_root": self.public_input_root,
            "verification_key_root": self.verification_key_root,
            "proof_bytes": self.proof_bytes,
            "completed_at_height": self.completed_at_height,
            "latency_blocks": self.latency_blocks,
            "fee_paid_units": self.fee_paid_units,
            "sponsored_units": self.sponsored_units,
            "penalty_units": self.penalty_units,
            "recursive_parent_id": self.recursive_parent_id,
            "status": self.status,
        })
    }

    pub fn receipt_root(&self) -> String {
        proof_receipt_root(self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecursiveBatchMarket {
    pub batch_id: String,
    pub coordinator_label: String,
    pub proof_system: String,
    pub receipt_ids: Vec<String>,
    pub auction_ids: Vec<String>,
    pub input_root: String,
    pub receipt_root: String,
    pub aggregate_public_input_root: String,
    pub max_fee_units: u64,
    pub aggregation_fee_units: u64,
    pub opened_at_height: u64,
    pub deadline_height: u64,
    pub status: String,
    pub assigned_batch_bid_id: Option<String>,
    pub aggregate_receipt_id: Option<String>,
}

impl RecursiveBatchMarket {
    pub fn new(
        coordinator_label: &str,
        receipts: &[ProofReceipt],
        max_fee_units: u64,
        aggregation_fee_units: u64,
        opened_at_height: u64,
        deadline_height: u64,
    ) -> ProverMarketResult<Self> {
        if coordinator_label.is_empty() {
            return Err("batch coordinator label is required".to_string());
        }
        if receipts.is_empty() {
            return Err("recursive batch requires at least one receipt".to_string());
        }
        if max_fee_units == 0 {
            return Err("recursive batch max fee must be nonzero".to_string());
        }
        if aggregation_fee_units > max_fee_units {
            return Err("recursive batch aggregation fee exceeds max fee".to_string());
        }
        if deadline_height < opened_at_height {
            return Err("recursive batch deadline is before open height".to_string());
        }
        let mut receipt_ids = receipts
            .iter()
            .map(|receipt| receipt.receipt_id.clone())
            .collect::<Vec<_>>();
        receipt_ids.sort();
        let mut auction_ids = receipts
            .iter()
            .map(|receipt| receipt.auction_id.clone())
            .collect::<Vec<_>>();
        auction_ids.sort();
        auction_ids.dedup();
        let receipt_records = receipts
            .iter()
            .map(ProofReceipt::public_record)
            .collect::<Vec<_>>();
        let public_input_records = receipts
            .iter()
            .map(|receipt| {
                json!({
                    "receipt_id": receipt.receipt_id,
                    "public_input_root": receipt.public_input_root,
                    "proof_root": receipt.proof_root,
                })
            })
            .collect::<Vec<_>>();
        let receipt_root = merkle_root("PROVER-MARKET-RECURSIVE-RECEIPT", &receipt_records);
        let aggregate_public_input_root = merkle_root(
            "PROVER-MARKET-RECURSIVE-PUBLIC-INPUT",
            &public_input_records,
        );
        let input_root = domain_hash(
            "PROVER-MARKET-RECURSIVE-INPUT",
            &[
                HashPart::Str(&receipt_root),
                HashPart::Str(&aggregate_public_input_root),
                HashPart::Int(receipts.len() as i128),
            ],
            32,
        );
        let batch_id = recursive_batch_market_id(
            coordinator_label,
            &receipt_root,
            &aggregate_public_input_root,
            opened_at_height,
        );
        Ok(Self {
            batch_id,
            coordinator_label: coordinator_label.to_string(),
            proof_system: PROVER_MARKET_RECURSIVE_PROOF_SYSTEM.to_string(),
            receipt_ids,
            auction_ids,
            input_root,
            receipt_root,
            aggregate_public_input_root,
            max_fee_units,
            aggregation_fee_units,
            opened_at_height,
            deadline_height,
            status: PROVER_MARKET_STATUS_OPEN.to_string(),
            assigned_batch_bid_id: None,
            aggregate_receipt_id: None,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "recursive_batch_market",
            "chain_id": CHAIN_ID,
            "batch_id": self.batch_id,
            "coordinator_label": self.coordinator_label,
            "proof_system": self.proof_system,
            "receipt_ids": self.receipt_ids,
            "auction_ids": self.auction_ids,
            "input_root": self.input_root,
            "receipt_root": self.receipt_root,
            "aggregate_public_input_root": self.aggregate_public_input_root,
            "max_fee_units": self.max_fee_units,
            "aggregation_fee_units": self.aggregation_fee_units,
            "opened_at_height": self.opened_at_height,
            "deadline_height": self.deadline_height,
            "status": self.status,
            "assigned_batch_bid_id": self.assigned_batch_bid_id,
            "aggregate_receipt_id": self.aggregate_receipt_id,
        })
    }

    pub fn batch_root(&self) -> String {
        recursive_batch_market_root(self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecursiveBatchBid {
    pub batch_bid_id: String,
    pub batch_id: String,
    pub prover_id: String,
    pub prover_label: String,
    pub capacity_commitment_id: String,
    pub fee_units: u64,
    pub promised_latency_blocks: u64,
    pub collateral_units: u64,
    pub score: u64,
    pub placed_at_height: u64,
    pub status: String,
}

impl RecursiveBatchBid {
    pub fn new(
        batch: &RecursiveBatchMarket,
        commitment: &ProverCapacityCommitment,
        fee_units: u64,
        promised_latency_blocks: u64,
        collateral_units: u64,
        placed_at_height: u64,
    ) -> ProverMarketResult<Self> {
        if fee_units == 0 {
            return Err("recursive batch bid fee must be nonzero".to_string());
        }
        if fee_units > batch.max_fee_units {
            return Err("recursive batch bid fee exceeds max fee".to_string());
        }
        if !commitment.supports(&batch.proof_system) {
            return Err("capacity does not support recursive proof system".to_string());
        }
        let required_collateral =
            required_bid_collateral_units(fee_units, PROVER_MARKET_MIN_BID_COLLATERAL_BPS);
        if collateral_units < required_collateral {
            return Err("recursive batch bid collateral is below market minimum".to_string());
        }
        let score =
            recursive_batch_bid_score(batch, commitment, fee_units, promised_latency_blocks);
        let batch_bid_id = recursive_batch_bid_id(
            &batch.batch_id,
            &commitment.prover_id,
            &commitment.commitment_id,
            fee_units,
            placed_at_height,
        );
        Ok(Self {
            batch_bid_id,
            batch_id: batch.batch_id.clone(),
            prover_id: commitment.prover_id.clone(),
            prover_label: commitment.prover_label.clone(),
            capacity_commitment_id: commitment.commitment_id.clone(),
            fee_units,
            promised_latency_blocks,
            collateral_units,
            score,
            placed_at_height,
            status: PROVER_MARKET_STATUS_OPEN.to_string(),
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "recursive_batch_bid",
            "chain_id": CHAIN_ID,
            "batch_bid_id": self.batch_bid_id,
            "batch_id": self.batch_id,
            "prover_id": self.prover_id,
            "prover_label": self.prover_label,
            "capacity_commitment_id": self.capacity_commitment_id,
            "fee_units": self.fee_units,
            "promised_latency_blocks": self.promised_latency_blocks,
            "collateral_units": self.collateral_units,
            "score": self.score,
            "placed_at_height": self.placed_at_height,
            "status": self.status,
        })
    }

    pub fn batch_bid_root(&self) -> String {
        recursive_batch_bid_root(self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlaPenalty {
    pub penalty_id: String,
    pub auction_id: String,
    pub bid_id: String,
    pub prover_id: String,
    pub receipt_id: Option<String>,
    pub reason: String,
    pub expected_height: u64,
    pub observed_height: u64,
    pub penalty_units: u64,
    pub sponsor_refund_units: u64,
    pub applied_at_height: u64,
    pub status: String,
}

impl SlaPenalty {
    pub fn new(
        auction: &ProofJobAuction,
        bid: &ProverBid,
        receipt_id: Option<String>,
        reason: &str,
        observed_height: u64,
        penalty_bps: u64,
        sponsored_units: u64,
        applied_at_height: u64,
    ) -> ProverMarketResult<Self> {
        if reason.is_empty() {
            return Err("SLA penalty reason is required".to_string());
        }
        let penalty_units = bid
            .bid_fee_units
            .saturating_mul(penalty_bps)
            .div_ceil(10_000)
            .min(bid.collateral_units);
        let sponsor_refund_units = sponsored_units.min(penalty_units);
        let penalty_id = sla_penalty_id(
            &auction.auction_id,
            &bid.bid_id,
            reason,
            observed_height,
            penalty_units,
        );
        Ok(Self {
            penalty_id,
            auction_id: auction.auction_id.clone(),
            bid_id: bid.bid_id.clone(),
            prover_id: bid.prover_id.clone(),
            receipt_id,
            reason: reason.to_string(),
            expected_height: auction.proof_deadline_height,
            observed_height,
            penalty_units,
            sponsor_refund_units,
            applied_at_height,
            status: PROVER_MARKET_STATUS_APPLIED.to_string(),
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "sla_penalty",
            "chain_id": CHAIN_ID,
            "penalty_id": self.penalty_id,
            "auction_id": self.auction_id,
            "bid_id": self.bid_id,
            "prover_id": self.prover_id,
            "receipt_id": self.receipt_id,
            "reason": self.reason,
            "expected_height": self.expected_height,
            "observed_height": self.observed_height,
            "penalty_units": self.penalty_units,
            "sponsor_refund_units": self.sponsor_refund_units,
            "applied_at_height": self.applied_at_height,
            "status": self.status,
        })
    }

    pub fn penalty_root(&self) -> String {
        sla_penalty_root(self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifierSample {
    pub sample_id: String,
    pub receipt_id: String,
    pub verifier_label: String,
    pub sample_index: u64,
    pub challenge_seed: String,
    pub sampled_public_input_root: String,
    pub expected_proof_root: String,
    pub observed_proof_root: String,
    pub accepted: bool,
    pub sampled_at_height: u64,
    pub response_deadline_height: u64,
    pub status: String,
}

impl VerifierSample {
    pub fn new(
        receipt: &ProofReceipt,
        verifier_label: &str,
        sample_index: u64,
        sampled_at_height: u64,
        response_deadline_height: u64,
    ) -> ProverMarketResult<Self> {
        if verifier_label.is_empty() {
            return Err("verifier label is required".to_string());
        }
        let challenge_seed = verifier_challenge_seed(
            &receipt.receipt_id,
            verifier_label,
            sample_index,
            sampled_at_height,
        );
        let sampled_public_input_root = domain_hash(
            "PROVER-MARKET-SAMPLED-PUBLIC-INPUT",
            &[
                HashPart::Str(&receipt.public_input_root),
                HashPart::Int(sample_index as i128),
                HashPart::Str(&challenge_seed),
            ],
            32,
        );
        let observed_proof_root = domain_hash(
            "PROVER-MARKET-SAMPLED-PROOF",
            &[
                HashPart::Str(&receipt.proof_root),
                HashPart::Str(&sampled_public_input_root),
                HashPart::Int(sample_index as i128),
            ],
            32,
        );
        let expected_proof_root = observed_proof_root.clone();
        let sample_id = verifier_sample_id(
            &receipt.receipt_id,
            verifier_label,
            sample_index,
            &challenge_seed,
        );
        Ok(Self {
            sample_id,
            receipt_id: receipt.receipt_id.clone(),
            verifier_label: verifier_label.to_string(),
            sample_index,
            challenge_seed,
            sampled_public_input_root,
            expected_proof_root,
            observed_proof_root,
            accepted: true,
            sampled_at_height,
            response_deadline_height,
            status: PROVER_MARKET_STATUS_SAMPLED.to_string(),
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "verifier_sample",
            "chain_id": CHAIN_ID,
            "sample_id": self.sample_id,
            "receipt_id": self.receipt_id,
            "verifier_label": self.verifier_label,
            "sample_index": self.sample_index,
            "challenge_seed": self.challenge_seed,
            "sampled_public_input_root": self.sampled_public_input_root,
            "expected_proof_root": self.expected_proof_root,
            "observed_proof_root": self.observed_proof_root,
            "accepted": self.accepted,
            "sampled_at_height": self.sampled_at_height,
            "response_deadline_height": self.response_deadline_height,
            "status": self.status,
        })
    }

    pub fn sample_root(&self) -> String {
        verifier_sample_root(self)
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProverMarketState {
    pub height: u64,
    pub config: ProverMarketConfig,
    pub capacity_commitments: BTreeMap<String, ProverCapacityCommitment>,
    pub auctions: BTreeMap<String, ProofJobAuction>,
    pub bids: BTreeMap<String, ProverBid>,
    pub sponsorships: BTreeMap<String, ProofSponsorship>,
    pub receipts: BTreeMap<String, ProofReceipt>,
    pub recursive_batches: BTreeMap<String, RecursiveBatchMarket>,
    pub recursive_batch_bids: BTreeMap<String, RecursiveBatchBid>,
    pub sla_penalties: BTreeMap<String, SlaPenalty>,
    pub verifier_samples: BTreeMap<String, VerifierSample>,
}

impl ProverMarketState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_config(config: ProverMarketConfig) -> Self {
        Self {
            config,
            ..Self::default()
        }
    }

    pub fn devnet() -> Self {
        let mut state = Self::new();
        state.height = 42;
        let gpu_capacity = ProverCapacityCommitment::new(
            "devnet-gpu-prover-a",
            ProverDeviceKind::Gpu,
            4,
            12,
            vec![
                PROVER_MARKET_STATE_PROOF_SYSTEM.to_string(),
                PROVER_MARKET_PRIVACY_PROOF_SYSTEM.to_string(),
                PROVER_MARKET_RECURSIVE_PROOF_SYSTEM.to_string(),
            ],
            180_000,
            125_000,
            92,
            40,
            240,
            1,
        )
        .expect("devnet gpu capacity");
        let cpu_capacity = ProverCapacityCommitment::new(
            "devnet-cpu-prover-b",
            ProverDeviceKind::Cpu,
            32,
            16,
            vec![
                PROVER_MARKET_STATE_PROOF_SYSTEM.to_string(),
                PROVER_MARKET_RECURSIVE_PROOF_SYSTEM.to_string(),
            ],
            12_500,
            65_000,
            58,
            40,
            240,
            2,
        )
        .expect("devnet cpu capacity");
        state
            .commit_capacity(gpu_capacity.clone())
            .expect("commit gpu capacity");
        state
            .commit_capacity(cpu_capacity.clone())
            .expect("commit cpu capacity");

        let eligibility_records = vec![
            json!({"lane": "low_fee_state_transition", "max_input_count": 4}),
            json!({"lane": "low_fee_state_transition", "beneficiary": "devnet-wallets"}),
        ];
        let sponsorship = ProofSponsorship::new(
            "devnet-foundation",
            "low_fee_state_transition",
            &domain_hash(
                "PROVER-MARKET-DEVNET-BENEFICIARY",
                &[HashPart::Str("devnet-wallets")],
                32,
            ),
            12_500,
            250,
            40,
            160,
            &eligibility_records,
        )
        .expect("devnet sponsorship");
        let sponsorship_id = state
            .add_sponsorship(sponsorship)
            .expect("insert devnet sponsorship")
            .sponsorship_id;

        let workload_a = ProofWorkloadProfile::devnet_state_transition(
            100,
            "devnet-prev-state-root-a",
            "devnet-state-root-a",
            "devnet-tx-root-a",
        );
        let workload_b = ProofWorkloadProfile::devnet_state_transition(
            101,
            "devnet-prev-state-root-b",
            "devnet-state-root-b",
            "devnet-tx-root-b",
        );
        let auction_a = ProofJobAuction::new(
            "devnet-sequencer",
            "low_fee_state_transition",
            workload_a,
            "xmr-devnet",
            420,
            80,
            10,
            42,
            2,
            6,
            Some(sponsorship_id.clone()),
        )
        .expect("devnet auction a");
        let auction_b = ProofJobAuction::new(
            "devnet-sequencer",
            "low_fee_state_transition",
            workload_b,
            "xmr-devnet",
            390,
            75,
            8,
            43,
            2,
            6,
            Some(sponsorship_id),
        )
        .expect("devnet auction b");
        let auction_a_id = state
            .open_auction(auction_a)
            .expect("open auction a")
            .auction_id;
        let auction_b_id = state
            .open_auction(auction_b)
            .expect("open auction b")
            .auction_id;
        state.height = 43;
        let bid_a = state
            .place_bid(&auction_a_id, &gpu_capacity.commitment_id, 160, 3, 80, 43)
            .expect("devnet bid a");
        state
            .place_bid(&auction_a_id, &gpu_capacity.commitment_id, 148, 4, 70, 43)
            .expect("devnet bid b");
        let bid_b = state
            .place_bid(&auction_b_id, &gpu_capacity.commitment_id, 155, 3, 80, 44)
            .expect("devnet bid c");
        state.height = 45;
        state
            .settle_auction(&auction_a_id)
            .expect("settle auction a");
        state
            .settle_auction(&auction_b_id)
            .expect("settle auction b");
        state.height = 49;
        let receipt_a = state
            .record_proof_receipt(
                &auction_a_id,
                &bid_a.bid_id,
                &domain_hash(
                    "PROVER-MARKET-DEVNET-PROOF-A",
                    &[HashPart::Str(&auction_a_id), HashPart::Str(&bid_a.bid_id)],
                    32,
                ),
                "devnet-vk-root-a",
                192_000,
                49,
            )
            .expect("devnet receipt a");
        state.height = 53;
        let receipt_b = state
            .record_proof_receipt(
                &auction_b_id,
                &bid_b.bid_id,
                &domain_hash(
                    "PROVER-MARKET-DEVNET-PROOF-B",
                    &[HashPart::Str(&auction_b_id), HashPart::Str(&bid_b.bid_id)],
                    32,
                ),
                "devnet-vk-root-b",
                194_000,
                53,
            )
            .expect("devnet receipt b");
        let batch = state
            .open_recursive_batch_market(
                "devnet-batch-coordinator",
                &[receipt_a.receipt_id.clone(), receipt_b.receipt_id.clone()],
                210,
                120,
                53,
                58,
            )
            .expect("open devnet recursive batch");
        state.height = 54;
        let batch_bid = state
            .place_recursive_batch_bid(&batch.batch_id, &gpu_capacity.commitment_id, 140, 2, 70, 54)
            .expect("devnet recursive batch bid");
        state
            .place_recursive_batch_bid(&batch.batch_id, &cpu_capacity.commitment_id, 118, 4, 50, 54)
            .expect("devnet cpu recursive batch bid");
        state
            .settle_recursive_batch_market(&batch.batch_id)
            .expect("settle devnet batch");
        state.height = 56;
        state
            .record_recursive_receipt(
                &batch.batch_id,
                &batch_bid.batch_bid_id,
                "devnet-recursive-vk-root",
                128_000,
                56,
            )
            .expect("record devnet recursive receipt");
        state
            .sample_receipt(
                &receipt_a.receipt_id,
                &[
                    "devnet-verifier-a".to_string(),
                    "devnet-verifier-b".to_string(),
                    "devnet-verifier-c".to_string(),
                ],
                5,
                50,
            )
            .expect("sample devnet receipt");
        state
    }

    pub fn set_height(&mut self, height: u64) {
        self.height = height;
    }

    pub fn commit_capacity(
        &mut self,
        commitment: ProverCapacityCommitment,
    ) -> ProverMarketResult<ProverCapacityCommitment> {
        if commitment.stake_locked_units < self.config.min_capacity_stake_units {
            return Err("capacity commitment stake is below configured minimum".to_string());
        }
        self.capacity_commitments
            .insert(commitment.commitment_id.clone(), commitment.clone());
        Ok(commitment)
    }

    pub fn add_sponsorship(
        &mut self,
        sponsorship: ProofSponsorship,
    ) -> ProverMarketResult<ProofSponsorship> {
        if sponsorship.budget_units == 0 {
            return Err("sponsorship budget must be nonzero".to_string());
        }
        self.sponsorships
            .insert(sponsorship.sponsorship_id.clone(), sponsorship.clone());
        Ok(sponsorship)
    }

    pub fn open_auction(
        &mut self,
        auction: ProofJobAuction,
    ) -> ProverMarketResult<ProofJobAuction> {
        if let Some(sponsorship_id) = auction.sponsorship_id.as_ref() {
            let sponsorship = self
                .sponsorships
                .get(sponsorship_id)
                .ok_or_else(|| "unknown proof sponsorship".to_string())?;
            if !sponsorship.is_active_at(auction.opened_at_height) {
                return Err("proof sponsorship is not active for auction".to_string());
            }
            if sponsorship.lane_key != auction.job_kind {
                return Err("proof sponsorship lane does not match auction job kind".to_string());
            }
        }
        self.auctions
            .insert(auction.auction_id.clone(), auction.clone());
        Ok(auction)
    }

    pub fn attach_sponsorship(
        &mut self,
        auction_id: &str,
        sponsorship_id: &str,
    ) -> ProverMarketResult<ProofJobAuction> {
        let sponsorship = self
            .sponsorships
            .get(sponsorship_id)
            .cloned()
            .ok_or_else(|| "unknown proof sponsorship".to_string())?;
        let auction = self
            .auctions
            .get_mut(auction_id)
            .ok_or_else(|| "unknown proof auction".to_string())?;
        if auction.status != PROVER_MARKET_STATUS_OPEN {
            return Err("only open auctions can receive sponsorship".to_string());
        }
        if !sponsorship.is_active_at(self.height) {
            return Err("proof sponsorship is not active".to_string());
        }
        if sponsorship.lane_key != auction.job_kind {
            return Err("proof sponsorship lane does not match auction job kind".to_string());
        }
        auction.sponsorship_id = Some(sponsorship_id.to_string());
        Ok(auction.clone())
    }

    pub fn place_bid(
        &mut self,
        auction_id: &str,
        capacity_commitment_id: &str,
        bid_fee_units: u64,
        promised_latency_blocks: u64,
        collateral_units: u64,
        estimated_start_height: u64,
    ) -> ProverMarketResult<ProverBid> {
        let auction = self
            .auctions
            .get(auction_id)
            .cloned()
            .ok_or_else(|| "unknown proof auction".to_string())?;
        if !auction.accepts_bids_at(self.height) {
            return Err("proof auction is not accepting bids".to_string());
        }
        let commitment = self
            .capacity_commitments
            .get(capacity_commitment_id)
            .cloned()
            .ok_or_else(|| "unknown capacity commitment".to_string())?;
        if !commitment.is_active_at(self.height) {
            return Err("capacity commitment is not active".to_string());
        }
        if !commitment.supports(&auction.workload.proof_system) {
            return Err("capacity commitment does not support auction proof system".to_string());
        }
        if auction.workload.requires_gpu && !commitment.device_kind.is_gpu() {
            return Err("auction workload requires GPU capacity".to_string());
        }
        let active_assignments = self.active_assignment_count(&commitment.prover_id);
        if active_assignments >= commitment.max_queue_depth {
            return Err("capacity commitment queue is full".to_string());
        }
        let bid = ProverBid::new(
            &auction,
            &commitment,
            bid_fee_units,
            promised_latency_blocks,
            collateral_units,
            estimated_start_height,
            self.height,
        )?;
        self.bids.insert(bid.bid_id.clone(), bid.clone());
        Ok(bid)
    }

    pub fn settle_auction(&mut self, auction_id: &str) -> ProverMarketResult<ProverBid> {
        let auction = self
            .auctions
            .get(auction_id)
            .cloned()
            .ok_or_else(|| "unknown proof auction".to_string())?;
        if auction.status != PROVER_MARKET_STATUS_OPEN {
            return Err("proof auction is not open".to_string());
        }
        if self.height < auction.bid_deadline_height {
            return Err("proof auction bid window is still open".to_string());
        }
        let mut candidates = self
            .bids
            .values()
            .filter(|bid| {
                bid.auction_id == auction.auction_id && bid.status == PROVER_MARKET_STATUS_OPEN
            })
            .cloned()
            .collect::<Vec<_>>();
        if candidates.is_empty() {
            return Err("proof auction has no open bids".to_string());
        }
        candidates.sort_by(|left, right| {
            right
                .score
                .cmp(&left.score)
                .then_with(|| left.bid_fee_units.cmp(&right.bid_fee_units))
                .then_with(|| {
                    left.promised_latency_blocks
                        .cmp(&right.promised_latency_blocks)
                })
                .then_with(|| left.bid_id.cmp(&right.bid_id))
        });
        let winner = candidates[0].clone();
        for candidate in candidates {
            if let Some(bid) = self.bids.get_mut(&candidate.bid_id) {
                bid.status = if candidate.bid_id == winner.bid_id {
                    PROVER_MARKET_STATUS_ACCEPTED.to_string()
                } else {
                    PROVER_MARKET_STATUS_REJECTED.to_string()
                };
            }
        }
        let auction_mut = self
            .auctions
            .get_mut(auction_id)
            .ok_or_else(|| "unknown proof auction".to_string())?;
        auction_mut.status = PROVER_MARKET_STATUS_ASSIGNED.to_string();
        auction_mut.winning_bid_id = Some(winner.bid_id.clone());
        Ok(self
            .bids
            .get(&winner.bid_id)
            .cloned()
            .ok_or_else(|| "winner bid missing after settlement".to_string())?)
    }

    pub fn record_proof_receipt(
        &mut self,
        auction_id: &str,
        bid_id: &str,
        proof_root: &str,
        verification_key_root: &str,
        proof_bytes: u64,
        completed_at_height: u64,
    ) -> ProverMarketResult<ProofReceipt> {
        let auction = self
            .auctions
            .get(auction_id)
            .cloned()
            .ok_or_else(|| "unknown proof auction".to_string())?;
        if auction.status != PROVER_MARKET_STATUS_ASSIGNED {
            return Err("proof auction is not assigned".to_string());
        }
        if auction.winning_bid_id.as_deref() != Some(bid_id) {
            return Err("proof receipt does not match winning bid".to_string());
        }
        let bid = self
            .bids
            .get(bid_id)
            .cloned()
            .ok_or_else(|| "unknown prover bid".to_string())?;
        if bid.status != PROVER_MARKET_STATUS_ACCEPTED {
            return Err("proof receipt bid is not accepted".to_string());
        }
        let sponsored_units = self.sponsored_units_for(&auction, bid.bid_fee_units);
        let penalty_units = if auction.proof_is_late(completed_at_height) {
            bid.bid_fee_units
                .saturating_mul(self.config.late_penalty_bps)
                .div_ceil(10_000)
                .min(bid.collateral_units)
        } else {
            0
        };
        let receipt = ProofReceipt::new(
            &auction,
            &bid,
            proof_root,
            verification_key_root,
            proof_bytes,
            completed_at_height,
            sponsored_units,
            penalty_units,
            None,
        )?;
        self.spend_sponsorship(&auction, sponsored_units)?;
        if penalty_units > 0 {
            let penalty = SlaPenalty::new(
                &auction,
                &bid,
                Some(receipt.receipt_id.clone()),
                "late_proof",
                completed_at_height,
                self.config.late_penalty_bps,
                sponsored_units,
                self.height.max(completed_at_height),
            )?;
            self.sla_penalties
                .insert(penalty.penalty_id.clone(), penalty);
        }
        if let Some(auction_mut) = self.auctions.get_mut(auction_id) {
            auction_mut.status = PROVER_MARKET_STATUS_FINALIZED.to_string();
            auction_mut.receipt_id = Some(receipt.receipt_id.clone());
        }
        if let Some(bid_mut) = self.bids.get_mut(bid_id) {
            bid_mut.status = PROVER_MARKET_STATUS_FULFILLED.to_string();
        }
        self.receipts
            .insert(receipt.receipt_id.clone(), receipt.clone());
        Ok(receipt)
    }

    pub fn apply_sla_penalty(
        &mut self,
        auction_id: &str,
        bid_id: &str,
        reason: &str,
        observed_height: u64,
        penalty_bps: u64,
    ) -> ProverMarketResult<SlaPenalty> {
        let auction = self
            .auctions
            .get(auction_id)
            .cloned()
            .ok_or_else(|| "unknown proof auction".to_string())?;
        let bid = self
            .bids
            .get(bid_id)
            .cloned()
            .ok_or_else(|| "unknown prover bid".to_string())?;
        let receipt_id = auction.receipt_id.clone();
        let sponsored_units = receipt_id
            .as_ref()
            .and_then(|id| self.receipts.get(id))
            .map(|receipt| receipt.sponsored_units)
            .unwrap_or(0);
        let penalty = SlaPenalty::new(
            &auction,
            &bid,
            receipt_id,
            reason,
            observed_height,
            penalty_bps,
            sponsored_units,
            self.height,
        )?;
        self.sla_penalties
            .insert(penalty.penalty_id.clone(), penalty.clone());
        Ok(penalty)
    }

    pub fn open_recursive_batch_market(
        &mut self,
        coordinator_label: &str,
        receipt_ids: &[String],
        max_fee_units: u64,
        aggregation_fee_units: u64,
        opened_at_height: u64,
        deadline_height: u64,
    ) -> ProverMarketResult<RecursiveBatchMarket> {
        let receipts = receipt_ids
            .iter()
            .map(|receipt_id| {
                self.receipts
                    .get(receipt_id)
                    .cloned()
                    .ok_or_else(|| "unknown proof receipt for recursive batch".to_string())
            })
            .collect::<ProverMarketResult<Vec<_>>>()?;
        let batch = RecursiveBatchMarket::new(
            coordinator_label,
            &receipts,
            max_fee_units,
            aggregation_fee_units,
            opened_at_height,
            deadline_height,
        )?;
        for receipt in receipts {
            if let Some(auction) = self.auctions.get_mut(&receipt.auction_id) {
                auction.batch_id = Some(batch.batch_id.clone());
            }
        }
        self.recursive_batches
            .insert(batch.batch_id.clone(), batch.clone());
        Ok(batch)
    }

    pub fn place_recursive_batch_bid(
        &mut self,
        batch_id: &str,
        capacity_commitment_id: &str,
        fee_units: u64,
        promised_latency_blocks: u64,
        collateral_units: u64,
        placed_at_height: u64,
    ) -> ProverMarketResult<RecursiveBatchBid> {
        let batch = self
            .recursive_batches
            .get(batch_id)
            .cloned()
            .ok_or_else(|| "unknown recursive batch market".to_string())?;
        if batch.status != PROVER_MARKET_STATUS_OPEN {
            return Err("recursive batch market is not open".to_string());
        }
        if self.height > batch.deadline_height {
            return Err("recursive batch market deadline has passed".to_string());
        }
        let commitment = self
            .capacity_commitments
            .get(capacity_commitment_id)
            .cloned()
            .ok_or_else(|| "unknown capacity commitment".to_string())?;
        if !commitment.is_active_at(self.height) {
            return Err("capacity commitment is not active".to_string());
        }
        let bid = RecursiveBatchBid::new(
            &batch,
            &commitment,
            fee_units,
            promised_latency_blocks,
            collateral_units,
            placed_at_height,
        )?;
        self.recursive_batch_bids
            .insert(bid.batch_bid_id.clone(), bid.clone());
        Ok(bid)
    }

    pub fn settle_recursive_batch_market(
        &mut self,
        batch_id: &str,
    ) -> ProverMarketResult<RecursiveBatchBid> {
        let batch = self
            .recursive_batches
            .get(batch_id)
            .cloned()
            .ok_or_else(|| "unknown recursive batch market".to_string())?;
        if batch.status != PROVER_MARKET_STATUS_OPEN {
            return Err("recursive batch market is not open".to_string());
        }
        let mut candidates = self
            .recursive_batch_bids
            .values()
            .filter(|bid| bid.batch_id == batch.batch_id && bid.status == PROVER_MARKET_STATUS_OPEN)
            .cloned()
            .collect::<Vec<_>>();
        if candidates.is_empty() {
            return Err("recursive batch market has no open bids".to_string());
        }
        candidates.sort_by(|left, right| {
            right
                .score
                .cmp(&left.score)
                .then_with(|| left.fee_units.cmp(&right.fee_units))
                .then_with(|| {
                    left.promised_latency_blocks
                        .cmp(&right.promised_latency_blocks)
                })
                .then_with(|| left.batch_bid_id.cmp(&right.batch_bid_id))
        });
        let winner = candidates[0].clone();
        for candidate in candidates {
            if let Some(bid) = self.recursive_batch_bids.get_mut(&candidate.batch_bid_id) {
                bid.status = if candidate.batch_bid_id == winner.batch_bid_id {
                    PROVER_MARKET_STATUS_ACCEPTED.to_string()
                } else {
                    PROVER_MARKET_STATUS_REJECTED.to_string()
                };
            }
        }
        if let Some(batch_mut) = self.recursive_batches.get_mut(batch_id) {
            batch_mut.status = PROVER_MARKET_STATUS_ASSIGNED.to_string();
            batch_mut.assigned_batch_bid_id = Some(winner.batch_bid_id.clone());
        }
        Ok(self
            .recursive_batch_bids
            .get(&winner.batch_bid_id)
            .cloned()
            .ok_or_else(|| "winner batch bid missing after settlement".to_string())?)
    }

    pub fn record_recursive_receipt(
        &mut self,
        batch_id: &str,
        batch_bid_id: &str,
        verification_key_root: &str,
        proof_bytes: u64,
        completed_at_height: u64,
    ) -> ProverMarketResult<ProofReceipt> {
        let batch = self
            .recursive_batches
            .get(batch_id)
            .cloned()
            .ok_or_else(|| "unknown recursive batch market".to_string())?;
        if batch.status != PROVER_MARKET_STATUS_ASSIGNED {
            return Err("recursive batch market is not assigned".to_string());
        }
        if batch.assigned_batch_bid_id.as_deref() != Some(batch_bid_id) {
            return Err("recursive proof receipt does not match assigned batch bid".to_string());
        }
        let batch_bid = self
            .recursive_batch_bids
            .get(batch_bid_id)
            .cloned()
            .ok_or_else(|| "unknown recursive batch bid".to_string())?;
        let synthetic_workload = ProofWorkloadProfile::new(
            &batch.proof_system,
            "recursive_batch",
            &batch.aggregate_public_input_root,
            &batch.input_root,
            batch.receipt_ids.len() as u64 * 512_000,
            proof_bytes,
            1,
            batch.receipt_ids.len() as u64,
            batch.auction_ids.len() as u64,
            true,
            batch
                .deadline_height
                .saturating_sub(batch.opened_at_height)
                .max(1),
        )?;
        let synthetic_auction = ProofJobAuction {
            auction_id: batch.batch_id.clone(),
            requester_label: batch.coordinator_label.clone(),
            job_kind: "recursive_batch".to_string(),
            workload: synthetic_workload,
            reward_asset_id: "xmr-devnet".to_string(),
            max_fee_units: batch.max_fee_units,
            reserve_fee_units: batch.aggregation_fee_units,
            priority_fee_units: 0,
            opened_at_height: batch.opened_at_height,
            bid_deadline_height: batch.opened_at_height,
            proof_deadline_height: batch.deadline_height,
            sponsorship_id: None,
            status: PROVER_MARKET_STATUS_ASSIGNED.to_string(),
            winning_bid_id: Some(batch_bid.batch_bid_id.clone()),
            receipt_id: None,
            batch_id: Some(batch.batch_id.clone()),
        };
        let synthetic_device_kind = self
            .capacity_commitments
            .get(&batch_bid.capacity_commitment_id)
            .map(|commitment| commitment.device_kind.clone())
            .unwrap_or(ProverDeviceKind::Gpu);
        let synthetic_bid = ProverBid {
            bid_id: batch_bid.batch_bid_id.clone(),
            auction_id: batch.batch_id.clone(),
            prover_id: batch_bid.prover_id.clone(),
            prover_label: batch_bid.prover_label.clone(),
            capacity_commitment_id: batch_bid.capacity_commitment_id.clone(),
            bid_fee_units: batch_bid.fee_units,
            promised_latency_blocks: batch_bid.promised_latency_blocks,
            collateral_units: batch_bid.collateral_units,
            device_kind: synthetic_device_kind,
            estimated_start_height: batch_bid.placed_at_height,
            score: batch_bid.score,
            placed_at_height: batch_bid.placed_at_height,
            status: PROVER_MARKET_STATUS_ACCEPTED.to_string(),
        };
        let aggregate_proof_root = domain_hash(
            "PROVER-MARKET-RECURSIVE-PROOF",
            &[
                HashPart::Str(&batch.input_root),
                HashPart::Str(&batch.receipt_root),
                HashPart::Str(batch_bid_id),
                HashPart::Int(completed_at_height as i128),
            ],
            32,
        );
        let penalty_units = if completed_at_height > batch.deadline_height {
            batch_bid
                .fee_units
                .saturating_mul(self.config.late_penalty_bps)
                .div_ceil(10_000)
                .min(batch_bid.collateral_units)
        } else {
            0
        };
        let receipt = ProofReceipt::new(
            &synthetic_auction,
            &synthetic_bid,
            &aggregate_proof_root,
            verification_key_root,
            proof_bytes,
            completed_at_height,
            0,
            penalty_units,
            Some(batch.batch_id.clone()),
        )?;
        if let Some(batch_mut) = self.recursive_batches.get_mut(batch_id) {
            batch_mut.status = PROVER_MARKET_STATUS_FINALIZED.to_string();
            batch_mut.aggregate_receipt_id = Some(receipt.receipt_id.clone());
        }
        if let Some(batch_bid_mut) = self.recursive_batch_bids.get_mut(batch_bid_id) {
            batch_bid_mut.status = PROVER_MARKET_STATUS_FULFILLED.to_string();
        }
        self.receipts
            .insert(receipt.receipt_id.clone(), receipt.clone());
        Ok(receipt)
    }

    pub fn sample_receipt(
        &mut self,
        receipt_id: &str,
        verifier_labels: &[String],
        sample_count: u64,
        sampled_at_height: u64,
    ) -> ProverMarketResult<Vec<VerifierSample>> {
        let receipt = self
            .receipts
            .get(receipt_id)
            .cloned()
            .ok_or_else(|| "unknown proof receipt".to_string())?;
        if verifier_labels.is_empty() {
            return Err("at least one verifier label is required".to_string());
        }
        let population = receipt
            .proof_bytes
            .div_ceil(64)
            .min(self.config.max_sample_population)
            .max(1);
        let seed = verifier_challenge_seed(
            &receipt.receipt_id,
            &verifier_labels.join("|"),
            sample_count,
            sampled_at_height,
        );
        let sample_indices = derive_verifier_sample_indices(&seed, population, sample_count.max(1));
        let mut samples = Vec::with_capacity(sample_indices.len());
        for (position, sample_index) in sample_indices.into_iter().enumerate() {
            let verifier_label = &verifier_labels[position % verifier_labels.len()];
            let sample = VerifierSample::new(
                &receipt,
                verifier_label,
                sample_index,
                sampled_at_height,
                sampled_at_height.saturating_add(2),
            )?;
            self.verifier_samples
                .insert(sample.sample_id.clone(), sample.clone());
            samples.push(sample);
        }
        Ok(samples)
    }

    pub fn capacity_commitment_root(&self) -> String {
        merkle_root(
            "PROVER-MARKET-CAPACITY-COMMITMENT",
            &self
                .capacity_commitments
                .values()
                .map(ProverCapacityCommitment::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn auction_root(&self) -> String {
        merkle_root(
            "PROVER-MARKET-AUCTION",
            &self
                .auctions
                .values()
                .map(ProofJobAuction::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn bid_root(&self) -> String {
        merkle_root(
            "PROVER-MARKET-BID",
            &self
                .bids
                .values()
                .map(ProverBid::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn sponsorship_root(&self) -> String {
        merkle_root(
            "PROVER-MARKET-SPONSORSHIP",
            &self
                .sponsorships
                .values()
                .map(ProofSponsorship::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn receipt_root(&self) -> String {
        merkle_root(
            "PROVER-MARKET-RECEIPT",
            &self
                .receipts
                .values()
                .map(ProofReceipt::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn recursive_batch_root(&self) -> String {
        merkle_root(
            "PROVER-MARKET-RECURSIVE-BATCH",
            &self
                .recursive_batches
                .values()
                .map(RecursiveBatchMarket::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn recursive_batch_bid_root(&self) -> String {
        merkle_root(
            "PROVER-MARKET-RECURSIVE-BATCH-BID",
            &self
                .recursive_batch_bids
                .values()
                .map(RecursiveBatchBid::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn sla_penalty_root(&self) -> String {
        merkle_root(
            "PROVER-MARKET-SLA-PENALTY",
            &self
                .sla_penalties
                .values()
                .map(SlaPenalty::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn verifier_sample_root(&self) -> String {
        merkle_root(
            "PROVER-MARKET-VERIFIER-SAMPLE",
            &self
                .verifier_samples
                .values()
                .map(VerifierSample::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn state_root(&self) -> String {
        prover_market_state_root_from_record(&self.public_record_without_root())
    }

    pub fn pending_auction_count(&self) -> u64 {
        self.auctions
            .values()
            .filter(|auction| {
                auction.status == PROVER_MARKET_STATUS_OPEN
                    || auction.status == PROVER_MARKET_STATUS_ASSIGNED
            })
            .count() as u64
    }

    pub fn active_capacity_count(&self) -> u64 {
        self.capacity_commitments
            .values()
            .filter(|commitment| commitment.is_active_at(self.height))
            .count() as u64
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_root();
        record
            .as_object_mut()
            .expect("prover market state record object")
            .insert("state_root".to_string(), Value::String(self.state_root()));
        record
    }

    fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "prover_market_state",
            "chain_id": CHAIN_ID,
            "height": self.height,
            "config": self.config.public_record(),
            "config_root": self.config.config_root(),
            "capacity_commitment_root": self.capacity_commitment_root(),
            "auction_root": self.auction_root(),
            "bid_root": self.bid_root(),
            "sponsorship_root": self.sponsorship_root(),
            "receipt_root": self.receipt_root(),
            "recursive_batch_root": self.recursive_batch_root(),
            "recursive_batch_bid_root": self.recursive_batch_bid_root(),
            "sla_penalty_root": self.sla_penalty_root(),
            "verifier_sample_root": self.verifier_sample_root(),
            "capacity_commitment_count": self.capacity_commitments.len() as u64,
            "active_capacity_count": self.active_capacity_count(),
            "auction_count": self.auctions.len() as u64,
            "pending_auction_count": self.pending_auction_count(),
            "bid_count": self.bids.len() as u64,
            "sponsorship_count": self.sponsorships.len() as u64,
            "receipt_count": self.receipts.len() as u64,
            "recursive_batch_count": self.recursive_batches.len() as u64,
            "recursive_batch_bid_count": self.recursive_batch_bids.len() as u64,
            "sla_penalty_count": self.sla_penalties.len() as u64,
            "verifier_sample_count": self.verifier_samples.len() as u64,
        })
    }

    fn active_assignment_count(&self, prover_id: &str) -> u64 {
        let proof_assignments = self
            .bids
            .values()
            .filter(|bid| bid.prover_id == prover_id && bid.status == PROVER_MARKET_STATUS_ACCEPTED)
            .count() as u64;
        let batch_assignments = self
            .recursive_batch_bids
            .values()
            .filter(|bid| bid.prover_id == prover_id && bid.status == PROVER_MARKET_STATUS_ACCEPTED)
            .count() as u64;
        proof_assignments.saturating_add(batch_assignments)
    }

    fn sponsored_units_for(&self, auction: &ProofJobAuction, bid_fee_units: u64) -> u64 {
        auction
            .sponsorship_id
            .as_ref()
            .and_then(|id| self.sponsorships.get(id))
            .filter(|sponsorship| {
                sponsorship.is_active_at(self.height.max(auction.opened_at_height))
            })
            .map(|sponsorship| {
                sponsorship
                    .available_budget_units()
                    .min(sponsorship.max_fee_per_job_units)
                    .min(bid_fee_units)
            })
            .unwrap_or(0)
    }

    fn spend_sponsorship(
        &mut self,
        auction: &ProofJobAuction,
        sponsored_units: u64,
    ) -> ProverMarketResult<()> {
        if sponsored_units == 0 {
            return Ok(());
        }
        let sponsorship_id = auction
            .sponsorship_id
            .as_ref()
            .ok_or_else(|| "auction has no sponsorship".to_string())?;
        let sponsorship = self
            .sponsorships
            .get_mut(sponsorship_id)
            .ok_or_else(|| "unknown proof sponsorship".to_string())?;
        sponsorship.spent_units = sponsorship.spent_units.saturating_add(sponsored_units);
        if sponsorship.available_budget_units() == 0 {
            sponsorship.status = PROVER_MARKET_STATUS_EXHAUSTED.to_string();
        }
        Ok(())
    }
}

pub fn prover_market_prover_id(prover_label: &str) -> String {
    domain_hash(
        "PROVER-MARKET-PROVER-ID",
        &[HashPart::Str(CHAIN_ID), HashPart::Str(prover_label)],
        32,
    )
}

pub fn prover_capacity_commitment_id(
    prover_id: &str,
    device_kind: &str,
    availability_start_height: u64,
    availability_end_height: u64,
    nonce: u64,
) -> String {
    domain_hash(
        "PROVER-MARKET-CAPACITY-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(prover_id),
            HashPart::Str(device_kind),
            HashPart::Int(availability_start_height as i128),
            HashPart::Int(availability_end_height as i128),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn proof_workload_id(
    proof_system: &str,
    circuit_family: &str,
    public_input_root: &str,
    witness_commitment: &str,
    recursion_depth: u64,
) -> String {
    domain_hash(
        "PROVER-MARKET-WORKLOAD-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(proof_system),
            HashPart::Str(circuit_family),
            HashPart::Str(public_input_root),
            HashPart::Str(witness_commitment),
            HashPart::Int(recursion_depth as i128),
        ],
        32,
    )
}

pub fn proof_job_auction_id(
    requester_label: &str,
    job_kind: &str,
    workload_root: &str,
    opened_at_height: u64,
    max_fee_units: u64,
) -> String {
    domain_hash(
        "PROVER-MARKET-AUCTION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(requester_label),
            HashPart::Str(job_kind),
            HashPart::Str(workload_root),
            HashPart::Int(opened_at_height as i128),
            HashPart::Int(max_fee_units as i128),
        ],
        32,
    )
}

pub fn prover_bid_id(
    auction_id: &str,
    prover_id: &str,
    capacity_commitment_id: &str,
    bid_fee_units: u64,
    placed_at_height: u64,
) -> String {
    domain_hash(
        "PROVER-MARKET-BID-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(auction_id),
            HashPart::Str(prover_id),
            HashPart::Str(capacity_commitment_id),
            HashPart::Int(bid_fee_units as i128),
            HashPart::Int(placed_at_height as i128),
        ],
        32,
    )
}

pub fn proof_sponsorship_id(
    sponsor_label: &str,
    lane_key: &str,
    beneficiary_commitment: &str,
    starts_at_height: u64,
    eligibility_root: &str,
) -> String {
    domain_hash(
        "PROVER-MARKET-SPONSORSHIP-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(sponsor_label),
            HashPart::Str(lane_key),
            HashPart::Str(beneficiary_commitment),
            HashPart::Int(starts_at_height as i128),
            HashPart::Str(eligibility_root),
        ],
        32,
    )
}

pub fn proof_receipt_id(
    auction_id: &str,
    bid_id: &str,
    proof_root: &str,
    completed_at_height: u64,
) -> String {
    domain_hash(
        "PROVER-MARKET-RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(auction_id),
            HashPart::Str(bid_id),
            HashPart::Str(proof_root),
            HashPart::Int(completed_at_height as i128),
        ],
        32,
    )
}

pub fn recursive_batch_market_id(
    coordinator_label: &str,
    receipt_root: &str,
    aggregate_public_input_root: &str,
    opened_at_height: u64,
) -> String {
    domain_hash(
        "PROVER-MARKET-RECURSIVE-BATCH-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(coordinator_label),
            HashPart::Str(receipt_root),
            HashPart::Str(aggregate_public_input_root),
            HashPart::Int(opened_at_height as i128),
        ],
        32,
    )
}

pub fn recursive_batch_bid_id(
    batch_id: &str,
    prover_id: &str,
    capacity_commitment_id: &str,
    fee_units: u64,
    placed_at_height: u64,
) -> String {
    domain_hash(
        "PROVER-MARKET-RECURSIVE-BID-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(batch_id),
            HashPart::Str(prover_id),
            HashPart::Str(capacity_commitment_id),
            HashPart::Int(fee_units as i128),
            HashPart::Int(placed_at_height as i128),
        ],
        32,
    )
}

pub fn sla_penalty_id(
    auction_id: &str,
    bid_id: &str,
    reason: &str,
    observed_height: u64,
    penalty_units: u64,
) -> String {
    domain_hash(
        "PROVER-MARKET-SLA-PENALTY-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(auction_id),
            HashPart::Str(bid_id),
            HashPart::Str(reason),
            HashPart::Int(observed_height as i128),
            HashPart::Int(penalty_units as i128),
        ],
        32,
    )
}

pub fn verifier_challenge_seed(
    receipt_id: &str,
    verifier_label: &str,
    sample_index: u64,
    sampled_at_height: u64,
) -> String {
    domain_hash(
        "PROVER-MARKET-VERIFIER-CHALLENGE",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(receipt_id),
            HashPart::Str(verifier_label),
            HashPart::Int(sample_index as i128),
            HashPart::Int(sampled_at_height as i128),
        ],
        32,
    )
}

pub fn verifier_sample_id(
    receipt_id: &str,
    verifier_label: &str,
    sample_index: u64,
    challenge_seed: &str,
) -> String {
    domain_hash(
        "PROVER-MARKET-VERIFIER-SAMPLE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(receipt_id),
            HashPart::Str(verifier_label),
            HashPart::Int(sample_index as i128),
            HashPart::Str(challenge_seed),
        ],
        32,
    )
}

pub fn prover_capacity_commitment_root(commitment: &ProverCapacityCommitment) -> String {
    domain_hash(
        "PROVER-MARKET-CAPACITY-COMMITMENT",
        &[HashPart::Json(&commitment.public_record())],
        32,
    )
}

pub fn proof_workload_root(workload: &ProofWorkloadProfile) -> String {
    domain_hash(
        "PROVER-MARKET-WORKLOAD",
        &[HashPart::Json(&workload.public_record())],
        32,
    )
}

pub fn proof_job_auction_root(auction: &ProofJobAuction) -> String {
    domain_hash(
        "PROVER-MARKET-AUCTION",
        &[HashPart::Json(&auction.public_record())],
        32,
    )
}

pub fn prover_bid_root(bid: &ProverBid) -> String {
    domain_hash(
        "PROVER-MARKET-BID",
        &[HashPart::Json(&bid.public_record())],
        32,
    )
}

pub fn proof_sponsorship_root(sponsorship: &ProofSponsorship) -> String {
    domain_hash(
        "PROVER-MARKET-SPONSORSHIP",
        &[HashPart::Json(&sponsorship.public_record())],
        32,
    )
}

pub fn proof_receipt_root(receipt: &ProofReceipt) -> String {
    domain_hash(
        "PROVER-MARKET-RECEIPT",
        &[HashPart::Json(&receipt.public_record())],
        32,
    )
}

pub fn recursive_batch_market_root(batch: &RecursiveBatchMarket) -> String {
    domain_hash(
        "PROVER-MARKET-RECURSIVE-BATCH",
        &[HashPart::Json(&batch.public_record())],
        32,
    )
}

pub fn recursive_batch_bid_root(bid: &RecursiveBatchBid) -> String {
    domain_hash(
        "PROVER-MARKET-RECURSIVE-BATCH-BID",
        &[HashPart::Json(&bid.public_record())],
        32,
    )
}

pub fn sla_penalty_root(penalty: &SlaPenalty) -> String {
    domain_hash(
        "PROVER-MARKET-SLA-PENALTY",
        &[HashPart::Json(&penalty.public_record())],
        32,
    )
}

pub fn verifier_sample_root(sample: &VerifierSample) -> String {
    domain_hash(
        "PROVER-MARKET-VERIFIER-SAMPLE",
        &[HashPart::Json(&sample.public_record())],
        32,
    )
}

pub fn prover_market_state_root(state: &ProverMarketState) -> String {
    state.state_root()
}

pub fn prover_market_state_root_from_record(record: &Value) -> String {
    domain_hash("PROVER-MARKET-STATE", &[HashPart::Json(record)], 32)
}

pub fn required_bid_collateral_units(bid_fee_units: u64, collateral_bps: u64) -> u64 {
    bid_fee_units
        .saturating_mul(collateral_bps)
        .div_ceil(10_000)
}

pub fn estimated_proof_fee_units(workload: &ProofWorkloadProfile, congestion_bps: u64) -> u64 {
    let base_units = 24_u64;
    let row_units = workload.estimated_rows.div_ceil(65_536);
    let byte_units = workload.estimated_proof_bytes.div_ceil(4_096);
    let recursion_units = workload.recursion_depth.saturating_mul(35);
    let privacy_units = workload.privacy_input_count.saturating_mul(9);
    let transition_units = workload.state_transition_count.saturating_mul(18);
    let raw_fee = base_units
        .saturating_add(row_units)
        .saturating_add(byte_units)
        .saturating_add(recursion_units)
        .saturating_add(privacy_units)
        .saturating_add(transition_units);
    raw_fee.saturating_mul(10_000_u64.saturating_add(congestion_bps)) / 10_000
}

pub fn prover_bid_score(
    auction: &ProofJobAuction,
    commitment: &ProverCapacityCommitment,
    bid_fee_units: u64,
    promised_latency_blocks: u64,
    collateral_units: u64,
) -> u64 {
    let price_component = auction
        .max_fee_units
        .saturating_sub(bid_fee_units)
        .saturating_mul(20_000)
        / auction.max_fee_units.max(1);
    let latency_component = auction
        .workload
        .requested_latency_blocks
        .saturating_sub(promised_latency_blocks)
        .saturating_mul(2_000);
    let compute_component = commitment.effective_compute_units().saturating_mul(1_000)
        / auction.workload.compute_units().max(1);
    let collateral_component =
        collateral_units.min(bid_fee_units).saturating_mul(2_000) / bid_fee_units.max(1);
    let device_component = if auction.workload.requires_gpu && commitment.device_kind.is_gpu() {
        5_000
    } else {
        1_000
    };
    price_component
        .saturating_add(latency_component)
        .saturating_add(compute_component)
        .saturating_add(collateral_component)
        .saturating_add(device_component)
        .saturating_add(auction.priority_fee_units)
}

pub fn recursive_batch_bid_score(
    batch: &RecursiveBatchMarket,
    commitment: &ProverCapacityCommitment,
    fee_units: u64,
    promised_latency_blocks: u64,
) -> u64 {
    let price_component = batch
        .max_fee_units
        .saturating_sub(fee_units)
        .saturating_mul(20_000)
        / batch.max_fee_units.max(1);
    let latency_budget = batch
        .deadline_height
        .saturating_sub(batch.opened_at_height)
        .max(1);
    let latency_component = latency_budget
        .saturating_sub(promised_latency_blocks)
        .saturating_mul(2_000);
    let receipt_component = (batch.receipt_ids.len() as u64).saturating_mul(500);
    let compute_component = commitment.effective_compute_units().saturating_div(1_000);
    price_component
        .saturating_add(latency_component)
        .saturating_add(receipt_component)
        .saturating_add(compute_component)
}

pub fn derive_verifier_sample_indices(seed: &str, population: u64, sample_count: u64) -> Vec<u64> {
    if population == 0 || sample_count == 0 {
        return Vec::new();
    }
    let target_count = sample_count.min(population);
    let mut indices = BTreeSet::new();
    let mut counter = 0_u64;
    while indices.len() < target_count as usize {
        let candidate_hash = domain_hash(
            "PROVER-MARKET-SAMPLE-INDEX",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(seed),
                HashPart::Int(counter as i128),
            ],
            32,
        );
        let mut candidate = hex_prefix_to_u64(&candidate_hash) % population;
        while indices.contains(&candidate) {
            candidate = (candidate + 1) % population;
        }
        indices.insert(candidate);
        counter = counter.saturating_add(1);
    }
    indices.into_iter().collect()
}

fn hex_prefix_to_u64(value: &str) -> u64 {
    value
        .as_bytes()
        .iter()
        .take(16)
        .fold(0_u64, |accumulator, byte| {
            let nibble = match byte {
                b'0'..=b'9' => (byte - b'0') as u64,
                b'a'..=b'f' => (byte - b'a' + 10) as u64,
                b'A'..=b'F' => (byte - b'A' + 10) as u64,
                _ => 0,
            };
            (accumulator << 4) | nibble
        })
}
