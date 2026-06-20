use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type LowFeeProofBatchSponsorAllocatorResult<T> = Result<T, String>;

pub const LOW_FEE_PROOF_BATCH_SPONSOR_ALLOCATOR_PROTOCOL_VERSION: &str =
    "nebula-low-fee-proof-batch-sponsor-allocator-v1";
pub const LOW_FEE_PROOF_BATCH_SPONSOR_ALLOCATOR_DEFAULT_MAX_USER_FEE_BPS: u64 = 35;
pub const LOW_FEE_PROOF_BATCH_SPONSOR_ALLOCATOR_DEFAULT_TARGET_BATCH_FILL_BPS: u64 = 8_500;
pub const LOW_FEE_PROOF_BATCH_SPONSOR_ALLOCATOR_DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 128;
pub const LOW_FEE_PROOF_BATCH_SPONSOR_ALLOCATOR_DEFAULT_MAX_LATENCY_BLOCKS: u64 = 4;
pub const LOW_FEE_PROOF_BATCH_SPONSOR_ALLOCATOR_DEFAULT_REBATE_EPOCH_BLOCKS: u64 = 720;
pub const LOW_FEE_PROOF_BATCH_SPONSOR_ALLOCATOR_MAX_BPS: u64 = 10_000;
pub const LOW_FEE_PROOF_BATCH_SPONSOR_ALLOCATOR_MAX_PROVERS: usize = 256;
pub const LOW_FEE_PROOF_BATCH_SPONSOR_ALLOCATOR_MAX_SPONSORS: usize = 256;
pub const LOW_FEE_PROOF_BATCH_SPONSOR_ALLOCATOR_MAX_REQUESTS: usize = 2_048;
pub const LOW_FEE_PROOF_BATCH_SPONSOR_ALLOCATOR_MAX_ALLOCATIONS: usize = 2_048;
pub const LOW_FEE_PROOF_BATCH_SPONSOR_ALLOCATOR_DEVNET_HEIGHT: u64 = 67_840;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofClass {
    Transfer,
    ContractCall,
    TokenMint,
    DefiSwap,
    Liquidation,
    BridgeExit,
    RecursiveAggregate,
}

impl ProofClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Transfer => "transfer",
            Self::ContractCall => "contract_call",
            Self::TokenMint => "token_mint",
            Self::DefiSwap => "defi_swap",
            Self::Liquidation => "liquidation",
            Self::BridgeExit => "bridge_exit",
            Self::RecursiveAggregate => "recursive_aggregate",
        }
    }

    pub fn latency_sensitive(self) -> bool {
        matches!(
            self,
            Self::ContractCall | Self::Liquidation | Self::BridgeExit
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorPolicy {
    PublicGoods,
    MarketMaker,
    AppPaymaster,
    BridgeSubsidy,
    EmergencyFeeRelief,
}

impl SponsorPolicy {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PublicGoods => "public_goods",
            Self::MarketMaker => "market_maker",
            Self::AppPaymaster => "app_paymaster",
            Self::BridgeSubsidy => "bridge_subsidy",
            Self::EmergencyFeeRelief => "emergency_fee_relief",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AllocationStatus {
    Pending,
    Assigned,
    Proving,
    Settled,
    Rebatable,
    Expired,
}

impl AllocationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Assigned => "assigned",
            Self::Proving => "proving",
            Self::Settled => "settled",
            Self::Rebatable => "rebatable",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub max_user_fee_bps: u64,
    pub target_batch_fill_bps: u64,
    pub min_privacy_set_size: u64,
    pub max_latency_blocks: u64,
    pub rebate_epoch_blocks: u64,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            max_user_fee_bps: LOW_FEE_PROOF_BATCH_SPONSOR_ALLOCATOR_DEFAULT_MAX_USER_FEE_BPS,
            target_batch_fill_bps:
                LOW_FEE_PROOF_BATCH_SPONSOR_ALLOCATOR_DEFAULT_TARGET_BATCH_FILL_BPS,
            min_privacy_set_size:
                LOW_FEE_PROOF_BATCH_SPONSOR_ALLOCATOR_DEFAULT_MIN_PRIVACY_SET_SIZE,
            max_latency_blocks: LOW_FEE_PROOF_BATCH_SPONSOR_ALLOCATOR_DEFAULT_MAX_LATENCY_BLOCKS,
            rebate_epoch_blocks: LOW_FEE_PROOF_BATCH_SPONSOR_ALLOCATOR_DEFAULT_REBATE_EPOCH_BLOCKS,
        }
    }

    pub fn validate(&self) -> LowFeeProofBatchSponsorAllocatorResult<()> {
        if self.max_user_fee_bps > LOW_FEE_PROOF_BATCH_SPONSOR_ALLOCATOR_MAX_BPS {
            return Err("max user fee cannot exceed 100%".to_string());
        }
        if self.target_batch_fill_bps == 0
            || self.target_batch_fill_bps > LOW_FEE_PROOF_BATCH_SPONSOR_ALLOCATOR_MAX_BPS
        {
            return Err("target batch fill must be within bps range".to_string());
        }
        if self.min_privacy_set_size == 0
            || self.max_latency_blocks == 0
            || self.rebate_epoch_blocks == 0
        {
            return Err("proof sponsor allocator windows must be positive".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "low_fee_proof_batch_sponsor_allocator_config",
            "chain_id": CHAIN_ID,
            "protocol_version": LOW_FEE_PROOF_BATCH_SPONSOR_ALLOCATOR_PROTOCOL_VERSION,
            "max_user_fee_bps": self.max_user_fee_bps,
            "target_batch_fill_bps": self.target_batch_fill_bps,
            "min_privacy_set_size": self.min_privacy_set_size,
            "max_latency_blocks": self.max_latency_blocks,
            "rebate_epoch_blocks": self.rebate_epoch_blocks,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProverLane {
    pub prover_id: String,
    pub label: String,
    pub supported_classes: BTreeSet<ProofClass>,
    pub capacity_weight: u64,
    pub base_fee_piconero: u64,
    pub max_batch_items: u64,
    pub latency_blocks: u64,
    pub pq_attestation_root: String,
}

impl ProverLane {
    pub fn new(
        label: &str,
        supported_classes: BTreeSet<ProofClass>,
        capacity_weight: u64,
        base_fee_piconero: u64,
        max_batch_items: u64,
        latency_blocks: u64,
        pq_attestation_root: &str,
    ) -> LowFeeProofBatchSponsorAllocatorResult<Self> {
        if label.is_empty() || pq_attestation_root.is_empty() {
            return Err("prover lane identifiers cannot be empty".to_string());
        }
        if supported_classes.is_empty() {
            return Err("prover lane must support at least one proof class".to_string());
        }
        if capacity_weight == 0 || max_batch_items == 0 || latency_blocks == 0 {
            return Err("prover lane capacity and latency must be positive".to_string());
        }
        let prover_id = prover_lane_id(
            label,
            &supported_classes,
            capacity_weight,
            base_fee_piconero,
            max_batch_items,
            latency_blocks,
            pq_attestation_root,
        );
        Ok(Self {
            prover_id,
            label: label.to_string(),
            supported_classes,
            capacity_weight,
            base_fee_piconero,
            max_batch_items,
            latency_blocks,
            pq_attestation_root: pq_attestation_root.to_string(),
        })
    }

    pub fn supports(&self, proof_class: ProofClass) -> bool {
        self.supported_classes.contains(&proof_class)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "low_fee_proof_batch_prover_lane",
            "chain_id": CHAIN_ID,
            "protocol_version": LOW_FEE_PROOF_BATCH_SPONSOR_ALLOCATOR_PROTOCOL_VERSION,
            "prover_id": self.prover_id,
            "label": self.label,
            "supported_classes": self.supported_classes.iter().map(|class| class.as_str()).collect::<Vec<_>>(),
            "capacity_weight": self.capacity_weight,
            "base_fee_piconero": self.base_fee_piconero,
            "max_batch_items": self.max_batch_items,
            "latency_blocks": self.latency_blocks,
            "pq_attestation_root": self.pq_attestation_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SponsorBudget {
    pub sponsor_id: String,
    pub policy: SponsorPolicy,
    pub label: String,
    pub budget_commitment: String,
    pub remaining_piconero: u64,
    pub max_fee_bps: u64,
    pub allowed_classes: BTreeSet<ProofClass>,
}

impl SponsorBudget {
    pub fn new(
        policy: SponsorPolicy,
        label: &str,
        budget_commitment: &str,
        remaining_piconero: u64,
        max_fee_bps: u64,
        allowed_classes: BTreeSet<ProofClass>,
    ) -> LowFeeProofBatchSponsorAllocatorResult<Self> {
        if label.is_empty() || budget_commitment.is_empty() {
            return Err("sponsor budget identifiers cannot be empty".to_string());
        }
        if remaining_piconero == 0 {
            return Err("sponsor budget must be positive".to_string());
        }
        if max_fee_bps > LOW_FEE_PROOF_BATCH_SPONSOR_ALLOCATOR_MAX_BPS {
            return Err("sponsor max fee cannot exceed 100%".to_string());
        }
        if allowed_classes.is_empty() {
            return Err("sponsor allowed proof classes cannot be empty".to_string());
        }
        let sponsor_id = sponsor_budget_id(
            policy,
            label,
            budget_commitment,
            remaining_piconero,
            max_fee_bps,
            &allowed_classes,
        );
        Ok(Self {
            sponsor_id,
            policy,
            label: label.to_string(),
            budget_commitment: budget_commitment.to_string(),
            remaining_piconero,
            max_fee_bps,
            allowed_classes,
        })
    }

    pub fn can_cover(&self, request: &ProofBatchRequest, fee_piconero: u64) -> bool {
        self.allowed_classes.contains(&request.proof_class)
            && self.remaining_piconero >= fee_piconero
            && self.max_fee_bps <= request.max_user_fee_bps
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "low_fee_proof_batch_sponsor_budget",
            "chain_id": CHAIN_ID,
            "protocol_version": LOW_FEE_PROOF_BATCH_SPONSOR_ALLOCATOR_PROTOCOL_VERSION,
            "sponsor_id": self.sponsor_id,
            "policy": self.policy.as_str(),
            "label": self.label,
            "budget_commitment": self.budget_commitment,
            "remaining_piconero": self.remaining_piconero,
            "max_fee_bps": self.max_fee_bps,
            "allowed_classes": self.allowed_classes.iter().map(|class| class.as_str()).collect::<Vec<_>>(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofBatchRequest {
    pub request_id: String,
    pub proof_class: ProofClass,
    pub request_commitment: String,
    pub witness_root: String,
    pub max_user_fee_bps: u64,
    pub privacy_set_size: u64,
    pub submitted_at_height: u64,
    pub deadline_height: u64,
    pub batch_items: u64,
}

impl ProofBatchRequest {
    pub fn new(
        proof_class: ProofClass,
        request_commitment: &str,
        witness: &Value,
        max_user_fee_bps: u64,
        privacy_set_size: u64,
        submitted_at_height: u64,
        deadline_height: u64,
        batch_items: u64,
    ) -> LowFeeProofBatchSponsorAllocatorResult<Self> {
        if request_commitment.is_empty() {
            return Err("proof batch request commitment cannot be empty".to_string());
        }
        if deadline_height <= submitted_at_height {
            return Err("proof batch request deadline must be after submission".to_string());
        }
        if batch_items == 0 {
            return Err("proof batch request items must be positive".to_string());
        }
        if max_user_fee_bps > LOW_FEE_PROOF_BATCH_SPONSOR_ALLOCATOR_MAX_BPS {
            return Err("proof batch request fee cap cannot exceed 100%".to_string());
        }
        let witness_root =
            low_fee_proof_batch_sponsor_allocator_payload_root("LOW-FEE-PROOF-WITNESS", witness);
        let request_id = proof_batch_request_id(
            proof_class,
            request_commitment,
            &witness_root,
            max_user_fee_bps,
            submitted_at_height,
            deadline_height,
            batch_items,
        );
        Ok(Self {
            request_id,
            proof_class,
            request_commitment: request_commitment.to_string(),
            witness_root,
            max_user_fee_bps,
            privacy_set_size,
            submitted_at_height,
            deadline_height,
            batch_items,
        })
    }

    pub fn urgent_at(&self, height: u64, config: &Config) -> bool {
        self.proof_class.latency_sensitive()
            || self.deadline_height.saturating_sub(height) <= config.max_latency_blocks
    }

    pub fn active_at(&self, height: u64) -> bool {
        self.submitted_at_height <= height && height <= self.deadline_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "low_fee_proof_batch_request",
            "chain_id": CHAIN_ID,
            "protocol_version": LOW_FEE_PROOF_BATCH_SPONSOR_ALLOCATOR_PROTOCOL_VERSION,
            "request_id": self.request_id,
            "proof_class": self.proof_class.as_str(),
            "request_commitment": self.request_commitment,
            "witness_root": self.witness_root,
            "max_user_fee_bps": self.max_user_fee_bps,
            "privacy_set_size": self.privacy_set_size,
            "submitted_at_height": self.submitted_at_height,
            "deadline_height": self.deadline_height,
            "batch_items": self.batch_items,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofBatchAllocation {
    pub allocation_id: String,
    pub request_id: String,
    pub prover_id: String,
    pub sponsor_id: String,
    pub status: AllocationStatus,
    pub assigned_fee_piconero: u64,
    pub user_fee_piconero: u64,
    pub rebate_piconero: u64,
    pub assigned_at_height: u64,
    pub settlement_height: u64,
}

impl ProofBatchAllocation {
    pub fn new(
        request_id: &str,
        prover_id: &str,
        sponsor_id: &str,
        status: AllocationStatus,
        assigned_fee_piconero: u64,
        user_fee_piconero: u64,
        assigned_at_height: u64,
        settlement_height: u64,
    ) -> LowFeeProofBatchSponsorAllocatorResult<Self> {
        if request_id.is_empty() || prover_id.is_empty() || sponsor_id.is_empty() {
            return Err("proof batch allocation identifiers cannot be empty".to_string());
        }
        if settlement_height < assigned_at_height {
            return Err("proof batch allocation cannot settle before assignment".to_string());
        }
        if user_fee_piconero > assigned_fee_piconero {
            return Err("user fee cannot exceed assigned proof fee".to_string());
        }
        let rebate_piconero = assigned_fee_piconero.saturating_sub(user_fee_piconero);
        let allocation_id = proof_batch_allocation_id(
            request_id,
            prover_id,
            sponsor_id,
            status,
            assigned_fee_piconero,
            user_fee_piconero,
            assigned_at_height,
            settlement_height,
        );
        Ok(Self {
            allocation_id,
            request_id: request_id.to_string(),
            prover_id: prover_id.to_string(),
            sponsor_id: sponsor_id.to_string(),
            status,
            assigned_fee_piconero,
            user_fee_piconero,
            rebate_piconero,
            assigned_at_height,
            settlement_height,
        })
    }

    pub fn settled(&self) -> bool {
        matches!(
            self.status,
            AllocationStatus::Settled | AllocationStatus::Rebatable
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "low_fee_proof_batch_allocation",
            "chain_id": CHAIN_ID,
            "protocol_version": LOW_FEE_PROOF_BATCH_SPONSOR_ALLOCATOR_PROTOCOL_VERSION,
            "allocation_id": self.allocation_id,
            "request_id": self.request_id,
            "prover_id": self.prover_id,
            "sponsor_id": self.sponsor_id,
            "status": self.status.as_str(),
            "assigned_fee_piconero": self.assigned_fee_piconero,
            "user_fee_piconero": self.user_fee_piconero,
            "rebate_piconero": self.rebate_piconero,
            "assigned_at_height": self.assigned_at_height,
            "settlement_height": self.settlement_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roots {
    pub config_root: String,
    pub prover_root: String,
    pub sponsor_root: String,
    pub request_root: String,
    pub allocation_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "prover_root": self.prover_root,
            "sponsor_root": self.sponsor_root,
            "request_root": self.request_root,
            "allocation_root": self.allocation_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    pub prover_count: u64,
    pub sponsor_count: u64,
    pub request_count: u64,
    pub allocation_count: u64,
    pub active_request_count: u64,
    pub sponsored_fee_piconero: u64,
    pub user_fee_piconero: u64,
    pub rebate_piconero: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "prover_count": self.prover_count,
            "sponsor_count": self.sponsor_count,
            "request_count": self.request_count,
            "allocation_count": self.allocation_count,
            "active_request_count": self.active_request_count,
            "sponsored_fee_piconero": self.sponsored_fee_piconero,
            "user_fee_piconero": self.user_fee_piconero,
            "rebate_piconero": self.rebate_piconero,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub height: u64,
    pub config: Config,
    pub provers: BTreeMap<String, ProverLane>,
    pub sponsors: BTreeMap<String, SponsorBudget>,
    pub requests: BTreeMap<String, ProofBatchRequest>,
    pub allocations: BTreeMap<String, ProofBatchAllocation>,
    pub roots: Roots,
    pub counters: Counters,
    pub state_root: String,
}

impl State {
    pub fn new(height: u64, config: Config) -> LowFeeProofBatchSponsorAllocatorResult<Self> {
        config.validate()?;
        let mut state = Self {
            height,
            config,
            provers: BTreeMap::new(),
            sponsors: BTreeMap::new(),
            requests: BTreeMap::new(),
            allocations: BTreeMap::new(),
            roots: Roots {
                config_root: String::new(),
                prover_root: String::new(),
                sponsor_root: String::new(),
                request_root: String::new(),
                allocation_root: String::new(),
            },
            counters: Counters {
                prover_count: 0,
                sponsor_count: 0,
                request_count: 0,
                allocation_count: 0,
                active_request_count: 0,
                sponsored_fee_piconero: 0,
                user_fee_piconero: 0,
                rebate_piconero: 0,
            },
            state_root: String::new(),
        };
        state.refresh();
        Ok(state)
    }

    pub fn insert_prover(
        &mut self,
        prover: ProverLane,
    ) -> LowFeeProofBatchSponsorAllocatorResult<()> {
        if self.provers.len() >= LOW_FEE_PROOF_BATCH_SPONSOR_ALLOCATOR_MAX_PROVERS {
            return Err("prover lane limit exceeded".to_string());
        }
        self.provers.insert(prover.prover_id.clone(), prover);
        self.refresh();
        Ok(())
    }

    pub fn insert_sponsor(
        &mut self,
        sponsor: SponsorBudget,
    ) -> LowFeeProofBatchSponsorAllocatorResult<()> {
        if self.sponsors.len() >= LOW_FEE_PROOF_BATCH_SPONSOR_ALLOCATOR_MAX_SPONSORS {
            return Err("sponsor budget limit exceeded".to_string());
        }
        if sponsor.max_fee_bps > self.config.max_user_fee_bps {
            return Err("sponsor budget fee cap exceeds configured user cap".to_string());
        }
        self.sponsors.insert(sponsor.sponsor_id.clone(), sponsor);
        self.refresh();
        Ok(())
    }

    pub fn insert_request(
        &mut self,
        request: ProofBatchRequest,
    ) -> LowFeeProofBatchSponsorAllocatorResult<()> {
        if self.requests.len() >= LOW_FEE_PROOF_BATCH_SPONSOR_ALLOCATOR_MAX_REQUESTS {
            return Err("proof batch request limit exceeded".to_string());
        }
        if request.privacy_set_size < self.config.min_privacy_set_size {
            return Err("proof batch request privacy set below configured floor".to_string());
        }
        if request.max_user_fee_bps > self.config.max_user_fee_bps {
            return Err("proof batch request fee cap exceeds configured cap".to_string());
        }
        self.requests.insert(request.request_id.clone(), request);
        self.refresh();
        Ok(())
    }

    pub fn insert_allocation(
        &mut self,
        allocation: ProofBatchAllocation,
    ) -> LowFeeProofBatchSponsorAllocatorResult<()> {
        if self.allocations.len() >= LOW_FEE_PROOF_BATCH_SPONSOR_ALLOCATOR_MAX_ALLOCATIONS {
            return Err("proof batch allocation limit exceeded".to_string());
        }
        if !self.requests.contains_key(&allocation.request_id) {
            return Err("proof batch allocation references unknown request".to_string());
        }
        if !self.provers.contains_key(&allocation.prover_id) {
            return Err("proof batch allocation references unknown prover".to_string());
        }
        if !self.sponsors.contains_key(&allocation.sponsor_id) {
            return Err("proof batch allocation references unknown sponsor".to_string());
        }
        self.allocations
            .insert(allocation.allocation_id.clone(), allocation);
        self.refresh();
        Ok(())
    }

    pub fn estimate_fee(&self, prover: &ProverLane, request: &ProofBatchRequest) -> u64 {
        let fill_discount_bps = self.config.target_batch_fill_bps.min(
            request
                .batch_items
                .saturating_mul(LOW_FEE_PROOF_BATCH_SPONSOR_ALLOCATOR_MAX_BPS)
                / prover.max_batch_items.max(1),
        );
        let undiscounted = prover.base_fee_piconero.saturating_mul(request.batch_items);
        undiscounted.saturating_mul(
            LOW_FEE_PROOF_BATCH_SPONSOR_ALLOCATOR_MAX_BPS.saturating_sub(fill_discount_bps / 2),
        ) / LOW_FEE_PROOF_BATCH_SPONSOR_ALLOCATOR_MAX_BPS
    }

    pub fn candidate_assignment(
        &self,
        request: &ProofBatchRequest,
    ) -> Option<(String, String, u64)> {
        let mut best: Option<(String, String, u64, u64)> = None;
        for prover in self
            .provers
            .values()
            .filter(|prover| prover.supports(request.proof_class))
        {
            if request.urgent_at(self.height, &self.config)
                && prover.latency_blocks > self.config.max_latency_blocks
            {
                continue;
            }
            let fee = self.estimate_fee(prover, request);
            for sponsor in self
                .sponsors
                .values()
                .filter(|sponsor| sponsor.can_cover(request, fee))
            {
                let score = prover
                    .capacity_weight
                    .saturating_mul(1_000_000)
                    .saturating_sub(fee)
                    .saturating_sub(prover.latency_blocks.saturating_mul(1_000));
                match &best {
                    Some((_, _, _, best_score)) if *best_score >= score => {}
                    _ => {
                        best = Some((
                            prover.prover_id.clone(),
                            sponsor.sponsor_id.clone(),
                            fee,
                            score,
                        ));
                    }
                }
            }
        }
        best.map(|(prover_id, sponsor_id, fee, _)| (prover_id, sponsor_id, fee))
    }

    pub fn allocate_pending(&mut self) -> LowFeeProofBatchSponsorAllocatorResult<Vec<String>> {
        let mut created = Vec::new();
        let requests = self
            .requests
            .values()
            .filter(|request| request.active_at(self.height))
            .cloned()
            .collect::<Vec<_>>();
        for request in requests {
            if self
                .allocations
                .values()
                .any(|allocation| allocation.request_id == request.request_id)
            {
                continue;
            }
            let Some((prover_id, sponsor_id, fee)) = self.candidate_assignment(&request) else {
                continue;
            };
            let user_fee = fee.saturating_mul(request.max_user_fee_bps)
                / LOW_FEE_PROOF_BATCH_SPONSOR_ALLOCATOR_MAX_BPS;
            let allocation = ProofBatchAllocation::new(
                &request.request_id,
                &prover_id,
                &sponsor_id,
                AllocationStatus::Assigned,
                fee,
                user_fee,
                self.height,
                self.height.saturating_add(self.config.max_latency_blocks),
            )?;
            created.push(allocation.allocation_id.clone());
            self.insert_allocation(allocation)?;
        }
        Ok(created)
    }

    pub fn refresh(&mut self) {
        self.roots = Roots {
            config_root: low_fee_proof_batch_sponsor_allocator_payload_root(
                "LOW-FEE-PROOF-SPONSOR-CONFIG",
                &self.config.public_record(),
            ),
            prover_root: prover_lane_root(&self.provers.values().cloned().collect::<Vec<_>>()),
            sponsor_root: sponsor_budget_root(&self.sponsors.values().cloned().collect::<Vec<_>>()),
            request_root: proof_batch_request_root(
                &self.requests.values().cloned().collect::<Vec<_>>(),
            ),
            allocation_root: proof_batch_allocation_root(
                &self.allocations.values().cloned().collect::<Vec<_>>(),
            ),
        };
        self.counters = Counters {
            prover_count: self.provers.len() as u64,
            sponsor_count: self.sponsors.len() as u64,
            request_count: self.requests.len() as u64,
            allocation_count: self.allocations.len() as u64,
            active_request_count: self
                .requests
                .values()
                .filter(|request| request.active_at(self.height))
                .count() as u64,
            sponsored_fee_piconero: self
                .allocations
                .values()
                .map(|allocation| allocation.assigned_fee_piconero)
                .fold(0_u64, u64::saturating_add),
            user_fee_piconero: self
                .allocations
                .values()
                .map(|allocation| allocation.user_fee_piconero)
                .fold(0_u64, u64::saturating_add),
            rebate_piconero: self
                .allocations
                .values()
                .map(|allocation| allocation.rebate_piconero)
                .fold(0_u64, u64::saturating_add),
        };
        self.state_root = root_from_record(&self.public_record_without_state_root());
    }

    fn public_record_without_state_root(&self) -> Value {
        json!({
            "kind": "low_fee_proof_batch_sponsor_allocator_state",
            "chain_id": CHAIN_ID,
            "protocol_version": LOW_FEE_PROOF_BATCH_SPONSOR_ALLOCATOR_PROTOCOL_VERSION,
            "height": self.height,
            "roots": self.roots.public_record(),
            "counters": self.counters.public_record(),
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        if let Value::Object(ref mut values) = record {
            values.insert("state_root".to_string(), json!(self.state_root));
        }
        record
    }

    pub fn devnet() -> LowFeeProofBatchSponsorAllocatorResult<Self> {
        let mut state = Self::new(
            LOW_FEE_PROOF_BATCH_SPONSOR_ALLOCATOR_DEVNET_HEIGHT,
            Config::devnet(),
        )?;
        let mut fast_classes = BTreeSet::new();
        fast_classes.insert(ProofClass::ContractCall);
        fast_classes.insert(ProofClass::DefiSwap);
        fast_classes.insert(ProofClass::BridgeExit);
        state.insert_prover(ProverLane::new(
            "devnet-fast-recursive-prover",
            fast_classes.clone(),
            95,
            2_000_000,
            128,
            2,
            "pq-attestation-root-fast-prover",
        )?)?;
        let mut broad_classes = fast_classes;
        broad_classes.insert(ProofClass::Transfer);
        broad_classes.insert(ProofClass::TokenMint);
        broad_classes.insert(ProofClass::RecursiveAggregate);
        state.insert_sponsor(SponsorBudget::new(
            SponsorPolicy::PublicGoods,
            "devnet-public-goods-proof-sponsor",
            "budget-commitment-public-goods",
            900_000_000,
            25,
            broad_classes,
        )?)?;
        state.insert_request(ProofBatchRequest::new(
            ProofClass::ContractCall,
            "proof-request-private-contract-call",
            &json!({"call_bundle_root": "bundle-root-a", "private": true}),
            25,
            256,
            LOW_FEE_PROOF_BATCH_SPONSOR_ALLOCATOR_DEVNET_HEIGHT,
            LOW_FEE_PROOF_BATCH_SPONSOR_ALLOCATOR_DEVNET_HEIGHT.saturating_add(4),
            96,
        )?)?;
        state.insert_request(ProofBatchRequest::new(
            ProofClass::BridgeExit,
            "proof-request-monero-bridge-exit",
            &json!({"exit_batch_root": "exit-batch-root-a", "monero": true}),
            20,
            384,
            LOW_FEE_PROOF_BATCH_SPONSOR_ALLOCATOR_DEVNET_HEIGHT,
            LOW_FEE_PROOF_BATCH_SPONSOR_ALLOCATOR_DEVNET_HEIGHT.saturating_add(3),
            48,
        )?)?;
        state.allocate_pending()?;
        Ok(state)
    }
}

pub fn prover_lane_id(
    label: &str,
    supported_classes: &BTreeSet<ProofClass>,
    capacity_weight: u64,
    base_fee_piconero: u64,
    max_batch_items: u64,
    latency_blocks: u64,
    pq_attestation_root: &str,
) -> String {
    let classes = supported_classes
        .iter()
        .map(|class| class.as_str())
        .collect::<Vec<_>>()
        .join(",");
    domain_hash(
        "LOW-FEE-PROOF-PROVER-LANE-ID",
        &[
            HashPart::Str(label),
            HashPart::Str(&classes),
            HashPart::Int(capacity_weight as i128),
            HashPart::Int(base_fee_piconero as i128),
            HashPart::Int(max_batch_items as i128),
            HashPart::Int(latency_blocks as i128),
            HashPart::Str(pq_attestation_root),
        ],
        32,
    )
}

pub fn sponsor_budget_id(
    policy: SponsorPolicy,
    label: &str,
    budget_commitment: &str,
    remaining_piconero: u64,
    max_fee_bps: u64,
    allowed_classes: &BTreeSet<ProofClass>,
) -> String {
    let classes = allowed_classes
        .iter()
        .map(|class| class.as_str())
        .collect::<Vec<_>>()
        .join(",");
    domain_hash(
        "LOW-FEE-PROOF-SPONSOR-BUDGET-ID",
        &[
            HashPart::Str(policy.as_str()),
            HashPart::Str(label),
            HashPart::Str(budget_commitment),
            HashPart::Int(remaining_piconero as i128),
            HashPart::Int(max_fee_bps as i128),
            HashPart::Str(&classes),
        ],
        32,
    )
}

pub fn proof_batch_request_id(
    proof_class: ProofClass,
    request_commitment: &str,
    witness_root: &str,
    max_user_fee_bps: u64,
    submitted_at_height: u64,
    deadline_height: u64,
    batch_items: u64,
) -> String {
    domain_hash(
        "LOW-FEE-PROOF-BATCH-REQUEST-ID",
        &[
            HashPart::Str(proof_class.as_str()),
            HashPart::Str(request_commitment),
            HashPart::Str(witness_root),
            HashPart::Int(max_user_fee_bps as i128),
            HashPart::Int(submitted_at_height as i128),
            HashPart::Int(deadline_height as i128),
            HashPart::Int(batch_items as i128),
        ],
        32,
    )
}

pub fn proof_batch_allocation_id(
    request_id: &str,
    prover_id: &str,
    sponsor_id: &str,
    status: AllocationStatus,
    assigned_fee_piconero: u64,
    user_fee_piconero: u64,
    assigned_at_height: u64,
    settlement_height: u64,
) -> String {
    domain_hash(
        "LOW-FEE-PROOF-BATCH-ALLOCATION-ID",
        &[
            HashPart::Str(request_id),
            HashPart::Str(prover_id),
            HashPart::Str(sponsor_id),
            HashPart::Str(status.as_str()),
            HashPart::Int(assigned_fee_piconero as i128),
            HashPart::Int(user_fee_piconero as i128),
            HashPart::Int(assigned_at_height as i128),
            HashPart::Int(settlement_height as i128),
        ],
        32,
    )
}

pub fn prover_lane_root(provers: &[ProverLane]) -> String {
    let leaves = provers
        .iter()
        .map(ProverLane::public_record)
        .collect::<Vec<_>>();
    merkle_root("LOW-FEE-PROOF-PROVER-LANES", &leaves)
}

pub fn sponsor_budget_root(sponsors: &[SponsorBudget]) -> String {
    let leaves = sponsors
        .iter()
        .map(SponsorBudget::public_record)
        .collect::<Vec<_>>();
    merkle_root("LOW-FEE-PROOF-SPONSOR-BUDGETS", &leaves)
}

pub fn proof_batch_request_root(requests: &[ProofBatchRequest]) -> String {
    let leaves = requests
        .iter()
        .map(ProofBatchRequest::public_record)
        .collect::<Vec<_>>();
    merkle_root("LOW-FEE-PROOF-BATCH-REQUESTS", &leaves)
}

pub fn proof_batch_allocation_root(allocations: &[ProofBatchAllocation]) -> String {
    let leaves = allocations
        .iter()
        .map(ProofBatchAllocation::public_record)
        .collect::<Vec<_>>();
    merkle_root("LOW-FEE-PROOF-BATCH-ALLOCATIONS", &leaves)
}

pub fn low_fee_proof_batch_sponsor_allocator_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(domain, &[HashPart::Json(payload)], 32)
}

pub fn root_from_record(record: &Value) -> String {
    domain_hash(
        "LOW-FEE-PROOF-BATCH-SPONSOR-ALLOCATOR-STATE-ROOT",
        &[HashPart::Json(record)],
        32,
    )
}

pub fn devnet() -> LowFeeProofBatchSponsorAllocatorResult<State> {
    State::devnet()
}
