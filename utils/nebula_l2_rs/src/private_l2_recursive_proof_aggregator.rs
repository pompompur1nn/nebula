use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;

pub const PRIVATE_L2_RECURSIVE_PROOF_AGGREGATOR_PROTOCOL_VERSION: &str =
    "nebula-private-l2-recursive-proof-aggregator-v1";
pub const PRIVATE_L2_RECURSIVE_PROOF_AGGREGATOR_SCHEMA_VERSION: u64 = 1;
pub const PRIVATE_L2_RECURSIVE_PROOF_AGGREGATOR_DEVNET_HEIGHT: u64 = 55_000;
pub const PRIVATE_L2_RECURSIVE_PROOF_AGGREGATOR_HASH_SUITE: &str = "SHAKE256-domain-separated";
pub const PRIVATE_L2_RECURSIVE_PROOF_AGGREGATOR_RECURSION_SUITE: &str =
    "recursive-pq-zk-private-l2-folding-v1";
pub const PRIVATE_L2_RECURSIVE_PROOF_AGGREGATOR_PQ_AUTH_SUITE: &str =
    "ML-DSA-87+SLH-DSA-SHAKE-256f-private-l2-recursive-auth";
pub const PRIVATE_L2_RECURSIVE_PROOF_AGGREGATOR_RECEIPT_SUITE: &str =
    "roots-only-private-l2-aggregate-receipts-v1";
pub const PRIVATE_L2_RECURSIVE_PROOF_AGGREGATOR_DEFAULT_MAX_JOBS_PER_BATCH: usize = 512;
pub const PRIVATE_L2_RECURSIVE_PROOF_AGGREGATOR_DEFAULT_MIN_JOBS_PER_BATCH: usize = 2;
pub const PRIVATE_L2_RECURSIVE_PROOF_AGGREGATOR_DEFAULT_MAX_RECURSION_DEPTH: u64 = 16;
pub const PRIVATE_L2_RECURSIVE_PROOF_AGGREGATOR_DEFAULT_TARGET_LATENCY_MS: u64 = 350;
pub const PRIVATE_L2_RECURSIVE_PROOF_AGGREGATOR_DEFAULT_SETTLEMENT_WINDOW_BLOCKS: u64 = 8;
pub const PRIVATE_L2_RECURSIVE_PROOF_AGGREGATOR_DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 512;
pub const PRIVATE_L2_RECURSIVE_PROOF_AGGREGATOR_DEFAULT_MIN_PQ_ATTESTATIONS: u64 = 3;
pub const PRIVATE_L2_RECURSIVE_PROOF_AGGREGATOR_DEFAULT_MAX_FEE_UNITS_PER_JOB: u64 = 50_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofFlowKind {
    TokenMint,
    ContractExecution,
    AmmSwap,
    FeeSponsorship,
    MoneroExit,
    PqAuth,
}

impl ProofFlowKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::TokenMint => "token_mint",
            Self::ContractExecution => "contract_execution",
            Self::AmmSwap => "amm_swap",
            Self::FeeSponsorship => "fee_sponsorship",
            Self::MoneroExit => "monero_exit",
            Self::PqAuth => "pq_auth",
        }
    }

    pub fn lane_weight(self) -> u64 {
        match self {
            Self::MoneroExit => 10_000,
            Self::PqAuth => 9_400,
            Self::FeeSponsorship => 8_800,
            Self::ContractExecution => 8_000,
            Self::AmmSwap => 7_200,
            Self::TokenMint => 6_400,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofJobStatus {
    Queued,
    Aggregating,
    Aggregated,
    Settled,
    Rejected,
    Expired,
}

impl ProofJobStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Aggregating => "aggregating",
            Self::Aggregated => "aggregated",
            Self::Settled => "settled",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }

    pub fn live(self) -> bool {
        matches!(self, Self::Queued | Self::Aggregating | Self::Aggregated)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AggregateStatus {
    Open,
    Sealed,
    SettlementReady,
    Settled,
    Rejected,
}

impl AggregateStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Sealed => "sealed",
            Self::SettlementReady => "settlement_ready",
            Self::Settled => "settled",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub devnet_height: u64,
    pub max_jobs_per_batch: usize,
    pub min_jobs_per_batch: usize,
    pub max_recursion_depth: u64,
    pub target_latency_ms: u64,
    pub settlement_window_blocks: u64,
    pub min_privacy_set_size: u64,
    pub min_pq_attestations: u64,
    pub max_fee_units_per_job: u64,
    pub hash_suite: String,
    pub recursion_suite: String,
    pub pq_auth_suite: String,
    pub receipt_suite: String,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            devnet_height: PRIVATE_L2_RECURSIVE_PROOF_AGGREGATOR_DEVNET_HEIGHT,
            max_jobs_per_batch: PRIVATE_L2_RECURSIVE_PROOF_AGGREGATOR_DEFAULT_MAX_JOBS_PER_BATCH,
            min_jobs_per_batch: PRIVATE_L2_RECURSIVE_PROOF_AGGREGATOR_DEFAULT_MIN_JOBS_PER_BATCH,
            max_recursion_depth: PRIVATE_L2_RECURSIVE_PROOF_AGGREGATOR_DEFAULT_MAX_RECURSION_DEPTH,
            target_latency_ms: PRIVATE_L2_RECURSIVE_PROOF_AGGREGATOR_DEFAULT_TARGET_LATENCY_MS,
            settlement_window_blocks:
                PRIVATE_L2_RECURSIVE_PROOF_AGGREGATOR_DEFAULT_SETTLEMENT_WINDOW_BLOCKS,
            min_privacy_set_size:
                PRIVATE_L2_RECURSIVE_PROOF_AGGREGATOR_DEFAULT_MIN_PRIVACY_SET_SIZE,
            min_pq_attestations: PRIVATE_L2_RECURSIVE_PROOF_AGGREGATOR_DEFAULT_MIN_PQ_ATTESTATIONS,
            max_fee_units_per_job:
                PRIVATE_L2_RECURSIVE_PROOF_AGGREGATOR_DEFAULT_MAX_FEE_UNITS_PER_JOB,
            hash_suite: PRIVATE_L2_RECURSIVE_PROOF_AGGREGATOR_HASH_SUITE.to_string(),
            recursion_suite: PRIVATE_L2_RECURSIVE_PROOF_AGGREGATOR_RECURSION_SUITE.to_string(),
            pq_auth_suite: PRIVATE_L2_RECURSIVE_PROOF_AGGREGATOR_PQ_AUTH_SUITE.to_string(),
            receipt_suite: PRIVATE_L2_RECURSIVE_PROOF_AGGREGATOR_RECEIPT_SUITE.to_string(),
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.min_jobs_per_batch == 0 || self.max_jobs_per_batch < self.min_jobs_per_batch {
            return Err("private L2 aggregator batch limits are invalid".into());
        }
        if self.max_recursion_depth == 0
            || self.target_latency_ms == 0
            || self.settlement_window_blocks == 0
            || self.min_privacy_set_size == 0
            || self.min_pq_attestations == 0
            || self.max_fee_units_per_job == 0
        {
            return Err("private L2 aggregator numeric config values must be positive".into());
        }
        if self.hash_suite.is_empty()
            || self.recursion_suite.is_empty()
            || self.pq_auth_suite.is_empty()
            || self.receipt_suite.is_empty()
        {
            return Err("private L2 aggregator suite labels must be populated".into());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "devnet_height": self.devnet_height,
            "max_jobs_per_batch": self.max_jobs_per_batch,
            "min_jobs_per_batch": self.min_jobs_per_batch,
            "max_recursion_depth": self.max_recursion_depth,
            "target_latency_ms": self.target_latency_ms,
            "settlement_window_blocks": self.settlement_window_blocks,
            "min_privacy_set_size": self.min_privacy_set_size,
            "min_pq_attestations": self.min_pq_attestations,
            "max_fee_units_per_job": self.max_fee_units_per_job,
            "hash_suite": self.hash_suite,
            "recursion_suite": self.recursion_suite,
            "pq_auth_suite": self.pq_auth_suite,
            "receipt_suite": self.receipt_suite,
        })
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    pub submitted_jobs: u64,
    pub token_mint_jobs: u64,
    pub contract_execution_jobs: u64,
    pub amm_swap_jobs: u64,
    pub fee_sponsorship_jobs: u64,
    pub monero_exit_jobs: u64,
    pub pq_auth_jobs: u64,
    pub aggregated_batches: u64,
    pub settled_aggregates: u64,
    pub rejected_jobs: u64,
    pub total_fee_units: u64,
    pub sponsored_fee_units: u64,
    pub aggregate_proof_receipts: u64,
    pub low_latency_batches: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "submitted_jobs": self.submitted_jobs,
            "token_mint_jobs": self.token_mint_jobs,
            "contract_execution_jobs": self.contract_execution_jobs,
            "amm_swap_jobs": self.amm_swap_jobs,
            "fee_sponsorship_jobs": self.fee_sponsorship_jobs,
            "monero_exit_jobs": self.monero_exit_jobs,
            "pq_auth_jobs": self.pq_auth_jobs,
            "aggregated_batches": self.aggregated_batches,
            "settled_aggregates": self.settled_aggregates,
            "rejected_jobs": self.rejected_jobs,
            "total_fee_units": self.total_fee_units,
            "sponsored_fee_units": self.sponsored_fee_units,
            "aggregate_proof_receipts": self.aggregate_proof_receipts,
            "low_latency_batches": self.low_latency_batches,
        })
    }

    fn count_job(&mut self, kind: ProofFlowKind, fee_units: u64, sponsored_fee_units: u64) {
        self.submitted_jobs = self.submitted_jobs.saturating_add(1);
        self.total_fee_units = self.total_fee_units.saturating_add(fee_units);
        self.sponsored_fee_units = self.sponsored_fee_units.saturating_add(sponsored_fee_units);
        match kind {
            ProofFlowKind::TokenMint => self.token_mint_jobs += 1,
            ProofFlowKind::ContractExecution => self.contract_execution_jobs += 1,
            ProofFlowKind::AmmSwap => self.amm_swap_jobs += 1,
            ProofFlowKind::FeeSponsorship => self.fee_sponsorship_jobs += 1,
            ProofFlowKind::MoneroExit => self.monero_exit_jobs += 1,
            ProofFlowKind::PqAuth => self.pq_auth_jobs += 1,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofRoots {
    pub token_mint_proof_root: String,
    pub contract_execution_proof_root: String,
    pub amm_swap_proof_root: String,
    pub fee_sponsorship_proof_root: String,
    pub monero_exit_proof_root: String,
    pub pq_auth_proof_root: String,
}

impl ProofRoots {
    pub fn empty() -> Self {
        Self {
            token_mint_proof_root: empty_root("TOKEN-MINT"),
            contract_execution_proof_root: empty_root("CONTRACT-EXECUTION"),
            amm_swap_proof_root: empty_root("AMM-SWAP"),
            fee_sponsorship_proof_root: empty_root("FEE-SPONSORSHIP"),
            monero_exit_proof_root: empty_root("MONERO-EXIT"),
            pq_auth_proof_root: empty_root("PQ-AUTH"),
        }
    }

    pub fn for_kind(kind: ProofFlowKind, proof_root: &str) -> Self {
        let mut roots = Self::empty();
        match kind {
            ProofFlowKind::TokenMint => roots.token_mint_proof_root = proof_root.to_string(),
            ProofFlowKind::ContractExecution => {
                roots.contract_execution_proof_root = proof_root.to_string()
            }
            ProofFlowKind::AmmSwap => roots.amm_swap_proof_root = proof_root.to_string(),
            ProofFlowKind::FeeSponsorship => {
                roots.fee_sponsorship_proof_root = proof_root.to_string()
            }
            ProofFlowKind::MoneroExit => roots.monero_exit_proof_root = proof_root.to_string(),
            ProofFlowKind::PqAuth => roots.pq_auth_proof_root = proof_root.to_string(),
        }
        roots
    }

    pub fn merge(&self, other: &Self) -> Self {
        Self {
            token_mint_proof_root: merge_roots(
                "TOKEN-MINT",
                &self.token_mint_proof_root,
                &other.token_mint_proof_root,
            ),
            contract_execution_proof_root: merge_roots(
                "CONTRACT-EXECUTION",
                &self.contract_execution_proof_root,
                &other.contract_execution_proof_root,
            ),
            amm_swap_proof_root: merge_roots(
                "AMM-SWAP",
                &self.amm_swap_proof_root,
                &other.amm_swap_proof_root,
            ),
            fee_sponsorship_proof_root: merge_roots(
                "FEE-SPONSORSHIP",
                &self.fee_sponsorship_proof_root,
                &other.fee_sponsorship_proof_root,
            ),
            monero_exit_proof_root: merge_roots(
                "MONERO-EXIT",
                &self.monero_exit_proof_root,
                &other.monero_exit_proof_root,
            ),
            pq_auth_proof_root: merge_roots(
                "PQ-AUTH",
                &self.pq_auth_proof_root,
                &other.pq_auth_proof_root,
            ),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "token_mint_proof_root": self.token_mint_proof_root,
            "contract_execution_proof_root": self.contract_execution_proof_root,
            "amm_swap_proof_root": self.amm_swap_proof_root,
            "fee_sponsorship_proof_root": self.fee_sponsorship_proof_root,
            "monero_exit_proof_root": self.monero_exit_proof_root,
            "pq_auth_proof_root": self.pq_auth_proof_root,
        })
    }

    pub fn root(&self) -> String {
        l2_hash("PROOF-ROOTS", &[HashPart::Json(&self.public_record())])
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofJob {
    pub job_id: String,
    pub kind: ProofFlowKind,
    pub flow_commitment: String,
    pub input_nullifier_root: String,
    pub output_commitment_root: String,
    pub proof_public_input_root: String,
    pub recursive_proof_root: String,
    pub witness_availability_root: String,
    pub pq_auth_root: String,
    pub fee_commitment_root: String,
    pub sponsor_commitment_root: Option<String>,
    pub monero_anchor_root: Option<String>,
    pub privacy_set_size: u64,
    pub recursion_depth: u64,
    pub fee_units: u64,
    pub sponsored_fee_units: u64,
    pub submitted_at_height: u64,
    pub expires_at_height: u64,
    pub status: ProofJobStatus,
}

impl ProofJob {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        kind: ProofFlowKind,
        flow_commitment: &str,
        input_nullifier_root: &str,
        output_commitment_root: &str,
        proof_public_input_root: &str,
        recursive_proof_root: &str,
        witness_availability_root: &str,
        pq_auth_root: &str,
        fee_commitment_root: &str,
        sponsor_commitment_root: Option<String>,
        monero_anchor_root: Option<String>,
        privacy_set_size: u64,
        recursion_depth: u64,
        fee_units: u64,
        sponsored_fee_units: u64,
        submitted_at_height: u64,
        expires_at_height: u64,
    ) -> Result<Self> {
        require_root("flow commitment", flow_commitment)?;
        require_root("input nullifier root", input_nullifier_root)?;
        require_root("output commitment root", output_commitment_root)?;
        require_root("proof public input root", proof_public_input_root)?;
        require_root("recursive proof root", recursive_proof_root)?;
        require_root("witness availability root", witness_availability_root)?;
        require_root("pq auth root", pq_auth_root)?;
        require_root("fee commitment root", fee_commitment_root)?;
        if let Some(root) = sponsor_commitment_root.as_deref() {
            require_root("sponsor commitment root", root)?;
        }
        if let Some(root) = monero_anchor_root.as_deref() {
            require_root("monero anchor root", root)?;
        }
        if expires_at_height <= submitted_at_height {
            return Err("proof job expiry must be after submission height".into());
        }

        let job_id = l2_hash(
            "PROOF-JOB-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(kind.as_str()),
                HashPart::Str(flow_commitment),
                HashPart::Str(input_nullifier_root),
                HashPart::Str(output_commitment_root),
                HashPart::Str(recursive_proof_root),
                HashPart::Int(submitted_at_height as i128),
                HashPart::Int(expires_at_height as i128),
            ],
        );
        Ok(Self {
            job_id,
            kind,
            flow_commitment: flow_commitment.to_string(),
            input_nullifier_root: input_nullifier_root.to_string(),
            output_commitment_root: output_commitment_root.to_string(),
            proof_public_input_root: proof_public_input_root.to_string(),
            recursive_proof_root: recursive_proof_root.to_string(),
            witness_availability_root: witness_availability_root.to_string(),
            pq_auth_root: pq_auth_root.to_string(),
            fee_commitment_root: fee_commitment_root.to_string(),
            sponsor_commitment_root,
            monero_anchor_root,
            privacy_set_size,
            recursion_depth,
            fee_units,
            sponsored_fee_units,
            submitted_at_height,
            expires_at_height,
            status: ProofJobStatus::Queued,
        })
    }

    pub fn roots(&self) -> ProofRoots {
        ProofRoots::for_kind(self.kind, &self.recursive_proof_root)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "job_id": self.job_id,
            "kind": self.kind.as_str(),
            "flow_commitment": self.flow_commitment,
            "input_nullifier_root": self.input_nullifier_root,
            "output_commitment_root": self.output_commitment_root,
            "proof_public_input_root": self.proof_public_input_root,
            "recursive_proof_root": self.recursive_proof_root,
            "witness_availability_root": self.witness_availability_root,
            "pq_auth_root": self.pq_auth_root,
            "fee_commitment_root": self.fee_commitment_root,
            "sponsor_commitment_root": self.sponsor_commitment_root,
            "monero_anchor_root": self.monero_anchor_root,
            "privacy_set_size": self.privacy_set_size,
            "recursion_depth": self.recursion_depth,
            "fee_units": self.fee_units,
            "sponsored_fee_units": self.sponsored_fee_units,
            "submitted_at_height": self.submitted_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn root(&self) -> String {
        l2_hash("PROOF-JOB", &[HashPart::Json(&self.public_record())])
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AggregateProofReceipt {
    pub aggregate_id: String,
    pub batch_sequence: u64,
    pub job_count: u64,
    pub lane_root: String,
    pub job_root: String,
    pub input_nullifier_root: String,
    pub output_commitment_root: String,
    pub proof_public_input_root: String,
    pub witness_availability_root: String,
    pub fee_commitment_root: String,
    pub sponsor_commitment_root: String,
    pub monero_anchor_root: String,
    pub pq_auth_root: String,
    pub flow_proof_roots: ProofRoots,
    pub recursive_aggregate_root: String,
    pub settlement_claim_root: String,
    pub privacy_set_size: u64,
    pub max_recursion_depth: u64,
    pub total_fee_units: u64,
    pub sponsored_fee_units: u64,
    pub opened_at_height: u64,
    pub settlement_ready_at_height: u64,
    pub target_latency_ms: u64,
    pub status: AggregateStatus,
}

impl AggregateProofReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "aggregate_id": self.aggregate_id,
            "batch_sequence": self.batch_sequence,
            "job_count": self.job_count,
            "lane_root": self.lane_root,
            "job_root": self.job_root,
            "input_nullifier_root": self.input_nullifier_root,
            "output_commitment_root": self.output_commitment_root,
            "proof_public_input_root": self.proof_public_input_root,
            "witness_availability_root": self.witness_availability_root,
            "fee_commitment_root": self.fee_commitment_root,
            "sponsor_commitment_root": self.sponsor_commitment_root,
            "monero_anchor_root": self.monero_anchor_root,
            "pq_auth_root": self.pq_auth_root,
            "flow_proof_roots": self.flow_proof_roots.public_record(),
            "recursive_aggregate_root": self.recursive_aggregate_root,
            "settlement_claim_root": self.settlement_claim_root,
            "privacy_set_size": self.privacy_set_size,
            "max_recursion_depth": self.max_recursion_depth,
            "total_fee_units": self.total_fee_units,
            "sponsored_fee_units": self.sponsored_fee_units,
            "opened_at_height": self.opened_at_height,
            "settlement_ready_at_height": self.settlement_ready_at_height,
            "target_latency_ms": self.target_latency_ms,
            "status": self.status.as_str(),
        })
    }

    pub fn root(&self) -> String {
        l2_hash(
            "AGGREGATE-PROOF-RECEIPT",
            &[HashPart::Json(&self.public_record())],
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementReceipt {
    pub settlement_id: String,
    pub aggregate_id: String,
    pub aggregate_receipt_root: String,
    pub settlement_claim_root: String,
    pub settlement_authority_root: String,
    pub pq_attestation_root: String,
    pub settled_job_root: String,
    pub settled_at_height: u64,
}

impl SettlementReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "settlement_id": self.settlement_id,
            "aggregate_id": self.aggregate_id,
            "aggregate_receipt_root": self.aggregate_receipt_root,
            "settlement_claim_root": self.settlement_claim_root,
            "settlement_authority_root": self.settlement_authority_root,
            "pq_attestation_root": self.pq_attestation_root,
            "settled_job_root": self.settled_job_root,
            "settled_at_height": self.settled_at_height,
        })
    }

    pub fn root(&self) -> String {
        l2_hash(
            "SETTLEMENT-RECEIPT",
            &[HashPart::Json(&self.public_record())],
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roots {
    pub queued_job_root: String,
    pub aggregate_receipt_root: String,
    pub settlement_receipt_root: String,
    pub token_mint_proof_root: String,
    pub contract_execution_proof_root: String,
    pub amm_swap_proof_root: String,
    pub fee_sponsorship_proof_root: String,
    pub monero_exit_proof_root: String,
    pub pq_auth_proof_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "queued_job_root": self.queued_job_root,
            "aggregate_receipt_root": self.aggregate_receipt_root,
            "settlement_receipt_root": self.settlement_receipt_root,
            "token_mint_proof_root": self.token_mint_proof_root,
            "contract_execution_proof_root": self.contract_execution_proof_root,
            "amm_swap_proof_root": self.amm_swap_proof_root,
            "fee_sponsorship_proof_root": self.fee_sponsorship_proof_root,
            "monero_exit_proof_root": self.monero_exit_proof_root,
            "pq_auth_proof_root": self.pq_auth_proof_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub jobs: BTreeMap<String, ProofJob>,
    pub aggregates: BTreeMap<String, AggregateProofReceipt>,
    pub aggregate_jobs: BTreeMap<String, Vec<String>>,
    pub settlements: BTreeMap<String, SettlementReceipt>,
    pub settled_aggregates: BTreeSet<String>,
    pub next_batch_sequence: u64,
}

impl State {
    pub fn devnet() -> Self {
        Self {
            config: Config::devnet(),
            counters: Counters::default(),
            jobs: BTreeMap::new(),
            aggregates: BTreeMap::new(),
            aggregate_jobs: BTreeMap::new(),
            settlements: BTreeMap::new(),
            settled_aggregates: BTreeSet::new(),
            next_batch_sequence: 1,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn submit_proof_job(
        &mut self,
        kind: ProofFlowKind,
        flow_commitment: &str,
        input_nullifier_root: &str,
        output_commitment_root: &str,
        proof_public_input_root: &str,
        recursive_proof_root: &str,
        witness_availability_root: &str,
        pq_auth_root: &str,
        fee_commitment_root: &str,
        sponsor_commitment_root: Option<String>,
        monero_anchor_root: Option<String>,
        privacy_set_size: u64,
        recursion_depth: u64,
        fee_units: u64,
        sponsored_fee_units: u64,
        submitted_at_height: u64,
        expires_at_height: u64,
    ) -> Result<ProofJob> {
        self.config.validate()?;
        if privacy_set_size < self.config.min_privacy_set_size {
            return Err("proof job privacy set is below aggregator policy".into());
        }
        if recursion_depth > self.config.max_recursion_depth {
            return Err("proof job recursion depth exceeds aggregator policy".into());
        }
        if fee_units > self.config.max_fee_units_per_job {
            return Err("proof job fee exceeds low-fee policy".into());
        }
        if sponsored_fee_units > fee_units {
            return Err("proof job sponsored fee cannot exceed total fee".into());
        }
        if kind == ProofFlowKind::FeeSponsorship && sponsor_commitment_root.is_none() {
            return Err("fee sponsorship jobs require a sponsor commitment root".into());
        }
        if kind == ProofFlowKind::MoneroExit && monero_anchor_root.is_none() {
            return Err("Monero exit jobs require a Monero anchor root".into());
        }

        let job = ProofJob::new(
            kind,
            flow_commitment,
            input_nullifier_root,
            output_commitment_root,
            proof_public_input_root,
            recursive_proof_root,
            witness_availability_root,
            pq_auth_root,
            fee_commitment_root,
            sponsor_commitment_root,
            monero_anchor_root,
            privacy_set_size,
            recursion_depth,
            fee_units,
            sponsored_fee_units,
            submitted_at_height,
            expires_at_height,
        )?;
        if self.jobs.contains_key(&job.job_id) {
            return Err("proof job already exists".into());
        }
        self.counters
            .count_job(kind, job.fee_units, job.sponsored_fee_units);
        self.jobs.insert(job.job_id.clone(), job.clone());
        Ok(job)
    }

    pub fn aggregate_batch(
        &mut self,
        job_ids: &[String],
        opened_at_height: u64,
    ) -> Result<AggregateProofReceipt> {
        self.config.validate()?;
        if job_ids.len() < self.config.min_jobs_per_batch {
            return Err("aggregate batch is below minimum batch size".into());
        }
        if job_ids.len() > self.config.max_jobs_per_batch {
            return Err("aggregate batch exceeds maximum batch size".into());
        }

        let mut seen = BTreeSet::new();
        let mut jobs = Vec::with_capacity(job_ids.len());
        for job_id in job_ids {
            if !seen.insert(job_id.clone()) {
                return Err("aggregate batch contains duplicate proof jobs".into());
            }
            let job = self
                .jobs
                .get(job_id)
                .ok_or_else(|| format!("unknown proof job {job_id}"))?;
            if job.status != ProofJobStatus::Queued {
                return Err(format!("proof job {job_id} is not queued"));
            }
            if opened_at_height >= job.expires_at_height {
                return Err(format!("proof job {job_id} has expired"));
            }
            jobs.push(job.clone());
        }

        jobs.sort_by(|left, right| {
            right
                .kind
                .lane_weight()
                .cmp(&left.kind.lane_weight())
                .then_with(|| left.submitted_at_height.cmp(&right.submitted_at_height))
                .then_with(|| left.job_id.cmp(&right.job_id))
        });

        let lane_root = merkle_root(
            "PRIVATE-L2-AGGREGATOR-LANES",
            &jobs
                .iter()
                .map(|job| {
                    json!({
                        "kind": job.kind.as_str(),
                        "weight": job.kind.lane_weight(),
                        "job_id": job.job_id,
                    })
                })
                .collect::<Vec<_>>(),
        );
        let job_root = merkle_root(
            "PRIVATE-L2-AGGREGATOR-JOBS",
            &jobs.iter().map(ProofJob::public_record).collect::<Vec<_>>(),
        );
        let input_nullifier_root = merkle_from_strings(
            "PRIVATE-L2-AGGREGATOR-INPUT-NULLIFIERS",
            jobs.iter().map(|job| job.input_nullifier_root.as_str()),
        );
        let output_commitment_root = merkle_from_strings(
            "PRIVATE-L2-AGGREGATOR-OUTPUT-COMMITMENTS",
            jobs.iter().map(|job| job.output_commitment_root.as_str()),
        );
        let proof_public_input_root = merkle_from_strings(
            "PRIVATE-L2-AGGREGATOR-PUBLIC-INPUTS",
            jobs.iter().map(|job| job.proof_public_input_root.as_str()),
        );
        let witness_availability_root = merkle_from_strings(
            "PRIVATE-L2-AGGREGATOR-WITNESS-AVAILABILITY",
            jobs.iter()
                .map(|job| job.witness_availability_root.as_str()),
        );
        let fee_commitment_root = merkle_from_strings(
            "PRIVATE-L2-AGGREGATOR-FEES",
            jobs.iter().map(|job| job.fee_commitment_root.as_str()),
        );
        let sponsor_commitment_root = merkle_from_strings(
            "PRIVATE-L2-AGGREGATOR-SPONSORS",
            jobs.iter()
                .filter_map(|job| job.sponsor_commitment_root.as_deref()),
        );
        let monero_anchor_root = merkle_from_strings(
            "PRIVATE-L2-AGGREGATOR-MONERO-ANCHORS",
            jobs.iter()
                .filter_map(|job| job.monero_anchor_root.as_deref()),
        );
        let pq_auth_root = merkle_from_strings(
            "PRIVATE-L2-AGGREGATOR-PQ-AUTH",
            jobs.iter().map(|job| job.pq_auth_root.as_str()),
        );
        let flow_proof_roots = jobs
            .iter()
            .fold(ProofRoots::empty(), |roots, job| roots.merge(&job.roots()));
        let privacy_set_size = jobs
            .iter()
            .map(|job| job.privacy_set_size)
            .min()
            .unwrap_or(self.config.min_privacy_set_size);
        let max_recursion_depth = jobs
            .iter()
            .map(|job| job.recursion_depth)
            .max()
            .unwrap_or(0)
            .saturating_add(1);
        if max_recursion_depth > self.config.max_recursion_depth {
            return Err("aggregate recursion depth exceeds aggregator policy".into());
        }
        let total_fee_units = jobs.iter().map(|job| job.fee_units).sum::<u64>();
        let sponsored_fee_units = jobs.iter().map(|job| job.sponsored_fee_units).sum::<u64>();
        let settlement_ready_at_height =
            opened_at_height.saturating_add(self.config.settlement_window_blocks);
        let batch_sequence = self.next_batch_sequence;
        let recursive_aggregate_root = l2_hash(
            "RECURSIVE-AGGREGATE-ROOT",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Int(batch_sequence as i128),
                HashPart::Str(&job_root),
                HashPart::Str(&input_nullifier_root),
                HashPart::Str(&output_commitment_root),
                HashPart::Str(&flow_proof_roots.root()),
                HashPart::Int(max_recursion_depth as i128),
            ],
        );
        let settlement_claim_root = l2_hash(
            "AGGREGATE-SETTLEMENT-CLAIM",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&recursive_aggregate_root),
                HashPart::Str(&pq_auth_root),
                HashPart::Int(settlement_ready_at_height as i128),
            ],
        );
        let aggregate_id = l2_hash(
            "AGGREGATE-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Int(batch_sequence as i128),
                HashPart::Str(&job_root),
                HashPart::Str(&recursive_aggregate_root),
                HashPart::Str(&settlement_claim_root),
            ],
        );
        let receipt = AggregateProofReceipt {
            aggregate_id: aggregate_id.clone(),
            batch_sequence,
            job_count: jobs.len() as u64,
            lane_root,
            job_root,
            input_nullifier_root,
            output_commitment_root,
            proof_public_input_root,
            witness_availability_root,
            fee_commitment_root,
            sponsor_commitment_root,
            monero_anchor_root,
            pq_auth_root,
            flow_proof_roots,
            recursive_aggregate_root,
            settlement_claim_root,
            privacy_set_size,
            max_recursion_depth,
            total_fee_units,
            sponsored_fee_units,
            opened_at_height,
            settlement_ready_at_height,
            target_latency_ms: self.config.target_latency_ms,
            status: AggregateStatus::SettlementReady,
        };

        for job in jobs {
            if let Some(stored) = self.jobs.get_mut(&job.job_id) {
                stored.status = ProofJobStatus::Aggregated;
            }
        }
        self.next_batch_sequence = self.next_batch_sequence.saturating_add(1);
        self.counters.aggregated_batches = self.counters.aggregated_batches.saturating_add(1);
        self.counters.aggregate_proof_receipts =
            self.counters.aggregate_proof_receipts.saturating_add(1);
        if receipt.target_latency_ms
            <= PRIVATE_L2_RECURSIVE_PROOF_AGGREGATOR_DEFAULT_TARGET_LATENCY_MS
        {
            self.counters.low_latency_batches = self.counters.low_latency_batches.saturating_add(1);
        }
        self.aggregate_jobs
            .insert(aggregate_id.clone(), job_ids.to_vec());
        self.aggregates.insert(aggregate_id, receipt.clone());
        Ok(receipt)
    }

    pub fn settle_aggregate(
        &mut self,
        aggregate_id: &str,
        settlement_authority_root: &str,
        pq_attestation_root: &str,
        settled_at_height: u64,
    ) -> Result<SettlementReceipt> {
        require_root("aggregate id", aggregate_id)?;
        require_root("settlement authority root", settlement_authority_root)?;
        require_root("pq attestation root", pq_attestation_root)?;
        if self.settled_aggregates.contains(aggregate_id) {
            return Err("aggregate already settled".into());
        }
        let aggregate = self
            .aggregates
            .get_mut(aggregate_id)
            .ok_or_else(|| format!("unknown aggregate {aggregate_id}"))?;
        if aggregate.status != AggregateStatus::SettlementReady {
            return Err("aggregate is not settlement ready".into());
        }
        if settled_at_height < aggregate.settlement_ready_at_height {
            return Err("aggregate settlement height is before readiness window".into());
        }
        let settled_job_root = aggregate.job_root.clone();
        let aggregate_receipt_root = aggregate.root();
        let settlement_id = l2_hash(
            "SETTLEMENT-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(aggregate_id),
                HashPart::Str(&aggregate_receipt_root),
                HashPart::Str(&aggregate.settlement_claim_root),
                HashPart::Str(settlement_authority_root),
                HashPart::Str(pq_attestation_root),
                HashPart::Int(settled_at_height as i128),
            ],
        );
        let receipt = SettlementReceipt {
            settlement_id: settlement_id.clone(),
            aggregate_id: aggregate_id.to_string(),
            aggregate_receipt_root,
            settlement_claim_root: aggregate.settlement_claim_root.clone(),
            settlement_authority_root: settlement_authority_root.to_string(),
            pq_attestation_root: pq_attestation_root.to_string(),
            settled_job_root,
            settled_at_height,
        };
        aggregate.status = AggregateStatus::Settled;
        for job_id in self
            .aggregate_jobs
            .get(aggregate_id)
            .cloned()
            .unwrap_or_default()
        {
            if let Some(job) = self.jobs.get_mut(&job_id) {
                job.status = ProofJobStatus::Settled;
            }
        }
        self.settled_aggregates.insert(aggregate_id.to_string());
        self.counters.settled_aggregates = self.counters.settled_aggregates.saturating_add(1);
        self.settlements.insert(settlement_id, receipt.clone());
        Ok(receipt)
    }

    pub fn roots(&self) -> Roots {
        let aggregate_receipts = self
            .aggregates
            .values()
            .map(AggregateProofReceipt::public_record)
            .collect::<Vec<_>>();
        let settlement_receipts = self
            .settlements
            .values()
            .map(SettlementReceipt::public_record)
            .collect::<Vec<_>>();
        let queued_jobs = self
            .jobs
            .values()
            .filter(|job| job.status.live())
            .map(ProofJob::public_record)
            .collect::<Vec<_>>();
        let flow_roots = self
            .jobs
            .values()
            .fold(ProofRoots::empty(), |roots, job| roots.merge(&job.roots()));
        Roots {
            queued_job_root: merkle_root("PRIVATE-L2-AGGREGATOR-QUEUED-JOBS", &queued_jobs),
            aggregate_receipt_root: merkle_root(
                "PRIVATE-L2-AGGREGATOR-AGGREGATE-RECEIPTS",
                &aggregate_receipts,
            ),
            settlement_receipt_root: merkle_root(
                "PRIVATE-L2-AGGREGATOR-SETTLEMENT-RECEIPTS",
                &settlement_receipts,
            ),
            token_mint_proof_root: flow_roots.token_mint_proof_root,
            contract_execution_proof_root: flow_roots.contract_execution_proof_root,
            amm_swap_proof_root: flow_roots.amm_swap_proof_root,
            fee_sponsorship_proof_root: flow_roots.fee_sponsorship_proof_root,
            monero_exit_proof_root: flow_roots.monero_exit_proof_root,
            pq_auth_proof_root: flow_roots.pq_auth_proof_root,
        }
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        json!({
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_L2_RECURSIVE_PROOF_AGGREGATOR_PROTOCOL_VERSION,
            "schema_version": PRIVATE_L2_RECURSIVE_PROOF_AGGREGATOR_SCHEMA_VERSION,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": roots.public_record(),
            "next_batch_sequence": self.next_batch_sequence,
            "job_count": self.jobs.len(),
            "aggregate_count": self.aggregates.len(),
            "settlement_count": self.settlements.len(),
            "settled_aggregate_count": self.settled_aggregates.len(),
        })
    }

    pub fn state_root(&self) -> String {
        l2_hash("STATE", &[HashPart::Json(&self.public_record())])
    }
}

fn l2_hash(domain: &str, parts: &[HashPart<'_>]) -> String {
    domain_hash(
        &format!("PRIVATE-L2-RECURSIVE-PROOF-AGGREGATOR-{domain}"),
        parts,
        32,
    )
}

fn empty_root(label: &str) -> String {
    merkle_root(
        &format!("PRIVATE-L2-RECURSIVE-PROOF-AGGREGATOR-{label}-EMPTY"),
        &[],
    )
}

fn merge_roots(label: &str, left: &str, right: &str) -> String {
    if left == empty_root(label) {
        return right.to_string();
    }
    if right == empty_root(label) {
        return left.to_string();
    }
    merkle_root(
        &format!("PRIVATE-L2-RECURSIVE-PROOF-AGGREGATOR-{label}-MERGE"),
        &[
            Value::String(left.to_string()),
            Value::String(right.to_string()),
        ],
    )
}

fn merkle_from_strings<'a>(domain: &str, roots: impl IntoIterator<Item = &'a str>) -> String {
    merkle_root(
        domain,
        &roots
            .into_iter()
            .map(|root| Value::String(root.to_string()))
            .collect::<Vec<_>>(),
    )
}

fn require_root(label: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        return Err(format!("{label} must be a non-empty root or commitment"));
    }
    if value.len() < 16 {
        return Err(format!("{label} is too short to be privacy-safe"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root(label: &str) -> String {
        l2_hash("TEST-ROOT", &[HashPart::Str(label)])
    }

    #[test]
    fn submit_aggregate_and_settle_roots_only_flow() {
        let mut state = State::devnet();
        let first = state
            .submit_proof_job(
                ProofFlowKind::TokenMint,
                &root("flow-a"),
                &root("nullifier-a"),
                &root("output-a"),
                &root("input-a"),
                &root("proof-a"),
                &root("witness-a"),
                &root("pq-a"),
                &root("fee-a"),
                None,
                None,
                1_024,
                1,
                100,
                0,
                10,
                20,
            )
            .expect("submit first job");
        let second = state
            .submit_proof_job(
                ProofFlowKind::MoneroExit,
                &root("flow-b"),
                &root("nullifier-b"),
                &root("output-b"),
                &root("input-b"),
                &root("proof-b"),
                &root("witness-b"),
                &root("pq-b"),
                &root("fee-b"),
                None,
                Some(root("monero-b")),
                1_024,
                2,
                120,
                0,
                10,
                20,
            )
            .expect("submit second job");
        let aggregate = state
            .aggregate_batch(&[first.job_id, second.job_id], 11)
            .expect("aggregate batch");
        assert_eq!(aggregate.status, AggregateStatus::SettlementReady);
        assert_eq!(state.counters.aggregated_batches, 1);
        let settlement = state
            .settle_aggregate(
                &aggregate.aggregate_id,
                &root("authority"),
                &root("pq-attestation"),
                aggregate.settlement_ready_at_height,
            )
            .expect("settle aggregate");
        assert_eq!(settlement.aggregate_id, aggregate.aggregate_id);
        assert_eq!(state.counters.settled_aggregates, 1);
        assert!(state.public_record().get("state_root").is_none());
        assert_eq!(state.state_root().len(), 64);
    }
}
