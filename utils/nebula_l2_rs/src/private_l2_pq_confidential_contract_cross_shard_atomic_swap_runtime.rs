use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2PqConfidentialContractCrossShardAtomicSwapRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-confidential-contract-cross-shard-atomic-swap-runtime-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_CROSS_SHARD_ATOMIC_SWAP_RUNTIME_PROTOCOL_VERSION:
    &str = PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const HTLC_NULLIFIER_SUITE: &str =
    "confidential-contract-htlc-nullifier-commitment+height-timelock-v1";
pub const SHARD_ESCROW_LANE_SUITE: &str = "roots-only-cross-shard-contract-escrow-lane-v1";
pub const PQ_SWAP_ATTESTATION_SUITE: &str =
    "ML-DSA-87+SLH-DSA-SHAKE-256f-cross-shard-swap-attestation-v1";
pub const PRIVATE_SOLVER_FILL_SUITE: &str =
    "sealed-private-solver-fill+cross-shard-atomic-settlement-v1";
pub const TIMEOUT_ROLLBACK_SUITE: &str =
    "deterministic-timeout-rollback-policy+redacted-contract-state-v1";
pub const LOW_FEE_REBATE_SUITE: &str = "low-fee-cross-shard-confidential-swap-rebate-v1";
pub const PUBLIC_RECORD_SUITE: &str =
    "roots-only-confidential-cross-shard-atomic-swap-public-record-v1";
pub const DEVNET_NETWORK_ID: &str = "nebula-private-l2-devnet";
pub const DEVNET_HEIGHT: u64 = 1_884_000;
pub const DEFAULT_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEFAULT_REBATE_ASSET_ID: &str = "dnr-low-fee-rebate-devnet";
pub const DEFAULT_BASE_ASSET_ID: &str = "private-xmr-devnet";
pub const DEFAULT_QUOTE_ASSET_ID: &str = "private-dusd-devnet";
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_TARGET_PRIVACY_SET_SIZE: u64 = 262_144;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_SWAP_TTL_BLOCKS: u64 = 72;
pub const DEFAULT_CLAIM_WINDOW_BLOCKS: u64 = 18;
pub const DEFAULT_ROLLBACK_GRACE_BLOCKS: u64 = 12;
pub const DEFAULT_ATTESTATION_TTL_BLOCKS: u64 = 144;
pub const DEFAULT_SOLVER_FILL_TTL_BLOCKS: u64 = 10;
pub const DEFAULT_REDACTION_BUDGET_BYTES: u64 = 16_384;
pub const DEFAULT_MAX_SOLVER_FEE_BPS: u64 = 18;
pub const DEFAULT_LOW_FEE_REBATE_BPS: u64 = 6;
pub const DEFAULT_MAX_ESCROW_LANE_FEE_BPS: u64 = 24;
pub const MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SwapDirection {
    ShardAToShardB,
    ShardBToShardA,
    Bidirectional,
    SolverInventoryRebalance,
    ContractCallbackSettlement,
}

impl SwapDirection {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ShardAToShardB => "shard_a_to_shard_b",
            Self::ShardBToShardA => "shard_b_to_shard_a",
            Self::Bidirectional => "bidirectional",
            Self::SolverInventoryRebalance => "solver_inventory_rebalance",
            Self::ContractCallbackSettlement => "contract_callback_settlement",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SwapStatus {
    Proposed,
    Escrowed,
    HtlcCommitted,
    Attested,
    SolverFilled,
    Claimable,
    Settled,
    RolledBack,
    TimedOut,
    Disputed,
}

impl SwapStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::Escrowed => "escrowed",
            Self::HtlcCommitted => "htlc_committed",
            Self::Attested => "attested",
            Self::SolverFilled => "solver_filled",
            Self::Claimable => "claimable",
            Self::Settled => "settled",
            Self::RolledBack => "rolled_back",
            Self::TimedOut => "timed_out",
            Self::Disputed => "disputed",
        }
    }

    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Proposed
                | Self::Escrowed
                | Self::HtlcCommitted
                | Self::Attested
                | Self::SolverFilled
                | Self::Claimable
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LaneStatus {
    Open,
    FillOnly,
    ClaimOnly,
    Congested,
    Paused,
    Retired,
}

impl LaneStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::FillOnly => "fill_only",
            Self::ClaimOnly => "claim_only",
            Self::Congested => "congested",
            Self::Paused => "paused",
            Self::Retired => "retired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RollbackPolicyKind {
    ClaimTimeout,
    AttestationTimeout,
    SolverFillTimeout,
    ReorgRollback,
    NullifierConflict,
    GovernancePause,
}

impl RollbackPolicyKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ClaimTimeout => "claim_timeout",
            Self::AttestationTimeout => "attestation_timeout",
            Self::SolverFillTimeout => "solver_fill_timeout",
            Self::ReorgRollback => "reorg_rollback",
            Self::NullifierConflict => "nullifier_conflict",
            Self::GovernancePause => "governance_pause",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub network_id: String,
    pub fee_asset_id: String,
    pub rebate_asset_id: String,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub swap_ttl_blocks: u64,
    pub claim_window_blocks: u64,
    pub rollback_grace_blocks: u64,
    pub attestation_ttl_blocks: u64,
    pub solver_fill_ttl_blocks: u64,
    pub redaction_budget_bytes: u64,
    pub max_solver_fee_bps: u64,
    pub low_fee_rebate_bps: u64,
    pub max_escrow_lane_fee_bps: u64,
    pub deterministic_roots: bool,
    pub enable_private_solver_fills: bool,
    pub enable_timeout_rollback: bool,
    pub enable_low_fee_rebates: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            network_id: DEVNET_NETWORK_ID.to_string(),
            fee_asset_id: DEFAULT_FEE_ASSET_ID.to_string(),
            rebate_asset_id: DEFAULT_REBATE_ASSET_ID.to_string(),
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            swap_ttl_blocks: DEFAULT_SWAP_TTL_BLOCKS,
            claim_window_blocks: DEFAULT_CLAIM_WINDOW_BLOCKS,
            rollback_grace_blocks: DEFAULT_ROLLBACK_GRACE_BLOCKS,
            attestation_ttl_blocks: DEFAULT_ATTESTATION_TTL_BLOCKS,
            solver_fill_ttl_blocks: DEFAULT_SOLVER_FILL_TTL_BLOCKS,
            redaction_budget_bytes: DEFAULT_REDACTION_BUDGET_BYTES,
            max_solver_fee_bps: DEFAULT_MAX_SOLVER_FEE_BPS,
            low_fee_rebate_bps: DEFAULT_LOW_FEE_REBATE_BPS,
            max_escrow_lane_fee_bps: DEFAULT_MAX_ESCROW_LANE_FEE_BPS,
            deterministic_roots: true,
            enable_private_solver_fills: true,
            enable_timeout_rollback: true,
            enable_low_fee_rebates: true,
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub swaps_opened: u64,
    pub htlc_commitments: u64,
    pub nullifiers_registered: u64,
    pub escrow_lanes: u64,
    pub pq_attestations: u64,
    pub solver_fills: u64,
    pub settled: u64,
    pub rolled_back: u64,
    pub timed_out: u64,
    pub rebates_issued: u64,
    pub redaction_bytes_used: u64,
    pub root_updates: u64,
    pub public_records: u64,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub counters_root: String,
    pub swap_contract_root: String,
    pub htlc_nullifier_root: String,
    pub shard_escrow_lane_root: String,
    pub pq_attestation_root: String,
    pub private_solver_fill_root: String,
    pub rollback_policy_root: String,
    pub low_fee_rebate_root: String,
    pub redaction_budget_root: String,
    pub deterministic_root: String,
    pub public_record_root: String,
    pub state_root: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SwapContract {
    pub swap_id: String,
    pub contract_id: String,
    pub direction: SwapDirection,
    pub status: SwapStatus,
    pub source_shard: u16,
    pub target_shard: u16,
    pub maker_commitment: String,
    pub taker_commitment: String,
    pub input_asset_id: String,
    pub output_asset_id: String,
    pub amount_commitment: String,
    pub min_output_commitment: String,
    pub escrow_lane_id: String,
    pub htlc_commitment_id: String,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct HtlcNullifierCommitment {
    pub commitment_id: String,
    pub swap_id: String,
    pub hashlock_root: String,
    pub timelock_height: u64,
    pub nullifier_commitment: String,
    pub refund_commitment: String,
    pub claim_commitment: String,
    pub redacted_preimage_root: String,
    pub consumed: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ShardEscrowLane {
    pub lane_id: String,
    pub source_shard: u16,
    pub target_shard: u16,
    pub lane_status: LaneStatus,
    pub capacity_commitment: String,
    pub escrow_root: String,
    pub inflight_root: String,
    pub lane_fee_bps: u64,
    pub low_fee_rebate_enabled: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqSwapAttestation {
    pub attestation_id: String,
    pub swap_id: String,
    pub lane_id: String,
    pub attestor_set_root: String,
    pub pq_signature_root: String,
    pub state_transition_root: String,
    pub security_bits: u16,
    pub accepted_at_height: u64,
    pub expires_at_height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivateSolverFill {
    pub fill_id: String,
    pub swap_id: String,
    pub solver_commitment: String,
    pub fill_note_commitment: String,
    pub route_commitment_root: String,
    pub solver_fee_bps: u64,
    pub filled_at_height: u64,
    pub expires_at_height: u64,
    pub sealed: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TimeoutRollbackPolicy {
    pub policy_id: String,
    pub swap_id: String,
    pub kind: RollbackPolicyKind,
    pub trigger_height: u64,
    pub rollback_to_root: String,
    pub refund_commitment: String,
    pub executed: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LowFeeRebate {
    pub rebate_id: String,
    pub swap_id: String,
    pub beneficiary_commitment: String,
    pub rebate_asset_id: String,
    pub rebate_bps: u64,
    pub rebate_commitment: String,
    pub issued_at_height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RedactionBudget {
    pub budget_id: String,
    pub subject_id: String,
    pub allowed_bytes: u64,
    pub used_bytes: u64,
    pub redacted_payload_root: String,
    pub exhausted: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub height: u64,
    pub swaps: BTreeMap<String, SwapContract>,
    pub htlc_nullifiers: BTreeMap<String, HtlcNullifierCommitment>,
    pub escrow_lanes: BTreeMap<String, ShardEscrowLane>,
    pub pq_attestations: BTreeMap<String, PqSwapAttestation>,
    pub solver_fills: BTreeMap<String, PrivateSolverFill>,
    pub rollback_policies: BTreeMap<String, TimeoutRollbackPolicy>,
    pub low_fee_rebates: BTreeMap<String, LowFeeRebate>,
    pub redaction_budgets: BTreeMap<String, RedactionBudget>,
    pub deterministic_roots: BTreeSet<String>,
    pub public_records: Vec<Value>,
}

impl State {
    pub fn new(config: Config, height: u64) -> Self {
        let mut state = Self {
            config,
            counters: Counters::default(),
            roots: Roots::default(),
            height,
            swaps: BTreeMap::new(),
            htlc_nullifiers: BTreeMap::new(),
            escrow_lanes: BTreeMap::new(),
            pq_attestations: BTreeMap::new(),
            solver_fills: BTreeMap::new(),
            rollback_policies: BTreeMap::new(),
            low_fee_rebates: BTreeMap::new(),
            redaction_budgets: BTreeMap::new(),
            deterministic_roots: BTreeSet::new(),
            public_records: Vec::new(),
        };
        state.refresh_roots();
        state
    }

    pub fn devnet() -> Self {
        devnet()
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "chain_id": CHAIN_ID,
            "height": self.height,
            "network_id": self.config.network_id,
            "hash_suite": HASH_SUITE,
            "suites": {
                "htlc_nullifier": HTLC_NULLIFIER_SUITE,
                "shard_escrow_lane": SHARD_ESCROW_LANE_SUITE,
                "pq_swap_attestation": PQ_SWAP_ATTESTATION_SUITE,
                "private_solver_fill": PRIVATE_SOLVER_FILL_SUITE,
                "timeout_rollback": TIMEOUT_ROLLBACK_SUITE,
                "low_fee_rebate": LOW_FEE_REBATE_SUITE,
                "public_record": PUBLIC_RECORD_SUITE,
            },
            "counters": self.counters,
            "roots": self.roots,
            "config": roots_only(&self.config),
        })
    }

    pub fn state_root(&self) -> String {
        self.roots.state_root.clone()
    }

    pub fn insert_escrow_lane(&mut self, lane: ShardEscrowLane) -> Result<()> {
        require_bps(
            lane.lane_fee_bps,
            self.config.max_escrow_lane_fee_bps,
            "lane_fee_bps",
        )?;
        require_non_empty("lane_id", &lane.lane_id)?;
        self.escrow_lanes.insert(lane.lane_id.clone(), lane);
        self.counters.escrow_lanes = self.escrow_lanes.len() as u64;
        self.refresh_roots();
        Ok(())
    }

    pub fn open_swap(&mut self, swap: SwapContract) -> Result<()> {
        require_non_empty("swap_id", &swap.swap_id)?;
        require_non_empty("contract_id", &swap.contract_id)?;
        require_non_empty("escrow_lane_id", &swap.escrow_lane_id)?;
        require!(
            self.escrow_lanes.contains_key(&swap.escrow_lane_id),
            "escrow lane is not registered",
        )?;
        require!(
            swap.expires_at_height > swap.opened_at_height,
            "swap expiry must be after open height",
        )?;
        self.public_records.push(json!({
            "event": "swap_opened",
            "swap_id": swap.swap_id,
            "contract_id": swap.contract_id,
            "direction": swap.direction.as_str(),
            "status": swap.status.as_str(),
            "source_shard": swap.source_shard,
            "target_shard": swap.target_shard,
            "escrow_lane_id": swap.escrow_lane_id,
        }));
        self.swaps.insert(swap.swap_id.clone(), swap);
        self.counters.swaps_opened = self.swaps.len() as u64;
        self.counters.public_records = self.public_records.len() as u64;
        self.refresh_roots();
        Ok(())
    }

    pub fn register_htlc_nullifier(&mut self, commitment: HtlcNullifierCommitment) -> Result<()> {
        require_non_empty("commitment_id", &commitment.commitment_id)?;
        require!(
            self.swaps.contains_key(&commitment.swap_id),
            "swap is not registered for htlc/nullifier commitment",
        )?;
        self.htlc_nullifiers
            .insert(commitment.commitment_id.clone(), commitment);
        self.counters.htlc_commitments = self.htlc_nullifiers.len() as u64;
        self.counters.nullifiers_registered = self
            .htlc_nullifiers
            .values()
            .filter(|commitment| !commitment.nullifier_commitment.is_empty())
            .count() as u64;
        self.refresh_roots();
        Ok(())
    }

    pub fn record_pq_attestation(&mut self, attestation: PqSwapAttestation) -> Result<()> {
        require!(
            attestation.security_bits >= self.config.min_pq_security_bits,
            "pq attestation security bits below config floor",
        )?;
        require!(
            self.swaps.contains_key(&attestation.swap_id),
            "swap is not registered for pq attestation",
        )?;
        self.pq_attestations
            .insert(attestation.attestation_id.clone(), attestation);
        self.counters.pq_attestations = self.pq_attestations.len() as u64;
        self.refresh_roots();
        Ok(())
    }

    pub fn record_solver_fill(&mut self, fill: PrivateSolverFill) -> Result<()> {
        require_bps(
            fill.solver_fee_bps,
            self.config.max_solver_fee_bps,
            "solver_fee_bps",
        )?;
        require!(
            self.config.enable_private_solver_fills,
            "private solver fills are disabled",
        )?;
        require!(
            self.swaps.contains_key(&fill.swap_id),
            "swap is not registered for solver fill",
        )?;
        self.solver_fills.insert(fill.fill_id.clone(), fill);
        self.counters.solver_fills = self.solver_fills.len() as u64;
        self.refresh_roots();
        Ok(())
    }

    pub fn install_rollback_policy(&mut self, policy: TimeoutRollbackPolicy) -> Result<()> {
        require!(
            self.config.enable_timeout_rollback,
            "timeout rollback policies are disabled",
        )?;
        require!(
            self.swaps.contains_key(&policy.swap_id),
            "swap is not registered for rollback policy",
        )?;
        self.rollback_policies
            .insert(policy.policy_id.clone(), policy);
        self.refresh_roots();
        Ok(())
    }

    pub fn issue_low_fee_rebate(&mut self, rebate: LowFeeRebate) -> Result<()> {
        require!(
            self.config.enable_low_fee_rebates,
            "low-fee rebates are disabled",
        )?;
        require_bps(
            rebate.rebate_bps,
            self.config.low_fee_rebate_bps,
            "rebate_bps",
        )?;
        self.low_fee_rebates
            .insert(rebate.rebate_id.clone(), rebate);
        self.counters.rebates_issued = self.low_fee_rebates.len() as u64;
        self.refresh_roots();
        Ok(())
    }

    pub fn reserve_redaction_budget(&mut self, budget: RedactionBudget) -> Result<()> {
        require!(
            budget.allowed_bytes <= self.config.redaction_budget_bytes,
            "redaction budget exceeds configured cap",
        )?;
        self.counters.redaction_bytes_used = self
            .counters
            .redaction_bytes_used
            .saturating_add(budget.used_bytes);
        self.redaction_budgets
            .insert(budget.budget_id.clone(), budget);
        self.refresh_roots();
        Ok(())
    }

    pub fn refresh_roots(&mut self) {
        self.roots.config_root = root_from_record("CONFIG", &json!(self.config));
        self.roots.counters_root = root_from_record("COUNTERS", &json!(self.counters));
        self.roots.swap_contract_root = map_root("SWAP-CONTRACTS", &self.swaps);
        self.roots.htlc_nullifier_root = map_root("HTLC-NULLIFIERS", &self.htlc_nullifiers);
        self.roots.shard_escrow_lane_root = map_root("SHARD-ESCROW-LANES", &self.escrow_lanes);
        self.roots.pq_attestation_root = map_root("PQ-SWAP-ATTESTATIONS", &self.pq_attestations);
        self.roots.private_solver_fill_root = map_root("PRIVATE-SOLVER-FILLS", &self.solver_fills);
        self.roots.rollback_policy_root = map_root("ROLLBACK-POLICIES", &self.rollback_policies);
        self.roots.low_fee_rebate_root = map_root("LOW-FEE-REBATES", &self.low_fee_rebates);
        self.roots.redaction_budget_root = map_root("REDACTION-BUDGETS", &self.redaction_budgets);
        self.roots.public_record_root = list_root("PUBLIC-RECORDS", &self.public_records);
        self.roots.deterministic_root = deterministic_root(self);
        self.deterministic_roots
            .insert(self.roots.deterministic_root.clone());
        self.roots.state_root = root_from_record(
            "STATE",
            &json!({
                "config_root": self.roots.config_root,
                "counters_root": self.roots.counters_root,
                "swap_contract_root": self.roots.swap_contract_root,
                "htlc_nullifier_root": self.roots.htlc_nullifier_root,
                "shard_escrow_lane_root": self.roots.shard_escrow_lane_root,
                "pq_attestation_root": self.roots.pq_attestation_root,
                "private_solver_fill_root": self.roots.private_solver_fill_root,
                "rollback_policy_root": self.roots.rollback_policy_root,
                "low_fee_rebate_root": self.roots.low_fee_rebate_root,
                "redaction_budget_root": self.roots.redaction_budget_root,
                "public_record_root": self.roots.public_record_root,
                "deterministic_root": self.roots.deterministic_root,
                "height": self.height,
            }),
        );
        self.counters.root_updates = self.counters.root_updates.saturating_add(1);
    }
}

pub fn devnet() -> State {
    let mut state = State::new(Config::default(), DEVNET_HEIGHT);
    let lane = ShardEscrowLane {
        lane_id: "escrow-lane-shard-3-to-7-devnet-alpha".to_string(),
        source_shard: 3,
        target_shard: 7,
        lane_status: LaneStatus::Open,
        capacity_commitment: demo_commitment("lane-capacity", 1),
        escrow_root: demo_root("lane-escrow", 1),
        inflight_root: demo_root("lane-inflight", 1),
        lane_fee_bps: DEFAULT_MAX_ESCROW_LANE_FEE_BPS / 2,
        low_fee_rebate_enabled: true,
    };
    let _ = state.insert_escrow_lane(lane);
    let swap = SwapContract {
        swap_id: "cross-shard-atomic-swap-devnet-alpha-001".to_string(),
        contract_id: "confidential-contract-swap-router-alpha".to_string(),
        direction: SwapDirection::ShardAToShardB,
        status: SwapStatus::HtlcCommitted,
        source_shard: 3,
        target_shard: 7,
        maker_commitment: demo_commitment("maker-account", 1),
        taker_commitment: demo_commitment("taker-account", 1),
        input_asset_id: DEFAULT_BASE_ASSET_ID.to_string(),
        output_asset_id: DEFAULT_QUOTE_ASSET_ID.to_string(),
        amount_commitment: demo_commitment("input-amount", 1),
        min_output_commitment: demo_commitment("min-output", 1),
        escrow_lane_id: "escrow-lane-shard-3-to-7-devnet-alpha".to_string(),
        htlc_commitment_id: "htlc-nullifier-devnet-alpha-001".to_string(),
        opened_at_height: state.height,
        expires_at_height: state.height + DEFAULT_SWAP_TTL_BLOCKS,
    };
    let _ = state.open_swap(swap);
    let _ = state.register_htlc_nullifier(HtlcNullifierCommitment {
        commitment_id: "htlc-nullifier-devnet-alpha-001".to_string(),
        swap_id: "cross-shard-atomic-swap-devnet-alpha-001".to_string(),
        hashlock_root: demo_root("hashlock", 1),
        timelock_height: state.height + DEFAULT_CLAIM_WINDOW_BLOCKS,
        nullifier_commitment: demo_commitment("nullifier", 1),
        refund_commitment: demo_commitment("refund", 1),
        claim_commitment: demo_commitment("claim", 1),
        redacted_preimage_root: demo_root("redacted-preimage", 1),
        consumed: false,
    });
    let _ = state.reserve_redaction_budget(RedactionBudget {
        budget_id: "redaction-budget-swap-alpha-001".to_string(),
        subject_id: "cross-shard-atomic-swap-devnet-alpha-001".to_string(),
        allowed_bytes: DEFAULT_REDACTION_BUDGET_BYTES,
        used_bytes: 4096,
        redacted_payload_root: demo_root("redacted-public-record", 1),
        exhausted: false,
    });
    state.refresh_roots();
    state
}

pub fn demo() -> State {
    let mut state = devnet();
    let _ = state.record_pq_attestation(PqSwapAttestation {
        attestation_id: "pq-swap-attestation-devnet-alpha-001".to_string(),
        swap_id: "cross-shard-atomic-swap-devnet-alpha-001".to_string(),
        lane_id: "escrow-lane-shard-3-to-7-devnet-alpha".to_string(),
        attestor_set_root: demo_root("attestor-set", 1),
        pq_signature_root: demo_root("pq-signature", 1),
        state_transition_root: demo_root("state-transition", 1),
        security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        accepted_at_height: state.height,
        expires_at_height: state.height + DEFAULT_ATTESTATION_TTL_BLOCKS,
    });
    let _ = state.record_solver_fill(PrivateSolverFill {
        fill_id: "private-solver-fill-devnet-alpha-001".to_string(),
        swap_id: "cross-shard-atomic-swap-devnet-alpha-001".to_string(),
        solver_commitment: demo_commitment("solver-alpha", 1),
        fill_note_commitment: demo_commitment("solver-fill-note", 1),
        route_commitment_root: demo_root("solver-route", 1),
        solver_fee_bps: 9,
        filled_at_height: state.height,
        expires_at_height: state.height + DEFAULT_SOLVER_FILL_TTL_BLOCKS,
        sealed: true,
    });
    let _ = state.install_rollback_policy(TimeoutRollbackPolicy {
        policy_id: "timeout-rollback-policy-devnet-alpha-001".to_string(),
        swap_id: "cross-shard-atomic-swap-devnet-alpha-001".to_string(),
        kind: RollbackPolicyKind::ClaimTimeout,
        trigger_height: state.height + DEFAULT_SWAP_TTL_BLOCKS + DEFAULT_ROLLBACK_GRACE_BLOCKS,
        rollback_to_root: state.roots.state_root.clone(),
        refund_commitment: demo_commitment("rollback-refund", 1),
        executed: false,
    });
    let _ = state.issue_low_fee_rebate(LowFeeRebate {
        rebate_id: "low-fee-rebate-cross-shard-swap-alpha-001".to_string(),
        swap_id: "cross-shard-atomic-swap-devnet-alpha-001".to_string(),
        beneficiary_commitment: demo_commitment("maker-account", 1),
        rebate_asset_id: DEFAULT_REBATE_ASSET_ID.to_string(),
        rebate_bps: DEFAULT_LOW_FEE_REBATE_BPS,
        rebate_commitment: demo_commitment("rebate-note", 1),
        issued_at_height: state.height,
    });
    state.refresh_roots();
    state
}

pub fn public_record(state: &State) -> Value {
    state.public_record()
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}

pub fn root_from_record(domain: &str, record: &Value) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-CROSS-SHARD-ATOMIC-SWAP-ROOT",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(domain),
            HashPart::Json(record),
        ],
        32,
    )
}

pub fn map_root<T>(domain: &str, map: &BTreeMap<String, T>) -> String
where
    T: Serialize,
{
    let leaves = map
        .iter()
        .map(|(key, value)| {
            Value::String(root_from_record(
                domain,
                &json!({
                    "key": key,
                    "value": value,
                }),
            ))
        })
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

pub fn list_root(domain: &str, records: &[Value]) -> String {
    let leaves = records
        .iter()
        .map(|record| Value::String(root_from_record(domain, record)))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

pub fn deterministic_root(state: &State) -> String {
    root_from_record(
        "DETERMINISTIC-ROOTS",
        &json!({
            "height": state.height,
            "swap_contract_root": state.roots.swap_contract_root,
            "htlc_nullifier_root": state.roots.htlc_nullifier_root,
            "shard_escrow_lane_root": state.roots.shard_escrow_lane_root,
            "pq_attestation_root": state.roots.pq_attestation_root,
            "private_solver_fill_root": state.roots.private_solver_fill_root,
            "rollback_policy_root": state.roots.rollback_policy_root,
            "low_fee_rebate_root": state.roots.low_fee_rebate_root,
            "redaction_budget_root": state.roots.redaction_budget_root,
        }),
    )
}

pub fn roots_only<T>(value: &T) -> Value
where
    T: Serialize,
{
    json!({
        "kind": "roots_only",
        "root": root_from_record("ROOTS-ONLY", &json!(value)),
    })
}

pub fn demo_root(label: &str, index: u64) -> String {
    root_from_record(
        "DEMO-ROOT",
        &json!({
            "label": label,
            "index": index,
        }),
    )
}

pub fn demo_commitment(label: &str, index: u64) -> String {
    root_from_record(
        "DEMO-COMMITMENT",
        &json!({
            "label": label,
            "index": index,
        }),
    )
}

fn require(condition: bool, message: &str) -> Result<()> {
    if !condition {
        return Err(message.to_string());
    }
    Ok(())
}

fn require_non_empty(label: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        return Err(format!("cross-shard atomic swap {label} is required"));
    }
    Ok(())
}

fn require_bps(value: u64, max: u64, label: &str) -> Result<()> {
    if value > max || value > MAX_BPS {
        return Err(format!("cross-shard atomic swap {label} exceeds fee cap"));
    }
    Ok(())
}
