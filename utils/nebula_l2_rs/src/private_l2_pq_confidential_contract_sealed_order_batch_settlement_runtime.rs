use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2PqConfidentialContractSealedOrderBatchSettlementRuntimeResult<T> =
    std::result::Result<T, String>;
pub type Result<T> = std::result::Result<T, String>;
pub type Runtime = State;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_SEALED_ORDER_BATCH_SETTLEMENT_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-confidential-contract-sealed-order-batch-settlement-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_SEALED_ORDER_BATCH_SETTLEMENT_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_ATTESTATION_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-confidential-settlement-v1";
pub const SEALED_ORDER_LOT_SCHEME: &str = "pq-threshold-sealed-order-lot-root-v1";
pub const BYTECODE_LANE_SCHEME: &str = "confidential-contract-settlement-bytecode-lane-root-v1";
pub const SETTLEMENT_BATCH_SCHEME: &str = "sealed-order-frequent-batch-settlement-root-v1";
pub const SOLVER_FILL_SCHEME: &str = "confidential-solver-fill-commitment-root-v1";
pub const ATTESTATION_SCHEME: &str = "pq-settlement-attestation-root-v1";
pub const REBATE_SCHEME: &str = "low-fee-confidential-settlement-rebate-root-v1";
pub const REDACTION_BUDGET_SCHEME: &str = "privacy-redaction-budget-root-v1";
pub const FIXTURE_SCHEME: &str = "devnet-demo-confidential-settlement-fixture-root-v1";
pub const DEVNET_L2_NETWORK: &str = "nebula-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEVNET_BASE_ASSET_ID: &str = "dxmr";
pub const DEVNET_QUOTE_ASSET_ID: &str = "dusd";
pub const DEVNET_HEIGHT: u64 = 4_096;
pub const DEFAULT_BATCH_EPOCH_BLOCKS: u64 = 8;
pub const DEFAULT_REVEAL_TIMEOUT_BLOCKS: u64 = 6;
pub const DEFAULT_ROLLBACK_WINDOW_BLOCKS: u64 = 64;
pub const DEFAULT_SETTLEMENT_FINALITY_BLOCKS: u64 = 12;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 262_144;
pub const DEFAULT_REDACTION_BUDGET_UNITS: u64 = 1_000_000;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 9;
pub const DEFAULT_LOW_FEE_REBATE_BPS: u64 = 4;
pub const DEFAULT_SOLVER_SLASH_BPS: u64 = 3_000;
pub const DEFAULT_TIMEOUT_PENALTY_BPS: u64 = 750;
pub const DEFAULT_MAX_ORDERS_PER_BATCH: usize = 1_024;
pub const DEFAULT_MAX_FILLS_PER_BATCH: usize = 2_048;
pub const DEFAULT_MAX_BYTECODE_LANES: usize = 256;
pub const DEFAULT_MAX_FIXTURES: usize = 64;
pub const MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ContractSettlementLaneKind {
    ConfidentialSwap,
    LendingRepay,
    Liquidation,
    PerpetualFunding,
    VaultRebalance,
    OracleUpdate,
    GovernanceExecution,
    EmergencyRollback,
}

impl ContractSettlementLaneKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ConfidentialSwap => "confidential_swap",
            Self::LendingRepay => "lending_repay",
            Self::Liquidation => "liquidation",
            Self::PerpetualFunding => "perpetual_funding",
            Self::VaultRebalance => "vault_rebalance",
            Self::OracleUpdate => "oracle_update",
            Self::GovernanceExecution => "governance_execution",
            Self::EmergencyRollback => "emergency_rollback",
        }
    }

    pub fn priority_weight(self) -> u64 {
        match self {
            Self::EmergencyRollback => 10_000,
            Self::Liquidation => 9_250,
            Self::OracleUpdate => 8_800,
            Self::ConfidentialSwap => 8_400,
            Self::PerpetualFunding => 8_100,
            Self::LendingRepay => 7_600,
            Self::VaultRebalance => 7_200,
            Self::GovernanceExecution => 5_500,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SealedOrderLotStatus {
    Sealed,
    Queued,
    RevealedToSolver,
    Filled,
    PartiallyFilled,
    Expired,
    RolledBack,
}

impl SealedOrderLotStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sealed => "sealed",
            Self::Queued => "queued",
            Self::RevealedToSolver => "revealed_to_solver",
            Self::Filled => "filled",
            Self::PartiallyFilled => "partially_filled",
            Self::Expired => "expired",
            Self::RolledBack => "rolled_back",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TimeoutPolicyKind {
    RefundOrder,
    RollbackBatch,
    SlashSolver,
    ExtendReveal,
}

impl TimeoutPolicyKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RefundOrder => "refund_order",
            Self::RollbackBatch => "rollback_batch",
            Self::SlashSolver => "slash_solver",
            Self::ExtendReveal => "extend_reveal",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationStatus {
    Pending,
    QuorumSigned,
    Finalized,
    Challenged,
    Rejected,
}

impl AttestationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::QuorumSigned => "quorum_signed",
            Self::Finalized => "finalized",
            Self::Challenged => "challenged",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub l2_network: String,
    pub fee_asset_id: String,
    pub batch_epoch_blocks: u64,
    pub reveal_timeout_blocks: u64,
    pub rollback_window_blocks: u64,
    pub settlement_finality_blocks: u64,
    pub min_privacy_set_size: u64,
    pub redaction_budget_units: u64,
    pub max_user_fee_bps: u64,
    pub low_fee_rebate_bps: u64,
    pub solver_slash_bps: u64,
    pub timeout_penalty_bps: u64,
    pub max_orders_per_batch: usize,
    pub max_fills_per_batch: usize,
    pub max_bytecode_lanes: usize,
    pub max_fixtures: usize,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            l2_network: DEVNET_L2_NETWORK.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            batch_epoch_blocks: DEFAULT_BATCH_EPOCH_BLOCKS,
            reveal_timeout_blocks: DEFAULT_REVEAL_TIMEOUT_BLOCKS,
            rollback_window_blocks: DEFAULT_ROLLBACK_WINDOW_BLOCKS,
            settlement_finality_blocks: DEFAULT_SETTLEMENT_FINALITY_BLOCKS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            redaction_budget_units: DEFAULT_REDACTION_BUDGET_UNITS,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            low_fee_rebate_bps: DEFAULT_LOW_FEE_REBATE_BPS,
            solver_slash_bps: DEFAULT_SOLVER_SLASH_BPS,
            timeout_penalty_bps: DEFAULT_TIMEOUT_PENALTY_BPS,
            max_orders_per_batch: DEFAULT_MAX_ORDERS_PER_BATCH,
            max_fills_per_batch: DEFAULT_MAX_FILLS_PER_BATCH,
            max_bytecode_lanes: DEFAULT_MAX_BYTECODE_LANES,
            max_fixtures: DEFAULT_MAX_FIXTURES,
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq, Serialize)]
pub struct Counters {
    pub bytecode_lanes: u64,
    pub sealed_order_lots: u64,
    pub settlement_batches: u64,
    pub solver_fills: u64,
    pub pq_attestations: u64,
    pub low_fee_rebates: u64,
    pub redaction_budgets: u64,
    pub timeout_rollbacks: u64,
    pub devnet_fixtures: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct Roots {
    pub bytecode_lane_root: String,
    pub sealed_order_lot_root: String,
    pub settlement_batch_root: String,
    pub solver_fill_root: String,
    pub pq_attestation_root: String,
    pub low_fee_rebate_root: String,
    pub redaction_budget_root: String,
    pub fixture_root: String,
}

impl Default for Roots {
    fn default() -> Self {
        Self {
            bytecode_lane_root: merkle_root(BYTECODE_LANE_SCHEME, &[]),
            sealed_order_lot_root: merkle_root(SEALED_ORDER_LOT_SCHEME, &[]),
            settlement_batch_root: merkle_root(SETTLEMENT_BATCH_SCHEME, &[]),
            solver_fill_root: merkle_root(SOLVER_FILL_SCHEME, &[]),
            pq_attestation_root: merkle_root(ATTESTATION_SCHEME, &[]),
            low_fee_rebate_root: merkle_root(REBATE_SCHEME, &[]),
            redaction_budget_root: merkle_root(REDACTION_BUDGET_SCHEME, &[]),
            fixture_root: merkle_root(FIXTURE_SCHEME, &[]),
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct BytecodeLane {
    pub lane_id: String,
    pub kind: ContractSettlementLaneKind,
    pub contract_commitment: String,
    pub bytecode_root: String,
    pub verifier_key_root: String,
    pub priority_weight: u64,
    pub enabled: bool,
}

impl BytecodeLane {
    pub fn public_record(&self) -> Value {
        json!({
            "lane_id": self.lane_id,
            "kind": self.kind.as_str(),
            "contract_commitment": self.contract_commitment,
            "bytecode_root": self.bytecode_root,
            "verifier_key_root": self.verifier_key_root,
            "priority_weight": self.priority_weight,
            "enabled": self.enabled,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct SealedOrderLot {
    pub lot_id: String,
    pub lane_id: String,
    pub owner_commitment: String,
    pub encrypted_order_root: String,
    pub nullifier_root: String,
    pub base_asset_id: String,
    pub quote_asset_id: String,
    pub max_fee_bps: u64,
    pub status: SealedOrderLotStatus,
    pub submitted_at_height: u64,
    pub expires_at_height: u64,
}

impl SealedOrderLot {
    pub fn public_record(&self) -> Value {
        json!({
            "lot_id": self.lot_id,
            "lane_id": self.lane_id,
            "owner_commitment": self.owner_commitment,
            "encrypted_order_root": self.encrypted_order_root,
            "nullifier_root": self.nullifier_root,
            "base_asset_id": self.base_asset_id,
            "quote_asset_id": self.quote_asset_id,
            "max_fee_bps": self.max_fee_bps,
            "status": self.status.as_str(),
            "submitted_at_height": self.submitted_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct SettlementBatch {
    pub batch_id: String,
    pub lane_id: String,
    pub epoch: u64,
    pub order_lot_root: String,
    pub pre_state_root: String,
    pub post_state_root: String,
    pub timeout_policy: TimeoutPolicyKind,
    pub rollback_deadline_height: u64,
}

impl SettlementBatch {
    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "lane_id": self.lane_id,
            "epoch": self.epoch,
            "order_lot_root": self.order_lot_root,
            "pre_state_root": self.pre_state_root,
            "post_state_root": self.post_state_root,
            "timeout_policy": self.timeout_policy.as_str(),
            "rollback_deadline_height": self.rollback_deadline_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct SolverFill {
    pub fill_id: String,
    pub batch_id: String,
    pub solver_commitment: String,
    pub fill_commitment_root: String,
    pub filled_lots: u64,
    pub surplus_commitment: String,
    pub low_fee_eligible: bool,
}

impl SolverFill {
    pub fn public_record(&self) -> Value {
        json!({
            "fill_id": self.fill_id,
            "batch_id": self.batch_id,
            "solver_commitment": self.solver_commitment,
            "fill_commitment_root": self.fill_commitment_root,
            "filled_lots": self.filled_lots,
            "surplus_commitment": self.surplus_commitment,
            "low_fee_eligible": self.low_fee_eligible,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct PqSettlementAttestation {
    pub attestation_id: String,
    pub batch_id: String,
    pub signer_set_root: String,
    pub transcript_root: String,
    pub pq_signature_root: String,
    pub security_bits: u16,
    pub status: AttestationStatus,
}

impl PqSettlementAttestation {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "batch_id": self.batch_id,
            "signer_set_root": self.signer_set_root,
            "transcript_root": self.transcript_root,
            "pq_signature_root": self.pq_signature_root,
            "security_bits": self.security_bits,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct LowFeeRebate {
    pub rebate_id: String,
    pub fill_id: String,
    pub beneficiary_commitment: String,
    pub fee_asset_id: String,
    pub rebate_bps: u64,
    pub rebate_note_root: String,
}

impl LowFeeRebate {
    pub fn public_record(&self) -> Value {
        json!({
            "rebate_id": self.rebate_id,
            "fill_id": self.fill_id,
            "beneficiary_commitment": self.beneficiary_commitment,
            "fee_asset_id": self.fee_asset_id,
            "rebate_bps": self.rebate_bps,
            "rebate_note_root": self.rebate_note_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct PrivacyRedactionBudget {
    pub budget_id: String,
    pub lane_id: String,
    pub disclosure_domain: String,
    pub allocated_units: u64,
    pub spent_units: u64,
    pub redacted_field_root: String,
}

impl PrivacyRedactionBudget {
    pub fn public_record(&self) -> Value {
        json!({
            "budget_id": self.budget_id,
            "lane_id": self.lane_id,
            "disclosure_domain": self.disclosure_domain,
            "allocated_units": self.allocated_units,
            "spent_units": self.spent_units,
            "redacted_field_root": self.redacted_field_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct DevnetFixture {
    pub fixture_id: String,
    pub label: String,
    pub deterministic_seed_root: String,
    pub expected_state_root: String,
}

impl DevnetFixture {
    pub fn public_record(&self) -> Value {
        json!({
            "fixture_id": self.fixture_id,
            "label": self.label,
            "deterministic_seed_root": self.deterministic_seed_root,
            "expected_state_root": self.expected_state_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub bytecode_lanes: BTreeMap<String, BytecodeLane>,
    pub sealed_order_lots: BTreeMap<String, SealedOrderLot>,
    pub settlement_batches: BTreeMap<String, SettlementBatch>,
    pub solver_fills: BTreeMap<String, SolverFill>,
    pub pq_attestations: BTreeMap<String, PqSettlementAttestation>,
    pub low_fee_rebates: BTreeMap<String, LowFeeRebate>,
    pub redaction_budgets: BTreeMap<String, PrivacyRedactionBudget>,
    pub devnet_fixtures: BTreeMap<String, DevnetFixture>,
}

impl State {
    pub fn devnet() -> Self {
        Self {
            config: Config::devnet(),
            counters: Counters::default(),
            roots: Roots::default(),
            bytecode_lanes: BTreeMap::new(),
            sealed_order_lots: BTreeMap::new(),
            settlement_batches: BTreeMap::new(),
            solver_fills: BTreeMap::new(),
            pq_attestations: BTreeMap::new(),
            low_fee_rebates: BTreeMap::new(),
            redaction_budgets: BTreeMap::new(),
            devnet_fixtures: BTreeMap::new(),
        }
    }

    pub fn demo() -> Self {
        let mut state = Self::devnet();
        let lane_kind = ContractSettlementLaneKind::ConfidentialSwap;
        let lane_id = lane_id(lane_kind, "contract-devnet-dex", 0);
        let lot_id = sealed_order_lot_id(&lane_id, "owner-commitment-alice", DEVNET_HEIGHT);
        let batch_id = settlement_batch_id(&lane_id, 1, DEVNET_HEIGHT);
        let fill_id = solver_fill_id(&batch_id, "solver-commitment-devnet", 0);
        let attestation_id = pq_attestation_id(&batch_id, "devnet-attestors-root", DEVNET_HEIGHT);
        let rebate_id = low_fee_rebate_id(&fill_id, "owner-commitment-alice", DEVNET_HEIGHT);
        let budget_id = redaction_budget_id(&lane_id, "batch-public-record", DEVNET_HEIGHT);

        state.bytecode_lanes.insert(
            lane_id.clone(),
            BytecodeLane {
                lane_id: lane_id.clone(),
                kind: lane_kind,
                contract_commitment: "contract-devnet-dex".to_string(),
                bytecode_root: deterministic_root("bytecode", "confidential-swap", 0),
                verifier_key_root: deterministic_root("verifier-key", "confidential-swap", 0),
                priority_weight: lane_kind.priority_weight(),
                enabled: true,
            },
        );
        state.sealed_order_lots.insert(
            lot_id.clone(),
            SealedOrderLot {
                lot_id: lot_id.clone(),
                lane_id: lane_id.clone(),
                owner_commitment: "owner-commitment-alice".to_string(),
                encrypted_order_root: deterministic_root("encrypted-order", "alice-lot", 0),
                nullifier_root: deterministic_root("nullifier", "alice-lot", 0),
                base_asset_id: DEVNET_BASE_ASSET_ID.to_string(),
                quote_asset_id: DEVNET_QUOTE_ASSET_ID.to_string(),
                max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
                status: SealedOrderLotStatus::Filled,
                submitted_at_height: DEVNET_HEIGHT,
                expires_at_height: DEVNET_HEIGHT + DEFAULT_REVEAL_TIMEOUT_BLOCKS,
            },
        );
        state.settlement_batches.insert(
            batch_id.clone(),
            SettlementBatch {
                batch_id: batch_id.clone(),
                lane_id: lane_id.clone(),
                epoch: 1,
                order_lot_root: root_for_values(SEALED_ORDER_LOT_SCHEME, &[json!(lot_id)]),
                pre_state_root: deterministic_root("pre-state", "demo-batch", 1),
                post_state_root: deterministic_root("post-state", "demo-batch", 1),
                timeout_policy: TimeoutPolicyKind::RollbackBatch,
                rollback_deadline_height: DEVNET_HEIGHT + DEFAULT_ROLLBACK_WINDOW_BLOCKS,
            },
        );
        state.solver_fills.insert(
            fill_id.clone(),
            SolverFill {
                fill_id: fill_id.clone(),
                batch_id: batch_id.clone(),
                solver_commitment: "solver-commitment-devnet".to_string(),
                fill_commitment_root: deterministic_root("fill", "demo-batch", 1),
                filled_lots: 1,
                surplus_commitment: deterministic_root("surplus", "demo-batch", 1),
                low_fee_eligible: true,
            },
        );
        state.pq_attestations.insert(
            attestation_id.clone(),
            PqSettlementAttestation {
                attestation_id,
                batch_id: batch_id.clone(),
                signer_set_root: deterministic_root("signers", "devnet-attestors", 1),
                transcript_root: deterministic_root("transcript", "demo-batch", 1),
                pq_signature_root: deterministic_root("pq-signature", "demo-batch", 1),
                security_bits: 256,
                status: AttestationStatus::Finalized,
            },
        );
        state.low_fee_rebates.insert(
            rebate_id.clone(),
            LowFeeRebate {
                rebate_id,
                fill_id,
                beneficiary_commitment: "owner-commitment-alice".to_string(),
                fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
                rebate_bps: DEFAULT_LOW_FEE_REBATE_BPS,
                rebate_note_root: deterministic_root("rebate-note", "alice-lot", 1),
            },
        );
        state.redaction_budgets.insert(
            budget_id.clone(),
            PrivacyRedactionBudget {
                budget_id,
                lane_id,
                disclosure_domain: "batch-public-record".to_string(),
                allocated_units: DEFAULT_REDACTION_BUDGET_UNITS,
                spent_units: 8_192,
                redacted_field_root: deterministic_root("redacted-fields", "demo-batch", 1),
            },
        );

        state.recompute_counters();
        state.recompute_roots();
        let expected_state_root = state.state_root();
        let fixture_id = fixture_id("sealed-order-batch-demo", 1);
        state.devnet_fixtures.insert(
            fixture_id.clone(),
            DevnetFixture {
                fixture_id,
                label: "sealed-order-batch-demo".to_string(),
                deterministic_seed_root: deterministic_root("fixture-seed", "demo", 1),
                expected_state_root,
            },
        );
        state.recompute_counters();
        state.recompute_roots();
        state
    }

    pub fn public_record_without_state_root(&self) -> Value {
        json!({
            "kind": "private_l2_pq_confidential_contract_sealed_order_batch_settlement_runtime_state",
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "hash_suite": HASH_SUITE,
            "pq_attestation_suite": PQ_ATTESTATION_SUITE,
            "config": self.config,
            "counters": self.counters,
            "roots": self.roots,
            "bytecode_lanes": self.bytecode_lanes.values().map(BytecodeLane::public_record).collect::<Vec<_>>(),
            "sealed_order_lots": self.sealed_order_lots.values().map(SealedOrderLot::public_record).collect::<Vec<_>>(),
            "settlement_batches": self.settlement_batches.values().map(SettlementBatch::public_record).collect::<Vec<_>>(),
            "solver_fills": self.solver_fills.values().map(SolverFill::public_record).collect::<Vec<_>>(),
            "pq_attestations": self.pq_attestations.values().map(PqSettlementAttestation::public_record).collect::<Vec<_>>(),
            "low_fee_rebates": self.low_fee_rebates.values().map(LowFeeRebate::public_record).collect::<Vec<_>>(),
            "redaction_budgets": self.redaction_budgets.values().map(PrivacyRedactionBudget::public_record).collect::<Vec<_>>(),
            "devnet_fixtures": self.devnet_fixtures.values().map(DevnetFixture::public_record).collect::<Vec<_>>(),
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        let state_root = state_root_from_record(&record);
        if let Some(object) = record.as_object_mut() {
            object.insert("state_root".to_string(), json!(state_root));
        }
        record
    }

    pub fn state_root(&self) -> String {
        state_root_from_record(&self.public_record_without_state_root())
    }

    pub fn recompute_counters(&mut self) {
        self.counters = Counters {
            bytecode_lanes: self.bytecode_lanes.len() as u64,
            sealed_order_lots: self.sealed_order_lots.len() as u64,
            settlement_batches: self.settlement_batches.len() as u64,
            solver_fills: self.solver_fills.len() as u64,
            pq_attestations: self.pq_attestations.len() as u64,
            low_fee_rebates: self.low_fee_rebates.len() as u64,
            redaction_budgets: self.redaction_budgets.len() as u64,
            timeout_rollbacks: self
                .sealed_order_lots
                .values()
                .filter(|lot| lot.status == SealedOrderLotStatus::RolledBack)
                .count() as u64,
            devnet_fixtures: self.devnet_fixtures.len() as u64,
        };
    }

    pub fn recompute_roots(&mut self) {
        self.roots = Roots {
            bytecode_lane_root: record_root(
                BYTECODE_LANE_SCHEME,
                self.bytecode_lanes
                    .values()
                    .map(BytecodeLane::public_record)
                    .collect::<Vec<_>>()
                    .as_slice(),
            ),
            sealed_order_lot_root: record_root(
                SEALED_ORDER_LOT_SCHEME,
                self.sealed_order_lots
                    .values()
                    .map(SealedOrderLot::public_record)
                    .collect::<Vec<_>>()
                    .as_slice(),
            ),
            settlement_batch_root: record_root(
                SETTLEMENT_BATCH_SCHEME,
                self.settlement_batches
                    .values()
                    .map(SettlementBatch::public_record)
                    .collect::<Vec<_>>()
                    .as_slice(),
            ),
            solver_fill_root: record_root(
                SOLVER_FILL_SCHEME,
                self.solver_fills
                    .values()
                    .map(SolverFill::public_record)
                    .collect::<Vec<_>>()
                    .as_slice(),
            ),
            pq_attestation_root: record_root(
                ATTESTATION_SCHEME,
                self.pq_attestations
                    .values()
                    .map(PqSettlementAttestation::public_record)
                    .collect::<Vec<_>>()
                    .as_slice(),
            ),
            low_fee_rebate_root: record_root(
                REBATE_SCHEME,
                self.low_fee_rebates
                    .values()
                    .map(LowFeeRebate::public_record)
                    .collect::<Vec<_>>()
                    .as_slice(),
            ),
            redaction_budget_root: record_root(
                REDACTION_BUDGET_SCHEME,
                self.redaction_budgets
                    .values()
                    .map(PrivacyRedactionBudget::public_record)
                    .collect::<Vec<_>>()
                    .as_slice(),
            ),
            fixture_root: record_root(
                FIXTURE_SCHEME,
                self.devnet_fixtures
                    .values()
                    .map(DevnetFixture::public_record)
                    .collect::<Vec<_>>()
                    .as_slice(),
            ),
        };
    }
}

pub fn lane_id(kind: ContractSettlementLaneKind, contract_commitment: &str, nonce: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SETTLEMENT-LANE-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(kind.as_str()),
            HashPart::Str(contract_commitment),
            HashPart::U64(nonce),
        ],
        32,
    )
}

pub fn sealed_order_lot_id(lane_id: &str, owner_commitment: &str, height: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-ORDER-LOT-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(lane_id),
            HashPart::Str(owner_commitment),
            HashPart::U64(height),
        ],
        32,
    )
}

pub fn settlement_batch_id(lane_id: &str, epoch: u64, height: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SETTLEMENT-BATCH-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(lane_id),
            HashPart::U64(epoch),
            HashPart::U64(height),
        ],
        32,
    )
}

pub fn solver_fill_id(batch_id: &str, solver_commitment: &str, nonce: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SOLVER-FILL-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(batch_id),
            HashPart::Str(solver_commitment),
            HashPart::U64(nonce),
        ],
        32,
    )
}

pub fn pq_attestation_id(batch_id: &str, signer_set_root: &str, height: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-PQ-ATTESTATION-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(batch_id),
            HashPart::Str(signer_set_root),
            HashPart::U64(height),
        ],
        32,
    )
}

pub fn low_fee_rebate_id(fill_id: &str, beneficiary_commitment: &str, height: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-LOW-FEE-REBATE-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(fill_id),
            HashPart::Str(beneficiary_commitment),
            HashPart::U64(height),
        ],
        32,
    )
}

pub fn redaction_budget_id(lane_id: &str, disclosure_domain: &str, height: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-REDACTION-BUDGET-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(lane_id),
            HashPart::Str(disclosure_domain),
            HashPart::U64(height),
        ],
        32,
    )
}

pub fn fixture_id(label: &str, nonce: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-FIXTURE-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
            HashPart::U64(nonce),
        ],
        32,
    )
}

pub fn deterministic_root(label: &str, subject: &str, nonce: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-DETERMINISTIC-ROOT",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
            HashPart::Str(subject),
            HashPart::U64(nonce),
        ],
        32,
    )
}

pub fn root_for_values(domain: &str, values: &[Value]) -> String {
    merkle_root(domain, values)
}

pub fn record_root(domain: &str, records: &[Value]) -> String {
    merkle_root(domain, records)
}

pub fn state_root_from_record(record: &Value) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-ORDER-BATCH-SETTLEMENT-STATE-ROOT",
        &[HashPart::Str(PROTOCOL_VERSION), HashPart::Json(record)],
        32,
    )
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn demo() -> State {
    State::demo()
}

pub fn public_record(state: &State) -> Value {
    state.public_record()
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}
