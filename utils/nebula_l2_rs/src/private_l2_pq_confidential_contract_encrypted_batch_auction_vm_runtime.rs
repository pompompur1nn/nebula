use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2PqConfidentialContractEncryptedBatchAuctionVmRuntimeResult<T> =
    std::result::Result<T, String>;
pub type Result<T> = PrivateL2PqConfidentialContractEncryptedBatchAuctionVmRuntimeResult<T>;
pub type Runtime = State;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_ENCRYPTED_BATCH_AUCTION_VM_RUNTIME_PROTOCOL_VERSION:
    &str =
    "nebula-private-l2-pq-confidential-contract-encrypted-batch-auction-vm-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_ENCRYPTED_BATCH_AUCTION_VM_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "shake256-domain-separated-canonical-json-v1";
pub const PQ_SEALING_SUITE: &str = "ml-kem-1024+hpke-confidential-contract-sealed-bid-lot-v1";
pub const PQ_SETTLEMENT_ATTESTATION_SUITE: &str =
    "ml-dsa-87+slh-dsa-shake-256f-contract-settlement-attestation-v1";
pub const VM_BYTECODE_SUITE: &str =
    "deterministic-confidential-contract-settlement-bytecode-lanes-v1";
pub const SOLVER_FILL_SUITE: &str = "encrypted-batch-auction-solver-fill-root-v1";
pub const LOW_FEE_REBATE_SUITE: &str = "private-l2-low-fee-contract-rebate-root-v1";
pub const PRIVACY_REDACTION_BUDGET_SUITE: &str = "private-l2-contract-auction-redaction-budget-v1";
pub const DEVNET_L2_NETWORK: &str = "nebula-private-l2-devnet";
pub const DEVNET_HEIGHT: u64 = 4_420_000;
pub const DEVNET_EPOCH: u64 = 88_064;
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEVNET_REBATE_ASSET_ID: &str = "contract-auction-rebate-devnet";
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 131_072;
pub const DEFAULT_TARGET_PRIVACY_SET_SIZE: u64 = 1_048_576;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_AUCTION_TTL_BLOCKS: u64 = 36;
pub const DEFAULT_REVEAL_TTL_BLOCKS: u64 = 12;
pub const DEFAULT_SETTLEMENT_TTL_BLOCKS: u64 = 48;
pub const DEFAULT_ROLLBACK_TTL_BLOCKS: u64 = 96;
pub const DEFAULT_REDACTION_WINDOW_BLOCKS: u64 = 256;
pub const DEFAULT_LOW_FEE_BPS: u64 = 6;
pub const DEFAULT_MAX_SOLVER_FEE_BPS: u64 = 22;
pub const DEFAULT_REBATE_BPS: u64 = 11;
pub const DEFAULT_MAX_VM_GAS: u64 = 50_000_000;
pub const DEFAULT_MAX_LOTS: usize = 524_288;
pub const DEFAULT_MAX_BIDS: usize = 2_097_152;
pub const DEFAULT_MAX_BYTECODE_LANES: usize = 262_144;
pub const DEFAULT_MAX_ATTESTATIONS: usize = 1_048_576;
pub const DEFAULT_MAX_SOLVER_FILLS: usize = 1_048_576;
pub const DEFAULT_MAX_POLICIES: usize = 65_536;
pub const DEFAULT_MAX_REBATES: usize = 524_288;
pub const DEFAULT_MAX_REDACTION_BUDGETS: usize = 262_144;
pub const DEFAULT_MAX_DEVNET_FIXTURES: usize = 4_096;
pub const DEFAULT_MAX_PUBLIC_EVENTS: usize = 4_194_304;

const D_STATE: &str = "PL2-PQ-CONF-CONTRACT-ENC-BATCH-AUCTION-VM:STATE";
const D_CONFIG: &str = "PL2-PQ-CONF-CONTRACT-ENC-BATCH-AUCTION-VM:CONFIG";
const D_COUNTERS: &str = "PL2-PQ-CONF-CONTRACT-ENC-BATCH-AUCTION-VM:COUNTERS";
const D_ROOTS: &str = "PL2-PQ-CONF-CONTRACT-ENC-BATCH-AUCTION-VM:ROOTS";
const D_LOTS: &str = "PL2-PQ-CONF-CONTRACT-ENC-BATCH-AUCTION-VM:LOTS";
const D_BIDS: &str = "PL2-PQ-CONF-CONTRACT-ENC-BATCH-AUCTION-VM:BIDS";
const D_LANES: &str = "PL2-PQ-CONF-CONTRACT-ENC-BATCH-AUCTION-VM:LANES";
const D_ATTESTATIONS: &str = "PL2-PQ-CONF-CONTRACT-ENC-BATCH-AUCTION-VM:ATTESTATIONS";
const D_FILLS: &str = "PL2-PQ-CONF-CONTRACT-ENC-BATCH-AUCTION-VM:FILLS";
const D_POLICIES: &str = "PL2-PQ-CONF-CONTRACT-ENC-BATCH-AUCTION-VM:POLICIES";
const D_REBATES: &str = "PL2-PQ-CONF-CONTRACT-ENC-BATCH-AUCTION-VM:REBATES";
const D_REDACTION: &str = "PL2-PQ-CONF-CONTRACT-ENC-BATCH-AUCTION-VM:REDACTION";
const D_FIXTURES: &str = "PL2-PQ-CONF-CONTRACT-ENC-BATCH-AUCTION-VM:FIXTURES";
const D_EVENTS: &str = "PL2-PQ-CONF-CONTRACT-ENC-BATCH-AUCTION-VM:EVENTS";
const D_PUBLIC: &str = "PL2-PQ-CONF-CONTRACT-ENC-BATCH-AUCTION-VM:PUBLIC";

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuctionLane {
    DexIntent,
    LendingLiquidation,
    VaultRebalance,
    BridgeSettlement,
    NftSweep,
    PaymasterSponsored,
    EmergencyUnwind,
    DevnetDemo,
}

impl AuctionLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DexIntent => "dex_intent",
            Self::LendingLiquidation => "lending_liquidation",
            Self::VaultRebalance => "vault_rebalance",
            Self::BridgeSettlement => "bridge_settlement",
            Self::NftSweep => "nft_sweep",
            Self::PaymasterSponsored => "paymaster_sponsored",
            Self::EmergencyUnwind => "emergency_unwind",
            Self::DevnetDemo => "devnet_demo",
        }
    }

    pub fn priority_weight(self) -> u64 {
        match self {
            Self::EmergencyUnwind => 1_000,
            Self::LendingLiquidation => 940,
            Self::BridgeSettlement => 900,
            Self::DexIntent => 860,
            Self::VaultRebalance => 780,
            Self::PaymasterSponsored => 720,
            Self::NftSweep => 660,
            Self::DevnetDemo => 500,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LotStatus {
    Open,
    Sealed,
    Bidding,
    Matched,
    Settling,
    Settled,
    Timeout,
    RolledBack,
    Rejected,
}

impl LotStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Sealed => "sealed",
            Self::Bidding => "bidding",
            Self::Matched => "matched",
            Self::Settling => "settling",
            Self::Settled => "settled",
            Self::Timeout => "timeout",
            Self::RolledBack => "rolled_back",
            Self::Rejected => "rejected",
        }
    }

    pub fn accepts_bids(self) -> bool {
        matches!(self, Self::Sealed | Self::Bidding)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementLaneStatus {
    Draft,
    Armed,
    Executing,
    Attested,
    Finalized,
    Paused,
    RolledBack,
}

impl SettlementLaneStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Armed => "armed",
            Self::Executing => "executing",
            Self::Attested => "attested",
            Self::Finalized => "finalized",
            Self::Paused => "paused",
            Self::RolledBack => "rolled_back",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyAction {
    Continue,
    Extend,
    Timeout,
    Rollback,
    Quarantine,
    EmergencySettle,
}

impl PolicyAction {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Continue => "continue",
            Self::Extend => "extend",
            Self::Timeout => "timeout",
            Self::Rollback => "rollback",
            Self::Quarantine => "quarantine",
            Self::EmergencySettle => "emergency_settle",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub protocol_version: String,
    pub schema_version: u64,
    pub chain_id: u64,
    pub l2_network: String,
    pub fee_asset_id: String,
    pub rebate_asset_id: String,
    pub hash_suite: String,
    pub pq_sealing_suite: String,
    pub pq_settlement_attestation_suite: String,
    pub vm_bytecode_suite: String,
    pub solver_fill_suite: String,
    pub auction_ttl_blocks: u64,
    pub reveal_ttl_blocks: u64,
    pub settlement_ttl_blocks: u64,
    pub rollback_ttl_blocks: u64,
    pub redaction_window_blocks: u64,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub low_fee_bps: u64,
    pub max_solver_fee_bps: u64,
    pub rebate_bps: u64,
    pub max_vm_gas: u64,
    pub max_lots: usize,
    pub max_bids: usize,
    pub max_bytecode_lanes: usize,
    pub max_attestations: usize,
    pub max_solver_fills: usize,
    pub max_policies: usize,
    pub max_rebates: usize,
    pub max_redaction_budgets: usize,
    pub max_devnet_fixtures: usize,
    pub max_public_events: usize,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            chain_id: CHAIN_ID,
            l2_network: DEVNET_L2_NETWORK.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            rebate_asset_id: DEVNET_REBATE_ASSET_ID.to_string(),
            hash_suite: HASH_SUITE.to_string(),
            pq_sealing_suite: PQ_SEALING_SUITE.to_string(),
            pq_settlement_attestation_suite: PQ_SETTLEMENT_ATTESTATION_SUITE.to_string(),
            vm_bytecode_suite: VM_BYTECODE_SUITE.to_string(),
            solver_fill_suite: SOLVER_FILL_SUITE.to_string(),
            auction_ttl_blocks: DEFAULT_AUCTION_TTL_BLOCKS,
            reveal_ttl_blocks: DEFAULT_REVEAL_TTL_BLOCKS,
            settlement_ttl_blocks: DEFAULT_SETTLEMENT_TTL_BLOCKS,
            rollback_ttl_blocks: DEFAULT_ROLLBACK_TTL_BLOCKS,
            redaction_window_blocks: DEFAULT_REDACTION_WINDOW_BLOCKS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            low_fee_bps: DEFAULT_LOW_FEE_BPS,
            max_solver_fee_bps: DEFAULT_MAX_SOLVER_FEE_BPS,
            rebate_bps: DEFAULT_REBATE_BPS,
            max_vm_gas: DEFAULT_MAX_VM_GAS,
            max_lots: DEFAULT_MAX_LOTS,
            max_bids: DEFAULT_MAX_BIDS,
            max_bytecode_lanes: DEFAULT_MAX_BYTECODE_LANES,
            max_attestations: DEFAULT_MAX_ATTESTATIONS,
            max_solver_fills: DEFAULT_MAX_SOLVER_FILLS,
            max_policies: DEFAULT_MAX_POLICIES,
            max_rebates: DEFAULT_MAX_REBATES,
            max_redaction_budgets: DEFAULT_MAX_REDACTION_BUDGETS,
            max_devnet_fixtures: DEFAULT_MAX_DEVNET_FIXTURES,
            max_public_events: DEFAULT_MAX_PUBLIC_EVENTS,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "chain_id": self.chain_id,
            "l2_network": self.l2_network,
            "fee_asset_id": self.fee_asset_id,
            "rebate_asset_id": self.rebate_asset_id,
            "hash_suite": self.hash_suite,
            "pq_sealing_suite": self.pq_sealing_suite,
            "pq_settlement_attestation_suite": self.pq_settlement_attestation_suite,
            "vm_bytecode_suite": self.vm_bytecode_suite,
            "solver_fill_suite": self.solver_fill_suite,
            "auction_ttl_blocks": self.auction_ttl_blocks,
            "reveal_ttl_blocks": self.reveal_ttl_blocks,
            "settlement_ttl_blocks": self.settlement_ttl_blocks,
            "rollback_ttl_blocks": self.rollback_ttl_blocks,
            "redaction_window_blocks": self.redaction_window_blocks,
            "min_privacy_set_size": self.min_privacy_set_size,
            "target_privacy_set_size": self.target_privacy_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
            "low_fee_bps": self.low_fee_bps,
            "max_solver_fee_bps": self.max_solver_fee_bps,
            "rebate_bps": self.rebate_bps,
            "max_vm_gas": self.max_vm_gas,
        })
    }

    pub fn validate(&self) -> Result<()> {
        if self.protocol_version != PROTOCOL_VERSION {
            return Err("protocol version mismatch".to_string());
        }
        if self.low_fee_bps > self.max_solver_fee_bps || self.max_solver_fee_bps > MAX_BPS {
            return Err("invalid fee bps envelope".to_string());
        }
        if self.min_privacy_set_size > self.target_privacy_set_size {
            return Err("privacy set target below minimum".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub lots_opened: u64,
    pub sealed_bid_lots: u64,
    pub bids_committed: u64,
    pub bytecode_lanes_armed: u64,
    pub pq_attestations_posted: u64,
    pub solver_fills_selected: u64,
    pub settlements_finalized: u64,
    pub timeout_policies_triggered: u64,
    pub rollback_policies_triggered: u64,
    pub low_fee_rebates_reserved: u64,
    pub redaction_budget_spent: u64,
    pub devnet_fixtures_loaded: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub lots_root: String,
    pub bids_root: String,
    pub bytecode_lanes_root: String,
    pub pq_attestations_root: String,
    pub solver_fills_root: String,
    pub policies_root: String,
    pub low_fee_rebates_root: String,
    pub redaction_budgets_root: String,
    pub devnet_fixtures_root: String,
    pub public_events_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SealedBidLot {
    pub lot_id: String,
    pub lane: AuctionLane,
    pub status: LotStatus,
    pub contract_commitment: String,
    pub encrypted_intent_root: String,
    pub sealed_lot_root: String,
    pub notional_micros: u64,
    pub privacy_set_size: u64,
    pub opened_at_height: u64,
    pub timeout_height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ContractSettlementBytecodeLane {
    pub lane_id: String,
    pub lot_id: String,
    pub status: SettlementLaneStatus,
    pub bytecode_commitment: String,
    pub calldata_root: String,
    pub gas_limit: u64,
    pub deterministic_lane_root: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqSettlementAttestation {
    pub attestation_id: String,
    pub lot_id: String,
    pub lane_id: String,
    pub signer_commitment: String,
    pub settlement_root: String,
    pub pq_signature_commitment: String,
    pub security_bits: u16,
    pub posted_at_height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SolverFill {
    pub fill_id: String,
    pub lot_id: String,
    pub solver_commitment: String,
    pub fill_root: String,
    pub fee_bps: u64,
    pub rebate_bps: u64,
    pub filled_notional_micros: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TimeoutRollbackPolicy {
    pub policy_id: String,
    pub lot_id: String,
    pub action: PolicyAction,
    pub trigger_height: u64,
    pub rollback_root: String,
    pub reason_code: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LowFeeRebate {
    pub rebate_id: String,
    pub lot_id: String,
    pub beneficiary_commitment: String,
    pub asset_id: String,
    pub rebate_micros: u64,
    pub receipt_root: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivacyRedactionBudget {
    pub budget_id: String,
    pub scope: String,
    pub max_public_fields: u64,
    pub spent_public_fields: u64,
    pub expires_at_height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub lots: BTreeMap<String, SealedBidLot>,
    pub sealed_bids: BTreeMap<String, String>,
    pub bytecode_lanes: BTreeMap<String, ContractSettlementBytecodeLane>,
    pub pq_attestations: BTreeMap<String, PqSettlementAttestation>,
    pub solver_fills: BTreeMap<String, SolverFill>,
    pub timeout_rollback_policies: BTreeMap<String, TimeoutRollbackPolicy>,
    pub low_fee_rebates: BTreeMap<String, LowFeeRebate>,
    pub redaction_budgets: BTreeMap<String, PrivacyRedactionBudget>,
    pub devnet_fixtures: BTreeMap<String, Value>,
    pub public_events: BTreeSet<String>,
}

impl State {
    pub fn devnet() -> Self {
        let mut state = Self {
            config: Config::devnet(),
            counters: Counters::default(),
            roots: empty_roots(),
            lots: BTreeMap::new(),
            sealed_bids: BTreeMap::new(),
            bytecode_lanes: BTreeMap::new(),
            pq_attestations: BTreeMap::new(),
            solver_fills: BTreeMap::new(),
            timeout_rollback_policies: BTreeMap::new(),
            low_fee_rebates: BTreeMap::new(),
            redaction_budgets: BTreeMap::new(),
            devnet_fixtures: BTreeMap::new(),
            public_events: BTreeSet::new(),
        };
        load_demo_fixtures(&mut state);
        refresh_roots(&mut state);
        state
    }

    pub fn public_record(&self) -> Value {
        public_record(self)
    }

    pub fn state_root(&self) -> String {
        state_root(self)
    }
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn demo() -> State {
    State::devnet()
}

pub fn public_record(state: &State) -> Value {
    json!({
        "protocol_version": PROTOCOL_VERSION,
        "schema_version": SCHEMA_VERSION,
        "chain_id": CHAIN_ID,
        "hash_suite": HASH_SUITE,
        "config": state.config.public_record(),
        "counters": state.counters.public_record(),
        "roots": state.roots.public_record(),
        "public_lots": state.lots.values().map(public_lot).collect::<Vec<_>>(),
        "public_bytecode_lanes": state.bytecode_lanes.values().map(public_lane).collect::<Vec<_>>(),
        "public_pq_attestations": state.pq_attestations.values().map(public_attestation).collect::<Vec<_>>(),
        "public_solver_fills": state.solver_fills.values().map(public_fill).collect::<Vec<_>>(),
        "public_rebates": state.low_fee_rebates.values().map(public_rebate).collect::<Vec<_>>(),
        "public_events": state.public_events.iter().cloned().collect::<Vec<_>>(),
    })
}

pub fn state_root(state: &State) -> String {
    domain_hash(
        D_STATE,
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(&state.roots.config_root),
            HashPart::Str(&state.roots.lots_root),
            HashPart::Str(&state.roots.bids_root),
            HashPart::Str(&state.roots.bytecode_lanes_root),
            HashPart::Str(&state.roots.pq_attestations_root),
            HashPart::Str(&state.roots.solver_fills_root),
            HashPart::Str(&state.roots.policies_root),
            HashPart::Str(&state.roots.low_fee_rebates_root),
            HashPart::Str(&state.roots.redaction_budgets_root),
            HashPart::Str(&state.roots.devnet_fixtures_root),
            HashPart::Str(&state.roots.public_events_root),
        ],
    )
}

fn load_demo_fixtures(state: &mut State) {
    let lot = SealedBidLot {
        lot_id: "devnet-lot-0001".to_string(),
        lane: AuctionLane::DexIntent,
        status: LotStatus::Matched,
        contract_commitment: devnet_commitment("contract", "private-amm-vault"),
        encrypted_intent_root: devnet_commitment("encrypted-intents", "lot-0001"),
        sealed_lot_root: devnet_commitment("sealed-lot", "lot-0001"),
        notional_micros: 25_000_000_000,
        privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
        opened_at_height: DEVNET_HEIGHT,
        timeout_height: DEVNET_HEIGHT + DEFAULT_AUCTION_TTL_BLOCKS,
    };
    let lane = ContractSettlementBytecodeLane {
        lane_id: "devnet-lane-0001".to_string(),
        lot_id: lot.lot_id.clone(),
        status: SettlementLaneStatus::Attested,
        bytecode_commitment: devnet_commitment("bytecode", "swap-and-rebate"),
        calldata_root: devnet_commitment("calldata", "redacted-swap-path"),
        gas_limit: 7_500_000,
        deterministic_lane_root: devnet_commitment("lane-root", "devnet-lane-0001"),
    };
    let attestation = PqSettlementAttestation {
        attestation_id: "devnet-attestation-0001".to_string(),
        lot_id: lot.lot_id.clone(),
        lane_id: lane.lane_id.clone(),
        signer_commitment: devnet_commitment("pq-signer", "committee-a"),
        settlement_root: devnet_commitment("settlement", "devnet-lot-0001"),
        pq_signature_commitment: devnet_commitment("pq-signature", "attestation-0001"),
        security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        posted_at_height: DEVNET_HEIGHT + 8,
    };
    let fill = SolverFill {
        fill_id: "devnet-fill-0001".to_string(),
        lot_id: lot.lot_id.clone(),
        solver_commitment: devnet_commitment("solver", "solver-alpha"),
        fill_root: devnet_commitment("fill", "best-execution-alpha"),
        fee_bps: DEFAULT_LOW_FEE_BPS,
        rebate_bps: DEFAULT_REBATE_BPS,
        filled_notional_micros: lot.notional_micros,
    };
    let policy = TimeoutRollbackPolicy {
        policy_id: "devnet-policy-0001".to_string(),
        lot_id: lot.lot_id.clone(),
        action: PolicyAction::Rollback,
        trigger_height: DEVNET_HEIGHT + DEFAULT_ROLLBACK_TTL_BLOCKS,
        rollback_root: devnet_commitment("rollback", "restore-vault-balances"),
        reason_code: "settlement_attestation_timeout".to_string(),
    };
    let rebate = LowFeeRebate {
        rebate_id: "devnet-rebate-0001".to_string(),
        lot_id: lot.lot_id.clone(),
        beneficiary_commitment: devnet_commitment("beneficiary", "shielded-user-a"),
        asset_id: DEVNET_REBATE_ASSET_ID.to_string(),
        rebate_micros: 27_500,
        receipt_root: devnet_commitment("rebate-receipt", "devnet-rebate-0001"),
    };
    let budget = PrivacyRedactionBudget {
        budget_id: "devnet-redaction-budget-0001".to_string(),
        scope: "sealed_bid_lot_public_record".to_string(),
        max_public_fields: 12,
        spent_public_fields: 8,
        expires_at_height: DEVNET_HEIGHT + DEFAULT_REDACTION_WINDOW_BLOCKS,
    };

    state.sealed_bids.insert(
        "devnet-bid-0001".to_string(),
        devnet_commitment("sealed-bid", "solver-alpha"),
    );
    state.public_events.insert("devnet_lot_matched".to_string());
    state.devnet_fixtures.insert(
        "demo_fixture".to_string(),
        json!({
            "height": DEVNET_HEIGHT,
            "epoch": DEVNET_EPOCH,
            "lane": lot.lane.as_str(),
            "privacy": "sealed bids and redacted public record",
        }),
    );
    state.bytecode_lanes.insert(lane.lane_id.clone(), lane);
    state
        .pq_attestations
        .insert(attestation.attestation_id.clone(), attestation);
    state.solver_fills.insert(fill.fill_id.clone(), fill);
    state
        .timeout_rollback_policies
        .insert(policy.policy_id.clone(), policy);
    state
        .low_fee_rebates
        .insert(rebate.rebate_id.clone(), rebate);
    state
        .redaction_budgets
        .insert(budget.budget_id.clone(), budget);
    state.lots.insert(lot.lot_id.clone(), lot);

    state.counters = Counters {
        lots_opened: state.lots.len() as u64,
        sealed_bid_lots: state
            .lots
            .values()
            .filter(|lot| matches!(lot.status, LotStatus::Sealed | LotStatus::Matched))
            .count() as u64,
        bids_committed: state.sealed_bids.len() as u64,
        bytecode_lanes_armed: state.bytecode_lanes.len() as u64,
        pq_attestations_posted: state.pq_attestations.len() as u64,
        solver_fills_selected: state.solver_fills.len() as u64,
        settlements_finalized: 0,
        timeout_policies_triggered: 0,
        rollback_policies_triggered: 0,
        low_fee_rebates_reserved: state.low_fee_rebates.len() as u64,
        redaction_budget_spent: state
            .redaction_budgets
            .values()
            .map(|budget| budget.spent_public_fields)
            .sum(),
        devnet_fixtures_loaded: state.devnet_fixtures.len() as u64,
    };
}

fn refresh_roots(state: &mut State) {
    state.roots = Roots {
        config_root: value_root(D_CONFIG, &state.config.public_record()),
        lots_root: map_root(D_LOTS, &state.lots),
        bids_root: map_root(D_BIDS, &state.sealed_bids),
        bytecode_lanes_root: map_root(D_LANES, &state.bytecode_lanes),
        pq_attestations_root: map_root(D_ATTESTATIONS, &state.pq_attestations),
        solver_fills_root: map_root(D_FILLS, &state.solver_fills),
        policies_root: map_root(D_POLICIES, &state.timeout_rollback_policies),
        low_fee_rebates_root: map_root(D_REBATES, &state.low_fee_rebates),
        redaction_budgets_root: map_root(D_REDACTION, &state.redaction_budgets),
        devnet_fixtures_root: map_root(D_FIXTURES, &state.devnet_fixtures),
        public_events_root: set_root(D_EVENTS, &state.public_events),
        state_root: String::new(),
    };
    state.roots.state_root = state_root(state);
}

fn empty_roots() -> Roots {
    Roots {
        config_root: empty_root(D_CONFIG),
        lots_root: empty_root(D_LOTS),
        bids_root: empty_root(D_BIDS),
        bytecode_lanes_root: empty_root(D_LANES),
        pq_attestations_root: empty_root(D_ATTESTATIONS),
        solver_fills_root: empty_root(D_FILLS),
        policies_root: empty_root(D_POLICIES),
        low_fee_rebates_root: empty_root(D_REBATES),
        redaction_budgets_root: empty_root(D_REDACTION),
        devnet_fixtures_root: empty_root(D_FIXTURES),
        public_events_root: empty_root(D_EVENTS),
        state_root: empty_root(D_STATE),
    }
}

fn public_lot(lot: &SealedBidLot) -> Value {
    json!({
        "lot_id": lot.lot_id,
        "lane": lot.lane.as_str(),
        "status": lot.status.as_str(),
        "contract_commitment": lot.contract_commitment,
        "sealed_lot_root": lot.sealed_lot_root,
        "notional_micros": lot.notional_micros,
        "privacy_set_size": lot.privacy_set_size,
        "opened_at_height": lot.opened_at_height,
        "timeout_height": lot.timeout_height,
        "accepts_bids": lot.status.accepts_bids(),
    })
}

fn public_lane(lane: &ContractSettlementBytecodeLane) -> Value {
    json!({
        "lane_id": lane.lane_id,
        "lot_id": lane.lot_id,
        "status": lane.status.as_str(),
        "bytecode_commitment": lane.bytecode_commitment,
        "gas_limit": lane.gas_limit,
        "deterministic_lane_root": lane.deterministic_lane_root,
    })
}

fn public_attestation(attestation: &PqSettlementAttestation) -> Value {
    json!({
        "attestation_id": attestation.attestation_id,
        "lot_id": attestation.lot_id,
        "lane_id": attestation.lane_id,
        "signer_commitment": attestation.signer_commitment,
        "settlement_root": attestation.settlement_root,
        "security_bits": attestation.security_bits,
        "posted_at_height": attestation.posted_at_height,
    })
}

fn public_fill(fill: &SolverFill) -> Value {
    json!({
        "fill_id": fill.fill_id,
        "lot_id": fill.lot_id,
        "solver_commitment": fill.solver_commitment,
        "fill_root": fill.fill_root,
        "fee_bps": fill.fee_bps,
        "rebate_bps": fill.rebate_bps,
        "filled_notional_micros": fill.filled_notional_micros,
    })
}

fn public_rebate(rebate: &LowFeeRebate) -> Value {
    json!({
        "rebate_id": rebate.rebate_id,
        "lot_id": rebate.lot_id,
        "beneficiary_commitment": rebate.beneficiary_commitment,
        "asset_id": rebate.asset_id,
        "rebate_micros": rebate.rebate_micros,
        "receipt_root": rebate.receipt_root,
    })
}

fn value_root(domain: &str, value: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(&canonical_value(value)),
        ],
    )
}

fn map_root<T>(domain: &str, map: &BTreeMap<String, T>) -> String
where
    T: Serialize,
{
    if map.is_empty() {
        return empty_root(domain);
    }
    let leaves = map
        .iter()
        .map(|(key, value)| {
            domain_hash(
                domain,
                &[
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(key),
                    HashPart::Str(&canonical_value(&json!(value))),
                ],
            )
        })
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn set_root(domain: &str, set: &BTreeSet<String>) -> String {
    if set.is_empty() {
        return empty_root(domain);
    }
    let leaves = set
        .iter()
        .map(|item| {
            domain_hash(
                domain,
                &[HashPart::Str(PROTOCOL_VERSION), HashPart::Str(item)],
            )
        })
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn empty_root(domain: &str) -> String {
    domain_hash(
        domain,
        &[HashPart::Str(PROTOCOL_VERSION), HashPart::Str("empty")],
    )
}

fn canonical_value(value: &Value) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| "null".to_string())
}

fn devnet_commitment(kind: &str, label: &str) -> String {
    domain_hash(
        D_PUBLIC,
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(kind),
            HashPart::Str(label),
        ],
    )
}
