use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2PqConfidentialContractPrivateAuctionSettlementVmRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_PRIVATE_AUCTION_SETTLEMENT_VM_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-confidential-contract-private-auction-settlement-vm-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_PRIVATE_AUCTION_SETTLEMENT_VM_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_ATTESTATION_SUITE: &str =
    "ML-DSA-87+SLH-DSA-SHAKE-256f-private-auction-settlement-vm-attestation-v1";
pub const ENCRYPTED_BID_LOT_SCHEME: &str = "ML-KEM-1024+XWing-sealed-private-bid-lot-v1";
pub const SETTLEMENT_BYTECODE_LANE_SCHEME: &str =
    "confidential-contract-settlement-bytecode-lane-root-v1";
pub const SOLVER_FILL_SCHEME: &str = "private-auction-solver-fill-commitment-root-v1";
pub const ROLLBACK_TIMEOUT_SCHEME: &str = "private-auction-rollback-timeout-guard-root-v1";
pub const LOW_FEE_REBATE_SCHEME: &str = "private-auction-low-fee-rebate-accounting-root-v1";
pub const PRIVACY_REDACTION_BUDGET_SCHEME: &str =
    "private-auction-privacy-redaction-budget-root-v1";
pub const DEVNET_HEIGHT: u64 = 3_422_880;
pub const DEVNET_EPOCH: u64 = 4_754;
pub const DEVNET_L2_NETWORK: &str = "nebula-private-l2-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEVNET_SETTLEMENT_ASSET_ID: &str = "dusd-devnet";
pub const DEFAULT_AUCTION_TTL_BLOCKS: u64 = 48;
pub const DEFAULT_ROLLBACK_WINDOW_BLOCKS: u64 = 288;
pub const DEFAULT_SOLVER_TIMEOUT_BLOCKS: u64 = 24;
pub const DEFAULT_REDACTION_EPOCH_BLOCKS: u64 = 720;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_TARGET_PRIVACY_SET_SIZE: u64 = 524_288;
pub const DEFAULT_BASE_SETTLEMENT_MICRO_FEE: u64 = 9;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 10;
pub const DEFAULT_SOLVER_FEE_BPS: u64 = 3;
pub const DEFAULT_REBATE_BPS: u64 = 6;
pub const DEFAULT_ROLLBACK_SLASH_BPS: u64 = 2_500;
pub const DEFAULT_MAX_BID_LOTS: usize = 8_388_608;
pub const DEFAULT_MAX_BYTECODE_LANES: usize = 262_144;
pub const DEFAULT_MAX_SETTLEMENTS: usize = 4_194_304;
pub const DEFAULT_MAX_SOLVER_FILLS: usize = 4_194_304;
pub const DEFAULT_MAX_ROLLBACKS: usize = 1_048_576;
pub const MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuctionKind {
    BatchSwap,
    Liquidation,
    VaultRebalance,
    BridgeExit,
    IntentMatch,
    NftDutch,
    OracleTriggered,
    EmergencyUnwind,
}

impl AuctionKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BatchSwap => "batch_swap",
            Self::Liquidation => "liquidation",
            Self::VaultRebalance => "vault_rebalance",
            Self::BridgeExit => "bridge_exit",
            Self::IntentMatch => "intent_match",
            Self::NftDutch => "nft_dutch",
            Self::OracleTriggered => "oracle_triggered",
            Self::EmergencyUnwind => "emergency_unwind",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuctionStatus {
    Open,
    Sealed,
    Solving,
    BytecodeLocked,
    Attested,
    Settling,
    Settled,
    TimedOut,
    RolledBack,
    Slashed,
}

impl AuctionStatus {
    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Open
                | Self::Sealed
                | Self::Solving
                | Self::BytecodeLocked
                | Self::Attested
                | Self::Settling
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BytecodeLaneKind {
    Transfer,
    Swap,
    MintBurn,
    Liquidation,
    VaultAccounting,
    OracleRead,
    BridgeMessage,
    Rebate,
    Rollback,
}

impl BytecodeLaneKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Transfer => "transfer",
            Self::Swap => "swap",
            Self::MintBurn => "mint_burn",
            Self::Liquidation => "liquidation",
            Self::VaultAccounting => "vault_accounting",
            Self::OracleRead => "oracle_read",
            Self::BridgeMessage => "bridge_message",
            Self::Rebate => "rebate",
            Self::Rollback => "rollback",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FillStatus {
    Proposed,
    Matched,
    PartiallyFilled,
    Filled,
    Settled,
    Rebated,
    Rejected,
    Expired,
    RolledBack,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct Config {
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub pq_attestation_suite: String,
    pub encrypted_bid_lot_scheme: String,
    pub settlement_bytecode_lane_scheme: String,
    pub solver_fill_scheme: String,
    pub rollback_timeout_scheme: String,
    pub low_fee_rebate_scheme: String,
    pub privacy_redaction_budget_scheme: String,
    pub l2_network: String,
    pub fee_asset_id: String,
    pub settlement_asset_id: String,
    pub auction_ttl_blocks: u64,
    pub rollback_window_blocks: u64,
    pub solver_timeout_blocks: u64,
    pub redaction_epoch_blocks: u64,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub base_settlement_micro_fee: u64,
    pub max_user_fee_bps: u64,
    pub solver_fee_bps: u64,
    pub rebate_bps: u64,
    pub rollback_slash_bps: u64,
    pub max_bid_lots: usize,
    pub max_bytecode_lanes: usize,
    pub max_settlements: usize,
    pub max_solver_fills: usize,
    pub max_rollbacks: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            pq_attestation_suite: PQ_ATTESTATION_SUITE.to_string(),
            encrypted_bid_lot_scheme: ENCRYPTED_BID_LOT_SCHEME.to_string(),
            settlement_bytecode_lane_scheme: SETTLEMENT_BYTECODE_LANE_SCHEME.to_string(),
            solver_fill_scheme: SOLVER_FILL_SCHEME.to_string(),
            rollback_timeout_scheme: ROLLBACK_TIMEOUT_SCHEME.to_string(),
            low_fee_rebate_scheme: LOW_FEE_REBATE_SCHEME.to_string(),
            privacy_redaction_budget_scheme: PRIVACY_REDACTION_BUDGET_SCHEME.to_string(),
            l2_network: DEVNET_L2_NETWORK.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            settlement_asset_id: DEVNET_SETTLEMENT_ASSET_ID.to_string(),
            auction_ttl_blocks: DEFAULT_AUCTION_TTL_BLOCKS,
            rollback_window_blocks: DEFAULT_ROLLBACK_WINDOW_BLOCKS,
            solver_timeout_blocks: DEFAULT_SOLVER_TIMEOUT_BLOCKS,
            redaction_epoch_blocks: DEFAULT_REDACTION_EPOCH_BLOCKS,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            base_settlement_micro_fee: DEFAULT_BASE_SETTLEMENT_MICRO_FEE,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            solver_fee_bps: DEFAULT_SOLVER_FEE_BPS,
            rebate_bps: DEFAULT_REBATE_BPS,
            rollback_slash_bps: DEFAULT_ROLLBACK_SLASH_BPS,
            max_bid_lots: DEFAULT_MAX_BID_LOTS,
            max_bytecode_lanes: DEFAULT_MAX_BYTECODE_LANES,
            max_settlements: DEFAULT_MAX_SETTLEMENTS,
            max_solver_fills: DEFAULT_MAX_SOLVER_FILLS,
            max_rollbacks: DEFAULT_MAX_ROLLBACKS,
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
pub struct Counters {
    pub auctions_opened: u64,
    pub encrypted_bid_lots: u64,
    pub bytecode_lanes_locked: u64,
    pub pq_settlement_attestations: u64,
    pub solver_fills: u64,
    pub settlements_finalized: u64,
    pub rollbacks: u64,
    pub timeouts: u64,
    pub low_fee_rebates: u64,
    pub redaction_budget_spent: u64,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
pub struct Roots {
    pub encrypted_bid_lots_root: String,
    pub settlement_bytecode_lanes_root: String,
    pub pq_settlement_attestations_root: String,
    pub solver_fills_root: String,
    pub rollback_timeouts_root: String,
    pub low_fee_rebates_root: String,
    pub privacy_redaction_budgets_root: String,
    pub deterministic_state_root: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct EncryptedBidLot {
    pub lot_id: String,
    pub auction_id: String,
    pub bidder_commitment: String,
    pub encrypted_bid_ciphertext_root: String,
    pub encrypted_quantity_ciphertext_root: String,
    pub max_fee_bps: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub expires_at_height: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct SettlementBytecodeLane {
    pub lane_id: String,
    pub auction_id: String,
    pub kind: BytecodeLaneKind,
    pub bytecode_commitment: String,
    pub read_set_root: String,
    pub write_set_root: String,
    pub gas_limit: u64,
    pub rollback_entrypoint: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct PqSettlementAttestation {
    pub attestation_id: String,
    pub auction_id: String,
    pub lane_id: String,
    pub solver_id: String,
    pub public_key_commitment: String,
    pub signature_root: String,
    pub transcript_root: String,
    pub security_bits: u16,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct SolverFill {
    pub fill_id: String,
    pub auction_id: String,
    pub solver_id: String,
    pub status: FillStatus,
    pub input_commitment_root: String,
    pub output_commitment_root: String,
    pub clearing_price_commitment: String,
    pub filled_lots: u64,
    pub solver_fee_bps: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct RollbackTimeout {
    pub guard_id: String,
    pub auction_id: String,
    pub timeout_height: u64,
    pub rollback_root: String,
    pub slash_bps: u64,
    pub executed: bool,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct LowFeeRebate {
    pub rebate_id: String,
    pub auction_id: String,
    pub beneficiary_commitment: String,
    pub rebate_asset_id: String,
    pub rebate_micro_units: u64,
    pub nullifier: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct PrivacyRedactionBudget {
    pub budget_id: String,
    pub auction_id: String,
    pub redaction_policy_root: String,
    pub opened_fields: u64,
    pub max_opened_fields: u64,
    pub spent: bool,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct Auction {
    pub auction_id: String,
    pub kind: AuctionKind,
    pub status: AuctionStatus,
    pub contract_commitment: String,
    pub encrypted_clearing_rule_root: String,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub auctions: BTreeMap<String, Auction>,
    pub encrypted_bid_lots: BTreeMap<String, EncryptedBidLot>,
    pub settlement_bytecode_lanes: BTreeMap<String, SettlementBytecodeLane>,
    pub pq_settlement_attestations: BTreeMap<String, PqSettlementAttestation>,
    pub solver_fills: BTreeMap<String, SolverFill>,
    pub rollback_timeouts: BTreeMap<String, RollbackTimeout>,
    pub low_fee_rebates: BTreeMap<String, LowFeeRebate>,
    pub privacy_redaction_budgets: BTreeMap<String, PrivacyRedactionBudget>,
    pub metadata: BTreeMap<String, String>,
}

impl State {
    pub fn devnet() -> Self {
        devnet()
    }

    pub fn public_record(&self) -> Value {
        public_record(self)
    }

    pub fn state_root(&self) -> String {
        state_root(self)
    }

    pub fn validate(&self) -> Result<()> {
        if self.config.protocol_version != PROTOCOL_VERSION {
            return Err("protocol version mismatch".to_string());
        }
        if self.config.max_user_fee_bps > MAX_BPS
            || self.config.solver_fee_bps > MAX_BPS
            || self.config.rebate_bps > MAX_BPS
            || self.config.rollback_slash_bps > MAX_BPS
        {
            return Err("basis point configuration exceeds MAX_BPS".to_string());
        }
        if self.config.min_privacy_set_size > self.config.target_privacy_set_size {
            return Err("minimum privacy set exceeds target privacy set".to_string());
        }
        Ok(())
    }
}

pub fn devnet() -> State {
    let config = Config::default();
    let mut auctions = BTreeMap::new();
    let mut encrypted_bid_lots = BTreeMap::new();
    let mut settlement_bytecode_lanes = BTreeMap::new();
    let mut pq_settlement_attestations = BTreeMap::new();
    let mut solver_fills = BTreeMap::new();
    let mut rollback_timeouts = BTreeMap::new();
    let mut low_fee_rebates = BTreeMap::new();
    let mut privacy_redaction_budgets = BTreeMap::new();

    let auction = Auction {
        auction_id: "auction_devnet_0001".to_string(),
        kind: AuctionKind::BatchSwap,
        status: AuctionStatus::Attested,
        contract_commitment: fixture_root("contract", "auction_devnet_0001"),
        encrypted_clearing_rule_root: fixture_root("clearing_rule", "auction_devnet_0001"),
        opened_at_height: DEVNET_HEIGHT,
        expires_at_height: DEVNET_HEIGHT + config.auction_ttl_blocks,
    };
    auctions.insert(auction.auction_id.clone(), auction);

    encrypted_bid_lots.insert(
        "bid_lot_devnet_0001".to_string(),
        EncryptedBidLot {
            lot_id: "bid_lot_devnet_0001".to_string(),
            auction_id: "auction_devnet_0001".to_string(),
            bidder_commitment: fixture_root("bidder", "alpha"),
            encrypted_bid_ciphertext_root: fixture_root("encrypted_bid", "alpha"),
            encrypted_quantity_ciphertext_root: fixture_root("encrypted_quantity", "alpha"),
            max_fee_bps: config.max_user_fee_bps,
            privacy_set_size: config.target_privacy_set_size,
            pq_security_bits: config.min_pq_security_bits,
            expires_at_height: DEVNET_HEIGHT + config.auction_ttl_blocks,
        },
    );
    encrypted_bid_lots.insert(
        "bid_lot_devnet_0002".to_string(),
        EncryptedBidLot {
            lot_id: "bid_lot_devnet_0002".to_string(),
            auction_id: "auction_devnet_0001".to_string(),
            bidder_commitment: fixture_root("bidder", "bravo"),
            encrypted_bid_ciphertext_root: fixture_root("encrypted_bid", "bravo"),
            encrypted_quantity_ciphertext_root: fixture_root("encrypted_quantity", "bravo"),
            max_fee_bps: config.max_user_fee_bps,
            privacy_set_size: config.target_privacy_set_size,
            pq_security_bits: config.min_pq_security_bits,
            expires_at_height: DEVNET_HEIGHT + config.auction_ttl_blocks,
        },
    );

    settlement_bytecode_lanes.insert(
        "lane_devnet_swap_0001".to_string(),
        SettlementBytecodeLane {
            lane_id: "lane_devnet_swap_0001".to_string(),
            auction_id: "auction_devnet_0001".to_string(),
            kind: BytecodeLaneKind::Swap,
            bytecode_commitment: fixture_root("settlement_bytecode", "swap_lane"),
            read_set_root: fixture_root("read_set", "swap_lane"),
            write_set_root: fixture_root("write_set", "swap_lane"),
            gas_limit: 1_250_000,
            rollback_entrypoint: "rollback_swap_lane".to_string(),
        },
    );

    pq_settlement_attestations.insert(
        "attestation_devnet_0001".to_string(),
        PqSettlementAttestation {
            attestation_id: "attestation_devnet_0001".to_string(),
            auction_id: "auction_devnet_0001".to_string(),
            lane_id: "lane_devnet_swap_0001".to_string(),
            solver_id: "solver_devnet_alpha".to_string(),
            public_key_commitment: fixture_root("pq_pk", "solver_alpha"),
            signature_root: fixture_root("pq_signature", "solver_alpha"),
            transcript_root: fixture_root("settlement_transcript", "solver_alpha"),
            security_bits: config.min_pq_security_bits,
        },
    );

    solver_fills.insert(
        "fill_devnet_0001".to_string(),
        SolverFill {
            fill_id: "fill_devnet_0001".to_string(),
            auction_id: "auction_devnet_0001".to_string(),
            solver_id: "solver_devnet_alpha".to_string(),
            status: FillStatus::Filled,
            input_commitment_root: fixture_root("fill_inputs", "solver_alpha"),
            output_commitment_root: fixture_root("fill_outputs", "solver_alpha"),
            clearing_price_commitment: fixture_root("clearing_price", "solver_alpha"),
            filled_lots: 2,
            solver_fee_bps: config.solver_fee_bps,
        },
    );

    rollback_timeouts.insert(
        "rollback_guard_devnet_0001".to_string(),
        RollbackTimeout {
            guard_id: "rollback_guard_devnet_0001".to_string(),
            auction_id: "auction_devnet_0001".to_string(),
            timeout_height: DEVNET_HEIGHT + config.rollback_window_blocks,
            rollback_root: fixture_root("rollback", "auction_devnet_0001"),
            slash_bps: config.rollback_slash_bps,
            executed: false,
        },
    );

    low_fee_rebates.insert(
        "rebate_devnet_0001".to_string(),
        LowFeeRebate {
            rebate_id: "rebate_devnet_0001".to_string(),
            auction_id: "auction_devnet_0001".to_string(),
            beneficiary_commitment: fixture_root("rebate_beneficiary", "alpha"),
            rebate_asset_id: config.fee_asset_id.clone(),
            rebate_micro_units: config.base_settlement_micro_fee,
            nullifier: fixture_root("rebate_nullifier", "alpha"),
        },
    );

    privacy_redaction_budgets.insert(
        "redaction_budget_devnet_0001".to_string(),
        PrivacyRedactionBudget {
            budget_id: "redaction_budget_devnet_0001".to_string(),
            auction_id: "auction_devnet_0001".to_string(),
            redaction_policy_root: fixture_root("redaction_policy", "auction_devnet_0001"),
            opened_fields: 2,
            max_opened_fields: 8,
            spent: false,
        },
    );

    let counters = Counters {
        auctions_opened: auctions.len() as u64,
        encrypted_bid_lots: encrypted_bid_lots.len() as u64,
        bytecode_lanes_locked: settlement_bytecode_lanes.len() as u64,
        pq_settlement_attestations: pq_settlement_attestations.len() as u64,
        solver_fills: solver_fills.len() as u64,
        settlements_finalized: 0,
        rollbacks: 0,
        timeouts: 0,
        low_fee_rebates: low_fee_rebates.len() as u64,
        redaction_budget_spent: privacy_redaction_budgets
            .values()
            .filter(|budget| budget.spent)
            .count() as u64,
    };

    let metadata = BTreeMap::from([
        ("chain_id".to_string(), CHAIN_ID.to_string()),
        ("fixture".to_string(), "devnet".to_string()),
        (
            "description".to_string(),
            "private auction settlement VM devnet fixture".to_string(),
        ),
    ]);

    let mut state = State {
        config,
        counters,
        roots: Roots::default(),
        auctions,
        encrypted_bid_lots,
        settlement_bytecode_lanes,
        pq_settlement_attestations,
        solver_fills,
        rollback_timeouts,
        low_fee_rebates,
        privacy_redaction_budgets,
        metadata,
    };
    state.roots = compute_roots(&state);
    state
}

pub fn demo() -> State {
    let mut state = devnet();
    state
        .metadata
        .insert("fixture".to_string(), "demo".to_string());
    state.metadata.insert(
        "description".to_string(),
        "demo private auction with sealed bids, solver fill, PQ attestation, rebate, and rollback guard"
            .to_string(),
    );
    state.roots = compute_roots(&state);
    state
}

pub fn public_record(state: &State) -> Value {
    json!({
        "chain_id": CHAIN_ID,
        "protocol_version": PROTOCOL_VERSION,
        "schema_version": SCHEMA_VERSION,
        "hash_suite": HASH_SUITE,
        "pq_attestation_suite": state.config.pq_attestation_suite,
        "l2_network": state.config.l2_network,
        "fee_asset_id": state.config.fee_asset_id,
        "settlement_asset_id": state.config.settlement_asset_id,
        "counters": state.counters,
        "roots": state.roots,
        "live_auctions": state.auctions.values().filter(|auction| auction.status.live()).count(),
        "privacy": {
            "min_privacy_set_size": state.config.min_privacy_set_size,
            "target_privacy_set_size": state.config.target_privacy_set_size,
            "redaction_epoch_blocks": state.config.redaction_epoch_blocks,
        },
        "fees": {
            "base_settlement_micro_fee": state.config.base_settlement_micro_fee,
            "max_user_fee_bps": state.config.max_user_fee_bps,
            "solver_fee_bps": state.config.solver_fee_bps,
            "rebate_bps": state.config.rebate_bps,
        },
        "metadata": state.metadata,
    })
}

pub fn state_root(state: &State) -> String {
    compute_state_root(state)
}

fn compute_roots(state: &State) -> Roots {
    let mut roots = Roots {
        encrypted_bid_lots_root: collection_root(
            ENCRYPTED_BID_LOT_SCHEME,
            state.encrypted_bid_lots.values(),
        ),
        settlement_bytecode_lanes_root: collection_root(
            SETTLEMENT_BYTECODE_LANE_SCHEME,
            state.settlement_bytecode_lanes.values(),
        ),
        pq_settlement_attestations_root: collection_root(
            PQ_ATTESTATION_SUITE,
            state.pq_settlement_attestations.values(),
        ),
        solver_fills_root: collection_root(SOLVER_FILL_SCHEME, state.solver_fills.values()),
        rollback_timeouts_root: collection_root(
            ROLLBACK_TIMEOUT_SCHEME,
            state.rollback_timeouts.values(),
        ),
        low_fee_rebates_root: collection_root(
            LOW_FEE_REBATE_SCHEME,
            state.low_fee_rebates.values(),
        ),
        privacy_redaction_budgets_root: collection_root(
            PRIVACY_REDACTION_BUDGET_SCHEME,
            state.privacy_redaction_budgets.values(),
        ),
        deterministic_state_root: String::new(),
    };
    roots.deterministic_state_root = compute_state_root_with_roots(state, &roots);
    roots
}

fn compute_state_root(state: &State) -> String {
    let roots = Roots {
        encrypted_bid_lots_root: collection_root(
            ENCRYPTED_BID_LOT_SCHEME,
            state.encrypted_bid_lots.values(),
        ),
        settlement_bytecode_lanes_root: collection_root(
            SETTLEMENT_BYTECODE_LANE_SCHEME,
            state.settlement_bytecode_lanes.values(),
        ),
        pq_settlement_attestations_root: collection_root(
            PQ_ATTESTATION_SUITE,
            state.pq_settlement_attestations.values(),
        ),
        solver_fills_root: collection_root(SOLVER_FILL_SCHEME, state.solver_fills.values()),
        rollback_timeouts_root: collection_root(
            ROLLBACK_TIMEOUT_SCHEME,
            state.rollback_timeouts.values(),
        ),
        low_fee_rebates_root: collection_root(
            LOW_FEE_REBATE_SCHEME,
            state.low_fee_rebates.values(),
        ),
        privacy_redaction_budgets_root: collection_root(
            PRIVACY_REDACTION_BUDGET_SCHEME,
            state.privacy_redaction_budgets.values(),
        ),
        deterministic_state_root: String::new(),
    };
    compute_state_root_with_roots(state, &roots)
}

fn compute_state_root_with_roots(state: &State, roots: &Roots) -> String {
    domain_hash(&[
        HashPart::Str(PROTOCOL_VERSION),
        HashPart::U64(SCHEMA_VERSION),
        HashPart::Str(&state.config.l2_network),
        HashPart::U64(state.counters.auctions_opened),
        HashPart::U64(state.counters.encrypted_bid_lots),
        HashPart::U64(state.counters.bytecode_lanes_locked),
        HashPart::U64(state.counters.pq_settlement_attestations),
        HashPart::U64(state.counters.solver_fills),
        HashPart::Str(&roots.encrypted_bid_lots_root),
        HashPart::Str(&roots.settlement_bytecode_lanes_root),
        HashPart::Str(&roots.pq_settlement_attestations_root),
        HashPart::Str(&roots.solver_fills_root),
        HashPart::Str(&roots.rollback_timeouts_root),
        HashPart::Str(&roots.low_fee_rebates_root),
        HashPart::Str(&roots.privacy_redaction_budgets_root),
    ])
}

fn collection_root<'a, T, I>(domain: &str, values: I) -> String
where
    T: Serialize + 'a,
    I: IntoIterator<Item = &'a T>,
{
    let records = values
        .into_iter()
        .map(|value| serde_json::to_string(value).unwrap_or_else(|_| "null".to_string()))
        .collect::<Vec<_>>();
    merkle_root(&format!("{PROTOCOL_VERSION}:{domain}"), &records)
}

fn fixture_root(domain: &str, id: &str) -> String {
    domain_hash(&[
        HashPart::Str(PROTOCOL_VERSION),
        HashPart::Str(domain),
        HashPart::Str(id),
    ])
}
