use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateBatchAuctionSolverResult<T> = Result<T, String>;

pub const PRIVATE_BATCH_AUCTION_SOLVER_PROTOCOL_VERSION: &str =
    "nebula-private-batch-auction-solver-v1";
pub const PRIVATE_BATCH_AUCTION_SOLVER_SCHEMA_VERSION: u64 = 1;
pub const PRIVATE_BATCH_AUCTION_SOLVER_HASH_SUITE: &str =
    "SHAKE256-domain-separated-canonical-json";
pub const PRIVATE_BATCH_AUCTION_SOLVER_SECURITY_MODEL: &str =
    "devnet-production-shaped-records-not-real-cryptography";
pub const PRIVATE_BATCH_AUCTION_SOLVER_ORDER_ENCRYPTION_SCHEME: &str =
    "ml-kem-1024+threshold-reveal+shake256-private-order-v1";
pub const PRIVATE_BATCH_AUCTION_SOLVER_COMMITMENT_SCHEME: &str =
    "sealed-order-poseidon-compatible-shake256-v1";
pub const PRIVATE_BATCH_AUCTION_SOLVER_PQ_ATTESTATION_SCHEME: &str =
    "ml-dsa-87+slh-dsa-shake-128f-solver-attestation-v1";
pub const PRIVATE_BATCH_AUCTION_SOLVER_RECEIPT_SCHEME: &str =
    "zk-private-batch-settlement-receipt-v1";
pub const PRIVATE_BATCH_AUCTION_SOLVER_REBATE_SCHEME: &str =
    "surplus-rebate-commitment-nullifier-v1";
pub const PRIVATE_BATCH_AUCTION_SOLVER_RISK_SCHEME: &str = "anti-correlation-cross-venue-risk-v1";
pub const PRIVATE_BATCH_AUCTION_SOLVER_DEVNET_HEIGHT: u64 = 896;
pub const PRIVATE_BATCH_AUCTION_SOLVER_DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const PRIVATE_BATCH_AUCTION_SOLVER_DEVNET_COLLATERAL_ASSET_ID: &str = "dxmr";
pub const PRIVATE_BATCH_AUCTION_SOLVER_DEVNET_QUOTE_ASSET_ID: &str = "dusd";
pub const PRIVATE_BATCH_AUCTION_SOLVER_DEFAULT_EPOCH_BLOCKS: u64 = 12;
pub const PRIVATE_BATCH_AUCTION_SOLVER_DEFAULT_COMMIT_TTL_BLOCKS: u64 = 18;
pub const PRIVATE_BATCH_AUCTION_SOLVER_DEFAULT_REVEAL_TTL_BLOCKS: u64 = 6;
pub const PRIVATE_BATCH_AUCTION_SOLVER_DEFAULT_SETTLEMENT_TTL_BLOCKS: u64 = 48;
pub const PRIVATE_BATCH_AUCTION_SOLVER_DEFAULT_BOND_TTL_BLOCKS: u64 = 7_200;
pub const PRIVATE_BATCH_AUCTION_SOLVER_DEFAULT_MIN_SOLVER_BOND_UNITS: u64 = 25_000_000_000;
pub const PRIVATE_BATCH_AUCTION_SOLVER_DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const PRIVATE_BATCH_AUCTION_SOLVER_DEFAULT_MAX_BATCH_ORDERS: usize = 512;
pub const PRIVATE_BATCH_AUCTION_SOLVER_DEFAULT_MAX_BATCH_NOTIONAL_UNITS: u128 = 5_000_000_000_000;
pub const PRIVATE_BATCH_AUCTION_SOLVER_DEFAULT_MAX_SOLVER_EXPOSURE_BPS: u64 = 2_500;
pub const PRIVATE_BATCH_AUCTION_SOLVER_DEFAULT_MAX_CORRELATION_BPS: u64 = 6_500;
pub const PRIVATE_BATCH_AUCTION_SOLVER_DEFAULT_MAX_LANE_FEE_BPS: u64 = 45;
pub const PRIVATE_BATCH_AUCTION_SOLVER_DEFAULT_LOW_FEE_LANE_BPS: u64 = 8;
pub const PRIVATE_BATCH_AUCTION_SOLVER_DEFAULT_REBATE_SHARE_BPS: u64 = 7_500;
pub const PRIVATE_BATCH_AUCTION_SOLVER_DEFAULT_SLASH_BPS: u64 = 2_500;
pub const PRIVATE_BATCH_AUCTION_SOLVER_DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 128;
pub const PRIVATE_BATCH_AUCTION_SOLVER_MAX_BPS: u64 = 10_000;
pub const PRIVATE_BATCH_AUCTION_SOLVER_MAX_SOLVERS: usize = 4_096;
pub const PRIVATE_BATCH_AUCTION_SOLVER_MAX_LANES: usize = 64;
pub const PRIVATE_BATCH_AUCTION_SOLVER_MAX_BATCHES: usize = 16_384;
pub const PRIVATE_BATCH_AUCTION_SOLVER_MAX_ORDERS: usize = 262_144;
pub const PRIVATE_BATCH_AUCTION_SOLVER_MAX_ATTESTATIONS: usize = 262_144;
pub const PRIVATE_BATCH_AUCTION_SOLVER_MAX_RISK_LIMITS: usize = 8_192;
pub const PRIVATE_BATCH_AUCTION_SOLVER_MAX_REBATES: usize = 262_144;
pub const PRIVATE_BATCH_AUCTION_SOLVER_MAX_RECEIPTS: usize = 262_144;
pub const PRIVATE_BATCH_AUCTION_SOLVER_MAX_EVENTS: usize = 262_144;
pub const PRIVATE_BATCH_AUCTION_SOLVER_STATE_ACTIVE: &str = "active";
pub const PRIVATE_BATCH_AUCTION_SOLVER_STATE_CHALLENGED: &str = "challenged";
pub const PRIVATE_BATCH_AUCTION_SOLVER_STATE_HALTED: &str = "halted";

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuctionFlowKind {
    AmmSwap,
    MoneroExit,
    LendingLiquidation,
    PerpsHedge,
    TokenMintBurn,
    SmartContractIntent,
}

impl AuctionFlowKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AmmSwap => "amm_swap",
            Self::MoneroExit => "monero_exit",
            Self::LendingLiquidation => "lending_liquidation",
            Self::PerpsHedge => "perps_hedge",
            Self::TokenMintBurn => "token_mint_burn",
            Self::SmartContractIntent => "smart_contract_intent",
        }
    }

    pub fn default_lane(self) -> SolverLaneKind {
        match self {
            Self::AmmSwap => SolverLaneKind::PrivateAmm,
            Self::MoneroExit => SolverLaneKind::MoneroExit,
            Self::LendingLiquidation => SolverLaneKind::Liquidation,
            Self::PerpsHedge => SolverLaneKind::PerpsRisk,
            Self::TokenMintBurn => SolverLaneKind::LowFee,
            Self::SmartContractIntent => SolverLaneKind::PrivateContract,
        }
    }

    pub fn risk_weight_bps(self) -> u64 {
        match self {
            Self::PerpsHedge => 1_250,
            Self::LendingLiquidation => 1_100,
            Self::MoneroExit => 900,
            Self::AmmSwap => 700,
            Self::SmartContractIntent => 650,
            Self::TokenMintBurn => 450,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SolverLaneKind {
    LowFee,
    PrivateAmm,
    MoneroExit,
    Liquidation,
    PerpsRisk,
    PrivateContract,
    EmergencyUnwind,
}

impl SolverLaneKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LowFee => "low_fee",
            Self::PrivateAmm => "private_amm",
            Self::MoneroExit => "monero_exit",
            Self::Liquidation => "liquidation",
            Self::PerpsRisk => "perps_risk",
            Self::PrivateContract => "private_contract",
            Self::EmergencyUnwind => "emergency_unwind",
        }
    }

    pub fn priority(self) -> u64 {
        match self {
            Self::EmergencyUnwind => 0,
            Self::MoneroExit => 1,
            Self::Liquidation => 2,
            Self::PerpsRisk => 3,
            Self::PrivateAmm => 4,
            Self::PrivateContract => 5,
            Self::LowFee => 6,
        }
    }

    pub fn privacy_sensitive(self) -> bool {
        matches!(
            self,
            Self::LowFee
                | Self::PrivateAmm
                | Self::MoneroExit
                | Self::Liquidation
                | Self::PerpsRisk
                | Self::PrivateContract
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchStatus {
    Collecting,
    Sealed,
    Solving,
    Attested,
    Settling,
    Settled,
    Challenged,
    Cancelled,
    Expired,
}

impl BatchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Collecting => "collecting",
            Self::Sealed => "sealed",
            Self::Solving => "solving",
            Self::Attested => "attested",
            Self::Settling => "settling",
            Self::Settled => "settled",
            Self::Challenged => "challenged",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
        }
    }

    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Collecting | Self::Sealed | Self::Solving | Self::Attested | Self::Settling
        )
    }

    pub fn accepts_orders(self) -> bool {
        matches!(self, Self::Collecting | Self::Sealed)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OrderStatus {
    Committed,
    Queued,
    Matched,
    Settled,
    Rebased,
    Refunded,
    Cancelled,
    Expired,
    Rejected,
}

impl OrderStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Committed => "committed",
            Self::Queued => "queued",
            Self::Matched => "matched",
            Self::Settled => "settled",
            Self::Rebased => "rebased",
            Self::Refunded => "refunded",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
            Self::Rejected => "rejected",
        }
    }

    pub fn active(self) -> bool {
        matches!(self, Self::Committed | Self::Queued | Self::Matched)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SolverBondStatus {
    Active,
    Locked,
    Withdrawing,
    Slashed,
    Retired,
    Expired,
}

impl SolverBondStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Locked => "locked",
            Self::Withdrawing => "withdrawing",
            Self::Slashed => "slashed",
            Self::Retired => "retired",
            Self::Expired => "expired",
        }
    }

    pub fn usable(self) -> bool {
        matches!(self, Self::Active | Self::Locked)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqAttestationStatus {
    Pending,
    Verified,
    Used,
    Revoked,
    Expired,
    Disputed,
}

impl PqAttestationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Verified => "verified",
            Self::Used => "used",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
            Self::Disputed => "disputed",
        }
    }

    pub fn valid_for_settlement(self) -> bool {
        matches!(self, Self::Verified | Self::Used)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptStatus {
    Pending,
    Published,
    Finalized,
    Disputed,
    Reversed,
}

impl ReceiptStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Published => "published",
            Self::Finalized => "finalized",
            Self::Disputed => "disputed",
            Self::Reversed => "reversed",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskAction {
    Allow,
    Haircut,
    SplitBatch,
    RequireHedge,
    Block,
}

impl RiskAction {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Haircut => "haircut",
            Self::SplitBatch => "split_batch",
            Self::RequireHedge => "require_hedge",
            Self::Block => "block",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SolverConfig {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub order_encryption_scheme: String,
    pub commitment_scheme: String,
    pub pq_attestation_scheme: String,
    pub receipt_scheme: String,
    pub rebate_scheme: String,
    pub risk_scheme: String,
    pub fee_asset_id: String,
    pub collateral_asset_id: String,
    pub quote_asset_id: String,
    pub epoch_blocks: u64,
    pub commit_ttl_blocks: u64,
    pub reveal_ttl_blocks: u64,
    pub settlement_ttl_blocks: u64,
    pub bond_ttl_blocks: u64,
    pub min_solver_bond_units: u64,
    pub min_pq_security_bits: u16,
    pub max_batch_orders: usize,
    pub max_batch_notional_units: u128,
    pub max_solver_exposure_bps: u64,
    pub max_correlation_bps: u64,
    pub max_lane_fee_bps: u64,
    pub low_fee_lane_bps: u64,
    pub rebate_share_bps: u64,
    pub slash_bps: u64,
    pub min_privacy_set_size: u64,
}

impl SolverConfig {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PRIVATE_BATCH_AUCTION_SOLVER_PROTOCOL_VERSION.to_string(),
            schema_version: PRIVATE_BATCH_AUCTION_SOLVER_SCHEMA_VERSION,
            hash_suite: PRIVATE_BATCH_AUCTION_SOLVER_HASH_SUITE.to_string(),
            order_encryption_scheme: PRIVATE_BATCH_AUCTION_SOLVER_ORDER_ENCRYPTION_SCHEME
                .to_string(),
            commitment_scheme: PRIVATE_BATCH_AUCTION_SOLVER_COMMITMENT_SCHEME.to_string(),
            pq_attestation_scheme: PRIVATE_BATCH_AUCTION_SOLVER_PQ_ATTESTATION_SCHEME.to_string(),
            receipt_scheme: PRIVATE_BATCH_AUCTION_SOLVER_RECEIPT_SCHEME.to_string(),
            rebate_scheme: PRIVATE_BATCH_AUCTION_SOLVER_REBATE_SCHEME.to_string(),
            risk_scheme: PRIVATE_BATCH_AUCTION_SOLVER_RISK_SCHEME.to_string(),
            fee_asset_id: PRIVATE_BATCH_AUCTION_SOLVER_DEVNET_FEE_ASSET_ID.to_string(),
            collateral_asset_id: PRIVATE_BATCH_AUCTION_SOLVER_DEVNET_COLLATERAL_ASSET_ID
                .to_string(),
            quote_asset_id: PRIVATE_BATCH_AUCTION_SOLVER_DEVNET_QUOTE_ASSET_ID.to_string(),
            epoch_blocks: PRIVATE_BATCH_AUCTION_SOLVER_DEFAULT_EPOCH_BLOCKS,
            commit_ttl_blocks: PRIVATE_BATCH_AUCTION_SOLVER_DEFAULT_COMMIT_TTL_BLOCKS,
            reveal_ttl_blocks: PRIVATE_BATCH_AUCTION_SOLVER_DEFAULT_REVEAL_TTL_BLOCKS,
            settlement_ttl_blocks: PRIVATE_BATCH_AUCTION_SOLVER_DEFAULT_SETTLEMENT_TTL_BLOCKS,
            bond_ttl_blocks: PRIVATE_BATCH_AUCTION_SOLVER_DEFAULT_BOND_TTL_BLOCKS,
            min_solver_bond_units: PRIVATE_BATCH_AUCTION_SOLVER_DEFAULT_MIN_SOLVER_BOND_UNITS,
            min_pq_security_bits: PRIVATE_BATCH_AUCTION_SOLVER_DEFAULT_MIN_PQ_SECURITY_BITS,
            max_batch_orders: PRIVATE_BATCH_AUCTION_SOLVER_DEFAULT_MAX_BATCH_ORDERS,
            max_batch_notional_units: PRIVATE_BATCH_AUCTION_SOLVER_DEFAULT_MAX_BATCH_NOTIONAL_UNITS,
            max_solver_exposure_bps: PRIVATE_BATCH_AUCTION_SOLVER_DEFAULT_MAX_SOLVER_EXPOSURE_BPS,
            max_correlation_bps: PRIVATE_BATCH_AUCTION_SOLVER_DEFAULT_MAX_CORRELATION_BPS,
            max_lane_fee_bps: PRIVATE_BATCH_AUCTION_SOLVER_DEFAULT_MAX_LANE_FEE_BPS,
            low_fee_lane_bps: PRIVATE_BATCH_AUCTION_SOLVER_DEFAULT_LOW_FEE_LANE_BPS,
            rebate_share_bps: PRIVATE_BATCH_AUCTION_SOLVER_DEFAULT_REBATE_SHARE_BPS,
            slash_bps: PRIVATE_BATCH_AUCTION_SOLVER_DEFAULT_SLASH_BPS,
            min_privacy_set_size: PRIVATE_BATCH_AUCTION_SOLVER_DEFAULT_MIN_PRIVACY_SET_SIZE,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "security_model": PRIVATE_BATCH_AUCTION_SOLVER_SECURITY_MODEL,
            "order_encryption_scheme": self.order_encryption_scheme,
            "commitment_scheme": self.commitment_scheme,
            "pq_attestation_scheme": self.pq_attestation_scheme,
            "receipt_scheme": self.receipt_scheme,
            "rebate_scheme": self.rebate_scheme,
            "risk_scheme": self.risk_scheme,
            "fee_asset_id": self.fee_asset_id,
            "collateral_asset_id": self.collateral_asset_id,
            "quote_asset_id": self.quote_asset_id,
            "epoch_blocks": self.epoch_blocks,
            "commit_ttl_blocks": self.commit_ttl_blocks,
            "reveal_ttl_blocks": self.reveal_ttl_blocks,
            "settlement_ttl_blocks": self.settlement_ttl_blocks,
            "bond_ttl_blocks": self.bond_ttl_blocks,
            "min_solver_bond_units": self.min_solver_bond_units,
            "min_pq_security_bits": self.min_pq_security_bits,
            "max_batch_orders": self.max_batch_orders,
            "max_batch_notional_units": self.max_batch_notional_units.to_string(),
            "max_solver_exposure_bps": self.max_solver_exposure_bps,
            "max_correlation_bps": self.max_correlation_bps,
            "max_lane_fee_bps": self.max_lane_fee_bps,
            "low_fee_lane_bps": self.low_fee_lane_bps,
            "rebate_share_bps": self.rebate_share_bps,
            "slash_bps": self.slash_bps,
            "min_privacy_set_size": self.min_privacy_set_size,
        })
    }

    pub fn state_root(&self) -> String {
        solver_payload_root("CONFIG", &self.public_record())
    }

    pub fn validate(&self) -> PrivateBatchAuctionSolverResult<String> {
        ensure_non_empty("chain id", &self.chain_id)?;
        ensure_non_empty("fee asset id", &self.fee_asset_id)?;
        ensure_non_empty("collateral asset id", &self.collateral_asset_id)?;
        ensure_bps("max solver exposure bps", self.max_solver_exposure_bps)?;
        ensure_bps("max correlation bps", self.max_correlation_bps)?;
        ensure_bps("max lane fee bps", self.max_lane_fee_bps)?;
        ensure_bps("low fee lane bps", self.low_fee_lane_bps)?;
        ensure_bps("rebate share bps", self.rebate_share_bps)?;
        ensure_bps("slash bps", self.slash_bps)?;
        if self.low_fee_lane_bps > self.max_lane_fee_bps {
            return Err("low fee lane bps exceeds max lane fee bps".to_string());
        }
        if self.max_batch_orders == 0 {
            return Err("max batch orders must be non-zero".to_string());
        }
        if self.min_pq_security_bits < 192 {
            return Err("minimum PQ security below production floor".to_string());
        }
        Ok(self.state_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchLanePolicy {
    pub lane_id: String,
    pub kind: SolverLaneKind,
    pub enabled: bool,
    pub fee_bps: u64,
    pub max_orders: usize,
    pub max_notional_units: u128,
    pub min_privacy_set_size: u64,
    pub sponsor_budget_units: u64,
    pub priority: u64,
    pub risk_weight_bps: u64,
}

impl BatchLanePolicy {
    pub fn new(
        lane_id: &str,
        kind: SolverLaneKind,
        fee_bps: u64,
        max_orders: usize,
        max_notional_units: u128,
    ) -> PrivateBatchAuctionSolverResult<Self> {
        ensure_non_empty("lane id", lane_id)?;
        ensure_bps("lane fee bps", fee_bps)?;
        Ok(Self {
            lane_id: lane_id.to_string(),
            kind,
            enabled: true,
            fee_bps,
            max_orders,
            max_notional_units,
            min_privacy_set_size: PRIVATE_BATCH_AUCTION_SOLVER_DEFAULT_MIN_PRIVACY_SET_SIZE,
            sponsor_budget_units: 50_000_000,
            priority: kind.priority(),
            risk_weight_bps: match kind {
                SolverLaneKind::EmergencyUnwind => 1_500,
                SolverLaneKind::PerpsRisk => 1_250,
                SolverLaneKind::Liquidation => 1_100,
                SolverLaneKind::MoneroExit => 900,
                SolverLaneKind::PrivateAmm => 700,
                SolverLaneKind::PrivateContract => 650,
                SolverLaneKind::LowFee => 450,
            },
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "lane_id": self.lane_id,
            "kind": self.kind.as_str(),
            "enabled": self.enabled,
            "fee_bps": self.fee_bps,
            "max_orders": self.max_orders,
            "max_notional_units": self.max_notional_units.to_string(),
            "min_privacy_set_size": self.min_privacy_set_size,
            "sponsor_budget_units": self.sponsor_budget_units,
            "priority": self.priority,
            "risk_weight_bps": self.risk_weight_bps,
        })
    }

    pub fn state_root(&self) -> String {
        solver_payload_root("LANE-POLICY", &self.public_record())
    }

    pub fn validate(&self, config: &SolverConfig) -> PrivateBatchAuctionSolverResult<String> {
        ensure_non_empty("lane id", &self.lane_id)?;
        ensure_bps("lane fee bps", self.fee_bps)?;
        ensure_bps("lane risk weight bps", self.risk_weight_bps)?;
        if self.fee_bps > config.max_lane_fee_bps {
            return Err(format!("lane {} fee exceeds config max", self.lane_id));
        }
        if self.kind == SolverLaneKind::LowFee && self.fee_bps > config.low_fee_lane_bps {
            return Err(format!(
                "low-fee lane {} fee exceeds low-fee cap",
                self.lane_id
            ));
        }
        if self.max_orders == 0 {
            return Err(format!("lane {} max orders must be non-zero", self.lane_id));
        }
        if self.min_privacy_set_size < config.min_privacy_set_size {
            return Err(format!(
                "lane {} privacy set below config floor",
                self.lane_id
            ));
        }
        Ok(self.state_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SolverBond {
    pub solver_id: String,
    pub bond_id: String,
    pub owner_commitment: String,
    pub stake_asset_id: String,
    pub bonded_units: u64,
    pub locked_units: u64,
    pub slashed_units: u64,
    pub opened_height: u64,
    pub expires_height: u64,
    pub status: SolverBondStatus,
    pub pq_identity_root: String,
    pub allowed_lanes: BTreeSet<SolverLaneKind>,
}

impl SolverBond {
    pub fn new(
        solver_id: &str,
        owner_commitment: &str,
        stake_asset_id: &str,
        bonded_units: u64,
        height: u64,
        allowed_lanes: BTreeSet<SolverLaneKind>,
    ) -> PrivateBatchAuctionSolverResult<Self> {
        ensure_non_empty("solver id", solver_id)?;
        ensure_non_empty("owner commitment", owner_commitment)?;
        ensure_non_empty("stake asset id", stake_asset_id)?;
        if allowed_lanes.is_empty() {
            return Err("solver bond requires at least one lane".to_string());
        }
        let bond_id =
            solver_id_from_parts("BOND", &[solver_id, owner_commitment, &height.to_string()]);
        let pq_identity_root = solver_id_from_parts("PQ-IDENTITY", &[solver_id, owner_commitment]);
        Ok(Self {
            solver_id: solver_id.to_string(),
            bond_id,
            owner_commitment: owner_commitment.to_string(),
            stake_asset_id: stake_asset_id.to_string(),
            bonded_units,
            locked_units: 0,
            slashed_units: 0,
            opened_height: height,
            expires_height: height + PRIVATE_BATCH_AUCTION_SOLVER_DEFAULT_BOND_TTL_BLOCKS,
            status: SolverBondStatus::Active,
            pq_identity_root,
            allowed_lanes,
        })
    }

    pub fn set_height(&mut self, height: u64) {
        if height > self.expires_height && self.status.usable() {
            self.status = SolverBondStatus::Expired;
        }
    }

    pub fn available_units(&self) -> u64 {
        self.bonded_units
            .saturating_sub(self.locked_units)
            .saturating_sub(self.slashed_units)
    }

    pub fn can_solve_lane(&self, lane: SolverLaneKind) -> bool {
        self.status.usable() && self.allowed_lanes.contains(&lane)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "solver_id": self.solver_id,
            "bond_id": self.bond_id,
            "owner_commitment": self.owner_commitment,
            "stake_asset_id": self.stake_asset_id,
            "bonded_units": self.bonded_units,
            "locked_units": self.locked_units,
            "slashed_units": self.slashed_units,
            "available_units": self.available_units(),
            "opened_height": self.opened_height,
            "expires_height": self.expires_height,
            "status": self.status.as_str(),
            "pq_identity_root": self.pq_identity_root,
            "allowed_lanes": self.allowed_lanes.iter().map(|lane| lane.as_str()).collect::<Vec<_>>(),
        })
    }

    pub fn state_root(&self) -> String {
        solver_payload_root("SOLVER-BOND", &self.public_record())
    }

    pub fn validate(&self, config: &SolverConfig) -> PrivateBatchAuctionSolverResult<String> {
        ensure_non_empty("solver id", &self.solver_id)?;
        ensure_non_empty("bond id", &self.bond_id)?;
        ensure_non_empty("owner commitment", &self.owner_commitment)?;
        if self.bonded_units < config.min_solver_bond_units {
            return Err(format!("solver {} bond below minimum", self.solver_id));
        }
        if self.locked_units + self.slashed_units > self.bonded_units {
            return Err(format!("solver {} over-allocated bond", self.solver_id));
        }
        if self.opened_height >= self.expires_height {
            return Err(format!(
                "solver {} bond expiry before opening",
                self.solver_id
            ));
        }
        if self.allowed_lanes.is_empty() {
            return Err(format!("solver {} has no allowed lanes", self.solver_id));
        }
        Ok(self.state_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedOrderCommitment {
    pub order_id: String,
    pub batch_id: String,
    pub owner_nullifier: String,
    pub flow: AuctionFlowKind,
    pub lane: SolverLaneKind,
    pub input_asset_id: String,
    pub output_asset_id: String,
    pub notional_commitment: String,
    pub min_output_commitment: String,
    pub encrypted_payload_root: String,
    pub ciphertext_bytes: u64,
    pub privacy_set_size: u64,
    pub fee_limit_units: u64,
    pub arrival_height: u64,
    pub expires_height: u64,
    pub status: OrderStatus,
    pub reveal_hint_root: String,
    pub replay_nullifier: String,
}

impl EncryptedOrderCommitment {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        batch_id: &str,
        owner_nullifier: &str,
        flow: AuctionFlowKind,
        input_asset_id: &str,
        output_asset_id: &str,
        notional_commitment: &str,
        min_output_commitment: &str,
        encrypted_payload_root: &str,
        fee_limit_units: u64,
        height: u64,
    ) -> PrivateBatchAuctionSolverResult<Self> {
        ensure_non_empty("batch id", batch_id)?;
        ensure_non_empty("owner nullifier", owner_nullifier)?;
        ensure_non_empty("input asset id", input_asset_id)?;
        ensure_non_empty("output asset id", output_asset_id)?;
        ensure_non_empty("notional commitment", notional_commitment)?;
        ensure_non_empty("min output commitment", min_output_commitment)?;
        ensure_non_empty("encrypted payload root", encrypted_payload_root)?;
        let lane = flow.default_lane();
        let order_id = solver_id_from_parts(
            "ORDER",
            &[
                batch_id,
                owner_nullifier,
                flow.as_str(),
                encrypted_payload_root,
                &height.to_string(),
            ],
        );
        let replay_nullifier = solver_id_from_parts("REPLAY", &[batch_id, owner_nullifier]);
        let reveal_hint_root =
            solver_id_from_parts("REVEAL-HINT", &[&order_id, encrypted_payload_root]);
        Ok(Self {
            order_id,
            batch_id: batch_id.to_string(),
            owner_nullifier: owner_nullifier.to_string(),
            flow,
            lane,
            input_asset_id: input_asset_id.to_string(),
            output_asset_id: output_asset_id.to_string(),
            notional_commitment: notional_commitment.to_string(),
            min_output_commitment: min_output_commitment.to_string(),
            encrypted_payload_root: encrypted_payload_root.to_string(),
            ciphertext_bytes: 2_048,
            privacy_set_size: PRIVATE_BATCH_AUCTION_SOLVER_DEFAULT_MIN_PRIVACY_SET_SIZE,
            fee_limit_units,
            arrival_height: height,
            expires_height: height + PRIVATE_BATCH_AUCTION_SOLVER_DEFAULT_COMMIT_TTL_BLOCKS,
            status: OrderStatus::Committed,
            reveal_hint_root,
            replay_nullifier,
        })
    }

    pub fn set_height(&mut self, height: u64) {
        if height > self.expires_height && self.status.active() {
            self.status = OrderStatus::Expired;
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "order_id": self.order_id,
            "batch_id": self.batch_id,
            "owner_nullifier": self.owner_nullifier,
            "flow": self.flow.as_str(),
            "lane": self.lane.as_str(),
            "input_asset_id": self.input_asset_id,
            "output_asset_id": self.output_asset_id,
            "notional_commitment": self.notional_commitment,
            "min_output_commitment": self.min_output_commitment,
            "encrypted_payload_root": self.encrypted_payload_root,
            "ciphertext_bytes": self.ciphertext_bytes,
            "privacy_set_size": self.privacy_set_size,
            "fee_limit_units": self.fee_limit_units,
            "arrival_height": self.arrival_height,
            "expires_height": self.expires_height,
            "status": self.status.as_str(),
            "reveal_hint_root": self.reveal_hint_root,
            "replay_nullifier": self.replay_nullifier,
        })
    }

    pub fn state_root(&self) -> String {
        solver_payload_root("ENCRYPTED-ORDER", &self.public_record())
    }

    pub fn validate(&self, config: &SolverConfig) -> PrivateBatchAuctionSolverResult<String> {
        ensure_non_empty("order id", &self.order_id)?;
        ensure_non_empty("batch id", &self.batch_id)?;
        ensure_non_empty("owner nullifier", &self.owner_nullifier)?;
        ensure_non_empty("encrypted payload root", &self.encrypted_payload_root)?;
        if self.input_asset_id == self.output_asset_id {
            return Err(format!("order {} swaps identical assets", self.order_id));
        }
        if self.ciphertext_bytes == 0 {
            return Err(format!("order {} ciphertext is empty", self.order_id));
        }
        if self.privacy_set_size < config.min_privacy_set_size {
            return Err(format!("order {} privacy set below floor", self.order_id));
        }
        if self.arrival_height >= self.expires_height {
            return Err(format!("order {} expiry before arrival", self.order_id));
        }
        Ok(self.state_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateAuctionBatch {
    pub batch_id: String,
    pub epoch: u64,
    pub lane: SolverLaneKind,
    pub status: BatchStatus,
    pub opened_height: u64,
    pub sealed_height: u64,
    pub settlement_deadline_height: u64,
    pub order_root: String,
    pub solver_id: String,
    pub clearing_price_root: String,
    pub notional_units: u128,
    pub expected_surplus_units: u64,
    pub lane_fee_units: u64,
    pub privacy_set_size: u64,
}

impl PrivateAuctionBatch {
    pub fn new(
        epoch: u64,
        lane: SolverLaneKind,
        opened_height: u64,
        solver_id: &str,
    ) -> PrivateBatchAuctionSolverResult<Self> {
        ensure_non_empty("solver id", solver_id)?;
        let batch_id = solver_id_from_parts(
            "BATCH",
            &[
                &epoch.to_string(),
                lane.as_str(),
                &opened_height.to_string(),
            ],
        );
        Ok(Self {
            batch_id,
            epoch,
            lane,
            status: BatchStatus::Collecting,
            opened_height,
            sealed_height: opened_height + PRIVATE_BATCH_AUCTION_SOLVER_DEFAULT_COMMIT_TTL_BLOCKS,
            settlement_deadline_height: opened_height
                + PRIVATE_BATCH_AUCTION_SOLVER_DEFAULT_SETTLEMENT_TTL_BLOCKS,
            order_root: merkle_root("PRIVATE-BATCH-AUCTION-SOLVER:EMPTY-ORDERS", &[]),
            solver_id: solver_id.to_string(),
            clearing_price_root: merkle_root("PRIVATE-BATCH-AUCTION-SOLVER:EMPTY-CLEARING", &[]),
            notional_units: 0,
            expected_surplus_units: 0,
            lane_fee_units: 0,
            privacy_set_size: PRIVATE_BATCH_AUCTION_SOLVER_DEFAULT_MIN_PRIVACY_SET_SIZE,
        })
    }

    pub fn set_height(&mut self, height: u64) {
        if height > self.settlement_deadline_height && self.status.live() {
            self.status = BatchStatus::Expired;
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "epoch": self.epoch,
            "lane": self.lane.as_str(),
            "status": self.status.as_str(),
            "opened_height": self.opened_height,
            "sealed_height": self.sealed_height,
            "settlement_deadline_height": self.settlement_deadline_height,
            "order_root": self.order_root,
            "solver_id": self.solver_id,
            "clearing_price_root": self.clearing_price_root,
            "notional_units": self.notional_units.to_string(),
            "expected_surplus_units": self.expected_surplus_units,
            "lane_fee_units": self.lane_fee_units,
            "privacy_set_size": self.privacy_set_size,
        })
    }

    pub fn state_root(&self) -> String {
        solver_payload_root("PRIVATE-AUCTION-BATCH", &self.public_record())
    }

    pub fn validate(
        &self,
        config: &SolverConfig,
        lanes: &BTreeMap<String, BatchLanePolicy>,
        solvers: &BTreeMap<String, SolverBond>,
    ) -> PrivateBatchAuctionSolverResult<String> {
        ensure_non_empty("batch id", &self.batch_id)?;
        ensure_non_empty("solver id", &self.solver_id)?;
        if self.opened_height >= self.sealed_height {
            return Err(format!("batch {} sealed before opening", self.batch_id));
        }
        if self.sealed_height > self.settlement_deadline_height {
            return Err(format!("batch {} settles before seal", self.batch_id));
        }
        if self.privacy_set_size < config.min_privacy_set_size {
            return Err(format!("batch {} privacy set below floor", self.batch_id));
        }
        if self.notional_units > config.max_batch_notional_units {
            return Err(format!("batch {} exceeds notional limit", self.batch_id));
        }
        let lane_policy = lanes
            .values()
            .find(|policy| policy.kind == self.lane && policy.enabled)
            .ok_or_else(|| format!("batch {} lane policy missing", self.batch_id))?;
        if self.notional_units > lane_policy.max_notional_units {
            return Err(format!("batch {} exceeds lane notional", self.batch_id));
        }
        let solver = solvers
            .get(&self.solver_id)
            .ok_or_else(|| format!("batch {} solver missing", self.batch_id))?;
        if !solver.can_solve_lane(self.lane) {
            return Err(format!(
                "solver {} cannot solve lane {}",
                self.solver_id,
                self.lane.as_str()
            ));
        }
        Ok(self.state_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqSolverAttestation {
    pub attestation_id: String,
    pub solver_id: String,
    pub batch_id: String,
    pub transcript_root: String,
    pub solution_root: String,
    pub quote_root: String,
    pub signature_root: String,
    pub security_bits: u16,
    pub issued_height: u64,
    pub expires_height: u64,
    pub status: PqAttestationStatus,
}

impl PqSolverAttestation {
    pub fn new(
        solver_id: &str,
        batch_id: &str,
        transcript_root: &str,
        solution_root: &str,
        quote_root: &str,
        signature_root: &str,
        height: u64,
    ) -> PrivateBatchAuctionSolverResult<Self> {
        ensure_non_empty("solver id", solver_id)?;
        ensure_non_empty("batch id", batch_id)?;
        ensure_non_empty("transcript root", transcript_root)?;
        ensure_non_empty("solution root", solution_root)?;
        ensure_non_empty("quote root", quote_root)?;
        ensure_non_empty("signature root", signature_root)?;
        let attestation_id = solver_id_from_parts(
            "PQ-ATTESTATION",
            &[solver_id, batch_id, transcript_root, solution_root],
        );
        Ok(Self {
            attestation_id,
            solver_id: solver_id.to_string(),
            batch_id: batch_id.to_string(),
            transcript_root: transcript_root.to_string(),
            solution_root: solution_root.to_string(),
            quote_root: quote_root.to_string(),
            signature_root: signature_root.to_string(),
            security_bits: PRIVATE_BATCH_AUCTION_SOLVER_DEFAULT_MIN_PQ_SECURITY_BITS,
            issued_height: height,
            expires_height: height + PRIVATE_BATCH_AUCTION_SOLVER_DEFAULT_REVEAL_TTL_BLOCKS,
            status: PqAttestationStatus::Verified,
        })
    }

    pub fn set_height(&mut self, height: u64) {
        if height > self.expires_height && self.status == PqAttestationStatus::Verified {
            self.status = PqAttestationStatus::Expired;
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "solver_id": self.solver_id,
            "batch_id": self.batch_id,
            "transcript_root": self.transcript_root,
            "solution_root": self.solution_root,
            "quote_root": self.quote_root,
            "signature_root": self.signature_root,
            "security_bits": self.security_bits,
            "issued_height": self.issued_height,
            "expires_height": self.expires_height,
            "status": self.status.as_str(),
            "scheme": PRIVATE_BATCH_AUCTION_SOLVER_PQ_ATTESTATION_SCHEME,
        })
    }

    pub fn state_root(&self) -> String {
        solver_payload_root("PQ-SOLVER-ATTESTATION", &self.public_record())
    }

    pub fn validate(&self, config: &SolverConfig) -> PrivateBatchAuctionSolverResult<String> {
        ensure_non_empty("attestation id", &self.attestation_id)?;
        ensure_non_empty("solver id", &self.solver_id)?;
        ensure_non_empty("batch id", &self.batch_id)?;
        if self.security_bits < config.min_pq_security_bits {
            return Err(format!(
                "attestation {} below PQ security floor",
                self.attestation_id
            ));
        }
        if self.issued_height >= self.expires_height {
            return Err(format!(
                "attestation {} expires before issue",
                self.attestation_id
            ));
        }
        if !self.status.valid_for_settlement() {
            return Err(format!(
                "attestation {} is not settlement-valid",
                self.attestation_id
            ));
        }
        Ok(self.state_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AntiCorrelationRiskControl {
    pub risk_id: String,
    pub lane: SolverLaneKind,
    pub base_asset_id: String,
    pub quote_asset_id: String,
    pub max_correlation_bps: u64,
    pub observed_correlation_bps: u64,
    pub exposure_units: u128,
    pub hedge_root: String,
    pub action: RiskAction,
    pub updated_height: u64,
}

impl AntiCorrelationRiskControl {
    pub fn new(
        lane: SolverLaneKind,
        base_asset_id: &str,
        quote_asset_id: &str,
        observed_correlation_bps: u64,
        exposure_units: u128,
        hedge_root: &str,
        height: u64,
    ) -> PrivateBatchAuctionSolverResult<Self> {
        ensure_non_empty("base asset id", base_asset_id)?;
        ensure_non_empty("quote asset id", quote_asset_id)?;
        ensure_non_empty("hedge root", hedge_root)?;
        ensure_bps("observed correlation bps", observed_correlation_bps)?;
        let risk_id = solver_id_from_parts("RISK", &[lane.as_str(), base_asset_id, quote_asset_id]);
        let action = if observed_correlation_bps
            > PRIVATE_BATCH_AUCTION_SOLVER_DEFAULT_MAX_CORRELATION_BPS
        {
            RiskAction::RequireHedge
        } else {
            RiskAction::Allow
        };
        Ok(Self {
            risk_id,
            lane,
            base_asset_id: base_asset_id.to_string(),
            quote_asset_id: quote_asset_id.to_string(),
            max_correlation_bps: PRIVATE_BATCH_AUCTION_SOLVER_DEFAULT_MAX_CORRELATION_BPS,
            observed_correlation_bps,
            exposure_units,
            hedge_root: hedge_root.to_string(),
            action,
            updated_height: height,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "risk_id": self.risk_id,
            "lane": self.lane.as_str(),
            "base_asset_id": self.base_asset_id,
            "quote_asset_id": self.quote_asset_id,
            "max_correlation_bps": self.max_correlation_bps,
            "observed_correlation_bps": self.observed_correlation_bps,
            "exposure_units": self.exposure_units.to_string(),
            "hedge_root": self.hedge_root,
            "action": self.action.as_str(),
            "updated_height": self.updated_height,
        })
    }

    pub fn state_root(&self) -> String {
        solver_payload_root("ANTI-CORRELATION-RISK", &self.public_record())
    }

    pub fn validate(&self, config: &SolverConfig) -> PrivateBatchAuctionSolverResult<String> {
        ensure_non_empty("risk id", &self.risk_id)?;
        ensure_bps("max correlation bps", self.max_correlation_bps)?;
        ensure_bps("observed correlation bps", self.observed_correlation_bps)?;
        if self.max_correlation_bps > config.max_correlation_bps {
            return Err(format!(
                "risk {} exceeds config correlation limit",
                self.risk_id
            ));
        }
        if self.observed_correlation_bps > self.max_correlation_bps
            && self.action == RiskAction::Allow
        {
            return Err(format!("risk {} allows over-correlated flow", self.risk_id));
        }
        Ok(self.state_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SurplusRebate {
    pub rebate_id: String,
    pub batch_id: String,
    pub order_id: String,
    pub recipient_commitment: String,
    pub surplus_units: u64,
    pub rebate_units: u64,
    pub rebate_nullifier: String,
    pub proof_root: String,
    pub posted_height: u64,
}

impl SurplusRebate {
    pub fn new(
        batch_id: &str,
        order_id: &str,
        recipient_commitment: &str,
        surplus_units: u64,
        proof_root: &str,
        height: u64,
        config: &SolverConfig,
    ) -> PrivateBatchAuctionSolverResult<Self> {
        ensure_non_empty("batch id", batch_id)?;
        ensure_non_empty("order id", order_id)?;
        ensure_non_empty("recipient commitment", recipient_commitment)?;
        ensure_non_empty("proof root", proof_root)?;
        let rebate_units = mul_bps(surplus_units, config.rebate_share_bps);
        let rebate_id = solver_id_from_parts("REBATE", &[batch_id, order_id, recipient_commitment]);
        let rebate_nullifier = solver_id_from_parts("REBATE-NULLIFIER", &[&rebate_id, proof_root]);
        Ok(Self {
            rebate_id,
            batch_id: batch_id.to_string(),
            order_id: order_id.to_string(),
            recipient_commitment: recipient_commitment.to_string(),
            surplus_units,
            rebate_units,
            rebate_nullifier,
            proof_root: proof_root.to_string(),
            posted_height: height,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "rebate_id": self.rebate_id,
            "batch_id": self.batch_id,
            "order_id": self.order_id,
            "recipient_commitment": self.recipient_commitment,
            "surplus_units": self.surplus_units,
            "rebate_units": self.rebate_units,
            "rebate_nullifier": self.rebate_nullifier,
            "proof_root": self.proof_root,
            "posted_height": self.posted_height,
            "scheme": PRIVATE_BATCH_AUCTION_SOLVER_REBATE_SCHEME,
        })
    }

    pub fn state_root(&self) -> String {
        solver_payload_root("SURPLUS-REBATE", &self.public_record())
    }

    pub fn validate(&self) -> PrivateBatchAuctionSolverResult<String> {
        ensure_non_empty("rebate id", &self.rebate_id)?;
        ensure_non_empty("batch id", &self.batch_id)?;
        ensure_non_empty("order id", &self.order_id)?;
        if self.rebate_units > self.surplus_units {
            return Err(format!("rebate {} exceeds surplus", self.rebate_id));
        }
        Ok(self.state_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementReceipt {
    pub receipt_id: String,
    pub batch_id: String,
    pub solver_id: String,
    pub attestation_id: String,
    pub order_root: String,
    pub fill_root: String,
    pub rebate_root: String,
    pub fee_root: String,
    pub monero_exit_root: String,
    pub lending_liquidation_root: String,
    pub perps_hedge_root: String,
    pub state_transition_root: String,
    pub receipt_proof_root: String,
    pub settled_height: u64,
    pub status: ReceiptStatus,
}

impl SettlementReceipt {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        batch_id: &str,
        solver_id: &str,
        attestation_id: &str,
        order_root: &str,
        fill_root: &str,
        rebate_root: &str,
        state_transition_root: &str,
        height: u64,
    ) -> PrivateBatchAuctionSolverResult<Self> {
        ensure_non_empty("batch id", batch_id)?;
        ensure_non_empty("solver id", solver_id)?;
        ensure_non_empty("attestation id", attestation_id)?;
        ensure_non_empty("order root", order_root)?;
        ensure_non_empty("fill root", fill_root)?;
        ensure_non_empty("rebate root", rebate_root)?;
        ensure_non_empty("state transition root", state_transition_root)?;
        let receipt_id = solver_id_from_parts(
            "RECEIPT",
            &[batch_id, solver_id, attestation_id, state_transition_root],
        );
        let fee_root = solver_id_from_parts("FEE-ROOT", &[batch_id, solver_id]);
        let monero_exit_root = solver_id_from_parts("MONERO-EXIT-ROOT", &[batch_id, solver_id]);
        let lending_liquidation_root =
            solver_id_from_parts("LENDING-LIQUIDATION-ROOT", &[batch_id, solver_id]);
        let perps_hedge_root = solver_id_from_parts("PERPS-HEDGE-ROOT", &[batch_id, solver_id]);
        let receipt_proof_root = solver_id_from_parts("RECEIPT-PROOF", &[&receipt_id, fill_root]);
        Ok(Self {
            receipt_id,
            batch_id: batch_id.to_string(),
            solver_id: solver_id.to_string(),
            attestation_id: attestation_id.to_string(),
            order_root: order_root.to_string(),
            fill_root: fill_root.to_string(),
            rebate_root: rebate_root.to_string(),
            fee_root,
            monero_exit_root,
            lending_liquidation_root,
            perps_hedge_root,
            state_transition_root: state_transition_root.to_string(),
            receipt_proof_root,
            settled_height: height,
            status: ReceiptStatus::Published,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "batch_id": self.batch_id,
            "solver_id": self.solver_id,
            "attestation_id": self.attestation_id,
            "order_root": self.order_root,
            "fill_root": self.fill_root,
            "rebate_root": self.rebate_root,
            "fee_root": self.fee_root,
            "monero_exit_root": self.monero_exit_root,
            "lending_liquidation_root": self.lending_liquidation_root,
            "perps_hedge_root": self.perps_hedge_root,
            "state_transition_root": self.state_transition_root,
            "receipt_proof_root": self.receipt_proof_root,
            "settled_height": self.settled_height,
            "status": self.status.as_str(),
            "scheme": PRIVATE_BATCH_AUCTION_SOLVER_RECEIPT_SCHEME,
        })
    }

    pub fn state_root(&self) -> String {
        solver_payload_root("SETTLEMENT-RECEIPT", &self.public_record())
    }

    pub fn validate(&self) -> PrivateBatchAuctionSolverResult<String> {
        ensure_non_empty("receipt id", &self.receipt_id)?;
        ensure_non_empty("batch id", &self.batch_id)?;
        ensure_non_empty("solver id", &self.solver_id)?;
        ensure_non_empty("attestation id", &self.attestation_id)?;
        Ok(self.state_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SolverEvent {
    pub event_id: String,
    pub kind: String,
    pub subject_id: String,
    pub height: u64,
    pub payload_root: String,
}

impl SolverEvent {
    pub fn new(kind: &str, subject_id: &str, height: u64, payload_root: &str) -> Self {
        let event_id = solver_id_from_parts("EVENT", &[kind, subject_id, &height.to_string()]);
        Self {
            event_id,
            kind: kind.to_string(),
            subject_id: subject_id.to_string(),
            height,
            payload_root: payload_root.to_string(),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "event_id": self.event_id,
            "kind": self.kind,
            "subject_id": self.subject_id,
            "height": self.height,
            "payload_root": self.payload_root,
        })
    }

    pub fn state_root(&self) -> String {
        solver_payload_root("SOLVER-EVENT", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateBatchAuctionSolverRoots {
    pub config_root: String,
    pub lane_root: String,
    pub solver_bond_root: String,
    pub batch_root: String,
    pub order_root: String,
    pub attestation_root: String,
    pub risk_root: String,
    pub rebate_root: String,
    pub receipt_root: String,
    pub event_root: String,
    pub public_record_root: String,
    pub state_root: String,
}

impl PrivateBatchAuctionSolverRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "lane_root": self.lane_root,
            "solver_bond_root": self.solver_bond_root,
            "batch_root": self.batch_root,
            "order_root": self.order_root,
            "attestation_root": self.attestation_root,
            "risk_root": self.risk_root,
            "rebate_root": self.rebate_root,
            "receipt_root": self.receipt_root,
            "event_root": self.event_root,
            "public_record_root": self.public_record_root,
            "state_root": self.state_root,
        })
    }

    pub fn roots_root(&self) -> String {
        solver_payload_root("ROOTS", &self.public_record())
    }

    pub fn validate(&self) -> PrivateBatchAuctionSolverResult<String> {
        for (name, root) in [
            ("config root", &self.config_root),
            ("lane root", &self.lane_root),
            ("solver bond root", &self.solver_bond_root),
            ("batch root", &self.batch_root),
            ("order root", &self.order_root),
            ("attestation root", &self.attestation_root),
            ("risk root", &self.risk_root),
            ("rebate root", &self.rebate_root),
            ("receipt root", &self.receipt_root),
            ("event root", &self.event_root),
            ("public record root", &self.public_record_root),
            ("state root", &self.state_root),
        ] {
            ensure_non_empty(name, root)?;
        }
        Ok(self.roots_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateBatchAuctionSolverCounters {
    pub lane_count: usize,
    pub solver_count: usize,
    pub batch_count: usize,
    pub order_count: usize,
    pub live_batch_count: usize,
    pub active_order_count: usize,
    pub attestation_count: usize,
    pub risk_control_count: usize,
    pub rebate_count: usize,
    pub receipt_count: usize,
    pub event_count: usize,
    pub public_record_count: usize,
    pub total_bonded_units: u64,
    pub total_locked_units: u64,
    pub total_slashed_units: u64,
    pub total_surplus_units: u64,
    pub total_rebate_units: u64,
}

impl PrivateBatchAuctionSolverCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "lane_count": self.lane_count,
            "solver_count": self.solver_count,
            "batch_count": self.batch_count,
            "order_count": self.order_count,
            "live_batch_count": self.live_batch_count,
            "active_order_count": self.active_order_count,
            "attestation_count": self.attestation_count,
            "risk_control_count": self.risk_control_count,
            "rebate_count": self.rebate_count,
            "receipt_count": self.receipt_count,
            "event_count": self.event_count,
            "public_record_count": self.public_record_count,
            "total_bonded_units": self.total_bonded_units,
            "total_locked_units": self.total_locked_units,
            "total_slashed_units": self.total_slashed_units,
            "total_surplus_units": self.total_surplus_units,
            "total_rebate_units": self.total_rebate_units,
        })
    }

    pub fn counters_root(&self) -> String {
        solver_payload_root("COUNTERS", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateBatchAuctionSolverState {
    pub height: u64,
    pub status: String,
    pub config: SolverConfig,
    pub lanes: BTreeMap<String, BatchLanePolicy>,
    pub solvers: BTreeMap<String, SolverBond>,
    pub batches: BTreeMap<String, PrivateAuctionBatch>,
    pub orders: BTreeMap<String, EncryptedOrderCommitment>,
    pub attestations: BTreeMap<String, PqSolverAttestation>,
    pub risk_controls: BTreeMap<String, AntiCorrelationRiskControl>,
    pub rebates: BTreeMap<String, SurplusRebate>,
    pub receipts: BTreeMap<String, SettlementReceipt>,
    pub events: BTreeMap<String, SolverEvent>,
    pub public_records: BTreeMap<String, Value>,
}

impl PrivateBatchAuctionSolverState {
    pub fn devnet() -> PrivateBatchAuctionSolverResult<Self> {
        let config = SolverConfig::devnet();
        let mut lanes = BTreeMap::new();
        for lane in [
            (
                SolverLaneKind::LowFee,
                "lane:low-fee",
                config.low_fee_lane_bps,
            ),
            (SolverLaneKind::PrivateAmm, "lane:private-amm", 18),
            (SolverLaneKind::MoneroExit, "lane:monero-exit", 24),
            (SolverLaneKind::Liquidation, "lane:liquidation", 20),
            (SolverLaneKind::PerpsRisk, "lane:perps-risk", 16),
            (SolverLaneKind::PrivateContract, "lane:private-contract", 22),
            (SolverLaneKind::EmergencyUnwind, "lane:emergency-unwind", 35),
        ] {
            let policy = BatchLanePolicy::new(
                lane.1,
                lane.0,
                lane.2,
                config.max_batch_orders,
                config.max_batch_notional_units / 2,
            )?;
            lanes.insert(policy.lane_id.clone(), policy);
        }

        let mut allowed_lanes = BTreeSet::new();
        allowed_lanes.insert(SolverLaneKind::LowFee);
        allowed_lanes.insert(SolverLaneKind::PrivateAmm);
        allowed_lanes.insert(SolverLaneKind::MoneroExit);
        allowed_lanes.insert(SolverLaneKind::Liquidation);
        allowed_lanes.insert(SolverLaneKind::PerpsRisk);
        let solver = SolverBond::new(
            "solver:devnet:001",
            "owner_commitment:devnet_solver_001",
            &config.collateral_asset_id,
            config.min_solver_bond_units * 4,
            PRIVATE_BATCH_AUCTION_SOLVER_DEVNET_HEIGHT,
            allowed_lanes,
        )?;

        let mut solvers = BTreeMap::new();
        solvers.insert(solver.solver_id.clone(), solver);

        let mut batch = PrivateAuctionBatch::new(
            1,
            SolverLaneKind::PrivateAmm,
            PRIVATE_BATCH_AUCTION_SOLVER_DEVNET_HEIGHT,
            "solver:devnet:001",
        )?;
        batch.status = BatchStatus::Attested;
        batch.notional_units = 1_250_000_000;
        batch.expected_surplus_units = 42_000;
        batch.lane_fee_units = 2_250;

        let order = EncryptedOrderCommitment::new(
            &batch.batch_id,
            "owner_nullifier:amm:001",
            AuctionFlowKind::AmmSwap,
            "dxmr",
            "dusd",
            "notional_commitment:amm:001",
            "min_output_commitment:amm:001",
            "encrypted_payload_root:amm:001",
            5_000,
            PRIVATE_BATCH_AUCTION_SOLVER_DEVNET_HEIGHT,
        )?;
        batch.order_root = merkle_root(
            "PRIVATE-BATCH-AUCTION-SOLVER:DEVNET-ORDER-ROOT",
            &[order.public_record()],
        );

        let attestation = PqSolverAttestation::new(
            "solver:devnet:001",
            &batch.batch_id,
            "transcript_root:devnet:001",
            "solution_root:devnet:001",
            "quote_root:devnet:001",
            "signature_root:devnet:001",
            PRIVATE_BATCH_AUCTION_SOLVER_DEVNET_HEIGHT,
        )?;

        let risk = AntiCorrelationRiskControl::new(
            SolverLaneKind::PrivateAmm,
            "dxmr",
            "dusd",
            3_200,
            batch.notional_units,
            "hedge_root:devnet:amm:001",
            PRIVATE_BATCH_AUCTION_SOLVER_DEVNET_HEIGHT,
        )?;

        let rebate = SurplusRebate::new(
            &batch.batch_id,
            &order.order_id,
            "recipient_commitment:rebate:001",
            batch.expected_surplus_units,
            "rebate_proof_root:devnet:001",
            PRIVATE_BATCH_AUCTION_SOLVER_DEVNET_HEIGHT,
            &config,
        )?;

        let receipt = SettlementReceipt::new(
            &batch.batch_id,
            "solver:devnet:001",
            &attestation.attestation_id,
            &batch.order_root,
            "fill_root:devnet:001",
            &rebate.state_root(),
            "state_transition_root:devnet:001",
            PRIVATE_BATCH_AUCTION_SOLVER_DEVNET_HEIGHT + 1,
        )?;

        let mut batches = BTreeMap::new();
        batches.insert(batch.batch_id.clone(), batch);
        let mut orders = BTreeMap::new();
        orders.insert(order.order_id.clone(), order);
        let mut attestations = BTreeMap::new();
        attestations.insert(attestation.attestation_id.clone(), attestation);
        let mut risk_controls = BTreeMap::new();
        risk_controls.insert(risk.risk_id.clone(), risk);
        let mut rebates = BTreeMap::new();
        rebates.insert(rebate.rebate_id.clone(), rebate);
        let mut receipts = BTreeMap::new();
        receipts.insert(receipt.receipt_id.clone(), receipt);

        let mut state = Self {
            height: PRIVATE_BATCH_AUCTION_SOLVER_DEVNET_HEIGHT,
            status: PRIVATE_BATCH_AUCTION_SOLVER_STATE_ACTIVE.to_string(),
            config,
            lanes,
            solvers,
            batches,
            orders,
            attestations,
            risk_controls,
            rebates,
            receipts,
            events: BTreeMap::new(),
            public_records: BTreeMap::new(),
        };
        state.refresh_public_records();
        state.add_event("devnet_initialized", "private_batch_auction_solver")?;
        state.validate()?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) -> PrivateBatchAuctionSolverResult<String> {
        if height < self.height {
            return Err("height cannot move backwards".to_string());
        }
        self.height = height;
        for solver in self.solvers.values_mut() {
            solver.set_height(height);
        }
        for batch in self.batches.values_mut() {
            batch.set_height(height);
        }
        for order in self.orders.values_mut() {
            order.set_height(height);
        }
        for attestation in self.attestations.values_mut() {
            attestation.set_height(height);
        }
        self.refresh_public_records();
        Ok(self.state_root())
    }

    pub fn submit_order(
        &mut self,
        order: EncryptedOrderCommitment,
    ) -> PrivateBatchAuctionSolverResult<String> {
        order.validate(&self.config)?;
        let batch = self.batches.get(&order.batch_id).ok_or_else(|| {
            format!(
                "batch {} missing for order {}",
                order.batch_id, order.order_id
            )
        })?;
        if !batch.status.accepts_orders() {
            return Err(format!("batch {} does not accept orders", batch.batch_id));
        }
        let lane = self
            .lanes
            .values()
            .find(|policy| policy.kind == order.lane && policy.enabled)
            .ok_or_else(|| {
                format!(
                    "lane {} missing for order {}",
                    order.lane.as_str(),
                    order.order_id
                )
            })?;
        if order.privacy_set_size < lane.min_privacy_set_size {
            return Err(format!(
                "order {} lane privacy set below floor",
                order.order_id
            ));
        }
        let id = order.order_id.clone();
        let root = order.state_root();
        self.orders.insert(id.clone(), order);
        self.add_event("order_committed", &id)?;
        self.refresh_public_records();
        Ok(root)
    }

    pub fn publish_attestation(
        &mut self,
        attestation: PqSolverAttestation,
    ) -> PrivateBatchAuctionSolverResult<String> {
        attestation.validate(&self.config)?;
        if !self.solvers.contains_key(&attestation.solver_id) {
            return Err(format!(
                "solver {} missing for attestation",
                attestation.solver_id
            ));
        }
        if !self.batches.contains_key(&attestation.batch_id) {
            return Err(format!(
                "batch {} missing for attestation",
                attestation.batch_id
            ));
        }
        let id = attestation.attestation_id.clone();
        let root = attestation.state_root();
        self.attestations.insert(id.clone(), attestation);
        self.add_event("pq_attestation_published", &id)?;
        self.refresh_public_records();
        Ok(root)
    }

    pub fn post_receipt(
        &mut self,
        receipt: SettlementReceipt,
    ) -> PrivateBatchAuctionSolverResult<String> {
        receipt.validate()?;
        if !self.batches.contains_key(&receipt.batch_id) {
            return Err(format!("batch {} missing for receipt", receipt.batch_id));
        }
        if !self.attestations.contains_key(&receipt.attestation_id) {
            return Err(format!(
                "attestation {} missing for receipt",
                receipt.attestation_id
            ));
        }
        if let Some(batch) = self.batches.get_mut(&receipt.batch_id) {
            batch.status = BatchStatus::Settled;
        }
        let id = receipt.receipt_id.clone();
        let root = receipt.state_root();
        self.receipts.insert(id.clone(), receipt);
        self.add_event("settlement_receipt_published", &id)?;
        self.refresh_public_records();
        Ok(root)
    }

    pub fn roots(&self) -> PrivateBatchAuctionSolverRoots {
        let config_root = self.config.state_root();
        let lane_root = merkle_public_records(
            "PRIVATE-BATCH-AUCTION-SOLVER:LANES",
            self.lanes
                .values()
                .map(BatchLanePolicy::public_record)
                .collect(),
        );
        let solver_bond_root = merkle_public_records(
            "PRIVATE-BATCH-AUCTION-SOLVER:SOLVER-BONDS",
            self.solvers
                .values()
                .map(SolverBond::public_record)
                .collect(),
        );
        let batch_root = merkle_public_records(
            "PRIVATE-BATCH-AUCTION-SOLVER:BATCHES",
            self.batches
                .values()
                .map(PrivateAuctionBatch::public_record)
                .collect(),
        );
        let order_root = merkle_public_records(
            "PRIVATE-BATCH-AUCTION-SOLVER:ORDERS",
            self.orders
                .values()
                .map(EncryptedOrderCommitment::public_record)
                .collect(),
        );
        let attestation_root = merkle_public_records(
            "PRIVATE-BATCH-AUCTION-SOLVER:ATTESTATIONS",
            self.attestations
                .values()
                .map(PqSolverAttestation::public_record)
                .collect(),
        );
        let risk_root = merkle_public_records(
            "PRIVATE-BATCH-AUCTION-SOLVER:RISK",
            self.risk_controls
                .values()
                .map(AntiCorrelationRiskControl::public_record)
                .collect(),
        );
        let rebate_root = merkle_public_records(
            "PRIVATE-BATCH-AUCTION-SOLVER:REBATES",
            self.rebates
                .values()
                .map(SurplusRebate::public_record)
                .collect(),
        );
        let receipt_root = merkle_public_records(
            "PRIVATE-BATCH-AUCTION-SOLVER:RECEIPTS",
            self.receipts
                .values()
                .map(SettlementReceipt::public_record)
                .collect(),
        );
        let event_root = merkle_public_records(
            "PRIVATE-BATCH-AUCTION-SOLVER:EVENTS",
            self.events
                .values()
                .map(SolverEvent::public_record)
                .collect(),
        );
        let public_record_root = merkle_public_records(
            "PRIVATE-BATCH-AUCTION-SOLVER:PUBLIC-RECORDS",
            self.public_records
                .iter()
                .map(|(key, value)| json!({"key": key, "value": value}))
                .collect(),
        );
        let state_record = json!({
            "height": self.height,
            "status": self.status,
            "config_root": config_root,
            "lane_root": lane_root,
            "solver_bond_root": solver_bond_root,
            "batch_root": batch_root,
            "order_root": order_root,
            "attestation_root": attestation_root,
            "risk_root": risk_root,
            "rebate_root": rebate_root,
            "receipt_root": receipt_root,
            "event_root": event_root,
            "public_record_root": public_record_root,
        });
        let state_root = private_batch_auction_solver_state_root_from_record(&state_record);
        PrivateBatchAuctionSolverRoots {
            config_root,
            lane_root,
            solver_bond_root,
            batch_root,
            order_root,
            attestation_root,
            risk_root,
            rebate_root,
            receipt_root,
            event_root,
            public_record_root,
            state_root,
        }
    }

    pub fn counters(&self) -> PrivateBatchAuctionSolverCounters {
        PrivateBatchAuctionSolverCounters {
            lane_count: self.lanes.len(),
            solver_count: self.solvers.len(),
            batch_count: self.batches.len(),
            order_count: self.orders.len(),
            live_batch_count: self
                .batches
                .values()
                .filter(|batch| batch.status.live())
                .count(),
            active_order_count: self
                .orders
                .values()
                .filter(|order| order.status.active())
                .count(),
            attestation_count: self.attestations.len(),
            risk_control_count: self.risk_controls.len(),
            rebate_count: self.rebates.len(),
            receipt_count: self.receipts.len(),
            event_count: self.events.len(),
            public_record_count: self.public_records.len(),
            total_bonded_units: self
                .solvers
                .values()
                .map(|solver| solver.bonded_units)
                .sum(),
            total_locked_units: self
                .solvers
                .values()
                .map(|solver| solver.locked_units)
                .sum(),
            total_slashed_units: self
                .solvers
                .values()
                .map(|solver| solver.slashed_units)
                .sum(),
            total_surplus_units: self
                .rebates
                .values()
                .map(|rebate| rebate.surplus_units)
                .sum(),
            total_rebate_units: self
                .rebates
                .values()
                .map(|rebate| rebate.rebate_units)
                .sum(),
        }
    }

    pub fn public_record_without_state_root(&self) -> Value {
        let roots = self.roots();
        let counters = self.counters();
        json!({
            "height": self.height,
            "status": self.status,
            "config": self.config.public_record(),
            "roots": roots.public_record(),
            "roots_root": roots.roots_root(),
            "counters": counters.public_record(),
            "counters_root": counters.counters_root(),
            "lanes": map_records(&self.lanes),
            "solvers": map_records(&self.solvers),
            "batches": map_records(&self.batches),
            "orders": map_records(&self.orders),
            "attestations": map_records(&self.attestations),
            "risk_controls": map_records(&self.risk_controls),
            "rebates": map_records(&self.rebates),
            "receipts": map_records(&self.receipts),
            "events": map_records(&self.events),
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        if let Some(object) = record.as_object_mut() {
            object.insert(
                "private_batch_auction_solver_state_root".to_string(),
                Value::String(self.state_root()),
            );
        }
        record
    }

    pub fn state_root(&self) -> String {
        private_batch_auction_solver_state_root_from_record(
            &self.public_record_without_state_root(),
        )
    }

    pub fn validate(&self) -> PrivateBatchAuctionSolverResult<String> {
        ensure_non_empty("state status", &self.status)?;
        if !matches!(
            self.status.as_str(),
            PRIVATE_BATCH_AUCTION_SOLVER_STATE_ACTIVE
                | PRIVATE_BATCH_AUCTION_SOLVER_STATE_CHALLENGED
                | PRIVATE_BATCH_AUCTION_SOLVER_STATE_HALTED
        ) {
            return Err(format!("unknown solver state status {}", self.status));
        }
        self.config.validate()?;
        ensure_len(
            "lanes",
            self.lanes.len(),
            PRIVATE_BATCH_AUCTION_SOLVER_MAX_LANES,
        )?;
        ensure_len(
            "solvers",
            self.solvers.len(),
            PRIVATE_BATCH_AUCTION_SOLVER_MAX_SOLVERS,
        )?;
        ensure_len(
            "batches",
            self.batches.len(),
            PRIVATE_BATCH_AUCTION_SOLVER_MAX_BATCHES,
        )?;
        ensure_len(
            "orders",
            self.orders.len(),
            PRIVATE_BATCH_AUCTION_SOLVER_MAX_ORDERS,
        )?;
        ensure_len(
            "attestations",
            self.attestations.len(),
            PRIVATE_BATCH_AUCTION_SOLVER_MAX_ATTESTATIONS,
        )?;
        ensure_len(
            "risk controls",
            self.risk_controls.len(),
            PRIVATE_BATCH_AUCTION_SOLVER_MAX_RISK_LIMITS,
        )?;
        ensure_len(
            "rebates",
            self.rebates.len(),
            PRIVATE_BATCH_AUCTION_SOLVER_MAX_REBATES,
        )?;
        ensure_len(
            "receipts",
            self.receipts.len(),
            PRIVATE_BATCH_AUCTION_SOLVER_MAX_RECEIPTS,
        )?;
        ensure_len(
            "events",
            self.events.len(),
            PRIVATE_BATCH_AUCTION_SOLVER_MAX_EVENTS,
        )?;

        for lane in self.lanes.values() {
            lane.validate(&self.config)?;
        }
        for solver in self.solvers.values() {
            solver.validate(&self.config)?;
        }
        for batch in self.batches.values() {
            batch.validate(&self.config, &self.lanes, &self.solvers)?;
        }
        let mut replay_nullifiers = BTreeSet::new();
        let mut batch_order_counts: BTreeMap<String, usize> = BTreeMap::new();
        for order in self.orders.values() {
            order.validate(&self.config)?;
            if !self.batches.contains_key(&order.batch_id) {
                return Err(format!("order {} references missing batch", order.order_id));
            }
            if !replay_nullifiers.insert(order.replay_nullifier.clone()) {
                return Err(format!(
                    "duplicate order replay nullifier {}",
                    order.replay_nullifier
                ));
            }
            *batch_order_counts
                .entry(order.batch_id.clone())
                .or_default() += 1;
        }
        for (batch_id, count) in batch_order_counts {
            if count > self.config.max_batch_orders {
                return Err(format!("batch {batch_id} exceeds max order count"));
            }
        }
        for attestation in self.attestations.values() {
            attestation.validate(&self.config)?;
            if !self.solvers.contains_key(&attestation.solver_id) {
                return Err(format!(
                    "attestation {} references missing solver",
                    attestation.attestation_id
                ));
            }
            if !self.batches.contains_key(&attestation.batch_id) {
                return Err(format!(
                    "attestation {} references missing batch",
                    attestation.attestation_id
                ));
            }
        }
        for risk in self.risk_controls.values() {
            risk.validate(&self.config)?;
        }
        let mut rebate_nullifiers = BTreeSet::new();
        for rebate in self.rebates.values() {
            rebate.validate()?;
            if !self.orders.contains_key(&rebate.order_id) {
                return Err(format!(
                    "rebate {} references missing order",
                    rebate.rebate_id
                ));
            }
            if !rebate_nullifiers.insert(rebate.rebate_nullifier.clone()) {
                return Err(format!(
                    "duplicate rebate nullifier {}",
                    rebate.rebate_nullifier
                ));
            }
        }
        for receipt in self.receipts.values() {
            receipt.validate()?;
            if !self.batches.contains_key(&receipt.batch_id) {
                return Err(format!(
                    "receipt {} references missing batch",
                    receipt.receipt_id
                ));
            }
            if !self.attestations.contains_key(&receipt.attestation_id) {
                return Err(format!(
                    "receipt {} references missing attestation",
                    receipt.receipt_id
                ));
            }
        }
        self.roots().validate()?;
        Ok(self.state_root())
    }

    fn add_event(&mut self, kind: &str, subject_id: &str) -> PrivateBatchAuctionSolverResult<()> {
        ensure_non_empty("event kind", kind)?;
        ensure_non_empty("event subject id", subject_id)?;
        let payload_root = solver_id_from_parts("EVENT-PAYLOAD", &[kind, subject_id]);
        let event = SolverEvent::new(kind, subject_id, self.height, &payload_root);
        self.events.insert(event.event_id.clone(), event);
        Ok(())
    }

    fn refresh_public_records(&mut self) {
        let mut records = BTreeMap::new();
        records.insert("config".to_string(), self.config.public_record());
        for (id, lane) in &self.lanes {
            records.insert(format!("lane:{id}"), lane.public_record());
        }
        for (id, solver) in &self.solvers {
            records.insert(format!("solver:{id}"), solver.public_record());
        }
        for (id, batch) in &self.batches {
            records.insert(format!("batch:{id}"), batch.public_record());
        }
        for (id, order) in &self.orders {
            records.insert(format!("order:{id}"), order.public_record());
        }
        for (id, attestation) in &self.attestations {
            records.insert(format!("attestation:{id}"), attestation.public_record());
        }
        for (id, risk) in &self.risk_controls {
            records.insert(format!("risk:{id}"), risk.public_record());
        }
        for (id, rebate) in &self.rebates {
            records.insert(format!("rebate:{id}"), rebate.public_record());
        }
        for (id, receipt) in &self.receipts {
            records.insert(format!("receipt:{id}"), receipt.public_record());
        }
        for (id, event) in &self.events {
            records.insert(format!("event:{id}"), event.public_record());
        }
        self.public_records = records;
    }
}

pub fn private_batch_auction_solver_state_root_from_record(record: &Value) -> String {
    solver_payload_root("STATE", record)
}

pub trait SolverPublicRecord {
    fn public_record(&self) -> Value;
}

impl SolverPublicRecord for BatchLanePolicy {
    fn public_record(&self) -> Value {
        BatchLanePolicy::public_record(self)
    }
}

impl SolverPublicRecord for SolverBond {
    fn public_record(&self) -> Value {
        SolverBond::public_record(self)
    }
}

impl SolverPublicRecord for PrivateAuctionBatch {
    fn public_record(&self) -> Value {
        PrivateAuctionBatch::public_record(self)
    }
}

impl SolverPublicRecord for EncryptedOrderCommitment {
    fn public_record(&self) -> Value {
        EncryptedOrderCommitment::public_record(self)
    }
}

impl SolverPublicRecord for PqSolverAttestation {
    fn public_record(&self) -> Value {
        PqSolverAttestation::public_record(self)
    }
}

impl SolverPublicRecord for AntiCorrelationRiskControl {
    fn public_record(&self) -> Value {
        AntiCorrelationRiskControl::public_record(self)
    }
}

impl SolverPublicRecord for SurplusRebate {
    fn public_record(&self) -> Value {
        SurplusRebate::public_record(self)
    }
}

impl SolverPublicRecord for SettlementReceipt {
    fn public_record(&self) -> Value {
        SettlementReceipt::public_record(self)
    }
}

impl SolverPublicRecord for SolverEvent {
    fn public_record(&self) -> Value {
        SolverEvent::public_record(self)
    }
}

fn map_records<T: SolverPublicRecord>(records: &BTreeMap<String, T>) -> Vec<Value> {
    records
        .iter()
        .map(|(key, value)| json!({"key": key, "value": value.public_record()}))
        .collect()
}

fn merkle_public_records(domain: &str, leaves: Vec<Value>) -> String {
    merkle_root(domain, &leaves)
}

fn solver_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        &format!("PRIVATE-BATCH-AUCTION-SOLVER:{domain}"),
        &[
            HashPart::Str(PRIVATE_BATCH_AUCTION_SOLVER_PROTOCOL_VERSION),
            HashPart::Json(payload),
        ],
        32,
    )
}

fn solver_id_from_parts(domain: &str, parts: &[&str]) -> String {
    let hash_parts = parts
        .iter()
        .map(|part| HashPart::Str(part))
        .collect::<Vec<_>>();
    domain_hash(
        &format!("PRIVATE-BATCH-AUCTION-SOLVER-ID:{domain}"),
        &hash_parts,
        20,
    )
}

fn mul_bps(amount: u64, bps: u64) -> u64 {
    ((amount as u128 * bps as u128) / PRIVATE_BATCH_AUCTION_SOLVER_MAX_BPS as u128) as u64
}

fn ensure_non_empty(name: &str, value: &str) -> PrivateBatchAuctionSolverResult<()> {
    if value.trim().is_empty() {
        Err(format!("{name} must not be empty"))
    } else {
        Ok(())
    }
}

fn ensure_bps(name: &str, value: u64) -> PrivateBatchAuctionSolverResult<()> {
    if value > PRIVATE_BATCH_AUCTION_SOLVER_MAX_BPS {
        Err(format!("{name} exceeds bps denominator"))
    } else {
        Ok(())
    }
}

fn ensure_len(name: &str, value: usize, max: usize) -> PrivateBatchAuctionSolverResult<()> {
    if value > max {
        Err(format!("{name} exceeds max {max}"))
    } else {
        Ok(())
    }
}
