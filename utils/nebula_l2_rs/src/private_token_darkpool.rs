use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateTokenDarkpoolResult<T> = Result<T, String>;

pub const PRIVATE_TOKEN_DARKPOOL_PROTOCOL_VERSION: &str = "nebula-private-token-darkpool-v1";
pub const PRIVATE_TOKEN_DARKPOOL_SCHEMA_VERSION: u64 = 1;
pub const PRIVATE_TOKEN_DARKPOOL_HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PRIVATE_TOKEN_DARKPOOL_COMMITMENT_SCHEME: &str = "confidential-token-pair-commitment-v1";
pub const PRIVATE_TOKEN_DARKPOOL_ORDER_ENCRYPTION_SCHEME: &str =
    "ml-kem-1024+threshold-sealed-order+viewkey-audit-v1";
pub const PRIVATE_TOKEN_DARKPOOL_SETTLEMENT_ATTESTATION_SCHEME: &str =
    "ml-dsa-87+slh-dsa-shake-128f-pq-settlement-attestation-v1";
pub const PRIVATE_TOKEN_DARKPOOL_NULLIFIER_SCHEME: &str = "one-shot-fill-nullifier-set-v1";
pub const PRIVATE_TOKEN_DARKPOOL_REBATE_SCHEME: &str = "low-fee-surplus-rebate-commitment-v1";
pub const PRIVATE_TOKEN_DARKPOOL_BATCH_PROOF_SYSTEM: &str =
    "zk-confidential-batch-auction-clearing-devnet-v1";
pub const PRIVATE_TOKEN_DARKPOOL_DEVNET_HEIGHT: u64 = 2_400;
pub const PRIVATE_TOKEN_DARKPOOL_DEFAULT_EPOCH_BLOCKS: u64 = 12;
pub const PRIVATE_TOKEN_DARKPOOL_DEFAULT_ORDER_TTL_BLOCKS: u64 = 36;
pub const PRIVATE_TOKEN_DARKPOOL_DEFAULT_CLEARING_WINDOW_BLOCKS: u64 = 4;
pub const PRIVATE_TOKEN_DARKPOOL_DEFAULT_SETTLEMENT_WINDOW_BLOCKS: u64 = 24;
pub const PRIVATE_TOKEN_DARKPOOL_DEFAULT_BOND_TTL_BLOCKS: u64 = 7_200;
pub const PRIVATE_TOKEN_DARKPOOL_DEFAULT_MIN_SOLVER_BOND_UNITS: u64 = 50_000_000;
pub const PRIVATE_TOKEN_DARKPOOL_DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 128;
pub const PRIVATE_TOKEN_DARKPOOL_DEFAULT_MAX_BATCH_ORDERS: usize = 1_024;
pub const PRIVATE_TOKEN_DARKPOOL_DEFAULT_MAX_PAIR_NOTIONAL_UNITS: u128 = 25_000_000_000_000;
pub const PRIVATE_TOKEN_DARKPOOL_DEFAULT_MAX_SLIPPAGE_BPS: u64 = 250;
pub const PRIVATE_TOKEN_DARKPOOL_DEFAULT_LOW_FEE_BPS: u64 = 6;
pub const PRIVATE_TOKEN_DARKPOOL_DEFAULT_REBATE_SHARE_BPS: u64 = 8_000;
pub const PRIVATE_TOKEN_DARKPOOL_DEFAULT_SOLVER_FEE_SHARE_BPS: u64 = 1_500;
pub const PRIVATE_TOKEN_DARKPOOL_DEFAULT_PROTOCOL_FEE_SHARE_BPS: u64 = 500;
pub const PRIVATE_TOKEN_DARKPOOL_DEFAULT_SLASH_BPS: u64 = 2_500;
pub const PRIVATE_TOKEN_DARKPOOL_DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const PRIVATE_TOKEN_DARKPOOL_MAX_BPS: u64 = 10_000;
pub const PRIVATE_TOKEN_DARKPOOL_MAX_PAIRS: usize = 8_192;
pub const PRIVATE_TOKEN_DARKPOOL_MAX_SOLVERS: usize = 4_096;
pub const PRIVATE_TOKEN_DARKPOOL_MAX_BATCHES: usize = 65_536;
pub const PRIVATE_TOKEN_DARKPOOL_MAX_ORDERS: usize = 1_048_576;
pub const PRIVATE_TOKEN_DARKPOOL_MAX_FILLS: usize = 1_048_576;
pub const PRIVATE_TOKEN_DARKPOOL_MAX_ATTESTATIONS: usize = 1_048_576;
pub const PRIVATE_TOKEN_DARKPOOL_MAX_REBATES: usize = 1_048_576;
pub const PRIVATE_TOKEN_DARKPOOL_MAX_EVENTS: usize = 1_048_576;
pub const PRIVATE_TOKEN_DARKPOOL_DEVNET_BASE_ASSET: &str = "dxmr";
pub const PRIVATE_TOKEN_DARKPOOL_DEVNET_QUOTE_ASSET: &str = "dusd";
pub const PRIVATE_TOKEN_DARKPOOL_DEVNET_GOVERNANCE_ASSET: &str = "dnr";

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivateTokenDarkpoolPairKind {
    Spot,
    Stable,
    Synthetic,
    BridgeWrapped,
    Governance,
    Rwa,
}

impl PrivateTokenDarkpoolPairKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Spot => "spot",
            Self::Stable => "stable",
            Self::Synthetic => "synthetic",
            Self::BridgeWrapped => "bridge_wrapped",
            Self::Governance => "governance",
            Self::Rwa => "rwa",
        }
    }

    pub fn default_risk_weight_bps(self) -> u64 {
        match self {
            Self::Stable => 250,
            Self::Spot => 600,
            Self::BridgeWrapped => 800,
            Self::Governance => 950,
            Self::Synthetic => 1_200,
            Self::Rwa => 1_400,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivateTokenDarkpoolOrderSide {
    BuyBase,
    SellBase,
}

impl PrivateTokenDarkpoolOrderSide {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BuyBase => "buy_base",
            Self::SellBase => "sell_base",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivateTokenDarkpoolOrderKind {
    Limit,
    Market,
    ExactInput,
    ExactOutput,
    Pegged,
}

impl PrivateTokenDarkpoolOrderKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Limit => "limit",
            Self::Market => "market",
            Self::ExactInput => "exact_input",
            Self::ExactOutput => "exact_output",
            Self::Pegged => "pegged",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivateTokenDarkpoolOrderStatus {
    Sealed,
    Queued,
    Included,
    Matched,
    PartiallyFilled,
    Settled,
    Cancelled,
    Expired,
    Rejected,
}

impl PrivateTokenDarkpoolOrderStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sealed => "sealed",
            Self::Queued => "queued",
            Self::Included => "included",
            Self::Matched => "matched",
            Self::PartiallyFilled => "partially_filled",
            Self::Settled => "settled",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
            Self::Rejected => "rejected",
        }
    }

    pub fn is_live(self) -> bool {
        matches!(
            self,
            Self::Sealed | Self::Queued | Self::Included | Self::Matched | Self::PartiallyFilled
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivateTokenDarkpoolBatchStatus {
    Collecting,
    Locked,
    Solving,
    Cleared,
    Attested,
    Settling,
    Settled,
    Challenged,
    Expired,
    Cancelled,
}

impl PrivateTokenDarkpoolBatchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Collecting => "collecting",
            Self::Locked => "locked",
            Self::Solving => "solving",
            Self::Cleared => "cleared",
            Self::Attested => "attested",
            Self::Settling => "settling",
            Self::Settled => "settled",
            Self::Challenged => "challenged",
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
        }
    }

    pub fn accepts_orders(self) -> bool {
        matches!(self, Self::Collecting)
    }

    pub fn requires_attestation(self) -> bool {
        matches!(self, Self::Cleared | Self::Settling)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivateTokenDarkpoolSolverStatus {
    Bonded,
    Active,
    Suspended,
    Slashed,
    Exiting,
}

impl PrivateTokenDarkpoolSolverStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Bonded => "bonded",
            Self::Active => "active",
            Self::Suspended => "suspended",
            Self::Slashed => "slashed",
            Self::Exiting => "exiting",
        }
    }

    pub fn can_solve(self) -> bool {
        matches!(self, Self::Bonded | Self::Active)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivateTokenDarkpoolFillStatus {
    Proposed,
    Attested,
    Settled,
    Rebated,
    Challenged,
    Reverted,
}

impl PrivateTokenDarkpoolFillStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::Attested => "attested",
            Self::Settled => "settled",
            Self::Rebated => "rebated",
            Self::Challenged => "challenged",
            Self::Reverted => "reverted",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivateTokenDarkpoolEventKind {
    PairRegistered,
    SolverBonded,
    OrderSealed,
    BatchOpened,
    BatchCleared,
    FillAttested,
    SettlementFinalized,
    RebateAccrued,
    NullifierRejected,
    SolverSlashed,
}

impl PrivateTokenDarkpoolEventKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PairRegistered => "pair_registered",
            Self::SolverBonded => "solver_bonded",
            Self::OrderSealed => "order_sealed",
            Self::BatchOpened => "batch_opened",
            Self::BatchCleared => "batch_cleared",
            Self::FillAttested => "fill_attested",
            Self::SettlementFinalized => "settlement_finalized",
            Self::RebateAccrued => "rebate_accrued",
            Self::NullifierRejected => "nullifier_rejected",
            Self::SolverSlashed => "solver_slashed",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateTokenDarkpoolConfig {
    pub epoch_blocks: u64,
    pub order_ttl_blocks: u64,
    pub clearing_window_blocks: u64,
    pub settlement_window_blocks: u64,
    pub bond_ttl_blocks: u64,
    pub min_solver_bond_units: u64,
    pub min_privacy_set_size: u64,
    pub max_batch_orders: usize,
    pub max_pair_notional_units: u128,
    pub max_slippage_bps: u64,
    pub low_fee_bps: u64,
    pub rebate_share_bps: u64,
    pub solver_fee_share_bps: u64,
    pub protocol_fee_share_bps: u64,
    pub slash_bps: u64,
    pub min_pq_security_bits: u16,
    pub order_encryption_scheme: String,
    pub settlement_attestation_scheme: String,
    pub commitment_scheme: String,
    pub nullifier_scheme: String,
    pub rebate_scheme: String,
    pub batch_proof_system: String,
    pub hash_suite: String,
}

impl PrivateTokenDarkpoolConfig {
    pub fn devnet() -> Self {
        Self {
            epoch_blocks: PRIVATE_TOKEN_DARKPOOL_DEFAULT_EPOCH_BLOCKS,
            order_ttl_blocks: PRIVATE_TOKEN_DARKPOOL_DEFAULT_ORDER_TTL_BLOCKS,
            clearing_window_blocks: PRIVATE_TOKEN_DARKPOOL_DEFAULT_CLEARING_WINDOW_BLOCKS,
            settlement_window_blocks: PRIVATE_TOKEN_DARKPOOL_DEFAULT_SETTLEMENT_WINDOW_BLOCKS,
            bond_ttl_blocks: PRIVATE_TOKEN_DARKPOOL_DEFAULT_BOND_TTL_BLOCKS,
            min_solver_bond_units: PRIVATE_TOKEN_DARKPOOL_DEFAULT_MIN_SOLVER_BOND_UNITS,
            min_privacy_set_size: PRIVATE_TOKEN_DARKPOOL_DEFAULT_MIN_PRIVACY_SET_SIZE,
            max_batch_orders: PRIVATE_TOKEN_DARKPOOL_DEFAULT_MAX_BATCH_ORDERS,
            max_pair_notional_units: PRIVATE_TOKEN_DARKPOOL_DEFAULT_MAX_PAIR_NOTIONAL_UNITS,
            max_slippage_bps: PRIVATE_TOKEN_DARKPOOL_DEFAULT_MAX_SLIPPAGE_BPS,
            low_fee_bps: PRIVATE_TOKEN_DARKPOOL_DEFAULT_LOW_FEE_BPS,
            rebate_share_bps: PRIVATE_TOKEN_DARKPOOL_DEFAULT_REBATE_SHARE_BPS,
            solver_fee_share_bps: PRIVATE_TOKEN_DARKPOOL_DEFAULT_SOLVER_FEE_SHARE_BPS,
            protocol_fee_share_bps: PRIVATE_TOKEN_DARKPOOL_DEFAULT_PROTOCOL_FEE_SHARE_BPS,
            slash_bps: PRIVATE_TOKEN_DARKPOOL_DEFAULT_SLASH_BPS,
            min_pq_security_bits: PRIVATE_TOKEN_DARKPOOL_DEFAULT_MIN_PQ_SECURITY_BITS,
            order_encryption_scheme: PRIVATE_TOKEN_DARKPOOL_ORDER_ENCRYPTION_SCHEME.to_string(),
            settlement_attestation_scheme: PRIVATE_TOKEN_DARKPOOL_SETTLEMENT_ATTESTATION_SCHEME
                .to_string(),
            commitment_scheme: PRIVATE_TOKEN_DARKPOOL_COMMITMENT_SCHEME.to_string(),
            nullifier_scheme: PRIVATE_TOKEN_DARKPOOL_NULLIFIER_SCHEME.to_string(),
            rebate_scheme: PRIVATE_TOKEN_DARKPOOL_REBATE_SCHEME.to_string(),
            batch_proof_system: PRIVATE_TOKEN_DARKPOOL_BATCH_PROOF_SYSTEM.to_string(),
            hash_suite: PRIVATE_TOKEN_DARKPOOL_HASH_SUITE.to_string(),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "epoch_blocks": self.epoch_blocks,
            "order_ttl_blocks": self.order_ttl_blocks,
            "clearing_window_blocks": self.clearing_window_blocks,
            "settlement_window_blocks": self.settlement_window_blocks,
            "bond_ttl_blocks": self.bond_ttl_blocks,
            "min_solver_bond_units": self.min_solver_bond_units,
            "min_privacy_set_size": self.min_privacy_set_size,
            "max_batch_orders": self.max_batch_orders,
            "max_pair_notional_units": self.max_pair_notional_units,
            "max_slippage_bps": self.max_slippage_bps,
            "low_fee_bps": self.low_fee_bps,
            "rebate_share_bps": self.rebate_share_bps,
            "solver_fee_share_bps": self.solver_fee_share_bps,
            "protocol_fee_share_bps": self.protocol_fee_share_bps,
            "slash_bps": self.slash_bps,
            "min_pq_security_bits": self.min_pq_security_bits,
            "order_encryption_scheme": self.order_encryption_scheme,
            "settlement_attestation_scheme": self.settlement_attestation_scheme,
            "commitment_scheme": self.commitment_scheme,
            "nullifier_scheme": self.nullifier_scheme,
            "rebate_scheme": self.rebate_scheme,
            "batch_proof_system": self.batch_proof_system,
            "hash_suite": self.hash_suite,
        })
    }

    pub fn config_root(&self) -> String {
        private_token_darkpool_hash("CONFIG", &[HashPart::Json(&self.public_record())])
    }

    pub fn validate(&self) -> PrivateTokenDarkpoolResult<()> {
        if self.epoch_blocks == 0
            || self.order_ttl_blocks == 0
            || self.clearing_window_blocks == 0
            || self.settlement_window_blocks == 0
            || self.bond_ttl_blocks == 0
            || self.min_solver_bond_units == 0
            || self.min_privacy_set_size == 0
            || self.max_batch_orders == 0
            || self.max_pair_notional_units == 0
        {
            return Err("private token darkpool config values must be positive".to_string());
        }
        if self.max_slippage_bps > PRIVATE_TOKEN_DARKPOOL_MAX_BPS
            || self.low_fee_bps > PRIVATE_TOKEN_DARKPOOL_MAX_BPS
            || self.rebate_share_bps > PRIVATE_TOKEN_DARKPOOL_MAX_BPS
            || self.solver_fee_share_bps > PRIVATE_TOKEN_DARKPOOL_MAX_BPS
            || self.protocol_fee_share_bps > PRIVATE_TOKEN_DARKPOOL_MAX_BPS
            || self.slash_bps > PRIVATE_TOKEN_DARKPOOL_MAX_BPS
        {
            return Err("private token darkpool bps values exceed max".to_string());
        }
        let fee_share = self
            .rebate_share_bps
            .checked_add(self.solver_fee_share_bps)
            .and_then(|value| value.checked_add(self.protocol_fee_share_bps))
            .ok_or_else(|| "private token darkpool fee shares overflow".to_string())?;
        if fee_share > PRIVATE_TOKEN_DARKPOOL_MAX_BPS {
            return Err("private token darkpool fee shares exceed max bps".to_string());
        }
        if self.min_pq_security_bits < PRIVATE_TOKEN_DARKPOOL_DEFAULT_MIN_PQ_SECURITY_BITS {
            return Err("private token darkpool pq security bits too low".to_string());
        }
        if self.order_encryption_scheme.is_empty()
            || self.settlement_attestation_scheme.is_empty()
            || self.commitment_scheme.is_empty()
            || self.nullifier_scheme.is_empty()
            || self.rebate_scheme.is_empty()
            || self.batch_proof_system.is_empty()
            || self.hash_suite.is_empty()
        {
            return Err("private token darkpool suite labels must be populated".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfidentialTokenPair {
    pub pair_id: String,
    pub base_asset_commitment: String,
    pub quote_asset_commitment: String,
    pub pair_kind: PrivateTokenDarkpoolPairKind,
    pub fee_asset_id: String,
    pub oracle_price_root: String,
    pub pair_commitment_root: String,
    pub policy_root: String,
    pub min_base_amount: u64,
    pub min_quote_amount: u64,
    pub price_scale: u64,
    pub risk_weight_bps: u64,
    pub active: bool,
    pub registered_at_height: u64,
}

impl ConfidentialTokenPair {
    pub fn new(
        pair_id: &str,
        base_asset_commitment: &str,
        quote_asset_commitment: &str,
        pair_kind: PrivateTokenDarkpoolPairKind,
        fee_asset_id: &str,
        registered_at_height: u64,
    ) -> PrivateTokenDarkpoolResult<Self> {
        require_non_empty("pair_id", pair_id)?;
        require_non_empty("base_asset_commitment", base_asset_commitment)?;
        require_non_empty("quote_asset_commitment", quote_asset_commitment)?;
        require_non_empty("fee_asset_id", fee_asset_id)?;
        if base_asset_commitment == quote_asset_commitment {
            return Err("private token darkpool pair assets must differ".to_string());
        }
        let oracle_price_root = private_token_darkpool_hash(
            "PAIR-ORACLE",
            &[
                HashPart::Str(pair_id),
                HashPart::Str(base_asset_commitment),
                HashPart::Str(quote_asset_commitment),
                HashPart::Int(registered_at_height as i128),
            ],
        );
        let pair_commitment_root = private_token_darkpool_hash(
            "PAIR-COMMITMENT",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(pair_id),
                HashPart::Str(base_asset_commitment),
                HashPart::Str(quote_asset_commitment),
                HashPart::Str(pair_kind.as_str()),
            ],
        );
        let policy_root = private_token_darkpool_hash(
            "PAIR-POLICY",
            &[
                HashPart::Str(pair_id),
                HashPart::Str(pair_kind.as_str()),
                HashPart::Int(pair_kind.default_risk_weight_bps() as i128),
            ],
        );
        Ok(Self {
            pair_id: pair_id.to_string(),
            base_asset_commitment: base_asset_commitment.to_string(),
            quote_asset_commitment: quote_asset_commitment.to_string(),
            pair_kind,
            fee_asset_id: fee_asset_id.to_string(),
            oracle_price_root,
            pair_commitment_root,
            policy_root,
            min_base_amount: 1,
            min_quote_amount: 1,
            price_scale: 1_000_000_000_000,
            risk_weight_bps: pair_kind.default_risk_weight_bps(),
            active: true,
            registered_at_height,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "pair_id": self.pair_id,
            "base_asset_commitment": self.base_asset_commitment,
            "quote_asset_commitment": self.quote_asset_commitment,
            "pair_kind": self.pair_kind.as_str(),
            "fee_asset_id": self.fee_asset_id,
            "oracle_price_root": self.oracle_price_root,
            "pair_commitment_root": self.pair_commitment_root,
            "policy_root": self.policy_root,
            "min_base_amount": self.min_base_amount,
            "min_quote_amount": self.min_quote_amount,
            "price_scale": self.price_scale,
            "risk_weight_bps": self.risk_weight_bps,
            "active": self.active,
            "registered_at_height": self.registered_at_height,
        })
    }

    pub fn pair_root(&self) -> String {
        private_token_darkpool_hash("PAIR", &[HashPart::Json(&self.public_record())])
    }

    pub fn validate(&self) -> PrivateTokenDarkpoolResult<()> {
        require_non_empty("pair_id", &self.pair_id)?;
        require_non_empty("base_asset_commitment", &self.base_asset_commitment)?;
        require_non_empty("quote_asset_commitment", &self.quote_asset_commitment)?;
        require_non_empty("fee_asset_id", &self.fee_asset_id)?;
        require_non_empty("oracle_price_root", &self.oracle_price_root)?;
        require_non_empty("pair_commitment_root", &self.pair_commitment_root)?;
        require_non_empty("policy_root", &self.policy_root)?;
        if self.base_asset_commitment == self.quote_asset_commitment {
            return Err("private token darkpool pair assets must differ".to_string());
        }
        if self.min_base_amount == 0 || self.min_quote_amount == 0 || self.price_scale == 0 {
            return Err("private token darkpool pair amounts must be positive".to_string());
        }
        if self.risk_weight_bps > PRIVATE_TOKEN_DARKPOOL_MAX_BPS {
            return Err("private token darkpool pair risk exceeds max bps".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SolverBond {
    pub solver_id: String,
    pub operator_commitment: String,
    pub bond_asset_id: String,
    pub bonded_units: u64,
    pub locked_units: u64,
    pub slashed_units: u64,
    pub status: PrivateTokenDarkpoolSolverStatus,
    pub pq_identity_root: String,
    pub allowed_pair_root: String,
    pub reputation_score: u64,
    pub bonded_at_height: u64,
    pub exit_after_height: u64,
}

impl SolverBond {
    pub fn new(
        solver_id: &str,
        operator_commitment: &str,
        bond_asset_id: &str,
        bonded_units: u64,
        bonded_at_height: u64,
        bond_ttl_blocks: u64,
    ) -> PrivateTokenDarkpoolResult<Self> {
        require_non_empty("solver_id", solver_id)?;
        require_non_empty("operator_commitment", operator_commitment)?;
        require_non_empty("bond_asset_id", bond_asset_id)?;
        if bonded_units == 0 {
            return Err("private token darkpool solver bond must be positive".to_string());
        }
        let exit_after_height = bonded_at_height
            .checked_add(bond_ttl_blocks)
            .ok_or_else(|| "private token darkpool solver bond height overflow".to_string())?;
        let pq_identity_root = private_token_darkpool_hash(
            "SOLVER-PQ-IDENTITY",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(solver_id),
                HashPart::Str(operator_commitment),
                HashPart::Int(bonded_at_height as i128),
            ],
        );
        let allowed_pair_root = private_token_darkpool_string_root(
            "SOLVER-ALLOWED-PAIR",
            &[
                PRIVATE_TOKEN_DARKPOOL_DEVNET_BASE_ASSET,
                PRIVATE_TOKEN_DARKPOOL_DEVNET_QUOTE_ASSET,
            ],
        );
        Ok(Self {
            solver_id: solver_id.to_string(),
            operator_commitment: operator_commitment.to_string(),
            bond_asset_id: bond_asset_id.to_string(),
            bonded_units,
            locked_units: 0,
            slashed_units: 0,
            status: PrivateTokenDarkpoolSolverStatus::Bonded,
            pq_identity_root,
            allowed_pair_root,
            reputation_score: 100,
            bonded_at_height,
            exit_after_height,
        })
    }

    pub fn available_bond_units(&self) -> u64 {
        self.bonded_units
            .saturating_sub(self.locked_units)
            .saturating_sub(self.slashed_units)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "solver_id": self.solver_id,
            "operator_commitment": self.operator_commitment,
            "bond_asset_id": self.bond_asset_id,
            "bonded_units": self.bonded_units,
            "locked_units": self.locked_units,
            "slashed_units": self.slashed_units,
            "available_bond_units": self.available_bond_units(),
            "status": self.status.as_str(),
            "pq_identity_root": self.pq_identity_root,
            "allowed_pair_root": self.allowed_pair_root,
            "reputation_score": self.reputation_score,
            "bonded_at_height": self.bonded_at_height,
            "exit_after_height": self.exit_after_height,
        })
    }

    pub fn bond_root(&self) -> String {
        private_token_darkpool_hash("SOLVER-BOND", &[HashPart::Json(&self.public_record())])
    }

    pub fn validate(&self, config: &PrivateTokenDarkpoolConfig) -> PrivateTokenDarkpoolResult<()> {
        require_non_empty("solver_id", &self.solver_id)?;
        require_non_empty("operator_commitment", &self.operator_commitment)?;
        require_non_empty("bond_asset_id", &self.bond_asset_id)?;
        require_non_empty("pq_identity_root", &self.pq_identity_root)?;
        require_non_empty("allowed_pair_root", &self.allowed_pair_root)?;
        if self.bonded_units < config.min_solver_bond_units {
            return Err("private token darkpool solver bond below minimum".to_string());
        }
        if self.locked_units > self.bonded_units {
            return Err("private token darkpool solver locked bond exceeds bonded".to_string());
        }
        if self.slashed_units > self.bonded_units {
            return Err("private token darkpool solver slashed bond exceeds bonded".to_string());
        }
        if self.bonded_at_height >= self.exit_after_height {
            return Err("private token darkpool solver exit height must be later".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedDarkpoolOrder {
    pub order_id: String,
    pub pair_id: String,
    pub account_commitment: String,
    pub side: PrivateTokenDarkpoolOrderSide,
    pub order_kind: PrivateTokenDarkpoolOrderKind,
    pub status: PrivateTokenDarkpoolOrderStatus,
    pub amount_commitment: String,
    pub limit_price_commitment: String,
    pub salt_commitment: String,
    pub sealed_payload_hash: String,
    pub viewing_key_commitment: String,
    pub nullifier_commitment: String,
    pub max_fee_units: u64,
    pub low_fee_eligible: bool,
    pub submitted_at_height: u64,
    pub expires_at_height: u64,
    pub privacy_set_hint: u64,
    pub batch_id: String,
}

impl SealedDarkpoolOrder {
    pub fn new(
        order_id: &str,
        pair_id: &str,
        account_commitment: &str,
        side: PrivateTokenDarkpoolOrderSide,
        order_kind: PrivateTokenDarkpoolOrderKind,
        amount_commitment: &str,
        limit_price_commitment: &str,
        submitted_at_height: u64,
        ttl_blocks: u64,
    ) -> PrivateTokenDarkpoolResult<Self> {
        require_non_empty("order_id", order_id)?;
        require_non_empty("pair_id", pair_id)?;
        require_non_empty("account_commitment", account_commitment)?;
        require_non_empty("amount_commitment", amount_commitment)?;
        require_non_empty("limit_price_commitment", limit_price_commitment)?;
        let expires_at_height = submitted_at_height
            .checked_add(ttl_blocks)
            .ok_or_else(|| "private token darkpool order expiry overflow".to_string())?;
        let salt_commitment = private_token_darkpool_hash(
            "ORDER-SALT",
            &[
                HashPart::Str(order_id),
                HashPart::Str(account_commitment),
                HashPart::Int(submitted_at_height as i128),
            ],
        );
        let sealed_payload_hash = private_token_darkpool_hash(
            "ORDER-SEALED-PAYLOAD",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(pair_id),
                HashPart::Str(side.as_str()),
                HashPart::Str(order_kind.as_str()),
                HashPart::Str(amount_commitment),
                HashPart::Str(limit_price_commitment),
                HashPart::Str(&salt_commitment),
            ],
        );
        let viewing_key_commitment = private_token_darkpool_hash(
            "ORDER-VIEWING-KEY",
            &[
                HashPart::Str(order_id),
                HashPart::Str(account_commitment),
                HashPart::Str(&sealed_payload_hash),
            ],
        );
        let nullifier_commitment = private_token_darkpool_hash(
            "ORDER-NULLIFIER-COMMITMENT",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(order_id),
                HashPart::Str(&sealed_payload_hash),
                HashPart::Int(expires_at_height as i128),
            ],
        );
        Ok(Self {
            order_id: order_id.to_string(),
            pair_id: pair_id.to_string(),
            account_commitment: account_commitment.to_string(),
            side,
            order_kind,
            status: PrivateTokenDarkpoolOrderStatus::Sealed,
            amount_commitment: amount_commitment.to_string(),
            limit_price_commitment: limit_price_commitment.to_string(),
            salt_commitment,
            sealed_payload_hash,
            viewing_key_commitment,
            nullifier_commitment,
            max_fee_units: 0,
            low_fee_eligible: true,
            submitted_at_height,
            expires_at_height,
            privacy_set_hint: 0,
            batch_id: String::new(),
        })
    }

    pub fn assign_batch(&mut self, batch_id: &str) -> PrivateTokenDarkpoolResult<()> {
        require_non_empty("batch_id", batch_id)?;
        if !self.status.is_live() {
            return Err("private token darkpool order is not live".to_string());
        }
        self.batch_id = batch_id.to_string();
        self.status = PrivateTokenDarkpoolOrderStatus::Included;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "order_id": self.order_id,
            "pair_id": self.pair_id,
            "account_commitment": self.account_commitment,
            "side": self.side.as_str(),
            "order_kind": self.order_kind.as_str(),
            "status": self.status.as_str(),
            "amount_commitment": self.amount_commitment,
            "limit_price_commitment": self.limit_price_commitment,
            "salt_commitment": self.salt_commitment,
            "sealed_payload_hash": self.sealed_payload_hash,
            "viewing_key_commitment": self.viewing_key_commitment,
            "nullifier_commitment": self.nullifier_commitment,
            "max_fee_units": self.max_fee_units,
            "low_fee_eligible": self.low_fee_eligible,
            "submitted_at_height": self.submitted_at_height,
            "expires_at_height": self.expires_at_height,
            "privacy_set_hint": self.privacy_set_hint,
            "batch_id": self.batch_id,
        })
    }

    pub fn order_root(&self) -> String {
        private_token_darkpool_hash("ORDER", &[HashPart::Json(&self.public_record())])
    }

    pub fn validate(&self, config: &PrivateTokenDarkpoolConfig) -> PrivateTokenDarkpoolResult<()> {
        require_non_empty("order_id", &self.order_id)?;
        require_non_empty("pair_id", &self.pair_id)?;
        require_non_empty("account_commitment", &self.account_commitment)?;
        require_non_empty("amount_commitment", &self.amount_commitment)?;
        require_non_empty("limit_price_commitment", &self.limit_price_commitment)?;
        require_non_empty("salt_commitment", &self.salt_commitment)?;
        require_non_empty("sealed_payload_hash", &self.sealed_payload_hash)?;
        require_non_empty("viewing_key_commitment", &self.viewing_key_commitment)?;
        require_non_empty("nullifier_commitment", &self.nullifier_commitment)?;
        if self.submitted_at_height >= self.expires_at_height {
            return Err("private token darkpool order expiry must be later".to_string());
        }
        if self.max_fee_units > 0 && self.low_fee_eligible && config.low_fee_bps == 0 {
            return Err("private token darkpool low fee order has disabled fee lane".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DarkpoolAuctionBatch {
    pub batch_id: String,
    pub pair_id: String,
    pub status: PrivateTokenDarkpoolBatchStatus,
    pub order_root: String,
    pub buy_order_root: String,
    pub sell_order_root: String,
    pub clearing_price_commitment: String,
    pub clearing_volume_commitment: String,
    pub surplus_commitment: String,
    pub proof_root: String,
    pub selected_solver_id: String,
    pub order_count: u64,
    pub buy_count: u64,
    pub sell_count: u64,
    pub opened_at_height: u64,
    pub locked_at_height: u64,
    pub clear_before_height: u64,
    pub settle_before_height: u64,
}

impl DarkpoolAuctionBatch {
    pub fn new(
        batch_id: &str,
        pair_id: &str,
        opened_at_height: u64,
        config: &PrivateTokenDarkpoolConfig,
    ) -> PrivateTokenDarkpoolResult<Self> {
        require_non_empty("batch_id", batch_id)?;
        require_non_empty("pair_id", pair_id)?;
        let clear_before_height = opened_at_height
            .checked_add(config.clearing_window_blocks)
            .ok_or_else(|| "private token darkpool batch clear height overflow".to_string())?;
        let settle_before_height = clear_before_height
            .checked_add(config.settlement_window_blocks)
            .ok_or_else(|| "private token darkpool batch settle height overflow".to_string())?;
        let order_root = private_token_darkpool_string_root("BATCH-ORDER", &[]);
        let buy_order_root = private_token_darkpool_string_root("BATCH-BUY-ORDER", &[]);
        let sell_order_root = private_token_darkpool_string_root("BATCH-SELL-ORDER", &[]);
        let clearing_price_commitment = private_token_darkpool_hash(
            "BATCH-CLEARING-PRICE",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(batch_id),
                HashPart::Str(pair_id),
                HashPart::Int(opened_at_height as i128),
            ],
        );
        let clearing_volume_commitment = private_token_darkpool_hash(
            "BATCH-CLEARING-VOLUME",
            &[
                HashPart::Str(batch_id),
                HashPart::Str(pair_id),
                HashPart::Int(clear_before_height as i128),
            ],
        );
        let surplus_commitment = private_token_darkpool_hash(
            "BATCH-SURPLUS",
            &[
                HashPart::Str(batch_id),
                HashPart::Str(&clearing_price_commitment),
                HashPart::Str(&clearing_volume_commitment),
            ],
        );
        let proof_root = private_token_darkpool_hash(
            "BATCH-PROOF-PLACEHOLDER",
            &[
                HashPart::Str(batch_id),
                HashPart::Str(PRIVATE_TOKEN_DARKPOOL_BATCH_PROOF_SYSTEM),
            ],
        );
        Ok(Self {
            batch_id: batch_id.to_string(),
            pair_id: pair_id.to_string(),
            status: PrivateTokenDarkpoolBatchStatus::Collecting,
            order_root,
            buy_order_root,
            sell_order_root,
            clearing_price_commitment,
            clearing_volume_commitment,
            surplus_commitment,
            proof_root,
            selected_solver_id: String::new(),
            order_count: 0,
            buy_count: 0,
            sell_count: 0,
            opened_at_height,
            locked_at_height: 0,
            clear_before_height,
            settle_before_height,
        })
    }

    pub fn ingest_order_roots(
        &mut self,
        orders: &BTreeMap<String, SealedDarkpoolOrder>,
    ) -> PrivateTokenDarkpoolResult<()> {
        if !self.status.accepts_orders() {
            return Err("private token darkpool batch no longer accepts orders".to_string());
        }
        let mut all = Vec::new();
        let mut buys = Vec::new();
        let mut sells = Vec::new();
        for order in orders.values() {
            if order.batch_id == self.batch_id {
                let root = order.order_root();
                all.push(root.clone());
                match order.side {
                    PrivateTokenDarkpoolOrderSide::BuyBase => buys.push(root),
                    PrivateTokenDarkpoolOrderSide::SellBase => sells.push(root),
                }
            }
        }
        self.order_count = all.len() as u64;
        self.buy_count = buys.len() as u64;
        self.sell_count = sells.len() as u64;
        self.order_root = private_token_darkpool_owned_string_root("BATCH-ORDER", &all);
        self.buy_order_root = private_token_darkpool_owned_string_root("BATCH-BUY-ORDER", &buys);
        self.sell_order_root = private_token_darkpool_owned_string_root("BATCH-SELL-ORDER", &sells);
        Ok(())
    }

    pub fn lock_for_solving(
        &mut self,
        solver_id: &str,
        locked_at_height: u64,
    ) -> PrivateTokenDarkpoolResult<()> {
        require_non_empty("solver_id", solver_id)?;
        if self.status != PrivateTokenDarkpoolBatchStatus::Collecting {
            return Err("private token darkpool batch must be collecting to lock".to_string());
        }
        if locked_at_height < self.opened_at_height {
            return Err("private token darkpool batch lock before open".to_string());
        }
        self.status = PrivateTokenDarkpoolBatchStatus::Solving;
        self.selected_solver_id = solver_id.to_string();
        self.locked_at_height = locked_at_height;
        Ok(())
    }

    pub fn mark_cleared(
        &mut self,
        clearing_price_commitment: &str,
        clearing_volume_commitment: &str,
        surplus_commitment: &str,
        proof_root: &str,
    ) -> PrivateTokenDarkpoolResult<()> {
        require_non_empty("clearing_price_commitment", clearing_price_commitment)?;
        require_non_empty("clearing_volume_commitment", clearing_volume_commitment)?;
        require_non_empty("surplus_commitment", surplus_commitment)?;
        require_non_empty("proof_root", proof_root)?;
        if self.status != PrivateTokenDarkpoolBatchStatus::Solving {
            return Err("private token darkpool batch must be solving to clear".to_string());
        }
        self.clearing_price_commitment = clearing_price_commitment.to_string();
        self.clearing_volume_commitment = clearing_volume_commitment.to_string();
        self.surplus_commitment = surplus_commitment.to_string();
        self.proof_root = proof_root.to_string();
        self.status = PrivateTokenDarkpoolBatchStatus::Cleared;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "pair_id": self.pair_id,
            "status": self.status.as_str(),
            "order_root": self.order_root,
            "buy_order_root": self.buy_order_root,
            "sell_order_root": self.sell_order_root,
            "clearing_price_commitment": self.clearing_price_commitment,
            "clearing_volume_commitment": self.clearing_volume_commitment,
            "surplus_commitment": self.surplus_commitment,
            "proof_root": self.proof_root,
            "selected_solver_id": self.selected_solver_id,
            "order_count": self.order_count,
            "buy_count": self.buy_count,
            "sell_count": self.sell_count,
            "opened_at_height": self.opened_at_height,
            "locked_at_height": self.locked_at_height,
            "clear_before_height": self.clear_before_height,
            "settle_before_height": self.settle_before_height,
        })
    }

    pub fn batch_root(&self) -> String {
        private_token_darkpool_hash("BATCH", &[HashPart::Json(&self.public_record())])
    }

    pub fn validate(&self, config: &PrivateTokenDarkpoolConfig) -> PrivateTokenDarkpoolResult<()> {
        require_non_empty("batch_id", &self.batch_id)?;
        require_non_empty("pair_id", &self.pair_id)?;
        require_non_empty("order_root", &self.order_root)?;
        require_non_empty("buy_order_root", &self.buy_order_root)?;
        require_non_empty("sell_order_root", &self.sell_order_root)?;
        require_non_empty("clearing_price_commitment", &self.clearing_price_commitment)?;
        require_non_empty(
            "clearing_volume_commitment",
            &self.clearing_volume_commitment,
        )?;
        require_non_empty("surplus_commitment", &self.surplus_commitment)?;
        require_non_empty("proof_root", &self.proof_root)?;
        if self.order_count as usize > config.max_batch_orders {
            return Err("private token darkpool batch exceeds max order count".to_string());
        }
        if self.opened_at_height >= self.clear_before_height {
            return Err("private token darkpool batch clear height must be later".to_string());
        }
        if self.clear_before_height >= self.settle_before_height {
            return Err("private token darkpool batch settle height must be later".to_string());
        }
        if self.status != PrivateTokenDarkpoolBatchStatus::Collecting
            && self.selected_solver_id.is_empty()
        {
            return Err("private token darkpool active batch missing selected solver".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateDarkpoolFill {
    pub fill_id: String,
    pub batch_id: String,
    pub pair_id: String,
    pub order_id: String,
    pub solver_id: String,
    pub status: PrivateTokenDarkpoolFillStatus,
    pub base_amount_commitment: String,
    pub quote_amount_commitment: String,
    pub fee_commitment: String,
    pub rebate_commitment: String,
    pub settlement_note_root: String,
    pub fill_nullifier: String,
    pub counterparty_root: String,
    pub pq_attestation_id: String,
    pub settled_at_height: u64,
}

impl PrivateDarkpoolFill {
    pub fn new(
        fill_id: &str,
        batch_id: &str,
        pair_id: &str,
        order_id: &str,
        solver_id: &str,
        base_amount_commitment: &str,
        quote_amount_commitment: &str,
        settled_at_height: u64,
    ) -> PrivateTokenDarkpoolResult<Self> {
        require_non_empty("fill_id", fill_id)?;
        require_non_empty("batch_id", batch_id)?;
        require_non_empty("pair_id", pair_id)?;
        require_non_empty("order_id", order_id)?;
        require_non_empty("solver_id", solver_id)?;
        require_non_empty("base_amount_commitment", base_amount_commitment)?;
        require_non_empty("quote_amount_commitment", quote_amount_commitment)?;
        let fee_commitment = private_token_darkpool_hash(
            "FILL-FEE",
            &[
                HashPart::Str(fill_id),
                HashPart::Str(order_id),
                HashPart::Str(base_amount_commitment),
                HashPart::Str(quote_amount_commitment),
            ],
        );
        let rebate_commitment = private_token_darkpool_hash(
            "FILL-REBATE",
            &[
                HashPart::Str(fill_id),
                HashPart::Str(solver_id),
                HashPart::Str(&fee_commitment),
            ],
        );
        let settlement_note_root = private_token_darkpool_hash(
            "FILL-SETTLEMENT-NOTE",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(fill_id),
                HashPart::Str(batch_id),
                HashPart::Int(settled_at_height as i128),
            ],
        );
        let fill_nullifier = private_token_darkpool_hash(
            "FILL-NULLIFIER",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(fill_id),
                HashPart::Str(order_id),
                HashPart::Str(&settlement_note_root),
            ],
        );
        let counterparty_root = private_token_darkpool_hash(
            "FILL-COUNTERPARTY",
            &[
                HashPart::Str(batch_id),
                HashPart::Str(order_id),
                HashPart::Str(solver_id),
            ],
        );
        Ok(Self {
            fill_id: fill_id.to_string(),
            batch_id: batch_id.to_string(),
            pair_id: pair_id.to_string(),
            order_id: order_id.to_string(),
            solver_id: solver_id.to_string(),
            status: PrivateTokenDarkpoolFillStatus::Proposed,
            base_amount_commitment: base_amount_commitment.to_string(),
            quote_amount_commitment: quote_amount_commitment.to_string(),
            fee_commitment,
            rebate_commitment,
            settlement_note_root,
            fill_nullifier,
            counterparty_root,
            pq_attestation_id: String::new(),
            settled_at_height,
        })
    }

    pub fn attach_attestation(&mut self, attestation_id: &str) -> PrivateTokenDarkpoolResult<()> {
        require_non_empty("attestation_id", attestation_id)?;
        self.pq_attestation_id = attestation_id.to_string();
        self.status = PrivateTokenDarkpoolFillStatus::Attested;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "fill_id": self.fill_id,
            "batch_id": self.batch_id,
            "pair_id": self.pair_id,
            "order_id": self.order_id,
            "solver_id": self.solver_id,
            "status": self.status.as_str(),
            "base_amount_commitment": self.base_amount_commitment,
            "quote_amount_commitment": self.quote_amount_commitment,
            "fee_commitment": self.fee_commitment,
            "rebate_commitment": self.rebate_commitment,
            "settlement_note_root": self.settlement_note_root,
            "fill_nullifier": self.fill_nullifier,
            "counterparty_root": self.counterparty_root,
            "pq_attestation_id": self.pq_attestation_id,
            "settled_at_height": self.settled_at_height,
        })
    }

    pub fn fill_root(&self) -> String {
        private_token_darkpool_hash("FILL", &[HashPart::Json(&self.public_record())])
    }

    pub fn validate(&self) -> PrivateTokenDarkpoolResult<()> {
        require_non_empty("fill_id", &self.fill_id)?;
        require_non_empty("batch_id", &self.batch_id)?;
        require_non_empty("pair_id", &self.pair_id)?;
        require_non_empty("order_id", &self.order_id)?;
        require_non_empty("solver_id", &self.solver_id)?;
        require_non_empty("base_amount_commitment", &self.base_amount_commitment)?;
        require_non_empty("quote_amount_commitment", &self.quote_amount_commitment)?;
        require_non_empty("fee_commitment", &self.fee_commitment)?;
        require_non_empty("rebate_commitment", &self.rebate_commitment)?;
        require_non_empty("settlement_note_root", &self.settlement_note_root)?;
        require_non_empty("fill_nullifier", &self.fill_nullifier)?;
        require_non_empty("counterparty_root", &self.counterparty_root)?;
        if matches!(
            self.status,
            PrivateTokenDarkpoolFillStatus::Attested
                | PrivateTokenDarkpoolFillStatus::Settled
                | PrivateTokenDarkpoolFillStatus::Rebated
        ) && self.pq_attestation_id.is_empty()
        {
            return Err("private token darkpool attested fill missing attestation".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqSettlementAttestation {
    pub attestation_id: String,
    pub batch_id: String,
    pub solver_id: String,
    pub attester_committee_root: String,
    pub signature_root: String,
    pub transcript_root: String,
    pub fill_root: String,
    pub nullifier_root: String,
    pub rebate_root: String,
    pub pq_security_bits: u16,
    pub attested_at_height: u64,
}

impl PqSettlementAttestation {
    pub fn new(
        attestation_id: &str,
        batch_id: &str,
        solver_id: &str,
        fill_root: &str,
        nullifier_root: &str,
        rebate_root: &str,
        pq_security_bits: u16,
        attested_at_height: u64,
    ) -> PrivateTokenDarkpoolResult<Self> {
        require_non_empty("attestation_id", attestation_id)?;
        require_non_empty("batch_id", batch_id)?;
        require_non_empty("solver_id", solver_id)?;
        require_non_empty("fill_root", fill_root)?;
        require_non_empty("nullifier_root", nullifier_root)?;
        require_non_empty("rebate_root", rebate_root)?;
        let attester_committee_root = private_token_darkpool_hash(
            "ATTESTATION-COMMITTEE",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(batch_id),
                HashPart::Str(solver_id),
                HashPart::Int(attested_at_height as i128),
            ],
        );
        let transcript_root = private_token_darkpool_hash(
            "ATTESTATION-TRANSCRIPT",
            &[
                HashPart::Str(attestation_id),
                HashPart::Str(batch_id),
                HashPart::Str(fill_root),
                HashPart::Str(nullifier_root),
                HashPart::Str(rebate_root),
            ],
        );
        let signature_root = private_token_darkpool_hash(
            "ATTESTATION-SIGNATURE",
            &[
                HashPart::Str(PRIVATE_TOKEN_DARKPOOL_SETTLEMENT_ATTESTATION_SCHEME),
                HashPart::Str(&attester_committee_root),
                HashPart::Str(&transcript_root),
                HashPart::Int(pq_security_bits as i128),
            ],
        );
        Ok(Self {
            attestation_id: attestation_id.to_string(),
            batch_id: batch_id.to_string(),
            solver_id: solver_id.to_string(),
            attester_committee_root,
            signature_root,
            transcript_root,
            fill_root: fill_root.to_string(),
            nullifier_root: nullifier_root.to_string(),
            rebate_root: rebate_root.to_string(),
            pq_security_bits,
            attested_at_height,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "batch_id": self.batch_id,
            "solver_id": self.solver_id,
            "attester_committee_root": self.attester_committee_root,
            "signature_root": self.signature_root,
            "transcript_root": self.transcript_root,
            "fill_root": self.fill_root,
            "nullifier_root": self.nullifier_root,
            "rebate_root": self.rebate_root,
            "pq_security_bits": self.pq_security_bits,
            "attested_at_height": self.attested_at_height,
        })
    }

    pub fn attestation_root(&self) -> String {
        private_token_darkpool_hash("ATTESTATION", &[HashPart::Json(&self.public_record())])
    }

    pub fn validate(&self, config: &PrivateTokenDarkpoolConfig) -> PrivateTokenDarkpoolResult<()> {
        require_non_empty("attestation_id", &self.attestation_id)?;
        require_non_empty("batch_id", &self.batch_id)?;
        require_non_empty("solver_id", &self.solver_id)?;
        require_non_empty("attester_committee_root", &self.attester_committee_root)?;
        require_non_empty("signature_root", &self.signature_root)?;
        require_non_empty("transcript_root", &self.transcript_root)?;
        require_non_empty("fill_root", &self.fill_root)?;
        require_non_empty("nullifier_root", &self.nullifier_root)?;
        require_non_empty("rebate_root", &self.rebate_root)?;
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err("private token darkpool attestation pq security too low".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeRebate {
    pub rebate_id: String,
    pub fill_id: String,
    pub order_id: String,
    pub solver_id: String,
    pub recipient_commitment: String,
    pub fee_commitment: String,
    pub rebate_commitment: String,
    pub rebate_nullifier: String,
    pub sponsor_pool_root: String,
    pub accrued_units: u64,
    pub claimed_units: u64,
    pub accrued_at_height: u64,
}

impl LowFeeRebate {
    pub fn new(
        rebate_id: &str,
        fill_id: &str,
        order_id: &str,
        solver_id: &str,
        recipient_commitment: &str,
        accrued_units: u64,
        accrued_at_height: u64,
    ) -> PrivateTokenDarkpoolResult<Self> {
        require_non_empty("rebate_id", rebate_id)?;
        require_non_empty("fill_id", fill_id)?;
        require_non_empty("order_id", order_id)?;
        require_non_empty("solver_id", solver_id)?;
        require_non_empty("recipient_commitment", recipient_commitment)?;
        if accrued_units == 0 {
            return Err("private token darkpool rebate units must be positive".to_string());
        }
        let fee_commitment = private_token_darkpool_hash(
            "REBATE-FEE",
            &[
                HashPart::Str(fill_id),
                HashPart::Str(order_id),
                HashPart::Int(accrued_units as i128),
            ],
        );
        let rebate_commitment = private_token_darkpool_hash(
            "REBATE-COMMITMENT",
            &[
                HashPart::Str(rebate_id),
                HashPart::Str(recipient_commitment),
                HashPart::Str(&fee_commitment),
            ],
        );
        let rebate_nullifier = private_token_darkpool_hash(
            "REBATE-NULLIFIER",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(rebate_id),
                HashPart::Str(fill_id),
                HashPart::Str(&rebate_commitment),
            ],
        );
        let sponsor_pool_root = private_token_darkpool_hash(
            "REBATE-SPONSOR-POOL",
            &[
                HashPart::Str(solver_id),
                HashPart::Str(&rebate_commitment),
                HashPart::Int(accrued_at_height as i128),
            ],
        );
        Ok(Self {
            rebate_id: rebate_id.to_string(),
            fill_id: fill_id.to_string(),
            order_id: order_id.to_string(),
            solver_id: solver_id.to_string(),
            recipient_commitment: recipient_commitment.to_string(),
            fee_commitment,
            rebate_commitment,
            rebate_nullifier,
            sponsor_pool_root,
            accrued_units,
            claimed_units: 0,
            accrued_at_height,
        })
    }

    pub fn claim(&mut self, units: u64) -> PrivateTokenDarkpoolResult<()> {
        let next = self
            .claimed_units
            .checked_add(units)
            .ok_or_else(|| "private token darkpool rebate claim overflow".to_string())?;
        if next > self.accrued_units {
            return Err("private token darkpool rebate claim exceeds accrued units".to_string());
        }
        self.claimed_units = next;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "rebate_id": self.rebate_id,
            "fill_id": self.fill_id,
            "order_id": self.order_id,
            "solver_id": self.solver_id,
            "recipient_commitment": self.recipient_commitment,
            "fee_commitment": self.fee_commitment,
            "rebate_commitment": self.rebate_commitment,
            "rebate_nullifier": self.rebate_nullifier,
            "sponsor_pool_root": self.sponsor_pool_root,
            "accrued_units": self.accrued_units,
            "claimed_units": self.claimed_units,
            "accrued_at_height": self.accrued_at_height,
        })
    }

    pub fn rebate_root(&self) -> String {
        private_token_darkpool_hash("REBATE", &[HashPart::Json(&self.public_record())])
    }

    pub fn validate(&self) -> PrivateTokenDarkpoolResult<()> {
        require_non_empty("rebate_id", &self.rebate_id)?;
        require_non_empty("fill_id", &self.fill_id)?;
        require_non_empty("order_id", &self.order_id)?;
        require_non_empty("solver_id", &self.solver_id)?;
        require_non_empty("recipient_commitment", &self.recipient_commitment)?;
        require_non_empty("fee_commitment", &self.fee_commitment)?;
        require_non_empty("rebate_commitment", &self.rebate_commitment)?;
        require_non_empty("rebate_nullifier", &self.rebate_nullifier)?;
        require_non_empty("sponsor_pool_root", &self.sponsor_pool_root)?;
        if self.accrued_units == 0 {
            return Err("private token darkpool rebate units must be positive".to_string());
        }
        if self.claimed_units > self.accrued_units {
            return Err("private token darkpool claimed rebate exceeds accrued".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DarkpoolNullifierSet {
    pub spent_order_nullifiers: BTreeSet<String>,
    pub spent_fill_nullifiers: BTreeSet<String>,
    pub spent_rebate_nullifiers: BTreeSet<String>,
    pub rejected_nullifiers: BTreeSet<String>,
}

impl DarkpoolNullifierSet {
    pub fn new() -> Self {
        Self {
            spent_order_nullifiers: BTreeSet::new(),
            spent_fill_nullifiers: BTreeSet::new(),
            spent_rebate_nullifiers: BTreeSet::new(),
            rejected_nullifiers: BTreeSet::new(),
        }
    }

    pub fn insert_order_nullifier(&mut self, nullifier: &str) -> PrivateTokenDarkpoolResult<()> {
        require_non_empty("order_nullifier", nullifier)?;
        if !self.spent_order_nullifiers.insert(nullifier.to_string()) {
            self.rejected_nullifiers.insert(nullifier.to_string());
            return Err("private token darkpool duplicate order nullifier".to_string());
        }
        Ok(())
    }

    pub fn insert_fill_nullifier(&mut self, nullifier: &str) -> PrivateTokenDarkpoolResult<()> {
        require_non_empty("fill_nullifier", nullifier)?;
        if !self.spent_fill_nullifiers.insert(nullifier.to_string()) {
            self.rejected_nullifiers.insert(nullifier.to_string());
            return Err("private token darkpool duplicate fill nullifier".to_string());
        }
        Ok(())
    }

    pub fn insert_rebate_nullifier(&mut self, nullifier: &str) -> PrivateTokenDarkpoolResult<()> {
        require_non_empty("rebate_nullifier", nullifier)?;
        if !self.spent_rebate_nullifiers.insert(nullifier.to_string()) {
            self.rejected_nullifiers.insert(nullifier.to_string());
            return Err("private token darkpool duplicate rebate nullifier".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "spent_order_nullifier_root": private_token_darkpool_set_root(
                "NULLIFIER-ORDER",
                &self.spent_order_nullifiers,
            ),
            "spent_fill_nullifier_root": private_token_darkpool_set_root(
                "NULLIFIER-FILL",
                &self.spent_fill_nullifiers,
            ),
            "spent_rebate_nullifier_root": private_token_darkpool_set_root(
                "NULLIFIER-REBATE",
                &self.spent_rebate_nullifiers,
            ),
            "rejected_nullifier_root": private_token_darkpool_set_root(
                "NULLIFIER-REJECTED",
                &self.rejected_nullifiers,
            ),
            "spent_order_nullifier_count": self.spent_order_nullifiers.len(),
            "spent_fill_nullifier_count": self.spent_fill_nullifiers.len(),
            "spent_rebate_nullifier_count": self.spent_rebate_nullifiers.len(),
            "rejected_nullifier_count": self.rejected_nullifiers.len(),
        })
    }

    pub fn nullifier_root(&self) -> String {
        private_token_darkpool_hash("NULLIFIER-SET", &[HashPart::Json(&self.public_record())])
    }

    pub fn validate(&self) -> PrivateTokenDarkpoolResult<()> {
        for value in &self.spent_order_nullifiers {
            require_non_empty("spent_order_nullifier", value)?;
        }
        for value in &self.spent_fill_nullifiers {
            require_non_empty("spent_fill_nullifier", value)?;
        }
        for value in &self.spent_rebate_nullifiers {
            require_non_empty("spent_rebate_nullifier", value)?;
        }
        for value in &self.rejected_nullifiers {
            require_non_empty("rejected_nullifier", value)?;
        }
        Ok(())
    }
}

impl Default for DarkpoolNullifierSet {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateTokenDarkpoolEvent {
    pub event_id: String,
    pub event_kind: PrivateTokenDarkpoolEventKind,
    pub subject_id: String,
    pub batch_id: String,
    pub pair_id: String,
    pub event_root: String,
    pub emitted_at_height: u64,
}

impl PrivateTokenDarkpoolEvent {
    pub fn new(
        event_kind: PrivateTokenDarkpoolEventKind,
        subject_id: &str,
        batch_id: &str,
        pair_id: &str,
        emitted_at_height: u64,
    ) -> PrivateTokenDarkpoolResult<Self> {
        require_non_empty("subject_id", subject_id)?;
        let event_id = private_token_darkpool_hash(
            "EVENT-ID",
            &[
                HashPart::Str(event_kind.as_str()),
                HashPart::Str(subject_id),
                HashPart::Str(batch_id),
                HashPart::Str(pair_id),
                HashPart::Int(emitted_at_height as i128),
            ],
        );
        let event_root = private_token_darkpool_hash(
            "EVENT-ROOT",
            &[
                HashPart::Str(&event_id),
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PRIVATE_TOKEN_DARKPOOL_PROTOCOL_VERSION),
            ],
        );
        Ok(Self {
            event_id,
            event_kind,
            subject_id: subject_id.to_string(),
            batch_id: batch_id.to_string(),
            pair_id: pair_id.to_string(),
            event_root,
            emitted_at_height,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "event_id": self.event_id,
            "event_kind": self.event_kind.as_str(),
            "subject_id": self.subject_id,
            "batch_id": self.batch_id,
            "pair_id": self.pair_id,
            "event_root": self.event_root,
            "emitted_at_height": self.emitted_at_height,
        })
    }

    pub fn validate(&self) -> PrivateTokenDarkpoolResult<()> {
        require_non_empty("event_id", &self.event_id)?;
        require_non_empty("subject_id", &self.subject_id)?;
        require_non_empty("event_root", &self.event_root)?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateTokenDarkpoolRoots {
    pub pair_root: String,
    pub solver_root: String,
    pub order_root: String,
    pub batch_root: String,
    pub fill_root: String,
    pub attestation_root: String,
    pub rebate_root: String,
    pub nullifier_root: String,
    pub event_root: String,
}

impl PrivateTokenDarkpoolRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "pair_root": self.pair_root,
            "solver_root": self.solver_root,
            "order_root": self.order_root,
            "batch_root": self.batch_root,
            "fill_root": self.fill_root,
            "attestation_root": self.attestation_root,
            "rebate_root": self.rebate_root,
            "nullifier_root": self.nullifier_root,
            "event_root": self.event_root,
        })
    }

    pub fn roots_root(&self) -> String {
        private_token_darkpool_hash("ROOTS", &[HashPart::Json(&self.public_record())])
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateTokenDarkpoolCounters {
    pub pair_count: u64,
    pub active_pair_count: u64,
    pub solver_count: u64,
    pub active_solver_count: u64,
    pub order_count: u64,
    pub live_order_count: u64,
    pub batch_count: u64,
    pub open_batch_count: u64,
    pub fill_count: u64,
    pub attestation_count: u64,
    pub rebate_count: u64,
    pub event_count: u64,
    pub spent_nullifier_count: u64,
    pub rejected_nullifier_count: u64,
}

impl PrivateTokenDarkpoolCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "pair_count": self.pair_count,
            "active_pair_count": self.active_pair_count,
            "solver_count": self.solver_count,
            "active_solver_count": self.active_solver_count,
            "order_count": self.order_count,
            "live_order_count": self.live_order_count,
            "batch_count": self.batch_count,
            "open_batch_count": self.open_batch_count,
            "fill_count": self.fill_count,
            "attestation_count": self.attestation_count,
            "rebate_count": self.rebate_count,
            "event_count": self.event_count,
            "spent_nullifier_count": self.spent_nullifier_count,
            "rejected_nullifier_count": self.rejected_nullifier_count,
        })
    }

    pub fn counters_root(&self) -> String {
        private_token_darkpool_hash("COUNTERS", &[HashPart::Json(&self.public_record())])
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateTokenDarkpoolState {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub height: u64,
    pub config: PrivateTokenDarkpoolConfig,
    pub pairs: BTreeMap<String, ConfidentialTokenPair>,
    pub solvers: BTreeMap<String, SolverBond>,
    pub orders: BTreeMap<String, SealedDarkpoolOrder>,
    pub batches: BTreeMap<String, DarkpoolAuctionBatch>,
    pub fills: BTreeMap<String, PrivateDarkpoolFill>,
    pub attestations: BTreeMap<String, PqSettlementAttestation>,
    pub rebates: BTreeMap<String, LowFeeRebate>,
    pub nullifiers: DarkpoolNullifierSet,
    pub events: BTreeMap<String, PrivateTokenDarkpoolEvent>,
}

impl PrivateTokenDarkpoolState {
    pub fn new(height: u64, config: PrivateTokenDarkpoolConfig) -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PRIVATE_TOKEN_DARKPOOL_PROTOCOL_VERSION.to_string(),
            schema_version: PRIVATE_TOKEN_DARKPOOL_SCHEMA_VERSION,
            height,
            config,
            pairs: BTreeMap::new(),
            solvers: BTreeMap::new(),
            orders: BTreeMap::new(),
            batches: BTreeMap::new(),
            fills: BTreeMap::new(),
            attestations: BTreeMap::new(),
            rebates: BTreeMap::new(),
            nullifiers: DarkpoolNullifierSet::new(),
            events: BTreeMap::new(),
        }
    }

    pub fn devnet() -> PrivateTokenDarkpoolResult<Self> {
        let config = PrivateTokenDarkpoolConfig::devnet();
        let mut state = Self::new(PRIVATE_TOKEN_DARKPOOL_DEVNET_HEIGHT, config);
        let pair = ConfidentialTokenPair::new(
            "dxmr-dusd-confidential",
            PRIVATE_TOKEN_DARKPOOL_DEVNET_BASE_ASSET,
            PRIVATE_TOKEN_DARKPOOL_DEVNET_QUOTE_ASSET,
            PrivateTokenDarkpoolPairKind::Spot,
            PRIVATE_TOKEN_DARKPOOL_DEVNET_BASE_ASSET,
            state.height,
        )?;
        state.register_pair(pair)?;
        let governance_pair = ConfidentialTokenPair::new(
            "dnr-dusd-governance-darkpool",
            PRIVATE_TOKEN_DARKPOOL_DEVNET_GOVERNANCE_ASSET,
            PRIVATE_TOKEN_DARKPOOL_DEVNET_QUOTE_ASSET,
            PrivateTokenDarkpoolPairKind::Governance,
            PRIVATE_TOKEN_DARKPOOL_DEVNET_BASE_ASSET,
            state.height,
        )?;
        state.register_pair(governance_pair)?;
        let solver = SolverBond::new(
            "solver-devnet-primary",
            "operator-commitment-devnet-primary",
            PRIVATE_TOKEN_DARKPOOL_DEVNET_BASE_ASSET,
            state.config.min_solver_bond_units.saturating_mul(4),
            state.height,
            state.config.bond_ttl_blocks,
        )?;
        state.register_solver(solver)?;
        let batch_id = state.open_batch("dxmr-dusd-confidential")?;
        let order = SealedDarkpoolOrder::new(
            "order-devnet-sealed-0",
            "dxmr-dusd-confidential",
            "account-commitment-devnet-0",
            PrivateTokenDarkpoolOrderSide::BuyBase,
            PrivateTokenDarkpoolOrderKind::Limit,
            "amount-commitment-devnet-0",
            "price-commitment-devnet-0",
            state.height,
            state.config.order_ttl_blocks,
        )?;
        state.submit_order(order, &batch_id)?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) -> PrivateTokenDarkpoolResult<()> {
        if height < self.height {
            return Err("private token darkpool height cannot go backwards".to_string());
        }
        self.height = height;
        Ok(())
    }

    pub fn register_pair(
        &mut self,
        pair: ConfidentialTokenPair,
    ) -> PrivateTokenDarkpoolResult<String> {
        self.ensure_capacity(self.pairs.len(), PRIVATE_TOKEN_DARKPOOL_MAX_PAIRS, "pairs")?;
        pair.validate()?;
        if self.pairs.contains_key(&pair.pair_id) {
            return Err("private token darkpool pair already exists".to_string());
        }
        let pair_id = pair.pair_id.clone();
        self.events.insert(
            private_token_darkpool_hash("EVENT-KEY", &[HashPart::Str(&pair_id)]),
            PrivateTokenDarkpoolEvent::new(
                PrivateTokenDarkpoolEventKind::PairRegistered,
                &pair_id,
                "",
                &pair_id,
                self.height,
            )?,
        );
        self.pairs.insert(pair_id.clone(), pair);
        Ok(pair_id)
    }

    pub fn register_solver(&mut self, solver: SolverBond) -> PrivateTokenDarkpoolResult<String> {
        self.ensure_capacity(
            self.solvers.len(),
            PRIVATE_TOKEN_DARKPOOL_MAX_SOLVERS,
            "solvers",
        )?;
        solver.validate(&self.config)?;
        if self.solvers.contains_key(&solver.solver_id) {
            return Err("private token darkpool solver already exists".to_string());
        }
        let solver_id = solver.solver_id.clone();
        self.events.insert(
            private_token_darkpool_hash("EVENT-KEY", &[HashPart::Str(&solver_id)]),
            PrivateTokenDarkpoolEvent::new(
                PrivateTokenDarkpoolEventKind::SolverBonded,
                &solver_id,
                "",
                "",
                self.height,
            )?,
        );
        self.solvers.insert(solver_id.clone(), solver);
        Ok(solver_id)
    }

    pub fn open_batch(&mut self, pair_id: &str) -> PrivateTokenDarkpoolResult<String> {
        self.ensure_capacity(
            self.batches.len(),
            PRIVATE_TOKEN_DARKPOOL_MAX_BATCHES,
            "batches",
        )?;
        let pair = self
            .pairs
            .get(pair_id)
            .ok_or_else(|| "private token darkpool pair not found".to_string())?;
        if !pair.active {
            return Err("private token darkpool pair is inactive".to_string());
        }
        let batch_id = private_token_darkpool_hash(
            "BATCH-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(pair_id),
                HashPart::Int(self.height as i128),
                HashPart::Int(self.batches.len() as i128),
            ],
        );
        let batch = DarkpoolAuctionBatch::new(&batch_id, pair_id, self.height, &self.config)?;
        self.events.insert(
            private_token_darkpool_hash("EVENT-KEY", &[HashPart::Str(&batch_id)]),
            PrivateTokenDarkpoolEvent::new(
                PrivateTokenDarkpoolEventKind::BatchOpened,
                &batch_id,
                &batch_id,
                pair_id,
                self.height,
            )?,
        );
        self.batches.insert(batch_id.clone(), batch);
        Ok(batch_id)
    }

    pub fn submit_order(
        &mut self,
        mut order: SealedDarkpoolOrder,
        batch_id: &str,
    ) -> PrivateTokenDarkpoolResult<String> {
        self.ensure_capacity(
            self.orders.len(),
            PRIVATE_TOKEN_DARKPOOL_MAX_ORDERS,
            "orders",
        )?;
        order.validate(&self.config)?;
        if self.orders.contains_key(&order.order_id) {
            return Err("private token darkpool order already exists".to_string());
        }
        if !self.pairs.contains_key(&order.pair_id) {
            return Err("private token darkpool order pair not found".to_string());
        }
        let batch = self
            .batches
            .get(batch_id)
            .ok_or_else(|| "private token darkpool batch not found".to_string())?;
        if batch.pair_id != order.pair_id {
            return Err("private token darkpool order pair does not match batch".to_string());
        }
        if !batch.status.accepts_orders() {
            return Err("private token darkpool batch does not accept orders".to_string());
        }
        if self.height > order.expires_at_height {
            return Err("private token darkpool order is expired".to_string());
        }
        self.nullifiers
            .insert_order_nullifier(&order.nullifier_commitment)?;
        let order_id = order.order_id.clone();
        let pair_id = order.pair_id.clone();
        order.assign_batch(batch_id)?;
        self.orders.insert(order_id.clone(), order);
        self.refresh_batch_order_roots(batch_id)?;
        self.events.insert(
            private_token_darkpool_hash("EVENT-KEY", &[HashPart::Str(&order_id)]),
            PrivateTokenDarkpoolEvent::new(
                PrivateTokenDarkpoolEventKind::OrderSealed,
                &order_id,
                batch_id,
                &pair_id,
                self.height,
            )?,
        );
        Ok(order_id)
    }

    pub fn lock_batch_for_solver(
        &mut self,
        batch_id: &str,
        solver_id: &str,
    ) -> PrivateTokenDarkpoolResult<String> {
        let solver = self
            .solvers
            .get(solver_id)
            .ok_or_else(|| "private token darkpool solver not found".to_string())?;
        if !solver.status.can_solve() {
            return Err("private token darkpool solver cannot solve".to_string());
        }
        if solver.available_bond_units() < self.config.min_solver_bond_units {
            return Err("private token darkpool solver available bond below minimum".to_string());
        }
        let batch = self
            .batches
            .get_mut(batch_id)
            .ok_or_else(|| "private token darkpool batch not found".to_string())?;
        batch.lock_for_solving(solver_id, self.height)?;
        Ok(batch.batch_root())
    }

    pub fn clear_batch(
        &mut self,
        batch_id: &str,
        clearing_price_commitment: &str,
        clearing_volume_commitment: &str,
        surplus_commitment: &str,
        proof_root: &str,
    ) -> PrivateTokenDarkpoolResult<String> {
        let pair_id = {
            let batch = self
                .batches
                .get_mut(batch_id)
                .ok_or_else(|| "private token darkpool batch not found".to_string())?;
            batch.mark_cleared(
                clearing_price_commitment,
                clearing_volume_commitment,
                surplus_commitment,
                proof_root,
            )?;
            batch.pair_id.clone()
        };
        self.events.insert(
            private_token_darkpool_hash("EVENT-KEY", &[HashPart::Str(batch_id)]),
            PrivateTokenDarkpoolEvent::new(
                PrivateTokenDarkpoolEventKind::BatchCleared,
                batch_id,
                batch_id,
                &pair_id,
                self.height,
            )?,
        );
        self.batches
            .get(batch_id)
            .map(DarkpoolAuctionBatch::batch_root)
            .ok_or_else(|| "private token darkpool batch not found".to_string())
    }

    pub fn add_fill(&mut self, fill: PrivateDarkpoolFill) -> PrivateTokenDarkpoolResult<String> {
        self.ensure_capacity(self.fills.len(), PRIVATE_TOKEN_DARKPOOL_MAX_FILLS, "fills")?;
        fill.validate()?;
        if self.fills.contains_key(&fill.fill_id) {
            return Err("private token darkpool fill already exists".to_string());
        }
        if !self.batches.contains_key(&fill.batch_id) {
            return Err("private token darkpool fill batch not found".to_string());
        }
        if !self.orders.contains_key(&fill.order_id) {
            return Err("private token darkpool fill order not found".to_string());
        }
        if !self.solvers.contains_key(&fill.solver_id) {
            return Err("private token darkpool fill solver not found".to_string());
        }
        self.nullifiers
            .insert_fill_nullifier(&fill.fill_nullifier)?;
        let fill_id = fill.fill_id.clone();
        self.events.insert(
            private_token_darkpool_hash("EVENT-KEY", &[HashPart::Str(&fill_id)]),
            PrivateTokenDarkpoolEvent::new(
                PrivateTokenDarkpoolEventKind::SettlementFinalized,
                &fill_id,
                &fill.batch_id,
                &fill.pair_id,
                self.height,
            )?,
        );
        self.fills.insert(fill_id.clone(), fill);
        Ok(fill_id)
    }

    pub fn add_attestation(
        &mut self,
        attestation: PqSettlementAttestation,
    ) -> PrivateTokenDarkpoolResult<String> {
        self.ensure_capacity(
            self.attestations.len(),
            PRIVATE_TOKEN_DARKPOOL_MAX_ATTESTATIONS,
            "attestations",
        )?;
        attestation.validate(&self.config)?;
        if self.attestations.contains_key(&attestation.attestation_id) {
            return Err("private token darkpool attestation already exists".to_string());
        }
        if !self.batches.contains_key(&attestation.batch_id) {
            return Err("private token darkpool attestation batch not found".to_string());
        }
        if !self.solvers.contains_key(&attestation.solver_id) {
            return Err("private token darkpool attestation solver not found".to_string());
        }
        let attestation_id = attestation.attestation_id.clone();
        self.events.insert(
            private_token_darkpool_hash("EVENT-KEY", &[HashPart::Str(&attestation_id)]),
            PrivateTokenDarkpoolEvent::new(
                PrivateTokenDarkpoolEventKind::FillAttested,
                &attestation_id,
                &attestation.batch_id,
                "",
                self.height,
            )?,
        );
        self.attestations
            .insert(attestation_id.clone(), attestation);
        Ok(attestation_id)
    }

    pub fn accrue_rebate(&mut self, rebate: LowFeeRebate) -> PrivateTokenDarkpoolResult<String> {
        self.ensure_capacity(
            self.rebates.len(),
            PRIVATE_TOKEN_DARKPOOL_MAX_REBATES,
            "rebates",
        )?;
        rebate.validate()?;
        if self.rebates.contains_key(&rebate.rebate_id) {
            return Err("private token darkpool rebate already exists".to_string());
        }
        if !self.fills.contains_key(&rebate.fill_id) {
            return Err("private token darkpool rebate fill not found".to_string());
        }
        self.nullifiers
            .insert_rebate_nullifier(&rebate.rebate_nullifier)?;
        let rebate_id = rebate.rebate_id.clone();
        self.events.insert(
            private_token_darkpool_hash("EVENT-KEY", &[HashPart::Str(&rebate_id)]),
            PrivateTokenDarkpoolEvent::new(
                PrivateTokenDarkpoolEventKind::RebateAccrued,
                &rebate_id,
                "",
                "",
                self.height,
            )?,
        );
        self.rebates.insert(rebate_id.clone(), rebate);
        Ok(rebate_id)
    }

    pub fn slash_solver(
        &mut self,
        solver_id: &str,
        reason_root: &str,
    ) -> PrivateTokenDarkpoolResult<String> {
        require_non_empty("solver_id", solver_id)?;
        require_non_empty("reason_root", reason_root)?;
        let solver = self
            .solvers
            .get_mut(solver_id)
            .ok_or_else(|| "private token darkpool solver not found".to_string())?;
        let slash_units = solver
            .bonded_units
            .saturating_mul(self.config.slash_bps)
            .saturating_div(PRIVATE_TOKEN_DARKPOOL_MAX_BPS);
        solver.slashed_units = solver
            .bonded_units
            .min(solver.slashed_units.saturating_add(slash_units));
        solver.status = PrivateTokenDarkpoolSolverStatus::Slashed;
        let event = PrivateTokenDarkpoolEvent::new(
            PrivateTokenDarkpoolEventKind::SolverSlashed,
            solver_id,
            reason_root,
            "",
            self.height,
        )?;
        let event_id = event.event_id.clone();
        self.events.insert(event_id.clone(), event);
        Ok(event_id)
    }

    pub fn roots(&self) -> PrivateTokenDarkpoolRoots {
        PrivateTokenDarkpoolRoots {
            pair_root: private_token_darkpool_map_root(
                "PAIR-MAP",
                self.pairs
                    .values()
                    .map(ConfidentialTokenPair::public_record)
                    .collect(),
            ),
            solver_root: private_token_darkpool_map_root(
                "SOLVER-MAP",
                self.solvers
                    .values()
                    .map(SolverBond::public_record)
                    .collect(),
            ),
            order_root: private_token_darkpool_map_root(
                "ORDER-MAP",
                self.orders
                    .values()
                    .map(SealedDarkpoolOrder::public_record)
                    .collect(),
            ),
            batch_root: private_token_darkpool_map_root(
                "BATCH-MAP",
                self.batches
                    .values()
                    .map(DarkpoolAuctionBatch::public_record)
                    .collect(),
            ),
            fill_root: private_token_darkpool_map_root(
                "FILL-MAP",
                self.fills
                    .values()
                    .map(PrivateDarkpoolFill::public_record)
                    .collect(),
            ),
            attestation_root: private_token_darkpool_map_root(
                "ATTESTATION-MAP",
                self.attestations
                    .values()
                    .map(PqSettlementAttestation::public_record)
                    .collect(),
            ),
            rebate_root: private_token_darkpool_map_root(
                "REBATE-MAP",
                self.rebates
                    .values()
                    .map(LowFeeRebate::public_record)
                    .collect(),
            ),
            nullifier_root: self.nullifiers.nullifier_root(),
            event_root: private_token_darkpool_map_root(
                "EVENT-MAP",
                self.events
                    .values()
                    .map(PrivateTokenDarkpoolEvent::public_record)
                    .collect(),
            ),
        }
    }

    pub fn counters(&self) -> PrivateTokenDarkpoolCounters {
        let spent_nullifier_count = self
            .nullifiers
            .spent_order_nullifiers
            .len()
            .saturating_add(self.nullifiers.spent_fill_nullifiers.len())
            .saturating_add(self.nullifiers.spent_rebate_nullifiers.len());
        PrivateTokenDarkpoolCounters {
            pair_count: self.pairs.len() as u64,
            active_pair_count: self.pairs.values().filter(|pair| pair.active).count() as u64,
            solver_count: self.solvers.len() as u64,
            active_solver_count: self
                .solvers
                .values()
                .filter(|solver| solver.status.can_solve())
                .count() as u64,
            order_count: self.orders.len() as u64,
            live_order_count: self
                .orders
                .values()
                .filter(|order| order.status.is_live())
                .count() as u64,
            batch_count: self.batches.len() as u64,
            open_batch_count: self
                .batches
                .values()
                .filter(|batch| {
                    batch.status.accepts_orders() || batch.status.requires_attestation()
                })
                .count() as u64,
            fill_count: self.fills.len() as u64,
            attestation_count: self.attestations.len() as u64,
            rebate_count: self.rebates.len() as u64,
            event_count: self.events.len() as u64,
            spent_nullifier_count: spent_nullifier_count as u64,
            rejected_nullifier_count: self.nullifiers.rejected_nullifiers.len() as u64,
        }
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        let counters = self.counters();
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "height": self.height,
            "config": self.config.public_record(),
            "roots": roots.public_record(),
            "roots_root": roots.roots_root(),
            "counters": counters.public_record(),
            "counters_root": counters.counters_root(),
            "state_root": self.state_root_without_record(),
        })
    }

    pub fn state_root(&self) -> String {
        private_token_darkpool_hash("STATE", &[HashPart::Json(&self.public_record())])
    }

    pub fn validate(&self) -> PrivateTokenDarkpoolResult<()> {
        if self.chain_id != CHAIN_ID {
            return Err("private token darkpool chain id mismatch".to_string());
        }
        if self.protocol_version != PRIVATE_TOKEN_DARKPOOL_PROTOCOL_VERSION {
            return Err("private token darkpool protocol version mismatch".to_string());
        }
        if self.schema_version != PRIVATE_TOKEN_DARKPOOL_SCHEMA_VERSION {
            return Err("private token darkpool schema version mismatch".to_string());
        }
        self.config.validate()?;
        if self.pairs.len() > PRIVATE_TOKEN_DARKPOOL_MAX_PAIRS
            || self.solvers.len() > PRIVATE_TOKEN_DARKPOOL_MAX_SOLVERS
            || self.batches.len() > PRIVATE_TOKEN_DARKPOOL_MAX_BATCHES
            || self.orders.len() > PRIVATE_TOKEN_DARKPOOL_MAX_ORDERS
            || self.fills.len() > PRIVATE_TOKEN_DARKPOOL_MAX_FILLS
            || self.attestations.len() > PRIVATE_TOKEN_DARKPOOL_MAX_ATTESTATIONS
            || self.rebates.len() > PRIVATE_TOKEN_DARKPOOL_MAX_REBATES
            || self.events.len() > PRIVATE_TOKEN_DARKPOOL_MAX_EVENTS
        {
            return Err("private token darkpool state exceeds configured limits".to_string());
        }
        for pair in self.pairs.values() {
            pair.validate()?;
        }
        for solver in self.solvers.values() {
            solver.validate(&self.config)?;
        }
        for order in self.orders.values() {
            order.validate(&self.config)?;
            if !self.pairs.contains_key(&order.pair_id) {
                return Err("private token darkpool order references missing pair".to_string());
            }
            if !order.batch_id.is_empty() && !self.batches.contains_key(&order.batch_id) {
                return Err("private token darkpool order references missing batch".to_string());
            }
        }
        for batch in self.batches.values() {
            batch.validate(&self.config)?;
            if !self.pairs.contains_key(&batch.pair_id) {
                return Err("private token darkpool batch references missing pair".to_string());
            }
            if !batch.selected_solver_id.is_empty()
                && !self.solvers.contains_key(&batch.selected_solver_id)
            {
                return Err("private token darkpool batch references missing solver".to_string());
            }
        }
        for fill in self.fills.values() {
            fill.validate()?;
            if !self.batches.contains_key(&fill.batch_id)
                || !self.orders.contains_key(&fill.order_id)
                || !self.solvers.contains_key(&fill.solver_id)
            {
                return Err("private token darkpool fill references missing state".to_string());
            }
        }
        for attestation in self.attestations.values() {
            attestation.validate(&self.config)?;
        }
        for rebate in self.rebates.values() {
            rebate.validate()?;
        }
        for event in self.events.values() {
            event.validate()?;
        }
        self.nullifiers.validate()?;
        self.validate_unique_public_sets()?;
        Ok(())
    }

    fn refresh_batch_order_roots(&mut self, batch_id: &str) -> PrivateTokenDarkpoolResult<()> {
        let batch = self
            .batches
            .get_mut(batch_id)
            .ok_or_else(|| "private token darkpool batch not found".to_string())?;
        batch.ingest_order_roots(&self.orders)
    }

    fn validate_unique_public_sets(&self) -> PrivateTokenDarkpoolResult<()> {
        let mut order_nullifiers = BTreeSet::new();
        for order in self.orders.values() {
            if !order_nullifiers.insert(order.nullifier_commitment.clone()) {
                return Err("private token darkpool duplicate order nullifier".to_string());
            }
        }
        let mut fill_nullifiers = BTreeSet::new();
        for fill in self.fills.values() {
            if !fill_nullifiers.insert(fill.fill_nullifier.clone()) {
                return Err("private token darkpool duplicate fill nullifier".to_string());
            }
        }
        let mut rebate_nullifiers = BTreeSet::new();
        for rebate in self.rebates.values() {
            if !rebate_nullifiers.insert(rebate.rebate_nullifier.clone()) {
                return Err("private token darkpool duplicate rebate nullifier".to_string());
            }
        }
        Ok(())
    }

    fn ensure_capacity(
        &self,
        current_len: usize,
        max_len: usize,
        label: &str,
    ) -> PrivateTokenDarkpoolResult<()> {
        if current_len >= max_len {
            return Err(format!("private token darkpool {label} capacity exhausted"));
        }
        Ok(())
    }

    fn state_root_without_record(&self) -> String {
        let roots = self.roots();
        let counters = self.counters();
        private_token_darkpool_hash(
            "STATE-SUMMARY",
            &[
                HashPart::Str(&self.chain_id),
                HashPart::Str(&self.protocol_version),
                HashPart::Int(self.schema_version as i128),
                HashPart::Int(self.height as i128),
                HashPart::Str(&self.config.config_root()),
                HashPart::Str(&roots.roots_root()),
                HashPart::Str(&counters.counters_root()),
            ],
        )
    }
}

pub fn private_token_darkpool_hash(domain: &str, parts: &[HashPart<'_>]) -> String {
    let full_domain = format!("PRIVATE-TOKEN-DARKPOOL:{domain}");
    let context = json!({
        "chain_id": CHAIN_ID,
        "protocol_version": PRIVATE_TOKEN_DARKPOOL_PROTOCOL_VERSION,
    });
    domain_hash(
        &full_domain,
        &[HashPart::Json(&context), HashPart::Bytes(&[])],
        32,
    )
    .chars()
    .chain(domain_hash(&full_domain, parts, 32).chars())
    .skip(64)
    .collect()
}

pub fn private_token_darkpool_payload_root(domain: &str, payload: &Value) -> String {
    private_token_darkpool_hash(domain, &[HashPart::Json(payload)])
}

pub fn private_token_darkpool_string_root(domain: &str, values: &[&str]) -> String {
    let leaves = values
        .iter()
        .map(|value| json!({ "value": value }))
        .collect::<Vec<_>>();
    merkle_root(&format!("PRIVATE-TOKEN-DARKPOOL:{domain}"), &leaves)
}

pub fn private_token_darkpool_owned_string_root(domain: &str, values: &[String]) -> String {
    let leaves = values
        .iter()
        .map(|value| json!({ "value": value }))
        .collect::<Vec<_>>();
    merkle_root(&format!("PRIVATE-TOKEN-DARKPOOL:{domain}"), &leaves)
}

pub fn private_token_darkpool_set_root(domain: &str, values: &BTreeSet<String>) -> String {
    let leaves = values
        .iter()
        .map(|value| json!({ "value": value }))
        .collect::<Vec<_>>();
    merkle_root(&format!("PRIVATE-TOKEN-DARKPOOL:{domain}"), &leaves)
}

pub fn private_token_darkpool_map_root(domain: &str, leaves: Vec<Value>) -> String {
    merkle_root(&format!("PRIVATE-TOKEN-DARKPOOL:{domain}"), &leaves)
}

fn require_non_empty(label: &str, value: &str) -> PrivateTokenDarkpoolResult<()> {
    if value.is_empty() {
        return Err(format!("private token darkpool {label} must be populated"));
    }
    Ok(())
}
