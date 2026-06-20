use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateDefiLiquidityCohesionOrchestratorResult<T> = Result<T, String>;

pub const PRIVATE_DEFI_LIQUIDITY_COHESION_ORCHESTRATOR_PROTOCOL_VERSION: &str =
    "nebula-private-defi-liquidity-cohesion-orchestrator-v1";
pub const PRIVATE_DEFI_LIQUIDITY_COHESION_ORCHESTRATOR_HASH_SUITE: &str =
    "SHAKE256-domain-separated";
pub const PRIVATE_DEFI_LIQUIDITY_COHESION_ORCHESTRATOR_PRIVACY_PROOF_SYSTEM: &str =
    "zk-private-liquidity-cohesion-v1";
pub const PRIVATE_DEFI_LIQUIDITY_COHESION_ORCHESTRATOR_NETTING_PROOF_SYSTEM: &str =
    "zk-confidential-swap-netting-v1";
pub const PRIVATE_DEFI_LIQUIDITY_COHESION_ORCHESTRATOR_LIQUIDATION_PROOF_SYSTEM: &str =
    "zk-private-liquidation-circuit-v1";
pub const PRIVATE_DEFI_LIQUIDITY_COHESION_ORCHESTRATOR_PQ_SIGNATURE_SCHEME: &str = "ML-DSA-87";
pub const PRIVATE_DEFI_LIQUIDITY_COHESION_ORCHESTRATOR_PQ_KEM_SCHEME: &str = "ML-KEM-1024";
pub const PRIVATE_DEFI_LIQUIDITY_COHESION_ORCHESTRATOR_DEVNET_HEIGHT: u64 = 1_728;
pub const PRIVATE_DEFI_LIQUIDITY_COHESION_ORCHESTRATOR_DEVNET_EPOCH: u64 = 12;
pub const PRIVATE_DEFI_LIQUIDITY_COHESION_ORCHESTRATOR_MAX_BPS: u64 = 10_000;
pub const PRIVATE_DEFI_LIQUIDITY_COHESION_ORCHESTRATOR_DEFAULT_EPOCH_BLOCKS: u64 = 720;
pub const PRIVATE_DEFI_LIQUIDITY_COHESION_ORCHESTRATOR_DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 1_024;
pub const PRIVATE_DEFI_LIQUIDITY_COHESION_ORCHESTRATOR_DEFAULT_MAX_FEE_BPS: u64 = 90;
pub const PRIVATE_DEFI_LIQUIDITY_COHESION_ORCHESTRATOR_DEFAULT_MAX_EDGE_RISK_BPS: u64 = 6_500;
pub const PRIVATE_DEFI_LIQUIDITY_COHESION_ORCHESTRATOR_DEFAULT_MAX_POOL_RISK_BPS: u64 = 7_250;
pub const PRIVATE_DEFI_LIQUIDITY_COHESION_ORCHESTRATOR_DEFAULT_MIN_CREDIT_SCORE: u64 = 620;
pub const PRIVATE_DEFI_LIQUIDITY_COHESION_ORCHESTRATOR_DEFAULT_LIQUIDATION_DELAY_BLOCKS: u64 = 18;
pub const PRIVATE_DEFI_LIQUIDITY_COHESION_ORCHESTRATOR_DEFAULT_RECEIPT_TTL_BLOCKS: u64 = 144;
pub const PRIVATE_DEFI_LIQUIDITY_COHESION_ORCHESTRATOR_MAX_MARKETS: usize = 131_072;
pub const PRIVATE_DEFI_LIQUIDITY_COHESION_ORCHESTRATOR_MAX_EDGES: usize = 262_144;
pub const PRIVATE_DEFI_LIQUIDITY_COHESION_ORCHESTRATOR_MAX_RISK_CAPS: usize = 131_072;
pub const PRIVATE_DEFI_LIQUIDITY_COHESION_ORCHESTRATOR_MAX_FEE_CEILINGS: usize = 131_072;
pub const PRIVATE_DEFI_LIQUIDITY_COHESION_ORCHESTRATOR_MAX_PRIVACY_BUCKETS: usize = 65_536;
pub const PRIVATE_DEFI_LIQUIDITY_COHESION_ORCHESTRATOR_MAX_NETTING_BATCHES: usize = 131_072;
pub const PRIVATE_DEFI_LIQUIDITY_COHESION_ORCHESTRATOR_MAX_RECEIPTS: usize = 262_144;
pub const PRIVATE_DEFI_LIQUIDITY_COHESION_ORCHESTRATOR_MAX_INCENTIVE_EPOCHS: usize = 65_536;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MarketKind {
    PrivateAmm,
    PrivateStableSwap,
    PrivateLending,
    PrivateVault,
    PrivateDerivative,
    PrivateCreditScore,
    PrivateLiquidationCircuit,
}

impl MarketKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrivateAmm => "private_amm",
            Self::PrivateStableSwap => "private_stable_swap",
            Self::PrivateLending => "private_lending",
            Self::PrivateVault => "private_vault",
            Self::PrivateDerivative => "private_derivative",
            Self::PrivateCreditScore => "private_credit_score",
            Self::PrivateLiquidationCircuit => "private_liquidation_circuit",
        }
    }

    pub fn needs_credit_score(self) -> bool {
        matches!(
            self,
            Self::PrivateLending | Self::PrivateVault | Self::PrivateDerivative
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EdgeKind {
    SwapRoute,
    StableSwapPegRoute,
    LendingCollateral,
    LendingDebt,
    VaultShare,
    DerivativeMargin,
    LiquidationBackstop,
    IncentiveFlow,
}

impl EdgeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SwapRoute => "swap_route",
            Self::StableSwapPegRoute => "stable_swap_peg_route",
            Self::LendingCollateral => "lending_collateral",
            Self::LendingDebt => "lending_debt",
            Self::VaultShare => "vault_share",
            Self::DerivativeMargin => "derivative_margin",
            Self::LiquidationBackstop => "liquidation_backstop",
            Self::IncentiveFlow => "incentive_flow",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivacyBucketKind {
    SwapInput,
    SwapOutput,
    LendingPosition,
    VaultPosition,
    DerivativePosition,
    LiquidationCandidate,
    IncentiveClaim,
}

impl PrivacyBucketKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SwapInput => "swap_input",
            Self::SwapOutput => "swap_output",
            Self::LendingPosition => "lending_position",
            Self::VaultPosition => "vault_position",
            Self::DerivativePosition => "derivative_position",
            Self::LiquidationCandidate => "liquidation_candidate",
            Self::IncentiveClaim => "incentive_claim",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CircuitStatus {
    Draft,
    Active,
    Guarded,
    Halted,
    Settling,
    Retired,
}

impl CircuitStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Active => "active",
            Self::Guarded => "guarded",
            Self::Halted => "halted",
            Self::Settling => "settling",
            Self::Retired => "retired",
        }
    }

    pub fn accepts_flow(self) -> bool {
        matches!(self, Self::Active | Self::Guarded | Self::Settling)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptKind {
    SwapNetting,
    LiquidityMove,
    CreditUpdate,
    LiquidationCircuit,
    IncentiveAccrual,
    RiskRebalance,
}

impl ReceiptKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SwapNetting => "swap_netting",
            Self::LiquidityMove => "liquidity_move",
            Self::CreditUpdate => "credit_update",
            Self::LiquidationCircuit => "liquidation_circuit",
            Self::IncentiveAccrual => "incentive_accrual",
            Self::RiskRebalance => "risk_rebalance",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Config {
    pub protocol_version: String,
    pub chain_id: String,
    pub epoch_blocks: u64,
    pub min_privacy_set_size: u64,
    pub max_fee_bps: u64,
    pub max_edge_risk_bps: u64,
    pub max_pool_risk_bps: u64,
    pub min_credit_score: u64,
    pub liquidation_delay_blocks: u64,
    pub receipt_ttl_blocks: u64,
    pub pq_signature_scheme: String,
    pub pq_kem_scheme: String,
    pub privacy_proof_system: String,
    pub netting_proof_system: String,
    pub liquidation_proof_system: String,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version: PRIVATE_DEFI_LIQUIDITY_COHESION_ORCHESTRATOR_PROTOCOL_VERSION
                .to_string(),
            chain_id: CHAIN_ID.to_string(),
            epoch_blocks: PRIVATE_DEFI_LIQUIDITY_COHESION_ORCHESTRATOR_DEFAULT_EPOCH_BLOCKS,
            min_privacy_set_size:
                PRIVATE_DEFI_LIQUIDITY_COHESION_ORCHESTRATOR_DEFAULT_MIN_PRIVACY_SET_SIZE,
            max_fee_bps: PRIVATE_DEFI_LIQUIDITY_COHESION_ORCHESTRATOR_DEFAULT_MAX_FEE_BPS,
            max_edge_risk_bps:
                PRIVATE_DEFI_LIQUIDITY_COHESION_ORCHESTRATOR_DEFAULT_MAX_EDGE_RISK_BPS,
            max_pool_risk_bps:
                PRIVATE_DEFI_LIQUIDITY_COHESION_ORCHESTRATOR_DEFAULT_MAX_POOL_RISK_BPS,
            min_credit_score: PRIVATE_DEFI_LIQUIDITY_COHESION_ORCHESTRATOR_DEFAULT_MIN_CREDIT_SCORE,
            liquidation_delay_blocks:
                PRIVATE_DEFI_LIQUIDITY_COHESION_ORCHESTRATOR_DEFAULT_LIQUIDATION_DELAY_BLOCKS,
            receipt_ttl_blocks:
                PRIVATE_DEFI_LIQUIDITY_COHESION_ORCHESTRATOR_DEFAULT_RECEIPT_TTL_BLOCKS,
            pq_signature_scheme: PRIVATE_DEFI_LIQUIDITY_COHESION_ORCHESTRATOR_PQ_SIGNATURE_SCHEME
                .to_string(),
            pq_kem_scheme: PRIVATE_DEFI_LIQUIDITY_COHESION_ORCHESTRATOR_PQ_KEM_SCHEME.to_string(),
            privacy_proof_system: PRIVATE_DEFI_LIQUIDITY_COHESION_ORCHESTRATOR_PRIVACY_PROOF_SYSTEM
                .to_string(),
            netting_proof_system: PRIVATE_DEFI_LIQUIDITY_COHESION_ORCHESTRATOR_NETTING_PROOF_SYSTEM
                .to_string(),
            liquidation_proof_system:
                PRIVATE_DEFI_LIQUIDITY_COHESION_ORCHESTRATOR_LIQUIDATION_PROOF_SYSTEM.to_string(),
        }
    }

    pub fn validate(&self) -> PrivateDefiLiquidityCohesionOrchestratorResult<()> {
        require_non_empty("protocol_version", &self.protocol_version)?;
        require_non_empty("chain_id", &self.chain_id)?;
        require_non_empty("pq_signature_scheme", &self.pq_signature_scheme)?;
        require_non_empty("pq_kem_scheme", &self.pq_kem_scheme)?;
        require_non_empty("privacy_proof_system", &self.privacy_proof_system)?;
        require_non_empty("netting_proof_system", &self.netting_proof_system)?;
        require_non_empty("liquidation_proof_system", &self.liquidation_proof_system)?;
        require_positive("epoch_blocks", self.epoch_blocks)?;
        require_positive("min_privacy_set_size", self.min_privacy_set_size)?;
        require_bps("max_fee_bps", self.max_fee_bps)?;
        require_bps("max_edge_risk_bps", self.max_edge_risk_bps)?;
        require_bps("max_pool_risk_bps", self.max_pool_risk_bps)?;
        require_positive("min_credit_score", self.min_credit_score)?;
        require_positive("liquidation_delay_blocks", self.liquidation_delay_blocks)?;
        require_positive("receipt_ttl_blocks", self.receipt_ttl_blocks)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.protocol_version,
            "chain_id": self.chain_id,
            "epoch_blocks": self.epoch_blocks.to_string(),
            "min_privacy_set_size": self.min_privacy_set_size.to_string(),
            "max_fee_bps": self.max_fee_bps.to_string(),
            "max_edge_risk_bps": self.max_edge_risk_bps.to_string(),
            "max_pool_risk_bps": self.max_pool_risk_bps.to_string(),
            "min_credit_score": self.min_credit_score.to_string(),
            "liquidation_delay_blocks": self.liquidation_delay_blocks.to_string(),
            "receipt_ttl_blocks": self.receipt_ttl_blocks.to_string(),
            "pq_signature_scheme": self.pq_signature_scheme,
            "pq_kem_scheme": self.pq_kem_scheme,
            "privacy_proof_system": self.privacy_proof_system,
            "netting_proof_system": self.netting_proof_system,
            "liquidation_proof_system": self.liquidation_proof_system,
        })
    }

    pub fn root(&self) -> String {
        hash_json("COHESION-CONFIG", &self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Market {
    pub market_id: String,
    pub kind: MarketKind,
    pub operator_commitment: String,
    pub asset_root: String,
    pub reserve_commitment_root: String,
    pub privacy_bucket_id: String,
    pub status: CircuitStatus,
    pub fee_bps: u64,
    pub risk_bps: u64,
    pub credit_floor: u64,
    pub metadata_root: String,
}

impl Market {
    pub fn new(
        market_id: &str,
        kind: MarketKind,
        operator_commitment: &str,
        asset_root: &str,
        privacy_bucket_id: &str,
        fee_bps: u64,
        risk_bps: u64,
        credit_floor: u64,
    ) -> Self {
        let reserve_commitment_root = hash_str("COHESION-MARKET-RESERVE", market_id);
        let metadata_root = hash_pair("COHESION-MARKET-METADATA", market_id, kind.as_str());
        Self {
            market_id: market_id.to_string(),
            kind,
            operator_commitment: operator_commitment.to_string(),
            asset_root: asset_root.to_string(),
            reserve_commitment_root,
            privacy_bucket_id: privacy_bucket_id.to_string(),
            status: CircuitStatus::Active,
            fee_bps,
            risk_bps,
            credit_floor,
            metadata_root,
        }
    }

    pub fn validate(&self, config: &Config) -> PrivateDefiLiquidityCohesionOrchestratorResult<()> {
        require_non_empty("market_id", &self.market_id)?;
        require_non_empty("operator_commitment", &self.operator_commitment)?;
        require_non_empty("asset_root", &self.asset_root)?;
        require_non_empty("reserve_commitment_root", &self.reserve_commitment_root)?;
        require_non_empty("privacy_bucket_id", &self.privacy_bucket_id)?;
        require_non_empty("metadata_root", &self.metadata_root)?;
        require_bps("market.fee_bps", self.fee_bps)?;
        require_bps("market.risk_bps", self.risk_bps)?;
        if self.fee_bps > config.max_fee_bps {
            return Err(format!("market {} exceeds fee ceiling", self.market_id));
        }
        if self.risk_bps > config.max_pool_risk_bps {
            return Err(format!("market {} exceeds risk cap", self.market_id));
        }
        if self.kind.needs_credit_score() && self.credit_floor < config.min_credit_score {
            return Err(format!("market {} credit floor is too low", self.market_id));
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "market_id": self.market_id,
            "kind": self.kind.as_str(),
            "operator_commitment": self.operator_commitment,
            "asset_root": self.asset_root,
            "reserve_commitment_root": self.reserve_commitment_root,
            "privacy_bucket_id": self.privacy_bucket_id,
            "status": self.status.as_str(),
            "accepts_flow": if self.status.accepts_flow() { "true" } else { "false" },
            "fee_bps": self.fee_bps.to_string(),
            "risk_bps": self.risk_bps.to_string(),
            "credit_floor": self.credit_floor.to_string(),
            "metadata_root": self.metadata_root,
        })
    }

    pub fn root(&self) -> String {
        domain_hash(
            "COHESION-MARKET",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&self.market_id),
                HashPart::Str(self.kind.as_str()),
                HashPart::Str(&self.operator_commitment),
                HashPart::Str(&self.asset_root),
                HashPart::Str(&self.reserve_commitment_root),
                HashPart::Str(&self.privacy_bucket_id),
                HashPart::Str(self.status.as_str()),
                HashPart::Str(&self.fee_bps.to_string()),
                HashPart::Str(&self.risk_bps.to_string()),
                HashPart::Str(&self.credit_floor.to_string()),
                HashPart::Str(&self.metadata_root),
            ],
            32,
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct LiquidityEdge {
    pub edge_id: String,
    pub kind: EdgeKind,
    pub from_market_id: String,
    pub to_market_id: String,
    pub asset_pair_root: String,
    pub capacity_commitment_root: String,
    pub fee_ceiling_id: String,
    pub risk_cap_id: String,
    pub privacy_bucket_id: String,
    pub netting_enabled: bool,
    pub status: CircuitStatus,
}

impl LiquidityEdge {
    pub fn new(
        edge_id: &str,
        kind: EdgeKind,
        from_market_id: &str,
        to_market_id: &str,
        asset_pair_root: &str,
        fee_ceiling_id: &str,
        risk_cap_id: &str,
        privacy_bucket_id: &str,
    ) -> Self {
        Self {
            edge_id: edge_id.to_string(),
            kind,
            from_market_id: from_market_id.to_string(),
            to_market_id: to_market_id.to_string(),
            asset_pair_root: asset_pair_root.to_string(),
            capacity_commitment_root: hash_pair("COHESION-EDGE-CAPACITY", edge_id, asset_pair_root),
            fee_ceiling_id: fee_ceiling_id.to_string(),
            risk_cap_id: risk_cap_id.to_string(),
            privacy_bucket_id: privacy_bucket_id.to_string(),
            netting_enabled: true,
            status: CircuitStatus::Active,
        }
    }

    pub fn validate(&self) -> PrivateDefiLiquidityCohesionOrchestratorResult<()> {
        require_non_empty("edge_id", &self.edge_id)?;
        require_non_empty("from_market_id", &self.from_market_id)?;
        require_non_empty("to_market_id", &self.to_market_id)?;
        require_non_empty("asset_pair_root", &self.asset_pair_root)?;
        require_non_empty("capacity_commitment_root", &self.capacity_commitment_root)?;
        require_non_empty("fee_ceiling_id", &self.fee_ceiling_id)?;
        require_non_empty("risk_cap_id", &self.risk_cap_id)?;
        require_non_empty("privacy_bucket_id", &self.privacy_bucket_id)?;
        if self.from_market_id == self.to_market_id {
            return Err(format!("edge {} loops to same market", self.edge_id));
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "edge_id": self.edge_id,
            "kind": self.kind.as_str(),
            "from_market_id": self.from_market_id,
            "to_market_id": self.to_market_id,
            "asset_pair_root": self.asset_pair_root,
            "capacity_commitment_root": self.capacity_commitment_root,
            "fee_ceiling_id": self.fee_ceiling_id,
            "risk_cap_id": self.risk_cap_id,
            "privacy_bucket_id": self.privacy_bucket_id,
            "netting_enabled": if self.netting_enabled { "true" } else { "false" },
            "status": self.status.as_str(),
        })
    }

    pub fn root(&self) -> String {
        hash_json("COHESION-LIQUIDITY-EDGE", &self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RiskCap {
    pub cap_id: String,
    pub market_id: String,
    pub edge_id: String,
    pub max_risk_bps: u64,
    pub max_notional_commitment_root: String,
    pub oracle_attestation_root: String,
    pub guardrail_root: String,
    pub status: CircuitStatus,
}

impl RiskCap {
    pub fn new(cap_id: &str, market_id: &str, edge_id: &str, max_risk_bps: u64) -> Self {
        Self {
            cap_id: cap_id.to_string(),
            market_id: market_id.to_string(),
            edge_id: edge_id.to_string(),
            max_risk_bps,
            max_notional_commitment_root: hash_str("COHESION-RISK-NOTIONAL", cap_id),
            oracle_attestation_root: hash_str("COHESION-RISK-ORACLE", cap_id),
            guardrail_root: hash_pair("COHESION-RISK-GUARDRAIL", market_id, edge_id),
            status: CircuitStatus::Active,
        }
    }

    pub fn validate(&self, config: &Config) -> PrivateDefiLiquidityCohesionOrchestratorResult<()> {
        require_non_empty("cap_id", &self.cap_id)?;
        require_non_empty("market_id", &self.market_id)?;
        require_non_empty("edge_id", &self.edge_id)?;
        require_bps("risk_cap.max_risk_bps", self.max_risk_bps)?;
        require_non_empty(
            "max_notional_commitment_root",
            &self.max_notional_commitment_root,
        )?;
        require_non_empty("oracle_attestation_root", &self.oracle_attestation_root)?;
        require_non_empty("guardrail_root", &self.guardrail_root)?;
        if self.max_risk_bps > config.max_edge_risk_bps {
            return Err(format!(
                "risk cap {} exceeds configured edge risk",
                self.cap_id
            ));
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "cap_id": self.cap_id,
            "market_id": self.market_id,
            "edge_id": self.edge_id,
            "max_risk_bps": self.max_risk_bps.to_string(),
            "max_notional_commitment_root": self.max_notional_commitment_root,
            "oracle_attestation_root": self.oracle_attestation_root,
            "guardrail_root": self.guardrail_root,
            "status": self.status.as_str(),
        })
    }

    pub fn root(&self) -> String {
        hash_json("COHESION-RISK-CAP", &self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct FeeCeiling {
    pub ceiling_id: String,
    pub market_id: String,
    pub edge_id: String,
    pub max_fee_bps: u64,
    pub rebate_commitment_root: String,
    pub sponsor_commitment: String,
}

impl FeeCeiling {
    pub fn new(
        ceiling_id: &str,
        market_id: &str,
        edge_id: &str,
        max_fee_bps: u64,
        sponsor_commitment: &str,
    ) -> Self {
        Self {
            ceiling_id: ceiling_id.to_string(),
            market_id: market_id.to_string(),
            edge_id: edge_id.to_string(),
            max_fee_bps,
            rebate_commitment_root: hash_pair(
                "COHESION-FEE-REBATE",
                ceiling_id,
                sponsor_commitment,
            ),
            sponsor_commitment: sponsor_commitment.to_string(),
        }
    }

    pub fn validate(&self, config: &Config) -> PrivateDefiLiquidityCohesionOrchestratorResult<()> {
        require_non_empty("ceiling_id", &self.ceiling_id)?;
        require_non_empty("market_id", &self.market_id)?;
        require_non_empty("edge_id", &self.edge_id)?;
        require_bps("fee_ceiling.max_fee_bps", self.max_fee_bps)?;
        require_non_empty("rebate_commitment_root", &self.rebate_commitment_root)?;
        require_non_empty("sponsor_commitment", &self.sponsor_commitment)?;
        if self.max_fee_bps > config.max_fee_bps {
            return Err(format!("fee ceiling {} exceeds config", self.ceiling_id));
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "ceiling_id": self.ceiling_id,
            "market_id": self.market_id,
            "edge_id": self.edge_id,
            "max_fee_bps": self.max_fee_bps.to_string(),
            "rebate_commitment_root": self.rebate_commitment_root,
            "sponsor_commitment": self.sponsor_commitment,
        })
    }

    pub fn root(&self) -> String {
        hash_json("COHESION-FEE-CEILING", &self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PrivacyBucket {
    pub bucket_id: String,
    pub kind: PrivacyBucketKind,
    pub asset_scope_root: String,
    pub min_set_size: u64,
    pub member_commitment_root: String,
    pub nullifier_root: String,
    pub alignment_root: String,
    pub status: CircuitStatus,
}

impl PrivacyBucket {
    pub fn new(
        bucket_id: &str,
        kind: PrivacyBucketKind,
        asset_scope_root: &str,
        min_set_size: u64,
    ) -> Self {
        Self {
            bucket_id: bucket_id.to_string(),
            kind,
            asset_scope_root: asset_scope_root.to_string(),
            min_set_size,
            member_commitment_root: hash_pair(
                "COHESION-BUCKET-MEMBER",
                bucket_id,
                asset_scope_root,
            ),
            nullifier_root: hash_str("COHESION-BUCKET-NULLIFIER", bucket_id),
            alignment_root: hash_pair("COHESION-BUCKET-ALIGNMENT", bucket_id, kind.as_str()),
            status: CircuitStatus::Active,
        }
    }

    pub fn validate(&self, config: &Config) -> PrivateDefiLiquidityCohesionOrchestratorResult<()> {
        require_non_empty("bucket_id", &self.bucket_id)?;
        require_non_empty("asset_scope_root", &self.asset_scope_root)?;
        require_positive("privacy_bucket.min_set_size", self.min_set_size)?;
        require_non_empty("member_commitment_root", &self.member_commitment_root)?;
        require_non_empty("nullifier_root", &self.nullifier_root)?;
        require_non_empty("alignment_root", &self.alignment_root)?;
        if self.min_set_size < config.min_privacy_set_size {
            return Err(format!(
                "privacy bucket {} below configured anonymity set",
                self.bucket_id
            ));
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "bucket_id": self.bucket_id,
            "kind": self.kind.as_str(),
            "asset_scope_root": self.asset_scope_root,
            "min_set_size": self.min_set_size.to_string(),
            "member_commitment_root": self.member_commitment_root,
            "nullifier_root": self.nullifier_root,
            "alignment_root": self.alignment_root,
            "status": self.status.as_str(),
        })
    }

    pub fn root(&self) -> String {
        hash_json("COHESION-PRIVACY-BUCKET", &self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CreditScore {
    pub score_id: String,
    pub subject_commitment: String,
    pub score_floor: u64,
    pub score_commitment_root: String,
    pub evidence_root: String,
    pub expiry_height: u64,
}

impl CreditScore {
    pub fn new(
        score_id: &str,
        subject_commitment: &str,
        score_floor: u64,
        expiry_height: u64,
    ) -> Self {
        Self {
            score_id: score_id.to_string(),
            subject_commitment: subject_commitment.to_string(),
            score_floor,
            score_commitment_root: hash_pair("COHESION-CREDIT-SCORE", score_id, subject_commitment),
            evidence_root: hash_str("COHESION-CREDIT-EVIDENCE", score_id),
            expiry_height,
        }
    }

    pub fn validate(
        &self,
        config: &Config,
        height: u64,
    ) -> PrivateDefiLiquidityCohesionOrchestratorResult<()> {
        require_non_empty("score_id", &self.score_id)?;
        require_non_empty("subject_commitment", &self.subject_commitment)?;
        require_positive("credit_score.score_floor", self.score_floor)?;
        require_non_empty("score_commitment_root", &self.score_commitment_root)?;
        require_non_empty("evidence_root", &self.evidence_root)?;
        if self.score_floor < config.min_credit_score {
            return Err(format!("credit score {} below floor", self.score_id));
        }
        if self.expiry_height <= height {
            return Err(format!("credit score {} expired", self.score_id));
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "score_id": self.score_id,
            "subject_commitment": self.subject_commitment,
            "score_floor": self.score_floor.to_string(),
            "score_commitment_root": self.score_commitment_root,
            "evidence_root": self.evidence_root,
            "expiry_height": self.expiry_height.to_string(),
        })
    }

    pub fn root(&self) -> String {
        hash_json("COHESION-CREDIT-SCORE-RECORD", &self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct NettingBatch {
    pub batch_id: String,
    pub edge_id: String,
    pub bucket_id: String,
    pub input_commitment_root: String,
    pub output_commitment_root: String,
    pub conservation_proof_root: String,
    pub settlement_call_root: String,
    pub batch_height: u64,
}

impl NettingBatch {
    pub fn new(batch_id: &str, edge_id: &str, bucket_id: &str, batch_height: u64) -> Self {
        Self {
            batch_id: batch_id.to_string(),
            edge_id: edge_id.to_string(),
            bucket_id: bucket_id.to_string(),
            input_commitment_root: hash_pair("COHESION-NETTING-INPUT", batch_id, edge_id),
            output_commitment_root: hash_pair("COHESION-NETTING-OUTPUT", batch_id, bucket_id),
            conservation_proof_root: hash_str("COHESION-NETTING-CONSERVATION", batch_id),
            settlement_call_root: hash_pair("COHESION-NETTING-SETTLEMENT", edge_id, bucket_id),
            batch_height,
        }
    }

    pub fn validate(&self) -> PrivateDefiLiquidityCohesionOrchestratorResult<()> {
        require_non_empty("batch_id", &self.batch_id)?;
        require_non_empty("edge_id", &self.edge_id)?;
        require_non_empty("bucket_id", &self.bucket_id)?;
        require_non_empty("input_commitment_root", &self.input_commitment_root)?;
        require_non_empty("output_commitment_root", &self.output_commitment_root)?;
        require_non_empty("conservation_proof_root", &self.conservation_proof_root)?;
        require_non_empty("settlement_call_root", &self.settlement_call_root)?;
        require_positive("netting_batch.batch_height", self.batch_height)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "edge_id": self.edge_id,
            "bucket_id": self.bucket_id,
            "input_commitment_root": self.input_commitment_root,
            "output_commitment_root": self.output_commitment_root,
            "conservation_proof_root": self.conservation_proof_root,
            "settlement_call_root": self.settlement_call_root,
            "batch_height": self.batch_height.to_string(),
        })
    }

    pub fn root(&self) -> String {
        hash_json("COHESION-NETTING-BATCH", &self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SettlementReceipt {
    pub receipt_id: String,
    pub kind: ReceiptKind,
    pub subject_id: String,
    pub receipt_root: String,
    pub proof_root: String,
    pub emitted_height: u64,
    pub expires_height: u64,
}

impl SettlementReceipt {
    pub fn new(
        receipt_id: &str,
        kind: ReceiptKind,
        subject_id: &str,
        emitted_height: u64,
        ttl_blocks: u64,
    ) -> Self {
        Self {
            receipt_id: receipt_id.to_string(),
            kind,
            subject_id: subject_id.to_string(),
            receipt_root: hash_pair("COHESION-RECEIPT", receipt_id, subject_id),
            proof_root: hash_pair("COHESION-RECEIPT-PROOF", receipt_id, kind.as_str()),
            emitted_height,
            expires_height: emitted_height.saturating_add(ttl_blocks),
        }
    }

    pub fn validate(&self, height: u64) -> PrivateDefiLiquidityCohesionOrchestratorResult<()> {
        require_non_empty("receipt_id", &self.receipt_id)?;
        require_non_empty("subject_id", &self.subject_id)?;
        require_non_empty("receipt_root", &self.receipt_root)?;
        require_non_empty("proof_root", &self.proof_root)?;
        require_positive("receipt.emitted_height", self.emitted_height)?;
        if self.expires_height <= self.emitted_height {
            return Err(format!(
                "receipt {} expires before emission",
                self.receipt_id
            ));
        }
        if self.expires_height <= height {
            return Err(format!("receipt {} expired", self.receipt_id));
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "kind": self.kind.as_str(),
            "subject_id": self.subject_id,
            "receipt_root": self.receipt_root,
            "proof_root": self.proof_root,
            "emitted_height": self.emitted_height.to_string(),
            "expires_height": self.expires_height.to_string(),
        })
    }

    pub fn root(&self) -> String {
        hash_json("COHESION-SETTLEMENT-RECEIPT", &self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct LiquidationCircuit {
    pub circuit_id: String,
    pub market_id: String,
    pub candidate_bucket_id: String,
    pub health_factor_root: String,
    pub auction_commitment_root: String,
    pub backstop_edge_id: String,
    pub delay_blocks: u64,
    pub status: CircuitStatus,
}

impl LiquidationCircuit {
    pub fn new(
        circuit_id: &str,
        market_id: &str,
        candidate_bucket_id: &str,
        backstop_edge_id: &str,
        delay_blocks: u64,
    ) -> Self {
        Self {
            circuit_id: circuit_id.to_string(),
            market_id: market_id.to_string(),
            candidate_bucket_id: candidate_bucket_id.to_string(),
            health_factor_root: hash_pair("COHESION-LIQUIDATION-HEALTH", circuit_id, market_id),
            auction_commitment_root: hash_pair(
                "COHESION-LIQUIDATION-AUCTION",
                circuit_id,
                candidate_bucket_id,
            ),
            backstop_edge_id: backstop_edge_id.to_string(),
            delay_blocks,
            status: CircuitStatus::Active,
        }
    }

    pub fn validate(&self, config: &Config) -> PrivateDefiLiquidityCohesionOrchestratorResult<()> {
        require_non_empty("circuit_id", &self.circuit_id)?;
        require_non_empty("market_id", &self.market_id)?;
        require_non_empty("candidate_bucket_id", &self.candidate_bucket_id)?;
        require_non_empty("health_factor_root", &self.health_factor_root)?;
        require_non_empty("auction_commitment_root", &self.auction_commitment_root)?;
        require_non_empty("backstop_edge_id", &self.backstop_edge_id)?;
        require_positive("liquidation.delay_blocks", self.delay_blocks)?;
        if self.delay_blocks < config.liquidation_delay_blocks {
            return Err(format!(
                "liquidation circuit {} delay too short",
                self.circuit_id
            ));
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "circuit_id": self.circuit_id,
            "market_id": self.market_id,
            "candidate_bucket_id": self.candidate_bucket_id,
            "health_factor_root": self.health_factor_root,
            "auction_commitment_root": self.auction_commitment_root,
            "backstop_edge_id": self.backstop_edge_id,
            "delay_blocks": self.delay_blocks.to_string(),
            "status": self.status.as_str(),
        })
    }

    pub fn root(&self) -> String {
        hash_json("COHESION-LIQUIDATION-CIRCUIT", &self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct IncentiveEpoch {
    pub epoch_id: String,
    pub sponsor_commitment: String,
    pub reward_asset_id: String,
    pub eligible_edge_root: String,
    pub reward_commitment_root: String,
    pub claim_bucket_id: String,
    pub starts_height: u64,
    pub ends_height: u64,
}

impl IncentiveEpoch {
    pub fn new(
        epoch_id: &str,
        sponsor_commitment: &str,
        reward_asset_id: &str,
        claim_bucket_id: &str,
        starts_height: u64,
        ends_height: u64,
    ) -> Self {
        Self {
            epoch_id: epoch_id.to_string(),
            sponsor_commitment: sponsor_commitment.to_string(),
            reward_asset_id: reward_asset_id.to_string(),
            eligible_edge_root: hash_str("COHESION-INCENTIVE-EDGE", epoch_id),
            reward_commitment_root: hash_pair(
                "COHESION-INCENTIVE-REWARD",
                epoch_id,
                reward_asset_id,
            ),
            claim_bucket_id: claim_bucket_id.to_string(),
            starts_height,
            ends_height,
        }
    }

    pub fn validate(&self) -> PrivateDefiLiquidityCohesionOrchestratorResult<()> {
        require_non_empty("epoch_id", &self.epoch_id)?;
        require_non_empty("sponsor_commitment", &self.sponsor_commitment)?;
        require_non_empty("reward_asset_id", &self.reward_asset_id)?;
        require_non_empty("eligible_edge_root", &self.eligible_edge_root)?;
        require_non_empty("reward_commitment_root", &self.reward_commitment_root)?;
        require_non_empty("claim_bucket_id", &self.claim_bucket_id)?;
        require_positive("incentive.starts_height", self.starts_height)?;
        if self.ends_height <= self.starts_height {
            return Err(format!(
                "incentive epoch {} has invalid range",
                self.epoch_id
            ));
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "epoch_id": self.epoch_id,
            "sponsor_commitment": self.sponsor_commitment,
            "reward_asset_id": self.reward_asset_id,
            "eligible_edge_root": self.eligible_edge_root,
            "reward_commitment_root": self.reward_commitment_root,
            "claim_bucket_id": self.claim_bucket_id,
            "starts_height": self.starts_height.to_string(),
            "ends_height": self.ends_height.to_string(),
        })
    }

    pub fn root(&self) -> String {
        hash_json("COHESION-INCENTIVE-EPOCH", &self.public_record())
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Roots {
    pub config_root: String,
    pub market_root: String,
    pub edge_root: String,
    pub risk_cap_root: String,
    pub fee_ceiling_root: String,
    pub privacy_bucket_root: String,
    pub credit_score_root: String,
    pub netting_batch_root: String,
    pub settlement_receipt_root: String,
    pub liquidation_circuit_root: String,
    pub incentive_epoch_root: String,
    pub registry_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "market_root": self.market_root,
            "edge_root": self.edge_root,
            "risk_cap_root": self.risk_cap_root,
            "fee_ceiling_root": self.fee_ceiling_root,
            "privacy_bucket_root": self.privacy_bucket_root,
            "credit_score_root": self.credit_score_root,
            "netting_batch_root": self.netting_batch_root,
            "settlement_receipt_root": self.settlement_receipt_root,
            "liquidation_circuit_root": self.liquidation_circuit_root,
            "incentive_epoch_root": self.incentive_epoch_root,
            "registry_root": self.registry_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Counters {
    pub markets: u64,
    pub active_markets: u64,
    pub edges: u64,
    pub active_edges: u64,
    pub risk_caps: u64,
    pub fee_ceilings: u64,
    pub privacy_buckets: u64,
    pub credit_scores: u64,
    pub netting_batches: u64,
    pub settlement_receipts: u64,
    pub liquidation_circuits: u64,
    pub incentive_epochs: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "markets": self.markets.to_string(),
            "active_markets": self.active_markets.to_string(),
            "edges": self.edges.to_string(),
            "active_edges": self.active_edges.to_string(),
            "risk_caps": self.risk_caps.to_string(),
            "fee_ceilings": self.fee_ceilings.to_string(),
            "privacy_buckets": self.privacy_buckets.to_string(),
            "credit_scores": self.credit_scores.to_string(),
            "netting_batches": self.netting_batches.to_string(),
            "settlement_receipts": self.settlement_receipts.to_string(),
            "liquidation_circuits": self.liquidation_circuits.to_string(),
            "incentive_epochs": self.incentive_epochs.to_string(),
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct State {
    pub height: u64,
    pub epoch: u64,
    pub config: Config,
    pub markets: BTreeMap<String, Market>,
    pub edges: BTreeMap<String, LiquidityEdge>,
    pub risk_caps: BTreeMap<String, RiskCap>,
    pub fee_ceilings: BTreeMap<String, FeeCeiling>,
    pub privacy_buckets: BTreeMap<String, PrivacyBucket>,
    pub credit_scores: BTreeMap<String, CreditScore>,
    pub netting_batches: BTreeMap<String, NettingBatch>,
    pub settlement_receipts: BTreeMap<String, SettlementReceipt>,
    pub liquidation_circuits: BTreeMap<String, LiquidationCircuit>,
    pub incentive_epochs: BTreeMap<String, IncentiveEpoch>,
}

impl State {
    pub fn devnet() -> PrivateDefiLiquidityCohesionOrchestratorResult<State> {
        let height = PRIVATE_DEFI_LIQUIDITY_COHESION_ORCHESTRATOR_DEVNET_HEIGHT;
        let mut state = State {
            height,
            epoch: PRIVATE_DEFI_LIQUIDITY_COHESION_ORCHESTRATOR_DEVNET_EPOCH,
            config: Config::devnet(),
            markets: BTreeMap::new(),
            edges: BTreeMap::new(),
            risk_caps: BTreeMap::new(),
            fee_ceilings: BTreeMap::new(),
            privacy_buckets: BTreeMap::new(),
            credit_scores: BTreeMap::new(),
            netting_batches: BTreeMap::new(),
            settlement_receipts: BTreeMap::new(),
            liquidation_circuits: BTreeMap::new(),
            incentive_epochs: BTreeMap::new(),
        };

        state.insert_privacy_bucket(PrivacyBucket::new(
            "bucket-swap-blue",
            PrivacyBucketKind::SwapInput,
            &hash_str("COHESION-DEVNET-ASSET-SCOPE", "usdd-wxmr"),
            state.config.min_privacy_set_size,
        ))?;
        state.insert_privacy_bucket(PrivacyBucket::new(
            "bucket-lending-green",
            PrivacyBucketKind::LendingPosition,
            &hash_str("COHESION-DEVNET-ASSET-SCOPE", "wbtc-usdd"),
            state.config.min_privacy_set_size.saturating_add(256),
        ))?;
        state.insert_privacy_bucket(PrivacyBucket::new(
            "bucket-liquidation-amber",
            PrivacyBucketKind::LiquidationCandidate,
            &hash_str("COHESION-DEVNET-ASSET-SCOPE", "risk-candidates"),
            state.config.min_privacy_set_size.saturating_add(512),
        ))?;
        state.insert_privacy_bucket(PrivacyBucket::new(
            "bucket-incentive-violet",
            PrivacyBucketKind::IncentiveClaim,
            &hash_str("COHESION-DEVNET-ASSET-SCOPE", "lp-incentives"),
            state.config.min_privacy_set_size,
        ))?;

        state.insert_market(Market::new(
            "amm-usdd-wxmr",
            MarketKind::PrivateAmm,
            &hash_str("COHESION-OPERATOR", "amm-operator"),
            &hash_str("COHESION-ASSETS", "usdd-wxmr"),
            "bucket-swap-blue",
            24,
            3_200,
            600,
        ))?;
        state.insert_market(Market::new(
            "stable-usdd-usdc",
            MarketKind::PrivateStableSwap,
            &hash_str("COHESION-OPERATOR", "stable-operator"),
            &hash_str("COHESION-ASSETS", "usdd-usdc"),
            "bucket-swap-blue",
            8,
            2_400,
            600,
        ))?;
        state.insert_market(Market::new(
            "lending-wbtc-usdd",
            MarketKind::PrivateLending,
            &hash_str("COHESION-OPERATOR", "lending-operator"),
            &hash_str("COHESION-ASSETS", "wbtc-usdd"),
            "bucket-lending-green",
            35,
            4_800,
            690,
        ))?;
        state.insert_market(Market::new(
            "vault-delta-neutral",
            MarketKind::PrivateVault,
            &hash_str("COHESION-OPERATOR", "vault-operator"),
            &hash_str("COHESION-ASSETS", "lp-delta-neutral"),
            "bucket-lending-green",
            48,
            5_200,
            710,
        ))?;
        state.insert_market(Market::new(
            "derivative-eth-perp",
            MarketKind::PrivateDerivative,
            &hash_str("COHESION-OPERATOR", "derivative-operator"),
            &hash_str("COHESION-ASSETS", "eth-perp-margin"),
            "bucket-lending-green",
            54,
            5_600,
            730,
        ))?;
        state.insert_market(Market::new(
            "liquidation-router",
            MarketKind::PrivateLiquidationCircuit,
            &hash_str("COHESION-OPERATOR", "liquidation-operator"),
            &hash_str("COHESION-ASSETS", "liquidation-backstop"),
            "bucket-liquidation-amber",
            18,
            3_900,
            650,
        ))?;

        state.insert_fee_ceiling(FeeCeiling::new(
            "fee-amm-to-stable",
            "amm-usdd-wxmr",
            "edge-amm-stable",
            28,
            &hash_str("COHESION-SPONSOR", "lp-sponsor"),
        ))?;
        state.insert_fee_ceiling(FeeCeiling::new(
            "fee-lending-vault",
            "lending-wbtc-usdd",
            "edge-lending-vault",
            42,
            &hash_str("COHESION-SPONSOR", "risk-sponsor"),
        ))?;
        state.insert_fee_ceiling(FeeCeiling::new(
            "fee-derivative-liquidation",
            "derivative-eth-perp",
            "edge-derivative-liquidation",
            55,
            &hash_str("COHESION-SPONSOR", "backstop-sponsor"),
        ))?;

        state.insert_risk_cap(RiskCap::new(
            "risk-amm-stable",
            "amm-usdd-wxmr",
            "edge-amm-stable",
            3_500,
        ))?;
        state.insert_risk_cap(RiskCap::new(
            "risk-lending-vault",
            "lending-wbtc-usdd",
            "edge-lending-vault",
            5_700,
        ))?;
        state.insert_risk_cap(RiskCap::new(
            "risk-derivative-liquidation",
            "derivative-eth-perp",
            "edge-derivative-liquidation",
            6_100,
        ))?;

        state.insert_edge(LiquidityEdge::new(
            "edge-amm-stable",
            EdgeKind::StableSwapPegRoute,
            "amm-usdd-wxmr",
            "stable-usdd-usdc",
            &hash_str("COHESION-PAIR", "usdd-wxmr-usdc"),
            "fee-amm-to-stable",
            "risk-amm-stable",
            "bucket-swap-blue",
        ))?;
        state.insert_edge(LiquidityEdge::new(
            "edge-lending-vault",
            EdgeKind::VaultShare,
            "lending-wbtc-usdd",
            "vault-delta-neutral",
            &hash_str("COHESION-PAIR", "wbtc-usdd-lp"),
            "fee-lending-vault",
            "risk-lending-vault",
            "bucket-lending-green",
        ))?;
        state.insert_edge(LiquidityEdge::new(
            "edge-derivative-liquidation",
            EdgeKind::LiquidationBackstop,
            "derivative-eth-perp",
            "liquidation-router",
            &hash_str("COHESION-PAIR", "eth-margin-backstop"),
            "fee-derivative-liquidation",
            "risk-derivative-liquidation",
            "bucket-liquidation-amber",
        ))?;

        state.insert_credit_score(CreditScore::new(
            "credit-solver-alpha",
            &hash_str("COHESION-SUBJECT", "solver-alpha"),
            740,
            height.saturating_add(2_880),
        ))?;
        state.insert_credit_score(CreditScore::new(
            "credit-liquidator-beta",
            &hash_str("COHESION-SUBJECT", "liquidator-beta"),
            705,
            height.saturating_add(2_160),
        ))?;

        state.insert_netting_batch(NettingBatch::new(
            "netting-usdd-wxmr-001",
            "edge-amm-stable",
            "bucket-swap-blue",
            height,
        ))?;
        state.insert_netting_batch(NettingBatch::new(
            "netting-vault-001",
            "edge-lending-vault",
            "bucket-lending-green",
            height,
        ))?;

        state.insert_liquidation_circuit(LiquidationCircuit::new(
            "liq-eth-perp-001",
            "derivative-eth-perp",
            "bucket-liquidation-amber",
            "edge-derivative-liquidation",
            state.config.liquidation_delay_blocks,
        ))?;

        state.insert_incentive_epoch(IncentiveEpoch::new(
            "incentive-epoch-012",
            &hash_str("COHESION-SPONSOR", "lp-incentive-sponsor"),
            "usdd-devnet",
            "bucket-incentive-violet",
            height.saturating_sub(24),
            height.saturating_add(state.config.epoch_blocks),
        ))?;

        state.insert_receipt(SettlementReceipt::new(
            "receipt-netting-usdd-wxmr-001",
            ReceiptKind::SwapNetting,
            "netting-usdd-wxmr-001",
            height,
            state.config.receipt_ttl_blocks,
        ))?;
        state.insert_receipt(SettlementReceipt::new(
            "receipt-risk-rebalance-001",
            ReceiptKind::RiskRebalance,
            "edge-lending-vault",
            height,
            state.config.receipt_ttl_blocks,
        ))?;
        state.insert_receipt(SettlementReceipt::new(
            "receipt-incentive-epoch-012",
            ReceiptKind::IncentiveAccrual,
            "incentive-epoch-012",
            height,
            state.config.receipt_ttl_blocks,
        ))?;

        state.validate()?;
        Ok(state)
    }

    pub fn validate(&self) -> PrivateDefiLiquidityCohesionOrchestratorResult<()> {
        self.config.validate()?;
        require_positive("height", self.height)?;
        require_positive("epoch", self.epoch)?;
        require_len(
            "markets",
            self.markets.len(),
            PRIVATE_DEFI_LIQUIDITY_COHESION_ORCHESTRATOR_MAX_MARKETS,
        )?;
        require_len(
            "edges",
            self.edges.len(),
            PRIVATE_DEFI_LIQUIDITY_COHESION_ORCHESTRATOR_MAX_EDGES,
        )?;
        require_len(
            "risk_caps",
            self.risk_caps.len(),
            PRIVATE_DEFI_LIQUIDITY_COHESION_ORCHESTRATOR_MAX_RISK_CAPS,
        )?;
        require_len(
            "fee_ceilings",
            self.fee_ceilings.len(),
            PRIVATE_DEFI_LIQUIDITY_COHESION_ORCHESTRATOR_MAX_FEE_CEILINGS,
        )?;
        require_len(
            "privacy_buckets",
            self.privacy_buckets.len(),
            PRIVATE_DEFI_LIQUIDITY_COHESION_ORCHESTRATOR_MAX_PRIVACY_BUCKETS,
        )?;
        require_len(
            "netting_batches",
            self.netting_batches.len(),
            PRIVATE_DEFI_LIQUIDITY_COHESION_ORCHESTRATOR_MAX_NETTING_BATCHES,
        )?;
        require_len(
            "settlement_receipts",
            self.settlement_receipts.len(),
            PRIVATE_DEFI_LIQUIDITY_COHESION_ORCHESTRATOR_MAX_RECEIPTS,
        )?;
        require_len(
            "incentive_epochs",
            self.incentive_epochs.len(),
            PRIVATE_DEFI_LIQUIDITY_COHESION_ORCHESTRATOR_MAX_INCENTIVE_EPOCHS,
        )?;

        for bucket in self.privacy_buckets.values() {
            bucket.validate(&self.config)?;
        }
        for market in self.markets.values() {
            market.validate(&self.config)?;
            require_reference(
                "market.privacy_bucket_id",
                &market.privacy_bucket_id,
                &self.privacy_buckets,
            )?;
        }
        for cap in self.risk_caps.values() {
            cap.validate(&self.config)?;
            require_reference("risk_cap.market_id", &cap.market_id, &self.markets)?;
        }
        for ceiling in self.fee_ceilings.values() {
            ceiling.validate(&self.config)?;
            require_reference("fee_ceiling.market_id", &ceiling.market_id, &self.markets)?;
        }
        for edge in self.edges.values() {
            edge.validate()?;
            require_reference("edge.from_market_id", &edge.from_market_id, &self.markets)?;
            require_reference("edge.to_market_id", &edge.to_market_id, &self.markets)?;
            require_reference("edge.risk_cap_id", &edge.risk_cap_id, &self.risk_caps)?;
            require_reference(
                "edge.fee_ceiling_id",
                &edge.fee_ceiling_id,
                &self.fee_ceilings,
            )?;
            require_reference(
                "edge.privacy_bucket_id",
                &edge.privacy_bucket_id,
                &self.privacy_buckets,
            )?;
        }
        for cap in self.risk_caps.values() {
            require_reference("risk_cap.edge_id", &cap.edge_id, &self.edges)?;
        }
        for ceiling in self.fee_ceilings.values() {
            require_reference("fee_ceiling.edge_id", &ceiling.edge_id, &self.edges)?;
        }
        for score in self.credit_scores.values() {
            score.validate(&self.config, self.height)?;
        }
        for batch in self.netting_batches.values() {
            batch.validate()?;
            require_reference("batch.edge_id", &batch.edge_id, &self.edges)?;
            require_reference("batch.bucket_id", &batch.bucket_id, &self.privacy_buckets)?;
        }
        for receipt in self.settlement_receipts.values() {
            receipt.validate(self.height)?;
        }
        for circuit in self.liquidation_circuits.values() {
            circuit.validate(&self.config)?;
            require_reference("circuit.market_id", &circuit.market_id, &self.markets)?;
            require_reference(
                "circuit.candidate_bucket_id",
                &circuit.candidate_bucket_id,
                &self.privacy_buckets,
            )?;
            require_reference(
                "circuit.backstop_edge_id",
                &circuit.backstop_edge_id,
                &self.edges,
            )?;
        }
        for epoch in self.incentive_epochs.values() {
            epoch.validate()?;
            require_reference(
                "incentive.claim_bucket_id",
                &epoch.claim_bucket_id,
                &self.privacy_buckets,
            )?;
        }
        Ok(())
    }

    pub fn set_height(
        &mut self,
        height: u64,
    ) -> PrivateDefiLiquidityCohesionOrchestratorResult<()> {
        require_positive("height", height)?;
        self.height = height;
        self.epoch = height / self.config.epoch_blocks;
        self.validate()
    }

    pub fn update_height(
        &mut self,
        height: u64,
    ) -> PrivateDefiLiquidityCohesionOrchestratorResult<()> {
        self.set_height(height)
    }

    pub fn roots(&self) -> Roots {
        let config_root = self.config.root();
        let market_root = map_merkle_root("COHESION-MARKETS", &self.markets);
        let edge_root = map_merkle_root("COHESION-EDGES", &self.edges);
        let risk_cap_root = map_merkle_root("COHESION-RISK-CAPS", &self.risk_caps);
        let fee_ceiling_root = map_merkle_root("COHESION-FEE-CEILINGS", &self.fee_ceilings);
        let privacy_bucket_root =
            map_merkle_root("COHESION-PRIVACY-BUCKETS", &self.privacy_buckets);
        let credit_score_root = map_merkle_root("COHESION-CREDIT-SCORES", &self.credit_scores);
        let netting_batch_root = map_merkle_root("COHESION-NETTING-BATCHES", &self.netting_batches);
        let settlement_receipt_root =
            map_merkle_root("COHESION-SETTLEMENT-RECEIPTS", &self.settlement_receipts);
        let liquidation_circuit_root =
            map_merkle_root("COHESION-LIQUIDATION-CIRCUITS", &self.liquidation_circuits);
        let incentive_epoch_root =
            map_merkle_root("COHESION-INCENTIVE-EPOCHS", &self.incentive_epochs);
        let registry_payload = json!({
            "config_root": config_root,
            "market_root": market_root,
            "edge_root": edge_root,
            "risk_cap_root": risk_cap_root,
            "fee_ceiling_root": fee_ceiling_root,
            "privacy_bucket_root": privacy_bucket_root,
            "credit_score_root": credit_score_root,
            "netting_batch_root": netting_batch_root,
            "settlement_receipt_root": settlement_receipt_root,
            "liquidation_circuit_root": liquidation_circuit_root,
            "incentive_epoch_root": incentive_epoch_root,
        });
        let registry_root = hash_json("COHESION-REGISTRY", &registry_payload);
        let state_payload = json!({
            "height": self.height.to_string(),
            "epoch": self.epoch.to_string(),
            "registry_root": registry_root,
            "counters": self.counters().public_record(),
        });
        let state_root = root_from_record(&state_payload);
        Roots {
            config_root,
            market_root,
            edge_root,
            risk_cap_root,
            fee_ceiling_root,
            privacy_bucket_root,
            credit_score_root,
            netting_batch_root,
            settlement_receipt_root,
            liquidation_circuit_root,
            incentive_epoch_root,
            registry_root,
            state_root,
        }
    }

    pub fn counters(&self) -> Counters {
        Counters {
            markets: self.markets.len() as u64,
            active_markets: self
                .markets
                .values()
                .filter(|market| market.status.accepts_flow())
                .count() as u64,
            edges: self.edges.len() as u64,
            active_edges: self
                .edges
                .values()
                .filter(|edge| edge.status.accepts_flow())
                .count() as u64,
            risk_caps: self.risk_caps.len() as u64,
            fee_ceilings: self.fee_ceilings.len() as u64,
            privacy_buckets: self.privacy_buckets.len() as u64,
            credit_scores: self.credit_scores.len() as u64,
            netting_batches: self.netting_batches.len() as u64,
            settlement_receipts: self.settlement_receipts.len() as u64,
            liquidation_circuits: self.liquidation_circuits.len() as u64,
            incentive_epochs: self.incentive_epochs.len() as u64,
        }
    }

    pub fn state_root(&self) -> String {
        self.roots().state_root
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        json!({
            "protocol_version": PRIVATE_DEFI_LIQUIDITY_COHESION_ORCHESTRATOR_PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "height": self.height.to_string(),
            "epoch": self.epoch.to_string(),
            "config": self.config.public_record(),
            "markets": records_from_map(&self.markets),
            "edges": records_from_map(&self.edges),
            "risk_caps": records_from_map(&self.risk_caps),
            "fee_ceilings": records_from_map(&self.fee_ceilings),
            "privacy_buckets": records_from_map(&self.privacy_buckets),
            "credit_scores": records_from_map(&self.credit_scores),
            "netting_batches": records_from_map(&self.netting_batches),
            "settlement_receipts": records_from_map(&self.settlement_receipts),
            "liquidation_circuits": records_from_map(&self.liquidation_circuits),
            "incentive_epochs": records_from_map(&self.incentive_epochs),
            "counters": self.counters().public_record(),
            "roots": roots.public_record(),
            "state_root": roots.state_root,
        })
    }

    pub fn insert_market(
        &mut self,
        market: Market,
    ) -> PrivateDefiLiquidityCohesionOrchestratorResult<()> {
        market.validate(&self.config)?;
        if !self.privacy_buckets.contains_key(&market.privacy_bucket_id) {
            return Err(format!(
                "missing privacy bucket {}",
                market.privacy_bucket_id
            ));
        }
        self.markets.insert(market.market_id.clone(), market);
        Ok(())
    }

    pub fn insert_edge(
        &mut self,
        edge: LiquidityEdge,
    ) -> PrivateDefiLiquidityCohesionOrchestratorResult<()> {
        edge.validate()?;
        self.edges.insert(edge.edge_id.clone(), edge);
        Ok(())
    }

    pub fn insert_risk_cap(
        &mut self,
        cap: RiskCap,
    ) -> PrivateDefiLiquidityCohesionOrchestratorResult<()> {
        cap.validate(&self.config)?;
        self.risk_caps.insert(cap.cap_id.clone(), cap);
        Ok(())
    }

    pub fn insert_fee_ceiling(
        &mut self,
        ceiling: FeeCeiling,
    ) -> PrivateDefiLiquidityCohesionOrchestratorResult<()> {
        ceiling.validate(&self.config)?;
        self.fee_ceilings
            .insert(ceiling.ceiling_id.clone(), ceiling);
        Ok(())
    }

    pub fn insert_privacy_bucket(
        &mut self,
        bucket: PrivacyBucket,
    ) -> PrivateDefiLiquidityCohesionOrchestratorResult<()> {
        bucket.validate(&self.config)?;
        self.privacy_buckets
            .insert(bucket.bucket_id.clone(), bucket);
        Ok(())
    }

    pub fn insert_credit_score(
        &mut self,
        score: CreditScore,
    ) -> PrivateDefiLiquidityCohesionOrchestratorResult<()> {
        score.validate(&self.config, self.height)?;
        self.credit_scores.insert(score.score_id.clone(), score);
        Ok(())
    }

    pub fn insert_netting_batch(
        &mut self,
        batch: NettingBatch,
    ) -> PrivateDefiLiquidityCohesionOrchestratorResult<()> {
        batch.validate()?;
        self.netting_batches.insert(batch.batch_id.clone(), batch);
        Ok(())
    }

    pub fn insert_receipt(
        &mut self,
        receipt: SettlementReceipt,
    ) -> PrivateDefiLiquidityCohesionOrchestratorResult<()> {
        receipt.validate(self.height)?;
        self.settlement_receipts
            .insert(receipt.receipt_id.clone(), receipt);
        Ok(())
    }

    pub fn insert_liquidation_circuit(
        &mut self,
        circuit: LiquidationCircuit,
    ) -> PrivateDefiLiquidityCohesionOrchestratorResult<()> {
        circuit.validate(&self.config)?;
        self.liquidation_circuits
            .insert(circuit.circuit_id.clone(), circuit);
        Ok(())
    }

    pub fn insert_incentive_epoch(
        &mut self,
        epoch: IncentiveEpoch,
    ) -> PrivateDefiLiquidityCohesionOrchestratorResult<()> {
        epoch.validate()?;
        self.incentive_epochs.insert(epoch.epoch_id.clone(), epoch);
        Ok(())
    }
}

pub fn root_from_record(record: &Value) -> String {
    domain_hash(
        "PRIVATE-DEFI-LIQUIDITY-COHESION-ORCHESTRATOR-STATE",
        &[
            HashPart::Str(PRIVATE_DEFI_LIQUIDITY_COHESION_ORCHESTRATOR_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Json(record),
        ],
        32,
    )
}

pub fn devnet() -> PrivateDefiLiquidityCohesionOrchestratorResult<State> {
    State::devnet()
}

trait PublicRecord {
    fn public_record(&self) -> Value;
}

impl PublicRecord for Market {
    fn public_record(&self) -> Value {
        Market::public_record(self)
    }
}

impl PublicRecord for LiquidityEdge {
    fn public_record(&self) -> Value {
        LiquidityEdge::public_record(self)
    }
}

impl PublicRecord for RiskCap {
    fn public_record(&self) -> Value {
        RiskCap::public_record(self)
    }
}

impl PublicRecord for FeeCeiling {
    fn public_record(&self) -> Value {
        FeeCeiling::public_record(self)
    }
}

impl PublicRecord for PrivacyBucket {
    fn public_record(&self) -> Value {
        PrivacyBucket::public_record(self)
    }
}

impl PublicRecord for CreditScore {
    fn public_record(&self) -> Value {
        CreditScore::public_record(self)
    }
}

impl PublicRecord for NettingBatch {
    fn public_record(&self) -> Value {
        NettingBatch::public_record(self)
    }
}

impl PublicRecord for SettlementReceipt {
    fn public_record(&self) -> Value {
        SettlementReceipt::public_record(self)
    }
}

impl PublicRecord for LiquidationCircuit {
    fn public_record(&self) -> Value {
        LiquidationCircuit::public_record(self)
    }
}

impl PublicRecord for IncentiveEpoch {
    fn public_record(&self) -> Value {
        IncentiveEpoch::public_record(self)
    }
}

fn records_from_map<T: PublicRecord>(values: &BTreeMap<String, T>) -> Vec<Value> {
    values.values().map(PublicRecord::public_record).collect()
}

fn map_merkle_root<T: PublicRecord>(domain: &str, values: &BTreeMap<String, T>) -> String {
    let leaves = records_from_map(values);
    merkle_root(domain, &leaves)
}

fn hash_str(domain: &str, value: &str) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PRIVATE_DEFI_LIQUIDITY_COHESION_ORCHESTRATOR_PROTOCOL_VERSION),
            HashPart::Str(value),
        ],
        32,
    )
}

fn hash_pair(domain: &str, left: &str, right: &str) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PRIVATE_DEFI_LIQUIDITY_COHESION_ORCHESTRATOR_PROTOCOL_VERSION),
            HashPart::Str(left),
            HashPart::Str(right),
        ],
        32,
    )
}

fn hash_json(domain: &str, value: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PRIVATE_DEFI_LIQUIDITY_COHESION_ORCHESTRATOR_PROTOCOL_VERSION),
            HashPart::Json(value),
        ],
        32,
    )
}

fn require_non_empty(
    label: &str,
    value: &str,
) -> PrivateDefiLiquidityCohesionOrchestratorResult<()> {
    if value.trim().is_empty() {
        Err(format!("{label} must not be empty"))
    } else {
        Ok(())
    }
}

fn require_positive(label: &str, value: u64) -> PrivateDefiLiquidityCohesionOrchestratorResult<()> {
    if value == 0 {
        Err(format!("{label} must be positive"))
    } else {
        Ok(())
    }
}

fn require_bps(label: &str, value: u64) -> PrivateDefiLiquidityCohesionOrchestratorResult<()> {
    if value > PRIVATE_DEFI_LIQUIDITY_COHESION_ORCHESTRATOR_MAX_BPS {
        Err(format!("{label} exceeds basis point maximum"))
    } else {
        Ok(())
    }
}

fn require_len(
    label: &str,
    len: usize,
    max: usize,
) -> PrivateDefiLiquidityCohesionOrchestratorResult<()> {
    if len > max {
        Err(format!("{label} exceeds maximum length"))
    } else {
        Ok(())
    }
}

fn require_reference<T>(
    label: &str,
    id: &str,
    values: &BTreeMap<String, T>,
) -> PrivateDefiLiquidityCohesionOrchestratorResult<()> {
    if values.contains_key(id) {
        Ok(())
    } else {
        Err(format!("{label} references missing id {id}"))
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct CohesionIndex {
    pub markets_by_bucket: BTreeMap<String, BTreeSet<String>>,
    pub edges_by_market: BTreeMap<String, BTreeSet<String>>,
    pub receipts_by_subject: BTreeMap<String, BTreeSet<String>>,
}

impl CohesionIndex {
    pub fn from_state(state: &State) -> Self {
        let mut index = Self::default();
        for market in state.markets.values() {
            index
                .markets_by_bucket
                .entry(market.privacy_bucket_id.clone())
                .or_default()
                .insert(market.market_id.clone());
        }
        for edge in state.edges.values() {
            index
                .edges_by_market
                .entry(edge.from_market_id.clone())
                .or_default()
                .insert(edge.edge_id.clone());
            index
                .edges_by_market
                .entry(edge.to_market_id.clone())
                .or_default()
                .insert(edge.edge_id.clone());
        }
        for receipt in state.settlement_receipts.values() {
            index
                .receipts_by_subject
                .entry(receipt.subject_id.clone())
                .or_default()
                .insert(receipt.receipt_id.clone());
        }
        index
    }

    pub fn public_record(&self) -> Value {
        json!({
            "markets_by_bucket": set_map_record(&self.markets_by_bucket),
            "edges_by_market": set_map_record(&self.edges_by_market),
            "receipts_by_subject": set_map_record(&self.receipts_by_subject),
        })
    }

    pub fn root(&self) -> String {
        hash_json("COHESION-INDEX", &self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CohesionPolicyReport {
    pub report_id: String,
    pub height: u64,
    pub state_root: String,
    pub registry_root: String,
    pub index_root: String,
    pub fee_policy_root: String,
    pub risk_policy_root: String,
    pub privacy_policy_root: String,
    pub liquidation_policy_root: String,
    pub incentive_policy_root: String,
}

impl CohesionPolicyReport {
    pub fn from_state(
        report_id: &str,
        state: &State,
    ) -> PrivateDefiLiquidityCohesionOrchestratorResult<Self> {
        require_non_empty("report_id", report_id)?;
        state.validate()?;
        let roots = state.roots();
        let index = CohesionIndex::from_state(state);
        let fee_policy_root = policy_root(
            "COHESION-FEE-POLICY",
            &state
                .fee_ceilings
                .values()
                .map(|ceiling| {
                    json!({
                        "ceiling_id": ceiling.ceiling_id,
                        "edge_id": ceiling.edge_id,
                        "max_fee_bps": ceiling.max_fee_bps.to_string(),
                    })
                })
                .collect::<Vec<_>>(),
        );
        let risk_policy_root = policy_root(
            "COHESION-RISK-POLICY",
            &state
                .risk_caps
                .values()
                .map(|cap| {
                    json!({
                        "cap_id": cap.cap_id,
                        "edge_id": cap.edge_id,
                        "max_risk_bps": cap.max_risk_bps.to_string(),
                    })
                })
                .collect::<Vec<_>>(),
        );
        let privacy_policy_root = policy_root(
            "COHESION-PRIVACY-POLICY",
            &state
                .privacy_buckets
                .values()
                .map(|bucket| {
                    json!({
                        "bucket_id": bucket.bucket_id,
                        "kind": bucket.kind.as_str(),
                        "min_set_size": bucket.min_set_size.to_string(),
                    })
                })
                .collect::<Vec<_>>(),
        );
        let liquidation_policy_root = policy_root(
            "COHESION-LIQUIDATION-POLICY",
            &state
                .liquidation_circuits
                .values()
                .map(|circuit| {
                    json!({
                        "circuit_id": circuit.circuit_id,
                        "market_id": circuit.market_id,
                        "delay_blocks": circuit.delay_blocks.to_string(),
                    })
                })
                .collect::<Vec<_>>(),
        );
        let incentive_policy_root = policy_root(
            "COHESION-INCENTIVE-POLICY",
            &state
                .incentive_epochs
                .values()
                .map(|epoch| {
                    json!({
                        "epoch_id": epoch.epoch_id,
                        "reward_asset_id": epoch.reward_asset_id,
                        "claim_bucket_id": epoch.claim_bucket_id,
                    })
                })
                .collect::<Vec<_>>(),
        );
        Ok(Self {
            report_id: report_id.to_string(),
            height: state.height,
            state_root: roots.state_root,
            registry_root: roots.registry_root,
            index_root: index.root(),
            fee_policy_root,
            risk_policy_root,
            privacy_policy_root,
            liquidation_policy_root,
            incentive_policy_root,
        })
    }

    pub fn validate(&self) -> PrivateDefiLiquidityCohesionOrchestratorResult<()> {
        require_non_empty("report_id", &self.report_id)?;
        require_positive("report.height", self.height)?;
        require_non_empty("state_root", &self.state_root)?;
        require_non_empty("registry_root", &self.registry_root)?;
        require_non_empty("index_root", &self.index_root)?;
        require_non_empty("fee_policy_root", &self.fee_policy_root)?;
        require_non_empty("risk_policy_root", &self.risk_policy_root)?;
        require_non_empty("privacy_policy_root", &self.privacy_policy_root)?;
        require_non_empty("liquidation_policy_root", &self.liquidation_policy_root)?;
        require_non_empty("incentive_policy_root", &self.incentive_policy_root)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "report_id": self.report_id,
            "height": self.height.to_string(),
            "state_root": self.state_root,
            "registry_root": self.registry_root,
            "index_root": self.index_root,
            "fee_policy_root": self.fee_policy_root,
            "risk_policy_root": self.risk_policy_root,
            "privacy_policy_root": self.privacy_policy_root,
            "liquidation_policy_root": self.liquidation_policy_root,
            "incentive_policy_root": self.incentive_policy_root,
        })
    }

    pub fn root(&self) -> String {
        hash_json("COHESION-POLICY-REPORT", &self.public_record())
    }
}

fn set_map_record(values: &BTreeMap<String, BTreeSet<String>>) -> Vec<Value> {
    values
        .iter()
        .map(|(key, set)| {
            json!({
                "key": key,
                "values": set.iter().cloned().collect::<Vec<_>>(),
                "root": merkle_root(
                    "COHESION-SET-MAP",
                    &set.iter().map(|value| json!(value)).collect::<Vec<_>>()
                ),
            })
        })
        .collect()
}

fn policy_root(domain: &str, leaves: &[Value]) -> String {
    merkle_root(domain, leaves)
}
