use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type LowFeeExecutionDerivativesResult<T> = Result<T, String>;

pub const LOW_FEE_EXECUTION_DERIVATIVES_PROTOCOL_VERSION: &str =
    "nebula-low-fee-execution-derivatives-v1";
pub const LOW_FEE_EXECUTION_DERIVATIVES_PQ_AUTH_SCHEME: &str =
    "ml-dsa-87-low-fee-execution-authorization-v1";
pub const LOW_FEE_EXECUTION_DERIVATIVES_PRIVATE_HEDGE_PROOF_SCHEME: &str =
    "zk-private-execution-hedge-proof-shake256-v1";
pub const LOW_FEE_EXECUTION_DERIVATIVES_SETTLEMENT_PROOF_SCHEME: &str =
    "zk-execution-cost-settlement-proof-shake256-v1";
pub const LOW_FEE_EXECUTION_DERIVATIVES_DEFAULT_HEIGHT: u64 = 64;
pub const LOW_FEE_EXECUTION_DERIVATIVES_DEFAULT_EPOCH_BLOCKS: u64 = 120;
pub const LOW_FEE_EXECUTION_DERIVATIVES_DEFAULT_QUOTE_TTL_BLOCKS: u64 = 16;
pub const LOW_FEE_EXECUTION_DERIVATIVES_DEFAULT_CONTRACT_TTL_BLOCKS: u64 = 720;
pub const LOW_FEE_EXECUTION_DERIVATIVES_DEFAULT_TRANCHE_TTL_BLOCKS: u64 = 480;
pub const LOW_FEE_EXECUTION_DERIVATIVES_DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 128;
pub const LOW_FEE_EXECUTION_DERIVATIVES_DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const LOW_FEE_EXECUTION_DERIVATIVES_DEFAULT_MARGIN_RATIO_BPS: u64 = 1_400;
pub const LOW_FEE_EXECUTION_DERIVATIVES_DEFAULT_SPONSOR_RESERVE_BPS: u64 = 2_000;
pub const LOW_FEE_EXECUTION_DERIVATIVES_MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionCostLane {
    PrivateTransfer,
    PrivateDefiSwap,
    ContractCall,
    ProofAggregation,
    DaBlob,
    MoneroBridge,
    WalletRecovery,
    EmergencyExit,
}

impl ExecutionCostLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrivateTransfer => "private_transfer",
            Self::PrivateDefiSwap => "private_defi_swap",
            Self::ContractCall => "contract_call",
            Self::ProofAggregation => "proof_aggregation",
            Self::DaBlob => "da_blob",
            Self::MoneroBridge => "monero_bridge",
            Self::WalletRecovery => "wallet_recovery",
            Self::EmergencyExit => "emergency_exit",
        }
    }

    pub fn default_unit_kind(self) -> ExecutionCostUnitKind {
        match self {
            Self::ProofAggregation => ExecutionCostUnitKind::ProofUnit,
            Self::DaBlob => ExecutionCostUnitKind::DaByte,
            _ => ExecutionCostUnitKind::GasUnit,
        }
    }

    pub fn default_target_micro_price(self) -> u64 {
        match self {
            Self::EmergencyExit => 300,
            Self::WalletRecovery => 450,
            Self::PrivateTransfer => 700,
            Self::MoneroBridge => 1_050,
            Self::PrivateDefiSwap => 1_350,
            Self::ContractCall => 1_700,
            Self::ProofAggregation => 2_200,
            Self::DaBlob => 2_800,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionCostUnitKind {
    GasUnit,
    ProofUnit,
    DaByte,
}

impl ExecutionCostUnitKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::GasUnit => "gas_unit",
            Self::ProofUnit => "proof_unit",
            Self::DaByte => "da_byte",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionDerivativeKind {
    Future,
    CallSpread,
    PutSpread,
    SponsoredCap,
    RebateSwap,
}

impl ExecutionDerivativeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Future => "future",
            Self::CallSpread => "call_spread",
            Self::PutSpread => "put_spread",
            Self::SponsoredCap => "sponsored_cap",
            Self::RebateSwap => "rebate_swap",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionHedgeSide {
    UserLongCost,
    SponsorShortCost,
    MarketMakerNeutral,
}

impl ExecutionHedgeSide {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::UserLongCost => "user_long_cost",
            Self::SponsorShortCost => "sponsor_short_cost",
            Self::MarketMakerNeutral => "market_maker_neutral",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionContractStatus {
    Open,
    Matched,
    Funded,
    Settled,
    Expired,
    Cancelled,
    Disputed,
}

impl ExecutionContractStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Matched => "matched",
            Self::Funded => "funded",
            Self::Settled => "settled",
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
            Self::Disputed => "disputed",
        }
    }

    pub fn live(self) -> bool {
        matches!(self, Self::Open | Self::Matched | Self::Funded)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsoredTrancheStatus {
    Open,
    Reserved,
    Settling,
    Settled,
    Exhausted,
    Expired,
    Revoked,
}

impl SponsoredTrancheStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Reserved => "reserved",
            Self::Settling => "settling",
            Self::Settled => "settled",
            Self::Exhausted => "exhausted",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
        }
    }

    pub fn spendable(self) -> bool {
        matches!(self, Self::Open | Self::Reserved | Self::Settling)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionSettlementStatus {
    Pending,
    Settled,
    Disputed,
    Expired,
}

impl ExecutionSettlementStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Settled => "settled",
            Self::Disputed => "disputed",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionOracleSource {
    SequencerTelemetry,
    ProverMarket,
    DaSamplingMarket,
    LowFeeMarket,
    BridgeQueue,
}

impl ExecutionOracleSource {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SequencerTelemetry => "sequencer_telemetry",
            Self::ProverMarket => "prover_market",
            Self::DaSamplingMarket => "da_sampling_market",
            Self::LowFeeMarket => "low_fee_market",
            Self::BridgeQueue => "bridge_queue",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeExecutionDerivativesConfig {
    pub protocol_version: String,
    pub chain_id: String,
    pub fee_asset_id: String,
    pub epoch_blocks: u64,
    pub quote_ttl_blocks: u64,
    pub contract_ttl_blocks: u64,
    pub tranche_ttl_blocks: u64,
    pub min_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub margin_ratio_bps: u64,
    pub sponsor_reserve_bps: u64,
}

impl Default for LowFeeExecutionDerivativesConfig {
    fn default() -> Self {
        Self {
            protocol_version: LOW_FEE_EXECUTION_DERIVATIVES_PROTOCOL_VERSION.to_string(),
            chain_id: CHAIN_ID.to_string(),
            fee_asset_id: "wxmr-devnet".to_string(),
            epoch_blocks: LOW_FEE_EXECUTION_DERIVATIVES_DEFAULT_EPOCH_BLOCKS,
            quote_ttl_blocks: LOW_FEE_EXECUTION_DERIVATIVES_DEFAULT_QUOTE_TTL_BLOCKS,
            contract_ttl_blocks: LOW_FEE_EXECUTION_DERIVATIVES_DEFAULT_CONTRACT_TTL_BLOCKS,
            tranche_ttl_blocks: LOW_FEE_EXECUTION_DERIVATIVES_DEFAULT_TRANCHE_TTL_BLOCKS,
            min_privacy_set_size: LOW_FEE_EXECUTION_DERIVATIVES_DEFAULT_MIN_PRIVACY_SET_SIZE,
            min_pq_security_bits: LOW_FEE_EXECUTION_DERIVATIVES_DEFAULT_MIN_PQ_SECURITY_BITS,
            margin_ratio_bps: LOW_FEE_EXECUTION_DERIVATIVES_DEFAULT_MARGIN_RATIO_BPS,
            sponsor_reserve_bps: LOW_FEE_EXECUTION_DERIVATIVES_DEFAULT_SPONSOR_RESERVE_BPS,
        }
    }
}

impl LowFeeExecutionDerivativesConfig {
    pub fn devnet() -> Self {
        Self {
            epoch_blocks: 60,
            quote_ttl_blocks: 12,
            contract_ttl_blocks: 360,
            tranche_ttl_blocks: 240,
            min_privacy_set_size: 96,
            margin_ratio_bps: 1_250,
            sponsor_reserve_bps: 1_500,
            ..Self::default()
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "low_fee_execution_derivatives_config",
            "protocol_version": self.protocol_version,
            "chain_id": self.chain_id,
            "fee_asset_id": self.fee_asset_id,
            "epoch_blocks": self.epoch_blocks,
            "quote_ttl_blocks": self.quote_ttl_blocks,
            "contract_ttl_blocks": self.contract_ttl_blocks,
            "tranche_ttl_blocks": self.tranche_ttl_blocks,
            "min_privacy_set_size": self.min_privacy_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
            "margin_ratio_bps": self.margin_ratio_bps,
            "sponsor_reserve_bps": self.sponsor_reserve_bps,
        })
    }

    pub fn config_root(&self) -> String {
        low_fee_execution_derivatives_payload_root(
            "LOW-FEE-EXECUTION-DERIVATIVES-CONFIG",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> LowFeeExecutionDerivativesResult<String> {
        require_non_empty("protocol version", &self.protocol_version)?;
        require_non_empty("chain id", &self.chain_id)?;
        require_non_empty("fee asset id", &self.fee_asset_id)?;
        require_positive("epoch blocks", self.epoch_blocks)?;
        require_positive("quote ttl blocks", self.quote_ttl_blocks)?;
        require_positive("contract ttl blocks", self.contract_ttl_blocks)?;
        require_positive("tranche ttl blocks", self.tranche_ttl_blocks)?;
        require_positive("minimum privacy set size", self.min_privacy_set_size)?;
        require_bps("margin ratio bps", self.margin_ratio_bps)?;
        require_bps("sponsor reserve bps", self.sponsor_reserve_bps)?;
        if self.quote_ttl_blocks >= self.contract_ttl_blocks {
            return Err("quote ttl must be shorter than contract ttl".to_string());
        }
        if self.min_privacy_set_size < 32 {
            return Err("minimum privacy set size must be at least 32".to_string());
        }
        if self.min_pq_security_bits < 192 {
            return Err("minimum pq security bits must be at least 192".to_string());
        }
        Ok(self.config_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionCostObservation {
    pub observation_id: String,
    pub lane: ExecutionCostLane,
    pub unit_kind: ExecutionCostUnitKind,
    pub source: ExecutionOracleSource,
    pub observed_micro_price: u64,
    pub target_micro_price: u64,
    pub volatility_bps: u64,
    pub confidence_bps: u64,
    pub sample_count: u64,
    pub privacy_set_size: u64,
    pub observed_at_height: u64,
    pub expires_at_height: u64,
    pub evidence_root: String,
}

impl ExecutionCostObservation {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        lane: ExecutionCostLane,
        unit_kind: ExecutionCostUnitKind,
        source: ExecutionOracleSource,
        observed_micro_price: u64,
        target_micro_price: u64,
        volatility_bps: u64,
        confidence_bps: u64,
        sample_count: u64,
        privacy_set_size: u64,
        observed_at_height: u64,
        expires_at_height: u64,
        evidence: &Value,
    ) -> LowFeeExecutionDerivativesResult<Self> {
        let evidence_root =
            low_fee_execution_derivatives_payload_root("LOW-FEE-EXECUTION-COST-EVIDENCE", evidence);
        let observation_id = execution_cost_observation_id(
            lane,
            unit_kind,
            source,
            observed_micro_price,
            observed_at_height,
            &evidence_root,
        );
        let observation = Self {
            observation_id,
            lane,
            unit_kind,
            source,
            observed_micro_price,
            target_micro_price,
            volatility_bps,
            confidence_bps,
            sample_count,
            privacy_set_size,
            observed_at_height,
            expires_at_height,
            evidence_root,
        };
        observation.validate()?;
        Ok(observation)
    }

    pub fn premium_bps(&self) -> u64 {
        if self.target_micro_price == 0 {
            return 0;
        }
        self.observed_micro_price
            .saturating_sub(self.target_micro_price)
            .saturating_mul(LOW_FEE_EXECUTION_DERIVATIVES_MAX_BPS)
            / self.target_micro_price
    }

    pub fn active_at(&self, height: u64) -> bool {
        height < self.expires_at_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "execution_cost_observation",
            "protocol_version": LOW_FEE_EXECUTION_DERIVATIVES_PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "observation_id": self.observation_id,
            "lane": self.lane.as_str(),
            "unit_kind": self.unit_kind.as_str(),
            "source": self.source.as_str(),
            "observed_micro_price": self.observed_micro_price,
            "target_micro_price": self.target_micro_price,
            "premium_bps": self.premium_bps(),
            "volatility_bps": self.volatility_bps,
            "confidence_bps": self.confidence_bps,
            "sample_count": self.sample_count,
            "privacy_set_size": self.privacy_set_size,
            "observed_at_height": self.observed_at_height,
            "expires_at_height": self.expires_at_height,
            "evidence_root": self.evidence_root,
        })
    }

    pub fn state_root(&self) -> String {
        low_fee_execution_derivatives_payload_root(
            "LOW-FEE-EXECUTION-COST-OBSERVATION",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> LowFeeExecutionDerivativesResult<String> {
        require_non_empty("observation id", &self.observation_id)?;
        require_positive("observed micro price", self.observed_micro_price)?;
        require_positive("target micro price", self.target_micro_price)?;
        require_bps("volatility bps", self.volatility_bps)?;
        require_bps("confidence bps", self.confidence_bps)?;
        require_positive("sample count", self.sample_count)?;
        require_positive("privacy set size", self.privacy_set_size)?;
        require_height_window(
            "observation",
            self.observed_at_height,
            self.expires_at_height,
        )?;
        require_non_empty("evidence root", &self.evidence_root)?;
        Ok(self.observation_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqExecutionAuthorization {
    pub authorization_id: String,
    pub account_commitment: String,
    pub scope: String,
    pub allowed_lane: ExecutionCostLane,
    pub max_notional_units: u64,
    pub nonce: u64,
    pub valid_from_height: u64,
    pub expires_at_height: u64,
    pub pq_security_bits: u16,
    pub public_key_commitment: String,
    pub signature_root: String,
}

impl PqExecutionAuthorization {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        account_commitment: &str,
        scope: &str,
        allowed_lane: ExecutionCostLane,
        max_notional_units: u64,
        nonce: u64,
        valid_from_height: u64,
        expires_at_height: u64,
        pq_security_bits: u16,
        public_key_commitment: &str,
        signature: &Value,
    ) -> LowFeeExecutionDerivativesResult<Self> {
        require_non_empty("account commitment", account_commitment)?;
        require_non_empty("authorization scope", scope)?;
        require_non_empty("public key commitment", public_key_commitment)?;
        let signature_root = low_fee_execution_derivatives_payload_root(
            "LOW-FEE-EXECUTION-PQ-AUTH-SIGNATURE",
            signature,
        );
        let authorization_id = pq_execution_authorization_id(
            account_commitment,
            scope,
            allowed_lane,
            nonce,
            valid_from_height,
            &signature_root,
        );
        let authorization = Self {
            authorization_id,
            account_commitment: account_commitment.to_string(),
            scope: scope.to_string(),
            allowed_lane,
            max_notional_units,
            nonce,
            valid_from_height,
            expires_at_height,
            pq_security_bits,
            public_key_commitment: public_key_commitment.to_string(),
            signature_root,
        };
        authorization.validate()?;
        Ok(authorization)
    }

    pub fn active_at(&self, height: u64) -> bool {
        height >= self.valid_from_height && height < self.expires_at_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_execution_authorization",
            "protocol_version": LOW_FEE_EXECUTION_DERIVATIVES_PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "scheme": LOW_FEE_EXECUTION_DERIVATIVES_PQ_AUTH_SCHEME,
            "authorization_id": self.authorization_id,
            "account_commitment": self.account_commitment,
            "scope": self.scope,
            "allowed_lane": self.allowed_lane.as_str(),
            "max_notional_units": self.max_notional_units,
            "nonce": self.nonce,
            "valid_from_height": self.valid_from_height,
            "expires_at_height": self.expires_at_height,
            "pq_security_bits": self.pq_security_bits,
            "public_key_commitment": self.public_key_commitment,
            "signature_root": self.signature_root,
        })
    }

    pub fn state_root(&self) -> String {
        low_fee_execution_derivatives_payload_root(
            "LOW-FEE-EXECUTION-PQ-AUTHORIZATION",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> LowFeeExecutionDerivativesResult<String> {
        require_non_empty("authorization id", &self.authorization_id)?;
        require_non_empty("account commitment", &self.account_commitment)?;
        require_non_empty("authorization scope", &self.scope)?;
        require_positive("max notional units", self.max_notional_units)?;
        require_height_window(
            "authorization",
            self.valid_from_height,
            self.expires_at_height,
        )?;
        if self.pq_security_bits < 192 {
            return Err("pq authorization security below 192 bits".to_string());
        }
        require_non_empty("public key commitment", &self.public_key_commitment)?;
        require_non_empty("signature root", &self.signature_root)?;
        Ok(self.authorization_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateExecutionHedge {
    pub hedge_id: String,
    pub owner_commitment: String,
    pub authorization_id: String,
    pub lane: ExecutionCostLane,
    pub unit_kind: ExecutionCostUnitKind,
    pub side: ExecutionHedgeSide,
    pub notional_units: u64,
    pub max_slippage_bps: u64,
    pub margin_units: u64,
    pub privacy_set_size: u64,
    pub hedge_proof_root: String,
    pub posted_at_height: u64,
    pub expires_at_height: u64,
    pub status: ExecutionContractStatus,
}

impl PrivateExecutionHedge {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        owner_commitment: &str,
        authorization_id: &str,
        lane: ExecutionCostLane,
        unit_kind: ExecutionCostUnitKind,
        side: ExecutionHedgeSide,
        notional_units: u64,
        max_slippage_bps: u64,
        margin_units: u64,
        privacy_set_size: u64,
        hedge_proof: &Value,
        posted_at_height: u64,
        expires_at_height: u64,
    ) -> LowFeeExecutionDerivativesResult<Self> {
        require_non_empty("owner commitment", owner_commitment)?;
        require_non_empty("authorization id", authorization_id)?;
        let hedge_proof_root = low_fee_execution_derivatives_payload_root(
            "LOW-FEE-EXECUTION-HEDGE-PROOF",
            hedge_proof,
        );
        let hedge_id = private_execution_hedge_id(
            owner_commitment,
            authorization_id,
            lane,
            side,
            posted_at_height,
            &hedge_proof_root,
        );
        let hedge = Self {
            hedge_id,
            owner_commitment: owner_commitment.to_string(),
            authorization_id: authorization_id.to_string(),
            lane,
            unit_kind,
            side,
            notional_units,
            max_slippage_bps,
            margin_units,
            privacy_set_size,
            hedge_proof_root,
            posted_at_height,
            expires_at_height,
            status: ExecutionContractStatus::Open,
        };
        hedge.validate()?;
        Ok(hedge)
    }

    pub fn collateralization_bps(&self) -> u64 {
        if self.notional_units == 0 {
            return 0;
        }
        self.margin_units
            .saturating_mul(LOW_FEE_EXECUTION_DERIVATIVES_MAX_BPS)
            / self.notional_units
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_execution_hedge",
            "protocol_version": LOW_FEE_EXECUTION_DERIVATIVES_PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "proof_scheme": LOW_FEE_EXECUTION_DERIVATIVES_PRIVATE_HEDGE_PROOF_SCHEME,
            "hedge_id": self.hedge_id,
            "owner_commitment": self.owner_commitment,
            "authorization_id": self.authorization_id,
            "lane": self.lane.as_str(),
            "unit_kind": self.unit_kind.as_str(),
            "side": self.side.as_str(),
            "notional_units": self.notional_units,
            "max_slippage_bps": self.max_slippage_bps,
            "margin_units": self.margin_units,
            "collateralization_bps": self.collateralization_bps(),
            "privacy_set_size": self.privacy_set_size,
            "hedge_proof_root": self.hedge_proof_root,
            "posted_at_height": self.posted_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn state_root(&self) -> String {
        low_fee_execution_derivatives_payload_root(
            "LOW-FEE-PRIVATE-EXECUTION-HEDGE",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> LowFeeExecutionDerivativesResult<String> {
        require_non_empty("hedge id", &self.hedge_id)?;
        require_non_empty("owner commitment", &self.owner_commitment)?;
        require_non_empty("authorization id", &self.authorization_id)?;
        require_positive("notional units", self.notional_units)?;
        require_bps("max slippage bps", self.max_slippage_bps)?;
        require_positive("margin units", self.margin_units)?;
        require_positive("privacy set size", self.privacy_set_size)?;
        require_height_window("hedge", self.posted_at_height, self.expires_at_height)?;
        require_non_empty("hedge proof root", &self.hedge_proof_root)?;
        Ok(self.hedge_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SponsoredExecutionTranche {
    pub tranche_id: String,
    pub sponsor_commitment: String,
    pub lane: ExecutionCostLane,
    pub unit_kind: ExecutionCostUnitKind,
    pub fee_asset_id: String,
    pub capacity_units: u64,
    pub reserved_units: u64,
    pub settled_units: u64,
    pub max_rebate_bps: u64,
    pub cap_micro_price: u64,
    pub min_privacy_set_size: u64,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub policy_root: String,
    pub status: SponsoredTrancheStatus,
}

impl SponsoredExecutionTranche {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        sponsor_commitment: &str,
        lane: ExecutionCostLane,
        unit_kind: ExecutionCostUnitKind,
        fee_asset_id: &str,
        capacity_units: u64,
        max_rebate_bps: u64,
        cap_micro_price: u64,
        min_privacy_set_size: u64,
        opened_at_height: u64,
        expires_at_height: u64,
        policy: &Value,
    ) -> LowFeeExecutionDerivativesResult<Self> {
        require_non_empty("sponsor commitment", sponsor_commitment)?;
        require_non_empty("fee asset id", fee_asset_id)?;
        let policy_root =
            low_fee_execution_derivatives_payload_root("LOW-FEE-EXECUTION-TRANCHE-POLICY", policy);
        let tranche_id = sponsored_execution_tranche_id(
            sponsor_commitment,
            lane,
            unit_kind,
            fee_asset_id,
            opened_at_height,
            &policy_root,
        );
        let tranche = Self {
            tranche_id,
            sponsor_commitment: sponsor_commitment.to_string(),
            lane,
            unit_kind,
            fee_asset_id: fee_asset_id.to_string(),
            capacity_units,
            reserved_units: 0,
            settled_units: 0,
            max_rebate_bps,
            cap_micro_price,
            min_privacy_set_size,
            opened_at_height,
            expires_at_height,
            policy_root,
            status: SponsoredTrancheStatus::Open,
        };
        tranche.validate()?;
        Ok(tranche)
    }

    pub fn available_units(&self) -> u64 {
        self.capacity_units
            .saturating_sub(self.reserved_units)
            .saturating_sub(self.settled_units)
    }

    pub fn reserve_units(
        &mut self,
        units: u64,
        height: u64,
    ) -> LowFeeExecutionDerivativesResult<String> {
        require_positive("reserve units", units)?;
        if !self.status.spendable() || height >= self.expires_at_height {
            return Err("sponsored tranche is not spendable".to_string());
        }
        if units > self.available_units() {
            return Err("insufficient sponsored tranche capacity".to_string());
        }
        self.reserved_units = self.reserved_units.saturating_add(units);
        self.status = SponsoredTrancheStatus::Reserved;
        self.validate()?;
        Ok(self.state_root())
    }

    pub fn settle_units(
        &mut self,
        reserved_units: u64,
        settled_units: u64,
    ) -> LowFeeExecutionDerivativesResult<String> {
        require_positive("settled units", settled_units)?;
        if reserved_units > self.reserved_units {
            return Err("settlement exceeds reserved tranche units".to_string());
        }
        if settled_units > reserved_units {
            return Err("settled units exceed released reserve".to_string());
        }
        self.reserved_units = self.reserved_units.saturating_sub(reserved_units);
        self.settled_units = self.settled_units.saturating_add(settled_units);
        self.status = if self.available_units() == 0 {
            SponsoredTrancheStatus::Exhausted
        } else {
            SponsoredTrancheStatus::Settling
        };
        self.validate()?;
        Ok(self.state_root())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "sponsored_execution_tranche",
            "protocol_version": LOW_FEE_EXECUTION_DERIVATIVES_PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "tranche_id": self.tranche_id,
            "sponsor_commitment": self.sponsor_commitment,
            "lane": self.lane.as_str(),
            "unit_kind": self.unit_kind.as_str(),
            "fee_asset_id": self.fee_asset_id,
            "capacity_units": self.capacity_units,
            "reserved_units": self.reserved_units,
            "settled_units": self.settled_units,
            "available_units": self.available_units(),
            "max_rebate_bps": self.max_rebate_bps,
            "cap_micro_price": self.cap_micro_price,
            "min_privacy_set_size": self.min_privacy_set_size,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "policy_root": self.policy_root,
            "status": self.status.as_str(),
        })
    }

    pub fn state_root(&self) -> String {
        low_fee_execution_derivatives_payload_root(
            "LOW-FEE-SPONSORED-EXECUTION-TRANCHE",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> LowFeeExecutionDerivativesResult<String> {
        require_non_empty("tranche id", &self.tranche_id)?;
        require_non_empty("sponsor commitment", &self.sponsor_commitment)?;
        require_non_empty("fee asset id", &self.fee_asset_id)?;
        require_positive("capacity units", self.capacity_units)?;
        if self.reserved_units.saturating_add(self.settled_units) > self.capacity_units {
            return Err("sponsored tranche accounting exceeds capacity".to_string());
        }
        require_bps("max rebate bps", self.max_rebate_bps)?;
        require_positive("cap micro price", self.cap_micro_price)?;
        require_positive("minimum privacy set size", self.min_privacy_set_size)?;
        require_height_window("tranche", self.opened_at_height, self.expires_at_height)?;
        require_non_empty("policy root", &self.policy_root)?;
        Ok(self.tranche_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionDerivativeContract {
    pub contract_id: String,
    pub hedge_id: String,
    pub tranche_id: String,
    pub lane: ExecutionCostLane,
    pub unit_kind: ExecutionCostUnitKind,
    pub derivative_kind: ExecutionDerivativeKind,
    pub side: ExecutionHedgeSide,
    pub notional_units: u64,
    pub strike_micro_price: u64,
    pub cap_micro_price: u64,
    pub premium_units: u64,
    pub margin_units: u64,
    pub opened_at_height: u64,
    pub maturity_height: u64,
    pub privacy_nullifier_root: String,
    pub status: ExecutionContractStatus,
}

impl ExecutionDerivativeContract {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        hedge_id: &str,
        tranche_id: &str,
        lane: ExecutionCostLane,
        unit_kind: ExecutionCostUnitKind,
        derivative_kind: ExecutionDerivativeKind,
        side: ExecutionHedgeSide,
        notional_units: u64,
        strike_micro_price: u64,
        cap_micro_price: u64,
        premium_units: u64,
        margin_units: u64,
        opened_at_height: u64,
        maturity_height: u64,
        privacy_nullifier: &Value,
    ) -> LowFeeExecutionDerivativesResult<Self> {
        require_non_empty("hedge id", hedge_id)?;
        require_non_empty("tranche id", tranche_id)?;
        let privacy_nullifier_root = low_fee_execution_derivatives_payload_root(
            "LOW-FEE-EXECUTION-CONTRACT-NULLIFIER",
            privacy_nullifier,
        );
        let contract_id = execution_derivative_contract_id(
            hedge_id,
            tranche_id,
            lane,
            derivative_kind,
            strike_micro_price,
            maturity_height,
            &privacy_nullifier_root,
        );
        let contract = Self {
            contract_id,
            hedge_id: hedge_id.to_string(),
            tranche_id: tranche_id.to_string(),
            lane,
            unit_kind,
            derivative_kind,
            side,
            notional_units,
            strike_micro_price,
            cap_micro_price,
            premium_units,
            margin_units,
            opened_at_height,
            maturity_height,
            privacy_nullifier_root,
            status: ExecutionContractStatus::Matched,
        };
        contract.validate()?;
        Ok(contract)
    }

    pub fn payoff_units(&self, observed_micro_price: u64) -> u64 {
        let spread = match self.derivative_kind {
            ExecutionDerivativeKind::Future | ExecutionDerivativeKind::SponsoredCap => {
                observed_micro_price.saturating_sub(self.strike_micro_price)
            }
            ExecutionDerivativeKind::CallSpread => observed_micro_price
                .min(self.cap_micro_price)
                .saturating_sub(self.strike_micro_price),
            ExecutionDerivativeKind::PutSpread => self
                .strike_micro_price
                .saturating_sub(observed_micro_price)
                .min(self.cap_micro_price.saturating_sub(observed_micro_price)),
            ExecutionDerivativeKind::RebateSwap => self.cap_micro_price.saturating_sub(
                observed_micro_price
                    .saturating_sub(self.strike_micro_price)
                    .saturating_add(self.strike_micro_price),
            ),
        };
        spread.saturating_mul(self.notional_units) / 1_000_000
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "execution_derivative_contract",
            "protocol_version": LOW_FEE_EXECUTION_DERIVATIVES_PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "contract_id": self.contract_id,
            "hedge_id": self.hedge_id,
            "tranche_id": self.tranche_id,
            "lane": self.lane.as_str(),
            "unit_kind": self.unit_kind.as_str(),
            "derivative_kind": self.derivative_kind.as_str(),
            "side": self.side.as_str(),
            "notional_units": self.notional_units,
            "strike_micro_price": self.strike_micro_price,
            "cap_micro_price": self.cap_micro_price,
            "premium_units": self.premium_units,
            "margin_units": self.margin_units,
            "opened_at_height": self.opened_at_height,
            "maturity_height": self.maturity_height,
            "privacy_nullifier_root": self.privacy_nullifier_root,
            "status": self.status.as_str(),
        })
    }

    pub fn state_root(&self) -> String {
        low_fee_execution_derivatives_payload_root(
            "LOW-FEE-EXECUTION-DERIVATIVE-CONTRACT",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> LowFeeExecutionDerivativesResult<String> {
        require_non_empty("contract id", &self.contract_id)?;
        require_non_empty("hedge id", &self.hedge_id)?;
        require_non_empty("tranche id", &self.tranche_id)?;
        require_positive("notional units", self.notional_units)?;
        require_positive("strike micro price", self.strike_micro_price)?;
        if matches!(
            self.derivative_kind,
            ExecutionDerivativeKind::CallSpread
                | ExecutionDerivativeKind::PutSpread
                | ExecutionDerivativeKind::SponsoredCap
                | ExecutionDerivativeKind::RebateSwap
        ) && self.cap_micro_price < self.strike_micro_price
        {
            return Err(
                "cap micro price must be at least strike for capped derivatives".to_string(),
            );
        }
        require_positive("margin units", self.margin_units)?;
        require_height_window("contract", self.opened_at_height, self.maturity_height)?;
        require_non_empty("privacy nullifier root", &self.privacy_nullifier_root)?;
        Ok(self.contract_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionSettlementReceipt {
    pub receipt_id: String,
    pub contract_id: String,
    pub tranche_id: String,
    pub observation_id: String,
    pub lane: ExecutionCostLane,
    pub unit_kind: ExecutionCostUnitKind,
    pub notional_units: u64,
    pub strike_micro_price: u64,
    pub observed_micro_price: u64,
    pub sponsor_paid_units: u64,
    pub user_rebate_units: u64,
    pub settlement_proof_root: String,
    pub settled_at_height: u64,
    pub status: ExecutionSettlementStatus,
}

impl ExecutionSettlementReceipt {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        contract_id: &str,
        tranche_id: &str,
        observation_id: &str,
        lane: ExecutionCostLane,
        unit_kind: ExecutionCostUnitKind,
        notional_units: u64,
        strike_micro_price: u64,
        observed_micro_price: u64,
        sponsor_paid_units: u64,
        user_rebate_units: u64,
        settlement_proof: &Value,
        settled_at_height: u64,
        status: ExecutionSettlementStatus,
    ) -> LowFeeExecutionDerivativesResult<Self> {
        require_non_empty("contract id", contract_id)?;
        require_non_empty("tranche id", tranche_id)?;
        require_non_empty("observation id", observation_id)?;
        let settlement_proof_root = low_fee_execution_derivatives_payload_root(
            "LOW-FEE-EXECUTION-SETTLEMENT-PROOF",
            settlement_proof,
        );
        let receipt_id = execution_settlement_receipt_id(
            contract_id,
            tranche_id,
            observation_id,
            lane,
            settled_at_height,
            &settlement_proof_root,
        );
        let receipt = Self {
            receipt_id,
            contract_id: contract_id.to_string(),
            tranche_id: tranche_id.to_string(),
            observation_id: observation_id.to_string(),
            lane,
            unit_kind,
            notional_units,
            strike_micro_price,
            observed_micro_price,
            sponsor_paid_units,
            user_rebate_units,
            settlement_proof_root,
            settled_at_height,
            status,
        };
        receipt.validate()?;
        Ok(receipt)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "execution_settlement_receipt",
            "protocol_version": LOW_FEE_EXECUTION_DERIVATIVES_PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "proof_scheme": LOW_FEE_EXECUTION_DERIVATIVES_SETTLEMENT_PROOF_SCHEME,
            "receipt_id": self.receipt_id,
            "contract_id": self.contract_id,
            "tranche_id": self.tranche_id,
            "observation_id": self.observation_id,
            "lane": self.lane.as_str(),
            "unit_kind": self.unit_kind.as_str(),
            "notional_units": self.notional_units,
            "strike_micro_price": self.strike_micro_price,
            "observed_micro_price": self.observed_micro_price,
            "sponsor_paid_units": self.sponsor_paid_units,
            "user_rebate_units": self.user_rebate_units,
            "settlement_proof_root": self.settlement_proof_root,
            "settled_at_height": self.settled_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn state_root(&self) -> String {
        low_fee_execution_derivatives_payload_root(
            "LOW-FEE-EXECUTION-SETTLEMENT-RECEIPT",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> LowFeeExecutionDerivativesResult<String> {
        require_non_empty("receipt id", &self.receipt_id)?;
        require_non_empty("contract id", &self.contract_id)?;
        require_non_empty("tranche id", &self.tranche_id)?;
        require_non_empty("observation id", &self.observation_id)?;
        require_positive("notional units", self.notional_units)?;
        require_positive("strike micro price", self.strike_micro_price)?;
        require_positive("observed micro price", self.observed_micro_price)?;
        require_non_empty("settlement proof root", &self.settlement_proof_root)?;
        Ok(self.receipt_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeExecutionDerivativesRoots {
    pub config_root: String,
    pub observation_root: String,
    pub authorization_root: String,
    pub hedge_root: String,
    pub tranche_root: String,
    pub contract_root: String,
    pub receipt_root: String,
    pub active_lane_root: String,
    pub public_record_root: String,
}

impl LowFeeExecutionDerivativesRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "low_fee_execution_derivatives_roots",
            "protocol_version": LOW_FEE_EXECUTION_DERIVATIVES_PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "config_root": self.config_root,
            "observation_root": self.observation_root,
            "authorization_root": self.authorization_root,
            "hedge_root": self.hedge_root,
            "tranche_root": self.tranche_root,
            "contract_root": self.contract_root,
            "receipt_root": self.receipt_root,
            "active_lane_root": self.active_lane_root,
            "public_record_root": self.public_record_root,
        })
    }

    pub fn roots_root(&self) -> String {
        low_fee_execution_derivatives_payload_root(
            "LOW-FEE-EXECUTION-DERIVATIVES-ROOTS",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeExecutionDerivativesCounters {
    pub observation_count: u64,
    pub active_observation_count: u64,
    pub authorization_count: u64,
    pub active_authorization_count: u64,
    pub hedge_count: u64,
    pub live_hedge_count: u64,
    pub tranche_count: u64,
    pub spendable_tranche_count: u64,
    pub contract_count: u64,
    pub live_contract_count: u64,
    pub receipt_count: u64,
    pub total_live_notional_units: u64,
    pub total_tranche_available_units: u64,
    pub total_user_rebate_units: u64,
    pub total_sponsor_paid_units: u64,
}

impl LowFeeExecutionDerivativesCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "low_fee_execution_derivatives_counters",
            "protocol_version": LOW_FEE_EXECUTION_DERIVATIVES_PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "observation_count": self.observation_count,
            "active_observation_count": self.active_observation_count,
            "authorization_count": self.authorization_count,
            "active_authorization_count": self.active_authorization_count,
            "hedge_count": self.hedge_count,
            "live_hedge_count": self.live_hedge_count,
            "tranche_count": self.tranche_count,
            "spendable_tranche_count": self.spendable_tranche_count,
            "contract_count": self.contract_count,
            "live_contract_count": self.live_contract_count,
            "receipt_count": self.receipt_count,
            "total_live_notional_units": self.total_live_notional_units,
            "total_tranche_available_units": self.total_tranche_available_units,
            "total_user_rebate_units": self.total_user_rebate_units,
            "total_sponsor_paid_units": self.total_sponsor_paid_units,
        })
    }

    pub fn counters_root(&self) -> String {
        low_fee_execution_derivatives_payload_root(
            "LOW-FEE-EXECUTION-DERIVATIVES-COUNTERS",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeExecutionDerivativesState {
    pub config: LowFeeExecutionDerivativesConfig,
    pub height: u64,
    pub observations: BTreeMap<String, ExecutionCostObservation>,
    pub authorizations: BTreeMap<String, PqExecutionAuthorization>,
    pub hedges: BTreeMap<String, PrivateExecutionHedge>,
    pub tranches: BTreeMap<String, SponsoredExecutionTranche>,
    pub contracts: BTreeMap<String, ExecutionDerivativeContract>,
    pub settlement_receipts: BTreeMap<String, ExecutionSettlementReceipt>,
}

impl LowFeeExecutionDerivativesState {
    pub fn devnet() -> LowFeeExecutionDerivativesResult<Self> {
        let config = LowFeeExecutionDerivativesConfig::devnet();
        let height = LOW_FEE_EXECUTION_DERIVATIVES_DEFAULT_HEIGHT;
        let mut state = Self {
            config,
            height,
            observations: BTreeMap::new(),
            authorizations: BTreeMap::new(),
            hedges: BTreeMap::new(),
            tranches: BTreeMap::new(),
            contracts: BTreeMap::new(),
            settlement_receipts: BTreeMap::new(),
        };

        let user_commitment = low_fee_execution_derivatives_string_root(
            "LOW-FEE-EXECUTION-DEVNET-USER",
            "defi-user-0",
        );
        let sponsor_commitment = low_fee_execution_derivatives_string_root(
            "LOW-FEE-EXECUTION-DEVNET-SPONSOR",
            "foundation-sponsor-0",
        );
        let public_key_commitment = low_fee_execution_derivatives_string_root(
            "LOW-FEE-EXECUTION-DEVNET-PQ-KEY",
            "ml-dsa-devnet-key-0",
        );

        let observation = ExecutionCostObservation::new(
            ExecutionCostLane::PrivateDefiSwap,
            ExecutionCostUnitKind::GasUnit,
            ExecutionOracleSource::SequencerTelemetry,
            1_950,
            ExecutionCostLane::PrivateDefiSwap.default_target_micro_price(),
            1_800,
            9_200,
            128,
            160,
            height,
            height.saturating_add(state.config.quote_ttl_blocks),
            &json!({"samples": [1810, 1950, 1880], "queue_depth": 42}),
        )?;
        let observation_id = state.insert_observation(observation)?;

        let authorization = PqExecutionAuthorization::new(
            &user_commitment,
            "private-defi-cost-hedge",
            ExecutionCostLane::PrivateDefiSwap,
            250_000,
            1,
            height,
            height.saturating_add(state.config.contract_ttl_blocks),
            256,
            &public_key_commitment,
            &json!({"scheme": LOW_FEE_EXECUTION_DERIVATIVES_PQ_AUTH_SCHEME, "devnet": true}),
        )?;
        let authorization_id = state.insert_authorization(authorization)?;

        let hedge = PrivateExecutionHedge::new(
            &user_commitment,
            &authorization_id,
            ExecutionCostLane::PrivateDefiSwap,
            ExecutionCostUnitKind::GasUnit,
            ExecutionHedgeSide::UserLongCost,
            100_000,
            600,
            16_000,
            160,
            &json!({"nullifier_set": "devnet-private-hedge", "range": "0..100000"}),
            height,
            height.saturating_add(state.config.contract_ttl_blocks),
        )?;
        let hedge_id = state.insert_hedge(hedge)?;

        let tranche = SponsoredExecutionTranche::new(
            &sponsor_commitment,
            ExecutionCostLane::PrivateDefiSwap,
            ExecutionCostUnitKind::GasUnit,
            &state.config.fee_asset_id,
            500_000,
            7_500,
            2_200,
            160,
            height,
            height.saturating_add(state.config.tranche_ttl_blocks),
            &json!({"purpose": "private defi fee caps", "sponsor_reserve_bps": state.config.sponsor_reserve_bps}),
        )?;
        let tranche_id = state.insert_tranche(tranche)?;

        let contract = ExecutionDerivativeContract::new(
            &hedge_id,
            &tranche_id,
            ExecutionCostLane::PrivateDefiSwap,
            ExecutionCostUnitKind::GasUnit,
            ExecutionDerivativeKind::SponsoredCap,
            ExecutionHedgeSide::UserLongCost,
            100_000,
            1_500,
            2_200,
            1_200,
            16_000,
            height,
            height.saturating_add(180),
            &json!({"owner": user_commitment, "nonce": 1}),
        )?;
        let contract_id = state.insert_contract(contract)?;

        let receipt = ExecutionSettlementReceipt::new(
            &contract_id,
            &tranche_id,
            &observation_id,
            ExecutionCostLane::PrivateDefiSwap,
            ExecutionCostUnitKind::GasUnit,
            100_000,
            1_500,
            1_950,
            45,
            45,
            &json!({"settlement": "devnet-sample", "observation_id": observation_id}),
            height.saturating_add(1),
            ExecutionSettlementStatus::Settled,
        )?;
        state.insert_settlement_receipt(receipt)?;
        state.validate()?;
        Ok(state)
    }

    pub fn insert_observation(
        &mut self,
        observation: ExecutionCostObservation,
    ) -> LowFeeExecutionDerivativesResult<String> {
        let observation_id = observation.validate()?;
        if observation.privacy_set_size < self.config.min_privacy_set_size {
            return Err("execution observation privacy set below configured floor".to_string());
        }
        self.observations
            .insert(observation_id.clone(), observation);
        Ok(observation_id)
    }

    pub fn insert_authorization(
        &mut self,
        authorization: PqExecutionAuthorization,
    ) -> LowFeeExecutionDerivativesResult<String> {
        let authorization_id = authorization.validate()?;
        if authorization.pq_security_bits < self.config.min_pq_security_bits {
            return Err("pq authorization security below configured floor".to_string());
        }
        self.authorizations
            .insert(authorization_id.clone(), authorization);
        Ok(authorization_id)
    }

    pub fn insert_hedge(
        &mut self,
        hedge: PrivateExecutionHedge,
    ) -> LowFeeExecutionDerivativesResult<String> {
        let hedge_id = hedge.validate()?;
        if !self.authorizations.contains_key(&hedge.authorization_id) {
            return Err("private execution hedge references missing authorization".to_string());
        }
        if hedge.privacy_set_size < self.config.min_privacy_set_size {
            return Err("private execution hedge privacy set below configured floor".to_string());
        }
        self.hedges.insert(hedge_id.clone(), hedge);
        Ok(hedge_id)
    }

    pub fn insert_tranche(
        &mut self,
        tranche: SponsoredExecutionTranche,
    ) -> LowFeeExecutionDerivativesResult<String> {
        let tranche_id = tranche.validate()?;
        if tranche.min_privacy_set_size < self.config.min_privacy_set_size {
            return Err(
                "sponsored execution tranche privacy set below configured floor".to_string(),
            );
        }
        self.tranches.insert(tranche_id.clone(), tranche);
        Ok(tranche_id)
    }

    pub fn insert_contract(
        &mut self,
        contract: ExecutionDerivativeContract,
    ) -> LowFeeExecutionDerivativesResult<String> {
        let contract_id = contract.validate()?;
        if !self.hedges.contains_key(&contract.hedge_id) {
            return Err("execution derivative references missing hedge".to_string());
        }
        if !self.tranches.contains_key(&contract.tranche_id) {
            return Err("execution derivative references missing sponsored tranche".to_string());
        }
        self.contracts.insert(contract_id.clone(), contract);
        Ok(contract_id)
    }

    pub fn insert_settlement_receipt(
        &mut self,
        receipt: ExecutionSettlementReceipt,
    ) -> LowFeeExecutionDerivativesResult<String> {
        let receipt_id = receipt.validate()?;
        if !self.contracts.contains_key(&receipt.contract_id) {
            return Err("execution settlement references missing contract".to_string());
        }
        if !self.tranches.contains_key(&receipt.tranche_id) {
            return Err("execution settlement references missing sponsored tranche".to_string());
        }
        if !self.observations.contains_key(&receipt.observation_id) {
            return Err("execution settlement references missing observation".to_string());
        }
        self.settlement_receipts.insert(receipt_id.clone(), receipt);
        Ok(receipt_id)
    }

    pub fn set_height(&mut self, height: u64) -> LowFeeExecutionDerivativesResult<String> {
        self.height = height;
        for hedge in self.hedges.values_mut() {
            if hedge.status.live() && height >= hedge.expires_at_height {
                hedge.status = ExecutionContractStatus::Expired;
            }
        }
        for contract in self.contracts.values_mut() {
            if contract.status.live() && height >= contract.maturity_height {
                contract.status = ExecutionContractStatus::Expired;
            }
        }
        for tranche in self.tranches.values_mut() {
            if tranche.status.spendable() && height >= tranche.expires_at_height {
                tranche.status = SponsoredTrancheStatus::Expired;
            }
        }
        self.validate()
    }

    pub fn active_lane_map(&self) -> BTreeMap<String, u64> {
        let mut lanes = BTreeMap::new();
        for contract in self
            .contracts
            .values()
            .filter(|contract| contract.status.live())
        {
            let entry = lanes
                .entry(contract.lane.as_str().to_string())
                .or_insert(0_u64);
            *entry = entry.saturating_add(contract.notional_units);
        }
        lanes
    }

    pub fn active_contract_ids(&self) -> Vec<String> {
        self.contracts
            .values()
            .filter(|contract| contract.status.live())
            .map(|contract| contract.contract_id.clone())
            .collect()
    }

    pub fn roots(&self) -> LowFeeExecutionDerivativesRoots {
        LowFeeExecutionDerivativesRoots {
            config_root: self.config.config_root(),
            observation_root: keyed_value_root(
                "LOW-FEE-EXECUTION-OBSERVATIONS",
                self.observations
                    .values()
                    .map(|item| (item.observation_id.clone(), item.public_record()))
                    .collect(),
            ),
            authorization_root: keyed_value_root(
                "LOW-FEE-EXECUTION-PQ-AUTHORIZATIONS",
                self.authorizations
                    .values()
                    .map(|item| (item.authorization_id.clone(), item.public_record()))
                    .collect(),
            ),
            hedge_root: keyed_value_root(
                "LOW-FEE-EXECUTION-HEDGES",
                self.hedges
                    .values()
                    .map(|item| (item.hedge_id.clone(), item.public_record()))
                    .collect(),
            ),
            tranche_root: keyed_value_root(
                "LOW-FEE-EXECUTION-TRANCHES",
                self.tranches
                    .values()
                    .map(|item| (item.tranche_id.clone(), item.public_record()))
                    .collect(),
            ),
            contract_root: keyed_value_root(
                "LOW-FEE-EXECUTION-CONTRACTS",
                self.contracts
                    .values()
                    .map(|item| (item.contract_id.clone(), item.public_record()))
                    .collect(),
            ),
            receipt_root: keyed_value_root(
                "LOW-FEE-EXECUTION-SETTLEMENT-RECEIPTS",
                self.settlement_receipts
                    .values()
                    .map(|item| (item.receipt_id.clone(), item.public_record()))
                    .collect(),
            ),
            active_lane_root: low_fee_execution_derivatives_payload_root(
                "LOW-FEE-EXECUTION-ACTIVE-LANES",
                &json!(self.active_lane_map()),
            ),
            public_record_root: low_fee_execution_derivatives_payload_root(
                "LOW-FEE-EXECUTION-PUBLIC-RECORD-WITHOUT-ROOT",
                &self.public_record_root_input(),
            ),
        }
    }

    pub fn counters(&self) -> LowFeeExecutionDerivativesCounters {
        LowFeeExecutionDerivativesCounters {
            observation_count: self.observations.len() as u64,
            active_observation_count: self
                .observations
                .values()
                .filter(|item| item.active_at(self.height))
                .count() as u64,
            authorization_count: self.authorizations.len() as u64,
            active_authorization_count: self
                .authorizations
                .values()
                .filter(|item| item.active_at(self.height))
                .count() as u64,
            hedge_count: self.hedges.len() as u64,
            live_hedge_count: self
                .hedges
                .values()
                .filter(|item| item.status.live())
                .count() as u64,
            tranche_count: self.tranches.len() as u64,
            spendable_tranche_count: self
                .tranches
                .values()
                .filter(|item| item.status.spendable() && self.height < item.expires_at_height)
                .count() as u64,
            contract_count: self.contracts.len() as u64,
            live_contract_count: self
                .contracts
                .values()
                .filter(|item| item.status.live())
                .count() as u64,
            receipt_count: self.settlement_receipts.len() as u64,
            total_live_notional_units: self
                .contracts
                .values()
                .filter(|item| item.status.live())
                .map(|item| item.notional_units)
                .sum(),
            total_tranche_available_units: self
                .tranches
                .values()
                .map(SponsoredExecutionTranche::available_units)
                .sum(),
            total_user_rebate_units: self
                .settlement_receipts
                .values()
                .map(|item| item.user_rebate_units)
                .sum(),
            total_sponsor_paid_units: self
                .settlement_receipts
                .values()
                .map(|item| item.sponsor_paid_units)
                .sum(),
        }
    }

    pub fn public_record_without_root(&self) -> Value {
        let roots = self.roots();
        let counters = self.counters();
        json!({
            "kind": "low_fee_execution_derivatives_state",
            "protocol_version": LOW_FEE_EXECUTION_DERIVATIVES_PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "height": self.height,
            "config": self.config.public_record(),
            "roots": roots.public_record(),
            "roots_root": roots.roots_root(),
            "counters": counters.public_record(),
            "counters_root": counters.counters_root(),
            "active_lane_map": self.active_lane_map(),
            "active_contract_ids": self.active_contract_ids(),
        })
    }

    fn public_record_root_input(&self) -> Value {
        json!({
            "kind": "low_fee_execution_derivatives_state_root_input",
            "protocol_version": LOW_FEE_EXECUTION_DERIVATIVES_PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "height": self.height,
            "config_root": self.config.config_root(),
            "observation_count": self.observations.len() as u64,
            "authorization_count": self.authorizations.len() as u64,
            "hedge_count": self.hedges.len() as u64,
            "tranche_count": self.tranches.len() as u64,
            "contract_count": self.contracts.len() as u64,
            "receipt_count": self.settlement_receipts.len() as u64,
            "active_lane_map": self.active_lane_map(),
            "active_contract_ids": self.active_contract_ids(),
        })
    }

    pub fn state_root(&self) -> String {
        low_fee_execution_derivatives_state_root_from_record(&self.public_record_without_root())
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_root();
        if let Value::Object(values) = &mut record {
            values.insert("state_root".to_string(), Value::String(self.state_root()));
        }
        record
    }

    pub fn validate(&self) -> LowFeeExecutionDerivativesResult<String> {
        self.config.validate()?;
        let observation_ids = self
            .observations
            .values()
            .map(ExecutionCostObservation::validate)
            .collect::<LowFeeExecutionDerivativesResult<Vec<_>>>()?;
        ensure_unique_strings(&observation_ids, "observation id")?;
        for observation in self.observations.values() {
            if observation.privacy_set_size < self.config.min_privacy_set_size {
                return Err("execution observation privacy set below configured floor".to_string());
            }
        }

        let authorization_ids = self
            .authorizations
            .values()
            .map(PqExecutionAuthorization::validate)
            .collect::<LowFeeExecutionDerivativesResult<Vec<_>>>()?;
        ensure_unique_strings(&authorization_ids, "authorization id")?;
        let authorization_set = authorization_ids.iter().cloned().collect::<BTreeSet<_>>();
        for authorization in self.authorizations.values() {
            if authorization.pq_security_bits < self.config.min_pq_security_bits {
                return Err("pq authorization security below configured floor".to_string());
            }
        }

        let hedge_ids = self
            .hedges
            .values()
            .map(PrivateExecutionHedge::validate)
            .collect::<LowFeeExecutionDerivativesResult<Vec<_>>>()?;
        ensure_unique_strings(&hedge_ids, "hedge id")?;
        let hedge_set = hedge_ids.iter().cloned().collect::<BTreeSet<_>>();
        for hedge in self.hedges.values() {
            if !authorization_set.contains(&hedge.authorization_id) {
                return Err("private execution hedge references missing authorization".to_string());
            }
            if hedge.privacy_set_size < self.config.min_privacy_set_size {
                return Err(
                    "private execution hedge privacy set below configured floor".to_string()
                );
            }
        }

        let tranche_ids = self
            .tranches
            .values()
            .map(SponsoredExecutionTranche::validate)
            .collect::<LowFeeExecutionDerivativesResult<Vec<_>>>()?;
        ensure_unique_strings(&tranche_ids, "tranche id")?;
        let tranche_set = tranche_ids.iter().cloned().collect::<BTreeSet<_>>();
        for tranche in self.tranches.values() {
            if tranche.min_privacy_set_size < self.config.min_privacy_set_size {
                return Err(
                    "sponsored execution tranche privacy set below configured floor".to_string(),
                );
            }
        }

        let contract_ids = self
            .contracts
            .values()
            .map(ExecutionDerivativeContract::validate)
            .collect::<LowFeeExecutionDerivativesResult<Vec<_>>>()?;
        ensure_unique_strings(&contract_ids, "contract id")?;
        let contract_set = contract_ids.iter().cloned().collect::<BTreeSet<_>>();
        for contract in self.contracts.values() {
            if !hedge_set.contains(&contract.hedge_id) {
                return Err("execution derivative references missing hedge".to_string());
            }
            if !tranche_set.contains(&contract.tranche_id) {
                return Err("execution derivative references missing sponsored tranche".to_string());
            }
            if contract.status.live() && contract.maturity_height < self.height {
                return Err("live execution derivative matured before state height".to_string());
            }
        }

        let receipt_ids = self
            .settlement_receipts
            .values()
            .map(ExecutionSettlementReceipt::validate)
            .collect::<LowFeeExecutionDerivativesResult<Vec<_>>>()?;
        ensure_unique_strings(&receipt_ids, "receipt id")?;
        let observation_set = observation_ids.iter().cloned().collect::<BTreeSet<_>>();
        for receipt in self.settlement_receipts.values() {
            if !contract_set.contains(&receipt.contract_id) {
                return Err("execution settlement references missing contract".to_string());
            }
            if !tranche_set.contains(&receipt.tranche_id) {
                return Err("execution settlement references missing sponsored tranche".to_string());
            }
            if !observation_set.contains(&receipt.observation_id) {
                return Err("execution settlement references missing observation".to_string());
            }
        }

        Ok(self.state_root())
    }
}

pub fn low_fee_execution_derivatives_state_root_from_record(record: &Value) -> String {
    low_fee_execution_derivatives_payload_root("LOW-FEE-EXECUTION-DERIVATIVES-STATE", record)
}

pub fn low_fee_execution_derivatives_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(LOW_FEE_EXECUTION_DERIVATIVES_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub fn low_fee_execution_derivatives_string_root(domain: &str, value: &str) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(LOW_FEE_EXECUTION_DERIVATIVES_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(value),
        ],
        32,
    )
}

pub fn execution_cost_observation_id(
    lane: ExecutionCostLane,
    unit_kind: ExecutionCostUnitKind,
    source: ExecutionOracleSource,
    observed_micro_price: u64,
    observed_at_height: u64,
    evidence_root: &str,
) -> String {
    domain_hash(
        "LOW-FEE-EXECUTION-COST-OBSERVATION-ID",
        &[
            HashPart::Str(lane.as_str()),
            HashPart::Str(unit_kind.as_str()),
            HashPart::Str(source.as_str()),
            HashPart::Int(observed_micro_price as i128),
            HashPart::Int(observed_at_height as i128),
            HashPart::Str(evidence_root),
        ],
        32,
    )
}

pub fn pq_execution_authorization_id(
    account_commitment: &str,
    scope: &str,
    allowed_lane: ExecutionCostLane,
    nonce: u64,
    valid_from_height: u64,
    signature_root: &str,
) -> String {
    domain_hash(
        "LOW-FEE-EXECUTION-PQ-AUTHORIZATION-ID",
        &[
            HashPart::Str(account_commitment),
            HashPart::Str(scope),
            HashPart::Str(allowed_lane.as_str()),
            HashPart::Int(nonce as i128),
            HashPart::Int(valid_from_height as i128),
            HashPart::Str(signature_root),
        ],
        32,
    )
}

pub fn private_execution_hedge_id(
    owner_commitment: &str,
    authorization_id: &str,
    lane: ExecutionCostLane,
    side: ExecutionHedgeSide,
    posted_at_height: u64,
    hedge_proof_root: &str,
) -> String {
    domain_hash(
        "LOW-FEE-PRIVATE-EXECUTION-HEDGE-ID",
        &[
            HashPart::Str(owner_commitment),
            HashPart::Str(authorization_id),
            HashPart::Str(lane.as_str()),
            HashPart::Str(side.as_str()),
            HashPart::Int(posted_at_height as i128),
            HashPart::Str(hedge_proof_root),
        ],
        32,
    )
}

pub fn sponsored_execution_tranche_id(
    sponsor_commitment: &str,
    lane: ExecutionCostLane,
    unit_kind: ExecutionCostUnitKind,
    fee_asset_id: &str,
    opened_at_height: u64,
    policy_root: &str,
) -> String {
    domain_hash(
        "LOW-FEE-SPONSORED-EXECUTION-TRANCHE-ID",
        &[
            HashPart::Str(sponsor_commitment),
            HashPart::Str(lane.as_str()),
            HashPart::Str(unit_kind.as_str()),
            HashPart::Str(fee_asset_id),
            HashPart::Int(opened_at_height as i128),
            HashPart::Str(policy_root),
        ],
        32,
    )
}

pub fn execution_derivative_contract_id(
    hedge_id: &str,
    tranche_id: &str,
    lane: ExecutionCostLane,
    derivative_kind: ExecutionDerivativeKind,
    strike_micro_price: u64,
    maturity_height: u64,
    privacy_nullifier_root: &str,
) -> String {
    domain_hash(
        "LOW-FEE-EXECUTION-DERIVATIVE-CONTRACT-ID",
        &[
            HashPart::Str(hedge_id),
            HashPart::Str(tranche_id),
            HashPart::Str(lane.as_str()),
            HashPart::Str(derivative_kind.as_str()),
            HashPart::Int(strike_micro_price as i128),
            HashPart::Int(maturity_height as i128),
            HashPart::Str(privacy_nullifier_root),
        ],
        32,
    )
}

pub fn execution_settlement_receipt_id(
    contract_id: &str,
    tranche_id: &str,
    observation_id: &str,
    lane: ExecutionCostLane,
    settled_at_height: u64,
    settlement_proof_root: &str,
) -> String {
    domain_hash(
        "LOW-FEE-EXECUTION-SETTLEMENT-RECEIPT-ID",
        &[
            HashPart::Str(contract_id),
            HashPart::Str(tranche_id),
            HashPart::Str(observation_id),
            HashPart::Str(lane.as_str()),
            HashPart::Int(settled_at_height as i128),
            HashPart::Str(settlement_proof_root),
        ],
        32,
    )
}

fn keyed_value_root(domain: &str, mut records: Vec<(String, Value)>) -> String {
    records.sort_by(|left, right| left.0.cmp(&right.0));
    let leaves = records
        .into_iter()
        .map(|(key, value)| json!({"key": key, "value": value}))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn require_non_empty(label: &str, value: &str) -> LowFeeExecutionDerivativesResult<()> {
    if value.trim().is_empty() {
        Err(format!("{label} cannot be empty"))
    } else {
        Ok(())
    }
}

fn require_positive(label: &str, value: u64) -> LowFeeExecutionDerivativesResult<()> {
    if value == 0 {
        Err(format!("{label} must be positive"))
    } else {
        Ok(())
    }
}

fn require_bps(label: &str, value: u64) -> LowFeeExecutionDerivativesResult<()> {
    if value > LOW_FEE_EXECUTION_DERIVATIVES_MAX_BPS {
        Err(format!("{label} exceeds 10000 bps"))
    } else {
        Ok(())
    }
}

fn require_height_window(
    label: &str,
    start: u64,
    end: u64,
) -> LowFeeExecutionDerivativesResult<()> {
    if end <= start {
        Err(format!("{label} height window is inverted"))
    } else {
        Ok(())
    }
}

fn ensure_unique_strings(values: &[String], label: &str) -> LowFeeExecutionDerivativesResult<()> {
    let mut seen = BTreeSet::new();
    for value in values {
        require_non_empty(label, value)?;
        if !seen.insert(value.clone()) {
            return Err(format!("{label} contains duplicate value"));
        }
    }
    Ok(())
}
