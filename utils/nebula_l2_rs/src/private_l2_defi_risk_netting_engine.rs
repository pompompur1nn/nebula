use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2DefiRiskNettingEngineResult<T> = Result<T, String>;

pub const PRIVATE_L2_DEFI_RISK_NETTING_ENGINE_PROTOCOL_VERSION: &str =
    "nebula-private-l2-defi-risk-netting-engine-v1";
pub const PRIVATE_L2_DEFI_RISK_NETTING_ENGINE_SCHEMA_VERSION: u64 = 1;
pub const PRIVATE_L2_DEFI_RISK_NETTING_ENGINE_HASH_SUITE: &str = "SHAKE256-domain-separated";
pub const PRIVATE_L2_DEFI_RISK_NETTING_ENGINE_SEALED_INTENT_SCHEME: &str =
    "zk-sealed-private-defi-intent-v1";
pub const PRIVATE_L2_DEFI_RISK_NETTING_ENGINE_RISK_ATTESTATION_SCHEME: &str =
    "zk-private-defi-risk-attestation-v1";
pub const PRIVATE_L2_DEFI_RISK_NETTING_ENGINE_NETTING_SCHEME: &str =
    "low-fee-private-defi-risk-netting-v1";
pub const PRIVATE_L2_DEFI_RISK_NETTING_ENGINE_SETTLEMENT_SCHEME: &str =
    "zk-private-defi-batch-settlement-v1";
pub const PRIVATE_L2_DEFI_RISK_NETTING_ENGINE_RECEIPT_SCHEME: &str =
    "roots-only-private-defi-fee-rebate-receipt-v1";
pub const PRIVATE_L2_DEFI_RISK_NETTING_ENGINE_PQ_AUTH_SCHEME: &str =
    "ml-dsa-87-private-defi-risk-netting-v1";
pub const PRIVATE_L2_DEFI_RISK_NETTING_ENGINE_PRIVACY_PROOF_SCHEME: &str =
    "zk-private-defi-liquidity-set-membership-v1";
pub const PRIVATE_L2_DEFI_RISK_NETTING_ENGINE_DEVNET_HEIGHT: u64 = 142_000;
pub const PRIVATE_L2_DEFI_RISK_NETTING_ENGINE_MAX_BPS: u64 = 10_000;
pub const PRIVATE_L2_DEFI_RISK_NETTING_ENGINE_DEFAULT_BATCH_WINDOW_BLOCKS: u64 = 6;
pub const PRIVATE_L2_DEFI_RISK_NETTING_ENGINE_DEFAULT_INTENT_TTL_BLOCKS: u64 = 30;
pub const PRIVATE_L2_DEFI_RISK_NETTING_ENGINE_DEFAULT_SETTLEMENT_TTL_BLOCKS: u64 = 16;
pub const PRIVATE_L2_DEFI_RISK_NETTING_ENGINE_DEFAULT_MAX_INTENTS_PER_BATCH: usize = 768;
pub const PRIVATE_L2_DEFI_RISK_NETTING_ENGINE_DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 96;
pub const PRIVATE_L2_DEFI_RISK_NETTING_ENGINE_DEFAULT_MIN_BATCH_PRIVACY_SET_SIZE: u64 = 192;
pub const PRIVATE_L2_DEFI_RISK_NETTING_ENGINE_DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const PRIVATE_L2_DEFI_RISK_NETTING_ENGINE_DEFAULT_MAX_USER_FEE_BPS: u64 = 28;
pub const PRIVATE_L2_DEFI_RISK_NETTING_ENGINE_DEFAULT_MIN_REBATE_BPS: u64 = 4;
pub const PRIVATE_L2_DEFI_RISK_NETTING_ENGINE_DEFAULT_MAX_REBATE_BPS: u64 = 18;
pub const PRIVATE_L2_DEFI_RISK_NETTING_ENGINE_DEFAULT_MAX_NET_EXPOSURE_BPS: u64 = 325;
pub const PRIVATE_L2_DEFI_RISK_NETTING_ENGINE_DEFAULT_MAX_RISK_SCORE_BPS: u64 = 8_500;
pub const PRIVATE_L2_DEFI_RISK_NETTING_ENGINE_DEFAULT_REDUCE_ONLY_RISK_BPS: u64 = 7_250;
pub const PRIVATE_L2_DEFI_RISK_NETTING_ENGINE_DEFAULT_MIN_MARGIN_HEALTH_BPS: u64 = 11_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DefiIntentKind {
    AmmSwap,
    DarkpoolSwap,
    VaultDeposit,
    VaultWithdraw,
    PerpOpen,
    PerpClose,
    PerpFunding,
    TokenMint,
    TokenBurn,
    LendingBorrow,
    LendingRepay,
    CrossMarginRebalance,
}

impl DefiIntentKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AmmSwap => "amm_swap",
            Self::DarkpoolSwap => "darkpool_swap",
            Self::VaultDeposit => "vault_deposit",
            Self::VaultWithdraw => "vault_withdraw",
            Self::PerpOpen => "perp_open",
            Self::PerpClose => "perp_close",
            Self::PerpFunding => "perp_funding",
            Self::TokenMint => "token_mint",
            Self::TokenBurn => "token_burn",
            Self::LendingBorrow => "lending_borrow",
            Self::LendingRepay => "lending_repay",
            Self::CrossMarginRebalance => "cross_margin_rebalance",
        }
    }

    pub fn risk_weight_bps(self) -> u64 {
        match self {
            Self::AmmSwap | Self::DarkpoolSwap => 650,
            Self::VaultDeposit | Self::LendingRepay | Self::PerpClose => 450,
            Self::VaultWithdraw | Self::TokenMint | Self::TokenBurn => 850,
            Self::PerpFunding | Self::CrossMarginRebalance => 1_150,
            Self::LendingBorrow => 1_450,
            Self::PerpOpen => 1_850,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskVerdict {
    Accepted,
    Watch,
    ReduceOnly,
    Rejected,
    CircuitBreak,
}

impl RiskVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Watch => "watch",
            Self::ReduceOnly => "reduce_only",
            Self::Rejected => "rejected",
            Self::CircuitBreak => "circuit_break",
        }
    }

    pub fn allows_netting(self) -> bool {
        matches!(self, Self::Accepted | Self::Watch | Self::ReduceOnly)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NettingStatus {
    Open,
    RiskAttested,
    Netted,
    SettlementReady,
    Settled,
    Disputed,
    Expired,
    Rejected,
}

impl NettingStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::RiskAttested => "risk_attested",
            Self::Netted => "netted",
            Self::SettlementReady => "settlement_ready",
            Self::Settled => "settled",
            Self::Disputed => "disputed",
            Self::Expired => "expired",
            Self::Rejected => "rejected",
        }
    }

    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Open | Self::RiskAttested | Self::Netted | Self::SettlementReady
        )
    }

    pub fn can_settle(self) -> bool {
        matches!(self, Self::SettlementReady)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LiquidityVenue {
    PrivateAmm,
    Darkpool,
    Vault,
    Perps,
    TokenLane,
    LendingPool,
    InternalCrossMargin,
    MoneroBridge,
}

impl LiquidityVenue {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrivateAmm => "private_amm",
            Self::Darkpool => "darkpool",
            Self::Vault => "vault",
            Self::Perps => "perps",
            Self::TokenLane => "token_lane",
            Self::LendingPool => "lending_pool",
            Self::InternalCrossMargin => "internal_cross_margin",
            Self::MoneroBridge => "monero_bridge",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub protocol_version: String,
    pub schema_version: u64,
    pub chain_id: String,
    pub hash_suite: String,
    pub sealed_intent_scheme: String,
    pub risk_attestation_scheme: String,
    pub netting_scheme: String,
    pub settlement_scheme: String,
    pub receipt_scheme: String,
    pub pq_authorization_scheme: String,
    pub privacy_proof_scheme: String,
    pub batch_window_blocks: u64,
    pub intent_ttl_blocks: u64,
    pub settlement_ttl_blocks: u64,
    pub max_intents_per_batch: usize,
    pub min_privacy_set_size: u64,
    pub min_batch_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub max_user_fee_bps: u64,
    pub min_rebate_bps: u64,
    pub max_rebate_bps: u64,
    pub max_net_exposure_bps: u64,
    pub max_risk_score_bps: u64,
    pub reduce_only_risk_bps: u64,
    pub min_margin_health_bps: u64,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version: PRIVATE_L2_DEFI_RISK_NETTING_ENGINE_PROTOCOL_VERSION.to_string(),
            schema_version: PRIVATE_L2_DEFI_RISK_NETTING_ENGINE_SCHEMA_VERSION,
            chain_id: CHAIN_ID.to_string(),
            hash_suite: PRIVATE_L2_DEFI_RISK_NETTING_ENGINE_HASH_SUITE.to_string(),
            sealed_intent_scheme: PRIVATE_L2_DEFI_RISK_NETTING_ENGINE_SEALED_INTENT_SCHEME
                .to_string(),
            risk_attestation_scheme: PRIVATE_L2_DEFI_RISK_NETTING_ENGINE_RISK_ATTESTATION_SCHEME
                .to_string(),
            netting_scheme: PRIVATE_L2_DEFI_RISK_NETTING_ENGINE_NETTING_SCHEME.to_string(),
            settlement_scheme: PRIVATE_L2_DEFI_RISK_NETTING_ENGINE_SETTLEMENT_SCHEME.to_string(),
            receipt_scheme: PRIVATE_L2_DEFI_RISK_NETTING_ENGINE_RECEIPT_SCHEME.to_string(),
            pq_authorization_scheme: PRIVATE_L2_DEFI_RISK_NETTING_ENGINE_PQ_AUTH_SCHEME.to_string(),
            privacy_proof_scheme: PRIVATE_L2_DEFI_RISK_NETTING_ENGINE_PRIVACY_PROOF_SCHEME
                .to_string(),
            batch_window_blocks: PRIVATE_L2_DEFI_RISK_NETTING_ENGINE_DEFAULT_BATCH_WINDOW_BLOCKS,
            intent_ttl_blocks: PRIVATE_L2_DEFI_RISK_NETTING_ENGINE_DEFAULT_INTENT_TTL_BLOCKS,
            settlement_ttl_blocks:
                PRIVATE_L2_DEFI_RISK_NETTING_ENGINE_DEFAULT_SETTLEMENT_TTL_BLOCKS,
            max_intents_per_batch:
                PRIVATE_L2_DEFI_RISK_NETTING_ENGINE_DEFAULT_MAX_INTENTS_PER_BATCH,
            min_privacy_set_size: PRIVATE_L2_DEFI_RISK_NETTING_ENGINE_DEFAULT_MIN_PRIVACY_SET_SIZE,
            min_batch_privacy_set_size:
                PRIVATE_L2_DEFI_RISK_NETTING_ENGINE_DEFAULT_MIN_BATCH_PRIVACY_SET_SIZE,
            min_pq_security_bits: PRIVATE_L2_DEFI_RISK_NETTING_ENGINE_DEFAULT_MIN_PQ_SECURITY_BITS,
            max_user_fee_bps: PRIVATE_L2_DEFI_RISK_NETTING_ENGINE_DEFAULT_MAX_USER_FEE_BPS,
            min_rebate_bps: PRIVATE_L2_DEFI_RISK_NETTING_ENGINE_DEFAULT_MIN_REBATE_BPS,
            max_rebate_bps: PRIVATE_L2_DEFI_RISK_NETTING_ENGINE_DEFAULT_MAX_REBATE_BPS,
            max_net_exposure_bps: PRIVATE_L2_DEFI_RISK_NETTING_ENGINE_DEFAULT_MAX_NET_EXPOSURE_BPS,
            max_risk_score_bps: PRIVATE_L2_DEFI_RISK_NETTING_ENGINE_DEFAULT_MAX_RISK_SCORE_BPS,
            reduce_only_risk_bps: PRIVATE_L2_DEFI_RISK_NETTING_ENGINE_DEFAULT_REDUCE_ONLY_RISK_BPS,
            min_margin_health_bps:
                PRIVATE_L2_DEFI_RISK_NETTING_ENGINE_DEFAULT_MIN_MARGIN_HEALTH_BPS,
        }
    }

    pub fn validate(&self) -> PrivateL2DefiRiskNettingEngineResult<()> {
        if self.protocol_version.is_empty()
            || self.chain_id.is_empty()
            || self.hash_suite.is_empty()
            || self.sealed_intent_scheme.is_empty()
            || self.risk_attestation_scheme.is_empty()
            || self.netting_scheme.is_empty()
            || self.settlement_scheme.is_empty()
            || self.receipt_scheme.is_empty()
            || self.pq_authorization_scheme.is_empty()
            || self.privacy_proof_scheme.is_empty()
        {
            return Err("private DeFi risk netting config schemes cannot be empty".to_string());
        }
        if self.batch_window_blocks == 0
            || self.intent_ttl_blocks == 0
            || self.settlement_ttl_blocks == 0
            || self.max_intents_per_batch == 0
        {
            return Err("private DeFi risk netting windows must be positive".to_string());
        }
        if self.min_privacy_set_size == 0
            || self.min_batch_privacy_set_size < self.min_privacy_set_size
        {
            return Err("batch privacy set must cover individual intent privacy set".to_string());
        }
        if self.min_pq_security_bits < 192 {
            return Err("post-quantum authorization must be at least 192 bits".to_string());
        }
        if self.max_user_fee_bps > PRIVATE_L2_DEFI_RISK_NETTING_ENGINE_MAX_BPS
            || self.min_rebate_bps > self.max_rebate_bps
            || self.max_rebate_bps > self.max_user_fee_bps
            || self.max_net_exposure_bps > PRIVATE_L2_DEFI_RISK_NETTING_ENGINE_MAX_BPS
            || self.max_risk_score_bps > PRIVATE_L2_DEFI_RISK_NETTING_ENGINE_MAX_BPS
            || self.reduce_only_risk_bps > self.max_risk_score_bps
        {
            return Err("private DeFi risk netting bps configuration is invalid".to_string());
        }
        if self.min_margin_health_bps < PRIVATE_L2_DEFI_RISK_NETTING_ENGINE_MAX_BPS {
            return Err(
                "minimum margin health must be at least full collateral coverage".to_string(),
            );
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_defi_risk_netting_engine_config",
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "chain_id": self.chain_id,
            "hash_suite": self.hash_suite,
            "sealed_intent_scheme": self.sealed_intent_scheme,
            "risk_attestation_scheme": self.risk_attestation_scheme,
            "netting_scheme": self.netting_scheme,
            "settlement_scheme": self.settlement_scheme,
            "receipt_scheme": self.receipt_scheme,
            "pq_authorization_scheme": self.pq_authorization_scheme,
            "privacy_proof_scheme": self.privacy_proof_scheme,
            "batch_window_blocks": self.batch_window_blocks,
            "intent_ttl_blocks": self.intent_ttl_blocks,
            "settlement_ttl_blocks": self.settlement_ttl_blocks,
            "max_intents_per_batch": self.max_intents_per_batch,
            "min_privacy_set_size": self.min_privacy_set_size,
            "min_batch_privacy_set_size": self.min_batch_privacy_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
            "max_user_fee_bps": self.max_user_fee_bps,
            "min_rebate_bps": self.min_rebate_bps,
            "max_rebate_bps": self.max_rebate_bps,
            "max_net_exposure_bps": self.max_net_exposure_bps,
            "max_risk_score_bps": self.max_risk_score_bps,
            "reduce_only_risk_bps": self.reduce_only_risk_bps,
            "min_margin_health_bps": self.min_margin_health_bps,
        })
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    pub sealed_intents: usize,
    pub risk_attestations: usize,
    pub netting_groups: usize,
    pub settlement_batches: usize,
    pub fee_rebate_receipts: usize,
    pub consumed_nullifiers: usize,
    pub public_records: usize,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_defi_risk_netting_engine_counters",
            "chain_id": CHAIN_ID,
            "sealed_intents": self.sealed_intents,
            "risk_attestations": self.risk_attestations,
            "netting_groups": self.netting_groups,
            "settlement_batches": self.settlement_batches,
            "fee_rebate_receipts": self.fee_rebate_receipts,
            "consumed_nullifiers": self.consumed_nullifiers,
            "public_records": self.public_records,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubmitIntentRequest {
    pub intent_kind: DefiIntentKind,
    pub venue: LiquidityVenue,
    pub account_commitment: String,
    pub sealed_payload_root: String,
    pub asset_pair_root: String,
    pub amount_commitment: String,
    pub price_limit_commitment: String,
    pub collateral_commitment: String,
    pub privacy_set_size: u64,
    pub pq_authorization_root: String,
    pub pq_security_bits: u16,
    pub nullifier: String,
    pub max_fee_bps: u64,
    pub requested_rebate_bps: u64,
    pub expiry_height: u64,
    pub client_entropy: String,
}

impl SubmitIntentRequest {
    pub fn validate(
        &self,
        config: &Config,
        current_height: u64,
    ) -> PrivateL2DefiRiskNettingEngineResult<()> {
        require_non_empty("account commitment", &self.account_commitment)?;
        require_non_empty("sealed payload root", &self.sealed_payload_root)?;
        require_non_empty("asset pair root", &self.asset_pair_root)?;
        require_non_empty("amount commitment", &self.amount_commitment)?;
        require_non_empty("price limit commitment", &self.price_limit_commitment)?;
        require_non_empty("collateral commitment", &self.collateral_commitment)?;
        require_non_empty("PQ authorization root", &self.pq_authorization_root)?;
        require_non_empty("intent nullifier", &self.nullifier)?;
        require_non_empty("client entropy", &self.client_entropy)?;
        require_privacy_set(config, self.privacy_set_size, false)?;
        require_pq_security(config, self.pq_security_bits)?;
        if self.max_fee_bps > config.max_user_fee_bps {
            return Err("intent fee cap exceeds low-fee lane maximum".to_string());
        }
        if self.requested_rebate_bps > config.max_rebate_bps {
            return Err("requested rebate exceeds configured rebate cap".to_string());
        }
        if self.expiry_height <= current_height
            || self.expiry_height > current_height.saturating_add(config.intent_ttl_blocks)
        {
            return Err("intent expiry must be live and within the configured TTL".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RiskAttestationRequest {
    pub intent_id: String,
    pub attestor_id: String,
    pub verdict: RiskVerdict,
    pub risk_score_bps: u64,
    pub exposure_delta_commitment: String,
    pub margin_health_bps: u64,
    pub oracle_root: String,
    pub proof_root: String,
    pub privacy_set_size: u64,
    pub pq_authorization_root: String,
    pub pq_security_bits: u16,
    pub attestation_nullifier: String,
}

impl RiskAttestationRequest {
    pub fn validate(&self, config: &Config) -> PrivateL2DefiRiskNettingEngineResult<()> {
        require_non_empty("intent id", &self.intent_id)?;
        require_non_empty("attestor id", &self.attestor_id)?;
        require_non_empty("exposure delta commitment", &self.exposure_delta_commitment)?;
        require_non_empty("oracle root", &self.oracle_root)?;
        require_non_empty("risk proof root", &self.proof_root)?;
        require_non_empty("PQ authorization root", &self.pq_authorization_root)?;
        require_non_empty("attestation nullifier", &self.attestation_nullifier)?;
        require_privacy_set(config, self.privacy_set_size, false)?;
        require_pq_security(config, self.pq_security_bits)?;
        if self.risk_score_bps > config.max_risk_score_bps {
            return Err("risk score exceeds configured circuit-break cap".to_string());
        }
        if self.verdict.allows_netting() && self.margin_health_bps < config.min_margin_health_bps {
            return Err("risk attestation margin health is below configured minimum".to_string());
        }
        if self.verdict == RiskVerdict::Accepted
            && self.risk_score_bps >= config.reduce_only_risk_bps
        {
            return Err("accepted verdict cannot exceed reduce-only risk threshold".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BuildNettingBatchRequest {
    pub batch_label: String,
    pub intent_ids: Vec<String>,
    pub venue: LiquidityVenue,
    pub solver_id: String,
    pub net_asset_delta_root: String,
    pub net_risk_delta_root: String,
    pub clearing_price_root: String,
    pub fee_plan_root: String,
    pub privacy_set_size: u64,
    pub max_user_fee_bps: u64,
    pub rebate_bps: u64,
    pub net_exposure_bps: u64,
    pub pq_authorization_root: String,
    pub pq_security_bits: u16,
}

impl BuildNettingBatchRequest {
    pub fn validate(&self, config: &Config) -> PrivateL2DefiRiskNettingEngineResult<()> {
        require_non_empty("batch label", &self.batch_label)?;
        require_non_empty("solver id", &self.solver_id)?;
        require_non_empty("net asset delta root", &self.net_asset_delta_root)?;
        require_non_empty("net risk delta root", &self.net_risk_delta_root)?;
        require_non_empty("clearing price root", &self.clearing_price_root)?;
        require_non_empty("fee plan root", &self.fee_plan_root)?;
        require_non_empty("PQ authorization root", &self.pq_authorization_root)?;
        require_privacy_set(config, self.privacy_set_size, true)?;
        require_pq_security(config, self.pq_security_bits)?;
        if self.intent_ids.is_empty() {
            return Err("netting batch must include at least one intent".to_string());
        }
        if self.intent_ids.len() > config.max_intents_per_batch {
            return Err("netting batch exceeds configured intent limit".to_string());
        }
        let unique = self.intent_ids.iter().collect::<BTreeSet<_>>();
        if unique.len() != self.intent_ids.len() {
            return Err("netting batch cannot contain duplicate intent ids".to_string());
        }
        if self.max_user_fee_bps > config.max_user_fee_bps {
            return Err("batch user fee exceeds low-fee cap".to_string());
        }
        if self.rebate_bps < config.min_rebate_bps || self.rebate_bps > config.max_rebate_bps {
            return Err("batch rebate is outside configured bounds".to_string());
        }
        if self.net_exposure_bps > config.max_net_exposure_bps {
            return Err("netted exposure exceeds configured imbalance cap".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettleBatchRequest {
    pub batch_id: String,
    pub settlement_proof_root: String,
    pub settlement_tx_root: String,
    pub posted_fee_bps: u64,
    pub rebate_commitment_root: String,
    pub operator_pq_authorization_root: String,
    pub pq_security_bits: u16,
    pub settlement_nullifier: String,
}

impl SettleBatchRequest {
    pub fn validate(&self, config: &Config) -> PrivateL2DefiRiskNettingEngineResult<()> {
        require_non_empty("batch id", &self.batch_id)?;
        require_non_empty("settlement proof root", &self.settlement_proof_root)?;
        require_non_empty("settlement transaction root", &self.settlement_tx_root)?;
        require_non_empty("rebate commitment root", &self.rebate_commitment_root)?;
        require_non_empty(
            "operator PQ authorization root",
            &self.operator_pq_authorization_root,
        )?;
        require_non_empty("settlement nullifier", &self.settlement_nullifier)?;
        require_pq_security(config, self.pq_security_bits)?;
        if self.posted_fee_bps > config.max_user_fee_bps {
            return Err("settlement fee exceeds low-fee cap".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedDefiIntentRecord {
    pub intent_id: String,
    pub intent_kind: DefiIntentKind,
    pub venue: LiquidityVenue,
    pub status: NettingStatus,
    pub account_commitment: String,
    pub sealed_payload_root: String,
    pub asset_pair_root: String,
    pub amount_commitment: String,
    pub price_limit_commitment: String,
    pub collateral_commitment: String,
    pub privacy_set_size: u64,
    pub pq_authorization_root: String,
    pub pq_security_bits: u16,
    pub nullifier_hash: String,
    pub max_fee_bps: u64,
    pub requested_rebate_bps: u64,
    pub expiry_height: u64,
    pub submitted_height: u64,
}

impl SealedDefiIntentRecord {
    pub fn from_request(request: &SubmitIntentRequest, submitted_height: u64) -> Self {
        let nullifier_hash = private_l2_defi_payload_id(
            "PRIVATE-L2-DEFI-INTENT-NULLIFIER",
            &[HashPart::Str(&request.nullifier)],
        );
        let intent_id = sealed_intent_id(request, submitted_height, &nullifier_hash);
        Self {
            intent_id,
            intent_kind: request.intent_kind,
            venue: request.venue,
            status: NettingStatus::Open,
            account_commitment: request.account_commitment.clone(),
            sealed_payload_root: request.sealed_payload_root.clone(),
            asset_pair_root: request.asset_pair_root.clone(),
            amount_commitment: request.amount_commitment.clone(),
            price_limit_commitment: request.price_limit_commitment.clone(),
            collateral_commitment: request.collateral_commitment.clone(),
            privacy_set_size: request.privacy_set_size,
            pq_authorization_root: request.pq_authorization_root.clone(),
            pq_security_bits: request.pq_security_bits,
            nullifier_hash,
            max_fee_bps: request.max_fee_bps,
            requested_rebate_bps: request.requested_rebate_bps,
            expiry_height: request.expiry_height,
            submitted_height,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "sealed_private_l2_defi_intent",
            "protocol_version": PRIVATE_L2_DEFI_RISK_NETTING_ENGINE_PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "intent_id": self.intent_id,
            "intent_kind": self.intent_kind.as_str(),
            "venue": self.venue.as_str(),
            "status": self.status.as_str(),
            "account_commitment": self.account_commitment,
            "sealed_payload_root": self.sealed_payload_root,
            "asset_pair_root": self.asset_pair_root,
            "amount_commitment": self.amount_commitment,
            "price_limit_commitment": self.price_limit_commitment,
            "collateral_commitment": self.collateral_commitment,
            "privacy_set_size": self.privacy_set_size,
            "pq_authorization_root": self.pq_authorization_root,
            "pq_security_bits": self.pq_security_bits,
            "nullifier_hash": self.nullifier_hash,
            "max_fee_bps": self.max_fee_bps,
            "requested_rebate_bps": self.requested_rebate_bps,
            "expiry_height": self.expiry_height,
            "submitted_height": self.submitted_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RiskAttestationRecord {
    pub attestation_id: String,
    pub intent_id: String,
    pub attestor_id: String,
    pub verdict: RiskVerdict,
    pub risk_score_bps: u64,
    pub exposure_delta_commitment: String,
    pub margin_health_bps: u64,
    pub oracle_root: String,
    pub proof_root: String,
    pub privacy_set_size: u64,
    pub pq_authorization_root: String,
    pub pq_security_bits: u16,
    pub attestation_nullifier_hash: String,
    pub attested_height: u64,
}

impl RiskAttestationRecord {
    pub fn from_request(request: &RiskAttestationRequest, attested_height: u64) -> Self {
        let attestation_nullifier_hash = private_l2_defi_payload_id(
            "PRIVATE-L2-DEFI-RISK-ATTESTATION-NULLIFIER",
            &[HashPart::Str(&request.attestation_nullifier)],
        );
        let attestation_id =
            risk_attestation_id(request, attested_height, &attestation_nullifier_hash);
        Self {
            attestation_id,
            intent_id: request.intent_id.clone(),
            attestor_id: request.attestor_id.clone(),
            verdict: request.verdict,
            risk_score_bps: request.risk_score_bps,
            exposure_delta_commitment: request.exposure_delta_commitment.clone(),
            margin_health_bps: request.margin_health_bps,
            oracle_root: request.oracle_root.clone(),
            proof_root: request.proof_root.clone(),
            privacy_set_size: request.privacy_set_size,
            pq_authorization_root: request.pq_authorization_root.clone(),
            pq_security_bits: request.pq_security_bits,
            attestation_nullifier_hash,
            attested_height,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_defi_risk_attestation",
            "protocol_version": PRIVATE_L2_DEFI_RISK_NETTING_ENGINE_PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "attestation_id": self.attestation_id,
            "intent_id": self.intent_id,
            "attestor_id": self.attestor_id,
            "verdict": self.verdict.as_str(),
            "risk_score_bps": self.risk_score_bps,
            "exposure_delta_commitment": self.exposure_delta_commitment,
            "margin_health_bps": self.margin_health_bps,
            "oracle_root": self.oracle_root,
            "proof_root": self.proof_root,
            "privacy_set_size": self.privacy_set_size,
            "pq_authorization_root": self.pq_authorization_root,
            "pq_security_bits": self.pq_security_bits,
            "attestation_nullifier_hash": self.attestation_nullifier_hash,
            "attested_height": self.attested_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NettingGroupRecord {
    pub group_id: String,
    pub batch_label: String,
    pub status: NettingStatus,
    pub venue: LiquidityVenue,
    pub solver_id: String,
    pub intent_ids: Vec<String>,
    pub intent_root: String,
    pub risk_attestation_root: String,
    pub net_asset_delta_root: String,
    pub net_risk_delta_root: String,
    pub clearing_price_root: String,
    pub fee_plan_root: String,
    pub privacy_set_size: u64,
    pub max_user_fee_bps: u64,
    pub rebate_bps: u64,
    pub net_exposure_bps: u64,
    pub pq_authorization_root: String,
    pub pq_security_bits: u16,
    pub opened_height: u64,
    pub settlement_deadline_height: u64,
}

impl NettingGroupRecord {
    pub fn from_request(
        request: &BuildNettingBatchRequest,
        risk_attestations: &[RiskAttestationRecord],
        opened_height: u64,
        settlement_deadline_height: u64,
    ) -> Self {
        let intent_leaves = request
            .intent_ids
            .iter()
            .map(|intent_id| json!(intent_id))
            .collect::<Vec<_>>();
        let attestation_leaves = risk_attestations
            .iter()
            .map(RiskAttestationRecord::public_record)
            .collect::<Vec<_>>();
        let intent_root = merkle_root("PRIVATE-L2-DEFI-NETTING-INTENTS", &intent_leaves);
        let risk_attestation_root = merkle_root(
            "PRIVATE-L2-DEFI-NETTING-RISK-ATTESTATIONS",
            &attestation_leaves,
        );
        let group_id = netting_group_id(
            &request.batch_label,
            request.venue,
            &request.solver_id,
            &intent_root,
            &risk_attestation_root,
            opened_height,
        );
        Self {
            group_id,
            batch_label: request.batch_label.clone(),
            status: NettingStatus::SettlementReady,
            venue: request.venue,
            solver_id: request.solver_id.clone(),
            intent_ids: request.intent_ids.clone(),
            intent_root,
            risk_attestation_root,
            net_asset_delta_root: request.net_asset_delta_root.clone(),
            net_risk_delta_root: request.net_risk_delta_root.clone(),
            clearing_price_root: request.clearing_price_root.clone(),
            fee_plan_root: request.fee_plan_root.clone(),
            privacy_set_size: request.privacy_set_size,
            max_user_fee_bps: request.max_user_fee_bps,
            rebate_bps: request.rebate_bps,
            net_exposure_bps: request.net_exposure_bps,
            pq_authorization_root: request.pq_authorization_root.clone(),
            pq_security_bits: request.pq_security_bits,
            opened_height,
            settlement_deadline_height,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_defi_netting_group",
            "protocol_version": PRIVATE_L2_DEFI_RISK_NETTING_ENGINE_PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "group_id": self.group_id,
            "batch_label": self.batch_label,
            "status": self.status.as_str(),
            "venue": self.venue.as_str(),
            "solver_id": self.solver_id,
            "intent_root": self.intent_root,
            "risk_attestation_root": self.risk_attestation_root,
            "net_asset_delta_root": self.net_asset_delta_root,
            "net_risk_delta_root": self.net_risk_delta_root,
            "clearing_price_root": self.clearing_price_root,
            "fee_plan_root": self.fee_plan_root,
            "privacy_set_size": self.privacy_set_size,
            "max_user_fee_bps": self.max_user_fee_bps,
            "rebate_bps": self.rebate_bps,
            "net_exposure_bps": self.net_exposure_bps,
            "pq_authorization_root": self.pq_authorization_root,
            "pq_security_bits": self.pq_security_bits,
            "opened_height": self.opened_height,
            "settlement_deadline_height": self.settlement_deadline_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementBatchRecord {
    pub batch_id: String,
    pub group_id: String,
    pub status: NettingStatus,
    pub settlement_proof_root: String,
    pub settlement_tx_root: String,
    pub posted_fee_bps: u64,
    pub rebate_commitment_root: String,
    pub operator_pq_authorization_root: String,
    pub pq_security_bits: u16,
    pub settlement_nullifier_hash: String,
    pub settled_height: u64,
}

impl SettlementBatchRecord {
    pub fn from_request(
        request: &SettleBatchRequest,
        group_id: &str,
        settlement_nullifier_hash: &str,
        settled_height: u64,
    ) -> Self {
        let batch_id = settlement_batch_id(
            group_id,
            &request.settlement_proof_root,
            &request.settlement_tx_root,
            settlement_nullifier_hash,
            settled_height,
        );
        Self {
            batch_id,
            group_id: group_id.to_string(),
            status: NettingStatus::Settled,
            settlement_proof_root: request.settlement_proof_root.clone(),
            settlement_tx_root: request.settlement_tx_root.clone(),
            posted_fee_bps: request.posted_fee_bps,
            rebate_commitment_root: request.rebate_commitment_root.clone(),
            operator_pq_authorization_root: request.operator_pq_authorization_root.clone(),
            pq_security_bits: request.pq_security_bits,
            settlement_nullifier_hash: settlement_nullifier_hash.to_string(),
            settled_height,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_defi_settlement_batch",
            "protocol_version": PRIVATE_L2_DEFI_RISK_NETTING_ENGINE_PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "batch_id": self.batch_id,
            "group_id": self.group_id,
            "status": self.status.as_str(),
            "settlement_proof_root": self.settlement_proof_root,
            "settlement_tx_root": self.settlement_tx_root,
            "posted_fee_bps": self.posted_fee_bps,
            "rebate_commitment_root": self.rebate_commitment_root,
            "operator_pq_authorization_root": self.operator_pq_authorization_root,
            "pq_security_bits": self.pq_security_bits,
            "settlement_nullifier_hash": self.settlement_nullifier_hash,
            "settled_height": self.settled_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeeRebateReceiptRecord {
    pub receipt_id: String,
    pub batch_id: String,
    pub group_id: String,
    pub fee_bps: u64,
    pub rebate_bps: u64,
    pub fee_plan_root: String,
    pub rebate_commitment_root: String,
    pub beneficiary_set_root: String,
    pub published_height: u64,
}

impl FeeRebateReceiptRecord {
    pub fn new(
        group: &NettingGroupRecord,
        batch: &SettlementBatchRecord,
        beneficiary_set_root: String,
    ) -> Self {
        let receipt_id = fee_rebate_receipt_id(
            &batch.batch_id,
            &group.group_id,
            &group.fee_plan_root,
            &batch.rebate_commitment_root,
            batch.settled_height,
        );
        Self {
            receipt_id,
            batch_id: batch.batch_id.clone(),
            group_id: group.group_id.clone(),
            fee_bps: batch.posted_fee_bps,
            rebate_bps: group.rebate_bps,
            fee_plan_root: group.fee_plan_root.clone(),
            rebate_commitment_root: batch.rebate_commitment_root.clone(),
            beneficiary_set_root,
            published_height: batch.settled_height,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_defi_fee_rebate_receipt",
            "protocol_version": PRIVATE_L2_DEFI_RISK_NETTING_ENGINE_PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "receipt_id": self.receipt_id,
            "batch_id": self.batch_id,
            "group_id": self.group_id,
            "fee_bps": self.fee_bps,
            "rebate_bps": self.rebate_bps,
            "fee_plan_root": self.fee_plan_root,
            "rebate_commitment_root": self.rebate_commitment_root,
            "beneficiary_set_root": self.beneficiary_set_root,
            "published_height": self.published_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roots {
    pub config_root: String,
    pub sealed_intent_root: String,
    pub risk_attestation_root: String,
    pub netting_group_root: String,
    pub settlement_batch_root: String,
    pub fee_rebate_receipt_root: String,
    pub nullifier_root: String,
    pub public_record_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_defi_risk_netting_engine_roots",
            "config_root": self.config_root,
            "sealed_intent_root": self.sealed_intent_root,
            "risk_attestation_root": self.risk_attestation_root,
            "netting_group_root": self.netting_group_root,
            "settlement_batch_root": self.settlement_batch_root,
            "fee_rebate_receipt_root": self.fee_rebate_receipt_root,
            "nullifier_root": self.nullifier_root,
            "public_record_root": self.public_record_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RootsOnlyPublicRecord {
    pub protocol_version: String,
    pub chain_id: String,
    pub height: u64,
    pub roots: Roots,
    pub counters: Counters,
    pub state_root: String,
}

impl RootsOnlyPublicRecord {
    pub fn public_record_without_state_root(&self) -> Value {
        json!({
            "kind": "private_l2_defi_risk_netting_engine_roots_only_public_record",
            "protocol_version": self.protocol_version,
            "chain_id": self.chain_id,
            "height": self.height,
            "roots": self.roots.public_record(),
            "counters": self.counters.public_record(),
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        if let Some(object) = record.as_object_mut() {
            object.insert(
                "state_root".to_string(),
                Value::String(self.state_root.clone()),
            );
        }
        record
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub current_height: u64,
    pub sealed_intents: BTreeMap<String, SealedDefiIntentRecord>,
    pub risk_attestations: BTreeMap<String, RiskAttestationRecord>,
    pub netting_groups: BTreeMap<String, NettingGroupRecord>,
    pub settlement_batches: BTreeMap<String, SettlementBatchRecord>,
    pub fee_rebate_receipts: BTreeMap<String, FeeRebateReceiptRecord>,
    pub consumed_nullifiers: BTreeSet<String>,
    pub public_records: BTreeMap<String, Value>,
}

impl State {
    pub fn devnet() -> PrivateL2DefiRiskNettingEngineResult<Self> {
        let config = Config::devnet();
        config.validate()?;
        let mut state = Self {
            config,
            current_height: PRIVATE_L2_DEFI_RISK_NETTING_ENGINE_DEVNET_HEIGHT,
            sealed_intents: BTreeMap::new(),
            risk_attestations: BTreeMap::new(),
            netting_groups: BTreeMap::new(),
            settlement_batches: BTreeMap::new(),
            fee_rebate_receipts: BTreeMap::new(),
            consumed_nullifiers: BTreeSet::new(),
            public_records: BTreeMap::new(),
        };
        state.publish_public_record("config", "devnet", state.config.public_record());
        Ok(state)
    }

    pub fn submit_intent(
        &mut self,
        request: SubmitIntentRequest,
    ) -> PrivateL2DefiRiskNettingEngineResult<SealedDefiIntentRecord> {
        self.config.validate()?;
        request.validate(&self.config, self.current_height)?;
        let nullifier_hash = private_l2_defi_payload_id(
            "PRIVATE-L2-DEFI-INTENT-NULLIFIER",
            &[HashPart::Str(&request.nullifier)],
        );
        self.consume_nullifier(&nullifier_hash)?;
        let record = SealedDefiIntentRecord::from_request(&request, self.current_height);
        self.sealed_intents
            .insert(record.intent_id.clone(), record.clone());
        self.publish_public_record("sealed_intent", &record.intent_id, record.public_record());
        Ok(record)
    }

    pub fn attest_risk(
        &mut self,
        request: RiskAttestationRequest,
    ) -> PrivateL2DefiRiskNettingEngineResult<RiskAttestationRecord> {
        self.config.validate()?;
        request.validate(&self.config)?;
        let intent = self
            .sealed_intents
            .get(&request.intent_id)
            .ok_or_else(|| "risk attestation references unknown intent".to_string())?;
        if !intent.status.live() {
            return Err("risk attestation cannot target a closed intent".to_string());
        }
        if intent.expiry_height <= self.current_height {
            if let Some(expired) = self.sealed_intents.get_mut(&request.intent_id) {
                expired.status = NettingStatus::Expired;
            }
            return Err("risk attestation cannot target expired intent".to_string());
        }
        let attestation_nullifier_hash = private_l2_defi_payload_id(
            "PRIVATE-L2-DEFI-RISK-ATTESTATION-NULLIFIER",
            &[HashPart::Str(&request.attestation_nullifier)],
        );
        self.consume_nullifier(&attestation_nullifier_hash)?;
        let record = RiskAttestationRecord::from_request(&request, self.current_height);
        let (intent_id, intent_record) = {
            let intent = self
                .sealed_intents
                .get_mut(&request.intent_id)
                .ok_or_else(|| "risk attestation references unknown intent".to_string())?;
            intent.status = if request.verdict.allows_netting() {
                NettingStatus::RiskAttested
            } else {
                NettingStatus::Rejected
            };
            (intent.intent_id.clone(), intent.public_record())
        };
        self.risk_attestations
            .insert(record.attestation_id.clone(), record.clone());
        self.publish_public_record("sealed_intent", &intent_id, intent_record);
        self.publish_public_record(
            "risk_attestation",
            &record.attestation_id,
            record.public_record(),
        );
        Ok(record)
    }

    pub fn build_netting_batch(
        &mut self,
        request: BuildNettingBatchRequest,
    ) -> PrivateL2DefiRiskNettingEngineResult<NettingGroupRecord> {
        self.config.validate()?;
        request.validate(&self.config)?;
        let mut attestations = Vec::new();
        for intent_id in &request.intent_ids {
            let intent = self
                .sealed_intents
                .get(intent_id)
                .ok_or_else(|| format!("netting batch references unknown intent {intent_id}"))?;
            if intent.venue != request.venue {
                return Err("netting batch venue must match all member intents".to_string());
            }
            if intent.expiry_height <= self.current_height {
                return Err("netting batch cannot include expired intents".to_string());
            }
            if intent.max_fee_bps < request.max_user_fee_bps {
                return Err("netting batch fee exceeds a member intent fee cap".to_string());
            }
            if intent.requested_rebate_bps > request.rebate_bps {
                return Err("netting batch rebate is below a member intent request".to_string());
            }
            let attestation = self
                .risk_attestations
                .values()
                .find(|attestation| {
                    attestation.intent_id == *intent_id && attestation.verdict.allows_netting()
                })
                .ok_or_else(|| {
                    format!("netting batch intent {intent_id} lacks a live risk attestation")
                })?;
            attestations.push(attestation.clone());
        }
        let deadline = self
            .current_height
            .saturating_add(self.config.settlement_ttl_blocks);
        let group = NettingGroupRecord::from_request(
            &request,
            &attestations,
            self.current_height,
            deadline,
        );
        for intent_id in &request.intent_ids {
            if let Some(intent) = self.sealed_intents.get_mut(intent_id) {
                intent.status = NettingStatus::Netted;
            }
        }
        self.netting_groups
            .insert(group.group_id.clone(), group.clone());
        self.refresh_intent_records(&request.intent_ids);
        self.publish_public_record("netting_group", &group.group_id, group.public_record());
        Ok(group)
    }

    pub fn settle_batch(
        &mut self,
        request: SettleBatchRequest,
    ) -> PrivateL2DefiRiskNettingEngineResult<SettlementBatchRecord> {
        self.config.validate()?;
        request.validate(&self.config)?;
        let group = self
            .netting_groups
            .get(&request.batch_id)
            .ok_or_else(|| "settlement references unknown netting group".to_string())?;
        if !group.status.can_settle() {
            return Err("netting group is not settlement-ready".to_string());
        }
        if group.settlement_deadline_height <= self.current_height {
            if let Some(expired) = self.netting_groups.get_mut(&request.batch_id) {
                expired.status = NettingStatus::Expired;
            }
            return Err("netting group settlement deadline has expired".to_string());
        }
        if request.posted_fee_bps > group.max_user_fee_bps {
            return Err("posted settlement fee exceeds group fee cap".to_string());
        }
        let settlement_nullifier_hash = private_l2_defi_payload_id(
            "PRIVATE-L2-DEFI-SETTLEMENT-NULLIFIER",
            &[HashPart::Str(&request.settlement_nullifier)],
        );
        self.consume_nullifier(&settlement_nullifier_hash)?;
        let (group_id, group_record, intent_ids, batch, receipt) = {
            let group = self
                .netting_groups
                .get_mut(&request.batch_id)
                .ok_or_else(|| "settlement references unknown netting group".to_string())?;
            let batch = SettlementBatchRecord::from_request(
                &request,
                &group.group_id,
                &settlement_nullifier_hash,
                self.current_height,
            );
            group.status = NettingStatus::Settled;
            let beneficiary_set_root = merkle_root(
                "PRIVATE-L2-DEFI-FEE-REBATE-BENEFICIARIES",
                &group
                    .intent_ids
                    .iter()
                    .map(|intent_id| json!(intent_id))
                    .collect::<Vec<_>>(),
            );
            let receipt = FeeRebateReceiptRecord::new(group, &batch, beneficiary_set_root);
            (
                group.group_id.clone(),
                group.public_record(),
                group.intent_ids.clone(),
                batch,
                receipt,
            )
        };
        for intent_id in &intent_ids {
            if let Some(intent) = self.sealed_intents.get_mut(intent_id) {
                intent.status = NettingStatus::Settled;
            }
        }
        self.settlement_batches
            .insert(batch.batch_id.clone(), batch.clone());
        self.fee_rebate_receipts
            .insert(receipt.receipt_id.clone(), receipt.clone());
        self.publish_public_record("netting_group", &group_id, group_record);
        self.refresh_intent_records(&intent_ids);
        self.publish_public_record("settlement_batch", &batch.batch_id, batch.public_record());
        self.publish_public_record(
            "fee_rebate_receipt",
            &receipt.receipt_id,
            receipt.public_record(),
        );
        Ok(batch)
    }

    pub fn counters(&self) -> Counters {
        Counters {
            sealed_intents: self.sealed_intents.len(),
            risk_attestations: self.risk_attestations.len(),
            netting_groups: self.netting_groups.len(),
            settlement_batches: self.settlement_batches.len(),
            fee_rebate_receipts: self.fee_rebate_receipts.len(),
            consumed_nullifiers: self.consumed_nullifiers.len(),
            public_records: self.public_records.len(),
        }
    }

    pub fn roots(&self) -> Roots {
        Roots {
            config_root: private_l2_defi_payload_root(
                "PRIVATE-L2-DEFI-CONFIG",
                &self.config.public_record(),
            ),
            sealed_intent_root: private_l2_defi_merkle_root(
                "PRIVATE-L2-DEFI-SEALED-INTENT-ROOT",
                self.sealed_intents
                    .values()
                    .map(SealedDefiIntentRecord::public_record)
                    .collect(),
            ),
            risk_attestation_root: private_l2_defi_merkle_root(
                "PRIVATE-L2-DEFI-RISK-ATTESTATION-ROOT",
                self.risk_attestations
                    .values()
                    .map(RiskAttestationRecord::public_record)
                    .collect(),
            ),
            netting_group_root: private_l2_defi_merkle_root(
                "PRIVATE-L2-DEFI-NETTING-GROUP-ROOT",
                self.netting_groups
                    .values()
                    .map(NettingGroupRecord::public_record)
                    .collect(),
            ),
            settlement_batch_root: private_l2_defi_merkle_root(
                "PRIVATE-L2-DEFI-SETTLEMENT-BATCH-ROOT",
                self.settlement_batches
                    .values()
                    .map(SettlementBatchRecord::public_record)
                    .collect(),
            ),
            fee_rebate_receipt_root: private_l2_defi_merkle_root(
                "PRIVATE-L2-DEFI-FEE-REBATE-RECEIPT-ROOT",
                self.fee_rebate_receipts
                    .values()
                    .map(FeeRebateReceiptRecord::public_record)
                    .collect(),
            ),
            nullifier_root: private_l2_defi_merkle_root(
                "PRIVATE-L2-DEFI-NULLIFIER-ROOT",
                self.consumed_nullifiers
                    .iter()
                    .map(|nullifier| json!(nullifier))
                    .collect(),
            ),
            public_record_root: private_l2_defi_merkle_root(
                "PRIVATE-L2-DEFI-PUBLIC-RECORD-ROOT",
                self.public_records.values().cloned().collect(),
            ),
        }
    }

    pub fn roots_only_public_record(&self) -> RootsOnlyPublicRecord {
        let roots = self.roots();
        let counters = self.counters();
        let without_state_root = json!({
            "kind": "private_l2_defi_risk_netting_engine_roots_only_public_record",
            "protocol_version": PRIVATE_L2_DEFI_RISK_NETTING_ENGINE_PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "height": self.current_height,
            "roots": roots.public_record(),
            "counters": counters.public_record(),
        });
        let state_root = private_l2_defi_state_root_from_record(&without_state_root);
        RootsOnlyPublicRecord {
            protocol_version: PRIVATE_L2_DEFI_RISK_NETTING_ENGINE_PROTOCOL_VERSION.to_string(),
            chain_id: CHAIN_ID.to_string(),
            height: self.current_height,
            roots,
            counters,
            state_root,
        }
    }

    pub fn public_record_without_root(&self) -> Value {
        let roots_only = self.roots_only_public_record();
        roots_only.public_record_without_state_root()
    }

    pub fn public_record(&self) -> Value {
        self.roots_only_public_record().public_record()
    }

    pub fn state_root(&self) -> String {
        private_l2_defi_state_root_from_record(&self.public_record_without_root())
    }

    pub fn public_record_root(&self) -> String {
        private_l2_defi_merkle_root(
            "PRIVATE-L2-DEFI-PUBLIC-RECORD-ROOT",
            self.public_records.values().cloned().collect(),
        )
    }

    fn consume_nullifier(
        &mut self,
        nullifier_hash: &str,
    ) -> PrivateL2DefiRiskNettingEngineResult<()> {
        if !self.consumed_nullifiers.insert(nullifier_hash.to_string()) {
            return Err("nullifier replay detected".to_string());
        }
        Ok(())
    }

    fn publish_public_record(&mut self, record_kind: &str, subject_id: &str, payload: Value) {
        let record_id = public_record_id(record_kind, subject_id, &payload);
        self.public_records
            .insert(record_id, roots_only_payload(payload));
    }

    fn refresh_intent_records(&mut self, intent_ids: &[String]) {
        let updates = intent_ids
            .iter()
            .filter_map(|intent_id| {
                self.sealed_intents
                    .get(intent_id)
                    .map(|intent| (intent.intent_id.clone(), intent.public_record()))
            })
            .collect::<Vec<_>>();
        for (intent_id, record) in updates {
            self.publish_public_record("sealed_intent", &intent_id, record);
        }
    }
}

pub fn private_l2_defi_state_root_from_record(record: &Value) -> String {
    domain_hash(
        "PRIVATE-L2-DEFI-RISK-NETTING-ENGINE-STATE-ROOT",
        &[HashPart::Str(CHAIN_ID), HashPart::Json(record)],
        32,
    )
}

pub fn private_l2_defi_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[HashPart::Str(CHAIN_ID), HashPart::Json(payload)],
        32,
    )
}

pub fn private_l2_defi_payload_id(domain: &str, parts: &[HashPart<'_>]) -> String {
    domain_hash(domain, parts, 32)
}

pub fn private_l2_defi_merkle_root(domain: &str, leaves: Vec<Value>) -> String {
    merkle_root(domain, &leaves)
}

fn sealed_intent_id(
    request: &SubmitIntentRequest,
    submitted_height: u64,
    nullifier_hash: &str,
) -> String {
    domain_hash(
        "PRIVATE-L2-DEFI-SEALED-INTENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(request.intent_kind.as_str()),
            HashPart::Str(request.venue.as_str()),
            HashPart::Str(&request.account_commitment),
            HashPart::Str(&request.sealed_payload_root),
            HashPart::Str(&request.asset_pair_root),
            HashPart::Str(nullifier_hash),
            HashPart::Int(submitted_height as i128),
        ],
        32,
    )
}

fn risk_attestation_id(
    request: &RiskAttestationRequest,
    attested_height: u64,
    attestation_nullifier_hash: &str,
) -> String {
    domain_hash(
        "PRIVATE-L2-DEFI-RISK-ATTESTATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.intent_id),
            HashPart::Str(&request.attestor_id),
            HashPart::Str(request.verdict.as_str()),
            HashPart::Int(request.risk_score_bps as i128),
            HashPart::Str(&request.proof_root),
            HashPart::Str(attestation_nullifier_hash),
            HashPart::Int(attested_height as i128),
        ],
        32,
    )
}

fn netting_group_id(
    batch_label: &str,
    venue: LiquidityVenue,
    solver_id: &str,
    intent_root: &str,
    risk_attestation_root: &str,
    opened_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-DEFI-NETTING-GROUP-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(batch_label),
            HashPart::Str(venue.as_str()),
            HashPart::Str(solver_id),
            HashPart::Str(intent_root),
            HashPart::Str(risk_attestation_root),
            HashPart::Int(opened_height as i128),
        ],
        32,
    )
}

fn settlement_batch_id(
    group_id: &str,
    settlement_proof_root: &str,
    settlement_tx_root: &str,
    settlement_nullifier_hash: &str,
    settled_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-DEFI-SETTLEMENT-BATCH-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(group_id),
            HashPart::Str(settlement_proof_root),
            HashPart::Str(settlement_tx_root),
            HashPart::Str(settlement_nullifier_hash),
            HashPart::Int(settled_height as i128),
        ],
        32,
    )
}

fn fee_rebate_receipt_id(
    batch_id: &str,
    group_id: &str,
    fee_plan_root: &str,
    rebate_commitment_root: &str,
    published_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-DEFI-FEE-REBATE-RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(batch_id),
            HashPart::Str(group_id),
            HashPart::Str(fee_plan_root),
            HashPart::Str(rebate_commitment_root),
            HashPart::Int(published_height as i128),
        ],
        32,
    )
}

fn public_record_id(record_kind: &str, subject_id: &str, payload: &Value) -> String {
    domain_hash(
        "PRIVATE-L2-DEFI-PUBLIC-RECORD-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(record_kind),
            HashPart::Str(subject_id),
            HashPart::Json(payload),
        ],
        32,
    )
}

fn roots_only_payload(payload: Value) -> Value {
    json!({
        "kind": "private_l2_defi_roots_only_public_payload",
        "chain_id": CHAIN_ID,
        "payload_root": private_l2_defi_payload_root("PRIVATE-L2-DEFI-ROOTS-ONLY-PAYLOAD", &payload),
    })
}

fn require_non_empty(label: &str, value: &str) -> PrivateL2DefiRiskNettingEngineResult<()> {
    if value.is_empty() {
        return Err(format!("{label} cannot be empty"));
    }
    Ok(())
}

fn require_privacy_set(
    config: &Config,
    privacy_set_size: u64,
    batch: bool,
) -> PrivateL2DefiRiskNettingEngineResult<()> {
    let minimum = if batch {
        config.min_batch_privacy_set_size
    } else {
        config.min_privacy_set_size
    };
    if privacy_set_size < minimum {
        return Err("privacy set is below configured anonymity threshold".to_string());
    }
    Ok(())
}

fn require_pq_security(
    config: &Config,
    pq_security_bits: u16,
) -> PrivateL2DefiRiskNettingEngineResult<()> {
    if pq_security_bits < config.min_pq_security_bits {
        return Err("PQ authorization security bits below configured minimum".to_string());
    }
    Ok(())
}
