use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2ConfidentialSyntheticAssetRuntimeResult<T> = Result<T, String>;

pub const PRIVATE_L2_CONFIDENTIAL_SYNTHETIC_ASSET_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-confidential-synthetic-asset-runtime-v1";
pub const PRIVATE_L2_CONFIDENTIAL_SYNTHETIC_ASSET_RUNTIME_SCHEMA_VERSION: u64 = 1;
pub const PRIVATE_L2_CONFIDENTIAL_SYNTHETIC_ASSET_RUNTIME_HASH_SUITE: &str =
    "SHAKE256-domain-separated-canonical-json";
pub const PRIVATE_L2_CONFIDENTIAL_SYNTHETIC_ASSET_RUNTIME_PQ_AUTH_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-synthetic-asset-v1";
pub const PRIVATE_L2_CONFIDENTIAL_SYNTHETIC_ASSET_RUNTIME_DEVNET_HEIGHT: u64 = 696_000;
pub const PRIVATE_L2_CONFIDENTIAL_SYNTHETIC_ASSET_RUNTIME_MAX_BPS: u64 = 10_000;
pub const PRIVATE_L2_CONFIDENTIAL_SYNTHETIC_ASSET_RUNTIME_DEFAULT_MAX_MARKETS: usize = 262_144;
pub const PRIVATE_L2_CONFIDENTIAL_SYNTHETIC_ASSET_RUNTIME_DEFAULT_MAX_MINTS: usize = 4_194_304;
pub const PRIVATE_L2_CONFIDENTIAL_SYNTHETIC_ASSET_RUNTIME_DEFAULT_MAX_REDEEMS: usize = 4_194_304;
pub const PRIVATE_L2_CONFIDENTIAL_SYNTHETIC_ASSET_RUNTIME_DEFAULT_MAX_RISK_ATTESTATIONS: usize =
    1_048_576;
pub const PRIVATE_L2_CONFIDENTIAL_SYNTHETIC_ASSET_RUNTIME_DEFAULT_MAX_RESERVATIONS: usize =
    1_048_576;
pub const PRIVATE_L2_CONFIDENTIAL_SYNTHETIC_ASSET_RUNTIME_DEFAULT_MAX_REBALANCES: usize = 524_288;
pub const PRIVATE_L2_CONFIDENTIAL_SYNTHETIC_ASSET_RUNTIME_DEFAULT_MAX_RECEIPTS: usize = 4_194_304;
pub const PRIVATE_L2_CONFIDENTIAL_SYNTHETIC_ASSET_RUNTIME_DEFAULT_MIN_PRIVACY_SET: usize = 128;
pub const PRIVATE_L2_CONFIDENTIAL_SYNTHETIC_ASSET_RUNTIME_DEFAULT_BATCH_PRIVACY_SET: usize = 512;
pub const PRIVATE_L2_CONFIDENTIAL_SYNTHETIC_ASSET_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const PRIVATE_L2_CONFIDENTIAL_SYNTHETIC_ASSET_RUNTIME_DEFAULT_MAX_USER_FEE_BPS: u64 = 30;
pub const PRIVATE_L2_CONFIDENTIAL_SYNTHETIC_ASSET_RUNTIME_DEFAULT_TARGET_REBATE_BPS: u64 = 16;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SyntheticAssetKind {
    PrivateUsd,
    PrivateBtc,
    PrivateXmr,
    PrivateEth,
    PrivateCommodity,
    PrivateIndex,
    PrivateRateToken,
    PrivateVolatilityToken,
}

impl SyntheticAssetKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrivateUsd => "private_usd",
            Self::PrivateBtc => "private_btc",
            Self::PrivateXmr => "private_xmr",
            Self::PrivateEth => "private_eth",
            Self::PrivateCommodity => "private_commodity",
            Self::PrivateIndex => "private_index",
            Self::PrivateRateToken => "private_rate_token",
            Self::PrivateVolatilityToken => "private_volatility_token",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MarketStatus {
    Proposed,
    Active,
    Rebalancing,
    Paused,
    Deprecated,
    Settled,
}

impl MarketStatus {
    pub fn accepts_flows(self) -> bool {
        matches!(self, Self::Active | Self::Rebalancing)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MintStatus {
    Submitted,
    Accepted,
    Netted,
    Settled,
    Refunded,
    Rejected,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RedeemStatus {
    Submitted,
    Accepted,
    Netted,
    Settled,
    Cancelled,
    Rejected,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskVerdict {
    Low,
    Medium,
    High,
    Pause,
    Deprecate,
}

impl RiskVerdict {
    pub fn allows_flow(self) -> bool {
        matches!(self, Self::Low | Self::Medium)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReservationStatus {
    Reserved,
    Consumed,
    RebateQueued,
    Refunded,
    Expired,
    Slashed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RebalanceStatus {
    Proposed,
    Executing,
    Settled,
    PartiallySettled,
    Disputed,
    Cancelled,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptKind {
    MarketRegistered,
    MintAccepted,
    RedeemAccepted,
    RiskAttested,
    SponsorReserved,
    RebalanceBuilt,
    SettlementPublished,
    RebatePublished,
}

impl ReceiptKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MarketRegistered => "market_registered",
            Self::MintAccepted => "mint_accepted",
            Self::RedeemAccepted => "redeem_accepted",
            Self::RiskAttested => "risk_attested",
            Self::SponsorReserved => "sponsor_reserved",
            Self::RebalanceBuilt => "rebalance_built",
            Self::SettlementPublished => "settlement_published",
            Self::RebatePublished => "rebate_published",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub protocol_version: String,
    pub schema_version: u64,
    pub chain_id: String,
    pub hash_suite: String,
    pub pq_auth_suite: String,
    pub max_markets: usize,
    pub max_mints: usize,
    pub max_redeems: usize,
    pub max_risk_attestations: usize,
    pub max_sponsor_reservations: usize,
    pub max_rebalances: usize,
    pub max_receipts: usize,
    pub min_privacy_set_size: usize,
    pub batch_privacy_set_size: usize,
    pub min_pq_security_bits: u16,
    pub max_user_fee_bps: u64,
    pub target_rebate_bps: u64,
    pub devnet_height: u64,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version: PRIVATE_L2_CONFIDENTIAL_SYNTHETIC_ASSET_RUNTIME_PROTOCOL_VERSION
                .to_string(),
            schema_version: PRIVATE_L2_CONFIDENTIAL_SYNTHETIC_ASSET_RUNTIME_SCHEMA_VERSION,
            chain_id: CHAIN_ID.to_string(),
            hash_suite: PRIVATE_L2_CONFIDENTIAL_SYNTHETIC_ASSET_RUNTIME_HASH_SUITE.to_string(),
            pq_auth_suite: PRIVATE_L2_CONFIDENTIAL_SYNTHETIC_ASSET_RUNTIME_PQ_AUTH_SUITE
                .to_string(),
            max_markets: PRIVATE_L2_CONFIDENTIAL_SYNTHETIC_ASSET_RUNTIME_DEFAULT_MAX_MARKETS,
            max_mints: PRIVATE_L2_CONFIDENTIAL_SYNTHETIC_ASSET_RUNTIME_DEFAULT_MAX_MINTS,
            max_redeems: PRIVATE_L2_CONFIDENTIAL_SYNTHETIC_ASSET_RUNTIME_DEFAULT_MAX_REDEEMS,
            max_risk_attestations:
                PRIVATE_L2_CONFIDENTIAL_SYNTHETIC_ASSET_RUNTIME_DEFAULT_MAX_RISK_ATTESTATIONS,
            max_sponsor_reservations:
                PRIVATE_L2_CONFIDENTIAL_SYNTHETIC_ASSET_RUNTIME_DEFAULT_MAX_RESERVATIONS,
            max_rebalances: PRIVATE_L2_CONFIDENTIAL_SYNTHETIC_ASSET_RUNTIME_DEFAULT_MAX_REBALANCES,
            max_receipts: PRIVATE_L2_CONFIDENTIAL_SYNTHETIC_ASSET_RUNTIME_DEFAULT_MAX_RECEIPTS,
            min_privacy_set_size:
                PRIVATE_L2_CONFIDENTIAL_SYNTHETIC_ASSET_RUNTIME_DEFAULT_MIN_PRIVACY_SET,
            batch_privacy_set_size:
                PRIVATE_L2_CONFIDENTIAL_SYNTHETIC_ASSET_RUNTIME_DEFAULT_BATCH_PRIVACY_SET,
            min_pq_security_bits:
                PRIVATE_L2_CONFIDENTIAL_SYNTHETIC_ASSET_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS,
            max_user_fee_bps:
                PRIVATE_L2_CONFIDENTIAL_SYNTHETIC_ASSET_RUNTIME_DEFAULT_MAX_USER_FEE_BPS,
            target_rebate_bps:
                PRIVATE_L2_CONFIDENTIAL_SYNTHETIC_ASSET_RUNTIME_DEFAULT_TARGET_REBATE_BPS,
            devnet_height: PRIVATE_L2_CONFIDENTIAL_SYNTHETIC_ASSET_RUNTIME_DEVNET_HEIGHT,
        }
    }

    pub fn validate(&self) -> PrivateL2ConfidentialSyntheticAssetRuntimeResult<()> {
        require_non_empty("protocol_version", &self.protocol_version)?;
        require_non_empty("chain_id", &self.chain_id)?;
        require_non_empty("hash_suite", &self.hash_suite)?;
        require_non_empty("pq_auth_suite", &self.pq_auth_suite)?;
        require_positive("max_markets", self.max_markets)?;
        require_positive("max_mints", self.max_mints)?;
        require_positive("max_redeems", self.max_redeems)?;
        require_positive("max_risk_attestations", self.max_risk_attestations)?;
        require_positive("max_sponsor_reservations", self.max_sponsor_reservations)?;
        require_positive("max_rebalances", self.max_rebalances)?;
        require_positive("max_receipts", self.max_receipts)?;
        require_positive("min_privacy_set_size", self.min_privacy_set_size)?;
        require_positive("batch_privacy_set_size", self.batch_privacy_set_size)?;
        if self.batch_privacy_set_size < self.min_privacy_set_size {
            return Err("batch_privacy_set_size cannot be below min_privacy_set_size".to_string());
        }
        if self.min_pq_security_bits < 192 {
            return Err("min_pq_security_bits must be at least 192".to_string());
        }
        require_bps("max_user_fee_bps", self.max_user_fee_bps)?;
        require_bps("target_rebate_bps", self.target_rebate_bps)?;
        if self.target_rebate_bps > self.max_user_fee_bps {
            return Err("target_rebate_bps cannot exceed max_user_fee_bps".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub market_counter: u64,
    pub mint_counter: u64,
    pub redeem_counter: u64,
    pub risk_attestation_counter: u64,
    pub sponsor_reservation_counter: u64,
    pub rebalance_counter: u64,
    pub receipt_counter: u64,
    pub rebate_counter: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RegisterSyntheticMarketRequest {
    pub market_operator_commitment: String,
    pub asset_kind: SyntheticAssetKind,
    pub asset_id: String,
    pub oracle_price_root: String,
    pub collateral_policy_root: String,
    pub mint_policy_root: String,
    pub redeem_policy_root: String,
    pub pq_governance_root: String,
    pub max_fee_bps: u64,
    pub min_privacy_set_size: usize,
    pub market_nonce: String,
}

impl RegisterSyntheticMarketRequest {
    pub fn validate(
        &self,
        config: &Config,
    ) -> PrivateL2ConfidentialSyntheticAssetRuntimeResult<()> {
        require_non_empty(
            "market_operator_commitment",
            &self.market_operator_commitment,
        )?;
        require_non_empty("asset_id", &self.asset_id)?;
        require_root("oracle_price_root", &self.oracle_price_root)?;
        require_root("collateral_policy_root", &self.collateral_policy_root)?;
        require_root("mint_policy_root", &self.mint_policy_root)?;
        require_root("redeem_policy_root", &self.redeem_policy_root)?;
        require_root("pq_governance_root", &self.pq_governance_root)?;
        require_non_empty("market_nonce", &self.market_nonce)?;
        require_bps("max_fee_bps", self.max_fee_bps)?;
        if self.max_fee_bps > config.max_user_fee_bps {
            return Err("max_fee_bps exceeds runtime fee ceiling".to_string());
        }
        if self.min_privacy_set_size < config.min_privacy_set_size {
            return Err("min_privacy_set_size below runtime minimum".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SubmitPrivateMintRequest {
    pub market_id: String,
    pub minter_commitment: String,
    pub collateral_note_root: String,
    pub minted_note_root: String,
    pub collateral_nullifier_root: String,
    pub mint_range_proof_root: String,
    pub encrypted_mint_payload_root: String,
    pub pq_authorization_root: String,
    pub privacy_set_size: usize,
    pub max_fee_bps: u64,
    pub expires_at_height: u64,
    pub mint_nonce: String,
}

impl SubmitPrivateMintRequest {
    pub fn validate(
        &self,
        config: &Config,
    ) -> PrivateL2ConfidentialSyntheticAssetRuntimeResult<()> {
        require_non_empty("market_id", &self.market_id)?;
        require_non_empty("minter_commitment", &self.minter_commitment)?;
        require_root("collateral_note_root", &self.collateral_note_root)?;
        require_root("minted_note_root", &self.minted_note_root)?;
        require_root("collateral_nullifier_root", &self.collateral_nullifier_root)?;
        require_root("mint_range_proof_root", &self.mint_range_proof_root)?;
        require_root(
            "encrypted_mint_payload_root",
            &self.encrypted_mint_payload_root,
        )?;
        require_root("pq_authorization_root", &self.pq_authorization_root)?;
        require_non_empty("mint_nonce", &self.mint_nonce)?;
        if self.privacy_set_size < config.min_privacy_set_size {
            return Err("mint privacy set below runtime minimum".to_string());
        }
        require_bps("max_fee_bps", self.max_fee_bps)?;
        if self.max_fee_bps > config.max_user_fee_bps {
            return Err("mint fee exceeds runtime ceiling".to_string());
        }
        if self.expires_at_height == 0 {
            return Err("expires_at_height must be positive".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SubmitPrivateRedeemRequest {
    pub market_id: String,
    pub redeemer_commitment: String,
    pub synthetic_note_root: String,
    pub redemption_output_root: String,
    pub synthetic_nullifier_root: String,
    pub redeem_range_proof_root: String,
    pub encrypted_redeem_payload_root: String,
    pub pq_authorization_root: String,
    pub privacy_set_size: usize,
    pub max_fee_bps: u64,
    pub expires_at_height: u64,
    pub redeem_nonce: String,
}

impl SubmitPrivateRedeemRequest {
    pub fn validate(
        &self,
        config: &Config,
    ) -> PrivateL2ConfidentialSyntheticAssetRuntimeResult<()> {
        require_non_empty("market_id", &self.market_id)?;
        require_non_empty("redeemer_commitment", &self.redeemer_commitment)?;
        require_root("synthetic_note_root", &self.synthetic_note_root)?;
        require_root("redemption_output_root", &self.redemption_output_root)?;
        require_root("synthetic_nullifier_root", &self.synthetic_nullifier_root)?;
        require_root("redeem_range_proof_root", &self.redeem_range_proof_root)?;
        require_root(
            "encrypted_redeem_payload_root",
            &self.encrypted_redeem_payload_root,
        )?;
        require_root("pq_authorization_root", &self.pq_authorization_root)?;
        require_non_empty("redeem_nonce", &self.redeem_nonce)?;
        if self.privacy_set_size < config.min_privacy_set_size {
            return Err("redeem privacy set below runtime minimum".to_string());
        }
        require_bps("max_fee_bps", self.max_fee_bps)?;
        if self.max_fee_bps > config.max_user_fee_bps {
            return Err("redeem fee exceeds runtime ceiling".to_string());
        }
        if self.expires_at_height == 0 {
            return Err("expires_at_height must be positive".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AttestSyntheticRiskRequest {
    pub market_id: String,
    pub attester_commitment: String,
    pub verdict: RiskVerdict,
    pub price_oracle_root: String,
    pub collateral_health_root: String,
    pub liquidity_risk_root: String,
    pub pq_signature_root: String,
    pub attested_at_height: u64,
    pub attestation_nonce: String,
}

impl AttestSyntheticRiskRequest {
    pub fn validate(&self) -> PrivateL2ConfidentialSyntheticAssetRuntimeResult<()> {
        require_non_empty("market_id", &self.market_id)?;
        require_non_empty("attester_commitment", &self.attester_commitment)?;
        require_root("price_oracle_root", &self.price_oracle_root)?;
        require_root("collateral_health_root", &self.collateral_health_root)?;
        require_root("liquidity_risk_root", &self.liquidity_risk_root)?;
        require_root("pq_signature_root", &self.pq_signature_root)?;
        require_non_empty("attestation_nonce", &self.attestation_nonce)?;
        if self.attested_at_height == 0 {
            return Err("attested_at_height must be positive".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReserveSyntheticFeeSponsorRequest {
    pub market_id: String,
    pub flow_ids: Vec<String>,
    pub sponsor_commitment: String,
    pub fee_asset_id: String,
    pub budget_commitment_root: String,
    pub rebate_policy_root: String,
    pub pq_sponsor_authorization_root: String,
    pub max_sponsor_fee_bps: u64,
    pub reserved_until_height: u64,
    pub reservation_nonce: String,
}

impl ReserveSyntheticFeeSponsorRequest {
    pub fn validate(
        &self,
        config: &Config,
    ) -> PrivateL2ConfidentialSyntheticAssetRuntimeResult<()> {
        require_non_empty("market_id", &self.market_id)?;
        if self.flow_ids.is_empty() {
            return Err("flow_ids cannot be empty".to_string());
        }
        require_unique("flow_ids", &self.flow_ids)?;
        require_non_empty("sponsor_commitment", &self.sponsor_commitment)?;
        require_non_empty("fee_asset_id", &self.fee_asset_id)?;
        require_root("budget_commitment_root", &self.budget_commitment_root)?;
        require_root("rebate_policy_root", &self.rebate_policy_root)?;
        require_root(
            "pq_sponsor_authorization_root",
            &self.pq_sponsor_authorization_root,
        )?;
        require_non_empty("reservation_nonce", &self.reservation_nonce)?;
        require_bps("max_sponsor_fee_bps", self.max_sponsor_fee_bps)?;
        if self.max_sponsor_fee_bps > config.max_user_fee_bps {
            return Err("max_sponsor_fee_bps exceeds runtime ceiling".to_string());
        }
        if self.reserved_until_height == 0 {
            return Err("reserved_until_height must be positive".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BuildSyntheticRebalanceRequest {
    pub market_ids: Vec<String>,
    pub mint_ids: Vec<String>,
    pub redeem_ids: Vec<String>,
    pub reservation_ids: Vec<String>,
    pub rebalancer_commitment: String,
    pub collateral_delta_root: String,
    pub supply_delta_root: String,
    pub recursive_proof_root: String,
    pub batch_privacy_set_size: usize,
    pub total_fee_bps: u64,
    pub built_at_height: u64,
    pub rebalance_nonce: String,
}

impl BuildSyntheticRebalanceRequest {
    pub fn validate(
        &self,
        config: &Config,
    ) -> PrivateL2ConfidentialSyntheticAssetRuntimeResult<()> {
        if self.market_ids.is_empty() {
            return Err("market_ids cannot be empty".to_string());
        }
        if self.mint_ids.is_empty() && self.redeem_ids.is_empty() {
            return Err("rebalance requires at least one mint or redeem".to_string());
        }
        require_unique("market_ids", &self.market_ids)?;
        require_unique("mint_ids", &self.mint_ids)?;
        require_unique("redeem_ids", &self.redeem_ids)?;
        require_unique("reservation_ids", &self.reservation_ids)?;
        require_non_empty("rebalancer_commitment", &self.rebalancer_commitment)?;
        require_root("collateral_delta_root", &self.collateral_delta_root)?;
        require_root("supply_delta_root", &self.supply_delta_root)?;
        require_root("recursive_proof_root", &self.recursive_proof_root)?;
        require_non_empty("rebalance_nonce", &self.rebalance_nonce)?;
        if self.batch_privacy_set_size < config.batch_privacy_set_size {
            return Err("batch_privacy_set_size below runtime target".to_string());
        }
        require_bps("total_fee_bps", self.total_fee_bps)?;
        if self.total_fee_bps > config.max_user_fee_bps {
            return Err("total_fee_bps exceeds runtime ceiling".to_string());
        }
        if self.built_at_height == 0 {
            return Err("built_at_height must be positive".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublishSyntheticReceiptRequest {
    pub subject_id: String,
    pub receipt_kind: ReceiptKind,
    pub settlement_root: String,
    pub state_root_before: String,
    pub state_root_after: String,
    pub pq_settlement_signature_root: String,
    pub emitted_at_height: u64,
    pub receipt_nonce: String,
}

impl PublishSyntheticReceiptRequest {
    pub fn validate(&self) -> PrivateL2ConfidentialSyntheticAssetRuntimeResult<()> {
        require_non_empty("subject_id", &self.subject_id)?;
        require_root("settlement_root", &self.settlement_root)?;
        require_root("state_root_before", &self.state_root_before)?;
        require_root("state_root_after", &self.state_root_after)?;
        require_root(
            "pq_settlement_signature_root",
            &self.pq_settlement_signature_root,
        )?;
        require_non_empty("receipt_nonce", &self.receipt_nonce)?;
        if self.emitted_at_height == 0 {
            return Err("emitted_at_height must be positive".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublishSyntheticRebateRequest {
    pub reservation_id: String,
    pub sponsor_commitment: String,
    pub rebate_asset_id: String,
    pub rebate_commitment_root: String,
    pub settlement_receipt_id: String,
    pub pq_rebate_signature_root: String,
    pub rebate_bps: u64,
    pub emitted_at_height: u64,
    pub rebate_nonce: String,
}

impl PublishSyntheticRebateRequest {
    pub fn validate(
        &self,
        config: &Config,
    ) -> PrivateL2ConfidentialSyntheticAssetRuntimeResult<()> {
        require_non_empty("reservation_id", &self.reservation_id)?;
        require_non_empty("sponsor_commitment", &self.sponsor_commitment)?;
        require_non_empty("rebate_asset_id", &self.rebate_asset_id)?;
        require_root("rebate_commitment_root", &self.rebate_commitment_root)?;
        require_non_empty("settlement_receipt_id", &self.settlement_receipt_id)?;
        require_root("pq_rebate_signature_root", &self.pq_rebate_signature_root)?;
        require_non_empty("rebate_nonce", &self.rebate_nonce)?;
        require_bps("rebate_bps", self.rebate_bps)?;
        if self.rebate_bps > config.max_user_fee_bps {
            return Err("rebate_bps exceeds runtime ceiling".to_string());
        }
        if self.emitted_at_height == 0 {
            return Err("emitted_at_height must be positive".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SyntheticMarketRecord {
    pub market_id: String,
    pub request: RegisterSyntheticMarketRequest,
    pub status: MarketStatus,
    pub market_root: String,
    pub registered_at_height: u64,
    pub updated_at_height: u64,
}

impl SyntheticMarketRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "market_id": self.market_id,
            "asset_kind": self.request.asset_kind,
            "asset_id": self.request.asset_id,
            "market_operator_commitment": self.request.market_operator_commitment,
            "oracle_price_root": self.request.oracle_price_root,
            "collateral_policy_root": self.request.collateral_policy_root,
            "mint_policy_root": self.request.mint_policy_root,
            "redeem_policy_root": self.request.redeem_policy_root,
            "pq_governance_root": self.request.pq_governance_root,
            "max_fee_bps": self.request.max_fee_bps,
            "min_privacy_set_size": self.request.min_privacy_set_size,
            "status": self.status,
            "market_root": self.market_root,
            "registered_at_height": self.registered_at_height,
            "updated_at_height": self.updated_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivateMintRecord {
    pub mint_id: String,
    pub request: SubmitPrivateMintRequest,
    pub status: MintStatus,
    pub mint_root: String,
    pub accepted_at_height: u64,
}

impl PrivateMintRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "mint_id": self.mint_id,
            "market_id": self.request.market_id,
            "minter_commitment": self.request.minter_commitment,
            "collateral_note_root": self.request.collateral_note_root,
            "minted_note_root": self.request.minted_note_root,
            "collateral_nullifier_root": self.request.collateral_nullifier_root,
            "mint_range_proof_root": self.request.mint_range_proof_root,
            "encrypted_mint_payload_root": self.request.encrypted_mint_payload_root,
            "pq_authorization_root": self.request.pq_authorization_root,
            "privacy_set_size": self.request.privacy_set_size,
            "max_fee_bps": self.request.max_fee_bps,
            "expires_at_height": self.request.expires_at_height,
            "status": self.status,
            "mint_root": self.mint_root,
            "accepted_at_height": self.accepted_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivateRedeemRecord {
    pub redeem_id: String,
    pub request: SubmitPrivateRedeemRequest,
    pub status: RedeemStatus,
    pub redeem_root: String,
    pub accepted_at_height: u64,
}

impl PrivateRedeemRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "redeem_id": self.redeem_id,
            "market_id": self.request.market_id,
            "redeemer_commitment": self.request.redeemer_commitment,
            "synthetic_note_root": self.request.synthetic_note_root,
            "redemption_output_root": self.request.redemption_output_root,
            "synthetic_nullifier_root": self.request.synthetic_nullifier_root,
            "redeem_range_proof_root": self.request.redeem_range_proof_root,
            "encrypted_redeem_payload_root": self.request.encrypted_redeem_payload_root,
            "pq_authorization_root": self.request.pq_authorization_root,
            "privacy_set_size": self.request.privacy_set_size,
            "max_fee_bps": self.request.max_fee_bps,
            "expires_at_height": self.request.expires_at_height,
            "status": self.status,
            "redeem_root": self.redeem_root,
            "accepted_at_height": self.accepted_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SyntheticRiskAttestationRecord {
    pub attestation_id: String,
    pub request: AttestSyntheticRiskRequest,
    pub attestation_root: String,
}

impl SyntheticRiskAttestationRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "market_id": self.request.market_id,
            "attester_commitment": self.request.attester_commitment,
            "verdict": self.request.verdict,
            "price_oracle_root": self.request.price_oracle_root,
            "collateral_health_root": self.request.collateral_health_root,
            "liquidity_risk_root": self.request.liquidity_risk_root,
            "pq_signature_root": self.request.pq_signature_root,
            "attested_at_height": self.request.attested_at_height,
            "attestation_root": self.attestation_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SyntheticSponsorReservationRecord {
    pub reservation_id: String,
    pub request: ReserveSyntheticFeeSponsorRequest,
    pub status: ReservationStatus,
    pub reservation_root: String,
    pub reserved_at_height: u64,
}

impl SyntheticSponsorReservationRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "reservation_id": self.reservation_id,
            "market_id": self.request.market_id,
            "flow_ids": self.request.flow_ids,
            "sponsor_commitment": self.request.sponsor_commitment,
            "fee_asset_id": self.request.fee_asset_id,
            "budget_commitment_root": self.request.budget_commitment_root,
            "rebate_policy_root": self.request.rebate_policy_root,
            "pq_sponsor_authorization_root": self.request.pq_sponsor_authorization_root,
            "max_sponsor_fee_bps": self.request.max_sponsor_fee_bps,
            "reserved_until_height": self.request.reserved_until_height,
            "status": self.status,
            "reservation_root": self.reservation_root,
            "reserved_at_height": self.reserved_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SyntheticRebalanceRecord {
    pub rebalance_id: String,
    pub request: BuildSyntheticRebalanceRequest,
    pub status: RebalanceStatus,
    pub rebalance_root: String,
    pub state_root_after: String,
}

impl SyntheticRebalanceRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "rebalance_id": self.rebalance_id,
            "market_ids": self.request.market_ids,
            "mint_ids": self.request.mint_ids,
            "redeem_ids": self.request.redeem_ids,
            "reservation_ids": self.request.reservation_ids,
            "rebalancer_commitment": self.request.rebalancer_commitment,
            "collateral_delta_root": self.request.collateral_delta_root,
            "supply_delta_root": self.request.supply_delta_root,
            "recursive_proof_root": self.request.recursive_proof_root,
            "batch_privacy_set_size": self.request.batch_privacy_set_size,
            "total_fee_bps": self.request.total_fee_bps,
            "built_at_height": self.request.built_at_height,
            "status": self.status,
            "rebalance_root": self.rebalance_root,
            "state_root_after": self.state_root_after,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SyntheticReceiptRecord {
    pub receipt_id: String,
    pub request: PublishSyntheticReceiptRequest,
    pub receipt_root: String,
}

impl SyntheticReceiptRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "subject_id": self.request.subject_id,
            "receipt_kind": self.request.receipt_kind,
            "settlement_root": self.request.settlement_root,
            "state_root_before": self.request.state_root_before,
            "state_root_after": self.request.state_root_after,
            "pq_settlement_signature_root": self.request.pq_settlement_signature_root,
            "emitted_at_height": self.request.emitted_at_height,
            "receipt_root": self.receipt_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SyntheticRebateRecord {
    pub rebate_id: String,
    pub request: PublishSyntheticRebateRequest,
    pub rebate_root: String,
}

impl SyntheticRebateRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "rebate_id": self.rebate_id,
            "reservation_id": self.request.reservation_id,
            "sponsor_commitment": self.request.sponsor_commitment,
            "rebate_asset_id": self.request.rebate_asset_id,
            "rebate_commitment_root": self.request.rebate_commitment_root,
            "settlement_receipt_id": self.request.settlement_receipt_id,
            "pq_rebate_signature_root": self.request.pq_rebate_signature_root,
            "rebate_bps": self.request.rebate_bps,
            "emitted_at_height": self.request.emitted_at_height,
            "rebate_root": self.rebate_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub market_root: String,
    pub mint_root: String,
    pub redeem_root: String,
    pub risk_attestation_root: String,
    pub sponsor_reservation_root: String,
    pub rebalance_root: String,
    pub receipt_root: String,
    pub rebate_root: String,
    pub nullifier_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub markets: BTreeMap<String, SyntheticMarketRecord>,
    pub mints: BTreeMap<String, PrivateMintRecord>,
    pub redeems: BTreeMap<String, PrivateRedeemRecord>,
    pub risk_attestations: BTreeMap<String, SyntheticRiskAttestationRecord>,
    pub sponsor_reservations: BTreeMap<String, SyntheticSponsorReservationRecord>,
    pub rebalances: BTreeMap<String, SyntheticRebalanceRecord>,
    pub receipts: BTreeMap<String, SyntheticReceiptRecord>,
    pub rebates: BTreeMap<String, SyntheticRebateRecord>,
    pub consumed_nullifiers: BTreeSet<String>,
}

impl State {
    pub fn devnet() -> PrivateL2ConfidentialSyntheticAssetRuntimeResult<Self> {
        Self::new(Config::devnet())
    }

    pub fn new(config: Config) -> PrivateL2ConfidentialSyntheticAssetRuntimeResult<Self> {
        config.validate()?;
        Ok(Self {
            config,
            counters: Counters::default(),
            markets: BTreeMap::new(),
            mints: BTreeMap::new(),
            redeems: BTreeMap::new(),
            risk_attestations: BTreeMap::new(),
            sponsor_reservations: BTreeMap::new(),
            rebalances: BTreeMap::new(),
            receipts: BTreeMap::new(),
            rebates: BTreeMap::new(),
            consumed_nullifiers: BTreeSet::new(),
        })
    }

    pub fn register_market(
        &mut self,
        request: RegisterSyntheticMarketRequest,
    ) -> PrivateL2ConfidentialSyntheticAssetRuntimeResult<SyntheticMarketRecord> {
        request.validate(&self.config)?;
        if self.markets.len() >= self.config.max_markets {
            return Err("synthetic market capacity exhausted".to_string());
        }
        self.counters.market_counter = self.counters.market_counter.saturating_add(1);
        let market_id = synthetic_market_id(&request, self.counters.market_counter);
        let market_root = root_from_record(
            "PRIVATE-L2-CONFIDENTIAL-SYNTHETIC-ASSET-MARKET",
            &request.public_record(),
        );
        let record = SyntheticMarketRecord {
            market_id: market_id.clone(),
            request,
            status: MarketStatus::Active,
            market_root,
            registered_at_height: self.config.devnet_height,
            updated_at_height: self.config.devnet_height,
        };
        self.markets.insert(market_id, record.clone());
        Ok(record)
    }

    pub fn submit_private_mint(
        &mut self,
        request: SubmitPrivateMintRequest,
    ) -> PrivateL2ConfidentialSyntheticAssetRuntimeResult<PrivateMintRecord> {
        request.validate(&self.config)?;
        if self.mints.len() >= self.config.max_mints {
            return Err("private mint capacity exhausted".to_string());
        }
        let market = self.require_market(&request.market_id)?;
        if !market.status.accepts_flows() {
            return Err(format!(
                "market {} does not accept mints",
                request.market_id
            ));
        }
        if self
            .consumed_nullifiers
            .contains(&request.collateral_nullifier_root)
        {
            return Err("collateral nullifier replay detected".to_string());
        }
        if let Some(attestation) = self.latest_risk_for_market(&request.market_id) {
            if !attestation.request.verdict.allows_flow() {
                return Err("latest PQ risk verdict blocks mint".to_string());
            }
        }
        self.counters.mint_counter = self.counters.mint_counter.saturating_add(1);
        let mint_id = private_mint_id(&request, self.counters.mint_counter);
        let mint_root = root_from_record(
            "PRIVATE-L2-CONFIDENTIAL-SYNTHETIC-ASSET-MINT",
            &request.public_record(),
        );
        let record = PrivateMintRecord {
            mint_id: mint_id.clone(),
            request: request.clone(),
            status: MintStatus::Accepted,
            mint_root,
            accepted_at_height: self.config.devnet_height,
        };
        self.consumed_nullifiers
            .insert(request.collateral_nullifier_root.clone());
        self.mints.insert(mint_id, record.clone());
        Ok(record)
    }

    pub fn submit_private_redeem(
        &mut self,
        request: SubmitPrivateRedeemRequest,
    ) -> PrivateL2ConfidentialSyntheticAssetRuntimeResult<PrivateRedeemRecord> {
        request.validate(&self.config)?;
        if self.redeems.len() >= self.config.max_redeems {
            return Err("private redeem capacity exhausted".to_string());
        }
        let market = self.require_market(&request.market_id)?;
        if !market.status.accepts_flows() {
            return Err(format!(
                "market {} does not accept redeems",
                request.market_id
            ));
        }
        if self
            .consumed_nullifiers
            .contains(&request.synthetic_nullifier_root)
        {
            return Err("synthetic nullifier replay detected".to_string());
        }
        if let Some(attestation) = self.latest_risk_for_market(&request.market_id) {
            if !attestation.request.verdict.allows_flow() {
                return Err("latest PQ risk verdict blocks redeem".to_string());
            }
        }
        self.counters.redeem_counter = self.counters.redeem_counter.saturating_add(1);
        let redeem_id = private_redeem_id(&request, self.counters.redeem_counter);
        let redeem_root = root_from_record(
            "PRIVATE-L2-CONFIDENTIAL-SYNTHETIC-ASSET-REDEEM",
            &request.public_record(),
        );
        let record = PrivateRedeemRecord {
            redeem_id: redeem_id.clone(),
            request: request.clone(),
            status: RedeemStatus::Accepted,
            redeem_root,
            accepted_at_height: self.config.devnet_height,
        };
        self.consumed_nullifiers
            .insert(request.synthetic_nullifier_root.clone());
        self.redeems.insert(redeem_id, record.clone());
        Ok(record)
    }

    pub fn attest_risk(
        &mut self,
        request: AttestSyntheticRiskRequest,
    ) -> PrivateL2ConfidentialSyntheticAssetRuntimeResult<SyntheticRiskAttestationRecord> {
        request.validate()?;
        if self.risk_attestations.len() >= self.config.max_risk_attestations {
            return Err("synthetic risk attestation capacity exhausted".to_string());
        }
        self.require_market(&request.market_id)?;
        self.counters.risk_attestation_counter =
            self.counters.risk_attestation_counter.saturating_add(1);
        let attestation_id =
            synthetic_risk_attestation_id(&request, self.counters.risk_attestation_counter);
        let attestation_root = root_from_record(
            "PRIVATE-L2-CONFIDENTIAL-SYNTHETIC-ASSET-RISK",
            &request.public_record(),
        );
        let verdict = request.verdict;
        let market_id_value = request.market_id.clone();
        let record = SyntheticRiskAttestationRecord {
            attestation_id: attestation_id.clone(),
            request,
            attestation_root,
        };
        self.risk_attestations
            .insert(attestation_id, record.clone());
        if let Some(market) = self.markets.get_mut(&market_id_value) {
            market.status = match verdict {
                RiskVerdict::Pause => MarketStatus::Paused,
                RiskVerdict::Deprecate => MarketStatus::Deprecated,
                _ => market.status,
            };
            market.updated_at_height = self.config.devnet_height;
        }
        Ok(record)
    }

    pub fn reserve_fee_sponsor(
        &mut self,
        request: ReserveSyntheticFeeSponsorRequest,
    ) -> PrivateL2ConfidentialSyntheticAssetRuntimeResult<SyntheticSponsorReservationRecord> {
        request.validate(&self.config)?;
        if self.sponsor_reservations.len() >= self.config.max_sponsor_reservations {
            return Err("synthetic sponsor reservation capacity exhausted".to_string());
        }
        self.require_market(&request.market_id)?;
        for flow_id in &request.flow_ids {
            if !self.mints.contains_key(flow_id) && !self.redeems.contains_key(flow_id) {
                return Err(format!("unknown synthetic flow {flow_id}"));
            }
        }
        self.counters.sponsor_reservation_counter =
            self.counters.sponsor_reservation_counter.saturating_add(1);
        let reservation_id =
            synthetic_sponsor_reservation_id(&request, self.counters.sponsor_reservation_counter);
        let reservation_root = root_from_record(
            "PRIVATE-L2-CONFIDENTIAL-SYNTHETIC-ASSET-SPONSOR",
            &request.public_record(),
        );
        let record = SyntheticSponsorReservationRecord {
            reservation_id: reservation_id.clone(),
            request,
            status: ReservationStatus::Reserved,
            reservation_root,
            reserved_at_height: self.config.devnet_height,
        };
        self.sponsor_reservations
            .insert(reservation_id, record.clone());
        Ok(record)
    }

    pub fn build_rebalance(
        &mut self,
        request: BuildSyntheticRebalanceRequest,
    ) -> PrivateL2ConfidentialSyntheticAssetRuntimeResult<SyntheticRebalanceRecord> {
        request.validate(&self.config)?;
        if self.rebalances.len() >= self.config.max_rebalances {
            return Err("synthetic rebalance capacity exhausted".to_string());
        }
        for market_id in &request.market_ids {
            self.require_market(market_id)?;
        }
        for mint_id in &request.mint_ids {
            self.require_mint(mint_id)?;
        }
        for redeem_id in &request.redeem_ids {
            self.require_redeem(redeem_id)?;
        }
        for reservation_id in &request.reservation_ids {
            self.require_reservation(reservation_id)?;
        }
        self.counters.rebalance_counter = self.counters.rebalance_counter.saturating_add(1);
        let rebalance_id = synthetic_rebalance_id(&request, self.counters.rebalance_counter);
        let rebalance_root = root_from_record(
            "PRIVATE-L2-CONFIDENTIAL-SYNTHETIC-ASSET-REBALANCE",
            &request.public_record(),
        );
        for mint_id in &request.mint_ids {
            if let Some(mint) = self.mints.get_mut(mint_id) {
                mint.status = MintStatus::Netted;
            }
        }
        for redeem_id in &request.redeem_ids {
            if let Some(redeem) = self.redeems.get_mut(redeem_id) {
                redeem.status = RedeemStatus::Netted;
            }
        }
        for reservation_id in &request.reservation_ids {
            if let Some(reservation) = self.sponsor_reservations.get_mut(reservation_id) {
                reservation.status = ReservationStatus::Consumed;
            }
        }
        let state_root_after = state_root_from_record(&json!({
            "rebalance_root": rebalance_root,
            "previous_state_root": self.state_root(),
            "rebalance_counter": self.counters.rebalance_counter,
        }));
        let record = SyntheticRebalanceRecord {
            rebalance_id: rebalance_id.clone(),
            request,
            status: RebalanceStatus::Proposed,
            rebalance_root,
            state_root_after,
        };
        self.rebalances.insert(rebalance_id, record.clone());
        Ok(record)
    }

    pub fn publish_receipt(
        &mut self,
        request: PublishSyntheticReceiptRequest,
    ) -> PrivateL2ConfidentialSyntheticAssetRuntimeResult<SyntheticReceiptRecord> {
        request.validate()?;
        if self.receipts.len() >= self.config.max_receipts {
            return Err("synthetic receipt capacity exhausted".to_string());
        }
        self.counters.receipt_counter = self.counters.receipt_counter.saturating_add(1);
        let receipt_id = synthetic_receipt_id(&request, self.counters.receipt_counter);
        let receipt_root = root_from_record(
            "PRIVATE-L2-CONFIDENTIAL-SYNTHETIC-ASSET-RECEIPT",
            &request.public_record(),
        );
        let record = SyntheticReceiptRecord {
            receipt_id: receipt_id.clone(),
            request,
            receipt_root,
        };
        self.receipts.insert(receipt_id, record.clone());
        Ok(record)
    }

    pub fn publish_rebate(
        &mut self,
        request: PublishSyntheticRebateRequest,
    ) -> PrivateL2ConfidentialSyntheticAssetRuntimeResult<SyntheticRebateRecord> {
        request.validate(&self.config)?;
        if self.rebates.len() >= self.config.max_receipts {
            return Err("synthetic rebate capacity exhausted".to_string());
        }
        self.require_reservation(&request.reservation_id)?;
        self.counters.rebate_counter = self.counters.rebate_counter.saturating_add(1);
        let rebate_id = synthetic_rebate_id(&request, self.counters.rebate_counter);
        let rebate_root = root_from_record(
            "PRIVATE-L2-CONFIDENTIAL-SYNTHETIC-ASSET-REBATE",
            &request.public_record(),
        );
        let record = SyntheticRebateRecord {
            rebate_id: rebate_id.clone(),
            request: request.clone(),
            rebate_root,
        };
        if let Some(reservation) = self.sponsor_reservations.get_mut(&request.reservation_id) {
            reservation.status = ReservationStatus::RebateQueued;
        }
        self.rebates.insert(rebate_id, record.clone());
        Ok(record)
    }

    pub fn roots(&self) -> Roots {
        let market_root = public_record_root(
            "PRIVATE-L2-CONFIDENTIAL-SYNTHETIC-ASSET-MARKETS",
            &self
                .markets
                .values()
                .map(SyntheticMarketRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let mint_root = public_record_root(
            "PRIVATE-L2-CONFIDENTIAL-SYNTHETIC-ASSET-MINTS",
            &self
                .mints
                .values()
                .map(PrivateMintRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let redeem_root = public_record_root(
            "PRIVATE-L2-CONFIDENTIAL-SYNTHETIC-ASSET-REDEEMS",
            &self
                .redeems
                .values()
                .map(PrivateRedeemRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let risk_attestation_root = public_record_root(
            "PRIVATE-L2-CONFIDENTIAL-SYNTHETIC-ASSET-RISK",
            &self
                .risk_attestations
                .values()
                .map(SyntheticRiskAttestationRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let sponsor_reservation_root = public_record_root(
            "PRIVATE-L2-CONFIDENTIAL-SYNTHETIC-ASSET-SPONSORS",
            &self
                .sponsor_reservations
                .values()
                .map(SyntheticSponsorReservationRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let rebalance_root = public_record_root(
            "PRIVATE-L2-CONFIDENTIAL-SYNTHETIC-ASSET-REBALANCES",
            &self
                .rebalances
                .values()
                .map(SyntheticRebalanceRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let receipt_root = public_record_root(
            "PRIVATE-L2-CONFIDENTIAL-SYNTHETIC-ASSET-RECEIPTS",
            &self
                .receipts
                .values()
                .map(SyntheticReceiptRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let rebate_root = public_record_root(
            "PRIVATE-L2-CONFIDENTIAL-SYNTHETIC-ASSET-REBATES",
            &self
                .rebates
                .values()
                .map(SyntheticRebateRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let nullifier_root = public_record_root(
            "PRIVATE-L2-CONFIDENTIAL-SYNTHETIC-ASSET-NULLIFIERS",
            &self
                .consumed_nullifiers
                .iter()
                .map(|nullifier| json!(nullifier))
                .collect::<Vec<_>>(),
        );
        let state_record = json!({
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "market_root": market_root,
            "mint_root": mint_root,
            "redeem_root": redeem_root,
            "risk_attestation_root": risk_attestation_root,
            "sponsor_reservation_root": sponsor_reservation_root,
            "rebalance_root": rebalance_root,
            "receipt_root": receipt_root,
            "rebate_root": rebate_root,
            "nullifier_root": nullifier_root,
        });
        let state_root = state_root_from_record(&state_record);
        Roots {
            market_root,
            mint_root,
            redeem_root,
            risk_attestation_root,
            sponsor_reservation_root,
            rebalance_root,
            receipt_root,
            rebate_root,
            nullifier_root,
            state_root,
        }
    }

    pub fn public_record_without_state_root(&self) -> Value {
        let roots = self.roots();
        json!({
            "protocol_version": self.config.protocol_version,
            "schema_version": self.config.schema_version,
            "chain_id": self.config.chain_id,
            "hash_suite": self.config.hash_suite,
            "pq_auth_suite": self.config.pq_auth_suite,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": roots.public_record(),
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        if let Some(map) = record.as_object_mut() {
            map.insert("state_root".to_string(), json!(self.state_root()));
        }
        record
    }

    pub fn state_root(&self) -> String {
        self.roots().state_root
    }

    fn require_market(
        &self,
        market_id: &str,
    ) -> PrivateL2ConfidentialSyntheticAssetRuntimeResult<&SyntheticMarketRecord> {
        self.markets
            .get(market_id)
            .ok_or_else(|| format!("unknown synthetic market {market_id}"))
    }

    fn require_mint(
        &self,
        mint_id: &str,
    ) -> PrivateL2ConfidentialSyntheticAssetRuntimeResult<&PrivateMintRecord> {
        self.mints
            .get(mint_id)
            .ok_or_else(|| format!("unknown private mint {mint_id}"))
    }

    fn require_redeem(
        &self,
        redeem_id: &str,
    ) -> PrivateL2ConfidentialSyntheticAssetRuntimeResult<&PrivateRedeemRecord> {
        self.redeems
            .get(redeem_id)
            .ok_or_else(|| format!("unknown private redeem {redeem_id}"))
    }

    fn require_reservation(
        &self,
        reservation_id: &str,
    ) -> PrivateL2ConfidentialSyntheticAssetRuntimeResult<&SyntheticSponsorReservationRecord> {
        self.sponsor_reservations
            .get(reservation_id)
            .ok_or_else(|| format!("unknown synthetic sponsor reservation {reservation_id}"))
    }

    fn latest_risk_for_market(&self, market_id: &str) -> Option<&SyntheticRiskAttestationRecord> {
        self.risk_attestations
            .values()
            .filter(|attestation| attestation.request.market_id == market_id)
            .max_by_key(|attestation| attestation.request.attested_at_height)
    }
}

pub type Runtime = State;

pub fn synthetic_market_id(request: &RegisterSyntheticMarketRequest, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-CONFIDENTIAL-SYNTHETIC-ASSET-MARKET-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PRIVATE_L2_CONFIDENTIAL_SYNTHETIC_ASSET_RUNTIME_PROTOCOL_VERSION),
            HashPart::Int(sequence as i128),
            HashPart::Str(request.asset_kind.as_str()),
            HashPart::Str(&request.asset_id),
            HashPart::Str(&request.market_operator_commitment),
            HashPart::Str(&request.market_nonce),
        ],
        32,
    )
}

pub fn private_mint_id(request: &SubmitPrivateMintRequest, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-CONFIDENTIAL-SYNTHETIC-ASSET-MINT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PRIVATE_L2_CONFIDENTIAL_SYNTHETIC_ASSET_RUNTIME_PROTOCOL_VERSION),
            HashPart::Int(sequence as i128),
            HashPart::Str(&request.market_id),
            HashPart::Str(&request.minter_commitment),
            HashPart::Str(&request.collateral_note_root),
            HashPart::Str(&request.collateral_nullifier_root),
            HashPart::Str(&request.mint_nonce),
        ],
        32,
    )
}

pub fn private_redeem_id(request: &SubmitPrivateRedeemRequest, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-CONFIDENTIAL-SYNTHETIC-ASSET-REDEEM-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PRIVATE_L2_CONFIDENTIAL_SYNTHETIC_ASSET_RUNTIME_PROTOCOL_VERSION),
            HashPart::Int(sequence as i128),
            HashPart::Str(&request.market_id),
            HashPart::Str(&request.redeemer_commitment),
            HashPart::Str(&request.synthetic_note_root),
            HashPart::Str(&request.synthetic_nullifier_root),
            HashPart::Str(&request.redeem_nonce),
        ],
        32,
    )
}

pub fn synthetic_risk_attestation_id(
    request: &AttestSyntheticRiskRequest,
    sequence: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-CONFIDENTIAL-SYNTHETIC-ASSET-RISK-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PRIVATE_L2_CONFIDENTIAL_SYNTHETIC_ASSET_RUNTIME_PROTOCOL_VERSION),
            HashPart::Int(sequence as i128),
            HashPart::Str(&request.market_id),
            HashPart::Str(&request.attester_commitment),
            HashPart::Str(&request.price_oracle_root),
            HashPart::Str(&request.pq_signature_root),
            HashPart::Str(&request.attestation_nonce),
        ],
        32,
    )
}

pub fn synthetic_sponsor_reservation_id(
    request: &ReserveSyntheticFeeSponsorRequest,
    sequence: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-CONFIDENTIAL-SYNTHETIC-ASSET-SPONSOR-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PRIVATE_L2_CONFIDENTIAL_SYNTHETIC_ASSET_RUNTIME_PROTOCOL_VERSION),
            HashPart::Int(sequence as i128),
            HashPart::Str(&request.market_id),
            HashPart::Str(&id_list_root("flows", &request.flow_ids)),
            HashPart::Str(&request.sponsor_commitment),
            HashPart::Str(&request.reservation_nonce),
        ],
        32,
    )
}

pub fn synthetic_rebalance_id(request: &BuildSyntheticRebalanceRequest, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-CONFIDENTIAL-SYNTHETIC-ASSET-REBALANCE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PRIVATE_L2_CONFIDENTIAL_SYNTHETIC_ASSET_RUNTIME_PROTOCOL_VERSION),
            HashPart::Int(sequence as i128),
            HashPart::Str(&id_list_root("markets", &request.market_ids)),
            HashPart::Str(&id_list_root("mints", &request.mint_ids)),
            HashPart::Str(&id_list_root("redeems", &request.redeem_ids)),
            HashPart::Str(&request.collateral_delta_root),
            HashPart::Str(&request.rebalance_nonce),
        ],
        32,
    )
}

pub fn synthetic_receipt_id(request: &PublishSyntheticReceiptRequest, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-CONFIDENTIAL-SYNTHETIC-ASSET-RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PRIVATE_L2_CONFIDENTIAL_SYNTHETIC_ASSET_RUNTIME_PROTOCOL_VERSION),
            HashPart::Int(sequence as i128),
            HashPart::Str(&request.subject_id),
            HashPart::Str(request.receipt_kind.as_str()),
            HashPart::Str(&request.settlement_root),
            HashPart::Str(&request.receipt_nonce),
        ],
        32,
    )
}

pub fn synthetic_rebate_id(request: &PublishSyntheticRebateRequest, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-CONFIDENTIAL-SYNTHETIC-ASSET-REBATE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PRIVATE_L2_CONFIDENTIAL_SYNTHETIC_ASSET_RUNTIME_PROTOCOL_VERSION),
            HashPart::Int(sequence as i128),
            HashPart::Str(&request.reservation_id),
            HashPart::Str(&request.sponsor_commitment),
            HashPart::Str(&request.rebate_commitment_root),
            HashPart::Str(&request.rebate_nonce),
        ],
        32,
    )
}

pub fn root_from_record(domain: &str, record: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(PRIVATE_L2_CONFIDENTIAL_SYNTHETIC_ASSET_RUNTIME_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Json(record),
        ],
        32,
    )
}

pub fn payload_root(domain: &str, payload: &Value) -> String {
    root_from_record(domain, payload)
}

pub fn public_record_root(domain: &str, records: &[Value]) -> String {
    merkle_root(domain, records)
}

pub fn state_root_from_record(record: &Value) -> String {
    root_from_record("PRIVATE-L2-CONFIDENTIAL-SYNTHETIC-ASSET-STATE", record)
}

fn id_list_root(domain: &str, ids: &[String]) -> String {
    public_record_root(
        &format!("PRIVATE-L2-CONFIDENTIAL-SYNTHETIC-ASSET-ID-LIST-{domain}"),
        &ids.iter().map(|id| json!(id)).collect::<Vec<_>>(),
    )
}

fn require_non_empty(
    field: &str,
    value: &str,
) -> PrivateL2ConfidentialSyntheticAssetRuntimeResult<()> {
    if value.trim().is_empty() {
        Err(format!("{field} cannot be empty"))
    } else {
        Ok(())
    }
}

fn require_root(field: &str, value: &str) -> PrivateL2ConfidentialSyntheticAssetRuntimeResult<()> {
    require_non_empty(field, value)?;
    if value.len() < 16 {
        return Err(format!("{field} must look like a commitment root"));
    }
    Ok(())
}

fn require_positive(
    field: &str,
    value: usize,
) -> PrivateL2ConfidentialSyntheticAssetRuntimeResult<()> {
    if value == 0 {
        Err(format!("{field} must be positive"))
    } else {
        Ok(())
    }
}

fn require_bps(field: &str, value: u64) -> PrivateL2ConfidentialSyntheticAssetRuntimeResult<()> {
    if value > PRIVATE_L2_CONFIDENTIAL_SYNTHETIC_ASSET_RUNTIME_MAX_BPS {
        Err(format!("{field} exceeds basis point maximum"))
    } else {
        Ok(())
    }
}

fn require_unique(
    field: &str,
    values: &[String],
) -> PrivateL2ConfidentialSyntheticAssetRuntimeResult<()> {
    let mut seen = BTreeSet::new();
    for value in values {
        require_non_empty(field, value)?;
        if !seen.insert(value) {
            return Err(format!("{field} contains duplicate value {value}"));
        }
    }
    Ok(())
}
