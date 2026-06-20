use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateGasFuturesResult<T> = Result<T, String>;

pub const PRIVATE_GAS_FUTURES_PROTOCOL_VERSION: &str = "nebula-private-gas-futures-v1";
pub const PRIVATE_GAS_FUTURES_MARGIN_PROOF_SCHEME: &str =
    "zk-margin-solvency-range-proof-shake256-v1";
pub const PRIVATE_GAS_FUTURES_PQ_AUTH_SCHEME: &str = "ml-dsa-87-gas-futures-authorization-v1";
pub const PRIVATE_GAS_FUTURES_NETTING_PROOF_SCHEME: &str =
    "zk-private-fee-netting-proof-shake256-v1";
pub const PRIVATE_GAS_FUTURES_REBATE_PROOF_SCHEME: &str =
    "zk-low-fee-rebate-voucher-proof-shake256-v1";
pub const PRIVATE_GAS_FUTURES_DEFAULT_HEIGHT: u64 = 64;
pub const PRIVATE_GAS_FUTURES_DEFAULT_EPOCH_BLOCKS: u64 = 120;
pub const PRIVATE_GAS_FUTURES_DEFAULT_QUOTE_TTL_BLOCKS: u64 = 18;
pub const PRIVATE_GAS_FUTURES_DEFAULT_CONTRACT_TTL_BLOCKS: u64 = 720;
pub const PRIVATE_GAS_FUTURES_DEFAULT_NETTING_INTERVAL_BLOCKS: u64 = 24;
pub const PRIVATE_GAS_FUTURES_DEFAULT_MARGIN_RATIO_BPS: u64 = 1_500;
pub const PRIVATE_GAS_FUTURES_DEFAULT_REBATE_FLOOR_BPS: u64 = 5_000;
pub const PRIVATE_GAS_FUTURES_DEFAULT_MAX_LANE_EXPOSURE_BPS: u64 = 4_000;
pub const PRIVATE_GAS_FUTURES_DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 96;
pub const PRIVATE_GAS_FUTURES_DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const PRIVATE_GAS_FUTURES_MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GasFuturesLane {
    PrivateTransfer,
    MoneroBridge,
    PrivateDefiSwap,
    ContractCall,
    ProofSubmission,
    WalletRecovery,
    EmergencyExit,
}

impl GasFuturesLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrivateTransfer => "private_transfer",
            Self::MoneroBridge => "monero_bridge",
            Self::PrivateDefiSwap => "private_defi_swap",
            Self::ContractCall => "contract_call",
            Self::ProofSubmission => "proof_submission",
            Self::WalletRecovery => "wallet_recovery",
            Self::EmergencyExit => "emergency_exit",
        }
    }

    pub fn default_target_micro_fee(self) -> u64 {
        match self {
            Self::EmergencyExit => 350,
            Self::WalletRecovery => 550,
            Self::PrivateTransfer => 800,
            Self::MoneroBridge => 1_100,
            Self::PrivateDefiSwap => 1_450,
            Self::ContractCall => 1_900,
            Self::ProofSubmission => 2_600,
        }
    }

    pub fn default_weight(self) -> u64 {
        match self {
            Self::EmergencyExit => 120,
            Self::WalletRecovery => 95,
            Self::MoneroBridge => 90,
            Self::PrivateTransfer => 80,
            Self::PrivateDefiSwap => 70,
            Self::ContractCall => 60,
            Self::ProofSubmission => 50,
        }
    }

    pub fn default_privacy_floor(self) -> u64 {
        match self {
            Self::PrivateTransfer => 192,
            Self::MoneroBridge => 160,
            Self::PrivateDefiSwap => 128,
            Self::ContractCall => 96,
            Self::ProofSubmission => 64,
            Self::WalletRecovery => 144,
            Self::EmergencyExit => 128,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HedgeSide {
    FeePayerLong,
    SponsorShort,
    MarketMakerNeutral,
}

impl HedgeSide {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FeePayerLong => "fee_payer_long",
            Self::SponsorShort => "sponsor_short",
            Self::MarketMakerNeutral => "market_maker_neutral",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GasFutureStatus {
    Open,
    Matched,
    Netted,
    Settled,
    Expired,
    Cancelled,
    Disputed,
}

impl GasFutureStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Matched => "matched",
            Self::Netted => "netted",
            Self::Settled => "settled",
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
            Self::Disputed => "disputed",
        }
    }

    pub fn live(self) -> bool {
        matches!(self, Self::Open | Self::Matched | Self::Netted)
    }

    pub fn terminal(self) -> bool {
        matches!(
            self,
            Self::Settled | Self::Expired | Self::Cancelled | Self::Disputed
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HedgeOrderStatus {
    Posted,
    Matched,
    Cancelled,
    Expired,
    Slashed,
}

impl HedgeOrderStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Posted => "posted",
            Self::Matched => "matched",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
            Self::Slashed => "slashed",
        }
    }

    pub fn matchable(self) -> bool {
        matches!(self, Self::Posted)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GasAuctionStatus {
    CommitOpen,
    RevealOpen,
    Clearing,
    Cleared,
    Cancelled,
    Expired,
}

impl GasAuctionStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CommitOpen => "commit_open",
            Self::RevealOpen => "reveal_open",
            Self::Clearing => "clearing",
            Self::Cleared => "cleared",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
        }
    }

    pub fn live(self) -> bool {
        matches!(self, Self::CommitOpen | Self::RevealOpen | Self::Clearing)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NettingCycleStatus {
    Open,
    Locked,
    Proved,
    Settled,
    Challenged,
    Expired,
}

impl NettingCycleStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Locked => "locked",
            Self::Proved => "proved",
            Self::Settled => "settled",
            Self::Challenged => "challenged",
            Self::Expired => "expired",
        }
    }

    pub fn accepts_contracts(self) -> bool {
        matches!(self, Self::Open)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MarginStatus {
    Healthy,
    Warning,
    Frozen,
    Liquidating,
    Closed,
}

impl MarginStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Healthy => "healthy",
            Self::Warning => "warning",
            Self::Frozen => "frozen",
            Self::Liquidating => "liquidating",
            Self::Closed => "closed",
        }
    }

    pub fn usable(self) -> bool {
        matches!(self, Self::Healthy | Self::Warning)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RebateVoucherStatus {
    Open,
    Reserved,
    Redeemed,
    Expired,
    Revoked,
}

impl RebateVoucherStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Reserved => "reserved",
            Self::Redeemed => "redeemed",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
        }
    }

    pub fn redeemable(self) -> bool {
        matches!(self, Self::Open | Self::Reserved)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GasOracleSource {
    SequencerTelemetry,
    ProverMarket,
    LowFeeMarket,
    DaSampling,
    MoneroBridge,
}

impl GasOracleSource {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SequencerTelemetry => "sequencer_telemetry",
            Self::ProverMarket => "prover_market",
            Self::LowFeeMarket => "low_fee_market",
            Self::DaSampling => "da_sampling",
            Self::MoneroBridge => "monero_bridge",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateGasFuturesConfig {
    pub protocol_version: String,
    pub chain_id: String,
    pub fee_asset_id: String,
    pub epoch_blocks: u64,
    pub quote_ttl_blocks: u64,
    pub contract_ttl_blocks: u64,
    pub netting_interval_blocks: u64,
    pub margin_ratio_bps: u64,
    pub rebate_floor_bps: u64,
    pub max_lane_exposure_bps: u64,
    pub min_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub allow_public_emergency_settlement: bool,
}

impl Default for PrivateGasFuturesConfig {
    fn default() -> Self {
        Self {
            protocol_version: PRIVATE_GAS_FUTURES_PROTOCOL_VERSION.to_string(),
            chain_id: CHAIN_ID.to_string(),
            fee_asset_id: "wxmr-devnet".to_string(),
            epoch_blocks: PRIVATE_GAS_FUTURES_DEFAULT_EPOCH_BLOCKS,
            quote_ttl_blocks: PRIVATE_GAS_FUTURES_DEFAULT_QUOTE_TTL_BLOCKS,
            contract_ttl_blocks: PRIVATE_GAS_FUTURES_DEFAULT_CONTRACT_TTL_BLOCKS,
            netting_interval_blocks: PRIVATE_GAS_FUTURES_DEFAULT_NETTING_INTERVAL_BLOCKS,
            margin_ratio_bps: PRIVATE_GAS_FUTURES_DEFAULT_MARGIN_RATIO_BPS,
            rebate_floor_bps: PRIVATE_GAS_FUTURES_DEFAULT_REBATE_FLOOR_BPS,
            max_lane_exposure_bps: PRIVATE_GAS_FUTURES_DEFAULT_MAX_LANE_EXPOSURE_BPS,
            min_privacy_set_size: PRIVATE_GAS_FUTURES_DEFAULT_MIN_PRIVACY_SET_SIZE,
            min_pq_security_bits: PRIVATE_GAS_FUTURES_DEFAULT_MIN_PQ_SECURITY_BITS,
            allow_public_emergency_settlement: false,
        }
    }
}

impl PrivateGasFuturesConfig {
    pub fn devnet() -> Self {
        Self {
            epoch_blocks: 60,
            quote_ttl_blocks: 12,
            contract_ttl_blocks: 360,
            netting_interval_blocks: 12,
            margin_ratio_bps: 1_250,
            rebate_floor_bps: 6_500,
            max_lane_exposure_bps: 3_500,
            min_privacy_set_size: 128,
            ..Self::default()
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_gas_futures_config",
            "protocol_version": self.protocol_version,
            "chain_id": self.chain_id,
            "fee_asset_id": self.fee_asset_id,
            "epoch_blocks": self.epoch_blocks,
            "quote_ttl_blocks": self.quote_ttl_blocks,
            "contract_ttl_blocks": self.contract_ttl_blocks,
            "netting_interval_blocks": self.netting_interval_blocks,
            "margin_ratio_bps": self.margin_ratio_bps,
            "rebate_floor_bps": self.rebate_floor_bps,
            "max_lane_exposure_bps": self.max_lane_exposure_bps,
            "min_privacy_set_size": self.min_privacy_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
            "allow_public_emergency_settlement": self.allow_public_emergency_settlement,
        })
    }

    pub fn config_root(&self) -> String {
        private_gas_futures_payload_root("PRIVATE-GAS-FUTURES-CONFIG", &self.public_record())
    }

    pub fn validate(&self) -> PrivateGasFuturesResult<()> {
        ensure_non_empty(&self.protocol_version, "protocol version")?;
        ensure_non_empty(&self.chain_id, "chain id")?;
        ensure_non_empty(&self.fee_asset_id, "fee asset id")?;
        ensure_positive(self.epoch_blocks, "epoch blocks")?;
        ensure_positive(self.quote_ttl_blocks, "quote ttl blocks")?;
        ensure_positive(self.contract_ttl_blocks, "contract ttl blocks")?;
        ensure_positive(self.netting_interval_blocks, "netting interval blocks")?;
        ensure_bps(self.margin_ratio_bps, "margin ratio")?;
        ensure_bps(self.rebate_floor_bps, "rebate floor")?;
        ensure_bps(self.max_lane_exposure_bps, "max lane exposure")?;
        if self.quote_ttl_blocks >= self.contract_ttl_blocks {
            return Err("quote ttl must be shorter than contract ttl".to_string());
        }
        if self.min_pq_security_bits < 192 {
            return Err("minimum pq security must be at least 192 bits".to_string());
        }
        if self.min_privacy_set_size < 32 {
            return Err("minimum privacy set size must be at least 32".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GasIndexObservation {
    pub observation_id: String,
    pub lane: GasFuturesLane,
    pub source: GasOracleSource,
    pub observed_micro_fee: u64,
    pub target_micro_fee: u64,
    pub congestion_bps: u64,
    pub volatility_bps: u64,
    pub sample_count: u64,
    pub privacy_set_size: u64,
    pub observed_at_height: u64,
    pub expires_at_height: u64,
    pub evidence_root: String,
}

impl GasIndexObservation {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        lane: GasFuturesLane,
        source: GasOracleSource,
        observed_micro_fee: u64,
        target_micro_fee: u64,
        congestion_bps: u64,
        volatility_bps: u64,
        sample_count: u64,
        privacy_set_size: u64,
        observed_at_height: u64,
        expires_at_height: u64,
        evidence: &Value,
    ) -> PrivateGasFuturesResult<Self> {
        let evidence_root =
            private_gas_futures_payload_root("PRIVATE-GAS-INDEX-EVIDENCE", evidence);
        let observation_id = gas_index_observation_id(
            lane,
            source,
            observed_micro_fee,
            observed_at_height,
            &evidence_root,
        );
        let observation = Self {
            observation_id,
            lane,
            source,
            observed_micro_fee,
            target_micro_fee,
            congestion_bps,
            volatility_bps,
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
        if self.target_micro_fee == 0 {
            return 0;
        }
        self.observed_micro_fee
            .saturating_sub(self.target_micro_fee)
            .saturating_mul(PRIVATE_GAS_FUTURES_MAX_BPS)
            / self.target_micro_fee
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "gas_index_observation",
            "observation_id": self.observation_id,
            "lane": self.lane.as_str(),
            "source": self.source.as_str(),
            "observed_micro_fee": self.observed_micro_fee,
            "target_micro_fee": self.target_micro_fee,
            "premium_bps": self.premium_bps(),
            "congestion_bps": self.congestion_bps,
            "volatility_bps": self.volatility_bps,
            "sample_count": self.sample_count,
            "privacy_set_size": self.privacy_set_size,
            "observed_at_height": self.observed_at_height,
            "expires_at_height": self.expires_at_height,
            "evidence_root": self.evidence_root,
        })
    }

    pub fn state_root(&self) -> String {
        private_gas_futures_payload_root("PRIVATE-GAS-INDEX-OBSERVATION", &self.public_record())
    }

    pub fn validate(&self) -> PrivateGasFuturesResult<()> {
        ensure_non_empty(&self.observation_id, "observation id")?;
        ensure_positive(self.observed_micro_fee, "observed micro fee")?;
        ensure_positive(self.target_micro_fee, "target micro fee")?;
        ensure_bps(self.congestion_bps, "congestion")?;
        ensure_bps(self.volatility_bps, "volatility")?;
        ensure_positive(self.sample_count, "sample count")?;
        ensure_positive(self.privacy_set_size, "privacy set size")?;
        ensure_height_window(
            self.observed_at_height,
            self.expires_at_height,
            "observation",
        )?;
        ensure_non_empty(&self.evidence_root, "evidence root")?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MarginAccount {
    pub margin_account_id: String,
    pub owner_commitment: String,
    pub fee_asset_id: String,
    pub posted_margin_units: u64,
    pub locked_margin_units: u64,
    pub realized_pnl_units: i64,
    pub max_exposure_units: u64,
    pub status: MarginStatus,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub margin_proof_root: String,
    pub created_at_height: u64,
    pub updated_at_height: u64,
}

impl MarginAccount {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        owner_commitment: &str,
        fee_asset_id: &str,
        posted_margin_units: u64,
        max_exposure_units: u64,
        privacy_set_size: u64,
        pq_security_bits: u16,
        margin_proof: &Value,
        height: u64,
    ) -> PrivateGasFuturesResult<Self> {
        ensure_non_empty(owner_commitment, "owner commitment")?;
        ensure_non_empty(fee_asset_id, "fee asset id")?;
        let margin_proof_root =
            private_gas_futures_payload_root("PRIVATE-GAS-MARGIN-PROOF", margin_proof);
        let margin_account_id =
            margin_account_id(owner_commitment, fee_asset_id, height, &margin_proof_root);
        let account = Self {
            margin_account_id,
            owner_commitment: owner_commitment.to_string(),
            fee_asset_id: fee_asset_id.to_string(),
            posted_margin_units,
            locked_margin_units: 0,
            realized_pnl_units: 0,
            max_exposure_units,
            status: MarginStatus::Healthy,
            privacy_set_size,
            pq_security_bits,
            margin_proof_root,
            created_at_height: height,
            updated_at_height: height,
        };
        account.validate()?;
        Ok(account)
    }

    pub fn available_margin_units(&self) -> u64 {
        self.posted_margin_units
            .saturating_sub(self.locked_margin_units)
    }

    pub fn utilization_bps(&self) -> u64 {
        if self.posted_margin_units == 0 {
            return PRIVATE_GAS_FUTURES_MAX_BPS;
        }
        self.locked_margin_units
            .saturating_mul(PRIVATE_GAS_FUTURES_MAX_BPS)
            / self.posted_margin_units
    }

    pub fn lock_margin(&mut self, units: u64, height: u64) -> PrivateGasFuturesResult<String> {
        ensure_positive(units, "margin lock units")?;
        if !self.status.usable() {
            return Err("margin account is not usable".to_string());
        }
        if units > self.available_margin_units() {
            return Err("insufficient available margin".to_string());
        }
        self.locked_margin_units = self.locked_margin_units.saturating_add(units);
        self.updated_at_height = height;
        if self.utilization_bps() > 8_000 {
            self.status = MarginStatus::Warning;
        }
        self.validate()?;
        Ok(self.state_root())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "margin_account",
            "margin_account_id": self.margin_account_id,
            "owner_commitment": self.owner_commitment,
            "fee_asset_id": self.fee_asset_id,
            "posted_margin_units": self.posted_margin_units,
            "locked_margin_units": self.locked_margin_units,
            "available_margin_units": self.available_margin_units(),
            "realized_pnl_units": self.realized_pnl_units,
            "max_exposure_units": self.max_exposure_units,
            "status": self.status.as_str(),
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "margin_proof_scheme": PRIVATE_GAS_FUTURES_MARGIN_PROOF_SCHEME,
            "margin_proof_root": self.margin_proof_root,
            "created_at_height": self.created_at_height,
            "updated_at_height": self.updated_at_height,
        })
    }

    pub fn state_root(&self) -> String {
        private_gas_futures_payload_root("PRIVATE-GAS-MARGIN-ACCOUNT", &self.public_record())
    }

    pub fn validate(&self) -> PrivateGasFuturesResult<()> {
        ensure_non_empty(&self.margin_account_id, "margin account id")?;
        ensure_non_empty(&self.owner_commitment, "owner commitment")?;
        ensure_non_empty(&self.fee_asset_id, "fee asset id")?;
        ensure_positive(self.posted_margin_units, "posted margin")?;
        ensure_positive(self.max_exposure_units, "max exposure")?;
        if self.locked_margin_units > self.posted_margin_units {
            return Err("locked margin cannot exceed posted margin".to_string());
        }
        if self.max_exposure_units < self.posted_margin_units {
            return Err("max exposure must cover posted margin".to_string());
        }
        ensure_positive(self.privacy_set_size, "privacy set size")?;
        if self.pq_security_bits < 192 {
            return Err("margin account pq security below minimum".to_string());
        }
        ensure_non_empty(&self.margin_proof_root, "margin proof root")?;
        if self.updated_at_height < self.created_at_height {
            return Err("margin update height cannot precede creation".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateGasFutureContract {
    pub contract_id: String,
    pub lane: GasFuturesLane,
    pub buyer_commitment: String,
    pub seller_commitment: String,
    pub buyer_margin_account_id: String,
    pub seller_margin_account_id: String,
    pub notional_gas_units: u64,
    pub strike_micro_fee: u64,
    pub cap_micro_fee: u64,
    pub premium_micro_fee: u64,
    pub hedge_side: HedgeSide,
    pub status: GasFutureStatus,
    pub opened_at_height: u64,
    pub maturity_height: u64,
    pub expires_at_height: u64,
    pub matched_order_id: String,
    pub netting_cycle_id: String,
    pub pq_authorization_root: String,
    pub privacy_nullifier_root: String,
    pub metadata_root: String,
}

impl PrivateGasFutureContract {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        lane: GasFuturesLane,
        buyer_commitment: &str,
        seller_commitment: &str,
        buyer_margin_account_id: &str,
        seller_margin_account_id: &str,
        notional_gas_units: u64,
        strike_micro_fee: u64,
        cap_micro_fee: u64,
        premium_micro_fee: u64,
        hedge_side: HedgeSide,
        opened_at_height: u64,
        maturity_height: u64,
        expires_at_height: u64,
        pq_authorization: &Value,
        privacy_nullifier: &Value,
        metadata: &Value,
    ) -> PrivateGasFuturesResult<Self> {
        let pq_authorization_root =
            private_gas_futures_payload_root("PRIVATE-GAS-PQ-AUTHORIZATION", pq_authorization);
        let privacy_nullifier_root =
            private_gas_futures_payload_root("PRIVATE-GAS-PRIVACY-NULLIFIER", privacy_nullifier);
        let metadata_root =
            private_gas_futures_payload_root("PRIVATE-GAS-CONTRACT-METADATA", metadata);
        let contract_id = gas_future_contract_id(
            lane,
            buyer_commitment,
            seller_commitment,
            strike_micro_fee,
            maturity_height,
            &privacy_nullifier_root,
        );
        let contract = Self {
            contract_id,
            lane,
            buyer_commitment: buyer_commitment.to_string(),
            seller_commitment: seller_commitment.to_string(),
            buyer_margin_account_id: buyer_margin_account_id.to_string(),
            seller_margin_account_id: seller_margin_account_id.to_string(),
            notional_gas_units,
            strike_micro_fee,
            cap_micro_fee,
            premium_micro_fee,
            hedge_side,
            status: GasFutureStatus::Matched,
            opened_at_height,
            maturity_height,
            expires_at_height,
            matched_order_id: String::new(),
            netting_cycle_id: String::new(),
            pq_authorization_root,
            privacy_nullifier_root,
            metadata_root,
        };
        contract.validate()?;
        Ok(contract)
    }

    pub fn mark_netted(
        &mut self,
        netting_cycle_id: &str,
        height: u64,
    ) -> PrivateGasFuturesResult<String> {
        ensure_non_empty(netting_cycle_id, "netting cycle id")?;
        if self.status.terminal() {
            return Err("terminal gas future cannot be netted".to_string());
        }
        if height < self.opened_at_height {
            return Err("netting height cannot precede open height".to_string());
        }
        self.netting_cycle_id = netting_cycle_id.to_string();
        self.status = GasFutureStatus::Netted;
        self.validate()?;
        Ok(self.state_root())
    }

    pub fn exposure_micro_units(&self) -> u64 {
        self.notional_gas_units.saturating_mul(self.cap_micro_fee)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_gas_future_contract",
            "contract_id": self.contract_id,
            "lane": self.lane.as_str(),
            "buyer_commitment": self.buyer_commitment,
            "seller_commitment": self.seller_commitment,
            "buyer_margin_account_id": self.buyer_margin_account_id,
            "seller_margin_account_id": self.seller_margin_account_id,
            "notional_gas_units": self.notional_gas_units,
            "strike_micro_fee": self.strike_micro_fee,
            "cap_micro_fee": self.cap_micro_fee,
            "premium_micro_fee": self.premium_micro_fee,
            "hedge_side": self.hedge_side.as_str(),
            "status": self.status.as_str(),
            "opened_at_height": self.opened_at_height,
            "maturity_height": self.maturity_height,
            "expires_at_height": self.expires_at_height,
            "matched_order_id": self.matched_order_id,
            "netting_cycle_id": self.netting_cycle_id,
            "pq_authorization_scheme": PRIVATE_GAS_FUTURES_PQ_AUTH_SCHEME,
            "pq_authorization_root": self.pq_authorization_root,
            "privacy_nullifier_root": self.privacy_nullifier_root,
            "metadata_root": self.metadata_root,
            "exposure_micro_units": self.exposure_micro_units(),
        })
    }

    pub fn state_root(&self) -> String {
        private_gas_futures_payload_root("PRIVATE-GAS-FUTURE-CONTRACT", &self.public_record())
    }

    pub fn validate(&self) -> PrivateGasFuturesResult<()> {
        ensure_non_empty(&self.contract_id, "contract id")?;
        ensure_non_empty(&self.buyer_commitment, "buyer commitment")?;
        ensure_non_empty(&self.seller_commitment, "seller commitment")?;
        ensure_non_empty(&self.buyer_margin_account_id, "buyer margin account id")?;
        ensure_non_empty(&self.seller_margin_account_id, "seller margin account id")?;
        ensure_positive(self.notional_gas_units, "notional gas units")?;
        ensure_positive(self.strike_micro_fee, "strike micro fee")?;
        ensure_positive(self.cap_micro_fee, "cap micro fee")?;
        if self.cap_micro_fee < self.strike_micro_fee {
            return Err("cap micro fee cannot be below strike".to_string());
        }
        ensure_height_window(
            self.opened_at_height,
            self.maturity_height,
            "contract maturity",
        )?;
        ensure_height_window(
            self.maturity_height,
            self.expires_at_height,
            "contract expiry",
        )?;
        ensure_non_empty(&self.pq_authorization_root, "pq authorization root")?;
        ensure_non_empty(&self.privacy_nullifier_root, "privacy nullifier root")?;
        ensure_non_empty(&self.metadata_root, "metadata root")?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateHedgeOrder {
    pub order_id: String,
    pub lane: GasFuturesLane,
    pub maker_commitment: String,
    pub margin_account_id: String,
    pub side: HedgeSide,
    pub min_strike_micro_fee: u64,
    pub max_strike_micro_fee: u64,
    pub notional_gas_units: u64,
    pub premium_limit_micro_fee: u64,
    pub status: HedgeOrderStatus,
    pub posted_at_height: u64,
    pub expires_at_height: u64,
    pub pq_authorization_root: String,
    pub private_terms_root: String,
}

impl PrivateHedgeOrder {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        lane: GasFuturesLane,
        maker_commitment: &str,
        margin_account_id: &str,
        side: HedgeSide,
        min_strike_micro_fee: u64,
        max_strike_micro_fee: u64,
        notional_gas_units: u64,
        premium_limit_micro_fee: u64,
        posted_at_height: u64,
        expires_at_height: u64,
        pq_authorization: &Value,
        private_terms: &Value,
    ) -> PrivateGasFuturesResult<Self> {
        let pq_authorization_root =
            private_gas_futures_payload_root("PRIVATE-GAS-ORDER-PQ-AUTH", pq_authorization);
        let private_terms_root =
            private_gas_futures_payload_root("PRIVATE-GAS-ORDER-TERMS", private_terms);
        let order_id = hedge_order_id(
            lane,
            maker_commitment,
            margin_account_id,
            side,
            posted_at_height,
            &private_terms_root,
        );
        let order = Self {
            order_id,
            lane,
            maker_commitment: maker_commitment.to_string(),
            margin_account_id: margin_account_id.to_string(),
            side,
            min_strike_micro_fee,
            max_strike_micro_fee,
            notional_gas_units,
            premium_limit_micro_fee,
            status: HedgeOrderStatus::Posted,
            posted_at_height,
            expires_at_height,
            pq_authorization_root,
            private_terms_root,
        };
        order.validate()?;
        Ok(order)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_hedge_order",
            "order_id": self.order_id,
            "lane": self.lane.as_str(),
            "maker_commitment": self.maker_commitment,
            "margin_account_id": self.margin_account_id,
            "side": self.side.as_str(),
            "min_strike_micro_fee": self.min_strike_micro_fee,
            "max_strike_micro_fee": self.max_strike_micro_fee,
            "notional_gas_units": self.notional_gas_units,
            "premium_limit_micro_fee": self.premium_limit_micro_fee,
            "status": self.status.as_str(),
            "posted_at_height": self.posted_at_height,
            "expires_at_height": self.expires_at_height,
            "pq_authorization_root": self.pq_authorization_root,
            "private_terms_root": self.private_terms_root,
        })
    }

    pub fn state_root(&self) -> String {
        private_gas_futures_payload_root("PRIVATE-GAS-HEDGE-ORDER", &self.public_record())
    }

    pub fn validate(&self) -> PrivateGasFuturesResult<()> {
        ensure_non_empty(&self.order_id, "order id")?;
        ensure_non_empty(&self.maker_commitment, "maker commitment")?;
        ensure_non_empty(&self.margin_account_id, "margin account id")?;
        ensure_positive(self.min_strike_micro_fee, "min strike")?;
        ensure_positive(self.max_strike_micro_fee, "max strike")?;
        if self.max_strike_micro_fee < self.min_strike_micro_fee {
            return Err("max strike cannot be below min strike".to_string());
        }
        ensure_positive(self.notional_gas_units, "notional gas units")?;
        ensure_height_window(
            self.posted_at_height,
            self.expires_at_height,
            "order expiry",
        )?;
        ensure_non_empty(&self.pq_authorization_root, "pq authorization root")?;
        ensure_non_empty(&self.private_terms_root, "private terms root")?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateGasAuction {
    pub auction_id: String,
    pub lane: GasFuturesLane,
    pub status: GasAuctionStatus,
    pub commit_root: String,
    pub reveal_root: String,
    pub clearing_price_micro_fee: u64,
    pub total_notional_gas_units: u64,
    pub min_privacy_set_size: u64,
    pub opened_at_height: u64,
    pub reveal_opens_at_height: u64,
    pub closes_at_height: u64,
    pub clearing_proof_root: String,
}

impl PrivateGasAuction {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        lane: GasFuturesLane,
        commit_root: &str,
        reveal_root: &str,
        clearing_price_micro_fee: u64,
        total_notional_gas_units: u64,
        min_privacy_set_size: u64,
        opened_at_height: u64,
        reveal_opens_at_height: u64,
        closes_at_height: u64,
        clearing_proof: &Value,
    ) -> PrivateGasFuturesResult<Self> {
        let clearing_proof_root =
            private_gas_futures_payload_root("PRIVATE-GAS-AUCTION-CLEARING-PROOF", clearing_proof);
        let auction_id = gas_auction_id(lane, opened_at_height, commit_root, &clearing_proof_root);
        let auction = Self {
            auction_id,
            lane,
            status: GasAuctionStatus::CommitOpen,
            commit_root: commit_root.to_string(),
            reveal_root: reveal_root.to_string(),
            clearing_price_micro_fee,
            total_notional_gas_units,
            min_privacy_set_size,
            opened_at_height,
            reveal_opens_at_height,
            closes_at_height,
            clearing_proof_root,
        };
        auction.validate()?;
        Ok(auction)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_gas_auction",
            "auction_id": self.auction_id,
            "lane": self.lane.as_str(),
            "status": self.status.as_str(),
            "commit_root": self.commit_root,
            "reveal_root": self.reveal_root,
            "clearing_price_micro_fee": self.clearing_price_micro_fee,
            "total_notional_gas_units": self.total_notional_gas_units,
            "min_privacy_set_size": self.min_privacy_set_size,
            "opened_at_height": self.opened_at_height,
            "reveal_opens_at_height": self.reveal_opens_at_height,
            "closes_at_height": self.closes_at_height,
            "clearing_proof_root": self.clearing_proof_root,
        })
    }

    pub fn state_root(&self) -> String {
        private_gas_futures_payload_root("PRIVATE-GAS-AUCTION", &self.public_record())
    }

    pub fn validate(&self) -> PrivateGasFuturesResult<()> {
        ensure_non_empty(&self.auction_id, "auction id")?;
        ensure_non_empty(&self.commit_root, "commit root")?;
        ensure_non_empty(&self.reveal_root, "reveal root")?;
        ensure_positive(self.clearing_price_micro_fee, "clearing price")?;
        ensure_positive(self.total_notional_gas_units, "total notional gas")?;
        ensure_positive(self.min_privacy_set_size, "min privacy set size")?;
        ensure_height_window(
            self.opened_at_height,
            self.reveal_opens_at_height,
            "auction reveal",
        )?;
        ensure_height_window(
            self.reveal_opens_at_height,
            self.closes_at_height,
            "auction close",
        )?;
        ensure_non_empty(&self.clearing_proof_root, "clearing proof root")?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GasNettingCycle {
    pub cycle_id: String,
    pub lane: GasFuturesLane,
    pub status: NettingCycleStatus,
    pub opened_at_height: u64,
    pub locks_at_height: u64,
    pub proves_at_height: u64,
    pub settles_at_height: u64,
    pub contract_root: String,
    pub margin_delta_root: String,
    pub rebate_root: String,
    pub netting_proof_root: String,
    pub total_long_notional_units: u64,
    pub total_short_notional_units: u64,
    pub net_exposure_micro_units: i64,
}

impl GasNettingCycle {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        lane: GasFuturesLane,
        opened_at_height: u64,
        locks_at_height: u64,
        proves_at_height: u64,
        settles_at_height: u64,
        contract_root: &str,
        margin_delta_root: &str,
        rebate_root: &str,
        netting_proof: &Value,
        total_long_notional_units: u64,
        total_short_notional_units: u64,
        net_exposure_micro_units: i64,
    ) -> PrivateGasFuturesResult<Self> {
        let netting_proof_root =
            private_gas_futures_payload_root("PRIVATE-GAS-NETTING-PROOF", netting_proof);
        let cycle_id = netting_cycle_id(lane, opened_at_height, contract_root, &netting_proof_root);
        let cycle = Self {
            cycle_id,
            lane,
            status: NettingCycleStatus::Open,
            opened_at_height,
            locks_at_height,
            proves_at_height,
            settles_at_height,
            contract_root: contract_root.to_string(),
            margin_delta_root: margin_delta_root.to_string(),
            rebate_root: rebate_root.to_string(),
            netting_proof_root,
            total_long_notional_units,
            total_short_notional_units,
            net_exposure_micro_units,
        };
        cycle.validate()?;
        Ok(cycle)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "gas_netting_cycle",
            "cycle_id": self.cycle_id,
            "lane": self.lane.as_str(),
            "status": self.status.as_str(),
            "opened_at_height": self.opened_at_height,
            "locks_at_height": self.locks_at_height,
            "proves_at_height": self.proves_at_height,
            "settles_at_height": self.settles_at_height,
            "contract_root": self.contract_root,
            "margin_delta_root": self.margin_delta_root,
            "rebate_root": self.rebate_root,
            "netting_proof_scheme": PRIVATE_GAS_FUTURES_NETTING_PROOF_SCHEME,
            "netting_proof_root": self.netting_proof_root,
            "total_long_notional_units": self.total_long_notional_units,
            "total_short_notional_units": self.total_short_notional_units,
            "net_exposure_micro_units": self.net_exposure_micro_units,
        })
    }

    pub fn state_root(&self) -> String {
        private_gas_futures_payload_root("PRIVATE-GAS-NETTING-CYCLE", &self.public_record())
    }

    pub fn validate(&self) -> PrivateGasFuturesResult<()> {
        ensure_non_empty(&self.cycle_id, "netting cycle id")?;
        ensure_height_window(self.opened_at_height, self.locks_at_height, "netting lock")?;
        ensure_height_window(self.locks_at_height, self.proves_at_height, "netting proof")?;
        ensure_height_window(
            self.proves_at_height,
            self.settles_at_height,
            "netting settle",
        )?;
        ensure_non_empty(&self.contract_root, "contract root")?;
        ensure_non_empty(&self.margin_delta_root, "margin delta root")?;
        ensure_non_empty(&self.rebate_root, "rebate root")?;
        ensure_non_empty(&self.netting_proof_root, "netting proof root")?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RebateVoucher {
    pub voucher_id: String,
    pub lane: GasFuturesLane,
    pub beneficiary_commitment: String,
    pub sponsor_commitment: String,
    pub fee_asset_id: String,
    pub rebate_units: u64,
    pub fee_cap_micro_units: u64,
    pub min_privacy_set_size: u64,
    pub status: RebateVoucherStatus,
    pub issued_at_height: u64,
    pub expires_at_height: u64,
    pub proof_root: String,
}

impl RebateVoucher {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        lane: GasFuturesLane,
        beneficiary_commitment: &str,
        sponsor_commitment: &str,
        fee_asset_id: &str,
        rebate_units: u64,
        fee_cap_micro_units: u64,
        min_privacy_set_size: u64,
        issued_at_height: u64,
        expires_at_height: u64,
        proof: &Value,
    ) -> PrivateGasFuturesResult<Self> {
        let proof_root = private_gas_futures_payload_root("PRIVATE-GAS-REBATE-PROOF", proof);
        let voucher_id = rebate_voucher_id(
            lane,
            beneficiary_commitment,
            sponsor_commitment,
            issued_at_height,
            &proof_root,
        );
        let voucher = Self {
            voucher_id,
            lane,
            beneficiary_commitment: beneficiary_commitment.to_string(),
            sponsor_commitment: sponsor_commitment.to_string(),
            fee_asset_id: fee_asset_id.to_string(),
            rebate_units,
            fee_cap_micro_units,
            min_privacy_set_size,
            status: RebateVoucherStatus::Open,
            issued_at_height,
            expires_at_height,
            proof_root,
        };
        voucher.validate()?;
        Ok(voucher)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "rebate_voucher",
            "voucher_id": self.voucher_id,
            "lane": self.lane.as_str(),
            "beneficiary_commitment": self.beneficiary_commitment,
            "sponsor_commitment": self.sponsor_commitment,
            "fee_asset_id": self.fee_asset_id,
            "rebate_units": self.rebate_units,
            "fee_cap_micro_units": self.fee_cap_micro_units,
            "min_privacy_set_size": self.min_privacy_set_size,
            "status": self.status.as_str(),
            "issued_at_height": self.issued_at_height,
            "expires_at_height": self.expires_at_height,
            "rebate_proof_scheme": PRIVATE_GAS_FUTURES_REBATE_PROOF_SCHEME,
            "proof_root": self.proof_root,
        })
    }

    pub fn state_root(&self) -> String {
        private_gas_futures_payload_root("PRIVATE-GAS-REBATE-VOUCHER", &self.public_record())
    }

    pub fn validate(&self) -> PrivateGasFuturesResult<()> {
        ensure_non_empty(&self.voucher_id, "voucher id")?;
        ensure_non_empty(&self.beneficiary_commitment, "beneficiary commitment")?;
        ensure_non_empty(&self.sponsor_commitment, "sponsor commitment")?;
        ensure_non_empty(&self.fee_asset_id, "fee asset id")?;
        ensure_positive(self.rebate_units, "rebate units")?;
        ensure_positive(self.fee_cap_micro_units, "fee cap micro units")?;
        ensure_positive(self.min_privacy_set_size, "min privacy set size")?;
        ensure_height_window(
            self.issued_at_height,
            self.expires_at_height,
            "rebate expiry",
        )?;
        ensure_non_empty(&self.proof_root, "rebate proof root")?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GasSettlementReceipt {
    pub receipt_id: String,
    pub contract_id: String,
    pub cycle_id: String,
    pub lane: GasFuturesLane,
    pub settlement_micro_fee: u64,
    pub pnl_micro_units: i64,
    pub rebate_units: u64,
    pub settled_at_height: u64,
    pub da_certificate_root: String,
    pub pq_witness_root: String,
    pub public_record_root: String,
}

impl GasSettlementReceipt {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        contract_id: &str,
        cycle_id: &str,
        lane: GasFuturesLane,
        settlement_micro_fee: u64,
        pnl_micro_units: i64,
        rebate_units: u64,
        settled_at_height: u64,
        da_certificate_root: &str,
        pq_witness_root: &str,
        public_record: &Value,
    ) -> PrivateGasFuturesResult<Self> {
        let public_record_root =
            private_gas_futures_payload_root("PRIVATE-GAS-SETTLEMENT-PUBLIC-RECORD", public_record);
        let receipt_id = gas_settlement_receipt_id(
            contract_id,
            cycle_id,
            lane,
            settled_at_height,
            &public_record_root,
        );
        let receipt = Self {
            receipt_id,
            contract_id: contract_id.to_string(),
            cycle_id: cycle_id.to_string(),
            lane,
            settlement_micro_fee,
            pnl_micro_units,
            rebate_units,
            settled_at_height,
            da_certificate_root: da_certificate_root.to_string(),
            pq_witness_root: pq_witness_root.to_string(),
            public_record_root,
        };
        receipt.validate()?;
        Ok(receipt)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "gas_settlement_receipt",
            "receipt_id": self.receipt_id,
            "contract_id": self.contract_id,
            "cycle_id": self.cycle_id,
            "lane": self.lane.as_str(),
            "settlement_micro_fee": self.settlement_micro_fee,
            "pnl_micro_units": self.pnl_micro_units,
            "rebate_units": self.rebate_units,
            "settled_at_height": self.settled_at_height,
            "da_certificate_root": self.da_certificate_root,
            "pq_witness_root": self.pq_witness_root,
            "public_record_root": self.public_record_root,
        })
    }

    pub fn state_root(&self) -> String {
        private_gas_futures_payload_root("PRIVATE-GAS-SETTLEMENT-RECEIPT", &self.public_record())
    }

    pub fn validate(&self) -> PrivateGasFuturesResult<()> {
        ensure_non_empty(&self.receipt_id, "receipt id")?;
        ensure_non_empty(&self.contract_id, "contract id")?;
        ensure_non_empty(&self.cycle_id, "cycle id")?;
        ensure_positive(self.settlement_micro_fee, "settlement micro fee")?;
        ensure_non_empty(&self.da_certificate_root, "da certificate root")?;
        ensure_non_empty(&self.pq_witness_root, "pq witness root")?;
        ensure_non_empty(&self.public_record_root, "public record root")?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LaneRiskBand {
    pub lane: GasFuturesLane,
    pub risk_band_id: String,
    pub max_open_notional_units: u64,
    pub max_net_exposure_micro_units: u64,
    pub margin_multiplier_bps: u64,
    pub rebate_multiplier_bps: u64,
    pub updated_at_height: u64,
    pub policy_root: String,
}

impl LaneRiskBand {
    pub fn new(
        lane: GasFuturesLane,
        max_open_notional_units: u64,
        max_net_exposure_micro_units: u64,
        margin_multiplier_bps: u64,
        rebate_multiplier_bps: u64,
        updated_at_height: u64,
        policy: &Value,
    ) -> PrivateGasFuturesResult<Self> {
        let policy_root = private_gas_futures_payload_root("PRIVATE-GAS-RISK-BAND-POLICY", policy);
        let risk_band_id = lane_risk_band_id(lane, updated_at_height, &policy_root);
        let band = Self {
            lane,
            risk_band_id,
            max_open_notional_units,
            max_net_exposure_micro_units,
            margin_multiplier_bps,
            rebate_multiplier_bps,
            updated_at_height,
            policy_root,
        };
        band.validate()?;
        Ok(band)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "lane_risk_band",
            "lane": self.lane.as_str(),
            "risk_band_id": self.risk_band_id,
            "max_open_notional_units": self.max_open_notional_units,
            "max_net_exposure_micro_units": self.max_net_exposure_micro_units,
            "margin_multiplier_bps": self.margin_multiplier_bps,
            "rebate_multiplier_bps": self.rebate_multiplier_bps,
            "updated_at_height": self.updated_at_height,
            "policy_root": self.policy_root,
        })
    }

    pub fn state_root(&self) -> String {
        private_gas_futures_payload_root("PRIVATE-GAS-RISK-BAND", &self.public_record())
    }

    pub fn validate(&self) -> PrivateGasFuturesResult<()> {
        ensure_non_empty(&self.risk_band_id, "risk band id")?;
        ensure_positive(self.max_open_notional_units, "max open notional")?;
        ensure_positive(
            self.max_net_exposure_micro_units,
            "max net exposure micro units",
        )?;
        ensure_bps(self.margin_multiplier_bps, "margin multiplier")?;
        ensure_bps(self.rebate_multiplier_bps, "rebate multiplier")?;
        ensure_non_empty(&self.policy_root, "policy root")?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateGasFuturesRoots {
    pub config_root: String,
    pub observation_root: String,
    pub margin_account_root: String,
    pub hedge_order_root: String,
    pub contract_root: String,
    pub auction_root: String,
    pub netting_cycle_root: String,
    pub rebate_voucher_root: String,
    pub settlement_receipt_root: String,
    pub lane_risk_band_root: String,
    pub active_lane_root: String,
    pub public_record_root: String,
}

impl PrivateGasFuturesRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_gas_futures_roots",
            "config_root": self.config_root,
            "observation_root": self.observation_root,
            "margin_account_root": self.margin_account_root,
            "hedge_order_root": self.hedge_order_root,
            "contract_root": self.contract_root,
            "auction_root": self.auction_root,
            "netting_cycle_root": self.netting_cycle_root,
            "rebate_voucher_root": self.rebate_voucher_root,
            "settlement_receipt_root": self.settlement_receipt_root,
            "lane_risk_band_root": self.lane_risk_band_root,
            "active_lane_root": self.active_lane_root,
            "public_record_root": self.public_record_root,
        })
    }

    pub fn roots_root(&self) -> String {
        private_gas_futures_payload_root("PRIVATE-GAS-FUTURES-ROOTS", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateGasFuturesCounters {
    pub observation_count: u64,
    pub margin_account_count: u64,
    pub healthy_margin_account_count: u64,
    pub hedge_order_count: u64,
    pub open_hedge_order_count: u64,
    pub contract_count: u64,
    pub live_contract_count: u64,
    pub auction_count: u64,
    pub live_auction_count: u64,
    pub netting_cycle_count: u64,
    pub open_netting_cycle_count: u64,
    pub rebate_voucher_count: u64,
    pub redeemable_voucher_count: u64,
    pub settlement_receipt_count: u64,
    pub lane_risk_band_count: u64,
    pub total_open_notional_units: u64,
    pub total_locked_margin_units: u64,
}

impl PrivateGasFuturesCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_gas_futures_counters",
            "observation_count": self.observation_count,
            "margin_account_count": self.margin_account_count,
            "healthy_margin_account_count": self.healthy_margin_account_count,
            "hedge_order_count": self.hedge_order_count,
            "open_hedge_order_count": self.open_hedge_order_count,
            "contract_count": self.contract_count,
            "live_contract_count": self.live_contract_count,
            "auction_count": self.auction_count,
            "live_auction_count": self.live_auction_count,
            "netting_cycle_count": self.netting_cycle_count,
            "open_netting_cycle_count": self.open_netting_cycle_count,
            "rebate_voucher_count": self.rebate_voucher_count,
            "redeemable_voucher_count": self.redeemable_voucher_count,
            "settlement_receipt_count": self.settlement_receipt_count,
            "lane_risk_band_count": self.lane_risk_band_count,
            "total_open_notional_units": self.total_open_notional_units,
            "total_locked_margin_units": self.total_locked_margin_units,
        })
    }

    pub fn counters_root(&self) -> String {
        private_gas_futures_payload_root("PRIVATE-GAS-FUTURES-COUNTERS", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateGasFuturesState {
    pub config: PrivateGasFuturesConfig,
    pub height: u64,
    pub observations: Vec<GasIndexObservation>,
    pub margin_accounts: Vec<MarginAccount>,
    pub hedge_orders: Vec<PrivateHedgeOrder>,
    pub contracts: Vec<PrivateGasFutureContract>,
    pub auctions: Vec<PrivateGasAuction>,
    pub netting_cycles: Vec<GasNettingCycle>,
    pub rebate_vouchers: Vec<RebateVoucher>,
    pub settlement_receipts: Vec<GasSettlementReceipt>,
    pub lane_risk_bands: Vec<LaneRiskBand>,
}

impl PrivateGasFuturesState {
    pub fn new(config: PrivateGasFuturesConfig) -> PrivateGasFuturesResult<Self> {
        config.validate()?;
        Ok(Self {
            config,
            height: 0,
            observations: Vec::new(),
            margin_accounts: Vec::new(),
            hedge_orders: Vec::new(),
            contracts: Vec::new(),
            auctions: Vec::new(),
            netting_cycles: Vec::new(),
            rebate_vouchers: Vec::new(),
            settlement_receipts: Vec::new(),
            lane_risk_bands: Vec::new(),
        })
    }

    pub fn devnet() -> PrivateGasFuturesResult<Self> {
        let config = PrivateGasFuturesConfig::devnet();
        let mut state = Self::new(config)?;
        state.height = PRIVATE_GAS_FUTURES_DEFAULT_HEIGHT;
        let height = state.height;

        let buyer_margin = MarginAccount::new(
            "gas-futures-buyer-commitment-devnet",
            &state.config.fee_asset_id,
            50_000,
            250_000,
            state.config.min_privacy_set_size,
            state.config.min_pq_security_bits,
            &json!({"fixture": "buyer_margin", "scheme": PRIVATE_GAS_FUTURES_MARGIN_PROOF_SCHEME}),
            height,
        )?;
        let seller_margin = MarginAccount::new(
            "gas-futures-seller-commitment-devnet",
            &state.config.fee_asset_id,
            75_000,
            375_000,
            state.config.min_privacy_set_size,
            state.config.min_pq_security_bits,
            &json!({"fixture": "seller_margin", "scheme": PRIVATE_GAS_FUTURES_MARGIN_PROOF_SCHEME}),
            height,
        )?;
        let buyer_margin_id = buyer_margin.margin_account_id.clone();
        let seller_margin_id = seller_margin.margin_account_id.clone();
        state.margin_accounts.push(buyer_margin);
        state.margin_accounts.push(seller_margin);

        for lane in [
            GasFuturesLane::PrivateTransfer,
            GasFuturesLane::MoneroBridge,
            GasFuturesLane::PrivateDefiSwap,
            GasFuturesLane::ContractCall,
            GasFuturesLane::ProofSubmission,
            GasFuturesLane::WalletRecovery,
            GasFuturesLane::EmergencyExit,
        ] {
            state.observations.push(GasIndexObservation::new(
                lane,
                GasOracleSource::SequencerTelemetry,
                lane.default_target_micro_fee().saturating_add(150),
                lane.default_target_micro_fee(),
                1_200,
                650,
                32,
                lane.default_privacy_floor(),
                height,
                height + state.config.quote_ttl_blocks,
                &json!({"fixture": "devnet_index", "lane": lane.as_str()}),
            )?);
            state.lane_risk_bands.push(LaneRiskBand::new(
                lane,
                2_500_000,
                500_000,
                state.config.margin_ratio_bps,
                state.config.rebate_floor_bps,
                height,
                &json!({"fixture": "risk_band", "lane": lane.as_str(), "weight": lane.default_weight()}),
            )?);
        }

        let order = PrivateHedgeOrder::new(
            GasFuturesLane::PrivateDefiSwap,
            "gas-futures-seller-commitment-devnet",
            &seller_margin_id,
            HedgeSide::SponsorShort,
            1_100,
            2_000,
            20_000,
            250,
            height,
            height + state.config.quote_ttl_blocks,
            &json!({"fixture": "seller_order", "scheme": PRIVATE_GAS_FUTURES_PQ_AUTH_SCHEME}),
            &json!({"private_terms": "sealed"}),
        )?;
        let order_id = order.order_id.clone();
        state.hedge_orders.push(order);

        let mut contract = PrivateGasFutureContract::new(
            GasFuturesLane::PrivateDefiSwap,
            "gas-futures-buyer-commitment-devnet",
            "gas-futures-seller-commitment-devnet",
            &buyer_margin_id,
            &seller_margin_id,
            20_000,
            1_400,
            2_200,
            210,
            HedgeSide::FeePayerLong,
            height,
            height + 48,
            height + state.config.contract_ttl_blocks,
            &json!({"fixture": "matched_contract", "scheme": PRIVATE_GAS_FUTURES_PQ_AUTH_SCHEME}),
            &json!({"nullifier": "devnet-private-gas-contract-nullifier"}),
            &json!({"execution": "private_defi_swap"}),
        )?;
        contract.matched_order_id = order_id;
        state.contracts.push(contract);

        let auction = PrivateGasAuction::new(
            GasFuturesLane::MoneroBridge,
            &private_gas_futures_payload_root("PRIVATE-GAS-AUCTION-COMMITS", &json!({"count": 4})),
            &private_gas_futures_payload_root("PRIVATE-GAS-AUCTION-REVEALS", &json!({"count": 0})),
            GasFuturesLane::MoneroBridge.default_target_micro_fee(),
            40_000,
            state.config.min_privacy_set_size,
            height,
            height + 4,
            height + 10,
            &json!({"fixture": "monero_bridge_clearing"}),
        )?;
        state.auctions.push(auction);

        let contract_root = gas_contract_collection_root(&state.contracts);
        let rebate = RebateVoucher::new(
            GasFuturesLane::PrivateDefiSwap,
            "gas-futures-buyer-commitment-devnet",
            "gas-futures-sponsor-commitment-devnet",
            &state.config.fee_asset_id,
            14,
            1_000,
            state.config.min_privacy_set_size,
            height,
            height + state.config.contract_ttl_blocks,
            &json!({"fixture": "low_fee_rebate", "scheme": PRIVATE_GAS_FUTURES_REBATE_PROOF_SCHEME}),
        )?;
        state.rebate_vouchers.push(rebate);
        let rebate_root = rebate_voucher_collection_root(&state.rebate_vouchers);

        let cycle = GasNettingCycle::new(
            GasFuturesLane::PrivateDefiSwap,
            height,
            height + state.config.netting_interval_blocks,
            height + state.config.netting_interval_blocks + 3,
            height + state.config.netting_interval_blocks + 8,
            &contract_root,
            &private_gas_futures_payload_root(
                "PRIVATE-GAS-MARGIN-DELTAS",
                &json!({"fixture": "devnet"}),
            ),
            &rebate_root,
            &json!({"fixture": "netting_proof", "scheme": PRIVATE_GAS_FUTURES_NETTING_PROOF_SCHEME}),
            20_000,
            20_000,
            0,
        )?;
        state.netting_cycles.push(cycle);

        state.validate()?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) -> PrivateGasFuturesResult<String> {
        if height < self.height {
            return Err("private gas futures height cannot move backwards".to_string());
        }
        self.height = height;
        for observation in &mut self.observations {
            if observation.expires_at_height < height {
                observation.expires_at_height = height;
            }
        }
        for order in &mut self.hedge_orders {
            if order.status.matchable() && order.expires_at_height < height {
                order.status = HedgeOrderStatus::Expired;
            }
        }
        for contract in &mut self.contracts {
            if contract.status.live() && contract.expires_at_height < height {
                contract.status = GasFutureStatus::Expired;
            }
        }
        for auction in &mut self.auctions {
            if auction.status == GasAuctionStatus::CommitOpen
                && height >= auction.reveal_opens_at_height
            {
                auction.status = GasAuctionStatus::RevealOpen;
            }
            if auction.status.live() && height > auction.closes_at_height {
                auction.status = GasAuctionStatus::Expired;
            }
        }
        for cycle in &mut self.netting_cycles {
            if cycle.status == NettingCycleStatus::Open && height >= cycle.locks_at_height {
                cycle.status = NettingCycleStatus::Locked;
            }
            if cycle.status == NettingCycleStatus::Locked && height >= cycle.proves_at_height {
                cycle.status = NettingCycleStatus::Proved;
            }
        }
        for voucher in &mut self.rebate_vouchers {
            if voucher.status.redeemable() && voucher.expires_at_height < height {
                voucher.status = RebateVoucherStatus::Expired;
            }
        }
        self.validate()
    }

    pub fn insert_observation(
        &mut self,
        observation: GasIndexObservation,
    ) -> PrivateGasFuturesResult<String> {
        observation.validate()?;
        if self
            .observations
            .iter()
            .any(|candidate| candidate.observation_id == observation.observation_id)
        {
            return Err("duplicate gas index observation".to_string());
        }
        let id = observation.observation_id.clone();
        self.observations.push(observation);
        self.validate()?;
        Ok(id)
    }

    pub fn insert_hedge_order(
        &mut self,
        order: PrivateHedgeOrder,
    ) -> PrivateGasFuturesResult<String> {
        order.validate()?;
        if !self
            .margin_accounts
            .iter()
            .any(|account| account.margin_account_id == order.margin_account_id)
        {
            return Err("hedge order references unknown margin account".to_string());
        }
        let id = order.order_id.clone();
        self.hedge_orders.push(order);
        self.validate()?;
        Ok(id)
    }

    pub fn open_contract(
        &mut self,
        contract: PrivateGasFutureContract,
    ) -> PrivateGasFuturesResult<String> {
        contract.validate()?;
        if !self
            .margin_accounts
            .iter()
            .any(|account| account.margin_account_id == contract.buyer_margin_account_id)
        {
            return Err("contract references unknown buyer margin account".to_string());
        }
        if !self
            .margin_accounts
            .iter()
            .any(|account| account.margin_account_id == contract.seller_margin_account_id)
        {
            return Err("contract references unknown seller margin account".to_string());
        }
        let id = contract.contract_id.clone();
        self.contracts.push(contract);
        self.validate()?;
        Ok(id)
    }

    pub fn active_lane_map(&self) -> BTreeMap<String, u64> {
        let mut lanes = BTreeMap::new();
        for contract in self
            .contracts
            .iter()
            .filter(|contract| contract.status.live())
        {
            let entry = lanes
                .entry(contract.lane.as_str().to_string())
                .or_insert(0_u64);
            *entry = entry.saturating_add(contract.notional_gas_units);
        }
        lanes
    }

    pub fn active_contract_ids(&self) -> Vec<String> {
        self.contracts
            .iter()
            .filter(|contract| contract.status.live())
            .map(|contract| contract.contract_id.clone())
            .collect()
    }

    pub fn margin_account_ids(&self) -> BTreeSet<String> {
        self.margin_accounts
            .iter()
            .map(|account| account.margin_account_id.clone())
            .collect()
    }

    pub fn roots(&self) -> PrivateGasFuturesRoots {
        let public_record_without_root = self.public_record_without_state_root();
        PrivateGasFuturesRoots {
            config_root: self.config.config_root(),
            observation_root: gas_observation_collection_root(&self.observations),
            margin_account_root: margin_account_collection_root(&self.margin_accounts),
            hedge_order_root: hedge_order_collection_root(&self.hedge_orders),
            contract_root: gas_contract_collection_root(&self.contracts),
            auction_root: gas_auction_collection_root(&self.auctions),
            netting_cycle_root: netting_cycle_collection_root(&self.netting_cycles),
            rebate_voucher_root: rebate_voucher_collection_root(&self.rebate_vouchers),
            settlement_receipt_root: settlement_receipt_collection_root(&self.settlement_receipts),
            lane_risk_band_root: lane_risk_band_collection_root(&self.lane_risk_bands),
            active_lane_root: private_gas_futures_payload_root(
                "PRIVATE-GAS-ACTIVE-LANES",
                &json!(self.active_lane_map()),
            ),
            public_record_root: private_gas_futures_payload_root(
                "PRIVATE-GAS-PUBLIC-RECORD-WITHOUT-ROOT",
                &public_record_without_root,
            ),
        }
    }

    pub fn counters(&self) -> PrivateGasFuturesCounters {
        PrivateGasFuturesCounters {
            observation_count: self.observations.len() as u64,
            margin_account_count: self.margin_accounts.len() as u64,
            healthy_margin_account_count: self
                .margin_accounts
                .iter()
                .filter(|account| account.status.usable())
                .count() as u64,
            hedge_order_count: self.hedge_orders.len() as u64,
            open_hedge_order_count: self
                .hedge_orders
                .iter()
                .filter(|order| order.status.matchable())
                .count() as u64,
            contract_count: self.contracts.len() as u64,
            live_contract_count: self
                .contracts
                .iter()
                .filter(|contract| contract.status.live())
                .count() as u64,
            auction_count: self.auctions.len() as u64,
            live_auction_count: self
                .auctions
                .iter()
                .filter(|auction| auction.status.live())
                .count() as u64,
            netting_cycle_count: self.netting_cycles.len() as u64,
            open_netting_cycle_count: self
                .netting_cycles
                .iter()
                .filter(|cycle| cycle.status.accepts_contracts())
                .count() as u64,
            rebate_voucher_count: self.rebate_vouchers.len() as u64,
            redeemable_voucher_count: self
                .rebate_vouchers
                .iter()
                .filter(|voucher| voucher.status.redeemable())
                .count() as u64,
            settlement_receipt_count: self.settlement_receipts.len() as u64,
            lane_risk_band_count: self.lane_risk_bands.len() as u64,
            total_open_notional_units: self
                .contracts
                .iter()
                .filter(|contract| contract.status.live())
                .map(|contract| contract.notional_gas_units)
                .sum(),
            total_locked_margin_units: self
                .margin_accounts
                .iter()
                .map(|account| account.locked_margin_units)
                .sum(),
        }
    }

    pub fn public_record_without_state_root(&self) -> Value {
        let roots = self.roots();
        let counters = self.counters();
        json!({
            "kind": "private_gas_futures_state",
            "protocol_version": PRIVATE_GAS_FUTURES_PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "height": self.height,
            "config": self.config.public_record(),
            "roots": roots.public_record(),
            "counters": counters.public_record(),
            "active_lane_map": self.active_lane_map(),
            "active_contract_ids": self.active_contract_ids(),
        })
    }

    pub fn state_root(&self) -> String {
        private_gas_futures_payload_root(
            "PRIVATE-GAS-FUTURES-STATE",
            &self.public_record_without_state_root(),
        )
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        if let Value::Object(ref mut object) = record {
            object.insert("state_root".to_string(), json!(self.state_root()));
        }
        record
    }

    pub fn validate(&self) -> PrivateGasFuturesResult<String> {
        self.config.validate()?;
        for observation in &self.observations {
            observation.validate()?;
            if observation.privacy_set_size < self.config.min_privacy_set_size {
                return Err("gas observation privacy set below configured floor".to_string());
            }
        }
        for account in &self.margin_accounts {
            account.validate()?;
            if account.pq_security_bits < self.config.min_pq_security_bits {
                return Err("margin account pq security below configured floor".to_string());
            }
            if account.privacy_set_size < self.config.min_privacy_set_size {
                return Err("margin account privacy set below configured floor".to_string());
            }
        }
        let margin_ids = self.margin_account_ids();
        for order in &self.hedge_orders {
            order.validate()?;
            if !margin_ids.contains(&order.margin_account_id) {
                return Err("hedge order references unknown margin account".to_string());
            }
        }
        for contract in &self.contracts {
            contract.validate()?;
            if !margin_ids.contains(&contract.buyer_margin_account_id) {
                return Err("contract references unknown buyer margin account".to_string());
            }
            if !margin_ids.contains(&contract.seller_margin_account_id) {
                return Err("contract references unknown seller margin account".to_string());
            }
            if contract.status.live() && contract.expires_at_height < self.height {
                return Err("live gas future expired before state height".to_string());
            }
        }
        for auction in &self.auctions {
            auction.validate()?;
            if auction.min_privacy_set_size < self.config.min_privacy_set_size {
                return Err("auction privacy set below configured floor".to_string());
            }
        }
        for cycle in &self.netting_cycles {
            cycle.validate()?;
        }
        for voucher in &self.rebate_vouchers {
            voucher.validate()?;
            if voucher.min_privacy_set_size < self.config.min_privacy_set_size {
                return Err("rebate voucher privacy set below configured floor".to_string());
            }
        }
        for receipt in &self.settlement_receipts {
            receipt.validate()?;
        }
        for band in &self.lane_risk_bands {
            band.validate()?;
        }
        ensure_unique(
            self.observations
                .iter()
                .map(|item| item.observation_id.as_str()),
            "gas index observation ids",
        )?;
        ensure_unique(
            self.margin_accounts
                .iter()
                .map(|item| item.margin_account_id.as_str()),
            "margin account ids",
        )?;
        ensure_unique(
            self.hedge_orders.iter().map(|item| item.order_id.as_str()),
            "hedge order ids",
        )?;
        ensure_unique(
            self.contracts.iter().map(|item| item.contract_id.as_str()),
            "gas future contract ids",
        )?;
        ensure_unique(
            self.auctions.iter().map(|item| item.auction_id.as_str()),
            "gas auction ids",
        )?;
        ensure_unique(
            self.netting_cycles
                .iter()
                .map(|item| item.cycle_id.as_str()),
            "netting cycle ids",
        )?;
        ensure_unique(
            self.rebate_vouchers
                .iter()
                .map(|item| item.voucher_id.as_str()),
            "rebate voucher ids",
        )?;
        Ok(self.state_root())
    }
}

pub fn private_gas_futures_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(domain, &[HashPart::Json(payload)], 32)
}

pub fn gas_index_observation_id(
    lane: GasFuturesLane,
    source: GasOracleSource,
    observed_micro_fee: u64,
    observed_at_height: u64,
    evidence_root: &str,
) -> String {
    domain_hash(
        "PRIVATE-GAS-INDEX-OBSERVATION-ID",
        &[
            HashPart::Str(lane.as_str()),
            HashPart::Str(source.as_str()),
            HashPart::Int(observed_micro_fee as i128),
            HashPart::Int(observed_at_height as i128),
            HashPart::Str(evidence_root),
        ],
        32,
    )
}

pub fn margin_account_id(
    owner_commitment: &str,
    fee_asset_id: &str,
    height: u64,
    margin_proof_root: &str,
) -> String {
    domain_hash(
        "PRIVATE-GAS-MARGIN-ACCOUNT-ID",
        &[
            HashPart::Str(owner_commitment),
            HashPart::Str(fee_asset_id),
            HashPart::Int(height as i128),
            HashPart::Str(margin_proof_root),
        ],
        32,
    )
}

pub fn gas_future_contract_id(
    lane: GasFuturesLane,
    buyer_commitment: &str,
    seller_commitment: &str,
    strike_micro_fee: u64,
    maturity_height: u64,
    privacy_nullifier_root: &str,
) -> String {
    domain_hash(
        "PRIVATE-GAS-FUTURE-CONTRACT-ID",
        &[
            HashPart::Str(lane.as_str()),
            HashPart::Str(buyer_commitment),
            HashPart::Str(seller_commitment),
            HashPart::Int(strike_micro_fee as i128),
            HashPart::Int(maturity_height as i128),
            HashPart::Str(privacy_nullifier_root),
        ],
        32,
    )
}

pub fn hedge_order_id(
    lane: GasFuturesLane,
    maker_commitment: &str,
    margin_account_id: &str,
    side: HedgeSide,
    posted_at_height: u64,
    private_terms_root: &str,
) -> String {
    domain_hash(
        "PRIVATE-GAS-HEDGE-ORDER-ID",
        &[
            HashPart::Str(lane.as_str()),
            HashPart::Str(maker_commitment),
            HashPart::Str(margin_account_id),
            HashPart::Str(side.as_str()),
            HashPart::Int(posted_at_height as i128),
            HashPart::Str(private_terms_root),
        ],
        32,
    )
}

pub fn gas_auction_id(
    lane: GasFuturesLane,
    opened_at_height: u64,
    commit_root: &str,
    clearing_proof_root: &str,
) -> String {
    domain_hash(
        "PRIVATE-GAS-AUCTION-ID",
        &[
            HashPart::Str(lane.as_str()),
            HashPart::Int(opened_at_height as i128),
            HashPart::Str(commit_root),
            HashPart::Str(clearing_proof_root),
        ],
        32,
    )
}

pub fn netting_cycle_id(
    lane: GasFuturesLane,
    opened_at_height: u64,
    contract_root: &str,
    netting_proof_root: &str,
) -> String {
    domain_hash(
        "PRIVATE-GAS-NETTING-CYCLE-ID",
        &[
            HashPart::Str(lane.as_str()),
            HashPart::Int(opened_at_height as i128),
            HashPart::Str(contract_root),
            HashPart::Str(netting_proof_root),
        ],
        32,
    )
}

pub fn rebate_voucher_id(
    lane: GasFuturesLane,
    beneficiary_commitment: &str,
    sponsor_commitment: &str,
    issued_at_height: u64,
    proof_root: &str,
) -> String {
    domain_hash(
        "PRIVATE-GAS-REBATE-VOUCHER-ID",
        &[
            HashPart::Str(lane.as_str()),
            HashPart::Str(beneficiary_commitment),
            HashPart::Str(sponsor_commitment),
            HashPart::Int(issued_at_height as i128),
            HashPart::Str(proof_root),
        ],
        32,
    )
}

pub fn gas_settlement_receipt_id(
    contract_id: &str,
    cycle_id: &str,
    lane: GasFuturesLane,
    settled_at_height: u64,
    public_record_root: &str,
) -> String {
    domain_hash(
        "PRIVATE-GAS-SETTLEMENT-RECEIPT-ID",
        &[
            HashPart::Str(contract_id),
            HashPart::Str(cycle_id),
            HashPart::Str(lane.as_str()),
            HashPart::Int(settled_at_height as i128),
            HashPart::Str(public_record_root),
        ],
        32,
    )
}

pub fn lane_risk_band_id(
    lane: GasFuturesLane,
    updated_at_height: u64,
    policy_root: &str,
) -> String {
    domain_hash(
        "PRIVATE-GAS-LANE-RISK-BAND-ID",
        &[
            HashPart::Str(lane.as_str()),
            HashPart::Int(updated_at_height as i128),
            HashPart::Str(policy_root),
        ],
        32,
    )
}

pub fn gas_observation_collection_root(observations: &[GasIndexObservation]) -> String {
    collection_root(
        "PRIVATE-GAS-OBSERVATION-COLLECTION",
        observations
            .iter()
            .map(GasIndexObservation::public_record)
            .collect(),
    )
}

pub fn margin_account_collection_root(accounts: &[MarginAccount]) -> String {
    collection_root(
        "PRIVATE-GAS-MARGIN-ACCOUNT-COLLECTION",
        accounts.iter().map(MarginAccount::public_record).collect(),
    )
}

pub fn hedge_order_collection_root(orders: &[PrivateHedgeOrder]) -> String {
    collection_root(
        "PRIVATE-GAS-HEDGE-ORDER-COLLECTION",
        orders
            .iter()
            .map(PrivateHedgeOrder::public_record)
            .collect(),
    )
}

pub fn gas_contract_collection_root(contracts: &[PrivateGasFutureContract]) -> String {
    collection_root(
        "PRIVATE-GAS-CONTRACT-COLLECTION",
        contracts
            .iter()
            .map(PrivateGasFutureContract::public_record)
            .collect(),
    )
}

pub fn gas_auction_collection_root(auctions: &[PrivateGasAuction]) -> String {
    collection_root(
        "PRIVATE-GAS-AUCTION-COLLECTION",
        auctions
            .iter()
            .map(PrivateGasAuction::public_record)
            .collect(),
    )
}

pub fn netting_cycle_collection_root(cycles: &[GasNettingCycle]) -> String {
    collection_root(
        "PRIVATE-GAS-NETTING-CYCLE-COLLECTION",
        cycles.iter().map(GasNettingCycle::public_record).collect(),
    )
}

pub fn rebate_voucher_collection_root(vouchers: &[RebateVoucher]) -> String {
    collection_root(
        "PRIVATE-GAS-REBATE-VOUCHER-COLLECTION",
        vouchers.iter().map(RebateVoucher::public_record).collect(),
    )
}

pub fn settlement_receipt_collection_root(receipts: &[GasSettlementReceipt]) -> String {
    collection_root(
        "PRIVATE-GAS-SETTLEMENT-RECEIPT-COLLECTION",
        receipts
            .iter()
            .map(GasSettlementReceipt::public_record)
            .collect(),
    )
}

pub fn lane_risk_band_collection_root(bands: &[LaneRiskBand]) -> String {
    collection_root(
        "PRIVATE-GAS-LANE-RISK-BAND-COLLECTION",
        bands.iter().map(LaneRiskBand::public_record).collect(),
    )
}

fn collection_root(domain: &str, records: Vec<Value>) -> String {
    merkle_root(domain, &records)
}

fn ensure_non_empty(value: &str, label: &str) -> PrivateGasFuturesResult<()> {
    if value.trim().is_empty() {
        return Err(format!("{label} cannot be empty"));
    }
    Ok(())
}

fn ensure_positive(value: u64, label: &str) -> PrivateGasFuturesResult<()> {
    if value == 0 {
        return Err(format!("{label} must be positive"));
    }
    Ok(())
}

fn ensure_bps(value: u64, label: &str) -> PrivateGasFuturesResult<()> {
    if value > PRIVATE_GAS_FUTURES_MAX_BPS {
        return Err(format!("{label} exceeds basis-point maximum"));
    }
    Ok(())
}

fn ensure_height_window(start: u64, end: u64, label: &str) -> PrivateGasFuturesResult<()> {
    if end <= start {
        return Err(format!("{label} height window is inverted"));
    }
    Ok(())
}

fn ensure_unique<'a, I>(items: I, label: &str) -> PrivateGasFuturesResult<()>
where
    I: IntoIterator<Item = &'a str>,
{
    let mut seen = BTreeSet::new();
    for item in items {
        if !seen.insert(item.to_string()) {
            return Err(format!("{label} contains duplicate value {item}"));
        }
    }
    Ok(())
}
