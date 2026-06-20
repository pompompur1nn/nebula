use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateDefiMarginHealthOrchestratorResult<T> = Result<T, String>;

pub const PRIVATE_DEFI_MARGIN_HEALTH_ORCHESTRATOR_PROTOCOL_VERSION: &str =
    "nebula-private-defi-margin-health-orchestrator-v1";
pub const PRIVATE_DEFI_MARGIN_HEALTH_ORCHESTRATOR_DEFAULT_MIN_HEALTH_BPS: u64 = 11_500;
pub const PRIVATE_DEFI_MARGIN_HEALTH_ORCHESTRATOR_DEFAULT_LIQUIDATION_BPS: u64 = 10_500;
pub const PRIVATE_DEFI_MARGIN_HEALTH_ORCHESTRATOR_DEFAULT_TARGET_BUFFER_BPS: u64 = 2_000;
pub const PRIVATE_DEFI_MARGIN_HEALTH_ORCHESTRATOR_DEFAULT_MAX_ORACLE_AGE_BLOCKS: u64 = 8;
pub const PRIVATE_DEFI_MARGIN_HEALTH_ORCHESTRATOR_DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 128;
pub const PRIVATE_DEFI_MARGIN_HEALTH_ORCHESTRATOR_DEFAULT_REMEDIATION_TTL_BLOCKS: u64 = 32;
pub const PRIVATE_DEFI_MARGIN_HEALTH_ORCHESTRATOR_MAX_BPS: u64 = 10_000;
pub const PRIVATE_DEFI_MARGIN_HEALTH_ORCHESTRATOR_MAX_ACCOUNTS: usize = 1_024;
pub const PRIVATE_DEFI_MARGIN_HEALTH_ORCHESTRATOR_MAX_MARKETS: usize = 512;
pub const PRIVATE_DEFI_MARGIN_HEALTH_ORCHESTRATOR_MAX_ORACLES: usize = 512;
pub const PRIVATE_DEFI_MARGIN_HEALTH_ORCHESTRATOR_MAX_REMEDIATIONS: usize = 2_048;
pub const PRIVATE_DEFI_MARGIN_HEALTH_ORCHESTRATOR_DEVNET_HEIGHT: u64 = 74_400;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MarginMarketKind {
    Lending,
    Perpetual,
    StableSwap,
    ConcentratedLiquidity,
    Options,
    TokenizedVault,
}

impl MarginMarketKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Lending => "lending",
            Self::Perpetual => "perpetual",
            Self::StableSwap => "stable_swap",
            Self::ConcentratedLiquidity => "concentrated_liquidity",
            Self::Options => "options",
            Self::TokenizedVault => "tokenized_vault",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MarginBand {
    Healthy,
    Watch,
    ReduceOnly,
    Liquidatable,
    OracleFrozen,
}

impl MarginBand {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Healthy => "healthy",
            Self::Watch => "watch",
            Self::ReduceOnly => "reduce_only",
            Self::Liquidatable => "liquidatable",
            Self::OracleFrozen => "oracle_frozen",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RemediationKind {
    IncreaseCollateral,
    ReduceExposure,
    RouteToPrivateAuction,
    FreezeMarket,
    SponsorProofFee,
    RequestFreshOracle,
}

impl RemediationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::IncreaseCollateral => "increase_collateral",
            Self::ReduceExposure => "reduce_exposure",
            Self::RouteToPrivateAuction => "route_to_private_auction",
            Self::FreezeMarket => "freeze_market",
            Self::SponsorProofFee => "sponsor_proof_fee",
            Self::RequestFreshOracle => "request_fresh_oracle",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub min_health_bps: u64,
    pub liquidation_bps: u64,
    pub target_buffer_bps: u64,
    pub max_oracle_age_blocks: u64,
    pub min_privacy_set_size: u64,
    pub remediation_ttl_blocks: u64,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            min_health_bps: PRIVATE_DEFI_MARGIN_HEALTH_ORCHESTRATOR_DEFAULT_MIN_HEALTH_BPS,
            liquidation_bps: PRIVATE_DEFI_MARGIN_HEALTH_ORCHESTRATOR_DEFAULT_LIQUIDATION_BPS,
            target_buffer_bps: PRIVATE_DEFI_MARGIN_HEALTH_ORCHESTRATOR_DEFAULT_TARGET_BUFFER_BPS,
            max_oracle_age_blocks:
                PRIVATE_DEFI_MARGIN_HEALTH_ORCHESTRATOR_DEFAULT_MAX_ORACLE_AGE_BLOCKS,
            min_privacy_set_size:
                PRIVATE_DEFI_MARGIN_HEALTH_ORCHESTRATOR_DEFAULT_MIN_PRIVACY_SET_SIZE,
            remediation_ttl_blocks:
                PRIVATE_DEFI_MARGIN_HEALTH_ORCHESTRATOR_DEFAULT_REMEDIATION_TTL_BLOCKS,
        }
    }

    pub fn validate(&self) -> PrivateDefiMarginHealthOrchestratorResult<()> {
        if self.liquidation_bps < PRIVATE_DEFI_MARGIN_HEALTH_ORCHESTRATOR_MAX_BPS {
            return Err(
                "liquidation threshold must be at least full collateral coverage".to_string(),
            );
        }
        if self.min_health_bps < self.liquidation_bps {
            return Err("minimum health cannot be below liquidation threshold".to_string());
        }
        if self.target_buffer_bps == 0 {
            return Err("target margin buffer must be positive".to_string());
        }
        if self.max_oracle_age_blocks == 0
            || self.min_privacy_set_size == 0
            || self.remediation_ttl_blocks == 0
        {
            return Err("margin orchestrator windows must be positive".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_defi_margin_health_orchestrator_config",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_DEFI_MARGIN_HEALTH_ORCHESTRATOR_PROTOCOL_VERSION,
            "min_health_bps": self.min_health_bps,
            "liquidation_bps": self.liquidation_bps,
            "target_buffer_bps": self.target_buffer_bps,
            "max_oracle_age_blocks": self.max_oracle_age_blocks,
            "min_privacy_set_size": self.min_privacy_set_size,
            "remediation_ttl_blocks": self.remediation_ttl_blocks,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MarginMarket {
    pub market_id: String,
    pub market_kind: MarginMarketKind,
    pub label: String,
    pub asset_root: String,
    pub oracle_set_root: String,
    pub max_leverage_bps: u64,
    pub maintenance_margin_bps: u64,
    pub private_liquidations_enabled: bool,
}

impl MarginMarket {
    pub fn new(
        market_kind: MarginMarketKind,
        label: &str,
        asset: &Value,
        oracle_set: &Value,
        max_leverage_bps: u64,
        maintenance_margin_bps: u64,
        private_liquidations_enabled: bool,
    ) -> PrivateDefiMarginHealthOrchestratorResult<Self> {
        if label.is_empty() {
            return Err("margin market label cannot be empty".to_string());
        }
        if max_leverage_bps < PRIVATE_DEFI_MARGIN_HEALTH_ORCHESTRATOR_MAX_BPS {
            return Err("margin market max leverage must be at least 1x".to_string());
        }
        if maintenance_margin_bps == 0 {
            return Err("maintenance margin must be positive".to_string());
        }
        let asset_root =
            private_defi_margin_health_payload_root("PRIVATE-DEFI-MARGIN-MARKET-ASSET", asset);
        let oracle_set_root = private_defi_margin_health_payload_root(
            "PRIVATE-DEFI-MARGIN-MARKET-ORACLE-SET",
            oracle_set,
        );
        let market_id = margin_market_id(
            market_kind,
            label,
            &asset_root,
            &oracle_set_root,
            max_leverage_bps,
            maintenance_margin_bps,
        );
        Ok(Self {
            market_id,
            market_kind,
            label: label.to_string(),
            asset_root,
            oracle_set_root,
            max_leverage_bps,
            maintenance_margin_bps,
            private_liquidations_enabled,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_defi_margin_market",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_DEFI_MARGIN_HEALTH_ORCHESTRATOR_PROTOCOL_VERSION,
            "market_id": self.market_id,
            "market_kind": self.market_kind.as_str(),
            "label": self.label,
            "asset_root": self.asset_root,
            "oracle_set_root": self.oracle_set_root,
            "max_leverage_bps": self.max_leverage_bps,
            "maintenance_margin_bps": self.maintenance_margin_bps,
            "private_liquidations_enabled": self.private_liquidations_enabled,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OracleSnapshot {
    pub oracle_snapshot_id: String,
    pub market_id: String,
    pub height: u64,
    pub price_commitment: String,
    pub volatility_bps: u64,
    pub confidence_bps: u64,
    pub signer_root: String,
}

impl OracleSnapshot {
    pub fn new(
        market_id: &str,
        height: u64,
        price_commitment: &str,
        volatility_bps: u64,
        confidence_bps: u64,
        signer: &Value,
    ) -> PrivateDefiMarginHealthOrchestratorResult<Self> {
        if market_id.is_empty() || price_commitment.is_empty() {
            return Err("oracle snapshot identifiers cannot be empty".to_string());
        }
        if confidence_bps > PRIVATE_DEFI_MARGIN_HEALTH_ORCHESTRATOR_MAX_BPS {
            return Err("oracle confidence cannot exceed bps scale".to_string());
        }
        let signer_root =
            private_defi_margin_health_payload_root("PRIVATE-DEFI-MARGIN-ORACLE-SIGNERS", signer);
        let oracle_snapshot_id = oracle_snapshot_id(
            market_id,
            height,
            price_commitment,
            volatility_bps,
            confidence_bps,
            &signer_root,
        );
        Ok(Self {
            oracle_snapshot_id,
            market_id: market_id.to_string(),
            height,
            price_commitment: price_commitment.to_string(),
            volatility_bps,
            confidence_bps,
            signer_root,
        })
    }

    pub fn stale_at(&self, height: u64, config: &Config) -> bool {
        height.saturating_sub(self.height) > config.max_oracle_age_blocks
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_defi_margin_oracle_snapshot",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_DEFI_MARGIN_HEALTH_ORCHESTRATOR_PROTOCOL_VERSION,
            "oracle_snapshot_id": self.oracle_snapshot_id,
            "market_id": self.market_id,
            "height": self.height,
            "price_commitment": self.price_commitment,
            "volatility_bps": self.volatility_bps,
            "confidence_bps": self.confidence_bps,
            "signer_root": self.signer_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MarginAccount {
    pub account_id: String,
    pub account_commitment: String,
    pub market_id: String,
    pub collateral_commitment: String,
    pub debt_commitment: String,
    pub health_factor_bps: u64,
    pub anonymity_set_size: u64,
    pub opened_at_height: u64,
}

impl MarginAccount {
    pub fn new(
        account_commitment: &str,
        market_id: &str,
        collateral_commitment: &str,
        debt_commitment: &str,
        health_factor_bps: u64,
        anonymity_set_size: u64,
        opened_at_height: u64,
    ) -> PrivateDefiMarginHealthOrchestratorResult<Self> {
        if account_commitment.is_empty()
            || market_id.is_empty()
            || collateral_commitment.is_empty()
            || debt_commitment.is_empty()
        {
            return Err("margin account commitments cannot be empty".to_string());
        }
        let account_id = margin_account_id(
            account_commitment,
            market_id,
            collateral_commitment,
            debt_commitment,
            opened_at_height,
        );
        Ok(Self {
            account_id,
            account_commitment: account_commitment.to_string(),
            market_id: market_id.to_string(),
            collateral_commitment: collateral_commitment.to_string(),
            debt_commitment: debt_commitment.to_string(),
            health_factor_bps,
            anonymity_set_size,
            opened_at_height,
        })
    }

    pub fn band(&self, oracle_stale: bool, config: &Config) -> MarginBand {
        if oracle_stale {
            MarginBand::OracleFrozen
        } else if self.health_factor_bps <= config.liquidation_bps {
            MarginBand::Liquidatable
        } else if self.health_factor_bps < config.min_health_bps {
            MarginBand::ReduceOnly
        } else if self.health_factor_bps
            < config
                .min_health_bps
                .saturating_add(config.target_buffer_bps)
        {
            MarginBand::Watch
        } else {
            MarginBand::Healthy
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_defi_margin_account",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_DEFI_MARGIN_HEALTH_ORCHESTRATOR_PROTOCOL_VERSION,
            "account_id": self.account_id,
            "account_commitment": self.account_commitment,
            "market_id": self.market_id,
            "collateral_commitment": self.collateral_commitment,
            "debt_commitment": self.debt_commitment,
            "health_factor_bps": self.health_factor_bps,
            "anonymity_set_size": self.anonymity_set_size,
            "opened_at_height": self.opened_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemediationAction {
    pub action_id: String,
    pub account_id: String,
    pub market_id: String,
    pub remediation_kind: RemediationKind,
    pub priority: u64,
    pub reason_root: String,
    pub expires_at_height: u64,
}

impl RemediationAction {
    pub fn new(
        account_id: &str,
        market_id: &str,
        remediation_kind: RemediationKind,
        priority: u64,
        reason: &Value,
        expires_at_height: u64,
    ) -> PrivateDefiMarginHealthOrchestratorResult<Self> {
        if account_id.is_empty() || market_id.is_empty() {
            return Err("remediation action identifiers cannot be empty".to_string());
        }
        let reason_root = private_defi_margin_health_payload_root(
            "PRIVATE-DEFI-MARGIN-REMEDIATION-REASON",
            reason,
        );
        let action_id = remediation_action_id(
            account_id,
            market_id,
            remediation_kind,
            priority,
            &reason_root,
            expires_at_height,
        );
        Ok(Self {
            action_id,
            account_id: account_id.to_string(),
            market_id: market_id.to_string(),
            remediation_kind,
            priority,
            reason_root,
            expires_at_height,
        })
    }

    pub fn active_at(&self, height: u64) -> bool {
        height <= self.expires_at_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_defi_margin_remediation_action",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_DEFI_MARGIN_HEALTH_ORCHESTRATOR_PROTOCOL_VERSION,
            "action_id": self.action_id,
            "account_id": self.account_id,
            "market_id": self.market_id,
            "remediation_kind": self.remediation_kind.as_str(),
            "priority": self.priority,
            "reason_root": self.reason_root,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roots {
    pub config_root: String,
    pub market_root: String,
    pub oracle_root: String,
    pub account_root: String,
    pub remediation_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "market_root": self.market_root,
            "oracle_root": self.oracle_root,
            "account_root": self.account_root,
            "remediation_root": self.remediation_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    pub market_count: u64,
    pub oracle_snapshot_count: u64,
    pub account_count: u64,
    pub remediation_count: u64,
    pub watch_count: u64,
    pub reduce_only_count: u64,
    pub liquidatable_count: u64,
    pub stale_oracle_market_count: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "market_count": self.market_count,
            "oracle_snapshot_count": self.oracle_snapshot_count,
            "account_count": self.account_count,
            "remediation_count": self.remediation_count,
            "watch_count": self.watch_count,
            "reduce_only_count": self.reduce_only_count,
            "liquidatable_count": self.liquidatable_count,
            "stale_oracle_market_count": self.stale_oracle_market_count,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub height: u64,
    pub config: Config,
    pub markets: BTreeMap<String, MarginMarket>,
    pub oracle_snapshots: BTreeMap<String, OracleSnapshot>,
    pub accounts: BTreeMap<String, MarginAccount>,
    pub remediations: BTreeMap<String, RemediationAction>,
    pub roots: Roots,
    pub counters: Counters,
    pub state_root: String,
}

impl State {
    pub fn new(height: u64, config: Config) -> PrivateDefiMarginHealthOrchestratorResult<Self> {
        config.validate()?;
        let mut state = Self {
            height,
            config,
            markets: BTreeMap::new(),
            oracle_snapshots: BTreeMap::new(),
            accounts: BTreeMap::new(),
            remediations: BTreeMap::new(),
            roots: Roots {
                config_root: String::new(),
                market_root: String::new(),
                oracle_root: String::new(),
                account_root: String::new(),
                remediation_root: String::new(),
            },
            counters: Counters {
                market_count: 0,
                oracle_snapshot_count: 0,
                account_count: 0,
                remediation_count: 0,
                watch_count: 0,
                reduce_only_count: 0,
                liquidatable_count: 0,
                stale_oracle_market_count: 0,
            },
            state_root: String::new(),
        };
        state.refresh();
        Ok(state)
    }

    pub fn insert_market(
        &mut self,
        market: MarginMarket,
    ) -> PrivateDefiMarginHealthOrchestratorResult<()> {
        if self.markets.len() >= PRIVATE_DEFI_MARGIN_HEALTH_ORCHESTRATOR_MAX_MARKETS {
            return Err("margin market limit exceeded".to_string());
        }
        self.markets.insert(market.market_id.clone(), market);
        self.refresh();
        Ok(())
    }

    pub fn insert_oracle_snapshot(
        &mut self,
        oracle: OracleSnapshot,
    ) -> PrivateDefiMarginHealthOrchestratorResult<()> {
        if self.oracle_snapshots.len() >= PRIVATE_DEFI_MARGIN_HEALTH_ORCHESTRATOR_MAX_ORACLES {
            return Err("oracle snapshot limit exceeded".to_string());
        }
        if !self.markets.contains_key(&oracle.market_id) {
            return Err("oracle snapshot references unknown market".to_string());
        }
        self.oracle_snapshots
            .insert(oracle.oracle_snapshot_id.clone(), oracle);
        self.refresh();
        Ok(())
    }

    pub fn insert_account(
        &mut self,
        account: MarginAccount,
    ) -> PrivateDefiMarginHealthOrchestratorResult<()> {
        if self.accounts.len() >= PRIVATE_DEFI_MARGIN_HEALTH_ORCHESTRATOR_MAX_ACCOUNTS {
            return Err("margin account limit exceeded".to_string());
        }
        if !self.markets.contains_key(&account.market_id) {
            return Err("margin account references unknown market".to_string());
        }
        if account.anonymity_set_size < self.config.min_privacy_set_size {
            return Err("margin account anonymity set below configured floor".to_string());
        }
        self.accounts.insert(account.account_id.clone(), account);
        self.refresh();
        Ok(())
    }

    pub fn insert_remediation(
        &mut self,
        remediation: RemediationAction,
    ) -> PrivateDefiMarginHealthOrchestratorResult<()> {
        if self.remediations.len() >= PRIVATE_DEFI_MARGIN_HEALTH_ORCHESTRATOR_MAX_REMEDIATIONS {
            return Err("remediation action limit exceeded".to_string());
        }
        if !self.accounts.contains_key(&remediation.account_id) {
            return Err("remediation references unknown account".to_string());
        }
        if !self.markets.contains_key(&remediation.market_id) {
            return Err("remediation references unknown market".to_string());
        }
        self.remediations
            .insert(remediation.action_id.clone(), remediation);
        self.refresh();
        Ok(())
    }

    pub fn latest_oracle_for_market(&self, market_id: &str) -> Option<&OracleSnapshot> {
        self.oracle_snapshots
            .values()
            .filter(|oracle| oracle.market_id == market_id)
            .max_by_key(|oracle| oracle.height)
    }

    pub fn stale_market_ids(&self) -> BTreeSet<String> {
        self.markets
            .keys()
            .filter(|market_id| {
                self.latest_oracle_for_market(market_id)
                    .map(|oracle| oracle.stale_at(self.height, &self.config))
                    .unwrap_or(true)
            })
            .cloned()
            .collect()
    }

    pub fn account_band(&self, account: &MarginAccount) -> MarginBand {
        let oracle_stale = self
            .latest_oracle_for_market(&account.market_id)
            .map(|oracle| oracle.stale_at(self.height, &self.config))
            .unwrap_or(true);
        account.band(oracle_stale, &self.config)
    }

    pub fn propose_remediations(
        &self,
    ) -> PrivateDefiMarginHealthOrchestratorResult<Vec<RemediationAction>> {
        let mut actions = Vec::new();
        for account in self.accounts.values() {
            let band = self.account_band(account);
            let remediation_kind = match band {
                MarginBand::Healthy => continue,
                MarginBand::Watch => RemediationKind::SponsorProofFee,
                MarginBand::ReduceOnly => RemediationKind::ReduceExposure,
                MarginBand::Liquidatable => RemediationKind::RouteToPrivateAuction,
                MarginBand::OracleFrozen => RemediationKind::RequestFreshOracle,
            };
            let priority = match band {
                MarginBand::OracleFrozen | MarginBand::Liquidatable => 100,
                MarginBand::ReduceOnly => 70,
                MarginBand::Watch => 40,
                MarginBand::Healthy => 0,
            };
            actions.push(RemediationAction::new(
                &account.account_id,
                &account.market_id,
                remediation_kind,
                priority,
                &json!({
                    "band": band.as_str(),
                    "health_factor_bps": account.health_factor_bps,
                    "privacy_set_size": account.anonymity_set_size,
                }),
                self.height
                    .saturating_add(self.config.remediation_ttl_blocks),
            )?);
        }
        Ok(actions)
    }

    pub fn refresh(&mut self) {
        self.roots = Roots {
            config_root: private_defi_margin_health_payload_root(
                "PRIVATE-DEFI-MARGIN-CONFIG",
                &self.config.public_record(),
            ),
            market_root: margin_market_root(&self.markets.values().cloned().collect::<Vec<_>>()),
            oracle_root: oracle_snapshot_root(
                &self.oracle_snapshots.values().cloned().collect::<Vec<_>>(),
            ),
            account_root: margin_account_root(&self.accounts.values().cloned().collect::<Vec<_>>()),
            remediation_root: remediation_action_root(
                &self.remediations.values().cloned().collect::<Vec<_>>(),
            ),
        };
        let bands = self
            .accounts
            .values()
            .map(|account| self.account_band(account))
            .collect::<Vec<_>>();
        self.counters = Counters {
            market_count: self.markets.len() as u64,
            oracle_snapshot_count: self.oracle_snapshots.len() as u64,
            account_count: self.accounts.len() as u64,
            remediation_count: self.remediations.len() as u64,
            watch_count: bands
                .iter()
                .filter(|band| **band == MarginBand::Watch)
                .count() as u64,
            reduce_only_count: bands
                .iter()
                .filter(|band| **band == MarginBand::ReduceOnly)
                .count() as u64,
            liquidatable_count: bands
                .iter()
                .filter(|band| **band == MarginBand::Liquidatable)
                .count() as u64,
            stale_oracle_market_count: self.stale_market_ids().len() as u64,
        };
        self.state_root = root_from_record(&self.public_record_without_state_root());
    }

    fn public_record_without_state_root(&self) -> Value {
        json!({
            "kind": "private_defi_margin_health_orchestrator_state",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_DEFI_MARGIN_HEALTH_ORCHESTRATOR_PROTOCOL_VERSION,
            "height": self.height,
            "roots": self.roots.public_record(),
            "counters": self.counters.public_record(),
            "stale_market_ids": self.stale_market_ids().into_iter().collect::<Vec<_>>(),
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        if let Value::Object(ref mut values) = record {
            values.insert("state_root".to_string(), json!(self.state_root));
        }
        record
    }

    pub fn devnet() -> PrivateDefiMarginHealthOrchestratorResult<Self> {
        let mut state = Self::new(
            PRIVATE_DEFI_MARGIN_HEALTH_ORCHESTRATOR_DEVNET_HEIGHT,
            Config::devnet(),
        )?;
        let market = MarginMarket::new(
            MarginMarketKind::Perpetual,
            "devnet-private-xmr-usd-perp",
            &json!({"base": "wxmr", "quote": "usd-private"}),
            &json!({"oracle_set": ["oracle-a", "oracle-b", "oracle-c"]}),
            30_000,
            1_250,
            true,
        )?;
        state.insert_market(market.clone())?;
        state.insert_oracle_snapshot(OracleSnapshot::new(
            &market.market_id,
            PRIVATE_DEFI_MARGIN_HEALTH_ORCHESTRATOR_DEVNET_HEIGHT,
            "price-commitment-xmr-usd-devnet",
            650,
            9_700,
            &json!({"threshold": 2, "signers": ["oracle-a", "oracle-b", "oracle-c"]}),
        )?)?;
        state.insert_account(MarginAccount::new(
            "margin-account-commitment-a",
            &market.market_id,
            "collateral-commitment-a",
            "debt-commitment-a",
            12_200,
            256,
            PRIVATE_DEFI_MARGIN_HEALTH_ORCHESTRATOR_DEVNET_HEIGHT.saturating_sub(24),
        )?)?;
        state.insert_account(MarginAccount::new(
            "margin-account-commitment-b",
            &market.market_id,
            "collateral-commitment-b",
            "debt-commitment-b",
            10_450,
            384,
            PRIVATE_DEFI_MARGIN_HEALTH_ORCHESTRATOR_DEVNET_HEIGHT.saturating_sub(8),
        )?)?;
        for action in state.propose_remediations()? {
            state.insert_remediation(action)?;
        }
        Ok(state)
    }
}

pub fn margin_market_id(
    market_kind: MarginMarketKind,
    label: &str,
    asset_root: &str,
    oracle_set_root: &str,
    max_leverage_bps: u64,
    maintenance_margin_bps: u64,
) -> String {
    domain_hash(
        "PRIVATE-DEFI-MARGIN-MARKET-ID",
        &[
            HashPart::Str(PRIVATE_DEFI_MARGIN_HEALTH_ORCHESTRATOR_PROTOCOL_VERSION),
            HashPart::Str(market_kind.as_str()),
            HashPart::Str(label),
            HashPart::Str(asset_root),
            HashPart::Str(oracle_set_root),
            HashPart::Int(max_leverage_bps as i128),
            HashPart::Int(maintenance_margin_bps as i128),
        ],
        32,
    )
}

pub fn oracle_snapshot_id(
    market_id: &str,
    height: u64,
    price_commitment: &str,
    volatility_bps: u64,
    confidence_bps: u64,
    signer_root: &str,
) -> String {
    domain_hash(
        "PRIVATE-DEFI-MARGIN-ORACLE-SNAPSHOT-ID",
        &[
            HashPart::Str(market_id),
            HashPart::Int(height as i128),
            HashPart::Str(price_commitment),
            HashPart::Int(volatility_bps as i128),
            HashPart::Int(confidence_bps as i128),
            HashPart::Str(signer_root),
        ],
        32,
    )
}

pub fn margin_account_id(
    account_commitment: &str,
    market_id: &str,
    collateral_commitment: &str,
    debt_commitment: &str,
    opened_at_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-DEFI-MARGIN-ACCOUNT-ID",
        &[
            HashPart::Str(account_commitment),
            HashPart::Str(market_id),
            HashPart::Str(collateral_commitment),
            HashPart::Str(debt_commitment),
            HashPart::Int(opened_at_height as i128),
        ],
        32,
    )
}

pub fn remediation_action_id(
    account_id: &str,
    market_id: &str,
    remediation_kind: RemediationKind,
    priority: u64,
    reason_root: &str,
    expires_at_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-DEFI-MARGIN-REMEDIATION-ACTION-ID",
        &[
            HashPart::Str(account_id),
            HashPart::Str(market_id),
            HashPart::Str(remediation_kind.as_str()),
            HashPart::Int(priority as i128),
            HashPart::Str(reason_root),
            HashPart::Int(expires_at_height as i128),
        ],
        32,
    )
}

pub fn margin_market_root(markets: &[MarginMarket]) -> String {
    let leaves = markets
        .iter()
        .map(MarginMarket::public_record)
        .collect::<Vec<_>>();
    merkle_root("PRIVATE-DEFI-MARGIN-MARKETS", &leaves)
}

pub fn oracle_snapshot_root(oracles: &[OracleSnapshot]) -> String {
    let leaves = oracles
        .iter()
        .map(OracleSnapshot::public_record)
        .collect::<Vec<_>>();
    merkle_root("PRIVATE-DEFI-MARGIN-ORACLES", &leaves)
}

pub fn margin_account_root(accounts: &[MarginAccount]) -> String {
    let leaves = accounts
        .iter()
        .map(MarginAccount::public_record)
        .collect::<Vec<_>>();
    merkle_root("PRIVATE-DEFI-MARGIN-ACCOUNTS", &leaves)
}

pub fn remediation_action_root(actions: &[RemediationAction]) -> String {
    let leaves = actions
        .iter()
        .map(RemediationAction::public_record)
        .collect::<Vec<_>>();
    merkle_root("PRIVATE-DEFI-MARGIN-REMEDIATIONS", &leaves)
}

pub fn private_defi_margin_health_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(domain, &[HashPart::Json(payload)], 32)
}

pub fn root_from_record(record: &Value) -> String {
    domain_hash(
        "PRIVATE-DEFI-MARGIN-HEALTH-ORCHESTRATOR-STATE-ROOT",
        &[HashPart::Json(record)],
        32,
    )
}

pub fn devnet() -> PrivateDefiMarginHealthOrchestratorResult<State> {
    State::devnet()
}
