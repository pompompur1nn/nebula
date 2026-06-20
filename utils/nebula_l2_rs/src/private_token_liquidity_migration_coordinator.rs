use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateTokenLiquidityMigrationCoordinatorResult<T> = Result<T, String>;

pub const PRIVATE_TOKEN_LIQUIDITY_MIGRATION_COORDINATOR_PROTOCOL_VERSION: &str =
    "nebula-private-token-liquidity-migration-coordinator-v1";
pub const PRIVATE_TOKEN_LIQUIDITY_MIGRATION_COORDINATOR_DEFAULT_MIN_PRIVACY_SET: u64 = 128;
pub const PRIVATE_TOKEN_LIQUIDITY_MIGRATION_COORDINATOR_DEFAULT_MAX_MIGRATION_FEE_BPS: u64 = 40;
pub const PRIVATE_TOKEN_LIQUIDITY_MIGRATION_COORDINATOR_DEFAULT_MIN_RESERVE_COVERAGE_BPS: u64 =
    10_250;
pub const PRIVATE_TOKEN_LIQUIDITY_MIGRATION_COORDINATOR_DEFAULT_RECEIPT_TTL_BLOCKS: u64 = 96;
pub const PRIVATE_TOKEN_LIQUIDITY_MIGRATION_COORDINATOR_MAX_BPS: u64 = 10_000;
pub const PRIVATE_TOKEN_LIQUIDITY_MIGRATION_COORDINATOR_MAX_POOLS: usize = 512;
pub const PRIVATE_TOKEN_LIQUIDITY_MIGRATION_COORDINATOR_MAX_PLANS: usize = 1_024;
pub const PRIVATE_TOKEN_LIQUIDITY_MIGRATION_COORDINATOR_MAX_RECEIPTS: usize = 2_048;
pub const PRIVATE_TOKEN_LIQUIDITY_MIGRATION_COORDINATOR_DEVNET_HEIGHT: u64 = 91_300;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LiquidityVenueKind {
    PrivateAmm,
    ConfidentialVault,
    LaunchPool,
    BridgeVault,
    WrappedXmrRoute,
    DarkPool,
}

impl LiquidityVenueKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrivateAmm => "private_amm",
            Self::ConfidentialVault => "confidential_vault",
            Self::LaunchPool => "launch_pool",
            Self::BridgeVault => "bridge_vault",
            Self::WrappedXmrRoute => "wrapped_xmr_route",
            Self::DarkPool => "dark_pool",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MigrationMode {
    Gradual,
    Atomic,
    EmergencyDrain,
    Incentivized,
    GovernanceScheduled,
}

impl MigrationMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Gradual => "gradual",
            Self::Atomic => "atomic",
            Self::EmergencyDrain => "emergency_drain",
            Self::Incentivized => "incentivized",
            Self::GovernanceScheduled => "governance_scheduled",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MigrationStatus {
    Planned,
    Open,
    Filling,
    Settled,
    Rebalanced,
    Expired,
}

impl MigrationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Planned => "planned",
            Self::Open => "open",
            Self::Filling => "filling",
            Self::Settled => "settled",
            Self::Rebalanced => "rebalanced",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub min_privacy_set: u64,
    pub max_migration_fee_bps: u64,
    pub min_reserve_coverage_bps: u64,
    pub receipt_ttl_blocks: u64,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            min_privacy_set: PRIVATE_TOKEN_LIQUIDITY_MIGRATION_COORDINATOR_DEFAULT_MIN_PRIVACY_SET,
            max_migration_fee_bps:
                PRIVATE_TOKEN_LIQUIDITY_MIGRATION_COORDINATOR_DEFAULT_MAX_MIGRATION_FEE_BPS,
            min_reserve_coverage_bps:
                PRIVATE_TOKEN_LIQUIDITY_MIGRATION_COORDINATOR_DEFAULT_MIN_RESERVE_COVERAGE_BPS,
            receipt_ttl_blocks:
                PRIVATE_TOKEN_LIQUIDITY_MIGRATION_COORDINATOR_DEFAULT_RECEIPT_TTL_BLOCKS,
        }
    }

    pub fn validate(&self) -> PrivateTokenLiquidityMigrationCoordinatorResult<()> {
        if self.min_privacy_set == 0 || self.receipt_ttl_blocks == 0 {
            return Err("token migration privacy and ttl limits must be positive".to_string());
        }
        if self.max_migration_fee_bps > PRIVATE_TOKEN_LIQUIDITY_MIGRATION_COORDINATOR_MAX_BPS {
            return Err("migration fee cap cannot exceed 100%".to_string());
        }
        if self.min_reserve_coverage_bps < PRIVATE_TOKEN_LIQUIDITY_MIGRATION_COORDINATOR_MAX_BPS {
            return Err("reserve coverage must be at least 100%".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_token_liquidity_migration_coordinator_config",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_TOKEN_LIQUIDITY_MIGRATION_COORDINATOR_PROTOCOL_VERSION,
            "min_privacy_set": self.min_privacy_set,
            "max_migration_fee_bps": self.max_migration_fee_bps,
            "min_reserve_coverage_bps": self.min_reserve_coverage_bps,
            "receipt_ttl_blocks": self.receipt_ttl_blocks,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiquidityVenue {
    pub venue_id: String,
    pub venue_kind: LiquidityVenueKind,
    pub label: String,
    pub token_root: String,
    pub reserve_commitment: String,
    pub available_liquidity_units: u64,
    pub fee_bps: u64,
    pub privacy_set_size: u64,
    pub supported_modes: BTreeSet<MigrationMode>,
}

impl LiquidityVenue {
    pub fn new(
        venue_kind: LiquidityVenueKind,
        label: &str,
        token: &Value,
        reserve_commitment: &str,
        available_liquidity_units: u64,
        fee_bps: u64,
        privacy_set_size: u64,
        supported_modes: BTreeSet<MigrationMode>,
    ) -> PrivateTokenLiquidityMigrationCoordinatorResult<Self> {
        if label.is_empty() || reserve_commitment.is_empty() {
            return Err("liquidity venue identifiers cannot be empty".to_string());
        }
        if available_liquidity_units == 0 {
            return Err("liquidity venue must have positive available liquidity".to_string());
        }
        if fee_bps > PRIVATE_TOKEN_LIQUIDITY_MIGRATION_COORDINATOR_MAX_BPS {
            return Err("liquidity venue fee cannot exceed 100%".to_string());
        }
        if supported_modes.is_empty() {
            return Err("liquidity venue supported modes cannot be empty".to_string());
        }
        let token_root =
            private_token_liquidity_migration_payload_root("PRIVATE-TOKEN-MIGRATION-TOKEN", token);
        let venue_id = liquidity_venue_id(
            venue_kind,
            label,
            &token_root,
            reserve_commitment,
            available_liquidity_units,
            fee_bps,
        );
        Ok(Self {
            venue_id,
            venue_kind,
            label: label.to_string(),
            token_root,
            reserve_commitment: reserve_commitment.to_string(),
            available_liquidity_units,
            fee_bps,
            privacy_set_size,
            supported_modes,
        })
    }

    pub fn supports(&self, mode: MigrationMode) -> bool {
        self.supported_modes.contains(&mode)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_token_liquidity_venue",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_TOKEN_LIQUIDITY_MIGRATION_COORDINATOR_PROTOCOL_VERSION,
            "venue_id": self.venue_id,
            "venue_kind": self.venue_kind.as_str(),
            "label": self.label,
            "token_root": self.token_root,
            "reserve_commitment": self.reserve_commitment,
            "available_liquidity_units": self.available_liquidity_units,
            "fee_bps": self.fee_bps,
            "privacy_set_size": self.privacy_set_size,
            "supported_modes": self.supported_modes.iter().map(|mode| mode.as_str()).collect::<Vec<_>>(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MigrationPlan {
    pub plan_id: String,
    pub source_venue_id: String,
    pub target_venue_id: String,
    pub mode: MigrationMode,
    pub liquidity_commitment: String,
    pub amount_units: u64,
    pub max_fee_bps: u64,
    pub privacy_set_size: u64,
    pub opens_at_height: u64,
    pub expires_at_height: u64,
    pub status: MigrationStatus,
}

impl MigrationPlan {
    pub fn new(
        source_venue_id: &str,
        target_venue_id: &str,
        mode: MigrationMode,
        liquidity_commitment: &str,
        amount_units: u64,
        max_fee_bps: u64,
        privacy_set_size: u64,
        opens_at_height: u64,
        expires_at_height: u64,
        status: MigrationStatus,
    ) -> PrivateTokenLiquidityMigrationCoordinatorResult<Self> {
        if source_venue_id.is_empty()
            || target_venue_id.is_empty()
            || liquidity_commitment.is_empty()
        {
            return Err("migration plan identifiers cannot be empty".to_string());
        }
        if source_venue_id == target_venue_id {
            return Err("migration source and target must differ".to_string());
        }
        if amount_units == 0 {
            return Err("migration amount must be positive".to_string());
        }
        if max_fee_bps > PRIVATE_TOKEN_LIQUIDITY_MIGRATION_COORDINATOR_MAX_BPS {
            return Err("migration plan fee cap cannot exceed 100%".to_string());
        }
        if expires_at_height <= opens_at_height {
            return Err("migration plan must expire after opening".to_string());
        }
        let plan_id = migration_plan_id(
            source_venue_id,
            target_venue_id,
            mode,
            liquidity_commitment,
            amount_units,
            max_fee_bps,
            opens_at_height,
            expires_at_height,
        );
        Ok(Self {
            plan_id,
            source_venue_id: source_venue_id.to_string(),
            target_venue_id: target_venue_id.to_string(),
            mode,
            liquidity_commitment: liquidity_commitment.to_string(),
            amount_units,
            max_fee_bps,
            privacy_set_size,
            opens_at_height,
            expires_at_height,
            status,
        })
    }

    pub fn active_at(&self, height: u64) -> bool {
        self.opens_at_height <= height
            && height <= self.expires_at_height
            && matches!(
                self.status,
                MigrationStatus::Open | MigrationStatus::Filling
            )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_token_liquidity_migration_plan",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_TOKEN_LIQUIDITY_MIGRATION_COORDINATOR_PROTOCOL_VERSION,
            "plan_id": self.plan_id,
            "source_venue_id": self.source_venue_id,
            "target_venue_id": self.target_venue_id,
            "mode": self.mode.as_str(),
            "liquidity_commitment": self.liquidity_commitment,
            "amount_units": self.amount_units,
            "max_fee_bps": self.max_fee_bps,
            "privacy_set_size": self.privacy_set_size,
            "opens_at_height": self.opens_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeeSponsor {
    pub sponsor_id: String,
    pub label: String,
    pub credit_commitment: String,
    pub remaining_credit_units: u64,
    pub max_fee_bps: u64,
    pub allowed_modes: BTreeSet<MigrationMode>,
}

impl FeeSponsor {
    pub fn new(
        label: &str,
        credit_commitment: &str,
        remaining_credit_units: u64,
        max_fee_bps: u64,
        allowed_modes: BTreeSet<MigrationMode>,
    ) -> PrivateTokenLiquidityMigrationCoordinatorResult<Self> {
        if label.is_empty() || credit_commitment.is_empty() {
            return Err("fee sponsor identifiers cannot be empty".to_string());
        }
        if remaining_credit_units == 0 {
            return Err("fee sponsor credit must be positive".to_string());
        }
        if max_fee_bps > PRIVATE_TOKEN_LIQUIDITY_MIGRATION_COORDINATOR_MAX_BPS {
            return Err("fee sponsor fee cap cannot exceed 100%".to_string());
        }
        if allowed_modes.is_empty() {
            return Err("fee sponsor allowed modes cannot be empty".to_string());
        }
        let sponsor_id = fee_sponsor_id(
            label,
            credit_commitment,
            remaining_credit_units,
            max_fee_bps,
            &allowed_modes,
        );
        Ok(Self {
            sponsor_id,
            label: label.to_string(),
            credit_commitment: credit_commitment.to_string(),
            remaining_credit_units,
            max_fee_bps,
            allowed_modes,
        })
    }

    pub fn can_sponsor(&self, plan: &MigrationPlan) -> bool {
        self.allowed_modes.contains(&plan.mode)
            && self.remaining_credit_units >= plan.amount_units
            && self.max_fee_bps <= plan.max_fee_bps
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_token_liquidity_migration_fee_sponsor",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_TOKEN_LIQUIDITY_MIGRATION_COORDINATOR_PROTOCOL_VERSION,
            "sponsor_id": self.sponsor_id,
            "label": self.label,
            "credit_commitment": self.credit_commitment,
            "remaining_credit_units": self.remaining_credit_units,
            "max_fee_bps": self.max_fee_bps,
            "allowed_modes": self.allowed_modes.iter().map(|mode| mode.as_str()).collect::<Vec<_>>(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MigrationReceipt {
    pub receipt_id: String,
    pub plan_id: String,
    pub source_venue_id: String,
    pub target_venue_id: String,
    pub sponsor_id: Option<String>,
    pub amount_units: u64,
    pub fee_bps: u64,
    pub receipt_root: String,
    pub expires_at_height: u64,
}

impl MigrationReceipt {
    pub fn new(
        plan: &MigrationPlan,
        sponsor_id: Option<String>,
        fee_bps: u64,
        receipt: &Value,
        expires_at_height: u64,
    ) -> PrivateTokenLiquidityMigrationCoordinatorResult<Self> {
        if fee_bps > plan.max_fee_bps {
            return Err("migration receipt fee exceeds plan cap".to_string());
        }
        if expires_at_height <= plan.opens_at_height {
            return Err("migration receipt must expire after plan opens".to_string());
        }
        let sponsor_label = sponsor_id.as_deref().unwrap_or("none");
        let receipt_root = private_token_liquidity_migration_payload_root(
            "PRIVATE-TOKEN-MIGRATION-RECEIPT",
            receipt,
        );
        let receipt_id = migration_receipt_id(
            &plan.plan_id,
            &plan.source_venue_id,
            &plan.target_venue_id,
            sponsor_label,
            plan.amount_units,
            fee_bps,
            &receipt_root,
            expires_at_height,
        );
        Ok(Self {
            receipt_id,
            plan_id: plan.plan_id.clone(),
            source_venue_id: plan.source_venue_id.clone(),
            target_venue_id: plan.target_venue_id.clone(),
            sponsor_id,
            amount_units: plan.amount_units,
            fee_bps,
            receipt_root,
            expires_at_height,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_token_liquidity_migration_receipt",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_TOKEN_LIQUIDITY_MIGRATION_COORDINATOR_PROTOCOL_VERSION,
            "receipt_id": self.receipt_id,
            "plan_id": self.plan_id,
            "source_venue_id": self.source_venue_id,
            "target_venue_id": self.target_venue_id,
            "sponsor_id": self.sponsor_id,
            "amount_units": self.amount_units,
            "fee_bps": self.fee_bps,
            "receipt_root": self.receipt_root,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roots {
    pub config_root: String,
    pub venue_root: String,
    pub plan_root: String,
    pub sponsor_root: String,
    pub receipt_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "venue_root": self.venue_root,
            "plan_root": self.plan_root,
            "sponsor_root": self.sponsor_root,
            "receipt_root": self.receipt_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    pub venue_count: u64,
    pub plan_count: u64,
    pub sponsor_count: u64,
    pub receipt_count: u64,
    pub active_plan_count: u64,
    pub sponsored_receipt_count: u64,
    pub total_migration_units: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "venue_count": self.venue_count,
            "plan_count": self.plan_count,
            "sponsor_count": self.sponsor_count,
            "receipt_count": self.receipt_count,
            "active_plan_count": self.active_plan_count,
            "sponsored_receipt_count": self.sponsored_receipt_count,
            "total_migration_units": self.total_migration_units,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub height: u64,
    pub config: Config,
    pub venues: BTreeMap<String, LiquidityVenue>,
    pub plans: BTreeMap<String, MigrationPlan>,
    pub sponsors: BTreeMap<String, FeeSponsor>,
    pub receipts: BTreeMap<String, MigrationReceipt>,
    pub roots: Roots,
    pub counters: Counters,
    pub state_root: String,
}

impl State {
    pub fn new(
        height: u64,
        config: Config,
    ) -> PrivateTokenLiquidityMigrationCoordinatorResult<Self> {
        config.validate()?;
        let mut state = Self {
            height,
            config,
            venues: BTreeMap::new(),
            plans: BTreeMap::new(),
            sponsors: BTreeMap::new(),
            receipts: BTreeMap::new(),
            roots: Roots {
                config_root: String::new(),
                venue_root: String::new(),
                plan_root: String::new(),
                sponsor_root: String::new(),
                receipt_root: String::new(),
            },
            counters: Counters {
                venue_count: 0,
                plan_count: 0,
                sponsor_count: 0,
                receipt_count: 0,
                active_plan_count: 0,
                sponsored_receipt_count: 0,
                total_migration_units: 0,
            },
            state_root: String::new(),
        };
        state.refresh();
        Ok(state)
    }

    pub fn insert_venue(
        &mut self,
        venue: LiquidityVenue,
    ) -> PrivateTokenLiquidityMigrationCoordinatorResult<()> {
        if self.venues.len() >= PRIVATE_TOKEN_LIQUIDITY_MIGRATION_COORDINATOR_MAX_POOLS {
            return Err("liquidity venue limit exceeded".to_string());
        }
        if venue.fee_bps > self.config.max_migration_fee_bps {
            return Err("liquidity venue fee exceeds configured cap".to_string());
        }
        if venue.privacy_set_size < self.config.min_privacy_set {
            return Err("liquidity venue privacy set below configured floor".to_string());
        }
        self.venues.insert(venue.venue_id.clone(), venue);
        self.refresh();
        Ok(())
    }

    pub fn insert_plan(
        &mut self,
        plan: MigrationPlan,
    ) -> PrivateTokenLiquidityMigrationCoordinatorResult<()> {
        if self.plans.len() >= PRIVATE_TOKEN_LIQUIDITY_MIGRATION_COORDINATOR_MAX_PLANS {
            return Err("migration plan limit exceeded".to_string());
        }
        let Some(source) = self.venues.get(&plan.source_venue_id) else {
            return Err("migration plan references unknown source venue".to_string());
        };
        let Some(target) = self.venues.get(&plan.target_venue_id) else {
            return Err("migration plan references unknown target venue".to_string());
        };
        if !source.supports(plan.mode) || !target.supports(plan.mode) {
            return Err("migration plan mode is unsupported by source or target".to_string());
        }
        if plan.privacy_set_size < self.config.min_privacy_set {
            return Err("migration plan privacy set below configured floor".to_string());
        }
        if plan.max_fee_bps > self.config.max_migration_fee_bps {
            return Err("migration plan fee exceeds configured cap".to_string());
        }
        self.plans.insert(plan.plan_id.clone(), plan);
        self.refresh();
        Ok(())
    }

    pub fn insert_sponsor(
        &mut self,
        sponsor: FeeSponsor,
    ) -> PrivateTokenLiquidityMigrationCoordinatorResult<()> {
        if sponsor.max_fee_bps > self.config.max_migration_fee_bps {
            return Err("fee sponsor cap exceeds configured migration cap".to_string());
        }
        self.sponsors.insert(sponsor.sponsor_id.clone(), sponsor);
        self.refresh();
        Ok(())
    }

    pub fn insert_receipt(
        &mut self,
        receipt: MigrationReceipt,
    ) -> PrivateTokenLiquidityMigrationCoordinatorResult<()> {
        if self.receipts.len() >= PRIVATE_TOKEN_LIQUIDITY_MIGRATION_COORDINATOR_MAX_RECEIPTS {
            return Err("migration receipt limit exceeded".to_string());
        }
        if !self.plans.contains_key(&receipt.plan_id) {
            return Err("migration receipt references unknown plan".to_string());
        }
        self.receipts.insert(receipt.receipt_id.clone(), receipt);
        self.refresh();
        Ok(())
    }

    pub fn best_sponsor_for_plan(&self, plan: &MigrationPlan) -> Option<&FeeSponsor> {
        self.sponsors
            .values()
            .filter(|sponsor| sponsor.can_sponsor(plan))
            .min_by_key(|sponsor| sponsor.max_fee_bps)
    }

    pub fn create_receipts(
        &mut self,
    ) -> PrivateTokenLiquidityMigrationCoordinatorResult<Vec<String>> {
        let mut created = Vec::new();
        let plans = self
            .plans
            .values()
            .filter(|plan| plan.active_at(self.height))
            .cloned()
            .collect::<Vec<_>>();
        for plan in plans {
            if self
                .receipts
                .values()
                .any(|receipt| receipt.plan_id == plan.plan_id)
            {
                continue;
            }
            let sponsor = self.best_sponsor_for_plan(&plan);
            let sponsor_id = sponsor.map(|sponsor| sponsor.sponsor_id.clone());
            let fee_bps = sponsor
                .map(|sponsor| sponsor.max_fee_bps)
                .unwrap_or(plan.max_fee_bps)
                .min(plan.max_fee_bps);
            let receipt = MigrationReceipt::new(
                &plan,
                sponsor_id,
                fee_bps,
                &json!({
                    "mode": plan.mode.as_str(),
                    "status": plan.status.as_str(),
                    "amount_units": plan.amount_units,
                    "private_receipt": true,
                }),
                self.height.saturating_add(self.config.receipt_ttl_blocks),
            )?;
            created.push(receipt.receipt_id.clone());
            self.insert_receipt(receipt)?;
        }
        Ok(created)
    }

    pub fn refresh(&mut self) {
        self.roots = Roots {
            config_root: private_token_liquidity_migration_payload_root(
                "PRIVATE-TOKEN-MIGRATION-CONFIG",
                &self.config.public_record(),
            ),
            venue_root: liquidity_venue_root(&self.venues.values().cloned().collect::<Vec<_>>()),
            plan_root: migration_plan_root(&self.plans.values().cloned().collect::<Vec<_>>()),
            sponsor_root: fee_sponsor_root(&self.sponsors.values().cloned().collect::<Vec<_>>()),
            receipt_root: migration_receipt_root(
                &self.receipts.values().cloned().collect::<Vec<_>>(),
            ),
        };
        self.counters = Counters {
            venue_count: self.venues.len() as u64,
            plan_count: self.plans.len() as u64,
            sponsor_count: self.sponsors.len() as u64,
            receipt_count: self.receipts.len() as u64,
            active_plan_count: self
                .plans
                .values()
                .filter(|plan| plan.active_at(self.height))
                .count() as u64,
            sponsored_receipt_count: self
                .receipts
                .values()
                .filter(|receipt| receipt.sponsor_id.is_some())
                .count() as u64,
            total_migration_units: self
                .plans
                .values()
                .map(|plan| plan.amount_units)
                .fold(0_u64, u64::saturating_add),
        };
        self.state_root = root_from_record(&self.public_record_without_state_root());
    }

    fn public_record_without_state_root(&self) -> Value {
        json!({
            "kind": "private_token_liquidity_migration_coordinator_state",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_TOKEN_LIQUIDITY_MIGRATION_COORDINATOR_PROTOCOL_VERSION,
            "height": self.height,
            "roots": self.roots.public_record(),
            "counters": self.counters.public_record(),
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        if let Value::Object(ref mut values) = record {
            values.insert("state_root".to_string(), json!(self.state_root));
        }
        record
    }

    pub fn devnet() -> PrivateTokenLiquidityMigrationCoordinatorResult<Self> {
        let mut state = Self::new(
            PRIVATE_TOKEN_LIQUIDITY_MIGRATION_COORDINATOR_DEVNET_HEIGHT,
            Config::devnet(),
        )?;
        let mut modes = BTreeSet::new();
        modes.insert(MigrationMode::Gradual);
        modes.insert(MigrationMode::Incentivized);
        modes.insert(MigrationMode::Atomic);
        let source = LiquidityVenue::new(
            LiquidityVenueKind::LaunchPool,
            "devnet-private-token-launch-pool",
            &json!({"token": "confidential-governance-token", "asset_id": "cgov-devnet"}),
            "reserve-commitment-launch-pool",
            9_000_000,
            20,
            256,
            modes.clone(),
        )?;
        let target = LiquidityVenue::new(
            LiquidityVenueKind::PrivateAmm,
            "devnet-private-amm-v2",
            &json!({"token": "confidential-governance-token", "paired": "wxmr"}),
            "reserve-commitment-private-amm",
            12_000_000,
            18,
            384,
            modes.clone(),
        )?;
        state.insert_venue(source.clone())?;
        state.insert_venue(target.clone())?;
        state.insert_sponsor(FeeSponsor::new(
            "devnet-token-migration-sponsor",
            "credit-commitment-token-migration",
            5_000_000,
            12,
            modes,
        )?)?;
        state.insert_plan(MigrationPlan::new(
            &source.venue_id,
            &target.venue_id,
            MigrationMode::Incentivized,
            "liquidity-migration-commitment-devnet",
            4_000_000,
            25,
            256,
            PRIVATE_TOKEN_LIQUIDITY_MIGRATION_COORDINATOR_DEVNET_HEIGHT.saturating_sub(1),
            PRIVATE_TOKEN_LIQUIDITY_MIGRATION_COORDINATOR_DEVNET_HEIGHT.saturating_add(48),
            MigrationStatus::Open,
        )?)?;
        state.create_receipts()?;
        Ok(state)
    }
}

pub fn liquidity_venue_id(
    venue_kind: LiquidityVenueKind,
    label: &str,
    token_root: &str,
    reserve_commitment: &str,
    available_liquidity_units: u64,
    fee_bps: u64,
) -> String {
    domain_hash(
        "PRIVATE-TOKEN-LIQUIDITY-VENUE-ID",
        &[
            HashPart::Str(PRIVATE_TOKEN_LIQUIDITY_MIGRATION_COORDINATOR_PROTOCOL_VERSION),
            HashPart::Str(venue_kind.as_str()),
            HashPart::Str(label),
            HashPart::Str(token_root),
            HashPart::Str(reserve_commitment),
            HashPart::Int(available_liquidity_units as i128),
            HashPart::Int(fee_bps as i128),
        ],
        32,
    )
}

pub fn migration_plan_id(
    source_venue_id: &str,
    target_venue_id: &str,
    mode: MigrationMode,
    liquidity_commitment: &str,
    amount_units: u64,
    max_fee_bps: u64,
    opens_at_height: u64,
    expires_at_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-TOKEN-LIQUIDITY-MIGRATION-PLAN-ID",
        &[
            HashPart::Str(source_venue_id),
            HashPart::Str(target_venue_id),
            HashPart::Str(mode.as_str()),
            HashPart::Str(liquidity_commitment),
            HashPart::Int(amount_units as i128),
            HashPart::Int(max_fee_bps as i128),
            HashPart::Int(opens_at_height as i128),
            HashPart::Int(expires_at_height as i128),
        ],
        32,
    )
}

pub fn fee_sponsor_id(
    label: &str,
    credit_commitment: &str,
    remaining_credit_units: u64,
    max_fee_bps: u64,
    allowed_modes: &BTreeSet<MigrationMode>,
) -> String {
    let modes = allowed_modes
        .iter()
        .map(|mode| mode.as_str())
        .collect::<Vec<_>>()
        .join(",");
    domain_hash(
        "PRIVATE-TOKEN-LIQUIDITY-MIGRATION-SPONSOR-ID",
        &[
            HashPart::Str(label),
            HashPart::Str(credit_commitment),
            HashPart::Int(remaining_credit_units as i128),
            HashPart::Int(max_fee_bps as i128),
            HashPart::Str(&modes),
        ],
        32,
    )
}

pub fn migration_receipt_id(
    plan_id: &str,
    source_venue_id: &str,
    target_venue_id: &str,
    sponsor_id: &str,
    amount_units: u64,
    fee_bps: u64,
    receipt_root: &str,
    expires_at_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-TOKEN-LIQUIDITY-MIGRATION-RECEIPT-ID",
        &[
            HashPart::Str(plan_id),
            HashPart::Str(source_venue_id),
            HashPart::Str(target_venue_id),
            HashPart::Str(sponsor_id),
            HashPart::Int(amount_units as i128),
            HashPart::Int(fee_bps as i128),
            HashPart::Str(receipt_root),
            HashPart::Int(expires_at_height as i128),
        ],
        32,
    )
}

pub fn liquidity_venue_root(venues: &[LiquidityVenue]) -> String {
    let leaves = venues
        .iter()
        .map(LiquidityVenue::public_record)
        .collect::<Vec<_>>();
    merkle_root("PRIVATE-TOKEN-LIQUIDITY-VENUES", &leaves)
}

pub fn migration_plan_root(plans: &[MigrationPlan]) -> String {
    let leaves = plans
        .iter()
        .map(MigrationPlan::public_record)
        .collect::<Vec<_>>();
    merkle_root("PRIVATE-TOKEN-LIQUIDITY-MIGRATION-PLANS", &leaves)
}

pub fn fee_sponsor_root(sponsors: &[FeeSponsor]) -> String {
    let leaves = sponsors
        .iter()
        .map(FeeSponsor::public_record)
        .collect::<Vec<_>>();
    merkle_root("PRIVATE-TOKEN-LIQUIDITY-MIGRATION-SPONSORS", &leaves)
}

pub fn migration_receipt_root(receipts: &[MigrationReceipt]) -> String {
    let leaves = receipts
        .iter()
        .map(MigrationReceipt::public_record)
        .collect::<Vec<_>>();
    merkle_root("PRIVATE-TOKEN-LIQUIDITY-MIGRATION-RECEIPTS", &leaves)
}

pub fn private_token_liquidity_migration_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(domain, &[HashPart::Json(payload)], 32)
}

pub fn root_from_record(record: &Value) -> String {
    domain_hash(
        "PRIVATE-TOKEN-LIQUIDITY-MIGRATION-COORDINATOR-STATE-ROOT",
        &[HashPart::Json(record)],
        32,
    )
}

pub fn devnet() -> PrivateTokenLiquidityMigrationCoordinatorResult<State> {
    State::devnet()
}
