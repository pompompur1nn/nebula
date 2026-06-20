use std::collections::{BTreeMap, BTreeSet, VecDeque};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2PqConfidentialDefiOracleVolatilitySurfaceRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-confidential-defi-oracle-volatility-surface-runtime-v1";
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_ORACLE_SUITE: &str = "ml-dsa-87+slh-dsa-shake-256f-confidential-volatility-oracle-v1";
pub const SURFACE_COMMITMENT_SCHEME: &str = "roots-only-confidential-volatility-surface-grid-v1";
pub const LOW_FEE_BATCH_SCHEME: &str = "low-fee-recursive-volatility-surface-update-batch-v1";
pub const PRIVACY_BUDGET_SCHEME: &str = "volatility-surface-query-leakage-budget-root-v1";
pub const DEVNET_L2_NETWORK: &str = "nebula-private-l2-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEVNET_HEIGHT: u64 = 3_440_000;
pub const DEVNET_EPOCH: u64 = 8_192;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_SURFACE_TTL_BLOCKS: u64 = 240;
pub const DEFAULT_NODE_TTL_BLOCKS: u64 = 120;
pub const DEFAULT_BATCH_TTL_BLOCKS: u64 = 32;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 10;
pub const DEFAULT_LOW_FEE_REBATE_BPS: u64 = 6;
pub const DEFAULT_MAX_ORACLE_DEVIATION_BPS: u64 = 900;
pub const DEFAULT_CONFIDENCE_FLOOR_BPS: u64 = 6_700;
pub const DEFAULT_LEAKAGE_BUDGET_UNITS: u64 = 1_000_000;
pub const MAX_BPS: u64 = 10_000;
pub const MAX_SIGNERS: usize = 65_536;
pub const MAX_SURFACES: usize = 262_144;
pub const MAX_NODES: usize = 4_194_304;
pub const MAX_GUARD_BANDS: usize = 1_048_576;
pub const MAX_BATCHES: usize = 524_288;
pub const MAX_EVENTS: usize = 1_048_576;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InstrumentKind {
    Spot,
    Perpetual,
    OptionCall,
    OptionPut,
    LendingRate,
    LiquidationBackstop,
    BridgeExitLiquidity,
    RwaVaultShare,
}

impl InstrumentKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Spot => "spot",
            Self::Perpetual => "perpetual",
            Self::OptionCall => "option_call",
            Self::OptionPut => "option_put",
            Self::LendingRate => "lending_rate",
            Self::LiquidationBackstop => "liquidation_backstop",
            Self::BridgeExitLiquidity => "bridge_exit_liquidity",
            Self::RwaVaultShare => "rwa_vault_share",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SurfaceStatus {
    Draft,
    Active,
    Guarded,
    LowFeeBatching,
    Frozen,
    Retired,
}

impl SurfaceStatus {
    pub fn accepts_updates(self) -> bool {
        matches!(
            self,
            Self::Draft | Self::Active | Self::Guarded | Self::LowFeeBatching
        )
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Active => "active",
            Self::Guarded => "guarded",
            Self::LowFeeBatching => "low_fee_batching",
            Self::Frozen => "frozen",
            Self::Retired => "retired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfidenceBand {
    Quarantined,
    Watch,
    Standard,
    Strong,
    Supermajority,
}

impl ConfidenceBand {
    pub fn from_bps(value: u64) -> Self {
        if value >= 9_000 {
            Self::Supermajority
        } else if value >= 8_000 {
            Self::Strong
        } else if value >= 6_700 {
            Self::Standard
        } else if value >= 5_000 {
            Self::Watch
        } else {
            Self::Quarantined
        }
    }

    pub fn usable(self) -> bool {
        matches!(self, Self::Standard | Self::Strong | Self::Supermajority)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Quarantined => "quarantined",
            Self::Watch => "watch",
            Self::Standard => "standard",
            Self::Strong => "strong",
            Self::Supermajority => "supermajority",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchStatus {
    Open,
    RootCommitted,
    Proved,
    Settled,
    Rejected,
    Expired,
}

impl BatchStatus {
    pub fn live(self) -> bool {
        matches!(self, Self::Open | Self::RootCommitted | Self::Proved)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::RootCommitted => "root_committed",
            Self::Proved => "proved",
            Self::Settled => "settled",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub l2_network: String,
    pub monero_network: String,
    pub fee_asset_id: String,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub surface_ttl_blocks: u64,
    pub node_ttl_blocks: u64,
    pub batch_ttl_blocks: u64,
    pub max_user_fee_bps: u64,
    pub low_fee_rebate_bps: u64,
    pub max_oracle_deviation_bps: u64,
    pub confidence_floor_bps: u64,
    pub leakage_budget_units: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            l2_network: DEVNET_L2_NETWORK.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            surface_ttl_blocks: DEFAULT_SURFACE_TTL_BLOCKS,
            node_ttl_blocks: DEFAULT_NODE_TTL_BLOCKS,
            batch_ttl_blocks: DEFAULT_BATCH_TTL_BLOCKS,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            low_fee_rebate_bps: DEFAULT_LOW_FEE_REBATE_BPS,
            max_oracle_deviation_bps: DEFAULT_MAX_ORACLE_DEVIATION_BPS,
            confidence_floor_bps: DEFAULT_CONFIDENCE_FLOOR_BPS,
            leakage_budget_units: DEFAULT_LEAKAGE_BUDGET_UNITS,
        }
    }
}

impl Config {
    pub fn validate(&self) -> Result<()> {
        ensure(!self.chain_id.is_empty(), "chain id is empty")?;
        ensure(
            self.protocol_version == PROTOCOL_VERSION,
            "protocol version mismatch",
        )?;
        ensure(
            self.schema_version == SCHEMA_VERSION,
            "schema version mismatch",
        )?;
        ensure(self.min_pq_security_bits >= 192, "pq security below floor")?;
        ensure(self.min_privacy_set_size > 0, "privacy set is empty")?;
        ensure(self.surface_ttl_blocks > 0, "surface ttl is zero")?;
        ensure(self.node_ttl_blocks > 0, "node ttl is zero")?;
        ensure(self.batch_ttl_blocks > 0, "batch ttl is zero")?;
        ensure(self.max_user_fee_bps <= MAX_BPS, "user fee cap above max")?;
        ensure(
            self.low_fee_rebate_bps <= self.max_user_fee_bps,
            "rebate above user cap",
        )?;
        ensure(
            self.max_oracle_deviation_bps <= MAX_BPS,
            "deviation above max",
        )?;
        ensure(self.confidence_floor_bps <= MAX_BPS, "confidence above max")?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "confidence_floor_bps": self.confidence_floor_bps,
            "fee_asset_id": self.fee_asset_id,
            "hash_suite": HASH_SUITE,
            "l2_network": self.l2_network,
            "leakage_budget_units": self.leakage_budget_units,
            "low_fee_batch_scheme": LOW_FEE_BATCH_SCHEME,
            "low_fee_rebate_bps": self.low_fee_rebate_bps,
            "max_oracle_deviation_bps": self.max_oracle_deviation_bps,
            "max_user_fee_bps": self.max_user_fee_bps,
            "min_pq_security_bits": self.min_pq_security_bits,
            "min_privacy_set_size": self.min_privacy_set_size,
            "monero_network": self.monero_network,
            "pq_oracle_suite": PQ_ORACLE_SUITE,
            "privacy_budget_scheme": PRIVACY_BUDGET_SCHEME,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "surface_commitment_scheme": SURFACE_COMMITMENT_SCHEME,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Counters {
    pub signers_registered: u64,
    pub surfaces_registered: u64,
    pub nodes_submitted: u64,
    pub guard_bands_opened: u64,
    pub low_fee_batches_opened: u64,
    pub low_fee_batches_settled: u64,
    pub quarantined_updates: u64,
    pub public_events: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub counters_root: String,
    pub signer_root: String,
    pub surface_root: String,
    pub node_root: String,
    pub guard_band_root: String,
    pub low_fee_batch_root: String,
    pub nullifier_root: String,
    pub event_root: String,
    pub state_root: String,
}

impl Default for Roots {
    fn default() -> Self {
        Self {
            config_root: empty_root("config"),
            counters_root: empty_root("counters"),
            signer_root: empty_root("signers"),
            surface_root: empty_root("surfaces"),
            node_root: empty_root("nodes"),
            guard_band_root: empty_root("guard_bands"),
            low_fee_batch_root: empty_root("low_fee_batches"),
            nullifier_root: empty_root("nullifiers"),
            event_root: empty_root("events"),
            state_root: empty_root("state"),
        }
    }
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OracleSignerRecord {
    pub signer_id: String,
    pub committee_id: String,
    pub pq_public_key_root: String,
    pub stake_weight: u64,
    pub privacy_set_size: u64,
    pub active: bool,
    pub registered_at_height: u64,
    pub signer_root: String,
}

impl OracleSignerRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "active": self.active,
            "committee_id": self.committee_id,
            "privacy_set_size": self.privacy_set_size,
            "registered_at_height": self.registered_at_height,
            "signer_id": self.signer_id,
            "signer_root": self.signer_root,
            "stake_weight": self.stake_weight,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct VolatilitySurfaceRecord {
    pub surface_id: String,
    pub market_id: String,
    pub base_asset_id: String,
    pub quote_asset_id: String,
    pub instrument_kind: InstrumentKind,
    pub status: SurfaceStatus,
    pub epoch: u64,
    pub created_at_height: u64,
    pub expires_at_height: u64,
    pub grid_commitment_root: String,
    pub confidence_band: ConfidenceBand,
    pub privacy_budget_remaining: u64,
    pub surface_root: String,
}

impl VolatilitySurfaceRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "base_asset_id": self.base_asset_id,
            "confidence_band": self.confidence_band.as_str(),
            "created_at_height": self.created_at_height,
            "epoch": self.epoch,
            "expires_at_height": self.expires_at_height,
            "grid_commitment_root": self.grid_commitment_root,
            "instrument_kind": self.instrument_kind.as_str(),
            "market_id": self.market_id,
            "privacy_budget_remaining": self.privacy_budget_remaining,
            "quote_asset_id": self.quote_asset_id,
            "status": self.status.as_str(),
            "surface_id": self.surface_id,
            "surface_root": self.surface_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct VolatilityNodeRecord {
    pub node_id: String,
    pub surface_id: String,
    pub tenor_bucket: u64,
    pub strike_bucket: u64,
    pub implied_vol_bps: u64,
    pub liquidity_depth_bucket: u64,
    pub confidence_bps: u64,
    pub signer_quorum_weight: u64,
    pub encrypted_observation_root: String,
    pub pq_attestation_root: String,
    pub submitted_at_height: u64,
    pub expires_at_height: u64,
    pub accepted: bool,
    pub node_root: String,
}

impl VolatilityNodeRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "accepted": self.accepted,
            "confidence_bps": self.confidence_bps,
            "encrypted_observation_root": self.encrypted_observation_root,
            "expires_at_height": self.expires_at_height,
            "implied_vol_bps": self.implied_vol_bps,
            "liquidity_depth_bucket": self.liquidity_depth_bucket,
            "node_id": self.node_id,
            "node_root": self.node_root,
            "pq_attestation_root": self.pq_attestation_root,
            "signer_quorum_weight": self.signer_quorum_weight,
            "strike_bucket": self.strike_bucket,
            "submitted_at_height": self.submitted_at_height,
            "surface_id": self.surface_id,
            "tenor_bucket": self.tenor_bucket,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct GuardBandRecord {
    pub guard_id: String,
    pub surface_id: String,
    pub previous_node_root: String,
    pub next_node_root: String,
    pub deviation_bps: u64,
    pub confidence_band: ConfidenceBand,
    pub action: String,
    pub opened_at_height: u64,
    pub guard_root: String,
}

impl GuardBandRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "action": self.action,
            "confidence_band": self.confidence_band.as_str(),
            "deviation_bps": self.deviation_bps,
            "guard_id": self.guard_id,
            "guard_root": self.guard_root,
            "next_node_root": self.next_node_root,
            "opened_at_height": self.opened_at_height,
            "previous_node_root": self.previous_node_root,
            "surface_id": self.surface_id,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LowFeeBatchRecord {
    pub batch_id: String,
    pub surface_ids: Vec<String>,
    pub node_ids: Vec<String>,
    pub coordinator_id: String,
    pub fee_bps: u64,
    pub rebate_bps: u64,
    pub recursive_proof_root: String,
    pub batch_status: BatchStatus,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub batch_root: String,
}

impl LowFeeBatchRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "batch_root": self.batch_root,
            "batch_status": self.batch_status.as_str(),
            "coordinator_id": self.coordinator_id,
            "expires_at_height": self.expires_at_height,
            "fee_bps": self.fee_bps,
            "node_root": list_root("batch_nodes", &self.node_ids),
            "opened_at_height": self.opened_at_height,
            "rebate_bps": self.rebate_bps,
            "surface_root": list_root("batch_surfaces", &self.surface_ids),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct EventRecord {
    pub event_id: String,
    pub kind: String,
    pub subject_id: String,
    pub height: u64,
    pub root: String,
}

impl EventRecord {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RegisterSignerRequest {
    pub signer_id: String,
    pub committee_id: String,
    pub pq_public_key_root: String,
    pub stake_weight: u64,
    pub privacy_set_size: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RegisterSurfaceRequest {
    pub surface_id: String,
    pub market_id: String,
    pub base_asset_id: String,
    pub quote_asset_id: String,
    pub instrument_kind: InstrumentKind,
    pub grid_commitment_root: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SubmitNodeRequest {
    pub node_id: String,
    pub surface_id: String,
    pub tenor_bucket: u64,
    pub strike_bucket: u64,
    pub implied_vol_bps: u64,
    pub liquidity_depth_bucket: u64,
    pub confidence_bps: u64,
    pub signer_ids: Vec<String>,
    pub encrypted_observation_root: String,
    pub pq_attestation_root: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OpenBatchRequest {
    pub batch_id: String,
    pub surface_ids: Vec<String>,
    pub node_ids: Vec<String>,
    pub coordinator_id: String,
    pub fee_bps: u64,
    pub recursive_proof_root: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub height: u64,
    pub epoch: u64,
    pub counters: Counters,
    pub roots: Roots,
    pub signers: BTreeMap<String, OracleSignerRecord>,
    pub surfaces: BTreeMap<String, VolatilitySurfaceRecord>,
    pub nodes: BTreeMap<String, VolatilityNodeRecord>,
    pub guard_bands: BTreeMap<String, GuardBandRecord>,
    pub low_fee_batches: BTreeMap<String, LowFeeBatchRecord>,
    pub nullifiers: BTreeSet<String>,
    pub events: VecDeque<EventRecord>,
}

impl Default for State {
    fn default() -> Self {
        Self::new(Config::default(), DEVNET_HEIGHT, DEVNET_EPOCH)
    }
}

impl State {
    pub fn new(config: Config, height: u64, epoch: u64) -> Self {
        let mut state = Self {
            config,
            height,
            epoch,
            counters: Counters::default(),
            roots: Roots::default(),
            signers: BTreeMap::new(),
            surfaces: BTreeMap::new(),
            nodes: BTreeMap::new(),
            guard_bands: BTreeMap::new(),
            low_fee_batches: BTreeMap::new(),
            nullifiers: BTreeSet::new(),
            events: VecDeque::new(),
        };
        state.refresh_roots();
        state
    }

    pub fn register_signer(&mut self, request: RegisterSignerRequest) -> Result<String> {
        self.config.validate()?;
        ensure(!request.signer_id.trim().is_empty(), "signer id is empty")?;
        ensure(
            !request.committee_id.trim().is_empty(),
            "committee id is empty",
        )?;
        ensure(
            is_root(&request.pq_public_key_root),
            "pq public key root is malformed",
        )?;
        ensure(request.stake_weight > 0, "stake weight is zero")?;
        ensure(
            request.privacy_set_size >= self.config.min_privacy_set_size,
            "signer privacy set below floor",
        )?;
        ensure(self.signers.len() < MAX_SIGNERS, "signer capacity reached")?;
        ensure(
            !self.signers.contains_key(&request.signer_id),
            "signer already exists",
        )?;

        let signer_root = record_root(
            "signer",
            &json!({
                "committee_id": request.committee_id,
                "pq_public_key_root": request.pq_public_key_root,
                "privacy_set_size": request.privacy_set_size,
                "signer_id": request.signer_id,
                "stake_weight": request.stake_weight,
            }),
        );
        let record = OracleSignerRecord {
            signer_id: request.signer_id,
            committee_id: request.committee_id,
            pq_public_key_root: request.pq_public_key_root,
            stake_weight: request.stake_weight,
            privacy_set_size: request.privacy_set_size,
            active: true,
            registered_at_height: self.height,
            signer_root,
        };
        let signer_id = record.signer_id.clone();
        self.signers.insert(signer_id.clone(), record);
        self.counters.signers_registered = self.counters.signers_registered.saturating_add(1);
        self.push_event("signer_registered", &signer_id);
        self.refresh_roots();
        Ok(signer_id)
    }

    pub fn register_surface(&mut self, request: RegisterSurfaceRequest) -> Result<String> {
        self.config.validate()?;
        ensure(
            self.surfaces.len() < MAX_SURFACES,
            "surface capacity reached",
        )?;
        ensure(
            !self.surfaces.contains_key(&request.surface_id),
            "surface already exists",
        )?;
        ensure(!request.market_id.trim().is_empty(), "market id is empty")?;
        ensure(
            !request.base_asset_id.trim().is_empty(),
            "base asset id is empty",
        )?;
        ensure(
            !request.quote_asset_id.trim().is_empty(),
            "quote asset id is empty",
        )?;
        ensure(
            is_root(&request.grid_commitment_root),
            "grid commitment root is malformed",
        )?;

        let surface_root = record_root(
            "surface",
            &json!({
                "base_asset_id": request.base_asset_id,
                "grid_commitment_root": request.grid_commitment_root,
                "instrument_kind": request.instrument_kind.as_str(),
                "market_id": request.market_id,
                "quote_asset_id": request.quote_asset_id,
                "surface_id": request.surface_id,
            }),
        );
        let record = VolatilitySurfaceRecord {
            surface_id: request.surface_id,
            market_id: request.market_id,
            base_asset_id: request.base_asset_id,
            quote_asset_id: request.quote_asset_id,
            instrument_kind: request.instrument_kind,
            status: SurfaceStatus::Draft,
            epoch: self.epoch,
            created_at_height: self.height,
            expires_at_height: self.height.saturating_add(self.config.surface_ttl_blocks),
            grid_commitment_root: request.grid_commitment_root,
            confidence_band: ConfidenceBand::Watch,
            privacy_budget_remaining: self.config.leakage_budget_units,
            surface_root,
        };
        let surface_id = record.surface_id.clone();
        self.surfaces.insert(surface_id.clone(), record);
        self.counters.surfaces_registered = self.counters.surfaces_registered.saturating_add(1);
        self.push_event("surface_registered", &surface_id);
        self.refresh_roots();
        Ok(surface_id)
    }

    pub fn submit_node(&mut self, request: SubmitNodeRequest) -> Result<String> {
        self.config.validate()?;
        ensure(self.nodes.len() < MAX_NODES, "node capacity reached")?;
        ensure(
            !self.nodes.contains_key(&request.node_id),
            "node already exists",
        )?;
        ensure(
            is_root(&request.encrypted_observation_root),
            "observation root is malformed",
        )?;
        ensure(
            is_root(&request.pq_attestation_root),
            "attestation root is malformed",
        )?;
        ensure(request.confidence_bps <= MAX_BPS, "confidence above max")?;
        ensure(
            request.implied_vol_bps <= MAX_BPS.saturating_mul(5),
            "implied vol above bound",
        )?;
        ensure(!request.signer_ids.is_empty(), "signer quorum is empty")?;

        let surface = self
            .surfaces
            .get(&request.surface_id)
            .ok_or_else(|| format!("unknown surface {}", request.surface_id))?;
        ensure(
            surface.status.accepts_updates(),
            "surface does not accept updates",
        )?;

        let mut signer_weight = 0_u64;
        for signer_id in &request.signer_ids {
            let signer = self
                .signers
                .get(signer_id)
                .ok_or_else(|| format!("unknown signer {signer_id}"))?;
            ensure(signer.active, "signer is inactive")?;
            signer_weight = signer_weight.saturating_add(signer.stake_weight);
        }

        let accepted = request.confidence_bps >= self.config.confidence_floor_bps;
        let band = ConfidenceBand::from_bps(request.confidence_bps);
        let node_root = record_root(
            "surface_node",
            &json!({
                "confidence_bps": request.confidence_bps,
                "encrypted_observation_root": request.encrypted_observation_root,
                "implied_vol_bps": request.implied_vol_bps,
                "liquidity_depth_bucket": request.liquidity_depth_bucket,
                "node_id": request.node_id,
                "pq_attestation_root": request.pq_attestation_root,
                "signer_quorum_weight": signer_weight,
                "strike_bucket": request.strike_bucket,
                "surface_id": request.surface_id,
                "tenor_bucket": request.tenor_bucket,
            }),
        );
        let record = VolatilityNodeRecord {
            node_id: request.node_id,
            surface_id: request.surface_id,
            tenor_bucket: request.tenor_bucket,
            strike_bucket: request.strike_bucket,
            implied_vol_bps: request.implied_vol_bps,
            liquidity_depth_bucket: request.liquidity_depth_bucket,
            confidence_bps: request.confidence_bps,
            signer_quorum_weight: signer_weight,
            encrypted_observation_root: request.encrypted_observation_root,
            pq_attestation_root: request.pq_attestation_root,
            submitted_at_height: self.height,
            expires_at_height: self.height.saturating_add(self.config.node_ttl_blocks),
            accepted,
            node_root,
        };
        let node_id = record.node_id.clone();
        let surface_id = record.surface_id.clone();
        let node_root_for_guard = record.node_root.clone();
        self.nodes.insert(node_id.clone(), record);
        if !accepted {
            self.counters.quarantined_updates = self.counters.quarantined_updates.saturating_add(1);
        }
        if let Some(surface) = self.surfaces.get_mut(&surface_id) {
            surface.confidence_band = band;
            surface.status = if band.usable() {
                SurfaceStatus::Active
            } else {
                SurfaceStatus::Guarded
            };
            surface.surface_root = record_root("surface_after_node", &surface.public_record());
        }
        self.maybe_open_guard_band(&surface_id, &node_root_for_guard, request.confidence_bps)?;
        self.counters.nodes_submitted = self.counters.nodes_submitted.saturating_add(1);
        self.push_event("volatility_node_submitted", &node_id);
        self.refresh_roots();
        Ok(node_id)
    }

    pub fn open_low_fee_batch(&mut self, request: OpenBatchRequest) -> Result<String> {
        self.config.validate()?;
        ensure(
            self.low_fee_batches.len() < MAX_BATCHES,
            "batch capacity reached",
        )?;
        ensure(
            !self.low_fee_batches.contains_key(&request.batch_id),
            "batch already exists",
        )?;
        ensure(!request.surface_ids.is_empty(), "surface batch is empty")?;
        ensure(!request.node_ids.is_empty(), "node batch is empty")?;
        ensure(
            !request.coordinator_id.trim().is_empty(),
            "coordinator id is empty",
        )?;
        ensure(
            is_root(&request.recursive_proof_root),
            "recursive proof root is malformed",
        )?;
        ensure(
            request.fee_bps <= self.config.max_user_fee_bps,
            "fee above cap",
        )?;
        for surface_id in &request.surface_ids {
            ensure(
                self.surfaces.contains_key(surface_id),
                "unknown surface in batch",
            )?;
        }
        for node_id in &request.node_ids {
            ensure(self.nodes.contains_key(node_id), "unknown node in batch")?;
        }
        let batch_root = record_root(
            "low_fee_batch",
            &json!({
                "batch_id": request.batch_id,
                "coordinator_id": request.coordinator_id,
                "fee_bps": request.fee_bps,
                "node_root": list_root("batch_node_ids", &request.node_ids),
                "recursive_proof_root": request.recursive_proof_root,
                "surface_root": list_root("batch_surface_ids", &request.surface_ids),
            }),
        );
        let record = LowFeeBatchRecord {
            batch_id: request.batch_id,
            surface_ids: request.surface_ids,
            node_ids: request.node_ids,
            coordinator_id: request.coordinator_id,
            fee_bps: request.fee_bps,
            rebate_bps: self.config.low_fee_rebate_bps,
            recursive_proof_root: request.recursive_proof_root,
            batch_status: BatchStatus::RootCommitted,
            opened_at_height: self.height,
            expires_at_height: self.height.saturating_add(self.config.batch_ttl_blocks),
            batch_root,
        };
        let batch_id = record.batch_id.clone();
        self.low_fee_batches.insert(batch_id.clone(), record);
        self.counters.low_fee_batches_opened =
            self.counters.low_fee_batches_opened.saturating_add(1);
        self.push_event("low_fee_volatility_batch_opened", &batch_id);
        self.refresh_roots();
        Ok(batch_id)
    }

    pub fn settle_low_fee_batch(&mut self, batch_id: &str, settlement_root: &str) -> Result<()> {
        ensure(is_root(settlement_root), "settlement root is malformed")?;
        let batch = self
            .low_fee_batches
            .get_mut(batch_id)
            .ok_or_else(|| format!("unknown batch {batch_id}"))?;
        ensure(batch.batch_status.live(), "batch is not live")?;
        batch.batch_status = BatchStatus::Settled;
        batch.batch_root = record_root(
            "low_fee_batch_settlement",
            &json!({
                "batch_id": batch.batch_id,
                "previous_root": batch.batch_root,
                "settlement_root": settlement_root,
            }),
        );
        self.counters.low_fee_batches_settled =
            self.counters.low_fee_batches_settled.saturating_add(1);
        self.push_event("low_fee_volatility_batch_settled", batch_id);
        self.refresh_roots();
        Ok(())
    }

    pub fn refresh_roots(&mut self) {
        self.roots.config_root = record_root("config", &self.config.public_record());
        self.roots.counters_root = record_root("counters", &self.counters.public_record());
        self.roots.signer_root = map_root("signers", &self.signers);
        self.roots.surface_root = map_root("surfaces", &self.surfaces);
        self.roots.node_root = map_root("nodes", &self.nodes);
        self.roots.guard_band_root = map_root("guard_bands", &self.guard_bands);
        self.roots.low_fee_batch_root = map_root("low_fee_batches", &self.low_fee_batches);
        self.roots.nullifier_root = set_root("nullifiers", &self.nullifiers);
        let event_values = self
            .events
            .iter()
            .map(EventRecord::public_record)
            .collect::<Vec<_>>();
        self.roots.event_root = merkle_root("volatility_surface_events", &event_values);
        self.roots.state_root = domain_hash(
            "volatility_surface_state",
            &[
                HashPart::Str(&self.roots.config_root),
                HashPart::Str(&self.roots.counters_root),
                HashPart::Str(&self.roots.signer_root),
                HashPart::Str(&self.roots.surface_root),
                HashPart::Str(&self.roots.node_root),
                HashPart::Str(&self.roots.guard_band_root),
                HashPart::Str(&self.roots.low_fee_batch_root),
                HashPart::Str(&self.roots.nullifier_root),
                HashPart::Str(&self.roots.event_root),
                HashPart::U64(self.height),
                HashPart::U64(self.epoch),
            ],
            32,
        );
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.config.chain_id,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "epoch": self.epoch,
            "height": self.height,
            "limits": {
                "max_batches": MAX_BATCHES,
                "max_guard_bands": MAX_GUARD_BANDS,
                "max_nodes": MAX_NODES,
                "max_signers": MAX_SIGNERS,
                "max_surfaces": MAX_SURFACES,
            },
            "protocol_version": PROTOCOL_VERSION,
            "roots": self.roots.public_record(),
        })
    }

    pub fn state_root(&self) -> String {
        self.roots.state_root.clone()
    }

    fn maybe_open_guard_band(
        &mut self,
        surface_id: &str,
        node_root: &str,
        confidence_bps: u64,
    ) -> Result<()> {
        let previous = self
            .nodes
            .values()
            .rev()
            .find(|node| node.surface_id == surface_id && node.node_root != node_root)
            .map(|node| node.node_root.clone())
            .unwrap_or_else(|| empty_root("previous_surface_node"));
        let deviation_bps = if confidence_bps >= self.config.confidence_floor_bps {
            confidence_bps.saturating_sub(self.config.confidence_floor_bps)
        } else {
            self.config
                .confidence_floor_bps
                .saturating_sub(confidence_bps)
        };
        if deviation_bps <= self.config.max_oracle_deviation_bps
            && confidence_bps >= self.config.confidence_floor_bps
        {
            return Ok(());
        }
        ensure(
            self.guard_bands.len() < MAX_GUARD_BANDS,
            "guard band capacity reached",
        )?;
        let guard_id = deterministic_id(
            "guard",
            &[
                HashPart::Str(surface_id),
                HashPart::Str(node_root),
                HashPart::U64(self.counters.guard_bands_opened.saturating_add(1)),
            ],
        );
        let band = ConfidenceBand::from_bps(confidence_bps);
        let action = if band.usable() {
            "deviation_review"
        } else {
            "quarantine_surface"
        }
        .to_string();
        let guard_root = record_root(
            "guard_band",
            &json!({
                "action": action,
                "confidence_bps": confidence_bps,
                "deviation_bps": deviation_bps,
                "next_node_root": node_root,
                "previous_node_root": previous,
                "surface_id": surface_id,
            }),
        );
        let record = GuardBandRecord {
            guard_id: guard_id.clone(),
            surface_id: surface_id.to_string(),
            previous_node_root: previous,
            next_node_root: node_root.to_string(),
            deviation_bps,
            confidence_band: band,
            action,
            opened_at_height: self.height,
            guard_root,
        };
        if let Some(surface) = self.surfaces.get_mut(surface_id) {
            surface.status = SurfaceStatus::Guarded;
        }
        self.guard_bands.insert(guard_id.clone(), record);
        self.counters.guard_bands_opened = self.counters.guard_bands_opened.saturating_add(1);
        self.push_event("volatility_guard_band_opened", &guard_id);
        Ok(())
    }

    fn push_event(&mut self, kind: &str, subject_id: &str) {
        if self.events.len() >= MAX_EVENTS {
            let _ = self.events.pop_front();
        }
        let root = domain_hash(
            "volatility_surface_event",
            &[
                HashPart::Str(kind),
                HashPart::Str(subject_id),
                HashPart::U64(self.height),
                HashPart::U64(self.counters.public_events.saturating_add(1)),
            ],
            32,
        );
        let event_id = deterministic_id(
            "event",
            &[
                HashPart::Str(kind),
                HashPart::Str(subject_id),
                HashPart::Str(&root),
            ],
        );
        self.events.push_back(EventRecord {
            event_id,
            kind: kind.to_string(),
            subject_id: subject_id.to_string(),
            height: self.height,
            root,
        });
        self.counters.public_events = self.counters.public_events.saturating_add(1);
    }
}

pub fn devnet() -> State {
    State::default()
}

pub fn demo() -> State {
    let mut state = devnet();
    let _ = state.register_signer(RegisterSignerRequest {
        signer_id: "vol-oracle-signer-a".to_string(),
        committee_id: "vol-oracle-committee-devnet".to_string(),
        pq_public_key_root: deterministic_id("pq-key", &[HashPart::Str("signer-a")]),
        stake_weight: 40_000,
        privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE.saturating_mul(2),
    });
    let _ = state.register_signer(RegisterSignerRequest {
        signer_id: "vol-oracle-signer-b".to_string(),
        committee_id: "vol-oracle-committee-devnet".to_string(),
        pq_public_key_root: deterministic_id("pq-key", &[HashPart::Str("signer-b")]),
        stake_weight: 38_000,
        privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE.saturating_mul(2),
    });
    let _ = state.register_surface(RegisterSurfaceRequest {
        surface_id: "xmr-usd-options-surface".to_string(),
        market_id: "xmr-usd-private-options".to_string(),
        base_asset_id: "wxmr-devnet".to_string(),
        quote_asset_id: "dusd-devnet".to_string(),
        instrument_kind: InstrumentKind::OptionCall,
        grid_commitment_root: deterministic_id("grid", &[HashPart::Str("xmr-usd-options")]),
    });
    let _ = state.submit_node(SubmitNodeRequest {
        node_id: "xmr-usd-node-30d-atm".to_string(),
        surface_id: "xmr-usd-options-surface".to_string(),
        tenor_bucket: 30,
        strike_bucket: 100,
        implied_vol_bps: 7_500,
        liquidity_depth_bucket: 2_048,
        confidence_bps: 8_800,
        signer_ids: vec![
            "vol-oracle-signer-a".to_string(),
            "vol-oracle-signer-b".to_string(),
        ],
        encrypted_observation_root: deterministic_id("observation", &[HashPart::Str("30d-atm")]),
        pq_attestation_root: deterministic_id("attestation", &[HashPart::Str("30d-atm")]),
    });
    let _ = state.open_low_fee_batch(OpenBatchRequest {
        batch_id: "vol-surface-batch-0".to_string(),
        surface_ids: vec!["xmr-usd-options-surface".to_string()],
        node_ids: vec!["xmr-usd-node-30d-atm".to_string()],
        coordinator_id: "low-fee-oracle-coordinator".to_string(),
        fee_bps: DEFAULT_MAX_USER_FEE_BPS,
        recursive_proof_root: deterministic_id("recursive-proof", &[HashPart::Str("batch-0")]),
    });
    let _ = state.settle_low_fee_batch(
        "vol-surface-batch-0",
        &deterministic_id("settlement", &[HashPart::Str("batch-0")]),
    );
    state.refresh_roots();
    state
}

fn ensure(condition: bool, message: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(message.to_string())
    }
}

fn is_root(value: &str) -> bool {
    !value.trim().is_empty() && value.len() <= 256
}

fn deterministic_id(domain: &str, parts: &[HashPart<'_>]) -> String {
    domain_hash(
        &format!("private_l2_pq_confidential_defi_oracle_volatility_surface_runtime/{domain}"),
        parts,
        32,
    )
}

fn record_root(domain: &str, value: &Value) -> String {
    deterministic_id(domain, &[HashPart::Str(CHAIN_ID), HashPart::Json(value)])
}

fn empty_root(domain: &str) -> String {
    merkle_root(
        &format!("private_l2_pq_confidential_defi_oracle_volatility_surface_runtime/{domain}"),
        &[],
    )
}

fn map_root<T: Serialize>(domain: &str, map: &BTreeMap<String, T>) -> String {
    let records = map
        .iter()
        .map(|(key, value)| {
            json!({
                "key": key,
                "value": value,
            })
        })
        .collect::<Vec<_>>();
    merkle_root(
        &format!("private_l2_pq_confidential_defi_oracle_volatility_surface_runtime/{domain}"),
        &records,
    )
}

fn set_root(domain: &str, set: &BTreeSet<String>) -> String {
    let records = set
        .iter()
        .map(|value| json!({ "value": value }))
        .collect::<Vec<_>>();
    merkle_root(
        &format!("private_l2_pq_confidential_defi_oracle_volatility_surface_runtime/{domain}"),
        &records,
    )
}

fn list_root(domain: &str, values: &[String]) -> String {
    let records = values
        .iter()
        .enumerate()
        .map(|(index, value)| {
            json!({
                "index": index,
                "value": value,
            })
        })
        .collect::<Vec<_>>();
    merkle_root(
        &format!("private_l2_pq_confidential_defi_oracle_volatility_surface_runtime/{domain}"),
        &records,
    )
}
