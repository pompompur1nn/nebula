use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type Runtime = State;

pub const PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-confidential-runtime-readiness-scoreboard-v1";
pub const SCHEMA_VERSION: u64 = 1;
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_L2_HEIGHT: u64 = 2_048_000;
pub const DEFAULT_MONERO_HEIGHT: u64 = 3_720_000;
pub const DEFAULT_MIN_RELEASE_SCORE_BPS: u64 = 9_250;
pub const DEFAULT_MIN_CATEGORY_SCORE_BPS: u64 = 8_750;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_MAX_CRITICAL_RISK_FLAGS: usize = 0;
pub const DEFAULT_MAX_HIGH_RISK_FLAGS: usize = 2;
pub const DEFAULT_LOW_FEE_TARGET_BPS: u64 = 18;
pub const DEFAULT_SPEED_TARGET_MS: u64 = 750;
pub const MAX_COMPONENTS: usize = 128;
pub const MAX_FEATURES: usize = 256;
pub const MAX_RISK_FLAGS: usize = 128;
pub const MAX_ROOTS: usize = 256;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    QuantumResistance,
    Speed,
    Defi,
    LowFee,
    Privacy,
    MoneroBridge,
}

impl Category {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::QuantumResistance => "quantum_resistance",
            Self::Speed => "speed",
            Self::Defi => "defi",
            Self::LowFee => "low_fee",
            Self::Privacy => "privacy",
            Self::MoneroBridge => "monero_bridge",
        }
    }

    pub fn release_weight_bps(self) -> u64 {
        match self {
            Self::QuantumResistance => 2_000,
            Self::Speed => 1_500,
            Self::Defi => 1_500,
            Self::LowFee => 1_250,
            Self::Privacy => 1_750,
            Self::MoneroBridge => 2_000,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ComponentKind {
    Sequencer,
    Prover,
    ContractRuntime,
    FeeMarket,
    DefiRouter,
    PrivacyPool,
    PqCommittee,
    MoneroBridge,
    Watchtower,
    OperatorRunbook,
}

impl ComponentKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sequencer => "sequencer",
            Self::Prover => "prover",
            Self::ContractRuntime => "contract_runtime",
            Self::FeeMarket => "fee_market",
            Self::DefiRouter => "defi_router",
            Self::PrivacyPool => "privacy_pool",
            Self::PqCommittee => "pq_committee",
            Self::MoneroBridge => "monero_bridge",
            Self::Watchtower => "watchtower",
            Self::OperatorRunbook => "operator_runbook",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FeatureStatus {
    Planned,
    Implemented,
    Tested,
    Audited,
    Released,
    Waived,
}

impl FeatureStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Planned => "planned",
            Self::Implemented => "implemented",
            Self::Tested => "tested",
            Self::Audited => "audited",
            Self::Released => "released",
            Self::Waived => "waived",
        }
    }

    pub fn completion_bps(self) -> u64 {
        match self {
            Self::Planned => 0,
            Self::Implemented => 5_000,
            Self::Tested => 7_500,
            Self::Audited => 9_000,
            Self::Released | Self::Waived => MAX_BPS,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskSeverity {
    Low,
    Medium,
    High,
    Critical,
}

impl RiskSeverity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }

    pub fn penalty_bps(self) -> u64 {
        match self {
            Self::Low => 100,
            Self::Medium => 400,
            Self::High => 1_000,
            Self::Critical => 2_500,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub min_release_score_bps: u64,
    pub min_category_score_bps: u64,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub max_critical_risk_flags: usize,
    pub max_high_risk_flags: usize,
    pub low_fee_target_bps: u64,
    pub speed_target_ms: u64,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            min_release_score_bps: DEFAULT_MIN_RELEASE_SCORE_BPS,
            min_category_score_bps: DEFAULT_MIN_CATEGORY_SCORE_BPS,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            max_critical_risk_flags: DEFAULT_MAX_CRITICAL_RISK_FLAGS,
            max_high_risk_flags: DEFAULT_MAX_HIGH_RISK_FLAGS,
            low_fee_target_bps: DEFAULT_LOW_FEE_TARGET_BPS,
            speed_target_ms: DEFAULT_SPEED_TARGET_MS,
        }
    }

    pub fn validate(&self) -> Result<()> {
        require(!self.chain_id.is_empty(), "chain id cannot be empty")?;
        require(
            self.protocol_version == PROTOCOL_VERSION,
            "protocol version mismatch",
        )?;
        require(
            self.min_release_score_bps <= MAX_BPS,
            "release score exceeds max bps",
        )?;
        require(
            self.min_category_score_bps <= MAX_BPS,
            "category score exceeds max bps",
        )?;
        require(
            self.min_pq_security_bits >= 192,
            "pq security bits below floor",
        )?;
        require(
            self.min_privacy_set_size >= 128,
            "privacy set size below floor",
        )?;
        require(
            self.low_fee_target_bps > 0,
            "low fee target must be positive",
        )?;
        require(self.speed_target_ms > 0, "speed target must be positive")
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "min_release_score_bps": self.min_release_score_bps,
            "min_category_score_bps": self.min_category_score_bps,
            "min_pq_security_bits": self.min_pq_security_bits,
            "min_privacy_set_size": self.min_privacy_set_size,
            "max_critical_risk_flags": self.max_critical_risk_flags,
            "max_high_risk_flags": self.max_high_risk_flags,
            "low_fee_target_bps": self.low_fee_target_bps,
            "speed_target_ms": self.speed_target_ms,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub components: u64,
    pub completed_features: u64,
    pub total_features: u64,
    pub open_risk_flags: u64,
    pub high_risk_flags: u64,
    pub critical_risk_flags: u64,
    pub pq_components: u64,
    pub privacy_components: u64,
    pub monero_bridge_components: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "components": self.components,
            "completed_features": self.completed_features,
            "total_features": self.total_features,
            "open_risk_flags": self.open_risk_flags,
            "high_risk_flags": self.high_risk_flags,
            "critical_risk_flags": self.critical_risk_flags,
            "pq_components": self.pq_components,
            "privacy_components": self.privacy_components,
            "monero_bridge_components": self.monero_bridge_components,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub component_root: String,
    pub feature_root: String,
    pub risk_flag_root: String,
    pub category_score_root: String,
    pub counter_root: String,
    pub scoreboard_root: String,
}

impl Roots {
    pub fn empty() -> Self {
        let counter_root = domain_hash(
            "PRIVATE-L2-PQ-RUNTIME-READINESS-COUNTERS",
            &[HashPart::Json(&Counters::default().public_record())],
            32,
        );
        let mut roots = Self {
            component_root: merkle_root("PRIVATE-L2-PQ-RUNTIME-READINESS-COMPONENT", &[]),
            feature_root: merkle_root("PRIVATE-L2-PQ-RUNTIME-READINESS-FEATURE", &[]),
            risk_flag_root: merkle_root("PRIVATE-L2-PQ-RUNTIME-READINESS-RISK-FLAG", &[]),
            category_score_root: merkle_root("PRIVATE-L2-PQ-RUNTIME-READINESS-CATEGORY-SCORE", &[]),
            counter_root,
            scoreboard_root: String::new(),
        };
        roots.scoreboard_root = roots.root();
        roots
    }

    pub fn root(&self) -> String {
        domain_hash(
            "PRIVATE-L2-PQ-RUNTIME-READINESS-ROOTS",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&self.component_root),
                HashPart::Str(&self.feature_root),
                HashPart::Str(&self.risk_flag_root),
                HashPart::Str(&self.category_score_root),
                HashPart::Str(&self.counter_root),
            ],
            32,
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "component_root": self.component_root,
            "feature_root": self.feature_root,
            "risk_flag_root": self.risk_flag_root,
            "category_score_root": self.category_score_root,
            "counter_root": self.counter_root,
            "scoreboard_root": self.scoreboard_root,
        })
    }
}

impl Default for Roots {
    fn default() -> Self {
        Self::empty()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ComponentReadiness {
    pub component_id: String,
    pub kind: ComponentKind,
    pub category: Category,
    pub root: String,
    pub score_bps: u64,
    pub pq_security_bits: u16,
    pub privacy_set_size: u64,
    pub median_latency_ms: u64,
    pub fee_bps: u64,
    pub monero_bridge_bound: bool,
}

impl ComponentReadiness {
    pub fn validate(&self, config: &Config) -> Result<()> {
        require(
            !self.component_id.is_empty(),
            "component id cannot be empty",
        )?;
        require(!self.root.is_empty(), "component root cannot be empty")?;
        require(self.score_bps <= MAX_BPS, "component score exceeds max bps")?;
        if matches!(self.category, Category::QuantumResistance) {
            require(
                self.pq_security_bits >= config.min_pq_security_bits,
                "pq component below security floor",
            )?;
        }
        if matches!(self.category, Category::Privacy) {
            require(
                self.privacy_set_size >= config.min_privacy_set_size,
                "privacy component below anonymity floor",
            )?;
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "component_id": self.component_id,
            "kind": self.kind.as_str(),
            "category": self.category.as_str(),
            "root": self.root,
            "score_bps": self.score_bps,
            "pq_security_bits": self.pq_security_bits,
            "privacy_set_size": self.privacy_set_size,
            "median_latency_ms": self.median_latency_ms,
            "fee_bps": self.fee_bps,
            "monero_bridge_bound": self.monero_bridge_bound,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FeatureCompletion {
    pub feature_id: String,
    pub category: Category,
    pub status: FeatureStatus,
    pub evidence_root: String,
}

impl FeatureCompletion {
    pub fn validate(&self) -> Result<()> {
        require(!self.feature_id.is_empty(), "feature id cannot be empty")?;
        require(
            !self.evidence_root.is_empty(),
            "feature evidence root cannot be empty",
        )
    }

    pub fn complete(&self) -> bool {
        self.status.completion_bps() >= MAX_BPS
    }

    pub fn public_record(&self) -> Value {
        json!({
            "feature_id": self.feature_id,
            "category": self.category.as_str(),
            "status": self.status.as_str(),
            "completion_bps": self.status.completion_bps(),
            "evidence_root": self.evidence_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskFlag {
    pub flag_id: String,
    pub category: Category,
    pub severity: RiskSeverity,
    pub open: bool,
    pub evidence_root: String,
    pub owner: String,
}

impl RiskFlag {
    pub fn validate(&self) -> Result<()> {
        require(!self.flag_id.is_empty(), "risk flag id cannot be empty")?;
        require(
            !self.evidence_root.is_empty(),
            "risk flag evidence root cannot be empty",
        )?;
        require(!self.owner.is_empty(), "risk flag owner cannot be empty")
    }

    pub fn public_record(&self) -> Value {
        json!({
            "flag_id": self.flag_id,
            "category": self.category.as_str(),
            "severity": self.severity.as_str(),
            "open": self.open,
            "evidence_root": self.evidence_root,
            "owner": self.owner,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ScoreBreakdown {
    pub category_scores: BTreeMap<Category, u64>,
    pub feature_completion_bps: u64,
    pub risk_penalty_bps: u64,
    pub overall_score_bps: u64,
    pub release_ready: bool,
    pub blocking_reasons: BTreeSet<String>,
}

impl ScoreBreakdown {
    pub fn public_record(&self) -> Value {
        json!({
            "category_scores": self.category_scores.iter().map(|(category, score)| {
                json!({"category": category.as_str(), "score_bps": score})
            }).collect::<Vec<_>>(),
            "feature_completion_bps": self.feature_completion_bps,
            "risk_penalty_bps": self.risk_penalty_bps,
            "overall_score_bps": self.overall_score_bps,
            "release_ready": self.release_ready,
            "blocking_reasons": self.blocking_reasons.iter().cloned().collect::<Vec<_>>(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct IngestRequest {
    pub observed_l2_height: u64,
    pub observed_monero_height: u64,
    pub components: Vec<ComponentReadiness>,
    pub features: Vec<FeatureCompletion>,
    pub risk_flags: Vec<RiskFlag>,
    pub external_roots: BTreeMap<String, String>,
}

impl IngestRequest {
    pub fn validate(&self, config: &Config) -> Result<()> {
        require(
            self.components.len() <= MAX_COMPONENTS,
            "too many components",
        )?;
        require(self.features.len() <= MAX_FEATURES, "too many features")?;
        require(
            self.risk_flags.len() <= MAX_RISK_FLAGS,
            "too many risk flags",
        )?;
        require(
            self.external_roots.len() <= MAX_ROOTS,
            "too many external roots",
        )?;
        for component in &self.components {
            component.validate(config)?;
        }
        for feature in &self.features {
            feature.validate()?;
        }
        for flag in &self.risk_flags {
            flag.validate()?;
        }
        require(
            unique_component_ids(&self.components),
            "duplicate component id",
        )?;
        require(unique_feature_ids(&self.features), "duplicate feature id")?;
        require(
            unique_risk_flag_ids(&self.risk_flags),
            "duplicate risk flag id",
        )?;
        for (name, root) in &self.external_roots {
            require(!name.is_empty(), "external root name cannot be empty")?;
            require(!root.is_empty(), "external root cannot be empty")?;
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "observed_l2_height": self.observed_l2_height,
            "observed_monero_height": self.observed_monero_height,
            "components": self.components.iter().map(ComponentReadiness::public_record).collect::<Vec<_>>(),
            "features": self.features.iter().map(FeatureCompletion::public_record).collect::<Vec<_>>(),
            "risk_flags": self.risk_flags.iter().map(RiskFlag::public_record).collect::<Vec<_>>(),
            "external_roots": self.external_roots,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct UpdateRequest {
    pub component_updates: Vec<ComponentReadiness>,
    pub feature_updates: Vec<FeatureCompletion>,
    pub risk_flag_updates: Vec<RiskFlag>,
    pub external_roots: BTreeMap<String, String>,
    pub observed_l2_height: u64,
    pub observed_monero_height: u64,
}

impl UpdateRequest {
    pub fn validate(&self, config: &Config) -> Result<()> {
        require(
            self.component_updates.len() <= MAX_COMPONENTS,
            "too many component updates",
        )?;
        require(
            self.feature_updates.len() <= MAX_FEATURES,
            "too many feature updates",
        )?;
        require(
            self.risk_flag_updates.len() <= MAX_RISK_FLAGS,
            "too many risk flag updates",
        )?;
        require(
            self.external_roots.len() <= MAX_ROOTS,
            "too many external roots",
        )?;
        for component in &self.component_updates {
            component.validate(config)?;
        }
        for feature in &self.feature_updates {
            feature.validate()?;
        }
        for flag in &self.risk_flag_updates {
            flag.validate()?;
        }
        require(
            unique_component_ids(&self.component_updates),
            "duplicate component update id",
        )?;
        require(
            unique_feature_ids(&self.feature_updates),
            "duplicate feature update id",
        )?;
        require(
            unique_risk_flag_ids(&self.risk_flag_updates),
            "duplicate risk flag update id",
        )?;
        for (name, root) in &self.external_roots {
            require(!name.is_empty(), "external root name cannot be empty")?;
            require(!root.is_empty(), "external root cannot be empty")?;
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "component_updates": self.component_updates.iter().map(ComponentReadiness::public_record).collect::<Vec<_>>(),
            "feature_updates": self.feature_updates.iter().map(FeatureCompletion::public_record).collect::<Vec<_>>(),
            "risk_flag_updates": self.risk_flag_updates.iter().map(RiskFlag::public_record).collect::<Vec<_>>(),
            "external_roots": self.external_roots,
            "observed_l2_height": self.observed_l2_height,
            "observed_monero_height": self.observed_monero_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub observed_l2_height: u64,
    pub observed_monero_height: u64,
    pub components: BTreeMap<String, ComponentReadiness>,
    pub features: BTreeMap<String, FeatureCompletion>,
    pub risk_flags: BTreeMap<String, RiskFlag>,
    pub external_roots: BTreeMap<String, String>,
    pub counters: Counters,
    pub scores: ScoreBreakdown,
    pub roots: Roots,
}

impl State {
    pub fn new(config: Config) -> Result<Self> {
        config.validate()?;
        let mut state = Self {
            config,
            observed_l2_height: DEFAULT_L2_HEIGHT,
            observed_monero_height: DEFAULT_MONERO_HEIGHT,
            components: BTreeMap::new(),
            features: BTreeMap::new(),
            risk_flags: BTreeMap::new(),
            external_roots: BTreeMap::new(),
            counters: Counters::default(),
            scores: empty_scores(),
            roots: Roots::empty(),
        };
        state.recompute();
        Ok(state)
    }

    pub fn devnet() -> Self {
        match Self::from_ingest(Config::devnet(), demo_ingest_request()) {
            Ok(state) => state,
            Err(_) => {
                let config = Config::devnet();
                let mut state = Self {
                    config,
                    observed_l2_height: DEFAULT_L2_HEIGHT,
                    observed_monero_height: DEFAULT_MONERO_HEIGHT,
                    components: BTreeMap::new(),
                    features: BTreeMap::new(),
                    risk_flags: BTreeMap::new(),
                    external_roots: BTreeMap::new(),
                    counters: Counters::default(),
                    scores: empty_scores(),
                    roots: Roots::empty(),
                };
                state.recompute();
                state
            }
        }
    }

    pub fn from_ingest(config: Config, request: IngestRequest) -> Result<Self> {
        config.validate()?;
        request.validate(&config)?;
        let mut state = Self {
            config,
            observed_l2_height: request.observed_l2_height,
            observed_monero_height: request.observed_monero_height,
            components: request
                .components
                .into_iter()
                .map(|item| (item.component_id.clone(), item))
                .collect(),
            features: request
                .features
                .into_iter()
                .map(|item| (item.feature_id.clone(), item))
                .collect(),
            risk_flags: request
                .risk_flags
                .into_iter()
                .map(|item| (item.flag_id.clone(), item))
                .collect(),
            external_roots: request.external_roots,
            counters: Counters::default(),
            scores: empty_scores(),
            roots: Roots::empty(),
        };
        state.validate()?;
        state.recompute();
        Ok(state)
    }

    pub fn ingest(&mut self, request: IngestRequest) -> Result<()> {
        request.validate(&self.config)?;
        self.observed_l2_height = request.observed_l2_height;
        self.observed_monero_height = request.observed_monero_height;
        self.components = request
            .components
            .into_iter()
            .map(|item| (item.component_id.clone(), item))
            .collect();
        self.features = request
            .features
            .into_iter()
            .map(|item| (item.feature_id.clone(), item))
            .collect();
        self.risk_flags = request
            .risk_flags
            .into_iter()
            .map(|item| (item.flag_id.clone(), item))
            .collect();
        self.external_roots = request.external_roots;
        self.recompute();
        self.validate()
    }

    pub fn update(&mut self, request: UpdateRequest) -> Result<()> {
        request.validate(&self.config)?;
        self.observed_l2_height = request.observed_l2_height;
        self.observed_monero_height = request.observed_monero_height;
        for component in request.component_updates {
            self.components
                .insert(component.component_id.clone(), component);
        }
        for feature in request.feature_updates {
            self.features.insert(feature.feature_id.clone(), feature);
        }
        for flag in request.risk_flag_updates {
            self.risk_flags.insert(flag.flag_id.clone(), flag);
        }
        for (name, root) in request.external_roots {
            self.external_roots.insert(name, root);
        }
        self.recompute();
        self.validate()
    }

    pub fn validate(&self) -> Result<()> {
        self.config.validate()?;
        require(
            self.components.len() <= MAX_COMPONENTS,
            "too many components",
        )?;
        require(self.features.len() <= MAX_FEATURES, "too many features")?;
        require(
            self.risk_flags.len() <= MAX_RISK_FLAGS,
            "too many risk flags",
        )?;
        require(
            self.external_roots.len() <= MAX_ROOTS,
            "too many external roots",
        )?;
        for component in self.components.values() {
            component.validate(&self.config)?;
        }
        for feature in self.features.values() {
            feature.validate()?;
        }
        for flag in self.risk_flags.values() {
            flag.validate()?;
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "schema_version": SCHEMA_VERSION,
            "config": self.config.public_record(),
            "observed_l2_height": self.observed_l2_height,
            "observed_monero_height": self.observed_monero_height,
            "counters": self.counters.public_record(),
            "scores": self.scores.public_record(),
            "roots": self.roots.public_record(),
            "external_roots": self.external_roots,
        })
    }

    pub fn detailed_public_record(&self) -> Value {
        json!({
            "summary": self.public_record(),
            "components": self.components.values().map(ComponentReadiness::public_record).collect::<Vec<_>>(),
            "features": self.features.values().map(FeatureCompletion::public_record).collect::<Vec<_>>(),
            "risk_flags": self.risk_flags.values().map(RiskFlag::public_record).collect::<Vec<_>>(),
        })
    }

    pub fn root(&self) -> String {
        domain_hash(
            "PRIVATE-L2-PQ-RUNTIME-READINESS-SCOREBOARD",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }

    pub fn recompute(&mut self) {
        self.counters = compute_counters(&self.components, &self.features, &self.risk_flags);
        self.scores = score(
            &self.config,
            &self.components,
            &self.features,
            &self.risk_flags,
        );
        self.roots = compute_roots(
            &self.components,
            &self.features,
            &self.risk_flags,
            &self.counters,
            &self.scores,
        );
    }
}

pub fn component_root(components: &BTreeMap<String, ComponentReadiness>) -> String {
    merkle_root(
        "PRIVATE-L2-PQ-RUNTIME-READINESS-COMPONENT",
        &components
            .values()
            .map(ComponentReadiness::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn feature_root(features: &BTreeMap<String, FeatureCompletion>) -> String {
    merkle_root(
        "PRIVATE-L2-PQ-RUNTIME-READINESS-FEATURE",
        &features
            .values()
            .map(FeatureCompletion::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn risk_flag_root(flags: &BTreeMap<String, RiskFlag>) -> String {
    merkle_root(
        "PRIVATE-L2-PQ-RUNTIME-READINESS-RISK-FLAG",
        &flags
            .values()
            .map(RiskFlag::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn score(
    config: &Config,
    components: &BTreeMap<String, ComponentReadiness>,
    features: &BTreeMap<String, FeatureCompletion>,
    risk_flags: &BTreeMap<String, RiskFlag>,
) -> ScoreBreakdown {
    let mut category_scores = BTreeMap::new();
    for category in [
        Category::QuantumResistance,
        Category::Speed,
        Category::Defi,
        Category::LowFee,
        Category::Privacy,
        Category::MoneroBridge,
    ] {
        let values = components
            .values()
            .filter(|item| item.category == category)
            .map(|item| item.score_bps)
            .collect::<Vec<_>>();
        let base = match average_bps(&values) {
            Some(value) => value,
            None => 0,
        };
        category_scores.insert(category, base);
    }

    let feature_values = features
        .values()
        .map(|item| item.status.completion_bps())
        .collect::<Vec<_>>();
    let feature_completion_bps = match average_bps(&feature_values) {
        Some(value) => value,
        None => 0,
    };
    let risk_penalty_bps = risk_flags
        .values()
        .filter(|flag| flag.open)
        .map(|flag| flag.severity.penalty_bps())
        .sum::<u64>()
        .min(MAX_BPS);
    let weighted_total = category_scores
        .iter()
        .map(|(category, value)| value.saturating_mul(category.release_weight_bps()))
        .sum::<u64>()
        / MAX_BPS;
    let blended = weighted_total
        .saturating_mul(8)
        .saturating_add(feature_completion_bps.saturating_mul(2))
        / 10;
    let overall_score_bps = blended.saturating_sub(risk_penalty_bps).min(MAX_BPS);

    let mut blocking_reasons = BTreeSet::new();
    if overall_score_bps < config.min_release_score_bps {
        blocking_reasons.insert("overall_score_below_release_floor".to_string());
    }
    for (category, value) in &category_scores {
        if *value < config.min_category_score_bps {
            blocking_reasons.insert(format!("{}_score_below_floor", category.as_str()));
        }
    }
    let critical = risk_flags
        .values()
        .filter(|flag| flag.open && flag.severity == RiskSeverity::Critical)
        .count();
    let high = risk_flags
        .values()
        .filter(|flag| flag.open && flag.severity == RiskSeverity::High)
        .count();
    if critical > config.max_critical_risk_flags {
        blocking_reasons.insert("critical_risk_flag_budget_exceeded".to_string());
    }
    if high > config.max_high_risk_flags {
        blocking_reasons.insert("high_risk_flag_budget_exceeded".to_string());
    }

    ScoreBreakdown {
        category_scores,
        feature_completion_bps,
        risk_penalty_bps,
        overall_score_bps,
        release_ready: blocking_reasons.is_empty(),
        blocking_reasons,
    }
}

pub fn demo_ingest_request() -> IngestRequest {
    let components = vec![
        demo_component(
            "pq-committee",
            ComponentKind::PqCommittee,
            Category::QuantumResistance,
            9_700,
            256,
            65_536,
            220,
            5,
            false,
        ),
        demo_component(
            "fast-sequencer",
            ComponentKind::Sequencer,
            Category::Speed,
            9_300,
            256,
            65_536,
            410,
            7,
            false,
        ),
        demo_component(
            "defi-router",
            ComponentKind::DefiRouter,
            Category::Defi,
            9_100,
            256,
            65_536,
            560,
            11,
            false,
        ),
        demo_component(
            "fee-market",
            ComponentKind::FeeMarket,
            Category::LowFee,
            9_400,
            256,
            65_536,
            390,
            12,
            false,
        ),
        demo_component(
            "privacy-pool",
            ComponentKind::PrivacyPool,
            Category::Privacy,
            9_500,
            256,
            131_072,
            640,
            9,
            false,
        ),
        demo_component(
            "monero-bridge",
            ComponentKind::MoneroBridge,
            Category::MoneroBridge,
            9_450,
            256,
            65_536,
            700,
            14,
            true,
        ),
    ];
    let features = [
        ("pq-session-auth", Category::QuantumResistance),
        ("recursive-proof-cache", Category::Speed),
        ("confidential-amm-routing", Category::Defi),
        ("sponsored-fee-netting", Category::LowFee),
        ("viewkey-selective-disclosure", Category::Privacy),
        ("monero-finality-watchtower", Category::MoneroBridge),
    ]
    .into_iter()
    .map(|(feature_id, category)| FeatureCompletion {
        feature_id: feature_id.to_string(),
        category,
        status: FeatureStatus::Released,
        evidence_root: named_root("PRIVATE-L2-PQ-RUNTIME-READINESS-DEMO-FEATURE", feature_id),
    })
    .collect::<Vec<_>>();
    let risk_flags = vec![RiskFlag {
        flag_id: "bridge-liquidity-drill-open".to_string(),
        category: Category::MoneroBridge,
        severity: RiskSeverity::Medium,
        open: true,
        evidence_root: named_root(
            "PRIVATE-L2-PQ-RUNTIME-READINESS-DEMO-RISK",
            "bridge-liquidity-drill-open",
        ),
        owner: "operator-readiness".to_string(),
    }];
    let mut external_roots = BTreeMap::new();
    external_roots.insert(
        "monero_header_cache".to_string(),
        named_root(
            "PRIVATE-L2-PQ-RUNTIME-READINESS-DEMO-ROOT",
            "monero_header_cache",
        ),
    );
    external_roots.insert(
        "contract_runtime_manifest".to_string(),
        named_root(
            "PRIVATE-L2-PQ-RUNTIME-READINESS-DEMO-ROOT",
            "contract_runtime_manifest",
        ),
    );
    IngestRequest {
        observed_l2_height: DEFAULT_L2_HEIGHT,
        observed_monero_height: DEFAULT_MONERO_HEIGHT,
        components,
        features,
        risk_flags,
        external_roots,
    }
}

pub fn demo_runtime() -> Runtime {
    State::devnet()
}

fn compute_counters(
    components: &BTreeMap<String, ComponentReadiness>,
    features: &BTreeMap<String, FeatureCompletion>,
    risk_flags: &BTreeMap<String, RiskFlag>,
) -> Counters {
    Counters {
        components: components.len() as u64,
        completed_features: features
            .values()
            .filter(|feature| feature.complete())
            .count() as u64,
        total_features: features.len() as u64,
        open_risk_flags: risk_flags.values().filter(|flag| flag.open).count() as u64,
        high_risk_flags: risk_flags
            .values()
            .filter(|flag| flag.open && flag.severity == RiskSeverity::High)
            .count() as u64,
        critical_risk_flags: risk_flags
            .values()
            .filter(|flag| flag.open && flag.severity == RiskSeverity::Critical)
            .count() as u64,
        pq_components: components
            .values()
            .filter(|item| item.pq_security_bits >= DEFAULT_MIN_PQ_SECURITY_BITS)
            .count() as u64,
        privacy_components: components
            .values()
            .filter(|item| item.privacy_set_size >= DEFAULT_MIN_PRIVACY_SET_SIZE)
            .count() as u64,
        monero_bridge_components: components
            .values()
            .filter(|item| item.monero_bridge_bound)
            .count() as u64,
    }
}

fn compute_roots(
    components: &BTreeMap<String, ComponentReadiness>,
    features: &BTreeMap<String, FeatureCompletion>,
    risk_flags: &BTreeMap<String, RiskFlag>,
    counters: &Counters,
    scores: &ScoreBreakdown,
) -> Roots {
    let counter_root = domain_hash(
        "PRIVATE-L2-PQ-RUNTIME-READINESS-COUNTERS",
        &[HashPart::Json(&counters.public_record())],
        32,
    );
    let category_score_root = merkle_root(
        "PRIVATE-L2-PQ-RUNTIME-READINESS-CATEGORY-SCORE",
        &scores
            .category_scores
            .iter()
            .map(|(category, value)| json!({"category": category.as_str(), "score_bps": value}))
            .collect::<Vec<_>>(),
    );
    let mut roots = Roots {
        component_root: component_root(components),
        feature_root: feature_root(features),
        risk_flag_root: risk_flag_root(risk_flags),
        category_score_root,
        counter_root,
        scoreboard_root: String::new(),
    };
    roots.scoreboard_root = roots.root();
    roots
}

fn empty_scores() -> ScoreBreakdown {
    ScoreBreakdown {
        category_scores: BTreeMap::new(),
        feature_completion_bps: 0,
        risk_penalty_bps: 0,
        overall_score_bps: 0,
        release_ready: false,
        blocking_reasons: BTreeSet::new(),
    }
}

fn average_bps(values: &[u64]) -> Option<u64> {
    if values.is_empty() {
        None
    } else {
        Some(values.iter().sum::<u64>() / values.len() as u64)
    }
}

fn demo_component(
    id: &str,
    kind: ComponentKind,
    category: Category,
    score_bps: u64,
    pq_security_bits: u16,
    privacy_set_size: u64,
    median_latency_ms: u64,
    fee_bps: u64,
    monero_bridge_bound: bool,
) -> ComponentReadiness {
    ComponentReadiness {
        component_id: id.to_string(),
        kind,
        category,
        root: named_root("PRIVATE-L2-PQ-RUNTIME-READINESS-DEMO-COMPONENT", id),
        score_bps,
        pq_security_bits,
        privacy_set_size,
        median_latency_ms,
        fee_bps,
        monero_bridge_bound,
    }
}

fn unique_component_ids(components: &[ComponentReadiness]) -> bool {
    let mut ids = BTreeSet::new();
    components
        .iter()
        .all(|component| ids.insert(component.component_id.as_str()))
}

fn unique_feature_ids(features: &[FeatureCompletion]) -> bool {
    let mut ids = BTreeSet::new();
    features
        .iter()
        .all(|feature| ids.insert(feature.feature_id.as_str()))
}

fn unique_risk_flag_ids(flags: &[RiskFlag]) -> bool {
    let mut ids = BTreeSet::new();
    flags.iter().all(|flag| ids.insert(flag.flag_id.as_str()))
}

fn named_root(domain: &str, name: &str) -> String {
    domain_hash(domain, &[HashPart::Str(CHAIN_ID), HashPart::Str(name)], 32)
}

fn require(condition: bool, message: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(message.to_string())
    }
}
