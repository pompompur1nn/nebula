use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type Runtime = State;

pub const PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-confidential-cross-runtime-live-root-ingestion-runtime-v1";
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_ATTESTATION_SUITE: &str = "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-root-feed-v1";
pub const PRIVACY_ACCOUNTING_SUITE: &str = "confidential-live-root-privacy-budget-accounting-v1";
pub const DEFAULT_L2_NETWORK: &str = "nebula-devnet";
pub const DEFAULT_MONERO_NETWORK: &str = "monero-devnet";
pub const DEFAULT_EPOCH: u64 = 1;
pub const DEFAULT_SLOT: u64 = 12_800_000;
pub const DEFAULT_L2_HEIGHT: u64 = 2_100_000;
pub const DEFAULT_MONERO_HEIGHT: u64 = 3_800_000;
pub const DEFAULT_FRESHNESS_WINDOW_SLOTS: u64 = 96;
pub const DEFAULT_COUNTER_FRESHNESS_WINDOW: u64 = 512;
pub const DEFAULT_PRIVACY_BUDGET_PER_EPOCH: u64 = 2_000_000;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_SOURCE_WEIGHT: u64 = 2;
pub const DEFAULT_RELEASE_READINESS_SCORE: u16 = 8_000;
pub const MAX_BPS: u16 = 10_000;

const D_CONFIG: &str = "PL2-PQ-XR-LIVE-ROOT-INGEST-CONFIG";
const D_COUNTERS: &str = "PL2-PQ-XR-LIVE-ROOT-INGEST-COUNTERS";
const D_ROOTS: &str = "PL2-PQ-XR-LIVE-ROOT-INGEST-ROOTS";
const D_STATE: &str = "PL2-PQ-XR-LIVE-ROOT-INGEST-STATE";
const D_SOURCE: &str = "PL2-PQ-XR-LIVE-ROOT-INGEST-SOURCE";
const D_OBSERVATION: &str = "PL2-PQ-XR-LIVE-ROOT-INGEST-OBSERVATION";
const D_DEPENDENCY: &str = "PL2-PQ-XR-LIVE-ROOT-INGEST-DEPENDENCY";
const D_FRESHNESS: &str = "PL2-PQ-XR-LIVE-ROOT-INGEST-FRESHNESS";
const D_INCONSISTENCY: &str = "PL2-PQ-XR-LIVE-ROOT-INGEST-INCONSISTENCY";
const D_REMEDIATION: &str = "PL2-PQ-XR-LIVE-ROOT-INGEST-REMEDIATION";
const D_PRIVACY: &str = "PL2-PQ-XR-LIVE-ROOT-INGEST-PRIVACY";
const D_ATTESTATION: &str = "PL2-PQ-XR-LIVE-ROOT-INGEST-ATTESTATION";
const D_SCENARIO: &str = "PL2-PQ-XR-LIVE-ROOT-INGEST-SCENARIO";
const D_MARKET: &str = "PL2-PQ-XR-LIVE-ROOT-INGEST-MARKET";
const D_GATEWAY: &str = "PL2-PQ-XR-LIVE-ROOT-INGEST-GATEWAY";
const D_PUBLIC: &str = "PL2-PQ-XR-LIVE-ROOT-INGEST-PUBLIC";

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceKind {
    WalletApi,
    DevnetScenarioRunner,
    OperatorProgressFeed,
    ReleaseReadiness,
    BridgeContractGateway,
    MobileFastSync,
    MoneroBridgeFinality,
    MoneroBridgeLiquidity,
    LowFeeMarket,
    ContractRuntime,
    TokenRuntime,
}

impl SourceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WalletApi => "wallet_api",
            Self::DevnetScenarioRunner => "devnet_scenario_runner",
            Self::OperatorProgressFeed => "operator_progress_feed",
            Self::ReleaseReadiness => "release_readiness",
            Self::BridgeContractGateway => "bridge_contract_gateway",
            Self::MobileFastSync => "mobile_fast_sync",
            Self::MoneroBridgeFinality => "monero_bridge_finality",
            Self::MoneroBridgeLiquidity => "monero_bridge_liquidity",
            Self::LowFeeMarket => "low_fee_market",
            Self::ContractRuntime => "contract_runtime",
            Self::TokenRuntime => "token_runtime",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RootKind {
    WalletApiCounter,
    DevnetScenario,
    OperatorProgress,
    ReleaseReadiness,
    BridgeContractGateway,
    MobileFastSync,
    MoneroFinality,
    MoneroLiquidity,
    LowFeeMarket,
    ContractState,
    TokenRuntime,
    PrivacyBudget,
    PqAttestation,
    ConflictWitness,
}

impl RootKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WalletApiCounter => "wallet_api_counter",
            Self::DevnetScenario => "devnet_scenario",
            Self::OperatorProgress => "operator_progress",
            Self::ReleaseReadiness => "release_readiness",
            Self::BridgeContractGateway => "bridge_contract_gateway",
            Self::MobileFastSync => "mobile_fast_sync",
            Self::MoneroFinality => "monero_finality",
            Self::MoneroLiquidity => "monero_liquidity",
            Self::LowFeeMarket => "low_fee_market",
            Self::ContractState => "contract_state",
            Self::TokenRuntime => "token_runtime",
            Self::PrivacyBudget => "privacy_budget",
            Self::PqAttestation => "pq_attestation",
            Self::ConflictWitness => "conflict_witness",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RootStatus {
    Draft,
    Accepted,
    Fresh,
    Stale,
    Conflicting,
    Quarantined,
    Remediated,
}

impl RootStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Accepted => "accepted",
            Self::Fresh => "fresh",
            Self::Stale => "stale",
            Self::Conflicting => "conflicting",
            Self::Quarantined => "quarantined",
            Self::Remediated => "remediated",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DependencyKind {
    RequiresFreshness,
    RequiresPrivacyBudget,
    RequiresPqAttestation,
    RequiresMoneroFinality,
    RequiresLiquidity,
    RequiresGateway,
    RequiresReleaseReadiness,
    ConflictsWith,
}

impl DependencyKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RequiresFreshness => "requires_freshness",
            Self::RequiresPrivacyBudget => "requires_privacy_budget",
            Self::RequiresPqAttestation => "requires_pq_attestation",
            Self::RequiresMoneroFinality => "requires_monero_finality",
            Self::RequiresLiquidity => "requires_liquidity",
            Self::RequiresGateway => "requires_gateway",
            Self::RequiresReleaseReadiness => "requires_release_readiness",
            Self::ConflictsWith => "conflicts_with",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InconsistencyKind {
    DuplicateDomainLabel,
    StaleObservation,
    CounterRegression,
    MissingDependency,
    PrivacyBudgetExceeded,
    PqAttestationMissing,
    PqAttestationWeak,
    ConflictingStateRoot,
    ReleaseReadinessBelowThreshold,
    LiquidityBelowFloor,
}

impl InconsistencyKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DuplicateDomainLabel => "duplicate_domain_label",
            Self::StaleObservation => "stale_observation",
            Self::CounterRegression => "counter_regression",
            Self::MissingDependency => "missing_dependency",
            Self::PrivacyBudgetExceeded => "privacy_budget_exceeded",
            Self::PqAttestationMissing => "pq_attestation_missing",
            Self::PqAttestationWeak => "pq_attestation_weak",
            Self::ConflictingStateRoot => "conflicting_state_root",
            Self::ReleaseReadinessBelowThreshold => "release_readiness_below_threshold",
            Self::LiquidityBelowFloor => "liquidity_below_floor",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RemediationAction {
    ReingestSource,
    QuarantineRoot,
    RequestAttestation,
    RefreshWalletCounters,
    RebuildDependency,
    ThrottlePrivacySpend,
    EscalateOperator,
    HoldRelease,
    ReconcileBridgeLiquidity,
}

impl RemediationAction {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ReingestSource => "reingest_source",
            Self::QuarantineRoot => "quarantine_root",
            Self::RequestAttestation => "request_attestation",
            Self::RefreshWalletCounters => "refresh_wallet_counters",
            Self::RebuildDependency => "rebuild_dependency",
            Self::ThrottlePrivacySpend => "throttle_privacy_spend",
            Self::EscalateOperator => "escalate_operator",
            Self::HoldRelease => "hold_release",
            Self::ReconcileBridgeLiquidity => "reconcile_bridge_liquidity",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub l2_network: String,
    pub monero_network: String,
    pub hash_suite: String,
    pub pq_attestation_suite: String,
    pub privacy_accounting_suite: String,
    pub epoch: u64,
    pub current_slot: u64,
    pub l2_height: u64,
    pub monero_height: u64,
    pub root_freshness_window_slots: u64,
    pub counter_freshness_window: u64,
    pub privacy_budget_per_epoch: u64,
    pub min_pq_security_bits: u16,
    pub min_source_weight: u64,
    pub min_release_readiness_score: u16,
    pub min_bridge_liquidity_reserve: u64,
    pub require_domain_labels: bool,
    pub require_pq_attestation_roots: bool,
    pub reject_conflicting_state_roots: bool,
    pub allow_demo_conflicts: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            l2_network: DEFAULT_L2_NETWORK.to_string(),
            monero_network: DEFAULT_MONERO_NETWORK.to_string(),
            hash_suite: HASH_SUITE.to_string(),
            pq_attestation_suite: PQ_ATTESTATION_SUITE.to_string(),
            privacy_accounting_suite: PRIVACY_ACCOUNTING_SUITE.to_string(),
            epoch: DEFAULT_EPOCH,
            current_slot: DEFAULT_SLOT,
            l2_height: DEFAULT_L2_HEIGHT,
            monero_height: DEFAULT_MONERO_HEIGHT,
            root_freshness_window_slots: DEFAULT_FRESHNESS_WINDOW_SLOTS,
            counter_freshness_window: DEFAULT_COUNTER_FRESHNESS_WINDOW,
            privacy_budget_per_epoch: DEFAULT_PRIVACY_BUDGET_PER_EPOCH,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_source_weight: DEFAULT_MIN_SOURCE_WEIGHT,
            min_release_readiness_score: DEFAULT_RELEASE_READINESS_SCORE,
            min_bridge_liquidity_reserve: 50_000_000,
            require_domain_labels: true,
            require_pq_attestation_roots: true,
            reject_conflicting_state_roots: true,
            allow_demo_conflicts: false,
        }
    }

    pub fn demo() -> Self {
        let mut config = Self::devnet();
        config.allow_demo_conflicts = true;
        config.min_bridge_liquidity_reserve = 10_000_000;
        config
    }

    pub fn validate(&self) -> Result<()> {
        ensure_nonempty("chain_id", &self.chain_id)?;
        ensure_nonempty("protocol_version", &self.protocol_version)?;
        ensure_nonempty("l2_network", &self.l2_network)?;
        ensure_nonempty("monero_network", &self.monero_network)?;
        ensure_nonempty("hash_suite", &self.hash_suite)?;
        ensure_nonempty("pq_attestation_suite", &self.pq_attestation_suite)?;
        if self.schema_version == 0 {
            return Err("schema_version must be nonzero".to_string());
        }
        if self.root_freshness_window_slots == 0 || self.counter_freshness_window == 0 {
            return Err("freshness windows must be nonzero".to_string());
        }
        if self.privacy_budget_per_epoch == 0 {
            return Err("privacy_budget_per_epoch must be nonzero".to_string());
        }
        if self.min_pq_security_bits < 128 {
            return Err("min_pq_security_bits must be at least 128".to_string());
        }
        if self.min_release_readiness_score > MAX_BPS {
            return Err("min_release_readiness_score exceeds MAX_BPS".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn id(&self) -> String {
        stable_id(
            D_CONFIG,
            &[
                HashPart::Str(&self.chain_id),
                HashPart::Str(&self.protocol_version),
                HashPart::U64(self.epoch),
            ],
        )
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub sources_registered: u64,
    pub observations_ingested: u64,
    pub observations_accepted: u64,
    pub observations_rejected: u64,
    pub dependencies_registered: u64,
    pub freshness_checks: u64,
    pub privacy_budget_checks: u64,
    pub pq_attestation_checks: u64,
    pub conflicts_detected: u64,
    pub remediations_opened: u64,
    pub remediations_closed: u64,
    pub wallet_api_counters_seen: u64,
    pub devnet_scenarios_seen: u64,
    pub operator_updates_seen: u64,
    pub release_readiness_reports_seen: u64,
    pub bridge_gateway_roots_seen: u64,
    pub mobile_fast_sync_roots_seen: u64,
    pub monero_finality_roots_seen: u64,
    pub monero_liquidity_roots_seen: u64,
    pub low_fee_market_roots_seen: u64,
    pub contract_runtime_roots_seen: u64,
    pub token_runtime_roots_seen: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn root(&self) -> String {
        merkle_root(D_COUNTERS, &[self.public_record()])
    }

    pub fn bump_source_kind(&mut self, kind: SourceKind) {
        match kind {
            SourceKind::WalletApi => self.wallet_api_counters_seen += 1,
            SourceKind::DevnetScenarioRunner => self.devnet_scenarios_seen += 1,
            SourceKind::OperatorProgressFeed => self.operator_updates_seen += 1,
            SourceKind::ReleaseReadiness => self.release_readiness_reports_seen += 1,
            SourceKind::BridgeContractGateway => self.bridge_gateway_roots_seen += 1,
            SourceKind::MobileFastSync => self.mobile_fast_sync_roots_seen += 1,
            SourceKind::MoneroBridgeFinality => self.monero_finality_roots_seen += 1,
            SourceKind::MoneroBridgeLiquidity => self.monero_liquidity_roots_seen += 1,
            SourceKind::LowFeeMarket => self.low_fee_market_roots_seen += 1,
            SourceKind::ContractRuntime => self.contract_runtime_roots_seen += 1,
            SourceKind::TokenRuntime => self.token_runtime_roots_seen += 1,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub counter_root: String,
    pub source_root: String,
    pub observation_root: String,
    pub dependency_root: String,
    pub freshness_root: String,
    pub inconsistency_root: String,
    pub remediation_root: String,
    pub privacy_budget_root: String,
    pub pq_attestation_root: String,
    pub scenario_root: String,
    pub market_root: String,
    pub gateway_root: String,
    pub public_record_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn empty() -> Self {
        let empty = merkle_root(D_ROOTS, &[]);
        Self {
            config_root: empty.clone(),
            counter_root: empty.clone(),
            source_root: empty.clone(),
            observation_root: empty.clone(),
            dependency_root: empty.clone(),
            freshness_root: empty.clone(),
            inconsistency_root: empty.clone(),
            remediation_root: empty.clone(),
            privacy_budget_root: empty.clone(),
            pq_attestation_root: empty.clone(),
            scenario_root: empty.clone(),
            market_root: empty.clone(),
            gateway_root: empty.clone(),
            public_record_root: empty.clone(),
            state_root: empty,
        }
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SourceRegistration {
    pub source_id: String,
    pub kind: SourceKind,
    pub label: String,
    pub endpoint_commitment: String,
    pub operator_id: String,
    pub domain_labels: BTreeSet<String>,
    pub weight: u64,
    pub pq_security_bits: u16,
    pub attestation_root: String,
    pub last_seen_slot: u64,
    pub enabled: bool,
}

impl SourceRegistration {
    pub fn new(
        kind: SourceKind,
        label: &str,
        operator_id: &str,
        domain_labels: BTreeSet<String>,
        weight: u64,
        pq_security_bits: u16,
        last_seen_slot: u64,
    ) -> Self {
        let endpoint_commitment = stable_id(
            D_SOURCE,
            &[
                HashPart::Str(kind.as_str()),
                HashPart::Str(label),
                HashPart::Str(operator_id),
            ],
        );
        let source_id = stable_id(
            D_SOURCE,
            &[
                HashPart::Str(kind.as_str()),
                HashPart::Str(label),
                HashPart::U64(weight),
            ],
        );
        let attestation_root = stable_root(
            D_ATTESTATION,
            &[json!({
                "source_id": source_id,
                "kind": kind.as_str(),
                "operator_id": operator_id,
                "pq_security_bits": pq_security_bits
            })],
        );
        Self {
            source_id,
            kind,
            label: label.to_string(),
            endpoint_commitment,
            operator_id: operator_id.to_string(),
            domain_labels,
            weight,
            pq_security_bits,
            attestation_root,
            last_seen_slot,
            enabled: true,
        }
    }

    pub fn validate(&self, config: &Config) -> Result<()> {
        ensure_nonempty("source_id", &self.source_id)?;
        ensure_nonempty("source label", &self.label)?;
        ensure_nonempty("operator_id", &self.operator_id)?;
        ensure_nonempty("attestation_root", &self.attestation_root)?;
        if self.weight < config.min_source_weight {
            return Err(format!("source {} weight below minimum", self.source_id));
        }
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err(format!(
                "source {} pq security below minimum",
                self.source_id
            ));
        }
        if config.require_domain_labels && self.domain_labels.is_empty() {
            return Err(format!("source {} missing domain labels", self.source_id));
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RootObservation {
    pub observation_id: String,
    pub source_id: String,
    pub source_kind: SourceKind,
    pub root_kind: RootKind,
    pub domain_label: String,
    pub root: String,
    pub previous_root: String,
    pub counter: u64,
    pub slot: u64,
    pub l2_height: u64,
    pub monero_height: u64,
    pub privacy_budget_spent: u64,
    pub pq_attestation_root: String,
    pub release_readiness_score: u16,
    pub bridge_liquidity_reserve: u64,
    pub status: RootStatus,
    pub metadata: BTreeMap<String, Value>,
}

impl RootObservation {
    pub fn new(input: RootObservationInput) -> Self {
        let record = json!({
            "source_id": input.source_id,
            "source_kind": input.source_kind.as_str(),
            "root_kind": input.root_kind.as_str(),
            "domain_label": input.domain_label,
            "root": input.root,
            "counter": input.counter,
            "slot": input.slot
        });
        let observation_id = stable_id(D_OBSERVATION, &[HashPart::Json(&record)]);
        Self {
            observation_id,
            source_id: input.source_id,
            source_kind: input.source_kind,
            root_kind: input.root_kind,
            domain_label: input.domain_label,
            root: input.root,
            previous_root: input.previous_root,
            counter: input.counter,
            slot: input.slot,
            l2_height: input.l2_height,
            monero_height: input.monero_height,
            privacy_budget_spent: input.privacy_budget_spent,
            pq_attestation_root: input.pq_attestation_root,
            release_readiness_score: input.release_readiness_score,
            bridge_liquidity_reserve: input.bridge_liquidity_reserve,
            status: RootStatus::Draft,
            metadata: input.metadata,
        }
    }

    pub fn validate(&self, config: &Config) -> Result<()> {
        ensure_nonempty("observation_id", &self.observation_id)?;
        ensure_nonempty("source_id", &self.source_id)?;
        ensure_nonempty("domain_label", &self.domain_label)?;
        ensure_nonempty("root", &self.root)?;
        if config.require_pq_attestation_roots {
            ensure_nonempty("pq_attestation_root", &self.pq_attestation_root)?;
        }
        if self.release_readiness_score > MAX_BPS {
            return Err(format!(
                "observation {} release readiness score exceeds MAX_BPS",
                self.observation_id
            ));
        }
        Ok(())
    }

    pub fn stale_at(&self, config: &Config) -> bool {
        self.slot.saturating_add(config.root_freshness_window_slots) < config.current_slot
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RootObservationInput {
    pub source_id: String,
    pub source_kind: SourceKind,
    pub root_kind: RootKind,
    pub domain_label: String,
    pub root: String,
    pub previous_root: String,
    pub counter: u64,
    pub slot: u64,
    pub l2_height: u64,
    pub monero_height: u64,
    pub privacy_budget_spent: u64,
    pub pq_attestation_root: String,
    pub release_readiness_score: u16,
    pub bridge_liquidity_reserve: u64,
    pub metadata: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DependencyEdge {
    pub edge_id: String,
    pub from_observation_id: String,
    pub to_observation_id: String,
    pub kind: DependencyKind,
    pub domain_label: String,
    pub min_counter: u64,
    pub required: bool,
}

impl DependencyEdge {
    pub fn new(
        from_observation_id: &str,
        to_observation_id: &str,
        kind: DependencyKind,
        domain_label: &str,
        min_counter: u64,
        required: bool,
    ) -> Self {
        let edge_id = stable_id(
            D_DEPENDENCY,
            &[
                HashPart::Str(from_observation_id),
                HashPart::Str(to_observation_id),
                HashPart::Str(kind.as_str()),
                HashPart::Str(domain_label),
                HashPart::U64(min_counter),
            ],
        );
        Self {
            edge_id,
            from_observation_id: from_observation_id.to_string(),
            to_observation_id: to_observation_id.to_string(),
            kind,
            domain_label: domain_label.to_string(),
            min_counter,
            required,
        }
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FreshnessWindow {
    pub window_id: String,
    pub domain_label: String,
    pub root_kind: RootKind,
    pub min_slot: u64,
    pub max_slot: u64,
    pub min_counter: u64,
    pub max_counter: u64,
}

impl FreshnessWindow {
    pub fn for_observation(config: &Config, observation: &RootObservation) -> Self {
        let min_slot = observation
            .slot
            .saturating_sub(config.root_freshness_window_slots);
        let max_slot = observation
            .slot
            .saturating_add(config.root_freshness_window_slots);
        let min_counter = observation
            .counter
            .saturating_sub(config.counter_freshness_window);
        let max_counter = observation
            .counter
            .saturating_add(config.counter_freshness_window);
        let window_id = stable_id(
            D_FRESHNESS,
            &[
                HashPart::Str(&observation.domain_label),
                HashPart::Str(observation.root_kind.as_str()),
                HashPart::U64(min_slot),
                HashPart::U64(max_slot),
            ],
        );
        Self {
            window_id,
            domain_label: observation.domain_label.clone(),
            root_kind: observation.root_kind,
            min_slot,
            max_slot,
            min_counter,
            max_counter,
        }
    }

    pub fn contains(&self, observation: &RootObservation) -> bool {
        observation.slot >= self.min_slot
            && observation.slot <= self.max_slot
            && observation.counter >= self.min_counter
            && observation.counter <= self.max_counter
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivacyBudgetRecord {
    pub budget_id: String,
    pub epoch: u64,
    pub source_id: String,
    pub domain_label: String,
    pub budget_limit: u64,
    pub spent: u64,
    pub reserved: u64,
}

impl PrivacyBudgetRecord {
    pub fn remaining(&self) -> u64 {
        self.budget_limit
            .saturating_sub(self.spent)
            .saturating_sub(self.reserved)
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqAttestationRecord {
    pub attestation_id: String,
    pub source_id: String,
    pub root: String,
    pub suite: String,
    pub security_bits: u16,
    pub signer_set_root: String,
    pub transcript_root: String,
    pub valid_from_slot: u64,
    pub valid_until_slot: u64,
}

impl PqAttestationRecord {
    pub fn fresh_at(&self, slot: u64) -> bool {
        slot >= self.valid_from_slot && slot <= self.valid_until_slot
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct InconsistencyRecord {
    pub inconsistency_id: String,
    pub kind: InconsistencyKind,
    pub observation_id: String,
    pub source_id: String,
    pub domain_label: String,
    pub severity: u8,
    pub details: String,
    pub evidence_root: String,
    pub opened_slot: u64,
    pub resolved: bool,
}

impl InconsistencyRecord {
    pub fn new(
        kind: InconsistencyKind,
        observation: &RootObservation,
        severity: u8,
        details: &str,
        evidence: &[Value],
    ) -> Self {
        let evidence_root = stable_root(D_INCONSISTENCY, evidence);
        let inconsistency_id = stable_id(
            D_INCONSISTENCY,
            &[
                HashPart::Str(kind.as_str()),
                HashPart::Str(&observation.observation_id),
                HashPart::Str(&evidence_root),
            ],
        );
        Self {
            inconsistency_id,
            kind,
            observation_id: observation.observation_id.clone(),
            source_id: observation.source_id.clone(),
            domain_label: observation.domain_label.clone(),
            severity,
            details: details.to_string(),
            evidence_root,
            opened_slot: observation.slot,
            resolved: false,
        }
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RemediationItem {
    pub remediation_id: String,
    pub inconsistency_id: String,
    pub action: RemediationAction,
    pub owner: String,
    pub priority: u8,
    pub opened_slot: u64,
    pub due_slot: u64,
    pub closed_slot: Option<u64>,
    pub note: String,
}

impl RemediationItem {
    pub fn new(
        inconsistency: &InconsistencyRecord,
        action: RemediationAction,
        owner: &str,
        priority: u8,
        due_slot: u64,
    ) -> Self {
        let remediation_id = stable_id(
            D_REMEDIATION,
            &[
                HashPart::Str(&inconsistency.inconsistency_id),
                HashPart::Str(action.as_str()),
                HashPart::Str(owner),
            ],
        );
        Self {
            remediation_id,
            inconsistency_id: inconsistency.inconsistency_id.clone(),
            action,
            owner: owner.to_string(),
            priority,
            opened_slot: inconsistency.opened_slot,
            due_slot,
            closed_slot: None,
            note: String::new(),
        }
    }

    pub fn close(&mut self, slot: u64, note: &str) {
        self.closed_slot = Some(slot);
        self.note = note.to_string();
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub sources: BTreeMap<String, SourceRegistration>,
    pub observations: BTreeMap<String, RootObservation>,
    pub domain_index: BTreeMap<String, BTreeSet<String>>,
    pub dependency_edges: BTreeMap<String, DependencyEdge>,
    pub freshness_windows: BTreeMap<String, FreshnessWindow>,
    pub privacy_budgets: BTreeMap<String, PrivacyBudgetRecord>,
    pub pq_attestations: BTreeMap<String, PqAttestationRecord>,
    pub inconsistencies: BTreeMap<String, InconsistencyRecord>,
    pub remediation_queue: BTreeMap<String, RemediationItem>,
}

impl State {
    pub fn new(config: Config) -> Result<Self> {
        config.validate()?;
        let mut state = Self {
            config,
            counters: Counters::default(),
            roots: Roots::empty(),
            sources: BTreeMap::new(),
            observations: BTreeMap::new(),
            domain_index: BTreeMap::new(),
            dependency_edges: BTreeMap::new(),
            freshness_windows: BTreeMap::new(),
            privacy_budgets: BTreeMap::new(),
            pq_attestations: BTreeMap::new(),
            inconsistencies: BTreeMap::new(),
            remediation_queue: BTreeMap::new(),
        };
        state.recompute_roots();
        Ok(state)
    }

    pub fn devnet() -> Self {
        Self::new(Config::devnet()).fallback_state()
    }

    pub fn demo() -> Self {
        let mut state = Self::new(Config::demo()).fallback_state();
        state.seed_demo_sources();
        state.seed_demo_observations();
        state.recompute_roots();
        state
    }

    pub fn register_source(&mut self, source: SourceRegistration) -> Result<String> {
        source.validate(&self.config)?;
        if self.sources.contains_key(&source.source_id) {
            return Err(format!("duplicate source {}", source.source_id));
        }
        if self.config.require_domain_labels {
            for label in &source.domain_labels {
                let existing_sources = match self.domain_index.get(label) {
                    Some(ids) => ids.clone(),
                    None => BTreeSet::new(),
                };
                if !existing_sources.is_empty() {
                    let evidence = vec![json!({
                        "domain_label": label,
                        "existing_sources": existing_sources,
                        "new_source": source.source_id
                    })];
                    let synthetic = synthetic_observation(
                        &source.source_id,
                        source.kind,
                        RootKind::ConflictWitness,
                        label,
                        self.config.current_slot,
                    );
                    self.record_inconsistency(
                        InconsistencyKind::DuplicateDomainLabel,
                        &synthetic,
                        5,
                        "domain label already owned by another live root source",
                        &evidence,
                    );
                }
                self.domain_index
                    .entry(label.clone())
                    .or_default()
                    .insert(source.source_id.clone());
            }
        }
        let attestation = PqAttestationRecord {
            attestation_id: stable_id(
                D_ATTESTATION,
                &[
                    HashPart::Str(&source.source_id),
                    HashPart::Str(&source.attestation_root),
                ],
            ),
            source_id: source.source_id.clone(),
            root: source.attestation_root.clone(),
            suite: self.config.pq_attestation_suite.clone(),
            security_bits: source.pq_security_bits,
            signer_set_root: stable_root(D_ATTESTATION, &[source.public_record()]),
            transcript_root: stable_root(D_ATTESTATION, &[json!({"source_id": source.source_id})]),
            valid_from_slot: self.config.current_slot.saturating_sub(1),
            valid_until_slot: self
                .config
                .current_slot
                .saturating_add(self.config.root_freshness_window_slots),
        };
        let source_id = source.source_id.clone();
        self.pq_attestations
            .insert(attestation.attestation_id.clone(), attestation);
        self.sources.insert(source_id.clone(), source);
        self.counters.sources_registered += 1;
        self.recompute_roots();
        Ok(source_id)
    }

    pub fn ingest_observation(&mut self, mut observation: RootObservation) -> Result<String> {
        observation.validate(&self.config)?;
        let source = match self.sources.get(&observation.source_id) {
            Some(source) => source.clone(),
            None => return Err(format!("unknown source {}", observation.source_id)),
        };
        if !source.enabled {
            return Err(format!("source {} disabled", source.source_id));
        }
        if source.kind != observation.source_kind {
            return Err(format!("source kind mismatch for {}", source.source_id));
        }
        self.counters.observations_ingested += 1;
        self.counters.bump_source_kind(observation.source_kind);

        let mut accepted = true;
        if observation.stale_at(&self.config) {
            accepted = false;
            observation.status = RootStatus::Stale;
            self.record_inconsistency(
                InconsistencyKind::StaleObservation,
                &observation,
                4,
                "observation is outside the configured freshness window",
                &[observation.public_record()],
            );
        }
        if !self.domain_label_allowed(&source, &observation.domain_label) {
            accepted = false;
            self.record_inconsistency(
                InconsistencyKind::DuplicateDomainLabel,
                &observation,
                5,
                "observation used a domain label not registered to its source",
                &[source.public_record(), observation.public_record()],
            );
        }
        if !self.attestation_satisfies(&observation) {
            accepted = false;
            self.record_inconsistency(
                InconsistencyKind::PqAttestationMissing,
                &observation,
                6,
                "observation attestation root is not present or not fresh",
                &[observation.public_record()],
            );
        }
        if !self.privacy_budget_satisfies(&observation) {
            accepted = false;
            self.record_inconsistency(
                InconsistencyKind::PrivacyBudgetExceeded,
                &observation,
                6,
                "observation would exceed privacy budget for the epoch",
                &[observation.public_record()],
            );
        }
        if observation.root_kind == RootKind::ReleaseReadiness
            && observation.release_readiness_score < self.config.min_release_readiness_score
        {
            accepted = false;
            self.record_inconsistency(
                InconsistencyKind::ReleaseReadinessBelowThreshold,
                &observation,
                7,
                "release readiness score below configured threshold",
                &[observation.public_record()],
            );
        }
        if matches!(
            observation.root_kind,
            RootKind::MoneroLiquidity | RootKind::BridgeContractGateway
        ) && observation.bridge_liquidity_reserve < self.config.min_bridge_liquidity_reserve
        {
            accepted = false;
            self.record_inconsistency(
                InconsistencyKind::LiquidityBelowFloor,
                &observation,
                7,
                "bridge liquidity reserve below configured floor",
                &[observation.public_record()],
            );
        }
        if self.detect_conflicting_root(&observation) {
            accepted = false;
            observation.status = RootStatus::Conflicting;
            self.counters.conflicts_detected += 1;
            self.record_inconsistency(
                InconsistencyKind::ConflictingStateRoot,
                &observation,
                9,
                "conflicting live state root for domain and counter",
                &[observation.public_record()],
            );
        }

        if accepted {
            observation.status = RootStatus::Fresh;
            self.counters.observations_accepted += 1;
        } else {
            self.counters.observations_rejected += 1;
            if self.config.reject_conflicting_state_roots && !self.config.allow_demo_conflicts {
                observation.status = RootStatus::Quarantined;
            }
        }

        let window = FreshnessWindow::for_observation(&self.config, &observation);
        self.freshness_windows
            .insert(window.window_id.clone(), window);
        self.charge_privacy_budget(&observation);
        let observation_id = observation.observation_id.clone();
        self.observations
            .insert(observation_id.clone(), observation);
        self.recompute_roots();
        Ok(observation_id)
    }

    pub fn add_dependency(&mut self, edge: DependencyEdge) -> Result<String> {
        ensure_nonempty("from_observation_id", &edge.from_observation_id)?;
        ensure_nonempty("to_observation_id", &edge.to_observation_id)?;
        if edge.required && !self.observations.contains_key(&edge.from_observation_id) {
            return Err(format!(
                "dependency from observation missing {}",
                edge.from_observation_id
            ));
        }
        if edge.required && !self.observations.contains_key(&edge.to_observation_id) {
            return Err(format!(
                "dependency to observation missing {}",
                edge.to_observation_id
            ));
        }
        let edge_id = edge.edge_id.clone();
        self.dependency_edges.insert(edge_id.clone(), edge);
        self.counters.dependencies_registered += 1;
        self.recompute_roots();
        Ok(edge_id)
    }

    pub fn validate_dependencies(&mut self) -> Vec<InconsistencyRecord> {
        let mut created = Vec::new();
        for edge in self.dependency_edges.values() {
            if !edge.required {
                continue;
            }
            let from = self.observations.get(&edge.from_observation_id);
            let to = self.observations.get(&edge.to_observation_id);
            if let (Some(from), Some(to)) = (from, to) {
                if to.counter < edge.min_counter {
                    created.push(InconsistencyRecord::new(
                        InconsistencyKind::MissingDependency,
                        from,
                        6,
                        "dependency counter below required minimum",
                        &[edge.public_record(), to.public_record()],
                    ));
                }
                if edge.kind == DependencyKind::ConflictsWith && from.root == to.root {
                    created.push(InconsistencyRecord::new(
                        InconsistencyKind::ConflictingStateRoot,
                        from,
                        8,
                        "conflict dependency resolved to the same root",
                        &[
                            edge.public_record(),
                            from.public_record(),
                            to.public_record(),
                        ],
                    ));
                }
            }
        }
        for record in &created {
            self.open_remediation(record);
            self.inconsistencies
                .insert(record.inconsistency_id.clone(), record.clone());
        }
        self.recompute_roots();
        created
    }

    pub fn public_record(&self) -> Value {
        json!({
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
            "source_count": self.sources.len(),
            "observation_count": self.observations.len(),
            "dependency_count": self.dependency_edges.len(),
            "freshness_window_count": self.freshness_windows.len(),
            "privacy_budget_count": self.privacy_budgets.len(),
            "pq_attestation_count": self.pq_attestations.len(),
            "inconsistency_count": self.inconsistencies.len(),
            "remediation_count": self.remediation_queue.len()
        })
    }

    pub fn state_root(&self) -> String {
        self.roots.state_root.clone()
    }

    pub fn public_records(&self) -> Vec<Value> {
        let mut records = Vec::new();
        records.push(self.config.public_record());
        records.push(self.counters.public_record());
        records.extend(self.sources.values().map(SourceRegistration::public_record));
        records.extend(
            self.observations
                .values()
                .map(RootObservation::public_record),
        );
        records.extend(
            self.dependency_edges
                .values()
                .map(DependencyEdge::public_record),
        );
        records.extend(
            self.freshness_windows
                .values()
                .map(FreshnessWindow::public_record),
        );
        records.extend(
            self.privacy_budgets
                .values()
                .map(PrivacyBudgetRecord::public_record),
        );
        records.extend(
            self.pq_attestations
                .values()
                .map(PqAttestationRecord::public_record),
        );
        records.extend(
            self.inconsistencies
                .values()
                .map(InconsistencyRecord::public_record),
        );
        records.extend(
            self.remediation_queue
                .values()
                .map(RemediationItem::public_record),
        );
        records
    }

    pub fn recompute_roots(&mut self) {
        let source_records = records_from_map(&self.sources);
        let observation_records = records_from_map(&self.observations);
        let dependency_records = records_from_map(&self.dependency_edges);
        let freshness_records = records_from_map(&self.freshness_windows);
        let inconsistency_records = records_from_map(&self.inconsistencies);
        let remediation_records = records_from_map(&self.remediation_queue);
        let privacy_records = records_from_map(&self.privacy_budgets);
        let attestation_records = records_from_map(&self.pq_attestations);
        let scenario_records = filter_records(&observation_records, "root_kind", "devnet_scenario");
        let market_records = market_records(&observation_records);
        let gateway_records =
            filter_records(&observation_records, "root_kind", "bridge_contract_gateway");
        let public_records = self.public_records_without_roots();
        let config_root = merkle_root(D_CONFIG, &[self.config.public_record()]);
        let counter_root = self.counters.root();
        let source_root = merkle_root(D_SOURCE, &source_records);
        let observation_root = merkle_root(D_OBSERVATION, &observation_records);
        let dependency_root = merkle_root(D_DEPENDENCY, &dependency_records);
        let freshness_root = merkle_root(D_FRESHNESS, &freshness_records);
        let inconsistency_root = merkle_root(D_INCONSISTENCY, &inconsistency_records);
        let remediation_root = merkle_root(D_REMEDIATION, &remediation_records);
        let privacy_budget_root = merkle_root(D_PRIVACY, &privacy_records);
        let pq_attestation_root = merkle_root(D_ATTESTATION, &attestation_records);
        let scenario_root = merkle_root(D_SCENARIO, &scenario_records);
        let market_root = merkle_root(D_MARKET, &market_records);
        let gateway_root = merkle_root(D_GATEWAY, &gateway_records);
        let public_record_root = merkle_root(D_PUBLIC, &public_records);
        let state_root = merkle_root(
            D_STATE,
            &[
                json!({"config_root": config_root}),
                json!({"counter_root": counter_root}),
                json!({"source_root": source_root}),
                json!({"observation_root": observation_root}),
                json!({"dependency_root": dependency_root}),
                json!({"freshness_root": freshness_root}),
                json!({"inconsistency_root": inconsistency_root}),
                json!({"remediation_root": remediation_root}),
                json!({"privacy_budget_root": privacy_budget_root}),
                json!({"pq_attestation_root": pq_attestation_root}),
                json!({"scenario_root": scenario_root}),
                json!({"market_root": market_root}),
                json!({"gateway_root": gateway_root}),
                json!({"public_record_root": public_record_root}),
            ],
        );
        self.roots = Roots {
            config_root,
            counter_root,
            source_root,
            observation_root,
            dependency_root,
            freshness_root,
            inconsistency_root,
            remediation_root,
            privacy_budget_root,
            pq_attestation_root,
            scenario_root,
            market_root,
            gateway_root,
            public_record_root,
            state_root,
        };
    }

    fn public_records_without_roots(&self) -> Vec<Value> {
        let mut records = Vec::new();
        records.push(self.config.public_record());
        records.push(self.counters.public_record());
        records.extend(self.sources.values().map(SourceRegistration::public_record));
        records.extend(
            self.observations
                .values()
                .map(RootObservation::public_record),
        );
        records
    }

    fn domain_label_allowed(&self, source: &SourceRegistration, label: &str) -> bool {
        source.domain_labels.contains(label)
    }

    fn attestation_satisfies(&mut self, observation: &RootObservation) -> bool {
        self.counters.pq_attestation_checks += 1;
        self.pq_attestations.values().any(|attestation| {
            attestation.source_id == observation.source_id
                && attestation.root == observation.pq_attestation_root
                && attestation.security_bits >= self.config.min_pq_security_bits
                && attestation.fresh_at(observation.slot)
        })
    }

    fn privacy_budget_satisfies(&mut self, observation: &RootObservation) -> bool {
        self.counters.privacy_budget_checks += 1;
        let key = privacy_budget_key(
            self.config.epoch,
            &observation.source_id,
            &observation.domain_label,
        );
        match self.privacy_budgets.get(&key) {
            Some(budget) => budget.remaining() >= observation.privacy_budget_spent,
            None => self.config.privacy_budget_per_epoch >= observation.privacy_budget_spent,
        }
    }

    fn charge_privacy_budget(&mut self, observation: &RootObservation) {
        let key = privacy_budget_key(
            self.config.epoch,
            &observation.source_id,
            &observation.domain_label,
        );
        let entry =
            self.privacy_budgets
                .entry(key.clone())
                .or_insert_with(|| PrivacyBudgetRecord {
                    budget_id: key,
                    epoch: self.config.epoch,
                    source_id: observation.source_id.clone(),
                    domain_label: observation.domain_label.clone(),
                    budget_limit: self.config.privacy_budget_per_epoch,
                    spent: 0,
                    reserved: 0,
                });
        entry.spent = entry.spent.saturating_add(observation.privacy_budget_spent);
    }

    fn detect_conflicting_root(&self, observation: &RootObservation) -> bool {
        self.observations.values().any(|existing| {
            existing.domain_label == observation.domain_label
                && existing.root_kind == observation.root_kind
                && existing.counter == observation.counter
                && existing.root != observation.root
        })
    }

    fn record_inconsistency(
        &mut self,
        kind: InconsistencyKind,
        observation: &RootObservation,
        severity: u8,
        details: &str,
        evidence: &[Value],
    ) {
        let record = InconsistencyRecord::new(kind, observation, severity, details, evidence);
        self.open_remediation(&record);
        self.inconsistencies
            .insert(record.inconsistency_id.clone(), record);
    }

    fn open_remediation(&mut self, record: &InconsistencyRecord) {
        let action = remediation_for(record.kind);
        let due_slot = record
            .opened_slot
            .saturating_add(self.config.root_freshness_window_slots);
        let item = RemediationItem::new(
            record,
            action,
            "operator-progress-feed",
            record.severity,
            due_slot,
        );
        self.remediation_queue
            .insert(item.remediation_id.clone(), item);
        self.counters.remediations_opened += 1;
    }

    fn seed_demo_sources(&mut self) {
        for (kind, label, domains, weight) in demo_source_specs() {
            let mut set = BTreeSet::new();
            for domain in domains {
                set.insert(domain.to_string());
            }
            let source = SourceRegistration::new(
                kind,
                label,
                "devnet-operator",
                set,
                weight,
                self.config.min_pq_security_bits,
                self.config.current_slot,
            );
            let _ = self.register_source(source);
        }
    }

    fn seed_demo_observations(&mut self) {
        let sources = self.sources.values().cloned().collect::<Vec<_>>();
        for source in sources {
            let label = match source.domain_labels.iter().next() {
                Some(label) => label.clone(),
                None => source.kind.as_str().to_string(),
            };
            let root_kind = root_kind_for_source(source.kind);
            let root = stable_root(
                D_OBSERVATION,
                &[json!({
                    "source": source.source_id,
                    "kind": root_kind.as_str(),
                    "label": label,
                    "slot": self.config.current_slot
                })],
            );
            let input = RootObservationInput {
                source_id: source.source_id.clone(),
                source_kind: source.kind,
                root_kind,
                domain_label: label,
                root,
                previous_root: merkle_root(D_OBSERVATION, &[]),
                counter: 1,
                slot: self.config.current_slot,
                l2_height: self.config.l2_height,
                monero_height: self.config.monero_height,
                privacy_budget_spent: 5_000,
                pq_attestation_root: source.attestation_root.clone(),
                release_readiness_score: 9_200,
                bridge_liquidity_reserve: self.config.min_bridge_liquidity_reserve + 25_000_000,
                metadata: BTreeMap::from([(
                    "demo".to_string(),
                    json!({"network": self.config.l2_network, "source_kind": source.kind.as_str()}),
                )]),
            };
            let _ = self.ingest_observation(RootObservation::new(input));
        }
    }
}

pub fn deterministic_root(domain: &str, records: &[Value]) -> String {
    stable_root(domain, records)
}

pub fn deterministic_id(domain: &str, label: &str, counter: u64) -> String {
    stable_id(
        domain,
        &[
            HashPart::Str(label),
            HashPart::U64(counter),
            HashPart::Str(CHAIN_ID),
        ],
    )
}

pub fn build_wallet_api_observation(
    source: &SourceRegistration,
    counter: u64,
    slot: u64,
    wallet_counter_root: &str,
) -> RootObservation {
    RootObservation::new(RootObservationInput {
        source_id: source.source_id.clone(),
        source_kind: source.kind,
        root_kind: RootKind::WalletApiCounter,
        domain_label: "wallet-api-live-counters".to_string(),
        root: wallet_counter_root.to_string(),
        previous_root: merkle_root(D_OBSERVATION, &[]),
        counter,
        slot,
        l2_height: DEFAULT_L2_HEIGHT,
        monero_height: DEFAULT_MONERO_HEIGHT,
        privacy_budget_spent: 1_000,
        pq_attestation_root: source.attestation_root.clone(),
        release_readiness_score: 9_500,
        bridge_liquidity_reserve: 100_000_000,
        metadata: BTreeMap::from([("ingest_path".to_string(), json!("wallet_api"))]),
    })
}

pub fn build_bridge_gateway_observation(
    source: &SourceRegistration,
    counter: u64,
    slot: u64,
    gateway_root: &str,
    liquidity_reserve: u64,
) -> RootObservation {
    RootObservation::new(RootObservationInput {
        source_id: source.source_id.clone(),
        source_kind: source.kind,
        root_kind: RootKind::BridgeContractGateway,
        domain_label: "bridge-contract-gateway".to_string(),
        root: gateway_root.to_string(),
        previous_root: merkle_root(D_GATEWAY, &[]),
        counter,
        slot,
        l2_height: DEFAULT_L2_HEIGHT,
        monero_height: DEFAULT_MONERO_HEIGHT,
        privacy_budget_spent: 2_500,
        pq_attestation_root: source.attestation_root.clone(),
        release_readiness_score: 8_900,
        bridge_liquidity_reserve: liquidity_reserve,
        metadata: BTreeMap::from([("ingest_path".to_string(), json!("bridge_contract_gateway"))]),
    })
}

pub fn devnet_runtime() -> State {
    State::devnet()
}

pub fn demo_runtime() -> State {
    State::demo()
}

fn remediation_for(kind: InconsistencyKind) -> RemediationAction {
    match kind {
        InconsistencyKind::DuplicateDomainLabel => RemediationAction::RebuildDependency,
        InconsistencyKind::StaleObservation => RemediationAction::ReingestSource,
        InconsistencyKind::CounterRegression => RemediationAction::RefreshWalletCounters,
        InconsistencyKind::MissingDependency => RemediationAction::RebuildDependency,
        InconsistencyKind::PrivacyBudgetExceeded => RemediationAction::ThrottlePrivacySpend,
        InconsistencyKind::PqAttestationMissing | InconsistencyKind::PqAttestationWeak => {
            RemediationAction::RequestAttestation
        }
        InconsistencyKind::ConflictingStateRoot => RemediationAction::QuarantineRoot,
        InconsistencyKind::ReleaseReadinessBelowThreshold => RemediationAction::HoldRelease,
        InconsistencyKind::LiquidityBelowFloor => RemediationAction::ReconcileBridgeLiquidity,
    }
}

fn records_from_map<T: Serialize>(map: &BTreeMap<String, T>) -> Vec<Value> {
    map.values().map(|value| json!(value)).collect()
}

fn filter_records(records: &[Value], key: &str, value: &str) -> Vec<Value> {
    records
        .iter()
        .filter(|record| record.get(key).and_then(Value::as_str) == Some(value))
        .cloned()
        .collect()
}

fn market_records(records: &[Value]) -> Vec<Value> {
    records
        .iter()
        .filter(|record| {
            matches!(
                record.get("root_kind").and_then(Value::as_str),
                Some("low_fee_market")
                    | Some("monero_liquidity")
                    | Some("token_runtime")
                    | Some("contract_state")
            )
        })
        .cloned()
        .collect()
}

fn stable_root(domain: &str, records: &[Value]) -> String {
    merkle_root(domain, records)
}

fn stable_id(domain: &str, parts: &[HashPart<'_>]) -> String {
    domain_hash(domain, parts, 32)
}

fn ensure_nonempty(name: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        Err(format!("{name} must not be empty"))
    } else {
        Ok(())
    }
}

fn privacy_budget_key(epoch: u64, source_id: &str, domain_label: &str) -> String {
    stable_id(
        D_PRIVACY,
        &[
            HashPart::U64(epoch),
            HashPart::Str(source_id),
            HashPart::Str(domain_label),
        ],
    )
}

fn root_kind_for_source(kind: SourceKind) -> RootKind {
    match kind {
        SourceKind::WalletApi => RootKind::WalletApiCounter,
        SourceKind::DevnetScenarioRunner => RootKind::DevnetScenario,
        SourceKind::OperatorProgressFeed => RootKind::OperatorProgress,
        SourceKind::ReleaseReadiness => RootKind::ReleaseReadiness,
        SourceKind::BridgeContractGateway => RootKind::BridgeContractGateway,
        SourceKind::MobileFastSync => RootKind::MobileFastSync,
        SourceKind::MoneroBridgeFinality => RootKind::MoneroFinality,
        SourceKind::MoneroBridgeLiquidity => RootKind::MoneroLiquidity,
        SourceKind::LowFeeMarket => RootKind::LowFeeMarket,
        SourceKind::ContractRuntime => RootKind::ContractState,
        SourceKind::TokenRuntime => RootKind::TokenRuntime,
    }
}

fn demo_source_specs() -> Vec<(SourceKind, &'static str, Vec<&'static str>, u64)> {
    vec![
        (
            SourceKind::WalletApi,
            "wallet-api-live-root-feed",
            vec!["wallet-api-live-counters"],
            3,
        ),
        (
            SourceKind::DevnetScenarioRunner,
            "devnet-scenario-runner-feed",
            vec!["devnet-scenario-roots"],
            2,
        ),
        (
            SourceKind::OperatorProgressFeed,
            "operator-progress-feed",
            vec!["operator-progress-roots"],
            3,
        ),
        (
            SourceKind::ReleaseReadiness,
            "release-readiness-feed",
            vec!["release-readiness-roots"],
            3,
        ),
        (
            SourceKind::BridgeContractGateway,
            "bridge-contract-gateway-feed",
            vec!["bridge-contract-gateway"],
            4,
        ),
        (
            SourceKind::MobileFastSync,
            "mobile-fast-sync-feed",
            vec!["mobile-fast-sync-roots"],
            2,
        ),
        (
            SourceKind::MoneroBridgeFinality,
            "monero-finality-feed",
            vec!["monero-finality-roots"],
            4,
        ),
        (
            SourceKind::MoneroBridgeLiquidity,
            "monero-liquidity-feed",
            vec!["monero-liquidity-roots"],
            4,
        ),
        (
            SourceKind::LowFeeMarket,
            "low-fee-market-feed",
            vec!["low-fee-market-roots"],
            2,
        ),
        (
            SourceKind::ContractRuntime,
            "contract-runtime-feed",
            vec!["contract-state-roots"],
            3,
        ),
        (
            SourceKind::TokenRuntime,
            "token-runtime-feed",
            vec!["token-runtime-roots"],
            3,
        ),
    ]
}

fn synthetic_observation(
    source_id: &str,
    source_kind: SourceKind,
    root_kind: RootKind,
    domain_label: &str,
    slot: u64,
) -> RootObservation {
    RootObservation::new(RootObservationInput {
        source_id: source_id.to_string(),
        source_kind,
        root_kind,
        domain_label: domain_label.to_string(),
        root: stable_root(D_INCONSISTENCY, &[json!({"synthetic": domain_label})]),
        previous_root: merkle_root(D_INCONSISTENCY, &[]),
        counter: 0,
        slot,
        l2_height: DEFAULT_L2_HEIGHT,
        monero_height: DEFAULT_MONERO_HEIGHT,
        privacy_budget_spent: 0,
        pq_attestation_root: merkle_root(D_ATTESTATION, &[]),
        release_readiness_score: MAX_BPS,
        bridge_liquidity_reserve: u64::MAX,
        metadata: BTreeMap::new(),
    })
}

trait StateResultExt {
    fn fallback_state(self) -> State;
}

impl StateResultExt for Result<State> {
    fn fallback_state(self) -> State {
        match self {
            Ok(state) => state,
            Err(_) => State {
                config: Config::devnet(),
                counters: Counters::default(),
                roots: Roots::empty(),
                sources: BTreeMap::new(),
                observations: BTreeMap::new(),
                domain_index: BTreeMap::new(),
                dependency_edges: BTreeMap::new(),
                freshness_windows: BTreeMap::new(),
                privacy_budgets: BTreeMap::new(),
                pq_attestations: BTreeMap::new(),
                inconsistencies: BTreeMap::new(),
                remediation_queue: BTreeMap::new(),
            },
        }
    }
}
