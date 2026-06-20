use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalUserEscapeAnswerVerticalSliceForceExitPackagePrivacyBudgetReleaseRegressionGuardRuntimeResult<
    T,
> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_ANSWER_VERTICAL_SLICE_FORCE_EXIT_PACKAGE_PRIVACY_BUDGET_RELEASE_REGRESSION_GUARD_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-canonical-user-escape-answer-vertical-slice-force-exit-package-privacy-budget-release-regression-guard-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_ANSWER_VERTICAL_SLICE_FORCE_EXIT_PACKAGE_PRIVACY_BUDGET_RELEASE_REGRESSION_GUARD_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PRIVACY_BUDGET_RELEASE_REGRESSION_GUARD_SUITE: &str =
    "monero-l2-pq-bridge-exit-force-exit-package-privacy-budget-release-regression-guard-v1";
pub const DEFAULT_MAX_WALLET_REDACTION_BUDGET_UNITS: u64 = 12;
pub const DEFAULT_MAX_SCAN_TAG_LEAKAGE_UNITS: u64 = 0;
pub const DEFAULT_MIN_DECOY_SET_QUALITY_BPS: u64 = 9_500;
pub const DEFAULT_MIN_NULLIFIER_CONTINUITY_BPS: u64 = 10_000;
pub const DEFAULT_MAX_BRIDGE_METADATA_LEAKAGE_UNITS: u64 = 0;
pub const DEFAULT_MAX_REGRESSION_FINDINGS: u64 = 0;

const DOMAIN: &str =
    "MONERO-L2-PQ-BRIDGE-EXIT-FORCE-EXIT-PACKAGE-PRIVACY-BUDGET-RELEASE-REGRESSION-GUARD";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub guard_suite: String,
    pub release_id: String,
    pub force_exit_package_id: String,
    pub max_wallet_redaction_budget_units: u64,
    pub max_scan_tag_leakage_units: u64,
    pub min_decoy_set_quality_bps: u64,
    pub min_nullifier_continuity_bps: u64,
    pub max_bridge_metadata_leakage_units: u64,
    pub max_regression_findings: u64,
    pub require_zero_release_blockers: bool,
    pub hold_release_on_privacy_regression: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            guard_suite: PRIVACY_BUDGET_RELEASE_REGRESSION_GUARD_SUITE.to_string(),
            release_id: "force-exit-package-privacy-budget-release-devnet-v1".to_string(),
            force_exit_package_id: "monero-l2-pq-bridge-force-exit-package-devnet-v1".to_string(),
            max_wallet_redaction_budget_units: DEFAULT_MAX_WALLET_REDACTION_BUDGET_UNITS,
            max_scan_tag_leakage_units: DEFAULT_MAX_SCAN_TAG_LEAKAGE_UNITS,
            min_decoy_set_quality_bps: DEFAULT_MIN_DECOY_SET_QUALITY_BPS,
            min_nullifier_continuity_bps: DEFAULT_MIN_NULLIFIER_CONTINUITY_BPS,
            max_bridge_metadata_leakage_units: DEFAULT_MAX_BRIDGE_METADATA_LEAKAGE_UNITS,
            max_regression_findings: DEFAULT_MAX_REGRESSION_FINDINGS,
            require_zero_release_blockers: true,
            hold_release_on_privacy_regression: true,
        }
    }
}

impl Config {
    pub fn devnet() -> Self {
        Self::default()
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "guard_suite": self.guard_suite,
            "release_id": self.release_id,
            "force_exit_package_id": self.force_exit_package_id,
            "max_wallet_redaction_budget_units": self.max_wallet_redaction_budget_units,
            "max_scan_tag_leakage_units": self.max_scan_tag_leakage_units,
            "min_decoy_set_quality_bps": self.min_decoy_set_quality_bps,
            "min_nullifier_continuity_bps": self.min_nullifier_continuity_bps,
            "max_bridge_metadata_leakage_units": self.max_bridge_metadata_leakage_units,
            "max_regression_findings": self.max_regression_findings,
            "require_zero_release_blockers": self.require_zero_release_blockers,
            "hold_release_on_privacy_regression": self.hold_release_on_privacy_regression,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GuardLane {
    WalletRedactionBudget,
    ScanTagLeakageBudget,
    DecoySetQuality,
    NullifierContinuity,
    BridgeMetadataLeakage,
    RegressionFinding,
}

impl GuardLane {
    pub fn all() -> [Self; 6] {
        [
            Self::WalletRedactionBudget,
            Self::ScanTagLeakageBudget,
            Self::DecoySetQuality,
            Self::NullifierContinuity,
            Self::BridgeMetadataLeakage,
            Self::RegressionFinding,
        ]
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::WalletRedactionBudget => "wallet_redaction_budget",
            Self::ScanTagLeakageBudget => "scan_tag_leakage_budget",
            Self::DecoySetQuality => "decoy_set_quality",
            Self::NullifierContinuity => "nullifier_continuity",
            Self::BridgeMetadataLeakage => "bridge_metadata_leakage",
            Self::RegressionFinding => "regression_finding",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GuardStatus {
    WithinBudget,
    AtBudgetCeiling,
    ReleaseBlockingRegression,
    HeldForPrivacyReview,
}

impl GuardStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WithinBudget => "within_budget",
            Self::AtBudgetCeiling => "at_budget_ceiling",
            Self::ReleaseBlockingRegression => "release_blocking_regression",
            Self::HeldForPrivacyReview => "held_for_privacy_review",
        }
    }

    pub fn blocks_release(self) -> bool {
        matches!(
            self,
            Self::ReleaseBlockingRegression | Self::HeldForPrivacyReview
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivacyBudgetGuard {
    pub guard_id: String,
    pub ordinal: u64,
    pub lane: GuardLane,
    pub wallet_redaction_budget_root: String,
    pub scan_tag_leakage_budget_root: String,
    pub decoy_set_quality_root: String,
    pub nullifier_continuity_root: String,
    pub bridge_metadata_leakage_root: String,
    pub regression_finding_root: String,
    pub guard_record_root: String,
    pub wallet_redaction_budget_units: u64,
    pub scan_tag_leakage_units: u64,
    pub decoy_set_quality_bps: u64,
    pub nullifier_continuity_bps: u64,
    pub bridge_metadata_leakage_units: u64,
    pub regression_finding_count: u64,
    pub release_blocker: bool,
    pub status: GuardStatus,
}

impl PrivacyBudgetGuard {
    pub fn devnet(config: &Config, lane: GuardLane, ordinal: u64) -> Self {
        let wallet_redaction_budget_units = wallet_redaction_budget_units(lane, config);
        let scan_tag_leakage_units = scan_tag_leakage_units(lane);
        let decoy_set_quality_bps = decoy_set_quality_bps(lane, config);
        let nullifier_continuity_bps = nullifier_continuity_bps(lane, config);
        let bridge_metadata_leakage_units = bridge_metadata_leakage_units(lane);
        let regression_finding_count = regression_finding_count(lane);
        let status = guard_status(
            config,
            wallet_redaction_budget_units,
            scan_tag_leakage_units,
            decoy_set_quality_bps,
            nullifier_continuity_bps,
            bridge_metadata_leakage_units,
            regression_finding_count,
        );
        let release_blocker = status.blocks_release();
        let wallet_redaction_budget_root = lane_metric_root(
            config,
            lane,
            ordinal,
            "wallet-redaction-budget",
            wallet_redaction_budget_units,
        );
        let scan_tag_leakage_budget_root = lane_metric_root(
            config,
            lane,
            ordinal,
            "scan-tag-leakage-budget",
            scan_tag_leakage_units,
        );
        let decoy_set_quality_root = lane_metric_root(
            config,
            lane,
            ordinal,
            "decoy-set-quality",
            decoy_set_quality_bps,
        );
        let nullifier_continuity_root = lane_metric_root(
            config,
            lane,
            ordinal,
            "nullifier-continuity",
            nullifier_continuity_bps,
        );
        let bridge_metadata_leakage_root = lane_metric_root(
            config,
            lane,
            ordinal,
            "bridge-metadata-leakage",
            bridge_metadata_leakage_units,
        );
        let regression_finding_root = lane_metric_root(
            config,
            lane,
            ordinal,
            "regression-finding",
            regression_finding_count,
        );
        let guard_record_root = guard_record_root(
            config,
            lane,
            ordinal,
            &wallet_redaction_budget_root,
            &scan_tag_leakage_budget_root,
            &decoy_set_quality_root,
            &nullifier_continuity_root,
            &bridge_metadata_leakage_root,
            &regression_finding_root,
            status,
            release_blocker,
        );
        let guard_id = guard_id(lane, ordinal, &guard_record_root);

        Self {
            guard_id,
            ordinal,
            lane,
            wallet_redaction_budget_root,
            scan_tag_leakage_budget_root,
            decoy_set_quality_root,
            nullifier_continuity_root,
            bridge_metadata_leakage_root,
            regression_finding_root,
            guard_record_root,
            wallet_redaction_budget_units,
            scan_tag_leakage_units,
            decoy_set_quality_bps,
            nullifier_continuity_bps,
            bridge_metadata_leakage_units,
            regression_finding_count,
            release_blocker,
            status,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "guard_id": self.guard_id,
            "ordinal": self.ordinal,
            "lane": self.lane.as_str(),
            "wallet_redaction_budget_root": self.wallet_redaction_budget_root,
            "scan_tag_leakage_budget_root": self.scan_tag_leakage_budget_root,
            "decoy_set_quality_root": self.decoy_set_quality_root,
            "nullifier_continuity_root": self.nullifier_continuity_root,
            "bridge_metadata_leakage_root": self.bridge_metadata_leakage_root,
            "regression_finding_root": self.regression_finding_root,
            "guard_record_root": self.guard_record_root,
            "wallet_redaction_budget_units": self.wallet_redaction_budget_units,
            "scan_tag_leakage_units": self.scan_tag_leakage_units,
            "decoy_set_quality_bps": self.decoy_set_quality_bps,
            "nullifier_continuity_bps": self.nullifier_continuity_bps,
            "bridge_metadata_leakage_units": self.bridge_metadata_leakage_units,
            "regression_finding_count": self.regression_finding_count,
            "release_blocker": self.release_blocker,
            "status": self.status.as_str(),
        })
    }

    pub fn state_root(&self) -> String {
        self.guard_record_root.clone()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub wallet_redaction_budget_root: String,
    pub scan_tag_leakage_budget_root: String,
    pub decoy_set_quality_root: String,
    pub nullifier_continuity_root: String,
    pub bridge_metadata_leakage_root: String,
    pub regression_finding_root: String,
    pub release_blocker_root: String,
    pub privacy_budget_guard_root: String,
}

impl Roots {
    pub fn from_guards(guards: &[PrivacyBudgetGuard]) -> Self {
        let wallet_redaction_budget_root =
            root_from_guard_values("wallet-redaction-budgets", guards, |guard| {
                guard.wallet_redaction_budget_root.clone()
            });
        let scan_tag_leakage_budget_root =
            root_from_guard_values("scan-tag-leakage-budgets", guards, |guard| {
                guard.scan_tag_leakage_budget_root.clone()
            });
        let decoy_set_quality_root = root_from_guard_values("decoy-set-quality", guards, |guard| {
            guard.decoy_set_quality_root.clone()
        });
        let nullifier_continuity_root =
            root_from_guard_values("nullifier-continuity", guards, |guard| {
                guard.nullifier_continuity_root.clone()
            });
        let bridge_metadata_leakage_root =
            root_from_guard_values("bridge-metadata-leakage", guards, |guard| {
                guard.bridge_metadata_leakage_root.clone()
            });
        let regression_finding_root =
            root_from_guard_values("regression-findings", guards, |guard| {
                guard.regression_finding_root.clone()
            });
        let release_blocker_root =
            root_from_guard_records("release-blockers", &release_blocker_records(guards));
        let privacy_budget_guard_root = merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-PRIVACY-BUDGET-GUARD-RECORDS",
            &guards
                .iter()
                .map(PrivacyBudgetGuard::public_record)
                .collect::<Vec<_>>(),
        );

        Self {
            wallet_redaction_budget_root,
            scan_tag_leakage_budget_root,
            decoy_set_quality_root,
            nullifier_continuity_root,
            bridge_metadata_leakage_root,
            regression_finding_root,
            release_blocker_root,
            privacy_budget_guard_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "wallet_redaction_budget_root": self.wallet_redaction_budget_root,
            "scan_tag_leakage_budget_root": self.scan_tag_leakage_budget_root,
            "decoy_set_quality_root": self.decoy_set_quality_root,
            "nullifier_continuity_root": self.nullifier_continuity_root,
            "bridge_metadata_leakage_root": self.bridge_metadata_leakage_root,
            "regression_finding_root": self.regression_finding_root,
            "release_blocker_root": self.release_blocker_root,
            "privacy_budget_guard_root": self.privacy_budget_guard_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("roots", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub guard_count: u64,
    pub wallet_redaction_budget_units: u64,
    pub scan_tag_leakage_units: u64,
    pub min_decoy_set_quality_bps: u64,
    pub min_nullifier_continuity_bps: u64,
    pub bridge_metadata_leakage_units: u64,
    pub regression_finding_count: u64,
    pub release_blocker_count: u64,
    pub within_budget_count: u64,
    pub held_for_privacy_review_count: u64,
}

impl Counters {
    pub fn from_guards(guards: &[PrivacyBudgetGuard]) -> Self {
        let guard_count = guards.len() as u64;
        let wallet_redaction_budget_units = guards
            .iter()
            .map(|guard| guard.wallet_redaction_budget_units)
            .sum();
        let scan_tag_leakage_units = guards
            .iter()
            .map(|guard| guard.scan_tag_leakage_units)
            .sum();
        let min_decoy_set_quality_bps = guards.iter().fold(10_000, |lowest, guard| {
            if guard.decoy_set_quality_bps < lowest {
                guard.decoy_set_quality_bps
            } else {
                lowest
            }
        });
        let min_nullifier_continuity_bps = guards.iter().fold(10_000, |lowest, guard| {
            if guard.nullifier_continuity_bps < lowest {
                guard.nullifier_continuity_bps
            } else {
                lowest
            }
        });
        let bridge_metadata_leakage_units = guards
            .iter()
            .map(|guard| guard.bridge_metadata_leakage_units)
            .sum();
        let regression_finding_count = guards
            .iter()
            .map(|guard| guard.regression_finding_count)
            .sum();
        let release_blocker_count =
            guards.iter().filter(|guard| guard.release_blocker).count() as u64;
        let within_budget_count = guards
            .iter()
            .filter(|guard| guard.status == GuardStatus::WithinBudget)
            .count() as u64;
        let held_for_privacy_review_count = guards
            .iter()
            .filter(|guard| guard.status == GuardStatus::HeldForPrivacyReview)
            .count() as u64;

        Self {
            guard_count,
            wallet_redaction_budget_units,
            scan_tag_leakage_units,
            min_decoy_set_quality_bps,
            min_nullifier_continuity_bps,
            bridge_metadata_leakage_units,
            regression_finding_count,
            release_blocker_count,
            within_budget_count,
            held_for_privacy_review_count,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "guard_count": self.guard_count,
            "wallet_redaction_budget_units": self.wallet_redaction_budget_units,
            "scan_tag_leakage_units": self.scan_tag_leakage_units,
            "min_decoy_set_quality_bps": self.min_decoy_set_quality_bps,
            "min_nullifier_continuity_bps": self.min_nullifier_continuity_bps,
            "bridge_metadata_leakage_units": self.bridge_metadata_leakage_units,
            "regression_finding_count": self.regression_finding_count,
            "release_blocker_count": self.release_blocker_count,
            "within_budget_count": self.within_budget_count,
            "held_for_privacy_review_count": self.held_for_privacy_review_count,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("counters", &self.public_record())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivacyHoldVerdict {
    ReleaseAllowed,
    HeldForBudgetRegression,
    HeldForLeakageRegression,
    HeldForQualityRegression,
    HeldForReleaseBlockers,
}

impl PrivacyHoldVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ReleaseAllowed => "release_allowed",
            Self::HeldForBudgetRegression => "held_for_budget_regression",
            Self::HeldForLeakageRegression => "held_for_leakage_regression",
            Self::HeldForQualityRegression => "held_for_quality_regression",
            Self::HeldForReleaseBlockers => "held_for_release_blockers",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub guards: Vec<PrivacyBudgetGuard>,
    pub roots: Roots,
    pub counters: Counters,
    pub privacy_hold_verdict: PrivacyHoldVerdict,
    pub release_allowed: bool,
    pub verdict_root: String,
    pub state_commitment_root: String,
}

impl State {
    pub fn new(
        config: Config,
        guards: Vec<PrivacyBudgetGuard>,
    ) -> MoneroL2PqBridgeExitCanonicalUserEscapeAnswerVerticalSliceForceExitPackagePrivacyBudgetReleaseRegressionGuardRuntimeResult<Self>
    {
        validate_config(&config)?;
        if guards.is_empty() {
            return Err("privacy budget release regression guard requires guard lanes".to_string());
        }

        let roots = Roots::from_guards(&guards);
        let counters = Counters::from_guards(&guards);
        let privacy_hold_verdict = privacy_hold_verdict(&config, &counters);
        let release_allowed = privacy_hold_verdict == PrivacyHoldVerdict::ReleaseAllowed;
        let verdict_root = verdict_root(&config, &roots, &counters, privacy_hold_verdict);
        let state_commitment_root =
            state_commitment_root(&config, &roots, &counters, &verdict_root, release_allowed);

        Ok(Self {
            config,
            guards,
            roots,
            counters,
            privacy_hold_verdict,
            release_allowed,
            verdict_root,
            state_commitment_root,
        })
    }

    pub fn devnet() -> Self {
        let config = Config::devnet();
        let guards = GuardLane::all()
            .into_iter()
            .enumerate()
            .map(|(index, lane)| PrivacyBudgetGuard::devnet(&config, lane, index as u64 + 1))
            .collect::<Vec<_>>();

        match Self::new(config, guards) {
            Ok(state) => state,
            Err(reason) => fallback_state(reason),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "privacy_budget_release_regression_guard_suite":
                PRIVACY_BUDGET_RELEASE_REGRESSION_GUARD_SUITE,
            "config": self.config.public_record(),
            "guards": self
                .guards
                .iter()
                .map(PrivacyBudgetGuard::public_record)
                .collect::<Vec<_>>(),
            "roots": self.roots.public_record(),
            "counters": self.counters.public_record(),
            "privacy_hold_verdict": self.privacy_hold_verdict.as_str(),
            "release_allowed": self.release_allowed,
            "verdict_root": self.verdict_root,
            "state_commitment_root": self.state_commitment_root,
        })
    }

    pub fn state_root(&self) -> String {
        self.state_commitment_root.clone()
    }
}

pub fn devnet() -> Runtime {
    State::devnet()
}

pub fn public_record() -> Value {
    devnet().public_record()
}

pub fn state_root() -> String {
    devnet().state_root()
}

fn wallet_redaction_budget_units(lane: GuardLane, config: &Config) -> u64 {
    match lane {
        GuardLane::WalletRedactionBudget => config.max_wallet_redaction_budget_units,
        GuardLane::RegressionFinding => 1,
        _ => 0,
    }
}

fn scan_tag_leakage_units(lane: GuardLane) -> u64 {
    match lane {
        GuardLane::ScanTagLeakageBudget | GuardLane::RegressionFinding => 1,
        _ => 0,
    }
}

fn decoy_set_quality_bps(lane: GuardLane, config: &Config) -> u64 {
    match lane {
        GuardLane::DecoySetQuality => config.min_decoy_set_quality_bps.saturating_sub(25),
        _ => 10_000,
    }
}

fn nullifier_continuity_bps(lane: GuardLane, config: &Config) -> u64 {
    match lane {
        GuardLane::NullifierContinuity => config.min_nullifier_continuity_bps,
        GuardLane::RegressionFinding => config.min_nullifier_continuity_bps.saturating_sub(100),
        _ => 10_000,
    }
}

fn bridge_metadata_leakage_units(lane: GuardLane) -> u64 {
    match lane {
        GuardLane::BridgeMetadataLeakage | GuardLane::RegressionFinding => 1,
        _ => 0,
    }
}

fn regression_finding_count(lane: GuardLane) -> u64 {
    match lane {
        GuardLane::RegressionFinding => 1,
        _ => 0,
    }
}

fn guard_status(
    config: &Config,
    wallet_redaction_budget_units: u64,
    scan_tag_leakage_units: u64,
    decoy_set_quality_bps: u64,
    nullifier_continuity_bps: u64,
    bridge_metadata_leakage_units: u64,
    regression_finding_count: u64,
) -> GuardStatus {
    if regression_finding_count > config.max_regression_findings {
        GuardStatus::ReleaseBlockingRegression
    } else if scan_tag_leakage_units > config.max_scan_tag_leakage_units
        || bridge_metadata_leakage_units > config.max_bridge_metadata_leakage_units
    {
        GuardStatus::HeldForPrivacyReview
    } else if decoy_set_quality_bps < config.min_decoy_set_quality_bps
        || nullifier_continuity_bps < config.min_nullifier_continuity_bps
    {
        GuardStatus::HeldForPrivacyReview
    } else if wallet_redaction_budget_units == config.max_wallet_redaction_budget_units {
        GuardStatus::AtBudgetCeiling
    } else {
        GuardStatus::WithinBudget
    }
}

fn privacy_hold_verdict(config: &Config, counters: &Counters) -> PrivacyHoldVerdict {
    if config.require_zero_release_blockers && counters.release_blocker_count > 0 {
        PrivacyHoldVerdict::HeldForReleaseBlockers
    } else if counters.wallet_redaction_budget_units > config.max_wallet_redaction_budget_units
        || counters.regression_finding_count > config.max_regression_findings
    {
        PrivacyHoldVerdict::HeldForBudgetRegression
    } else if counters.scan_tag_leakage_units > config.max_scan_tag_leakage_units
        || counters.bridge_metadata_leakage_units > config.max_bridge_metadata_leakage_units
    {
        PrivacyHoldVerdict::HeldForLeakageRegression
    } else if counters.min_decoy_set_quality_bps < config.min_decoy_set_quality_bps
        || counters.min_nullifier_continuity_bps < config.min_nullifier_continuity_bps
    {
        PrivacyHoldVerdict::HeldForQualityRegression
    } else {
        PrivacyHoldVerdict::ReleaseAllowed
    }
}

fn lane_metric_root(
    config: &Config,
    lane: GuardLane,
    ordinal: u64,
    metric: &str,
    value: u64,
) -> String {
    record_root(
        metric,
        &json!({
            "chain_id": config.chain_id,
            "release_id": config.release_id,
            "force_exit_package_id": config.force_exit_package_id,
            "lane": lane.as_str(),
            "ordinal": ordinal,
            "metric": metric,
            "value": value,
            "guard_suite": config.guard_suite,
        }),
    )
}

fn guard_record_root(
    config: &Config,
    lane: GuardLane,
    ordinal: u64,
    wallet_redaction_budget_root: &str,
    scan_tag_leakage_budget_root: &str,
    decoy_set_quality_root: &str,
    nullifier_continuity_root: &str,
    bridge_metadata_leakage_root: &str,
    regression_finding_root: &str,
    status: GuardStatus,
    release_blocker: bool,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-PRIVACY-BUDGET-GUARD-RECORD",
        &[
            HashPart::Str(&config.chain_id),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(lane.as_str()),
            HashPart::U64(ordinal),
            HashPart::Str(wallet_redaction_budget_root),
            HashPart::Str(scan_tag_leakage_budget_root),
            HashPart::Str(decoy_set_quality_root),
            HashPart::Str(nullifier_continuity_root),
            HashPart::Str(bridge_metadata_leakage_root),
            HashPart::Str(regression_finding_root),
            HashPart::Str(status.as_str()),
            HashPart::Str(bool_str(release_blocker)),
        ],
        32,
    )
}

fn guard_id(lane: GuardLane, ordinal: u64, guard_record_root: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-PRIVACY-BUDGET-GUARD-ID",
        &[
            HashPart::Str(lane.as_str()),
            HashPart::U64(ordinal),
            HashPart::Str(guard_record_root),
        ],
        16,
    )
}

fn root_from_guard_values<F>(kind: &str, guards: &[PrivacyBudgetGuard], select: F) -> String
where
    F: Fn(&PrivacyBudgetGuard) -> String,
{
    let leaves = guards
        .iter()
        .map(|guard| {
            json!({
                "guard_id": guard.guard_id,
                "lane": guard.lane.as_str(),
                "root": select(guard),
            })
        })
        .collect::<Vec<_>>();
    root_from_guard_records(kind, &leaves)
}

fn root_from_guard_records(kind: &str, leaves: &[Value]) -> String {
    record_root(
        kind,
        &json!({
            "kind": kind,
            "leaf_count": leaves.len() as u64,
            "leaf_root": merkle_root(
                "MONERO-L2-PQ-BRIDGE-EXIT-PRIVACY-BUDGET-GUARD-LEAVES",
                leaves
            ),
        }),
    )
}

fn release_blocker_records(guards: &[PrivacyBudgetGuard]) -> Vec<Value> {
    guards
        .iter()
        .filter(|guard| guard.release_blocker)
        .map(|guard| {
            json!({
                "guard_id": guard.guard_id,
                "lane": guard.lane.as_str(),
                "status": guard.status.as_str(),
                "guard_record_root": guard.guard_record_root,
            })
        })
        .collect()
}

fn verdict_root(
    config: &Config,
    roots: &Roots,
    counters: &Counters,
    privacy_hold_verdict: PrivacyHoldVerdict,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-PRIVACY-BUDGET-GUARD-VERDICT",
        &[
            HashPart::Str(&config.chain_id),
            HashPart::Str(&roots.state_root()),
            HashPart::Str(&counters.state_root()),
            HashPart::U64(counters.wallet_redaction_budget_units),
            HashPart::U64(counters.scan_tag_leakage_units),
            HashPart::U64(counters.bridge_metadata_leakage_units),
            HashPart::U64(counters.regression_finding_count),
            HashPart::U64(counters.release_blocker_count),
            HashPart::Str(privacy_hold_verdict.as_str()),
        ],
        32,
    )
}

fn state_commitment_root(
    config: &Config,
    roots: &Roots,
    counters: &Counters,
    verdict_root: &str,
    release_allowed: bool,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-PRIVACY-BUDGET-GUARD-STATE",
        &[
            HashPart::Str(&config.state_root()),
            HashPart::Str(&roots.state_root()),
            HashPart::Str(&counters.state_root()),
            HashPart::Str(verdict_root),
            HashPart::Str(bool_str(release_allowed)),
        ],
        32,
    )
}

fn validate_config(config: &Config) -> Result<()> {
    if config.chain_id != CHAIN_ID {
        return Err("privacy budget release regression guard chain mismatch".to_string());
    }
    if config.protocol_version != PROTOCOL_VERSION {
        return Err("privacy budget release regression guard protocol mismatch".to_string());
    }
    if config.schema_version != SCHEMA_VERSION {
        return Err("privacy budget release regression guard schema mismatch".to_string());
    }
    if config.min_decoy_set_quality_bps > 10_000 {
        return Err("privacy budget release regression guard decoy threshold too high".to_string());
    }
    if config.min_nullifier_continuity_bps > 10_000 {
        return Err(
            "privacy budget release regression guard nullifier threshold too high".to_string(),
        );
    }
    Ok(())
}

fn fallback_state(reason: String) -> State {
    let config = Config::default();
    let fallback_guard = PrivacyBudgetGuard {
        guard_id: record_root("fallback-guard-id", &json!({"reason": &reason})),
        ordinal: 1,
        lane: GuardLane::RegressionFinding,
        wallet_redaction_budget_root: record_root(
            "fallback-wallet-redaction-budget",
            &json!({"reason": &reason}),
        ),
        scan_tag_leakage_budget_root: record_root(
            "fallback-scan-tag-leakage-budget",
            &json!({"reason": &reason}),
        ),
        decoy_set_quality_root: record_root(
            "fallback-decoy-set-quality",
            &json!({"reason": &reason}),
        ),
        nullifier_continuity_root: record_root(
            "fallback-nullifier-continuity",
            &json!({"reason": &reason}),
        ),
        bridge_metadata_leakage_root: record_root(
            "fallback-bridge-metadata-leakage",
            &json!({"reason": &reason}),
        ),
        regression_finding_root: record_root(
            "fallback-regression-finding",
            &json!({"reason": &reason}),
        ),
        guard_record_root: record_root("fallback-guard-record", &json!({"reason": &reason})),
        wallet_redaction_budget_units: 1,
        scan_tag_leakage_units: 1,
        decoy_set_quality_bps: 0,
        nullifier_continuity_bps: 0,
        bridge_metadata_leakage_units: 1,
        regression_finding_count: 1,
        release_blocker: true,
        status: GuardStatus::ReleaseBlockingRegression,
    };
    let guards = vec![fallback_guard];
    let roots = Roots::from_guards(&guards);
    let counters = Counters::from_guards(&guards);
    let privacy_hold_verdict = PrivacyHoldVerdict::HeldForReleaseBlockers;
    let release_allowed = false;
    let verdict_root = verdict_root(&config, &roots, &counters, privacy_hold_verdict);
    let state_commitment_root =
        state_commitment_root(&config, &roots, &counters, &verdict_root, release_allowed);

    State {
        config,
        guards,
        roots,
        counters,
        privacy_hold_verdict,
        release_allowed,
        verdict_root,
        state_commitment_root,
    }
}

pub fn record_root(kind: &str, record: &Value) -> String {
    domain_hash(
        DOMAIN,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(kind),
            HashPart::Json(record),
        ],
        32,
    )
}

fn bool_str(value: bool) -> &'static str {
    if value {
        "true"
    } else {
        "false"
    }
}
