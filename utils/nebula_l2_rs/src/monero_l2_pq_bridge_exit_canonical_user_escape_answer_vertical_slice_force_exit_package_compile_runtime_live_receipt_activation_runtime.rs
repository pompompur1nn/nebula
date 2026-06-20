use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalUserEscapeAnswerVerticalSliceForceExitPackageCompileRuntimeLiveReceiptActivationRuntimeResult<
    T,
> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_ANSWER_VERTICAL_SLICE_FORCE_EXIT_PACKAGE_COMPILE_RUNTIME_LIVE_RECEIPT_ACTIVATION_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-canonical-user-escape-answer-vertical-slice-force-exit-package-compile-runtime-live-receipt-activation-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_ANSWER_VERTICAL_SLICE_FORCE_EXIT_PACKAGE_COMPILE_RUNTIME_LIVE_RECEIPT_ACTIVATION_RUNTIME_PROTOCOL_VERSION;
pub const ACTIVATION_SUITE: &str =
    "monero-l2-pq-force-exit-package-compile-runtime-live-receipt-activation-v1";
pub const DEFAULT_VERTICAL_SLICE_ID: &str =
    "monero-l2-pq-bridge-exit-canonical-user-escape-answer-vertical-slice-devnet-v1";
pub const DEFAULT_FORCE_EXIT_PACKAGE_ID: &str =
    "force-exit-package-compile-runtime-live-receipt-activation-devnet-0001";
pub const DEFAULT_RECEIPT_EPOCH: u64 = 78;
pub const DEFAULT_L2_HEIGHT: u64 = 884_378;
pub const DEFAULT_SOURCE_HEIGHT: u64 = 2_771_878;
pub const DEFAULT_MAX_RECEIPT_AGE_BLOCKS: u64 = 72;
pub const DEFAULT_MIN_LIVE_RECEIPTS: u64 = 5;
pub const DEFAULT_MIN_ACCEPTED_FAMILIES: u64 = 5;
pub const DEFAULT_MIN_DISTINCT_OPERATORS: u64 = 3;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub activation_suite: String,
    pub vertical_slice_id: String,
    pub force_exit_package_id: String,
    pub receipt_epoch: u64,
    pub l2_height: u64,
    pub source_height: u64,
    pub max_receipt_age_blocks: u64,
    pub min_live_receipts: u64,
    pub min_accepted_families: u64,
    pub min_distinct_operators: u64,
    pub min_release_policy_roots: u64,
    pub require_compile_receipt: bool,
    pub require_cargo_check_receipt: bool,
    pub require_rustfmt_receipt: bool,
    pub require_clippy_receipt: bool,
    pub require_cargo_test_receipt: bool,
    pub require_release_policy_binding: bool,
    pub require_live_observer_quorum: bool,
    pub reject_stale_receipts: bool,
    pub fail_closed_on_missing_root: bool,
    pub fail_closed_on_status_mismatch: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: 1,
            hash_suite: "SHAKE256-domain-separated-canonical-json".to_string(),
            activation_suite: ACTIVATION_SUITE.to_string(),
            vertical_slice_id: DEFAULT_VERTICAL_SLICE_ID.to_string(),
            force_exit_package_id: DEFAULT_FORCE_EXIT_PACKAGE_ID.to_string(),
            receipt_epoch: DEFAULT_RECEIPT_EPOCH,
            l2_height: DEFAULT_L2_HEIGHT,
            source_height: DEFAULT_SOURCE_HEIGHT,
            max_receipt_age_blocks: DEFAULT_MAX_RECEIPT_AGE_BLOCKS,
            min_live_receipts: DEFAULT_MIN_LIVE_RECEIPTS,
            min_accepted_families: DEFAULT_MIN_ACCEPTED_FAMILIES,
            min_distinct_operators: DEFAULT_MIN_DISTINCT_OPERATORS,
            min_release_policy_roots: 2,
            require_compile_receipt: true,
            require_cargo_check_receipt: true,
            require_rustfmt_receipt: true,
            require_clippy_receipt: true,
            require_cargo_test_receipt: true,
            require_release_policy_binding: true,
            require_live_observer_quorum: true,
            reject_stale_receipts: true,
            fail_closed_on_missing_root: true,
            fail_closed_on_status_mismatch: true,
        }
    }
}

impl Config {
    pub fn devnet() -> Self {
        Self::default()
    }

    pub fn required_family_count(&self) -> u64 {
        [
            self.require_compile_receipt,
            self.require_cargo_check_receipt,
            self.require_rustfmt_receipt,
            self.require_clippy_receipt,
            self.require_cargo_test_receipt,
        ]
        .iter()
        .filter(|required| **required)
        .count() as u64
    }

    pub fn effective_min_accepted_families(&self) -> u64 {
        self.min_accepted_families
            .max(self.required_family_count())
            .min(ReceiptFamily::ordered().len() as u64)
    }

    pub fn state_root(&self) -> String {
        record_root("config", &json!(self))
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptFamily {
    Compile,
    CargoCheck,
    Rustfmt,
    Clippy,
    CargoTest,
}

impl ReceiptFamily {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Compile => "compile",
            Self::CargoCheck => "cargo_check",
            Self::Rustfmt => "rustfmt",
            Self::Clippy => "clippy",
            Self::CargoTest => "cargo_test",
        }
    }

    pub fn required_by(self, config: &Config) -> bool {
        match self {
            Self::Compile => config.require_compile_receipt,
            Self::CargoCheck => config.require_cargo_check_receipt,
            Self::Rustfmt => config.require_rustfmt_receipt,
            Self::Clippy => config.require_clippy_receipt,
            Self::CargoTest => config.require_cargo_test_receipt,
        }
    }

    pub fn ordered() -> &'static [Self] {
        &[
            Self::Compile,
            Self::CargoCheck,
            Self::Rustfmt,
            Self::Clippy,
            Self::CargoTest,
        ]
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolExitStatus {
    Passed,
    Failed,
    ReplayedOnly,
}

impl ToolExitStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Passed => "passed",
            Self::Failed => "failed",
            Self::ReplayedOnly => "replayed_only",
        }
    }

    pub fn is_success(self) -> bool {
        matches!(self, Self::Passed | Self::ReplayedOnly)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptFreshness {
    Live,
    Stale,
}

impl ReceiptFreshness {
    pub fn is_live(self) -> bool {
        matches!(self, Self::Live)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptActivationStatus {
    AcceptedLive,
    AcceptedReplayOnly,
    HeldMissingRoot,
    HeldStale,
    HeldCommandFailed,
    HeldStatusMismatch,
    HeldMissingPolicyBinding,
}

impl ReceiptActivationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AcceptedLive => "accepted_live",
            Self::AcceptedReplayOnly => "accepted_replay_only",
            Self::HeldMissingRoot => "held_missing_root",
            Self::HeldStale => "held_stale",
            Self::HeldCommandFailed => "held_command_failed",
            Self::HeldStatusMismatch => "held_status_mismatch",
            Self::HeldMissingPolicyBinding => "held_missing_policy_binding",
        }
    }

    pub fn permits_activation(self) -> bool {
        matches!(self, Self::AcceptedLive | Self::AcceptedReplayOnly)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ActivationVerdictStatus {
    Activated,
    HeldForQuorum,
    HeldForRequiredFamily,
    HeldForObserverQuorum,
    HeldForReleasePolicy,
    FailClosed,
}

impl ActivationVerdictStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Activated => "activated",
            Self::HeldForQuorum => "held_for_quorum",
            Self::HeldForRequiredFamily => "held_for_required_family",
            Self::HeldForObserverQuorum => "held_for_observer_quorum",
            Self::HeldForReleasePolicy => "held_for_release_policy",
            Self::FailClosed => "fail_closed",
        }
    }

    pub fn permits_release(self) -> bool {
        matches!(self, Self::Activated)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiveReceiptEvidence {
    pub receipt_id: String,
    pub family: ReceiptFamily,
    pub tool_status: ToolExitStatus,
    pub artifact_root: String,
    pub diagnostic_root: String,
    pub environment_root: String,
    pub release_policy_root: String,
    pub observer_quorum_root: String,
    pub operator_commitment: String,
    pub observed_height: u64,
    pub current_height: u64,
    pub receipt_age_blocks: u64,
    pub freshness: ReceiptFreshness,
    pub required_status_root: String,
    pub observed_status_root: String,
    pub activation_status: ReceiptActivationStatus,
    pub activation_root: String,
}

impl LiveReceiptEvidence {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        family: ReceiptFamily,
        tool_status: ToolExitStatus,
        artifact_root: &str,
        diagnostic_root: &str,
        environment_root: &str,
        release_policy_root: &str,
        observer_quorum_root: &str,
        operator_commitment: &str,
        observed_height: u64,
        current_height: u64,
        config: &Config,
    ) -> Self {
        let receipt_age_blocks = current_height.saturating_sub(observed_height);
        let freshness = if config.reject_stale_receipts
            && (observed_height == 0 || receipt_age_blocks > config.max_receipt_age_blocks)
        {
            ReceiptFreshness::Stale
        } else {
            ReceiptFreshness::Live
        };
        let required_status_root = status_root(family, ToolExitStatus::Passed, config);
        let observed_status_root = status_root(family, tool_status, config);
        let has_missing_root = [
            artifact_root,
            diagnostic_root,
            environment_root,
            observer_quorum_root,
        ]
        .iter()
        .any(|root| root.is_empty());
        let status_mismatch = config.fail_closed_on_status_mismatch
            && family.required_by(config)
            && !tool_status.is_success();
        let missing_policy_binding =
            config.require_release_policy_binding && release_policy_root.is_empty();
        let activation_status = if config.fail_closed_on_missing_root && has_missing_root {
            ReceiptActivationStatus::HeldMissingRoot
        } else if !freshness.is_live() {
            ReceiptActivationStatus::HeldStale
        } else if status_mismatch {
            ReceiptActivationStatus::HeldStatusMismatch
        } else if !tool_status.is_success() {
            ReceiptActivationStatus::HeldCommandFailed
        } else if missing_policy_binding {
            ReceiptActivationStatus::HeldMissingPolicyBinding
        } else if tool_status == ToolExitStatus::ReplayedOnly {
            ReceiptActivationStatus::AcceptedReplayOnly
        } else {
            ReceiptActivationStatus::AcceptedLive
        };
        let receipt_id = live_receipt_id(
            family,
            tool_status,
            artifact_root,
            release_policy_root,
            operator_commitment,
            observed_height,
            current_height,
        );
        let activation_root = domain_hash(
            "FORCE-EXIT-COMPILE-RUNTIME-LIVE-RECEIPT-ACTIVATION",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&receipt_id),
                HashPart::Str(family.as_str()),
                HashPart::Str(activation_status.as_str()),
                HashPart::Str(artifact_root),
                HashPart::Str(observer_quorum_root),
                HashPart::Str(release_policy_root),
            ],
            32,
        );
        Self {
            receipt_id,
            family,
            tool_status,
            artifact_root: artifact_root.to_string(),
            diagnostic_root: diagnostic_root.to_string(),
            environment_root: environment_root.to_string(),
            release_policy_root: release_policy_root.to_string(),
            observer_quorum_root: observer_quorum_root.to_string(),
            operator_commitment: operator_commitment.to_string(),
            observed_height,
            current_height,
            receipt_age_blocks,
            freshness,
            required_status_root,
            observed_status_root,
            activation_status,
            activation_root,
        }
    }

    pub fn accepted(&self) -> bool {
        self.activation_status.permits_activation()
    }

    pub fn live(&self) -> bool {
        self.activation_status == ReceiptActivationStatus::AcceptedLive
    }

    pub fn state_root(&self) -> String {
        record_root("live-receipt-evidence", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FamilyActivation {
    pub family: ReceiptFamily,
    pub required: bool,
    pub receipt_count: u64,
    pub accepted_count: u64,
    pub live_count: u64,
    pub held_count: u64,
    pub family_receipt_root: String,
    pub family_activation_root: String,
    pub required_satisfied: bool,
    pub status: ReceiptActivationStatus,
}

impl FamilyActivation {
    pub fn from_receipts(
        family: ReceiptFamily,
        receipts: &[LiveReceiptEvidence],
        config: &Config,
    ) -> Self {
        let family_receipts: Vec<&LiveReceiptEvidence> = receipts
            .iter()
            .filter(|receipt| receipt.family == family)
            .collect();
        let receipt_count = family_receipts.len() as u64;
        let accepted_count = family_receipts
            .iter()
            .filter(|receipt| receipt.accepted())
            .count() as u64;
        let live_count = family_receipts
            .iter()
            .filter(|receipt| receipt.live())
            .count() as u64;
        let held_count = receipt_count.saturating_sub(accepted_count);
        let roots: Vec<String> = family_receipts
            .iter()
            .map(|receipt| receipt.state_root())
            .collect();
        let family_receipt_root = merkle_or_empty("family-receipts", roots);
        let required = family.required_by(config);
        let required_satisfied = if required { accepted_count > 0 } else { true };
        let status = if accepted_count > 0 {
            ReceiptActivationStatus::AcceptedLive
        } else if receipt_count == 0 {
            ReceiptActivationStatus::HeldMissingRoot
        } else {
            ReceiptActivationStatus::HeldCommandFailed
        };
        let family_activation_root = domain_hash(
            "FORCE-EXIT-COMPILE-RUNTIME-LIVE-RECEIPT-FAMILY-ACTIVATION",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(family.as_str()),
                HashPart::Int(receipt_count as i128),
                HashPart::Int(accepted_count as i128),
                HashPart::Int(live_count as i128),
                HashPart::Int(held_count as i128),
                HashPart::Str(&family_receipt_root),
                HashPart::Str(status.as_str()),
            ],
            32,
        );
        Self {
            family,
            required,
            receipt_count,
            accepted_count,
            live_count,
            held_count,
            family_receipt_root,
            family_activation_root,
            required_satisfied,
            status,
        }
    }

    pub fn state_root(&self) -> String {
        record_root("family-activation", &json!(self))
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct ActivationCounters {
    pub total_receipts: u64,
    pub accepted_receipts: u64,
    pub live_receipts: u64,
    pub replay_only_receipts: u64,
    pub held_receipts: u64,
    pub stale_receipts: u64,
    pub status_mismatch_receipts: u64,
    pub missing_root_receipts: u64,
    pub accepted_families: u64,
    pub required_families: u64,
    pub satisfied_required_families: u64,
    pub distinct_operator_commitments: u64,
    pub release_policy_root_count: u64,
}

impl ActivationCounters {
    pub fn from_parts(
        receipts: &[LiveReceiptEvidence],
        families: &[FamilyActivation],
        config: &Config,
    ) -> Self {
        let mut operators: Vec<String> = receipts
            .iter()
            .filter(|receipt| !receipt.operator_commitment.is_empty())
            .map(|receipt| receipt.operator_commitment.clone())
            .collect();
        operators.sort();
        operators.dedup();

        let mut release_policy_roots: Vec<String> = receipts
            .iter()
            .filter(|receipt| !receipt.release_policy_root.is_empty())
            .map(|receipt| receipt.release_policy_root.clone())
            .collect();
        release_policy_roots.sort();
        release_policy_roots.dedup();

        Self {
            total_receipts: receipts.len() as u64,
            accepted_receipts: receipts.iter().filter(|receipt| receipt.accepted()).count() as u64,
            live_receipts: receipts.iter().filter(|receipt| receipt.live()).count() as u64,
            replay_only_receipts: receipts
                .iter()
                .filter(|receipt| {
                    receipt.activation_status == ReceiptActivationStatus::AcceptedReplayOnly
                })
                .count() as u64,
            held_receipts: receipts
                .iter()
                .filter(|receipt| !receipt.accepted())
                .count() as u64,
            stale_receipts: receipts
                .iter()
                .filter(|receipt| receipt.freshness == ReceiptFreshness::Stale)
                .count() as u64,
            status_mismatch_receipts: receipts
                .iter()
                .filter(|receipt| {
                    receipt.activation_status == ReceiptActivationStatus::HeldStatusMismatch
                })
                .count() as u64,
            missing_root_receipts: receipts
                .iter()
                .filter(|receipt| {
                    receipt.activation_status == ReceiptActivationStatus::HeldMissingRoot
                })
                .count() as u64,
            accepted_families: families
                .iter()
                .filter(|family| family.accepted_count > 0)
                .count() as u64,
            required_families: config.required_family_count(),
            satisfied_required_families: families
                .iter()
                .filter(|family| family.required && family.required_satisfied)
                .count() as u64,
            distinct_operator_commitments: operators.len() as u64,
            release_policy_root_count: release_policy_roots.len() as u64,
        }
    }

    pub fn state_root(&self) -> String {
        record_root("activation-counters", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ActivationVerdict {
    pub verdict_id: String,
    pub status: ActivationVerdictStatus,
    pub release_permitted: bool,
    pub fail_closed: bool,
    pub reason_root: String,
    pub accepted_receipt_root: String,
    pub held_receipt_root: String,
    pub family_activation_root: String,
    pub observer_quorum_root: String,
    pub release_policy_binding_root: String,
    pub activation_height: u64,
    pub activation_epoch: u64,
}

impl ActivationVerdict {
    pub fn evaluate(
        config: &Config,
        counters: &ActivationCounters,
        receipts: &[LiveReceiptEvidence],
        families: &[FamilyActivation],
    ) -> Self {
        let required_missing = counters.satisfied_required_families < counters.required_families;
        let family_quorum_missing =
            counters.accepted_families < config.effective_min_accepted_families();
        let live_quorum_missing = counters.live_receipts < config.min_live_receipts;
        let observer_quorum_missing = config.require_live_observer_quorum
            && counters.distinct_operator_commitments < config.min_distinct_operators;
        let release_policy_missing = config.require_release_policy_binding
            && counters.release_policy_root_count < config.min_release_policy_roots;
        let fail_closed =
            counters.status_mismatch_receipts > 0 || counters.missing_root_receipts > 0;
        let status = if fail_closed {
            ActivationVerdictStatus::FailClosed
        } else if required_missing {
            ActivationVerdictStatus::HeldForRequiredFamily
        } else if observer_quorum_missing {
            ActivationVerdictStatus::HeldForObserverQuorum
        } else if release_policy_missing {
            ActivationVerdictStatus::HeldForReleasePolicy
        } else if family_quorum_missing || live_quorum_missing {
            ActivationVerdictStatus::HeldForQuorum
        } else {
            ActivationVerdictStatus::Activated
        };
        let accepted_roots: Vec<String> = receipts
            .iter()
            .filter(|receipt| receipt.accepted())
            .map(|receipt| receipt.state_root())
            .collect();
        let held_roots: Vec<String> = receipts
            .iter()
            .filter(|receipt| !receipt.accepted())
            .map(|receipt| receipt.state_root())
            .collect();
        let family_roots: Vec<String> = families.iter().map(|family| family.state_root()).collect();
        let accepted_receipt_root = merkle_or_empty("accepted-receipts", accepted_roots);
        let held_receipt_root = merkle_or_empty("held-receipts", held_roots);
        let family_activation_root = merkle_or_empty("family-activation-set", family_roots);
        let observer_quorum_root = observer_quorum_root(receipts);
        let release_policy_binding_root = release_policy_binding_root(receipts, config);
        let reason_root = verdict_reason_root(status, counters, config);
        let verdict_id = activation_verdict_id(
            status,
            &accepted_receipt_root,
            &held_receipt_root,
            &family_activation_root,
            &release_policy_binding_root,
            config,
        );
        Self {
            verdict_id,
            status,
            release_permitted: status.permits_release(),
            fail_closed,
            reason_root,
            accepted_receipt_root,
            held_receipt_root,
            family_activation_root,
            observer_quorum_root,
            release_policy_binding_root,
            activation_height: config.l2_height,
            activation_epoch: config.receipt_epoch,
        }
    }

    pub fn state_root(&self) -> String {
        record_root("activation-verdict", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub receipt_root: String,
    pub accepted_receipt_root: String,
    pub held_receipt_root: String,
    pub family_activation_root: String,
    pub counters_root: String,
    pub verdict_root: String,
    pub observer_quorum_root: String,
    pub release_policy_binding_root: String,
    pub state_commitment_root: String,
}

impl Roots {
    pub fn state_root(&self) -> String {
        record_root("roots", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub receipts: Vec<LiveReceiptEvidence>,
    pub families: Vec<FamilyActivation>,
    pub counters: ActivationCounters,
    pub verdict: ActivationVerdict,
    pub roots: Roots,
}

impl State {
    pub fn new(config: Config, receipts: Vec<LiveReceiptEvidence>) -> Self {
        let families: Vec<FamilyActivation> = ReceiptFamily::ordered()
            .iter()
            .map(|family| FamilyActivation::from_receipts(*family, &receipts, &config))
            .collect();
        let counters = ActivationCounters::from_parts(&receipts, &families, &config);
        let verdict = ActivationVerdict::evaluate(&config, &counters, &receipts, &families);
        let receipt_roots: Vec<String> = receipts
            .iter()
            .map(|receipt| receipt.state_root())
            .collect();
        let accepted_roots: Vec<String> = receipts
            .iter()
            .filter(|receipt| receipt.accepted())
            .map(|receipt| receipt.state_root())
            .collect();
        let held_roots: Vec<String> = receipts
            .iter()
            .filter(|receipt| !receipt.accepted())
            .map(|receipt| receipt.state_root())
            .collect();
        let family_roots: Vec<String> = families.iter().map(|family| family.state_root()).collect();
        let mut roots = Roots {
            config_root: config.state_root(),
            receipt_root: merkle_or_empty("receipts", receipt_roots),
            accepted_receipt_root: merkle_or_empty("accepted-receipts", accepted_roots),
            held_receipt_root: merkle_or_empty("held-receipts", held_roots),
            family_activation_root: merkle_or_empty("family-activation-set", family_roots),
            counters_root: counters.state_root(),
            verdict_root: verdict.state_root(),
            observer_quorum_root: verdict.observer_quorum_root.clone(),
            release_policy_binding_root: verdict.release_policy_binding_root.clone(),
            state_commitment_root: empty_root("pending-state-commitment"),
        };
        roots.state_commitment_root = state_commitment_root(&roots, &verdict, &counters);
        Self {
            config,
            receipts,
            families,
            counters,
            verdict,
            roots,
        }
    }

    pub fn devnet() -> Self {
        let config = Config::devnet();
        let receipts = ReceiptFamily::ordered()
            .iter()
            .enumerate()
            .map(|(index, family)| devnet_receipt(*family, index as u64, &config))
            .collect();
        Self::new(config, receipts)
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        if let Value::Object(ref mut map) = record {
            map.insert("state_root".to_string(), Value::String(self.state_root()));
        }
        record
    }

    pub fn state_root(&self) -> String {
        record_root("state", &self.public_record_without_state_root())
    }

    fn public_record_without_state_root(&self) -> Value {
        json!({
            "config": self.config,
            "receipt_root": self.roots.receipt_root,
            "family_activation_root": self.roots.family_activation_root,
            "counters": self.counters,
            "verdict": self.verdict,
            "roots": self.roots,
        })
    }
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn public_record() -> Value {
    devnet().public_record()
}

pub fn state_root() -> String {
    devnet().state_root()
}

fn devnet_receipt(family: ReceiptFamily, ordinal: u64, config: &Config) -> LiveReceiptEvidence {
    let family_label = family.as_str();
    let artifact_root = seeded_root("artifact", family_label, ordinal, config);
    let diagnostic_root = seeded_root("diagnostic", family_label, ordinal, config);
    let environment_root = seeded_root("environment", family_label, ordinal, config);
    let release_policy_root = seeded_root("release-policy", family_label, ordinal % 2, config);
    let observer_quorum_root = seeded_root("observer-quorum", family_label, ordinal, config);
    let operator_commitment = seeded_root("operator", family_label, ordinal % 3, config);
    LiveReceiptEvidence::new(
        family,
        ToolExitStatus::Passed,
        &artifact_root,
        &diagnostic_root,
        &environment_root,
        &release_policy_root,
        &observer_quorum_root,
        &operator_commitment,
        config.l2_height.saturating_sub(ordinal + 1),
        config.l2_height,
        config,
    )
}

fn status_root(family: ReceiptFamily, status: ToolExitStatus, config: &Config) -> String {
    domain_hash(
        "FORCE-EXIT-COMPILE-RUNTIME-LIVE-RECEIPT-STATUS",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&config.force_exit_package_id),
            HashPart::Str(family.as_str()),
            HashPart::Str(status.as_str()),
            HashPart::Int(config.receipt_epoch as i128),
        ],
        32,
    )
}

fn live_receipt_id(
    family: ReceiptFamily,
    status: ToolExitStatus,
    artifact_root: &str,
    release_policy_root: &str,
    operator_commitment: &str,
    observed_height: u64,
    current_height: u64,
) -> String {
    domain_hash(
        "FORCE-EXIT-COMPILE-RUNTIME-LIVE-RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(family.as_str()),
            HashPart::Str(status.as_str()),
            HashPart::Str(artifact_root),
            HashPart::Str(release_policy_root),
            HashPart::Str(operator_commitment),
            HashPart::Int(observed_height as i128),
            HashPart::Int(current_height as i128),
        ],
        32,
    )
}

fn observer_quorum_root(receipts: &[LiveReceiptEvidence]) -> String {
    let mut commitments: Vec<String> = receipts
        .iter()
        .filter(|receipt| receipt.accepted() && !receipt.operator_commitment.is_empty())
        .map(|receipt| receipt.operator_commitment.clone())
        .collect();
    commitments.sort();
    commitments.dedup();
    merkle_or_empty("observer-quorum", commitments)
}

fn release_policy_binding_root(receipts: &[LiveReceiptEvidence], config: &Config) -> String {
    let mut policy_roots: Vec<String> = receipts
        .iter()
        .filter(|receipt| receipt.accepted() && !receipt.release_policy_root.is_empty())
        .map(|receipt| receipt.release_policy_root.clone())
        .collect();
    policy_roots.sort();
    policy_roots.dedup();
    domain_hash(
        "FORCE-EXIT-COMPILE-RUNTIME-LIVE-RECEIPT-RELEASE-POLICY-BINDING",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&config.force_exit_package_id),
            HashPart::Str(&merkle_or_empty("release-policy-roots", policy_roots)),
            HashPart::Int(config.receipt_epoch as i128),
            HashPart::Int(config.source_height as i128),
            HashPart::Int(config.l2_height as i128),
        ],
        32,
    )
}

fn verdict_reason_root(
    status: ActivationVerdictStatus,
    counters: &ActivationCounters,
    config: &Config,
) -> String {
    domain_hash(
        "FORCE-EXIT-COMPILE-RUNTIME-LIVE-RECEIPT-VERDICT-REASON",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(status.as_str()),
            HashPart::Int(counters.accepted_receipts as i128),
            HashPart::Int(counters.live_receipts as i128),
            HashPart::Int(counters.accepted_families as i128),
            HashPart::Int(counters.satisfied_required_families as i128),
            HashPart::Int(counters.distinct_operator_commitments as i128),
            HashPart::Int(counters.release_policy_root_count as i128),
            HashPart::Int(config.effective_min_accepted_families() as i128),
            HashPart::Int(config.min_live_receipts as i128),
        ],
        32,
    )
}

fn activation_verdict_id(
    status: ActivationVerdictStatus,
    accepted_receipt_root: &str,
    held_receipt_root: &str,
    family_activation_root: &str,
    release_policy_binding_root: &str,
    config: &Config,
) -> String {
    domain_hash(
        "FORCE-EXIT-COMPILE-RUNTIME-LIVE-RECEIPT-VERDICT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&config.vertical_slice_id),
            HashPart::Str(&config.force_exit_package_id),
            HashPart::Str(status.as_str()),
            HashPart::Str(accepted_receipt_root),
            HashPart::Str(held_receipt_root),
            HashPart::Str(family_activation_root),
            HashPart::Str(release_policy_binding_root),
            HashPart::Int(config.receipt_epoch as i128),
        ],
        32,
    )
}

fn state_commitment_root(
    roots: &Roots,
    verdict: &ActivationVerdict,
    counters: &ActivationCounters,
) -> String {
    domain_hash(
        "FORCE-EXIT-COMPILE-RUNTIME-LIVE-RECEIPT-STATE-COMMITMENT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&roots.config_root),
            HashPart::Str(&roots.receipt_root),
            HashPart::Str(&roots.family_activation_root),
            HashPart::Str(&roots.counters_root),
            HashPart::Str(&roots.verdict_root),
            HashPart::Str(verdict.status.as_str()),
            HashPart::Int(counters.accepted_receipts as i128),
            HashPart::Int(counters.held_receipts as i128),
        ],
        32,
    )
}

fn seeded_root(scope: &str, family: &str, ordinal: u64, config: &Config) -> String {
    domain_hash(
        "FORCE-EXIT-COMPILE-RUNTIME-LIVE-RECEIPT-DEVNET-SEED",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&config.force_exit_package_id),
            HashPart::Str(scope),
            HashPart::Str(family),
            HashPart::Int(ordinal as i128),
            HashPart::Int(config.receipt_epoch as i128),
        ],
        32,
    )
}

fn record_root(label: &str, record: &Value) -> String {
    domain_hash(
        "FORCE-EXIT-COMPILE-RUNTIME-LIVE-RECEIPT-RECORD",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Json(record),
        ],
        32,
    )
}

fn empty_root(label: &str) -> String {
    domain_hash(
        "FORCE-EXIT-COMPILE-RUNTIME-LIVE-RECEIPT-EMPTY",
        &[HashPart::Str(CHAIN_ID), HashPart::Str(label)],
        32,
    )
}

fn merkle_or_empty(label: &str, roots: Vec<String>) -> String {
    if roots.is_empty() {
        empty_root(label)
    } else {
        merkle_root(&roots)
    }
}
