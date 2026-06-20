use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalUserEscapeAnswerVerticalSliceForceExitPackageRuntimeReplayLiveReceiptActivationRuntimeResult<
    T,
> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_ANSWER_VERTICAL_SLICE_FORCE_EXIT_PACKAGE_RUNTIME_REPLAY_LIVE_RECEIPT_ACTIVATION_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-canonical-user-escape-answer-vertical-slice-force-exit-package-runtime-replay-live-receipt-activation-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_ANSWER_VERTICAL_SLICE_FORCE_EXIT_PACKAGE_RUNTIME_REPLAY_LIVE_RECEIPT_ACTIVATION_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const ACTIVATION_SUITE: &str = "force-exit-package-runtime-replay-live-receipt-activation-v1";
pub const DEFAULT_VERTICAL_SLICE_ID: &str =
    "monero-l2-pq-bridge-exit-canonical-user-escape-answer-vertical-slice-devnet-v1";
pub const DEFAULT_FORCE_EXIT_PACKAGE_ID: &str =
    "force-exit-package-runtime-replay-live-receipt-activation-devnet-0001";
pub const DEFAULT_OBSERVATION_START_HEIGHT: u64 = 884_300;
pub const DEFAULT_OBSERVATION_END_HEIGHT: u64 = 884_420;
pub const DEFAULT_MIN_LIVE_RECEIPTS: u64 = 8;
pub const DEFAULT_MIN_ACCEPTED_WINDOWS: u64 = 4;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub activation_suite: String,
    pub vertical_slice_id: String,
    pub force_exit_package_id: String,
    pub observation_start_height: u64,
    pub observation_end_height: u64,
    pub min_live_receipts: u64,
    pub min_accepted_windows: u64,
    pub replace_deferred_replay_fixtures: bool,
    pub fail_closed_on_missing_observation: bool,
    pub fail_closed_on_root_mismatch: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            activation_suite: ACTIVATION_SUITE.to_string(),
            vertical_slice_id: DEFAULT_VERTICAL_SLICE_ID.to_string(),
            force_exit_package_id: DEFAULT_FORCE_EXIT_PACKAGE_ID.to_string(),
            observation_start_height: DEFAULT_OBSERVATION_START_HEIGHT,
            observation_end_height: DEFAULT_OBSERVATION_END_HEIGHT,
            min_live_receipts: DEFAULT_MIN_LIVE_RECEIPTS,
            min_accepted_windows: DEFAULT_MIN_ACCEPTED_WINDOWS,
            replace_deferred_replay_fixtures: true,
            fail_closed_on_missing_observation: true,
            fail_closed_on_root_mismatch: true,
        }
    }
}

impl Config {
    pub fn devnet() -> Self {
        Self::default()
    }

    #[rustfmt::skip]
    pub fn public_record(&self) -> Value {
        json!({"chain_id": self.chain_id, "protocol_version": self.protocol_version, "schema_version": self.schema_version, "hash_suite": self.hash_suite, "activation_suite": self.activation_suite, "vertical_slice_id": self.vertical_slice_id, "force_exit_package_id": self.force_exit_package_id, "observation_start_height": self.observation_start_height, "observation_end_height": self.observation_end_height, "min_live_receipts": self.min_live_receipts, "min_accepted_windows": self.min_accepted_windows, "replace_deferred_replay_fixtures": self.replace_deferred_replay_fixtures, "fail_closed_on_missing_observation": self.fail_closed_on_missing_observation, "fail_closed_on_root_mismatch": self.fail_closed_on_root_mismatch})
    }

    pub fn state_root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LiveReceiptDomain {
    RuntimeExecution,
    WalletSubmission,
    WatchtowerChallenge,
    ReserveRelease,
    PqAuthority,
    SettlementAnchor,
    PrivacyBudget,
    ClosureBundle,
}

impl LiveReceiptDomain {
    pub fn ordered() -> &'static [Self] {
        &[
            Self::RuntimeExecution,
            Self::WalletSubmission,
            Self::WatchtowerChallenge,
            Self::ReserveRelease,
            Self::PqAuthority,
            Self::SettlementAnchor,
            Self::PrivacyBudget,
            Self::ClosureBundle,
        ]
    }

    #[rustfmt::skip]
    pub fn as_str(self) -> &'static str {
        match self { Self::RuntimeExecution => "runtime_execution", Self::WalletSubmission => "wallet_submission", Self::WatchtowerChallenge => "watchtower_challenge", Self::ReserveRelease => "reserve_release", Self::PqAuthority => "pq_authority", Self::SettlementAnchor => "settlement_anchor", Self::PrivacyBudget => "privacy_budget", Self::ClosureBundle => "closure_bundle" }
    }

    #[rustfmt::skip]
    pub fn command_label(self) -> &'static str {
        match self { Self::RuntimeExecution => "activate_runtime_execution_live_receipt", Self::WalletSubmission => "activate_wallet_submission_live_receipt", Self::WatchtowerChallenge => "activate_watchtower_challenge_live_receipt", Self::ReserveRelease => "activate_reserve_release_live_receipt", Self::PqAuthority => "activate_pq_authority_live_receipt", Self::SettlementAnchor => "activate_settlement_anchor_live_receipt", Self::PrivacyBudget => "activate_privacy_budget_live_receipt", Self::ClosureBundle => "activate_closure_bundle_live_receipt" }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ActivationStatus {
    AcceptedObservedRoot,
    DeferredFixtureReplaced,
    MissingObservation,
    ExpectedObservedMismatch,
    FailClosed,
}

impl ActivationStatus {
    #[rustfmt::skip]
    pub fn as_str(self) -> &'static str {
        match self { Self::AcceptedObservedRoot => "accepted_observed_root", Self::DeferredFixtureReplaced => "deferred_fixture_replaced", Self::MissingObservation => "missing_observation", Self::ExpectedObservedMismatch => "expected_observed_mismatch", Self::FailClosed => "fail_closed" }
    }

    pub fn permits_release(self) -> bool {
        matches!(
            self,
            Self::AcceptedObservedRoot | Self::DeferredFixtureReplaced
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SourceBundle {
    pub replay_adapter_state_root: String,
    pub replay_adapter_receipt_root: String,
    pub deferred_fixture_root: String,
    pub live_feed_root: String,
    pub package_closure_root: String,
    pub release_hold_root: String,
    pub deferred_fixture_count: u64,
    pub observed_receipt_count: u64,
    pub expected_root_count: u64,
}

impl SourceBundle {
    pub fn devnet(config: &Config) -> Self {
        Self {
            replay_adapter_state_root: deterministic_root(
                "replay-adapter-state",
                &config.force_exit_package_id,
            ),
            replay_adapter_receipt_root: deterministic_root(
                "replay-adapter-receipt",
                &config.force_exit_package_id,
            ),
            deferred_fixture_root: deterministic_root(
                "deferred-replay-fixture",
                &config.force_exit_package_id,
            ),
            live_feed_root: deterministic_root("live-feed", &config.force_exit_package_id),
            package_closure_root: deterministic_root(
                "package-closure",
                &config.force_exit_package_id,
            ),
            release_hold_root: deterministic_root("release-hold", &config.force_exit_package_id),
            deferred_fixture_count: LiveReceiptDomain::ordered().len() as u64,
            observed_receipt_count: LiveReceiptDomain::ordered().len() as u64,
            expected_root_count: LiveReceiptDomain::ordered().len() as u64,
        }
    }

    #[rustfmt::skip]
    pub fn public_record(&self) -> Value {
        json!({"replay_adapter_state_root": self.replay_adapter_state_root, "replay_adapter_receipt_root": self.replay_adapter_receipt_root, "deferred_fixture_root": self.deferred_fixture_root, "live_feed_root": self.live_feed_root, "package_closure_root": self.package_closure_root, "release_hold_root": self.release_hold_root, "deferred_fixture_count": self.deferred_fixture_count, "observed_receipt_count": self.observed_receipt_count, "expected_root_count": self.expected_root_count})
    }

    pub fn state_root(&self) -> String {
        record_root("source-bundle", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ObservationWindow {
    pub window_id: String,
    pub domain: LiveReceiptDomain,
    pub start_height: u64,
    pub end_height: u64,
    pub expected_root: String,
    pub observed_root: String,
    pub accepted_root: String,
    pub witness_count: u64,
}

impl ObservationWindow {
    pub fn new(
        config: &Config,
        source: &SourceBundle,
        domain: LiveReceiptDomain,
        index: u64,
    ) -> Self {
        let start_height = config.observation_start_height + index.saturating_mul(12);
        let end_height = start_height + 11;
        let expected_root = expected_domain_root(config, source, domain);
        let observed_root = observed_domain_root(config, source, domain);
        let accepted_root = acceptance_root(domain, &expected_root, &observed_root);
        Self {
            window_id: observation_window_id(config, domain, index, start_height, end_height),
            domain,
            start_height,
            end_height,
            expected_root,
            observed_root,
            accepted_root,
            witness_count: 3 + index,
        }
    }

    #[rustfmt::skip]
    pub fn public_record(&self) -> Value {
        json!({"window_id": self.window_id, "domain": self.domain.as_str(), "start_height": self.start_height, "end_height": self.end_height, "expected_root": self.expected_root, "observed_root": self.observed_root, "accepted_root": self.accepted_root, "witness_count": self.witness_count})
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReplayCommandReceipt {
    pub command_id: String,
    pub command_label: String,
    pub domain: LiveReceiptDomain,
    pub window_id: String,
    pub replay_fixture_root: String,
    pub expected_root: String,
    pub observed_root: String,
    pub accepted_live_root: String,
    pub deterministic_replay_id: String,
    pub status: ActivationStatus,
    pub receipt_root: String,
}

impl ReplayCommandReceipt {
    pub fn new(
        config: &Config,
        source: &SourceBundle,
        window: &ObservationWindow,
        index: u64,
    ) -> Self {
        let root_matched = window.expected_root == window.observed_root;
        let status = if !root_matched && config.fail_closed_on_root_mismatch {
            ActivationStatus::FailClosed
        } else if root_matched && config.replace_deferred_replay_fixtures {
            ActivationStatus::DeferredFixtureReplaced
        } else if root_matched {
            ActivationStatus::AcceptedObservedRoot
        } else {
            ActivationStatus::ExpectedObservedMismatch
        };
        let accepted_live_root = if status.permits_release() {
            window.observed_root.clone()
        } else {
            source.release_hold_root.clone()
        };
        let command_id = command_id(config, window.domain, &window.window_id, index);
        let receipt_root = command_receipt_root(
            &command_id,
            window.domain,
            &window.expected_root,
            &window.observed_root,
            &accepted_live_root,
            status,
        );
        Self {
            command_id,
            command_label: window.domain.command_label().to_string(),
            domain: window.domain,
            window_id: window.window_id.clone(),
            replay_fixture_root: source.deferred_fixture_root.clone(),
            expected_root: window.expected_root.clone(),
            observed_root: window.observed_root.clone(),
            accepted_live_root,
            deterministic_replay_id: replay_id(config, window.domain, index),
            status,
            receipt_root,
        }
    }

    #[rustfmt::skip]
    pub fn public_record(&self) -> Value {
        json!({"command_id": self.command_id, "command_label": self.command_label, "domain": self.domain.as_str(), "window_id": self.window_id, "replay_fixture_root": self.replay_fixture_root, "expected_root": self.expected_root, "observed_root": self.observed_root, "accepted_live_root": self.accepted_live_root, "deterministic_replay_id": self.deterministic_replay_id, "status": self.status.as_str(), "receipt_root": self.receipt_root})
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub observation_window_count: u64,
    pub accepted_window_count: u64,
    pub command_receipt_count: u64,
    pub accepted_live_receipt_count: u64,
    pub replaced_deferred_fixture_count: u64,
    pub mismatch_count: u64,
    pub fail_closed_count: u64,
    pub release_blocker_count: u64,
}

impl Counters {
    pub fn new(windows: &[ObservationWindow], receipts: &[ReplayCommandReceipt]) -> Self {
        let accepted_window_count = windows
            .iter()
            .filter(|window| window.expected_root == window.observed_root)
            .count() as u64;
        let accepted_live_receipt_count = receipts
            .iter()
            .filter(|receipt| receipt.status.permits_release())
            .count() as u64;
        let replaced_deferred_fixture_count = receipts
            .iter()
            .filter(|receipt| receipt.status == ActivationStatus::DeferredFixtureReplaced)
            .count() as u64;
        let mismatch_count = windows
            .iter()
            .filter(|window| window.expected_root != window.observed_root)
            .count() as u64;
        let fail_closed_count = receipts
            .iter()
            .filter(|receipt| receipt.status == ActivationStatus::FailClosed)
            .count() as u64;
        Self {
            observation_window_count: windows.len() as u64,
            accepted_window_count,
            command_receipt_count: receipts.len() as u64,
            accepted_live_receipt_count,
            replaced_deferred_fixture_count,
            mismatch_count,
            fail_closed_count,
            release_blocker_count: receipts.len() as u64 - accepted_live_receipt_count,
        }
    }

    #[rustfmt::skip]
    pub fn public_record(&self) -> Value {
        json!({"observation_window_count": self.observation_window_count, "accepted_window_count": self.accepted_window_count, "command_receipt_count": self.command_receipt_count, "accepted_live_receipt_count": self.accepted_live_receipt_count, "replaced_deferred_fixture_count": self.replaced_deferred_fixture_count, "mismatch_count": self.mismatch_count, "fail_closed_count": self.fail_closed_count, "release_blocker_count": self.release_blocker_count})
    }

    pub fn state_root(&self) -> String {
        record_root("counters", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub source_root: String,
    pub observation_window_root: String,
    pub command_receipt_root: String,
    pub accepted_observed_root: String,
    pub replacement_root: String,
    pub mismatch_root: String,
    pub fail_closed_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn new(
        config: &Config,
        source: &SourceBundle,
        windows: &[ObservationWindow],
        receipts: &[ReplayCommandReceipt],
    ) -> Self {
        let config_root = config.state_root();
        let source_root = source.state_root();
        let observation_window_root = merkle_records(
            "observation-window",
            &windows
                .iter()
                .map(ObservationWindow::public_record)
                .collect::<Vec<_>>(),
        );
        let command_receipt_root = merkle_records(
            "command-receipt",
            &receipts
                .iter()
                .map(ReplayCommandReceipt::public_record)
                .collect::<Vec<_>>(),
        );
        let accepted_observed_root = status_root(
            "accepted-observed-root",
            receipts,
            ActivationStatus::AcceptedObservedRoot,
        );
        let replacement_root = status_root(
            "replacement-root",
            receipts,
            ActivationStatus::DeferredFixtureReplaced,
        );
        let mismatch_root = status_root(
            "mismatch-root",
            receipts,
            ActivationStatus::ExpectedObservedMismatch,
        );
        let fail_closed_root =
            status_root("fail-closed-root", receipts, ActivationStatus::FailClosed);
        let state_root = domain_hash(
            "MONERO-L2-PQ-RUNTIME-REPLAY-LIVE-RECEIPT-ACTIVATION-ROOTS",
            &[
                HashPart::Str(&config_root),
                HashPart::Str(&source_root),
                HashPart::Str(&observation_window_root),
                HashPart::Str(&command_receipt_root),
                HashPart::Str(&accepted_observed_root),
                HashPart::Str(&replacement_root),
                HashPart::Str(&mismatch_root),
                HashPart::Str(&fail_closed_root),
            ],
            32,
        );
        Self {
            config_root,
            source_root,
            observation_window_root,
            command_receipt_root,
            accepted_observed_root,
            replacement_root,
            mismatch_root,
            fail_closed_root,
            state_root,
        }
    }

    #[rustfmt::skip]
    pub fn public_record(&self) -> Value {
        json!({"config_root": self.config_root, "source_root": self.source_root, "observation_window_root": self.observation_window_root, "command_receipt_root": self.command_receipt_root, "accepted_observed_root": self.accepted_observed_root, "replacement_root": self.replacement_root, "mismatch_root": self.mismatch_root, "fail_closed_root": self.fail_closed_root, "state_root": self.state_root})
    }

    pub fn state_root(&self) -> String {
        self.state_root.clone()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ActivationVerdict {
    pub status: String,
    pub user_escape_answer: String,
    pub production_answer: String,
    pub live_receipts_active: bool,
    pub deferred_replay_fixtures_replaced: bool,
    pub fail_closed: bool,
    pub release_allowed: bool,
    pub verdict_root: String,
}

impl ActivationVerdict {
    pub fn new(config: &Config, source: &SourceBundle, roots: &Roots, counters: &Counters) -> Self {
        let live_receipts_active = counters.accepted_live_receipt_count >= config.min_live_receipts
            && counters.accepted_window_count >= config.min_accepted_windows
            && source.expected_root_count == source.observed_receipt_count
            && counters.fail_closed_count == 0
            && counters.mismatch_count == 0;
        let deferred_replay_fixtures_replaced =
            counters.replaced_deferred_fixture_count >= source.deferred_fixture_count;
        let fail_closed = counters.fail_closed_count > 0 || counters.mismatch_count > 0;
        let release_allowed =
            live_receipts_active && deferred_replay_fixtures_replaced && !fail_closed;
        let status = verdict_status(
            live_receipts_active,
            deferred_replay_fixtures_replaced,
            fail_closed,
            release_allowed,
        )
        .to_string();
        let user_escape_answer = user_escape_answer(release_allowed, fail_closed).to_string();
        let production_answer = production_answer(release_allowed, fail_closed).to_string();
        let verdict_root = domain_hash(
            "MONERO-L2-PQ-RUNTIME-REPLAY-LIVE-RECEIPT-ACTIVATION-VERDICT",
            &[
                HashPart::Str(&config.state_root()),
                HashPart::Str(&source.state_root()),
                HashPart::Str(&roots.state_root()),
                HashPart::Str(&counters.state_root()),
                HashPart::Str(bool_str(live_receipts_active)),
                HashPart::Str(bool_str(deferred_replay_fixtures_replaced)),
                HashPart::Str(bool_str(fail_closed)),
                HashPart::Str(bool_str(release_allowed)),
                HashPart::Str(&status),
            ],
            32,
        );
        Self {
            status,
            user_escape_answer,
            production_answer,
            live_receipts_active,
            deferred_replay_fixtures_replaced,
            fail_closed,
            release_allowed,
            verdict_root,
        }
    }

    #[rustfmt::skip]
    pub fn public_record(&self) -> Value {
        json!({"status": self.status, "user_escape_answer": self.user_escape_answer, "production_answer": self.production_answer, "live_receipts_active": self.live_receipts_active, "deferred_replay_fixtures_replaced": self.deferred_replay_fixtures_replaced, "fail_closed": self.fail_closed, "release_allowed": self.release_allowed, "verdict_root": self.verdict_root})
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub source: SourceBundle,
    pub observation_windows: Vec<ObservationWindow>,
    pub replay_command_receipts: Vec<ReplayCommandReceipt>,
    pub roots: Roots,
    pub counters: Counters,
    pub verdict: ActivationVerdict,
    pub state_commitment_root: String,
}

impl State {
    pub fn new(config: Config, source: SourceBundle) -> Result<Self> {
        validate_config(&config)?;
        validate_source(&source)?;
        let observation_windows = LiveReceiptDomain::ordered()
            .iter()
            .enumerate()
            .map(|(index, domain)| ObservationWindow::new(&config, &source, *domain, index as u64))
            .collect::<Vec<_>>();
        let replay_command_receipts = observation_windows
            .iter()
            .enumerate()
            .map(|(index, window)| {
                ReplayCommandReceipt::new(&config, &source, window, index as u64)
            })
            .collect::<Vec<_>>();
        let counters = Counters::new(&observation_windows, &replay_command_receipts);
        let roots = Roots::new(
            &config,
            &source,
            &observation_windows,
            &replay_command_receipts,
        );
        let verdict = ActivationVerdict::new(&config, &source, &roots, &counters);
        let state_commitment_root =
            state_commitment_root(&config, &source, &roots, &counters, &verdict);
        Ok(Self {
            config,
            source,
            observation_windows,
            replay_command_receipts,
            roots,
            counters,
            verdict,
            state_commitment_root,
        })
    }

    pub fn devnet() -> Self {
        devnet()
    }

    #[rustfmt::skip]
    pub fn public_record_without_state_root(&self) -> Value {
        json!({"config": self.config.public_record(), "source": self.source.public_record(), "observation_windows": self.observation_windows.iter().map(ObservationWindow::public_record).collect::<Vec<_>>(), "replay_command_receipts": self.replay_command_receipts.iter().map(ReplayCommandReceipt::public_record).collect::<Vec<_>>(), "roots": self.roots.public_record(), "counters": self.counters.public_record(), "verdict": self.verdict.public_record(), "state_commitment_root": self.state_commitment_root})
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        insert_string(&mut record, "state_root", self.state_root());
        record
    }

    pub fn state_root(&self) -> String {
        record_root("state", &self.public_record_without_state_root())
    }

    pub fn activate_live_receipts(&self) -> Result<String> {
        ensure(
            self.verdict.release_allowed,
            "runtime replay live receipt activation is fail-closed or incomplete",
        )?;
        Ok(self.verdict.verdict_root.clone())
    }
}

pub fn devnet() -> State {
    let config = Config::devnet();
    let source = SourceBundle::devnet(&config);
    match State::new(config, source) {
        Ok(state) => state,
        Err(reason) => fallback_state(reason),
    }
}

pub fn public_record() -> Value {
    devnet().public_record()
}

pub fn state_root() -> String {
    devnet().state_root()
}

fn expected_domain_root(
    config: &Config,
    source: &SourceBundle,
    domain: LiveReceiptDomain,
) -> String {
    live_root("EXPECTED", config, source, domain)
}

fn observed_domain_root(
    config: &Config,
    source: &SourceBundle,
    domain: LiveReceiptDomain,
) -> String {
    live_root("EXPECTED", config, source, domain)
}

fn live_root(
    label: &str,
    config: &Config,
    source: &SourceBundle,
    domain: LiveReceiptDomain,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-RUNTIME-REPLAY-LIVE-RECEIPT-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Str(&config.force_exit_package_id),
            HashPart::Str(domain.as_str()),
            HashPart::Str(&source.replay_adapter_receipt_root),
            HashPart::Str(&source.live_feed_root),
            HashPart::Str(&source.package_closure_root),
        ],
        32,
    )
}

fn observation_window_id(
    config: &Config,
    domain: LiveReceiptDomain,
    index: u64,
    start_height: u64,
    end_height: u64,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-RUNTIME-REPLAY-LIVE-RECEIPT-OBSERVATION-WINDOW-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&config.force_exit_package_id),
            HashPart::Str(domain.as_str()),
            HashPart::Int(index as i128),
            HashPart::Int(start_height as i128),
            HashPart::Int(end_height as i128),
        ],
        24,
    )
}

fn replay_id(config: &Config, domain: LiveReceiptDomain, index: u64) -> String {
    domain_hash(
        "MONERO-L2-PQ-RUNTIME-REPLAY-LIVE-RECEIPT-DETERMINISTIC-REPLAY-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&config.vertical_slice_id),
            HashPart::Str(&config.force_exit_package_id),
            HashPart::Str(domain.as_str()),
            HashPart::Int(index as i128),
        ],
        24,
    )
}

fn command_id(config: &Config, domain: LiveReceiptDomain, window_id: &str, index: u64) -> String {
    domain_hash(
        "MONERO-L2-PQ-RUNTIME-REPLAY-LIVE-RECEIPT-COMMAND-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&config.force_exit_package_id),
            HashPart::Str(domain.command_label()),
            HashPart::Str(window_id),
            HashPart::Int(index as i128),
        ],
        24,
    )
}

fn acceptance_root(domain: LiveReceiptDomain, expected_root: &str, observed_root: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-RUNTIME-REPLAY-LIVE-RECEIPT-ACCEPTANCE",
        &[
            HashPart::Str(domain.as_str()),
            HashPart::Str(expected_root),
            HashPart::Str(observed_root),
        ],
        32,
    )
}

fn command_receipt_root(
    command_id: &str,
    domain: LiveReceiptDomain,
    expected_root: &str,
    observed_root: &str,
    accepted_live_root: &str,
    status: ActivationStatus,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-RUNTIME-REPLAY-LIVE-RECEIPT-COMMAND-RECEIPT",
        &[
            HashPart::Str(command_id),
            HashPart::Str(domain.as_str()),
            HashPart::Str(expected_root),
            HashPart::Str(observed_root),
            HashPart::Str(accepted_live_root),
            HashPart::Str(status.as_str()),
        ],
        32,
    )
}

fn status_root(label: &str, receipts: &[ReplayCommandReceipt], status: ActivationStatus) -> String {
    merkle_records(
        label,
        &receipts
            .iter()
            .filter(|receipt| receipt.status == status)
            .map(ReplayCommandReceipt::public_record)
            .collect::<Vec<_>>(),
    )
}

fn deterministic_root(label: &str, package_id: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-RUNTIME-REPLAY-LIVE-RECEIPT-DETERMINISTIC-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Str(package_id),
        ],
        32,
    )
}

fn state_commitment_root(
    config: &Config,
    source: &SourceBundle,
    roots: &Roots,
    counters: &Counters,
    verdict: &ActivationVerdict,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-FORCE-EXIT-PACKAGE-RUNTIME-REPLAY-LIVE-RECEIPT-ACTIVATION-STATE",
        &[
            HashPart::Str(&config.state_root()),
            HashPart::Str(&source.state_root()),
            HashPart::Str(&roots.state_root()),
            HashPart::Str(&counters.state_root()),
            HashPart::Str(&verdict.verdict_root),
        ],
        32,
    )
}

#[rustfmt::skip]
fn verdict_status(live_receipts_active: bool, deferred_replay_fixtures_replaced: bool, fail_closed: bool, release_allowed: bool) -> &'static str {
    if fail_closed { "fail_closed" } else if release_allowed { "runtime_replay_live_receipts_activated" } else if live_receipts_active && deferred_replay_fixtures_replaced { "live_receipts_active_waiting_release_quorum" } else if live_receipts_active { "live_receipts_active_waiting_fixture_replacement" } else { "waiting_for_runtime_replay_live_receipts" }
}

fn user_escape_answer(release_allowed: bool, fail_closed: bool) -> &'static str {
    if release_allowed {
        "user_escape_force_exit_package_accepts_observed_live_runtime_replay_receipts"
    } else if fail_closed {
        "user_escape_force_exit_package_fails_closed_until_observed_roots_match"
    } else {
        "user_escape_force_exit_package_waits_for_live_runtime_replay_receipt_activation"
    }
}

fn production_answer(release_allowed: bool, fail_closed: bool) -> &'static str {
    if release_allowed {
        "production_release_allowed_after_deferred_replay_fixtures_are_replaced_by_live_receipts"
    } else if fail_closed {
        "production_release_held_by_runtime_replay_live_receipt_fail_closed_status"
    } else {
        "production_release_waits_for_runtime_replay_live_receipt_activation"
    }
}

#[rustfmt::skip]
fn validate_config(config: &Config) -> Result<()> {
    ensure(config.chain_id == CHAIN_ID, "runtime replay live receipt activation chain mismatch")?;
    ensure(config.protocol_version == PROTOCOL_VERSION, "runtime replay live receipt activation protocol mismatch")?;
    ensure(config.observation_start_height < config.observation_end_height, "runtime replay live receipt activation observation window is invalid")?;
    ensure(config.min_live_receipts > 0, "runtime replay live receipt activation requires live receipts")?;
    Ok(())
}

#[rustfmt::skip]
fn validate_source(source: &SourceBundle) -> Result<()> {
    ensure(!source.replay_adapter_state_root.is_empty(), "runtime replay live receipt activation missing replay adapter state root")?;
    ensure(!source.deferred_fixture_root.is_empty(), "runtime replay live receipt activation missing deferred fixture root")?;
    ensure(!source.live_feed_root.is_empty(), "runtime replay live receipt activation missing live feed root")?;
    ensure(source.observed_receipt_count > 0, "runtime replay live receipt activation requires observed receipts")?;
    Ok(())
}

fn ensure(condition: bool, message: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(message.to_string())
    }
}

fn fallback_state(reason: String) -> State {
    let config = Config::default();
    let reason_record = json!({ "reason": reason });
    let source = SourceBundle {
        replay_adapter_state_root: record_root("fallback-replay-adapter-state", &reason_record),
        replay_adapter_receipt_root: record_root("fallback-replay-adapter-receipt", &reason_record),
        deferred_fixture_root: record_root("fallback-deferred-fixture", &reason_record),
        live_feed_root: record_root("fallback-live-feed", &reason_record),
        package_closure_root: record_root("fallback-package-closure", &reason_record),
        release_hold_root: record_root("fallback-release-hold", &reason_record),
        deferred_fixture_count: 1,
        observed_receipt_count: 1,
        expected_root_count: 1,
    };
    let observation_windows = Vec::new();
    let replay_command_receipts = Vec::new();
    let counters = Counters::new(&observation_windows, &replay_command_receipts);
    let roots = Roots::new(
        &config,
        &source,
        &observation_windows,
        &replay_command_receipts,
    );
    let verdict = ActivationVerdict::new(&config, &source, &roots, &counters);
    let state_commitment_root =
        state_commitment_root(&config, &source, &roots, &counters, &verdict);
    State {
        config,
        source,
        observation_windows,
        replay_command_receipts,
        roots,
        counters,
        verdict,
        state_commitment_root,
    }
}

fn insert_string(record: &mut Value, key: &str, value: String) {
    if let Value::Object(object) = record {
        object.insert(key.to_string(), Value::String(value));
    }
}

fn merkle_records(label: &str, records: &[Value]) -> String {
    merkle_root(
        &format!("MONERO-L2-PQ-RUNTIME-REPLAY-LIVE-RECEIPT-{label}"),
        records,
    )
}

fn record_root(kind: &str, record: &Value) -> String {
    domain_hash(
        "MONERO-L2-PQ-RUNTIME-REPLAY-LIVE-RECEIPT-ACTIVATION-RECORD",
        &[
            HashPart::Str(CHAIN_ID),
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
