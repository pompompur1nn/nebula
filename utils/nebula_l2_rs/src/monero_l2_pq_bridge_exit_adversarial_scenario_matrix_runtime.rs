use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    monero_l2_pq_trust_minimized_bridge_exit_spine_runtime::{
        AnchorReceiptRequest, BridgeLane, ChallengeKind, ChallengeRequest,
        DepositCertificateRequest, DepositLockRequest, ExitMode, ExitSettlementRequest,
        ForcedExitRequest, MintPrivateNoteRequest, PrivateActionKind, PrivateActionRequest,
        State as BridgeExitSpineState, WatcherQuorum, WithdrawalRequest,
    },
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitAdversarialScenarioMatrixRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_ADVERSARIAL_SCENARIO_MATRIX_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-adversarial-scenario-matrix-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_ADVERSARIAL_SCENARIO_MATRIX_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const MATRIX_SUITE: &str = "monero-l2-pq-bridge-exit-fail-closed-adversarial-scenarios-v1";
pub const DEVNET_MATRIX_LABEL: &str = "devnet-bridge-exit-fail-closed-matrix";
pub const DEFAULT_MIN_CASES: u64 = 8;
pub const DEFAULT_CASE_AMOUNT: u128 = 700_000_000_000;
pub const DEFAULT_EXIT_AMOUNT: u128 = 699_999_960_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AdversarialCaseKind {
    WeakPqWatcherQuorum,
    ShallowMoneroFinality,
    DepositPrivacyFloor,
    PrivateActionFeeCap,
    ExitAmountCap,
    ReplayNullifier,
    PrematureForcedSettlement,
    OpenChallengeBlocksSettlement,
}

impl AdversarialCaseKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WeakPqWatcherQuorum => "weak_pq_watcher_quorum",
            Self::ShallowMoneroFinality => "shallow_monero_finality",
            Self::DepositPrivacyFloor => "deposit_privacy_floor",
            Self::PrivateActionFeeCap => "private_action_fee_cap",
            Self::ExitAmountCap => "exit_amount_cap",
            Self::ReplayNullifier => "replay_nullifier",
            Self::PrematureForcedSettlement => "premature_forced_settlement",
            Self::OpenChallengeBlocksSettlement => "open_challenge_blocks_settlement",
        }
    }

    pub fn threat(self) -> &'static str {
        match self {
            Self::WeakPqWatcherQuorum => "watcher_collusion",
            Self::ShallowMoneroFinality => "monero_reorg",
            Self::DepositPrivacyFloor => "metadata_linkage",
            Self::PrivateActionFeeCap => "fee_extraction",
            Self::ExitAmountCap => "liquidity_exhaustion",
            Self::ReplayNullifier => "replay_withdrawal",
            Self::PrematureForcedSettlement => "sequencer_censorship_timing",
            Self::OpenChallengeBlocksSettlement => "invalid_release_under_dispute",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExpectedOutcome {
    RejectWeakWatcher,
    RejectShallowFinality,
    RejectPrivacyFloor,
    RejectHighFee,
    RejectOversizedExit,
    RejectReplayNullifier,
    BlockPrematureSettlement,
    BlockOpenChallengeSettlement,
}

impl ExpectedOutcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RejectWeakWatcher => "reject_weak_watcher",
            Self::RejectShallowFinality => "reject_shallow_finality",
            Self::RejectPrivacyFloor => "reject_privacy_floor",
            Self::RejectHighFee => "reject_high_fee",
            Self::RejectOversizedExit => "reject_oversized_exit",
            Self::RejectReplayNullifier => "reject_replay_nullifier",
            Self::BlockPrematureSettlement => "block_premature_settlement",
            Self::BlockOpenChallengeSettlement => "block_open_challenge_settlement",
        }
    }

    pub fn expected_error_fragment(self) -> &'static str {
        match self {
            Self::RejectWeakWatcher => "observed weight below threshold",
            Self::RejectShallowFinality => "lacks required Monero finality depth",
            Self::RejectPrivacyFloor => "privacy set below minimum",
            Self::RejectHighFee => "fee exceeds bridge policy cap",
            Self::RejectOversizedExit => "exit amount exceeds path amount",
            Self::RejectReplayNullifier => "burn nullifier already spent",
            Self::BlockPrematureSettlement => "forced exit delay has not elapsed",
            Self::BlockOpenChallengeSettlement => "open exit challenge",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CaseStatus {
    Passed,
    Watch,
    Failed,
}

impl CaseStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Passed => "passed",
            Self::Watch => "watch",
            Self::Failed => "failed",
        }
    }

    pub fn passes(self) -> bool {
        matches!(self, Self::Passed | Self::Watch)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MatrixStatus {
    Passed,
    Watch,
    Failed,
}

impl MatrixStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Passed => "passed",
            Self::Watch => "watch",
            Self::Failed => "failed",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub matrix_suite: String,
    pub label: String,
    pub min_cases: u64,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            matrix_suite: MATRIX_SUITE.to_string(),
            label: DEVNET_MATRIX_LABEL.to_string(),
            min_cases: DEFAULT_MIN_CASES,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "matrix_suite": self.matrix_suite,
            "label": self.label,
            "min_cases": self.min_cases,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("adversarial_matrix_config", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AdversarialCaseResult {
    pub case_id: String,
    pub kind: AdversarialCaseKind,
    pub status: CaseStatus,
    pub expected: ExpectedOutcome,
    pub operation: String,
    pub threat_surface: String,
    pub expected_error_fragment: String,
    pub observed: String,
    pub before_spine_root: String,
    pub after_spine_root: String,
    pub mutated_state: bool,
    pub evidence_root: String,
    pub remediation: String,
}

impl AdversarialCaseResult {
    pub fn public_record(&self) -> Value {
        json!({
            "case_id": self.case_id,
            "kind": self.kind.as_str(),
            "status": self.status.as_str(),
            "expected": self.expected.as_str(),
            "operation": self.operation,
            "threat_surface": self.threat_surface,
            "expected_error_fragment": self.expected_error_fragment,
            "observed": self.observed,
            "before_spine_root": self.before_spine_root,
            "after_spine_root": self.after_spine_root,
            "mutated_state": self.mutated_state,
            "evidence_root": self.evidence_root,
            "remediation": self.remediation,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("adversarial_case", &self.public_record())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Counters {
    pub cases_run: u64,
    pub cases_passed: u64,
    pub cases_watch: u64,
    pub cases_failed: u64,
    pub weak_watcher_rejections: u64,
    pub shallow_finality_rejections: u64,
    pub privacy_floor_rejections: u64,
    pub high_fee_rejections: u64,
    pub liquidity_rejections: u64,
    pub replay_rejections: u64,
    pub premature_settlement_blocks: u64,
    pub open_challenge_blocks: u64,
    pub fail_closed_cases: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "cases_run": self.cases_run,
            "cases_passed": self.cases_passed,
            "cases_watch": self.cases_watch,
            "cases_failed": self.cases_failed,
            "weak_watcher_rejections": self.weak_watcher_rejections,
            "shallow_finality_rejections": self.shallow_finality_rejections,
            "privacy_floor_rejections": self.privacy_floor_rejections,
            "high_fee_rejections": self.high_fee_rejections,
            "liquidity_rejections": self.liquidity_rejections,
            "replay_rejections": self.replay_rejections,
            "premature_settlement_blocks": self.premature_settlement_blocks,
            "open_challenge_blocks": self.open_challenge_blocks,
            "fail_closed_cases": self.fail_closed_cases,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("adversarial_counters", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub case_root: String,
    pub counters_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn empty(config: &Config, counters: &Counters) -> Self {
        let mut roots = Self {
            config_root: config.state_root(),
            case_root: merkle_root(
                "MONERO-L2-PQ-BRIDGE-EXIT-ADVERSARIAL-MATRIX-EMPTY-CASES",
                &[],
            ),
            counters_root: counters.state_root(),
            state_root: String::new(),
        };
        roots.state_root = roots.compute_state_root();
        roots
    }

    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "case_root": self.case_root,
            "counters_root": self.counters_root,
            "state_root": self.state_root,
        })
    }

    pub fn compute_state_root(&self) -> String {
        domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-ADVERSARIAL-MATRIX-ROOTS",
            &[
                HashPart::Str(&self.config_root),
                HashPart::Str(&self.case_root),
                HashPart::Str(&self.counters_root),
            ],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub matrix_status: MatrixStatus,
    pub cases: BTreeMap<String, AdversarialCaseResult>,
    pub counters: Counters,
    pub roots: Roots,
}

impl State {
    pub fn devnet() -> Self {
        let config = Config::devnet();
        let counters = Counters::default();
        let roots = Roots::empty(&config, &counters);
        let mut state = Self {
            config,
            matrix_status: MatrixStatus::Watch,
            cases: BTreeMap::new(),
            counters,
            roots,
        };
        state
            .run_devnet_matrix()
            .expect("devnet bridge/exit adversarial scenario matrix");
        state
    }

    pub fn run_devnet_matrix(&mut self) -> Result<()> {
        let baseline = BridgeExitSpineState::devnet();
        let cases = [
            weak_pq_watcher_quorum_case(&baseline),
            shallow_monero_finality_case(&baseline),
            deposit_privacy_floor_case(&baseline),
            private_action_fee_cap_case(&baseline),
            exit_amount_cap_case(&baseline),
            replay_nullifier_case(&baseline),
            premature_forced_settlement_case(&baseline),
            open_challenge_blocks_settlement_case(&baseline),
        ];
        for case in cases {
            self.record_case(case);
        }
        self.matrix_status = self.aggregate_status();
        self.refresh_roots();
        Ok(())
    }

    fn record_case(&mut self, case: AdversarialCaseResult) {
        self.counters.cases_run += 1;
        match case.status {
            CaseStatus::Passed => self.counters.cases_passed += 1,
            CaseStatus::Watch => self.counters.cases_watch += 1,
            CaseStatus::Failed => self.counters.cases_failed += 1,
        }
        if case.status.passes() {
            self.counters.fail_closed_cases += 1;
            match case.kind {
                AdversarialCaseKind::WeakPqWatcherQuorum => {
                    self.counters.weak_watcher_rejections += 1
                }
                AdversarialCaseKind::ShallowMoneroFinality => {
                    self.counters.shallow_finality_rejections += 1
                }
                AdversarialCaseKind::DepositPrivacyFloor => {
                    self.counters.privacy_floor_rejections += 1
                }
                AdversarialCaseKind::PrivateActionFeeCap => self.counters.high_fee_rejections += 1,
                AdversarialCaseKind::ExitAmountCap => self.counters.liquidity_rejections += 1,
                AdversarialCaseKind::ReplayNullifier => self.counters.replay_rejections += 1,
                AdversarialCaseKind::PrematureForcedSettlement => {
                    self.counters.premature_settlement_blocks += 1
                }
                AdversarialCaseKind::OpenChallengeBlocksSettlement => {
                    self.counters.open_challenge_blocks += 1
                }
            }
        }
        self.cases.insert(case.case_id.clone(), case);
    }

    fn aggregate_status(&self) -> MatrixStatus {
        if self
            .cases
            .values()
            .any(|case| case.status == CaseStatus::Failed)
        {
            MatrixStatus::Failed
        } else if self.cases.len() < self.config.min_cases as usize
            || self
                .cases
                .values()
                .any(|case| case.status == CaseStatus::Watch)
        {
            MatrixStatus::Watch
        } else {
            MatrixStatus::Passed
        }
    }

    fn refresh_roots(&mut self) {
        let case_records = self
            .cases
            .values()
            .map(AdversarialCaseResult::public_record)
            .collect::<Vec<_>>();
        self.roots = Roots {
            config_root: self.config.state_root(),
            case_root: merkle_root(
                "MONERO-L2-PQ-BRIDGE-EXIT-ADVERSARIAL-MATRIX-CASES",
                &case_records,
            ),
            counters_root: self.counters.state_root(),
            state_root: String::new(),
        };
        self.roots.state_root = self.roots.compute_state_root();
    }

    pub fn public_record(&self) -> Value {
        let cases = self
            .cases
            .values()
            .map(AdversarialCaseResult::public_record)
            .collect::<Vec<_>>();
        json!({
            "protocol_version": self.config.protocol_version,
            "schema_version": self.config.schema_version,
            "matrix_suite": self.config.matrix_suite,
            "matrix_status": self.matrix_status.as_str(),
            "cases": cases,
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
        })
    }

    pub fn state_root(&self) -> String {
        self.roots.state_root.clone()
    }
}

fn weak_pq_watcher_quorum_case(baseline: &BridgeExitSpineState) -> AdversarialCaseResult {
    let mut spine = baseline.clone();
    let before = spine.state_root();
    let kind = AdversarialCaseKind::WeakPqWatcherQuorum;
    let seed = kind.as_str();
    let watcher_set_root = root(seed, "weak-watcher-set");
    let pq_committee_root = root(seed, "weak-pq-committee");
    let quorum = WatcherQuorum {
        quorum_id: root(seed, "weak-quorum-id"),
        watcher_set_root,
        pq_committee_root,
        threshold_weight: spine.config.min_watcher_weight,
        observed_weight: spine.config.min_watcher_weight.saturating_sub(1),
        min_pq_security_bits: spine.config.min_pq_security_bits,
        monero_finality_depth: spine.config.monero_finality_depth,
        last_certified_height: base_height(&spine),
        certificate_root: root(seed, "weak-certificate-root"),
    };
    let result = spine.register_watcher_quorum(quorum);
    case_from_result(
        kind,
        ExpectedOutcome::RejectWeakWatcher,
        "register_watcher_quorum",
        before,
        spine.state_root(),
        result.map(|_| "registered".to_string()),
        "rotate or slash watcher quorum before accepting bridge certificates",
    )
}

fn shallow_monero_finality_case(baseline: &BridgeExitSpineState) -> AdversarialCaseResult {
    let mut spine = baseline.clone();
    let before = spine.state_root();
    let kind = AdversarialCaseKind::ShallowMoneroFinality;
    let seed = kind.as_str();
    let quorum_id = first_quorum_id(&spine);
    let result = spine.open_deposit_path(DepositLockRequest {
        monero_lock_txid: format!("{seed}-lock-txid"),
        deposit_commitment: root(seed, "deposit-commitment"),
        amount: DEFAULT_CASE_AMOUNT,
        sender_viewtag_commitment: root(seed, "viewtag"),
        deposit_subaddress_commitment: root(seed, "subaddress"),
        privacy_set_size: spine.config.target_privacy_set_size,
        pq_authorization_root: root(seed, "pq-auth"),
        watcher_quorum_id: quorum_id,
        observed_monero_height: spine.config.genesis_height + spine.config.fast_finality_depth,
        lane: BridgeLane::Standard,
        user_fee_bps: spine.config.low_fee_bps,
    });
    case_from_result(
        kind,
        ExpectedOutcome::RejectShallowFinality,
        "open_deposit_path",
        before,
        spine.state_root(),
        result,
        "hold Monero locks until the selected bridge lane finality depth is reached",
    )
}

fn deposit_privacy_floor_case(baseline: &BridgeExitSpineState) -> AdversarialCaseResult {
    let mut spine = baseline.clone();
    let before = spine.state_root();
    let kind = AdversarialCaseKind::DepositPrivacyFloor;
    let seed = kind.as_str();
    let quorum_id = first_quorum_id(&spine);
    let result = spine.open_deposit_path(DepositLockRequest {
        monero_lock_txid: format!("{seed}-lock-txid"),
        deposit_commitment: root(seed, "deposit-commitment"),
        amount: DEFAULT_CASE_AMOUNT,
        sender_viewtag_commitment: root(seed, "viewtag"),
        deposit_subaddress_commitment: root(seed, "subaddress"),
        privacy_set_size: spine.config.min_privacy_set_size.saturating_sub(1),
        pq_authorization_root: root(seed, "pq-auth"),
        watcher_quorum_id: quorum_id,
        observed_monero_height: base_height(&spine),
        lane: BridgeLane::Standard,
        user_fee_bps: spine.config.low_fee_bps,
    });
    case_from_result(
        kind,
        ExpectedOutcome::RejectPrivacyFloor,
        "open_deposit_path",
        before,
        spine.state_root(),
        result,
        "batch or delay deposits until the privacy set floor is available",
    )
}

fn private_action_fee_cap_case(baseline: &BridgeExitSpineState) -> AdversarialCaseResult {
    let mut spine = baseline.clone();
    let before = spine.state_root();
    let kind = AdversarialCaseKind::PrivateActionFeeCap;
    let seed = kind.as_str();
    let ready = build_ready_path(&mut spine, seed);
    let result = ready.and_then(|ready| {
        spine.record_private_action(PrivateActionRequest {
            path_id: ready.path_id,
            action_kind: PrivateActionKind::ContractCall,
            action_commitment: root(seed, "high-fee-action"),
            private_state_root: root(seed, "high-fee-private-state"),
            contract_call_root: root(seed, "high-fee-contract-call"),
            token_transfer_root: root(seed, "high-fee-token-transfer"),
            fee_sponsor_root: root(seed, "high-fee-sponsor"),
            sequencer_pq_root: root(seed, "high-fee-sequencer-pq"),
            receipt_root: root(seed, "high-fee-receipt"),
            privacy_set_size: spine.config.target_privacy_set_size,
            user_fee_bps: spine.policy.fee_cap_bps.saturating_add(1),
        })
    });
    case_from_result(
        kind,
        ExpectedOutcome::RejectHighFee,
        "record_private_action",
        before,
        spine.state_root(),
        result,
        "route expensive actions through sponsor/rebate lanes or reject before sequencing",
    )
}

fn exit_amount_cap_case(baseline: &BridgeExitSpineState) -> AdversarialCaseResult {
    let mut spine = baseline.clone();
    let before = spine.state_root();
    let kind = AdversarialCaseKind::ExitAmountCap;
    let seed = kind.as_str();
    let ready = build_ready_path(&mut spine, seed);
    let result = ready.and_then(|ready| {
        let height = ready.anchor_height.saturating_add(4);
        spine.request_exit(exit_request(
            &spine,
            &ready,
            seed,
            DEFAULT_CASE_AMOUNT.saturating_add(1),
            root(seed, "oversized-nullifier"),
            height,
        ))
    });
    case_from_result(
        kind,
        ExpectedOutcome::RejectOversizedExit,
        "request_exit",
        before,
        spine.state_root(),
        result,
        "prove reserve coverage and reject exits larger than the locked private note amount",
    )
}

fn replay_nullifier_case(baseline: &BridgeExitSpineState) -> AdversarialCaseResult {
    let mut spine = baseline.clone();
    let before = spine.state_root();
    let kind = AdversarialCaseKind::ReplayNullifier;
    let seed = kind.as_str();
    let ready = build_ready_path(&mut spine, seed);
    let result = ready.and_then(|ready| {
        let height = ready.anchor_height.saturating_add(4);
        let nullifier = root(seed, "replay-nullifier");
        spine.request_exit(exit_request(
            &spine,
            &ready,
            seed,
            DEFAULT_EXIT_AMOUNT,
            nullifier.clone(),
            height,
        ))?;
        spine.request_exit(exit_request(
            &spine,
            &ready,
            "replay-nullifier-second-attempt",
            DEFAULT_EXIT_AMOUNT,
            nullifier,
            height.saturating_add(1),
        ))
    });
    case_from_result(
        kind,
        ExpectedOutcome::RejectReplayNullifier,
        "request_exit",
        before,
        spine.state_root(),
        result,
        "reject duplicate burn nullifiers before path state or settlement release is evaluated",
    )
}

fn premature_forced_settlement_case(baseline: &BridgeExitSpineState) -> AdversarialCaseResult {
    let mut spine = baseline.clone();
    let before = spine.state_root();
    let kind = AdversarialCaseKind::PrematureForcedSettlement;
    let seed = kind.as_str();
    let ready = build_ready_path(&mut spine, seed);
    let result = ready.and_then(|ready| {
        let request_height = ready.anchor_height.saturating_add(6);
        spine.request_exit(exit_request(
            &spine,
            &ready,
            seed,
            DEFAULT_EXIT_AMOUNT,
            root(seed, "premature-nullifier"),
            request_height,
        ))?;
        spine.settle_exit(ExitSettlementRequest {
            path_id: ready.path_id,
            settlement_tx_root: root(seed, "premature-settlement-tx"),
            release_certificate_root: root(seed, "premature-release-cert"),
            final_private_state_root: root(seed, "premature-final-private-state"),
            settled_height: request_height
                .saturating_add(spine.config.forced_exit_delay_blocks)
                .saturating_sub(1),
        })
    });
    case_from_result(
        kind,
        ExpectedOutcome::BlockPrematureSettlement,
        "settle_exit",
        before,
        spine.state_root(),
        result,
        "hold forced exits until the delay elapses even when settlement liquidity is present",
    )
}

fn open_challenge_blocks_settlement_case(baseline: &BridgeExitSpineState) -> AdversarialCaseResult {
    let mut spine = baseline.clone();
    let before = spine.state_root();
    let kind = AdversarialCaseKind::OpenChallengeBlocksSettlement;
    let seed = kind.as_str();
    let ready = build_ready_path(&mut spine, seed);
    let result = ready.and_then(|ready| {
        let request_height = ready.anchor_height.saturating_add(6);
        spine.request_exit(exit_request(
            &spine,
            &ready,
            seed,
            DEFAULT_EXIT_AMOUNT,
            root(seed, "challenge-nullifier"),
            request_height,
        ))?;
        let armed_height = request_height.saturating_add(spine.config.exit_liveness_window_blocks);
        spine.arm_forced_exit(ForcedExitRequest {
            path_id: ready.path_id.clone(),
            censorship_evidence_root: root(seed, "challenge-censorship-evidence"),
            liveness_failure_root: root(seed, "challenge-liveness-failure"),
            watcher_quorum_id: ready.quorum_id.clone(),
            armed_height,
        })?;
        spine.challenge_path(ChallengeRequest {
            path_id: ready.path_id.clone(),
            challenger_commitment: root(seed, "challenger"),
            kind: ChallengeKind::SequencerCensorship,
            evidence_root: root(seed, "challenge-evidence"),
            opened_height: armed_height.saturating_add(1),
        })?;
        spine.settle_exit(ExitSettlementRequest {
            path_id: ready.path_id,
            settlement_tx_root: root(seed, "open-challenge-settlement-tx"),
            release_certificate_root: root(seed, "open-challenge-release-cert"),
            final_private_state_root: root(seed, "open-challenge-final-state"),
            settled_height: armed_height
                .saturating_add(spine.config.forced_exit_delay_blocks)
                .saturating_add(1),
        })
    });
    case_from_result(
        kind,
        ExpectedOutcome::BlockOpenChallengeSettlement,
        "settle_exit",
        before,
        spine.state_root(),
        result,
        "block exit release while adversarial challenges remain open",
    )
}

fn case_from_result<T>(
    kind: AdversarialCaseKind,
    expected: ExpectedOutcome,
    operation: &str,
    before_spine_root: String,
    after_spine_root: String,
    result: Result<T>,
    remediation: &str,
) -> AdversarialCaseResult {
    let expected_fragment = expected.expected_error_fragment().to_string();
    let observed = match result {
        Ok(_) => "operation accepted unexpectedly".to_string(),
        Err(error) => error,
    };
    let status = if observed == "operation accepted unexpectedly" {
        CaseStatus::Failed
    } else if observed.contains(&expected_fragment) {
        CaseStatus::Passed
    } else {
        CaseStatus::Watch
    };
    let mutated_state = before_spine_root != after_spine_root;
    let evidence = json!({
        "kind": kind.as_str(),
        "expected": expected.as_str(),
        "operation": operation,
        "expected_error_fragment": expected_fragment,
        "observed": observed,
        "before_spine_root": before_spine_root,
        "after_spine_root": after_spine_root,
        "mutated_state": mutated_state,
    });
    let evidence_root = record_root("adversarial_case_evidence", &evidence);
    let case_id = adversarial_case_id(kind, expected, &evidence_root);
    AdversarialCaseResult {
        case_id,
        kind,
        status,
        expected,
        operation: operation.to_string(),
        threat_surface: kind.threat().to_string(),
        expected_error_fragment,
        observed,
        before_spine_root,
        after_spine_root,
        mutated_state,
        evidence_root,
        remediation: remediation.to_string(),
    }
}

#[derive(Clone, Debug)]
struct ReadyPath {
    path_id: String,
    quorum_id: String,
    anchor_height: u64,
}

fn build_ready_path(spine: &mut BridgeExitSpineState, seed: &str) -> Result<ReadyPath> {
    let quorum_id = first_quorum_id(spine);
    let base = base_height(spine);
    let privacy_set_size = spine.config.target_privacy_set_size;
    let fee_bps = spine.config.low_fee_bps;
    let path_id = spine.open_deposit_path(DepositLockRequest {
        monero_lock_txid: format!("{seed}-ready-lock-txid"),
        deposit_commitment: root(seed, "ready-deposit-commitment"),
        amount: DEFAULT_CASE_AMOUNT,
        sender_viewtag_commitment: root(seed, "ready-viewtag"),
        deposit_subaddress_commitment: root(seed, "ready-subaddress"),
        privacy_set_size,
        pq_authorization_root: root(seed, "ready-pq-auth"),
        watcher_quorum_id: quorum_id.clone(),
        observed_monero_height: base,
        lane: BridgeLane::Standard,
        user_fee_bps: fee_bps,
    })?;
    spine.certify_deposit_lock(DepositCertificateRequest {
        path_id: path_id.clone(),
        watcher_quorum_id: quorum_id.clone(),
        certificate_root: root(seed, "ready-certificate"),
        monero_finality_depth: spine.config.monero_finality_depth,
        certified_height: base.saturating_add(1),
    })?;
    spine.mint_private_note(MintPrivateNoteRequest {
        path_id: path_id.clone(),
        private_note_commitment: root(seed, "ready-note"),
        note_membership_root: root(seed, "ready-note-membership"),
        wallet_scan_hint_root: root(seed, "ready-wallet-scan-hint"),
        privacy_set_size,
    })?;
    let receipt_root = root(seed, "ready-receipt");
    spine.record_private_action(PrivateActionRequest {
        path_id: path_id.clone(),
        action_kind: PrivateActionKind::Transfer,
        action_commitment: root(seed, "ready-action"),
        private_state_root: root(seed, "ready-private-state"),
        contract_call_root: root(seed, "ready-contract-call"),
        token_transfer_root: root(seed, "ready-token-transfer"),
        fee_sponsor_root: root(seed, "ready-fee-sponsor"),
        sequencer_pq_root: root(seed, "ready-sequencer-pq"),
        receipt_root: receipt_root.clone(),
        privacy_set_size,
        user_fee_bps: fee_bps,
    })?;
    let anchor_height = base.saturating_add(3);
    spine.anchor_settlement_receipt(AnchorReceiptRequest {
        path_id: path_id.clone(),
        receipt_root,
        settlement_state_root: root(seed, "ready-settlement-state"),
        bridge_checkpoint_root: root(seed, "ready-bridge-checkpoint"),
        anchor_height,
    })?;
    Ok(ReadyPath {
        path_id,
        quorum_id,
        anchor_height,
    })
}

fn exit_request(
    spine: &BridgeExitSpineState,
    ready: &ReadyPath,
    seed: &str,
    amount: u128,
    nullifier: String,
    requested_height: u64,
) -> WithdrawalRequest {
    WithdrawalRequest {
        path_id: ready.path_id.clone(),
        withdrawal_commitment: root(seed, "withdrawal-commitment"),
        burn_nullifier: nullifier,
        payout_subaddress_commitment: root(seed, "payout-subaddress"),
        requested_amount: amount,
        exit_mode: ExitMode::Forced,
        watcher_quorum_id: ready.quorum_id.clone(),
        liquidity_root: root(seed, "liquidity-root"),
        pq_authorization_root: root(seed, "exit-pq-auth"),
        privacy_set_size: spine.config.target_privacy_set_size,
        requested_height,
        user_fee_bps: spine.config.low_fee_bps,
    }
}

fn first_quorum_id(spine: &BridgeExitSpineState) -> String {
    spine
        .watcher_quorums
        .keys()
        .next()
        .cloned()
        .unwrap_or_else(|| "missing-devnet-quorum".to_string())
}

fn base_height(spine: &BridgeExitSpineState) -> u64 {
    spine
        .config
        .genesis_height
        .saturating_add(spine.config.monero_finality_depth)
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn public_record(state: &State) -> Value {
    state.public_record()
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}

pub fn adversarial_case_id(
    kind: AdversarialCaseKind,
    expected: ExpectedOutcome,
    evidence_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-ADVERSARIAL-MATRIX-CASE-ID",
        &[
            HashPart::Str(kind.as_str()),
            HashPart::Str(expected.as_str()),
            HashPart::Str(evidence_root),
        ],
        32,
    )
}

pub fn root(seed: &str, label: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-ADVERSARIAL-MATRIX-ROOT",
        &[HashPart::Str(seed), HashPart::Str(label)],
        32,
    )
}

pub fn record_root(kind: &str, record: &Value) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-ADVERSARIAL-MATRIX-RECORD",
        &[HashPart::Str(kind), HashPart::Json(record)],
        32,
    )
}
