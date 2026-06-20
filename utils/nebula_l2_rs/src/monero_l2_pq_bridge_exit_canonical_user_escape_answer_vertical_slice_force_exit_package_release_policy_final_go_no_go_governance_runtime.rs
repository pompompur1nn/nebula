use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalUserEscapeAnswerVerticalSliceForceExitPackageReleasePolicyFinalGoNoGoGovernanceRuntimeResult<
    T,
> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_ANSWER_VERTICAL_SLICE_FORCE_EXIT_PACKAGE_RELEASE_POLICY_FINAL_GO_NO_GO_GOVERNANCE_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-canonical-user-escape-answer-vertical-slice-force-exit-package-release-policy-final-go-no-go-governance-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_ANSWER_VERTICAL_SLICE_FORCE_EXIT_PACKAGE_RELEASE_POLICY_FINAL_GO_NO_GO_GOVERNANCE_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const GOVERNANCE_SUITE: &str =
    "monero-l2-pq-force-exit-package-release-policy-final-go-no-go-governance-v1";
pub const DEFAULT_VERTICAL_SLICE_ID: &str =
    "monero-l2-pq-bridge-exit-canonical-user-escape-answer-vertical-slice-devnet-v1";
pub const DEFAULT_FORCE_EXIT_PACKAGE_ID: &str =
    "force-exit-release-policy-final-go-no-go-governance-devnet-0001";
pub const DEFAULT_GOVERNANCE_EPOCH: u64 = 80;
pub const DEFAULT_MIN_LANE_BINDINGS: u64 = 7;
pub const DEFAULT_MIN_GOVERNANCE_SIGNATURES: u64 = 5;
pub const DEFAULT_MIN_OPERATOR_ACKS: u64 = 4;
pub const DEFAULT_MAX_RELEASE_HOLDS: u64 = 0;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub governance_suite: String,
    pub vertical_slice_id: String,
    pub force_exit_package_id: String,
    pub governance_epoch: u64,
    pub min_lane_bindings: u64,
    pub min_governance_signatures: u64,
    pub min_operator_acks: u64,
    pub max_release_holds: u64,
    pub require_circuit_breaker_root: bool,
    pub require_lane_binding_roots: bool,
    pub require_wallet_notice_root: bool,
    pub require_operator_action_root: bool,
    pub require_public_governance_record: bool,
    pub fail_closed_on_any_hold: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            governance_suite: GOVERNANCE_SUITE.to_string(),
            vertical_slice_id: DEFAULT_VERTICAL_SLICE_ID.to_string(),
            force_exit_package_id: DEFAULT_FORCE_EXIT_PACKAGE_ID.to_string(),
            governance_epoch: DEFAULT_GOVERNANCE_EPOCH,
            min_lane_bindings: DEFAULT_MIN_LANE_BINDINGS,
            min_governance_signatures: DEFAULT_MIN_GOVERNANCE_SIGNATURES,
            min_operator_acks: DEFAULT_MIN_OPERATOR_ACKS,
            max_release_holds: DEFAULT_MAX_RELEASE_HOLDS,
            require_circuit_breaker_root: true,
            require_lane_binding_roots: true,
            require_wallet_notice_root: true,
            require_operator_action_root: true,
            require_public_governance_record: true,
            fail_closed_on_any_hold: true,
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
            "governance_suite": self.governance_suite,
            "vertical_slice_id": self.vertical_slice_id,
            "force_exit_package_id": self.force_exit_package_id,
            "governance_epoch": self.governance_epoch,
            "min_lane_bindings": self.min_lane_bindings,
            "min_governance_signatures": self.min_governance_signatures,
            "min_operator_acks": self.min_operator_acks,
            "max_release_holds": self.max_release_holds,
            "require_circuit_breaker_root": self.require_circuit_breaker_root,
            "require_lane_binding_roots": self.require_lane_binding_roots,
            "require_wallet_notice_root": self.require_wallet_notice_root,
            "require_operator_action_root": self.require_operator_action_root,
            "require_public_governance_record": self.require_public_governance_record,
            "fail_closed_on_any_hold": self.fail_closed_on_any_hold,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GovernanceLane {
    CompileRuntime,
    RuntimeReplay,
    AuditSecurity,
    BridgeCustody,
    WalletWatchtower,
    PqReservePrivacy,
    CircuitBreaker,
}

impl GovernanceLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CompileRuntime => "compile_runtime",
            Self::RuntimeReplay => "runtime_replay",
            Self::AuditSecurity => "audit_security",
            Self::BridgeCustody => "bridge_custody",
            Self::WalletWatchtower => "wallet_watchtower",
            Self::PqReservePrivacy => "pq_reserve_privacy",
            Self::CircuitBreaker => "circuit_breaker",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BindingStatus {
    Accepted,
    Held,
    Missing,
    Stale,
    GovernancePending,
    OperatorPending,
}

impl BindingStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Held => "held",
            Self::Missing => "missing",
            Self::Stale => "stale",
            Self::GovernancePending => "governance_pending",
            Self::OperatorPending => "operator_pending",
        }
    }

    pub fn permits_release(self) -> bool {
        matches!(self, Self::Accepted)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FinalDecision {
    PermitRelease,
    HoldRelease,
}

impl FinalDecision {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PermitRelease => "permit_release",
            Self::HoldRelease => "hold_release",
        }
    }

    pub fn permits_release(self) -> bool {
        matches!(self, Self::PermitRelease)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GovernanceBinding {
    pub binding_id: String,
    pub lane: GovernanceLane,
    pub enforcement_root: String,
    pub circuit_breaker_root: String,
    pub go_no_go_root: String,
    pub governance_signature_root: String,
    pub operator_ack_root: String,
    pub wallet_notice_root: String,
    pub public_record_root: String,
    pub governance_signatures: u64,
    pub operator_acks: u64,
    pub status: BindingStatus,
    pub hold_reason: String,
}

impl GovernanceBinding {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        lane: GovernanceLane,
        enforcement_root: &str,
        circuit_breaker_root: &str,
        go_no_go_root: &str,
        governance_signature_root: &str,
        operator_ack_root: &str,
        wallet_notice_root: &str,
        public_record_root: &str,
        governance_signatures: u64,
        operator_acks: u64,
        status: BindingStatus,
        hold_reason: &str,
    ) -> Self {
        let binding_id = governance_binding_id(
            lane,
            enforcement_root,
            circuit_breaker_root,
            go_no_go_root,
            governance_signature_root,
            operator_ack_root,
            wallet_notice_root,
            public_record_root,
            governance_signatures,
            operator_acks,
            status,
            hold_reason,
        );
        Self {
            binding_id,
            lane,
            enforcement_root: enforcement_root.to_string(),
            circuit_breaker_root: circuit_breaker_root.to_string(),
            go_no_go_root: go_no_go_root.to_string(),
            governance_signature_root: governance_signature_root.to_string(),
            operator_ack_root: operator_ack_root.to_string(),
            wallet_notice_root: wallet_notice_root.to_string(),
            public_record_root: public_record_root.to_string(),
            governance_signatures,
            operator_acks,
            status,
            hold_reason: hold_reason.to_string(),
        }
    }

    pub fn has_required_roots(&self) -> bool {
        !self.enforcement_root.is_empty()
            && !self.circuit_breaker_root.is_empty()
            && !self.go_no_go_root.is_empty()
            && !self.governance_signature_root.is_empty()
            && !self.operator_ack_root.is_empty()
            && !self.wallet_notice_root.is_empty()
            && !self.public_record_root.is_empty()
    }

    pub fn accepted(&self, config: &Config) -> bool {
        self.status.permits_release()
            && self.has_required_roots()
            && self.governance_signatures >= config.min_governance_signatures
            && self.operator_acks >= config.min_operator_acks
    }

    pub fn public_record(&self) -> Value {
        json!({
            "binding_id": self.binding_id,
            "lane": self.lane.as_str(),
            "enforcement_root": self.enforcement_root,
            "circuit_breaker_root": self.circuit_breaker_root,
            "go_no_go_root": self.go_no_go_root,
            "governance_signature_root": self.governance_signature_root,
            "operator_ack_root": self.operator_ack_root,
            "wallet_notice_root": self.wallet_notice_root,
            "public_record_root": self.public_record_root,
            "governance_signatures": self.governance_signatures,
            "operator_acks": self.operator_acks,
            "status": self.status.as_str(),
            "hold_reason": self.hold_reason,
            "has_required_roots": self.has_required_roots(),
        })
    }

    pub fn state_root(&self) -> String {
        record_root("governance-binding", &self.public_record())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub lane_bindings: u64,
    pub accepted_bindings: u64,
    pub held_bindings: u64,
    pub missing_bindings: u64,
    pub governance_pending: u64,
    pub operator_pending: u64,
    pub missing_root_bindings: u64,
}

impl Counters {
    pub fn from_bindings(config: &Config, bindings: &[GovernanceBinding]) -> Self {
        let mut counters = Self {
            lane_bindings: bindings.len() as u64,
            ..Self::default()
        };
        for binding in bindings {
            if binding.accepted(config) {
                counters.accepted_bindings = counters.accepted_bindings.saturating_add(1);
            } else {
                counters.held_bindings = counters.held_bindings.saturating_add(1);
            }
            match binding.status {
                BindingStatus::Missing => {
                    counters.missing_bindings = counters.missing_bindings.saturating_add(1)
                }
                BindingStatus::GovernancePending => {
                    counters.governance_pending = counters.governance_pending.saturating_add(1)
                }
                BindingStatus::OperatorPending => {
                    counters.operator_pending = counters.operator_pending.saturating_add(1)
                }
                BindingStatus::Accepted | BindingStatus::Held | BindingStatus::Stale => {}
            }
            if !binding.has_required_roots() {
                counters.missing_root_bindings = counters.missing_root_bindings.saturating_add(1);
            }
        }
        counters
    }

    pub fn public_record(&self) -> Value {
        json!({
            "lane_bindings": self.lane_bindings,
            "accepted_bindings": self.accepted_bindings,
            "held_bindings": self.held_bindings,
            "missing_bindings": self.missing_bindings,
            "governance_pending": self.governance_pending,
            "operator_pending": self.operator_pending,
            "missing_root_bindings": self.missing_root_bindings,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("counters", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FinalGovernanceVerdict {
    pub verdict_id: String,
    pub decision: FinalDecision,
    pub release_allowed: bool,
    pub binding_root: String,
    pub operator_action_root: String,
    pub wallet_notice_root: String,
    pub public_governance_record_root: String,
    pub hold_reason_root: String,
    pub detail: String,
}

impl FinalGovernanceVerdict {
    pub fn new(config: &Config, counters: &Counters, binding_root: &str) -> Self {
        let release_allowed = release_allowed(config, counters);
        let decision = if release_allowed {
            FinalDecision::PermitRelease
        } else {
            FinalDecision::HoldRelease
        };
        let detail = final_detail(config, counters, decision);
        let operator_action_root = verdict_root("operator-action", decision, &detail);
        let wallet_notice_root = verdict_root("wallet-notice", decision, &detail);
        let public_governance_record_root =
            verdict_root("public-governance-record", decision, &detail);
        let hold_reason_root = verdict_root("hold-reason", decision, &detail);
        let verdict_id = final_verdict_id(
            decision,
            binding_root,
            &operator_action_root,
            &wallet_notice_root,
            &public_governance_record_root,
            &hold_reason_root,
            &detail,
        );
        Self {
            verdict_id,
            decision,
            release_allowed,
            binding_root: binding_root.to_string(),
            operator_action_root,
            wallet_notice_root,
            public_governance_record_root,
            hold_reason_root,
            detail,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "verdict_id": self.verdict_id,
            "decision": self.decision.as_str(),
            "release_allowed": self.release_allowed,
            "binding_root": self.binding_root,
            "operator_action_root": self.operator_action_root,
            "wallet_notice_root": self.wallet_notice_root,
            "public_governance_record_root": self.public_governance_record_root,
            "hold_reason_root": self.hold_reason_root,
            "detail": self.detail,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("final-governance-verdict", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub binding_root: String,
    pub counter_root: String,
    pub verdict_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "binding_root": self.binding_root,
            "counter_root": self.counter_root,
            "verdict_root": self.verdict_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub bindings: Vec<GovernanceBinding>,
    pub counters: Counters,
    pub verdict: FinalGovernanceVerdict,
    pub roots: Roots,
}

impl State {
    pub fn new(config: Config, bindings: Vec<GovernanceBinding>) -> Self {
        let counters = Counters::from_bindings(&config, &bindings);
        let binding_root = merkle_root(
            "release-policy-final-go-no-go-governance-bindings",
            &bindings
                .iter()
                .map(GovernanceBinding::state_root)
                .collect::<Vec<_>>(),
        );
        let verdict = FinalGovernanceVerdict::new(&config, &counters, &binding_root);
        let roots = build_roots(&config, &binding_root, &counters, &verdict);
        Self {
            config,
            bindings,
            counters,
            verdict,
            roots,
        }
    }

    pub fn devnet() -> Self {
        let config = Config::devnet();
        let bindings = devnet_bindings(&config);
        Self::new(config, bindings)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "config": self.config.public_record(),
            "bindings": self.bindings.iter().map(GovernanceBinding::public_record).collect::<Vec<_>>(),
            "counters": self.counters.public_record(),
            "verdict": self.verdict.public_record(),
            "roots": self.roots.public_record(),
        })
    }

    pub fn state_root(&self) -> String {
        self.roots.state_root.clone()
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

pub fn devnet_bindings(config: &Config) -> Vec<GovernanceBinding> {
    [
        (
            GovernanceLane::CompileRuntime,
            BindingStatus::GovernancePending,
            "compile governance quorum still pending",
        ),
        (
            GovernanceLane::RuntimeReplay,
            BindingStatus::Held,
            "runtime replay enforcement remains held",
        ),
        (
            GovernanceLane::AuditSecurity,
            BindingStatus::GovernancePending,
            "audit security final signoff pending",
        ),
        (
            GovernanceLane::BridgeCustody,
            BindingStatus::Accepted,
            "bridge custody go/no-go binding accepted",
        ),
        (
            GovernanceLane::WalletWatchtower,
            BindingStatus::Accepted,
            "wallet watchtower go/no-go binding accepted",
        ),
        (
            GovernanceLane::PqReservePrivacy,
            BindingStatus::Held,
            "PQ reserve privacy enforcement remains held",
        ),
        (
            GovernanceLane::CircuitBreaker,
            BindingStatus::Held,
            "circuit breaker requires every lane to clear",
        ),
    ]
    .iter()
    .map(|(lane, status, reason)| {
        GovernanceBinding::new(
            *lane,
            &fixture_root("enforcement", lane.as_str()),
            &fixture_root("circuit-breaker", lane.as_str()),
            &fixture_root("go-no-go", lane.as_str()),
            &fixture_root("governance-signature", lane.as_str()),
            &fixture_root("operator-ack", lane.as_str()),
            &fixture_root("wallet-notice", lane.as_str()),
            &fixture_root("public-record", lane.as_str()),
            if status.permits_release() {
                config.min_governance_signatures
            } else {
                config.min_governance_signatures.saturating_sub(1)
            },
            if status.permits_release() {
                config.min_operator_acks
            } else {
                config.min_operator_acks.saturating_sub(1)
            },
            *status,
            reason,
        )
    })
    .collect()
}

pub fn release_allowed(config: &Config, counters: &Counters) -> bool {
    counters.lane_bindings >= config.min_lane_bindings
        && counters.accepted_bindings >= config.min_lane_bindings
        && counters.held_bindings <= config.max_release_holds
        && counters.missing_bindings == 0
        && counters.governance_pending == 0
        && counters.operator_pending == 0
        && counters.missing_root_bindings == 0
        && !config.fail_closed_on_any_hold
}

pub fn final_detail(config: &Config, counters: &Counters, decision: FinalDecision) -> String {
    if decision.permits_release() {
        return format!(
            "release permitted with accepted_bindings={}/{}",
            counters.accepted_bindings, config.min_lane_bindings
        );
    }
    format!(
        "release held: accepted_bindings={}/{}, held={}, missing={}, governance_pending={}, operator_pending={}, missing_roots={}",
        counters.accepted_bindings,
        config.min_lane_bindings,
        counters.held_bindings,
        counters.missing_bindings,
        counters.governance_pending,
        counters.operator_pending,
        counters.missing_root_bindings
    )
}

pub fn build_roots(
    config: &Config,
    binding_root: &str,
    counters: &Counters,
    verdict: &FinalGovernanceVerdict,
) -> Roots {
    let config_root = config.state_root();
    let counter_root = counters.state_root();
    let verdict_root = verdict.state_root();
    let state_root =
        final_governance_state_root(&config_root, binding_root, &counter_root, &verdict_root);
    Roots {
        config_root,
        binding_root: binding_root.to_string(),
        counter_root,
        verdict_root,
        state_root,
    }
}

#[allow(clippy::too_many_arguments)]
pub fn governance_binding_id(
    lane: GovernanceLane,
    enforcement_root: &str,
    circuit_breaker_root: &str,
    go_no_go_root: &str,
    governance_signature_root: &str,
    operator_ack_root: &str,
    wallet_notice_root: &str,
    public_record_root: &str,
    governance_signatures: u64,
    operator_acks: u64,
    status: BindingStatus,
    hold_reason: &str,
) -> String {
    domain_hash(
        "RELEASE-POLICY-FINAL-GO-NO-GO-GOVERNANCE-BINDING-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(lane.as_str()),
            HashPart::Str(enforcement_root),
            HashPart::Str(circuit_breaker_root),
            HashPart::Str(go_no_go_root),
            HashPart::Str(governance_signature_root),
            HashPart::Str(operator_ack_root),
            HashPart::Str(wallet_notice_root),
            HashPart::Str(public_record_root),
            HashPart::U64(governance_signatures),
            HashPart::U64(operator_acks),
            HashPart::Str(status.as_str()),
            HashPart::Str(hold_reason),
        ],
        32,
    )
}

pub fn final_verdict_id(
    decision: FinalDecision,
    binding_root: &str,
    operator_action_root: &str,
    wallet_notice_root: &str,
    public_governance_record_root: &str,
    hold_reason_root: &str,
    detail: &str,
) -> String {
    domain_hash(
        "RELEASE-POLICY-FINAL-GO-NO-GO-GOVERNANCE-VERDICT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(decision.as_str()),
            HashPart::Str(binding_root),
            HashPart::Str(operator_action_root),
            HashPart::Str(wallet_notice_root),
            HashPart::Str(public_governance_record_root),
            HashPart::Str(hold_reason_root),
            HashPart::Str(detail),
        ],
        32,
    )
}

pub fn verdict_root(kind: &str, decision: FinalDecision, detail: &str) -> String {
    domain_hash(
        "RELEASE-POLICY-FINAL-GO-NO-GO-GOVERNANCE-VERDICT-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(kind),
            HashPart::Str(decision.as_str()),
            HashPart::Str(detail),
        ],
        32,
    )
}

pub fn final_governance_state_root(
    config_root: &str,
    binding_root: &str,
    counter_root: &str,
    verdict_root: &str,
) -> String {
    domain_hash(
        "RELEASE-POLICY-FINAL-GO-NO-GO-GOVERNANCE-STATE",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(config_root),
            HashPart::Str(binding_root),
            HashPart::Str(counter_root),
            HashPart::Str(verdict_root),
        ],
        32,
    )
}

pub fn fixture_root(kind: &str, value: &str) -> String {
    domain_hash(
        "RELEASE-POLICY-FINAL-GO-NO-GO-GOVERNANCE-FIXTURE",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(kind),
            HashPart::Str(value),
        ],
        32,
    )
}

pub fn record_root(kind: &str, record: &Value) -> String {
    domain_hash(
        "RELEASE-POLICY-FINAL-GO-NO-GO-GOVERNANCE-RECORD",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(kind),
            HashPart::Json(record),
        ],
        32,
    )
}
