use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalUserEscapeAnswerVerticalSliceForceExitPackageCompileRuntimeGoNoGoGovernanceBindingRuntimeResult<
    T,
> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_ANSWER_VERTICAL_SLICE_FORCE_EXIT_PACKAGE_COMPILE_RUNTIME_GO_NO_GO_GOVERNANCE_BINDING_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-canonical-user-escape-answer-vertical-slice-force-exit-package-compile-runtime-go-no-go-governance-binding-runtime-v1";
pub const PROTOCOL_VERSION: &str = MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_ANSWER_VERTICAL_SLICE_FORCE_EXIT_PACKAGE_COMPILE_RUNTIME_GO_NO_GO_GOVERNANCE_BINDING_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const GOVERNANCE_BINDING_SUITE: &str =
    "monero-l2-pq-force-exit-package-compile-runtime-go-no-go-governance-binding-v1";
pub const DEFAULT_MIN_REVIEWER_APPROVALS: u64 = 4;
pub const DEFAULT_MIN_GOVERNANCE_APPROVALS: u64 = 5;
pub const DEFAULT_MIN_OPERATOR_ACKS: u64 = 2;
pub const DEFAULT_MIN_PUBLIC_HOLD_NOTICES: u64 = 2;
pub const DEFAULT_MAX_EVIDENCE_AGE_BLOCKS: u64 = 144;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub governance_binding_suite: String,
    pub min_reviewer_approvals: u64,
    pub min_governance_approvals: u64,
    pub min_operator_acks: u64,
    pub min_public_hold_notices: u64,
    pub max_evidence_age_blocks: u64,
    pub require_circuit_breaker_root: bool,
    pub require_compile_enforcement_root: bool,
    pub require_reviewer_quorum_root: bool,
    pub require_governance_quorum_root: bool,
    pub require_operator_acknowledgement: bool,
    pub require_wallet_hold_notice: bool,
    pub require_public_hold_notice: bool,
    pub require_manifest_lock: bool,
    pub reject_stale_evidence: bool,
    pub fail_closed_on_any_missing_root: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            governance_binding_suite: GOVERNANCE_BINDING_SUITE.to_string(),
            min_reviewer_approvals: DEFAULT_MIN_REVIEWER_APPROVALS,
            min_governance_approvals: DEFAULT_MIN_GOVERNANCE_APPROVALS,
            min_operator_acks: DEFAULT_MIN_OPERATOR_ACKS,
            min_public_hold_notices: DEFAULT_MIN_PUBLIC_HOLD_NOTICES,
            max_evidence_age_blocks: DEFAULT_MAX_EVIDENCE_AGE_BLOCKS,
            require_circuit_breaker_root: true,
            require_compile_enforcement_root: true,
            require_reviewer_quorum_root: true,
            require_governance_quorum_root: true,
            require_operator_acknowledgement: true,
            require_wallet_hold_notice: true,
            require_public_hold_notice: true,
            require_manifest_lock: true,
            reject_stale_evidence: true,
            fail_closed_on_any_missing_root: true,
        }
    }
}

impl Config {
    pub fn devnet() -> Self {
        Self::default()
    }

    pub fn required_root_count(&self) -> u64 {
        [
            self.require_circuit_breaker_root,
            self.require_compile_enforcement_root,
            self.require_reviewer_quorum_root,
            self.require_governance_quorum_root,
            self.require_wallet_hold_notice,
            self.require_public_hold_notice,
            self.require_manifest_lock,
        ]
        .iter()
        .filter(|required| **required)
        .count() as u64
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "governance_binding_suite": self.governance_binding_suite,
            "min_reviewer_approvals": self.min_reviewer_approvals,
            "min_governance_approvals": self.min_governance_approvals,
            "min_operator_acks": self.min_operator_acks,
            "min_public_hold_notices": self.min_public_hold_notices,
            "max_evidence_age_blocks": self.max_evidence_age_blocks,
            "required_root_count": self.required_root_count(),
            "require_circuit_breaker_root": self.require_circuit_breaker_root,
            "require_compile_enforcement_root": self.require_compile_enforcement_root,
            "require_reviewer_quorum_root": self.require_reviewer_quorum_root,
            "require_governance_quorum_root": self.require_governance_quorum_root,
            "require_operator_acknowledgement": self.require_operator_acknowledgement,
            "require_wallet_hold_notice": self.require_wallet_hold_notice,
            "require_public_hold_notice": self.require_public_hold_notice,
            "require_manifest_lock": self.require_manifest_lock,
            "reject_stale_evidence": self.reject_stale_evidence,
            "fail_closed_on_any_missing_root": self.fail_closed_on_any_missing_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BindingLane {
    CircuitBreaker,
    CompileEnforcement,
    ReviewerQuorum,
    GovernanceQuorum,
    OperatorAcknowledgement,
    WalletHoldNotice,
    PublicHoldNotice,
    ManifestLock,
}

impl BindingLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CircuitBreaker => "circuit_breaker",
            Self::CompileEnforcement => "compile_enforcement",
            Self::ReviewerQuorum => "reviewer_quorum",
            Self::GovernanceQuorum => "governance_quorum",
            Self::OperatorAcknowledgement => "operator_acknowledgement",
            Self::WalletHoldNotice => "wallet_hold_notice",
            Self::PublicHoldNotice => "public_hold_notice",
            Self::ManifestLock => "manifest_lock",
        }
    }

    pub fn ordered() -> &'static [Self] {
        &[
            Self::CircuitBreaker,
            Self::CompileEnforcement,
            Self::ReviewerQuorum,
            Self::GovernanceQuorum,
            Self::OperatorAcknowledgement,
            Self::WalletHoldNotice,
            Self::PublicHoldNotice,
            Self::ManifestLock,
        ]
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BindingStatus {
    Accepted,
    MissingRoot,
    MissingQuorum,
    MissingAcknowledgement,
    HoldNoticeActive,
    StaleEvidence,
    ManifestUnlocked,
    FailClosed,
}

impl BindingStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::MissingRoot => "missing_root",
            Self::MissingQuorum => "missing_quorum",
            Self::MissingAcknowledgement => "missing_acknowledgement",
            Self::HoldNoticeActive => "hold_notice_active",
            Self::StaleEvidence => "stale_evidence",
            Self::ManifestUnlocked => "manifest_unlocked",
            Self::FailClosed => "fail_closed",
        }
    }

    pub fn blocks_go(self) -> bool {
        !matches!(self, Self::Accepted)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GoNoGoDecision {
    Go,
    NoGo,
}

impl GoNoGoDecision {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Go => "go",
            Self::NoGo => "no_go",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HoldScope {
    Wallet,
    Public,
    Both,
}

impl HoldScope {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Wallet => "wallet",
            Self::Public => "public",
            Self::Both => "both",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RootBinding {
    pub binding_id: String,
    pub lane: BindingLane,
    pub source_runtime: String,
    pub source_state_root: String,
    pub evidence_root: String,
    pub observed_at_height: u64,
    pub current_height: u64,
    pub status: BindingStatus,
    pub required: bool,
    pub fail_closed: bool,
}

impl RootBinding {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        lane: BindingLane,
        source_runtime: &str,
        source_state_root: &str,
        evidence_root: &str,
        observed_at_height: u64,
        current_height: u64,
        required: bool,
        config: &Config,
    ) -> Self {
        let stale = config.reject_stale_evidence
            && current_height.saturating_sub(observed_at_height) > config.max_evidence_age_blocks;
        let status = if required && evidence_root.is_empty() {
            BindingStatus::MissingRoot
        } else if stale {
            BindingStatus::StaleEvidence
        } else {
            BindingStatus::Accepted
        };
        let fail_closed =
            status.blocks_go() && (required || config.fail_closed_on_any_missing_root);
        let binding_id = root_binding_id(
            lane,
            source_runtime,
            source_state_root,
            evidence_root,
            observed_at_height,
            current_height,
            required,
            status,
        );
        Self {
            binding_id,
            lane,
            source_runtime: source_runtime.to_string(),
            source_state_root: source_state_root.to_string(),
            evidence_root: evidence_root.to_string(),
            observed_at_height,
            current_height,
            status,
            required,
            fail_closed,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "binding_id": self.binding_id,
            "lane": self.lane.as_str(),
            "source_runtime": self.source_runtime,
            "source_state_root": self.source_state_root,
            "evidence_root": self.evidence_root,
            "observed_at_height": self.observed_at_height,
            "current_height": self.current_height,
            "status": self.status.as_str(),
            "required": self.required,
            "fail_closed": self.fail_closed,
            "binding_root": self.binding_root(),
        })
    }

    pub fn binding_root(&self) -> String {
        record_root("root-binding", &self.public_record_without_root())
    }

    fn public_record_without_root(&self) -> Value {
        json!({
            "binding_id": self.binding_id,
            "lane": self.lane.as_str(),
            "source_runtime": self.source_runtime,
            "source_state_root": self.source_state_root,
            "evidence_root": self.evidence_root,
            "observed_at_height": self.observed_at_height,
            "current_height": self.current_height,
            "status": self.status.as_str(),
            "required": self.required,
            "fail_closed": self.fail_closed,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct QuorumBinding {
    pub quorum_id: String,
    pub lane: BindingLane,
    pub quorum_root: String,
    pub participant_root: String,
    pub approval_count: u64,
    pub required_approvals: u64,
    pub observed_at_height: u64,
    pub current_height: u64,
    pub status: BindingStatus,
}

impl QuorumBinding {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        lane: BindingLane,
        quorum_root: &str,
        participant_root: &str,
        approval_count: u64,
        required_approvals: u64,
        observed_at_height: u64,
        current_height: u64,
        config: &Config,
    ) -> Self {
        let stale = config.reject_stale_evidence
            && current_height.saturating_sub(observed_at_height) > config.max_evidence_age_blocks;
        let status = if quorum_root.is_empty() || participant_root.is_empty() {
            BindingStatus::MissingRoot
        } else if approval_count < required_approvals {
            BindingStatus::MissingQuorum
        } else if stale {
            BindingStatus::StaleEvidence
        } else {
            BindingStatus::Accepted
        };
        let quorum_id = quorum_binding_id(
            lane,
            quorum_root,
            participant_root,
            approval_count,
            required_approvals,
            observed_at_height,
            current_height,
            status,
        );
        Self {
            quorum_id,
            lane,
            quorum_root: quorum_root.to_string(),
            participant_root: participant_root.to_string(),
            approval_count,
            required_approvals,
            observed_at_height,
            current_height,
            status,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "quorum_id": self.quorum_id,
            "lane": self.lane.as_str(),
            "quorum_root": self.quorum_root,
            "participant_root": self.participant_root,
            "approval_count": self.approval_count,
            "required_approvals": self.required_approvals,
            "observed_at_height": self.observed_at_height,
            "current_height": self.current_height,
            "status": self.status.as_str(),
            "quorum_binding_root": self.quorum_binding_root(),
        })
    }

    pub fn quorum_binding_root(&self) -> String {
        record_root("quorum-binding", &self.public_record_without_root())
    }

    fn public_record_without_root(&self) -> Value {
        json!({
            "quorum_id": self.quorum_id,
            "lane": self.lane.as_str(),
            "quorum_root": self.quorum_root,
            "participant_root": self.participant_root,
            "approval_count": self.approval_count,
            "required_approvals": self.required_approvals,
            "observed_at_height": self.observed_at_height,
            "current_height": self.current_height,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OperatorAcknowledgement {
    pub acknowledgement_id: String,
    pub operator_id: String,
    pub acknowledgement_root: String,
    pub manifest_root: String,
    pub signed_at_height: u64,
    pub current_height: u64,
    pub status: BindingStatus,
}

impl OperatorAcknowledgement {
    pub fn new(
        operator_id: &str,
        acknowledgement_root: &str,
        manifest_root: &str,
        signed_at_height: u64,
        current_height: u64,
        config: &Config,
    ) -> Self {
        let stale = config.reject_stale_evidence
            && current_height.saturating_sub(signed_at_height) > config.max_evidence_age_blocks;
        let status = if acknowledgement_root.is_empty() || manifest_root.is_empty() {
            BindingStatus::MissingAcknowledgement
        } else if stale {
            BindingStatus::StaleEvidence
        } else {
            BindingStatus::Accepted
        };
        let acknowledgement_id = operator_acknowledgement_id(
            operator_id,
            acknowledgement_root,
            manifest_root,
            signed_at_height,
            current_height,
            status,
        );
        Self {
            acknowledgement_id,
            operator_id: operator_id.to_string(),
            acknowledgement_root: acknowledgement_root.to_string(),
            manifest_root: manifest_root.to_string(),
            signed_at_height,
            current_height,
            status,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "acknowledgement_id": self.acknowledgement_id,
            "operator_id": self.operator_id,
            "acknowledgement_root": self.acknowledgement_root,
            "manifest_root": self.manifest_root,
            "signed_at_height": self.signed_at_height,
            "current_height": self.current_height,
            "status": self.status.as_str(),
            "acknowledgement_binding_root": self.acknowledgement_binding_root(),
        })
    }

    pub fn acknowledgement_binding_root(&self) -> String {
        record_root(
            "operator-acknowledgement",
            &self.public_record_without_root(),
        )
    }

    fn public_record_without_root(&self) -> Value {
        json!({
            "acknowledgement_id": self.acknowledgement_id,
            "operator_id": self.operator_id,
            "acknowledgement_root": self.acknowledgement_root,
            "manifest_root": self.manifest_root,
            "signed_at_height": self.signed_at_height,
            "current_height": self.current_height,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct HoldNotice {
    pub notice_id: String,
    pub scope: HoldScope,
    pub notice_root: String,
    pub wallet_root: String,
    pub public_channel_root: String,
    pub active: bool,
    pub issued_at_height: u64,
    pub status: BindingStatus,
}

impl HoldNotice {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        scope: HoldScope,
        notice_root: &str,
        wallet_root: &str,
        public_channel_root: &str,
        active: bool,
        issued_at_height: u64,
        config: &Config,
    ) -> Self {
        let wallet_missing = matches!(scope, HoldScope::Wallet | HoldScope::Both)
            && config.require_wallet_hold_notice
            && wallet_root.is_empty();
        let public_missing = matches!(scope, HoldScope::Public | HoldScope::Both)
            && config.require_public_hold_notice
            && public_channel_root.is_empty();
        let status = if notice_root.is_empty() || wallet_missing || public_missing {
            BindingStatus::MissingRoot
        } else if active {
            BindingStatus::HoldNoticeActive
        } else {
            BindingStatus::Accepted
        };
        let notice_id = hold_notice_id(
            scope,
            notice_root,
            wallet_root,
            public_channel_root,
            active,
            issued_at_height,
            status,
        );
        Self {
            notice_id,
            scope,
            notice_root: notice_root.to_string(),
            wallet_root: wallet_root.to_string(),
            public_channel_root: public_channel_root.to_string(),
            active,
            issued_at_height,
            status,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "notice_id": self.notice_id,
            "scope": self.scope.as_str(),
            "notice_root": self.notice_root,
            "wallet_root": self.wallet_root,
            "public_channel_root": self.public_channel_root,
            "active": self.active,
            "issued_at_height": self.issued_at_height,
            "status": self.status.as_str(),
            "notice_binding_root": self.notice_binding_root(),
        })
    }

    pub fn notice_binding_root(&self) -> String {
        record_root("hold-notice", &self.public_record_without_root())
    }

    fn public_record_without_root(&self) -> Value {
        json!({
            "notice_id": self.notice_id,
            "scope": self.scope.as_str(),
            "notice_root": self.notice_root,
            "wallet_root": self.wallet_root,
            "public_channel_root": self.public_channel_root,
            "active": self.active,
            "issued_at_height": self.issued_at_height,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct BindingCounters {
    pub root_bindings: u64,
    pub accepted_root_bindings: u64,
    pub quorum_bindings: u64,
    pub accepted_quorum_bindings: u64,
    pub operator_acknowledgements: u64,
    pub accepted_operator_acknowledgements: u64,
    pub hold_notices: u64,
    pub active_hold_notices: u64,
    pub fail_closed_blocks: u64,
}

impl BindingCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "root_bindings": self.root_bindings,
            "accepted_root_bindings": self.accepted_root_bindings,
            "quorum_bindings": self.quorum_bindings,
            "accepted_quorum_bindings": self.accepted_quorum_bindings,
            "operator_acknowledgements": self.operator_acknowledgements,
            "accepted_operator_acknowledgements": self.accepted_operator_acknowledgements,
            "hold_notices": self.hold_notices,
            "active_hold_notices": self.active_hold_notices,
            "fail_closed_blocks": self.fail_closed_blocks,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("counters", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GoNoGoRecord {
    pub record_id: String,
    pub decision: GoNoGoDecision,
    pub reason: String,
    pub config_root: String,
    pub circuit_breaker_root: String,
    pub compile_enforcement_root: String,
    pub reviewer_quorum_root: String,
    pub governance_quorum_root: String,
    pub operator_acknowledgement_root: String,
    pub wallet_hold_notice_root: String,
    pub public_hold_notice_root: String,
    pub manifest_lock_root: String,
    pub counters_root: String,
    pub fail_closed: bool,
    pub decided_at_height: u64,
}

impl GoNoGoRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "record_id": self.record_id,
            "decision": self.decision.as_str(),
            "reason": self.reason,
            "config_root": self.config_root,
            "circuit_breaker_root": self.circuit_breaker_root,
            "compile_enforcement_root": self.compile_enforcement_root,
            "reviewer_quorum_root": self.reviewer_quorum_root,
            "governance_quorum_root": self.governance_quorum_root,
            "operator_acknowledgement_root": self.operator_acknowledgement_root,
            "wallet_hold_notice_root": self.wallet_hold_notice_root,
            "public_hold_notice_root": self.public_hold_notice_root,
            "manifest_lock_root": self.manifest_lock_root,
            "counters_root": self.counters_root,
            "fail_closed": self.fail_closed,
            "decided_at_height": self.decided_at_height,
            "go_no_go_root": self.go_no_go_root(),
        })
    }

    pub fn go_no_go_root(&self) -> String {
        record_root("go-no-go-record", &self.public_record_without_root())
    }

    fn public_record_without_root(&self) -> Value {
        json!({
            "record_id": self.record_id,
            "decision": self.decision.as_str(),
            "reason": self.reason,
            "config_root": self.config_root,
            "circuit_breaker_root": self.circuit_breaker_root,
            "compile_enforcement_root": self.compile_enforcement_root,
            "reviewer_quorum_root": self.reviewer_quorum_root,
            "governance_quorum_root": self.governance_quorum_root,
            "operator_acknowledgement_root": self.operator_acknowledgement_root,
            "wallet_hold_notice_root": self.wallet_hold_notice_root,
            "public_hold_notice_root": self.public_hold_notice_root,
            "manifest_lock_root": self.manifest_lock_root,
            "counters_root": self.counters_root,
            "fail_closed": self.fail_closed,
            "decided_at_height": self.decided_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub root_bindings: Vec<RootBinding>,
    pub quorum_bindings: Vec<QuorumBinding>,
    pub operator_acknowledgements: Vec<OperatorAcknowledgement>,
    pub hold_notices: Vec<HoldNotice>,
    pub counters: BindingCounters,
    pub go_no_go: GoNoGoRecord,
}

impl State {
    pub fn new(
        config: Config,
        root_bindings: Vec<RootBinding>,
        quorum_bindings: Vec<QuorumBinding>,
        operator_acknowledgements: Vec<OperatorAcknowledgement>,
        hold_notices: Vec<HoldNotice>,
        decided_at_height: u64,
    ) -> Self {
        let counters = count_bindings(
            &root_bindings,
            &quorum_bindings,
            &operator_acknowledgements,
            &hold_notices,
        );
        let go_no_go = assemble_go_no_go(
            &config,
            &root_bindings,
            &quorum_bindings,
            &operator_acknowledgements,
            &hold_notices,
            &counters,
            decided_at_height,
        );
        Self {
            config,
            root_bindings,
            quorum_bindings,
            operator_acknowledgements,
            hold_notices,
            counters,
            go_no_go,
        }
    }

    pub fn devnet() -> Self {
        devnet()
    }

    pub fn public_record(&self) -> Value {
        json!({
            "config": self.config.public_record(),
            "root_bindings": self.root_bindings.iter().map(RootBinding::public_record).collect::<Vec<_>>(),
            "quorum_bindings": self.quorum_bindings.iter().map(QuorumBinding::public_record).collect::<Vec<_>>(),
            "operator_acknowledgements": self.operator_acknowledgements.iter().map(OperatorAcknowledgement::public_record).collect::<Vec<_>>(),
            "hold_notices": self.hold_notices.iter().map(HoldNotice::public_record).collect::<Vec<_>>(),
            "counters": self.counters.public_record(),
            "go_no_go": self.go_no_go.public_record(),
            "state_root": self.state_root(),
        })
    }

    pub fn state_root(&self) -> String {
        record_root("state", &self.public_record_without_state_root())
    }

    fn public_record_without_state_root(&self) -> Value {
        json!({
            "config_root": self.config.state_root(),
            "root_binding_root": merkle_root("MONERO-L2-PQ-GOV-BINDING-ROOT-BINDINGS", &self.root_bindings.iter().map(RootBinding::public_record).collect::<Vec<_>>()),
            "quorum_binding_root": merkle_root("MONERO-L2-PQ-GOV-BINDING-QUORUM-BINDINGS", &self.quorum_bindings.iter().map(QuorumBinding::public_record).collect::<Vec<_>>()),
            "operator_acknowledgement_root": merkle_root("MONERO-L2-PQ-GOV-BINDING-OPERATOR-ACKS", &self.operator_acknowledgements.iter().map(OperatorAcknowledgement::public_record).collect::<Vec<_>>()),
            "hold_notice_root": merkle_root("MONERO-L2-PQ-GOV-BINDING-HOLD-NOTICES", &self.hold_notices.iter().map(HoldNotice::public_record).collect::<Vec<_>>()),
            "counters_root": self.counters.state_root(),
            "go_no_go_root": self.go_no_go.go_no_go_root(),
        })
    }
}

pub fn public_record() -> Value {
    devnet().public_record()
}

pub fn state_root() -> String {
    devnet().state_root()
}

pub fn devnet() -> State {
    let config = Config::devnet();
    let current_height = 2_080;
    let compile_root = deterministic_root("compile-enforcement", "devnet-release-manifest");
    let breaker_root = deterministic_root("circuit-breaker", "armed-open-only-after-go");
    let reviewer_root = deterministic_root("reviewer-quorum", "four-of-six");
    let governance_root = deterministic_root("governance-quorum", "five-of-seven");
    let manifest_root = deterministic_root("manifest-lock", "force-exit-package-runtime-v1");
    let wallet_notice_root = deterministic_root("wallet-hold-notice", "no-active-wallet-hold");
    let public_notice_root = deterministic_root("public-hold-notice", "no-active-public-hold");
    let root_bindings = vec![
        RootBinding::new(
            BindingLane::CircuitBreaker,
            "release-policy-live-receipt-circuit-breaker-runtime",
            &breaker_root,
            &breaker_root,
            current_height - 8,
            current_height,
            config.require_circuit_breaker_root,
            &config,
        ),
        RootBinding::new(
            BindingLane::CompileEnforcement,
            "compile-runtime-live-receipt-release-manifest-enforcement-runtime",
            &compile_root,
            &compile_root,
            current_height - 6,
            current_height,
            config.require_compile_enforcement_root,
            &config,
        ),
        RootBinding::new(
            BindingLane::ManifestLock,
            "release-policy-manifest-binding-runtime",
            &manifest_root,
            &manifest_root,
            current_height - 5,
            current_height,
            config.require_manifest_lock,
            &config,
        ),
    ];
    let quorum_bindings = vec![
        QuorumBinding::new(
            BindingLane::ReviewerQuorum,
            &reviewer_root,
            &deterministic_root("reviewer-participants", "devnet-reviewers"),
            4,
            config.min_reviewer_approvals,
            current_height - 4,
            current_height,
            &config,
        ),
        QuorumBinding::new(
            BindingLane::GovernanceQuorum,
            &governance_root,
            &deterministic_root("governance-participants", "devnet-governance"),
            5,
            config.min_governance_approvals,
            current_height - 3,
            current_height,
            &config,
        ),
    ];
    let operator_acknowledgements = vec![
        OperatorAcknowledgement::new(
            "operator-alpha",
            &deterministic_root("operator-ack", "alpha"),
            &manifest_root,
            current_height - 2,
            current_height,
            &config,
        ),
        OperatorAcknowledgement::new(
            "operator-beta",
            &deterministic_root("operator-ack", "beta"),
            &manifest_root,
            current_height - 2,
            current_height,
            &config,
        ),
    ];
    let hold_notices = vec![
        HoldNotice::new(
            HoldScope::Wallet,
            &wallet_notice_root,
            &wallet_notice_root,
            "",
            false,
            current_height - 1,
            &config,
        ),
        HoldNotice::new(
            HoldScope::Public,
            &public_notice_root,
            "",
            &public_notice_root,
            false,
            current_height - 1,
            &config,
        ),
    ];
    State::new(
        config,
        root_bindings,
        quorum_bindings,
        operator_acknowledgements,
        hold_notices,
        current_height,
    )
}

fn count_bindings(
    root_bindings: &[RootBinding],
    quorum_bindings: &[QuorumBinding],
    operator_acknowledgements: &[OperatorAcknowledgement],
    hold_notices: &[HoldNotice],
) -> BindingCounters {
    let accepted_root_bindings = root_bindings
        .iter()
        .filter(|binding| binding.status == BindingStatus::Accepted)
        .count() as u64;
    let accepted_quorum_bindings = quorum_bindings
        .iter()
        .filter(|binding| binding.status == BindingStatus::Accepted)
        .count() as u64;
    let accepted_operator_acknowledgements = operator_acknowledgements
        .iter()
        .filter(|ack| ack.status == BindingStatus::Accepted)
        .count() as u64;
    let active_hold_notices = hold_notices.iter().filter(|notice| notice.active).count() as u64;
    let fail_closed_blocks = root_bindings
        .iter()
        .filter(|binding| binding.fail_closed)
        .count() as u64
        + quorum_bindings
            .iter()
            .filter(|binding| binding.status.blocks_go())
            .count() as u64
        + operator_acknowledgements
            .iter()
            .filter(|ack| ack.status.blocks_go())
            .count() as u64
        + hold_notices
            .iter()
            .filter(|notice| notice.status.blocks_go())
            .count() as u64;
    BindingCounters {
        root_bindings: root_bindings.len() as u64,
        accepted_root_bindings,
        quorum_bindings: quorum_bindings.len() as u64,
        accepted_quorum_bindings,
        operator_acknowledgements: operator_acknowledgements.len() as u64,
        accepted_operator_acknowledgements,
        hold_notices: hold_notices.len() as u64,
        active_hold_notices,
        fail_closed_blocks,
    }
}

fn assemble_go_no_go(
    config: &Config,
    root_bindings: &[RootBinding],
    quorum_bindings: &[QuorumBinding],
    operator_acknowledgements: &[OperatorAcknowledgement],
    hold_notices: &[HoldNotice],
    counters: &BindingCounters,
    decided_at_height: u64,
) -> GoNoGoRecord {
    let required_roots_satisfied = counters.accepted_root_bindings >= 3;
    let reviewer_ok = quorum_bindings.iter().any(|binding| {
        binding.lane == BindingLane::ReviewerQuorum && binding.status == BindingStatus::Accepted
    });
    let governance_ok = quorum_bindings.iter().any(|binding| {
        binding.lane == BindingLane::GovernanceQuorum && binding.status == BindingStatus::Accepted
    });
    let operator_ok = counters.accepted_operator_acknowledgements >= config.min_operator_acks
        || !config.require_operator_acknowledgement;
    let holds_clear = hold_notices
        .iter()
        .all(|notice| notice.status == BindingStatus::Accepted);
    let fail_closed = counters.fail_closed_blocks > 0
        || !required_roots_satisfied
        || !reviewer_ok
        || !governance_ok
        || !operator_ok
        || !holds_clear;
    let decision = if fail_closed {
        GoNoGoDecision::NoGo
    } else {
        GoNoGoDecision::Go
    };
    let reason = if fail_closed {
        "fail_closed_governance_binding_incomplete"
    } else {
        "all_compile_runtime_governance_bindings_satisfied"
    };
    let circuit_breaker_root = lane_root(root_bindings, BindingLane::CircuitBreaker);
    let compile_enforcement_root = lane_root(root_bindings, BindingLane::CompileEnforcement);
    let manifest_lock_root = lane_root(root_bindings, BindingLane::ManifestLock);
    let reviewer_quorum_root = quorum_lane_root(quorum_bindings, BindingLane::ReviewerQuorum);
    let governance_quorum_root = quorum_lane_root(quorum_bindings, BindingLane::GovernanceQuorum);
    let operator_acknowledgement_root = merkle_root(
        "MONERO-L2-PQ-GOV-BINDING-GO-NO-GO-OPERATOR-ACKS",
        &operator_acknowledgements
            .iter()
            .map(OperatorAcknowledgement::public_record)
            .collect::<Vec<_>>(),
    );
    let wallet_hold_notice_root = hold_scope_root(hold_notices, HoldScope::Wallet);
    let public_hold_notice_root = hold_scope_root(hold_notices, HoldScope::Public);
    let counters_root = counters.state_root();
    let config_root = config.state_root();
    let record_id = go_no_go_record_id(
        decision,
        &config_root,
        &circuit_breaker_root,
        &compile_enforcement_root,
        &reviewer_quorum_root,
        &governance_quorum_root,
        &operator_acknowledgement_root,
        &wallet_hold_notice_root,
        &public_hold_notice_root,
        &manifest_lock_root,
        &counters_root,
        fail_closed,
        decided_at_height,
    );
    GoNoGoRecord {
        record_id,
        decision,
        reason: reason.to_string(),
        config_root,
        circuit_breaker_root,
        compile_enforcement_root,
        reviewer_quorum_root,
        governance_quorum_root,
        operator_acknowledgement_root,
        wallet_hold_notice_root,
        public_hold_notice_root,
        manifest_lock_root,
        counters_root,
        fail_closed,
        decided_at_height,
    }
}

fn lane_root(root_bindings: &[RootBinding], lane: BindingLane) -> String {
    merkle_root(
        "MONERO-L2-PQ-GOV-BINDING-LANE-ROOT",
        &root_bindings
            .iter()
            .filter(|binding| binding.lane == lane)
            .map(RootBinding::public_record)
            .collect::<Vec<_>>(),
    )
}

fn quorum_lane_root(quorum_bindings: &[QuorumBinding], lane: BindingLane) -> String {
    merkle_root(
        "MONERO-L2-PQ-GOV-BINDING-QUORUM-LANE-ROOT",
        &quorum_bindings
            .iter()
            .filter(|binding| binding.lane == lane)
            .map(QuorumBinding::public_record)
            .collect::<Vec<_>>(),
    )
}

fn hold_scope_root(hold_notices: &[HoldNotice], scope: HoldScope) -> String {
    merkle_root(
        "MONERO-L2-PQ-GOV-BINDING-HOLD-SCOPE-ROOT",
        &hold_notices
            .iter()
            .filter(|notice| notice.scope == scope || notice.scope == HoldScope::Both)
            .map(HoldNotice::public_record)
            .collect::<Vec<_>>(),
    )
}

fn root_binding_id(
    lane: BindingLane,
    source_runtime: &str,
    source_state_root: &str,
    evidence_root: &str,
    observed_at_height: u64,
    current_height: u64,
    required: bool,
    status: BindingStatus,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-GOV-BINDING-ROOT-BINDING-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(lane.as_str()),
            HashPart::Str(source_runtime),
            HashPart::Str(source_state_root),
            HashPart::Str(evidence_root),
            HashPart::U64(observed_at_height),
            HashPart::U64(current_height),
            HashPart::Str(bool_str(required)),
            HashPart::Str(status.as_str()),
        ],
        32,
    )
}

fn quorum_binding_id(
    lane: BindingLane,
    quorum_root: &str,
    participant_root: &str,
    approval_count: u64,
    required_approvals: u64,
    observed_at_height: u64,
    current_height: u64,
    status: BindingStatus,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-GOV-BINDING-QUORUM-BINDING-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(lane.as_str()),
            HashPart::Str(quorum_root),
            HashPart::Str(participant_root),
            HashPart::U64(approval_count),
            HashPart::U64(required_approvals),
            HashPart::U64(observed_at_height),
            HashPart::U64(current_height),
            HashPart::Str(status.as_str()),
        ],
        32,
    )
}

fn operator_acknowledgement_id(
    operator_id: &str,
    acknowledgement_root: &str,
    manifest_root: &str,
    signed_at_height: u64,
    current_height: u64,
    status: BindingStatus,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-GOV-BINDING-OPERATOR-ACK-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(operator_id),
            HashPart::Str(acknowledgement_root),
            HashPart::Str(manifest_root),
            HashPart::U64(signed_at_height),
            HashPart::U64(current_height),
            HashPart::Str(status.as_str()),
        ],
        32,
    )
}

fn hold_notice_id(
    scope: HoldScope,
    notice_root: &str,
    wallet_root: &str,
    public_channel_root: &str,
    active: bool,
    issued_at_height: u64,
    status: BindingStatus,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-GOV-BINDING-HOLD-NOTICE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(scope.as_str()),
            HashPart::Str(notice_root),
            HashPart::Str(wallet_root),
            HashPart::Str(public_channel_root),
            HashPart::Str(bool_str(active)),
            HashPart::U64(issued_at_height),
            HashPart::Str(status.as_str()),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
fn go_no_go_record_id(
    decision: GoNoGoDecision,
    config_root: &str,
    circuit_breaker_root: &str,
    compile_enforcement_root: &str,
    reviewer_quorum_root: &str,
    governance_quorum_root: &str,
    operator_acknowledgement_root: &str,
    wallet_hold_notice_root: &str,
    public_hold_notice_root: &str,
    manifest_lock_root: &str,
    counters_root: &str,
    fail_closed: bool,
    decided_at_height: u64,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-GOV-BINDING-GO-NO-GO-RECORD-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(decision.as_str()),
            HashPart::Str(config_root),
            HashPart::Str(circuit_breaker_root),
            HashPart::Str(compile_enforcement_root),
            HashPart::Str(reviewer_quorum_root),
            HashPart::Str(governance_quorum_root),
            HashPart::Str(operator_acknowledgement_root),
            HashPart::Str(wallet_hold_notice_root),
            HashPart::Str(public_hold_notice_root),
            HashPart::Str(manifest_lock_root),
            HashPart::Str(counters_root),
            HashPart::Str(bool_str(fail_closed)),
            HashPart::U64(decided_at_height),
        ],
        32,
    )
}

fn deterministic_root(label: &str, value: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-GOV-BINDING-DETERMINISTIC-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
            HashPart::Str(value),
        ],
        32,
    )
}

fn record_root(label: &str, record: &Value) -> String {
    domain_hash(
        "MONERO-L2-PQ-GOV-BINDING-RECORD-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
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
