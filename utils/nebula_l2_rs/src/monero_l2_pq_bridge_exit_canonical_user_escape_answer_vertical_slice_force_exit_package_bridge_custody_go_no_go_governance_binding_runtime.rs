use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalUserEscapeAnswerVerticalSliceForceExitPackageBridgeCustodyGoNoGoGovernanceBindingRuntimeResult<
    T,
> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_ANSWER_VERTICAL_SLICE_FORCE_EXIT_PACKAGE_BRIDGE_CUSTODY_GO_NO_GO_GOVERNANCE_BINDING_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-canonical-user-escape-answer-vertical-slice-force-exit-package-bridge-custody-go-no-go-governance-binding-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_ANSWER_VERTICAL_SLICE_FORCE_EXIT_PACKAGE_BRIDGE_CUSTODY_GO_NO_GO_GOVERNANCE_BINDING_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const GOVERNANCE_BINDING_SUITE: &str =
    "monero-l2-pq-force-exit-package-bridge-custody-go-no-go-governance-binding-v1";
pub const DEFAULT_MIN_GOVERNANCE_SIGNERS: u64 = 5;
pub const DEFAULT_MIN_CUSTODY_SIGNERS: u64 = 4;
pub const DEFAULT_MIN_MONERO_OBSERVERS: u64 = 3;
pub const DEFAULT_MIN_RESERVE_HANDOFFS: u64 = 2;
pub const DEFAULT_MIN_OPERATOR_ACKS: u64 = 1;
pub const DEFAULT_MIN_WALLET_NOTICE_ACKS: u64 = 3;
pub const DEFAULT_CHALLENGE_WINDOW_BLOCKS: u64 = 720;
pub const DEFAULT_REQUIRED_CONFIRMATIONS: u64 = 18;
pub const DEFAULT_MAX_OBSERVATION_LAG: u64 = 12;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub governance_binding_suite: String,
    pub min_governance_signers: u64,
    pub min_custody_signers: u64,
    pub min_monero_observers: u64,
    pub min_reserve_handoffs: u64,
    pub min_operator_acknowledgements: u64,
    pub min_wallet_notice_acknowledgements: u64,
    pub challenge_window_blocks: u64,
    pub required_confirmations: u64,
    pub max_observation_lag: u64,
    pub require_custody_enforcement_root: bool,
    pub require_circuit_breaker_root: bool,
    pub require_signer_custody_quorum_root: bool,
    pub require_monero_release_observation_root: bool,
    pub require_reserve_handoff_root: bool,
    pub require_challenge_window_root: bool,
    pub require_operator_acknowledgement: bool,
    pub require_wallet_public_hold_notices: bool,
    pub require_zero_public_holds: bool,
    pub require_governance_binding_root: bool,
    pub fail_closed_on_missing_root: bool,
    pub fail_closed_on_any_hold: bool,
    pub fail_closed_on_counter_mismatch: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            governance_binding_suite: GOVERNANCE_BINDING_SUITE.to_string(),
            min_governance_signers: DEFAULT_MIN_GOVERNANCE_SIGNERS,
            min_custody_signers: DEFAULT_MIN_CUSTODY_SIGNERS,
            min_monero_observers: DEFAULT_MIN_MONERO_OBSERVERS,
            min_reserve_handoffs: DEFAULT_MIN_RESERVE_HANDOFFS,
            min_operator_acknowledgements: DEFAULT_MIN_OPERATOR_ACKS,
            min_wallet_notice_acknowledgements: DEFAULT_MIN_WALLET_NOTICE_ACKS,
            challenge_window_blocks: DEFAULT_CHALLENGE_WINDOW_BLOCKS,
            required_confirmations: DEFAULT_REQUIRED_CONFIRMATIONS,
            max_observation_lag: DEFAULT_MAX_OBSERVATION_LAG,
            require_custody_enforcement_root: true,
            require_circuit_breaker_root: true,
            require_signer_custody_quorum_root: true,
            require_monero_release_observation_root: true,
            require_reserve_handoff_root: true,
            require_challenge_window_root: true,
            require_operator_acknowledgement: true,
            require_wallet_public_hold_notices: true,
            require_zero_public_holds: true,
            require_governance_binding_root: true,
            fail_closed_on_missing_root: true,
            fail_closed_on_any_hold: true,
            fail_closed_on_counter_mismatch: true,
        }
    }
}

impl Config {
    pub fn devnet() -> Self {
        Self::default()
    }

    pub fn required_root_count(&self) -> u64 {
        [
            self.require_custody_enforcement_root,
            self.require_circuit_breaker_root,
            self.require_signer_custody_quorum_root,
            self.require_monero_release_observation_root,
            self.require_reserve_handoff_root,
            self.require_challenge_window_root,
            self.require_governance_binding_root,
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
            "min_governance_signers": self.min_governance_signers,
            "min_custody_signers": self.min_custody_signers,
            "min_monero_observers": self.min_monero_observers,
            "min_reserve_handoffs": self.min_reserve_handoffs,
            "min_operator_acknowledgements": self.min_operator_acknowledgements,
            "min_wallet_notice_acknowledgements": self.min_wallet_notice_acknowledgements,
            "challenge_window_blocks": self.challenge_window_blocks,
            "required_confirmations": self.required_confirmations,
            "max_observation_lag": self.max_observation_lag,
            "required_root_count": self.required_root_count(),
            "require_custody_enforcement_root": self.require_custody_enforcement_root,
            "require_circuit_breaker_root": self.require_circuit_breaker_root,
            "require_signer_custody_quorum_root": self.require_signer_custody_quorum_root,
            "require_monero_release_observation_root": self.require_monero_release_observation_root,
            "require_reserve_handoff_root": self.require_reserve_handoff_root,
            "require_challenge_window_root": self.require_challenge_window_root,
            "require_operator_acknowledgement": self.require_operator_acknowledgement,
            "require_wallet_public_hold_notices": self.require_wallet_public_hold_notices,
            "require_zero_public_holds": self.require_zero_public_holds,
            "require_governance_binding_root": self.require_governance_binding_root,
            "fail_closed_on_missing_root": self.fail_closed_on_missing_root,
            "fail_closed_on_any_hold": self.fail_closed_on_any_hold,
            "fail_closed_on_counter_mismatch": self.fail_closed_on_counter_mismatch,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GovernanceDecision {
    Go,
    NoGo,
    FailClosed,
}

impl GovernanceDecision {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Go => "go",
            Self::NoGo => "no_go",
            Self::FailClosed => "fail_closed",
        }
    }

    pub fn permits_release(self) -> bool {
        matches!(self, Self::Go)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceStatus {
    Accepted,
    Missing,
    Held,
    Rejected,
    Stale,
}

impl EvidenceStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Missing => "missing",
            Self::Held => "held",
            Self::Rejected => "rejected",
            Self::Stale => "stale",
        }
    }

    pub fn is_accepted(self) -> bool {
        matches!(self, Self::Accepted)
    }

    pub fn is_fail_closed(self) -> bool {
        matches!(
            self,
            Self::Missing | Self::Held | Self::Rejected | Self::Stale
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RootKind {
    CustodyEnforcement,
    CircuitBreaker,
    SignerCustodyQuorum,
    MoneroReleaseObservation,
    ReserveHandoff,
    ChallengeWindow,
    GovernanceBinding,
}

impl RootKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CustodyEnforcement => "custody_enforcement",
            Self::CircuitBreaker => "circuit_breaker",
            Self::SignerCustodyQuorum => "signer_custody_quorum",
            Self::MoneroReleaseObservation => "monero_release_observation",
            Self::ReserveHandoff => "reserve_handoff",
            Self::ChallengeWindow => "challenge_window",
            Self::GovernanceBinding => "governance_binding",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NoticeKind {
    OperatorAcknowledgement,
    WalletPublicHold,
    WalletReleaseClearance,
    GovernanceVote,
}

impl NoticeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::OperatorAcknowledgement => "operator_acknowledgement",
            Self::WalletPublicHold => "wallet_public_hold",
            Self::WalletReleaseClearance => "wallet_release_clearance",
            Self::GovernanceVote => "governance_vote",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HoldSeverity {
    None,
    Informational,
    Blocking,
    Emergency,
}

impl HoldSeverity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Informational => "informational",
            Self::Blocking => "blocking",
            Self::Emergency => "emergency",
        }
    }

    pub fn blocks_release(self) -> bool {
        matches!(self, Self::Blocking | Self::Emergency)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RequiredRoot {
    pub root_id: String,
    pub kind: RootKind,
    pub source_runtime: String,
    pub source_state_root: String,
    pub release_id: String,
    pub manifest_root: String,
    pub observed_height: u64,
    pub accepted_height: u64,
    pub status: EvidenceStatus,
    pub hold_reason: String,
}

impl RequiredRoot {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        kind: RootKind,
        source_runtime: &str,
        source_state_root: &str,
        release_id: &str,
        manifest_root: &str,
        observed_height: u64,
        accepted_height: u64,
        status: EvidenceStatus,
        hold_reason: &str,
    ) -> Self {
        let root_id = deterministic_id(
            "required-root",
            &[
                kind.as_str(),
                source_runtime,
                source_state_root,
                release_id,
                manifest_root,
            ],
        );
        Self {
            root_id,
            kind,
            source_runtime: source_runtime.to_string(),
            source_state_root: source_state_root.to_string(),
            release_id: release_id.to_string(),
            manifest_root: manifest_root.to_string(),
            observed_height,
            accepted_height,
            status,
            hold_reason: hold_reason.to_string(),
        }
    }

    pub fn is_live_accepted(&self, config: &Config) -> bool {
        self.status.is_accepted()
            && self.accepted_height >= self.observed_height
            && self.accepted_height.saturating_sub(self.observed_height)
                <= config.max_observation_lag
    }

    pub fn public_record(&self) -> Value {
        json!({
            "root_id": self.root_id,
            "kind": self.kind.as_str(),
            "source_runtime": self.source_runtime,
            "source_state_root": self.source_state_root,
            "release_id": self.release_id,
            "manifest_root": self.manifest_root,
            "observed_height": self.observed_height,
            "accepted_height": self.accepted_height,
            "status": self.status.as_str(),
            "hold_reason": self.hold_reason,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("required-root", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GovernanceSigner {
    pub signer_id: String,
    pub signer_role: String,
    pub release_id: String,
    pub governance_epoch: u64,
    pub vote_root: String,
    pub custody_enforcement_root: String,
    pub signature_root: String,
    pub decision: GovernanceDecision,
}

impl GovernanceSigner {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        signer_label: &str,
        signer_role: &str,
        release_id: &str,
        governance_epoch: u64,
        vote_root: &str,
        custody_enforcement_root: &str,
        signature_root: &str,
        decision: GovernanceDecision,
    ) -> Self {
        let signer_id = deterministic_id(
            "governance-signer",
            &[
                signer_label,
                signer_role,
                release_id,
                vote_root,
                signature_root,
            ],
        );
        Self {
            signer_id,
            signer_role: signer_role.to_string(),
            release_id: release_id.to_string(),
            governance_epoch,
            vote_root: vote_root.to_string(),
            custody_enforcement_root: custody_enforcement_root.to_string(),
            signature_root: signature_root.to_string(),
            decision,
        }
    }

    pub fn votes_go(&self) -> bool {
        self.decision == GovernanceDecision::Go
    }

    pub fn public_record(&self) -> Value {
        json!({
            "signer_id": self.signer_id,
            "signer_role": self.signer_role,
            "release_id": self.release_id,
            "governance_epoch": self.governance_epoch,
            "vote_root": self.vote_root,
            "custody_enforcement_root": self.custody_enforcement_root,
            "signature_root": self.signature_root,
            "decision": self.decision.as_str(),
        })
    }

    pub fn state_root(&self) -> String {
        record_root("governance-signer", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OperatorAcknowledgement {
    pub acknowledgement_id: String,
    pub operator_id: String,
    pub release_id: String,
    pub custody_enforcement_root: String,
    pub circuit_breaker_root: String,
    pub operator_receipt_root: String,
    pub acknowledged_height: u64,
    pub status: EvidenceStatus,
}

impl OperatorAcknowledgement {
    pub fn new(
        operator_label: &str,
        release_id: &str,
        custody_enforcement_root: &str,
        circuit_breaker_root: &str,
        operator_receipt_root: &str,
        acknowledged_height: u64,
        status: EvidenceStatus,
    ) -> Self {
        let acknowledgement_id = deterministic_id(
            "operator-acknowledgement",
            &[
                operator_label,
                release_id,
                custody_enforcement_root,
                circuit_breaker_root,
                operator_receipt_root,
            ],
        );
        Self {
            acknowledgement_id,
            operator_id: operator_label.to_string(),
            release_id: release_id.to_string(),
            custody_enforcement_root: custody_enforcement_root.to_string(),
            circuit_breaker_root: circuit_breaker_root.to_string(),
            operator_receipt_root: operator_receipt_root.to_string(),
            acknowledged_height,
            status,
        }
    }

    pub fn is_accepted(&self) -> bool {
        self.status.is_accepted()
    }

    pub fn public_record(&self) -> Value {
        json!({
            "acknowledgement_id": self.acknowledgement_id,
            "operator_id": self.operator_id,
            "release_id": self.release_id,
            "custody_enforcement_root": self.custody_enforcement_root,
            "circuit_breaker_root": self.circuit_breaker_root,
            "operator_receipt_root": self.operator_receipt_root,
            "acknowledged_height": self.acknowledged_height,
            "status": self.status.as_str(),
        })
    }

    pub fn state_root(&self) -> String {
        record_root("operator-acknowledgement", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WalletPublicHoldNotice {
    pub notice_id: String,
    pub notice_kind: NoticeKind,
    pub wallet_group_id: String,
    pub release_id: String,
    pub public_hold_root: String,
    pub public_notice_root: String,
    pub custody_release_root: String,
    pub acknowledged_wallets: u64,
    pub held_wallets: u64,
    pub severity: HoldSeverity,
    pub status: EvidenceStatus,
}

impl WalletPublicHoldNotice {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        notice_kind: NoticeKind,
        wallet_group_label: &str,
        release_id: &str,
        public_hold_root: &str,
        public_notice_root: &str,
        custody_release_root: &str,
        acknowledged_wallets: u64,
        held_wallets: u64,
        severity: HoldSeverity,
        status: EvidenceStatus,
    ) -> Self {
        let notice_id = deterministic_id(
            "wallet-public-hold-notice",
            &[
                notice_kind.as_str(),
                wallet_group_label,
                release_id,
                public_hold_root,
                public_notice_root,
            ],
        );
        Self {
            notice_id,
            notice_kind,
            wallet_group_id: wallet_group_label.to_string(),
            release_id: release_id.to_string(),
            public_hold_root: public_hold_root.to_string(),
            public_notice_root: public_notice_root.to_string(),
            custody_release_root: custody_release_root.to_string(),
            acknowledged_wallets,
            held_wallets,
            severity,
            status,
        }
    }

    pub fn blocks_release(&self) -> bool {
        self.severity.blocks_release() || self.status.is_fail_closed() || self.held_wallets > 0
    }

    pub fn public_record(&self) -> Value {
        json!({
            "notice_id": self.notice_id,
            "notice_kind": self.notice_kind.as_str(),
            "wallet_group_id": self.wallet_group_id,
            "release_id": self.release_id,
            "public_hold_root": self.public_hold_root,
            "public_notice_root": self.public_notice_root,
            "custody_release_root": self.custody_release_root,
            "acknowledged_wallets": self.acknowledged_wallets,
            "held_wallets": self.held_wallets,
            "severity": self.severity.as_str(),
            "status": self.status.as_str(),
        })
    }

    pub fn state_root(&self) -> String {
        record_root("wallet-public-hold-notice", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GovernanceCounters {
    pub required_roots: u64,
    pub accepted_roots: u64,
    pub missing_roots: u64,
    pub stale_roots: u64,
    pub rejected_roots: u64,
    pub held_roots: u64,
    pub governance_signers: u64,
    pub go_votes: u64,
    pub no_go_votes: u64,
    pub fail_closed_votes: u64,
    pub operator_acknowledgements: u64,
    pub accepted_operator_acknowledgements: u64,
    pub wallet_notice_acknowledgements: u64,
    pub public_hold_notices: u64,
    pub blocking_public_holds: u64,
}

impl GovernanceCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "required_roots": self.required_roots,
            "accepted_roots": self.accepted_roots,
            "missing_roots": self.missing_roots,
            "stale_roots": self.stale_roots,
            "rejected_roots": self.rejected_roots,
            "held_roots": self.held_roots,
            "governance_signers": self.governance_signers,
            "go_votes": self.go_votes,
            "no_go_votes": self.no_go_votes,
            "fail_closed_votes": self.fail_closed_votes,
            "operator_acknowledgements": self.operator_acknowledgements,
            "accepted_operator_acknowledgements": self.accepted_operator_acknowledgements,
            "wallet_notice_acknowledgements": self.wallet_notice_acknowledgements,
            "public_hold_notices": self.public_hold_notices,
            "blocking_public_holds": self.blocking_public_holds,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("governance-counters", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GovernanceBindingReceipt {
    pub receipt_id: String,
    pub release_id: String,
    pub custody_enforcement_root: String,
    pub circuit_breaker_root: String,
    pub signer_custody_quorum_root: String,
    pub monero_release_observation_root: String,
    pub reserve_handoff_root: String,
    pub challenge_window_root: String,
    pub operator_acknowledgement_root: String,
    pub wallet_public_hold_notice_root: String,
    pub governance_signer_root: String,
    pub counters_root: String,
    pub decision: GovernanceDecision,
    pub fail_closed: bool,
    pub reason: String,
}

impl GovernanceBindingReceipt {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        release_id: &str,
        custody_enforcement_root: &str,
        circuit_breaker_root: &str,
        signer_custody_quorum_root: &str,
        monero_release_observation_root: &str,
        reserve_handoff_root: &str,
        challenge_window_root: &str,
        operator_acknowledgement_root: &str,
        wallet_public_hold_notice_root: &str,
        governance_signer_root: &str,
        counters_root: &str,
        decision: GovernanceDecision,
        fail_closed: bool,
        reason: &str,
    ) -> Self {
        let receipt_id = deterministic_id(
            "governance-binding-receipt",
            &[
                release_id,
                custody_enforcement_root,
                circuit_breaker_root,
                signer_custody_quorum_root,
                monero_release_observation_root,
                reserve_handoff_root,
                challenge_window_root,
                counters_root,
                decision.as_str(),
            ],
        );
        Self {
            receipt_id,
            release_id: release_id.to_string(),
            custody_enforcement_root: custody_enforcement_root.to_string(),
            circuit_breaker_root: circuit_breaker_root.to_string(),
            signer_custody_quorum_root: signer_custody_quorum_root.to_string(),
            monero_release_observation_root: monero_release_observation_root.to_string(),
            reserve_handoff_root: reserve_handoff_root.to_string(),
            challenge_window_root: challenge_window_root.to_string(),
            operator_acknowledgement_root: operator_acknowledgement_root.to_string(),
            wallet_public_hold_notice_root: wallet_public_hold_notice_root.to_string(),
            governance_signer_root: governance_signer_root.to_string(),
            counters_root: counters_root.to_string(),
            decision,
            fail_closed,
            reason: reason.to_string(),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "release_id": self.release_id,
            "custody_enforcement_root": self.custody_enforcement_root,
            "circuit_breaker_root": self.circuit_breaker_root,
            "signer_custody_quorum_root": self.signer_custody_quorum_root,
            "monero_release_observation_root": self.monero_release_observation_root,
            "reserve_handoff_root": self.reserve_handoff_root,
            "challenge_window_root": self.challenge_window_root,
            "operator_acknowledgement_root": self.operator_acknowledgement_root,
            "wallet_public_hold_notice_root": self.wallet_public_hold_notice_root,
            "governance_signer_root": self.governance_signer_root,
            "counters_root": self.counters_root,
            "decision": self.decision.as_str(),
            "fail_closed": self.fail_closed,
            "reason": self.reason,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("governance-binding-receipt", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub release_id: String,
    pub governance_epoch: u64,
    pub required_roots: Vec<RequiredRoot>,
    pub governance_signers: Vec<GovernanceSigner>,
    pub operator_acknowledgements: Vec<OperatorAcknowledgement>,
    pub wallet_public_hold_notices: Vec<WalletPublicHoldNotice>,
    pub receipt: GovernanceBindingReceipt,
}

impl State {
    pub fn new(
        config: Config,
        release_id: &str,
        governance_epoch: u64,
        required_roots: Vec<RequiredRoot>,
        governance_signers: Vec<GovernanceSigner>,
        operator_acknowledgements: Vec<OperatorAcknowledgement>,
        wallet_public_hold_notices: Vec<WalletPublicHoldNotice>,
    ) -> Result<Self> {
        let counters = Self::derive_counters(
            &config,
            &required_roots,
            &governance_signers,
            &operator_acknowledgements,
            &wallet_public_hold_notices,
        );
        let decision = Self::derive_decision(&config, &counters);
        let reason = Self::derive_reason(&config, &counters, decision);
        let receipt = GovernanceBindingReceipt::new(
            release_id,
            &kind_root(RootKind::CustodyEnforcement, &required_roots),
            &kind_root(RootKind::CircuitBreaker, &required_roots),
            &kind_root(RootKind::SignerCustodyQuorum, &required_roots),
            &kind_root(RootKind::MoneroReleaseObservation, &required_roots),
            &kind_root(RootKind::ReserveHandoff, &required_roots),
            &kind_root(RootKind::ChallengeWindow, &required_roots),
            &operator_acknowledgement_root(&operator_acknowledgements),
            &wallet_public_hold_notice_root(&wallet_public_hold_notices),
            &governance_signer_root(&governance_signers),
            &counters.state_root(),
            decision,
            decision == GovernanceDecision::FailClosed,
            &reason,
        );
        let state = Self {
            config,
            release_id: release_id.to_string(),
            governance_epoch,
            required_roots,
            governance_signers,
            operator_acknowledgements,
            wallet_public_hold_notices,
            receipt,
        };
        state.validate()?;
        Ok(state)
    }

    pub fn devnet() -> Self {
        let config = Config::devnet();
        let release_id = "force-exit-package-bridge-custody-governance-devnet-release";
        let required_roots = vec![
            RequiredRoot::new(
                RootKind::CustodyEnforcement,
                "bridge-custody-live-receipt-release-manifest-enforcement",
                "custody-enforcement-state-root-devnet",
                release_id,
                "custody-enforcement-manifest-root-devnet",
                42_000,
                42_006,
                EvidenceStatus::Accepted,
                "custody release manifest enforcement accepted",
            ),
            RequiredRoot::new(
                RootKind::CircuitBreaker,
                "release-policy-live-receipt-circuit-breaker",
                "circuit-breaker-state-root-devnet",
                release_id,
                "circuit-breaker-manifest-root-devnet",
                42_001,
                42_006,
                EvidenceStatus::Accepted,
                "circuit breaker clear",
            ),
            RequiredRoot::new(
                RootKind::SignerCustodyQuorum,
                "custody-wallet-watchtower-release-consensus",
                "signer-custody-quorum-state-root-devnet",
                release_id,
                "signer-custody-quorum-manifest-root-devnet",
                42_002,
                42_007,
                EvidenceStatus::Accepted,
                "custody signer quorum satisfied",
            ),
            RequiredRoot::new(
                RootKind::MoneroReleaseObservation,
                "settlement-observation",
                "monero-release-observation-state-root-devnet",
                release_id,
                "monero-release-observation-manifest-root-devnet",
                42_003,
                42_008,
                EvidenceStatus::Accepted,
                "monero release observed with required confirmations",
            ),
            RequiredRoot::new(
                RootKind::ReserveHandoff,
                "reserve-fallback-observation",
                "reserve-handoff-state-root-devnet",
                release_id,
                "reserve-handoff-manifest-root-devnet",
                42_004,
                42_009,
                EvidenceStatus::Accepted,
                "reserve handoff accepted",
            ),
            RequiredRoot::new(
                RootKind::ChallengeWindow,
                "challenge-window-monitor",
                "challenge-window-state-root-devnet",
                release_id,
                "challenge-window-manifest-root-devnet",
                42_005,
                42_010,
                EvidenceStatus::Accepted,
                "challenge window elapsed without live dispute",
            ),
            RequiredRoot::new(
                RootKind::GovernanceBinding,
                "go-no-go-governance-binding",
                "governance-binding-state-root-devnet",
                release_id,
                "governance-binding-manifest-root-devnet",
                42_006,
                42_011,
                EvidenceStatus::Accepted,
                "governance binding ready",
            ),
        ];
        let governance_signers = vec![
            GovernanceSigner::new(
                "governance-signer-alpha",
                "release-council",
                release_id,
                80,
                "vote-root-alpha",
                "custody-enforcement-manifest-root-devnet",
                "pq-signature-root-alpha",
                GovernanceDecision::Go,
            ),
            GovernanceSigner::new(
                "governance-signer-beta",
                "custody-council",
                release_id,
                80,
                "vote-root-beta",
                "custody-enforcement-manifest-root-devnet",
                "pq-signature-root-beta",
                GovernanceDecision::Go,
            ),
            GovernanceSigner::new(
                "governance-signer-gamma",
                "reserve-council",
                release_id,
                80,
                "vote-root-gamma",
                "custody-enforcement-manifest-root-devnet",
                "pq-signature-root-gamma",
                GovernanceDecision::Go,
            ),
            GovernanceSigner::new(
                "governance-signer-delta",
                "watchtower-council",
                release_id,
                80,
                "vote-root-delta",
                "custody-enforcement-manifest-root-devnet",
                "pq-signature-root-delta",
                GovernanceDecision::Go,
            ),
            GovernanceSigner::new(
                "governance-signer-epsilon",
                "wallet-council",
                release_id,
                80,
                "vote-root-epsilon",
                "custody-enforcement-manifest-root-devnet",
                "pq-signature-root-epsilon",
                GovernanceDecision::Go,
            ),
        ];
        let operator_acknowledgements = vec![OperatorAcknowledgement::new(
            "force-exit-operator-primary",
            release_id,
            "custody-enforcement-manifest-root-devnet",
            "circuit-breaker-manifest-root-devnet",
            "operator-acknowledgement-root-devnet",
            42_012,
            EvidenceStatus::Accepted,
        )];
        let wallet_public_hold_notices = vec![
            WalletPublicHoldNotice::new(
                NoticeKind::WalletReleaseClearance,
                "wallet-cohort-a",
                release_id,
                "public-hold-root-a",
                "public-notice-root-a",
                "custody-release-root-a",
                24,
                0,
                HoldSeverity::None,
                EvidenceStatus::Accepted,
            ),
            WalletPublicHoldNotice::new(
                NoticeKind::WalletReleaseClearance,
                "wallet-cohort-b",
                release_id,
                "public-hold-root-b",
                "public-notice-root-b",
                "custody-release-root-b",
                18,
                0,
                HoldSeverity::None,
                EvidenceStatus::Accepted,
            ),
            WalletPublicHoldNotice::new(
                NoticeKind::WalletReleaseClearance,
                "wallet-cohort-c",
                release_id,
                "public-hold-root-c",
                "public-notice-root-c",
                "custody-release-root-c",
                21,
                0,
                HoldSeverity::None,
                EvidenceStatus::Accepted,
            ),
        ];
        match Self::new(
            config,
            release_id,
            80,
            required_roots,
            governance_signers,
            operator_acknowledgements,
            wallet_public_hold_notices,
        ) {
            Ok(state) => state,
            Err(reason) => fail_closed_devnet(reason),
        }
    }

    pub fn counters(&self) -> GovernanceCounters {
        Self::derive_counters(
            &self.config,
            &self.required_roots,
            &self.governance_signers,
            &self.operator_acknowledgements,
            &self.wallet_public_hold_notices,
        )
    }

    pub fn validate(&self) -> Result<()> {
        if self.config.chain_id != CHAIN_ID {
            return Err("chain id mismatch".to_string());
        }
        if self.config.protocol_version != PROTOCOL_VERSION {
            return Err("protocol version mismatch".to_string());
        }
        if self.release_id.is_empty() {
            return Err("release id is empty".to_string());
        }
        if self.receipt.release_id != self.release_id {
            return Err("receipt release id mismatch".to_string());
        }
        let counters = self.counters();
        if self.config.fail_closed_on_counter_mismatch
            && self.receipt.counters_root != counters.state_root()
        {
            return Err("governance counter root mismatch".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        let counters = self.counters();
        json!({
            "config": self.config.public_record(),
            "release_id": self.release_id,
            "governance_epoch": self.governance_epoch,
            "required_roots": self.required_roots.iter().map(RequiredRoot::public_record).collect::<Vec<_>>(),
            "governance_signers": self.governance_signers.iter().map(GovernanceSigner::public_record).collect::<Vec<_>>(),
            "operator_acknowledgements": self.operator_acknowledgements.iter().map(OperatorAcknowledgement::public_record).collect::<Vec<_>>(),
            "wallet_public_hold_notices": self.wallet_public_hold_notices.iter().map(WalletPublicHoldNotice::public_record).collect::<Vec<_>>(),
            "counters": counters.public_record(),
            "receipt": self.receipt.public_record(),
            "state_root": self.state_root(),
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "MONERO-L2-PQ-BRIDGE-CUSTODY-GO-NO-GO-GOVERNANCE-BINDING-STATE",
            &[
                HashPart::Json(&self.config.public_record()),
                HashPart::Str(&self.release_id),
                HashPart::U64(self.governance_epoch),
                HashPart::Str(&required_root_set_root(&self.required_roots)),
                HashPart::Str(&governance_signer_root(&self.governance_signers)),
                HashPart::Str(&operator_acknowledgement_root(
                    &self.operator_acknowledgements,
                )),
                HashPart::Str(&wallet_public_hold_notice_root(
                    &self.wallet_public_hold_notices,
                )),
                HashPart::Str(&self.receipt.state_root()),
            ],
            32,
        )
    }

    fn derive_counters(
        config: &Config,
        required_roots: &[RequiredRoot],
        governance_signers: &[GovernanceSigner],
        operator_acknowledgements: &[OperatorAcknowledgement],
        wallet_public_hold_notices: &[WalletPublicHoldNotice],
    ) -> GovernanceCounters {
        let required_root_kinds = config.required_root_count();
        let accepted_roots = required_roots
            .iter()
            .filter(|root| root.is_live_accepted(config))
            .count() as u64;
        let missing_roots = required_root_kinds.saturating_sub(required_roots.len() as u64)
            + required_roots
                .iter()
                .filter(|root| root.status == EvidenceStatus::Missing)
                .count() as u64;
        let stale_roots = required_roots
            .iter()
            .filter(|root| root.status == EvidenceStatus::Stale)
            .count() as u64;
        let rejected_roots = required_roots
            .iter()
            .filter(|root| root.status == EvidenceStatus::Rejected)
            .count() as u64;
        let held_roots = required_roots
            .iter()
            .filter(|root| root.status == EvidenceStatus::Held)
            .count() as u64;
        let go_votes = governance_signers
            .iter()
            .filter(|signer| signer.decision == GovernanceDecision::Go)
            .count() as u64;
        let no_go_votes = governance_signers
            .iter()
            .filter(|signer| signer.decision == GovernanceDecision::NoGo)
            .count() as u64;
        let fail_closed_votes = governance_signers
            .iter()
            .filter(|signer| signer.decision == GovernanceDecision::FailClosed)
            .count() as u64;
        let accepted_operator_acknowledgements = operator_acknowledgements
            .iter()
            .filter(|ack| ack.is_accepted())
            .count() as u64;
        let wallet_notice_acknowledgements = wallet_public_hold_notices
            .iter()
            .filter(|notice| notice.status.is_accepted())
            .count() as u64;
        let blocking_public_holds = wallet_public_hold_notices
            .iter()
            .filter(|notice| notice.blocks_release())
            .count() as u64;
        GovernanceCounters {
            required_roots: required_root_kinds,
            accepted_roots,
            missing_roots,
            stale_roots,
            rejected_roots,
            held_roots,
            governance_signers: governance_signers.len() as u64,
            go_votes,
            no_go_votes,
            fail_closed_votes,
            operator_acknowledgements: operator_acknowledgements.len() as u64,
            accepted_operator_acknowledgements,
            wallet_notice_acknowledgements,
            public_hold_notices: wallet_public_hold_notices.len() as u64,
            blocking_public_holds,
        }
    }

    fn derive_decision(config: &Config, counters: &GovernanceCounters) -> GovernanceDecision {
        let missing_root_failure = config.fail_closed_on_missing_root && counters.missing_roots > 0;
        let held_root_failure = config.fail_closed_on_any_hold && counters.held_roots > 0;
        let stale_or_rejected_failure = counters.stale_roots > 0 || counters.rejected_roots > 0;
        let blocking_public_hold_failure =
            config.fail_closed_on_any_hold && counters.blocking_public_holds > 0;
        let operator_failure = config.require_operator_acknowledgement
            && counters.accepted_operator_acknowledgements < config.min_operator_acknowledgements;
        let wallet_notice_failure = config.require_wallet_public_hold_notices
            && counters.wallet_notice_acknowledgements < config.min_wallet_notice_acknowledgements;
        if missing_root_failure
            || held_root_failure
            || stale_or_rejected_failure
            || blocking_public_hold_failure
            || operator_failure
            || wallet_notice_failure
            || counters.fail_closed_votes > 0
        {
            return GovernanceDecision::FailClosed;
        }
        if counters.accepted_roots < counters.required_roots
            || counters.go_votes < config.min_governance_signers
            || counters.no_go_votes > 0
        {
            return GovernanceDecision::NoGo;
        }
        GovernanceDecision::Go
    }

    fn derive_reason(
        config: &Config,
        counters: &GovernanceCounters,
        decision: GovernanceDecision,
    ) -> String {
        if decision == GovernanceDecision::Go {
            return "all custody, circuit-breaker, quorum, monero, reserve, challenge-window, operator, wallet, and governance roots accepted".to_string();
        }
        if config.fail_closed_on_missing_root && counters.missing_roots > 0 {
            return "fail closed because one or more required roots are missing".to_string();
        }
        if counters.stale_roots > 0 || counters.rejected_roots > 0 {
            return "fail closed because one or more required roots are stale or rejected"
                .to_string();
        }
        if config.fail_closed_on_any_hold
            && (counters.held_roots > 0 || counters.blocking_public_holds > 0)
        {
            return "fail closed because a custody or wallet public hold remains active"
                .to_string();
        }
        if config.require_operator_acknowledgement
            && counters.accepted_operator_acknowledgements < config.min_operator_acknowledgements
        {
            return "fail closed because operator acknowledgement quorum is missing".to_string();
        }
        if config.require_wallet_public_hold_notices
            && counters.wallet_notice_acknowledgements < config.min_wallet_notice_acknowledgements
        {
            return "fail closed because wallet public hold notices are incomplete".to_string();
        }
        if counters.go_votes < config.min_governance_signers {
            return "no-go because governance go vote quorum is incomplete".to_string();
        }
        "no-go because final release governance did not satisfy binding policy".to_string()
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

pub fn record_root(label: &str, record: &Value) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-CUSTODY-GO-NO-GO-GOVERNANCE-BINDING-RECORD",
        &[HashPart::Str(label), HashPart::Json(record)],
        32,
    )
}

pub fn deterministic_id(label: &str, parts: &[&str]) -> String {
    let mut hash_parts = Vec::with_capacity(parts.len() + 1);
    hash_parts.push(HashPart::Str(label));
    for part in parts {
        hash_parts.push(HashPart::Str(part));
    }
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-CUSTODY-GO-NO-GO-GOVERNANCE-BINDING-ID",
        &hash_parts,
        16,
    )
}

pub fn required_root_set_root(roots: &[RequiredRoot]) -> String {
    merkle_root(
        "MONERO-L2-PQ-BRIDGE-CUSTODY-GO-NO-GO-REQUIRED-ROOTS",
        roots
            .iter()
            .map(|root| Value::String(root.state_root()))
            .collect::<Vec<_>>()
            .as_slice(),
    )
}

pub fn kind_root(kind: RootKind, roots: &[RequiredRoot]) -> String {
    merkle_root(
        "MONERO-L2-PQ-BRIDGE-CUSTODY-GO-NO-GO-ROOT-KIND",
        roots
            .iter()
            .filter(|root| root.kind == kind)
            .map(|root| Value::String(root.state_root()))
            .collect::<Vec<_>>()
            .as_slice(),
    )
}

pub fn governance_signer_root(signers: &[GovernanceSigner]) -> String {
    merkle_root(
        "MONERO-L2-PQ-BRIDGE-CUSTODY-GO-NO-GO-GOVERNANCE-SIGNERS",
        signers
            .iter()
            .map(|signer| Value::String(signer.state_root()))
            .collect::<Vec<_>>()
            .as_slice(),
    )
}

pub fn operator_acknowledgement_root(acks: &[OperatorAcknowledgement]) -> String {
    merkle_root(
        "MONERO-L2-PQ-BRIDGE-CUSTODY-GO-NO-GO-OPERATOR-ACKNOWLEDGEMENTS",
        acks.iter()
            .map(|ack| Value::String(ack.state_root()))
            .collect::<Vec<_>>()
            .as_slice(),
    )
}

pub fn wallet_public_hold_notice_root(notices: &[WalletPublicHoldNotice]) -> String {
    merkle_root(
        "MONERO-L2-PQ-BRIDGE-CUSTODY-GO-NO-GO-WALLET-PUBLIC-HOLD-NOTICES",
        notices
            .iter()
            .map(|notice| Value::String(notice.state_root()))
            .collect::<Vec<_>>()
            .as_slice(),
    )
}

fn fail_closed_devnet(reason: String) -> State {
    let config = Config::devnet();
    let release_id = "force-exit-package-bridge-custody-governance-devnet-fail-closed";
    let required_roots = vec![RequiredRoot::new(
        RootKind::CustodyEnforcement,
        "bridge-custody-governance-fail-closed-devnet",
        "missing-custody-enforcement-state-root",
        release_id,
        "missing-custody-enforcement-manifest-root",
        0,
        0,
        EvidenceStatus::Missing,
        &reason,
    )];
    let governance_signers = Vec::new();
    let operator_acknowledgements = Vec::new();
    let wallet_public_hold_notices = Vec::new();
    let counters = State::derive_counters(
        &config,
        &required_roots,
        &governance_signers,
        &operator_acknowledgements,
        &wallet_public_hold_notices,
    );
    let receipt = GovernanceBindingReceipt::new(
        release_id,
        &kind_root(RootKind::CustodyEnforcement, &required_roots),
        &kind_root(RootKind::CircuitBreaker, &required_roots),
        &kind_root(RootKind::SignerCustodyQuorum, &required_roots),
        &kind_root(RootKind::MoneroReleaseObservation, &required_roots),
        &kind_root(RootKind::ReserveHandoff, &required_roots),
        &kind_root(RootKind::ChallengeWindow, &required_roots),
        &operator_acknowledgement_root(&operator_acknowledgements),
        &wallet_public_hold_notice_root(&wallet_public_hold_notices),
        &governance_signer_root(&governance_signers),
        &counters.state_root(),
        GovernanceDecision::FailClosed,
        true,
        &reason,
    );
    State {
        config,
        release_id: release_id.to_string(),
        governance_epoch: 80,
        required_roots,
        governance_signers,
        operator_acknowledgements,
        wallet_public_hold_notices,
        receipt,
    }
}
