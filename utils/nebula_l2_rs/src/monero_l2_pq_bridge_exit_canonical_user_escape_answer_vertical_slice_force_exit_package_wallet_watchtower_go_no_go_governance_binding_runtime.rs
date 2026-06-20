use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalUserEscapeAnswerVerticalSliceForceExitPackageWalletWatchtowerGoNoGoGovernanceBindingRuntimeResult<
    T,
> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_ANSWER_VERTICAL_SLICE_FORCE_EXIT_PACKAGE_WALLET_WATCHTOWER_GO_NO_GO_GOVERNANCE_BINDING_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-canonical-user-escape-answer-vertical-slice-force-exit-package-wallet-watchtower-go-no-go-governance-binding-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_ANSWER_VERTICAL_SLICE_FORCE_EXIT_PACKAGE_WALLET_WATCHTOWER_GO_NO_GO_GOVERNANCE_BINDING_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const GOVERNANCE_BINDING_SUITE: &str =
    "monero-l2-pq-force-exit-package-wallet-watchtower-go-no-go-governance-binding-v1";
pub const DEFAULT_MIN_WALLET_RELEASE_MANIFESTS: u64 = 3;
pub const DEFAULT_MIN_WATCHTOWER_RELEASE_MANIFESTS: u64 = 4;
pub const DEFAULT_MIN_WATCHTOWER_QUORUM_MEMBERS: u64 = 5;
pub const DEFAULT_MIN_OPERATOR_ACKNOWLEDGEMENTS: u64 = 2;
pub const DEFAULT_MIN_WALLET_HOLD_NOTICES: u64 = 1;
pub const DEFAULT_MIN_PUBLIC_HOLD_NOTICES: u64 = 1;
pub const DEFAULT_MIN_RECOVERY_PATHS: u64 = 2;
pub const DEFAULT_MAX_CIRCUIT_BREAKER_INCIDENTS: u64 = 0;
pub const DEFAULT_MAX_TRANSCRIPT_GAPS: u64 = 0;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub governance_binding_suite: String,
    pub min_wallet_release_manifests: u64,
    pub min_watchtower_release_manifests: u64,
    pub min_watchtower_quorum_members: u64,
    pub min_operator_acknowledgements: u64,
    pub min_wallet_hold_notices: u64,
    pub min_public_hold_notices: u64,
    pub min_recovery_paths: u64,
    pub max_circuit_breaker_incidents: u64,
    pub max_transcript_gaps: u64,
    pub require_wallet_enforcement_root: bool,
    pub require_watchtower_enforcement_root: bool,
    pub require_circuit_breaker_root: bool,
    pub require_wallet_transcript_continuity_root: bool,
    pub require_watchtower_quorum_root: bool,
    pub require_recovery_root: bool,
    pub require_operator_acknowledgement: bool,
    pub require_wallet_hold_notice: bool,
    pub require_public_hold_notice: bool,
    pub require_zero_circuit_breakers: bool,
    pub require_zero_transcript_gaps: bool,
    pub fail_closed_on_missing_root: bool,
    pub fail_closed_on_any_hold: bool,
    pub hold_force_exit_until_governance_go: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            governance_binding_suite: GOVERNANCE_BINDING_SUITE.to_string(),
            min_wallet_release_manifests: DEFAULT_MIN_WALLET_RELEASE_MANIFESTS,
            min_watchtower_release_manifests: DEFAULT_MIN_WATCHTOWER_RELEASE_MANIFESTS,
            min_watchtower_quorum_members: DEFAULT_MIN_WATCHTOWER_QUORUM_MEMBERS,
            min_operator_acknowledgements: DEFAULT_MIN_OPERATOR_ACKNOWLEDGEMENTS,
            min_wallet_hold_notices: DEFAULT_MIN_WALLET_HOLD_NOTICES,
            min_public_hold_notices: DEFAULT_MIN_PUBLIC_HOLD_NOTICES,
            min_recovery_paths: DEFAULT_MIN_RECOVERY_PATHS,
            max_circuit_breaker_incidents: DEFAULT_MAX_CIRCUIT_BREAKER_INCIDENTS,
            max_transcript_gaps: DEFAULT_MAX_TRANSCRIPT_GAPS,
            require_wallet_enforcement_root: true,
            require_watchtower_enforcement_root: true,
            require_circuit_breaker_root: true,
            require_wallet_transcript_continuity_root: true,
            require_watchtower_quorum_root: true,
            require_recovery_root: true,
            require_operator_acknowledgement: true,
            require_wallet_hold_notice: true,
            require_public_hold_notice: true,
            require_zero_circuit_breakers: true,
            require_zero_transcript_gaps: true,
            fail_closed_on_missing_root: true,
            fail_closed_on_any_hold: true,
            hold_force_exit_until_governance_go: true,
        }
    }
}

impl Config {
    pub fn devnet() -> Self {
        Self::default()
    }

    pub fn public_record(&self) -> Value {
        json!(self)
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
}

impl GovernanceDecision {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Go => "go",
            Self::NoGo => "no_go",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FailClosedStatus {
    Clear,
    Engaged,
}

impl FailClosedStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Clear => "clear",
            Self::Engaged => "engaged",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BindingHoldReason {
    None,
    MissingWalletEnforcementRoot,
    MissingWatchtowerEnforcementRoot,
    CircuitBreakerEngaged,
    WalletTranscriptContinuityGap,
    WatchtowerQuorumMissing,
    RecoveryRootMissing,
    OperatorAcknowledgementMissing,
    WalletHoldNoticeMissing,
    PublicHoldNoticeMissing,
}

impl BindingHoldReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::MissingWalletEnforcementRoot => "missing_wallet_enforcement_root",
            Self::MissingWatchtowerEnforcementRoot => "missing_watchtower_enforcement_root",
            Self::CircuitBreakerEngaged => "circuit_breaker_engaged",
            Self::WalletTranscriptContinuityGap => "wallet_transcript_continuity_gap",
            Self::WatchtowerQuorumMissing => "watchtower_quorum_missing",
            Self::RecoveryRootMissing => "recovery_root_missing",
            Self::OperatorAcknowledgementMissing => "operator_acknowledgement_missing",
            Self::WalletHoldNoticeMissing => "wallet_hold_notice_missing",
            Self::PublicHoldNoticeMissing => "public_hold_notice_missing",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WalletReleaseManifestEnforcement {
    pub manifest_id: String,
    pub wallet_id: String,
    pub release_id: String,
    pub wallet_enforcement_root: String,
    pub release_manifest_root: String,
    pub transcript_continuity_root: String,
    pub hold_notice_root: String,
    pub release_epoch: u64,
    pub transcript_ordinal: u64,
    pub accepted: bool,
}

impl WalletReleaseManifestEnforcement {
    pub fn new(
        wallet_label: &str,
        release_id: &str,
        release_epoch: u64,
        transcript_ordinal: u64,
        accepted: bool,
    ) -> Self {
        let wallet_enforcement_root = sample_root("wallet-enforcement", wallet_label);
        let release_manifest_root = sample_root("wallet-release-manifest", wallet_label);
        let transcript_continuity_root = sample_root("wallet-transcript-continuity", wallet_label);
        let hold_notice_root = sample_root("wallet-hold-notice", wallet_label);
        Self {
            manifest_id: deterministic_id(
                "wallet-release-manifest-enforcement",
                &[wallet_label, release_id, &release_manifest_root],
            ),
            wallet_id: deterministic_id("wallet", &[wallet_label, release_id]),
            release_id: release_id.to_string(),
            wallet_enforcement_root,
            release_manifest_root,
            transcript_continuity_root,
            hold_notice_root,
            release_epoch,
            transcript_ordinal,
            accepted,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WatchtowerReleaseManifestEnforcement {
    pub enforcement_id: String,
    pub watchtower_id: String,
    pub release_id: String,
    pub watchtower_enforcement_root: String,
    pub replay_audit_root: String,
    pub quorum_member_root: String,
    pub public_hold_notice_root: String,
    pub observed_height: u64,
    pub accepted: bool,
}

impl WatchtowerReleaseManifestEnforcement {
    pub fn new(tower_label: &str, release_id: &str, observed_height: u64, accepted: bool) -> Self {
        let watchtower_enforcement_root = sample_root("watchtower-enforcement", tower_label);
        let replay_audit_root = sample_root("watchtower-replay-audit", tower_label);
        let quorum_member_root = sample_root("watchtower-quorum-member", tower_label);
        let public_hold_notice_root = sample_root("public-hold-notice", tower_label);
        Self {
            enforcement_id: deterministic_id(
                "watchtower-release-manifest-enforcement",
                &[tower_label, release_id, &watchtower_enforcement_root],
            ),
            watchtower_id: deterministic_id("watchtower", &[tower_label, release_id]),
            release_id: release_id.to_string(),
            watchtower_enforcement_root,
            replay_audit_root,
            quorum_member_root,
            public_hold_notice_root,
            observed_height,
            accepted,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CircuitBreakerObservation {
    pub breaker_id: String,
    pub release_id: String,
    pub breaker_root: String,
    pub incident_root: String,
    pub severity: String,
    pub opened_height: u64,
    pub closed_height: u64,
    pub engaged: bool,
}

impl CircuitBreakerObservation {
    pub fn cleared(label: &str, release_id: &str, height: u64) -> Self {
        let breaker_root = sample_root("circuit-breaker", label);
        Self {
            breaker_id: deterministic_id("circuit-breaker", &[label, release_id, &breaker_root]),
            release_id: release_id.to_string(),
            breaker_root,
            incident_root: sample_root("circuit-breaker-incident", "none"),
            severity: "none".to_string(),
            opened_height: height,
            closed_height: height,
            engaged: false,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WalletTranscriptContinuity {
    pub continuity_id: String,
    pub release_id: String,
    pub wallet_id: String,
    pub previous_transcript_root: String,
    pub current_transcript_root: String,
    pub continuity_root: String,
    pub gap_count: u64,
    pub verified: bool,
}

impl WalletTranscriptContinuity {
    pub fn verified(wallet_label: &str, release_id: &str, ordinal: u64) -> Self {
        let previous_transcript_root = sample_root("previous-wallet-transcript", wallet_label);
        let current_transcript_root = sample_root("current-wallet-transcript", wallet_label);
        let continuity_root = domain_hash(
            "MONERO-L2-PQ-WALLET-WATCHTOWER-GO-NO-GO-GOVERNANCE-TRANSCRIPT-CONTINUITY",
            &[
                HashPart::Str(&previous_transcript_root),
                HashPart::Str(&current_transcript_root),
                HashPart::U64(ordinal),
            ],
            32,
        );
        Self {
            continuity_id: deterministic_id(
                "wallet-transcript-continuity",
                &[wallet_label, release_id, &continuity_root],
            ),
            release_id: release_id.to_string(),
            wallet_id: deterministic_id("wallet", &[wallet_label, release_id]),
            previous_transcript_root,
            current_transcript_root,
            continuity_root,
            gap_count: 0,
            verified: true,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WatchtowerQuorumAttestation {
    pub quorum_id: String,
    pub release_id: String,
    pub quorum_root: String,
    pub member_set_root: String,
    pub signature_root: String,
    pub member_count: u64,
    pub threshold: u64,
    pub accepted: bool,
}

impl WatchtowerQuorumAttestation {
    pub fn accepted(label: &str, release_id: &str, member_count: u64, threshold: u64) -> Self {
        let member_set_root = sample_root("watchtower-quorum-member-set", label);
        let signature_root = sample_root("watchtower-quorum-signature", label);
        let quorum_root = domain_hash(
            "MONERO-L2-PQ-WALLET-WATCHTOWER-GO-NO-GO-GOVERNANCE-WATCHTOWER-QUORUM",
            &[
                HashPart::Str(&member_set_root),
                HashPart::Str(&signature_root),
                HashPart::U64(member_count),
                HashPart::U64(threshold),
            ],
            32,
        );
        Self {
            quorum_id: deterministic_id("watchtower-quorum", &[label, release_id, &quorum_root]),
            release_id: release_id.to_string(),
            quorum_root,
            member_set_root,
            signature_root,
            member_count,
            threshold,
            accepted: true,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RecoveryPathBinding {
    pub recovery_id: String,
    pub release_id: String,
    pub recovery_root: String,
    pub wallet_recovery_root: String,
    pub watchtower_recovery_root: String,
    pub operator_recovery_root: String,
    pub priority: u64,
    pub enabled: bool,
}

impl RecoveryPathBinding {
    pub fn enabled(label: &str, release_id: &str, priority: u64) -> Self {
        let wallet_recovery_root = sample_root("wallet-recovery", label);
        let watchtower_recovery_root = sample_root("watchtower-recovery", label);
        let operator_recovery_root = sample_root("operator-recovery", label);
        let recovery_root = domain_hash(
            "MONERO-L2-PQ-WALLET-WATCHTOWER-GO-NO-GO-GOVERNANCE-RECOVERY-PATH",
            &[
                HashPart::Str(&wallet_recovery_root),
                HashPart::Str(&watchtower_recovery_root),
                HashPart::Str(&operator_recovery_root),
                HashPart::U64(priority),
            ],
            32,
        );
        Self {
            recovery_id: deterministic_id("recovery-path", &[label, release_id, &recovery_root]),
            release_id: release_id.to_string(),
            recovery_root,
            wallet_recovery_root,
            watchtower_recovery_root,
            operator_recovery_root,
            priority,
            enabled: true,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OperatorAcknowledgement {
    pub acknowledgement_id: String,
    pub operator_id: String,
    pub release_id: String,
    pub acknowledgement_root: String,
    pub governance_packet_root: String,
    pub bound_release_manifest_root: String,
    pub acknowledged_height: u64,
    pub accepted: bool,
}

impl OperatorAcknowledgement {
    pub fn accepted(operator_label: &str, release_id: &str, height: u64) -> Self {
        let acknowledgement_root = sample_root("operator-acknowledgement", operator_label);
        let governance_packet_root = sample_root("operator-governance-packet", operator_label);
        let bound_release_manifest_root =
            sample_root("operator-bound-release-manifest", operator_label);
        Self {
            acknowledgement_id: deterministic_id(
                "operator-acknowledgement",
                &[operator_label, release_id, &acknowledgement_root],
            ),
            operator_id: deterministic_id("operator", &[operator_label, release_id]),
            release_id: release_id.to_string(),
            acknowledgement_root,
            governance_packet_root,
            bound_release_manifest_root,
            acknowledged_height: height,
            accepted: true,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct HoldNotice {
    pub notice_id: String,
    pub release_id: String,
    pub audience: String,
    pub notice_root: String,
    pub reason_root: String,
    pub published_height: u64,
    pub acknowledged: bool,
}

impl HoldNotice {
    pub fn acknowledged(audience: &str, release_id: &str, height: u64) -> Self {
        let notice_root = sample_root("hold-notice", audience);
        Self {
            notice_id: deterministic_id("hold-notice", &[audience, release_id, &notice_root]),
            release_id: release_id.to_string(),
            audience: audience.to_string(),
            notice_root,
            reason_root: sample_root("hold-notice-reason", "force-exit-governance"),
            published_height: height,
            acknowledged: true,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub wallet_enforcement_root: String,
    pub watchtower_enforcement_root: String,
    pub circuit_breaker_root: String,
    pub wallet_transcript_continuity_root: String,
    pub watchtower_quorum_root: String,
    pub recovery_root: String,
    pub operator_acknowledgement_root: String,
    pub wallet_hold_notice_root: String,
    pub public_hold_notice_root: String,
    pub governance_decision_root: String,
    pub fail_closed_status_root: String,
    pub state_commitment_root: String,
}

impl Roots {
    pub fn new(
        wallet_manifests: &[WalletReleaseManifestEnforcement],
        watchtower_manifests: &[WatchtowerReleaseManifestEnforcement],
        circuit_breakers: &[CircuitBreakerObservation],
        transcript_continuities: &[WalletTranscriptContinuity],
        watchtower_quorums: &[WatchtowerQuorumAttestation],
        recovery_paths: &[RecoveryPathBinding],
        operator_acknowledgements: &[OperatorAcknowledgement],
        wallet_hold_notices: &[HoldNotice],
        public_hold_notices: &[HoldNotice],
    ) -> Self {
        Self {
            wallet_enforcement_root: vector_record_root(
                "wallet-release-manifest-enforcement",
                &records(wallet_manifests),
            ),
            watchtower_enforcement_root: vector_record_root(
                "watchtower-release-manifest-enforcement",
                &records(watchtower_manifests),
            ),
            circuit_breaker_root: vector_record_root(
                "circuit-breakers",
                &records(circuit_breakers),
            ),
            wallet_transcript_continuity_root: vector_record_root(
                "wallet-transcript-continuity",
                &records(transcript_continuities),
            ),
            watchtower_quorum_root: vector_record_root(
                "watchtower-quorum",
                &records(watchtower_quorums),
            ),
            recovery_root: vector_record_root("recovery-paths", &records(recovery_paths)),
            operator_acknowledgement_root: vector_record_root(
                "operator-acknowledgements",
                &records(operator_acknowledgements),
            ),
            wallet_hold_notice_root: vector_record_root(
                "wallet-hold-notices",
                &records(wallet_hold_notices),
            ),
            public_hold_notice_root: vector_record_root(
                "public-hold-notices",
                &records(public_hold_notices),
            ),
            governance_decision_root: String::new(),
            fail_closed_status_root: String::new(),
            state_commitment_root: String::new(),
        }
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn state_root(&self) -> String {
        record_root("roots", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub wallet_release_manifest_count: u64,
    pub accepted_wallet_release_manifest_count: u64,
    pub watchtower_release_manifest_count: u64,
    pub accepted_watchtower_release_manifest_count: u64,
    pub circuit_breaker_count: u64,
    pub engaged_circuit_breaker_count: u64,
    pub transcript_continuity_count: u64,
    pub verified_transcript_continuity_count: u64,
    pub transcript_gap_count: u64,
    pub watchtower_quorum_count: u64,
    pub accepted_watchtower_quorum_count: u64,
    pub watchtower_quorum_member_count: u64,
    pub recovery_path_count: u64,
    pub enabled_recovery_path_count: u64,
    pub operator_acknowledgement_count: u64,
    pub accepted_operator_acknowledgement_count: u64,
    pub wallet_hold_notice_count: u64,
    pub acknowledged_wallet_hold_notice_count: u64,
    pub public_hold_notice_count: u64,
    pub acknowledged_public_hold_notice_count: u64,
}

impl Counters {
    pub fn new(
        wallet_manifests: &[WalletReleaseManifestEnforcement],
        watchtower_manifests: &[WatchtowerReleaseManifestEnforcement],
        circuit_breakers: &[CircuitBreakerObservation],
        transcript_continuities: &[WalletTranscriptContinuity],
        watchtower_quorums: &[WatchtowerQuorumAttestation],
        recovery_paths: &[RecoveryPathBinding],
        operator_acknowledgements: &[OperatorAcknowledgement],
        wallet_hold_notices: &[HoldNotice],
        public_hold_notices: &[HoldNotice],
    ) -> Self {
        Self {
            wallet_release_manifest_count: wallet_manifests.len() as u64,
            accepted_wallet_release_manifest_count: count_where(wallet_manifests, |manifest| {
                manifest.accepted
            }),
            watchtower_release_manifest_count: watchtower_manifests.len() as u64,
            accepted_watchtower_release_manifest_count: count_where(
                watchtower_manifests,
                |manifest| manifest.accepted,
            ),
            circuit_breaker_count: circuit_breakers.len() as u64,
            engaged_circuit_breaker_count: count_where(circuit_breakers, |breaker| breaker.engaged),
            transcript_continuity_count: transcript_continuities.len() as u64,
            verified_transcript_continuity_count: count_where(
                transcript_continuities,
                |continuity| continuity.verified,
            ),
            transcript_gap_count: transcript_continuities
                .iter()
                .map(|continuity| continuity.gap_count)
                .sum(),
            watchtower_quorum_count: watchtower_quorums.len() as u64,
            accepted_watchtower_quorum_count: count_where(watchtower_quorums, |quorum| {
                quorum.accepted
            }),
            watchtower_quorum_member_count: watchtower_quorums
                .iter()
                .map(|quorum| quorum.member_count)
                .sum(),
            recovery_path_count: recovery_paths.len() as u64,
            enabled_recovery_path_count: count_where(recovery_paths, |path| path.enabled),
            operator_acknowledgement_count: operator_acknowledgements.len() as u64,
            accepted_operator_acknowledgement_count: count_where(
                operator_acknowledgements,
                |acknowledgement| acknowledgement.accepted,
            ),
            wallet_hold_notice_count: wallet_hold_notices.len() as u64,
            acknowledged_wallet_hold_notice_count: count_where(wallet_hold_notices, |notice| {
                notice.acknowledged
            }),
            public_hold_notice_count: public_hold_notices.len() as u64,
            acknowledged_public_hold_notice_count: count_where(public_hold_notices, |notice| {
                notice.acknowledged
            }),
        }
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn state_root(&self) -> String {
        record_root("counters", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GovernanceVerdict {
    pub wallet_enforcement_accepted: bool,
    pub watchtower_enforcement_accepted: bool,
    pub circuit_breakers_clear: bool,
    pub wallet_transcript_continuity_accepted: bool,
    pub watchtower_quorum_accepted: bool,
    pub recovery_accepted: bool,
    pub operator_acknowledgement_accepted: bool,
    pub wallet_hold_notice_accepted: bool,
    pub public_hold_notice_accepted: bool,
    pub all_required_roots_present: bool,
    pub governance_decision: GovernanceDecision,
    pub fail_closed_status: FailClosedStatus,
    pub hold_reason: BindingHoldReason,
    pub force_exit_authorized: bool,
    pub governance_answer: String,
    pub user_escape_answer: String,
    pub verdict_root: String,
}

impl GovernanceVerdict {
    pub fn new(config: &Config, roots: &Roots, counters: &Counters) -> Self {
        let wallet_enforcement_accepted = counters.wallet_release_manifest_count
            >= config.min_wallet_release_manifests
            && counters.accepted_wallet_release_manifest_count
                >= config.min_wallet_release_manifests;
        let watchtower_enforcement_accepted = counters.watchtower_release_manifest_count
            >= config.min_watchtower_release_manifests
            && counters.accepted_watchtower_release_manifest_count
                >= config.min_watchtower_release_manifests;
        let circuit_breakers_clear = counters.engaged_circuit_breaker_count
            <= config.max_circuit_breaker_incidents
            && optional_requirement(
                config.require_zero_circuit_breakers,
                counters.engaged_circuit_breaker_count == 0,
            );
        let wallet_transcript_continuity_accepted = counters.transcript_continuity_count > 0
            && counters.verified_transcript_continuity_count
                == counters.transcript_continuity_count
            && counters.transcript_gap_count <= config.max_transcript_gaps
            && optional_requirement(
                config.require_zero_transcript_gaps,
                counters.transcript_gap_count == 0,
            );
        let watchtower_quorum_accepted = counters.accepted_watchtower_quorum_count > 0
            && counters.watchtower_quorum_member_count >= config.min_watchtower_quorum_members;
        let recovery_accepted = counters.enabled_recovery_path_count >= config.min_recovery_paths;
        let operator_acknowledgement_accepted = counters.accepted_operator_acknowledgement_count
            >= config.min_operator_acknowledgements;
        let wallet_hold_notice_accepted =
            counters.acknowledged_wallet_hold_notice_count >= config.min_wallet_hold_notices;
        let public_hold_notice_accepted =
            counters.acknowledged_public_hold_notice_count >= config.min_public_hold_notices;
        let all_required_roots_present = required_roots_present(config, roots);
        let required_lanes_accepted = optional_requirement(
            config.require_wallet_enforcement_root,
            wallet_enforcement_accepted,
        ) && optional_requirement(
            config.require_watchtower_enforcement_root,
            watchtower_enforcement_accepted,
        ) && optional_requirement(
            config.require_circuit_breaker_root,
            circuit_breakers_clear,
        ) && optional_requirement(
            config.require_wallet_transcript_continuity_root,
            wallet_transcript_continuity_accepted,
        ) && optional_requirement(
            config.require_watchtower_quorum_root,
            watchtower_quorum_accepted,
        ) && optional_requirement(
            config.require_recovery_root,
            recovery_accepted,
        ) && optional_requirement(
            config.require_operator_acknowledgement,
            operator_acknowledgement_accepted,
        ) && optional_requirement(
            config.require_wallet_hold_notice,
            wallet_hold_notice_accepted,
        ) && optional_requirement(
            config.require_public_hold_notice,
            public_hold_notice_accepted,
        );
        let fail_closed = (config.fail_closed_on_missing_root && !all_required_roots_present)
            || (config.fail_closed_on_any_hold && !required_lanes_accepted)
            || !circuit_breakers_clear
            || !wallet_transcript_continuity_accepted;
        let force_exit_authorized =
            required_lanes_accepted && all_required_roots_present && !fail_closed;
        let governance_decision =
            if force_exit_authorized && config.hold_force_exit_until_governance_go {
                GovernanceDecision::Go
            } else {
                GovernanceDecision::NoGo
            };
        let fail_closed_status = if fail_closed {
            FailClosedStatus::Engaged
        } else {
            FailClosedStatus::Clear
        };
        let hold_reason = first_hold_reason(
            all_required_roots_present,
            wallet_enforcement_accepted,
            watchtower_enforcement_accepted,
            circuit_breakers_clear,
            wallet_transcript_continuity_accepted,
            watchtower_quorum_accepted,
            recovery_accepted,
            operator_acknowledgement_accepted,
            wallet_hold_notice_accepted,
            public_hold_notice_accepted,
        );
        let governance_answer = if force_exit_authorized {
            "wallet_watchtower_governance_go".to_string()
        } else {
            "wallet_watchtower_governance_no_go_fail_closed".to_string()
        };
        let user_escape_answer = if force_exit_authorized {
            "user_escape_force_exit_package_governance_go".to_string()
        } else {
            "user_escape_force_exit_package_governance_no_go_hold".to_string()
        };
        let verdict_root = governance_verdict_root(
            config,
            roots,
            counters,
            governance_decision,
            fail_closed_status,
            hold_reason,
            force_exit_authorized,
        );
        Self {
            wallet_enforcement_accepted,
            watchtower_enforcement_accepted,
            circuit_breakers_clear,
            wallet_transcript_continuity_accepted,
            watchtower_quorum_accepted,
            recovery_accepted,
            operator_acknowledgement_accepted,
            wallet_hold_notice_accepted,
            public_hold_notice_accepted,
            all_required_roots_present,
            governance_decision,
            fail_closed_status,
            hold_reason,
            force_exit_authorized,
            governance_answer,
            user_escape_answer,
            verdict_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn state_root(&self) -> String {
        record_root("governance-verdict", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub wallet_manifests: Vec<WalletReleaseManifestEnforcement>,
    pub watchtower_manifests: Vec<WatchtowerReleaseManifestEnforcement>,
    pub circuit_breakers: Vec<CircuitBreakerObservation>,
    pub transcript_continuities: Vec<WalletTranscriptContinuity>,
    pub watchtower_quorums: Vec<WatchtowerQuorumAttestation>,
    pub recovery_paths: Vec<RecoveryPathBinding>,
    pub operator_acknowledgements: Vec<OperatorAcknowledgement>,
    pub wallet_hold_notices: Vec<HoldNotice>,
    pub public_hold_notices: Vec<HoldNotice>,
    pub roots: Roots,
    pub counters: Counters,
    pub verdict: GovernanceVerdict,
}

impl State {
    pub fn devnet() -> Self {
        devnet()
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "state": self,
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "MONERO-L2-PQ-WALLET-WATCHTOWER-GO-NO-GO-GOVERNANCE-BINDING-STATE-ROOT",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(&self.config.state_root()),
                HashPart::Str(&self.roots.state_root()),
                HashPart::Str(&self.counters.state_root()),
                HashPart::Str(&self.verdict.state_root()),
            ],
            32,
        )
    }
}

pub fn devnet() -> State {
    let config = Config::devnet();
    let release_id = deterministic_id("release", &["devnet", "wallet-watchtower-governance"]);
    let wallet_manifests = (0..DEFAULT_MIN_WALLET_RELEASE_MANIFESTS)
        .map(|index| {
            WalletReleaseManifestEnforcement::new(
                &format!("wallet-{index}"),
                &release_id,
                80,
                index,
                true,
            )
        })
        .collect::<Vec<_>>();
    let watchtower_manifests = (0..DEFAULT_MIN_WATCHTOWER_RELEASE_MANIFESTS)
        .map(|index| {
            WatchtowerReleaseManifestEnforcement::new(
                &format!("watchtower-{index}"),
                &release_id,
                92_100 + index,
                true,
            )
        })
        .collect::<Vec<_>>();
    let circuit_breakers = vec![CircuitBreakerObservation::cleared(
        "devnet-governance",
        &release_id,
        92_120,
    )];
    let transcript_continuities = (0..DEFAULT_MIN_WALLET_RELEASE_MANIFESTS)
        .map(|index| {
            WalletTranscriptContinuity::verified(&format!("wallet-{index}"), &release_id, index)
        })
        .collect::<Vec<_>>();
    let watchtower_quorums = vec![WatchtowerQuorumAttestation::accepted(
        "devnet-quorum",
        &release_id,
        DEFAULT_MIN_WATCHTOWER_QUORUM_MEMBERS,
        DEFAULT_MIN_WATCHTOWER_QUORUM_MEMBERS,
    )];
    let recovery_paths = (0..DEFAULT_MIN_RECOVERY_PATHS)
        .map(|index| RecoveryPathBinding::enabled(&format!("recovery-{index}"), &release_id, index))
        .collect::<Vec<_>>();
    let operator_acknowledgements = (0..DEFAULT_MIN_OPERATOR_ACKNOWLEDGEMENTS)
        .map(|index| {
            OperatorAcknowledgement::accepted(
                &format!("operator-{index}"),
                &release_id,
                92_140 + index,
            )
        })
        .collect::<Vec<_>>();
    let wallet_hold_notices = (0..DEFAULT_MIN_WALLET_HOLD_NOTICES)
        .map(|index| {
            HoldNotice::acknowledged(&format!("wallet-audience-{index}"), &release_id, 92_150)
        })
        .collect::<Vec<_>>();
    let public_hold_notices = (0..DEFAULT_MIN_PUBLIC_HOLD_NOTICES)
        .map(|index| {
            HoldNotice::acknowledged(&format!("public-audience-{index}"), &release_id, 92_151)
        })
        .collect::<Vec<_>>();
    let counters = Counters::new(
        &wallet_manifests,
        &watchtower_manifests,
        &circuit_breakers,
        &transcript_continuities,
        &watchtower_quorums,
        &recovery_paths,
        &operator_acknowledgements,
        &wallet_hold_notices,
        &public_hold_notices,
    );
    let mut roots = Roots::new(
        &wallet_manifests,
        &watchtower_manifests,
        &circuit_breakers,
        &transcript_continuities,
        &watchtower_quorums,
        &recovery_paths,
        &operator_acknowledgements,
        &wallet_hold_notices,
        &public_hold_notices,
    );
    let verdict = GovernanceVerdict::new(&config, &roots, &counters);
    roots.governance_decision_root = record_root(
        "governance-decision",
        &json!({
            "governance_decision": verdict.governance_decision.as_str(),
            "force_exit_authorized": verdict.force_exit_authorized,
            "hold_reason": verdict.hold_reason.as_str(),
            "verdict_root": verdict.verdict_root,
        }),
    );
    roots.fail_closed_status_root = record_root("fail-closed-status", &verdict.public_record());
    roots.state_commitment_root = state_commitment_root(&config, &roots, &counters, &verdict);
    State {
        config,
        wallet_manifests,
        watchtower_manifests,
        circuit_breakers,
        transcript_continuities,
        watchtower_quorums,
        recovery_paths,
        operator_acknowledgements,
        wallet_hold_notices,
        public_hold_notices,
        roots,
        counters,
        verdict,
    }
}

pub fn public_record() -> Value {
    devnet().public_record()
}

pub fn state_root() -> String {
    devnet().state_root()
}

pub fn record_root(kind: &str, record: &Value) -> String {
    domain_hash(
        "MONERO-L2-PQ-WALLET-WATCHTOWER-GO-NO-GO-GOVERNANCE-BINDING-RECORD",
        &[HashPart::Str(kind), HashPart::Json(record)],
        32,
    )
}

fn vector_record_root(kind: &str, records: &[Value]) -> String {
    let leaves = records
        .iter()
        .enumerate()
        .map(|(index, record)| {
            json!({
                "chain_id": CHAIN_ID,
                "kind": kind,
                "index": index,
                "record": record,
                "record_root": record_root(kind, record),
            })
        })
        .collect::<Vec<_>>();
    merkle_root(
        "MONERO-L2-PQ-WALLET-WATCHTOWER-GO-NO-GO-GOVERNANCE-BINDING-VECTOR",
        &leaves,
    )
}

fn records<T: Serialize>(items: &[T]) -> Vec<Value> {
    items.iter().map(|item| json!(item)).collect::<Vec<_>>()
}

fn governance_verdict_root(
    config: &Config,
    roots: &Roots,
    counters: &Counters,
    governance_decision: GovernanceDecision,
    fail_closed_status: FailClosedStatus,
    hold_reason: BindingHoldReason,
    force_exit_authorized: bool,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-WALLET-WATCHTOWER-GO-NO-GO-GOVERNANCE-BINDING-VERDICT",
        &[
            HashPart::Str(&config.governance_binding_suite),
            HashPart::Str(&roots.wallet_enforcement_root),
            HashPart::Str(&roots.watchtower_enforcement_root),
            HashPart::Str(&roots.circuit_breaker_root),
            HashPart::Str(&roots.wallet_transcript_continuity_root),
            HashPart::Str(&roots.watchtower_quorum_root),
            HashPart::Str(&roots.recovery_root),
            HashPart::Str(&roots.operator_acknowledgement_root),
            HashPart::Str(&roots.wallet_hold_notice_root),
            HashPart::Str(&roots.public_hold_notice_root),
            HashPart::U64(counters.accepted_wallet_release_manifest_count),
            HashPart::U64(counters.accepted_watchtower_release_manifest_count),
            HashPart::U64(counters.engaged_circuit_breaker_count),
            HashPart::U64(counters.verified_transcript_continuity_count),
            HashPart::U64(counters.transcript_gap_count),
            HashPart::U64(counters.watchtower_quorum_member_count),
            HashPart::U64(counters.enabled_recovery_path_count),
            HashPart::U64(counters.accepted_operator_acknowledgement_count),
            HashPart::U64(counters.acknowledged_wallet_hold_notice_count),
            HashPart::U64(counters.acknowledged_public_hold_notice_count),
            HashPart::Str(governance_decision.as_str()),
            HashPart::Str(fail_closed_status.as_str()),
            HashPart::Str(hold_reason.as_str()),
            HashPart::Str(bool_str(force_exit_authorized)),
        ],
        32,
    )
}

fn state_commitment_root(
    config: &Config,
    roots: &Roots,
    counters: &Counters,
    verdict: &GovernanceVerdict,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-WALLET-WATCHTOWER-GO-NO-GO-GOVERNANCE-BINDING-COMMITMENT",
        &[
            HashPart::Str(&record_root("config", &config.public_record())),
            HashPart::Str(&record_root("roots", &roots.public_record())),
            HashPart::Str(&record_root("counters", &counters.public_record())),
            HashPart::Str(&verdict.verdict_root),
            HashPart::Str(verdict.governance_decision.as_str()),
            HashPart::Str(verdict.fail_closed_status.as_str()),
            HashPart::Str(verdict.hold_reason.as_str()),
            HashPart::Str(bool_str(verdict.force_exit_authorized)),
        ],
        32,
    )
}

fn required_roots_present(config: &Config, roots: &Roots) -> bool {
    optional_requirement(
        config.require_wallet_enforcement_root,
        !roots.wallet_enforcement_root.is_empty(),
    ) && optional_requirement(
        config.require_watchtower_enforcement_root,
        !roots.watchtower_enforcement_root.is_empty(),
    ) && optional_requirement(
        config.require_circuit_breaker_root,
        !roots.circuit_breaker_root.is_empty(),
    ) && optional_requirement(
        config.require_wallet_transcript_continuity_root,
        !roots.wallet_transcript_continuity_root.is_empty(),
    ) && optional_requirement(
        config.require_watchtower_quorum_root,
        !roots.watchtower_quorum_root.is_empty(),
    ) && optional_requirement(
        config.require_recovery_root,
        !roots.recovery_root.is_empty(),
    ) && optional_requirement(
        config.require_operator_acknowledgement,
        !roots.operator_acknowledgement_root.is_empty(),
    ) && optional_requirement(
        config.require_wallet_hold_notice,
        !roots.wallet_hold_notice_root.is_empty(),
    ) && optional_requirement(
        config.require_public_hold_notice,
        !roots.public_hold_notice_root.is_empty(),
    )
}

fn first_hold_reason(
    all_required_roots_present: bool,
    wallet_enforcement_accepted: bool,
    watchtower_enforcement_accepted: bool,
    circuit_breakers_clear: bool,
    wallet_transcript_continuity_accepted: bool,
    watchtower_quorum_accepted: bool,
    recovery_accepted: bool,
    operator_acknowledgement_accepted: bool,
    wallet_hold_notice_accepted: bool,
    public_hold_notice_accepted: bool,
) -> BindingHoldReason {
    if !all_required_roots_present {
        BindingHoldReason::MissingWalletEnforcementRoot
    } else if !wallet_enforcement_accepted {
        BindingHoldReason::MissingWalletEnforcementRoot
    } else if !watchtower_enforcement_accepted {
        BindingHoldReason::MissingWatchtowerEnforcementRoot
    } else if !circuit_breakers_clear {
        BindingHoldReason::CircuitBreakerEngaged
    } else if !wallet_transcript_continuity_accepted {
        BindingHoldReason::WalletTranscriptContinuityGap
    } else if !watchtower_quorum_accepted {
        BindingHoldReason::WatchtowerQuorumMissing
    } else if !recovery_accepted {
        BindingHoldReason::RecoveryRootMissing
    } else if !operator_acknowledgement_accepted {
        BindingHoldReason::OperatorAcknowledgementMissing
    } else if !wallet_hold_notice_accepted {
        BindingHoldReason::WalletHoldNoticeMissing
    } else if !public_hold_notice_accepted {
        BindingHoldReason::PublicHoldNoticeMissing
    } else {
        BindingHoldReason::None
    }
}

fn deterministic_id(kind: &str, parts: &[&str]) -> String {
    let leaves = parts
        .iter()
        .enumerate()
        .map(|(index, part)| json!({ "index": index, "part": part }))
        .collect::<Vec<_>>();
    domain_hash(
        "MONERO-L2-PQ-WALLET-WATCHTOWER-GO-NO-GO-GOVERNANCE-BINDING-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(kind),
            HashPart::Str(&merkle_root(
                "MONERO-L2-PQ-WALLET-WATCHTOWER-GO-NO-GO-GOVERNANCE-BINDING-ID-PARTS",
                &leaves,
            )),
        ],
        32,
    )
}

fn sample_root(kind: &str, label: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-WALLET-WATCHTOWER-GO-NO-GO-GOVERNANCE-BINDING-DEVNET-SAMPLE",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(kind),
            HashPart::Str(label),
        ],
        32,
    )
}

fn count_where<T>(items: &[T], predicate: impl Fn(&T) -> bool) -> u64 {
    items.iter().filter(|item| predicate(item)).count() as u64
}

fn optional_requirement(required: bool, satisfied: bool) -> bool {
    !required || satisfied
}

fn bool_str(value: bool) -> &'static str {
    if value {
        "true"
    } else {
        "false"
    }
}
