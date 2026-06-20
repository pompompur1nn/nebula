use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type Runtime = State;
pub type MoneroL2PqBridgeExitCanonicalUserEscapeAnswerVerticalSliceForceExitPackageAuditSecurityGoNoGoGovernanceBindingRuntimeResult<
    T,
> = Result<T>;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_ANSWER_VERTICAL_SLICE_FORCE_EXIT_PACKAGE_AUDIT_SECURITY_GO_NO_GO_GOVERNANCE_BINDING_RUNTIME_PROTOCOL_VERSION: &str =
    "monero-l2-pq-bridge-exit-canonical-force-exit-audit-security-go-no-go-governance-binding-v1";
pub const PROTOCOL_VERSION: &str = MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_ANSWER_VERTICAL_SLICE_FORCE_EXIT_PACKAGE_AUDIT_SECURITY_GO_NO_GO_GOVERNANCE_BINDING_RUNTIME_PROTOCOL_VERSION;
pub const DEFAULT_EVALUATED_HEIGHT: u64 = 88_000;
pub const DEFAULT_FINALITY_WINDOW_BLOCKS: u64 = 40;
pub const DEFAULT_MIN_SECURITY_REVIEWERS: u16 = 5;
pub const DEFAULT_MIN_PRIVACY_REVIEWERS: u16 = 3;
pub const DEFAULT_MIN_OPERATOR_ACKS: u16 = 2;
pub const DEFAULT_MAX_OPEN_BLOCKING_FINDINGS: u32 = 0;
pub const DEFAULT_MAX_WALLET_NOTICE_LAG_BLOCKS: u64 = 6;
pub const DEFAULT_MAX_PUBLIC_NOTICE_LAG_BLOCKS: u64 = 3;
pub const DEFAULT_MIN_NON_LINKAGE_SCORE_BPS: u16 = 9_900;
pub const DEFAULT_MIN_HOLD_NOTICE_CONFIRMATIONS: u16 = 2;
pub const MAX_BPS: u16 = 10_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GateStatus {
    Missing,
    Pending,
    Held,
    FailedClosed,
    Passed,
}

impl GateStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Missing => "missing",
            Self::Pending => "pending",
            Self::Held => "held",
            Self::FailedClosed => "failed_closed",
            Self::Passed => "passed",
        }
    }

    pub fn permits_release(self) -> bool {
        matches!(self, Self::Passed)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingSeverity {
    Informational,
    Low,
    Medium,
    High,
    Critical,
}

impl FindingSeverity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Informational => "informational",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }

    pub fn blocks_release(self) -> bool {
        matches!(self, Self::Medium | Self::High | Self::Critical)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingStatus {
    Open,
    Mitigating,
    WaiverRequested,
    WaivedByGovernance,
    Closed,
}

impl FindingStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Mitigating => "mitigating",
            Self::WaiverRequested => "waiver_requested",
            Self::WaivedByGovernance => "waived_by_governance",
            Self::Closed => "closed",
        }
    }

    pub fn unresolved(self) -> bool {
        matches!(self, Self::Open | Self::Mitigating | Self::WaiverRequested)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewerRole {
    Security,
    Privacy,
    CircuitBreaker,
    ReleaseManager,
    Governance,
}

impl ReviewerRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Security => "security",
            Self::Privacy => "privacy",
            Self::CircuitBreaker => "circuit_breaker",
            Self::ReleaseManager => "release_manager",
            Self::Governance => "governance",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Vote {
    Abstain,
    NoGo,
    GoWithHold,
    Go,
}

impl Vote {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Abstain => "abstain",
            Self::NoGo => "no_go",
            Self::GoWithHold => "go_with_hold",
            Self::Go => "go",
        }
    }

    pub fn affirmative(self) -> bool {
        matches!(self, Self::Go)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GovernanceDecision {
    Go,
    NoGoSecurityRootMissing,
    NoGoCircuitBreakerArmed,
    NoGoReviewerQuorumMissing,
    NoGoUnresolvedFindings,
    NoGoPrivacyNonLinkageMissing,
    NoGoOperatorAcknowledgementMissing,
    NoGoWalletNoticeMissing,
    NoGoPublicHoldNoticeMissing,
    NoGoFailClosed,
}

impl GovernanceDecision {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Go => "go",
            Self::NoGoSecurityRootMissing => "no_go_security_root_missing",
            Self::NoGoCircuitBreakerArmed => "no_go_circuit_breaker_armed",
            Self::NoGoReviewerQuorumMissing => "no_go_reviewer_quorum_missing",
            Self::NoGoUnresolvedFindings => "no_go_unresolved_findings",
            Self::NoGoPrivacyNonLinkageMissing => "no_go_privacy_non_linkage_missing",
            Self::NoGoOperatorAcknowledgementMissing => "no_go_operator_acknowledgement_missing",
            Self::NoGoWalletNoticeMissing => "no_go_wallet_notice_missing",
            Self::NoGoPublicHoldNoticeMissing => "no_go_public_hold_notice_missing",
            Self::NoGoFailClosed => "no_go_fail_closed",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub chain_id: String,
    pub finality_window_blocks: u64,
    pub min_security_reviewers: u16,
    pub min_privacy_reviewers: u16,
    pub min_operator_acks: u16,
    pub max_open_blocking_findings: u32,
    pub max_wallet_notice_lag_blocks: u64,
    pub max_public_notice_lag_blocks: u64,
    pub min_non_linkage_score_bps: u16,
    pub min_hold_notice_confirmations: u16,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            finality_window_blocks: DEFAULT_FINALITY_WINDOW_BLOCKS,
            min_security_reviewers: DEFAULT_MIN_SECURITY_REVIEWERS,
            min_privacy_reviewers: DEFAULT_MIN_PRIVACY_REVIEWERS,
            min_operator_acks: DEFAULT_MIN_OPERATOR_ACKS,
            max_open_blocking_findings: DEFAULT_MAX_OPEN_BLOCKING_FINDINGS,
            max_wallet_notice_lag_blocks: DEFAULT_MAX_WALLET_NOTICE_LAG_BLOCKS,
            max_public_notice_lag_blocks: DEFAULT_MAX_PUBLIC_NOTICE_LAG_BLOCKS,
            min_non_linkage_score_bps: DEFAULT_MIN_NON_LINKAGE_SCORE_BPS,
            min_hold_notice_confirmations: DEFAULT_MIN_HOLD_NOTICE_CONFIRMATIONS,
        }
    }

    pub fn validate(&self) -> Result<()> {
        require_non_empty("chain_id", &self.chain_id)?;
        require(
            self.finality_window_blocks > 0,
            "finality window must be nonzero",
        )?;
        require(
            self.min_security_reviewers > 0,
            "security quorum must be nonzero",
        )?;
        require(
            self.min_privacy_reviewers > 0,
            "privacy quorum must be nonzero",
        )?;
        require(
            self.min_operator_acks > 0,
            "operator quorum must be nonzero",
        )?;
        require(
            self.min_non_linkage_score_bps <= MAX_BPS,
            "non-linkage bps out of range",
        )?;
        require(
            self.min_hold_notice_confirmations > 0,
            "notice confirmations must be nonzero",
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "finality_window_blocks": self.finality_window_blocks,
            "min_security_reviewers": self.min_security_reviewers,
            "min_privacy_reviewers": self.min_privacy_reviewers,
            "min_operator_acks": self.min_operator_acks,
            "max_open_blocking_findings": self.max_open_blocking_findings,
            "max_wallet_notice_lag_blocks": self.max_wallet_notice_lag_blocks,
            "max_public_notice_lag_blocks": self.max_public_notice_lag_blocks,
            "min_non_linkage_score_bps": self.min_non_linkage_score_bps,
            "min_hold_notice_confirmations": self.min_hold_notice_confirmations,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecurityEnforcementRoot {
    pub root_id: String,
    pub manifest_root: String,
    pub audit_bundle_root: String,
    pub release_manifest_root: String,
    pub enforcement_policy_root: String,
    pub status: GateStatus,
    pub generated_at_height: u64,
}

impl SecurityEnforcementRoot {
    pub fn new(
        manifest_root: impl Into<String>,
        audit_bundle_root: impl Into<String>,
        release_manifest_root: impl Into<String>,
        enforcement_policy_root: impl Into<String>,
        generated_at_height: u64,
    ) -> Self {
        let manifest_root = manifest_root.into();
        let audit_bundle_root = audit_bundle_root.into();
        let release_manifest_root = release_manifest_root.into();
        let enforcement_policy_root = enforcement_policy_root.into();
        let root_id = domain_hash(
            "MONERO-FORCE-EXIT-AUDIT-SECURITY-ROOT-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&manifest_root),
                HashPart::Str(&audit_bundle_root),
                HashPart::Str(&release_manifest_root),
                HashPart::Str(&enforcement_policy_root),
                HashPart::Int(generated_at_height as i128),
            ],
            32,
        );
        Self {
            root_id,
            manifest_root,
            audit_bundle_root,
            release_manifest_root,
            enforcement_policy_root,
            status: GateStatus::Pending,
            generated_at_height,
        }
    }

    pub fn validate(&self) -> Result<()> {
        require_non_empty("security root id", &self.root_id)?;
        require_non_empty("manifest root", &self.manifest_root)?;
        require_non_empty("audit bundle root", &self.audit_bundle_root)?;
        require_non_empty("release manifest root", &self.release_manifest_root)?;
        require_non_empty("enforcement policy root", &self.enforcement_policy_root)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "root_id": self.root_id,
            "manifest_root": self.manifest_root,
            "audit_bundle_root": self.audit_bundle_root,
            "release_manifest_root": self.release_manifest_root,
            "enforcement_policy_root": self.enforcement_policy_root,
            "status": self.status.as_str(),
            "generated_at_height": self.generated_at_height,
        })
    }

    pub fn state_root(&self) -> String {
        record_root(
            "MONERO-FORCE-EXIT-AUDIT-SECURITY-ROOT",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CircuitBreakerRoot {
    pub breaker_id: String,
    pub breaker_root: String,
    pub reason_root: String,
    pub armed: bool,
    pub last_transition_height: u64,
    pub status: GateStatus,
}

impl CircuitBreakerRoot {
    pub fn disarmed(
        breaker_root: impl Into<String>,
        reason_root: impl Into<String>,
        last_transition_height: u64,
    ) -> Self {
        let breaker_root = breaker_root.into();
        let reason_root = reason_root.into();
        let breaker_id = binding_id(
            "MONERO-FORCE-EXIT-CIRCUIT-BREAKER-ID",
            &breaker_root,
            &reason_root,
            last_transition_height,
        );
        Self {
            breaker_id,
            breaker_root,
            reason_root,
            armed: false,
            last_transition_height,
            status: GateStatus::Passed,
        }
    }

    pub fn validate(&self) -> Result<()> {
        require_non_empty("circuit breaker id", &self.breaker_id)?;
        require_non_empty("circuit breaker root", &self.breaker_root)?;
        require_non_empty("circuit breaker reason root", &self.reason_root)?;
        require(
            !(self.armed && self.status == GateStatus::Passed),
            "armed breaker cannot pass",
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "breaker_id": self.breaker_id,
            "breaker_root": self.breaker_root,
            "reason_root": self.reason_root,
            "armed": self.armed,
            "last_transition_height": self.last_transition_height,
            "status": self.status.as_str(),
        })
    }

    pub fn state_root(&self) -> String {
        record_root(
            "MONERO-FORCE-EXIT-CIRCUIT-BREAKER-ROOT",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReviewerAttestation {
    pub reviewer_id: String,
    pub role: ReviewerRole,
    pub vote: Vote,
    pub attestation_root: String,
    pub signed_height: u64,
}

impl ReviewerAttestation {
    pub fn new(
        reviewer_id: impl Into<String>,
        role: ReviewerRole,
        vote: Vote,
        attestation_root: impl Into<String>,
        signed_height: u64,
    ) -> Self {
        Self {
            reviewer_id: reviewer_id.into(),
            role,
            vote,
            attestation_root: attestation_root.into(),
            signed_height,
        }
    }

    pub fn validate(&self) -> Result<()> {
        require_non_empty("reviewer id", &self.reviewer_id)?;
        require_non_empty("reviewer attestation root", &self.attestation_root)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "reviewer_id": self.reviewer_id,
            "role": self.role.as_str(),
            "vote": self.vote.as_str(),
            "attestation_root": self.attestation_root,
            "signed_height": self.signed_height,
        })
    }

    pub fn state_root(&self) -> String {
        record_root(
            "MONERO-FORCE-EXIT-REVIEWER-ATTESTATION",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditFinding {
    pub finding_id: String,
    pub title: String,
    pub severity: FindingSeverity,
    pub status: FindingStatus,
    pub evidence_root: String,
    pub mitigation_root: String,
}

impl AuditFinding {
    pub fn new(
        title: impl Into<String>,
        severity: FindingSeverity,
        status: FindingStatus,
        evidence_root: impl Into<String>,
        mitigation_root: impl Into<String>,
    ) -> Self {
        let title = title.into();
        let evidence_root = evidence_root.into();
        let mitigation_root = mitigation_root.into();
        let finding_id = domain_hash(
            "MONERO-FORCE-EXIT-AUDIT-FINDING-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&title),
                HashPart::Str(severity.as_str()),
                HashPart::Str(status.as_str()),
                HashPart::Str(&evidence_root),
                HashPart::Str(&mitigation_root),
            ],
            32,
        );
        Self {
            finding_id,
            title,
            severity,
            status,
            evidence_root,
            mitigation_root,
        }
    }

    pub fn blocks_release(&self) -> bool {
        self.severity.blocks_release() && self.status.unresolved()
    }

    pub fn validate(&self) -> Result<()> {
        require_non_empty("finding id", &self.finding_id)?;
        require_non_empty("finding title", &self.title)?;
        require_non_empty("finding evidence root", &self.evidence_root)?;
        require_non_empty("finding mitigation root", &self.mitigation_root)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "finding_id": self.finding_id,
            "title": self.title,
            "severity": self.severity.as_str(),
            "status": self.status.as_str(),
            "evidence_root": self.evidence_root,
            "mitigation_root": self.mitigation_root,
            "blocks_release": self.blocks_release(),
        })
    }

    pub fn state_root(&self) -> String {
        record_root("MONERO-FORCE-EXIT-AUDIT-FINDING", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivacyNonLinkageGovernanceRoot {
    pub governance_id: String,
    pub non_linkage_root: String,
    pub privacy_budget_root: String,
    pub reviewer_root: String,
    pub minimum_score_bps: u16,
    pub observed_score_bps: u16,
    pub status: GateStatus,
}

impl PrivacyNonLinkageGovernanceRoot {
    pub fn new(
        non_linkage_root: impl Into<String>,
        privacy_budget_root: impl Into<String>,
        reviewer_root: impl Into<String>,
        minimum_score_bps: u16,
        observed_score_bps: u16,
    ) -> Self {
        let non_linkage_root = non_linkage_root.into();
        let privacy_budget_root = privacy_budget_root.into();
        let reviewer_root = reviewer_root.into();
        let governance_id = domain_hash(
            "MONERO-FORCE-EXIT-PRIVACY-NON-LINKAGE-GOVERNANCE-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&non_linkage_root),
                HashPart::Str(&privacy_budget_root),
                HashPart::Str(&reviewer_root),
                HashPart::Int(minimum_score_bps as i128),
                HashPart::Int(observed_score_bps as i128),
            ],
            32,
        );
        let status = if observed_score_bps >= minimum_score_bps {
            GateStatus::Passed
        } else {
            GateStatus::FailedClosed
        };
        Self {
            governance_id,
            non_linkage_root,
            privacy_budget_root,
            reviewer_root,
            minimum_score_bps,
            observed_score_bps,
            status,
        }
    }

    pub fn validate(&self) -> Result<()> {
        require_non_empty("privacy governance id", &self.governance_id)?;
        require_non_empty("non-linkage root", &self.non_linkage_root)?;
        require_non_empty("privacy budget root", &self.privacy_budget_root)?;
        require_non_empty("privacy reviewer root", &self.reviewer_root)?;
        require(
            self.minimum_score_bps <= MAX_BPS && self.observed_score_bps <= MAX_BPS,
            "privacy score out of range",
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "governance_id": self.governance_id,
            "non_linkage_root": self.non_linkage_root,
            "privacy_budget_root": self.privacy_budget_root,
            "reviewer_root": self.reviewer_root,
            "minimum_score_bps": self.minimum_score_bps,
            "observed_score_bps": self.observed_score_bps,
            "status": self.status.as_str(),
        })
    }

    pub fn state_root(&self) -> String {
        record_root(
            "MONERO-FORCE-EXIT-PRIVACY-NON-LINKAGE-GOVERNANCE-ROOT",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperatorAcknowledgement {
    pub operator_id: String,
    pub acknowledgement_root: String,
    pub release_manifest_root: String,
    pub acknowledged_height: u64,
    pub status: GateStatus,
}

impl OperatorAcknowledgement {
    pub fn new(
        operator_id: impl Into<String>,
        acknowledgement_root: impl Into<String>,
        release_manifest_root: impl Into<String>,
        acknowledged_height: u64,
    ) -> Self {
        Self {
            operator_id: operator_id.into(),
            acknowledgement_root: acknowledgement_root.into(),
            release_manifest_root: release_manifest_root.into(),
            acknowledged_height,
            status: GateStatus::Passed,
        }
    }

    pub fn validate(&self) -> Result<()> {
        require_non_empty("operator id", &self.operator_id)?;
        require_non_empty("operator acknowledgement root", &self.acknowledgement_root)?;
        require_non_empty(
            "operator release manifest root",
            &self.release_manifest_root,
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "operator_id": self.operator_id,
            "acknowledgement_root": self.acknowledgement_root,
            "release_manifest_root": self.release_manifest_root,
            "acknowledged_height": self.acknowledged_height,
            "status": self.status.as_str(),
        })
    }

    pub fn state_root(&self) -> String {
        record_root(
            "MONERO-FORCE-EXIT-OPERATOR-ACKNOWLEDGEMENT",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HoldNotice {
    pub notice_id: String,
    pub audience: String,
    pub hold_root: String,
    pub publication_root: String,
    pub issued_height: u64,
    pub confirmed_height: u64,
    pub confirmations: u16,
    pub status: GateStatus,
}

impl HoldNotice {
    pub fn new(
        audience: impl Into<String>,
        hold_root: impl Into<String>,
        publication_root: impl Into<String>,
        issued_height: u64,
        confirmed_height: u64,
        confirmations: u16,
    ) -> Self {
        let audience = audience.into();
        let hold_root = hold_root.into();
        let publication_root = publication_root.into();
        let notice_id = domain_hash(
            "MONERO-FORCE-EXIT-HOLD-NOTICE-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&audience),
                HashPart::Str(&hold_root),
                HashPart::Str(&publication_root),
                HashPart::Int(issued_height as i128),
                HashPart::Int(confirmed_height as i128),
                HashPart::Int(confirmations as i128),
            ],
            32,
        );
        Self {
            notice_id,
            audience,
            hold_root,
            publication_root,
            issued_height,
            confirmed_height,
            confirmations,
            status: GateStatus::Passed,
        }
    }

    pub fn lag_blocks(&self) -> u64 {
        self.confirmed_height.saturating_sub(self.issued_height)
    }

    pub fn validate(&self) -> Result<()> {
        require_non_empty("hold notice id", &self.notice_id)?;
        require_non_empty("hold notice audience", &self.audience)?;
        require_non_empty("hold notice root", &self.hold_root)?;
        require_non_empty("hold notice publication root", &self.publication_root)?;
        require(
            self.confirmed_height >= self.issued_height,
            "notice confirmation precedes issue",
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "notice_id": self.notice_id,
            "audience": self.audience,
            "hold_root": self.hold_root,
            "publication_root": self.publication_root,
            "issued_height": self.issued_height,
            "confirmed_height": self.confirmed_height,
            "confirmations": self.confirmations,
            "lag_blocks": self.lag_blocks(),
            "status": self.status.as_str(),
        })
    }

    pub fn state_root(&self) -> String {
        record_root("MONERO-FORCE-EXIT-HOLD-NOTICE", &self.public_record())
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    pub security_roots: u64,
    pub circuit_breakers: u64,
    pub reviewer_attestations: u64,
    pub audit_findings: u64,
    pub unresolved_findings: u64,
    pub blocking_findings: u64,
    pub operator_acknowledgements: u64,
    pub wallet_hold_notices: u64,
    pub public_hold_notices: u64,
    pub failed_closed_gates: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "security_roots": self.security_roots,
            "circuit_breakers": self.circuit_breakers,
            "reviewer_attestations": self.reviewer_attestations,
            "audit_findings": self.audit_findings,
            "unresolved_findings": self.unresolved_findings,
            "blocking_findings": self.blocking_findings,
            "operator_acknowledgements": self.operator_acknowledgements,
            "wallet_hold_notices": self.wallet_hold_notices,
            "public_hold_notices": self.public_hold_notices,
            "failed_closed_gates": self.failed_closed_gates,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RootSet {
    pub security_enforcement_root: String,
    pub circuit_breaker_root: String,
    pub reviewer_quorum_root: String,
    pub unresolved_finding_hold_root: String,
    pub privacy_non_linkage_governance_root: String,
    pub operator_acknowledgement_root: String,
    pub wallet_hold_notice_root: String,
    pub public_hold_notice_root: String,
    pub governance_decision_root: String,
}

impl RootSet {
    pub fn public_record(&self) -> Value {
        json!({
            "security_enforcement_root": self.security_enforcement_root,
            "circuit_breaker_root": self.circuit_breaker_root,
            "reviewer_quorum_root": self.reviewer_quorum_root,
            "unresolved_finding_hold_root": self.unresolved_finding_hold_root,
            "privacy_non_linkage_governance_root": self.privacy_non_linkage_governance_root,
            "operator_acknowledgement_root": self.operator_acknowledgement_root,
            "wallet_hold_notice_root": self.wallet_hold_notice_root,
            "public_hold_notice_root": self.public_hold_notice_root,
            "governance_decision_root": self.governance_decision_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovernanceVerdict {
    pub verdict_id: String,
    pub decision: GovernanceDecision,
    pub reason: String,
    pub evaluated_at_height: u64,
    pub counters: Counters,
    pub roots: RootSet,
}

impl GovernanceVerdict {
    pub fn public_record(&self) -> Value {
        json!({
            "verdict_id": self.verdict_id,
            "decision": self.decision.as_str(),
            "reason": self.reason,
            "evaluated_at_height": self.evaluated_at_height,
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
        })
    }

    pub fn state_root(&self) -> String {
        record_root("MONERO-FORCE-EXIT-GO-NO-GO-VERDICT", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub evaluated_at_height: u64,
    pub security_enforcement: Option<SecurityEnforcementRoot>,
    pub circuit_breaker: Option<CircuitBreakerRoot>,
    pub reviewer_attestations: BTreeMap<String, ReviewerAttestation>,
    pub findings: BTreeMap<String, AuditFinding>,
    pub privacy_non_linkage: Option<PrivacyNonLinkageGovernanceRoot>,
    pub operator_acknowledgements: BTreeMap<String, OperatorAcknowledgement>,
    pub wallet_hold_notices: BTreeMap<String, HoldNotice>,
    pub public_hold_notices: BTreeMap<String, HoldNotice>,
}

impl State {
    pub fn new(config: Config, evaluated_at_height: u64) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            config,
            evaluated_at_height,
            security_enforcement: None,
            circuit_breaker: None,
            reviewer_attestations: BTreeMap::new(),
            findings: BTreeMap::new(),
            privacy_non_linkage: None,
            operator_acknowledgements: BTreeMap::new(),
            wallet_hold_notices: BTreeMap::new(),
            public_hold_notices: BTreeMap::new(),
        })
    }

    pub fn devnet() -> Self {
        devnet()
    }

    pub fn set_security_enforcement(&mut self, root: SecurityEnforcementRoot) -> Result<()> {
        root.validate()?;
        self.security_enforcement = Some(root);
        Ok(())
    }

    pub fn set_circuit_breaker(&mut self, root: CircuitBreakerRoot) -> Result<()> {
        root.validate()?;
        self.circuit_breaker = Some(root);
        Ok(())
    }

    pub fn add_reviewer_attestation(&mut self, attestation: ReviewerAttestation) -> Result<()> {
        attestation.validate()?;
        self.reviewer_attestations
            .insert(attestation.reviewer_id.clone(), attestation);
        Ok(())
    }

    pub fn add_finding(&mut self, finding: AuditFinding) -> Result<()> {
        finding.validate()?;
        self.findings.insert(finding.finding_id.clone(), finding);
        Ok(())
    }

    pub fn set_privacy_non_linkage(&mut self, root: PrivacyNonLinkageGovernanceRoot) -> Result<()> {
        root.validate()?;
        self.privacy_non_linkage = Some(root);
        Ok(())
    }

    pub fn add_operator_acknowledgement(
        &mut self,
        acknowledgement: OperatorAcknowledgement,
    ) -> Result<()> {
        acknowledgement.validate()?;
        self.operator_acknowledgements
            .insert(acknowledgement.operator_id.clone(), acknowledgement);
        Ok(())
    }

    pub fn add_wallet_hold_notice(&mut self, notice: HoldNotice) -> Result<()> {
        notice.validate()?;
        self.wallet_hold_notices
            .insert(notice.notice_id.clone(), notice);
        Ok(())
    }

    pub fn add_public_hold_notice(&mut self, notice: HoldNotice) -> Result<()> {
        notice.validate()?;
        self.public_hold_notices
            .insert(notice.notice_id.clone(), notice);
        Ok(())
    }

    pub fn counters(&self) -> Counters {
        let unresolved_findings = self
            .findings
            .values()
            .filter(|finding| finding.status.unresolved())
            .count() as u64;
        let blocking_findings = self
            .findings
            .values()
            .filter(|finding| finding.blocks_release())
            .count() as u64;
        let failed_closed_gates = self
            .gate_statuses()
            .iter()
            .filter(|status| **status == GateStatus::FailedClosed)
            .count() as u64;
        Counters {
            security_roots: self.security_enforcement.iter().count() as u64,
            circuit_breakers: self.circuit_breaker.iter().count() as u64,
            reviewer_attestations: self.reviewer_attestations.len() as u64,
            audit_findings: self.findings.len() as u64,
            unresolved_findings,
            blocking_findings,
            operator_acknowledgements: self.operator_acknowledgements.len() as u64,
            wallet_hold_notices: self.wallet_hold_notices.len() as u64,
            public_hold_notices: self.public_hold_notices.len() as u64,
            failed_closed_gates,
        }
    }

    pub fn roots(&self) -> RootSet {
        let security_enforcement_root = match &self.security_enforcement {
            Some(root) => root.state_root(),
            None => empty_root("MONERO-FORCE-EXIT-MISSING-SECURITY-ROOT"),
        };
        let circuit_breaker_root = match &self.circuit_breaker {
            Some(root) => root.state_root(),
            None => empty_root("MONERO-FORCE-EXIT-MISSING-CIRCUIT-BREAKER"),
        };
        let reviewer_quorum_root = map_root(
            "MONERO-FORCE-EXIT-REVIEWER-QUORUM",
            self.reviewer_attestations
                .values()
                .map(ReviewerAttestation::state_root),
        );
        let unresolved_finding_hold_root = map_root(
            "MONERO-FORCE-EXIT-UNRESOLVED-FINDING-HOLD",
            self.findings
                .values()
                .filter(|finding| finding.status.unresolved())
                .map(AuditFinding::state_root),
        );
        let privacy_non_linkage_governance_root = match &self.privacy_non_linkage {
            Some(root) => root.state_root(),
            None => empty_root("MONERO-FORCE-EXIT-MISSING-PRIVACY-GOVERNANCE"),
        };
        let operator_acknowledgement_root = map_root(
            "MONERO-FORCE-EXIT-OPERATOR-ACKNOWLEDGEMENTS",
            self.operator_acknowledgements
                .values()
                .map(OperatorAcknowledgement::state_root),
        );
        let wallet_hold_notice_root = map_root(
            "MONERO-FORCE-EXIT-WALLET-HOLD-NOTICES",
            self.wallet_hold_notices
                .values()
                .map(HoldNotice::state_root),
        );
        let public_hold_notice_root = map_root(
            "MONERO-FORCE-EXIT-PUBLIC-HOLD-NOTICES",
            self.public_hold_notices
                .values()
                .map(HoldNotice::state_root),
        );
        let governance_decision_root = record_root(
            "MONERO-FORCE-EXIT-GOVERNANCE-DECISION-PREIMAGE",
            &json!({
                "security_enforcement_root": security_enforcement_root.clone(),
                "circuit_breaker_root": circuit_breaker_root.clone(),
                "reviewer_quorum_root": reviewer_quorum_root.clone(),
                "unresolved_finding_hold_root": unresolved_finding_hold_root.clone(),
                "privacy_non_linkage_governance_root": privacy_non_linkage_governance_root.clone(),
                "operator_acknowledgement_root": operator_acknowledgement_root.clone(),
                "wallet_hold_notice_root": wallet_hold_notice_root.clone(),
                "public_hold_notice_root": public_hold_notice_root.clone(),
            }),
        );
        RootSet {
            security_enforcement_root,
            circuit_breaker_root,
            reviewer_quorum_root,
            unresolved_finding_hold_root,
            privacy_non_linkage_governance_root,
            operator_acknowledgement_root,
            wallet_hold_notice_root,
            public_hold_notice_root,
            governance_decision_root,
        }
    }

    pub fn verdict(&self) -> GovernanceVerdict {
        let counters = self.counters();
        let roots = self.roots();
        let decision = self.evaluate_decision(&counters);
        let verdict_id = domain_hash(
            "MONERO-FORCE-EXIT-GO-NO-GO-VERDICT-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(decision.as_str()),
                HashPart::Str(&roots.governance_decision_root),
                HashPart::Int(self.evaluated_at_height as i128),
            ],
            32,
        );
        GovernanceVerdict {
            verdict_id,
            decision,
            reason: decision.as_str().to_string(),
            evaluated_at_height: self.evaluated_at_height,
            counters,
            roots,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_ANSWER_VERTICAL_SLICE_FORCE_EXIT_PACKAGE_AUDIT_SECURITY_GO_NO_GO_GOVERNANCE_BINDING_RUNTIME_PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "config": self.config.public_record(),
            "evaluated_at_height": self.evaluated_at_height,
            "security_enforcement": self.security_enforcement.as_ref().map(SecurityEnforcementRoot::public_record),
            "circuit_breaker": self.circuit_breaker.as_ref().map(CircuitBreakerRoot::public_record),
            "reviewer_attestations": values_record(self.reviewer_attestations.values().map(ReviewerAttestation::public_record)),
            "findings": values_record(self.findings.values().map(AuditFinding::public_record)),
            "privacy_non_linkage": self.privacy_non_linkage.as_ref().map(PrivacyNonLinkageGovernanceRoot::public_record),
            "operator_acknowledgements": values_record(self.operator_acknowledgements.values().map(OperatorAcknowledgement::public_record)),
            "wallet_hold_notices": values_record(self.wallet_hold_notices.values().map(HoldNotice::public_record)),
            "public_hold_notices": values_record(self.public_hold_notices.values().map(HoldNotice::public_record)),
            "counters": self.counters().public_record(),
            "roots": self.roots().public_record(),
            "verdict": self.verdict().public_record(),
        })
    }

    pub fn state_root(&self) -> String {
        record_root("MONERO-FORCE-EXIT-GO-NO-GO-STATE", &self.public_record())
    }

    fn evaluate_decision(&self, counters: &Counters) -> GovernanceDecision {
        if !self.security_enforcement.as_ref().map_or_release() {
            return GovernanceDecision::NoGoSecurityRootMissing;
        }
        if !self.circuit_breaker_clear() {
            return GovernanceDecision::NoGoCircuitBreakerArmed;
        }
        if !self.reviewer_quorum_satisfied() {
            return GovernanceDecision::NoGoReviewerQuorumMissing;
        }
        if counters.blocking_findings > self.config.max_open_blocking_findings as u64 {
            return GovernanceDecision::NoGoUnresolvedFindings;
        }
        if !self.privacy_non_linkage.as_ref().map_or_release() {
            return GovernanceDecision::NoGoPrivacyNonLinkageMissing;
        }
        if self.operator_acknowledgements.len() < self.config.min_operator_acks as usize {
            return GovernanceDecision::NoGoOperatorAcknowledgementMissing;
        }
        if !self.notices_satisfied(
            &self.wallet_hold_notices,
            self.config.max_wallet_notice_lag_blocks,
        ) {
            return GovernanceDecision::NoGoWalletNoticeMissing;
        }
        if !self.notices_satisfied(
            &self.public_hold_notices,
            self.config.max_public_notice_lag_blocks,
        ) {
            return GovernanceDecision::NoGoPublicHoldNoticeMissing;
        }
        if counters.failed_closed_gates > 0 {
            return GovernanceDecision::NoGoFailClosed;
        }
        GovernanceDecision::Go
    }

    fn circuit_breaker_clear(&self) -> bool {
        match &self.circuit_breaker {
            Some(root) => !root.armed && root.status.permits_release(),
            None => false,
        }
    }

    fn reviewer_quorum_satisfied(&self) -> bool {
        let security = self
            .reviewer_attestations
            .values()
            .filter(|attestation| {
                attestation.role == ReviewerRole::Security && attestation.vote.affirmative()
            })
            .count();
        let privacy = self
            .reviewer_attestations
            .values()
            .filter(|attestation| {
                attestation.role == ReviewerRole::Privacy && attestation.vote.affirmative()
            })
            .count();
        security >= self.config.min_security_reviewers as usize
            && privacy >= self.config.min_privacy_reviewers as usize
    }

    fn notices_satisfied(
        &self,
        notices: &BTreeMap<String, HoldNotice>,
        max_lag_blocks: u64,
    ) -> bool {
        notices.values().any(|notice| {
            notice.status.permits_release()
                && notice.confirmations >= self.config.min_hold_notice_confirmations
                && notice.lag_blocks() <= max_lag_blocks
        })
    }

    fn gate_statuses(&self) -> Vec<GateStatus> {
        let mut statuses = Vec::new();
        if let Some(root) = &self.security_enforcement {
            statuses.push(root.status);
        }
        if let Some(root) = &self.circuit_breaker {
            statuses.push(root.status);
        }
        if let Some(root) = &self.privacy_non_linkage {
            statuses.push(root.status);
        }
        statuses.extend(
            self.operator_acknowledgements
                .values()
                .map(|item| item.status),
        );
        statuses.extend(self.wallet_hold_notices.values().map(|item| item.status));
        statuses.extend(self.public_hold_notices.values().map(|item| item.status));
        statuses
    }
}

pub trait OptionalReleaseGate {
    fn map_or_release(&self) -> bool;
}

impl OptionalReleaseGate for Option<&SecurityEnforcementRoot> {
    fn map_or_release(&self) -> bool {
        match self {
            Some(root) => root.status.permits_release(),
            None => false,
        }
    }
}

impl OptionalReleaseGate for Option<&PrivacyNonLinkageGovernanceRoot> {
    fn map_or_release(&self) -> bool {
        match self {
            Some(root) => root.status.permits_release(),
            None => false,
        }
    }
}

pub fn devnet() -> State {
    let mut state = match State::new(Config::devnet(), DEFAULT_EVALUATED_HEIGHT) {
        Ok(state) => state,
        Err(_) => State {
            config: Config::devnet(),
            evaluated_at_height: DEFAULT_EVALUATED_HEIGHT,
            security_enforcement: None,
            circuit_breaker: None,
            reviewer_attestations: BTreeMap::new(),
            findings: BTreeMap::new(),
            privacy_non_linkage: None,
            operator_acknowledgements: BTreeMap::new(),
            wallet_hold_notices: BTreeMap::new(),
            public_hold_notices: BTreeMap::new(),
        },
    };
    let mut security = SecurityEnforcementRoot::new(
        sample_root("devnet-force-exit-release-manifest"),
        sample_root("devnet-audit-bundle"),
        sample_root("devnet-release-manifest-enforcement"),
        sample_root("devnet-security-policy"),
        87_960,
    );
    security.status = GateStatus::Passed;
    let _ = state.set_security_enforcement(security);
    let _ = state.set_circuit_breaker(CircuitBreakerRoot::disarmed(
        sample_root("devnet-breaker"),
        sample_root("devnet-breaker-reason-clear"),
        87_961,
    ));
    for index in 0..DEFAULT_MIN_SECURITY_REVIEWERS {
        let _ = state.add_reviewer_attestation(ReviewerAttestation::new(
            format!("security-reviewer-{index}"),
            ReviewerRole::Security,
            Vote::Go,
            sample_root(&format!("security-reviewer-{index}-attestation")),
            87_970 + u64::from(index),
        ));
    }
    for index in 0..DEFAULT_MIN_PRIVACY_REVIEWERS {
        let _ = state.add_reviewer_attestation(ReviewerAttestation::new(
            format!("privacy-reviewer-{index}"),
            ReviewerRole::Privacy,
            Vote::Go,
            sample_root(&format!("privacy-reviewer-{index}-attestation")),
            87_980 + u64::from(index),
        ));
    }
    let _ = state.add_finding(AuditFinding::new(
        "devnet informational release manifest traceability",
        FindingSeverity::Informational,
        FindingStatus::Closed,
        sample_root("devnet-info-finding-evidence"),
        sample_root("devnet-info-finding-closure"),
    ));
    let _ = state.set_privacy_non_linkage(PrivacyNonLinkageGovernanceRoot::new(
        sample_root("devnet-non-linkage"),
        sample_root("devnet-privacy-budget"),
        sample_root("devnet-privacy-reviewer-quorum"),
        DEFAULT_MIN_NON_LINKAGE_SCORE_BPS,
        MAX_BPS,
    ));
    for index in 0..DEFAULT_MIN_OPERATOR_ACKS {
        let _ = state.add_operator_acknowledgement(OperatorAcknowledgement::new(
            format!("operator-{index}"),
            sample_root(&format!("operator-{index}-ack")),
            sample_root("devnet-release-manifest-enforcement"),
            87_990 + u64::from(index),
        ));
    }
    let _ = state.add_wallet_hold_notice(HoldNotice::new(
        "wallet",
        sample_root("devnet-wallet-hold"),
        sample_root("devnet-wallet-publication"),
        87_991,
        87_993,
        DEFAULT_MIN_HOLD_NOTICE_CONFIRMATIONS,
    ));
    let _ = state.add_public_hold_notice(HoldNotice::new(
        "public",
        sample_root("devnet-public-hold"),
        sample_root("devnet-publication"),
        87_991,
        87_992,
        DEFAULT_MIN_HOLD_NOTICE_CONFIRMATIONS,
    ));
    state
}

pub fn public_record() -> Value {
    devnet().public_record()
}

pub fn state_root() -> String {
    devnet().state_root()
}

pub fn security_release_manifest_id(label: &str, release_manifest_root: &str) -> String {
    domain_hash(
        "MONERO-FORCE-EXIT-SECURITY-RELEASE-MANIFEST-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Str(release_manifest_root),
        ],
        32,
    )
}

pub fn governance_binding_id(subject_id: &str, root: &str, height: u64) -> String {
    binding_id(
        "MONERO-FORCE-EXIT-GOVERNANCE-BINDING-ID",
        subject_id,
        root,
        height,
    )
}

fn binding_id(domain: &str, left: &str, right: &str, height: u64) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(left),
            HashPart::Str(right),
            HashPart::Int(height as i128),
        ],
        32,
    )
}

fn record_root(domain: &str, record: &Value) -> String {
    domain_hash(
        domain,
        &[HashPart::Str(CHAIN_ID), HashPart::Json(record)],
        32,
    )
}

fn empty_root(domain: &str) -> String {
    merkle_root(domain, &[])
}

fn map_root<I>(domain: &str, roots: I) -> String
where
    I: IntoIterator<Item = String>,
{
    let leaves = roots.into_iter().collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn sample_root(label: &str) -> String {
    domain_hash(
        "MONERO-FORCE-EXIT-GO-NO-GO-DEVNET-SAMPLE",
        &[HashPart::Str(CHAIN_ID), HashPart::Str(label)],
        32,
    )
}

fn values_record<I>(records: I) -> Value
where
    I: IntoIterator<Item = Value>,
{
    Value::Array(records.into_iter().collect::<Vec<_>>())
}

fn require(condition: bool, message: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(message.to_string())
    }
}

fn require_non_empty(label: &str, value: &str) -> Result<()> {
    require(
        !value.trim().is_empty(),
        &format!("{label} must not be empty"),
    )
}
