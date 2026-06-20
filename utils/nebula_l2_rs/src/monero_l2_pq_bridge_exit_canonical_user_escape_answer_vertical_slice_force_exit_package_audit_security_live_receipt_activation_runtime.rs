use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalUserEscapeAnswerVerticalSliceForceExitPackageAuditSecurityLiveReceiptActivationRuntimeResult<
    T,
> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_ANSWER_VERTICAL_SLICE_FORCE_EXIT_PACKAGE_AUDIT_SECURITY_LIVE_RECEIPT_ACTIVATION_RUNTIME_PROTOCOL_VERSION: &str =
    "monero-l2-pq-force-exit-audit-security-live-receipt-activation-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_ANSWER_VERTICAL_SLICE_FORCE_EXIT_PACKAGE_AUDIT_SECURITY_LIVE_RECEIPT_ACTIVATION_RUNTIME_PROTOCOL_VERSION;
pub const REVIEW_SUITE: &str = "ml-dsa-87+privacy-non-linkage-review-live-receipt-v1";
pub const DEFAULT_RELEASE_POLICY_ID: &str = "force-exit-release-policy-canonical-user-escape";
pub const DEFAULT_ACTIVATION_EPOCH: u64 = 78;
pub const DEFAULT_MIN_REVIEWER_QUORUM: u16 = 5;
pub const DEFAULT_MIN_SECURITY_REVIEWERS: u16 = 2;
pub const DEFAULT_MIN_PRIVACY_REVIEWERS: u16 = 2;
pub const DEFAULT_MIN_SCOPE_COVERAGE_BPS: u16 = 9_800;
pub const DEFAULT_MAX_UNRESOLVED_HIGH_FINDINGS: u16 = 0;
pub const DEFAULT_MAX_UNRESOLVED_MEDIUM_FINDINGS: u16 = 1;
pub const DEFAULT_MIN_NON_LINKAGE_SCORE_BPS: u16 = 9_700;
pub const DEFAULT_MIN_RECEIPT_ACCEPTANCE_BPS: u16 = 9_900;
pub const BASIS_POINTS: u16 = 10_000;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum ReviewTrack {
    Security,
    Privacy,
    Protocol,
    BridgeCustody,
    Runtime,
    Watchtower,
    ReleasePolicy,
}

impl ReviewTrack {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Security => "security",
            Self::Privacy => "privacy",
            Self::Protocol => "protocol",
            Self::BridgeCustody => "bridge_custody",
            Self::Runtime => "runtime",
            Self::Watchtower => "watchtower",
            Self::ReleasePolicy => "release_policy",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum FindingSeverity {
    Informational,
    Low,
    Medium,
    High,
    Critical,
}

impl FindingSeverity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Informational => "informational",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }

    pub fn release_blocking_weight(&self) -> u64 {
        match self {
            Self::Informational => 0,
            Self::Low => 1,
            Self::Medium => 8,
            Self::High => 64,
            Self::Critical => 512,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum FindingStatus {
    Open,
    Mitigated,
    AcceptedRisk,
    DeferredNonBlocking,
    Closed,
}

impl FindingStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Mitigated => "mitigated",
            Self::AcceptedRisk => "accepted_risk",
            Self::DeferredNonBlocking => "deferred_non_blocking",
            Self::Closed => "closed",
        }
    }

    pub fn is_unresolved(&self) -> bool {
        matches!(self, Self::Open | Self::Mitigated)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum AcceptanceStatus {
    Accepted,
    Held,
    Rejected,
}

impl AcceptanceStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Held => "held",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    pub chain_id: String,
    pub release_policy_id: String,
    pub activation_epoch: u64,
    pub review_suite: String,
    pub min_reviewer_quorum: u16,
    pub min_security_reviewers: u16,
    pub min_privacy_reviewers: u16,
    pub min_scope_coverage_bps: u16,
    pub max_unresolved_high_findings: u16,
    pub max_unresolved_medium_findings: u16,
    pub min_non_linkage_score_bps: u16,
    pub min_receipt_acceptance_bps: u16,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            release_policy_id: DEFAULT_RELEASE_POLICY_ID.to_string(),
            activation_epoch: DEFAULT_ACTIVATION_EPOCH,
            review_suite: REVIEW_SUITE.to_string(),
            min_reviewer_quorum: DEFAULT_MIN_REVIEWER_QUORUM,
            min_security_reviewers: DEFAULT_MIN_SECURITY_REVIEWERS,
            min_privacy_reviewers: DEFAULT_MIN_PRIVACY_REVIEWERS,
            min_scope_coverage_bps: DEFAULT_MIN_SCOPE_COVERAGE_BPS,
            max_unresolved_high_findings: DEFAULT_MAX_UNRESOLVED_HIGH_FINDINGS,
            max_unresolved_medium_findings: DEFAULT_MAX_UNRESOLVED_MEDIUM_FINDINGS,
            min_non_linkage_score_bps: DEFAULT_MIN_NON_LINKAGE_SCORE_BPS,
            min_receipt_acceptance_bps: DEFAULT_MIN_RECEIPT_ACCEPTANCE_BPS,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "release_policy_id": self.release_policy_id,
            "activation_epoch": self.activation_epoch,
            "review_suite": self.review_suite,
            "min_reviewer_quorum": self.min_reviewer_quorum,
            "min_security_reviewers": self.min_security_reviewers,
            "min_privacy_reviewers": self.min_privacy_reviewers,
            "min_scope_coverage_bps": self.min_scope_coverage_bps,
            "max_unresolved_high_findings": self.max_unresolved_high_findings,
            "max_unresolved_medium_findings": self.max_unresolved_medium_findings,
            "min_non_linkage_score_bps": self.min_non_linkage_score_bps,
            "min_receipt_acceptance_bps": self.min_receipt_acceptance_bps,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReviewerQuorumReceipt {
    pub reviewer_id: String,
    pub reviewer_role: ReviewTrack,
    pub credential_root: String,
    pub scope_root: String,
    pub signed_receipt_root: String,
    pub observed_policy_root: String,
    pub signed_at_height: u64,
}

impl ReviewerQuorumReceipt {
    pub fn receipt_id(&self) -> String {
        domain_hash(
            "FORCE-EXIT-AUDIT-REVIEWER-RECEIPT-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&self.reviewer_id),
                HashPart::Str(self.reviewer_role.as_str()),
                HashPart::Str(&self.credential_root),
                HashPart::Str(&self.scope_root),
                HashPart::Str(&self.signed_receipt_root),
                HashPart::U64(self.signed_at_height),
            ],
            32,
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id(),
            "reviewer_id": self.reviewer_id,
            "reviewer_role": self.reviewer_role.as_str(),
            "credential_root": self.credential_root,
            "scope_root": self.scope_root,
            "signed_receipt_root": self.signed_receipt_root,
            "observed_policy_root": self.observed_policy_root,
            "signed_at_height": self.signed_at_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ScopeCoverageItem {
    pub scope_id: String,
    pub track: ReviewTrack,
    pub artifact_root: String,
    pub required_controls: u16,
    pub covered_controls: u16,
    pub witness_root: String,
}

impl ScopeCoverageItem {
    pub fn coverage_bps(&self) -> u16 {
        ratio_bps(self.covered_controls as u64, self.required_controls as u64)
    }

    pub fn coverage_id(&self) -> String {
        domain_hash(
            "FORCE-EXIT-AUDIT-SCOPE-COVERAGE-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&self.scope_id),
                HashPart::Str(self.track.as_str()),
                HashPart::Str(&self.artifact_root),
                HashPart::U64(self.required_controls as u64),
                HashPart::U64(self.covered_controls as u64),
                HashPart::Str(&self.witness_root),
            ],
            32,
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "coverage_id": self.coverage_id(),
            "scope_id": self.scope_id,
            "track": self.track.as_str(),
            "artifact_root": self.artifact_root,
            "required_controls": self.required_controls,
            "covered_controls": self.covered_controls,
            "coverage_bps": self.coverage_bps(),
            "witness_root": self.witness_root,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FindingHold {
    pub finding_id: String,
    pub severity: FindingSeverity,
    pub status: FindingStatus,
    pub track: ReviewTrack,
    pub disclosure_root: String,
    pub mitigation_root: String,
    pub owner_commitment: String,
    pub opened_at_height: u64,
    pub last_reviewed_height: u64,
}

impl FindingHold {
    pub fn hold_id(&self) -> String {
        domain_hash(
            "FORCE-EXIT-AUDIT-FINDING-HOLD-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&self.finding_id),
                HashPart::Str(self.severity.as_str()),
                HashPart::Str(self.status.as_str()),
                HashPart::Str(self.track.as_str()),
                HashPart::Str(&self.disclosure_root),
                HashPart::Str(&self.mitigation_root),
                HashPart::Str(&self.owner_commitment),
            ],
            32,
        )
    }

    pub fn release_blocking_score(&self) -> u64 {
        if self.status.is_unresolved() {
            self.severity.release_blocking_weight()
        } else {
            0
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "hold_id": self.hold_id(),
            "finding_id": self.finding_id,
            "severity": self.severity.as_str(),
            "status": self.status.as_str(),
            "track": self.track.as_str(),
            "disclosure_root": self.disclosure_root,
            "mitigation_root": self.mitigation_root,
            "owner_commitment": self.owner_commitment,
            "opened_at_height": self.opened_at_height,
            "last_reviewed_height": self.last_reviewed_height,
            "release_blocking_score": self.release_blocking_score(),
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrivacyNonLinkageEvidence {
    pub evidence_id: String,
    pub transcript_root: String,
    pub nullifier_set_root: String,
    pub decoy_distribution_root: String,
    pub view_tag_bucket_root: String,
    pub wallet_transcript_root: String,
    pub unlinkability_score_bps: u16,
    pub sampled_receipts: u32,
    pub replay_window_start: u64,
    pub replay_window_end: u64,
}

impl PrivacyNonLinkageEvidence {
    pub fn evidence_root(&self) -> String {
        domain_hash(
            "FORCE-EXIT-AUDIT-PRIVACY-NON-LINKAGE-EVIDENCE-ROOT",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&self.evidence_id),
                HashPart::Str(&self.transcript_root),
                HashPart::Str(&self.nullifier_set_root),
                HashPart::Str(&self.decoy_distribution_root),
                HashPart::Str(&self.view_tag_bucket_root),
                HashPart::Str(&self.wallet_transcript_root),
                HashPart::U64(self.unlinkability_score_bps as u64),
                HashPart::U64(self.sampled_receipts as u64),
                HashPart::U64(self.replay_window_start),
                HashPart::U64(self.replay_window_end),
            ],
            32,
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "evidence_id": self.evidence_id,
            "evidence_root": self.evidence_root(),
            "transcript_root": self.transcript_root,
            "nullifier_set_root": self.nullifier_set_root,
            "decoy_distribution_root": self.decoy_distribution_root,
            "view_tag_bucket_root": self.view_tag_bucket_root,
            "wallet_transcript_root": self.wallet_transcript_root,
            "unlinkability_score_bps": self.unlinkability_score_bps,
            "sampled_receipts": self.sampled_receipts,
            "replay_window_start": self.replay_window_start,
            "replay_window_end": self.replay_window_end,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AcceptancePacket {
    pub packet_id: String,
    pub status: AcceptanceStatus,
    pub policy_root: String,
    pub reviewer_quorum_root: String,
    pub scope_coverage_root: String,
    pub finding_hold_root: String,
    pub privacy_evidence_root: String,
    pub release_gate_root: String,
    pub activated_at_height: u64,
}

impl AcceptancePacket {
    pub fn acceptance_root(&self) -> String {
        domain_hash(
            "FORCE-EXIT-AUDIT-ACCEPTANCE-PACKET-ROOT",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&self.packet_id),
                HashPart::Str(self.status.as_str()),
                HashPart::Str(&self.policy_root),
                HashPart::Str(&self.reviewer_quorum_root),
                HashPart::Str(&self.scope_coverage_root),
                HashPart::Str(&self.finding_hold_root),
                HashPart::Str(&self.privacy_evidence_root),
                HashPart::Str(&self.release_gate_root),
                HashPart::U64(self.activated_at_height),
            ],
            32,
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "packet_id": self.packet_id,
            "status": self.status.as_str(),
            "policy_root": self.policy_root,
            "reviewer_quorum_root": self.reviewer_quorum_root,
            "scope_coverage_root": self.scope_coverage_root,
            "finding_hold_root": self.finding_hold_root,
            "privacy_evidence_root": self.privacy_evidence_root,
            "release_gate_root": self.release_gate_root,
            "activated_at_height": self.activated_at_height,
            "acceptance_root": self.acceptance_root(),
        })
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Counters {
    pub reviewer_receipts: u64,
    pub security_reviewers: u64,
    pub privacy_reviewers: u64,
    pub covered_scopes: u64,
    pub required_controls: u64,
    pub covered_controls: u64,
    pub unresolved_medium_findings: u64,
    pub unresolved_high_findings: u64,
    pub unresolved_critical_findings: u64,
    pub accepted_packets: u64,
    pub held_packets: u64,
    pub rejected_packets: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "reviewer_receipts": self.reviewer_receipts,
            "security_reviewers": self.security_reviewers,
            "privacy_reviewers": self.privacy_reviewers,
            "covered_scopes": self.covered_scopes,
            "required_controls": self.required_controls,
            "covered_controls": self.covered_controls,
            "unresolved_medium_findings": self.unresolved_medium_findings,
            "unresolved_high_findings": self.unresolved_high_findings,
            "unresolved_critical_findings": self.unresolved_critical_findings,
            "accepted_packets": self.accepted_packets,
            "held_packets": self.held_packets,
            "rejected_packets": self.rejected_packets,
            "scope_coverage_bps": ratio_bps(self.covered_controls, self.required_controls),
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Roots {
    pub config_root: String,
    pub reviewer_quorum_root: String,
    pub scope_coverage_root: String,
    pub finding_hold_root: String,
    pub privacy_evidence_root: String,
    pub acceptance_packet_root: String,
    pub counters_root: String,
    pub activation_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "reviewer_quorum_root": self.reviewer_quorum_root,
            "scope_coverage_root": self.scope_coverage_root,
            "finding_hold_root": self.finding_hold_root,
            "privacy_evidence_root": self.privacy_evidence_root,
            "acceptance_packet_root": self.acceptance_packet_root,
            "counters_root": self.counters_root,
            "activation_root": self.activation_root,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub reviewer_receipts: Vec<ReviewerQuorumReceipt>,
    pub scope_coverage: Vec<ScopeCoverageItem>,
    pub finding_holds: Vec<FindingHold>,
    pub privacy_evidence: Vec<PrivacyNonLinkageEvidence>,
    pub acceptance_packets: Vec<AcceptancePacket>,
    pub counters: Counters,
    pub roots: Roots,
}

impl State {
    pub fn new(
        config: Config,
        reviewer_receipts: Vec<ReviewerQuorumReceipt>,
        scope_coverage: Vec<ScopeCoverageItem>,
        finding_holds: Vec<FindingHold>,
        privacy_evidence: Vec<PrivacyNonLinkageEvidence>,
        acceptance_packets: Vec<AcceptancePacket>,
    ) -> Self {
        let counters = derive_counters(
            &reviewer_receipts,
            &scope_coverage,
            &finding_holds,
            &acceptance_packets,
        );
        let roots = derive_roots(
            &config,
            &reviewer_receipts,
            &scope_coverage,
            &finding_holds,
            &privacy_evidence,
            &acceptance_packets,
            &counters,
        );

        Self {
            config,
            reviewer_receipts,
            scope_coverage,
            finding_holds,
            privacy_evidence,
            acceptance_packets,
            counters,
            roots,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": self.config.chain_id,
            "config": self.config.public_record(),
            "reviewer_receipts": records(&self.reviewer_receipts),
            "scope_coverage": records(&self.scope_coverage),
            "finding_holds": records(&self.finding_holds),
            "privacy_evidence": records(&self.privacy_evidence),
            "acceptance_packets": records(&self.acceptance_packets),
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
            "state_root": self.state_root(),
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "FORCE-EXIT-AUDIT-LIVE-RECEIPT-ACTIVATION-STATE-ROOT",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(&self.roots.activation_root),
                HashPart::Json(&self.counters.public_record()),
            ],
            32,
        )
    }
}

pub trait PublicRecord {
    fn public_record(&self) -> Value;
}

impl PublicRecord for ReviewerQuorumReceipt {
    fn public_record(&self) -> Value {
        ReviewerQuorumReceipt::public_record(self)
    }
}

impl PublicRecord for ScopeCoverageItem {
    fn public_record(&self) -> Value {
        ScopeCoverageItem::public_record(self)
    }
}

impl PublicRecord for FindingHold {
    fn public_record(&self) -> Value {
        FindingHold::public_record(self)
    }
}

impl PublicRecord for PrivacyNonLinkageEvidence {
    fn public_record(&self) -> Value {
        PrivacyNonLinkageEvidence::public_record(self)
    }
}

impl PublicRecord for AcceptancePacket {
    fn public_record(&self) -> Value {
        AcceptancePacket::public_record(self)
    }
}

pub fn devnet() -> State {
    let config = Config::devnet();
    let policy_root = release_policy_root(&config);
    let reviewer_receipts = devnet_reviewer_receipts(&policy_root);
    let scope_coverage = devnet_scope_coverage();
    let finding_holds = devnet_finding_holds();
    let privacy_evidence = devnet_privacy_evidence();
    let preliminary_counters = derive_counters(
        &reviewer_receipts,
        &scope_coverage,
        &finding_holds,
        &Vec::new(),
    );
    let preliminary_roots = derive_roots(
        &config,
        &reviewer_receipts,
        &scope_coverage,
        &finding_holds,
        &privacy_evidence,
        &Vec::new(),
        &preliminary_counters,
    );
    let acceptance_packets = devnet_acceptance_packets(&policy_root, &preliminary_roots);
    State::new(
        config,
        reviewer_receipts,
        scope_coverage,
        finding_holds,
        privacy_evidence,
        acceptance_packets,
    )
}

pub fn public_record() -> Value {
    devnet().public_record()
}

pub fn state_root() -> String {
    devnet().state_root()
}

fn records<T: PublicRecord>(items: &[T]) -> Vec<Value> {
    items.iter().map(PublicRecord::public_record).collect()
}

fn derive_counters(
    reviewer_receipts: &[ReviewerQuorumReceipt],
    scope_coverage: &[ScopeCoverageItem],
    finding_holds: &[FindingHold],
    acceptance_packets: &[AcceptancePacket],
) -> Counters {
    let mut counters = Counters {
        reviewer_receipts: reviewer_receipts.len() as u64,
        covered_scopes: scope_coverage.len() as u64,
        ..Counters::default()
    };

    for receipt in reviewer_receipts {
        match receipt.reviewer_role {
            ReviewTrack::Security => counters.security_reviewers += 1,
            ReviewTrack::Privacy => counters.privacy_reviewers += 1,
            _ => {}
        }
    }

    for item in scope_coverage {
        counters.required_controls += item.required_controls as u64;
        counters.covered_controls += item.covered_controls as u64;
    }

    for finding in finding_holds {
        if finding.status.is_unresolved() {
            match finding.severity {
                FindingSeverity::Medium => counters.unresolved_medium_findings += 1,
                FindingSeverity::High => counters.unresolved_high_findings += 1,
                FindingSeverity::Critical => counters.unresolved_critical_findings += 1,
                _ => {}
            }
        }
    }

    for packet in acceptance_packets {
        match packet.status {
            AcceptanceStatus::Accepted => counters.accepted_packets += 1,
            AcceptanceStatus::Held => counters.held_packets += 1,
            AcceptanceStatus::Rejected => counters.rejected_packets += 1,
        }
    }
    counters
}

fn derive_roots(
    config: &Config,
    reviewer_receipts: &[ReviewerQuorumReceipt],
    scope_coverage: &[ScopeCoverageItem],
    finding_holds: &[FindingHold],
    privacy_evidence: &[PrivacyNonLinkageEvidence],
    acceptance_packets: &[AcceptancePacket],
    counters: &Counters,
) -> Roots {
    let config_root = domain_hash(
        "FORCE-EXIT-AUDIT-CONFIG-ROOT",
        &[HashPart::Json(&config.public_record())],
        32,
    );
    let reviewer_quorum_root = merkle_root(
        "FORCE-EXIT-AUDIT-REVIEWER-QUORUM",
        &records(reviewer_receipts),
    );
    let scope_coverage_root =
        merkle_root("FORCE-EXIT-AUDIT-SCOPE-COVERAGE", &records(scope_coverage));
    let finding_hold_root = merkle_root("FORCE-EXIT-AUDIT-FINDING-HOLDS", &records(finding_holds));
    let privacy_evidence_root = merkle_root(
        "FORCE-EXIT-AUDIT-PRIVACY-EVIDENCE",
        &records(privacy_evidence),
    );
    let acceptance_packet_root = merkle_root(
        "FORCE-EXIT-AUDIT-ACCEPTANCE-PACKETS",
        &records(acceptance_packets),
    );
    let counters_root = domain_hash(
        "FORCE-EXIT-AUDIT-COUNTERS-ROOT",
        &[HashPart::Json(&counters.public_record())],
        32,
    );
    let activation_root = domain_hash(
        "FORCE-EXIT-AUDIT-ACTIVATION-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&config.release_policy_id),
            HashPart::Str(&config_root),
            HashPart::Str(&reviewer_quorum_root),
            HashPart::Str(&scope_coverage_root),
            HashPart::Str(&finding_hold_root),
            HashPart::Str(&privacy_evidence_root),
            HashPart::Str(&acceptance_packet_root),
            HashPart::Str(&counters_root),
        ],
        32,
    );

    Roots {
        config_root,
        reviewer_quorum_root,
        scope_coverage_root,
        finding_hold_root,
        privacy_evidence_root,
        acceptance_packet_root,
        counters_root,
        activation_root,
    }
}

fn release_policy_root(config: &Config) -> String {
    domain_hash(
        "FORCE-EXIT-AUDIT-RELEASE-POLICY-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&config.release_policy_id),
            HashPart::U64(config.activation_epoch),
            HashPart::Str(&config.review_suite),
        ],
        32,
    )
}

fn ratio_bps(numerator: u64, denominator: u64) -> u16 {
    if denominator == 0 {
        return 0;
    }
    let scaled = numerator.saturating_mul(BASIS_POINTS as u64) / denominator;
    if scaled > BASIS_POINTS as u64 {
        BASIS_POINTS
    } else {
        scaled as u16
    }
}

fn seeded_root(domain: &str, label: &str) -> String {
    domain_hash(domain, &[HashPart::Str(CHAIN_ID), HashPart::Str(label)], 32)
}

fn devnet_reviewer_receipts(policy_root: &str) -> Vec<ReviewerQuorumReceipt> {
    vec![
        reviewer(
            "security-lead",
            ReviewTrack::Security,
            policy_root,
            1_780_010,
        ),
        reviewer(
            "security-redteam",
            ReviewTrack::Security,
            policy_root,
            1_780_012,
        ),
        reviewer("privacy-lead", ReviewTrack::Privacy, policy_root, 1_780_014),
        reviewer(
            "privacy-cryptographer",
            ReviewTrack::Privacy,
            policy_root,
            1_780_016,
        ),
        reviewer(
            "protocol-maintainer",
            ReviewTrack::Protocol,
            policy_root,
            1_780_018,
        ),
    ]
}

fn reviewer(
    label: &str,
    role: ReviewTrack,
    policy_root: &str,
    signed_at_height: u64,
) -> ReviewerQuorumReceipt {
    ReviewerQuorumReceipt {
        reviewer_id: format!("force-exit-reviewer-{label}"),
        reviewer_role: role,
        credential_root: seeded_root("FORCE-EXIT-AUDIT-REVIEWER-CREDENTIAL", label),
        scope_root: seeded_root("FORCE-EXIT-AUDIT-REVIEWER-SCOPE", label),
        signed_receipt_root: seeded_root("FORCE-EXIT-AUDIT-REVIEWER-SIGNATURE", label),
        observed_policy_root: policy_root.to_string(),
        signed_at_height,
    }
}

fn devnet_scope_coverage() -> Vec<ScopeCoverageItem> {
    vec![
        scope("release-policy-binding", ReviewTrack::ReleasePolicy, 64, 64),
        scope("force-exit-claim-validation", ReviewTrack::Security, 72, 72),
        scope("pq-authority-quorum", ReviewTrack::Protocol, 54, 54),
        scope("custody-wallet-release", ReviewTrack::BridgeCustody, 50, 50),
        scope("watchtower-live-receipts", ReviewTrack::Watchtower, 44, 44),
        scope("runtime-replay-consistency", ReviewTrack::Runtime, 68, 68),
        scope("privacy-budget-regression", ReviewTrack::Privacy, 56, 55),
        scope(
            "non-linkage-transcript-sampling",
            ReviewTrack::Privacy,
            60,
            59,
        ),
    ]
}

fn scope(
    scope_id: &str,
    track: ReviewTrack,
    required_controls: u16,
    covered_controls: u16,
) -> ScopeCoverageItem {
    ScopeCoverageItem {
        scope_id: scope_id.to_string(),
        track,
        artifact_root: seeded_root("FORCE-EXIT-AUDIT-SCOPE-ARTIFACT", scope_id),
        required_controls,
        covered_controls,
        witness_root: seeded_root("FORCE-EXIT-AUDIT-SCOPE-WITNESS", scope_id),
    }
}

fn devnet_finding_holds() -> Vec<FindingHold> {
    vec![
        finding(
            "release-policy-doc-crossref",
            FindingSeverity::Low,
            FindingStatus::DeferredNonBlocking,
            ReviewTrack::ReleasePolicy,
            1_779_000,
            1_780_100,
        ),
        finding(
            "wallet-copy-clarity",
            FindingSeverity::Medium,
            FindingStatus::AcceptedRisk,
            ReviewTrack::Privacy,
            1_779_100,
            1_780_120,
        ),
    ]
}

fn finding(
    label: &str,
    severity: FindingSeverity,
    status: FindingStatus,
    track: ReviewTrack,
    opened_at_height: u64,
    last_reviewed_height: u64,
) -> FindingHold {
    FindingHold {
        finding_id: format!("force-exit-finding-{label}"),
        severity,
        status,
        track,
        disclosure_root: seeded_root("FORCE-EXIT-AUDIT-FINDING-DISCLOSURE", label),
        mitigation_root: seeded_root("FORCE-EXIT-AUDIT-FINDING-MITIGATION", label),
        owner_commitment: seeded_root("FORCE-EXIT-AUDIT-FINDING-OWNER", label),
        opened_at_height,
        last_reviewed_height,
    }
}

fn devnet_privacy_evidence() -> Vec<PrivacyNonLinkageEvidence> {
    vec![
        privacy_evidence(
            "wallet-transcript-sample-a",
            9_842,
            4_096,
            1_778_000,
            1_780_000,
        ),
        privacy_evidence(
            "wallet-transcript-sample-b",
            9_811,
            4_096,
            1_778_500,
            1_780_500,
        ),
        privacy_evidence(
            "release-receipt-sample-c",
            9_786,
            8_192,
            1_779_000,
            1_781_000,
        ),
    ]
}

fn privacy_evidence(
    label: &str,
    unlinkability_score_bps: u16,
    sampled_receipts: u32,
    replay_window_start: u64,
    replay_window_end: u64,
) -> PrivacyNonLinkageEvidence {
    PrivacyNonLinkageEvidence {
        evidence_id: format!("force-exit-non-linkage-{label}"),
        transcript_root: seeded_root("FORCE-EXIT-AUDIT-PRIVACY-TRANSCRIPT", label),
        nullifier_set_root: seeded_root("FORCE-EXIT-AUDIT-PRIVACY-NULLIFIER-SET", label),
        decoy_distribution_root: seeded_root("FORCE-EXIT-AUDIT-PRIVACY-DECOY-DIST", label),
        view_tag_bucket_root: seeded_root("FORCE-EXIT-AUDIT-PRIVACY-VIEW-TAG-BUCKET", label),
        wallet_transcript_root: seeded_root("FORCE-EXIT-AUDIT-PRIVACY-WALLET-TRANSCRIPT", label),
        unlinkability_score_bps,
        sampled_receipts,
        replay_window_start,
        replay_window_end,
    }
}

fn devnet_acceptance_packets(policy_root: &str, roots: &Roots) -> Vec<AcceptancePacket> {
    let packet_id = domain_hash(
        "FORCE-EXIT-AUDIT-ACCEPTANCE-PACKET-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(policy_root),
            HashPart::Str(&roots.reviewer_quorum_root),
            HashPart::Str(&roots.scope_coverage_root),
            HashPart::Str(&roots.privacy_evidence_root),
        ],
        32,
    );
    vec![AcceptancePacket {
        packet_id,
        status: AcceptanceStatus::Accepted,
        policy_root: policy_root.to_string(),
        reviewer_quorum_root: roots.reviewer_quorum_root.clone(),
        scope_coverage_root: roots.scope_coverage_root.clone(),
        finding_hold_root: roots.finding_hold_root.clone(),
        privacy_evidence_root: roots.privacy_evidence_root.clone(),
        release_gate_root: roots.activation_root.clone(),
        activated_at_height: 1_781_000,
    }]
}
