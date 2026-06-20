use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::hash::{domain_hash, merkle_root, HashPart};
use crate::CHAIN_ID;

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalVerticalSliceRuntimeExitAcceptanceEvidenceManifestRuntimeResult<
    T,
> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_RUNTIME_EXIT_ACCEPTANCE_EVIDENCE_MANIFEST_RUNTIME_PROTOCOL_VERSION:
    &str = "monero-l2-pq-bridge-exit-canonical-vertical-slice-runtime-exit-acceptance-evidence-manifest-runtime/v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_RUNTIME_EXIT_ACCEPTANCE_EVIDENCE_MANIFEST_RUNTIME_PROTOCOL_VERSION;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum ExitAcceptanceLane {
    WalletRecovery,
    ForcedExitRelease,
    PqAuthority,
    PrivacyBoundary,
    ObservedReceipt,
    LiveFeed,
    LiquidityReserve,
    ChallengeWindow,
    ReleaseBlocker,
}

impl ExitAcceptanceLane {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::WalletRecovery => "wallet_recovery",
            Self::ForcedExitRelease => "forced_exit_release",
            Self::PqAuthority => "pq_authority",
            Self::PrivacyBoundary => "privacy_boundary",
            Self::ObservedReceipt => "observed_receipt",
            Self::LiveFeed => "live_feed",
            Self::LiquidityReserve => "liquidity_reserve",
            Self::ChallengeWindow => "challenge_window",
            Self::ReleaseBlocker => "release_blocker",
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::WalletRecovery => "Wallet recovery",
            Self::ForcedExitRelease => "Forced-exit release",
            Self::PqAuthority => "PQ authority",
            Self::PrivacyBoundary => "Privacy boundary",
            Self::ObservedReceipt => "Observed receipt",
            Self::LiveFeed => "Live feed",
            Self::LiquidityReserve => "Liquidity reserve",
            Self::ChallengeWindow => "Challenge window",
            Self::ReleaseBlocker => "Release blocker",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum ExitAcceptanceStatus {
    Accepted,
    Conditional,
    Watch,
    Blocked,
}

impl ExitAcceptanceStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Conditional => "conditional",
            Self::Watch => "watch",
            Self::Blocked => "blocked",
        }
    }

    pub fn blocks_release(&self) -> bool {
        !matches!(self, Self::Accepted)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum ExitAcceptanceDecision {
    AcceptExit,
    HoldForEvidence,
    RejectClaim,
}

impl ExitAcceptanceDecision {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::AcceptExit => "accept_exit",
            Self::HoldForEvidence => "hold_for_evidence",
            Self::RejectClaim => "reject_claim",
        }
    }

    pub fn blocks_release(&self) -> bool {
        !matches!(self, Self::AcceptExit)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    pub chain_id: String,
    pub l2_reference_height: u64,
    pub monero_reference_height: u64,
    pub wallet_scan_window: u64,
    pub challenge_window_blocks: u64,
    pub min_monero_confirmations: u64,
    pub min_pq_quorum_bps: u64,
    pub max_metadata_units: u64,
    pub min_liquidity_coverage_bps: u64,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            l2_reference_height: 1_048_576,
            monero_reference_height: 3_241_200,
            wallet_scan_window: 720,
            challenge_window_blocks: 48,
            min_monero_confirmations: 18,
            min_pq_quorum_bps: 6_700,
            max_metadata_units: 12,
            min_liquidity_coverage_bps: 10_500,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "exit_acceptance_config",
            "chain_id": self.chain_id,
            "protocol_version": PROTOCOL_VERSION,
            "l2_reference_height": self.l2_reference_height,
            "monero_reference_height": self.monero_reference_height,
            "wallet_scan_window": self.wallet_scan_window,
            "challenge_window_blocks": self.challenge_window_blocks,
            "min_monero_confirmations": self.min_monero_confirmations,
            "min_pq_quorum_bps": self.min_pq_quorum_bps,
            "max_metadata_units": self.max_metadata_units,
            "min_liquidity_coverage_bps": self.min_liquidity_coverage_bps,
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "monero-l2-pq-bridge-exit-acceptance-config",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExitAcceptanceRequirement {
    pub lane: ExitAcceptanceLane,
    pub requirement_id: String,
    pub required_root: String,
    pub minimum_weight_bps: u64,
    pub release_critical: bool,
    pub evidence_kind: String,
    pub description: String,
}

impl ExitAcceptanceRequirement {
    pub fn new(
        config: &Config,
        lane: ExitAcceptanceLane,
        evidence_kind: &str,
        minimum_weight_bps: u64,
        release_critical: bool,
        description: &str,
    ) -> Self {
        let required_root = requirement_expected_root(config, &lane, evidence_kind);
        let requirement_id = domain_hash(
            "monero-l2-pq-bridge-exit-acceptance-requirement-id",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(lane.as_str()),
                HashPart::Str(evidence_kind),
                HashPart::Str(&required_root),
                HashPart::U64(minimum_weight_bps),
            ],
            16,
        );
        Self {
            lane,
            requirement_id,
            required_root,
            minimum_weight_bps,
            release_critical,
            evidence_kind: evidence_kind.to_string(),
            description: description.to_string(),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "exit_acceptance_requirement",
            "lane": self.lane.as_str(),
            "lane_label": self.lane.label(),
            "requirement_id": self.requirement_id,
            "required_root": self.required_root,
            "minimum_weight_bps": self.minimum_weight_bps,
            "release_critical": self.release_critical,
            "evidence_kind": self.evidence_kind,
            "description": self.description,
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "monero-l2-pq-bridge-exit-acceptance-requirement",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExitAcceptanceEvidence {
    pub lane: ExitAcceptanceLane,
    pub evidence_id: String,
    pub requirement_id: String,
    pub expected_root: String,
    pub supplied_root: String,
    pub evidence_weight_bps: u64,
    pub confidence_bps: u64,
    pub status: ExitAcceptanceStatus,
    pub decision: ExitAcceptanceDecision,
    pub release_blockers: u64,
    pub public_summary_root: String,
}

impl ExitAcceptanceEvidence {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "exit_acceptance_evidence",
            "lane": self.lane.as_str(),
            "lane_label": self.lane.label(),
            "evidence_id": self.evidence_id,
            "requirement_id": self.requirement_id,
            "expected_root": self.expected_root,
            "supplied_root": self.supplied_root,
            "evidence_weight_bps": self.evidence_weight_bps,
            "confidence_bps": self.confidence_bps,
            "status": self.status.as_str(),
            "decision": self.decision.as_str(),
            "release_blockers": self.release_blockers,
            "public_summary_root": self.public_summary_root,
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "monero-l2-pq-bridge-exit-acceptance-evidence",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExitAcceptanceMismatch {
    pub lane: ExitAcceptanceLane,
    pub mismatch_id: String,
    pub requirement_id: String,
    pub expected_root: String,
    pub supplied_root: String,
    pub code: String,
    pub severity_bps: u64,
    pub release_hold: String,
}

impl ExitAcceptanceMismatch {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "exit_acceptance_mismatch",
            "lane": self.lane.as_str(),
            "lane_label": self.lane.label(),
            "mismatch_id": self.mismatch_id,
            "requirement_id": self.requirement_id,
            "expected_root": self.expected_root,
            "supplied_root": self.supplied_root,
            "code": self.code,
            "severity_bps": self.severity_bps,
            "release_hold": self.release_hold,
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "monero-l2-pq-bridge-exit-acceptance-mismatch",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExitAcceptanceCounters {
    pub requirement_count: u64,
    pub evidence_count: u64,
    pub accepted_count: u64,
    pub conditional_count: u64,
    pub watch_count: u64,
    pub blocked_count: u64,
    pub mismatch_count: u64,
    pub release_blocker_count: u64,
    pub critical_hold_count: u64,
}

impl ExitAcceptanceCounters {
    pub fn from_records(
        requirements: &[ExitAcceptanceRequirement],
        evidence: &[ExitAcceptanceEvidence],
        mismatches: &[ExitAcceptanceMismatch],
    ) -> Self {
        let accepted_count = evidence
            .iter()
            .filter(|record| record.status == ExitAcceptanceStatus::Accepted)
            .count() as u64;
        let conditional_count = evidence
            .iter()
            .filter(|record| record.status == ExitAcceptanceStatus::Conditional)
            .count() as u64;
        let watch_count = evidence
            .iter()
            .filter(|record| record.status == ExitAcceptanceStatus::Watch)
            .count() as u64;
        let blocked_count = evidence
            .iter()
            .filter(|record| record.status == ExitAcceptanceStatus::Blocked)
            .count() as u64;
        let release_blocker_count = evidence
            .iter()
            .map(|record| record.release_blockers)
            .sum::<u64>();
        let critical_hold_count = requirements
            .iter()
            .filter(|requirement| {
                requirement.release_critical
                    && evidence.iter().any(|record| {
                        record.requirement_id == requirement.requirement_id
                            && record.decision.blocks_release()
                    })
            })
            .count() as u64;
        Self {
            requirement_count: requirements.len() as u64,
            evidence_count: evidence.len() as u64,
            accepted_count,
            conditional_count,
            watch_count,
            blocked_count,
            mismatch_count: mismatches.len() as u64,
            release_blocker_count,
            critical_hold_count,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "exit_acceptance_counters",
            "requirement_count": self.requirement_count,
            "evidence_count": self.evidence_count,
            "accepted_count": self.accepted_count,
            "conditional_count": self.conditional_count,
            "watch_count": self.watch_count,
            "blocked_count": self.blocked_count,
            "mismatch_count": self.mismatch_count,
            "release_blocker_count": self.release_blocker_count,
            "critical_hold_count": self.critical_hold_count,
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "monero-l2-pq-bridge-exit-acceptance-counters",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExitAcceptanceRoots {
    pub config_root: String,
    pub requirement_root: String,
    pub evidence_root: String,
    pub lane_status_root: String,
    pub mismatch_root: String,
    pub hold_root: String,
    pub public_decision_root: String,
    pub acceptance_root: String,
    pub manifest_id: String,
}

impl ExitAcceptanceRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "exit_acceptance_roots",
            "config_root": self.config_root,
            "requirement_root": self.requirement_root,
            "evidence_root": self.evidence_root,
            "lane_status_root": self.lane_status_root,
            "mismatch_root": self.mismatch_root,
            "hold_root": self.hold_root,
            "public_decision_root": self.public_decision_root,
            "acceptance_root": self.acceptance_root,
            "manifest_id": self.manifest_id,
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "monero-l2-pq-bridge-exit-acceptance-roots",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExitAcceptanceManifest {
    pub manifest_id: String,
    pub verdict: ExitAcceptanceDecision,
    pub counters: ExitAcceptanceCounters,
    pub roots: ExitAcceptanceRoots,
    pub release_holds: BTreeMap<String, String>,
}

impl ExitAcceptanceManifest {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "exit_acceptance_manifest",
            "manifest_id": self.manifest_id,
            "verdict": self.verdict.as_str(),
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
            "release_holds": self.release_holds,
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "monero-l2-pq-bridge-exit-acceptance-manifest",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub requirements: Vec<ExitAcceptanceRequirement>,
    pub evidence: Vec<ExitAcceptanceEvidence>,
    pub mismatches: Vec<ExitAcceptanceMismatch>,
    pub manifest: ExitAcceptanceManifest,
}

impl State {
    pub fn devnet() -> Self {
        let config = Config::devnet();
        let requirements = acceptance_requirements(&config);
        let evidence = acceptance_evidence(&config, &requirements);
        let mismatches = mismatch_records(&requirements, &evidence);
        let counters = ExitAcceptanceCounters::from_records(&requirements, &evidence, &mismatches);
        let release_holds = release_holds(&requirements, &evidence, &mismatches);
        let roots = acceptance_roots(
            &config,
            &requirements,
            &evidence,
            &mismatches,
            &release_holds,
        );
        let verdict = manifest_verdict(&counters, &release_holds);
        let manifest = ExitAcceptanceManifest {
            manifest_id: roots.manifest_id.clone(),
            verdict,
            counters,
            roots,
            release_holds,
        };
        Self {
            config,
            requirements,
            evidence,
            mismatches,
            manifest,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "exit_acceptance_evidence_manifest_state",
            "protocol_version": PROTOCOL_VERSION,
            "config": self.config.public_record(),
            "requirements": self
                .requirements
                .iter()
                .map(ExitAcceptanceRequirement::public_record)
                .collect::<Vec<_>>(),
            "evidence": self
                .evidence
                .iter()
                .map(ExitAcceptanceEvidence::public_record)
                .collect::<Vec<_>>(),
            "mismatches": self
                .mismatches
                .iter()
                .map(ExitAcceptanceMismatch::public_record)
                .collect::<Vec<_>>(),
            "manifest": self.manifest.public_record(),
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "monero-l2-pq-bridge-exit-acceptance-state",
            &[HashPart::Json(&self.public_record())],
            32,
        )
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

fn acceptance_requirements(config: &Config) -> Vec<ExitAcceptanceRequirement> {
    vec![
        ExitAcceptanceRequirement::new(
            config,
            ExitAcceptanceLane::WalletRecovery,
            "wallet_scan_export_and_recovered_note_bundle",
            9_500,
            true,
            "Wallet scan export must bind recovered notes, encrypted scan windows, and forced-exit claim roots.",
        ),
        ExitAcceptanceRequirement::new(
            config,
            ExitAcceptanceLane::ForcedExitRelease,
            "forced_exit_release_receipt_and_settlement_order",
            9_000,
            true,
            "Forced-exit release evidence must bind claim order, settlement target, and release receipt roots.",
        ),
        ExitAcceptanceRequirement::new(
            config,
            ExitAcceptanceLane::PqAuthority,
            "pq_watcher_quorum_and_withdrawal_authority",
            config.min_pq_quorum_bps,
            true,
            "PQ authority must bind watcher quorum, withdrawal authorization, and key epoch continuity.",
        ),
        ExitAcceptanceRequirement::new(
            config,
            ExitAcceptanceLane::PrivacyBoundary,
            "privacy_budget_and_public_disclosure_bounds",
            9_000,
            true,
            "Exit evidence must preserve committed private fields while exposing only bounded public roots.",
        ),
        ExitAcceptanceRequirement::new(
            config,
            ExitAcceptanceLane::ObservedReceipt,
            "observed_receipt_conformance_roots",
            9_000,
            true,
            "Observed receipt roots must match the expected vertical-slice receipt contract.",
        ),
        ExitAcceptanceRequirement::new(
            config,
            ExitAcceptanceLane::LiveFeed,
            "live_monero_header_and_feed_observation_roots",
            8_500,
            true,
            "Live feed roots must bind Monero finality, deposit lock observation, and watcher evidence.",
        ),
        ExitAcceptanceRequirement::new(
            config,
            ExitAcceptanceLane::LiquidityReserve,
            "reserve_coverage_and_release_liquidity_roots",
            config.min_liquidity_coverage_bps,
            true,
            "Reserve roots must prove enough release liquidity for the forced exit before release is accepted.",
        ),
        ExitAcceptanceRequirement::new(
            config,
            ExitAcceptanceLane::ChallengeWindow,
            "challenge_window_closure_and_dispute_resolution",
            9_000,
            true,
            "Challenge-window evidence must prove disputes are closed or that a valid timeout path applies.",
        ),
        ExitAcceptanceRequirement::new(
            config,
            ExitAcceptanceLane::ReleaseBlocker,
            "release_blocker_clearance_surface",
            10_000,
            true,
            "Release blockers must be cleared or intentionally hold the acceptance decision closed.",
        ),
    ]
}

fn acceptance_evidence(
    config: &Config,
    requirements: &[ExitAcceptanceRequirement],
) -> Vec<ExitAcceptanceEvidence> {
    requirements
        .iter()
        .map(|requirement| {
            let supplied_root = supplied_evidence_root(config, requirement);
            let status = status_for(requirement, &supplied_root);
            let decision = decision_for(&status, requirement);
            let release_blockers = release_blockers_for(&status, requirement);
            let public_summary_root =
                evidence_summary_root(config, requirement, &supplied_root, &status, &decision);
            let evidence_id = domain_hash(
                "monero-l2-pq-bridge-exit-acceptance-evidence-id",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(requirement.lane.as_str()),
                    HashPart::Str(&requirement.requirement_id),
                    HashPart::Str(&supplied_root),
                    HashPart::Str(status.as_str()),
                    HashPart::Str(decision.as_str()),
                ],
                16,
            );
            ExitAcceptanceEvidence {
                lane: requirement.lane.clone(),
                evidence_id,
                requirement_id: requirement.requirement_id.clone(),
                expected_root: requirement.required_root.clone(),
                supplied_root,
                evidence_weight_bps: evidence_weight_for(requirement),
                confidence_bps: confidence_for(requirement),
                status,
                decision,
                release_blockers,
                public_summary_root,
            }
        })
        .collect()
}

fn requirement_expected_root(
    config: &Config,
    lane: &ExitAcceptanceLane,
    evidence_kind: &str,
) -> String {
    domain_hash(
        "monero-l2-pq-bridge-exit-acceptance-required-root",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(lane.as_str()),
            HashPart::Str(evidence_kind),
            HashPart::U64(config.l2_reference_height),
            HashPart::U64(config.monero_reference_height),
            HashPart::U64(config.challenge_window_blocks),
            HashPart::U64(config.min_monero_confirmations),
        ],
        32,
    )
}

fn supplied_evidence_root(config: &Config, requirement: &ExitAcceptanceRequirement) -> String {
    match requirement.lane {
        ExitAcceptanceLane::WalletRecovery
        | ExitAcceptanceLane::PqAuthority
        | ExitAcceptanceLane::PrivacyBoundary
        | ExitAcceptanceLane::ObservedReceipt => requirement.required_root.clone(),
        ExitAcceptanceLane::ForcedExitRelease => domain_hash(
            "monero-l2-pq-bridge-exit-acceptance-supplied-runtime-release-root",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(requirement.lane.as_str()),
                HashPart::Str(&requirement.requirement_id),
                HashPart::U64(config.l2_reference_height),
            ],
            32,
        ),
        ExitAcceptanceLane::LiveFeed => domain_hash(
            "monero-l2-pq-bridge-exit-acceptance-supplied-live-feed-root",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(requirement.lane.as_str()),
                HashPart::Str(&requirement.requirement_id),
                HashPart::U64(config.monero_reference_height),
            ],
            32,
        ),
        ExitAcceptanceLane::LiquidityReserve => domain_hash(
            "monero-l2-pq-bridge-exit-acceptance-supplied-reserve-root",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(requirement.lane.as_str()),
                HashPart::Str(&requirement.requirement_id),
                HashPart::U64(config.min_liquidity_coverage_bps - 250),
            ],
            32,
        ),
        ExitAcceptanceLane::ChallengeWindow => domain_hash(
            "monero-l2-pq-bridge-exit-acceptance-supplied-challenge-root",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(requirement.lane.as_str()),
                HashPart::Str(&requirement.requirement_id),
                HashPart::U64(config.challenge_window_blocks - 4),
            ],
            32,
        ),
        ExitAcceptanceLane::ReleaseBlocker => domain_hash(
            "monero-l2-pq-bridge-exit-acceptance-supplied-release-blocker-root",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(requirement.lane.as_str()),
                HashPart::Str(&requirement.requirement_id),
                HashPart::Str("runtime-and-audit-hold-open"),
            ],
            32,
        ),
    }
}

fn status_for(
    requirement: &ExitAcceptanceRequirement,
    supplied_root: &str,
) -> ExitAcceptanceStatus {
    if supplied_root == requirement.required_root && requirement.minimum_weight_bps >= 9_000 {
        ExitAcceptanceStatus::Accepted
    } else if supplied_root == requirement.required_root {
        ExitAcceptanceStatus::Conditional
    } else {
        match requirement.lane {
            ExitAcceptanceLane::ForcedExitRelease
            | ExitAcceptanceLane::LiveFeed
            | ExitAcceptanceLane::ReleaseBlocker => ExitAcceptanceStatus::Blocked,
            ExitAcceptanceLane::LiquidityReserve | ExitAcceptanceLane::ChallengeWindow => {
                ExitAcceptanceStatus::Watch
            }
            _ => ExitAcceptanceStatus::Conditional,
        }
    }
}

fn decision_for(
    status: &ExitAcceptanceStatus,
    requirement: &ExitAcceptanceRequirement,
) -> ExitAcceptanceDecision {
    match status {
        ExitAcceptanceStatus::Accepted => ExitAcceptanceDecision::AcceptExit,
        ExitAcceptanceStatus::Blocked => ExitAcceptanceDecision::HoldForEvidence,
        ExitAcceptanceStatus::Conditional | ExitAcceptanceStatus::Watch => {
            if requirement.release_critical {
                ExitAcceptanceDecision::HoldForEvidence
            } else {
                ExitAcceptanceDecision::AcceptExit
            }
        }
    }
}

fn release_blockers_for(
    status: &ExitAcceptanceStatus,
    requirement: &ExitAcceptanceRequirement,
) -> u64 {
    match status {
        ExitAcceptanceStatus::Accepted => 0,
        ExitAcceptanceStatus::Conditional => {
            if requirement.release_critical {
                1
            } else {
                0
            }
        }
        ExitAcceptanceStatus::Watch => 1,
        ExitAcceptanceStatus::Blocked => 2,
    }
}

fn evidence_weight_for(requirement: &ExitAcceptanceRequirement) -> u64 {
    match requirement.lane {
        ExitAcceptanceLane::WalletRecovery => 9_800,
        ExitAcceptanceLane::ForcedExitRelease => 8_200,
        ExitAcceptanceLane::PqAuthority => 7_200,
        ExitAcceptanceLane::PrivacyBoundary => 9_300,
        ExitAcceptanceLane::ObservedReceipt => 9_100,
        ExitAcceptanceLane::LiveFeed => 7_900,
        ExitAcceptanceLane::LiquidityReserve => 10_200,
        ExitAcceptanceLane::ChallengeWindow => 8_600,
        ExitAcceptanceLane::ReleaseBlocker => 6_500,
    }
}

fn confidence_for(requirement: &ExitAcceptanceRequirement) -> u64 {
    match requirement.lane {
        ExitAcceptanceLane::WalletRecovery => 9_400,
        ExitAcceptanceLane::ForcedExitRelease => 7_600,
        ExitAcceptanceLane::PqAuthority => 8_900,
        ExitAcceptanceLane::PrivacyBoundary => 9_100,
        ExitAcceptanceLane::ObservedReceipt => 8_800,
        ExitAcceptanceLane::LiveFeed => 7_300,
        ExitAcceptanceLane::LiquidityReserve => 8_100,
        ExitAcceptanceLane::ChallengeWindow => 8_000,
        ExitAcceptanceLane::ReleaseBlocker => 6_800,
    }
}

fn evidence_summary_root(
    config: &Config,
    requirement: &ExitAcceptanceRequirement,
    supplied_root: &str,
    status: &ExitAcceptanceStatus,
    decision: &ExitAcceptanceDecision,
) -> String {
    let summary = json!({
        "lane": requirement.lane.as_str(),
        "requirement_id": requirement.requirement_id,
        "expected_root": requirement.required_root,
        "supplied_root": supplied_root,
        "status": status.as_str(),
        "decision": decision.as_str(),
        "l2_reference_height": config.l2_reference_height,
        "monero_reference_height": config.monero_reference_height,
    });
    domain_hash(
        "monero-l2-pq-bridge-exit-acceptance-evidence-summary",
        &[HashPart::Json(&summary)],
        32,
    )
}

fn mismatch_records(
    requirements: &[ExitAcceptanceRequirement],
    evidence: &[ExitAcceptanceEvidence],
) -> Vec<ExitAcceptanceMismatch> {
    requirements
        .iter()
        .filter_map(|requirement| {
            evidence
                .iter()
                .find(|record| record.requirement_id == requirement.requirement_id)
                .filter(|record| {
                    record.expected_root != record.supplied_root
                        || record.status.blocks_release()
                        || record.decision.blocks_release()
                })
                .map(|record| {
                    let code = mismatch_code(requirement, record);
                    let release_hold = release_hold_for(requirement, record);
                    let mismatch_id = domain_hash(
                        "monero-l2-pq-bridge-exit-acceptance-mismatch-id",
                        &[
                            HashPart::Str(CHAIN_ID),
                            HashPart::Str(PROTOCOL_VERSION),
                            HashPart::Str(requirement.lane.as_str()),
                            HashPart::Str(&requirement.requirement_id),
                            HashPart::Str(&record.supplied_root),
                            HashPart::Str(&code),
                        ],
                        16,
                    );
                    ExitAcceptanceMismatch {
                        lane: requirement.lane.clone(),
                        mismatch_id,
                        requirement_id: requirement.requirement_id.clone(),
                        expected_root: record.expected_root.clone(),
                        supplied_root: record.supplied_root.clone(),
                        code,
                        severity_bps: mismatch_severity(requirement, record),
                        release_hold,
                    }
                })
        })
        .collect()
}

fn mismatch_code(
    requirement: &ExitAcceptanceRequirement,
    record: &ExitAcceptanceEvidence,
) -> String {
    if record.expected_root != record.supplied_root {
        format!("{}_root_mismatch", requirement.lane.as_str())
    } else if record.status.blocks_release() {
        format!("{}_status_holds_release", requirement.lane.as_str())
    } else if record.decision.blocks_release() {
        format!("{}_decision_holds_release", requirement.lane.as_str())
    } else {
        format!("{}_accepted", requirement.lane.as_str())
    }
}

fn mismatch_severity(
    requirement: &ExitAcceptanceRequirement,
    record: &ExitAcceptanceEvidence,
) -> u64 {
    let root_penalty = if record.expected_root == record.supplied_root {
        0
    } else {
        3_000
    };
    let status_penalty = match record.status {
        ExitAcceptanceStatus::Accepted => 0,
        ExitAcceptanceStatus::Conditional => 1_000,
        ExitAcceptanceStatus::Watch => 1_500,
        ExitAcceptanceStatus::Blocked => 4_000,
    };
    let critical_penalty = if requirement.release_critical {
        1_000
    } else {
        0
    };
    (root_penalty + status_penalty + critical_penalty).min(10_000)
}

fn release_hold_for(
    requirement: &ExitAcceptanceRequirement,
    record: &ExitAcceptanceEvidence,
) -> String {
    match requirement.lane {
        ExitAcceptanceLane::WalletRecovery => {
            "wallet recovery evidence must bind scan export, recovered notes, and claim roots"
                .to_string()
        }
        ExitAcceptanceLane::ForcedExitRelease => {
            "forced-exit release requires executable receipt evidence from the runtime harness"
                .to_string()
        }
        ExitAcceptanceLane::PqAuthority => {
            "PQ authority must bind watcher quorum and withdrawal authorization roots".to_string()
        }
        ExitAcceptanceLane::PrivacyBoundary => {
            "privacy boundary must keep wallet and receipt metadata within committed limits"
                .to_string()
        }
        ExitAcceptanceLane::ObservedReceipt => {
            "observed receipt roots must match the expected receipt conformance surface".to_string()
        }
        ExitAcceptanceLane::LiveFeed => {
            "live Monero and watcher feed roots must be exercised by the runtime harness"
                .to_string()
        }
        ExitAcceptanceLane::LiquidityReserve => {
            "release liquidity must exceed the forced-exit coverage floor".to_string()
        }
        ExitAcceptanceLane::ChallengeWindow => {
            "challenge window must be closed or timeout evidence must be accepted".to_string()
        }
        ExitAcceptanceLane::ReleaseBlocker => format!(
            "release blocker remains active with status {} and decision {}",
            record.status.as_str(),
            record.decision.as_str()
        ),
    }
}

fn release_holds(
    requirements: &[ExitAcceptanceRequirement],
    evidence: &[ExitAcceptanceEvidence],
    mismatches: &[ExitAcceptanceMismatch],
) -> BTreeMap<String, String> {
    let mut holds = BTreeMap::new();
    holds.insert(
        "production_readiness".to_string(),
        "cargo/runtime execution, live feed substitution, and independent audits remain deferred"
            .to_string(),
    );
    holds.insert(
        "exit_acceptance_scope".to_string(),
        "this manifest records deterministic accept/block evidence and does not release value by itself"
            .to_string(),
    );
    for mismatch in mismatches {
        holds.insert(
            format!("mismatch_{}", mismatch.lane.as_str()),
            mismatch.release_hold.clone(),
        );
    }
    for requirement in requirements {
        if let Some(record) = evidence
            .iter()
            .find(|item| item.requirement_id == requirement.requirement_id)
        {
            if record.decision.blocks_release() {
                holds.insert(
                    format!("lane_{}", requirement.lane.as_str()),
                    release_hold_for(requirement, record),
                );
            }
        }
    }
    holds
}

fn acceptance_roots(
    config: &Config,
    requirements: &[ExitAcceptanceRequirement],
    evidence: &[ExitAcceptanceEvidence],
    mismatches: &[ExitAcceptanceMismatch],
    release_holds: &BTreeMap<String, String>,
) -> ExitAcceptanceRoots {
    let config_root = config.state_root();
    let requirement_root = requirement_root(requirements);
    let evidence_root = evidence_root(evidence);
    let lane_status_root = lane_status_root(evidence);
    let mismatch_root = mismatch_root(mismatches);
    let hold_root = hold_root(release_holds);
    let public_decision_root = public_decision_root(evidence, release_holds);
    let acceptance_root = domain_hash(
        "monero-l2-pq-bridge-exit-acceptance-root",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(&config_root),
            HashPart::Str(&requirement_root),
            HashPart::Str(&evidence_root),
            HashPart::Str(&lane_status_root),
            HashPart::Str(&mismatch_root),
            HashPart::Str(&hold_root),
            HashPart::Str(&public_decision_root),
        ],
        32,
    );
    let manifest_id = domain_hash(
        "monero-l2-pq-bridge-exit-acceptance-manifest-id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::U64(config.l2_reference_height),
            HashPart::U64(config.monero_reference_height),
            HashPart::Str(&acceptance_root),
            HashPart::Str(&hold_root),
        ],
        16,
    );
    ExitAcceptanceRoots {
        config_root,
        requirement_root,
        evidence_root,
        lane_status_root,
        mismatch_root,
        hold_root,
        public_decision_root,
        acceptance_root,
        manifest_id,
    }
}

fn requirement_root(requirements: &[ExitAcceptanceRequirement]) -> String {
    merkle_root(
        "monero-l2-pq-bridge-exit-acceptance-requirements",
        &requirements
            .iter()
            .map(ExitAcceptanceRequirement::public_record)
            .collect::<Vec<_>>(),
    )
}

fn evidence_root(evidence: &[ExitAcceptanceEvidence]) -> String {
    merkle_root(
        "monero-l2-pq-bridge-exit-acceptance-evidence",
        &evidence
            .iter()
            .map(ExitAcceptanceEvidence::public_record)
            .collect::<Vec<_>>(),
    )
}

fn lane_status_root(evidence: &[ExitAcceptanceEvidence]) -> String {
    let leaves = evidence
        .iter()
        .map(|record| {
            json!({
                "lane": record.lane.as_str(),
                "status": record.status.as_str(),
                "decision": record.decision.as_str(),
                "release_blockers": record.release_blockers,
                "evidence_root": record.state_root(),
            })
        })
        .collect::<Vec<_>>();
    merkle_root("monero-l2-pq-bridge-exit-acceptance-lane-status", &leaves)
}

fn mismatch_root(mismatches: &[ExitAcceptanceMismatch]) -> String {
    merkle_root(
        "monero-l2-pq-bridge-exit-acceptance-mismatches",
        &mismatches
            .iter()
            .map(ExitAcceptanceMismatch::public_record)
            .collect::<Vec<_>>(),
    )
}

fn hold_root(release_holds: &BTreeMap<String, String>) -> String {
    let leaves = release_holds
        .iter()
        .map(|(key, value)| json!({ "key": key, "value": value }))
        .collect::<Vec<_>>();
    merkle_root("monero-l2-pq-bridge-exit-acceptance-release-holds", &leaves)
}

fn public_decision_root(
    evidence: &[ExitAcceptanceEvidence],
    release_holds: &BTreeMap<String, String>,
) -> String {
    let leaves = evidence
        .iter()
        .map(|record| {
            json!({
                "lane": record.lane.as_str(),
                "decision": record.decision.as_str(),
                "status": record.status.as_str(),
                "hold_count": release_holds.len() as u64,
                "summary_root": record.public_summary_root,
            })
        })
        .collect::<Vec<_>>();
    merkle_root(
        "monero-l2-pq-bridge-exit-acceptance-public-decisions",
        &leaves,
    )
}

fn manifest_verdict(
    counters: &ExitAcceptanceCounters,
    release_holds: &BTreeMap<String, String>,
) -> ExitAcceptanceDecision {
    if counters.critical_hold_count == 0
        && counters.blocked_count == 0
        && counters.mismatch_count == 0
        && release_holds.len() <= 1
    {
        ExitAcceptanceDecision::AcceptExit
    } else if counters.blocked_count > 0 || counters.critical_hold_count > 0 {
        ExitAcceptanceDecision::HoldForEvidence
    } else {
        ExitAcceptanceDecision::RejectClaim
    }
}
