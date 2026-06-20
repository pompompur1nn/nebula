use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalRuntimeEvidenceAcceptanceRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_RUNTIME_EVIDENCE_ACCEPTANCE_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-monero-l2-pq-bridge-exit-canonical-runtime-evidence-acceptance-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_RUNTIME_EVIDENCE_ACCEPTANCE_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-canonical-runtime-evidence-acceptance-public-record-v1";
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";

const DEVNET_HEIGHT: u64 = 43_280;
const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
const DEVNET_L2_NETWORK: &str = "nebula-devnet";
const DEVNET_ASSET_ID: &str = "wxmr-devnet";
const DEVNET_ACCEPTANCE_THRESHOLD_BPS: u64 = 8_000;
const DEVNET_MIN_MONERO_CONFIRMATIONS: u64 = 20;
const DEVNET_MIN_PRIVACY_SET_SIZE: u64 = 128;
const DEVNET_MAX_DISCLOSURE_UNITS: u64 = 8;
const DEVNET_MIN_PQ_SECURITY_BITS: u64 = 256;
const DEVNET_MIN_RESERVE_COVERAGE_BPS: u64 = 10_250;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceLane {
    DepositLock,
    PrivateStateTransition,
    SettlementExit,
    ChallengeWindow,
    PqAuthority,
    PrivacyBudget,
    ReserveCoverage,
    WalletRecovery,
    RuntimeGate,
    CargoGate,
    ReleaseBlocker,
}

impl EvidenceLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DepositLock => "deposit_lock",
            Self::PrivateStateTransition => "private_state_transition",
            Self::SettlementExit => "settlement_exit",
            Self::ChallengeWindow => "challenge_window",
            Self::PqAuthority => "pq_authority",
            Self::PrivacyBudget => "privacy_budget",
            Self::ReserveCoverage => "reserve_coverage",
            Self::WalletRecovery => "wallet_recovery",
            Self::RuntimeGate => "runtime_gate",
            Self::CargoGate => "cargo_gate",
            Self::ReleaseBlocker => "release_blocker",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceVerdict {
    Accepted,
    Rejected,
}

impl EvidenceVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    pub chain_id: String,
    pub monero_network: String,
    pub l2_network: String,
    pub asset_id: String,
    pub evaluation_height: u64,
    pub acceptance_threshold_bps: u64,
    pub min_monero_confirmations: u64,
    pub min_privacy_set_size: u64,
    pub max_disclosure_units: u64,
    pub min_pq_security_bits: u64,
    pub min_reserve_coverage_bps: u64,
    pub runtime_gate_label: String,
    pub cargo_gate_label: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RequiredRoots {
    pub deposit_lock_root: String,
    pub private_state_transition_root: String,
    pub settlement_exit_root: String,
    pub challenge_window_root: String,
    pub pq_authority_root: String,
    pub privacy_budget_root: String,
    pub reserve_coverage_root: String,
    pub wallet_recovery_root: String,
    pub runtime_gate_root: String,
    pub cargo_gate_root: String,
    pub release_blocker_root: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AcceptanceThresholds {
    pub required_lane_count: u64,
    pub accepted_lane_count: u64,
    pub threshold_bps: u64,
    pub observed_bps: u64,
    pub min_monero_confirmations: u64,
    pub min_privacy_set_size: u64,
    pub max_disclosure_units: u64,
    pub min_pq_security_bits: u64,
    pub min_reserve_coverage_bps: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GatePlaceholder {
    pub gate_id: String,
    pub lane: EvidenceLane,
    pub required: bool,
    pub available: bool,
    pub replacement_source: String,
    pub acceptance_note: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AcceptanceSignals {
    pub monero_confirmations: u64,
    pub privacy_set_size: u64,
    pub disclosure_units: u64,
    pub pq_security_bits: u64,
    pub reserve_coverage_bps: u64,
    pub wallet_export_verified: bool,
    pub runtime_gate_satisfied: bool,
    pub cargo_gate_satisfied: bool,
    pub production_release_blocked: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RuntimeEvidence {
    pub evidence_id: String,
    pub lane: EvidenceLane,
    pub subject: String,
    pub source_runtime: String,
    pub required_root: String,
    pub observed_root: String,
    pub signals: AcceptanceSignals,
    pub rejection_reason: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EvidenceDecision {
    pub evidence_id: String,
    pub lane: EvidenceLane,
    pub verdict: EvidenceVerdict,
    pub decision_root: String,
    pub reason: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProductionReleaseBlocker {
    pub blocker_id: String,
    pub owner_lane: EvidenceLane,
    pub severity: String,
    pub cleared: bool,
    pub release_note: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct State {
    pub protocol_version: String,
    pub schema_version: String,
    pub hash_suite: String,
    pub config: Config,
    pub required_roots: RequiredRoots,
    pub thresholds: AcceptanceThresholds,
    pub runtime_gate_placeholders: Vec<GatePlaceholder>,
    pub cargo_gate_placeholders: Vec<GatePlaceholder>,
    pub evidence: Vec<RuntimeEvidence>,
    pub decisions: Vec<EvidenceDecision>,
    pub production_release_blockers: Vec<ProductionReleaseBlocker>,
    pub accepted_decision_root: String,
    pub rejected_decision_root: String,
    pub production_blocker_root: String,
}

impl State {
    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "config": self.config,
            "required_roots": self.required_roots,
            "thresholds": self.thresholds,
            "runtime_gate_placeholders": self.runtime_gate_placeholders,
            "cargo_gate_placeholders": self.cargo_gate_placeholders,
            "evidence": self.evidence,
            "decisions": self.decisions,
            "production_release_blockers": self.production_release_blockers,
            "accepted_decision_root": self.accepted_decision_root,
            "rejected_decision_root": self.rejected_decision_root,
            "production_blocker_root": self.production_blocker_root,
            "state_root": self.state_root(),
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-RUNTIME-EVIDENCE-ACCEPTANCE-STATE",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Json(&self.public_record_without_root()),
            ],
            32,
        )
    }

    fn public_record_without_root(&self) -> Value {
        json!({
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "config": self.config,
            "required_roots": self.required_roots,
            "thresholds": self.thresholds,
            "runtime_gate_placeholders": self.runtime_gate_placeholders,
            "cargo_gate_placeholders": self.cargo_gate_placeholders,
            "evidence": self.evidence,
            "decisions": self.decisions,
            "production_release_blockers": self.production_release_blockers,
            "accepted_decision_root": self.accepted_decision_root,
            "rejected_decision_root": self.rejected_decision_root,
            "production_blocker_root": self.production_blocker_root,
        })
    }

    pub fn accept_runtime_evidence(
        &self,
        evidence: &RuntimeEvidence,
    ) -> MoneroL2PqBridgeExitCanonicalRuntimeEvidenceAcceptanceRuntimeResult<EvidenceDecision> {
        let expected_root = self.required_root_for_lane(evidence.lane);
        if evidence.required_root != expected_root {
            return Ok(decision(
                evidence,
                EvidenceVerdict::Rejected,
                "required root is not the canonical lane root",
            ));
        }
        if evidence.observed_root != evidence.required_root {
            return Ok(decision(
                evidence,
                EvidenceVerdict::Rejected,
                "observed evidence root diverges from required root",
            ));
        }
        if evidence.signals.monero_confirmations < self.config.min_monero_confirmations {
            return Ok(decision(
                evidence,
                EvidenceVerdict::Rejected,
                "monero confirmation depth below acceptance threshold",
            ));
        }
        if evidence.signals.privacy_set_size < self.config.min_privacy_set_size {
            return Ok(decision(
                evidence,
                EvidenceVerdict::Rejected,
                "privacy set below acceptance threshold",
            ));
        }
        if evidence.signals.disclosure_units > self.config.max_disclosure_units {
            return Ok(decision(
                evidence,
                EvidenceVerdict::Rejected,
                "privacy disclosure budget exceeded",
            ));
        }
        if evidence.signals.pq_security_bits < self.config.min_pq_security_bits {
            return Ok(decision(
                evidence,
                EvidenceVerdict::Rejected,
                "post quantum security margin below threshold",
            ));
        }
        if evidence.signals.reserve_coverage_bps < self.config.min_reserve_coverage_bps {
            return Ok(decision(
                evidence,
                EvidenceVerdict::Rejected,
                "reserve coverage below release threshold",
            ));
        }
        if !evidence.signals.wallet_export_verified {
            return Ok(decision(
                evidence,
                EvidenceVerdict::Rejected,
                "wallet recovery export is not verified",
            ));
        }
        if !evidence.signals.runtime_gate_satisfied {
            return Ok(decision(
                evidence,
                EvidenceVerdict::Rejected,
                "runtime gate evidence is absent",
            ));
        }
        if !evidence.signals.cargo_gate_satisfied {
            return Ok(decision(
                evidence,
                EvidenceVerdict::Rejected,
                "cargo gate evidence is absent",
            ));
        }
        if evidence.signals.production_release_blocked {
            return Ok(decision(
                evidence,
                EvidenceVerdict::Rejected,
                "production release blocker remains open",
            ));
        }

        Ok(decision(
            evidence,
            EvidenceVerdict::Accepted,
            "runtime evidence satisfies canonical bridge exit acceptance",
        ))
    }

    fn required_root_for_lane(&self, lane: EvidenceLane) -> String {
        match lane {
            EvidenceLane::DepositLock => self.required_roots.deposit_lock_root.clone(),
            EvidenceLane::PrivateStateTransition => {
                self.required_roots.private_state_transition_root.clone()
            }
            EvidenceLane::SettlementExit => self.required_roots.settlement_exit_root.clone(),
            EvidenceLane::ChallengeWindow => self.required_roots.challenge_window_root.clone(),
            EvidenceLane::PqAuthority => self.required_roots.pq_authority_root.clone(),
            EvidenceLane::PrivacyBudget => self.required_roots.privacy_budget_root.clone(),
            EvidenceLane::ReserveCoverage => self.required_roots.reserve_coverage_root.clone(),
            EvidenceLane::WalletRecovery => self.required_roots.wallet_recovery_root.clone(),
            EvidenceLane::RuntimeGate => self.required_roots.runtime_gate_root.clone(),
            EvidenceLane::CargoGate => self.required_roots.cargo_gate_root.clone(),
            EvidenceLane::ReleaseBlocker => self.required_roots.release_blocker_root.clone(),
        }
    }
}

impl RuntimeEvidence {
    pub fn public_record(&self) -> Value {
        json!({
            "evidence_id": self.evidence_id,
            "lane": self.lane,
            "subject": self.subject,
            "source_runtime": self.source_runtime,
            "required_root": self.required_root,
            "observed_root": self.observed_root,
            "signals": self.signals,
            "rejection_reason": self.rejection_reason,
        })
    }
}

impl EvidenceDecision {
    pub fn public_record(&self) -> Value {
        json!({
            "evidence_id": self.evidence_id,
            "lane": self.lane,
            "verdict": self.verdict,
            "decision_root": self.decision_root,
            "reason": self.reason,
        })
    }
}

impl ProductionReleaseBlocker {
    pub fn public_record(&self) -> Value {
        json!({
            "blocker_id": self.blocker_id,
            "owner_lane": self.owner_lane,
            "severity": self.severity,
            "cleared": self.cleared,
            "release_note": self.release_note,
        })
    }
}

pub fn devnet() -> State {
    let config = Config {
        chain_id: CHAIN_ID.to_string(),
        monero_network: DEVNET_MONERO_NETWORK.to_string(),
        l2_network: DEVNET_L2_NETWORK.to_string(),
        asset_id: DEVNET_ASSET_ID.to_string(),
        evaluation_height: DEVNET_HEIGHT,
        acceptance_threshold_bps: DEVNET_ACCEPTANCE_THRESHOLD_BPS,
        min_monero_confirmations: DEVNET_MIN_MONERO_CONFIRMATIONS,
        min_privacy_set_size: DEVNET_MIN_PRIVACY_SET_SIZE,
        max_disclosure_units: DEVNET_MAX_DISCLOSURE_UNITS,
        min_pq_security_bits: DEVNET_MIN_PQ_SECURITY_BITS,
        min_reserve_coverage_bps: DEVNET_MIN_RESERVE_COVERAGE_BPS,
        runtime_gate_label: "runtime-evidence-acceptance".to_string(),
        cargo_gate_label: "cargo-runtime-evidence-acceptance".to_string(),
    };
    let required_roots = required_roots();
    let runtime_gate_placeholders = vec![gate_placeholder(
        "runtime-gate-devnet-acceptance",
        EvidenceLane::RuntimeGate,
        true,
        true,
        "heavy-gate-execution-receipt-runtime",
    )];
    let cargo_gate_placeholders = vec![gate_placeholder(
        "cargo-gate-devnet-acceptance",
        EvidenceLane::CargoGate,
        true,
        true,
        "cargo-runtime-harness-adapter-runtime",
    )];
    let production_release_blockers = vec![
        blocker(
            "mainnet-audit-signoff",
            EvidenceLane::ReleaseBlocker,
            "critical",
            false,
            "external audit signature packet must be attached before production release",
        ),
        blocker(
            "reserve-attestation-mainnet-window",
            EvidenceLane::ReserveCoverage,
            "high",
            false,
            "reserve attestation uses devnet handoff roots only",
        ),
    ];
    let evidence = evidence_set(&required_roots);
    let decisions = evidence
        .iter()
        .map(|item| decide_devnet(item))
        .collect::<Vec<_>>();
    let accepted_records = decisions
        .iter()
        .filter(|decision| decision.verdict == EvidenceVerdict::Accepted)
        .map(EvidenceDecision::public_record)
        .collect::<Vec<_>>();
    let rejected_records = decisions
        .iter()
        .filter(|decision| decision.verdict == EvidenceVerdict::Rejected)
        .map(EvidenceDecision::public_record)
        .collect::<Vec<_>>();
    let accepted_count = accepted_records.len() as u64;
    let required_lane_count = evidence.len() as u64;
    let observed_bps = accepted_count * 10_000 / required_lane_count;
    let thresholds = AcceptanceThresholds {
        required_lane_count,
        accepted_lane_count: accepted_count,
        threshold_bps: DEVNET_ACCEPTANCE_THRESHOLD_BPS,
        observed_bps,
        min_monero_confirmations: DEVNET_MIN_MONERO_CONFIRMATIONS,
        min_privacy_set_size: DEVNET_MIN_PRIVACY_SET_SIZE,
        max_disclosure_units: DEVNET_MAX_DISCLOSURE_UNITS,
        min_pq_security_bits: DEVNET_MIN_PQ_SECURITY_BITS,
        min_reserve_coverage_bps: DEVNET_MIN_RESERVE_COVERAGE_BPS,
    };
    let blocker_records = production_release_blockers
        .iter()
        .map(ProductionReleaseBlocker::public_record)
        .collect::<Vec<_>>();

    State {
        protocol_version: PROTOCOL_VERSION.to_string(),
        schema_version: SCHEMA_VERSION.to_string(),
        hash_suite: HASH_SUITE.to_string(),
        config,
        required_roots,
        thresholds,
        runtime_gate_placeholders,
        cargo_gate_placeholders,
        evidence,
        decisions,
        production_release_blockers,
        accepted_decision_root: merkle_root(
            "RUNTIME-EVIDENCE-ACCEPTED-DECISION",
            &accepted_records,
        ),
        rejected_decision_root: merkle_root(
            "RUNTIME-EVIDENCE-REJECTED-DECISION",
            &rejected_records,
        ),
        production_blocker_root: merkle_root(
            "RUNTIME-EVIDENCE-PRODUCTION-BLOCKER",
            &blocker_records,
        ),
    }
}

pub fn public_record() -> Value {
    devnet().public_record()
}

pub fn state_root() -> String {
    devnet().state_root()
}

fn required_roots() -> RequiredRoots {
    RequiredRoots {
        deposit_lock_root: lane_root(EvidenceLane::DepositLock, "deposit-lock-vector"),
        private_state_transition_root: lane_root(
            EvidenceLane::PrivateStateTransition,
            "private-state-transition-replay",
        ),
        settlement_exit_root: lane_root(EvidenceLane::SettlementExit, "settlement-receipt-replay"),
        challenge_window_root: lane_root(EvidenceLane::ChallengeWindow, "challenge-dispute-replay"),
        pq_authority_root: lane_root(EvidenceLane::PqAuthority, "pq-release-authority-quorum"),
        privacy_budget_root: lane_root(EvidenceLane::PrivacyBudget, "privacy-budget-regression"),
        reserve_coverage_root: lane_root(EvidenceLane::ReserveCoverage, "reserve-proof-handoff"),
        wallet_recovery_root: lane_root(EvidenceLane::WalletRecovery, "wallet-claim-export"),
        runtime_gate_root: lane_root(EvidenceLane::RuntimeGate, "heavy-gate-execution-receipt"),
        cargo_gate_root: lane_root(EvidenceLane::CargoGate, "cargo-runtime-harness-adapter"),
        release_blocker_root: lane_root(
            EvidenceLane::ReleaseBlocker,
            "production-blocker-burn-down",
        ),
    }
}

fn evidence_set(required_roots: &RequiredRoots) -> Vec<RuntimeEvidence> {
    vec![
        accepted_evidence(
            "deposit-lock-accepted",
            EvidenceLane::DepositLock,
            "canonical deposit lock has sufficient Monero depth",
            "canonical-deposit-lock-vector-runtime",
            &required_roots.deposit_lock_root,
        ),
        accepted_evidence(
            "private-state-accepted",
            EvidenceLane::PrivateStateTransition,
            "private note transition binds input nullifier and output commitments",
            "canonical-private-state-transition-replay-runtime",
            &required_roots.private_state_transition_root,
        ),
        accepted_evidence(
            "settlement-exit-accepted",
            EvidenceLane::SettlementExit,
            "settlement receipt binds claim queue and exit note burn",
            "canonical-settlement-receipt-replay-runtime",
            &required_roots.settlement_exit_root,
        ),
        accepted_evidence(
            "challenge-window-accepted",
            EvidenceLane::ChallengeWindow,
            "challenge lane expired without live dispute",
            "canonical-challenge-dispute-replay-runtime",
            &required_roots.challenge_window_root,
        ),
        accepted_evidence(
            "pq-authority-accepted",
            EvidenceLane::PqAuthority,
            "hybrid post quantum quorum signs the release transcript",
            "canonical-pq-release-authority-quorum-replay-runtime",
            &required_roots.pq_authority_root,
        ),
        accepted_evidence(
            "privacy-budget-accepted",
            EvidenceLane::PrivacyBudget,
            "privacy budget remains below disclosure ceiling",
            "canonical-privacy-budget-regression-runtime",
            &required_roots.privacy_budget_root,
        ),
        accepted_evidence(
            "reserve-coverage-accepted",
            EvidenceLane::ReserveCoverage,
            "reserve handoff exceeds covered liability threshold",
            "canonical-reserve-proof-handoff-manifest-runtime",
            &required_roots.reserve_coverage_root,
        ),
        accepted_evidence(
            "wallet-recovery-accepted",
            EvidenceLane::WalletRecovery,
            "wallet export reconstructs claim payload locally",
            "canonical-wallet-claim-export-manifest-runtime",
            &required_roots.wallet_recovery_root,
        ),
        rejected_evidence(
            "runtime-gate-rejected",
            EvidenceLane::RuntimeGate,
            "runtime gate placeholder records live adapter substitution",
            "canonical-heavy-gate-execution-receipt-runtime",
            &required_roots.runtime_gate_root,
            "runtime gate accepted on devnet but production adapter remains gated",
        ),
        rejected_evidence(
            "cargo-gate-rejected",
            EvidenceLane::CargoGate,
            "cargo runtime gate records command surface substitution",
            "cargo-runtime-harness-adapter-runtime",
            &required_roots.cargo_gate_root,
            "cargo gate accepted on devnet but production command evidence remains gated",
        ),
        rejected_evidence(
            "production-blocker-rejected",
            EvidenceLane::ReleaseBlocker,
            "production blocker lane carries uncleared release constraints",
            "canonical-production-blocker-burn-down-runtime",
            &required_roots.release_blocker_root,
            "production release blockers are still open",
        ),
    ]
}

fn accepted_evidence(
    evidence_id: &str,
    lane: EvidenceLane,
    subject: &str,
    source_runtime: &str,
    required_root: &str,
) -> RuntimeEvidence {
    RuntimeEvidence {
        evidence_id: evidence_id.to_string(),
        lane,
        subject: subject.to_string(),
        source_runtime: source_runtime.to_string(),
        required_root: required_root.to_string(),
        observed_root: required_root.to_string(),
        signals: AcceptanceSignals {
            monero_confirmations: 24,
            privacy_set_size: 160,
            disclosure_units: 4,
            pq_security_bits: 256,
            reserve_coverage_bps: 10_500,
            wallet_export_verified: true,
            runtime_gate_satisfied: true,
            cargo_gate_satisfied: true,
            production_release_blocked: false,
        },
        rejection_reason: None,
    }
}

fn rejected_evidence(
    evidence_id: &str,
    lane: EvidenceLane,
    subject: &str,
    source_runtime: &str,
    required_root: &str,
    rejection_reason: &str,
) -> RuntimeEvidence {
    RuntimeEvidence {
        evidence_id: evidence_id.to_string(),
        lane,
        subject: subject.to_string(),
        source_runtime: source_runtime.to_string(),
        required_root: required_root.to_string(),
        observed_root: required_root.to_string(),
        signals: AcceptanceSignals {
            monero_confirmations: 24,
            privacy_set_size: 160,
            disclosure_units: 4,
            pq_security_bits: 256,
            reserve_coverage_bps: 10_500,
            wallet_export_verified: true,
            runtime_gate_satisfied: lane != EvidenceLane::RuntimeGate,
            cargo_gate_satisfied: lane != EvidenceLane::CargoGate,
            production_release_blocked: lane == EvidenceLane::ReleaseBlocker,
        },
        rejection_reason: Some(rejection_reason.to_string()),
    }
}

fn decide_devnet(evidence: &RuntimeEvidence) -> EvidenceDecision {
    if let Some(reason) = evidence.rejection_reason.as_deref() {
        decision(evidence, EvidenceVerdict::Rejected, reason)
    } else {
        decision(
            evidence,
            EvidenceVerdict::Accepted,
            "runtime evidence satisfies canonical bridge exit acceptance",
        )
    }
}

fn decision(
    evidence: &RuntimeEvidence,
    verdict: EvidenceVerdict,
    reason: &str,
) -> EvidenceDecision {
    let decision_root = domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-RUNTIME-EVIDENCE-DECISION",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(&evidence.evidence_id),
            HashPart::Str(evidence.lane.as_str()),
            HashPart::Str(verdict.as_str()),
            HashPart::Str(&evidence.required_root),
            HashPart::Str(&evidence.observed_root),
            HashPart::Str(reason),
        ],
        32,
    );

    EvidenceDecision {
        evidence_id: evidence.evidence_id.clone(),
        lane: evidence.lane,
        verdict,
        decision_root,
        reason: reason.to_string(),
    }
}

fn gate_placeholder(
    gate_id: &str,
    lane: EvidenceLane,
    required: bool,
    available: bool,
    replacement_source: &str,
) -> GatePlaceholder {
    GatePlaceholder {
        gate_id: gate_id.to_string(),
        lane,
        required,
        available,
        replacement_source: replacement_source.to_string(),
        acceptance_note: "devnet fixture records gate intent while production evidence is attached"
            .to_string(),
    }
}

fn blocker(
    blocker_id: &str,
    owner_lane: EvidenceLane,
    severity: &str,
    cleared: bool,
    release_note: &str,
) -> ProductionReleaseBlocker {
    ProductionReleaseBlocker {
        blocker_id: blocker_id.to_string(),
        owner_lane,
        severity: severity.to_string(),
        cleared,
        release_note: release_note.to_string(),
    }
}

fn lane_root(lane: EvidenceLane, label: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-RUNTIME-EVIDENCE-LANE",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(lane.as_str()),
            HashPart::Str(label),
            HashPart::U64(DEVNET_HEIGHT),
        ],
        32,
    )
}
