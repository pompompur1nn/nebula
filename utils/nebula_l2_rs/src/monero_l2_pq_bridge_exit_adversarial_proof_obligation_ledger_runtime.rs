use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitAdversarialProofObligationLedgerRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_ADVERSARIAL_PROOF_OBLIGATION_LEDGER_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-monero-l2-pq-bridge-exit-adversarial-proof-obligation-ledger-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_ADVERSARIAL_PROOF_OBLIGATION_LEDGER_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const OBLIGATION_LEDGER_SUITE: &str =
    "monero-l2-pq-bridge-exit-adversarial-proof-obligation-ledger-v1";
pub const DEVNET_LEDGER_LABEL: &str = "devnet-monero-private-l2-bridge-exit-security-spine";
pub const DEFAULT_MIN_OBLIGATIONS: usize = 30;
pub const DEFAULT_MIN_EVIDENCE_ROOTS: usize = 18;
pub const DEFAULT_MAX_BLOCKERS_FOR_WATCH: usize = 3;
pub const DEFAULT_REQUIRED_WATCHER_QUORUM_WEIGHT: u64 = 67;
pub const DEFAULT_MONERO_FINALITY_DEPTH: u64 = 60;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ObligationDomain {
    DepositAdmission,
    PrivateTransfer,
    SettlementReceipt,
    ForcedWithdrawal,
    SequencerShutdown,
    WatcherCollusion,
    MoneroReorg,
    LiquidityExhaustion,
    PrivacyLeakage,
    PqAuthorityCompromise,
}

impl ObligationDomain {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DepositAdmission => "deposit_admission",
            Self::PrivateTransfer => "private_transfer",
            Self::SettlementReceipt => "settlement_receipt",
            Self::ForcedWithdrawal => "forced_withdrawal",
            Self::SequencerShutdown => "sequencer_shutdown",
            Self::WatcherCollusion => "watcher_collusion",
            Self::MoneroReorg => "monero_reorg",
            Self::LiquidityExhaustion => "liquidity_exhaustion",
            Self::PrivacyLeakage => "privacy_leakage",
            Self::PqAuthorityCompromise => "pq_authority_compromise",
        }
    }

    pub fn production_gate(self) -> ProductionGate {
        match self {
            Self::DepositAdmission => ProductionGate::DepositAdmissionGate,
            Self::PrivateTransfer => ProductionGate::PrivateTransferGate,
            Self::SettlementReceipt => ProductionGate::SettlementReceiptGate,
            Self::ForcedWithdrawal => ProductionGate::ForcedWithdrawalGate,
            Self::SequencerShutdown => ProductionGate::SequencerShutdownGate,
            Self::WatcherCollusion => ProductionGate::WatcherCollusionGate,
            Self::MoneroReorg => ProductionGate::MoneroReorgGate,
            Self::LiquidityExhaustion => ProductionGate::LiquidityExhaustionGate,
            Self::PrivacyLeakage => ProductionGate::PrivacyLeakageGate,
            Self::PqAuthorityCompromise => ProductionGate::PqAuthorityCompromiseGate,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ObligationStatus {
    Proven,
    PartiallyProven,
    BlockedMissingProof,
    BlockedByDeferredCargoChecks,
    BlockedByProductionGate,
    Rejected,
}

impl ObligationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proven => "proven",
            Self::PartiallyProven => "partially_proven",
            Self::BlockedMissingProof => "blocked_missing_proof",
            Self::BlockedByDeferredCargoChecks => "blocked_by_deferred_cargo_checks",
            Self::BlockedByProductionGate => "blocked_by_production_gate",
            Self::Rejected => "rejected",
        }
    }

    pub fn is_release_blocking(self) -> bool {
        !matches!(self, Self::Proven)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    MoneroFinalityCertificate,
    WatcherQuorumSignature,
    PqAggregateSignature,
    DepositNullifierSetRoot,
    PrivateTransferReceiptRoot,
    SettlementReceiptRoot,
    ForcedWithdrawalTranscriptRoot,
    SequencerShutdownHeartbeatRoot,
    ChallengeWindowTranscriptRoot,
    LiquidityReserveAttestationRoot,
    PrivacyBudgetAuditRoot,
    AuthorityRotationTranscriptRoot,
    NegativeFixtureCorpusRoot,
    StaticVerifierReportRoot,
    CargoCheckReceiptRoot,
}

impl EvidenceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MoneroFinalityCertificate => "monero_finality_certificate",
            Self::WatcherQuorumSignature => "watcher_quorum_signature",
            Self::PqAggregateSignature => "pq_aggregate_signature",
            Self::DepositNullifierSetRoot => "deposit_nullifier_set_root",
            Self::PrivateTransferReceiptRoot => "private_transfer_receipt_root",
            Self::SettlementReceiptRoot => "settlement_receipt_root",
            Self::ForcedWithdrawalTranscriptRoot => "forced_withdrawal_transcript_root",
            Self::SequencerShutdownHeartbeatRoot => "sequencer_shutdown_heartbeat_root",
            Self::ChallengeWindowTranscriptRoot => "challenge_window_transcript_root",
            Self::LiquidityReserveAttestationRoot => "liquidity_reserve_attestation_root",
            Self::PrivacyBudgetAuditRoot => "privacy_budget_audit_root",
            Self::AuthorityRotationTranscriptRoot => "authority_rotation_transcript_root",
            Self::NegativeFixtureCorpusRoot => "negative_fixture_corpus_root",
            Self::StaticVerifierReportRoot => "static_verifier_report_root",
            Self::CargoCheckReceiptRoot => "cargo_check_receipt_root",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MissingProofBlockerKind {
    MissingFinalityDepthProof,
    MissingWatcherDiversityProof,
    MissingPqSignatureBinding,
    MissingNullifierNonMembership,
    MissingPrivateStateTransitionProof,
    MissingSettlementReleaseBinding,
    MissingForcedExitLivenessProof,
    MissingSequencerShutdownEscapeProof,
    MissingLiquiditySolvencyProof,
    MissingMetadataLeakageBound,
    MissingAuthorityCompromiseContainment,
    DeferredCargoVerification,
    ProductionReleaseDisabled,
}

impl MissingProofBlockerKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MissingFinalityDepthProof => "missing_finality_depth_proof",
            Self::MissingWatcherDiversityProof => "missing_watcher_diversity_proof",
            Self::MissingPqSignatureBinding => "missing_pq_signature_binding",
            Self::MissingNullifierNonMembership => "missing_nullifier_non_membership",
            Self::MissingPrivateStateTransitionProof => "missing_private_state_transition_proof",
            Self::MissingSettlementReleaseBinding => "missing_settlement_release_binding",
            Self::MissingForcedExitLivenessProof => "missing_forced_exit_liveness_proof",
            Self::MissingSequencerShutdownEscapeProof => "missing_sequencer_shutdown_escape_proof",
            Self::MissingLiquiditySolvencyProof => "missing_liquidity_solvency_proof",
            Self::MissingMetadataLeakageBound => "missing_metadata_leakage_bound",
            Self::MissingAuthorityCompromiseContainment => {
                "missing_authority_compromise_containment"
            }
            Self::DeferredCargoVerification => "deferred_cargo_verification",
            Self::ProductionReleaseDisabled => "production_release_disabled",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProductionGate {
    DepositAdmissionGate,
    PrivateTransferGate,
    SettlementReceiptGate,
    ForcedWithdrawalGate,
    SequencerShutdownGate,
    WatcherCollusionGate,
    MoneroReorgGate,
    LiquidityExhaustionGate,
    PrivacyLeakageGate,
    PqAuthorityCompromiseGate,
    CargoVerificationGate,
    GlobalReleaseGate,
}

impl ProductionGate {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DepositAdmissionGate => "deposit_admission_gate",
            Self::PrivateTransferGate => "private_transfer_gate",
            Self::SettlementReceiptGate => "settlement_receipt_gate",
            Self::ForcedWithdrawalGate => "forced_withdrawal_gate",
            Self::SequencerShutdownGate => "sequencer_shutdown_gate",
            Self::WatcherCollusionGate => "watcher_collusion_gate",
            Self::MoneroReorgGate => "monero_reorg_gate",
            Self::LiquidityExhaustionGate => "liquidity_exhaustion_gate",
            Self::PrivacyLeakageGate => "privacy_leakage_gate",
            Self::PqAuthorityCompromiseGate => "pq_authority_compromise_gate",
            Self::CargoVerificationGate => "cargo_verification_gate",
            Self::GlobalReleaseGate => "global_release_gate",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GateStatus {
    Open,
    Watch,
    Blocked,
}

impl GateStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Watch => "watch",
            Self::Blocked => "blocked",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LedgerVerdict {
    ProductionReady,
    Watch,
    Blocked,
}

impl LedgerVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ProductionReady => "production_ready",
            Self::Watch => "watch",
            Self::Blocked => "blocked",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub obligation_ledger_suite: String,
    pub label: String,
    pub min_obligations: usize,
    pub min_evidence_roots: usize,
    pub max_blockers_for_watch: usize,
    pub required_watcher_quorum_weight: u64,
    pub required_monero_finality_depth: u64,
    pub cargo_checks_deferred: bool,
    pub production_release_allowed: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            obligation_ledger_suite: OBLIGATION_LEDGER_SUITE.to_string(),
            label: DEVNET_LEDGER_LABEL.to_string(),
            min_obligations: DEFAULT_MIN_OBLIGATIONS,
            min_evidence_roots: DEFAULT_MIN_EVIDENCE_ROOTS,
            max_blockers_for_watch: DEFAULT_MAX_BLOCKERS_FOR_WATCH,
            required_watcher_quorum_weight: DEFAULT_REQUIRED_WATCHER_QUORUM_WEIGHT,
            required_monero_finality_depth: DEFAULT_MONERO_FINALITY_DEPTH,
            cargo_checks_deferred: true,
            production_release_allowed: false,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "obligation_ledger_suite": self.obligation_ledger_suite,
            "label": self.label,
            "min_obligations": self.min_obligations,
            "min_evidence_roots": self.min_evidence_roots,
            "max_blockers_for_watch": self.max_blockers_for_watch,
            "required_watcher_quorum_weight": self.required_watcher_quorum_weight,
            "required_monero_finality_depth": self.required_monero_finality_depth,
            "cargo_checks_deferred": self.cargo_checks_deferred,
            "production_release_allowed": self.production_release_allowed,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct EvidenceRoot {
    pub evidence_id: String,
    pub kind: EvidenceKind,
    pub domain: ObligationDomain,
    pub root: String,
    pub source: String,
    pub height: u64,
    pub accepted: bool,
    pub notes: String,
}

impl EvidenceRoot {
    pub fn new(
        evidence_id: impl Into<String>,
        kind: EvidenceKind,
        domain: ObligationDomain,
        source: impl Into<String>,
        height: u64,
        accepted: bool,
        notes: impl Into<String>,
    ) -> Self {
        let evidence_id = evidence_id.into();
        let source = source.into();
        let notes = notes.into();
        let root = domain_hash(
            "monero_l2_pq_bridge_exit_obligation:evidence",
            &[
                HashPart::Str(&evidence_id),
                HashPart::Str(kind.as_str()),
                HashPart::Str(domain.as_str()),
                HashPart::Str(&source),
                HashPart::U64(height),
                HashPart::Str(if accepted { "accepted" } else { "rejected" }),
                HashPart::Str(&notes),
            ],
            32,
        );
        Self {
            evidence_id,
            kind,
            domain,
            root,
            source,
            height,
            accepted,
            notes,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "evidence_id": self.evidence_id,
            "kind": self.kind.as_str(),
            "domain": self.domain.as_str(),
            "root": self.root,
            "source": self.source,
            "height": self.height,
            "accepted": self.accepted,
            "notes": self.notes,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct MissingProofBlocker {
    pub blocker_id: String,
    pub kind: MissingProofBlockerKind,
    pub domain: ObligationDomain,
    pub severity: u8,
    pub required_evidence: Vec<EvidenceKind>,
    pub remediation: String,
    pub release_blocking: bool,
}

impl MissingProofBlocker {
    pub fn public_record(&self) -> Value {
        let required_evidence = self
            .required_evidence
            .iter()
            .map(|kind| kind.as_str())
            .collect::<Vec<_>>();
        json!({
            "blocker_id": self.blocker_id,
            "kind": self.kind.as_str(),
            "domain": self.domain.as_str(),
            "severity": self.severity,
            "required_evidence": required_evidence,
            "remediation": self.remediation,
            "release_blocking": self.release_blocking,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("missing_proof_blocker", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ProofObligation {
    pub obligation_id: String,
    pub domain: ObligationDomain,
    pub statement: String,
    pub adversary_model: String,
    pub required_evidence: Vec<EvidenceKind>,
    pub evidence_roots: Vec<String>,
    pub blockers: Vec<MissingProofBlocker>,
    pub status: ObligationStatus,
    pub production_gate: ProductionGate,
}

impl ProofObligation {
    pub fn public_record(&self) -> Value {
        let required_evidence = self
            .required_evidence
            .iter()
            .map(|kind| kind.as_str())
            .collect::<Vec<_>>();
        json!({
            "obligation_id": self.obligation_id,
            "domain": self.domain.as_str(),
            "statement": self.statement,
            "adversary_model": self.adversary_model,
            "required_evidence": required_evidence,
            "evidence_roots": self.evidence_roots,
            "blockers": self.blockers.iter().map(MissingProofBlocker::public_record).collect::<Vec<_>>(),
            "status": self.status.as_str(),
            "production_gate": self.production_gate.as_str(),
            "release_blocking": self.status.is_release_blocking(),
        })
    }

    pub fn state_root(&self) -> String {
        record_root("proof_obligation", &self.public_record())
    }

    pub fn missing_evidence(&self) -> Vec<EvidenceKind> {
        self.required_evidence
            .iter()
            .skip(self.evidence_roots.len())
            .copied()
            .collect()
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ProductionGateDecision {
    pub gate: ProductionGate,
    pub status: GateStatus,
    pub blocker_count: usize,
    pub evidence_count: usize,
    pub decision_root: String,
    pub reason: String,
}

impl ProductionGateDecision {
    pub fn public_record(&self) -> Value {
        json!({
            "gate": self.gate.as_str(),
            "status": self.status.as_str(),
            "blocker_count": self.blocker_count,
            "evidence_count": self.evidence_count,
            "decision_root": self.decision_root,
            "reason": self.reason,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LedgerSummary {
    pub verdict: LedgerVerdict,
    pub obligation_count: usize,
    pub proven_count: usize,
    pub partial_count: usize,
    pub blocked_count: usize,
    pub evidence_root_count: usize,
    pub blocker_count: usize,
    pub production_gate_count: usize,
    pub blocked_gate_count: usize,
    pub cargo_checks_deferred: bool,
    pub production_release_allowed: bool,
}

impl LedgerSummary {
    pub fn public_record(&self) -> Value {
        json!({
            "verdict": self.verdict.as_str(),
            "obligation_count": self.obligation_count,
            "proven_count": self.proven_count,
            "partial_count": self.partial_count,
            "blocked_count": self.blocked_count,
            "evidence_root_count": self.evidence_root_count,
            "blocker_count": self.blocker_count,
            "production_gate_count": self.production_gate_count,
            "blocked_gate_count": self.blocked_gate_count,
            "cargo_checks_deferred": self.cargo_checks_deferred,
            "production_release_allowed": self.production_release_allowed,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub obligations: Vec<ProofObligation>,
    pub evidence_roots: Vec<EvidenceRoot>,
    pub production_gates: Vec<ProductionGateDecision>,
    pub summary: LedgerSummary,
}

impl State {
    pub fn new(config: Config) -> Self {
        let evidence_roots = devnet_evidence_roots();
        let obligations = devnet_obligations(&config, &evidence_roots);
        let production_gates = build_gate_decisions(&config, &obligations, &evidence_roots);
        let summary = build_summary(&config, &obligations, &evidence_roots, &production_gates);
        Self {
            config,
            obligations,
            evidence_roots,
            production_gates,
            summary,
        }
    }

    pub fn devnet() -> Self {
        Self::new(Config::devnet())
    }

    pub fn public_record_without_state_root(&self) -> Value {
        json!({
            "config": self.config.public_record(),
            "obligations": self.obligations.iter().map(ProofObligation::public_record).collect::<Vec<_>>(),
            "evidence_roots": self.evidence_roots.iter().map(EvidenceRoot::public_record).collect::<Vec<_>>(),
            "production_gates": self.production_gates.iter().map(ProductionGateDecision::public_record).collect::<Vec<_>>(),
            "summary": self.summary.public_record(),
            "roots": {
                "config_root": self.config.state_root(),
                "obligation_root": self.obligation_root(),
                "evidence_root": self.evidence_root(),
                "blocker_root": self.blocker_root(),
                "production_gate_root": self.production_gate_root(),
            }
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        if let Some(object) = record.as_object_mut() {
            object.insert("state_root".to_string(), json!(self.state_root()));
        }
        record
    }

    pub fn state_root(&self) -> String {
        record_root("state", &self.public_record_without_state_root())
    }

    pub fn obligation_root(&self) -> String {
        let leaves = self
            .obligations
            .iter()
            .map(ProofObligation::public_record)
            .collect::<Vec<_>>();
        merkle_root("monero_l2_pq_bridge_exit_obligation:obligations", &leaves)
    }

    pub fn evidence_root(&self) -> String {
        let leaves = self
            .evidence_roots
            .iter()
            .map(EvidenceRoot::public_record)
            .collect::<Vec<_>>();
        merkle_root(
            "monero_l2_pq_bridge_exit_obligation:evidence_roots",
            &leaves,
        )
    }

    pub fn blocker_root(&self) -> String {
        let leaves = self
            .obligations
            .iter()
            .flat_map(|obligation| obligation.blockers.iter())
            .map(MissingProofBlocker::public_record)
            .collect::<Vec<_>>();
        merkle_root("monero_l2_pq_bridge_exit_obligation:blockers", &leaves)
    }

    pub fn production_gate_root(&self) -> String {
        let leaves = self
            .production_gates
            .iter()
            .map(ProductionGateDecision::public_record)
            .collect::<Vec<_>>();
        merkle_root(
            "monero_l2_pq_bridge_exit_obligation:production_gates",
            &leaves,
        )
    }

    pub fn obligations_by_domain(&self) -> BTreeMap<String, Vec<String>> {
        let mut by_domain = BTreeMap::new();
        for obligation in &self.obligations {
            by_domain
                .entry(obligation.domain.as_str().to_string())
                .or_insert_with(Vec::new)
                .push(obligation.obligation_id.clone());
        }
        by_domain
    }

    pub fn release_blockers(&self) -> Vec<Value> {
        self.obligations
            .iter()
            .filter(|obligation| obligation.status.is_release_blocking())
            .map(ProofObligation::public_record)
            .collect()
    }

    pub fn production_release_allowed(&self) -> bool {
        self.config.production_release_allowed
            && !self.config.cargo_checks_deferred
            && self
                .production_gates
                .iter()
                .all(|gate| gate.status == GateStatus::Open)
    }
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

fn record_root(domain: &str, record: &Value) -> String {
    domain_hash(
        &format!("monero_l2_pq_bridge_exit_obligation:{domain}"),
        &[HashPart::Json(record)],
        32,
    )
}

fn evidence_root_by_kind(
    evidence_roots: &[EvidenceRoot],
    domain: ObligationDomain,
    kind: EvidenceKind,
) -> Option<String> {
    evidence_roots
        .iter()
        .find(|evidence| evidence.domain == domain && evidence.kind == kind && evidence.accepted)
        .map(|evidence| evidence.root.clone())
}

fn roots_for(
    evidence_roots: &[EvidenceRoot],
    domain: ObligationDomain,
    required: &[EvidenceKind],
) -> Vec<String> {
    required
        .iter()
        .filter_map(|kind| evidence_root_by_kind(evidence_roots, domain, *kind))
        .collect()
}

fn blocker(
    id: &str,
    kind: MissingProofBlockerKind,
    domain: ObligationDomain,
    severity: u8,
    required_evidence: Vec<EvidenceKind>,
    remediation: &str,
) -> MissingProofBlocker {
    MissingProofBlocker {
        blocker_id: id.to_string(),
        kind,
        domain,
        severity,
        required_evidence,
        remediation: remediation.to_string(),
        release_blocking: true,
    }
}

fn obligation(
    evidence_roots: &[EvidenceRoot],
    obligation_id: &str,
    domain: ObligationDomain,
    statement: &str,
    adversary_model: &str,
    required_evidence: Vec<EvidenceKind>,
    blockers: Vec<MissingProofBlocker>,
) -> ProofObligation {
    let evidence_roots = roots_for(evidence_roots, domain, &required_evidence);
    let status = if blockers.is_empty() && evidence_roots.len() == required_evidence.len() {
        ObligationStatus::Proven
    } else if blockers.is_empty() && !evidence_roots.is_empty() {
        ObligationStatus::PartiallyProven
    } else {
        ObligationStatus::BlockedMissingProof
    };
    ProofObligation {
        obligation_id: obligation_id.to_string(),
        domain,
        statement: statement.to_string(),
        adversary_model: adversary_model.to_string(),
        required_evidence,
        evidence_roots,
        blockers,
        status,
        production_gate: domain.production_gate(),
    }
}

fn devnet_evidence_roots() -> Vec<EvidenceRoot> {
    vec![
        EvidenceRoot::new(
            "evidence.deposit.finality.certificate",
            EvidenceKind::MoneroFinalityCertificate,
            ObligationDomain::DepositAdmission,
            "devnet-monero-lock-observer",
            900_060,
            true,
            "lock output buried beyond configured finality floor",
        ),
        EvidenceRoot::new(
            "evidence.deposit.watcher.quorum",
            EvidenceKind::WatcherQuorumSignature,
            ObligationDomain::DepositAdmission,
            "devnet-watcher-quorum",
            900_060,
            true,
            "weighted watcher quorum attests deposit lock admission",
        ),
        EvidenceRoot::new(
            "evidence.deposit.nullifier.nonmembership",
            EvidenceKind::DepositNullifierSetRoot,
            ObligationDomain::DepositAdmission,
            "devnet-nullifier-index",
            900_060,
            true,
            "deposit nullifier has no prior admission edge",
        ),
        EvidenceRoot::new(
            "evidence.private.transfer.receipt",
            EvidenceKind::PrivateTransferReceiptRoot,
            ObligationDomain::PrivateTransfer,
            "devnet-private-transfer-runtime",
            900_070,
            true,
            "private state transition receipt is anchored",
        ),
        EvidenceRoot::new(
            "evidence.private.transfer.pq.binding",
            EvidenceKind::PqAggregateSignature,
            ObligationDomain::PrivateTransfer,
            "devnet-pq-control-plane",
            900_070,
            true,
            "PQ aggregate signature binds transfer transcript",
        ),
        EvidenceRoot::new(
            "evidence.settlement.receipt.root",
            EvidenceKind::SettlementReceiptRoot,
            ObligationDomain::SettlementReceipt,
            "devnet-settlement-adapter",
            900_080,
            true,
            "settlement receipt commits withdrawal binding and release amount",
        ),
        EvidenceRoot::new(
            "evidence.settlement.challenge.window",
            EvidenceKind::ChallengeWindowTranscriptRoot,
            ObligationDomain::SettlementReceipt,
            "devnet-dispute-liveness-runtime",
            900_080,
            true,
            "challenge window observed closed before release",
        ),
        EvidenceRoot::new(
            "evidence.forced.withdrawal.transcript",
            EvidenceKind::ForcedWithdrawalTranscriptRoot,
            ObligationDomain::ForcedWithdrawal,
            "devnet-forced-exit-runtime",
            900_090,
            true,
            "forced withdrawal transcript preserves claimant path",
        ),
        EvidenceRoot::new(
            "evidence.forced.withdrawal.challenge.window",
            EvidenceKind::ChallengeWindowTranscriptRoot,
            ObligationDomain::ForcedWithdrawal,
            "devnet-dispute-liveness-runtime",
            900_090,
            true,
            "forced exit settlement respects dispute window",
        ),
        EvidenceRoot::new(
            "evidence.shutdown.heartbeat",
            EvidenceKind::SequencerShutdownHeartbeatRoot,
            ObligationDomain::SequencerShutdown,
            "devnet-sequencer-liveness-monitor",
            900_100,
            true,
            "sequencer heartbeat loss is externally observable",
        ),
        EvidenceRoot::new(
            "evidence.collusion.watcher.diversity",
            EvidenceKind::WatcherQuorumSignature,
            ObligationDomain::WatcherCollusion,
            "devnet-watcher-quorum",
            900_110,
            true,
            "quorum signature includes independent watcher families",
        ),
        EvidenceRoot::new(
            "evidence.reorg.finality.bound",
            EvidenceKind::MoneroFinalityCertificate,
            ObligationDomain::MoneroReorg,
            "devnet-monero-finality-monitor",
            900_120,
            true,
            "reorg model is bounded by configured finality depth",
        ),
        EvidenceRoot::new(
            "evidence.liquidity.reserve",
            EvidenceKind::LiquidityReserveAttestationRoot,
            ObligationDomain::LiquidityExhaustion,
            "devnet-liquidity-reserve-monitor",
            900_130,
            true,
            "reserve root exposes exit queue solvency gap",
        ),
        EvidenceRoot::new(
            "evidence.privacy.budget",
            EvidenceKind::PrivacyBudgetAuditRoot,
            ObligationDomain::PrivacyLeakage,
            "devnet-privacy-budget-auditor",
            900_140,
            true,
            "privacy budget records metadata minimization floor",
        ),
        EvidenceRoot::new(
            "evidence.pq.authority.rotation",
            EvidenceKind::AuthorityRotationTranscriptRoot,
            ObligationDomain::PqAuthorityCompromise,
            "devnet-pq-authority-rotation",
            900_150,
            true,
            "authority rotation transcript records compromise containment",
        ),
        EvidenceRoot::new(
            "evidence.global.static.verifier",
            EvidenceKind::StaticVerifierReportRoot,
            ObligationDomain::PqAuthorityCompromise,
            "devnet-static-verifier",
            900_150,
            true,
            "static verifier report roots authority release rules",
        ),
        EvidenceRoot::new(
            "evidence.global.negative.fixtures",
            EvidenceKind::NegativeFixtureCorpusRoot,
            ObligationDomain::WatcherCollusion,
            "devnet-negative-fixture-manifest",
            900_151,
            true,
            "negative fixtures exercise collusion and invalid evidence paths",
        ),
    ]
}

fn devnet_obligations(config: &Config, evidence_roots: &[EvidenceRoot]) -> Vec<ProofObligation> {
    let cargo_blocker = blocker(
        "blocker.global.cargo_checks_deferred",
        MissingProofBlockerKind::DeferredCargoVerification,
        ObligationDomain::PqAuthorityCompromise,
        9,
        vec![EvidenceKind::CargoCheckReceiptRoot],
        "run cargo check, tests, clippy, and rustc verification outside this generation pass",
    );
    let release_blocker = blocker(
        "blocker.global.production_release_disabled",
        MissingProofBlockerKind::ProductionReleaseDisabled,
        ObligationDomain::PqAuthorityCompromise,
        10,
        vec![EvidenceKind::StaticVerifierReportRoot],
        "set production release only after independent review and non-deferred cargo receipts",
    );

    let mut obligations = vec![
        obligation(
            evidence_roots,
            "obligation.deposit.lock_finality",
            ObligationDomain::DepositAdmission,
            "Deposit admission must prove the Monero lock is final before minting private L2 value.",
            "adversary submits shallow lock then reorgs the Monero output after private mint",
            vec![EvidenceKind::MoneroFinalityCertificate],
            Vec::new(),
        ),
        obligation(
            evidence_roots,
            "obligation.deposit.watcher_quorum_weight",
            ObligationDomain::DepositAdmission,
            "Deposit admission must bind watcher quorum weight and signer diversity.",
            "colluding watchers attest a lock without enough independent weight",
            vec![EvidenceKind::WatcherQuorumSignature],
            Vec::new(),
        ),
        obligation(
            evidence_roots,
            "obligation.deposit.nullifier_non_membership",
            ObligationDomain::DepositAdmission,
            "Deposit nullifier must be proven absent from prior admissions.",
            "attacker replays a prior Monero lock into a second private mint",
            vec![EvidenceKind::DepositNullifierSetRoot],
            Vec::new(),
        ),
        obligation(
            evidence_roots,
            "obligation.private_transfer.state_transition",
            ObligationDomain::PrivateTransfer,
            "Private transfer must prove conservation without revealing sender, recipient, or amount.",
            "malicious prover inflates private balance through an unbound transfer receipt",
            vec![EvidenceKind::PrivateTransferReceiptRoot, EvidenceKind::PqAggregateSignature],
            Vec::new(),
        ),
        obligation(
            evidence_roots,
            "obligation.private_transfer.replay_resistance",
            ObligationDomain::PrivateTransfer,
            "Private transfer nullifiers must be single-use across bridge-bound exits.",
            "attacker reuses a valid private spend transcript across exit paths",
            vec![EvidenceKind::PrivateTransferReceiptRoot],
            vec![blocker(
                "blocker.private_transfer.replay_membership",
                MissingProofBlockerKind::MissingPrivateStateTransitionProof,
                ObligationDomain::PrivateTransfer,
                7,
                vec![EvidenceKind::PrivateTransferReceiptRoot],
                "attach full nullifier accumulator transition proof to transfer receipt root",
            )],
        ),
        obligation(
            evidence_roots,
            "obligation.settlement.withdrawal_binding",
            ObligationDomain::SettlementReceipt,
            "Settlement receipt must bind exit claim, withdrawal destination, amount, and custody release.",
            "settler redirects a valid exit receipt to a different Monero release target",
            vec![EvidenceKind::SettlementReceiptRoot],
            Vec::new(),
        ),
        obligation(
            evidence_roots,
            "obligation.settlement.challenge_window_closed",
            ObligationDomain::SettlementReceipt,
            "Settlement must prove no open challenge can invalidate the release.",
            "sequencer settles while a watcher challenge is still live",
            vec![
                EvidenceKind::SettlementReceiptRoot,
                EvidenceKind::ChallengeWindowTranscriptRoot,
            ],
            Vec::new(),
        ),
        obligation(
            evidence_roots,
            "obligation.forced_withdrawal.liveness",
            ObligationDomain::ForcedWithdrawal,
            "Forced withdrawal must remain available when the sequencer censors exits.",
            "sequencer withholds private transfer inclusion and blocks user exit",
            vec![EvidenceKind::ForcedWithdrawalTranscriptRoot],
            Vec::new(),
        ),
        obligation(
            evidence_roots,
            "obligation.forced_withdrawal.dispute_ordering",
            ObligationDomain::ForcedWithdrawal,
            "Forced withdrawal settlement must respect challenge ordering before release.",
            "attacker races forced exit settlement before dispute evidence is ordered",
            vec![
                EvidenceKind::ForcedWithdrawalTranscriptRoot,
                EvidenceKind::ChallengeWindowTranscriptRoot,
            ],
            Vec::new(),
        ),
        obligation(
            evidence_roots,
            "obligation.sequencer_shutdown.escape_hatch",
            ObligationDomain::SequencerShutdown,
            "Sequencer shutdown must activate an externally verifiable exit escape hatch.",
            "operator disappears and leaves private balances without a settlement path",
            vec![EvidenceKind::SequencerShutdownHeartbeatRoot],
            Vec::new(),
        ),
        obligation(
            evidence_roots,
            "obligation.sequencer_shutdown_receipt_continuity",
            ObligationDomain::SequencerShutdown,
            "Shutdown path must preserve receipt continuity from last accepted private state root.",
            "operator halts after accepting transfers but before anchoring the receipt root",
            vec![
                EvidenceKind::SequencerShutdownHeartbeatRoot,
                EvidenceKind::PrivateTransferReceiptRoot,
            ],
            vec![blocker(
                "blocker.shutdown.private_receipt_cross_domain",
                MissingProofBlockerKind::MissingSequencerShutdownEscapeProof,
                ObligationDomain::SequencerShutdown,
                8,
                vec![EvidenceKind::PrivateTransferReceiptRoot],
                "publish cross-domain receipt continuity proof for shutdown checkpoints",
            )],
        ),
        obligation(
            evidence_roots,
            "obligation.watcher_collusion.diversity",
            ObligationDomain::WatcherCollusion,
            "Watcher quorum must prove diversity sufficient to resist cartel admission.",
            "watcher cartel signs a fabricated finality certificate",
            vec![EvidenceKind::WatcherQuorumSignature],
            Vec::new(),
        ),
        obligation(
            evidence_roots,
            "obligation.watcher_collusion.negative_fixtures",
            ObligationDomain::WatcherCollusion,
            "Watcher collusion defenses must include executable negative fixtures.",
            "invalid quorum evidence passes because rejected cases are not rooted",
            vec![
                EvidenceKind::WatcherQuorumSignature,
                EvidenceKind::NegativeFixtureCorpusRoot,
            ],
            Vec::new(),
        ),
        obligation(
            evidence_roots,
            "obligation.monero_reorg.finality_floor",
            ObligationDomain::MoneroReorg,
            "Monero reorg risk must be bounded by a finality floor before custody credit.",
            "deep reorg removes the lock after L2 value circulates",
            vec![EvidenceKind::MoneroFinalityCertificate],
            Vec::new(),
        ),
        obligation(
            evidence_roots,
            "obligation.monero_reorg.reversal_accounting",
            ObligationDomain::MoneroReorg,
            "Reorg handling must prove reversal accounting cannot create unbacked exits.",
            "reorged lock remains spendable in private state after custody backing disappears",
            vec![EvidenceKind::MoneroFinalityCertificate, EvidenceKind::SettlementReceiptRoot],
            vec![blocker(
                "blocker.reorg.reversal_accounting",
                MissingProofBlockerKind::MissingFinalityDepthProof,
                ObligationDomain::MoneroReorg,
                8,
                vec![EvidenceKind::SettlementReceiptRoot],
                "root reorg reversal accounting receipts against settlement obligations",
            )],
        ),
        obligation(
            evidence_roots,
            "obligation.liquidity.reserve_visibility",
            ObligationDomain::LiquidityExhaustion,
            "Liquidity exhaustion must be visible before accepting new bridge exits.",
            "exit queue grows beyond available reserve while admissions continue",
            vec![EvidenceKind::LiquidityReserveAttestationRoot],
            Vec::new(),
        ),
        obligation(
            evidence_roots,
            "obligation.liquidity.fair_queueing",
            ObligationDomain::LiquidityExhaustion,
            "Liquidity shortage must preserve fair queueing and prevent favored release.",
            "operator releases preferred exits while earlier valid exits remain unpaid",
            vec![
                EvidenceKind::LiquidityReserveAttestationRoot,
                EvidenceKind::SettlementReceiptRoot,
            ],
            vec![blocker(
                "blocker.liquidity.fair_queueing",
                MissingProofBlockerKind::MissingLiquiditySolvencyProof,
                ObligationDomain::LiquidityExhaustion,
                7,
                vec![EvidenceKind::SettlementReceiptRoot],
                "add queue-position proof to reserve attestation and settlement receipt",
            )],
        ),
        obligation(
            evidence_roots,
            "obligation.privacy.metadata_budget",
            ObligationDomain::PrivacyLeakage,
            "Privacy leakage must be bounded across deposit, transfer, and exit metadata.",
            "observer links Monero lock, private transfer, and exit timing through metadata",
            vec![EvidenceKind::PrivacyBudgetAuditRoot],
            Vec::new(),
        ),
        obligation(
            evidence_roots,
            "obligation.privacy.amount_timing_floor",
            ObligationDomain::PrivacyLeakage,
            "Privacy proof must enforce amount and timing anonymity floors.",
            "small anonymity sets reveal the user during bridge-bound transfer",
            vec![EvidenceKind::PrivacyBudgetAuditRoot],
            vec![blocker(
                "blocker.privacy.amount_timing_floor",
                MissingProofBlockerKind::MissingMetadataLeakageBound,
                ObligationDomain::PrivacyLeakage,
                8,
                vec![EvidenceKind::PrivacyBudgetAuditRoot],
                "publish anonymity-set and timing-bucket lower bounds per transfer corridor",
            )],
        ),
        obligation(
            evidence_roots,
            "obligation.pq_authority.rotation",
            ObligationDomain::PqAuthorityCompromise,
            "PQ authority compromise must be containable through rotation and transcript binding.",
            "compromised authority signs a stale release key into production custody",
            vec![EvidenceKind::AuthorityRotationTranscriptRoot],
            Vec::new(),
        ),
        obligation(
            evidence_roots,
            "obligation.pq_authority.static_rules",
            ObligationDomain::PqAuthorityCompromise,
            "Static verifier rules must block unilateral authority release.",
            "authority bypasses watcher and settlement gates with a direct release message",
            vec![
                EvidenceKind::AuthorityRotationTranscriptRoot,
                EvidenceKind::StaticVerifierReportRoot,
            ],
            Vec::new(),
        ),
    ];

    if config.cargo_checks_deferred {
        obligations.push(ProofObligation {
            obligation_id: "obligation.global.cargo_check_receipts".to_string(),
            domain: ObligationDomain::PqAuthorityCompromise,
            statement: "Cargo, clippy, tests, and rustc receipts must be present before production release."
                .to_string(),
            adversary_model:
                "runtime logic ships with type, lint, or test failures because verification was deferred"
                    .to_string(),
            required_evidence: vec![EvidenceKind::CargoCheckReceiptRoot],
            evidence_roots: Vec::new(),
            blockers: vec![cargo_blocker],
            status: ObligationStatus::BlockedByDeferredCargoChecks,
            production_gate: ProductionGate::CargoVerificationGate,
        });
    }

    if !config.production_release_allowed {
        obligations.push(ProofObligation {
            obligation_id: "obligation.global.production_release_gate".to_string(),
            domain: ObligationDomain::PqAuthorityCompromise,
            statement: "Production release must remain disabled until all proof obligations are independently accepted."
                .to_string(),
            adversary_model: "devnet ledger is mistaken for a production-ready safety case".to_string(),
            required_evidence: vec![EvidenceKind::StaticVerifierReportRoot],
            evidence_roots: roots_for(
                evidence_roots,
                ObligationDomain::PqAuthorityCompromise,
                &[EvidenceKind::StaticVerifierReportRoot],
            ),
            blockers: vec![release_blocker],
            status: ObligationStatus::BlockedByProductionGate,
            production_gate: ProductionGate::GlobalReleaseGate,
        });
    }

    obligations
}

fn build_gate_decisions(
    config: &Config,
    obligations: &[ProofObligation],
    evidence_roots: &[EvidenceRoot],
) -> Vec<ProductionGateDecision> {
    let mut gate_names = BTreeSet::new();
    for obligation in obligations {
        gate_names.insert(obligation.production_gate);
    }
    gate_names.insert(ProductionGate::GlobalReleaseGate);
    gate_names.insert(ProductionGate::CargoVerificationGate);

    gate_names
        .into_iter()
        .map(|gate| {
            let gate_obligations = obligations
                .iter()
                .filter(|obligation| obligation.production_gate == gate)
                .collect::<Vec<_>>();
            let blocker_count = gate_obligations
                .iter()
                .map(|obligation| obligation.blockers.len())
                .sum::<usize>();
            let evidence_count = gate_obligations
                .iter()
                .map(|obligation| obligation.evidence_roots.len())
                .sum::<usize>();
            let status = if gate == ProductionGate::GlobalReleaseGate
                && !config.production_release_allowed
            {
                GateStatus::Blocked
            } else if gate == ProductionGate::CargoVerificationGate && config.cargo_checks_deferred
            {
                GateStatus::Blocked
            } else if blocker_count == 0
                && gate_obligations
                    .iter()
                    .all(|obligation| obligation.status == ObligationStatus::Proven)
            {
                GateStatus::Open
            } else if blocker_count <= config.max_blockers_for_watch {
                GateStatus::Watch
            } else {
                GateStatus::Blocked
            };
            let reason = match status {
                GateStatus::Open => "all obligations under gate are proven".to_string(),
                GateStatus::Watch => "gate has limited unresolved proof blockers".to_string(),
                GateStatus::Blocked => {
                    if gate == ProductionGate::GlobalReleaseGate {
                        "production_release_allowed is false".to_string()
                    } else if gate == ProductionGate::CargoVerificationGate {
                        "cargo_checks_deferred is true".to_string()
                    } else {
                        "gate has unresolved release-blocking proof obligations".to_string()
                    }
                }
            };
            let decision_seed = json!({
                "gate": gate.as_str(),
                "status": status.as_str(),
                "blocker_count": blocker_count,
                "evidence_count": evidence_count,
                "accepted_evidence_roots": evidence_roots.iter().filter(|evidence| evidence.accepted).count(),
                "reason": reason,
            });
            let decision_root = record_root("production_gate_decision", &decision_seed);
            ProductionGateDecision {
                gate,
                status,
                blocker_count,
                evidence_count,
                decision_root,
                reason,
            }
        })
        .collect()
}

fn build_summary(
    config: &Config,
    obligations: &[ProofObligation],
    evidence_roots: &[EvidenceRoot],
    production_gates: &[ProductionGateDecision],
) -> LedgerSummary {
    let proven_count = obligations
        .iter()
        .filter(|obligation| obligation.status == ObligationStatus::Proven)
        .count();
    let partial_count = obligations
        .iter()
        .filter(|obligation| obligation.status == ObligationStatus::PartiallyProven)
        .count();
    let blocked_count = obligations
        .iter()
        .filter(|obligation| obligation.status.is_release_blocking())
        .count();
    let blocker_count = obligations
        .iter()
        .map(|obligation| obligation.blockers.len())
        .sum::<usize>();
    let blocked_gate_count = production_gates
        .iter()
        .filter(|gate| gate.status == GateStatus::Blocked)
        .count();
    let accepted_evidence_count = evidence_roots
        .iter()
        .filter(|evidence| evidence.accepted)
        .count();
    let verdict = if !config.production_release_allowed
        || config.cargo_checks_deferred
        || blocked_gate_count > 0
        || blocked_count > config.max_blockers_for_watch
    {
        LedgerVerdict::Blocked
    } else if blocked_count > 0
        || obligations.len() < config.min_obligations
        || accepted_evidence_count < config.min_evidence_roots
    {
        LedgerVerdict::Watch
    } else {
        LedgerVerdict::ProductionReady
    };
    LedgerSummary {
        verdict,
        obligation_count: obligations.len(),
        proven_count,
        partial_count,
        blocked_count,
        evidence_root_count: accepted_evidence_count,
        blocker_count,
        production_gate_count: production_gates.len(),
        blocked_gate_count,
        cargo_checks_deferred: config.cargo_checks_deferred,
        production_release_allowed: config.production_release_allowed,
    }
}
