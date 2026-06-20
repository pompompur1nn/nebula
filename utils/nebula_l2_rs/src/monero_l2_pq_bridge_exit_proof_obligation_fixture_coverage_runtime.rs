use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitProofObligationFixtureCoverageRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_PROOF_OBLIGATION_FIXTURE_COVERAGE_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-monero-l2-pq-bridge-exit-proof-obligation-fixture-coverage-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_PROOF_OBLIGATION_FIXTURE_COVERAGE_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const COVERAGE_SUITE: &str = "monero-l2-pq-bridge-exit-proof-obligation-fixture-coverage-v1";
pub const DEVNET_LABEL: &str = "devnet-monero-private-l2-bridge-exit-fixture-coverage";
pub const DEFAULT_MIN_DOMAIN_COVERAGE_BPS: u16 = 8_000;
pub const DEFAULT_MIN_TOTAL_COVERAGE_BPS: u16 = 8_500;
pub const DEFAULT_MAX_MISSING_FIXTURE_BLOCKERS: usize = 0;
pub const DEFAULT_MAX_PRODUCTION_GATE_BLOCKERS: usize = 0;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ObligationDomain {
    Deposit,
    PrivateTransfer,
    Settlement,
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
            Self::Deposit => "deposit",
            Self::PrivateTransfer => "private_transfer",
            Self::Settlement => "settlement",
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
            Self::Deposit => ProductionGate::DepositFixtureGate,
            Self::PrivateTransfer => ProductionGate::PrivateTransferFixtureGate,
            Self::Settlement => ProductionGate::SettlementFixtureGate,
            Self::ForcedWithdrawal => ProductionGate::ForcedWithdrawalFixtureGate,
            Self::SequencerShutdown => ProductionGate::SequencerShutdownFixtureGate,
            Self::WatcherCollusion => ProductionGate::WatcherCollusionFixtureGate,
            Self::MoneroReorg => ProductionGate::MoneroReorgFixtureGate,
            Self::LiquidityExhaustion => ProductionGate::LiquidityExhaustionFixtureGate,
            Self::PrivacyLeakage => ProductionGate::PrivacyLeakageFixtureGate,
            Self::PqAuthorityCompromise => ProductionGate::PqAuthorityCompromiseFixtureGate,
        }
    }

    pub fn all() -> [Self; 10] {
        [
            Self::Deposit,
            Self::PrivateTransfer,
            Self::Settlement,
            Self::ForcedWithdrawal,
            Self::SequencerShutdown,
            Self::WatcherCollusion,
            Self::MoneroReorg,
            Self::LiquidityExhaustion,
            Self::PrivacyLeakage,
            Self::PqAuthorityCompromise,
        ]
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FixtureEvidenceKind {
    PositiveTranscript,
    NegativeTranscript,
    BoundaryTranscript,
    MerkleWitness,
    WatcherQuorum,
    PqSignatureBinding,
    MoneroHeaderWindow,
    LiquidityReserveWitness,
    PrivacyBudgetAudit,
    IncidentRunbook,
}

impl FixtureEvidenceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PositiveTranscript => "positive_transcript",
            Self::NegativeTranscript => "negative_transcript",
            Self::BoundaryTranscript => "boundary_transcript",
            Self::MerkleWitness => "merkle_witness",
            Self::WatcherQuorum => "watcher_quorum",
            Self::PqSignatureBinding => "pq_signature_binding",
            Self::MoneroHeaderWindow => "monero_header_window",
            Self::LiquidityReserveWitness => "liquidity_reserve_witness",
            Self::PrivacyBudgetAudit => "privacy_budget_audit",
            Self::IncidentRunbook => "incident_runbook",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CoverageStatus {
    Covered,
    Partial,
    Blocked,
}

impl CoverageStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Covered => "covered",
            Self::Partial => "partial",
            Self::Blocked => "blocked",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MissingFixtureBlockerKind {
    MissingPositiveFixture,
    MissingNegativeFixture,
    MissingBoundaryFixture,
    MissingFixtureEvidenceRoot,
    MissingCrossDomainReplayFixture,
    MissingMoneroReorgWindow,
    MissingWatcherCollusionMatrix,
    MissingLiquidityExhaustionVector,
    MissingPrivacyLeakageRegression,
    MissingPqAuthorityCompromiseDrill,
    DeferredCargoVerification,
    ProductionReleaseDisabled,
}

impl MissingFixtureBlockerKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MissingPositiveFixture => "missing_positive_fixture",
            Self::MissingNegativeFixture => "missing_negative_fixture",
            Self::MissingBoundaryFixture => "missing_boundary_fixture",
            Self::MissingFixtureEvidenceRoot => "missing_fixture_evidence_root",
            Self::MissingCrossDomainReplayFixture => "missing_cross_domain_replay_fixture",
            Self::MissingMoneroReorgWindow => "missing_monero_reorg_window",
            Self::MissingWatcherCollusionMatrix => "missing_watcher_collusion_matrix",
            Self::MissingLiquidityExhaustionVector => "missing_liquidity_exhaustion_vector",
            Self::MissingPrivacyLeakageRegression => "missing_privacy_leakage_regression",
            Self::MissingPqAuthorityCompromiseDrill => "missing_pq_authority_compromise_drill",
            Self::DeferredCargoVerification => "deferred_cargo_verification",
            Self::ProductionReleaseDisabled => "production_release_disabled",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProductionGate {
    DepositFixtureGate,
    PrivateTransferFixtureGate,
    SettlementFixtureGate,
    ForcedWithdrawalFixtureGate,
    SequencerShutdownFixtureGate,
    WatcherCollusionFixtureGate,
    MoneroReorgFixtureGate,
    LiquidityExhaustionFixtureGate,
    PrivacyLeakageFixtureGate,
    PqAuthorityCompromiseFixtureGate,
    CargoCheckGate,
    GlobalProductionReleaseGate,
}

impl ProductionGate {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DepositFixtureGate => "deposit_fixture_gate",
            Self::PrivateTransferFixtureGate => "private_transfer_fixture_gate",
            Self::SettlementFixtureGate => "settlement_fixture_gate",
            Self::ForcedWithdrawalFixtureGate => "forced_withdrawal_fixture_gate",
            Self::SequencerShutdownFixtureGate => "sequencer_shutdown_fixture_gate",
            Self::WatcherCollusionFixtureGate => "watcher_collusion_fixture_gate",
            Self::MoneroReorgFixtureGate => "monero_reorg_fixture_gate",
            Self::LiquidityExhaustionFixtureGate => "liquidity_exhaustion_fixture_gate",
            Self::PrivacyLeakageFixtureGate => "privacy_leakage_fixture_gate",
            Self::PqAuthorityCompromiseFixtureGate => "pq_authority_compromise_fixture_gate",
            Self::CargoCheckGate => "cargo_check_gate",
            Self::GlobalProductionReleaseGate => "global_production_release_gate",
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
pub enum ReleaseVerdict {
    FixtureCovered,
    NeedsFixtures,
    ProductionBlocked,
}

impl ReleaseVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FixtureCovered => "fixture_covered",
            Self::NeedsFixtures => "needs_fixtures",
            Self::ProductionBlocked => "production_blocked",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub coverage_suite: String,
    pub min_domain_coverage_bps: u16,
    pub min_total_coverage_bps: u16,
    pub max_missing_fixture_blockers: usize,
    pub max_production_gate_blockers: usize,
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
            coverage_suite: COVERAGE_SUITE.to_string(),
            min_domain_coverage_bps: DEFAULT_MIN_DOMAIN_COVERAGE_BPS,
            min_total_coverage_bps: DEFAULT_MIN_TOTAL_COVERAGE_BPS,
            max_missing_fixture_blockers: DEFAULT_MAX_MISSING_FIXTURE_BLOCKERS,
            max_production_gate_blockers: DEFAULT_MAX_PRODUCTION_GATE_BLOCKERS,
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
            "coverage_suite": self.coverage_suite,
            "min_domain_coverage_bps": self.min_domain_coverage_bps,
            "min_total_coverage_bps": self.min_total_coverage_bps,
            "max_missing_fixture_blockers": self.max_missing_fixture_blockers,
            "max_production_gate_blockers": self.max_production_gate_blockers,
            "cargo_checks_deferred": self.cargo_checks_deferred,
            "production_release_allowed": self.production_release_allowed,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FixtureEvidenceRoot {
    pub evidence_id: String,
    pub domain: ObligationDomain,
    pub kind: FixtureEvidenceKind,
    pub label: String,
    pub fixture_count: u16,
    pub evidence_root: String,
    pub source_manifest_root: String,
    pub required_for_production: bool,
}

impl FixtureEvidenceRoot {
    pub fn new(
        domain: ObligationDomain,
        kind: FixtureEvidenceKind,
        label: impl Into<String>,
        fixture_count: u16,
        source_manifest_root: impl Into<String>,
        required_for_production: bool,
    ) -> Self {
        let label = label.into();
        let source_manifest_root = source_manifest_root.into();
        let evidence_root = fixture_evidence_root(
            domain,
            kind,
            &label,
            fixture_count,
            &source_manifest_root,
            required_for_production,
        );
        let evidence_id = fixture_evidence_id(domain, kind, &evidence_root);
        Self {
            evidence_id,
            domain,
            kind,
            label,
            fixture_count,
            evidence_root,
            source_manifest_root,
            required_for_production,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "evidence_id": self.evidence_id,
            "domain": self.domain.as_str(),
            "kind": self.kind.as_str(),
            "label": self.label,
            "fixture_count": self.fixture_count,
            "evidence_root": self.evidence_root,
            "source_manifest_root": self.source_manifest_root,
            "required_for_production": self.required_for_production,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("fixture_evidence_root", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct MissingFixtureBlocker {
    pub blocker_id: String,
    pub domain: ObligationDomain,
    pub kind: MissingFixtureBlockerKind,
    pub severity: u8,
    pub blocker: String,
    pub remediation: String,
    pub evidence_gap_root: String,
    pub blocks_production: bool,
}

impl MissingFixtureBlocker {
    pub fn new(
        domain: ObligationDomain,
        kind: MissingFixtureBlockerKind,
        severity: u8,
        blocker: impl Into<String>,
        remediation: impl Into<String>,
        gap_material: Value,
        blocks_production: bool,
    ) -> Self {
        let blocker = blocker.into();
        let remediation = remediation.into();
        let evidence_gap_root = evidence_gap_root(domain, kind, &gap_material);
        let blocker_id = missing_fixture_blocker_id(domain, kind, &evidence_gap_root);
        Self {
            blocker_id,
            domain,
            kind,
            severity,
            blocker,
            remediation,
            evidence_gap_root,
            blocks_production,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "blocker_id": self.blocker_id,
            "domain": self.domain.as_str(),
            "kind": self.kind.as_str(),
            "severity": self.severity,
            "blocker": self.blocker,
            "remediation": self.remediation,
            "evidence_gap_root": self.evidence_gap_root,
            "blocks_production": self.blocks_production,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("missing_fixture_blocker", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ProofObligationCoverage {
    pub obligation_id: String,
    pub domain: ObligationDomain,
    pub title: String,
    pub required_fixture_count: u16,
    pub covered_fixture_count: u16,
    pub coverage_bps: u16,
    pub coverage_percent: String,
    pub status: CoverageStatus,
    pub fixture_evidence_root: String,
    pub blocker_root: String,
    pub production_gate: ProductionGate,
    pub production_gate_status: GateStatus,
    pub release_note: String,
}

impl ProofObligationCoverage {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        domain: ObligationDomain,
        title: impl Into<String>,
        required_fixture_count: u16,
        covered_fixture_count: u16,
        evidence_roots: &[FixtureEvidenceRoot],
        blockers: &[MissingFixtureBlocker],
        production_gate_status: GateStatus,
        release_note: impl Into<String>,
    ) -> Self {
        let title = title.into();
        let coverage_bps = coverage_bps(covered_fixture_count, required_fixture_count);
        let status = if coverage_bps >= 10_000 && blockers.is_empty() {
            CoverageStatus::Covered
        } else if coverage_bps > 0 {
            CoverageStatus::Partial
        } else {
            CoverageStatus::Blocked
        };
        let fixture_evidence_root =
            slice_root("OBLIGATION-FIXTURE-EVIDENCE", evidence_roots, |e| {
                e.public_record()
            });
        let blocker_root = slice_root("OBLIGATION-MISSING-FIXTURE-BLOCKER", blockers, |b| {
            b.public_record()
        });
        let production_gate = domain.production_gate();
        let obligation_id = proof_obligation_id(
            domain,
            &title,
            required_fixture_count,
            covered_fixture_count,
            &fixture_evidence_root,
            &blocker_root,
        );
        Self {
            obligation_id,
            domain,
            title,
            required_fixture_count,
            covered_fixture_count,
            coverage_bps,
            coverage_percent: percent_string(coverage_bps),
            status,
            fixture_evidence_root,
            blocker_root,
            production_gate,
            production_gate_status,
            release_note: release_note.into(),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "obligation_id": self.obligation_id,
            "domain": self.domain.as_str(),
            "title": self.title,
            "required_fixture_count": self.required_fixture_count,
            "covered_fixture_count": self.covered_fixture_count,
            "coverage_bps": self.coverage_bps,
            "coverage_percent": self.coverage_percent,
            "status": self.status.as_str(),
            "fixture_evidence_root": self.fixture_evidence_root,
            "blocker_root": self.blocker_root,
            "production_gate": self.production_gate.as_str(),
            "production_gate_status": self.production_gate_status.as_str(),
            "release_note": self.release_note,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("proof_obligation_coverage", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ProductionGateRecord {
    pub gate_id: String,
    pub gate: ProductionGate,
    pub status: GateStatus,
    pub domain: Option<ObligationDomain>,
    pub requirement: String,
    pub observed: String,
    pub evidence_root: String,
    pub blocks_production: bool,
}

impl ProductionGateRecord {
    pub fn new(
        gate: ProductionGate,
        status: GateStatus,
        domain: Option<ObligationDomain>,
        requirement: impl Into<String>,
        observed: impl Into<String>,
        evidence_root: impl Into<String>,
        blocks_production: bool,
    ) -> Self {
        let requirement = requirement.into();
        let observed = observed.into();
        let evidence_root = evidence_root.into();
        let domain_label = domain.map(ObligationDomain::as_str).unwrap_or("global");
        let gate_id = production_gate_id(gate, domain_label, &evidence_root);
        Self {
            gate_id,
            gate,
            status,
            domain,
            requirement,
            observed,
            evidence_root,
            blocks_production,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "gate_id": self.gate_id,
            "gate": self.gate.as_str(),
            "status": self.status.as_str(),
            "domain": self.domain.map(ObligationDomain::as_str),
            "requirement": self.requirement,
            "observed": self.observed,
            "evidence_root": self.evidence_root,
            "blocks_production": self.blocks_production,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("production_gate", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CoverageSummary {
    pub total_required_fixtures: u16,
    pub total_covered_fixtures: u16,
    pub total_coverage_bps: u16,
    pub total_coverage_percent: String,
    pub covered_obligations: u16,
    pub partial_obligations: u16,
    pub blocked_obligations: u16,
    pub missing_fixture_blockers: usize,
    pub production_gate_blockers: usize,
    pub verdict: ReleaseVerdict,
    pub summary_root: String,
}

impl CoverageSummary {
    pub fn from_state(state: &State) -> Self {
        let total_required_fixtures = state
            .obligations
            .values()
            .map(|obligation| obligation.required_fixture_count)
            .sum::<u16>();
        let total_covered_fixtures = state
            .obligations
            .values()
            .map(|obligation| obligation.covered_fixture_count)
            .sum::<u16>();
        let total_coverage_bps = coverage_bps(total_covered_fixtures, total_required_fixtures);
        let covered_obligations = count_status(&state.obligations, CoverageStatus::Covered);
        let partial_obligations = count_status(&state.obligations, CoverageStatus::Partial);
        let blocked_obligations = count_status(&state.obligations, CoverageStatus::Blocked);
        let missing_fixture_blockers = state.missing_fixture_blockers.len();
        let production_gate_blockers = state
            .production_gates
            .values()
            .filter(|gate| gate.blocks_production)
            .count();
        let verdict = if production_gate_blockers > state.config.max_production_gate_blockers
            || !state.config.production_release_allowed
            || state.config.cargo_checks_deferred
        {
            ReleaseVerdict::ProductionBlocked
        } else if missing_fixture_blockers > state.config.max_missing_fixture_blockers
            || total_coverage_bps < state.config.min_total_coverage_bps
            || state
                .obligations
                .values()
                .any(|obligation| obligation.coverage_bps < state.config.min_domain_coverage_bps)
        {
            ReleaseVerdict::NeedsFixtures
        } else {
            ReleaseVerdict::FixtureCovered
        };
        let summary_record = json!({
            "total_required_fixtures": total_required_fixtures,
            "total_covered_fixtures": total_covered_fixtures,
            "total_coverage_bps": total_coverage_bps,
            "covered_obligations": covered_obligations,
            "partial_obligations": partial_obligations,
            "blocked_obligations": blocked_obligations,
            "missing_fixture_blockers": missing_fixture_blockers,
            "production_gate_blockers": production_gate_blockers,
            "verdict": verdict.as_str(),
        });
        let summary_root = record_root("coverage_summary", &summary_record);
        Self {
            total_required_fixtures,
            total_covered_fixtures,
            total_coverage_bps,
            total_coverage_percent: percent_string(total_coverage_bps),
            covered_obligations,
            partial_obligations,
            blocked_obligations,
            missing_fixture_blockers,
            production_gate_blockers,
            verdict,
            summary_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "total_required_fixtures": self.total_required_fixtures,
            "total_covered_fixtures": self.total_covered_fixtures,
            "total_coverage_bps": self.total_coverage_bps,
            "total_coverage_percent": self.total_coverage_percent,
            "covered_obligations": self.covered_obligations,
            "partial_obligations": self.partial_obligations,
            "blocked_obligations": self.blocked_obligations,
            "missing_fixture_blockers": self.missing_fixture_blockers,
            "production_gate_blockers": self.production_gate_blockers,
            "verdict": self.verdict.as_str(),
            "summary_root": self.summary_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub label: String,
    pub fixture_evidence_roots: BTreeMap<String, FixtureEvidenceRoot>,
    pub missing_fixture_blockers: BTreeMap<String, MissingFixtureBlocker>,
    pub obligations: BTreeMap<String, ProofObligationCoverage>,
    pub production_gates: BTreeMap<String, ProductionGateRecord>,
}

impl State {
    pub fn new(config: Config, label: impl Into<String>) -> Self {
        Self {
            config,
            label: label.into(),
            fixture_evidence_roots: BTreeMap::new(),
            missing_fixture_blockers: BTreeMap::new(),
            obligations: BTreeMap::new(),
            production_gates: BTreeMap::new(),
        }
    }

    pub fn insert_fixture_evidence_root(&mut self, evidence: FixtureEvidenceRoot) -> Result<()> {
        if evidence.fixture_count == 0 {
            return Err("fixture evidence root must cover at least one fixture".to_string());
        }
        self.fixture_evidence_roots
            .insert(evidence.evidence_id.clone(), evidence);
        Ok(())
    }

    pub fn insert_missing_fixture_blocker(&mut self, blocker: MissingFixtureBlocker) -> Result<()> {
        if blocker.severity == 0 || blocker.severity > 5 {
            return Err("missing fixture blocker severity must be in 1..=5".to_string());
        }
        self.missing_fixture_blockers
            .insert(blocker.blocker_id.clone(), blocker);
        Ok(())
    }

    pub fn insert_obligation(&mut self, obligation: ProofObligationCoverage) -> Result<()> {
        if obligation.covered_fixture_count > obligation.required_fixture_count {
            return Err("covered fixture count cannot exceed required fixture count".to_string());
        }
        self.obligations
            .insert(obligation.obligation_id.clone(), obligation);
        Ok(())
    }

    pub fn insert_production_gate(&mut self, gate: ProductionGateRecord) -> Result<()> {
        self.production_gates.insert(gate.gate_id.clone(), gate);
        Ok(())
    }

    pub fn summary(&self) -> CoverageSummary {
        CoverageSummary::from_state(self)
    }

    pub fn fixture_evidence_root(&self) -> String {
        map_root(
            "FIXTURE-EVIDENCE-ROOTS",
            &self.fixture_evidence_roots,
            |e| e.public_record(),
        )
    }

    pub fn missing_fixture_blocker_root(&self) -> String {
        map_root(
            "MISSING-FIXTURE-BLOCKERS",
            &self.missing_fixture_blockers,
            |b| b.public_record(),
        )
    }

    pub fn obligation_root(&self) -> String {
        map_root("PROOF-OBLIGATION-COVERAGE", &self.obligations, |o| {
            o.public_record()
        })
    }

    pub fn production_gate_root(&self) -> String {
        map_root("PRODUCTION-GATES", &self.production_gates, |g| {
            g.public_record()
        })
    }

    pub fn public_record(&self) -> Value {
        let summary = self.summary();
        json!({
            "chain_id": CHAIN_ID,
            "label": self.label,
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "config": self.config.public_record(),
            "fixture_evidence_root": self.fixture_evidence_root(),
            "missing_fixture_blocker_root": self.missing_fixture_blocker_root(),
            "obligation_root": self.obligation_root(),
            "production_gate_root": self.production_gate_root(),
            "summary": summary.public_record(),
            "cargo_checks_deferred": self.config.cargo_checks_deferred,
            "production_release_allowed": self.config.production_release_allowed,
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-PROOF-OBLIGATION-FIXTURE-COVERAGE-STATE",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

pub fn devnet() -> State {
    let config = Config::devnet();
    let mut state = State::new(config, DEVNET_LABEL);

    for domain in ObligationDomain::all() {
        let evidence = devnet_evidence(domain);
        let blockers = devnet_blockers(domain);
        for item in evidence.iter().cloned() {
            state
                .insert_fixture_evidence_root(item)
                .expect("devnet fixture evidence root must be valid");
        }
        for blocker in blockers.iter().cloned() {
            state
                .insert_missing_fixture_blocker(blocker)
                .expect("devnet missing fixture blocker must be valid");
        }
        let (required, covered, gate_status, release_note) = devnet_domain_profile(domain);
        let obligation = ProofObligationCoverage::new(
            domain,
            devnet_domain_title(domain),
            required,
            covered,
            &evidence,
            &blockers,
            gate_status,
            release_note,
        );
        let gate = ProductionGateRecord::new(
            domain.production_gate(),
            gate_status,
            Some(domain),
            "domain fixture coverage must meet the release threshold with no critical blocker",
            format!(
                "{} of {} required fixtures covered ({})",
                covered,
                required,
                percent_string(coverage_bps(covered, required))
            ),
            obligation.fixture_evidence_root.clone(),
            gate_status == GateStatus::Blocked,
        );
        state
            .insert_obligation(obligation)
            .expect("devnet proof obligation coverage must be valid");
        state
            .insert_production_gate(gate)
            .expect("devnet production gate must be valid");
    }

    let cargo_gate = ProductionGateRecord::new(
        ProductionGate::CargoCheckGate,
        GateStatus::Blocked,
        None,
        "cargo, check, test, clippy, and rustc receipts must be attached before production",
        "cargo_checks_deferred=true; no compiler receipt is claimed by this standalone fixture module",
        state.obligation_root(),
        true,
    );
    state
        .insert_production_gate(cargo_gate)
        .expect("devnet cargo gate must be valid");

    let release_gate = ProductionGateRecord::new(
        ProductionGate::GlobalProductionReleaseGate,
        GateStatus::Blocked,
        None,
        "production release flag must be explicitly enabled after fixture and cargo evidence clears",
        "production_release_allowed=false",
        state.production_gate_root(),
        true,
    );
    state
        .insert_production_gate(release_gate)
        .expect("devnet release gate must be valid");

    state
}

pub fn public_record() -> Value {
    devnet().public_record()
}

pub fn state_root() -> String {
    devnet().state_root()
}

fn devnet_domain_profile(domain: ObligationDomain) -> (u16, u16, GateStatus, &'static str) {
    match domain {
        ObligationDomain::Deposit => (
            12,
            11,
            GateStatus::Watch,
            "deposit admission fixtures have finality and nullifier roots; cross-domain replay remains watched",
        ),
        ObligationDomain::PrivateTransfer => (
            14,
            12,
            GateStatus::Watch,
            "private transfer fixtures cover spend and receipt roots; metadata boundary cases need expansion",
        ),
        ObligationDomain::Settlement => (
            13,
            12,
            GateStatus::Watch,
            "settlement receipt fixtures bind release roots; negative replay fixture remains missing",
        ),
        ObligationDomain::ForcedWithdrawal => (
            15,
            13,
            GateStatus::Watch,
            "forced withdrawal fixtures cover escape and liveness paths with boundary fixture debt",
        ),
        ObligationDomain::SequencerShutdown => (
            10,
            8,
            GateStatus::Blocked,
            "shutdown escape fixtures exist but heartbeat halt ordering needs a production blocker fixture",
        ),
        ObligationDomain::WatcherCollusion => (
            12,
            9,
            GateStatus::Blocked,
            "watcher collusion matrix is partial and cannot clear production without diversity evidence",
        ),
        ObligationDomain::MoneroReorg => (
            12,
            9,
            GateStatus::Blocked,
            "Monero reorg windows cover shallow and medium depths; deep reorg adversarial fixtures are missing",
        ),
        ObligationDomain::LiquidityExhaustion => (
            11,
            8,
            GateStatus::Blocked,
            "liquidity exhaustion runbook has reserve witnesses but lacks full queue-drain fixtures",
        ),
        ObligationDomain::PrivacyLeakage => (
            13,
            10,
            GateStatus::Blocked,
            "privacy leakage regression fixtures are present but below metadata leakage closure threshold",
        ),
        ObligationDomain::PqAuthorityCompromise => (
            12,
            8,
            GateStatus::Blocked,
            "PQ authority compromise drills cover rotation but not quorum capture and stale key replay",
        ),
    }
}

fn devnet_domain_title(domain: ObligationDomain) -> &'static str {
    match domain {
        ObligationDomain::Deposit => "deposit evidence roots bind lock, finality, and nullifier obligations",
        ObligationDomain::PrivateTransfer => {
            "private transfer evidence roots bind notes, receipts, and hidden-state transitions"
        }
        ObligationDomain::Settlement => {
            "settlement evidence roots bind exit claim, release receipt, and replay fence obligations"
        }
        ObligationDomain::ForcedWithdrawal => {
            "forced withdrawal evidence roots bind escape liveness and user recovery obligations"
        }
        ObligationDomain::SequencerShutdown => {
            "sequencer shutdown evidence roots bind halt detection and escape queue obligations"
        }
        ObligationDomain::WatcherCollusion => {
            "watcher collusion evidence roots bind quorum diversity and slashing obligations"
        }
        ObligationDomain::MoneroReorg => {
            "Monero reorg evidence roots bind header windows and delayed release obligations"
        }
        ObligationDomain::LiquidityExhaustion => {
            "liquidity exhaustion evidence roots bind reserve solvency and queue recovery obligations"
        }
        ObligationDomain::PrivacyLeakage => {
            "privacy leakage evidence roots bind metadata budget and regression obligations"
        }
        ObligationDomain::PqAuthorityCompromise => {
            "PQ authority compromise evidence roots bind key rotation and containment obligations"
        }
    }
}

fn devnet_evidence(domain: ObligationDomain) -> Vec<FixtureEvidenceRoot> {
    let manifest = domain_manifest_root(domain);
    let mut evidence = vec![
        FixtureEvidenceRoot::new(
            domain,
            FixtureEvidenceKind::PositiveTranscript,
            format!("{}-positive-transcripts", domain.as_str()),
            3,
            manifest.clone(),
            true,
        ),
        FixtureEvidenceRoot::new(
            domain,
            FixtureEvidenceKind::NegativeTranscript,
            format!("{}-negative-transcripts", domain.as_str()),
            2,
            manifest.clone(),
            true,
        ),
        FixtureEvidenceRoot::new(
            domain,
            FixtureEvidenceKind::MerkleWitness,
            format!("{}-fixture-evidence-roots", domain.as_str()),
            2,
            manifest.clone(),
            true,
        ),
    ];
    match domain {
        ObligationDomain::Deposit => {
            evidence.push(FixtureEvidenceRoot::new(
                domain,
                FixtureEvidenceKind::MoneroHeaderWindow,
                "deposit-finality-window",
                4,
                manifest,
                true,
            ));
        }
        ObligationDomain::PrivateTransfer => {
            evidence.push(FixtureEvidenceRoot::new(
                domain,
                FixtureEvidenceKind::PrivacyBudgetAudit,
                "private-transfer-metadata-budget",
                5,
                manifest,
                true,
            ));
        }
        ObligationDomain::Settlement => {
            evidence.push(FixtureEvidenceRoot::new(
                domain,
                FixtureEvidenceKind::PqSignatureBinding,
                "settlement-release-pq-binding",
                5,
                manifest,
                true,
            ));
        }
        ObligationDomain::ForcedWithdrawal => {
            evidence.push(FixtureEvidenceRoot::new(
                domain,
                FixtureEvidenceKind::BoundaryTranscript,
                "forced-withdrawal-timeout-boundaries",
                6,
                manifest,
                true,
            ));
        }
        ObligationDomain::SequencerShutdown => {
            evidence.push(FixtureEvidenceRoot::new(
                domain,
                FixtureEvidenceKind::IncidentRunbook,
                "sequencer-shutdown-escape-runbook",
                1,
                manifest,
                true,
            ));
        }
        ObligationDomain::WatcherCollusion => {
            evidence.push(FixtureEvidenceRoot::new(
                domain,
                FixtureEvidenceKind::WatcherQuorum,
                "watcher-collusion-quorum-slices",
                2,
                manifest,
                true,
            ));
        }
        ObligationDomain::MoneroReorg => {
            evidence.push(FixtureEvidenceRoot::new(
                domain,
                FixtureEvidenceKind::MoneroHeaderWindow,
                "monero-reorg-header-windows",
                2,
                manifest,
                true,
            ));
        }
        ObligationDomain::LiquidityExhaustion => {
            evidence.push(FixtureEvidenceRoot::new(
                domain,
                FixtureEvidenceKind::LiquidityReserveWitness,
                "liquidity-exhaustion-reserve-witness",
                1,
                manifest,
                true,
            ));
        }
        ObligationDomain::PrivacyLeakage => {
            evidence.push(FixtureEvidenceRoot::new(
                domain,
                FixtureEvidenceKind::PrivacyBudgetAudit,
                "privacy-leakage-regression-audit",
                3,
                manifest,
                true,
            ));
        }
        ObligationDomain::PqAuthorityCompromise => {
            evidence.push(FixtureEvidenceRoot::new(
                domain,
                FixtureEvidenceKind::PqSignatureBinding,
                "pq-authority-compromise-rotation-drill",
                1,
                manifest,
                true,
            ));
        }
    }
    evidence
}

fn devnet_blockers(domain: ObligationDomain) -> Vec<MissingFixtureBlocker> {
    let mut blockers = Vec::new();
    let (kind, blocker, remediation, severity) = match domain {
        ObligationDomain::Deposit => (
            MissingFixtureBlockerKind::MissingCrossDomainReplayFixture,
            "deposit replay between admission and settlement has only a positive fixture",
            "add a negative replay fixture with mismatched lock root and nullifier root",
            3,
        ),
        ObligationDomain::PrivateTransfer => (
            MissingFixtureBlockerKind::MissingPrivacyLeakageRegression,
            "private transfer metadata boundary fixtures do not cover repeated decoy reuse",
            "add leakage regression vectors for repeated decoy and viewtag timing reuse",
            4,
        ),
        ObligationDomain::Settlement => (
            MissingFixtureBlockerKind::MissingNegativeFixture,
            "settlement release rejects malformed replay fences but lacks a persisted fixture root",
            "persist the negative replay fixture root beside settlement receipt evidence",
            3,
        ),
        ObligationDomain::ForcedWithdrawal => (
            MissingFixtureBlockerKind::MissingBoundaryFixture,
            "forced withdrawal timeout edge at the dispute boundary is not fixture-backed",
            "add boundary transcripts for open, close, and one-block-late challenge windows",
            4,
        ),
        ObligationDomain::SequencerShutdown => (
            MissingFixtureBlockerKind::MissingBoundaryFixture,
            "sequencer shutdown ordering between final heartbeat and first forced exit is uncovered",
            "add halt-ordering fixtures that bind heartbeat root to escape queue root",
            5,
        ),
        ObligationDomain::WatcherCollusion => (
            MissingFixtureBlockerKind::MissingWatcherCollusionMatrix,
            "watcher collusion fixtures do not enumerate quorum capture and minority dissent",
            "add matrix fixtures for captured quorum, honest minority, and slashable equivocation",
            5,
        ),
        ObligationDomain::MoneroReorg => (
            MissingFixtureBlockerKind::MissingMoneroReorgWindow,
            "deep Monero reorg windows beyond finality depth are not fixture-backed",
            "add delayed release and rollback fixtures for deep header-window replacement",
            5,
        ),
        ObligationDomain::LiquidityExhaustion => (
            MissingFixtureBlockerKind::MissingLiquidityExhaustionVector,
            "liquidity exhaustion fixtures stop before full reserve drain and queue replay",
            "add reserve-drain fixtures with sponsor failure and delayed settlement recovery",
            5,
        ),
        ObligationDomain::PrivacyLeakage => (
            MissingFixtureBlockerKind::MissingPrivacyLeakageRegression,
            "privacy leakage fixtures lack cross-session linkage regression evidence",
            "add cross-session metadata budget and spendlink regression fixtures",
            5,
        ),
        ObligationDomain::PqAuthorityCompromise => (
            MissingFixtureBlockerKind::MissingPqAuthorityCompromiseDrill,
            "PQ authority compromise fixtures lack quorum-capture and stale-key replay drills",
            "add compromised quorum containment and stale-key rejection fixtures",
            5,
        ),
    };
    blockers.push(MissingFixtureBlocker::new(
        domain,
        kind,
        severity,
        blocker,
        remediation,
        json!({
            "domain": domain.as_str(),
            "blocker": blocker,
            "required_gate": domain.production_gate().as_str(),
        }),
        true,
    ));
    blockers
}

fn coverage_bps(covered: u16, required: u16) -> u16 {
    if required == 0 {
        0
    } else {
        ((covered as u32 * 10_000) / required as u32).min(10_000) as u16
    }
}

fn percent_string(bps: u16) -> String {
    format!("{}.{:02}%", bps / 100, bps % 100)
}

fn count_status(
    obligations: &BTreeMap<String, ProofObligationCoverage>,
    status: CoverageStatus,
) -> u16 {
    obligations
        .values()
        .filter(|obligation| obligation.status == status)
        .count() as u16
}

fn map_root<T, F>(domain_suffix: &str, map: &BTreeMap<String, T>, record: F) -> String
where
    F: Fn(&T) -> Value,
{
    let leaves = map.values().map(record).collect::<Vec<_>>();
    merkle_root(
        &format!(
            "MONERO-L2-PQ-BRIDGE-EXIT-PROOF-OBLIGATION-FIXTURE-COVERAGE-{}",
            domain_suffix
        ),
        &leaves,
    )
}

fn slice_root<T, F>(domain_suffix: &str, slice: &[T], record: F) -> String
where
    F: Fn(&T) -> Value,
{
    let leaves = slice.iter().map(record).collect::<Vec<_>>();
    merkle_root(
        &format!(
            "MONERO-L2-PQ-BRIDGE-EXIT-PROOF-OBLIGATION-FIXTURE-COVERAGE-{}",
            domain_suffix
        ),
        &leaves,
    )
}

fn record_root(label: &str, record: &Value) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-PROOF-OBLIGATION-FIXTURE-COVERAGE-RECORD",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
            HashPart::Json(record),
        ],
        32,
    )
}

fn fixture_evidence_root(
    domain: ObligationDomain,
    kind: FixtureEvidenceKind,
    label: &str,
    fixture_count: u16,
    source_manifest_root: &str,
    required_for_production: bool,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-FIXTURE-EVIDENCE-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(domain.as_str()),
            HashPart::Str(kind.as_str()),
            HashPart::Str(label),
            HashPart::Int(fixture_count as i128),
            HashPart::Str(source_manifest_root),
            HashPart::Str(if required_for_production {
                "required"
            } else {
                "advisory"
            }),
        ],
        32,
    )
}

fn fixture_evidence_id(
    domain: ObligationDomain,
    kind: FixtureEvidenceKind,
    evidence_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-FIXTURE-EVIDENCE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(domain.as_str()),
            HashPart::Str(kind.as_str()),
            HashPart::Str(evidence_root),
        ],
        16,
    )
}

fn evidence_gap_root(
    domain: ObligationDomain,
    kind: MissingFixtureBlockerKind,
    gap_material: &Value,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-FIXTURE-EVIDENCE-GAP",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(domain.as_str()),
            HashPart::Str(kind.as_str()),
            HashPart::Json(gap_material),
        ],
        32,
    )
}

fn missing_fixture_blocker_id(
    domain: ObligationDomain,
    kind: MissingFixtureBlockerKind,
    evidence_gap_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-MISSING-FIXTURE-BLOCKER-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(domain.as_str()),
            HashPart::Str(kind.as_str()),
            HashPart::Str(evidence_gap_root),
        ],
        16,
    )
}

fn proof_obligation_id(
    domain: ObligationDomain,
    title: &str,
    required_fixture_count: u16,
    covered_fixture_count: u16,
    fixture_evidence_root: &str,
    blocker_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-PROOF-OBLIGATION-COVERAGE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(domain.as_str()),
            HashPart::Str(title),
            HashPart::Int(required_fixture_count as i128),
            HashPart::Int(covered_fixture_count as i128),
            HashPart::Str(fixture_evidence_root),
            HashPart::Str(blocker_root),
        ],
        16,
    )
}

fn production_gate_id(gate: ProductionGate, domain_label: &str, evidence_root: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-FIXTURE-COVERAGE-PRODUCTION-GATE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(gate.as_str()),
            HashPart::Str(domain_label),
            HashPart::Str(evidence_root),
        ],
        16,
    )
}

fn domain_manifest_root(domain: ObligationDomain) -> String {
    let record = json!({
        "chain_id": CHAIN_ID,
        "protocol_version": PROTOCOL_VERSION,
        "domain": domain.as_str(),
        "fixture_manifest": format!("devnet-{}-fixture-manifest", domain.as_str()),
    });
    record_root("domain_manifest", &record)
}
