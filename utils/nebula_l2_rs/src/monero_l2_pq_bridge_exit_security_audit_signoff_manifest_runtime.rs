use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    monero_l2_pq_bridge_exit_release_remediation_planner_runtime::{
        ReleaseRemediationPlan, RemediationActionKind, RemediationActionStatus,
        RemediationPlanStatus, State as ReleaseRemediationPlannerState,
    },
    monero_l2_pq_bridge_exit_security_audit_harness_adapter_runtime::{
        SecurityAuditFindingSeverity, SecurityAuditHarnessReport, SecurityAuditHarnessReportStatus,
        State as SecurityAuditHarnessState,
    },
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitSecurityAuditSignoffManifestRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_SECURITY_AUDIT_SIGNOFF_MANIFEST_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-security-audit-signoff-manifest-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_SECURITY_AUDIT_SIGNOFF_MANIFEST_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const SECURITY_AUDIT_SIGNOFF_MANIFEST_SUITE: &str =
    "monero-l2-pq-bridge-exit-security-audit-signoff-manifest-v1";
pub const DEFAULT_MIN_SIGNOFFS: u64 = 5;
pub const DEFAULT_MAX_RELEASE_BLOCKERS: u64 = 0;
pub const DEFAULT_MAX_MANUAL_ACTIONS: u64 = 0;
pub const DEFAULT_MAX_MANIFESTS: usize = 256;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SignoffDomain {
    Privacy,
    PostQuantum,
    Settlement,
    ForcedExit,
    ProductionRelease,
}

impl SignoffDomain {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Privacy => "privacy",
            Self::PostQuantum => "post_quantum",
            Self::Settlement => "settlement",
            Self::ForcedExit => "forced_exit",
            Self::ProductionRelease => "production_release",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SignoffStatus {
    Accepted,
    Conditional,
    Blocked,
}

impl SignoffStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Conditional => "conditional",
            Self::Blocked => "blocked",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ManifestStatus {
    ReleaseReady,
    RemediationRequired,
    Blocked,
}

impl ManifestStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ReleaseReady => "release_ready",
            Self::RemediationRequired => "remediation_required",
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
    pub manifest_suite: String,
    pub min_signoffs: u64,
    pub max_release_blockers: u64,
    pub max_manual_actions: u64,
    pub require_privacy_signoff: bool,
    pub require_pq_signoff: bool,
    pub require_settlement_signoff: bool,
    pub require_forced_exit_signoff: bool,
    pub require_production_release_signoff: bool,
    pub production_release_allowed: bool,
    pub max_manifests: usize,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            manifest_suite: SECURITY_AUDIT_SIGNOFF_MANIFEST_SUITE.to_string(),
            min_signoffs: DEFAULT_MIN_SIGNOFFS,
            max_release_blockers: DEFAULT_MAX_RELEASE_BLOCKERS,
            max_manual_actions: DEFAULT_MAX_MANUAL_ACTIONS,
            require_privacy_signoff: true,
            require_pq_signoff: true,
            require_settlement_signoff: true,
            require_forced_exit_signoff: true,
            require_production_release_signoff: true,
            production_release_allowed: false,
            max_manifests: DEFAULT_MAX_MANIFESTS,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "manifest_suite": self.manifest_suite,
            "min_signoffs": self.min_signoffs,
            "max_release_blockers": self.max_release_blockers,
            "max_manual_actions": self.max_manual_actions,
            "require_privacy_signoff": self.require_privacy_signoff,
            "require_pq_signoff": self.require_pq_signoff,
            "require_settlement_signoff": self.require_settlement_signoff,
            "require_forced_exit_signoff": self.require_forced_exit_signoff,
            "require_production_release_signoff": self.require_production_release_signoff,
            "production_release_allowed": self.production_release_allowed,
            "max_manifests": self.max_manifests,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AuditSignoffManifestEntry {
    pub signoff_id: String,
    pub domain: SignoffDomain,
    pub status: SignoffStatus,
    pub release_claim_id: String,
    pub audit_report_id: String,
    pub remediation_plan_id: String,
    pub evidence_root: String,
    pub audit_root: String,
    pub remediation_root: String,
    pub acceptance_root: String,
    pub blocker_root: String,
    pub release_blockers: u64,
    pub production_blockers: u64,
    pub manual_actions: u64,
    pub signoff_root: String,
}

impl AuditSignoffManifestEntry {
    pub fn from_sources(
        config: &Config,
        domain: SignoffDomain,
        audit_report: &SecurityAuditHarnessReport,
        remediation_plan: &ReleaseRemediationPlan,
    ) -> Self {
        let release_blockers = release_blockers(domain, audit_report, remediation_plan);
        let production_blockers = production_blockers(domain, audit_report, remediation_plan);
        let manual_actions = manual_actions(domain, remediation_plan);
        let status = signoff_status(
            config,
            domain,
            audit_report,
            remediation_plan,
            release_blockers,
            production_blockers,
            manual_actions,
        );
        let evidence_root = evidence_root(domain, audit_report, remediation_plan);
        let audit_root = audit_alignment_root(domain, audit_report);
        let remediation_root = remediation_alignment_root(domain, remediation_plan);
        let acceptance_root = acceptance_root(
            domain,
            status,
            &evidence_root,
            &audit_root,
            &remediation_root,
            release_blockers,
            production_blockers,
            manual_actions,
        );
        let blocker_root = blocker_root(
            domain,
            status,
            release_blockers,
            production_blockers,
            manual_actions,
            &remediation_root,
        );
        let signoff_root = audit_signoff_root(
            domain,
            status,
            &audit_report.report_id,
            &remediation_plan.plan_id,
            &evidence_root,
            &acceptance_root,
            &blocker_root,
        );
        let signoff_id = audit_signoff_id(domain, &audit_report.release_claim_id, &signoff_root);
        Self {
            signoff_id,
            domain,
            status,
            release_claim_id: audit_report.release_claim_id.clone(),
            audit_report_id: audit_report.report_id.clone(),
            remediation_plan_id: remediation_plan.plan_id.clone(),
            evidence_root,
            audit_root,
            remediation_root,
            acceptance_root,
            blocker_root,
            release_blockers,
            production_blockers,
            manual_actions,
            signoff_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "signoff_id": self.signoff_id,
            "domain": self.domain.as_str(),
            "status": self.status.as_str(),
            "release_claim_id": self.release_claim_id,
            "audit_report_id": self.audit_report_id,
            "remediation_plan_id": self.remediation_plan_id,
            "evidence_root": self.evidence_root,
            "audit_root": self.audit_root,
            "remediation_root": self.remediation_root,
            "acceptance_root": self.acceptance_root,
            "blocker_root": self.blocker_root,
            "release_blockers": self.release_blockers,
            "production_blockers": self.production_blockers,
            "manual_actions": self.manual_actions,
            "signoff_root": self.signoff_root,
        })
    }

    pub fn state_root(&self) -> String {
        self.signoff_root.clone()
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AuditSignoffManifest {
    pub manifest_id: String,
    pub status: ManifestStatus,
    pub release_claim_id: String,
    pub audit_report_id: String,
    pub audit_report_status: SecurityAuditHarnessReportStatus,
    pub remediation_plan_id: String,
    pub remediation_plan_status: RemediationPlanStatus,
    pub signoffs_total: u64,
    pub signoffs_accepted: u64,
    pub signoffs_conditional: u64,
    pub signoffs_blocked: u64,
    pub release_blockers: u64,
    pub production_blockers: u64,
    pub manual_actions: u64,
    pub entries: BTreeMap<String, AuditSignoffManifestEntry>,
    pub roots: AuditSignoffManifestRoots,
}

impl AuditSignoffManifest {
    pub fn public_record(&self) -> Value {
        let entries = self
            .entries
            .values()
            .map(AuditSignoffManifestEntry::public_record)
            .collect::<Vec<_>>();
        json!({
            "manifest_id": self.manifest_id,
            "status": self.status.as_str(),
            "release_claim_id": self.release_claim_id,
            "audit_report_id": self.audit_report_id,
            "audit_report_status": self.audit_report_status.as_str(),
            "remediation_plan_id": self.remediation_plan_id,
            "remediation_plan_status": self.remediation_plan_status.as_str(),
            "signoffs_total": self.signoffs_total,
            "signoffs_accepted": self.signoffs_accepted,
            "signoffs_conditional": self.signoffs_conditional,
            "signoffs_blocked": self.signoffs_blocked,
            "release_blockers": self.release_blockers,
            "production_blockers": self.production_blockers,
            "manual_actions": self.manual_actions,
            "entries": entries,
            "roots": self.roots.public_record(),
        })
    }

    pub fn state_root(&self) -> String {
        self.roots.manifest_root.clone()
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AuditSignoffManifestRoots {
    pub audit_source_root: String,
    pub remediation_source_root: String,
    pub signoff_root: String,
    pub blocker_root: String,
    pub manifest_root: String,
}

impl AuditSignoffManifestRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "audit_source_root": self.audit_source_root,
            "remediation_source_root": self.remediation_source_root,
            "signoff_root": self.signoff_root,
            "blocker_root": self.blocker_root,
            "manifest_root": self.manifest_root,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Counters {
    pub manifests_run: u64,
    pub manifests_release_ready: u64,
    pub manifests_remediation_required: u64,
    pub manifests_blocked: u64,
    pub signoffs_total: u64,
    pub signoffs_accepted: u64,
    pub signoffs_conditional: u64,
    pub signoffs_blocked: u64,
    pub release_blockers: u64,
    pub production_blockers: u64,
    pub manual_actions: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "manifests_run": self.manifests_run,
            "manifests_release_ready": self.manifests_release_ready,
            "manifests_remediation_required": self.manifests_remediation_required,
            "manifests_blocked": self.manifests_blocked,
            "signoffs_total": self.signoffs_total,
            "signoffs_accepted": self.signoffs_accepted,
            "signoffs_conditional": self.signoffs_conditional,
            "signoffs_blocked": self.signoffs_blocked,
            "release_blockers": self.release_blockers,
            "production_blockers": self.production_blockers,
            "manual_actions": self.manual_actions,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("counters", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub manifest_root: String,
    pub counters_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn empty(config: &Config, counters: &Counters) -> Self {
        let mut roots = Self {
            config_root: config.state_root(),
            manifest_root: merkle_root(
                "MONERO-L2-PQ-BRIDGE-EXIT-SECURITY-AUDIT-SIGNOFF-MANIFEST-EMPTY",
                &[],
            ),
            counters_root: counters.state_root(),
            state_root: String::new(),
        };
        roots.state_root = roots.compute_state_root();
        roots
    }

    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "manifest_root": self.manifest_root,
            "counters_root": self.counters_root,
            "state_root": self.state_root,
        })
    }

    pub fn compute_state_root(&self) -> String {
        domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-SECURITY-AUDIT-SIGNOFF-MANIFEST-STATE",
            &[
                HashPart::Str(&self.config_root),
                HashPart::Str(&self.manifest_root),
                HashPart::Str(&self.counters_root),
            ],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub latest_manifest: Option<AuditSignoffManifest>,
    pub manifest_history: Vec<AuditSignoffManifest>,
    pub counters: Counters,
    pub roots: Roots,
}

impl State {
    pub fn devnet() -> Self {
        let config = Config::devnet();
        let counters = Counters::default();
        let roots = Roots::empty(&config, &counters);
        let mut state = Self {
            config,
            latest_manifest: None,
            manifest_history: Vec::new(),
            counters,
            roots,
        };
        let audit_harness =
            crate::monero_l2_pq_bridge_exit_security_audit_harness_adapter_runtime::devnet();
        let remediation_planner =
            crate::monero_l2_pq_bridge_exit_release_remediation_planner_runtime::devnet();
        let _ = state.build_signoff_manifest(&audit_harness, &remediation_planner);
        state
    }

    pub fn build_signoff_manifest(
        &mut self,
        audit_harness: &SecurityAuditHarnessState,
        remediation_planner: &ReleaseRemediationPlannerState,
    ) -> Result<String> {
        let audit_report = audit_harness
            .latest_report
            .as_ref()
            .ok_or_else(|| "security audit harness has no latest report".to_string())?;
        let remediation_plan = remediation_planner
            .latest_plan
            .as_ref()
            .ok_or_else(|| "release remediation planner has no latest plan".to_string())?;
        ensure(
            audit_report.release_claim_id == remediation_plan.release_claim_id,
            "security audit signoff manifest release claim mismatch",
        )?;
        let entries = build_entries(&self.config, audit_report, remediation_plan);
        let signoffs_total = entries.len() as u64;
        ensure(
            signoffs_total >= self.config.min_signoffs,
            "security audit signoff manifest missing required domains",
        )?;
        let signoffs_accepted = entries
            .values()
            .filter(|entry| entry.status == SignoffStatus::Accepted)
            .count() as u64;
        let signoffs_conditional = entries
            .values()
            .filter(|entry| entry.status == SignoffStatus::Conditional)
            .count() as u64;
        let signoffs_blocked = entries
            .values()
            .filter(|entry| entry.status == SignoffStatus::Blocked)
            .count() as u64;
        let release_blockers = entries
            .values()
            .map(|entry| entry.release_blockers)
            .sum::<u64>();
        let production_blockers = entries
            .values()
            .map(|entry| entry.production_blockers)
            .sum::<u64>();
        let manual_actions = entries
            .values()
            .map(|entry| entry.manual_actions)
            .sum::<u64>();
        let status = manifest_status(
            &self.config,
            signoffs_blocked,
            release_blockers,
            production_blockers,
            manual_actions,
        );
        let entry_records = entries
            .values()
            .map(AuditSignoffManifestEntry::public_record)
            .collect::<Vec<_>>();
        let signoff_root = merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-SECURITY-AUDIT-SIGNOFF-MANIFEST-SIGNOFFS",
            &entry_records,
        );
        let blocker_records = entries
            .values()
            .filter(|entry| entry.status != SignoffStatus::Accepted)
            .map(AuditSignoffManifestEntry::public_record)
            .collect::<Vec<_>>();
        let blocker_root = merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-SECURITY-AUDIT-SIGNOFF-MANIFEST-BLOCKERS",
            &blocker_records,
        );
        let audit_source_root = audit_report.roots.source_root.clone();
        let remediation_source_root = remediation_plan.roots.source_root.clone();
        let manifest_root = manifest_root(
            status,
            &audit_source_root,
            &remediation_source_root,
            &signoff_root,
            &blocker_root,
            &audit_report.release_claim_id,
            signoffs_total,
            signoffs_blocked,
            release_blockers,
            production_blockers,
        );
        let manifest_id = audit_signoff_manifest_id(&audit_report.release_claim_id, &manifest_root);
        let manifest = AuditSignoffManifest {
            manifest_id: manifest_id.clone(),
            status,
            release_claim_id: audit_report.release_claim_id.clone(),
            audit_report_id: audit_report.report_id.clone(),
            audit_report_status: audit_report.status,
            remediation_plan_id: remediation_plan.plan_id.clone(),
            remediation_plan_status: remediation_plan.status,
            signoffs_total,
            signoffs_accepted,
            signoffs_conditional,
            signoffs_blocked,
            release_blockers,
            production_blockers,
            manual_actions,
            entries,
            roots: AuditSignoffManifestRoots {
                audit_source_root,
                remediation_source_root,
                signoff_root,
                blocker_root,
                manifest_root,
            },
        };
        self.record_manifest(manifest);
        Ok(manifest_id)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.config.protocol_version,
            "schema_version": self.config.schema_version,
            "manifest_suite": self.config.manifest_suite,
            "latest_manifest": self.latest_manifest.as_ref().map(AuditSignoffManifest::public_record),
            "manifest_history_len": self.manifest_history.len(),
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
        })
    }

    pub fn state_root(&self) -> String {
        self.roots.state_root.clone()
    }

    fn record_manifest(&mut self, manifest: AuditSignoffManifest) {
        self.counters.manifests_run += 1;
        self.counters.signoffs_total += manifest.signoffs_total;
        self.counters.signoffs_accepted += manifest.signoffs_accepted;
        self.counters.signoffs_conditional += manifest.signoffs_conditional;
        self.counters.signoffs_blocked += manifest.signoffs_blocked;
        self.counters.release_blockers += manifest.release_blockers;
        self.counters.production_blockers += manifest.production_blockers;
        self.counters.manual_actions += manifest.manual_actions;
        match manifest.status {
            ManifestStatus::ReleaseReady => self.counters.manifests_release_ready += 1,
            ManifestStatus::RemediationRequired => {
                self.counters.manifests_remediation_required += 1
            }
            ManifestStatus::Blocked => self.counters.manifests_blocked += 1,
        }
        self.latest_manifest = Some(manifest.clone());
        self.manifest_history.push(manifest);
        if self.manifest_history.len() > self.config.max_manifests {
            self.manifest_history.remove(0);
        }
        self.refresh_roots();
    }

    fn refresh_roots(&mut self) {
        let manifest_records = self
            .manifest_history
            .iter()
            .map(AuditSignoffManifest::public_record)
            .collect::<Vec<_>>();
        self.roots = Roots {
            config_root: self.config.state_root(),
            manifest_root: merkle_root(
                "MONERO-L2-PQ-BRIDGE-EXIT-SECURITY-AUDIT-SIGNOFF-MANIFESTS",
                &manifest_records,
            ),
            counters_root: self.counters.state_root(),
            state_root: String::new(),
        };
        self.roots.state_root = self.roots.compute_state_root();
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

fn build_entries(
    config: &Config,
    audit_report: &SecurityAuditHarnessReport,
    remediation_plan: &ReleaseRemediationPlan,
) -> BTreeMap<String, AuditSignoffManifestEntry> {
    [
        SignoffDomain::Privacy,
        SignoffDomain::PostQuantum,
        SignoffDomain::Settlement,
        SignoffDomain::ForcedExit,
        SignoffDomain::ProductionRelease,
    ]
    .into_iter()
    .map(|domain| {
        let entry =
            AuditSignoffManifestEntry::from_sources(config, domain, audit_report, remediation_plan);
        (entry.signoff_id.clone(), entry)
    })
    .collect()
}

fn signoff_status(
    config: &Config,
    domain: SignoffDomain,
    audit_report: &SecurityAuditHarnessReport,
    remediation_plan: &ReleaseRemediationPlan,
    release_blockers: u64,
    production_blockers: u64,
    manual_actions: u64,
) -> SignoffStatus {
    let required = signoff_required(config, domain);
    let audit_blocked = audit_report.status == SecurityAuditHarnessReportStatus::Failed
        || audit_report.high_or_critical_findings > 0;
    let remediation_blocked = remediation_plan.status == RemediationPlanStatus::Blocked
        || release_blockers > config.max_release_blockers
        || manual_actions > config.max_manual_actions;
    let production_blocked = domain == SignoffDomain::ProductionRelease && production_blockers > 0;
    if required && (audit_blocked || remediation_blocked || production_blocked) {
        SignoffStatus::Blocked
    } else if audit_report.status == SecurityAuditHarnessReportStatus::Watch
        || remediation_plan.status == RemediationPlanStatus::Active
        || release_blockers > 0
        || production_blockers > 0
    {
        SignoffStatus::Conditional
    } else {
        SignoffStatus::Accepted
    }
}

fn signoff_required(config: &Config, domain: SignoffDomain) -> bool {
    match domain {
        SignoffDomain::Privacy => config.require_privacy_signoff,
        SignoffDomain::PostQuantum => config.require_pq_signoff,
        SignoffDomain::Settlement => config.require_settlement_signoff,
        SignoffDomain::ForcedExit => config.require_forced_exit_signoff,
        SignoffDomain::ProductionRelease => config.require_production_release_signoff,
    }
}

fn release_blockers(
    domain: SignoffDomain,
    audit_report: &SecurityAuditHarnessReport,
    remediation_plan: &ReleaseRemediationPlan,
) -> u64 {
    let audit_holds = match domain {
        SignoffDomain::Privacy => audit_report.quarantine_required,
        SignoffDomain::PostQuantum => audit_report.high_or_critical_findings,
        SignoffDomain::Settlement => audit_report.cases_rejected,
        SignoffDomain::ForcedExit => audit_report.release_holds_required,
        SignoffDomain::ProductionRelease => audit_report.release_holds_required,
    };
    audit_holds.saturating_add(action_count(domain, remediation_plan, true))
}

fn production_blockers(
    domain: SignoffDomain,
    audit_report: &SecurityAuditHarnessReport,
    remediation_plan: &ReleaseRemediationPlan,
) -> u64 {
    let audit_blocks = match domain {
        SignoffDomain::Privacy => audit_report.medium_findings,
        SignoffDomain::PostQuantum => audit_report.high_or_critical_findings,
        SignoffDomain::Settlement => audit_report.cases_deferred,
        SignoffDomain::ForcedExit => audit_report.release_holds_required,
        SignoffDomain::ProductionRelease => remediation_plan.production_actions,
    };
    audit_blocks.saturating_add(action_count(domain, remediation_plan, false))
}

fn manual_actions(domain: SignoffDomain, remediation_plan: &ReleaseRemediationPlan) -> u64 {
    remediation_plan
        .actions
        .values()
        .filter(|action| action.manual_required && action_domain(action.kind) == domain)
        .count() as u64
}

fn action_count(
    domain: SignoffDomain,
    remediation_plan: &ReleaseRemediationPlan,
    user_release: bool,
) -> u64 {
    remediation_plan
        .actions
        .values()
        .filter(|action| action_domain(action.kind) == domain)
        .filter(|action| action.status != RemediationActionStatus::Complete)
        .filter(|action| {
            if user_release {
                action.blocks_user_release
            } else {
                action.blocks_production
            }
        })
        .count() as u64
}

fn action_domain(kind: RemediationActionKind) -> SignoffDomain {
    match kind {
        RemediationActionKind::PreservePrivacyReceiptScanning => SignoffDomain::Privacy,
        RemediationActionKind::EnablePqAuthorityVerification => SignoffDomain::PostQuantum,
        RemediationActionKind::EnableLiveSettlementExecution
        | RemediationActionKind::MaterializeCargoRuntimeTests => SignoffDomain::Settlement,
        RemediationActionKind::ResolveForcedExitUserAnswer => SignoffDomain::ForcedExit,
        RemediationActionKind::CompleteSecurityPrivacyAudit
        | RemediationActionKind::ClearProductionReleaseGate => SignoffDomain::ProductionRelease,
    }
}

fn manifest_status(
    config: &Config,
    signoffs_blocked: u64,
    release_blockers: u64,
    production_blockers: u64,
    manual_actions: u64,
) -> ManifestStatus {
    if signoffs_blocked > 0
        || release_blockers > config.max_release_blockers
        || manual_actions > config.max_manual_actions
        || (!config.production_release_allowed && production_blockers > 0)
    {
        ManifestStatus::Blocked
    } else if release_blockers > 0 || production_blockers > 0 || manual_actions > 0 {
        ManifestStatus::RemediationRequired
    } else {
        ManifestStatus::ReleaseReady
    }
}

pub fn evidence_root(
    domain: SignoffDomain,
    audit_report: &SecurityAuditHarnessReport,
    remediation_plan: &ReleaseRemediationPlan,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-SECURITY-AUDIT-SIGNOFF-EVIDENCE",
        &[
            HashPart::Str(domain.as_str()),
            HashPart::Str(&audit_report.roots.report_root),
            HashPart::Str(&audit_report.roots.case_root),
            HashPart::Str(&audit_report.roots.response_root),
            HashPart::Str(&remediation_plan.roots.plan_root),
            HashPart::Str(&remediation_plan.roots.action_root),
        ],
        32,
    )
}

pub fn audit_alignment_root(
    domain: SignoffDomain,
    audit_report: &SecurityAuditHarnessReport,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-SECURITY-AUDIT-SIGNOFF-AUDIT-ALIGNMENT",
        &[
            HashPart::Str(domain.as_str()),
            HashPart::Str(audit_report.status.as_str()),
            HashPart::U64(audit_report.cases_total),
            HashPart::U64(audit_report.cases_passed),
            HashPart::U64(audit_report.cases_deferred),
            HashPart::U64(audit_report.cases_rejected),
            HashPart::U64(audit_report.findings_total),
            HashPart::U64(audit_report.high_or_critical_findings),
        ],
        32,
    )
}

pub fn remediation_alignment_root(
    domain: SignoffDomain,
    remediation_plan: &ReleaseRemediationPlan,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-SECURITY-AUDIT-SIGNOFF-REMEDIATION-ALIGNMENT",
        &[
            HashPart::Str(domain.as_str()),
            HashPart::Str(remediation_plan.status.as_str()),
            HashPart::U64(remediation_plan.actions_total),
            HashPart::U64(remediation_plan.actions_ready),
            HashPart::U64(remediation_plan.actions_waiting),
            HashPart::U64(remediation_plan.actions_blocked),
            HashPart::U64(remediation_plan.production_actions),
            HashPart::U64(remediation_plan.manual_actions),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn acceptance_root(
    domain: SignoffDomain,
    status: SignoffStatus,
    evidence_root: &str,
    audit_root: &str,
    remediation_root: &str,
    release_blockers: u64,
    production_blockers: u64,
    manual_actions: u64,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-SECURITY-AUDIT-SIGNOFF-ACCEPTANCE",
        &[
            HashPart::Str(domain.as_str()),
            HashPart::Str(status.as_str()),
            HashPart::Str(evidence_root),
            HashPart::Str(audit_root),
            HashPart::Str(remediation_root),
            HashPart::U64(release_blockers),
            HashPart::U64(production_blockers),
            HashPart::U64(manual_actions),
        ],
        32,
    )
}

pub fn blocker_root(
    domain: SignoffDomain,
    status: SignoffStatus,
    release_blockers: u64,
    production_blockers: u64,
    manual_actions: u64,
    remediation_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-SECURITY-AUDIT-SIGNOFF-BLOCKER",
        &[
            HashPart::Str(domain.as_str()),
            HashPart::Str(status.as_str()),
            HashPart::U64(release_blockers),
            HashPart::U64(production_blockers),
            HashPart::U64(manual_actions),
            HashPart::Str(remediation_root),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn audit_signoff_root(
    domain: SignoffDomain,
    status: SignoffStatus,
    audit_report_id: &str,
    remediation_plan_id: &str,
    evidence_root: &str,
    acceptance_root: &str,
    blocker_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-SECURITY-AUDIT-SIGNOFF",
        &[
            HashPart::Str(domain.as_str()),
            HashPart::Str(status.as_str()),
            HashPart::Str(audit_report_id),
            HashPart::Str(remediation_plan_id),
            HashPart::Str(evidence_root),
            HashPart::Str(acceptance_root),
            HashPart::Str(blocker_root),
        ],
        32,
    )
}

pub fn audit_signoff_id(
    domain: SignoffDomain,
    release_claim_id: &str,
    signoff_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-SECURITY-AUDIT-SIGNOFF-ID",
        &[
            HashPart::Str(domain.as_str()),
            HashPart::Str(release_claim_id),
            HashPart::Str(signoff_root),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn manifest_root(
    status: ManifestStatus,
    audit_source_root: &str,
    remediation_source_root: &str,
    signoff_root: &str,
    blocker_root: &str,
    release_claim_id: &str,
    signoffs_total: u64,
    signoffs_blocked: u64,
    release_blockers: u64,
    production_blockers: u64,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-SECURITY-AUDIT-SIGNOFF-MANIFEST",
        &[
            HashPart::Str(status.as_str()),
            HashPart::Str(audit_source_root),
            HashPart::Str(remediation_source_root),
            HashPart::Str(signoff_root),
            HashPart::Str(blocker_root),
            HashPart::Str(release_claim_id),
            HashPart::U64(signoffs_total),
            HashPart::U64(signoffs_blocked),
            HashPart::U64(release_blockers),
            HashPart::U64(production_blockers),
        ],
        32,
    )
}

pub fn audit_signoff_manifest_id(release_claim_id: &str, manifest_root: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-SECURITY-AUDIT-SIGNOFF-MANIFEST-ID",
        &[
            HashPart::Str(release_claim_id),
            HashPart::Str(manifest_root),
        ],
        32,
    )
}

pub fn record_root(kind: &str, record: &Value) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-SECURITY-AUDIT-SIGNOFF-MANIFEST-RECORD",
        &[HashPart::Str(kind), HashPart::Json(record)],
        32,
    )
}

pub fn ensure(condition: bool, message: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(message.to_string())
    }
}

pub fn highest_finding_severity(
    report: &SecurityAuditHarnessReport,
) -> SecurityAuditFindingSeverity {
    if report.high_or_critical_findings > 0 {
        SecurityAuditFindingSeverity::High
    } else if report.medium_findings > 0 {
        SecurityAuditFindingSeverity::Medium
    } else if report.findings_total > 0 {
        SecurityAuditFindingSeverity::Low
    } else {
        SecurityAuditFindingSeverity::None
    }
}
