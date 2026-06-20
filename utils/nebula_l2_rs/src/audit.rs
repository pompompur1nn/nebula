use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    config::{NebulaRuntimeProfile, DEFAULT_QUANTUM_RESISTANCE_POLICY},
    daemon::NebulaDaemon,
    devnet::DevnetRunSummary,
    hash::{domain_hash, merkle_root, HashPart},
    p2p::P2pOverlayState,
    relayer::RelayerState,
    rpc::RpcControlPlaneState,
    storage::StorageState,
    telemetry::TelemetryState,
    workload::WorkloadPlannerState,
    CHAIN_ID, TARGET_BLOCK_MS,
};

pub type AuditResult<T> = Result<T, String>;

pub const AUDIT_PROTOCOL_VERSION: &str = "nebula-l2-audit-v1";
pub const AUDIT_MIN_READY_SCORE: u64 = 80;
pub const AUDIT_WARN_SCORE: u64 = 60;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum AuditCategory {
    QuantumResistance,
    Speed,
    Defi,
    LowFees,
    Privacy,
    MoneroBridge,
    Storage,
    P2p,
    Rpc,
    Telemetry,
}

impl AuditCategory {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::QuantumResistance => "quantum_resistance",
            Self::Speed => "speed",
            Self::Defi => "defi",
            Self::LowFees => "low_fees",
            Self::Privacy => "privacy",
            Self::MoneroBridge => "monero_bridge",
            Self::Storage => "storage",
            Self::P2p => "p2p",
            Self::Rpc => "rpc",
            Self::Telemetry => "telemetry",
        }
    }

    pub fn all() -> Vec<Self> {
        vec![
            Self::QuantumResistance,
            Self::Speed,
            Self::Defi,
            Self::LowFees,
            Self::Privacy,
            Self::MoneroBridge,
            Self::Storage,
            Self::P2p,
            Self::Rpc,
            Self::Telemetry,
        ]
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum AuditSeverity {
    Info,
    Warning,
    Critical,
}

impl AuditSeverity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Warning => "warning",
            Self::Critical => "critical",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditFinding {
    pub finding_id: String,
    pub category: AuditCategory,
    pub severity: AuditSeverity,
    pub title: String,
    pub evidence_root: String,
    pub recommendation: String,
    pub score_delta: i64,
}

impl AuditFinding {
    pub fn new(
        category: AuditCategory,
        severity: AuditSeverity,
        title: impl Into<String>,
        evidence: &Value,
        recommendation: impl Into<String>,
        score_delta: i64,
    ) -> Self {
        let title = title.into();
        let recommendation = recommendation.into();
        let evidence_root = audit_payload_root("AUDIT-FINDING-EVIDENCE", evidence);
        let finding_id =
            audit_finding_id(category.as_str(), severity.as_str(), &title, &evidence_root);
        Self {
            finding_id,
            category,
            severity,
            title,
            evidence_root,
            recommendation,
            score_delta,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "audit_finding",
            "chain_id": CHAIN_ID,
            "audit_protocol_version": AUDIT_PROTOCOL_VERSION,
            "finding_id": self.finding_id,
            "category": self.category.as_str(),
            "severity": self.severity.as_str(),
            "title": self.title,
            "evidence_root": self.evidence_root,
            "recommendation": self.recommendation,
            "score_delta": self.score_delta,
        })
    }

    pub fn finding_root(&self) -> String {
        domain_hash(
            "AUDIT-FINDING",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditScore {
    pub category: AuditCategory,
    pub score: u64,
    pub finding_root: String,
    pub finding_count: u64,
    pub status: String,
}

impl AuditScore {
    pub fn from_findings(category: AuditCategory, findings: &[AuditFinding]) -> Self {
        let raw = findings
            .iter()
            .filter(|finding| finding.category == category)
            .fold(100_i64, |score, finding| score + finding.score_delta);
        let score = raw.clamp(0, 100) as u64;
        let category_findings = findings
            .iter()
            .filter(|finding| finding.category == category)
            .cloned()
            .collect::<Vec<_>>();
        let finding_root = audit_finding_root(&category_findings);
        let status = if score >= AUDIT_MIN_READY_SCORE {
            "ready"
        } else if score >= AUDIT_WARN_SCORE {
            "needs_attention"
        } else {
            "incomplete"
        }
        .to_string();
        Self {
            category,
            score,
            finding_root,
            finding_count: category_findings.len() as u64,
            status,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "audit_score",
            "chain_id": CHAIN_ID,
            "audit_protocol_version": AUDIT_PROTOCOL_VERSION,
            "category": self.category.as_str(),
            "score": self.score,
            "finding_root": self.finding_root,
            "finding_count": self.finding_count,
            "status": self.status,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditTargetRoots {
    pub profile_root: String,
    pub daemon_root: String,
    pub devnet_summary_root: String,
    pub p2p_root: String,
    pub rpc_root: String,
    pub relayer_root: String,
    pub storage_root: String,
    pub telemetry_root: String,
    pub workload_root: String,
}

impl AuditTargetRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "audit_target_roots",
            "chain_id": CHAIN_ID,
            "audit_protocol_version": AUDIT_PROTOCOL_VERSION,
            "profile_root": self.profile_root,
            "daemon_root": self.daemon_root,
            "devnet_summary_root": self.devnet_summary_root,
            "p2p_root": self.p2p_root,
            "rpc_root": self.rpc_root,
            "relayer_root": self.relayer_root,
            "storage_root": self.storage_root,
            "telemetry_root": self.telemetry_root,
            "workload_root": self.workload_root,
        })
    }

    pub fn target_root(&self) -> String {
        domain_hash(
            "AUDIT-TARGET-ROOTS",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditReport {
    pub report_id: String,
    pub generated_at_height: u64,
    pub target_roots: AuditTargetRoots,
    pub finding_root: String,
    pub score_root: String,
    pub overall_score: u64,
    pub status: String,
    pub findings: Vec<AuditFinding>,
    pub scores: Vec<AuditScore>,
}

impl AuditReport {
    pub fn new(
        generated_at_height: u64,
        target_roots: AuditTargetRoots,
        findings: Vec<AuditFinding>,
    ) -> Self {
        let scores = AuditCategory::all()
            .into_iter()
            .map(|category| AuditScore::from_findings(category, &findings))
            .collect::<Vec<_>>();
        let finding_root = audit_finding_root(&findings);
        let score_root = audit_score_root(&scores);
        let overall_score = if scores.is_empty() {
            0
        } else {
            scores.iter().map(|score| score.score).sum::<u64>() / scores.len() as u64
        };
        let status = if overall_score >= AUDIT_MIN_READY_SCORE
            && !findings
                .iter()
                .any(|finding| finding.severity == AuditSeverity::Critical)
        {
            "ready"
        } else if overall_score >= AUDIT_WARN_SCORE {
            "needs_attention"
        } else {
            "incomplete"
        }
        .to_string();
        let report_id = audit_report_id(
            generated_at_height,
            &target_roots.target_root(),
            &finding_root,
            &score_root,
            overall_score,
        );
        Self {
            report_id,
            generated_at_height,
            target_roots,
            finding_root,
            score_root,
            overall_score,
            status,
            findings,
            scores,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "audit_report",
            "chain_id": CHAIN_ID,
            "audit_protocol_version": AUDIT_PROTOCOL_VERSION,
            "report_id": self.report_id,
            "generated_at_height": self.generated_at_height,
            "target_roots": self.target_roots.public_record(),
            "finding_root": self.finding_root,
            "score_root": self.score_root,
            "overall_score": self.overall_score,
            "status": self.status,
            "finding_count": self.findings.len() as u64,
            "scores": self.scores.iter().map(AuditScore::public_record).collect::<Vec<_>>(),
        })
    }

    pub fn report_root(&self) -> String {
        domain_hash("AUDIT-REPORT", &[HashPart::Json(&self.public_record())], 32)
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditState {
    pub reports: BTreeMap<String, AuditReport>,
}

impl AuditState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert_report(&mut self, report: AuditReport) -> AuditResult<String> {
        if self.reports.contains_key(&report.report_id) {
            return Err("audit report already exists".to_string());
        }
        let report_id = report.report_id.clone();
        self.reports.insert(report_id.clone(), report);
        Ok(report_id)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn audit_runtime(
        &mut self,
        profile: &NebulaRuntimeProfile,
        daemon: &NebulaDaemon,
        devnet_summary: Option<&DevnetRunSummary>,
        p2p: &P2pOverlayState,
        rpc: &RpcControlPlaneState,
        relayer: &RelayerState,
        storage: &StorageState,
        telemetry: Option<&TelemetryState>,
        workload: Option<&WorkloadPlannerState>,
    ) -> AuditResult<AuditReport> {
        let report = audit_runtime(
            profile,
            daemon,
            devnet_summary,
            p2p,
            rpc,
            relayer,
            storage,
            telemetry,
            workload,
        );
        self.insert_report(report.clone())?;
        Ok(report)
    }

    pub fn report_root(&self) -> String {
        merkle_root(
            "AUDIT-REPORT",
            &self
                .reports
                .values()
                .map(AuditReport::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "audit_state",
            "chain_id": CHAIN_ID,
            "audit_protocol_version": AUDIT_PROTOCOL_VERSION,
            "report_root": self.report_root(),
            "report_count": self.reports.len() as u64,
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash("AUDIT-STATE", &[HashPart::Json(&self.public_record())], 32)
    }
}

#[allow(clippy::too_many_arguments)]
pub fn audit_runtime(
    profile: &NebulaRuntimeProfile,
    daemon: &NebulaDaemon,
    devnet_summary: Option<&DevnetRunSummary>,
    p2p: &P2pOverlayState,
    rpc: &RpcControlPlaneState,
    relayer: &RelayerState,
    storage: &StorageState,
    telemetry: Option<&TelemetryState>,
    workload: Option<&WorkloadPlannerState>,
) -> AuditReport {
    let mut findings = Vec::new();
    audit_profile(profile, &mut findings);
    audit_daemon(daemon, &mut findings);
    audit_devnet_summary(devnet_summary, &mut findings);
    audit_p2p(p2p, &mut findings);
    audit_rpc(rpc, &mut findings);
    audit_relayer(relayer, &mut findings);
    audit_storage(storage, &mut findings);
    audit_telemetry(telemetry, &mut findings);
    audit_workload(workload, &mut findings);
    let target_roots = AuditTargetRoots {
        profile_root: profile.profile_root(),
        daemon_root: daemon.daemon_root(),
        devnet_summary_root: devnet_summary
            .map(DevnetRunSummary::summary_root)
            .unwrap_or_else(|| merkle_root("AUDIT-EMPTY-DEVNET-SUMMARY", &[])),
        p2p_root: p2p.overlay_root(),
        rpc_root: rpc.state_root(),
        relayer_root: relayer.state_root(),
        storage_root: storage.manifest_root(),
        telemetry_root: telemetry
            .map(TelemetryState::state_root)
            .unwrap_or_else(|| merkle_root("AUDIT-EMPTY-TELEMETRY", &[])),
        workload_root: workload
            .map(WorkloadPlannerState::state_root)
            .unwrap_or_else(|| merkle_root("AUDIT-EMPTY-WORKLOAD", &[])),
    };
    AuditReport::new(daemon.node.height(), target_roots, findings)
}

fn audit_profile(profile: &NebulaRuntimeProfile, findings: &mut Vec<AuditFinding>) {
    if profile.quantum_resistance_policy != DEFAULT_QUANTUM_RESISTANCE_POLICY {
        findings.push(AuditFinding::new(
            AuditCategory::QuantumResistance,
            AuditSeverity::Critical,
            "runtime profile does not use default quantum resistance policy",
            &profile.public_record(),
            "Use the ML-DSA/SLH-DSA/SHAKE256 policy before treating the profile as production-like.",
            -60,
        ));
    }
    if profile.block_time_ms > TARGET_BLOCK_MS {
        findings.push(AuditFinding::new(
            AuditCategory::Speed,
            AuditSeverity::Warning,
            "profile block time is slower than target",
            &json!({"block_time_ms": profile.block_time_ms, "target_block_ms": TARGET_BLOCK_MS}),
            "Lower block_time_ms or use the local_fast profile for speed work.",
            -15,
        ));
    }
    if !profile.low_fee.enabled || profile.low_fee.epoch_budget_units == 0 {
        findings.push(AuditFinding::new(
            AuditCategory::LowFees,
            AuditSeverity::Critical,
            "low-fee lanes are disabled",
            &profile.public_record(),
            "Enable low-fee lanes for privacy transfers, bridge operations, and small DeFi calls.",
            -60,
        ));
    }
    if !profile.privacy_mode.contains("hash")
        && !profile.privacy_mode.contains("confidential")
        && !profile.privacy_mode.contains("private")
    {
        findings.push(AuditFinding::new(
            AuditCategory::Privacy,
            AuditSeverity::Warning,
            "privacy mode is not privacy-oriented",
            &profile.public_record(),
            "Use hashes_only, confidential_da, or relay_private privacy modes.",
            -20,
        ));
    }
}

fn audit_daemon(daemon: &NebulaDaemon, findings: &mut Vec<AuditFinding>) {
    if daemon.node.height() == 0 {
        findings.push(AuditFinding::new(
            AuditCategory::Speed,
            AuditSeverity::Warning,
            "daemon has not produced blocks",
            &daemon.public_record(),
            "Run the devnet loop or produce at least one block before assessing speed.",
            -20,
        ));
    }
    if daemon.daemon_root().is_empty() {
        findings.push(AuditFinding::new(
            AuditCategory::Storage,
            AuditSeverity::Critical,
            "daemon root is empty",
            &daemon.public_record(),
            "Ensure daemon state, API, storage, and node roots are committed.",
            -50,
        ));
    }
}

fn audit_devnet_summary(summary: Option<&DevnetRunSummary>, findings: &mut Vec<AuditFinding>) {
    match summary {
        Some(summary) if summary.success && summary.block_count > 0 => {}
        Some(summary) => findings.push(AuditFinding::new(
            AuditCategory::Speed,
            AuditSeverity::Warning,
            "devnet run summary is not successful",
            &summary.public_record(),
            "Complete a successful devnet run with produced blocks.",
            -20,
        )),
        None => findings.push(AuditFinding::new(
            AuditCategory::Speed,
            AuditSeverity::Warning,
            "devnet summary is missing",
            &json!({ "summary": null }),
            "Capture a DevnetRunSummary after running the node loop.",
            -15,
        )),
    }
}

fn audit_p2p(p2p: &P2pOverlayState, findings: &mut Vec<AuditFinding>) {
    if p2p.handshakes.is_empty() {
        findings.push(AuditFinding::new(
            AuditCategory::P2p,
            AuditSeverity::Warning,
            "p2p overlay has no peers",
            &p2p.public_record(),
            "Install local or remote P2P handshakes before syncing roots.",
            -25,
        ));
    }
}

fn audit_rpc(rpc: &RpcControlPlaneState, findings: &mut Vec<AuditFinding>) {
    if rpc.method_registry.is_empty() {
        findings.push(AuditFinding::new(
            AuditCategory::Rpc,
            AuditSeverity::Warning,
            "rpc method registry is empty",
            &rpc.public_record(),
            "Register default RPC methods for status, fee quote, block production, and bridge status.",
            -25,
        ));
    }
}

fn audit_relayer(relayer: &RelayerState, findings: &mut Vec<AuditFinding>) {
    if relayer.endpoints.is_empty() {
        findings.push(AuditFinding::new(
            AuditCategory::MoneroBridge,
            AuditSeverity::Critical,
            "relayer has no Monero endpoints",
            &relayer.public_record(),
            "Configure at least one Monero RPC/ZMQ commitment for bridge anchoring and withdrawals.",
            -50,
        ));
    }
}

fn audit_storage(storage: &StorageState, findings: &mut Vec<AuditFinding>) {
    if storage.snapshots.is_empty() {
        findings.push(AuditFinding::new(
            AuditCategory::Storage,
            AuditSeverity::Warning,
            "storage has no snapshots",
            &storage.public_record(),
            "Commit periodic storage snapshots so devnet state can be replayed.",
            -20,
        ));
    }
}

fn audit_telemetry(telemetry: Option<&TelemetryState>, findings: &mut Vec<AuditFinding>) {
    if telemetry.is_none() {
        findings.push(AuditFinding::new(
            AuditCategory::Telemetry,
            AuditSeverity::Warning,
            "telemetry state is missing",
            &json!({ "telemetry": null }),
            "Capture protocol counters/gauges for daemon, RPC, P2P, relayer, and storage.",
            -15,
        ));
    }
}

fn audit_workload(workload: Option<&WorkloadPlannerState>, findings: &mut Vec<AuditFinding>) {
    match workload {
        Some(workload) if !workload.batches.is_empty() => {}
        Some(workload) => findings.push(AuditFinding::new(
            AuditCategory::Defi,
            AuditSeverity::Warning,
            "workload planner has not produced batches",
            &workload.public_record(),
            "Run workload planning to exercise private transfers, DeFi, bridge, and proof jobs.",
            -20,
        )),
        None => findings.push(AuditFinding::new(
            AuditCategory::Defi,
            AuditSeverity::Warning,
            "workload planner is missing",
            &json!({ "workload": null }),
            "Attach a workload planner to the devnet runner.",
            -15,
        )),
    }
}

pub fn audit_finding_id(
    category: &str,
    severity: &str,
    title: &str,
    evidence_root: &str,
) -> String {
    domain_hash(
        "AUDIT-FINDING-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(category),
            HashPart::Str(severity),
            HashPart::Str(title),
            HashPart::Str(evidence_root),
        ],
        32,
    )
}

pub fn audit_report_id(
    generated_at_height: u64,
    target_root: &str,
    finding_root: &str,
    score_root: &str,
    overall_score: u64,
) -> String {
    domain_hash(
        "AUDIT-REPORT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(generated_at_height as i128),
            HashPart::Str(target_root),
            HashPart::Str(finding_root),
            HashPart::Str(score_root),
            HashPart::Int(overall_score as i128),
        ],
        32,
    )
}

pub fn audit_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[HashPart::Str(CHAIN_ID), HashPart::Json(payload)],
        32,
    )
}

pub fn audit_finding_root(findings: &[AuditFinding]) -> String {
    merkle_root(
        "AUDIT-FINDING",
        &findings
            .iter()
            .map(AuditFinding::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn audit_score_root(scores: &[AuditScore]) -> String {
    merkle_root(
        "AUDIT-SCORE",
        &scores
            .iter()
            .map(AuditScore::public_record)
            .collect::<Vec<_>>(),
    )
}
