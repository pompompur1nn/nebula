use std::collections::BTreeMap;

const CHAIN_ID: &str = "nebula-monero-private-l2-devnet";
const PROTOCOL_VERSION: &str =
    "wave105-live-heavy-gate-release-execution-monero-confirmed-credit-accounting-guard-wallet-watchtower-lane-runtime-v1";
const LANE_ID: &str =
    "wave105-live-heavy-gate-release-execution-monero-confirmed-credit-accounting-guard-wallet-watchtower";
const WAVE: u64 = 105;
const MIN_MONERO_CONFIRMATIONS: u64 = 720;
const MIN_WATCHTOWER_QUORUM: u16 = 3;
const MIN_WALLET_HISTORY_EPOCH: u64 = 105_000;
const MIN_ACCOUNTING_EPOCH: u64 = 105_100;
const MIN_RESERVE_COVER_BPS: u16 = 10_000;
const MAX_FEE_REBATE_DRIFT_BPS: u16 = 2;
const ROOT_HEX_LEN: usize = 64;

pub type PublicRecord = String;
pub type Runtime = State;
pub type Result<T> = std::result::Result<T, CreditAccountingError>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CreditAccountingError {
    InvalidConfig(&'static str),
    InvalidRoot(&'static str),
    MissingRoot(&'static str),
    RootsOnlyBoundaryViolated,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum GateKind {
    Watchtower,
    WalletHistory,
    Reorg,
    Confirmation,
    Accounting,
    FeeRebate,
    Reserve,
    PqAuthorization,
    CircuitBreaker,
    LiveEvidence,
    Signoff,
    RootsOnly,
}

impl GateKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Watchtower => "watchtower",
            Self::WalletHistory => "wallet_history",
            Self::Reorg => "reorg",
            Self::Confirmation => "confirmation",
            Self::Accounting => "accounting",
            Self::FeeRebate => "fee_rebate",
            Self::Reserve => "reserve",
            Self::PqAuthorization => "pq_authorization",
            Self::CircuitBreaker => "circuit_breaker",
            Self::LiveEvidence => "live_evidence",
            Self::Signoff => "signoff",
            Self::RootsOnly => "roots_only",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GateStatus {
    Missing,
    Failed,
    Clear,
}

impl GateStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Missing => "missing",
            Self::Failed => "failed",
            Self::Clear => "clear",
        }
    }

    pub fn is_clear(self) -> bool {
        self == Self::Clear
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AccountingDecision {
    FailClosed,
    EvidenceObserved,
    HeavyGateCandidate,
    ReleaseCreditAllowed,
}

impl AccountingDecision {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FailClosed => "fail_closed",
            Self::EvidenceObserved => "evidence_observed",
            Self::HeavyGateCandidate => "heavy_gate_candidate",
            Self::ReleaseCreditAllowed => "release_credit_allowed",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub wave: u64,
    pub lane_id: String,
    pub min_monero_confirmations: u64,
    pub min_watchtower_quorum: u16,
    pub min_wallet_history_epoch: u64,
    pub min_accounting_epoch: u64,
    pub min_reserve_cover_bps: u16,
    pub max_fee_rebate_drift_bps: u16,
    pub require_watchtower_root: bool,
    pub require_wallet_history_root: bool,
    pub require_reorg_root: bool,
    pub require_confirmation_root: bool,
    pub require_accounting_root: bool,
    pub require_fee_rebate_root: bool,
    pub require_reserve_root: bool,
    pub require_pq_authorization_root: bool,
    pub require_circuit_breaker_root: bool,
    pub require_live_evidence_root: bool,
    pub require_operator_signoff_root: bool,
    pub require_reviewer_signoff_root: bool,
    pub require_roots_only_records: bool,
    pub arm_circuit_breaker_by_default: bool,
    pub heavy_gates_ran: bool,
    pub release_credit_allowed: bool,
    pub credit_accounting_allowed: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            wave: WAVE,
            lane_id: LANE_ID.to_string(),
            min_monero_confirmations: MIN_MONERO_CONFIRMATIONS,
            min_watchtower_quorum: MIN_WATCHTOWER_QUORUM,
            min_wallet_history_epoch: MIN_WALLET_HISTORY_EPOCH,
            min_accounting_epoch: MIN_ACCOUNTING_EPOCH,
            min_reserve_cover_bps: MIN_RESERVE_COVER_BPS,
            max_fee_rebate_drift_bps: MAX_FEE_REBATE_DRIFT_BPS,
            require_watchtower_root: true,
            require_wallet_history_root: true,
            require_reorg_root: true,
            require_confirmation_root: true,
            require_accounting_root: true,
            require_fee_rebate_root: true,
            require_reserve_root: true,
            require_pq_authorization_root: true,
            require_circuit_breaker_root: true,
            require_live_evidence_root: true,
            require_operator_signoff_root: true,
            require_reviewer_signoff_root: true,
            require_roots_only_records: true,
            arm_circuit_breaker_by_default: true,
            heavy_gates_ran: false,
            release_credit_allowed: false,
            credit_accounting_allowed: false,
        }
    }
}

impl Config {
    pub fn public_record(&self) -> PublicRecord {
        let mut record = RecordBuilder::new("config");
        record.field("chain_id", &self.chain_id);
        record.field("protocol_version", &self.protocol_version);
        record.u64_field("wave", self.wave);
        record.field("lane_id", &self.lane_id);
        record.u64_field("min_monero_confirmations", self.min_monero_confirmations);
        record.u64_field("min_watchtower_quorum", self.min_watchtower_quorum as u64);
        record.u64_field("min_wallet_history_epoch", self.min_wallet_history_epoch);
        record.u64_field("min_accounting_epoch", self.min_accounting_epoch);
        record.u64_field("min_reserve_cover_bps", self.min_reserve_cover_bps as u64);
        record.u64_field(
            "max_fee_rebate_drift_bps",
            self.max_fee_rebate_drift_bps as u64,
        );
        record.bool_field(
            "require_roots_only_records",
            self.require_roots_only_records,
        );
        record.bool_field(
            "arm_circuit_breaker_by_default",
            self.arm_circuit_breaker_by_default,
        );
        record.bool_field("release_credit_allowed", self.release_credit_allowed);
        record.bool_field("credit_accounting_allowed", self.credit_accounting_allowed);
        record.bool_field("heavy_gates_ran", self.heavy_gates_ran);
        record.list_field("fail_closed_defaults", fail_closed_snippets());
        record.finish()
    }

    pub fn validate(&self) -> Result<()> {
        if self.chain_id != CHAIN_ID {
            return Err(CreditAccountingError::InvalidConfig("chain_id"));
        }
        if self.protocol_version != PROTOCOL_VERSION {
            return Err(CreditAccountingError::InvalidConfig("protocol_version"));
        }
        if self.wave != WAVE {
            return Err(CreditAccountingError::InvalidConfig("wave"));
        }
        if self.lane_id != LANE_ID {
            return Err(CreditAccountingError::InvalidConfig("lane_id"));
        }
        if self.min_monero_confirmations == 0 {
            return Err(CreditAccountingError::InvalidConfig(
                "min_monero_confirmations",
            ));
        }
        if self.min_watchtower_quorum == 0 {
            return Err(CreditAccountingError::InvalidConfig(
                "min_watchtower_quorum",
            ));
        }
        if self.min_reserve_cover_bps < MIN_RESERVE_COVER_BPS {
            return Err(CreditAccountingError::InvalidConfig(
                "min_reserve_cover_bps",
            ));
        }
        if !self.require_roots_only_records {
            return Err(CreditAccountingError::RootsOnlyBoundaryViolated);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RootBundle {
    pub watchtower_root: String,
    pub wallet_history_root: String,
    pub reorg_root: String,
    pub confirmation_root: String,
    pub accounting_root: String,
    pub fee_rebate_root: String,
    pub reserve_root: String,
    pub pq_authorization_root: String,
    pub circuit_breaker_root: String,
    pub live_evidence_root: String,
    pub operator_signoff_root: String,
    pub reviewer_signoff_root: String,
}

impl Default for RootBundle {
    fn default() -> Self {
        Self {
            watchtower_root: String::new(),
            wallet_history_root: String::new(),
            reorg_root: String::new(),
            confirmation_root: String::new(),
            accounting_root: String::new(),
            fee_rebate_root: String::new(),
            reserve_root: String::new(),
            pq_authorization_root: String::new(),
            circuit_breaker_root: String::new(),
            live_evidence_root: String::new(),
            operator_signoff_root: String::new(),
            reviewer_signoff_root: String::new(),
        }
    }
}

impl RootBundle {
    pub fn root_for(&self, gate: GateKind) -> &str {
        match gate {
            GateKind::Watchtower => &self.watchtower_root,
            GateKind::WalletHistory => &self.wallet_history_root,
            GateKind::Reorg => &self.reorg_root,
            GateKind::Confirmation => &self.confirmation_root,
            GateKind::Accounting => &self.accounting_root,
            GateKind::FeeRebate => &self.fee_rebate_root,
            GateKind::Reserve => &self.reserve_root,
            GateKind::PqAuthorization => &self.pq_authorization_root,
            GateKind::CircuitBreaker => &self.circuit_breaker_root,
            GateKind::LiveEvidence => &self.live_evidence_root,
            GateKind::Signoff => &self.operator_signoff_root,
            GateKind::RootsOnly => &self.reviewer_signoff_root,
        }
    }

    pub fn validate_required(&self, config: &Config) -> Result<()> {
        for check in [
            (
                "watchtower_root",
                &self.watchtower_root,
                config.require_watchtower_root,
            ),
            (
                "wallet_history_root",
                &self.wallet_history_root,
                config.require_wallet_history_root,
            ),
            ("reorg_root", &self.reorg_root, config.require_reorg_root),
            (
                "confirmation_root",
                &self.confirmation_root,
                config.require_confirmation_root,
            ),
            (
                "accounting_root",
                &self.accounting_root,
                config.require_accounting_root,
            ),
            (
                "fee_rebate_root",
                &self.fee_rebate_root,
                config.require_fee_rebate_root,
            ),
            (
                "reserve_root",
                &self.reserve_root,
                config.require_reserve_root,
            ),
            (
                "pq_authorization_root",
                &self.pq_authorization_root,
                config.require_pq_authorization_root,
            ),
            (
                "circuit_breaker_root",
                &self.circuit_breaker_root,
                config.require_circuit_breaker_root,
            ),
            (
                "live_evidence_root",
                &self.live_evidence_root,
                config.require_live_evidence_root,
            ),
            (
                "operator_signoff_root",
                &self.operator_signoff_root,
                config.require_operator_signoff_root,
            ),
            (
                "reviewer_signoff_root",
                &self.reviewer_signoff_root,
                config.require_reviewer_signoff_root,
            ),
        ] {
            validate_root_when_required(check.0, check.1, check.2)?;
        }
        Ok(())
    }

    pub fn public_record(&self) -> PublicRecord {
        let mut record = RecordBuilder::new("roots");
        record.root_field("watchtower_root", &self.watchtower_root);
        record.root_field("wallet_history_root", &self.wallet_history_root);
        record.root_field("reorg_root", &self.reorg_root);
        record.root_field("confirmation_root", &self.confirmation_root);
        record.root_field("accounting_root", &self.accounting_root);
        record.root_field("fee_rebate_root", &self.fee_rebate_root);
        record.root_field("reserve_root", &self.reserve_root);
        record.root_field("pq_authorization_root", &self.pq_authorization_root);
        record.root_field("circuit_breaker_root", &self.circuit_breaker_root);
        record.root_field("live_evidence_root", &self.live_evidence_root);
        record.root_field("operator_signoff_root", &self.operator_signoff_root);
        record.root_field("reviewer_signoff_root", &self.reviewer_signoff_root);
        record.finish()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EvidenceStatus {
    pub monero_confirmations: u64,
    pub watchtower_quorum: u16,
    pub wallet_history_epoch: u64,
    pub accounting_epoch: u64,
    pub reserve_cover_bps: u16,
    pub fee_rebate_drift_bps: u16,
    pub reorg_safe: bool,
    pub circuit_breaker_armed: bool,
    pub live_evidence_seen: bool,
    pub pq_authorized: bool,
    pub operator_signed: bool,
    pub reviewer_signed: bool,
    pub roots_only: bool,
}

impl Default for EvidenceStatus {
    fn default() -> Self {
        Self {
            monero_confirmations: 0,
            watchtower_quorum: 0,
            wallet_history_epoch: 0,
            accounting_epoch: 0,
            reserve_cover_bps: 0,
            fee_rebate_drift_bps: u16::MAX,
            reorg_safe: false,
            circuit_breaker_armed: true,
            live_evidence_seen: false,
            pq_authorized: false,
            operator_signed: false,
            reviewer_signed: false,
            roots_only: true,
        }
    }
}

impl EvidenceStatus {
    pub fn devnet_clear(config: &Config) -> Self {
        Self {
            monero_confirmations: config.min_monero_confirmations,
            watchtower_quorum: config.min_watchtower_quorum,
            wallet_history_epoch: config.min_wallet_history_epoch,
            accounting_epoch: config.min_accounting_epoch,
            reserve_cover_bps: config.min_reserve_cover_bps,
            fee_rebate_drift_bps: 0,
            reorg_safe: true,
            circuit_breaker_armed: false,
            live_evidence_seen: true,
            pq_authorized: true,
            operator_signed: true,
            reviewer_signed: true,
            roots_only: true,
        }
    }

    pub fn public_record(&self) -> PublicRecord {
        let mut record = RecordBuilder::new("evidence_status");
        record.u64_field("monero_confirmations", self.monero_confirmations);
        record.u64_field("watchtower_quorum", self.watchtower_quorum as u64);
        record.u64_field("wallet_history_epoch", self.wallet_history_epoch);
        record.u64_field("accounting_epoch", self.accounting_epoch);
        record.u64_field("reserve_cover_bps", self.reserve_cover_bps as u64);
        record.u64_field("fee_rebate_drift_bps", self.fee_rebate_drift_bps as u64);
        record.bool_field("reorg_safe", self.reorg_safe);
        record.bool_field("circuit_breaker_armed", self.circuit_breaker_armed);
        record.bool_field("live_evidence_seen", self.live_evidence_seen);
        record.bool_field("pq_authorized", self.pq_authorized);
        record.bool_field("operator_signed", self.operator_signed);
        record.bool_field("reviewer_signed", self.reviewer_signed);
        record.bool_field("roots_only", self.roots_only);
        record.finish()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GateReport {
    pub gate: GateKind,
    pub status: GateStatus,
    pub reason: String,
    pub root: String,
}

impl GateReport {
    pub fn new(gate: GateKind, status: GateStatus, reason: &str, root: &str) -> Self {
        Self {
            gate,
            status,
            reason: reason.to_string(),
            root: root.to_string(),
        }
    }

    pub fn clear(gate: GateKind, root: &str) -> Self {
        Self::new(gate, GateStatus::Clear, "clear", root)
    }

    pub fn failed(gate: GateKind, reason: &str, root: &str) -> Self {
        Self::new(gate, GateStatus::Failed, reason, root)
    }

    pub fn missing(gate: GateKind, reason: &str) -> Self {
        Self::new(gate, GateStatus::Missing, reason, "")
    }

    pub fn public_record(&self) -> PublicRecord {
        let mut record = RecordBuilder::new("gate_report");
        record.field("gate", self.gate.as_str());
        record.field("status", self.status.as_str());
        record.field("reason", &self.reason);
        record.root_field("root", &self.root);
        record.finish()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct State {
    pub config: Config,
    pub roots: RootBundle,
    pub evidence: EvidenceStatus,
    pub gate_reports: Vec<GateReport>,
    pub decision: AccountingDecision,
    pub release_credit_allowed: bool,
    pub credit_accounting_allowed: bool,
    pub heavy_gates_ran: bool,
    pub state_root: String,
}

impl Default for State {
    fn default() -> Self {
        let config = Config::default();
        let roots = RootBundle::default();
        let evidence = EvidenceStatus::default();
        let gate_reports = evaluate_gates(&config, &roots, &evidence);
        let state_root = compute_state_root(&config, &roots, &evidence, &gate_reports);
        Self {
            config,
            roots,
            evidence,
            gate_reports,
            decision: AccountingDecision::FailClosed,
            release_credit_allowed: false,
            credit_accounting_allowed: false,
            heavy_gates_ran: false,
            state_root,
        }
    }
}

impl State {
    pub fn new(config: Config, roots: RootBundle, evidence: EvidenceStatus) -> Result<Self> {
        config.validate()?;
        roots.validate_required(&config)?;
        let gate_reports = evaluate_gates(&config, &roots, &evidence);
        let all_clear = gate_reports.iter().all(|report| report.status.is_clear());
        let heavy_gates_ran = config.heavy_gates_ran && all_clear;
        let release_credit_allowed = config.release_credit_allowed && heavy_gates_ran;
        let credit_accounting_allowed = config.credit_accounting_allowed && release_credit_allowed;
        let decision = if credit_accounting_allowed {
            AccountingDecision::ReleaseCreditAllowed
        } else if heavy_gates_ran {
            AccountingDecision::HeavyGateCandidate
        } else if evidence.live_evidence_seen {
            AccountingDecision::EvidenceObserved
        } else {
            AccountingDecision::FailClosed
        };
        let state_root = compute_state_root(&config, &roots, &evidence, &gate_reports);
        Ok(Self {
            config,
            roots,
            evidence,
            gate_reports,
            decision,
            release_credit_allowed,
            credit_accounting_allowed,
            heavy_gates_ran,
            state_root,
        })
    }

    pub fn fail_closed_with(config: Config) -> Self {
        let roots = RootBundle::default();
        let evidence = EvidenceStatus::default();
        let gate_reports = evaluate_gates(&config, &roots, &evidence);
        let state_root = compute_state_root(&config, &roots, &evidence, &gate_reports);
        Self {
            config,
            roots,
            evidence,
            gate_reports,
            decision: AccountingDecision::FailClosed,
            release_credit_allowed: false,
            credit_accounting_allowed: false,
            heavy_gates_ran: false,
            state_root,
        }
    }

    pub fn denied_reasons(&self) -> Vec<String> {
        self.gate_reports
            .iter()
            .filter(|report| !report.status.is_clear())
            .map(|report| format!("{}:{}", report.gate.as_str(), report.reason))
            .collect()
    }

    pub fn public_record(&self) -> PublicRecord {
        let mut record = RecordBuilder::new("wallet_watchtower_credit_accounting_status");
        record.field("chain_id", &self.config.chain_id);
        record.field("protocol_version", &self.config.protocol_version);
        record.u64_field("wave", self.config.wave);
        record.field("lane_id", &self.config.lane_id);
        record.field("decision", self.decision.as_str());
        record.bool_field("release_credit_allowed", self.release_credit_allowed);
        record.bool_field("credit_accounting_allowed", self.credit_accounting_allowed);
        record.bool_field("heavy_gates_ran", self.heavy_gates_ran);
        record.root_field("state_root", &self.state_root);
        record.nested_field("roots", self.roots.public_record());
        record.nested_field("evidence_status", self.evidence.public_record());
        record.list_field("denied_reasons", self.denied_reasons());
        record.list_field("fail_closed_defaults", fail_closed_snippets());
        record.list_field("gate_reports", self.gate_report_records());
        record.finish()
    }

    pub fn gate_report_records(&self) -> Vec<String> {
        self.gate_reports
            .iter()
            .map(GateReport::public_record)
            .collect()
    }
}

pub fn devnet() -> Runtime {
    let config = Config::default();
    State::fail_closed_with(config)
}

pub fn public_record(runtime: &Runtime) -> PublicRecord {
    runtime.public_record()
}

pub fn state_root(runtime: &Runtime) -> String {
    runtime.state_root.clone()
}

pub fn evaluate_gates(
    config: &Config,
    roots: &RootBundle,
    evidence: &EvidenceStatus,
) -> Vec<GateReport> {
    let mut reports = Vec::new();
    reports.push(evaluate_watchtower(config, roots, evidence));
    reports.push(evaluate_wallet_history(config, roots, evidence));
    reports.push(evaluate_reorg(config, roots, evidence));
    reports.push(evaluate_confirmation(config, roots, evidence));
    reports.push(evaluate_accounting(config, roots, evidence));
    reports.push(evaluate_fee_rebate(config, roots, evidence));
    reports.push(evaluate_reserve(config, roots, evidence));
    reports.push(evaluate_pq_authorization(config, roots, evidence));
    reports.push(evaluate_circuit_breaker(config, roots, evidence));
    reports.push(evaluate_live_evidence(config, roots, evidence));
    reports.push(evaluate_signoff(config, roots, evidence));
    reports.push(evaluate_roots_only(config, roots, evidence));
    reports
}

fn evaluate_watchtower(
    config: &Config,
    roots: &RootBundle,
    evidence: &EvidenceStatus,
) -> GateReport {
    let root = &roots.watchtower_root;
    if let Some(report) = root_gate_report(
        GateKind::Watchtower,
        root,
        config.require_watchtower_root,
        "missing_watchtower_root",
        "invalid_watchtower_root",
    ) {
        return report;
    }
    if evidence.watchtower_quorum < config.min_watchtower_quorum {
        return GateReport::failed(GateKind::Watchtower, "watchtower_quorum_too_low", root);
    }
    GateReport::clear(GateKind::Watchtower, root)
}

fn evaluate_wallet_history(
    config: &Config,
    roots: &RootBundle,
    evidence: &EvidenceStatus,
) -> GateReport {
    let root = &roots.wallet_history_root;
    if let Some(report) = root_gate_report(
        GateKind::WalletHistory,
        root,
        config.require_wallet_history_root,
        "missing_wallet_history_root",
        "invalid_wallet_history_root",
    ) {
        return report;
    }
    if evidence.wallet_history_epoch < config.min_wallet_history_epoch {
        return GateReport::failed(
            GateKind::WalletHistory,
            "wallet_history_epoch_too_low",
            root,
        );
    }
    GateReport::clear(GateKind::WalletHistory, root)
}

fn evaluate_reorg(config: &Config, roots: &RootBundle, evidence: &EvidenceStatus) -> GateReport {
    let root = &roots.reorg_root;
    if let Some(report) = root_gate_report(
        GateKind::Reorg,
        root,
        config.require_reorg_root,
        "missing_reorg_root",
        "invalid_reorg_root",
    ) {
        return report;
    }
    if !evidence.reorg_safe {
        return GateReport::failed(GateKind::Reorg, "reorg_not_safe", root);
    }
    GateReport::clear(GateKind::Reorg, root)
}

fn evaluate_confirmation(
    config: &Config,
    roots: &RootBundle,
    evidence: &EvidenceStatus,
) -> GateReport {
    let root = &roots.confirmation_root;
    if let Some(report) = root_gate_report(
        GateKind::Confirmation,
        root,
        config.require_confirmation_root,
        "missing_confirmation_root",
        "invalid_confirmation_root",
    ) {
        return report;
    }
    if evidence.monero_confirmations < config.min_monero_confirmations {
        return GateReport::failed(GateKind::Confirmation, "monero_confirmations_too_low", root);
    }
    GateReport::clear(GateKind::Confirmation, root)
}

fn evaluate_accounting(
    config: &Config,
    roots: &RootBundle,
    evidence: &EvidenceStatus,
) -> GateReport {
    let root = &roots.accounting_root;
    if let Some(report) = root_gate_report(
        GateKind::Accounting,
        root,
        config.require_accounting_root,
        "missing_accounting_root",
        "invalid_accounting_root",
    ) {
        return report;
    }
    if evidence.accounting_epoch < config.min_accounting_epoch {
        return GateReport::failed(GateKind::Accounting, "accounting_epoch_too_low", root);
    }
    GateReport::clear(GateKind::Accounting, root)
}

fn evaluate_fee_rebate(
    config: &Config,
    roots: &RootBundle,
    evidence: &EvidenceStatus,
) -> GateReport {
    let root = &roots.fee_rebate_root;
    if let Some(report) = root_gate_report(
        GateKind::FeeRebate,
        root,
        config.require_fee_rebate_root,
        "missing_fee_rebate_root",
        "invalid_fee_rebate_root",
    ) {
        return report;
    }
    if evidence.fee_rebate_drift_bps > config.max_fee_rebate_drift_bps {
        return GateReport::failed(GateKind::FeeRebate, "fee_rebate_drift_too_high", root);
    }
    GateReport::clear(GateKind::FeeRebate, root)
}

fn evaluate_reserve(config: &Config, roots: &RootBundle, evidence: &EvidenceStatus) -> GateReport {
    let root = &roots.reserve_root;
    if let Some(report) = root_gate_report(
        GateKind::Reserve,
        root,
        config.require_reserve_root,
        "missing_reserve_root",
        "invalid_reserve_root",
    ) {
        return report;
    }
    if evidence.reserve_cover_bps < config.min_reserve_cover_bps {
        return GateReport::failed(GateKind::Reserve, "reserve_cover_too_low", root);
    }
    GateReport::clear(GateKind::Reserve, root)
}

fn evaluate_pq_authorization(
    config: &Config,
    roots: &RootBundle,
    evidence: &EvidenceStatus,
) -> GateReport {
    let root = &roots.pq_authorization_root;
    if let Some(report) = root_gate_report(
        GateKind::PqAuthorization,
        root,
        config.require_pq_authorization_root,
        "missing_pq_authorization_root",
        "invalid_pq_authorization_root",
    ) {
        return report;
    }
    if !evidence.pq_authorized {
        return GateReport::failed(GateKind::PqAuthorization, "pq_authorization_missing", root);
    }
    GateReport::clear(GateKind::PqAuthorization, root)
}

fn evaluate_circuit_breaker(
    config: &Config,
    roots: &RootBundle,
    evidence: &EvidenceStatus,
) -> GateReport {
    let root = &roots.circuit_breaker_root;
    if let Some(report) = root_gate_report(
        GateKind::CircuitBreaker,
        root,
        config.require_circuit_breaker_root,
        "missing_circuit_breaker_root",
        "invalid_circuit_breaker_root",
    ) {
        return report;
    }
    if evidence.circuit_breaker_armed || config.arm_circuit_breaker_by_default {
        return GateReport::failed(GateKind::CircuitBreaker, "circuit_breaker_armed", root);
    }
    GateReport::clear(GateKind::CircuitBreaker, root)
}

fn evaluate_live_evidence(
    config: &Config,
    roots: &RootBundle,
    evidence: &EvidenceStatus,
) -> GateReport {
    let root = &roots.live_evidence_root;
    if let Some(report) = root_gate_report(
        GateKind::LiveEvidence,
        root,
        config.require_live_evidence_root,
        "missing_live_evidence_root",
        "invalid_live_evidence_root",
    ) {
        return report;
    }
    if !evidence.live_evidence_seen {
        return GateReport::failed(GateKind::LiveEvidence, "live_evidence_missing", root);
    }
    GateReport::clear(GateKind::LiveEvidence, root)
}

fn evaluate_signoff(config: &Config, roots: &RootBundle, evidence: &EvidenceStatus) -> GateReport {
    if config.require_operator_signoff_root && roots.operator_signoff_root.is_empty() {
        return GateReport::missing(GateKind::Signoff, "missing_operator_signoff_root");
    }
    if config.require_reviewer_signoff_root && roots.reviewer_signoff_root.is_empty() {
        return GateReport::missing(GateKind::Signoff, "missing_reviewer_signoff_root");
    }
    if !is_valid_root(&roots.operator_signoff_root) {
        return GateReport::failed(
            GateKind::Signoff,
            "invalid_operator_signoff_root",
            &roots.operator_signoff_root,
        );
    }
    if !is_valid_root(&roots.reviewer_signoff_root) {
        return GateReport::failed(
            GateKind::Signoff,
            "invalid_reviewer_signoff_root",
            &roots.reviewer_signoff_root,
        );
    }
    if !evidence.operator_signed || !evidence.reviewer_signed {
        return GateReport::failed(
            GateKind::Signoff,
            "lane_signoff_missing",
            &roots.operator_signoff_root,
        );
    }
    GateReport::clear(GateKind::Signoff, &roots.operator_signoff_root)
}

fn evaluate_roots_only(
    config: &Config,
    roots: &RootBundle,
    evidence: &EvidenceStatus,
) -> GateReport {
    let root = roots.root_for(GateKind::RootsOnly);
    if !config.require_roots_only_records || !evidence.roots_only {
        return GateReport::failed(GateKind::RootsOnly, "roots_only_boundary_violated", root);
    }
    GateReport::clear(GateKind::RootsOnly, root)
}

fn validate_root_when_required(name: &'static str, root: &str, required: bool) -> Result<()> {
    if required && root.is_empty() {
        return Err(CreditAccountingError::MissingRoot(name));
    }
    if !root.is_empty() && !is_valid_root(root) {
        return Err(CreditAccountingError::InvalidRoot(name));
    }
    Ok(())
}

fn root_gate_report(
    gate: GateKind,
    root: &str,
    required: bool,
    missing: &str,
    invalid: &str,
) -> Option<GateReport> {
    if required && root.is_empty() {
        return Some(GateReport::missing(gate, missing));
    }
    if !is_valid_root(root) {
        return Some(GateReport::failed(gate, invalid, root));
    }
    None
}

fn is_valid_root(root: &str) -> bool {
    root.len() == ROOT_HEX_LEN && root.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn fail_closed_snippets() -> Vec<String> {
    vec![
        "release_credit_allowed: false".to_string(),
        "credit_accounting_allowed: false".to_string(),
        "heavy_gates_ran: false".to_string(),
    ]
}

fn compute_state_root(
    config: &Config,
    roots: &RootBundle,
    evidence: &EvidenceStatus,
    gate_reports: &[GateReport],
) -> String {
    let mut parts = Vec::new();
    parts.push(config.public_record());
    parts.push(roots.public_record());
    parts.push(evidence.public_record());
    for report in gate_reports {
        parts.push(report.public_record());
    }
    stable_root(&parts.join("|"))
}

fn stable_root(input: &str) -> String {
    let mut lanes = [
        0x243f_6a88_85a3_08d3_u64,
        0x1319_8a2e_0370_7344_u64,
        0xa409_3822_299f_31d0_u64,
        0x082e_fa98_ec4e_6c89_u64,
    ];
    for (index, byte) in input.bytes().enumerate() {
        let lane = index % lanes.len();
        lanes[lane] ^= byte as u64;
        lanes[lane] = lanes[lane].rotate_left(7);
        lanes[lane] = lanes[lane].wrapping_mul(0x1000_0000_01b3);
        lanes[lane] ^= (index as u64).rotate_left((lane * 11) as u32);
    }
    format!(
        "{:016x}{:016x}{:016x}{:016x}",
        lanes[0], lanes[1], lanes[2], lanes[3]
    )
}

fn escape_value(value: &str) -> String {
    let mut escaped = String::new();
    for ch in value.chars() {
        match ch {
            '\\' => escaped.push_str("\\\\"),
            '"' => escaped.push_str("\\\""),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            _ => escaped.push(ch),
        }
    }
    escaped
}

#[derive(Clone, Debug)]
struct RecordBuilder {
    label: String,
    fields: BTreeMap<String, String>,
}

impl RecordBuilder {
    fn new(label: &str) -> Self {
        let mut fields = BTreeMap::new();
        fields.insert("record".to_string(), quoted(label));
        Self {
            label: label.to_string(),
            fields,
        }
    }

    fn field(&mut self, name: &str, value: &str) {
        self.fields.insert(name.to_string(), quoted(value));
    }

    fn root_field(&mut self, name: &str, value: &str) {
        let rendered = if value.is_empty() {
            quoted("missing")
        } else {
            quoted(value)
        };
        self.fields.insert(name.to_string(), rendered);
    }

    fn bool_field(&mut self, name: &str, value: bool) {
        self.fields.insert(name.to_string(), value.to_string());
    }

    fn u64_field(&mut self, name: &str, value: u64) {
        self.fields.insert(name.to_string(), value.to_string());
    }

    fn nested_field(&mut self, name: &str, value: String) {
        self.fields.insert(name.to_string(), value);
    }

    fn list_field(&mut self, name: &str, values: Vec<String>) {
        let rendered = values
            .iter()
            .map(|value| quoted(value))
            .collect::<Vec<String>>()
            .join(", ");
        self.fields
            .insert(name.to_string(), format!("[{}]", rendered));
    }

    fn finish(self) -> String {
        let mut rendered = Vec::new();
        rendered.push(format!("\"record\": {}", quoted(&self.label)));
        for (key, value) in self.fields {
            if key != "record" {
                rendered.push(format!("\"{}\": {}", escape_value(&key), value));
            }
        }
        format!("{{{}}}", rendered.join(", "))
    }
}

fn quoted(value: &str) -> String {
    format!("\"{}\"", escape_value(value))
}
