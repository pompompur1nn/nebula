use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

const CHAIN_ID: &str = "nebula-monero-private-l2-devnet";
const PROTOCOL_VERSION: &str =
    "wave105-live-heavy-gate-release-execution-monero-confirmed-credit-accounting-guard-compile-lane-runtime-v1";
const LANE_ID: &str =
    "wave105-live-heavy-gate-release-execution-monero-confirmed-credit-accounting-guard-compile";
const WAVE: u64 = 105;
const SOURCE_WAVE: u64 = 104;
const MIN_CONFIRMATION_DEPTH: u64 = 10;
const MIN_REORG_MONITOR_DEPTH: u64 = 720;
const MIN_RELAY_WITNESSES: u64 = 3;
const MIN_OPERATOR_SIGNOFFS: u64 = 2;
const MIN_REVIEWER_SIGNOFFS: u64 = 2;
const MIN_HEAVY_GATE_EVIDENCE_ITEMS: u64 = 4;
const MIN_BENEFICIARY_RECORDS: u64 = 1;
const MIN_LEDGER_DELTAS: u64 = 1;

pub type PublicRecord = String;
pub type Runtime = State;
pub type Result<T> = std::result::Result<T, CreditAccountingGuardError>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CreditAccountingGuardError {
    EmptyLane,
    WrongLane,
    MissingWave104RelayWitnessRoot,
    MissingWave104ConfirmationLadderRoot,
    MissingWave104ReorgMonitorRoot,
    MissingCreditLedgerDeltaRoot,
    MissingBeneficiaryAccountingRoot,
    MissingFeeRebateNettingRoot,
    MissingReserveBalanceRoot,
    MissingPqAuthorizationRoot,
    MissingCircuitBreakerRoot,
    MissingLiveHeavyGateEvidenceRoot,
    MissingOperatorSignoffRoot,
    MissingReviewerSignoffRoot,
    MissingConfirmedRelayEvidenceRoot,
    ConfirmationDepthTooLow,
    ReorgMonitorDepthTooLow,
    RelayWitnessCountTooLow,
    HeavyGateEvidenceTooSmall,
    OperatorSignoffsTooLow,
    ReviewerSignoffsTooLow,
    LedgerDeltasTooLow,
    BeneficiaryRecordsTooLow,
    CircuitBreakerArmed,
    LedgerDeltaNotBalanced,
    ReserveBalanceNotBalanced,
    FeeRebateNettingNotBalanced,
    BeneficiaryAccountingNotBalanced,
    PqAuthorizationNotBound,
    ReleaseCreditDisabled,
    CreditAccountingDisabled,
}

impl CreditAccountingGuardError {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::EmptyLane => "empty_lane",
            Self::WrongLane => "wrong_lane",
            Self::MissingWave104RelayWitnessRoot => "missing_wave104_relay_witness_root",
            Self::MissingWave104ConfirmationLadderRoot => {
                "missing_wave104_confirmation_ladder_root"
            }
            Self::MissingWave104ReorgMonitorRoot => "missing_wave104_reorg_monitor_root",
            Self::MissingCreditLedgerDeltaRoot => "missing_credit_ledger_delta_root",
            Self::MissingBeneficiaryAccountingRoot => "missing_beneficiary_accounting_root",
            Self::MissingFeeRebateNettingRoot => "missing_fee_rebate_netting_root",
            Self::MissingReserveBalanceRoot => "missing_reserve_balance_root",
            Self::MissingPqAuthorizationRoot => "missing_pq_authorization_root",
            Self::MissingCircuitBreakerRoot => "missing_circuit_breaker_root",
            Self::MissingLiveHeavyGateEvidenceRoot => "missing_live_heavy_gate_evidence_root",
            Self::MissingOperatorSignoffRoot => "missing_operator_signoff_root",
            Self::MissingReviewerSignoffRoot => "missing_reviewer_signoff_root",
            Self::MissingConfirmedRelayEvidenceRoot => "missing_confirmed_relay_evidence_root",
            Self::ConfirmationDepthTooLow => "confirmation_depth_too_low",
            Self::ReorgMonitorDepthTooLow => "reorg_monitor_depth_too_low",
            Self::RelayWitnessCountTooLow => "relay_witness_count_too_low",
            Self::HeavyGateEvidenceTooSmall => "heavy_gate_evidence_too_small",
            Self::OperatorSignoffsTooLow => "operator_signoffs_too_low",
            Self::ReviewerSignoffsTooLow => "reviewer_signoffs_too_low",
            Self::LedgerDeltasTooLow => "ledger_deltas_too_low",
            Self::BeneficiaryRecordsTooLow => "beneficiary_records_too_low",
            Self::CircuitBreakerArmed => "circuit_breaker_armed",
            Self::LedgerDeltaNotBalanced => "ledger_delta_not_balanced",
            Self::ReserveBalanceNotBalanced => "reserve_balance_not_balanced",
            Self::FeeRebateNettingNotBalanced => "fee_rebate_netting_not_balanced",
            Self::BeneficiaryAccountingNotBalanced => "beneficiary_accounting_not_balanced",
            Self::PqAuthorizationNotBound => "pq_authorization_not_bound",
            Self::ReleaseCreditDisabled => "release_credit_disabled",
            Self::CreditAccountingDisabled => "credit_accounting_disabled",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LaneKind {
    Compile,
}

impl LaneKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Compile => "compile",
        }
    }

    pub fn title(&self) -> &'static str {
        match self {
            Self::Compile => "Compile confirmed Monero credit accounting guard",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GateStatus {
    Empty,
    Blocked,
    RootsPending,
    BalancesPending,
    SignoffsPending,
    HeavyGatePending,
    Ready,
}

impl GateStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Empty => "empty",
            Self::Blocked => "blocked",
            Self::RootsPending => "roots_pending",
            Self::BalancesPending => "balances_pending",
            Self::SignoffsPending => "signoffs_pending",
            Self::HeavyGatePending => "heavy_gate_pending",
            Self::Ready => "ready",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RootKind {
    Wave104RelayWitness,
    Wave104ConfirmationLadder,
    Wave104ReorgMonitor,
    CreditLedgerDelta,
    BeneficiaryAccounting,
    FeeRebateNetting,
    ReserveBalance,
    PqAuthorization,
    CircuitBreaker,
    LiveHeavyGateEvidence,
    OperatorSignoff,
    ReviewerSignoff,
    ConfirmedRelayEvidence,
}

impl RootKind {
    pub fn missing_error(&self) -> CreditAccountingGuardError {
        match self {
            Self::Wave104RelayWitness => CreditAccountingGuardError::MissingWave104RelayWitnessRoot,
            Self::Wave104ConfirmationLadder => {
                CreditAccountingGuardError::MissingWave104ConfirmationLadderRoot
            }
            Self::Wave104ReorgMonitor => CreditAccountingGuardError::MissingWave104ReorgMonitorRoot,
            Self::CreditLedgerDelta => CreditAccountingGuardError::MissingCreditLedgerDeltaRoot,
            Self::BeneficiaryAccounting => {
                CreditAccountingGuardError::MissingBeneficiaryAccountingRoot
            }
            Self::FeeRebateNetting => CreditAccountingGuardError::MissingFeeRebateNettingRoot,
            Self::ReserveBalance => CreditAccountingGuardError::MissingReserveBalanceRoot,
            Self::PqAuthorization => CreditAccountingGuardError::MissingPqAuthorizationRoot,
            Self::CircuitBreaker => CreditAccountingGuardError::MissingCircuitBreakerRoot,
            Self::LiveHeavyGateEvidence => {
                CreditAccountingGuardError::MissingLiveHeavyGateEvidenceRoot
            }
            Self::OperatorSignoff => CreditAccountingGuardError::MissingOperatorSignoffRoot,
            Self::ReviewerSignoff => CreditAccountingGuardError::MissingReviewerSignoffRoot,
            Self::ConfirmedRelayEvidence => {
                CreditAccountingGuardError::MissingConfirmedRelayEvidenceRoot
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub lane_id: String,
    pub active_lane: String,
    pub wave: u64,
    pub source_wave: u64,
    pub min_confirmation_depth: u64,
    pub min_reorg_monitor_depth: u64,
    pub min_relay_witnesses: u64,
    pub min_operator_signoffs: u64,
    pub min_reviewer_signoffs: u64,
    pub min_heavy_gate_evidence_items: u64,
    pub min_beneficiary_records: u64,
    pub min_ledger_deltas: u64,
    pub require_wave104_relay_witness_root: bool,
    pub require_wave104_confirmation_ladder_root: bool,
    pub require_wave104_reorg_monitor_root: bool,
    pub require_credit_ledger_delta_root: bool,
    pub require_beneficiary_accounting_root: bool,
    pub require_fee_rebate_netting_root: bool,
    pub require_reserve_balance_root: bool,
    pub require_pq_authorization_root: bool,
    pub require_circuit_breaker_root: bool,
    pub require_live_heavy_gate_evidence_root: bool,
    pub require_operator_signoff_root: bool,
    pub require_reviewer_signoff_root: bool,
    pub require_confirmed_relay_evidence_root: bool,
    pub require_balanced_credit_ledger_delta: bool,
    pub require_balanced_beneficiary_accounting: bool,
    pub require_balanced_fee_rebate_netting: bool,
    pub require_balanced_reserve_balance: bool,
    pub require_pq_authorization_binding: bool,
    pub arm_circuit_breaker_by_default: bool,
    pub release_credit_allowed: bool,
    pub credit_accounting_allowed: bool,
    pub heavy_gates_ran: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            lane_id: LANE_ID.to_string(),
            active_lane: LaneKind::Compile.as_str().to_string(),
            wave: WAVE,
            source_wave: SOURCE_WAVE,
            min_confirmation_depth: MIN_CONFIRMATION_DEPTH,
            min_reorg_monitor_depth: MIN_REORG_MONITOR_DEPTH,
            min_relay_witnesses: MIN_RELAY_WITNESSES,
            min_operator_signoffs: MIN_OPERATOR_SIGNOFFS,
            min_reviewer_signoffs: MIN_REVIEWER_SIGNOFFS,
            min_heavy_gate_evidence_items: MIN_HEAVY_GATE_EVIDENCE_ITEMS,
            min_beneficiary_records: MIN_BENEFICIARY_RECORDS,
            min_ledger_deltas: MIN_LEDGER_DELTAS,
            require_wave104_relay_witness_root: true,
            require_wave104_confirmation_ladder_root: true,
            require_wave104_reorg_monitor_root: true,
            require_credit_ledger_delta_root: true,
            require_beneficiary_accounting_root: true,
            require_fee_rebate_netting_root: true,
            require_reserve_balance_root: true,
            require_pq_authorization_root: true,
            require_circuit_breaker_root: true,
            require_live_heavy_gate_evidence_root: true,
            require_operator_signoff_root: true,
            require_reviewer_signoff_root: true,
            require_confirmed_relay_evidence_root: true,
            require_balanced_credit_ledger_delta: true,
            require_balanced_beneficiary_accounting: true,
            require_balanced_fee_rebate_netting: true,
            require_balanced_reserve_balance: true,
            require_pq_authorization_binding: true,
            arm_circuit_breaker_by_default: true,
            release_credit_allowed: false,
            credit_accounting_allowed: false,
            heavy_gates_ran: false,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RootEvidence {
    pub kind: RootKind,
    pub root: String,
    pub present: bool,
    pub source_wave: u64,
}

impl RootEvidence {
    pub fn missing(kind: RootKind) -> Self {
        Self {
            kind,
            root: String::new(),
            present: false,
            source_wave: SOURCE_WAVE,
        }
    }

    pub fn present(kind: RootKind, root: &str) -> Self {
        Self {
            kind,
            root: root.to_string(),
            present: !root.trim().is_empty(),
            source_wave: SOURCE_WAVE,
        }
    }

    pub fn is_clear(&self) -> bool {
        self.present && !self.root.trim().is_empty()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Wave104Roots {
    pub relay_witness: RootEvidence,
    pub confirmation_ladder: RootEvidence,
    pub reorg_monitor: RootEvidence,
}

impl Default for Wave104Roots {
    fn default() -> Self {
        Self {
            relay_witness: RootEvidence::missing(RootKind::Wave104RelayWitness),
            confirmation_ladder: RootEvidence::missing(RootKind::Wave104ConfirmationLadder),
            reorg_monitor: RootEvidence::missing(RootKind::Wave104ReorgMonitor),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountingRoots {
    pub credit_ledger_delta: RootEvidence,
    pub beneficiary_accounting: RootEvidence,
    pub fee_rebate_netting: RootEvidence,
    pub reserve_balance: RootEvidence,
}

impl Default for AccountingRoots {
    fn default() -> Self {
        Self {
            credit_ledger_delta: RootEvidence::missing(RootKind::CreditLedgerDelta),
            beneficiary_accounting: RootEvidence::missing(RootKind::BeneficiaryAccounting),
            fee_rebate_netting: RootEvidence::missing(RootKind::FeeRebateNetting),
            reserve_balance: RootEvidence::missing(RootKind::ReserveBalance),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorizationRoots {
    pub pq_authorization: RootEvidence,
    pub circuit_breaker: RootEvidence,
    pub live_heavy_gate_evidence: RootEvidence,
    pub operator_signoff: RootEvidence,
    pub reviewer_signoff: RootEvidence,
}

impl Default for AuthorizationRoots {
    fn default() -> Self {
        Self {
            pq_authorization: RootEvidence::missing(RootKind::PqAuthorization),
            circuit_breaker: RootEvidence::missing(RootKind::CircuitBreaker),
            live_heavy_gate_evidence: RootEvidence::missing(RootKind::LiveHeavyGateEvidence),
            operator_signoff: RootEvidence::missing(RootKind::OperatorSignoff),
            reviewer_signoff: RootEvidence::missing(RootKind::ReviewerSignoff),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelayEvidence {
    pub confirmed_relay_evidence_root: RootEvidence,
    pub confirmation_depth: u64,
    pub reorg_monitor_depth: u64,
    pub relay_witness_count: u64,
}

impl Default for RelayEvidence {
    fn default() -> Self {
        Self {
            confirmed_relay_evidence_root: RootEvidence::missing(RootKind::ConfirmedRelayEvidence),
            confirmation_depth: 0,
            reorg_monitor_depth: 0,
            relay_witness_count: 0,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountingChecks {
    pub ledger_delta_count: u64,
    pub beneficiary_record_count: u64,
    pub fee_rebate_entries: u64,
    pub reserve_balance_entries: u64,
    pub ledger_delta_balanced: bool,
    pub beneficiary_accounting_balanced: bool,
    pub fee_rebate_netting_balanced: bool,
    pub reserve_balance_balanced: bool,
    pub pq_authorization_bound: bool,
}

impl Default for AccountingChecks {
    fn default() -> Self {
        Self {
            ledger_delta_count: 0,
            beneficiary_record_count: 0,
            fee_rebate_entries: 0,
            reserve_balance_entries: 0,
            ledger_delta_balanced: false,
            beneficiary_accounting_balanced: false,
            fee_rebate_netting_balanced: false,
            reserve_balance_balanced: false,
            pq_authorization_bound: false,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeavyGateChecks {
    pub evidence_item_count: u64,
    pub operator_signoff_count: u64,
    pub reviewer_signoff_count: u64,
    pub circuit_breaker_armed: bool,
    pub live_evidence_attested: bool,
}

impl Default for HeavyGateChecks {
    fn default() -> Self {
        Self {
            evidence_item_count: 0,
            operator_signoff_count: 0,
            reviewer_signoff_count: 0,
            circuit_breaker_armed: true,
            live_evidence_attested: false,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GateDecision {
    pub release_credit_allowed: bool,
    pub credit_accounting_allowed: bool,
    pub heavy_gates_ran: bool,
    pub status: GateStatus,
    pub blockers: Vec<CreditAccountingGuardError>,
}

impl Default for GateDecision {
    fn default() -> Self {
        Self {
            release_credit_allowed: false,
            credit_accounting_allowed: false,
            heavy_gates_ran: false,
            status: GateStatus::Empty,
            blockers: Vec::new(),
        }
    }
}

impl GateDecision {
    pub fn push_blocker(&mut self, blocker: CreditAccountingGuardError) {
        if !self.blockers.contains(&blocker) {
            self.blockers.push(blocker);
        }
    }

    pub fn blocker_list(&self) -> String {
        if self.blockers.is_empty() {
            return "none".to_string();
        }
        let mut out = String::new();
        let mut first = true;
        for blocker in &self.blockers {
            if first {
                first = false;
            } else {
                out.push(',');
            }
            out.push_str(blocker.as_str());
        }
        out
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct State {
    pub config: Config,
    pub lane: LaneKind,
    pub wave104_roots: Wave104Roots,
    pub accounting_roots: AccountingRoots,
    pub authorization_roots: AuthorizationRoots,
    pub relay_evidence: RelayEvidence,
    pub accounting_checks: AccountingChecks,
    pub heavy_gate_checks: HeavyGateChecks,
    pub decision: GateDecision,
}

impl Default for State {
    fn default() -> Self {
        let config = Config::default();
        let mut state = Self {
            config,
            lane: LaneKind::Compile,
            wave104_roots: Wave104Roots::default(),
            accounting_roots: AccountingRoots::default(),
            authorization_roots: AuthorizationRoots::default(),
            relay_evidence: RelayEvidence::default(),
            accounting_checks: AccountingChecks::default(),
            heavy_gate_checks: HeavyGateChecks::default(),
            decision: GateDecision::default(),
        };
        state.decision = state.evaluate();
        state
    }
}

impl State {
    pub fn new(config: Config) -> Self {
        let mut state = Self {
            heavy_gate_checks: HeavyGateChecks {
                circuit_breaker_armed: config.arm_circuit_breaker_by_default,
                ..HeavyGateChecks::default()
            },
            config,
            lane: LaneKind::Compile,
            wave104_roots: Wave104Roots::default(),
            accounting_roots: AccountingRoots::default(),
            authorization_roots: AuthorizationRoots::default(),
            relay_evidence: RelayEvidence::default(),
            accounting_checks: AccountingChecks::default(),
            decision: GateDecision::default(),
        };
        state.decision = state.evaluate();
        state
    }

    pub fn evaluate(&self) -> GateDecision {
        let mut decision = GateDecision {
            release_credit_allowed: false,
            credit_accounting_allowed: false,
            heavy_gates_ran: false,
            status: GateStatus::Blocked,
            blockers: Vec::new(),
        };

        self.validate_lane(&mut decision);
        self.validate_roots(&mut decision);
        self.validate_relay(&mut decision);
        self.validate_accounting(&mut decision);
        self.validate_heavy_gates(&mut decision);

        decision.heavy_gates_ran = self.heavy_gate_checks.live_evidence_attested
            && self.heavy_gate_checks.evidence_item_count
                >= self.config.min_heavy_gate_evidence_items
            && self.authorization_roots.live_heavy_gate_evidence.is_clear();

        if decision.blockers.is_empty()
            && self.config.release_credit_allowed
            && self.config.credit_accounting_allowed
            && self.config.heavy_gates_ran
            && decision.heavy_gates_ran
        {
            decision.release_credit_allowed = true;
            decision.credit_accounting_allowed = true;
            decision.status = GateStatus::Ready;
        } else {
            if !self.config.release_credit_allowed {
                decision.push_blocker(CreditAccountingGuardError::ReleaseCreditDisabled);
            }
            if !self.config.credit_accounting_allowed {
                decision.push_blocker(CreditAccountingGuardError::CreditAccountingDisabled);
            }
            if !decision.heavy_gates_ran {
                decision.status = GateStatus::HeavyGatePending;
            }
            if self.has_missing_roots(&decision) {
                decision.status = GateStatus::RootsPending;
            }
            if self.has_balance_blockers(&decision) {
                decision.status = GateStatus::BalancesPending;
            }
            if self.has_signoff_blockers(&decision) {
                decision.status = GateStatus::SignoffsPending;
            }
        }

        decision
    }

    fn validate_lane(&self, decision: &mut GateDecision) {
        if self.config.active_lane.trim().is_empty() {
            decision.push_blocker(CreditAccountingGuardError::EmptyLane);
        }
        if self.config.active_lane != self.lane.as_str() {
            decision.push_blocker(CreditAccountingGuardError::WrongLane);
        }
    }

    fn validate_roots(&self, decision: &mut GateDecision) {
        self.require_root(
            decision,
            self.config.require_wave104_relay_witness_root,
            &self.wave104_roots.relay_witness,
        );
        self.require_root(
            decision,
            self.config.require_wave104_confirmation_ladder_root,
            &self.wave104_roots.confirmation_ladder,
        );
        self.require_root(
            decision,
            self.config.require_wave104_reorg_monitor_root,
            &self.wave104_roots.reorg_monitor,
        );
        self.require_root(
            decision,
            self.config.require_credit_ledger_delta_root,
            &self.accounting_roots.credit_ledger_delta,
        );
        self.require_root(
            decision,
            self.config.require_beneficiary_accounting_root,
            &self.accounting_roots.beneficiary_accounting,
        );
        self.require_root(
            decision,
            self.config.require_fee_rebate_netting_root,
            &self.accounting_roots.fee_rebate_netting,
        );
        self.require_root(
            decision,
            self.config.require_reserve_balance_root,
            &self.accounting_roots.reserve_balance,
        );
        self.require_root(
            decision,
            self.config.require_pq_authorization_root,
            &self.authorization_roots.pq_authorization,
        );
        self.require_root(
            decision,
            self.config.require_circuit_breaker_root,
            &self.authorization_roots.circuit_breaker,
        );
        self.require_root(
            decision,
            self.config.require_live_heavy_gate_evidence_root,
            &self.authorization_roots.live_heavy_gate_evidence,
        );
        self.require_root(
            decision,
            self.config.require_operator_signoff_root,
            &self.authorization_roots.operator_signoff,
        );
        self.require_root(
            decision,
            self.config.require_reviewer_signoff_root,
            &self.authorization_roots.reviewer_signoff,
        );
        self.require_root(
            decision,
            self.config.require_confirmed_relay_evidence_root,
            &self.relay_evidence.confirmed_relay_evidence_root,
        );
    }

    fn require_root(&self, decision: &mut GateDecision, required: bool, evidence: &RootEvidence) {
        if required && !evidence.is_clear() {
            decision.push_blocker(evidence.kind.missing_error());
        }
    }

    fn validate_relay(&self, decision: &mut GateDecision) {
        if self.relay_evidence.confirmation_depth < self.config.min_confirmation_depth {
            decision.push_blocker(CreditAccountingGuardError::ConfirmationDepthTooLow);
        }
        if self.relay_evidence.reorg_monitor_depth < self.config.min_reorg_monitor_depth {
            decision.push_blocker(CreditAccountingGuardError::ReorgMonitorDepthTooLow);
        }
        if self.relay_evidence.relay_witness_count < self.config.min_relay_witnesses {
            decision.push_blocker(CreditAccountingGuardError::RelayWitnessCountTooLow);
        }
    }

    fn validate_accounting(&self, decision: &mut GateDecision) {
        if self.accounting_checks.ledger_delta_count < self.config.min_ledger_deltas {
            decision.push_blocker(CreditAccountingGuardError::LedgerDeltasTooLow);
        }
        if self.accounting_checks.beneficiary_record_count < self.config.min_beneficiary_records {
            decision.push_blocker(CreditAccountingGuardError::BeneficiaryRecordsTooLow);
        }
        if self.config.require_balanced_credit_ledger_delta
            && !self.accounting_checks.ledger_delta_balanced
        {
            decision.push_blocker(CreditAccountingGuardError::LedgerDeltaNotBalanced);
        }
        if self.config.require_balanced_beneficiary_accounting
            && !self.accounting_checks.beneficiary_accounting_balanced
        {
            decision.push_blocker(CreditAccountingGuardError::BeneficiaryAccountingNotBalanced);
        }
        if self.config.require_balanced_fee_rebate_netting
            && !self.accounting_checks.fee_rebate_netting_balanced
        {
            decision.push_blocker(CreditAccountingGuardError::FeeRebateNettingNotBalanced);
        }
        if self.config.require_balanced_reserve_balance
            && !self.accounting_checks.reserve_balance_balanced
        {
            decision.push_blocker(CreditAccountingGuardError::ReserveBalanceNotBalanced);
        }
        if self.config.require_pq_authorization_binding
            && !self.accounting_checks.pq_authorization_bound
        {
            decision.push_blocker(CreditAccountingGuardError::PqAuthorizationNotBound);
        }
    }

    fn validate_heavy_gates(&self, decision: &mut GateDecision) {
        if self.heavy_gate_checks.circuit_breaker_armed {
            decision.push_blocker(CreditAccountingGuardError::CircuitBreakerArmed);
        }
        if self.heavy_gate_checks.evidence_item_count < self.config.min_heavy_gate_evidence_items {
            decision.push_blocker(CreditAccountingGuardError::HeavyGateEvidenceTooSmall);
        }
        if self.heavy_gate_checks.operator_signoff_count < self.config.min_operator_signoffs {
            decision.push_blocker(CreditAccountingGuardError::OperatorSignoffsTooLow);
        }
        if self.heavy_gate_checks.reviewer_signoff_count < self.config.min_reviewer_signoffs {
            decision.push_blocker(CreditAccountingGuardError::ReviewerSignoffsTooLow);
        }
    }

    fn has_missing_roots(&self, decision: &GateDecision) -> bool {
        decision.blockers.iter().any(|blocker| {
            matches!(
                blocker,
                CreditAccountingGuardError::MissingWave104RelayWitnessRoot
                    | CreditAccountingGuardError::MissingWave104ConfirmationLadderRoot
                    | CreditAccountingGuardError::MissingWave104ReorgMonitorRoot
                    | CreditAccountingGuardError::MissingCreditLedgerDeltaRoot
                    | CreditAccountingGuardError::MissingBeneficiaryAccountingRoot
                    | CreditAccountingGuardError::MissingFeeRebateNettingRoot
                    | CreditAccountingGuardError::MissingReserveBalanceRoot
                    | CreditAccountingGuardError::MissingPqAuthorizationRoot
                    | CreditAccountingGuardError::MissingCircuitBreakerRoot
                    | CreditAccountingGuardError::MissingLiveHeavyGateEvidenceRoot
                    | CreditAccountingGuardError::MissingOperatorSignoffRoot
                    | CreditAccountingGuardError::MissingReviewerSignoffRoot
                    | CreditAccountingGuardError::MissingConfirmedRelayEvidenceRoot
            )
        })
    }

    fn has_balance_blockers(&self, decision: &GateDecision) -> bool {
        decision.blockers.iter().any(|blocker| {
            matches!(
                blocker,
                CreditAccountingGuardError::LedgerDeltasTooLow
                    | CreditAccountingGuardError::BeneficiaryRecordsTooLow
                    | CreditAccountingGuardError::LedgerDeltaNotBalanced
                    | CreditAccountingGuardError::ReserveBalanceNotBalanced
                    | CreditAccountingGuardError::FeeRebateNettingNotBalanced
                    | CreditAccountingGuardError::BeneficiaryAccountingNotBalanced
                    | CreditAccountingGuardError::PqAuthorizationNotBound
            )
        })
    }

    fn has_signoff_blockers(&self, decision: &GateDecision) -> bool {
        decision.blockers.iter().any(|blocker| {
            matches!(
                blocker,
                CreditAccountingGuardError::OperatorSignoffsTooLow
                    | CreditAccountingGuardError::ReviewerSignoffsTooLow
                    | CreditAccountingGuardError::MissingOperatorSignoffRoot
                    | CreditAccountingGuardError::MissingReviewerSignoffRoot
            )
        })
    }
}

pub fn devnet() -> Runtime {
    State::default()
}

pub fn public_record(runtime: &Runtime) -> PublicRecord {
    let state_root_value = state_root(runtime);
    let mut record = String::new();
    for (key, value) in public_text_fields(runtime, &state_root_value) {
        push_line(&mut record, key, &value);
    }
    push_bool(
        &mut record,
        "release_credit_allowed",
        runtime.decision.release_credit_allowed,
    );
    push_bool(
        &mut record,
        "credit_accounting_allowed",
        runtime.decision.credit_accounting_allowed,
    );
    push_bool(
        &mut record,
        "heavy_gates_ran",
        runtime.decision.heavy_gates_ran,
    );
    record
}

pub fn state_root(runtime: &Runtime) -> String {
    let mut parts = Vec::new();
    parts.push(runtime.config.chain_id.clone());
    parts.push(runtime.config.protocol_version.clone());
    parts.push(runtime.config.lane_id.clone());
    parts.push(runtime.config.active_lane.clone());
    parts.push(runtime.config.wave.to_string());
    parts.push(runtime.config.source_wave.to_string());
    parts.push(runtime.wave104_roots.relay_witness.root.clone());
    parts.push(runtime.wave104_roots.confirmation_ladder.root.clone());
    parts.push(runtime.wave104_roots.reorg_monitor.root.clone());
    parts.push(runtime.accounting_roots.credit_ledger_delta.root.clone());
    parts.push(runtime.accounting_roots.beneficiary_accounting.root.clone());
    parts.push(runtime.accounting_roots.fee_rebate_netting.root.clone());
    parts.push(runtime.accounting_roots.reserve_balance.root.clone());
    parts.push(runtime.authorization_roots.pq_authorization.root.clone());
    parts.push(runtime.authorization_roots.circuit_breaker.root.clone());
    parts.push(
        runtime
            .authorization_roots
            .live_heavy_gate_evidence
            .root
            .clone(),
    );
    parts.push(runtime.authorization_roots.operator_signoff.root.clone());
    parts.push(runtime.authorization_roots.reviewer_signoff.root.clone());
    parts.push(
        runtime
            .relay_evidence
            .confirmed_relay_evidence_root
            .root
            .clone(),
    );
    parts.push(runtime.relay_evidence.confirmation_depth.to_string());
    parts.push(runtime.relay_evidence.reorg_monitor_depth.to_string());
    parts.push(runtime.relay_evidence.relay_witness_count.to_string());
    parts.push(runtime.accounting_checks.ledger_delta_count.to_string());
    parts.push(
        runtime
            .accounting_checks
            .beneficiary_record_count
            .to_string(),
    );
    parts.push(runtime.accounting_checks.ledger_delta_balanced.to_string());
    parts.push(
        runtime
            .accounting_checks
            .beneficiary_accounting_balanced
            .to_string(),
    );
    parts.push(
        runtime
            .accounting_checks
            .fee_rebate_netting_balanced
            .to_string(),
    );
    parts.push(
        runtime
            .accounting_checks
            .reserve_balance_balanced
            .to_string(),
    );
    parts.push(runtime.accounting_checks.pq_authorization_bound.to_string());
    parts.push(runtime.heavy_gate_checks.evidence_item_count.to_string());
    parts.push(runtime.heavy_gate_checks.operator_signoff_count.to_string());
    parts.push(runtime.heavy_gate_checks.reviewer_signoff_count.to_string());
    parts.push(runtime.heavy_gate_checks.circuit_breaker_armed.to_string());
    parts.push(runtime.heavy_gate_checks.live_evidence_attested.to_string());
    parts.push(runtime.decision.release_credit_allowed.to_string());
    parts.push(runtime.decision.credit_accounting_allowed.to_string());
    parts.push(runtime.decision.heavy_gates_ran.to_string());
    parts.push(runtime.decision.status.as_str().to_string());
    parts.push(runtime.decision.blocker_list());
    stable_root("wave105-confirmed-credit-accounting-guard", &parts)
}

fn public_text_fields(runtime: &Runtime, state_root_value: &str) -> Vec<(&'static str, String)> {
    vec![
        ("record_kind", "public_credit_accounting_guard".to_string()),
        ("chain_id", runtime.config.chain_id.clone()),
        ("protocol_version", runtime.config.protocol_version.clone()),
        ("lane_id", runtime.config.lane_id.clone()),
        ("active_lane", runtime.config.active_lane.clone()),
        ("lane_title", runtime.lane.title().to_string()),
        ("status", runtime.decision.status.as_str().to_string()),
        ("blockers", runtime.decision.blocker_list()),
        ("state_root", state_root_value.to_string()),
        (
            "wave104_relay_witness_root",
            display_root(&runtime.wave104_roots.relay_witness),
        ),
        (
            "wave104_confirmation_ladder_root",
            display_root(&runtime.wave104_roots.confirmation_ladder),
        ),
        (
            "wave104_reorg_monitor_root",
            display_root(&runtime.wave104_roots.reorg_monitor),
        ),
        (
            "credit_ledger_delta_root",
            display_root(&runtime.accounting_roots.credit_ledger_delta),
        ),
        (
            "beneficiary_accounting_root",
            display_root(&runtime.accounting_roots.beneficiary_accounting),
        ),
        (
            "fee_rebate_netting_root",
            display_root(&runtime.accounting_roots.fee_rebate_netting),
        ),
        (
            "reserve_balance_root",
            display_root(&runtime.accounting_roots.reserve_balance),
        ),
        (
            "pq_authorization_root",
            display_root(&runtime.authorization_roots.pq_authorization),
        ),
        (
            "circuit_breaker_root",
            display_root(&runtime.authorization_roots.circuit_breaker),
        ),
        (
            "live_heavy_gate_evidence_root",
            display_root(&runtime.authorization_roots.live_heavy_gate_evidence),
        ),
        (
            "operator_signoff_root",
            display_root(&runtime.authorization_roots.operator_signoff),
        ),
        (
            "reviewer_signoff_root",
            display_root(&runtime.authorization_roots.reviewer_signoff),
        ),
        (
            "confirmed_relay_evidence_root",
            display_root(&runtime.relay_evidence.confirmed_relay_evidence_root),
        ),
    ]
}

fn display_root(evidence: &RootEvidence) -> String {
    if evidence.is_clear() {
        evidence.root.clone()
    } else {
        "missing".to_string()
    }
}

fn push_line(record: &mut String, key: &str, value: &str) {
    record.push_str(key);
    record.push_str(": ");
    record.push_str(value);
    record.push('\n');
}

fn push_bool(record: &mut String, key: &str, value: bool) {
    record.push_str(key);
    record.push_str(": ");
    if value {
        record.push_str("true");
    } else {
        record.push_str("false");
    }
    record.push('\n');
}

fn stable_root(domain: &str, parts: &[String]) -> String {
    let mut leaves = Vec::new();
    for part in parts {
        leaves.push(stable_hash(&format!("{}:{}", domain, part)));
    }
    if leaves.is_empty() {
        return stable_hash(domain);
    }
    while leaves.len() > 1 {
        let mut next = Vec::new();
        let mut index = 0usize;
        while index < leaves.len() {
            let left = &leaves[index];
            let right = if index + 1 < leaves.len() {
                &leaves[index + 1]
            } else {
                &leaves[index]
            };
            next.push(stable_hash(&format!("{}:{}:{}", domain, left, right)));
            index += 2;
        }
        leaves = next;
    }
    match leaves.first() {
        Some(root) => root.clone(),
        None => stable_hash(domain),
    }
}

fn stable_hash(value: &str) -> String {
    let mut hasher = DefaultHasher::new();
    value.hash(&mut hasher);
    let high = hasher.finish();
    let mut second = DefaultHasher::new();
    "wave105-credit-accounting-guard".hash(&mut second);
    value.hash(&mut second);
    let low = second.finish();
    format!("{:016x}{:016x}", high, low)
}
