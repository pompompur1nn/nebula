use std::collections::BTreeMap;

const CHAIN_ID: &str = "nebula-monero-private-l2-devnet";
const LANE_ID: &str = "bridge_custody";
const PROTOCOL_VERSION: &str =
    "wave105-live-heavy-gate-release-execution-monero-confirmed-credit-accounting-guard-bridge-custody-lane-runtime-v1";
const WAVE: u64 = 105;
const PREVIOUS_WAVE: u64 = 104;
const MIN_REORG_CLEARANCE_DEPTH: u64 = 720;
const MIN_RELEASE_QUEUE_AGE: u64 = 40;
const MIN_HEAVY_GATE_ROUNDS: u64 = 6;
const MAX_FEE_REBATE_DRIFT_ATOMIC_UNITS: i128 = 0;
const MAX_ACCOUNTING_DELTA_ATOMIC_UNITS: i128 = 0;
const DEFAULT_RESERVE_FLOOR_ATOMIC_UNITS: u128 = 1_000_000_000_000;
const DEFAULT_SIGNOFF_QUORUM: u16 = 4;

pub type PublicRecord = Record;
pub type Runtime = State;
pub type Result<T> = std::result::Result<T, CreditGateError>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FieldValue {
    Text(String),
    Bool(bool),
    U64(u64),
    U128(u128),
    I128(i128),
    List(Vec<String>),
}

impl FieldValue {
    pub fn render(&self) -> String {
        match self {
            Self::Text(value) => value.clone(),
            Self::Bool(value) => value.to_string(),
            Self::U64(value) => value.to_string(),
            Self::U128(value) => value.to_string(),
            Self::I128(value) => value.to_string(),
            Self::List(values) => values.join(","),
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Record {
    fields: BTreeMap<String, FieldValue>,
}

impl Record {
    pub fn new() -> Self {
        Self {
            fields: BTreeMap::new(),
        }
    }

    pub fn insert_text(&mut self, key: &str, value: &str) {
        self.fields
            .insert(key.to_string(), FieldValue::Text(value.to_string()));
    }

    pub fn insert_bool(&mut self, key: &str, value: bool) {
        self.fields.insert(key.to_string(), FieldValue::Bool(value));
    }

    pub fn insert_u64(&mut self, key: &str, value: u64) {
        self.fields.insert(key.to_string(), FieldValue::U64(value));
    }

    pub fn insert_u128(&mut self, key: &str, value: u128) {
        self.fields.insert(key.to_string(), FieldValue::U128(value));
    }

    pub fn insert_i128(&mut self, key: &str, value: i128) {
        self.fields.insert(key.to_string(), FieldValue::I128(value));
    }

    pub fn insert_list(&mut self, key: &str, value: Vec<String>) {
        self.fields.insert(key.to_string(), FieldValue::List(value));
    }

    pub fn canonical_string(&self) -> String {
        let mut out = String::new();
        for (key, value) in &self.fields {
            out.push_str(key);
            out.push('=');
            out.push_str(&value.render());
            out.push(';');
        }
        out
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CreditGateError {
    EmptyField(&'static str),
    InvalidRoot(&'static str),
    InvalidAmount(&'static str),
    InvalidThreshold(&'static str),
    MissingRoot(RootKind),
    MissingSignoff(SignoffRole),
    CircuitBreakerArmed,
    ReorgClearanceTooLow,
    ReleaseQueueTooYoung,
    ReserveBelowFloor,
    AccountingDeltaNonZero,
    FeeRebateNettingNonZero,
    PqAuthorizationMissing,
    HeavyGateEvidenceMissing,
    HeavyGateRoundsTooLow,
    ConfirmedRelayEvidenceMissing,
    CreditStillBlocked,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum RootKind {
    Wave104ConfirmedRelay,
    CustodyReserve,
    ThresholdSigner,
    ReleaseQueue,
    ReorgClearance,
    AccountingDelta,
    FeeRebateNetting,
    PqAuthorization,
    CircuitBreaker,
    LiveHeavyGateEvidence,
    OperatorSignoff,
    ReviewerSignoff,
    ReleaseCaptainSignoff,
    BeneficiaryCreditLedger,
}

impl RootKind {
    pub fn all() -> [Self; 14] {
        [
            Self::Wave104ConfirmedRelay,
            Self::CustodyReserve,
            Self::ThresholdSigner,
            Self::ReleaseQueue,
            Self::ReorgClearance,
            Self::AccountingDelta,
            Self::FeeRebateNetting,
            Self::PqAuthorization,
            Self::CircuitBreaker,
            Self::LiveHeavyGateEvidence,
            Self::OperatorSignoff,
            Self::ReviewerSignoff,
            Self::ReleaseCaptainSignoff,
            Self::BeneficiaryCreditLedger,
        ]
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Wave104ConfirmedRelay => "wave104_confirmed_relay",
            Self::CustodyReserve => "custody_reserve",
            Self::ThresholdSigner => "threshold_signer",
            Self::ReleaseQueue => "release_queue",
            Self::ReorgClearance => "reorg_clearance",
            Self::AccountingDelta => "accounting_delta",
            Self::FeeRebateNetting => "fee_rebate_netting",
            Self::PqAuthorization => "pq_authorization",
            Self::CircuitBreaker => "circuit_breaker",
            Self::LiveHeavyGateEvidence => "live_heavy_gate_evidence",
            Self::OperatorSignoff => "operator_signoff",
            Self::ReviewerSignoff => "reviewer_signoff",
            Self::ReleaseCaptainSignoff => "release_captain_signoff",
            Self::BeneficiaryCreditLedger => "beneficiary_credit_ledger",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum SignoffRole {
    Operator,
    Reviewer,
    ReleaseCaptain,
    CustodyController,
}

impl SignoffRole {
    pub fn all() -> [Self; 4] {
        [
            Self::Operator,
            Self::Reviewer,
            Self::ReleaseCaptain,
            Self::CustodyController,
        ]
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Operator => "operator",
            Self::Reviewer => "reviewer",
            Self::ReleaseCaptain => "release_captain",
            Self::CustodyController => "custody_controller",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GateStatus {
    Empty,
    Blocked,
    Ready,
}

impl GateStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Empty => "empty",
            Self::Blocked => "blocked",
            Self::Ready => "ready",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Config {
    pub chain_id: String,
    pub lane_id: String,
    pub protocol_version: String,
    pub wave: u64,
    pub previous_wave: u64,
    pub min_reorg_clearance_depth: u64,
    pub min_release_queue_age: u64,
    pub min_heavy_gate_rounds: u64,
    pub max_fee_rebate_drift_atomic_units: i128,
    pub max_accounting_delta_atomic_units: i128,
    pub reserve_floor_atomic_units: u128,
    pub signoff_quorum: u16,
    pub roots_only_public_records: bool,
    pub release_credit_allowed: bool,
    pub credit_accounting_allowed: bool,
    pub heavy_gates_ran: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            lane_id: LANE_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            wave: WAVE,
            previous_wave: PREVIOUS_WAVE,
            min_reorg_clearance_depth: MIN_REORG_CLEARANCE_DEPTH,
            min_release_queue_age: MIN_RELEASE_QUEUE_AGE,
            min_heavy_gate_rounds: MIN_HEAVY_GATE_ROUNDS,
            max_fee_rebate_drift_atomic_units: MAX_FEE_REBATE_DRIFT_ATOMIC_UNITS,
            max_accounting_delta_atomic_units: MAX_ACCOUNTING_DELTA_ATOMIC_UNITS,
            reserve_floor_atomic_units: DEFAULT_RESERVE_FLOOR_ATOMIC_UNITS,
            signoff_quorum: DEFAULT_SIGNOFF_QUORUM,
            roots_only_public_records: true,
            release_credit_allowed: false,
            credit_accounting_allowed: false,
            heavy_gates_ran: false,
        }
    }
}

impl Config {
    pub fn devnet() -> Self {
        Self::default()
    }

    pub fn validate(&self) -> Result<()> {
        ensure_text("chain_id", &self.chain_id)?;
        ensure_text("lane_id", &self.lane_id)?;
        ensure_text("protocol_version", &self.protocol_version)?;
        ensure_nonzero("wave", self.wave)?;
        ensure_nonzero("previous_wave", self.previous_wave)?;
        ensure_nonzero("min_reorg_clearance_depth", self.min_reorg_clearance_depth)?;
        ensure_nonzero("min_release_queue_age", self.min_release_queue_age)?;
        ensure_nonzero("min_heavy_gate_rounds", self.min_heavy_gate_rounds)?;
        ensure_nonzero("signoff_quorum", u64::from(self.signoff_quorum))?;
        if self.reserve_floor_atomic_units == 0 {
            return Err(CreditGateError::InvalidAmount("reserve_floor_atomic_units"));
        }
        if self.wave <= self.previous_wave {
            return Err(CreditGateError::InvalidThreshold("wave"));
        }
        if self.max_fee_rebate_drift_atomic_units != 0 {
            return Err(CreditGateError::InvalidThreshold(
                "max_fee_rebate_drift_atomic_units",
            ));
        }
        if self.max_accounting_delta_atomic_units != 0 {
            return Err(CreditGateError::InvalidThreshold(
                "max_accounting_delta_atomic_units",
            ));
        }
        if !self.roots_only_public_records {
            return Err(CreditGateError::InvalidThreshold(
                "roots_only_public_records",
            ));
        }
        if self.release_credit_allowed {
            return Err(CreditGateError::CreditStillBlocked);
        }
        if self.credit_accounting_allowed {
            return Err(CreditGateError::CreditStillBlocked);
        }
        if self.heavy_gates_ran {
            return Err(CreditGateError::HeavyGateEvidenceMissing);
        }
        Ok(())
    }

    pub fn public_record(&self) -> PublicRecord {
        let mut record = Record::new();
        record.insert_text("chain_root", &field_root("chain", &self.chain_id));
        record.insert_text("lane_root", &field_root("lane", &self.lane_id));
        record.insert_text(
            "protocol_root",
            &field_root("protocol", &self.protocol_version),
        );
        record.insert_u64("wave", self.wave);
        record.insert_u64("previous_wave", self.previous_wave);
        record.insert_u64("min_reorg_clearance_depth", self.min_reorg_clearance_depth);
        record.insert_u64("min_release_queue_age", self.min_release_queue_age);
        record.insert_u64("min_heavy_gate_rounds", self.min_heavy_gate_rounds);
        record.insert_i128(
            "max_fee_rebate_drift_atomic_units",
            self.max_fee_rebate_drift_atomic_units,
        );
        record.insert_i128(
            "max_accounting_delta_atomic_units",
            self.max_accounting_delta_atomic_units,
        );
        record.insert_u128(
            "reserve_floor_atomic_units",
            self.reserve_floor_atomic_units,
        );
        record.insert_u64("signoff_quorum", u64::from(self.signoff_quorum));
        record.insert_bool("roots_only_public_records", self.roots_only_public_records);
        record.insert_bool("release_credit_allowed", self.release_credit_allowed);
        record.insert_bool("credit_accounting_allowed", self.credit_accounting_allowed);
        record.insert_bool("heavy_gates_ran", self.heavy_gates_ran);
        record
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvidenceRoot {
    pub kind: RootKind,
    pub root: String,
    pub source: String,
    pub observed_height: u64,
    pub accepted: bool,
}

impl EvidenceRoot {
    pub fn rejected(kind: RootKind, root: &str, source: &str, observed_height: u64) -> Self {
        Self {
            kind,
            root: root.to_string(),
            source: source.to_string(),
            observed_height,
            accepted: false,
        }
    }

    pub fn validate(&self) -> Result<()> {
        ensure_root("root", &self.root)?;
        ensure_text("source", &self.source)?;
        ensure_nonzero("observed_height", self.observed_height)?;
        if !self.accepted {
            return Err(CreditGateError::MissingRoot(self.kind));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Signoff {
    pub role: SignoffRole,
    pub signer_root: String,
    pub attestation_root: String,
    pub approved: bool,
}

impl Signoff {
    pub fn missing(role: SignoffRole) -> Self {
        Self {
            role,
            signer_root: String::new(),
            attestation_root: String::new(),
            approved: false,
        }
    }

    pub fn validate(&self) -> Result<()> {
        if !self.approved {
            return Err(CreditGateError::MissingSignoff(self.role));
        }
        ensure_root("signer_root", &self.signer_root)?;
        ensure_root("attestation_root", &self.attestation_root)?;
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccountingDelta {
    pub beneficiary_root: String,
    pub pending_credit_atomic_units: u128,
    pub custody_debit_atomic_units: u128,
    pub fee_atomic_units: u128,
    pub rebate_atomic_units: u128,
    pub net_delta_atomic_units: i128,
}

impl AccountingDelta {
    pub fn blocked() -> Self {
        Self {
            beneficiary_root: "root:beneficiary:withheld-until-wave105-credit-gate-clears"
                .to_string(),
            pending_credit_atomic_units: 0,
            custody_debit_atomic_units: 0,
            fee_atomic_units: 0,
            rebate_atomic_units: 0,
            net_delta_atomic_units: 1,
        }
    }

    pub fn validate(&self, config: &Config) -> Result<()> {
        ensure_root("beneficiary_root", &self.beneficiary_root)?;
        if self.pending_credit_atomic_units == 0 {
            return Err(CreditGateError::InvalidAmount(
                "pending_credit_atomic_units",
            ));
        }
        if self.custody_debit_atomic_units == 0 {
            return Err(CreditGateError::InvalidAmount("custody_debit_atomic_units"));
        }
        if self.net_delta_atomic_units != config.max_accounting_delta_atomic_units {
            return Err(CreditGateError::AccountingDeltaNonZero);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FeeRebateNetting {
    pub fee_root: String,
    pub rebate_root: String,
    pub gross_fee_atomic_units: u128,
    pub gross_rebate_atomic_units: u128,
    pub net_drift_atomic_units: i128,
}

impl FeeRebateNetting {
    pub fn blocked() -> Self {
        Self {
            fee_root: "root:fee:withheld-until-fee-rebate-netting-clears".to_string(),
            rebate_root: "root:rebate:withheld-until-fee-rebate-netting-clears".to_string(),
            gross_fee_atomic_units: 0,
            gross_rebate_atomic_units: 0,
            net_drift_atomic_units: 1,
        }
    }

    pub fn validate(&self, config: &Config) -> Result<()> {
        ensure_root("fee_root", &self.fee_root)?;
        ensure_root("rebate_root", &self.rebate_root)?;
        if self.net_drift_atomic_units != config.max_fee_rebate_drift_atomic_units {
            return Err(CreditGateError::FeeRebateNettingNonZero);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CustodyReserve {
    pub reserve_root: String,
    pub reserve_atomic_units: u128,
    pub liabilities_atomic_units: u128,
    pub reserve_floor_atomic_units: u128,
}

impl CustodyReserve {
    pub fn blocked(config: &Config) -> Self {
        Self {
            reserve_root: "root:custody-reserve:unproven".to_string(),
            reserve_atomic_units: 0,
            liabilities_atomic_units: config.reserve_floor_atomic_units,
            reserve_floor_atomic_units: config.reserve_floor_atomic_units,
        }
    }

    pub fn validate(&self) -> Result<()> {
        ensure_root("reserve_root", &self.reserve_root)?;
        if self.reserve_atomic_units < self.reserve_floor_atomic_units {
            return Err(CreditGateError::ReserveBelowFloor);
        }
        if self.reserve_atomic_units < self.liabilities_atomic_units {
            return Err(CreditGateError::ReserveBelowFloor);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReleaseQueue {
    pub queue_root: String,
    pub queue_age_blocks: u64,
    pub beneficiary_count: u64,
    pub queue_frozen: bool,
}

impl ReleaseQueue {
    pub fn blocked() -> Self {
        Self {
            queue_root: "root:release-queue:blocked".to_string(),
            queue_age_blocks: 0,
            beneficiary_count: 0,
            queue_frozen: true,
        }
    }

    pub fn validate(&self, config: &Config) -> Result<()> {
        ensure_root("queue_root", &self.queue_root)?;
        if self.queue_age_blocks < config.min_release_queue_age {
            return Err(CreditGateError::ReleaseQueueTooYoung);
        }
        if self.beneficiary_count == 0 {
            return Err(CreditGateError::InvalidAmount("beneficiary_count"));
        }
        if self.queue_frozen {
            return Err(CreditGateError::CreditStillBlocked);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReorgClearance {
    pub clearance_root: String,
    pub depth: u64,
    pub competing_branch_count: u64,
    pub cleared: bool,
}

impl ReorgClearance {
    pub fn blocked() -> Self {
        Self {
            clearance_root: "root:reorg-clearance:pending".to_string(),
            depth: 0,
            competing_branch_count: 1,
            cleared: false,
        }
    }

    pub fn validate(&self, config: &Config) -> Result<()> {
        ensure_root("clearance_root", &self.clearance_root)?;
        if self.depth < config.min_reorg_clearance_depth {
            return Err(CreditGateError::ReorgClearanceTooLow);
        }
        if self.competing_branch_count != 0 {
            return Err(CreditGateError::ReorgClearanceTooLow);
        }
        if !self.cleared {
            return Err(CreditGateError::ReorgClearanceTooLow);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HeavyGateEvidence {
    pub evidence_root: String,
    pub rounds: u64,
    pub live_feed_root: String,
    pub ran_live: bool,
}

impl HeavyGateEvidence {
    pub fn blocked() -> Self {
        Self {
            evidence_root: "root:live-heavy-gate:missing".to_string(),
            rounds: 0,
            live_feed_root: "root:live-feed:missing".to_string(),
            ran_live: false,
        }
    }

    pub fn validate(&self, config: &Config) -> Result<()> {
        ensure_root("evidence_root", &self.evidence_root)?;
        ensure_root("live_feed_root", &self.live_feed_root)?;
        if !self.ran_live {
            return Err(CreditGateError::HeavyGateEvidenceMissing);
        }
        if self.rounds < config.min_heavy_gate_rounds {
            return Err(CreditGateError::HeavyGateRoundsTooLow);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct State {
    pub config: Config,
    pub roots: Vec<EvidenceRoot>,
    pub signoffs: Vec<Signoff>,
    pub custody_reserve: CustodyReserve,
    pub release_queue: ReleaseQueue,
    pub reorg_clearance: ReorgClearance,
    pub accounting_delta: AccountingDelta,
    pub fee_rebate_netting: FeeRebateNetting,
    pub heavy_gate_evidence: HeavyGateEvidence,
    pub circuit_breaker_armed: bool,
    pub pq_authorized: bool,
    pub confirmed_relay_evidence_accepted: bool,
    pub release_credit_allowed: bool,
    pub credit_accounting_allowed: bool,
    pub heavy_gates_ran: bool,
    pub status: GateStatus,
}

impl Default for State {
    fn default() -> Self {
        Self::devnet()
    }
}

impl State {
    pub fn devnet() -> Self {
        let config = Config::devnet();
        Self {
            roots: fail_closed_roots(),
            signoffs: fail_closed_signoffs(),
            custody_reserve: CustodyReserve::blocked(&config),
            release_queue: ReleaseQueue::blocked(),
            reorg_clearance: ReorgClearance::blocked(),
            accounting_delta: AccountingDelta::blocked(),
            fee_rebate_netting: FeeRebateNetting::blocked(),
            heavy_gate_evidence: HeavyGateEvidence::blocked(),
            circuit_breaker_armed: true,
            pq_authorized: false,
            confirmed_relay_evidence_accepted: false,
            release_credit_allowed: false,
            credit_accounting_allowed: false,
            heavy_gates_ran: false,
            status: GateStatus::Blocked,
            config,
        }
    }

    pub fn validate(&self) -> Result<()> {
        self.config.validate()?;
        self.validate_required_roots()?;
        self.validate_signoffs()?;
        self.custody_reserve.validate()?;
        self.release_queue.validate(&self.config)?;
        self.reorg_clearance.validate(&self.config)?;
        self.accounting_delta.validate(&self.config)?;
        self.fee_rebate_netting.validate(&self.config)?;
        self.heavy_gate_evidence.validate(&self.config)?;
        if self.circuit_breaker_armed {
            return Err(CreditGateError::CircuitBreakerArmed);
        }
        if !self.pq_authorized {
            return Err(CreditGateError::PqAuthorizationMissing);
        }
        if !self.confirmed_relay_evidence_accepted {
            return Err(CreditGateError::ConfirmedRelayEvidenceMissing);
        }
        if !self.heavy_gates_ran {
            return Err(CreditGateError::HeavyGateEvidenceMissing);
        }
        if !self.release_credit_allowed || !self.credit_accounting_allowed {
            return Err(CreditGateError::CreditStillBlocked);
        }
        Ok(())
    }

    pub fn blockers(&self) -> Vec<String> {
        let mut blockers = Vec::new();
        collect_result(&mut blockers, self.config.validate());
        collect_result(&mut blockers, self.validate_required_roots());
        collect_result(&mut blockers, self.validate_signoffs());
        collect_result(&mut blockers, self.custody_reserve.validate());
        collect_result(&mut blockers, self.release_queue.validate(&self.config));
        collect_result(&mut blockers, self.reorg_clearance.validate(&self.config));
        collect_result(&mut blockers, self.accounting_delta.validate(&self.config));
        collect_result(
            &mut blockers,
            self.fee_rebate_netting.validate(&self.config),
        );
        collect_result(
            &mut blockers,
            self.heavy_gate_evidence.validate(&self.config),
        );
        if self.circuit_breaker_armed {
            blockers.push("circuit_breaker_armed".to_string());
        }
        if !self.pq_authorized {
            blockers.push("pq_authorization_missing".to_string());
        }
        if !self.confirmed_relay_evidence_accepted {
            blockers.push("confirmed_relay_evidence_missing".to_string());
        }
        if !self.release_credit_allowed {
            blockers.push("release_credit_allowed: false".to_string());
        }
        if !self.credit_accounting_allowed {
            blockers.push("credit_accounting_allowed: false".to_string());
        }
        if !self.heavy_gates_ran {
            blockers.push("heavy_gates_ran: false".to_string());
        }
        dedupe(blockers)
    }

    pub fn public_record(&self) -> PublicRecord {
        let blockers = self.blockers();
        let root_list = self
            .roots
            .iter()
            .map(|root| stable_root(root.kind.as_str(), &evidence_summary(root)))
            .collect::<Vec<String>>();
        let signoff_list = self
            .signoffs
            .iter()
            .map(|signoff| stable_root(signoff.role.as_str(), &signoff_summary(signoff)))
            .collect::<Vec<String>>();
        let mut record = Record::new();
        record.insert_text(
            "config_root",
            &record_root("config", &self.config.public_record()),
        );
        record.insert_list("evidence_roots", root_list);
        record.insert_list("signoff_roots", signoff_list);
        record.insert_text(
            "custody_reserve_root",
            &stable_root(
                "custody_reserve",
                &custody_reserve_summary(&self.custody_reserve),
            ),
        );
        record.insert_text(
            "release_queue_root",
            &stable_root("release_queue", &release_queue_summary(&self.release_queue)),
        );
        record.insert_text(
            "reorg_clearance_root",
            &stable_root(
                "reorg_clearance",
                &reorg_clearance_summary(&self.reorg_clearance),
            ),
        );
        record.insert_text(
            "accounting_delta_root",
            &stable_root(
                "accounting_delta",
                &accounting_delta_summary(&self.accounting_delta),
            ),
        );
        record.insert_text(
            "fee_rebate_netting_root",
            &stable_root(
                "fee_rebate_netting",
                &fee_rebate_summary(&self.fee_rebate_netting),
            ),
        );
        record.insert_text(
            "heavy_gate_evidence_root",
            &stable_root(
                "heavy_gate_evidence",
                &heavy_gate_summary(&self.heavy_gate_evidence),
            ),
        );
        record.insert_bool("circuit_breaker_armed", self.circuit_breaker_armed);
        record.insert_bool("pq_authorized", self.pq_authorized);
        record.insert_bool(
            "confirmed_relay_evidence_accepted",
            self.confirmed_relay_evidence_accepted,
        );
        record.insert_bool("release_credit_allowed", self.release_credit_allowed);
        record.insert_bool("credit_accounting_allowed", self.credit_accounting_allowed);
        record.insert_bool("heavy_gates_ran", self.heavy_gates_ran);
        record.insert_text("status", self.status.as_str());
        record.insert_list("blockers", blockers);
        record
    }

    pub fn root(&self) -> String {
        record_root("state", &self.public_record())
    }

    fn validate_required_roots(&self) -> Result<()> {
        for kind in RootKind::all() {
            if !self.has_accepted_root(kind) {
                return Err(CreditGateError::MissingRoot(kind));
            }
        }
        Ok(())
    }

    fn validate_signoffs(&self) -> Result<()> {
        let mut approved = 0_u16;
        for role in SignoffRole::all() {
            let mut found = false;
            for signoff in &self.signoffs {
                if signoff.role == role {
                    found = true;
                    signoff.validate()?;
                    if signoff.approved {
                        approved = approved.saturating_add(1);
                    }
                }
            }
            if !found {
                return Err(CreditGateError::MissingSignoff(role));
            }
        }
        if approved < self.config.signoff_quorum {
            return Err(CreditGateError::InvalidThreshold("signoff_quorum"));
        }
        Ok(())
    }

    fn has_accepted_root(&self, kind: RootKind) -> bool {
        self.roots
            .iter()
            .any(|root| root.kind == kind && root.accepted && root.validate().is_ok())
    }
}

pub fn devnet() -> Runtime {
    State::devnet()
}

pub fn public_record(runtime: &Runtime) -> PublicRecord {
    runtime.public_record()
}

pub fn state_root(state: &State) -> String {
    state.root()
}

fn fail_closed_roots() -> Vec<EvidenceRoot> {
    RootKind::all()
        .iter()
        .map(|kind| {
            EvidenceRoot::rejected(
                *kind,
                &format!(
                    "root:{}:withheld-until-wave105-credit-accounting-guard-clears",
                    kind.as_str()
                ),
                "fail-closed-devnet-default",
                1,
            )
        })
        .collect()
}

fn fail_closed_signoffs() -> Vec<Signoff> {
    SignoffRole::all()
        .iter()
        .map(|role| Signoff::missing(*role))
        .collect()
}

fn collect_result(blockers: &mut Vec<String>, result: Result<()>) {
    if let Err(error) = result {
        blockers.push(format!("{:?}", error));
    }
}

fn dedupe(values: Vec<String>) -> Vec<String> {
    let mut seen = BTreeMap::new();
    for value in values {
        seen.insert(value, true);
    }
    seen.keys().cloned().collect()
}

fn ensure_text(name: &'static str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        return Err(CreditGateError::EmptyField(name));
    }
    Ok(())
}

fn ensure_nonzero(name: &'static str, value: u64) -> Result<()> {
    if value == 0 {
        return Err(CreditGateError::InvalidThreshold(name));
    }
    Ok(())
}

fn ensure_root(name: &'static str, value: &str) -> Result<()> {
    ensure_text(name, value)?;
    if !value.starts_with("root:") {
        return Err(CreditGateError::InvalidRoot(name));
    }
    Ok(())
}

fn field_root(domain: &str, value: &str) -> String {
    stable_root(domain, value)
}

fn record_root(domain: &str, record: &Record) -> String {
    stable_root(domain, &record.canonical_string())
}

fn evidence_summary(root: &EvidenceRoot) -> String {
    format!(
        "{}:{}:{}:{}",
        root.kind.as_str(),
        root.root,
        root.observed_height,
        root.accepted
    )
}

fn signoff_summary(signoff: &Signoff) -> String {
    format!(
        "{}:{}:{}:{}",
        signoff.role.as_str(),
        signoff.signer_root,
        signoff.attestation_root,
        signoff.approved
    )
}

fn custody_reserve_summary(reserve: &CustodyReserve) -> String {
    format!(
        "{}:{}:{}:{}",
        reserve.reserve_root,
        reserve.reserve_atomic_units,
        reserve.liabilities_atomic_units,
        reserve.reserve_floor_atomic_units
    )
}

fn release_queue_summary(queue: &ReleaseQueue) -> String {
    format!(
        "{}:{}:{}:{}",
        queue.queue_root, queue.queue_age_blocks, queue.beneficiary_count, queue.queue_frozen
    )
}

fn reorg_clearance_summary(clearance: &ReorgClearance) -> String {
    format!(
        "{}:{}:{}:{}",
        clearance.clearance_root,
        clearance.depth,
        clearance.competing_branch_count,
        clearance.cleared
    )
}

fn accounting_delta_summary(delta: &AccountingDelta) -> String {
    format!(
        "{}:{}:{}:{}:{}:{}",
        delta.beneficiary_root,
        delta.pending_credit_atomic_units,
        delta.custody_debit_atomic_units,
        delta.fee_atomic_units,
        delta.rebate_atomic_units,
        delta.net_delta_atomic_units
    )
}

fn fee_rebate_summary(netting: &FeeRebateNetting) -> String {
    format!(
        "{}:{}:{}:{}:{}",
        netting.fee_root,
        netting.rebate_root,
        netting.gross_fee_atomic_units,
        netting.gross_rebate_atomic_units,
        netting.net_drift_atomic_units
    )
}

fn heavy_gate_summary(evidence: &HeavyGateEvidence) -> String {
    format!(
        "{}:{}:{}:{}",
        evidence.evidence_root, evidence.rounds, evidence.live_feed_root, evidence.ran_live
    )
}

fn stable_root(domain: &str, value: &str) -> String {
    let mut hash = 0xcbf29ce484222325_u64;
    for byte in domain.as_bytes().iter().chain(value.as_bytes()) {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("root:{}:{:016x}", domain, hash)
}
